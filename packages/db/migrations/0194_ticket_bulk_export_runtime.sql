CREATE ROLE "periapsis_ticket_runtime_owner" WITH NOINHERIT;--> statement-breakpoint
CREATE TABLE "ticket_bulk_batches" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"kind" "ticket_aggregate_kind" NOT NULL,
	"worker_id" uuid NOT NULL,
	"revision" bigint NOT NULL,
	"attempt" smallint NOT NULL,
	"fence_digest" "bytea" NOT NULL,
	"target_set_digest" "bytea" NOT NULL,
	"projection_version" bigint NOT NULL,
	"claimed_at" timestamp with time zone NOT NULL,
	"lease_expires_at" timestamp with time zone NOT NULL,
	"job_expires_at" timestamp with time zone NOT NULL,
	"state" text NOT NULL,
	"processed" integer DEFAULT 0 NOT NULL,
	"receipt_digest" "bytea",
	"failure_code" text,
	"retry_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	CONSTRAINT "ticket_bulk_batches_tenant_job_id_key" UNIQUE("tenant_id","job_id","id"),
	CONSTRAINT "ticket_bulk_batches_shape_check" CHECK ((uuid_extract_version("ticket_bulk_batches"."id") = 7) is true
        and (uuid_extract_version("ticket_bulk_batches"."worker_id") = 7) is true
        and "ticket_bulk_batches"."revision" between 1 and 9007199254740991
        and "ticket_bulk_batches"."attempt" between 1 and 100
        and octet_length("ticket_bulk_batches"."fence_digest") = 32
        and octet_length("ticket_bulk_batches"."target_set_digest") = 32
        and "ticket_bulk_batches"."projection_version" = 1
        and "ticket_bulk_batches"."lease_expires_at" > "ticket_bulk_batches"."claimed_at"
        and "ticket_bulk_batches"."job_expires_at" >= "ticket_bulk_batches"."lease_expires_at"
        and "ticket_bulk_batches"."state" in ('active','released','retry_scheduled','terminal')
        and "ticket_bulk_batches"."processed" between 0 and 100)
);
--> statement-breakpoint
ALTER TABLE "ticket_bulk_batches" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_bulk_command_receipts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"kind" "ticket_aggregate_kind" NOT NULL,
	"action" text NOT NULL,
	"idempotency_key_digest" "bytea" NOT NULL,
	"request_fingerprint_digest" "bytea" NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "ticket_bulk_command_receipts_replay_key" UNIQUE("tenant_id","actor_user_id","owner_membership_id","kind","action","idempotency_key_digest"),
	CONSTRAINT "ticket_bulk_command_receipts_shape_check" CHECK ((uuid_extract_version("ticket_bulk_command_receipts"."id") = 7) is true
        and octet_length("ticket_bulk_command_receipts"."idempotency_key_digest") = 32
        and octet_length("ticket_bulk_command_receipts"."request_fingerprint_digest") = 32
        and jsonb_typeof("ticket_bulk_command_receipts"."result_snapshot") = 'object'
        and octet_length("ticket_bulk_command_receipts"."result_snapshot"::text) <= 1048576
        and "ticket_bulk_command_receipts"."expires_at" > "ticket_bulk_command_receipts"."created_at")
);
--> statement-breakpoint
ALTER TABLE "ticket_bulk_command_receipts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_bulk_jobs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"requester_user_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"kind" "ticket_aggregate_kind" NOT NULL,
	"selection_source" text NOT NULL,
	"mutation" jsonb NOT NULL,
	"target_set_digest" "bytea" NOT NULL,
	"query_digest" "bytea",
	"catalog_digest" "bytea",
	"saved_view_id" uuid,
	"saved_view_revision" bigint,
	"saved_view_digest" "bytea",
	"projection_version" bigint DEFAULT 1 NOT NULL,
	"maximum_attempts" smallint NOT NULL,
	"state" text NOT NULL,
	"revision" bigint NOT NULL,
	"total" integer NOT NULL,
	"succeeded" integer DEFAULT 0 NOT NULL,
	"no_change" integer DEFAULT 0 NOT NULL,
	"version_conflict" integer DEFAULT 0 NOT NULL,
	"not_found_or_hidden" integer DEFAULT 0 NOT NULL,
	"authorization_denied" integer DEFAULT 0 NOT NULL,
	"rejected" integer DEFAULT 0 NOT NULL,
	"cancelled" integer DEFAULT 0 NOT NULL,
	"authorization_revoked" integer DEFAULT 0 NOT NULL,
	"internal_failure" integer DEFAULT 0 NOT NULL,
	"requested_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	"available_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"active_batch" boolean DEFAULT false NOT NULL,
	"terminal_at" timestamp with time zone,
	CONSTRAINT "ticket_bulk_jobs_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_bulk_jobs_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_bulk_jobs"."id") = 7) is true),
	CONSTRAINT "ticket_bulk_jobs_definition_check" CHECK ("ticket_bulk_jobs"."selection_source" in ('explicit', 'query')
        and jsonb_typeof("ticket_bulk_jobs"."mutation") = 'object'
        and octet_length("ticket_bulk_jobs"."target_set_digest") = 32
        and "ticket_bulk_jobs"."projection_version" = 1
        and "ticket_bulk_jobs"."maximum_attempts" between 1 and 100
        and (("ticket_bulk_jobs"."selection_source" = 'explicit'
              and "ticket_bulk_jobs"."query_digest" is null
              and "ticket_bulk_jobs"."catalog_digest" is null
              and "ticket_bulk_jobs"."saved_view_id" is null
              and "ticket_bulk_jobs"."saved_view_revision" is null
              and "ticket_bulk_jobs"."saved_view_digest" is null)
          or ("ticket_bulk_jobs"."selection_source" = 'query'
              and octet_length("ticket_bulk_jobs"."query_digest") = 32
              and octet_length("ticket_bulk_jobs"."catalog_digest") = 32
              and (("ticket_bulk_jobs"."saved_view_id" is null
                    and "ticket_bulk_jobs"."saved_view_revision" is null
                    and "ticket_bulk_jobs"."saved_view_digest" is null)
                or ("ticket_bulk_jobs"."saved_view_id" is not null
                    and "ticket_bulk_jobs"."saved_view_revision" between 1 and 9007199254740991
                    and octet_length("ticket_bulk_jobs"."saved_view_digest") = 32))))),
	CONSTRAINT "ticket_bulk_jobs_state_check" CHECK ("ticket_bulk_jobs"."state" in ('pending','running','cancellation_requested','completed','failed','cancelled','authorization_revoked')
        and "ticket_bulk_jobs"."revision" between 1 and 9007199254740991
        and "ticket_bulk_jobs"."total" between 1 and 100000
        and "ticket_bulk_jobs"."succeeded" >= 0 and "ticket_bulk_jobs"."no_change" >= 0
        and "ticket_bulk_jobs"."version_conflict" >= 0 and "ticket_bulk_jobs"."not_found_or_hidden" >= 0
        and "ticket_bulk_jobs"."authorization_denied" >= 0 and "ticket_bulk_jobs"."rejected" >= 0
        and "ticket_bulk_jobs"."cancelled" >= 0 and "ticket_bulk_jobs"."authorization_revoked" >= 0
        and "ticket_bulk_jobs"."internal_failure" >= 0
        and ("ticket_bulk_jobs"."succeeded" + "ticket_bulk_jobs"."no_change" + "ticket_bulk_jobs"."version_conflict"
          + "ticket_bulk_jobs"."not_found_or_hidden" + "ticket_bulk_jobs"."authorization_denied"
          + "ticket_bulk_jobs"."rejected" + "ticket_bulk_jobs"."cancelled"
          + "ticket_bulk_jobs"."authorization_revoked" + "ticket_bulk_jobs"."internal_failure") <= "ticket_bulk_jobs"."total"
        and "ticket_bulk_jobs"."updated_at" >= "ticket_bulk_jobs"."requested_at"
        and "ticket_bulk_jobs"."available_at" >= "ticket_bulk_jobs"."requested_at"
        and "ticket_bulk_jobs"."expires_at" > "ticket_bulk_jobs"."requested_at"
        and ("ticket_bulk_jobs"."terminal_at" is null) = ("ticket_bulk_jobs"."state" not in ('completed','failed','cancelled','authorization_revoked')))
);
--> statement-breakpoint
ALTER TABLE "ticket_bulk_jobs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_bulk_query_snapshots" (
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"source" text NOT NULL,
	"spec_canonical" text COLLATE "C" NOT NULL,
	"query_digest" "bytea" NOT NULL,
	"catalog_digest" "bytea" NOT NULL,
	"saved_view_id" uuid,
	"saved_view_owner_id" uuid,
	"saved_view_revision" bigint,
	"saved_view_digest" "bytea",
	CONSTRAINT "ticket_bulk_query_snapshots_pkey" PRIMARY KEY("job_id"),
	CONSTRAINT "ticket_bulk_query_snapshots_shape_check" CHECK ("ticket_bulk_query_snapshots"."source" in ('inline','saved_view')
        and octet_length("ticket_bulk_query_snapshots"."spec_canonical") between 1 and 262144
        and octet_length("ticket_bulk_query_snapshots"."query_digest") = 32
        and octet_length("ticket_bulk_query_snapshots"."catalog_digest") = 32
        and (("ticket_bulk_query_snapshots"."source" = 'inline'
              and "ticket_bulk_query_snapshots"."saved_view_id" is null
              and "ticket_bulk_query_snapshots"."saved_view_owner_id" is null
              and "ticket_bulk_query_snapshots"."saved_view_revision" is null
              and "ticket_bulk_query_snapshots"."saved_view_digest" is null)
          or ("ticket_bulk_query_snapshots"."source" = 'saved_view'
              and "ticket_bulk_query_snapshots"."saved_view_id" is not null
              and "ticket_bulk_query_snapshots"."saved_view_owner_id" is not null
              and "ticket_bulk_query_snapshots"."saved_view_revision" between 1 and 9007199254740991
              and octet_length("ticket_bulk_query_snapshots"."saved_view_digest") = 32)))
);
--> statement-breakpoint
ALTER TABLE "ticket_bulk_query_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_bulk_targets" (
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"target_id" uuid NOT NULL,
	"target_version" bigint NOT NULL,
	"result" text,
	"recorded_at" timestamp with time zone,
	CONSTRAINT "ticket_bulk_targets_pkey" PRIMARY KEY("tenant_id","job_id","sequence"),
	CONSTRAINT "ticket_bulk_targets_job_target_key" UNIQUE("tenant_id","job_id","target_id"),
	CONSTRAINT "ticket_bulk_targets_shape_check" CHECK ("ticket_bulk_targets"."sequence" between 1 and 100000
        and "ticket_bulk_targets"."target_version" between 1 and 9007199254740991
        and ("ticket_bulk_targets"."result" is null) = ("ticket_bulk_targets"."recorded_at" is null)
        and ("ticket_bulk_targets"."result" is null or "ticket_bulk_targets"."result" in ('succeeded','no_change','version_conflict','not_found_or_hidden','authorization_denied','rejected','cancelled','authorization_revoked','internal_failure')))
);
--> statement-breakpoint
ALTER TABLE "ticket_bulk_targets" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_export_artifact_cleanups" (
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"artifact_id" uuid NOT NULL,
	"kind" "ticket_aggregate_kind" NOT NULL,
	"audience" text NOT NULL,
	"reason" text NOT NULL,
	"job_revision" bigint NOT NULL,
	"cleanup_revision" bigint NOT NULL,
	"cleanup_attempt" smallint NOT NULL,
	"state" text NOT NULL,
	"eligible_at" timestamp with time zone NOT NULL,
	"worker_id" uuid,
	"cleanup_fence" "bytea",
	"claimed_at" timestamp with time zone,
	"lease_expires_at" timestamp with time zone,
	"failure_code" text,
	"retry_at" timestamp with time zone,
	"completed_at" timestamp with time zone,
	"updated_at" timestamp with time zone NOT NULL,
	CONSTRAINT "ticket_export_artifact_cleanups_pkey" PRIMARY KEY("tenant_id","artifact_id"),
	CONSTRAINT "ticket_export_artifact_cleanups_shape_check" CHECK ("ticket_export_artifact_cleanups"."audience" in ('operator','customer')
        and "ticket_export_artifact_cleanups"."reason" in ('expired','orphaned')
        and "ticket_export_artifact_cleanups"."job_revision" between 1 and 9007199254740991
        and "ticket_export_artifact_cleanups"."cleanup_revision" between 1 and 9007199254740991
        and "ticket_export_artifact_cleanups"."cleanup_attempt" between 0 and 100
        and "ticket_export_artifact_cleanups"."state" in ('pending','leased','retry_scheduled','dead_lettered','completed')
        and (("ticket_export_artifact_cleanups"."state" = 'leased'
              and "ticket_export_artifact_cleanups"."worker_id" is not null
              and octet_length("ticket_export_artifact_cleanups"."cleanup_fence") = 32
              and "ticket_export_artifact_cleanups"."claimed_at" is not null
              and "ticket_export_artifact_cleanups"."lease_expires_at" > "ticket_export_artifact_cleanups"."claimed_at")
          or ("ticket_export_artifact_cleanups"."state" <> 'leased'
              and "ticket_export_artifact_cleanups"."worker_id" is null
              and "ticket_export_artifact_cleanups"."cleanup_fence" is null
              and "ticket_export_artifact_cleanups"."claimed_at" is null
              and "ticket_export_artifact_cleanups"."lease_expires_at" is null))
        and ("ticket_export_artifact_cleanups"."state" = 'completed') = ("ticket_export_artifact_cleanups"."completed_at" is not null)
        and ("ticket_export_artifact_cleanups"."state" = 'retry_scheduled') = ("ticket_export_artifact_cleanups"."retry_at" is not null)
        and "ticket_export_artifact_cleanups"."updated_at" >= "ticket_export_artifact_cleanups"."eligible_at")
);
--> statement-breakpoint
ALTER TABLE "ticket_export_artifact_cleanups" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_export_command_receipts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"kind" "ticket_aggregate_kind" NOT NULL,
	"audience" text NOT NULL,
	"action" text NOT NULL,
	"idempotency_key_digest" "bytea" NOT NULL,
	"request_fingerprint_digest" "bytea" NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "ticket_export_command_receipts_replay_key" UNIQUE("tenant_id","actor_user_id","owner_membership_id","kind","audience","action","idempotency_key_digest"),
	CONSTRAINT "ticket_export_command_receipts_shape_check" CHECK ((uuid_extract_version("ticket_export_command_receipts"."id") = 7) is true
        and "ticket_export_command_receipts"."audience" in ('operator','customer')
        and octet_length("ticket_export_command_receipts"."idempotency_key_digest") = 32
        and octet_length("ticket_export_command_receipts"."request_fingerprint_digest") = 32
        and jsonb_typeof("ticket_export_command_receipts"."result_snapshot") = 'object'
        and octet_length("ticket_export_command_receipts"."result_snapshot"::text) <= 1048576
        and "ticket_export_command_receipts"."expires_at" > "ticket_export_command_receipts"."created_at")
);
--> statement-breakpoint
ALTER TABLE "ticket_export_command_receipts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_export_jobs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"requester_user_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"customer_contact_id" uuid,
	"kind" "ticket_aggregate_kind" NOT NULL,
	"audience" text NOT NULL,
	"comment_scope" text NOT NULL,
	"query_source" text NOT NULL,
	"saved_view_id" uuid,
	"saved_view_owner_id" uuid,
	"saved_view_revision" bigint,
	"saved_view_digest" "bytea",
	"query_digest" "bytea" NOT NULL,
	"catalog_digest" "bytea" NOT NULL,
	"projection_version" bigint NOT NULL,
	"format" text NOT NULL,
	"maximum_rows" integer NOT NULL,
	"maximum_bytes" bigint NOT NULL,
	"maximum_attempts" smallint NOT NULL,
	"state" text NOT NULL,
	"revision" bigint NOT NULL,
	"attempts" smallint NOT NULL,
	"failure_code" text NOT NULL,
	"requested_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	"available_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"lease_worker_id" uuid,
	"lease_fence_digest" "bytea",
	"lease_claimed_at" timestamp with time zone,
	"lease_expires_at" timestamp with time zone,
	"artifact_id" uuid,
	"artifact_digest" "bytea",
	"artifact_rows" integer,
	"artifact_bytes" bigint,
	"artifact_expires_at" timestamp with time zone,
	"terminal_at" timestamp with time zone,
	CONSTRAINT "ticket_export_jobs_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "ticket_export_jobs_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_export_jobs"."id") = 7) is true),
	CONSTRAINT "ticket_export_jobs_definition_check" CHECK ("ticket_export_jobs"."audience" in ('operator','customer')
        and "ticket_export_jobs"."comment_scope" in ('none','public','public_and_private')
        and ("ticket_export_jobs"."audience" = 'operator' or "ticket_export_jobs"."comment_scope" <> 'public_and_private')
        and "ticket_export_jobs"."query_source" in ('inline','saved_view')
        and (("ticket_export_jobs"."query_source" = 'inline'
              and "ticket_export_jobs"."saved_view_id" is null
              and "ticket_export_jobs"."saved_view_owner_id" is null
              and "ticket_export_jobs"."saved_view_revision" is null
              and "ticket_export_jobs"."saved_view_digest" is null)
          or ("ticket_export_jobs"."query_source" = 'saved_view'
              and "ticket_export_jobs"."saved_view_id" is not null
              and "ticket_export_jobs"."saved_view_owner_id" is not null
              and "ticket_export_jobs"."saved_view_revision" between 1 and 9007199254740991
              and octet_length("ticket_export_jobs"."saved_view_digest") = 32))
        and octet_length("ticket_export_jobs"."query_digest") = 32
        and octet_length("ticket_export_jobs"."catalog_digest") = 32
        and "ticket_export_jobs"."projection_version" = 1
        and "ticket_export_jobs"."format" = 'csv'
        and "ticket_export_jobs"."maximum_rows" between 1 and 1000000
        and "ticket_export_jobs"."maximum_bytes" between 1 and 1073741824
        and "ticket_export_jobs"."maximum_attempts" between 1 and 100),
	CONSTRAINT "ticket_export_jobs_state_check" CHECK ("ticket_export_jobs"."state" in ('pending','running','cancellation_requested','succeeded','failed','cancelled')
        and "ticket_export_jobs"."revision" between 1 and 9007199254740991
        and "ticket_export_jobs"."attempts" between 0 and "ticket_export_jobs"."maximum_attempts"
        and "ticket_export_jobs"."failure_code" in ('none','transient_storage','transient_database','authorization_revoked','snapshot_stale','output_limit','lease_expired','expired','internal')
        and "ticket_export_jobs"."updated_at" >= "ticket_export_jobs"."requested_at"
        and "ticket_export_jobs"."available_at" >= "ticket_export_jobs"."requested_at"
        and "ticket_export_jobs"."expires_at" > "ticket_export_jobs"."requested_at"
        and (("ticket_export_jobs"."lease_worker_id" is null and "ticket_export_jobs"."lease_fence_digest" is null
              and "ticket_export_jobs"."lease_claimed_at" is null and "ticket_export_jobs"."lease_expires_at" is null)
          or ("ticket_export_jobs"."lease_worker_id" is not null
              and octet_length("ticket_export_jobs"."lease_fence_digest") = 32
              and "ticket_export_jobs"."lease_expires_at" > "ticket_export_jobs"."lease_claimed_at"))
        and (("ticket_export_jobs"."artifact_id" is null and "ticket_export_jobs"."artifact_digest" is null
              and "ticket_export_jobs"."artifact_rows" is null and "ticket_export_jobs"."artifact_bytes" is null
              and "ticket_export_jobs"."artifact_expires_at" is null)
          or ("ticket_export_jobs"."artifact_id" is not null
              and octet_length("ticket_export_jobs"."artifact_digest") = 32
              and "ticket_export_jobs"."artifact_rows" >= 0 and "ticket_export_jobs"."artifact_bytes" > 0
              and "ticket_export_jobs"."artifact_expires_at" > "ticket_export_jobs"."requested_at"))
        and ("ticket_export_jobs"."terminal_at" is null) = ("ticket_export_jobs"."state" not in ('succeeded','failed','cancelled')))
);
--> statement-breakpoint
ALTER TABLE "ticket_export_jobs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_export_manifests" (
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"artifact_id" uuid NOT NULL,
	"job_revision" bigint NOT NULL,
	"attempt" smallint NOT NULL,
	"projection_version" bigint NOT NULL,
	"digest" "bytea" NOT NULL,
	"rows" integer NOT NULL,
	"bytes" bigint NOT NULL,
	"recorded_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"published_at" timestamp with time zone,
	CONSTRAINT "ticket_export_manifests_pkey" PRIMARY KEY("tenant_id","job_id","artifact_id"),
	CONSTRAINT "ticket_export_manifests_artifact_id_key" UNIQUE("artifact_id"),
	CONSTRAINT "ticket_export_manifests_job_attempt_key" UNIQUE("tenant_id","job_id","attempt"),
	CONSTRAINT "ticket_export_manifests_shape_check" CHECK ((uuid_extract_version("ticket_export_manifests"."artifact_id") = 7) is true
        and "ticket_export_manifests"."job_revision" between 1 and 9007199254740991
        and "ticket_export_manifests"."attempt" between 1 and 100
        and "ticket_export_manifests"."projection_version" = 1
        and octet_length("ticket_export_manifests"."digest") = 32
        and "ticket_export_manifests"."rows" >= 0 and "ticket_export_manifests"."bytes" > 0
        and "ticket_export_manifests"."expires_at" > "ticket_export_manifests"."recorded_at"
        and ("ticket_export_manifests"."published_at" is null or "ticket_export_manifests"."published_at" >= "ticket_export_manifests"."recorded_at"))
);
--> statement-breakpoint
ALTER TABLE "ticket_export_manifests" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_export_query_snapshots" (
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"spec_canonical" text COLLATE "C" NOT NULL,
	"query_digest" "bytea" NOT NULL,
	"catalog_digest" "bytea" NOT NULL,
	CONSTRAINT "ticket_export_query_snapshots_pkey" PRIMARY KEY("job_id"),
	CONSTRAINT "ticket_export_query_snapshots_shape_check" CHECK (octet_length("ticket_export_query_snapshots"."spec_canonical") between 1 and 262144
        and octet_length("ticket_export_query_snapshots"."query_digest") = 32
        and octet_length("ticket_export_query_snapshots"."catalog_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "ticket_export_query_snapshots" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "ticket_runtime_service_principals" (
	"id" uuid PRIMARY KEY NOT NULL,
	"key" text NOT NULL,
	"enabled" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "ticket_runtime_service_principals_key_key" UNIQUE("key"),
	CONSTRAINT "ticket_runtime_service_principals_id_uuidv7_check" CHECK ((uuid_extract_version("ticket_runtime_service_principals"."id") = 7) is true),
	CONSTRAINT "ticket_runtime_service_principals_key_check" CHECK ("ticket_runtime_service_principals"."key" = 'ticket_runtime')
);
--> statement-breakpoint
ALTER TABLE "ticket_bulk_batches" ADD CONSTRAINT "ticket_bulk_batches_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."ticket_bulk_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_bulk_command_receipts" ADD CONSTRAINT "ticket_bulk_command_receipts_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."ticket_bulk_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_bulk_jobs" ADD CONSTRAINT "ticket_bulk_jobs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_bulk_jobs" ADD CONSTRAINT "ticket_bulk_jobs_owner_fk" FOREIGN KEY ("tenant_id","owner_membership_id","requester_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_bulk_query_snapshots" ADD CONSTRAINT "ticket_bulk_query_snapshots_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."ticket_bulk_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_bulk_targets" ADD CONSTRAINT "ticket_bulk_targets_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."ticket_bulk_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_export_artifact_cleanups" ADD CONSTRAINT "ticket_export_artifact_cleanups_manifest_fk" FOREIGN KEY ("tenant_id","job_id","artifact_id") REFERENCES "public"."ticket_export_manifests"("tenant_id","job_id","artifact_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_export_command_receipts" ADD CONSTRAINT "ticket_export_command_receipts_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."ticket_export_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_export_jobs" ADD CONSTRAINT "ticket_export_jobs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "ticket_export_jobs" ADD CONSTRAINT "ticket_export_jobs_owner_fk" FOREIGN KEY ("tenant_id","owner_membership_id","requester_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_export_manifests" ADD CONSTRAINT "ticket_export_manifests_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."ticket_export_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "ticket_export_query_snapshots" ADD CONSTRAINT "ticket_export_query_snapshots_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."ticket_export_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "ticket_bulk_batches_lease_idx" ON "ticket_bulk_batches" USING btree ("tenant_id","kind","state","lease_expires_at","id");--> statement-breakpoint
CREATE INDEX "ticket_bulk_command_receipts_expiry_idx" ON "ticket_bulk_command_receipts" USING btree ("expires_at","tenant_id","id");--> statement-breakpoint
CREATE INDEX "ticket_bulk_jobs_claim_idx" ON "ticket_bulk_jobs" USING btree ("tenant_id","kind","state","available_at","id");--> statement-breakpoint
CREATE INDEX "ticket_bulk_jobs_owner_idx" ON "ticket_bulk_jobs" USING btree ("tenant_id","owner_membership_id","requested_at","id");--> statement-breakpoint
CREATE INDEX "ticket_bulk_targets_pending_idx" ON "ticket_bulk_targets" USING btree ("tenant_id","job_id","result","sequence");--> statement-breakpoint
CREATE INDEX "ticket_export_artifact_cleanups_queue_idx" ON "ticket_export_artifact_cleanups" USING btree ("tenant_id","kind","audience","state","eligible_at","artifact_id");--> statement-breakpoint
CREATE INDEX "ticket_export_artifact_cleanups_lease_idx" ON "ticket_export_artifact_cleanups" USING btree ("state","lease_expires_at","artifact_id");--> statement-breakpoint
CREATE INDEX "ticket_export_command_receipts_expiry_idx" ON "ticket_export_command_receipts" USING btree ("expires_at","tenant_id","id");--> statement-breakpoint
CREATE INDEX "ticket_export_jobs_claim_idx" ON "ticket_export_jobs" USING btree ("tenant_id","kind","audience","state","available_at","id");--> statement-breakpoint
CREATE INDEX "ticket_export_jobs_owner_idx" ON "ticket_export_jobs" USING btree ("tenant_id","owner_membership_id","requested_at","id");--> statement-breakpoint
CREATE INDEX "ticket_export_manifests_expiry_idx" ON "ticket_export_manifests" USING btree ("tenant_id","expires_at","artifact_id");--> statement-breakpoint
CREATE POLICY "ticket_bulk_batches_owner_access" ON "ticket_bulk_batches" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_bulk_command_receipts_owner_access" ON "ticket_bulk_command_receipts" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_bulk_jobs_owner_access" ON "ticket_bulk_jobs" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_bulk_query_snapshots_owner_access" ON "ticket_bulk_query_snapshots" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_bulk_targets_owner_access" ON "ticket_bulk_targets" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_export_artifact_cleanups_owner_access" ON "ticket_export_artifact_cleanups" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_export_command_receipts_owner_access" ON "ticket_export_command_receipts" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_export_jobs_owner_access" ON "ticket_export_jobs" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_export_manifests_owner_access" ON "ticket_export_manifests" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);--> statement-breakpoint
CREATE POLICY "ticket_export_query_snapshots_owner_access" ON "ticket_export_query_snapshots" AS PERMISSIVE FOR ALL TO "periapsis_ticket_runtime_owner" USING (true) WITH CHECK (true);
--> statement-breakpoint

-- The runtime owner is an inert capability principal. Closed entry points are
-- owned by the migration role; API and worker roles never inherit this owner.
ALTER ROLE periapsis_ticket_runtime_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;
ALTER ROLE periapsis_ticket_runtime_owner
  SET search_path = pg_catalog, app, public;
REVOKE periapsis_ticket_runtime_owner
FROM periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

ALTER TABLE public.ticket_bulk_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_bulk_query_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_bulk_targets FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_bulk_batches FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_bulk_command_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_export_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_export_query_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_export_manifests FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_export_command_receipts FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_export_artifact_cleanups FORCE ROW LEVEL SECURITY;
--> statement-breakpoint

ALTER TABLE public.ticket_runtime_service_principals OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_bulk_jobs OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_bulk_query_snapshots OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_bulk_targets OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_bulk_batches OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_bulk_command_receipts OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_export_jobs OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_export_query_snapshots OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_export_manifests OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_export_command_receipts OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_export_artifact_cleanups OWNER TO periapsis_ticket_runtime_owner;
--> statement-breakpoint

REVOKE ALL ON TABLE public.ticket_runtime_service_principals,
  public.ticket_bulk_jobs,
  public.ticket_bulk_query_snapshots,
  public.ticket_bulk_targets,
  public.ticket_bulk_batches,
  public.ticket_bulk_command_receipts,
  public.ticket_export_jobs,
  public.ticket_export_query_snapshots,
  public.ticket_export_manifests,
  public.ticket_export_command_receipts,
  public.ticket_export_artifact_cleanups
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
GRANT ALL ON TABLE public.ticket_runtime_service_principals,
  public.ticket_bulk_jobs,
  public.ticket_bulk_query_snapshots,
  public.ticket_bulk_targets,
  public.ticket_bulk_batches,
  public.ticket_bulk_command_receipts,
  public.ticket_export_jobs,
  public.ticket_export_query_snapshots,
  public.ticket_export_manifests,
  public.ticket_export_command_receipts,
  public.ticket_export_artifact_cleanups
TO periapsis_migrator;
GRANT USAGE ON SCHEMA app, public TO periapsis_ticket_runtime_owner;
--> statement-breakpoint

INSERT INTO public.ticket_runtime_service_principals(
  id, key, enabled, created_at
) VALUES (
  '01890f00-0000-7000-8000-0000000000f1'::uuid,
  'ticket_runtime', true, transaction_timestamp()
)
ON CONFLICT (key) DO NOTHING;
DO $ticket_runtime_principal_contract$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM public.ticket_runtime_service_principals AS principal
    WHERE principal.id = '01890f00-0000-7000-8000-0000000000f1'::uuid
      AND principal.key = 'ticket_runtime'
      AND principal.enabled
  ) OR (SELECT count(*) FROM public.ticket_runtime_service_principals) <> 1 THEN
    RAISE EXCEPTION 'ticket runtime service principal catalog is poisoned'
      USING ERRCODE = '55000';
  END IF;
END
$ticket_runtime_principal_contract$;
--> statement-breakpoint

CREATE FUNCTION app.guard_ticket_runtime_rows_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF current_setting('app.ticket_runtime_write_v1', true) IS DISTINCT FROM 'enabled' THEN
    RAISE EXCEPTION 'ticket runtime table mutation requires the closed ABI'
      USING ERRCODE = '42501';
  END IF;
  IF TG_ARGV[0] = 'immutable' AND TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'ticket runtime ledger rows are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_ARGV[0] = 'publish_once' AND TG_OP = 'UPDATE' AND NOT (
       (to_jsonb(NEW) - 'published_at') = (to_jsonb(OLD) - 'published_at')
       AND to_jsonb(OLD) -> 'published_at' = 'null'::jsonb
       AND to_jsonb(NEW) -> 'published_at' <> 'null'::jsonb
     ) THEN
    RAISE EXCEPTION 'ticket export manifest may only be published once'
      USING ERRCODE = '55000';
  ELSIF TG_ARGV[0] = 'publish_once' AND TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'ticket runtime ledger rows are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$function$;
ALTER FUNCTION app.guard_ticket_runtime_rows_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_ticket_runtime_rows_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE TRIGGER ticket_bulk_jobs_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_bulk_jobs
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('mutable');
CREATE TRIGGER ticket_bulk_query_snapshots_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_bulk_query_snapshots
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_bulk_targets_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_bulk_targets
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('mutable');
CREATE TRIGGER ticket_bulk_batches_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_bulk_batches
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('mutable');
CREATE TRIGGER ticket_bulk_command_receipts_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_bulk_command_receipts
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_export_jobs_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_export_jobs
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('mutable');
CREATE TRIGGER ticket_export_query_snapshots_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_export_query_snapshots
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_export_manifests_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_export_manifests
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('publish_once');
CREATE TRIGGER ticket_export_command_receipts_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_export_command_receipts
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('immutable');
CREATE TRIGGER ticket_export_artifact_cleanups_write_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.ticket_export_artifact_cleanups
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_runtime_rows_v1('mutable');
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_exact_keys_v1(
  p_document jsonb, p_keys text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT p_document IS NOT NULL
    AND jsonb_typeof(p_document) = 'object'
    AND (SELECT count(*) FROM jsonb_object_keys(p_document)) = cardinality(p_keys)
    AND NOT EXISTS (
      SELECT 1 FROM jsonb_object_keys(p_document) AS actual(key)
      WHERE NOT actual.key = ANY(p_keys)
    );
$function$;
ALTER FUNCTION app.private_ticket_runtime_exact_keys_v1(jsonb, text[])
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_exact_keys_v1(jsonb, text[])
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_uuid_v1(
  p_value text, p_empty_allowed boolean DEFAULT false
)
RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE result uuid;
BEGIN
  IF p_empty_allowed AND p_value = '' THEN RETURN NULL; END IF;
  IF p_value IS NULL OR p_value !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'ticket runtime UUID is invalid' USING ERRCODE = '22023';
  END IF;
  result := p_value::uuid;
  IF result::text IS DISTINCT FROM p_value THEN
    RAISE EXCEPTION 'ticket runtime UUID is not canonical' USING ERRCODE = '22023';
  END IF;
  RETURN result;
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_uuid_v1(text, boolean)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_uuid_v1(text, boolean)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_digest_v1(p_value text)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
BEGIN
  IF p_value IS NULL OR p_value !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'ticket runtime digest is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN decode(p_value, 'hex');
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_digest_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_digest_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_instant_v1(p_value jsonb)
RETURNS timestamp with time zone
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE result timestamp with time zone;
BEGIN
  IF jsonb_typeof(p_value) <> 'string'
     OR p_value #>> '{}' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?(Z|[+]00:00)$' THEN
    RAISE EXCEPTION 'ticket runtime instant is invalid' USING ERRCODE = '22023';
  END IF;
  BEGIN result := (p_value #>> '{}')::timestamp with time zone;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'ticket runtime instant is invalid' USING ERRCODE = '22023';
  END;
  IF result < '1970-01-01 00:00:00+00'::timestamp with time zone
     OR result >= '10000-01-01 00:00:00+00'::timestamp with time zone
     OR date_trunc('microseconds', result) IS DISTINCT FROM result THEN
    RAISE EXCEPTION 'ticket runtime instant is out of range' USING ERRCODE = '22023';
  END IF;
  RETURN result;
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_instant_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_instant_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_require_human_v1(
  p_actor jsonb, p_tenant_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  session_id uuid;
  active_tenant_id uuid;
  method text;
  live_method text;
  membership_id uuid;
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_actor, ARRAY['userId','sessionId','activeTenantId','authenticationMethod']
     )
     OR jsonb_typeof(p_actor -> 'userId') <> 'string'
     OR jsonb_typeof(p_actor -> 'sessionId') <> 'string'
     OR jsonb_typeof(p_actor -> 'activeTenantId') <> 'string'
     OR jsonb_typeof(p_actor -> 'authenticationMethod') <> 'string' THEN
    RAISE EXCEPTION 'ticket runtime actor is invalid' USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_ticket_runtime_uuid_v1(p_actor ->> 'userId');
  session_id := app.private_ticket_runtime_uuid_v1(p_actor ->> 'sessionId');
  active_tenant_id := app.private_ticket_runtime_uuid_v1(p_actor ->> 'activeTenantId');
  method := p_actor ->> 'authenticationMethod';
  IF p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR active_tenant_id IS DISTINCT FROM p_tenant_id
     OR actor_id IS DISTINCT FROM app.context_user_id()
     OR method !~ '^[a-z][a-z0-9_.-]{0,63}$' THEN
    RAISE EXCEPTION 'ticket runtime actor authority is unavailable' USING ERRCODE = '42501';
  END IF;
  live_method := app.require_live_audit_session_v1(session_id, p_tenant_id);
  membership_id := app.current_tenant_membership_id();
  IF live_method IS DISTINCT FROM method OR membership_id IS NULL THEN
    RAISE EXCEPTION 'ticket runtime actor authority is unavailable' USING ERRCODE = '42501';
  END IF;
  PERFORM 1
  FROM ONLY public.tenants AS tenant
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = tenant.id
  WHERE tenant.id = p_tenant_id
    AND tenant.status = 'active'
    AND membership.id = membership_id
    AND membership.user_id = actor_id
    AND membership.status = 'active'
  FOR SHARE OF tenant, membership;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket runtime actor authority is unavailable' USING ERRCODE = '42501';
  END IF;
  RETURN membership_id;
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_require_human_v1(jsonb, uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_require_human_v1(jsonb, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_require_worker_v1(
  p_identity jsonb, p_purpose text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE service_account_id uuid; worker_id uuid;
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_identity, ARRAY['serviceAccountId','workerId','purpose']
     )
     OR jsonb_typeof(p_identity -> 'serviceAccountId') <> 'string'
     OR jsonb_typeof(p_identity -> 'workerId') <> 'string'
     OR jsonb_typeof(p_identity -> 'purpose') <> 'string'
     OR p_identity ->> 'purpose' IS DISTINCT FROM p_purpose
     OR p_purpose NOT IN ('ticket_runtime','ticket_bulk','ticket_export','ticket_export_reconcile') THEN
    RAISE EXCEPTION 'ticket runtime worker identity is invalid' USING ERRCODE = '42501';
  END IF;
  service_account_id := app.private_ticket_runtime_uuid_v1(
    p_identity ->> 'serviceAccountId'
  );
  worker_id := app.private_ticket_runtime_uuid_v1(p_identity ->> 'workerId');
  PERFORM 1
  FROM public.ticket_runtime_service_principals AS principal
  WHERE principal.id = service_account_id
    AND principal.key = 'ticket_runtime'
    AND principal.enabled
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket runtime worker identity is unavailable' USING ERRCODE = '42501';
  END IF;
  RETURN worker_id;
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_require_worker_v1(jsonb, text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_require_worker_v1(jsonb, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.lookup_ticket_runtime_service_principal_v1(p_key text)
RETURNS uuid
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT principal.id
  FROM public.ticket_runtime_service_principals AS principal
  WHERE p_key = 'ticket_runtime'
    AND principal.key = p_key
    AND principal.enabled;
$function$;
ALTER FUNCTION app.lookup_ticket_runtime_service_principal_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.lookup_ticket_runtime_service_principal_v1(text)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.lookup_ticket_runtime_service_principal_v1(text)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_bulk_progress_document_v1(
  p_job public.ticket_bulk_jobs
)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $function$
  SELECT jsonb_build_object(
    'total', p_job.total,
    'succeeded', p_job.succeeded,
    'noChange', p_job.no_change,
    'versionConflict', p_job.version_conflict,
    'notFoundOrHidden', p_job.not_found_or_hidden,
    'authorizationDenied', p_job.authorization_denied,
    'rejected', p_job.rejected,
    'cancelled', p_job.cancelled,
    'authorizationRevoked', p_job.authorization_revoked,
    'internalFailure', p_job.internal_failure
  );
$function$;
ALTER FUNCTION app.private_ticket_bulk_progress_document_v1(public.ticket_bulk_jobs)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_bulk_progress_document_v1(public.ticket_bulk_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_bulk_query_document_v1(
  p_job public.ticket_bulk_jobs
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE snapshot public.ticket_bulk_query_snapshots%ROWTYPE;
BEGIN
  IF p_job.selection_source = 'explicit' THEN RETURN 'null'::jsonb; END IF;
  SELECT query.* INTO STRICT snapshot
  FROM public.ticket_bulk_query_snapshots AS query
  WHERE query.tenant_id = p_job.tenant_id AND query.job_id = p_job.id;
  RETURN jsonb_build_object(
    'source', snapshot.source,
    'specCanonicalBase64', replace(encode(convert_to(snapshot.spec_canonical, 'UTF8'), 'base64'), E'\n', ''),
    'querySha256', encode(snapshot.query_digest, 'hex'),
    'catalogSha256', encode(snapshot.catalog_digest, 'hex'),
    'savedView', CASE WHEN snapshot.source = 'inline' THEN 'null'::jsonb ELSE
      jsonb_build_object(
        'id', snapshot.saved_view_id,
        'ownerId', snapshot.saved_view_owner_id,
        'revision', snapshot.saved_view_revision,
        'specSha256', encode(snapshot.saved_view_digest, 'hex')
      ) END
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_bulk_query_document_v1(public.ticket_bulk_jobs)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_bulk_query_document_v1(public.ticket_bulk_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_bulk_record_v1(p_job_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  job public.ticket_bulk_jobs%ROWTYPE;
  selection jsonb;
  query_document jsonb;
BEGIN
  SELECT candidate.* INTO STRICT job
  FROM public.ticket_bulk_jobs AS candidate WHERE candidate.id = p_job_id;
  query_document := app.private_ticket_bulk_query_document_v1(job);
  selection := jsonb_build_object(
    'source', job.selection_source,
    'explicitTargets', CASE WHEN job.selection_source = 'explicit' THEN (
      SELECT coalesce(jsonb_agg(jsonb_build_object(
        'id', target.target_id, 'version', target.target_version
      ) ORDER BY target.sequence), '[]'::jsonb)
      FROM public.ticket_bulk_targets AS target
      WHERE target.tenant_id = job.tenant_id AND target.job_id = job.id
    ) ELSE 'null'::jsonb END,
    'querySha256', CASE WHEN job.query_digest IS NULL THEN '' ELSE encode(job.query_digest, 'hex') END,
    'targetSetSha256', encode(job.target_set_digest, 'hex'),
    'targetCount', job.total,
    'savedView', CASE WHEN job.saved_view_id IS NULL THEN 'null'::jsonb ELSE
      jsonb_build_object(
        'id', job.saved_view_id,
        'ownerId', job.owner_membership_id,
        'revision', job.saved_view_revision,
        'specSha256', encode(job.saved_view_digest, 'hex')
      ) END
  );
  RETURN jsonb_build_object(
    'job', jsonb_build_object(
      'definition', jsonb_build_object(
        'id', job.id,
        'tenantId', job.tenant_id,
        'requesterId', job.requester_user_id,
        'ownerMembershipId', job.owner_membership_id,
        'kind', job.kind,
        'selection', selection,
        'mutation', job.mutation,
        'projectionVersion', job.projection_version,
        'maximumAttempts', job.maximum_attempts
      ),
      'state', job.state,
      'revision', job.revision,
      'progress', app.private_ticket_bulk_progress_document_v1(job),
      'requestedAt', job.requested_at,
      'updatedAt', job.updated_at,
      'availableAt', job.available_at,
      'expiresAt', job.expires_at,
      'activeBatch', job.active_batch,
      'terminalAt', CASE WHEN job.terminal_at IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(job.terminal_at) END
    ),
    'query', query_document
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_bulk_record_v1(uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_bulk_record_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_query_document_v1(
  p_job public.ticket_export_jobs
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE snapshot public.ticket_export_query_snapshots%ROWTYPE;
BEGIN
  SELECT query.* INTO STRICT snapshot
  FROM public.ticket_export_query_snapshots AS query
  WHERE query.tenant_id = p_job.tenant_id AND query.job_id = p_job.id;
  RETURN jsonb_build_object(
    'source', p_job.query_source,
    'specCanonicalBase64', replace(encode(convert_to(snapshot.spec_canonical, 'UTF8'), 'base64'), E'\n', ''),
    'querySha256', encode(snapshot.query_digest, 'hex'),
    'catalogSha256', encode(snapshot.catalog_digest, 'hex'),
    'savedView', CASE WHEN p_job.query_source = 'inline' THEN 'null'::jsonb ELSE
      jsonb_build_object(
        'id', p_job.saved_view_id,
        'ownerId', p_job.saved_view_owner_id,
        'revision', p_job.saved_view_revision,
        'specSha256', encode(p_job.saved_view_digest, 'hex')
      ) END
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_export_query_document_v1(public.ticket_export_jobs)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_query_document_v1(public.ticket_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_job_document_v1(
  p_job public.ticket_export_jobs
)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $function$
  SELECT jsonb_build_object(
    'definition', jsonb_build_object(
      'id', p_job.id,
      'tenantId', p_job.tenant_id,
      'requesterId', p_job.requester_user_id,
      'ownerMembershipId', p_job.owner_membership_id,
      'customerContactId', coalesce(p_job.customer_contact_id::text, ''),
      'kind', p_job.kind,
      'audience', p_job.audience,
      'commentScope', p_job.comment_scope,
      'querySource', p_job.query_source,
      'savedView', CASE WHEN p_job.saved_view_id IS NULL THEN 'null'::jsonb ELSE
        jsonb_build_object(
          'id', p_job.saved_view_id,
          'ownerId', p_job.saved_view_owner_id,
          'revision', p_job.saved_view_revision,
          'specSha256', encode(p_job.saved_view_digest, 'hex')
        ) END,
      'querySha256', encode(p_job.query_digest, 'hex'),
      'catalogSha256', encode(p_job.catalog_digest, 'hex'),
      'projectionVersion', p_job.projection_version,
      'format', p_job.format,
      'maximumRows', p_job.maximum_rows,
      'maximumBytes', p_job.maximum_bytes,
      'maximumAttempts', p_job.maximum_attempts
    ),
    'state', p_job.state,
    'revision', p_job.revision,
    'attempts', p_job.attempts,
    'failureCode', p_job.failure_code,
    'requestedAt', p_job.requested_at,
    'updatedAt', p_job.updated_at,
    'availableAt', p_job.available_at,
    'expiresAt', p_job.expires_at,
    'lease', CASE WHEN p_job.lease_worker_id IS NULL THEN 'null'::jsonb ELSE
      jsonb_build_object(
        'workerId', p_job.lease_worker_id,
        'fenceSha256', encode(p_job.lease_fence_digest, 'hex'),
        'claimedAt', p_job.lease_claimed_at,
        'expiresAt', p_job.lease_expires_at
      ) END,
    'artifact', CASE WHEN p_job.artifact_id IS NULL THEN 'null'::jsonb ELSE
      jsonb_build_object(
        'id', p_job.artifact_id,
        'sha256', encode(p_job.artifact_digest, 'hex'),
        'rows', p_job.artifact_rows,
        'bytes', p_job.artifact_bytes,
        'expiresAt', p_job.artifact_expires_at
      ) END,
    'terminalAt', CASE WHEN p_job.terminal_at IS NULL THEN 'null'::jsonb
      ELSE to_jsonb(p_job.terminal_at) END
  );
$function$;
ALTER FUNCTION app.private_ticket_export_job_document_v1(public.ticket_export_jobs)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_job_document_v1(public.ticket_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_record_v1(
  p_job_id uuid, p_include_query boolean DEFAULT true
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE job public.ticket_export_jobs%ROWTYPE;
BEGIN
  SELECT candidate.* INTO STRICT job
  FROM public.ticket_export_jobs AS candidate WHERE candidate.id = p_job_id;
  IF p_include_query THEN
    RETURN jsonb_build_object(
      'job', app.private_ticket_export_job_document_v1(job),
      'query', app.private_ticket_export_query_document_v1(job)
    );
  END IF;
  RETURN jsonb_build_object('job', app.private_ticket_export_job_document_v1(job));
END;
$function$;
ALTER FUNCTION app.private_ticket_export_record_v1(uuid, boolean)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_record_v1(uuid, boolean)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_catalog_digest_v1(p_spec text)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
  document jsonb;
  pins text;
  envelope text;
BEGIN
  IF p_spec IS NULL OR octet_length(p_spec) NOT BETWEEN 1 AND 262144 THEN
    RAISE EXCEPTION 'ticket runtime catalog specification is invalid'
      USING ERRCODE = '22023';
  END IF;
  BEGIN document := p_spec::jsonb;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'ticket runtime catalog specification is malformed'
      USING ERRCODE = '22023';
  END;
  WITH candidates AS (
    SELECT 'custom_field'::text AS source, item -> 'definition' AS definition
    FROM jsonb_array_elements(document #> '{filters,custom}') AS item
    UNION ALL
    SELECT item ->> 'source', item -> 'definition'
    FROM jsonb_array_elements(document -> 'columns') AS item
    WHERE item ->> 'source' IN ('custom_field','sla')
    UNION ALL
    SELECT document #>> '{sort,source}', document #> '{sort,definition}'
    WHERE document #>> '{sort,source}' IN ('custom_field','sla')
  ), normalized AS (
    SELECT DISTINCT ON (source, definition ->> 'id')
      source, definition
    FROM candidates
    WHERE jsonb_typeof(definition) = 'object'
    ORDER BY source COLLATE "C", definition ->> 'id' COLLATE "C"
  )
  SELECT coalesce(string_agg(
    '{"source":' || to_json(source)::text ||
    ',"id":' || to_json(definition ->> 'id')::text ||
    ',"tenant":' || to_json(definition ->> 'tenantId')::text ||
    ',"kind":' || to_json(definition ->> 'kind')::text ||
    ',"key":' || to_json(definition ->> 'key')::text ||
    ',"version":' || (definition ->> 'version') ||
    ',"digest":' || to_json(definition ->> 'digest')::text || '}',
    ',' ORDER BY source COLLATE "C", definition ->> 'id' COLLATE "C"
  ), '') INTO pins
  FROM normalized;
  envelope := '{"domain":"periapsis.ticketing.async-export.catalog.v1","pins":[' || pins || ']}';
  RETURN sha256(convert_to(envelope, 'UTF8'));
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_catalog_digest_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_catalog_digest_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_permission_v1(
  p_kind public.ticket_aggregate_kind, p_action text
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT CASE
    WHEN p_kind = 'alert' AND p_action IN ('assign','transfer') THEN 'alert.assign'
    WHEN p_kind = 'alert' AND p_action IN ('claim','release') THEN 'alert.claim'
    WHEN p_kind = 'alert' AND p_action = 'transition' THEN 'alert.update'
    WHEN p_kind = 'case' AND p_action IN ('assign','transfer') THEN 'case.transfer'
    WHEN p_kind = 'case' AND p_action IN ('claim','release') THEN 'case.claim'
    WHEN p_kind = 'case' AND p_action = 'transition' THEN 'case.transition'
    WHEN p_kind = 'alert' AND p_action = 'read' THEN 'alert.read'
    WHEN p_kind = 'case' AND p_action = 'read' THEN 'case.read'
    ELSE NULL
  END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_permission_v1(public.ticket_aggregate_kind, text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_permission_v1(public.ticket_aggregate_kind, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_has_any_scope_v1(p_permission text)
RETURNS boolean
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_permission IS NOT NULL AND (
    app.current_tenant_human_has_exact_permission_v3(p_permission, 'tenant')
    OR app.current_tenant_human_has_exact_permission_v3(p_permission, 'assigned')
    OR app.current_tenant_human_has_exact_permission_v3(p_permission, 'operator_team')
    OR app.current_tenant_human_has_exact_permission_v3(p_permission, 'own')
  );
$function$;
ALTER FUNCTION app.private_ticket_runtime_has_any_scope_v1(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_has_any_scope_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.resolve_ticket_bulk_access_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid;
  actor_id uuid;
  membership_id uuid;
  kind public.ticket_aggregate_kind;
  capability text;
  mutation_action text;
  permission_key text;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','actor','tenantId','kind','capability','mutationAction']
     )
     OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'actor') <> 'object'
     OR jsonb_typeof(request -> 'tenantId') <> 'string'
     OR jsonb_typeof(request -> 'kind') <> 'string'
     OR jsonb_typeof(request -> 'capability') <> 'string'
     OR jsonb_typeof(request -> 'mutationAction') <> 'string' THEN
    RAISE EXCEPTION 'ticket bulk access request is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  BEGIN kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk kind is invalid' USING ERRCODE = '22023';
  END;
  capability := request ->> 'capability';
  mutation_action := request ->> 'mutationAction';
  IF capability NOT IN ('ticket.bulk.request','ticket.bulk.read','ticket.bulk.cancel')
     OR (capability = 'ticket.bulk.request') IS DISTINCT FROM
        (mutation_action IN ('transition','assign','transfer','claim','release'))
     OR capability <> 'ticket.bulk.request' AND mutation_action <> '' THEN
    RAISE EXCEPTION 'ticket bulk capability is invalid' USING ERRCODE = '22023';
  END IF;
  membership_id := app.private_ticket_runtime_require_human_v1(
    request -> 'actor', tenant_id
  );
  actor_id := app.context_user_id();
  permission_key := app.private_ticket_runtime_permission_v1(
    kind, CASE WHEN capability = 'ticket.bulk.request' THEN mutation_action ELSE 'read' END
  );
  IF NOT app.private_ticket_runtime_has_any_scope_v1(permission_key) THEN
    RAISE EXCEPTION 'ticket bulk permission is required' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'tenantId', tenant_id,
    'actorId', actor_id,
    'membershipId', membership_id,
    'kind', kind,
    'capability', capability,
    'principal', 'operator',
    'mutationAction', mutation_action,
    'allowed', true
  );
END;
$function$;
ALTER FUNCTION app.resolve_ticket_bulk_access_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.resolve_ticket_bulk_access_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.resolve_ticket_bulk_access_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.resolve_ticket_bulk_query_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_id uuid;
  kind public.ticket_aggregate_kind;
  source jsonb;
  source_mode text;
  view_record public.ticket_saved_views%ROWTYPE;
  resolved jsonb;
  spec_base64 text;
  spec_canonical text;
  query_digest bytea;
  catalog_digest bytea;
  saved_view jsonb := 'null'::jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','actor','tenantId','kind','membershipId','source']
     )
     OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'source') <> 'object' THEN
    RAISE EXCEPTION 'ticket bulk query request is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  owner_id := app.private_ticket_runtime_uuid_v1(request ->> 'membershipId');
  BEGIN kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk kind is invalid' USING ERRCODE = '22023';
  END;
  IF app.private_ticket_runtime_require_human_v1(request -> 'actor', tenant_id)
       IS DISTINCT FROM owner_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(
       app.private_ticket_runtime_permission_v1(kind, 'read')
     ) THEN
    RAISE EXCEPTION 'ticket bulk query authority is required' USING ERRCODE = '42501';
  END IF;
  actor_id := app.context_user_id();
  source := request -> 'source';
  source_mode := source ->> 'mode';
  IF source_mode = 'inline' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(source, ARRAY['mode','spec'])
       OR jsonb_typeof(source -> 'spec') <> 'object' THEN
      RAISE EXCEPTION 'inline ticket bulk source is invalid' USING ERRCODE = '22023';
    END IF;
    resolved := app.private_resolve_ticket_saved_view_spec_v1(source -> 'spec');
    spec_base64 := resolved ->> 'specCanonicalBase64';
  ELSIF source_mode = 'saved_view' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(
         source, ARRAY['mode','id','revision','specSha256']
       ) OR source ->> 'revision' !~ '^[1-9][0-9]{0,15}$' THEN
      RAISE EXCEPTION 'saved ticket bulk source is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT view.* INTO view_record
    FROM public.ticket_saved_views AS view
    WHERE view.tenant_id = tenant_id
      AND view.id = app.private_ticket_runtime_uuid_v1(source ->> 'id')
      AND view.owner_membership_id = owner_id
      AND view.aggregate_kind = kind
      AND view.status = 'active'
      AND view.revision = (source ->> 'revision')::bigint
      AND view.spec_digest = app.private_ticket_runtime_digest_v1(source ->> 'specSha256')
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'saved ticket bulk source is unavailable' USING ERRCODE = 'P0002';
    END IF;
    spec_canonical := view_record.spec_canonical;
    PERFORM app.private_ticket_saved_view_spec_pins_current_v1(
      tenant_id, actor_id, owner_id, kind, spec_canonical
    );
    spec_base64 := replace(encode(convert_to(spec_canonical, 'UTF8'), 'base64'), E'\n', '');
    saved_view := jsonb_build_object(
      'id', view_record.id, 'ownerId', owner_id,
      'revision', view_record.revision,
      'specSha256', encode(view_record.spec_digest, 'hex')
    );
  ELSE
    RAISE EXCEPTION 'ticket bulk source mode is invalid' USING ERRCODE = '22023';
  END IF;
  IF spec_canonical IS NULL THEN
    BEGIN
      spec_canonical := convert_from(decode(spec_base64, 'base64'), 'UTF8');
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'ticket bulk canonical source is invalid' USING ERRCODE = '55000';
    END;
  END IF;
  query_digest := sha256(convert_to(spec_canonical, 'UTF8'));
  catalog_digest := app.private_ticket_runtime_catalog_digest_v1(spec_canonical);
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'query', jsonb_build_object(
      'source', source_mode,
      'specCanonicalBase64', spec_base64,
      'querySha256', encode(query_digest, 'hex'),
      'catalogSha256', encode(catalog_digest, 'hex'),
      'savedView', saved_view
    )
  );
END;
$function$;
ALTER FUNCTION app.resolve_ticket_bulk_query_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.resolve_ticket_bulk_query_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.resolve_ticket_bulk_query_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_bulk_target_set_digest_v1(
  p_tenant_id uuid, p_job_id uuid
)
RETURNS bytea
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target record;
  material bytea;
  target_count bigint;
BEGIN
  SELECT count(*) INTO target_count
  FROM public.ticket_bulk_targets AS item
  WHERE item.tenant_id = p_tenant_id AND item.job_id = p_job_id;
  material := int8send(target_count);
  FOR target IN
    SELECT item.target_id, item.target_version
    FROM public.ticket_bulk_targets AS item
    WHERE item.tenant_id = p_tenant_id AND item.job_id = p_job_id
    ORDER BY item.target_id
  LOOP
    material := material || uuid_send(target.target_id) || int8send(target.target_version);
  END LOOP;
  RETURN sha256(material);
END;
$function$;
ALTER FUNCTION app.private_ticket_bulk_target_set_digest_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_bulk_target_set_digest_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_bulk_validate_mutation_v1(p_mutation jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
DECLARE action text;
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_mutation, ARRAY['action','transition','to','teamId','assigneeId']
     )
     OR jsonb_typeof(p_mutation -> 'action') <> 'string'
     OR jsonb_typeof(p_mutation -> 'transition') <> 'string'
     OR jsonb_typeof(p_mutation -> 'to') <> 'string'
     OR jsonb_typeof(p_mutation -> 'teamId') <> 'string'
     OR jsonb_typeof(p_mutation -> 'assigneeId') <> 'string' THEN
    RAISE EXCEPTION 'ticket bulk mutation is invalid' USING ERRCODE = '22023';
  END IF;
  action := p_mutation ->> 'action';
  IF action = 'transition' THEN
    IF p_mutation ->> 'transition' !~ '^[a-z][a-z0-9_.-]{0,63}$'
       OR p_mutation ->> 'to' !~ '^[a-z][a-z0-9_.-]{0,63}$'
       OR p_mutation ->> 'teamId' <> '' OR p_mutation ->> 'assigneeId' <> '' THEN
      RAISE EXCEPTION 'ticket bulk transition is invalid' USING ERRCODE = '22023';
    END IF;
  ELSIF action IN ('assign','transfer') THEN
    PERFORM app.private_ticket_runtime_uuid_v1(p_mutation ->> 'teamId');
    PERFORM app.private_ticket_runtime_uuid_v1(p_mutation ->> 'assigneeId', true);
    IF p_mutation ->> 'transition' <> '' OR p_mutation ->> 'to' <> '' THEN
      RAISE EXCEPTION 'ticket bulk assignment is invalid' USING ERRCODE = '22023';
    END IF;
  ELSIF action = 'claim' THEN
    PERFORM app.private_ticket_runtime_uuid_v1(p_mutation ->> 'teamId');
    IF p_mutation ->> 'transition' <> '' OR p_mutation ->> 'to' <> ''
       OR p_mutation ->> 'assigneeId' <> '' THEN
      RAISE EXCEPTION 'ticket bulk claim is invalid' USING ERRCODE = '22023';
    END IF;
  ELSIF action = 'release' THEN
    IF p_mutation ->> 'transition' <> '' OR p_mutation ->> 'to' <> ''
       OR p_mutation ->> 'teamId' <> '' OR p_mutation ->> 'assigneeId' <> '' THEN
      RAISE EXCEPTION 'ticket bulk release is invalid' USING ERRCODE = '22023';
    END IF;
  ELSE
    RAISE EXCEPTION 'ticket bulk mutation action is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN action;
END;
$function$;
ALTER FUNCTION app.private_ticket_bulk_validate_mutation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_bulk_validate_mutation_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_audit_is_valid_v1(p_audit jsonb)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, app
AS $function$
DECLARE ignored inet;
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_audit, ARRAY['requestId','correlationId','remoteAddress','userAgent']
     )
     OR jsonb_typeof(p_audit -> 'requestId') <> 'string'
     OR jsonb_typeof(p_audit -> 'correlationId') <> 'string'
     OR jsonb_typeof(p_audit -> 'remoteAddress') <> 'string'
     OR jsonb_typeof(p_audit -> 'userAgent') <> 'string'
     OR p_audit ->> 'requestId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR p_audit ->> 'correlationId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
     OR octet_length(p_audit ->> 'userAgent') > 1024
     OR p_audit ->> 'userAgent' ~ '[\u0000]' THEN
    RETURN false;
  END IF;
  BEGIN ignored := (p_audit ->> 'remoteAddress')::inet;
  EXCEPTION WHEN OTHERS THEN RETURN false;
  END;
  RETURN true;
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_audit_is_valid_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_audit_is_valid_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_bulk_materialize_query_v1(
  p_tenant_id uuid,
  p_job_id uuid,
  p_kind public.ticket_aggregate_kind,
  p_permission text,
  p_spec text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  document jsonb := p_spec::jsonb;
  filters jsonb;
  actor_id uuid := app.context_user_id();
  inserted integer;
  candidate_count integer;
BEGIN
  filters := document -> 'filters';
  IF jsonb_typeof(filters) <> 'object'
     OR jsonb_typeof(filters -> 'states') <> 'array'
     OR jsonb_typeof(filters -> 'severities') <> 'array'
     OR jsonb_typeof(filters -> 'priorities') <> 'array'
     OR jsonb_typeof(filters -> 'custom') <> 'array'
     OR filters ->> 'queue' NOT IN ('all','assigned_to_me','my_operator_teams','unassigned') THEN
    RAISE EXCEPTION 'ticket bulk canonical filters are invalid' USING ERRCODE = '22023';
  END IF;
  IF p_kind = 'alert' THEN
    SELECT count(*)::integer INTO candidate_count
    FROM (
      SELECT alert.id
      FROM public.alerts AS alert
      WHERE alert.tenant_id = p_tenant_id
        AND alert.deleted_at IS NULL
        AND app.private_current_ticket_scope_allows_v1(
          p_permission, alert.assigned_team_id, alert.created_by,
          alert.assignee_user_id, alert.claimed_by_user_id
        )
        AND (jsonb_array_length(filters -> 'states') = 0 OR alert.state_key IN (
          SELECT value FROM jsonb_array_elements_text(filters -> 'states') AS value
        ))
        AND (jsonb_array_length(filters -> 'severities') = 0 OR alert.severity::text IN (
          SELECT value FROM jsonb_array_elements_text(filters -> 'severities') AS value
        ))
        AND (jsonb_array_length(filters -> 'priorities') = 0 OR alert.priority IN (
          SELECT value FROM jsonb_array_elements_text(filters -> 'priorities') AS value
        ))
        AND (NOT filters ? 'assignedTeamId' OR alert.assigned_team_id = (filters ->> 'assignedTeamId')::uuid)
        AND (NOT filters ? 'assigneeUserId' OR alert.assignee_user_id = (filters ->> 'assigneeUserId')::uuid)
        AND (NOT filters ? 'claimedBy' OR alert.claimed_by_user_id = (filters ->> 'claimedBy')::uuid)
        AND (NOT filters ? 'customerVisible' OR alert.customer_visible = (filters ->> 'customerVisible')::boolean)
        AND (NOT filters ? 'search' OR to_tsvector('simple', coalesce(alert.number,'') || ' ' || coalesce(alert.title,'') || ' ' || coalesce(alert.description,''))
          @@ plainto_tsquery('simple', filters ->> 'search'))
        AND CASE filters ->> 'queue'
          WHEN 'all' THEN true
          WHEN 'assigned_to_me' THEN alert.assignee_user_id = actor_id
          WHEN 'unassigned' THEN alert.assigned_team_id IS NULL
          WHEN 'my_operator_teams' THEN alert.assigned_team_id IS NOT NULL
            AND app.current_tenant_has_live_operator_team_relationship(
              alert.assigned_team_id, alert.assigned_team_epoch_id
            )
        END
        AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(filters -> 'custom') AS filter(value)
          WHERE NOT EXISTS (
            SELECT 1 FROM public.custom_field_values AS field
            WHERE field.tenant_id = p_tenant_id
              AND field.object_type = 'alert'
              AND field.alert_id = alert.id
              AND field.definition_id = (filter.value #>> '{definition,id}')::uuid
              AND field.definition_schema_version = (filter.value #>> '{definition,version}')::bigint
              AND field.canonical_value = filter.value -> 'value'
          )
        )
      ORDER BY alert.id LIMIT 100001
    ) AS candidates;
    IF candidate_count > 100000 THEN
      RAISE EXCEPTION 'ticket bulk query target limit is exceeded' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.ticket_bulk_targets(
      tenant_id, job_id, sequence, target_id, target_version
    )
    SELECT p_tenant_id, p_job_id,
      row_number() OVER (ORDER BY alert.id)::integer,
      alert.id, alert.version
    FROM public.alerts AS alert
    WHERE alert.tenant_id = p_tenant_id
      AND alert.deleted_at IS NULL
      AND app.private_current_ticket_scope_allows_v1(
        p_permission, alert.assigned_team_id, alert.created_by,
        alert.assignee_user_id, alert.claimed_by_user_id
      )
      AND (jsonb_array_length(filters -> 'states') = 0 OR alert.state_key IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'states') AS value
      ))
      AND (jsonb_array_length(filters -> 'severities') = 0 OR alert.severity::text IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'severities') AS value
      ))
      AND (jsonb_array_length(filters -> 'priorities') = 0 OR alert.priority IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'priorities') AS value
      ))
      AND (NOT filters ? 'assignedTeamId' OR alert.assigned_team_id = (filters ->> 'assignedTeamId')::uuid)
      AND (NOT filters ? 'assigneeUserId' OR alert.assignee_user_id = (filters ->> 'assigneeUserId')::uuid)
      AND (NOT filters ? 'claimedBy' OR alert.claimed_by_user_id = (filters ->> 'claimedBy')::uuid)
      AND (NOT filters ? 'customerVisible' OR alert.customer_visible = (filters ->> 'customerVisible')::boolean)
      AND (NOT filters ? 'search' OR to_tsvector('simple', coalesce(alert.number,'') || ' ' || coalesce(alert.title,'') || ' ' || coalesce(alert.description,''))
        @@ plainto_tsquery('simple', filters ->> 'search'))
      AND CASE filters ->> 'queue'
        WHEN 'all' THEN true
        WHEN 'assigned_to_me' THEN alert.assignee_user_id = actor_id
        WHEN 'unassigned' THEN alert.assigned_team_id IS NULL
        WHEN 'my_operator_teams' THEN alert.assigned_team_id IS NOT NULL
          AND app.current_tenant_has_live_operator_team_relationship(
            alert.assigned_team_id, alert.assigned_team_epoch_id
          )
      END
      AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(filters -> 'custom') AS filter(value)
        WHERE NOT EXISTS (
          SELECT 1 FROM public.custom_field_values AS field
          WHERE field.tenant_id = p_tenant_id AND field.object_type = 'alert'
            AND field.alert_id = alert.id
            AND field.definition_id = (filter.value #>> '{definition,id}')::uuid
            AND field.definition_schema_version = (filter.value #>> '{definition,version}')::bigint
            AND field.canonical_value = filter.value -> 'value'
        )
      )
    ORDER BY alert.id;
  ELSE
    SELECT count(*)::integer INTO candidate_count
    FROM (
      SELECT case_row.id
      FROM public.cases AS case_row
      WHERE case_row.tenant_id = p_tenant_id
        AND app.private_current_ticket_scope_allows_v1(
          p_permission, case_row.assigned_team_id, case_row.created_by_user_id,
          case_row.assignee_user_id, case_row.claimed_by_user_id
        )
        AND (jsonb_array_length(filters -> 'states') = 0 OR case_row.state_key IN (
          SELECT value FROM jsonb_array_elements_text(filters -> 'states') AS value
        ))
        AND (jsonb_array_length(filters -> 'severities') = 0 OR case_row.severity::text IN (
          SELECT value FROM jsonb_array_elements_text(filters -> 'severities') AS value
        ))
        AND (jsonb_array_length(filters -> 'priorities') = 0 OR case_row.priority IN (
          SELECT value FROM jsonb_array_elements_text(filters -> 'priorities') AS value
        ))
        AND (NOT filters ? 'assignedTeamId' OR case_row.assigned_team_id = (filters ->> 'assignedTeamId')::uuid)
        AND (NOT filters ? 'assigneeUserId' OR case_row.assignee_user_id = (filters ->> 'assigneeUserId')::uuid)
        AND (NOT filters ? 'claimedBy' OR case_row.claimed_by_user_id = (filters ->> 'claimedBy')::uuid)
        AND (NOT filters ? 'customerVisible' OR case_row.customer_visible = (filters ->> 'customerVisible')::boolean)
        AND (NOT filters ? 'search' OR to_tsvector('simple', coalesce(case_row.number,'') || ' ' || coalesce(case_row.title,'') || ' ' || coalesce(case_row.description,''))
          @@ plainto_tsquery('simple', filters ->> 'search'))
        AND CASE filters ->> 'queue'
          WHEN 'all' THEN true
          WHEN 'assigned_to_me' THEN case_row.assignee_user_id = actor_id
          WHEN 'unassigned' THEN case_row.assigned_team_id IS NULL
          WHEN 'my_operator_teams' THEN case_row.assigned_team_id IS NOT NULL
            AND app.current_tenant_has_live_operator_team_relationship(
              case_row.assigned_team_id, case_row.assigned_team_epoch_id
            )
        END
        AND NOT EXISTS (
          SELECT 1 FROM jsonb_array_elements(filters -> 'custom') AS filter(value)
          WHERE NOT EXISTS (
            SELECT 1 FROM public.custom_field_values AS field
            WHERE field.tenant_id = p_tenant_id AND field.object_type = 'case'
              AND field.case_id = case_row.id
              AND field.definition_id = (filter.value #>> '{definition,id}')::uuid
              AND field.definition_schema_version = (filter.value #>> '{definition,version}')::bigint
              AND field.canonical_value = filter.value -> 'value'
          )
        )
      ORDER BY case_row.id LIMIT 100001
    ) AS candidates;
    IF candidate_count > 100000 THEN
      RAISE EXCEPTION 'ticket bulk query target limit is exceeded' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.ticket_bulk_targets(
      tenant_id, job_id, sequence, target_id, target_version
    )
    SELECT p_tenant_id, p_job_id,
      row_number() OVER (ORDER BY case_row.id)::integer,
      case_row.id, case_row.version
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = p_tenant_id
      AND app.private_current_ticket_scope_allows_v1(
        p_permission, case_row.assigned_team_id, case_row.created_by_user_id,
        case_row.assignee_user_id, case_row.claimed_by_user_id
      )
      AND (jsonb_array_length(filters -> 'states') = 0 OR case_row.state_key IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'states') AS value
      ))
      AND (jsonb_array_length(filters -> 'severities') = 0 OR case_row.severity::text IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'severities') AS value
      ))
      AND (jsonb_array_length(filters -> 'priorities') = 0 OR case_row.priority IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'priorities') AS value
      ))
      AND (NOT filters ? 'assignedTeamId' OR case_row.assigned_team_id = (filters ->> 'assignedTeamId')::uuid)
      AND (NOT filters ? 'assigneeUserId' OR case_row.assignee_user_id = (filters ->> 'assigneeUserId')::uuid)
      AND (NOT filters ? 'claimedBy' OR case_row.claimed_by_user_id = (filters ->> 'claimedBy')::uuid)
      AND (NOT filters ? 'customerVisible' OR case_row.customer_visible = (filters ->> 'customerVisible')::boolean)
      AND (NOT filters ? 'search' OR to_tsvector('simple', coalesce(case_row.number,'') || ' ' || coalesce(case_row.title,'') || ' ' || coalesce(case_row.description,''))
        @@ plainto_tsquery('simple', filters ->> 'search'))
      AND CASE filters ->> 'queue'
        WHEN 'all' THEN true
        WHEN 'assigned_to_me' THEN case_row.assignee_user_id = actor_id
        WHEN 'unassigned' THEN case_row.assigned_team_id IS NULL
        WHEN 'my_operator_teams' THEN case_row.assigned_team_id IS NOT NULL
          AND app.current_tenant_has_live_operator_team_relationship(
            case_row.assigned_team_id, case_row.assigned_team_epoch_id
          )
      END
      AND NOT EXISTS (
        SELECT 1 FROM jsonb_array_elements(filters -> 'custom') AS filter(value)
        WHERE NOT EXISTS (
          SELECT 1 FROM public.custom_field_values AS field
          WHERE field.tenant_id = p_tenant_id AND field.object_type = 'case'
            AND field.case_id = case_row.id
            AND field.definition_id = (filter.value #>> '{definition,id}')::uuid
            AND field.definition_schema_version = (filter.value #>> '{definition,version}')::bigint
            AND field.canonical_value = filter.value -> 'value'
        )
      )
    ORDER BY case_row.id;
  END IF;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  IF inserted = 0 THEN
    RAISE EXCEPTION 'ticket bulk query has no authorized targets' USING ERRCODE = '22023';
  END IF;
  RETURN inserted;
END;
$function$;
ALTER FUNCTION app.private_ticket_bulk_materialize_query_v1(uuid, uuid, public.ticket_aggregate_kind, text, text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_bulk_materialize_query_v1(uuid, uuid, public.ticket_aggregate_kind, text, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.lookup_ticket_bulk_replay_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_id uuid;
  kind public.ticket_aggregate_kind;
  key_digest bytea;
  receipt public.ticket_bulk_command_receipts%ROWTYPE;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','tenantId','actorId','ownerMembershipId','kind','action','idempotencyKeySha256']
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'action' NOT IN ('request','cancel') THEN
    RAISE EXCEPTION 'ticket bulk replay request is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  actor_id := app.private_ticket_runtime_uuid_v1(request ->> 'actorId');
  owner_id := app.private_ticket_runtime_uuid_v1(request ->> 'ownerMembershipId');
  BEGIN kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk replay kind is invalid' USING ERRCODE = '22023';
  END;
  key_digest := app.private_ticket_runtime_digest_v1(request ->> 'idempotencyKeySha256');
  IF tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR actor_id IS DISTINCT FROM app.context_user_id()
     OR owner_id IS DISTINCT FROM app.current_tenant_membership_id() THEN
    RAISE EXCEPTION 'ticket bulk replay authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT candidate.* INTO receipt
  FROM public.ticket_bulk_command_receipts AS candidate
  WHERE candidate.tenant_id = tenant_id
    AND candidate.actor_user_id = actor_id
    AND candidate.owner_membership_id = owner_id
    AND candidate.kind = kind
    AND candidate.action = request ->> 'action'
    AND candidate.idempotency_key_digest = key_digest;
  IF NOT FOUND THEN RETURN; END IF;
  IF NOT app.private_ticket_runtime_has_any_scope_v1(
    app.private_ticket_runtime_permission_v1(kind, 'read')
  ) THEN
    RAISE EXCEPTION 'ticket bulk replay authority is required' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT jsonb_set(
    receipt.result_snapshot, '{replayed}', 'true'::jsonb, false
  );
END;
$function$;
ALTER FUNCTION app.lookup_ticket_bulk_replay_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.lookup_ticket_bulk_replay_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.lookup_ticket_bulk_replay_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_js_uint_v1(
  p_value jsonb, p_min bigint, p_max bigint
)
RETURNS bigint
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE result bigint;
BEGIN
  IF jsonb_typeof(p_value) <> 'number'
     OR p_value::text !~ '^(0|[1-9][0-9]*)$' THEN
    RAISE EXCEPTION 'ticket runtime integer is invalid' USING ERRCODE = '22023';
  END IF;
  BEGIN result := (p_value::text)::bigint;
  EXCEPTION WHEN numeric_value_out_of_range THEN
    RAISE EXCEPTION 'ticket runtime integer is out of range' USING ERRCODE = '22023';
  END;
  IF result < p_min OR result > p_max OR p_max > 9007199254740991 THEN
    RAISE EXCEPTION 'ticket runtime integer is out of range' USING ERRCODE = '22023';
  END IF;
  RETURN result;
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_js_uint_v1(jsonb, bigint, bigint)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_js_uint_v1(jsonb, bigint, bigint)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_reconciliation_seed_v1(
  p_tenant_id uuid,
  p_kind public.ticket_aggregate_kind,
  p_audience text,
  p_now timestamp with time zone
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE inserted integer;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_kind NOT IN ('alert','case')
     OR p_audience NOT IN ('operator','customer')
     OR p_now IS NULL THEN
    RAISE EXCEPTION 'ticket export reconciliation queue is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  INSERT INTO public.ticket_export_artifact_cleanups(
    tenant_id, job_id, artifact_id, kind, audience, reason,
    job_revision, cleanup_revision, cleanup_attempt, state,
    eligible_at, updated_at
  )
  SELECT manifest.tenant_id, manifest.job_id, manifest.artifact_id,
    job.kind, job.audience,
    CASE WHEN manifest.published_at IS NOT NULL THEN 'expired' ELSE 'orphaned' END,
    job.revision, 1, 0, 'pending',
    CASE
      WHEN manifest.published_at IS NOT NULL THEN manifest.expires_at
      WHEN job.terminal_at IS NOT NULL THEN greatest(manifest.recorded_at, job.terminal_at)
      WHEN job.lease_expires_at IS NOT NULL THEN greatest(manifest.recorded_at, job.lease_expires_at)
      ELSE greatest(manifest.recorded_at, job.expires_at)
    END,
    p_now
  FROM public.ticket_export_manifests AS manifest
  JOIN public.ticket_export_jobs AS job
    ON job.tenant_id = manifest.tenant_id AND job.id = manifest.job_id
  WHERE manifest.tenant_id = p_tenant_id
    AND job.kind = p_kind
    AND job.audience = p_audience
    AND (
      manifest.published_at IS NOT NULL AND manifest.expires_at <= p_now
      OR manifest.published_at IS NULL AND (
        job.state IN ('succeeded','failed','cancelled')
        OR job.lease_expires_at <= p_now
        OR job.expires_at <= p_now
      )
    )
  ON CONFLICT (tenant_id, artifact_id) DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  RETURN inserted;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_reconciliation_seed_v1(
  uuid, public.ticket_aggregate_kind, text, timestamp with time zone
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_reconciliation_seed_v1(
  uuid, public.ticket_aggregate_kind, text, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_reconciliation_claim_v1(
  p_claim jsonb
)
RETURNS TABLE(
  tenant_id uuid,
  job_id uuid,
  artifact_id uuid,
  kind public.ticket_aggregate_kind,
  audience text,
  object_revision bigint,
  object_attempt smallint,
  projection_version bigint,
  artifact_digest bytea,
  artifact_rows integer,
  artifact_bytes bigint,
  reason text,
  job_revision bigint,
  cleanup_revision bigint,
  cleanup_attempt smallint,
  cleanup_fence bytea,
  eligible_at timestamp with time zone,
  claimed_at timestamp with time zone,
  lease_expires_at timestamp with time zone
)
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
DECLARE artifact jsonb;
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_claim, ARRAY[
         'artifact','reason','jobRevision','cleanupRevision','cleanupAttempt',
         'cleanupFenceSha256','eligibleAt','claimedAt','leaseExpiresAt'
       ]
     ) OR jsonb_typeof(p_claim -> 'artifact') <> 'object'
     OR jsonb_typeof(p_claim -> 'reason') <> 'string'
     OR jsonb_typeof(p_claim -> 'cleanupFenceSha256') <> 'string' THEN
    RAISE EXCEPTION 'ticket export reconciliation claim is invalid'
      USING ERRCODE = '22023';
  END IF;
  artifact := p_claim -> 'artifact';
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       artifact, ARRAY[
         'tenantId','jobId','artifactId','kind','audience','objectRevision',
         'objectAttempt','projectionVersion','sha256','rows','bytes'
       ]
     ) OR jsonb_typeof(artifact -> 'kind') <> 'string'
     OR jsonb_typeof(artifact -> 'audience') <> 'string'
     OR p_claim ->> 'reason' NOT IN ('expired','orphaned')
     OR artifact ->> 'kind' NOT IN ('alert','case')
     OR artifact ->> 'audience' NOT IN ('operator','customer') THEN
    RAISE EXCEPTION 'ticket export reconciliation claim is invalid'
      USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_runtime_uuid_v1(artifact ->> 'tenantId');
  job_id := app.private_ticket_runtime_uuid_v1(artifact ->> 'jobId');
  artifact_id := app.private_ticket_runtime_uuid_v1(artifact ->> 'artifactId');
  kind := (artifact ->> 'kind')::public.ticket_aggregate_kind;
  audience := artifact ->> 'audience';
  object_revision := app.private_ticket_runtime_js_uint_v1(
    artifact -> 'objectRevision', 1, 2147483647
  );
  object_attempt := app.private_ticket_runtime_js_uint_v1(
    artifact -> 'objectAttempt', 1, 5
  )::smallint;
  projection_version := app.private_ticket_runtime_js_uint_v1(
    artifact -> 'projectionVersion', 1, 1
  );
  artifact_digest := app.private_ticket_runtime_digest_v1(artifact ->> 'sha256');
  artifact_rows := app.private_ticket_runtime_js_uint_v1(
    artifact -> 'rows', 0, 1000000
  )::integer;
  artifact_bytes := app.private_ticket_runtime_js_uint_v1(
    artifact -> 'bytes', 1, 1073741824
  );
  reason := p_claim ->> 'reason';
  job_revision := app.private_ticket_runtime_js_uint_v1(
    p_claim -> 'jobRevision', 1, 9007199254740991
  );
  cleanup_revision := app.private_ticket_runtime_js_uint_v1(
    p_claim -> 'cleanupRevision', 2, 9007199254740990
  );
  cleanup_attempt := app.private_ticket_runtime_js_uint_v1(
    p_claim -> 'cleanupAttempt', 1, 100
  )::smallint;
  cleanup_fence := app.private_ticket_runtime_digest_v1(
    p_claim ->> 'cleanupFenceSha256'
  );
  eligible_at := app.private_ticket_runtime_instant_v1(p_claim -> 'eligibleAt');
  claimed_at := app.private_ticket_runtime_instant_v1(p_claim -> 'claimedAt');
  lease_expires_at := app.private_ticket_runtime_instant_v1(
    p_claim -> 'leaseExpiresAt'
  );
  IF claimed_at < eligible_at
     OR lease_expires_at - claimed_at < interval '30 seconds'
     OR lease_expires_at - claimed_at > interval '15 minutes' THEN
    RAISE EXCEPTION 'ticket export reconciliation claim is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEXT;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_reconciliation_claim_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_reconciliation_claim_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_reconciliation_claim_document_v1(
  p_cleanup public.ticket_export_artifact_cleanups,
  p_manifest public.ticket_export_manifests
)
RETURNS jsonb
LANGUAGE sql
STABLE
SET search_path = pg_catalog, public
AS $function$
  SELECT jsonb_build_object(
    'artifact', jsonb_build_object(
      'tenantId', p_cleanup.tenant_id,
      'jobId', p_cleanup.job_id,
      'artifactId', p_cleanup.artifact_id,
      'kind', p_cleanup.kind,
      'audience', p_cleanup.audience,
      'objectRevision', p_manifest.job_revision,
      'objectAttempt', p_manifest.attempt,
      'projectionVersion', p_manifest.projection_version,
      'sha256', encode(p_manifest.digest, 'hex'),
      'rows', p_manifest.rows,
      'bytes', p_manifest.bytes
    ),
    'reason', p_cleanup.reason,
    'jobRevision', p_cleanup.job_revision,
    'cleanupRevision', p_cleanup.cleanup_revision,
    'cleanupAttempt', p_cleanup.cleanup_attempt,
    'cleanupFenceSha256', encode(p_cleanup.cleanup_fence, 'hex'),
    'eligibleAt', p_cleanup.eligible_at,
    'claimedAt', p_cleanup.claimed_at,
    'leaseExpiresAt', p_cleanup.lease_expires_at
  );
$function$;
ALTER FUNCTION app.private_ticket_export_reconciliation_claim_document_v1(
  public.ticket_export_artifact_cleanups,
  public.ticket_export_manifests
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_reconciliation_claim_document_v1(
  public.ticket_export_artifact_cleanups,
  public.ticket_export_manifests
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.claim_ticket_export_artifact_reconciliation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  queue_tenant_id uuid;
  queue_kind public.ticket_aggregate_kind;
  queue_audience text;
  claimed_worker_id uuid;
  observed_at timestamp with time zone;
  lease_microseconds bigint;
  item_limit integer;
  claims jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 32768
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','tenantId','kind','audience','now',
         'leaseMicroseconds','limit'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'kind') <> 'string'
     OR jsonb_typeof(request -> 'audience') <> 'string'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer') THEN
    RAISE EXCEPTION 'ticket export reconciliation claim request is invalid'
      USING ERRCODE = '22023';
  END IF;
  claimed_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export_reconcile'
  );
  queue_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  queue_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  queue_audience := request ->> 'audience';
  PERFORM set_config('app.tenant_id', queue_tenant_id::text, true);
  observed_at := app.private_ticket_runtime_instant_v1(request -> 'now');
  lease_microseconds := app.private_ticket_runtime_js_uint_v1(
    request -> 'leaseMicroseconds', 30000000, 900000000
  );
  item_limit := app.private_ticket_runtime_js_uint_v1(
    request -> 'limit', 1, 100
  )::integer;
  IF queue_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR observed_at < transaction_timestamp() - interval '5 minutes'
     OR observed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket export reconciliation queue authority is unavailable'
      USING ERRCODE = '42501';
  END IF;
  PERFORM app.private_ticket_export_reconciliation_seed_v1(
    queue_tenant_id, queue_kind, queue_audience, observed_at
  );
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  WITH candidates AS MATERIALIZED (
    SELECT cleanup.tenant_id, cleanup.artifact_id
    FROM public.ticket_export_artifact_cleanups AS cleanup
    WHERE cleanup.tenant_id = queue_tenant_id
      AND cleanup.kind = queue_kind
      AND cleanup.audience = queue_audience
      AND cleanup.cleanup_attempt < 100
      AND (
        cleanup.state = 'pending' AND cleanup.eligible_at <= observed_at
        OR cleanup.state = 'retry_scheduled' AND cleanup.retry_at <= observed_at
        OR cleanup.state = 'leased' AND cleanup.lease_expires_at <= observed_at
      )
    ORDER BY cleanup.eligible_at, cleanup.artifact_id
    FOR UPDATE SKIP LOCKED
    LIMIT item_limit
  ), leased AS (
    UPDATE public.ticket_export_artifact_cleanups AS cleanup
    SET state = 'leased',
        cleanup_revision = cleanup.cleanup_revision + 1,
        cleanup_attempt = cleanup.cleanup_attempt + 1,
        worker_id = claimed_worker_id,
        cleanup_fence = sha256(convert_to(
          uuidv7()::text || ':' || clock_timestamp()::text || ':'
          || claimed_worker_id::text, 'UTF8'
        )),
        claimed_at = observed_at,
        lease_expires_at = observed_at
          + make_interval(secs => lease_microseconds::double precision / 1000000.0),
        failure_code = NULL,
        retry_at = NULL,
        completed_at = NULL,
        updated_at = observed_at
    FROM candidates
    WHERE cleanup.tenant_id = candidates.tenant_id
      AND cleanup.artifact_id = candidates.artifact_id
    RETURNING cleanup.*
  )
  SELECT coalesce(jsonb_agg(
    app.private_ticket_export_reconciliation_claim_document_v1(leased, manifest)
    ORDER BY leased.eligible_at, leased.artifact_id
  ), '[]'::jsonb)
  INTO claims
  FROM leased
  JOIN public.ticket_export_manifests AS manifest
    ON manifest.tenant_id = leased.tenant_id
   AND manifest.job_id = leased.job_id
   AND manifest.artifact_id = leased.artifact_id;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'claims', claims
  );
END;
$function$;
ALTER FUNCTION app.claim_ticket_export_artifact_reconciliation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.claim_ticket_export_artifact_reconciliation_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.claim_ticket_export_artifact_reconciliation_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_reconciliation_result_v1(
  p_disposition text,
  p_cleanup_revision bigint,
  p_artifact_id uuid,
  p_reason text,
  p_fence bytea,
  p_code text DEFAULT '',
  p_retry_at timestamp with time zone DEFAULT NULL
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT jsonb_build_object(
    'schemaVersion', 1,
    'disposition', p_disposition,
    'currentCleanupRevision', p_cleanup_revision,
    'artifactId', coalesce(p_artifact_id::text, ''),
    'reason', coalesce(p_reason, ''),
    'cleanupFenceSha256', CASE WHEN p_fence IS NULL THEN '' ELSE encode(p_fence, 'hex') END,
    'code', coalesce(p_code, ''),
    'retryAt', CASE WHEN p_retry_at IS NULL THEN 'null'::jsonb ELSE to_jsonb(p_retry_at) END
  );
$function$;
ALTER FUNCTION app.private_ticket_export_reconciliation_result_v1(
  text, bigint, uuid, text, bytea, text, timestamp with time zone
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_reconciliation_result_v1(
  text, bigint, uuid, text, bytea, text, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.finalize_ticket_export_artifact_reconciliation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  worker_id uuid;
  purged_at timestamp with time zone;
  cleanup public.ticket_export_artifact_cleanups%ROWTYPE;
  receipt public.audit_events%ROWTYPE;
  proof text;
  next_revision bigint;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','claim','purgedAt']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'claim') <> 'object' THEN
    RAISE EXCEPTION 'ticket export reconciliation finalize request is invalid'
      USING ERRCODE = '22023';
  END IF;
  worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export_reconcile'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_export_reconciliation_claim_v1(request -> 'claim') AS parsed;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  purged_at := app.private_ticket_runtime_instant_v1(request -> 'purgedAt');
  IF binding.tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR purged_at < binding.claimed_at
     OR purged_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket export reconciliation finalize authority is unavailable'
      USING ERRCODE = '42501';
  END IF;
  proof := encode(sha256(binding.cleanup_fence), 'hex');
  SELECT event.* INTO receipt
  FROM public.audit_events AS event
  WHERE event.tenant_id = binding.tenant_id
    AND event.resource_type = 'ticket_export_artifact_cleanup'
    AND event.resource_id = binding.artifact_id
    AND event.action = 'tenant.ticket_export.artifact_reconciliation.finalized'
    AND event.metadata ->> 'fenceProofSha256' = proof
  ORDER BY event.sequence DESC LIMIT 1;
  IF FOUND THEN
    IF (receipt.metadata ->> 'inputCleanupRevision')::bigint IS DISTINCT FROM binding.cleanup_revision
       OR (receipt.metadata ->> 'inputCleanupAttempt')::smallint IS DISTINCT FROM binding.cleanup_attempt
       OR receipt.metadata ->> 'reason' IS DISTINCT FROM binding.reason THEN
      RAISE EXCEPTION 'ticket export reconciliation replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT app.private_ticket_export_reconciliation_result_v1(
      'replayed', (receipt.metadata ->> 'resultCleanupRevision')::bigint,
      binding.artifact_id, binding.reason, binding.cleanup_fence
    );
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.audit_events AS event
    WHERE event.tenant_id = binding.tenant_id
      AND event.resource_type = 'ticket_export_artifact_cleanup'
      AND event.resource_id = binding.artifact_id
      AND event.metadata ->> 'fenceProofSha256' = proof
  ) THEN
    RAISE EXCEPTION 'ticket export reconciliation replay payload mismatch'
      USING ERRCODE = '23505';
  END IF;
  SELECT candidate.* INTO cleanup
  FROM public.ticket_export_artifact_cleanups AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.artifact_id = binding.artifact_id
  FOR UPDATE;
  IF NOT FOUND
     OR cleanup.job_id IS DISTINCT FROM binding.job_id
     OR cleanup.kind IS DISTINCT FROM binding.kind
     OR cleanup.audience IS DISTINCT FROM binding.audience
     OR cleanup.reason IS DISTINCT FROM binding.reason
     OR cleanup.job_revision IS DISTINCT FROM binding.job_revision
     OR cleanup.cleanup_revision IS DISTINCT FROM binding.cleanup_revision
     OR cleanup.cleanup_attempt IS DISTINCT FROM binding.cleanup_attempt
     OR cleanup.state IS DISTINCT FROM 'leased'
     OR cleanup.worker_id IS DISTINCT FROM worker_id
     OR cleanup.cleanup_fence IS DISTINCT FROM binding.cleanup_fence
     OR cleanup.eligible_at IS DISTINCT FROM binding.eligible_at
     OR cleanup.claimed_at IS DISTINCT FROM binding.claimed_at
     OR cleanup.lease_expires_at IS DISTINCT FROM binding.lease_expires_at
     OR NOT EXISTS (
       SELECT 1 FROM public.ticket_export_manifests AS manifest
       WHERE manifest.tenant_id = binding.tenant_id
         AND manifest.job_id = binding.job_id
         AND manifest.artifact_id = binding.artifact_id
         AND manifest.job_revision = binding.object_revision
         AND manifest.attempt = binding.object_attempt
         AND manifest.projection_version = binding.projection_version
         AND manifest.digest = binding.artifact_digest
         AND manifest.rows = binding.artifact_rows
         AND manifest.bytes = binding.artifact_bytes
     ) THEN
    RETURN QUERY SELECT app.private_ticket_export_reconciliation_result_v1(
      'fence_lost', 0, NULL, NULL, NULL
    );
    RETURN;
  END IF;
  IF cleanup.cleanup_revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'ticket export reconciliation revision is exhausted'
      USING ERRCODE = '54000';
  END IF;
  next_revision := cleanup.cleanup_revision + 1;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_export_artifact_cleanups
  SET cleanup_revision = next_revision,
      state = 'completed', worker_id = NULL, cleanup_fence = NULL,
      claimed_at = NULL, lease_expires_at = NULL, failure_code = NULL,
      retry_at = NULL, completed_at = purged_at, updated_at = purged_at
  WHERE tenant_id = binding.tenant_id AND artifact_id = binding.artifact_id;
  IF binding.reason = 'orphaned' THEN
    UPDATE public.ticket_export_jobs AS job
    SET state = CASE WHEN job.state = 'cancellation_requested' THEN 'cancelled' ELSE 'failed' END,
        revision = job.revision + 1,
        failure_code = CASE WHEN job.state = 'cancellation_requested' THEN 'none' ELSE 'internal' END,
        updated_at = least(purged_at, job.expires_at),
        available_at = least(purged_at, job.expires_at),
        lease_worker_id = NULL, lease_fence_digest = NULL,
        lease_claimed_at = NULL, lease_expires_at = NULL,
        artifact_id = NULL, artifact_digest = NULL, artifact_rows = NULL,
        artifact_bytes = NULL, artifact_expires_at = NULL,
        terminal_at = least(purged_at, job.expires_at)
    WHERE job.tenant_id = binding.tenant_id AND job.id = binding.job_id
      AND job.revision = binding.job_revision
      AND job.state IN ('running','cancellation_requested')
      AND job.revision < 9007199254740991;
  END IF;
  INSERT INTO public.audit_events(
    tenant_id, sequence, occurred_at, actor_type, action,
    resource_type, resource_id, authentication_method, outcome, metadata
  ) VALUES (
    binding.tenant_id, 0, purged_at, 'system',
    'tenant.ticket_export.artifact_reconciliation.finalized',
    'ticket_export_artifact_cleanup', binding.artifact_id,
    'system', 'success', jsonb_build_object(
      'jobId', binding.job_id,
      'reason', binding.reason,
      'inputCleanupRevision', binding.cleanup_revision,
      'inputCleanupAttempt', binding.cleanup_attempt,
      'resultCleanupRevision', next_revision,
      'fenceProofSha256', proof,
      'contentRedacted', true
    )
  );
  RETURN QUERY SELECT app.private_ticket_export_reconciliation_result_v1(
    'applied', next_revision, binding.artifact_id,
    binding.reason, binding.cleanup_fence
  );
END;
$function$;
ALTER FUNCTION app.finalize_ticket_export_artifact_reconciliation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.finalize_ticket_export_artifact_reconciliation_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.finalize_ticket_export_artifact_reconciliation_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.report_ticket_export_artifact_reconciliation_failure_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  worker_id uuid;
  code text;
  failed_at timestamp with time zone;
  requested_retry_at timestamp with time zone;
  cleanup public.ticket_export_artifact_cleanups%ROWTYPE;
  receipt public.audit_events%ROWTYPE;
  proof text;
  disposition text;
  replay_disposition text;
  next_revision bigint;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','claim','code','failedAt','retryAt']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'claim') <> 'object'
     OR jsonb_typeof(request -> 'code') <> 'string'
     OR request ->> 'code' NOT IN ('storage_unavailable','object_conflict')
     OR jsonb_typeof(request -> 'retryAt') NOT IN ('null','string') THEN
    RAISE EXCEPTION 'ticket export reconciliation failure request is invalid'
      USING ERRCODE = '22023';
  END IF;
  worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export_reconcile'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_export_reconciliation_claim_v1(request -> 'claim') AS parsed;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  code := request ->> 'code';
  failed_at := app.private_ticket_runtime_instant_v1(request -> 'failedAt');
  IF jsonb_typeof(request -> 'retryAt') = 'string' THEN
    requested_retry_at := app.private_ticket_runtime_instant_v1(request -> 'retryAt');
  END IF;
  IF binding.tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR failed_at < binding.claimed_at
     OR failed_at > transaction_timestamp() + interval '1 minute'
     OR code = 'storage_unavailable' AND (
       requested_retry_at IS NULL
       OR requested_retry_at - failed_at < interval '1 second'
       OR requested_retry_at - failed_at > interval '24 hours'
     )
     OR code = 'object_conflict' AND requested_retry_at IS NOT NULL THEN
    RAISE EXCEPTION 'ticket export reconciliation failure request is invalid'
      USING ERRCODE = '22023';
  END IF;
  proof := encode(sha256(binding.cleanup_fence), 'hex');
  SELECT event.* INTO receipt
  FROM public.audit_events AS event
  WHERE event.tenant_id = binding.tenant_id
    AND event.resource_type = 'ticket_export_artifact_cleanup'
    AND event.resource_id = binding.artifact_id
    AND event.action = 'tenant.ticket_export.artifact_reconciliation.failure_reported'
    AND event.metadata ->> 'fenceProofSha256' = proof
  ORDER BY event.sequence DESC LIMIT 1;
  IF FOUND THEN
    IF (receipt.metadata ->> 'inputCleanupRevision')::bigint IS DISTINCT FROM binding.cleanup_revision
       OR (receipt.metadata ->> 'inputCleanupAttempt')::smallint IS DISTINCT FROM binding.cleanup_attempt
       OR receipt.metadata ->> 'reason' IS DISTINCT FROM binding.reason
       OR receipt.metadata ->> 'code' IS DISTINCT FROM code
       OR (CASE WHEN receipt.metadata -> 'retryAt' = 'null'::jsonb THEN NULL
          ELSE (receipt.metadata ->> 'retryAt')::timestamp with time zone END)
          IS DISTINCT FROM requested_retry_at THEN
      RAISE EXCEPTION 'ticket export reconciliation replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    replay_disposition := CASE receipt.metadata ->> 'disposition'
      WHEN 'retry_scheduled' THEN 'replay_retry'
      ELSE 'replay_dead_letter'
    END;
    RETURN QUERY SELECT app.private_ticket_export_reconciliation_result_v1(
      replay_disposition,
      (receipt.metadata ->> 'resultCleanupRevision')::bigint,
      binding.artifact_id, binding.reason, binding.cleanup_fence,
      code, requested_retry_at
    );
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.audit_events AS event
    WHERE event.tenant_id = binding.tenant_id
      AND event.resource_type = 'ticket_export_artifact_cleanup'
      AND event.resource_id = binding.artifact_id
      AND event.metadata ->> 'fenceProofSha256' = proof
  ) THEN
    RAISE EXCEPTION 'ticket export reconciliation replay payload mismatch'
      USING ERRCODE = '23505';
  END IF;
  SELECT candidate.* INTO cleanup
  FROM public.ticket_export_artifact_cleanups AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.artifact_id = binding.artifact_id
  FOR UPDATE;
  IF NOT FOUND
     OR cleanup.job_id IS DISTINCT FROM binding.job_id
     OR cleanup.kind IS DISTINCT FROM binding.kind
     OR cleanup.audience IS DISTINCT FROM binding.audience
     OR cleanup.reason IS DISTINCT FROM binding.reason
     OR cleanup.job_revision IS DISTINCT FROM binding.job_revision
     OR cleanup.cleanup_revision IS DISTINCT FROM binding.cleanup_revision
     OR cleanup.cleanup_attempt IS DISTINCT FROM binding.cleanup_attempt
     OR cleanup.state IS DISTINCT FROM 'leased'
     OR cleanup.worker_id IS DISTINCT FROM worker_id
     OR cleanup.cleanup_fence IS DISTINCT FROM binding.cleanup_fence
     OR cleanup.eligible_at IS DISTINCT FROM binding.eligible_at
     OR cleanup.claimed_at IS DISTINCT FROM binding.claimed_at
     OR cleanup.lease_expires_at IS DISTINCT FROM binding.lease_expires_at THEN
    RETURN QUERY SELECT app.private_ticket_export_reconciliation_result_v1(
      'fence_lost', 0, NULL, NULL, NULL
    );
    RETURN;
  END IF;
  IF cleanup.cleanup_revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'ticket export reconciliation revision is exhausted'
      USING ERRCODE = '54000';
  END IF;
  next_revision := cleanup.cleanup_revision + 1;
  disposition := CASE
    WHEN code = 'object_conflict' OR cleanup.cleanup_attempt >= 100
      THEN 'dead_lettered'
    ELSE 'retry_scheduled'
  END;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_export_artifact_cleanups
  SET cleanup_revision = next_revision,
      state = disposition,
      worker_id = NULL, cleanup_fence = NULL,
      claimed_at = NULL, lease_expires_at = NULL,
      failure_code = code,
      retry_at = CASE WHEN disposition = 'retry_scheduled'
        THEN requested_retry_at END,
      completed_at = NULL,
      updated_at = failed_at
  WHERE tenant_id = binding.tenant_id AND artifact_id = binding.artifact_id;
  INSERT INTO public.audit_events(
    tenant_id, sequence, occurred_at, actor_type, action,
    resource_type, resource_id, authentication_method, outcome, metadata
  ) VALUES (
    binding.tenant_id, 0, failed_at, 'system',
    'tenant.ticket_export.artifact_reconciliation.failure_reported',
    'ticket_export_artifact_cleanup', binding.artifact_id,
    'system', 'failure', jsonb_build_object(
      'jobId', binding.job_id,
      'reason', binding.reason,
      'code', code,
      'retryAt', CASE WHEN disposition = 'retry_scheduled'
        THEN to_jsonb(requested_retry_at) ELSE 'null'::jsonb END,
      'disposition', disposition,
      'inputCleanupRevision', binding.cleanup_revision,
      'inputCleanupAttempt', binding.cleanup_attempt,
      'resultCleanupRevision', next_revision,
      'fenceProofSha256', proof,
      'contentRedacted', true
    )
  );
  RETURN QUERY SELECT app.private_ticket_export_reconciliation_result_v1(
    disposition, next_revision, binding.artifact_id,
    binding.reason, binding.cleanup_fence, code,
    CASE WHEN disposition = 'retry_scheduled' THEN requested_retry_at END
  );
END;
$function$;
ALTER FUNCTION app.report_ticket_export_artifact_reconciliation_failure_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.report_ticket_export_artifact_reconciliation_failure_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.report_ticket_export_artifact_reconciliation_failure_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.read_ticket_export_reconciliation_metrics_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  snapshot_at timestamp with time zone := transaction_timestamp();
  pending bigint;
  reclaimable bigint;
  dead bigint;
  oldest timestamp with time zone;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 8192
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','identity']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object' THEN
    RAISE EXCEPTION 'ticket export reconciliation metrics request is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export_reconcile'
  );
  SELECT
    count(*) FILTER (WHERE cleanup.state = 'pending' AND cleanup.eligible_at <= snapshot_at
      OR cleanup.state = 'retry_scheduled' AND cleanup.retry_at <= snapshot_at),
    count(*) FILTER (WHERE cleanup.state = 'leased' AND cleanup.lease_expires_at <= snapshot_at),
    count(*) FILTER (WHERE cleanup.state = 'dead_lettered'),
    min(CASE
      WHEN cleanup.state = 'pending' AND cleanup.eligible_at <= snapshot_at THEN cleanup.eligible_at
      WHEN cleanup.state = 'retry_scheduled' AND cleanup.retry_at <= snapshot_at THEN cleanup.retry_at
      WHEN cleanup.state = 'leased' AND cleanup.lease_expires_at <= snapshot_at THEN cleanup.lease_expires_at
    END)
  INTO pending, reclaimable, dead, oldest
  FROM public.ticket_export_artifact_cleanups AS cleanup;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'snapshotAt', snapshot_at,
    'pendingEligible', pending,
    'reclaimable', reclaimable,
    'deadLettered', dead,
    'oldestPendingMicroseconds', CASE WHEN oldest IS NULL THEN 0
      ELSE floor(extract(epoch FROM snapshot_at - oldest) * 1000000)::bigint END
  );
END;
$function$;
ALTER FUNCTION app.read_ticket_export_reconciliation_metrics_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.read_ticket_export_reconciliation_metrics_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.read_ticket_export_reconciliation_metrics_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.list_ticket_work_queues_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  item_limit integer;
  queue_document jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 8192
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','serviceAccountId','workerId','purpose','limit']
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'purpose' <> 'ticket_runtime' THEN
    RAISE EXCEPTION 'ticket work queue request is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_ticket_runtime_require_worker_v1(
    jsonb_build_object(
      'serviceAccountId', request ->> 'serviceAccountId',
      'workerId', request ->> 'workerId',
      'purpose', request ->> 'purpose'
    ), 'ticket_runtime'
  );
  item_limit := app.private_ticket_runtime_js_uint_v1(
    request -> 'limit', 1, 1000
  )::integer;
  WITH discovered AS (
    SELECT 'bulk'::text AS queue_type, job.tenant_id, job.kind,
      ''::text AS audience
    FROM public.ticket_bulk_jobs AS job
    WHERE job.state IN ('pending','running','cancellation_requested')
    UNION
    SELECT 'export', job.tenant_id, job.kind, job.audience
    FROM public.ticket_export_jobs AS job
    WHERE job.state IN ('pending','running','cancellation_requested')
    UNION
    SELECT 'export', cleanup.tenant_id, cleanup.kind, cleanup.audience
    FROM public.ticket_export_artifact_cleanups AS cleanup
    WHERE cleanup.state IN ('pending','retry_scheduled','leased')
    UNION
    SELECT 'export', job.tenant_id, job.kind, job.audience
    FROM public.ticket_export_manifests AS manifest
    JOIN public.ticket_export_jobs AS job
      ON job.tenant_id = manifest.tenant_id AND job.id = manifest.job_id
    WHERE manifest.published_at IS NOT NULL
      AND manifest.expires_at <= transaction_timestamp()
      OR manifest.published_at IS NULL AND (
        job.state IN ('succeeded','failed','cancelled')
        OR job.lease_expires_at <= transaction_timestamp()
        OR job.expires_at <= transaction_timestamp()
      )
  ), bounded AS (
    SELECT queue_type, tenant_id, kind, audience
    FROM discovered
    ORDER BY queue_type, tenant_id, kind, audience
    LIMIT item_limit
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'type', queue_type,
    'tenantId', tenant_id,
    'kind', kind,
    'audience', audience
  ) ORDER BY queue_type, tenant_id, kind, audience), '[]'::jsonb)
  INTO queue_document
  FROM bounded;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'queues', queue_document
  );
END;
$function$;
ALTER FUNCTION app.list_ticket_work_queues_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.list_ticket_work_queues_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.list_ticket_work_queues_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_append_human_effects_v1(
  p_tenant_id uuid,
  p_actor jsonb,
  p_audit jsonb,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_resource_version bigint,
  p_occurred_at timestamp with time zone,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE actor_id uuid;
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR NOT app.private_ticket_runtime_audit_is_valid_v1(p_audit)
     OR p_action !~ '^[a-z][a-z0-9_.]{2,127}$'
     OR p_resource_type NOT IN ('ticket_bulk_job','ticket_export_job')
     OR p_resource_id IS NULL
     OR p_resource_version NOT BETWEEN 1 AND 2147483647
     OR p_occurred_at IS NULL
     OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_metadata) > 16384 THEN
    RAISE EXCEPTION 'ticket runtime mutation effects are invalid'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_ticket_runtime_uuid_v1(p_actor ->> 'userId');
  INSERT INTO public.audit_events(
    tenant_id, sequence, occurred_at, actor_type, actor_user_id,
    action, resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome, metadata
  ) VALUES (
    p_tenant_id, 0, p_occurred_at, 'user', actor_id,
    p_action, p_resource_type, p_resource_id,
    (p_audit ->> 'requestId')::uuid,
    (p_audit ->> 'correlationId')::uuid,
    (p_audit ->> 'remoteAddress')::inet,
    p_audit ->> 'userAgent', p_actor ->> 'authenticationMethod',
    'success', p_metadata || jsonb_build_object('contentRedacted', true)
  );
  INSERT INTO public.outbox_events(
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, actor_kind, actor_id, producer, maximum_audience,
    occurred_at, available_at
  ) VALUES (
    uuidv7(), p_tenant_id, p_resource_type, p_resource_id,
    p_resource_version::integer, p_action, 1,
    jsonb_build_object(
      'resourceId', p_resource_id,
      'resourceVersion', p_resource_version,
      'contentRedacted', true
    ),
    p_resource_type || ':' || p_resource_id::text || ':'
      || p_resource_version::text || ':' || p_action,
    (p_audit ->> 'correlationId')::uuid,
    'operator', actor_id, 'ticket-runtime', 'operator',
    p_occurred_at, p_occurred_at
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_append_human_effects_v1(
  uuid, jsonb, jsonb, text, text, uuid, bigint,
  timestamp with time zone, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_append_human_effects_v1(
  uuid, jsonb, jsonb, text, text, uuid, bigint,
  timestamp with time zone, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_bulk_request_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_actor_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  requested_at timestamp with time zone;
  expires_at timestamp with time zone;
  key_digest bytea;
  fingerprint bytea;
  mutation_action text;
  permission_key text;
  explicit_targets jsonb;
  query_document jsonb;
  query_source text;
  query_spec text;
  query_digest bytea;
  catalog_digest bytea;
  saved_view_id uuid;
  saved_view_revision bigint;
  saved_view_digest bytea;
  target_count integer;
  target_digest bytea;
  result_document jsonb;
  prior public.ticket_bulk_command_receipts%ROWTYPE;
  target jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','audit','tenantId','ownerMembershipId','kind',
         'requiredCapability','jobId','explicitTargets','query','mutation',
         'requestedAt','expiresAt','action','idempotencyKeySha256',
         'requestFingerprintSha256'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'actor') <> 'object'
     OR jsonb_typeof(request -> 'audit') <> 'object'
     OR NOT app.private_ticket_runtime_audit_is_valid_v1(request -> 'audit')
     OR request ->> 'requiredCapability' <> 'ticket.bulk.request'
     OR request ->> 'action' <> 'request'
     OR jsonb_typeof(request -> 'mutation') <> 'object'
     OR (jsonb_typeof(request -> 'explicitTargets') = 'array')
        = (jsonb_typeof(request -> 'query') = 'object') THEN
    RAISE EXCEPTION 'ticket bulk request command is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(request ->> 'ownerMembershipId');
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk request kind is invalid' USING ERRCODE = '22023';
  END;
  requested_at := app.private_ticket_runtime_instant_v1(request -> 'requestedAt');
  expires_at := app.private_ticket_runtime_instant_v1(request -> 'expiresAt');
  key_digest := app.private_ticket_runtime_digest_v1(request ->> 'idempotencyKeySha256');
  fingerprint := app.private_ticket_runtime_digest_v1(request ->> 'requestFingerprintSha256');
  mutation_action := app.private_ticket_bulk_validate_mutation_v1(request -> 'mutation');
  permission_key := app.private_ticket_runtime_permission_v1(request_kind, mutation_action);
  IF app.private_ticket_runtime_require_human_v1(
       request -> 'actor', request_tenant_id
     ) IS DISTINCT FROM request_owner_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(permission_key) THEN
    RAISE EXCEPTION 'ticket bulk request authority is required' USING ERRCODE = '42501';
  END IF;
  request_actor_id := app.context_user_id();
  SELECT receipt.* INTO prior
  FROM public.ticket_bulk_command_receipts AS receipt
  WHERE receipt.tenant_id = request_tenant_id
    AND receipt.actor_user_id = request_actor_id
    AND receipt.owner_membership_id = request_owner_id
    AND receipt.kind = request_kind
    AND receipt.action = 'request'
    AND receipt.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF prior.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'ticket bulk command replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT jsonb_set(
      prior.result_snapshot, '{replayed}', 'true'::jsonb, false
    );
    RETURN;
  END IF;
  IF requested_at < transaction_timestamp() - interval '5 minutes'
     OR requested_at > transaction_timestamp() + interval '1 minute'
     OR expires_at - requested_at < interval '5 minutes'
     OR expires_at - requested_at > interval '30 days' THEN
    RAISE EXCEPTION 'ticket bulk request retention is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  explicit_targets := request -> 'explicitTargets';
  query_document := request -> 'query';
  IF jsonb_typeof(explicit_targets) = 'array' THEN
    target_count := jsonb_array_length(explicit_targets);
    IF target_count NOT BETWEEN 1 AND 1000 THEN
      RAISE EXCEPTION 'ticket bulk explicit target count is invalid' USING ERRCODE = '22023';
    END IF;
  ELSE
    IF NOT app.private_ticket_runtime_exact_keys_v1(
       query_document, ARRAY[
         'source','specCanonicalBase64','querySha256','catalogSha256','savedView'
       ]
    ) OR query_document ->> 'source' NOT IN ('inline','saved_view') THEN
      RAISE EXCEPTION 'ticket bulk query snapshot is invalid' USING ERRCODE = '22023';
    END IF;
    BEGIN
      query_spec := convert_from(decode(query_document ->> 'specCanonicalBase64', 'base64'), 'UTF8');
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'ticket bulk query snapshot is invalid' USING ERRCODE = '22023';
    END;
    IF octet_length(query_spec) NOT BETWEEN 1 AND 262144 THEN
      RAISE EXCEPTION 'ticket bulk query snapshot is invalid' USING ERRCODE = '22023';
    END IF;
    query_digest := app.private_ticket_runtime_digest_v1(query_document ->> 'querySha256');
    catalog_digest := app.private_ticket_runtime_digest_v1(query_document ->> 'catalogSha256');
    IF sha256(convert_to(query_spec, 'UTF8')) IS DISTINCT FROM query_digest
       OR app.private_ticket_runtime_catalog_digest_v1(query_spec) IS DISTINCT FROM catalog_digest THEN
      RAISE EXCEPTION 'ticket bulk query snapshot digest is stale' USING ERRCODE = '40001';
    END IF;
    query_source := query_document ->> 'source';
    IF query_source = 'inline' THEN
      IF query_document -> 'savedView' <> 'null'::jsonb THEN
        RAISE EXCEPTION 'ticket bulk inline snapshot is invalid' USING ERRCODE = '22023';
      END IF;
    ELSE
      IF NOT app.private_ticket_runtime_exact_keys_v1(
        query_document -> 'savedView', ARRAY['id','ownerId','revision','specSha256']
      ) THEN
        RAISE EXCEPTION 'ticket bulk saved-view snapshot is invalid' USING ERRCODE = '22023';
      END IF;
      saved_view_id := app.private_ticket_runtime_uuid_v1(query_document #>> '{savedView,id}');
      IF app.private_ticket_runtime_uuid_v1(query_document #>> '{savedView,ownerId}')
           IS DISTINCT FROM request_owner_id THEN
        RAISE EXCEPTION 'ticket bulk saved-view owner is invalid' USING ERRCODE = '42501';
      END IF;
      saved_view_revision := app.private_ticket_runtime_js_uint_v1(
        query_document #> '{savedView,revision}', 1, 9007199254740991
      );
      saved_view_digest := app.private_ticket_runtime_digest_v1(
        query_document #>> '{savedView,specSha256}'
      );
      PERFORM 1 FROM public.ticket_saved_views AS view
      WHERE view.tenant_id = request_tenant_id AND view.id = saved_view_id
        AND view.owner_membership_id = request_owner_id
        AND view.aggregate_kind = request_kind AND view.status = 'active'
        AND view.revision = saved_view_revision
        AND view.spec_digest = saved_view_digest
      FOR SHARE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'ticket bulk saved-view snapshot is stale' USING ERRCODE = '40001';
      END IF;
    END IF;
  END IF;
  INSERT INTO public.ticket_bulk_jobs(
    id, tenant_id, requester_user_id, owner_membership_id, kind,
    selection_source, mutation, target_set_digest, query_digest,
    catalog_digest, saved_view_id, saved_view_revision, saved_view_digest,
    projection_version, maximum_attempts, state, revision, total,
    requested_at, updated_at, available_at, expires_at, active_batch
  ) VALUES (
    request_job_id, request_tenant_id, request_actor_id, request_owner_id,
    request_kind, CASE WHEN jsonb_typeof(explicit_targets) = 'array'
      THEN 'explicit' ELSE 'query' END,
    request -> 'mutation', decode(repeat('00', 32), 'hex'),
    query_digest, catalog_digest, saved_view_id, saved_view_revision,
    saved_view_digest, 1, 5, 'pending', 1, 1,
    requested_at, requested_at, requested_at, expires_at, false
  );
  IF jsonb_typeof(explicit_targets) = 'array' THEN
    FOR target IN SELECT value FROM jsonb_array_elements(explicit_targets) AS element(value)
    LOOP
      IF NOT app.private_ticket_runtime_exact_keys_v1(target, ARRAY['id','version']) THEN
        RAISE EXCEPTION 'ticket bulk explicit target is invalid' USING ERRCODE = '22023';
      END IF;
      PERFORM app.private_ticket_runtime_uuid_v1(target ->> 'id');
      PERFORM app.private_ticket_runtime_js_uint_v1(
        target -> 'version', 1, 9007199254740991
      );
    END LOOP;
    IF (SELECT count(DISTINCT value ->> 'id')
        FROM jsonb_array_elements(explicit_targets) AS element(value)) <> target_count THEN
      RAISE EXCEPTION 'ticket bulk explicit targets are duplicated' USING ERRCODE = '22023';
    END IF;
    IF request_kind = 'alert' THEN
      INSERT INTO public.ticket_bulk_targets(
        tenant_id, job_id, sequence, target_id, target_version
      )
      SELECT request_tenant_id, request_job_id,
        row_number() OVER (ORDER BY alert.id)::integer, alert.id, alert.version
      FROM public.alerts AS alert
      JOIN jsonb_array_elements(explicit_targets) AS element(value)
        ON alert.id = (element.value ->> 'id')::uuid
       AND alert.version = (element.value ->> 'version')::bigint
      WHERE alert.tenant_id = request_tenant_id AND alert.deleted_at IS NULL
        AND app.private_current_ticket_scope_allows_v1(
          permission_key, alert.assigned_team_id, alert.created_by,
          alert.assignee_user_id, alert.claimed_by_user_id
        )
      ORDER BY alert.id;
    ELSE
      INSERT INTO public.ticket_bulk_targets(
        tenant_id, job_id, sequence, target_id, target_version
      )
      SELECT request_tenant_id, request_job_id,
        row_number() OVER (ORDER BY case_row.id)::integer,
        case_row.id, case_row.version
      FROM public.cases AS case_row
      JOIN jsonb_array_elements(explicit_targets) AS element(value)
        ON case_row.id = (element.value ->> 'id')::uuid
       AND case_row.version = (element.value ->> 'version')::bigint
      WHERE case_row.tenant_id = request_tenant_id
        AND app.private_current_ticket_scope_allows_v1(
          permission_key, case_row.assigned_team_id, case_row.created_by_user_id,
          case_row.assignee_user_id, case_row.claimed_by_user_id
        )
      ORDER BY case_row.id;
    END IF;
    GET DIAGNOSTICS target_count = ROW_COUNT;
    IF target_count <> jsonb_array_length(explicit_targets) THEN
      RAISE EXCEPTION 'ticket bulk targets are unavailable' USING ERRCODE = '42501';
    END IF;
  ELSE
    INSERT INTO public.ticket_bulk_query_snapshots(
      tenant_id, job_id, source, spec_canonical, query_digest, catalog_digest,
      saved_view_id, saved_view_owner_id, saved_view_revision, saved_view_digest
    ) VALUES (
      request_tenant_id, request_job_id, query_source, query_spec,
      query_digest, catalog_digest, saved_view_id,
      CASE WHEN saved_view_id IS NULL THEN NULL ELSE request_owner_id END,
      saved_view_revision, saved_view_digest
    );
    target_count := app.private_ticket_bulk_materialize_query_v1(
      request_tenant_id, request_job_id, request_kind, permission_key, query_spec
    );
  END IF;
  target_digest := app.private_ticket_bulk_target_set_digest_v1(
    request_tenant_id, request_job_id
  );
  UPDATE public.ticket_bulk_jobs
  SET total = target_count, target_set_digest = target_digest
  WHERE tenant_id = request_tenant_id AND id = request_job_id;
  result_document := jsonb_build_object(
    'schemaVersion', 1,
    'replayed', false,
    'requestFingerprintSha256', encode(fingerprint, 'hex'),
    'record', app.private_ticket_bulk_record_v1(request_job_id)
  );
  INSERT INTO public.ticket_bulk_command_receipts(
    tenant_id, job_id, actor_user_id, owner_membership_id, kind, action,
    idempotency_key_digest, request_fingerprint_digest, result_snapshot,
    created_at, expires_at
  ) VALUES (
    request_tenant_id, request_job_id, request_actor_id, request_owner_id,
    request_kind, 'request', key_digest, fingerprint, result_document,
    requested_at, expires_at
  );
  PERFORM app.private_ticket_runtime_append_human_effects_v1(
    request_tenant_id, request -> 'actor', request -> 'audit',
    'ticket.bulk.requested', 'ticket_bulk_job', request_job_id, 1,
    requested_at, jsonb_build_object(
      'kind', request_kind,
      'selectionSource', CASE WHEN jsonb_typeof(explicit_targets) = 'array'
        THEN 'explicit' ELSE 'query' END,
      'targetCount', target_count,
      'mutationAction', mutation_action,
      'targetSetSha256', encode(target_digest, 'hex')
    )
  );
  RETURN QUERY SELECT result_document;
EXCEPTION WHEN unique_violation THEN
  SELECT receipt.* INTO prior
  FROM public.ticket_bulk_command_receipts AS receipt
  WHERE receipt.tenant_id = request_tenant_id
    AND receipt.actor_user_id = request_actor_id
    AND receipt.owner_membership_id = request_owner_id
    AND receipt.kind = request_kind
    AND receipt.action = 'request'
    AND receipt.idempotency_key_digest = key_digest;
  IF FOUND AND prior.request_fingerprint_digest = fingerprint THEN
    RETURN QUERY SELECT jsonb_set(
      prior.result_snapshot, '{replayed}', 'true'::jsonb, false
    );
    RETURN;
  END IF;
  RAISE EXCEPTION 'ticket bulk command replay payload mismatch'
    USING ERRCODE = '23505';
END;
$function$;
ALTER FUNCTION app.commit_ticket_bulk_request_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_bulk_request_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_bulk_request_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_ticket_bulk_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  capability text;
  job public.ticket_bulk_jobs%ROWTYPE;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 32768
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','tenantId','ownerMembershipId',
         'kind','capability','jobId'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'capability' NOT IN ('ticket.bulk.read','ticket.bulk.cancel') THEN
    RAISE EXCEPTION 'ticket bulk get request is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(request ->> 'ownerMembershipId');
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk get kind is invalid' USING ERRCODE = '22023';
  END;
  capability := request ->> 'capability';
  IF app.private_ticket_runtime_require_human_v1(
       request -> 'actor', request_tenant_id
     ) IS DISTINCT FROM request_owner_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(
       app.private_ticket_runtime_permission_v1(request_kind, 'read')
     ) THEN
    RAISE EXCEPTION 'ticket bulk get authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_bulk_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id
    AND candidate.id = request_job_id
    AND candidate.requester_user_id = app.context_user_id()
    AND candidate.owner_membership_id = request_owner_id
    AND candidate.kind = request_kind;
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'record', app.private_ticket_bulk_record_v1(job.id)
  );
END;
$function$;
ALTER FUNCTION app.get_ticket_bulk_v1(jsonb) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.get_ticket_bulk_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.get_ticket_bulk_v1(jsonb) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_bulk_cancellation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  next_document jsonb;
  definition jsonb;
  request_tenant_id uuid;
  request_actor_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  expected_revision bigint;
  next_revision bigint;
  changed_at timestamp with time zone;
  key_digest bytea;
  fingerprint bytea;
  job public.ticket_bulk_jobs%ROWTYPE;
  prior public.ticket_bulk_command_receipts%ROWTYPE;
  result_document jsonb;
  terminal boolean;
  remaining integer;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','audit','requiredCapability','expectedRevision',
         'next','action','idempotencyKeySha256','requestFingerprintSha256'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'requiredCapability' <> 'ticket.bulk.cancel'
     OR request ->> 'action' <> 'cancel'
     OR jsonb_typeof(request -> 'actor') <> 'object'
     OR NOT app.private_ticket_runtime_audit_is_valid_v1(request -> 'audit')
     OR jsonb_typeof(request -> 'next') <> 'object' THEN
    RAISE EXCEPTION 'ticket bulk cancellation command is invalid' USING ERRCODE = '22023';
  END IF;
  next_document := request -> 'next';
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       next_document, ARRAY[
         'definition','state','revision','progress','requestedAt','updatedAt',
         'availableAt','expiresAt','activeBatch','terminalAt'
       ]
     ) OR jsonb_typeof(next_document -> 'definition') <> 'object'
     OR jsonb_typeof(next_document -> 'progress') <> 'object' THEN
    RAISE EXCEPTION 'ticket bulk cancellation projection is invalid' USING ERRCODE = '22023';
  END IF;
  definition := next_document -> 'definition';
  request_tenant_id := app.private_ticket_runtime_uuid_v1(definition ->> 'tenantId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(definition ->> 'ownerMembershipId');
  request_job_id := app.private_ticket_runtime_uuid_v1(definition ->> 'id');
  request_actor_id := app.private_ticket_runtime_uuid_v1(definition ->> 'requesterId');
  BEGIN request_kind := (definition ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk cancellation kind is invalid' USING ERRCODE = '22023';
  END;
  expected_revision := app.private_ticket_runtime_js_uint_v1(
    request -> 'expectedRevision', 1, 9007199254740990
  );
  next_revision := app.private_ticket_runtime_js_uint_v1(
    next_document -> 'revision', 2, 9007199254740991
  );
  changed_at := app.private_ticket_runtime_instant_v1(next_document -> 'updatedAt');
  key_digest := app.private_ticket_runtime_digest_v1(request ->> 'idempotencyKeySha256');
  fingerprint := app.private_ticket_runtime_digest_v1(request ->> 'requestFingerprintSha256');
  IF app.private_ticket_runtime_require_human_v1(
       request -> 'actor', request_tenant_id
     ) IS DISTINCT FROM request_owner_id
     OR app.context_user_id() IS DISTINCT FROM request_actor_id THEN
    RAISE EXCEPTION 'ticket bulk cancellation authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT receipt.* INTO prior
  FROM public.ticket_bulk_command_receipts AS receipt
  WHERE receipt.tenant_id = request_tenant_id
    AND receipt.actor_user_id = request_actor_id
    AND receipt.owner_membership_id = request_owner_id
    AND receipt.kind = request_kind
    AND receipt.action = 'cancel'
    AND receipt.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF prior.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'ticket bulk command replay payload mismatch' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT jsonb_set(
      prior.result_snapshot, '{replayed}', 'true'::jsonb, false
    );
    RETURN;
  END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_bulk_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id AND candidate.id = request_job_id
  FOR UPDATE;
  IF NOT FOUND OR job.requester_user_id IS DISTINCT FROM request_actor_id
     OR job.owner_membership_id IS DISTINCT FROM request_owner_id
     OR job.kind IS DISTINCT FROM request_kind THEN
    RAISE EXCEPTION 'ticket bulk job is unavailable' USING ERRCODE = 'P0002';
  END IF;
  IF NOT app.private_ticket_runtime_has_any_scope_v1(
       app.private_ticket_runtime_permission_v1(request_kind, 'read')
     ) OR NOT app.private_ticket_runtime_has_any_scope_v1(
       app.private_ticket_runtime_permission_v1(request_kind, job.mutation ->> 'action')
     ) THEN
    RAISE EXCEPTION 'ticket bulk cancellation authority is required' USING ERRCODE = '42501';
  END IF;
  IF job.revision IS DISTINCT FROM expected_revision
     OR next_revision IS DISTINCT FROM expected_revision + 1 THEN
    RAISE EXCEPTION 'ticket bulk revision conflict' USING ERRCODE = '40001';
  END IF;
  IF job.state NOT IN ('pending','running')
     OR changed_at < job.updated_at OR changed_at >= job.expires_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'requestedAt') IS DISTINCT FROM job.requested_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'availableAt') IS DISTINCT FROM job.available_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'expiresAt') IS DISTINCT FROM job.expires_at
     OR next_document -> 'definition' IS DISTINCT FROM
        (app.private_ticket_bulk_record_v1(job.id) #> '{job,definition}')
     OR next_document ->> 'state' IS DISTINCT FROM
        (CASE WHEN job.state = 'pending' THEN 'cancelled'
          ELSE 'cancellation_requested' END)
     OR (next_document ->> 'activeBatch')::boolean IS DISTINCT FROM job.active_batch THEN
    RAISE EXCEPTION 'ticket bulk cancellation transition is invalid' USING ERRCODE = '22023';
  END IF;
  terminal := job.state = 'pending';
  IF terminal THEN
    remaining := job.total - (
      job.succeeded + job.no_change + job.version_conflict
      + job.not_found_or_hidden + job.authorization_denied + job.rejected
      + job.cancelled + job.authorization_revoked + job.internal_failure
    );
    IF next_document -> 'progress' IS DISTINCT FROM jsonb_set(
         app.private_ticket_bulk_progress_document_v1(job),
         '{cancelled}', to_jsonb(job.cancelled + remaining), false
       ) OR jsonb_typeof(next_document -> 'terminalAt') <> 'string'
       OR app.private_ticket_runtime_instant_v1(next_document -> 'terminalAt')
          IS DISTINCT FROM changed_at THEN
      RAISE EXCEPTION 'ticket bulk cancellation transition is invalid' USING ERRCODE = '22023';
    END IF;
  ELSE
    IF next_document -> 'progress' IS DISTINCT FROM
         app.private_ticket_bulk_progress_document_v1(job)
       OR next_document -> 'terminalAt' <> 'null'::jsonb THEN
      RAISE EXCEPTION 'ticket bulk cancellation transition is invalid' USING ERRCODE = '22023';
    END IF;
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_bulk_jobs
  SET state = CASE WHEN terminal THEN 'cancelled' ELSE 'cancellation_requested' END,
      revision = next_revision,
      cancelled = CASE WHEN terminal THEN cancelled + remaining ELSE cancelled END,
      updated_at = changed_at,
      terminal_at = CASE WHEN terminal THEN changed_at END
  WHERE tenant_id = request_tenant_id AND id = request_job_id;
  result_document := jsonb_build_object(
    'schemaVersion', 1, 'replayed', false,
    'requestFingerprintSha256', encode(fingerprint, 'hex'),
    'record', app.private_ticket_bulk_record_v1(request_job_id)
  );
  INSERT INTO public.ticket_bulk_command_receipts(
    tenant_id, job_id, actor_user_id, owner_membership_id, kind, action,
    idempotency_key_digest, request_fingerprint_digest, result_snapshot,
    created_at, expires_at
  ) VALUES (
    request_tenant_id, request_job_id, request_actor_id, request_owner_id,
    request_kind, 'cancel', key_digest, fingerprint, result_document,
    changed_at, job.expires_at
  );
  PERFORM app.private_ticket_runtime_append_human_effects_v1(
    request_tenant_id, request -> 'actor', request -> 'audit',
    CASE WHEN terminal THEN 'ticket.bulk.cancelled'
      ELSE 'ticket.bulk.cancellation_requested' END,
    'ticket_bulk_job', request_job_id, next_revision, changed_at,
    jsonb_build_object('kind', request_kind, 'terminal', terminal)
  );
  RETURN QUERY SELECT result_document;
END;
$function$;
ALTER FUNCTION app.commit_ticket_bulk_cancellation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_bulk_cancellation_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_bulk_cancellation_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.list_ticket_bulk_results_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  item_limit integer;
  after_sequence integer := 0;
  encoded_after bytea;
  items jsonb;
  next_cursor text := '';
  last_sequence integer;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 32768
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','tenantId','ownerMembershipId',
         'kind','jobId','limit','after'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'after') <> 'string' THEN
    RAISE EXCEPTION 'ticket bulk result page request is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(request ->> 'ownerMembershipId');
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk result kind is invalid' USING ERRCODE = '22023';
  END;
  item_limit := app.private_ticket_runtime_js_uint_v1(request -> 'limit', 1, 100)::integer;
  IF request ->> 'after' <> '' THEN
    BEGIN
      encoded_after := decode(
        translate(request ->> 'after', '-_', '+/')
          || repeat('=', (4 - length(request ->> 'after') % 4) % 4),
        'base64'
      );
      IF convert_from(encoded_after, 'UTF8') !~ '^[1-9][0-9]{0,5}$' THEN
        RAISE EXCEPTION 'invalid';
      END IF;
      after_sequence := convert_from(encoded_after, 'UTF8')::integer;
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'ticket bulk result cursor is invalid' USING ERRCODE = '22023';
    END;
  END IF;
  IF app.private_ticket_runtime_require_human_v1(
       request -> 'actor', request_tenant_id
     ) IS DISTINCT FROM request_owner_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(
       app.private_ticket_runtime_permission_v1(request_kind, 'read')
     ) THEN
    RAISE EXCEPTION 'ticket bulk result authority is required' USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM public.ticket_bulk_jobs AS job
  WHERE job.tenant_id = request_tenant_id AND job.id = request_job_id
    AND job.requester_user_id = app.context_user_id()
    AND job.owner_membership_id = request_owner_id AND job.kind = request_kind;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket bulk job is unavailable' USING ERRCODE = 'P0002';
  END IF;
  WITH page AS MATERIALIZED (
    SELECT target.*
    FROM public.ticket_bulk_targets AS target
    WHERE target.tenant_id = request_tenant_id
      AND target.job_id = request_job_id
      AND target.sequence > after_sequence
      AND target.result IS NOT NULL
    ORDER BY target.sequence
    LIMIT item_limit + 1
  ), visible AS (
    SELECT * FROM page ORDER BY sequence LIMIT item_limit
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object(
      'sequence', sequence,
      'targetId', target_id,
      'targetVersion', target_version,
      'result', result,
      'recordedAt', recorded_at
    ) ORDER BY sequence), '[]'::jsonb), max(sequence)
  INTO items, last_sequence
  FROM visible;
  IF last_sequence IS NOT NULL AND EXISTS (
    SELECT 1 FROM public.ticket_bulk_targets AS target
    WHERE target.tenant_id = request_tenant_id
      AND target.job_id = request_job_id
      AND target.sequence > last_sequence AND target.result IS NOT NULL
  ) THEN
    next_cursor := translate(rtrim(encode(
      convert_to(last_sequence::text, 'UTF8'), 'base64'
    ), E'=\n'), '+/', '-_');
  END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'items', items,
    'next', next_cursor
  );
END;
$function$;
ALTER FUNCTION app.list_ticket_bulk_results_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.list_ticket_bulk_results_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.list_ticket_bulk_results_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_bulk_binding_v1(p_binding jsonb)
RETURNS TABLE(
  tenant_id uuid,
  job_id uuid,
  batch_id uuid,
  kind public.ticket_aggregate_kind,
  worker_id uuid,
  revision bigint,
  attempt smallint,
  fence_digest bytea,
  target_set_digest bytea,
  projection_version bigint,
  claimed_at timestamp with time zone,
  lease_expires_at timestamp with time zone,
  job_expires_at timestamp with time zone
)
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_binding, ARRAY[
         'tenantId','jobId','batchId','kind','workerId','revision','attempt',
         'fenceSha256','targetSetSha256','projectionVersion','claimedAt',
         'leaseExpiresAt','jobExpiresAt'
       ]
     ) OR p_binding ->> 'kind' NOT IN ('alert','case') THEN
    RAISE EXCEPTION 'ticket bulk binding is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_runtime_uuid_v1(p_binding ->> 'tenantId');
  job_id := app.private_ticket_runtime_uuid_v1(p_binding ->> 'jobId');
  batch_id := app.private_ticket_runtime_uuid_v1(p_binding ->> 'batchId');
  kind := (p_binding ->> 'kind')::public.ticket_aggregate_kind;
  worker_id := app.private_ticket_runtime_uuid_v1(p_binding ->> 'workerId');
  revision := app.private_ticket_runtime_js_uint_v1(
    p_binding -> 'revision', 2, 9007199254740991
  );
  attempt := app.private_ticket_runtime_js_uint_v1(
    p_binding -> 'attempt', 1, 5
  )::smallint;
  fence_digest := app.private_ticket_runtime_digest_v1(p_binding ->> 'fenceSha256');
  target_set_digest := app.private_ticket_runtime_digest_v1(
    p_binding ->> 'targetSetSha256'
  );
  projection_version := app.private_ticket_runtime_js_uint_v1(
    p_binding -> 'projectionVersion', 1, 1
  );
  claimed_at := app.private_ticket_runtime_instant_v1(p_binding -> 'claimedAt');
  lease_expires_at := app.private_ticket_runtime_instant_v1(
    p_binding -> 'leaseExpiresAt'
  );
  job_expires_at := app.private_ticket_runtime_instant_v1(
    p_binding -> 'jobExpiresAt'
  );
  IF lease_expires_at - claimed_at < interval '30 seconds'
     OR lease_expires_at - claimed_at > interval '15 minutes'
     OR job_expires_at < lease_expires_at THEN
    RAISE EXCEPTION 'ticket bulk binding lifetime is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN NEXT;
END;
$function$;
ALTER FUNCTION app.private_ticket_bulk_binding_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_bulk_binding_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.claim_ticket_bulk_batch_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  queue_tenant_id uuid;
  queue_kind public.ticket_aggregate_kind;
  claimed_worker_id uuid;
  observed_at timestamp with time zone;
  lease_microseconds bigint;
  item_limit integer;
  job public.ticket_bulk_jobs%ROWTYPE;
  batch_id uuid;
  batch_attempt smallint;
  batch_fence bytea;
  lease_until timestamp with time zone;
  permission_key text;
  targets jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 32768
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','tenantId','kind','now',
         'leaseMicroseconds','limit'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'kind' NOT IN ('alert','case') THEN
    RAISE EXCEPTION 'ticket bulk claim request is invalid' USING ERRCODE = '22023';
  END IF;
  claimed_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_bulk'
  );
  queue_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  queue_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  observed_at := app.private_ticket_runtime_instant_v1(request -> 'now');
  lease_microseconds := app.private_ticket_runtime_js_uint_v1(
    request -> 'leaseMicroseconds', 30000000, 900000000
  );
  item_limit := app.private_ticket_runtime_js_uint_v1(request -> 'limit', 1, 100)::integer;
  IF observed_at < transaction_timestamp() - interval '5 minutes'
     OR observed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket bulk claim time is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', queue_tenant_id::text, true);
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  SELECT candidate.* INTO job
  FROM public.ticket_bulk_jobs AS candidate
  WHERE candidate.tenant_id = queue_tenant_id
    AND candidate.kind = queue_kind
    AND candidate.state = 'pending'
    AND candidate.available_at <= observed_at
    AND candidate.expires_at > observed_at
    AND NOT candidate.active_batch
  ORDER BY candidate.available_at, candidate.id
  FOR UPDATE SKIP LOCKED
  LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  PERFORM set_config('app.user_id', job.requester_user_id::text, true);
  permission_key := app.private_ticket_runtime_permission_v1(
    job.kind, job.mutation ->> 'action'
  );
  IF app.current_tenant_membership_id() IS DISTINCT FROM job.owner_membership_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(permission_key) THEN
    UPDATE public.ticket_bulk_targets
    SET result = 'authorization_revoked', recorded_at = observed_at
    WHERE tenant_id = job.tenant_id AND job_id = job.id AND result IS NULL;
    UPDATE public.ticket_bulk_jobs
    SET state = 'authorization_revoked', revision = revision + 1,
        authorization_revoked = total - (
          succeeded + no_change + version_conflict + not_found_or_hidden
          + authorization_denied + rejected + cancelled
          + authorization_revoked + internal_failure
        ) + authorization_revoked,
        updated_at = observed_at, terminal_at = observed_at
    WHERE tenant_id = job.tenant_id AND id = job.id
      AND revision < 9007199254740991;
    RETURN;
  END IF;
  SELECT coalesce(max(batch.attempt), 0) + 1 INTO batch_attempt
  FROM public.ticket_bulk_batches AS batch
  WHERE batch.tenant_id = job.tenant_id AND batch.job_id = job.id;
  IF batch_attempt > job.maximum_attempts THEN
    UPDATE public.ticket_bulk_targets
    SET result = 'internal_failure', recorded_at = observed_at
    WHERE tenant_id = job.tenant_id AND job_id = job.id AND result IS NULL;
    UPDATE public.ticket_bulk_jobs
    SET state = 'failed', revision = revision + 1,
        internal_failure = total - (
          succeeded + no_change + version_conflict + not_found_or_hidden
          + authorization_denied + rejected + cancelled
          + authorization_revoked + internal_failure
        ) + internal_failure,
        updated_at = observed_at, terminal_at = observed_at
    WHERE tenant_id = job.tenant_id AND id = job.id
      AND revision < 9007199254740991;
    RETURN;
  END IF;
  IF job.revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'ticket bulk revision is exhausted' USING ERRCODE = '54000';
  END IF;
  batch_id := uuidv7();
  batch_fence := sha256(convert_to(
    batch_id::text || ':' || claimed_worker_id::text || ':'
    || clock_timestamp()::text, 'UTF8'
  ));
  lease_until := observed_at
    + make_interval(secs => lease_microseconds::double precision / 1000000.0);
  IF lease_until > job.expires_at THEN RETURN; END IF;
  UPDATE public.ticket_bulk_jobs
  SET state = 'running', revision = revision + 1,
      active_batch = true, updated_at = observed_at
  WHERE tenant_id = job.tenant_id AND id = job.id
  RETURNING * INTO job;
  INSERT INTO public.ticket_bulk_batches(
    id, tenant_id, job_id, kind, worker_id, revision, attempt,
    fence_digest, target_set_digest, projection_version,
    claimed_at, lease_expires_at, job_expires_at, state, processed
  ) VALUES (
    batch_id, job.tenant_id, job.id, job.kind, claimed_worker_id,
    job.revision, batch_attempt, batch_fence, job.target_set_digest,
    job.projection_version, observed_at, lease_until, job.expires_at,
    'active', 0
  );
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'id', target.target_id,
    'version', target.target_version,
    'sequence', target.sequence
  ) ORDER BY target.sequence), '[]'::jsonb)
  INTO targets
  FROM (
    SELECT candidate.*
    FROM public.ticket_bulk_targets AS candidate
    WHERE candidate.tenant_id = job.tenant_id AND candidate.job_id = job.id
      AND candidate.result IS NULL
    ORDER BY candidate.sequence
    LIMIT item_limit
  ) AS target;
  IF jsonb_array_length(targets) = 0 THEN
    RAISE EXCEPTION 'ticket bulk pending job has no pending targets' USING ERRCODE = '55000';
  END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'definition', app.private_ticket_bulk_record_v1(job.id) #> '{job,definition}',
    'binding', jsonb_build_object(
      'tenantId', job.tenant_id,
      'jobId', job.id,
      'batchId', batch_id,
      'kind', job.kind,
      'workerId', claimed_worker_id,
      'revision', job.revision,
      'attempt', batch_attempt,
      'fenceSha256', encode(batch_fence, 'hex'),
      'targetSetSha256', encode(job.target_set_digest, 'hex'),
      'projectionVersion', job.projection_version,
      'claimedAt', observed_at,
      'leaseExpiresAt', lease_until,
      'jobExpiresAt', job.expires_at
    ),
    'targets', targets,
    'progress', app.private_ticket_bulk_progress_document_v1(job),
    'observedAt', observed_at
  );
END;
$function$;
ALTER FUNCTION app.claim_ticket_bulk_batch_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.claim_ticket_bulk_batch_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.claim_ticket_bulk_batch_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.apply_ticket_bulk_target_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  sequence_number integer;
  target_id uuid;
  target_version bigint;
  command_action text;
  job public.ticket_bulk_jobs%ROWTYPE;
  batch public.ticket_bulk_batches%ROWTYPE;
  target public.ticket_bulk_targets%ROWTYPE;
  locked_ticket record;
  permission_key text;
  target_result text;
  applied record;
  next_team_id uuid;
  next_assignee_id uuid;
  next_claimant_id uuid;
  next_state text;
  transition_key text;
  replay_key bytea;
  replay_request bytea;
  applied_at timestamp with time zone := date_trunc('microseconds', transaction_timestamp());
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','binding','sequence',
         'targetId','targetVersion','action'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'binding') <> 'object'
     OR request ->> 'action' NOT IN ('transition','assign','transfer','claim','release') THEN
    RAISE EXCEPTION 'ticket bulk target request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_bulk'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_bulk_binding_v1(request -> 'binding') AS parsed;
  sequence_number := app.private_ticket_runtime_js_uint_v1(
    request -> 'sequence', 1, 100000
  )::integer;
  target_id := app.private_ticket_runtime_uuid_v1(request ->> 'targetId');
  target_version := app.private_ticket_runtime_js_uint_v1(
    request -> 'targetVersion', 1, 9007199254740991
  );
  command_action := request ->> 'action';
  IF admitted_worker_id IS DISTINCT FROM binding.worker_id THEN
    RAISE EXCEPTION 'ticket bulk worker binding is invalid' USING ERRCODE = '42501';
  END IF;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_bulk_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  SELECT candidate.* INTO batch
  FROM public.ticket_bulk_batches AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.job_id = binding.job_id AND candidate.id = binding.batch_id
  FOR UPDATE;
  IF NOT FOUND OR batch.kind IS DISTINCT FROM binding.kind
     OR batch.worker_id IS DISTINCT FROM binding.worker_id
     OR batch.revision IS DISTINCT FROM binding.revision
     OR batch.attempt IS DISTINCT FROM binding.attempt
     OR batch.fence_digest IS DISTINCT FROM binding.fence_digest
     OR batch.target_set_digest IS DISTINCT FROM binding.target_set_digest
     OR batch.projection_version IS DISTINCT FROM binding.projection_version
     OR batch.claimed_at IS DISTINCT FROM binding.claimed_at
     OR batch.lease_expires_at IS DISTINCT FROM binding.lease_expires_at
     OR batch.job_expires_at IS DISTINCT FROM binding.job_expires_at
     OR batch.state IS DISTINCT FROM 'active' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'sequence', sequence_number, 'result', '', 'controlRevision', 0
    );
    RETURN;
  END IF;
  IF job.id IS NULL OR job.kind IS DISTINCT FROM binding.kind
     OR job.target_set_digest IS DISTINCT FROM binding.target_set_digest
     OR job.projection_version IS DISTINCT FROM binding.projection_version
     OR job.expires_at IS DISTINCT FROM binding.job_expires_at
     OR job.mutation ->> 'action' IS DISTINCT FROM command_action THEN
    RAISE EXCEPTION 'ticket bulk job binding is invalid' USING ERRCODE = '55000';
  END IF;
  IF job.state = 'cancellation_requested' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'cancellation_requested',
      'sequence', sequence_number, 'result', '', 'controlRevision', job.revision
    );
    RETURN;
  ELSIF job.state = 'authorization_revoked' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'authorization_revoked',
      'sequence', sequence_number, 'result', '', 'controlRevision', job.revision
    );
    RETURN;
  ELSIF job.state <> 'running' OR job.revision IS DISTINCT FROM binding.revision
        OR NOT job.active_batch OR batch.lease_expires_at <= applied_at THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'sequence', sequence_number, 'result', '', 'controlRevision', 0
    );
    RETURN;
  END IF;
  SELECT candidate.* INTO target
  FROM public.ticket_bulk_targets AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.job_id = binding.job_id
    AND candidate.sequence = sequence_number
  FOR UPDATE;
  IF NOT FOUND OR target.target_id IS DISTINCT FROM target_id
     OR target.target_version IS DISTINCT FROM target_version THEN
    RAISE EXCEPTION 'ticket bulk target binding is invalid' USING ERRCODE = '22023';
  END IF;
  IF target.result IS NOT NULL THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'replayed',
      'sequence', sequence_number, 'result', target.result, 'controlRevision', 0
    );
    RETURN;
  END IF;
  PERFORM set_config('app.user_id', job.requester_user_id::text, true);
  permission_key := app.private_ticket_runtime_permission_v1(job.kind, command_action);
  IF app.current_tenant_membership_id() IS DISTINCT FROM job.owner_membership_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(permission_key) THEN
    IF job.revision >= 9007199254740991 THEN
      RAISE EXCEPTION 'ticket bulk revision is exhausted' USING ERRCODE = '54000';
    END IF;
    PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
    UPDATE public.ticket_bulk_targets
    SET result = 'authorization_revoked', recorded_at = applied_at
    WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
      AND result IS NULL;
    UPDATE public.ticket_bulk_jobs
    SET state = 'authorization_revoked', revision = revision + 1,
        authorization_revoked = authorization_revoked + total - (
          succeeded + no_change + version_conflict + not_found_or_hidden
          + authorization_denied + rejected + cancelled
          + authorization_revoked + internal_failure
        ),
        active_batch = false, updated_at = applied_at, terminal_at = applied_at
    WHERE tenant_id = binding.tenant_id AND id = binding.job_id
      AND state = 'running' AND revision = binding.revision
    RETURNING revision INTO job.revision;
    UPDATE public.ticket_bulk_batches
    SET state = 'terminal', failure_code = 'authorization_revoked',
        completed_at = applied_at
    WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
      AND id = binding.batch_id AND state = 'active';
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'authorization_revoked',
      'sequence', sequence_number, 'result', '', 'controlRevision', job.revision
    );
    RETURN;
  END IF;
  IF job.kind = 'alert' THEN
    SELECT alert.* INTO locked_ticket
    FROM public.alerts AS alert
    WHERE alert.tenant_id = binding.tenant_id AND alert.id = target_id
      AND alert.deleted_at IS NULL
    FOR UPDATE;
  ELSE
    SELECT case_row.* INTO locked_ticket
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = binding.tenant_id AND case_row.id = target_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    target_result := 'not_found_or_hidden';
  ELSIF locked_ticket.version IS DISTINCT FROM target_version
        OR target_version > 2147483646 THEN
    target_result := 'version_conflict';
  ELSE
    next_team_id := locked_ticket.assigned_team_id;
    next_assignee_id := locked_ticket.assignee_user_id;
    next_claimant_id := locked_ticket.claimed_by_user_id;
    next_state := locked_ticket.state_key;
    IF command_action = 'transition' THEN
      transition_key := job.mutation ->> 'transition';
      next_state := job.mutation ->> 'to';
      IF next_state = locked_ticket.state_key THEN target_result := 'no_change'; END IF;
    ELSIF command_action IN ('assign','transfer') THEN
      next_team_id := app.private_ticket_runtime_uuid_v1(job.mutation ->> 'teamId');
      next_assignee_id := app.private_ticket_runtime_uuid_v1(
        job.mutation ->> 'assigneeId', true
      );
      next_claimant_id := NULL;
      IF next_team_id IS NOT DISTINCT FROM locked_ticket.assigned_team_id
         AND next_assignee_id IS NOT DISTINCT FROM locked_ticket.assignee_user_id
         AND locked_ticket.claimed_by_user_id IS NULL THEN
        target_result := 'no_change';
      END IF;
    ELSIF command_action = 'claim' THEN
      next_team_id := app.private_ticket_runtime_uuid_v1(job.mutation ->> 'teamId');
      next_assignee_id := job.requester_user_id;
      next_claimant_id := job.requester_user_id;
      IF locked_ticket.claimed_by_user_id = job.requester_user_id THEN
        target_result := 'no_change';
      END IF;
    ELSE
      next_assignee_id := NULL;
      next_claimant_id := NULL;
      IF locked_ticket.claimed_by_user_id IS NULL THEN target_result := 'no_change'; END IF;
    END IF;
    IF target_result IS NULL THEN
      replay_key := sha256(convert_to(
        binding.batch_id::text || ':' || sequence_number::text, 'UTF8'
      ));
      replay_request := sha256(convert_to(
        binding.job_id::text || ':' || target_id::text || ':'
        || target_version::text || ':' || command_action, 'UTF8'
      ));
      BEGIN
        SELECT result.* INTO STRICT applied
        FROM app.apply_tenant_ticket_mutation_v1(
          job.kind, target_id, command_action,
          target_version::integer, target_version::integer + 1,
          locked_ticket.workflow_id, locked_ticket.workflow_version,
          locked_ticket.state_key, next_state, transition_key,
          locked_ticket.customer_visible,
          next_team_id, next_assignee_id, next_claimant_id,
          'bulk operation', NULL, NULL, '{}'::jsonb,
          CASE WHEN command_action = 'transition' THEN replay_key END,
          CASE WHEN command_action = 'transition' THEN replay_request END,
          binding.batch_id, binding.batch_id, NULL::inet,
          'ticket-bulk-worker', 'system'
        ) AS result;
        IF applied.result_version IS DISTINCT FROM target_version + 1 THEN
          RAISE EXCEPTION 'ticket bulk mutation returned a divergent version'
            USING ERRCODE = '55000';
        END IF;
        target_result := 'succeeded';
      EXCEPTION
        WHEN no_data_found THEN target_result := 'not_found_or_hidden';
        WHEN serialization_failure THEN target_result := 'version_conflict';
        WHEN insufficient_privilege THEN target_result := 'authorization_denied';
        WHEN invalid_parameter_value OR check_violation OR foreign_key_violation
          THEN target_result := 'rejected';
      END;
    END IF;
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_bulk_targets
  SET result = target_result, recorded_at = applied_at
  WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
    AND sequence = sequence_number AND result IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket bulk target result lost its fence' USING ERRCODE = '40001';
  END IF;
  UPDATE public.ticket_bulk_jobs
  SET succeeded = succeeded + CASE WHEN target_result = 'succeeded' THEN 1 ELSE 0 END,
      no_change = no_change + CASE WHEN target_result = 'no_change' THEN 1 ELSE 0 END,
      version_conflict = version_conflict + CASE WHEN target_result = 'version_conflict' THEN 1 ELSE 0 END,
      not_found_or_hidden = not_found_or_hidden + CASE WHEN target_result = 'not_found_or_hidden' THEN 1 ELSE 0 END,
      authorization_denied = authorization_denied + CASE WHEN target_result = 'authorization_denied' THEN 1 ELSE 0 END,
      rejected = rejected + CASE WHEN target_result = 'rejected' THEN 1 ELSE 0 END,
      internal_failure = internal_failure + CASE WHEN target_result = 'internal_failure' THEN 1 ELSE 0 END,
      updated_at = greatest(updated_at, applied_at)
  WHERE tenant_id = binding.tenant_id AND id = binding.job_id
    AND state = 'running' AND revision = binding.revision;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket bulk progress lost its fence' USING ERRCODE = '40001';
  END IF;
  UPDATE public.ticket_bulk_batches
  SET processed = processed + 1
  WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
    AND id = binding.batch_id AND state = 'active'
    AND processed < 100;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket bulk batch progress lost its fence' USING ERRCODE = '40001';
  END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1, 'disposition', 'applied',
    'sequence', sequence_number, 'result', target_result, 'controlRevision', 0
  );
END;
$function$;
ALTER FUNCTION app.apply_ticket_bulk_target_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.apply_ticket_bulk_target_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.apply_ticket_bulk_target_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_runtime_append_system_effects_v1(
  p_tenant_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_resource_version bigint,
  p_occurred_at timestamp with time zone,
  p_outcome text,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_action !~ '^[a-z][a-z0-9_.]{2,127}$'
     OR p_resource_type NOT IN ('ticket_bulk_job','ticket_export_job')
     OR p_resource_id IS NULL
     OR p_resource_version NOT BETWEEN 1 AND 2147483647
     OR p_occurred_at IS NULL
     OR p_outcome NOT IN ('success','failure')
     OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_metadata) > 16384 THEN
    RAISE EXCEPTION 'ticket runtime system effects are invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events(
    tenant_id, sequence, occurred_at, actor_type, action,
    resource_type, resource_id, authentication_method, outcome, metadata
  ) VALUES (
    p_tenant_id, 0, p_occurred_at, 'system', p_action,
    p_resource_type, p_resource_id, 'system', p_outcome,
    p_metadata || jsonb_build_object('contentRedacted', true)
  );
  INSERT INTO public.outbox_events(
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    actor_kind, producer, maximum_audience, occurred_at, available_at
  ) VALUES (
    uuidv7(), p_tenant_id, p_resource_type, p_resource_id,
    p_resource_version::integer, p_action, 1,
    jsonb_build_object(
      'resourceId', p_resource_id,
      'resourceVersion', p_resource_version,
      'contentRedacted', true
    ),
    p_resource_type || ':' || p_resource_id::text || ':'
      || p_resource_version::text || ':' || p_action,
    'system', 'ticket-runtime', 'operator', p_occurred_at, p_occurred_at
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_runtime_append_system_effects_v1(
  uuid, text, text, uuid, bigint, timestamp with time zone, text, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_runtime_append_system_effects_v1(
  uuid, text, text, uuid, bigint, timestamp with time zone, text, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.release_ticket_bulk_batch_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  processed_count integer;
  requested_receipt_digest bytea;
  released_at timestamp with time zone;
  job public.ticket_bulk_jobs%ROWTYPE;
  batch public.ticket_bulk_batches%ROWTYPE;
  disposition text;
  terminal_state text;
  next_revision bigint;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','binding','processed',
         'receiptSha256','releasedAt'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object' THEN
    RAISE EXCEPTION 'ticket bulk release request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_bulk'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_bulk_binding_v1(request -> 'binding') AS parsed;
  processed_count := app.private_ticket_runtime_js_uint_v1(
    request -> 'processed', 1, 100
  )::integer;
  requested_receipt_digest := app.private_ticket_runtime_digest_v1(
    request ->> 'receiptSha256'
  );
  released_at := app.private_ticket_runtime_instant_v1(request -> 'releasedAt');
  IF admitted_worker_id IS DISTINCT FROM binding.worker_id
     OR released_at < binding.claimed_at
     OR released_at > binding.lease_expires_at
     OR released_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket bulk release binding is invalid' USING ERRCODE = '42501';
  END IF;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_bulk_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  SELECT candidate.* INTO batch
  FROM public.ticket_bulk_batches AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.job_id = binding.job_id AND candidate.id = binding.batch_id
  FOR UPDATE;
  IF batch.id IS NULL OR batch.kind IS DISTINCT FROM binding.kind
     OR batch.worker_id IS DISTINCT FROM binding.worker_id
     OR batch.revision IS DISTINCT FROM binding.revision
     OR batch.attempt IS DISTINCT FROM binding.attempt
     OR batch.fence_digest IS DISTINCT FROM binding.fence_digest
     OR batch.target_set_digest IS DISTINCT FROM binding.target_set_digest
     OR batch.projection_version IS DISTINCT FROM binding.projection_version
     OR batch.claimed_at IS DISTINCT FROM binding.claimed_at
     OR batch.lease_expires_at IS DISTINCT FROM binding.lease_expires_at
     OR batch.job_expires_at IS DISTINCT FROM binding.job_expires_at
     OR job.id IS NULL OR job.kind IS DISTINCT FROM binding.kind
     OR job.target_set_digest IS DISTINCT FROM binding.target_set_digest
     OR job.projection_version IS DISTINCT FROM binding.projection_version
     OR job.expires_at IS DISTINCT FROM binding.job_expires_at THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'progress', 'null'::jsonb, 'controlRevision', 0
    );
    RETURN;
  END IF;
  IF batch.receipt_digest IS NOT NULL THEN
    IF batch.receipt_digest IS DISTINCT FROM requested_receipt_digest
       OR batch.processed IS DISTINCT FROM processed_count
       OR batch.completed_at IS DISTINCT FROM released_at THEN
      RAISE EXCEPTION 'ticket bulk release replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    disposition := CASE job.state
      WHEN 'completed' THEN 'job_completed'
      WHEN 'failed' THEN 'job_failed'
      WHEN 'cancellation_requested' THEN 'cancellation_requested'
      WHEN 'authorization_revoked' THEN 'authorization_revoked'
      ELSE 'batch_released'
    END;
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', disposition,
      'progress', CASE WHEN disposition IN ('batch_released','job_completed','job_failed')
        THEN app.private_ticket_bulk_progress_document_v1(job) ELSE 'null'::jsonb END,
      'controlRevision', CASE WHEN disposition IN (
        'cancellation_requested','authorization_revoked'
      ) THEN job.revision ELSE 0 END
    );
    RETURN;
  END IF;
  IF batch.failure_code IS NOT NULL THEN
    RAISE EXCEPTION 'ticket bulk release conflicts with batch failure'
      USING ERRCODE = '23505';
  END IF;
  IF job.state = 'cancellation_requested' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'cancellation_requested',
      'progress', 'null'::jsonb, 'controlRevision', job.revision
    );
    RETURN;
  ELSIF job.state = 'authorization_revoked' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'authorization_revoked',
      'progress', 'null'::jsonb, 'controlRevision', job.revision
    );
    RETURN;
  END IF;
  IF batch.state <> 'active' OR job.state <> 'running'
     OR job.revision IS DISTINCT FROM binding.revision OR NOT job.active_batch
     OR batch.processed IS DISTINCT FROM processed_count THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'progress', 'null'::jsonb, 'controlRevision', 0
    );
    RETURN;
  END IF;
  IF job.revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'ticket bulk revision is exhausted' USING ERRCODE = '54000';
  END IF;
  IF job.succeeded + job.no_change + job.version_conflict
       + job.not_found_or_hidden + job.authorization_denied + job.rejected
       + job.cancelled + job.authorization_revoked + job.internal_failure
       = job.total THEN
    terminal_state := CASE WHEN job.internal_failure > 0 THEN 'failed' ELSE 'completed' END;
    disposition := CASE terminal_state WHEN 'failed' THEN 'job_failed' ELSE 'job_completed' END;
  ELSE
    terminal_state := 'pending';
    disposition := 'batch_released';
  END IF;
  next_revision := job.revision + 1;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_bulk_batches
  SET state = 'released', receipt_digest = requested_receipt_digest,
      completed_at = released_at
  WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
    AND id = binding.batch_id AND state = 'active';
  UPDATE public.ticket_bulk_jobs
  SET state = terminal_state, revision = next_revision, active_batch = false,
      available_at = CASE WHEN terminal_state = 'pending' THEN released_at ELSE available_at END,
      updated_at = released_at,
      terminal_at = CASE WHEN terminal_state IN ('completed','failed') THEN released_at END
  WHERE tenant_id = binding.tenant_id AND id = binding.job_id
    AND state = 'running' AND revision = binding.revision
  RETURNING * INTO job;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    binding.tenant_id,
    CASE disposition
      WHEN 'batch_released' THEN 'ticket.bulk.batch_released'
      WHEN 'job_completed' THEN 'ticket.bulk.completed'
      ELSE 'ticket.bulk.failed'
    END,
    'ticket_bulk_job', binding.job_id, next_revision, released_at,
    CASE WHEN disposition = 'job_failed' THEN 'failure' ELSE 'success' END,
    jsonb_build_object(
      'batchId', binding.batch_id, 'attempt', binding.attempt,
      'processed', processed_count, 'disposition', disposition
    )
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1, 'disposition', disposition,
    'progress', app.private_ticket_bulk_progress_document_v1(job),
    'controlRevision', 0
  );
END;
$function$;
ALTER FUNCTION app.release_ticket_bulk_batch_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.release_ticket_bulk_batch_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.release_ticket_bulk_batch_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.report_ticket_bulk_batch_failure_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  requested_failure_code text;
  failed_at timestamp with time zone;
  requested_retry_at timestamp with time zone;
  job public.ticket_bulk_jobs%ROWTYPE;
  batch public.ticket_bulk_batches%ROWTYPE;
  disposition text;
  next_revision bigint;
  processed_total integer;
  remaining integer;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','binding','code','failedAt','retryAt'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object'
     OR request ->> 'code' NOT IN (
       'transient_database','invalid_projection','lease_safety','interrupted','internal'
     ) OR jsonb_typeof(request -> 'retryAt') NOT IN ('null','string') THEN
    RAISE EXCEPTION 'ticket bulk failure request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_bulk'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_bulk_binding_v1(request -> 'binding') AS parsed;
  requested_failure_code := request ->> 'code';
  failed_at := app.private_ticket_runtime_instant_v1(request -> 'failedAt');
  IF jsonb_typeof(request -> 'retryAt') = 'string' THEN
    requested_retry_at := app.private_ticket_runtime_instant_v1(request -> 'retryAt');
  END IF;
  IF admitted_worker_id IS DISTINCT FROM binding.worker_id
     OR failed_at < binding.claimed_at
     OR failed_at > transaction_timestamp() + interval '1 minute'
     OR requested_failure_code = 'invalid_projection' AND requested_retry_at IS NOT NULL
     OR requested_failure_code <> 'invalid_projection' AND requested_retry_at IS NOT NULL
        AND (requested_retry_at <= failed_at
          OR requested_retry_at - failed_at > interval '24 hours') THEN
    RAISE EXCEPTION 'ticket bulk failure binding is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_bulk_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  SELECT candidate.* INTO batch
  FROM public.ticket_bulk_batches AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.job_id = binding.job_id AND candidate.id = binding.batch_id
  FOR UPDATE;
  IF batch.id IS NULL OR batch.kind IS DISTINCT FROM binding.kind
     OR batch.worker_id IS DISTINCT FROM binding.worker_id
     OR batch.revision IS DISTINCT FROM binding.revision
     OR batch.attempt IS DISTINCT FROM binding.attempt
     OR batch.fence_digest IS DISTINCT FROM binding.fence_digest
     OR batch.target_set_digest IS DISTINCT FROM binding.target_set_digest
     OR batch.projection_version IS DISTINCT FROM binding.projection_version
     OR batch.claimed_at IS DISTINCT FROM binding.claimed_at
     OR batch.lease_expires_at IS DISTINCT FROM binding.lease_expires_at
     OR batch.job_expires_at IS DISTINCT FROM binding.job_expires_at
     OR job.id IS NULL OR job.kind IS DISTINCT FROM binding.kind
     OR job.target_set_digest IS DISTINCT FROM binding.target_set_digest
     OR job.projection_version IS DISTINCT FROM binding.projection_version
     OR job.expires_at IS DISTINCT FROM binding.job_expires_at THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'progress', 'null'::jsonb, 'controlRevision', 0, 'retryAt', 'null'::jsonb
    );
    RETURN;
  END IF;
  IF batch.failure_code IS NOT NULL THEN
    IF batch.failure_code IS DISTINCT FROM requested_failure_code
       OR batch.completed_at IS DISTINCT FROM failed_at
       OR batch.retry_at IS DISTINCT FROM requested_retry_at THEN
      RAISE EXCEPTION 'ticket bulk failure replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    disposition := CASE batch.state
      WHEN 'retry_scheduled' THEN 'replay_retry'
      WHEN 'released' THEN CASE job.state
        WHEN 'completed' THEN 'replay_job_completed'
        WHEN 'failed' THEN 'replay_job_failed'
        ELSE 'replay_batch_released' END
      ELSE CASE job.state
        WHEN 'failed' THEN 'replay_job_failed'
        ELSE 'replay_batch_terminalized' END
    END;
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', disposition,
      'progress', CASE WHEN disposition = 'replay_retry' THEN 'null'::jsonb
        ELSE app.private_ticket_bulk_progress_document_v1(job) END,
      'controlRevision', 0,
      'retryAt', CASE WHEN disposition = 'replay_retry'
        THEN to_jsonb(batch.retry_at) ELSE 'null'::jsonb END
    );
    RETURN;
  END IF;
  IF batch.receipt_digest IS NOT NULL THEN
    RAISE EXCEPTION 'ticket bulk failure conflicts with release'
      USING ERRCODE = '23505';
  END IF;
  IF job.state = 'cancellation_requested' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'cancellation_requested',
      'progress', 'null'::jsonb, 'controlRevision', job.revision,
      'retryAt', 'null'::jsonb
    );
    RETURN;
  ELSIF job.state = 'authorization_revoked' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'authorization_revoked',
      'progress', 'null'::jsonb, 'controlRevision', job.revision,
      'retryAt', 'null'::jsonb
    );
    RETURN;
  END IF;
  IF batch.state <> 'active' OR job.state <> 'running'
     OR job.revision IS DISTINCT FROM binding.revision OR NOT job.active_batch THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'progress', 'null'::jsonb, 'controlRevision', 0, 'retryAt', 'null'::jsonb
    );
    RETURN;
  END IF;
  IF job.revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'ticket bulk revision is exhausted' USING ERRCODE = '54000';
  END IF;
  processed_total := job.succeeded + job.no_change + job.version_conflict
    + job.not_found_or_hidden + job.authorization_denied + job.rejected
    + job.cancelled + job.authorization_revoked + job.internal_failure;
  next_revision := job.revision + 1;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  IF processed_total = job.total THEN
    disposition := CASE WHEN job.internal_failure > 0
      THEN 'job_failed' ELSE 'job_completed' END;
    UPDATE public.ticket_bulk_batches
    SET state = 'released', failure_code = requested_failure_code,
        retry_at = NULL, completed_at = failed_at
    WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
      AND id = binding.batch_id AND state = 'active';
    UPDATE public.ticket_bulk_jobs
    SET state = CASE WHEN disposition = 'job_failed' THEN 'failed' ELSE 'completed' END,
        revision = next_revision, active_batch = false,
        updated_at = failed_at, terminal_at = failed_at
    WHERE tenant_id = binding.tenant_id AND id = binding.job_id
      AND state = 'running' AND revision = binding.revision
    RETURNING * INTO job;
  ELSIF requested_failure_code <> 'invalid_projection'
        AND requested_retry_at IS NOT NULL
        AND binding.attempt < job.maximum_attempts
        AND requested_retry_at < job.expires_at THEN
    disposition := 'retry_scheduled';
    UPDATE public.ticket_bulk_batches
    SET state = 'retry_scheduled', failure_code = requested_failure_code,
        retry_at = requested_retry_at, completed_at = failed_at
    WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
      AND id = binding.batch_id AND state = 'active';
    UPDATE public.ticket_bulk_jobs
    SET state = 'pending', revision = next_revision, active_batch = false,
        available_at = requested_retry_at, updated_at = failed_at
    WHERE tenant_id = binding.tenant_id AND id = binding.job_id
      AND state = 'running' AND revision = binding.revision
    RETURNING * INTO job;
  ELSE
    disposition := 'job_failed';
    remaining := job.total - processed_total;
    UPDATE public.ticket_bulk_targets
    SET result = 'internal_failure', recorded_at = failed_at
    WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
      AND result IS NULL;
    UPDATE public.ticket_bulk_batches
    SET state = 'terminal', failure_code = requested_failure_code,
        retry_at = NULL, completed_at = failed_at
    WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
      AND id = binding.batch_id AND state = 'active';
    UPDATE public.ticket_bulk_jobs
    SET state = 'failed', revision = next_revision, active_batch = false,
        internal_failure = internal_failure + remaining,
        updated_at = failed_at, terminal_at = failed_at
    WHERE tenant_id = binding.tenant_id AND id = binding.job_id
      AND state = 'running' AND revision = binding.revision
    RETURNING * INTO job;
  END IF;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    binding.tenant_id,
    CASE disposition
      WHEN 'retry_scheduled' THEN 'ticket.bulk.retry_scheduled'
      WHEN 'job_completed' THEN 'ticket.bulk.completed'
      ELSE 'ticket.bulk.failed'
    END,
    'ticket_bulk_job', binding.job_id, next_revision, failed_at,
    CASE WHEN disposition = 'job_completed' THEN 'success' ELSE 'failure' END,
    jsonb_build_object(
      'batchId', binding.batch_id, 'attempt', binding.attempt,
      'code', requested_failure_code, 'disposition', disposition
    )
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1, 'disposition', disposition,
    'progress', CASE WHEN disposition = 'retry_scheduled' THEN 'null'::jsonb
      ELSE app.private_ticket_bulk_progress_document_v1(job) END,
    'controlRevision', 0,
    'retryAt', CASE WHEN disposition = 'retry_scheduled'
      THEN to_jsonb(requested_retry_at) ELSE 'null'::jsonb END
  );
END;
$function$;
ALTER FUNCTION app.report_ticket_bulk_batch_failure_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.report_ticket_bulk_batch_failure_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.report_ticket_bulk_batch_failure_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_finalize_ticket_bulk_control_v1(
  request jsonb,
  p_control text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  expected_revision bigint;
  finalized_at timestamp with time zone;
  job public.ticket_bulk_jobs%ROWTYPE;
  batch public.ticket_bulk_batches%ROWTYPE;
  remaining integer;
  result_value text;
  terminal_state text;
BEGIN
  IF p_control NOT IN ('cancellation','authorization_revocation')
     OR request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','binding','expectedRevision','finalizedAt'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object' THEN
    RAISE EXCEPTION 'ticket bulk control request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_bulk'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_bulk_binding_v1(request -> 'binding') AS parsed;
  expected_revision := app.private_ticket_runtime_js_uint_v1(
    request -> 'expectedRevision', 2, 9007199254740991
  );
  finalized_at := app.private_ticket_runtime_instant_v1(request -> 'finalizedAt');
  IF admitted_worker_id IS DISTINCT FROM binding.worker_id
     OR expected_revision <= binding.revision
     OR finalized_at < binding.claimed_at
     OR finalized_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket bulk control binding is invalid' USING ERRCODE = '42501';
  END IF;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_bulk_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  SELECT candidate.* INTO batch
  FROM public.ticket_bulk_batches AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.job_id = binding.job_id AND candidate.id = binding.batch_id
  FOR UPDATE;
  IF batch.id IS NULL OR batch.kind IS DISTINCT FROM binding.kind
     OR batch.worker_id IS DISTINCT FROM binding.worker_id
     OR batch.revision IS DISTINCT FROM binding.revision
     OR batch.attempt IS DISTINCT FROM binding.attempt
     OR batch.fence_digest IS DISTINCT FROM binding.fence_digest
     OR batch.target_set_digest IS DISTINCT FROM binding.target_set_digest
     OR batch.projection_version IS DISTINCT FROM binding.projection_version
     OR batch.claimed_at IS DISTINCT FROM binding.claimed_at
     OR batch.lease_expires_at IS DISTINCT FROM binding.lease_expires_at
     OR batch.job_expires_at IS DISTINCT FROM binding.job_expires_at
     OR job.id IS NULL OR job.revision IS DISTINCT FROM expected_revision THEN
    RETURN jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'progress', 'null'::jsonb, 'controlRevision', 0
    );
  END IF;
  terminal_state := CASE p_control
    WHEN 'cancellation' THEN 'cancelled' ELSE 'authorization_revoked' END;
  result_value := CASE p_control
    WHEN 'cancellation' THEN 'cancelled' ELSE 'authorization_revoked' END;
  IF job.state = terminal_state AND job.terminal_at IS NOT NULL THEN
    RETURN jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'replayed',
      'progress', app.private_ticket_bulk_progress_document_v1(job),
      'controlRevision', expected_revision
    );
  END IF;
  IF p_control = 'cancellation' AND job.state <> 'cancellation_requested'
     OR p_control = 'authorization_revocation' AND job.state <> 'authorization_revoked' THEN
    RETURN jsonb_build_object(
      'schemaVersion', 1, 'disposition', 'fence_lost',
      'progress', 'null'::jsonb, 'controlRevision', 0
    );
  END IF;
  remaining := job.total - (
    job.succeeded + job.no_change + job.version_conflict
    + job.not_found_or_hidden + job.authorization_denied + job.rejected
    + job.cancelled + job.authorization_revoked + job.internal_failure
  );
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_bulk_targets
  SET result = result_value, recorded_at = finalized_at
  WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
    AND result IS NULL;
  UPDATE public.ticket_bulk_jobs
  SET state = terminal_state, active_batch = false,
      cancelled = cancelled + CASE WHEN p_control = 'cancellation' THEN remaining ELSE 0 END,
      authorization_revoked = authorization_revoked
        + CASE WHEN p_control = 'authorization_revocation' THEN remaining ELSE 0 END,
      updated_at = finalized_at, terminal_at = finalized_at
  WHERE tenant_id = binding.tenant_id AND id = binding.job_id
    AND revision = expected_revision
  RETURNING * INTO job;
  UPDATE public.ticket_bulk_batches
  SET state = 'terminal', failure_code = result_value,
      completed_at = finalized_at
  WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
    AND id = binding.batch_id AND state = 'active';
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    binding.tenant_id,
    CASE p_control WHEN 'cancellation' THEN 'ticket.bulk.cancelled'
      ELSE 'ticket.bulk.authorization_revoked' END,
    'ticket_bulk_job', binding.job_id, expected_revision, finalized_at,
    CASE p_control WHEN 'cancellation' THEN 'success' ELSE 'failure' END,
    jsonb_build_object(
      'batchId', binding.batch_id, 'attempt', binding.attempt,
      'remaining', remaining, 'control', p_control
    )
  );
  RETURN jsonb_build_object(
    'schemaVersion', 1, 'disposition', 'applied',
    'progress', app.private_ticket_bulk_progress_document_v1(job),
    'controlRevision', expected_revision
  );
END;
$function$;
ALTER FUNCTION app.private_finalize_ticket_bulk_control_v1(jsonb, text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_finalize_ticket_bulk_control_v1(jsonb, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.finalize_ticket_bulk_cancellation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT app.private_finalize_ticket_bulk_control_v1(request, 'cancellation');
$function$;
ALTER FUNCTION app.finalize_ticket_bulk_cancellation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.finalize_ticket_bulk_cancellation_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.finalize_ticket_bulk_cancellation_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.finalize_ticket_bulk_authorization_revocation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT app.private_finalize_ticket_bulk_control_v1(
    request, 'authorization_revocation'
  );
$function$;
ALTER FUNCTION app.finalize_ticket_bulk_authorization_revocation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.finalize_ticket_bulk_authorization_revocation_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.finalize_ticket_bulk_authorization_revocation_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_require_human_v1(
  p_actor jsonb,
  p_tenant_id uuid,
  p_kind public.ticket_aggregate_kind,
  p_audience text,
  p_capability text
)
RETURNS TABLE(
  actor_id uuid,
  membership_id uuid,
  principal text,
  customer_contact_id uuid,
  public_comments boolean,
  private_comments boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE contact_count integer;
BEGIN
  IF p_audience NOT IN ('operator','customer')
     OR p_capability NOT IN (
       'ticket_export.request','ticket_export.read','ticket_export.cancel'
     ) THEN
    RAISE EXCEPTION 'ticket export capability is invalid' USING ERRCODE = '22023';
  END IF;
  membership_id := app.private_ticket_runtime_require_human_v1(
    p_actor, p_tenant_id
  );
  actor_id := app.context_user_id();
  IF p_audience = 'operator' THEN
    IF NOT app.private_ticket_runtime_has_any_scope_v1(
      app.private_ticket_runtime_permission_v1(p_kind, 'read')
    ) THEN
      RAISE EXCEPTION 'ticket export permission is required' USING ERRCODE = '42501';
    END IF;
    principal := 'operator';
    customer_contact_id := NULL;
    public_comments := true;
    private_comments := true;
  ELSE
    SELECT count(*), min(contact.id)
    INTO contact_count, customer_contact_id
    FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = p_tenant_id
      AND contact.linked_membership_id = membership_id
      AND contact.linked_user_id = actor_id
      AND contact.active AND contact.archived_at IS NULL;
    IF contact_count <> 1 THEN
      RAISE EXCEPTION 'customer ticket export authority is required'
        USING ERRCODE = '42501';
    END IF;
    principal := 'customer';
    public_comments := true;
    private_comments := false;
  END IF;
  RETURN NEXT;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_require_human_v1(
  jsonb, uuid, public.ticket_aggregate_kind, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_require_human_v1(
  jsonb, uuid, public.ticket_aggregate_kind, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.resolve_ticket_export_access_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  request_capability text;
  authority record;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','tenantId','kind','audience','capability'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'actor') <> 'object'
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'capability' NOT IN (
       'ticket_export.request','ticket_export.read','ticket_export.cancel'
     ) THEN
    RAISE EXCEPTION 'ticket export access request is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export kind is invalid' USING ERRCODE = '22023';
  END;
  request_audience := request ->> 'audience';
  request_capability := request ->> 'capability';
  SELECT admitted.* INTO STRICT authority
  FROM app.private_ticket_export_require_human_v1(
    request -> 'actor', request_tenant_id, request_kind,
    request_audience, request_capability
  ) AS admitted;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'tenantId', request_tenant_id,
    'actorId', authority.actor_id,
    'membershipId', authority.membership_id,
    'kind', request_kind,
    'audience', request_audience,
    'capability', request_capability,
    'principal', authority.principal,
    'customerContactId', coalesce(authority.customer_contact_id::text, ''),
    'publicComments', authority.public_comments,
    'privateComments', authority.private_comments,
    'allowed', true
  );
END;
$function$;
ALTER FUNCTION app.resolve_ticket_export_access_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.resolve_ticket_export_access_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.resolve_ticket_export_access_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_resolve_query_v1(
  p_actor jsonb,
  p_tenant_id uuid,
  p_owner_id uuid,
  p_kind public.ticket_aggregate_kind,
  p_audience text,
  p_source jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  authority record;
  source_mode text;
  view_record public.ticket_saved_views%ROWTYPE;
  resolved jsonb;
  spec_base64 text;
  spec_canonical text;
  query_digest bytea;
  catalog_digest bytea;
  saved_view jsonb := 'null'::jsonb;
BEGIN
  SELECT admitted.* INTO STRICT authority
  FROM app.private_ticket_export_require_human_v1(
    p_actor, p_tenant_id, p_kind, p_audience, 'ticket_export.read'
  ) AS admitted;
  IF authority.membership_id IS DISTINCT FROM p_owner_id
     OR jsonb_typeof(p_source) <> 'object' THEN
    RAISE EXCEPTION 'ticket export query authority is required' USING ERRCODE = '42501';
  END IF;
  source_mode := p_source ->> 'mode';
  IF source_mode = 'inline' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(p_source, ARRAY['mode','spec'])
       OR jsonb_typeof(p_source -> 'spec') <> 'object' THEN
      RAISE EXCEPTION 'inline ticket export source is invalid' USING ERRCODE = '22023';
    END IF;
    resolved := app.private_resolve_ticket_saved_view_spec_v1(p_source -> 'spec');
    spec_base64 := resolved ->> 'specCanonicalBase64';
  ELSIF source_mode = 'saved_view' AND p_audience = 'operator' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(
         p_source, ARRAY['mode','id','revision','specSha256']
       ) THEN
      RAISE EXCEPTION 'saved ticket export source is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT view.* INTO view_record
    FROM public.ticket_saved_views AS view
    WHERE view.tenant_id = p_tenant_id
      AND view.id = app.private_ticket_runtime_uuid_v1(p_source ->> 'id')
      AND view.owner_membership_id = p_owner_id
      AND view.aggregate_kind = p_kind
      AND view.status = 'active'
      AND view.revision = app.private_ticket_runtime_js_uint_v1(
        p_source -> 'revision', 1, 9007199254740991
      )
      AND view.spec_digest = app.private_ticket_runtime_digest_v1(
        p_source ->> 'specSha256'
      )
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'saved ticket export source is unavailable' USING ERRCODE = 'P0002';
    END IF;
    spec_canonical := view_record.spec_canonical;
    PERFORM app.private_ticket_saved_view_spec_pins_current_v1(
      p_tenant_id, authority.actor_id, p_owner_id, p_kind, spec_canonical
    );
    spec_base64 := replace(
      encode(convert_to(spec_canonical, 'UTF8'), 'base64'), E'\n', ''
    );
    saved_view := jsonb_build_object(
      'id', view_record.id, 'ownerId', p_owner_id,
      'revision', view_record.revision,
      'specSha256', encode(view_record.spec_digest, 'hex')
    );
  ELSE
    RAISE EXCEPTION 'ticket export source mode is invalid' USING ERRCODE = '22023';
  END IF;
  IF spec_canonical IS NULL THEN
    BEGIN spec_canonical := convert_from(decode(spec_base64, 'base64'), 'UTF8');
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'ticket export canonical source is invalid' USING ERRCODE = '55000';
    END;
  END IF;
  IF p_audience = 'customer' AND (
       (spec_canonical::jsonb #>> '{filters,customerVisible}') IS DISTINCT FROM 'true'
       OR source_mode <> 'inline'
     ) THEN
    RAISE EXCEPTION 'customer ticket export query is not customer-safe'
      USING ERRCODE = '42501';
  END IF;
  query_digest := sha256(convert_to(spec_canonical, 'UTF8'));
  catalog_digest := app.private_ticket_runtime_catalog_digest_v1(spec_canonical);
  RETURN jsonb_build_object(
    'source', source_mode,
    'specCanonicalBase64', spec_base64,
    'querySha256', encode(query_digest, 'hex'),
    'catalogSha256', encode(catalog_digest, 'hex'),
    'savedView', saved_view
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_export_resolve_query_v1(
  jsonb, uuid, uuid, public.ticket_aggregate_kind, text, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_resolve_query_v1(
  jsonb, uuid, uuid, public.ticket_aggregate_kind, text, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.resolve_ticket_export_query_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_owner_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  query_document jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','tenantId','ownerMembershipId',
         'kind','audience','source'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR jsonb_typeof(request -> 'source') <> 'object' THEN
    RAISE EXCEPTION 'ticket export query request is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(
    request ->> 'ownerMembershipId'
  );
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export kind is invalid' USING ERRCODE = '22023';
  END;
  request_audience := request ->> 'audience';
  query_document := app.private_ticket_export_resolve_query_v1(
    request -> 'actor', request_tenant_id, request_owner_id,
    request_kind, request_audience, request -> 'source'
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1, 'query', query_document
  );
END;
$function$;
ALTER FUNCTION app.resolve_ticket_export_query_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.resolve_ticket_export_query_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.resolve_ticket_export_query_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_query_input_v1(p_query jsonb)
RETURNS TABLE(
  source text,
  spec_canonical text,
  query_digest bytea,
  catalog_digest bytea,
  saved_view_id uuid,
  saved_view_owner_id uuid,
  saved_view_revision bigint,
  saved_view_digest bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE saved_view jsonb;
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_query, ARRAY[
         'source','specCanonicalBase64','querySha256','catalogSha256','savedView'
       ]
     ) OR p_query ->> 'source' NOT IN ('inline','saved_view')
     OR jsonb_typeof(p_query -> 'specCanonicalBase64') <> 'string'
     OR jsonb_typeof(p_query -> 'querySha256') <> 'string'
     OR jsonb_typeof(p_query -> 'catalogSha256') <> 'string'
     OR jsonb_typeof(p_query -> 'savedView') NOT IN ('null','object') THEN
    RAISE EXCEPTION 'ticket export query projection is invalid' USING ERRCODE = '22023';
  END IF;
  source := p_query ->> 'source';
  BEGIN
    spec_canonical := convert_from(
      decode(p_query ->> 'specCanonicalBase64', 'base64'), 'UTF8'
    );
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'ticket export canonical query is invalid' USING ERRCODE = '22023';
  END;
  IF octet_length(spec_canonical) NOT BETWEEN 1 AND 262144
     OR jsonb_typeof(spec_canonical::jsonb) <> 'object'
     OR jsonb_array_length(spec_canonical::jsonb -> 'columns') NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'ticket export canonical query is invalid' USING ERRCODE = '22023';
  END IF;
  query_digest := app.private_ticket_runtime_digest_v1(p_query ->> 'querySha256');
  catalog_digest := app.private_ticket_runtime_digest_v1(p_query ->> 'catalogSha256');
  IF query_digest IS DISTINCT FROM sha256(convert_to(spec_canonical, 'UTF8'))
     OR catalog_digest IS DISTINCT FROM
        app.private_ticket_runtime_catalog_digest_v1(spec_canonical) THEN
    RAISE EXCEPTION 'ticket export query digest is stale' USING ERRCODE = '40001';
  END IF;
  saved_view := p_query -> 'savedView';
  IF source = 'inline' THEN
    IF saved_view <> 'null'::jsonb THEN
      RAISE EXCEPTION 'inline ticket export saved view is invalid' USING ERRCODE = '22023';
    END IF;
  ELSE
    IF jsonb_typeof(saved_view) <> 'object'
       OR NOT app.private_ticket_runtime_exact_keys_v1(
         saved_view, ARRAY['id','ownerId','revision','specSha256']
       ) THEN
      RAISE EXCEPTION 'saved ticket export pin is invalid' USING ERRCODE = '22023';
    END IF;
    saved_view_id := app.private_ticket_runtime_uuid_v1(saved_view ->> 'id');
    saved_view_owner_id := app.private_ticket_runtime_uuid_v1(saved_view ->> 'ownerId');
    saved_view_revision := app.private_ticket_runtime_js_uint_v1(
      saved_view -> 'revision', 1, 9007199254740991
    );
    saved_view_digest := app.private_ticket_runtime_digest_v1(
      saved_view ->> 'specSha256'
    );
  END IF;
  RETURN NEXT;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_query_input_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_query_input_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.lookup_ticket_export_replay_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_actor_id uuid;
  request_owner_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  key_digest bytea;
  receipt public.ticket_export_command_receipts%ROWTYPE;
  contact_count integer;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','tenantId','actorId','ownerMembershipId','kind',
         'audience','action','idempotencyKeySha256'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'action' NOT IN ('request','cancel') THEN
    RAISE EXCEPTION 'ticket export replay request is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_actor_id := app.private_ticket_runtime_uuid_v1(request ->> 'actorId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(
    request ->> 'ownerMembershipId'
  );
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export replay kind is invalid' USING ERRCODE = '22023';
  END;
  request_audience := request ->> 'audience';
  key_digest := app.private_ticket_runtime_digest_v1(
    request ->> 'idempotencyKeySha256'
  );
  IF request_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR request_actor_id IS DISTINCT FROM app.context_user_id()
     OR request_owner_id IS DISTINCT FROM app.current_tenant_membership_id() THEN
    RAISE EXCEPTION 'ticket export replay authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT candidate.* INTO receipt
  FROM public.ticket_export_command_receipts AS candidate
  WHERE candidate.tenant_id = request_tenant_id
    AND candidate.actor_user_id = request_actor_id
    AND candidate.owner_membership_id = request_owner_id
    AND candidate.kind = request_kind
    AND candidate.audience = request_audience
    AND candidate.action = request ->> 'action'
    AND candidate.idempotency_key_digest = key_digest;
  IF NOT FOUND THEN RETURN; END IF;
  IF request_audience = 'operator' THEN
    IF NOT app.private_ticket_runtime_has_any_scope_v1(
      app.private_ticket_runtime_permission_v1(request_kind, 'read')
    ) THEN
      RAISE EXCEPTION 'ticket export replay authority is required' USING ERRCODE = '42501';
    END IF;
  ELSE
    SELECT count(*) INTO contact_count
    FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = request_tenant_id
      AND contact.linked_membership_id = request_owner_id
      AND contact.linked_user_id = request_actor_id
      AND contact.active AND contact.archived_at IS NULL;
    IF contact_count <> 1 THEN
      RAISE EXCEPTION 'ticket export replay authority is required' USING ERRCODE = '42501';
    END IF;
  END IF;
  RETURN QUERY SELECT jsonb_set(
    receipt.result_snapshot, '{replayed}', 'true'::jsonb, false
  );
END;
$function$;
ALTER FUNCTION app.lookup_ticket_export_replay_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.lookup_ticket_export_replay_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.lookup_ticket_export_replay_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_export_request_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  next_document jsonb;
  definition jsonb;
  query_input record;
  authority record;
  request_tenant_id uuid;
  request_actor_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  requested_at timestamp with time zone;
  updated_at timestamp with time zone;
  available_at timestamp with time zone;
  expires_at timestamp with time zone;
  customer_contact_id uuid;
  comment_scope text;
  maximum_rows integer;
  maximum_bytes bigint;
  maximum_attempts smallint;
  key_digest bytea;
  fingerprint bytea;
  prior public.ticket_export_command_receipts%ROWTYPE;
  result_document jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','audit','requiredCapability','expectedRevision',
         'next','query','action','idempotencyKeySha256',
         'requestFingerprintSha256'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'requiredCapability' <> 'ticket_export.request'
     OR request ->> 'action' <> 'request'
     OR request ->> 'expectedRevision' <> '0'
     OR jsonb_typeof(request -> 'actor') <> 'object'
     OR NOT app.private_ticket_runtime_audit_is_valid_v1(request -> 'audit')
     OR jsonb_typeof(request -> 'next') <> 'object'
     OR jsonb_typeof(request -> 'query') <> 'object' THEN
    RAISE EXCEPTION 'ticket export request command is invalid' USING ERRCODE = '22023';
  END IF;
  next_document := request -> 'next';
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       next_document, ARRAY[
         'definition','state','revision','attempts','failureCode','requestedAt',
         'updatedAt','availableAt','expiresAt','lease','artifact','terminalAt'
       ]
     ) OR jsonb_typeof(next_document -> 'definition') <> 'object'
     OR jsonb_typeof(next_document -> 'lease') <> 'null'
     OR jsonb_typeof(next_document -> 'artifact') <> 'null'
     OR jsonb_typeof(next_document -> 'terminalAt') <> 'null' THEN
    RAISE EXCEPTION 'ticket export job projection is invalid' USING ERRCODE = '22023';
  END IF;
  definition := next_document -> 'definition';
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       definition, ARRAY[
         'id','tenantId','requesterId','ownerMembershipId','customerContactId',
         'kind','audience','commentScope','querySource','savedView','querySha256',
         'catalogSha256','projectionVersion','format','maximumRows',
         'maximumBytes','maximumAttempts'
       ]
     ) OR definition ->> 'audience' NOT IN ('operator','customer')
     OR definition ->> 'commentScope' NOT IN ('none','public','public_and_private')
     OR definition ->> 'querySource' NOT IN ('inline','saved_view')
     OR definition ->> 'format' <> 'csv' THEN
    RAISE EXCEPTION 'ticket export definition is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(definition ->> 'tenantId');
  request_actor_id := app.private_ticket_runtime_uuid_v1(definition ->> 'requesterId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(
    definition ->> 'ownerMembershipId'
  );
  request_job_id := app.private_ticket_runtime_uuid_v1(definition ->> 'id');
  BEGIN request_kind := (definition ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export kind is invalid' USING ERRCODE = '22023';
  END;
  request_audience := definition ->> 'audience';
  comment_scope := definition ->> 'commentScope';
  customer_contact_id := app.private_ticket_runtime_uuid_v1(
    definition ->> 'customerContactId', true
  );
  maximum_rows := app.private_ticket_runtime_js_uint_v1(
    definition -> 'maximumRows', 1,
    CASE request_audience WHEN 'customer' THEN 10000 ELSE 100000 END
  )::integer;
  maximum_bytes := app.private_ticket_runtime_js_uint_v1(
    definition -> 'maximumBytes', 1,
    CASE request_audience WHEN 'customer' THEN 67108864 ELSE 536870912 END
  );
  maximum_attempts := app.private_ticket_runtime_js_uint_v1(
    definition -> 'maximumAttempts', 1, 5
  )::smallint;
  requested_at := app.private_ticket_runtime_instant_v1(next_document -> 'requestedAt');
  updated_at := app.private_ticket_runtime_instant_v1(next_document -> 'updatedAt');
  available_at := app.private_ticket_runtime_instant_v1(next_document -> 'availableAt');
  expires_at := app.private_ticket_runtime_instant_v1(next_document -> 'expiresAt');
  key_digest := app.private_ticket_runtime_digest_v1(
    request ->> 'idempotencyKeySha256'
  );
  fingerprint := app.private_ticket_runtime_digest_v1(
    request ->> 'requestFingerprintSha256'
  );
  SELECT parsed.* INTO STRICT query_input
  FROM app.private_ticket_export_query_input_v1(request -> 'query') AS parsed;
  SELECT admitted.* INTO STRICT authority
  FROM app.private_ticket_export_require_human_v1(
    request -> 'actor', request_tenant_id, request_kind,
    request_audience, 'ticket_export.request'
  ) AS admitted;
  IF authority.actor_id IS DISTINCT FROM request_actor_id
     OR authority.membership_id IS DISTINCT FROM request_owner_id
     OR authority.customer_contact_id IS DISTINCT FROM customer_contact_id THEN
    RAISE EXCEPTION 'ticket export request authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT receipt.* INTO prior
  FROM public.ticket_export_command_receipts AS receipt
  WHERE receipt.tenant_id = request_tenant_id
    AND receipt.actor_user_id = request_actor_id
    AND receipt.owner_membership_id = request_owner_id
    AND receipt.kind = request_kind AND receipt.audience = request_audience
    AND receipt.action = 'request'
    AND receipt.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF prior.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'ticket export command replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT jsonb_set(
      prior.result_snapshot, '{replayed}', 'true'::jsonb, false
    );
    RETURN;
  END IF;
  IF next_document ->> 'state' <> 'pending'
     OR next_document ->> 'revision' <> '1'
     OR next_document ->> 'attempts' <> '0'
     OR next_document ->> 'failureCode' <> 'none'
     OR updated_at IS DISTINCT FROM requested_at
     OR available_at IS DISTINCT FROM requested_at
     OR expires_at - requested_at NOT BETWEEN interval '15 minutes' AND interval '7 days'
     OR requested_at < transaction_timestamp() - interval '5 minutes'
     OR requested_at > transaction_timestamp() + interval '1 minute'
     OR definition ->> 'querySource' IS DISTINCT FROM query_input.source
     OR app.private_ticket_runtime_digest_v1(definition ->> 'querySha256')
        IS DISTINCT FROM query_input.query_digest
     OR app.private_ticket_runtime_digest_v1(definition ->> 'catalogSha256')
        IS DISTINCT FROM query_input.catalog_digest
     OR definition ->> 'projectionVersion' <> '1'
     OR request_audience = 'customer' AND (
       comment_scope = 'public_and_private' OR query_input.source <> 'inline'
     )
     OR request_audience = 'operator' AND customer_contact_id IS NOT NULL
     OR request_audience = 'customer' AND customer_contact_id IS NULL THEN
    RAISE EXCEPTION 'ticket export request transition is invalid' USING ERRCODE = '22023';
  END IF;
  IF query_input.source = 'saved_view' THEN
    IF query_input.saved_view_owner_id IS DISTINCT FROM request_owner_id
       OR definition -> 'savedView' IS DISTINCT FROM request -> 'query' -> 'savedView' THEN
      RAISE EXCEPTION 'ticket export saved view pin is invalid' USING ERRCODE = '22023';
    END IF;
  ELSIF definition -> 'savedView' <> 'null'::jsonb THEN
    RAISE EXCEPTION 'ticket export saved view pin is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  INSERT INTO public.ticket_export_jobs(
    id, tenant_id, requester_user_id, owner_membership_id, customer_contact_id,
    kind, audience, comment_scope, query_source,
    saved_view_id, saved_view_owner_id, saved_view_revision, saved_view_digest,
    query_digest, catalog_digest, projection_version, format,
    maximum_rows, maximum_bytes, maximum_attempts,
    state, revision, attempts, failure_code,
    requested_at, updated_at, available_at, expires_at
  ) VALUES (
    request_job_id, request_tenant_id, request_actor_id, request_owner_id,
    customer_contact_id, request_kind, request_audience, comment_scope,
    query_input.source, query_input.saved_view_id, query_input.saved_view_owner_id,
    query_input.saved_view_revision, query_input.saved_view_digest,
    query_input.query_digest, query_input.catalog_digest, 1, 'csv',
    maximum_rows, maximum_bytes, maximum_attempts,
    'pending', 1, 0, 'none', requested_at, requested_at, requested_at, expires_at
  );
  INSERT INTO public.ticket_export_query_snapshots(
    tenant_id, job_id, spec_canonical, query_digest, catalog_digest
  ) VALUES (
    request_tenant_id, request_job_id, query_input.spec_canonical,
    query_input.query_digest, query_input.catalog_digest
  );
  result_document := jsonb_build_object(
    'schemaVersion', 1, 'replayed', false,
    'requestFingerprintSha256', encode(fingerprint, 'hex'),
    'record', app.private_ticket_export_record_v1(request_job_id, true)
  );
  INSERT INTO public.ticket_export_command_receipts(
    tenant_id, job_id, actor_user_id, owner_membership_id, kind, audience,
    action, idempotency_key_digest, request_fingerprint_digest,
    result_snapshot, created_at, expires_at
  ) VALUES (
    request_tenant_id, request_job_id, request_actor_id, request_owner_id,
    request_kind, request_audience, 'request', key_digest, fingerprint,
    result_document, requested_at, expires_at
  );
  PERFORM app.private_ticket_runtime_append_human_effects_v1(
    request_tenant_id, request -> 'actor', request -> 'audit',
    'ticket.export.requested', 'ticket_export_job', request_job_id, 1,
    requested_at, jsonb_build_object(
      'kind', request_kind, 'audience', request_audience,
      'commentScope', comment_scope, 'format', 'csv'
    )
  );
  RETURN QUERY SELECT result_document;
END;
$function$;
ALTER FUNCTION app.commit_ticket_export_request_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_export_request_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_export_request_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_ticket_export_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  authority record;
  job public.ticket_export_jobs%ROWTYPE;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','tenantId','ownerMembershipId','kind',
         'audience','capability','jobId'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'capability' NOT IN ('ticket_export.read','ticket_export.cancel') THEN
    RAISE EXCEPTION 'ticket export get request is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(
    request ->> 'ownerMembershipId'
  );
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export get kind is invalid' USING ERRCODE = '22023';
  END;
  request_audience := request ->> 'audience';
  SELECT admitted.* INTO STRICT authority
  FROM app.private_ticket_export_require_human_v1(
    request -> 'actor', request_tenant_id, request_kind,
    request_audience, request ->> 'capability'
  ) AS admitted;
  IF authority.membership_id IS DISTINCT FROM request_owner_id THEN
    RAISE EXCEPTION 'ticket export get authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id AND candidate.id = request_job_id
    AND candidate.owner_membership_id = request_owner_id
    AND candidate.requester_user_id = authority.actor_id
    AND candidate.kind = request_kind AND candidate.audience = request_audience
    AND candidate.customer_contact_id IS NOT DISTINCT FROM authority.customer_contact_id;
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'record', app.private_ticket_export_record_v1(job.id, true)
  );
END;
$function$;
ALTER FUNCTION app.get_ticket_export_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.get_ticket_export_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.get_ticket_export_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_export_owner_transition_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  next_document jsonb;
  definition jsonb;
  request_tenant_id uuid;
  request_actor_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  expected_revision bigint;
  next_revision bigint;
  changed_at timestamp with time zone;
  key_digest bytea;
  fingerprint bytea;
  authority record;
  prior public.ticket_export_command_receipts%ROWTYPE;
  job public.ticket_export_jobs%ROWTYPE;
  result_document jsonb;
  terminal boolean;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','audit','requiredCapability','expectedRevision',
         'next','query','action','idempotencyKeySha256',
         'requestFingerprintSha256'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'requiredCapability' <> 'ticket_export.cancel'
     OR request ->> 'action' <> 'cancel'
     OR jsonb_typeof(request -> 'next') <> 'object'
     OR jsonb_typeof(request -> 'query') <> 'object'
     OR NOT app.private_ticket_runtime_audit_is_valid_v1(request -> 'audit') THEN
    RAISE EXCEPTION 'ticket export owner transition is invalid' USING ERRCODE = '22023';
  END IF;
  next_document := request -> 'next';
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       next_document, ARRAY[
         'definition','state','revision','attempts','failureCode','requestedAt',
         'updatedAt','availableAt','expiresAt','lease','artifact','terminalAt'
       ]
     ) OR jsonb_typeof(next_document -> 'definition') <> 'object' THEN
    RAISE EXCEPTION 'ticket export owner projection is invalid' USING ERRCODE = '22023';
  END IF;
  definition := next_document -> 'definition';
  request_tenant_id := app.private_ticket_runtime_uuid_v1(definition ->> 'tenantId');
  request_actor_id := app.private_ticket_runtime_uuid_v1(definition ->> 'requesterId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(
    definition ->> 'ownerMembershipId'
  );
  request_job_id := app.private_ticket_runtime_uuid_v1(definition ->> 'id');
  BEGIN request_kind := (definition ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export owner kind is invalid' USING ERRCODE = '22023';
  END;
  request_audience := definition ->> 'audience';
  IF request_audience NOT IN ('operator','customer') THEN
    RAISE EXCEPTION 'ticket export owner audience is invalid' USING ERRCODE = '22023';
  END IF;
  expected_revision := app.private_ticket_runtime_js_uint_v1(
    request -> 'expectedRevision', 1, 9007199254740990
  );
  next_revision := app.private_ticket_runtime_js_uint_v1(
    next_document -> 'revision', 2, 9007199254740991
  );
  changed_at := app.private_ticket_runtime_instant_v1(next_document -> 'updatedAt');
  key_digest := app.private_ticket_runtime_digest_v1(
    request ->> 'idempotencyKeySha256'
  );
  fingerprint := app.private_ticket_runtime_digest_v1(
    request ->> 'requestFingerprintSha256'
  );
  SELECT admitted.* INTO STRICT authority
  FROM app.private_ticket_export_require_human_v1(
    request -> 'actor', request_tenant_id, request_kind,
    request_audience, 'ticket_export.cancel'
  ) AS admitted;
  IF authority.actor_id IS DISTINCT FROM request_actor_id
     OR authority.membership_id IS DISTINCT FROM request_owner_id THEN
    RAISE EXCEPTION 'ticket export owner authority is required' USING ERRCODE = '42501';
  END IF;
  SELECT receipt.* INTO prior
  FROM public.ticket_export_command_receipts AS receipt
  WHERE receipt.tenant_id = request_tenant_id
    AND receipt.actor_user_id = request_actor_id
    AND receipt.owner_membership_id = request_owner_id
    AND receipt.kind = request_kind AND receipt.audience = request_audience
    AND receipt.action = 'cancel'
    AND receipt.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF prior.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'ticket export command replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT jsonb_set(
      prior.result_snapshot, '{replayed}', 'true'::jsonb, false
    );
    RETURN;
  END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id AND candidate.id = request_job_id
  FOR UPDATE;
  IF NOT FOUND OR job.requester_user_id IS DISTINCT FROM request_actor_id
     OR job.owner_membership_id IS DISTINCT FROM request_owner_id
     OR job.kind IS DISTINCT FROM request_kind
     OR job.audience IS DISTINCT FROM request_audience
     OR job.customer_contact_id IS DISTINCT FROM authority.customer_contact_id THEN
    RAISE EXCEPTION 'ticket export job is unavailable' USING ERRCODE = 'P0002';
  END IF;
  IF job.revision IS DISTINCT FROM expected_revision
     OR next_revision IS DISTINCT FROM expected_revision + 1 THEN
    RAISE EXCEPTION 'ticket export revision conflict' USING ERRCODE = '40001';
  END IF;
  terminal := job.state = 'pending';
  IF job.state NOT IN ('pending','running')
     OR changed_at < job.updated_at
     OR changed_at > transaction_timestamp() + interval '1 minute'
     OR next_document -> 'definition' IS DISTINCT FROM
        app.private_ticket_export_job_document_v1(job) -> 'definition'
     OR request -> 'query' IS DISTINCT FROM app.private_ticket_export_query_document_v1(job)
     OR app.private_ticket_runtime_instant_v1(next_document -> 'requestedAt')
        IS DISTINCT FROM job.requested_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'availableAt')
        IS DISTINCT FROM job.available_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'expiresAt')
        IS DISTINCT FROM job.expires_at
     OR next_document ->> 'attempts' IS DISTINCT FROM job.attempts::text
     OR next_document ->> 'failureCode' IS DISTINCT FROM job.failure_code
     OR next_document -> 'lease' IS DISTINCT FROM
        app.private_ticket_export_job_document_v1(job) -> 'lease'
     OR next_document -> 'artifact' IS DISTINCT FROM
        app.private_ticket_export_job_document_v1(job) -> 'artifact'
     OR next_document ->> 'state' IS DISTINCT FROM
        (CASE WHEN terminal THEN 'cancelled' ELSE 'cancellation_requested' END)
     OR terminal AND (
       jsonb_typeof(next_document -> 'terminalAt') <> 'string'
       OR app.private_ticket_runtime_instant_v1(next_document -> 'terminalAt')
          IS DISTINCT FROM changed_at
     )
     OR NOT terminal AND next_document -> 'terminalAt' <> 'null'::jsonb THEN
    RAISE EXCEPTION 'ticket export owner transition is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_export_jobs
  SET state = CASE WHEN terminal THEN 'cancelled' ELSE 'cancellation_requested' END,
      revision = next_revision, updated_at = changed_at,
      terminal_at = CASE WHEN terminal THEN changed_at END
  WHERE tenant_id = request_tenant_id AND id = request_job_id;
  result_document := jsonb_build_object(
    'schemaVersion', 1, 'replayed', false,
    'requestFingerprintSha256', encode(fingerprint, 'hex'),
    'record', app.private_ticket_export_record_v1(request_job_id, true)
  );
  INSERT INTO public.ticket_export_command_receipts(
    tenant_id, job_id, actor_user_id, owner_membership_id, kind, audience,
    action, idempotency_key_digest, request_fingerprint_digest,
    result_snapshot, created_at, expires_at
  ) VALUES (
    request_tenant_id, request_job_id, request_actor_id, request_owner_id,
    request_kind, request_audience, 'cancel', key_digest, fingerprint,
    result_document, changed_at, job.expires_at
  );
  PERFORM app.private_ticket_runtime_append_human_effects_v1(
    request_tenant_id, request -> 'actor', request -> 'audit',
    CASE WHEN terminal THEN 'ticket.export.cancelled'
      ELSE 'ticket.export.cancellation_requested' END,
    'ticket_export_job', request_job_id, next_revision, changed_at,
    jsonb_build_object(
      'kind', request_kind, 'audience', request_audience, 'terminal', terminal
    )
  );
  RETURN QUERY SELECT result_document;
END;
$function$;
ALTER FUNCTION app.commit_ticket_export_owner_transition_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_export_owner_transition_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_export_owner_transition_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_requester_live_v1(
  p_job public.ticket_export_jobs
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE membership_live boolean;
BEGIN
  IF p_job.tenant_id IS DISTINCT FROM app.context_tenant_id() THEN RETURN false; END IF;
  SELECT membership.status = 'active' AND account.status = 'active'
  INTO membership_live
  FROM public.tenant_memberships AS membership
  JOIN public.users AS account ON account.id = membership.user_id
  WHERE membership.tenant_id = p_job.tenant_id
    AND membership.id = p_job.owner_membership_id
    AND membership.user_id = p_job.requester_user_id;
  IF coalesce(membership_live, false) IS NOT TRUE THEN RETURN false; END IF;
  PERFORM set_config('app.user_id', p_job.requester_user_id::text, true);
  IF p_job.audience = 'operator' THEN
    RETURN app.current_tenant_membership_id() IS NOT DISTINCT FROM p_job.owner_membership_id
      AND app.private_ticket_runtime_has_any_scope_v1(
        app.private_ticket_runtime_permission_v1(p_job.kind, 'read')
      );
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = p_job.tenant_id
      AND contact.id = p_job.customer_contact_id
      AND contact.linked_membership_id = p_job.owner_membership_id
      AND contact.linked_user_id = p_job.requester_user_id
      AND contact.active AND contact.archived_at IS NULL
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_header_v1(
  p_job public.ticket_export_jobs
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE snapshot public.ticket_export_query_snapshots%ROWTYPE;
DECLARE header jsonb;
BEGIN
  SELECT candidate.* INTO STRICT snapshot
  FROM public.ticket_export_query_snapshots AS candidate
  WHERE candidate.tenant_id = p_job.tenant_id AND candidate.job_id = p_job.id;
  SELECT jsonb_agg(
    CASE item ->> 'source'
      WHEN 'core' THEN item ->> 'coreKey'
      WHEN 'custom_field' THEN item #>> '{definition,key}'
      WHEN 'sla' THEN item #>> '{definition,key}'
      ELSE NULL
    END ORDER BY ordinal
  ) INTO header
  FROM jsonb_array_elements(snapshot.spec_canonical::jsonb -> 'columns')
       WITH ORDINALITY AS column_item(item, ordinal);
  IF jsonb_typeof(header) <> 'array'
     OR jsonb_array_length(header) NOT BETWEEN 1 AND 64
     OR EXISTS (
       SELECT 1 FROM jsonb_array_elements(header) AS item(value)
       WHERE jsonb_typeof(item.value) <> 'string'
         OR octet_length(item.value #>> '{}') NOT BETWEEN 1 AND 256
     ) THEN
    RAISE EXCEPTION 'ticket export header is invalid' USING ERRCODE = '55000';
  END IF;
  RETURN header;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_header_v1(public.ticket_export_jobs)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_header_v1(public.ticket_export_jobs)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_binding_v1(p_binding jsonb)
RETURNS TABLE(
  tenant_id uuid,
  job_id uuid,
  kind public.ticket_aggregate_kind,
  audience text,
  worker_id uuid,
  revision bigint,
  attempt smallint,
  fence_digest bytea,
  query_digest bytea,
  catalog_digest bytea,
  projection_version bigint,
  lease_claimed_at timestamp with time zone,
  lease_expires_at timestamp with time zone,
  job_expires_at timestamp with time zone
)
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_binding, ARRAY[
         'tenantId','jobId','kind','audience','workerId','revision','attempt',
         'fenceSha256','querySha256','catalogSha256','projectionVersion',
         'leaseClaimedAt','leaseExpiresAt','jobExpiresAt'
       ]
     ) OR p_binding ->> 'kind' NOT IN ('alert','case')
     OR p_binding ->> 'audience' NOT IN ('operator','customer') THEN
    RAISE EXCEPTION 'ticket export binding is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_runtime_uuid_v1(p_binding ->> 'tenantId');
  job_id := app.private_ticket_runtime_uuid_v1(p_binding ->> 'jobId');
  kind := (p_binding ->> 'kind')::public.ticket_aggregate_kind;
  audience := p_binding ->> 'audience';
  worker_id := app.private_ticket_runtime_uuid_v1(p_binding ->> 'workerId');
  revision := app.private_ticket_runtime_js_uint_v1(
    p_binding -> 'revision', 2, 9007199254740991
  );
  attempt := app.private_ticket_runtime_js_uint_v1(
    p_binding -> 'attempt', 1, 5
  )::smallint;
  fence_digest := app.private_ticket_runtime_digest_v1(p_binding ->> 'fenceSha256');
  query_digest := app.private_ticket_runtime_digest_v1(p_binding ->> 'querySha256');
  catalog_digest := app.private_ticket_runtime_digest_v1(p_binding ->> 'catalogSha256');
  projection_version := app.private_ticket_runtime_js_uint_v1(
    p_binding -> 'projectionVersion', 1, 1
  );
  lease_claimed_at := app.private_ticket_runtime_instant_v1(
    p_binding -> 'leaseClaimedAt'
  );
  lease_expires_at := app.private_ticket_runtime_instant_v1(
    p_binding -> 'leaseExpiresAt'
  );
  job_expires_at := app.private_ticket_runtime_instant_v1(
    p_binding -> 'jobExpiresAt'
  );
  IF lease_expires_at - lease_claimed_at NOT BETWEEN
       interval '30 seconds' AND interval '15 minutes'
     OR job_expires_at < lease_expires_at THEN
    RAISE EXCEPTION 'ticket export binding lifetime is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN NEXT;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_binding_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_binding_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.resolve_ticket_export_worker_access_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE service_account_id uuid;
DECLARE worker_id uuid;
DECLARE request_tenant_id uuid;
DECLARE request_kind public.ticket_aggregate_kind;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 8192
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','serviceAccountId','workerId','purpose','tenantId',
         'kind','audience','capability'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'purpose' <> 'ticket_export'
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'capability' NOT IN ('ticket_export.claim','ticket_export.execute') THEN
    RAISE EXCEPTION 'ticket export worker access is invalid' USING ERRCODE = '22023';
  END IF;
  service_account_id := app.private_ticket_runtime_uuid_v1(
    request ->> 'serviceAccountId'
  );
  worker_id := app.private_ticket_runtime_require_worker_v1(
    jsonb_build_object(
      'serviceAccountId', service_account_id,
      'workerId', request ->> 'workerId',
      'purpose', request ->> 'purpose'
    ), 'ticket_export'
  );
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export worker kind is invalid' USING ERRCODE = '22023';
  END;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'serviceAccountId', service_account_id,
    'tenantId', request_tenant_id,
    'kind', request_kind,
    'audience', request ->> 'audience',
    'capability', request ->> 'capability',
    'allowed', true
  );
END;
$function$;
ALTER FUNCTION app.resolve_ticket_export_worker_access_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.resolve_ticket_export_worker_access_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.resolve_ticket_export_worker_access_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.claim_ticket_export_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  admitted_worker_id uuid;
  request_tenant_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  requested_artifact_id uuid;
  observed_at timestamp with time zone;
  lease_microseconds bigint;
  lease_until timestamp with time zone;
  lease_fence bytea;
  job public.ticket_export_jobs%ROWTYPE;
  snapshot public.ticket_export_query_snapshots%ROWTYPE;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','tenantId','kind','audience','artifactId',
         'now','leaseMicroseconds'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer') THEN
    RAISE EXCEPTION 'ticket export claim request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export'
  );
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  request_audience := request ->> 'audience';
  requested_artifact_id := app.private_ticket_runtime_uuid_v1(request ->> 'artifactId');
  observed_at := app.private_ticket_runtime_instant_v1(request -> 'now');
  lease_microseconds := app.private_ticket_runtime_js_uint_v1(
    request -> 'leaseMicroseconds', 30000000, 900000000
  );
  IF observed_at < transaction_timestamp() - interval '5 minutes'
     OR observed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket export claim time is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', request_tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id
    AND candidate.kind = request_kind AND candidate.audience = request_audience
    AND candidate.expires_at > observed_at
    AND (
      candidate.state = 'pending' AND candidate.available_at <= observed_at
      OR candidate.state = 'running' AND candidate.lease_expires_at <= observed_at
    )
  ORDER BY candidate.available_at, candidate.id
  FOR UPDATE SKIP LOCKED
  LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  IF job.revision >= 9007199254740991 OR job.attempts >= job.maximum_attempts THEN
    PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
    UPDATE public.ticket_export_jobs
    SET state = 'failed', revision = least(revision + 1, 9007199254740991),
        failure_code = 'lease_expired', updated_at = observed_at,
        lease_worker_id = NULL, lease_fence_digest = NULL,
        lease_claimed_at = NULL, lease_expires_at = NULL,
        terminal_at = observed_at
    WHERE tenant_id = job.tenant_id AND id = job.id;
    RETURN;
  END IF;
  IF NOT app.private_ticket_export_requester_live_v1(job) THEN
    PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
    UPDATE public.ticket_export_jobs
    SET state = 'failed', revision = revision + 1,
        failure_code = 'authorization_revoked', updated_at = observed_at,
        lease_worker_id = NULL, lease_fence_digest = NULL,
        lease_claimed_at = NULL, lease_expires_at = NULL,
        terminal_at = observed_at
    WHERE tenant_id = job.tenant_id AND id = job.id;
    RETURN;
  END IF;
  SELECT candidate.* INTO STRICT snapshot
  FROM public.ticket_export_query_snapshots AS candidate
  WHERE candidate.tenant_id = job.tenant_id AND candidate.job_id = job.id;
  IF snapshot.query_digest IS DISTINCT FROM job.query_digest
     OR snapshot.catalog_digest IS DISTINCT FROM job.catalog_digest
     OR app.private_ticket_runtime_catalog_digest_v1(snapshot.spec_canonical)
        IS DISTINCT FROM job.catalog_digest THEN
    PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
    UPDATE public.ticket_export_jobs
    SET state = 'failed', revision = revision + 1,
        failure_code = 'snapshot_stale', updated_at = observed_at,
        lease_worker_id = NULL, lease_fence_digest = NULL,
        lease_claimed_at = NULL, lease_expires_at = NULL,
        terminal_at = observed_at
    WHERE tenant_id = job.tenant_id AND id = job.id;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.ticket_export_manifests AS manifest
    WHERE manifest.artifact_id = requested_artifact_id
  ) THEN
    RAISE EXCEPTION 'ticket export artifact is already reserved' USING ERRCODE = '23505';
  END IF;
  lease_until := observed_at
    + make_interval(secs => lease_microseconds::double precision / 1000000.0);
  IF lease_until > job.expires_at THEN RETURN; END IF;
  lease_fence := sha256(convert_to(
    job.id::text || ':' || requested_artifact_id::text || ':'
      || admitted_worker_id::text || ':' || clock_timestamp()::text, 'UTF8'
  ));
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_export_jobs
  SET state = 'running', revision = revision + 1, attempts = attempts + 1,
      failure_code = 'none', updated_at = observed_at,
      lease_worker_id = admitted_worker_id, lease_fence_digest = lease_fence,
      lease_claimed_at = observed_at, lease_expires_at = lease_until,
      artifact_id = NULL, artifact_digest = NULL, artifact_rows = NULL,
      artifact_bytes = NULL, artifact_expires_at = NULL, terminal_at = NULL
  WHERE tenant_id = job.tenant_id AND id = job.id
  RETURNING * INTO job;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    job.tenant_id, 'ticket.export.claimed', 'ticket_export_job', job.id,
    job.revision, observed_at, 'success', jsonb_build_object(
      'artifactId', requested_artifact_id,
      'attempt', job.attempts,
      'fenceProofSha256', encode(sha256(job.lease_fence_digest), 'hex'),
      'projectionVersion', job.projection_version
    )
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'job', app.private_ticket_export_job_document_v1(job),
    'artifactId', requested_artifact_id,
    'header', app.private_ticket_export_header_v1(job),
    'observedAt', observed_at
  );
END;
$function$;
ALTER FUNCTION app.claim_ticket_export_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.claim_ticket_export_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.claim_ticket_export_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_cell_v1(
  p_job public.ticket_export_jobs,
  p_ticket_id uuid,
  p_comment_id uuid,
  p_column jsonb
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE value text := '';
DECLARE core_key text;
DECLARE definition_id uuid;
DECLARE definition_version bigint;
BEGIN
  IF p_column ->> 'source' = 'core' THEN
    core_key := p_column ->> 'coreKey';
    IF p_comment_id IS NOT NULL THEN
      SELECT CASE core_key
        WHEN 'ticket' THEN comment.body_markdown
        WHEN 'customer_visibility' THEN comment.visibility
        WHEN 'created' THEN to_char(comment.created_at AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        WHEN 'updated' THEN to_char(comment.updated_at AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        ELSE '' END
      INTO value
      FROM public.ticket_comments AS comment
      WHERE comment.tenant_id = p_job.tenant_id AND comment.id = p_comment_id;
    ELSIF p_job.kind = 'alert' THEN
      SELECT CASE core_key
        WHEN 'ticket' THEN coalesce(alert.number, alert.id::text)
        WHEN 'state' THEN alert.state_key
        WHEN 'risk' THEN alert.severity::text
        WHEN 'assignment' THEN coalesce(alert.assignee_user_id::text,
          alert.assigned_team_id::text, '')
        WHEN 'category' THEN coalesce(alert.category, '')
        WHEN 'source' THEN coalesce(alert.source, '')
        WHEN 'customer_visibility' THEN alert.customer_visible::text
        WHEN 'created' THEN to_char(alert.created_at AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        WHEN 'updated' THEN to_char(alert.updated_at AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        ELSE '' END
      INTO value
      FROM public.alerts AS alert
      WHERE alert.tenant_id = p_job.tenant_id AND alert.id = p_ticket_id
        AND alert.deleted_at IS NULL;
    ELSE
      SELECT CASE core_key
        WHEN 'ticket' THEN coalesce(case_row.number, case_row.id::text)
        WHEN 'state' THEN case_row.state_key
        WHEN 'risk' THEN case_row.severity::text
        WHEN 'assignment' THEN coalesce(case_row.assignee_user_id::text,
          case_row.assigned_team_id::text, '')
        WHEN 'category' THEN coalesce(case_row.category, '')
        WHEN 'source' THEN ''
        WHEN 'customer_visibility' THEN case_row.customer_visible::text
        WHEN 'created' THEN to_char(case_row.created_at AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        WHEN 'updated' THEN to_char(case_row.updated_at AT TIME ZONE 'UTC',
          'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
        ELSE '' END
      INTO value
      FROM public.cases AS case_row
      WHERE case_row.tenant_id = p_job.tenant_id AND case_row.id = p_ticket_id;
    END IF;
  ELSIF p_comment_id IS NULL AND p_column ->> 'source' = 'custom_field' THEN
    definition_id := app.private_ticket_runtime_uuid_v1(
      p_column #>> '{definition,id}'
    );
    definition_version := app.private_ticket_runtime_js_uint_v1(
      p_column #> '{definition,version}', 1, 9007199254740991
    );
    SELECT coalesce(field.canonical_value::text, '') INTO value
    FROM public.custom_field_values AS field
    WHERE field.tenant_id = p_job.tenant_id
      AND field.object_type = p_job.kind::text
      AND field.alert_id IS NOT DISTINCT FROM
        CASE WHEN p_job.kind = 'alert' THEN p_ticket_id END
      AND field.case_id IS NOT DISTINCT FROM
        CASE WHEN p_job.kind = 'case' THEN p_ticket_id END
      AND field.definition_id = definition_id
      AND field.definition_schema_version = definition_version;
  ELSIF p_comment_id IS NULL AND p_column ->> 'source' = 'sla' THEN
    definition_id := app.private_ticket_runtime_uuid_v1(
      p_column #>> '{definition,id}'
    );
    definition_version := app.private_ticket_runtime_js_uint_v1(
      p_column #> '{definition,version}', 1, 9007199254740991
    );
    SELECT coalesce(
      materialized.state_value,
      to_char(materialized.instant_value AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
      materialized.duration_micros_value::text,
      materialized.percentage_value::text,
      ''
    ) INTO value
    FROM public.sla_materialized_column_values AS materialized
    WHERE materialized.tenant_id = p_job.tenant_id
      AND materialized.object_type = p_job.kind::text
      AND materialized.object_id = p_ticket_id
      AND materialized.column_id = definition_id
      AND materialized.column_version = definition_version;
  END IF;
  value := coalesce(value, '');
  value := replace(replace(value, chr(8234), ''), chr(8235), '');
  RETURN left(value, 32768);
END;
$function$;
ALTER FUNCTION app.private_ticket_export_cell_v1(
  public.ticket_export_jobs, uuid, uuid, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_cell_v1(
  public.ticket_export_jobs, uuid, uuid, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_page_document_v1(
  p_job public.ticket_export_jobs,
  p_after text,
  p_limit integer,
  p_snapshot_keys boolean
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  snapshot public.ticket_export_query_snapshots%ROWTYPE;
  document jsonb;
  filters jsonb;
  cursor_offset bigint := 0;
  rows_document jsonb;
  selected_count integer;
  admitted_count integer;
  next_cursor text := '';
  permission_key text;
BEGIN
  IF p_limit NOT BETWEEN 1 AND 1000 OR p_after IS NULL
     OR octet_length(p_after) > 128
     OR p_after <> '' AND p_after !~ '^[0-9a-f]{16}$' THEN
    RAISE EXCEPTION 'ticket export page cursor is invalid' USING ERRCODE = '22023';
  END IF;
  IF p_after <> '' THEN
    cursor_offset := ('x' || p_after)::bit(64)::bigint;
    IF cursor_offset < 0 THEN
      RAISE EXCEPTION 'ticket export page cursor is invalid' USING ERRCODE = '22023';
    END IF;
  END IF;
  SELECT candidate.* INTO STRICT snapshot
  FROM public.ticket_export_query_snapshots AS candidate
  WHERE candidate.tenant_id = p_job.tenant_id AND candidate.job_id = p_job.id;
  document := snapshot.spec_canonical::jsonb;
  filters := document -> 'filters';
  permission_key := app.private_ticket_runtime_permission_v1(p_job.kind, 'read');
  IF jsonb_typeof(filters) <> 'object'
     OR jsonb_typeof(document -> 'columns') <> 'array' THEN
    RAISE EXCEPTION 'ticket export snapshot is malformed' USING ERRCODE = '55000';
  END IF;
  WITH ticket_rows AS (
    SELECT alert.id AS ticket_id, NULL::uuid AS comment_id,
      0 AS row_rank, alert.id AS row_id, alert.version::bigint AS row_revision
    FROM public.alerts AS alert
    WHERE p_job.kind = 'alert' AND alert.tenant_id = p_job.tenant_id
      AND alert.deleted_at IS NULL
      AND (p_job.audience = 'customer' AND alert.customer_visible AND EXISTS (
        SELECT 1 FROM public.ticket_customer_contacts AS link
        WHERE link.tenant_id = p_job.tenant_id AND link.alert_id = alert.id
          AND link.case_id IS NULL AND link.contact_id = p_job.customer_contact_id
          AND link.archived_at IS NULL
      ) OR p_job.audience = 'operator' AND app.private_current_ticket_scope_allows_v1(
        permission_key, alert.assigned_team_id, alert.created_by,
        alert.assignee_user_id, alert.claimed_by_user_id
      ))
      AND (jsonb_array_length(filters -> 'states') = 0 OR alert.state_key IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'states') AS value
      ))
      AND (jsonb_array_length(filters -> 'severities') = 0 OR alert.severity::text IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'severities') AS value
      ))
      AND (jsonb_array_length(filters -> 'priorities') = 0 OR alert.priority IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'priorities') AS value
      ))
      AND (NOT filters ? 'customerVisible'
        OR alert.customer_visible = (filters ->> 'customerVisible')::boolean)
      AND (NOT filters ? 'search' OR to_tsvector(
        'simple', coalesce(alert.number,'') || ' ' || coalesce(alert.title,'')
          || ' ' || coalesce(alert.description,'')
      ) @@ plainto_tsquery('simple', filters ->> 'search'))
    UNION ALL
    SELECT case_row.id, NULL::uuid, 0, case_row.id, case_row.version::bigint
    FROM public.cases AS case_row
    WHERE p_job.kind = 'case' AND case_row.tenant_id = p_job.tenant_id
      AND (p_job.audience = 'customer' AND case_row.customer_visible AND EXISTS (
        SELECT 1 FROM public.ticket_customer_contacts AS link
        WHERE link.tenant_id = p_job.tenant_id AND link.case_id = case_row.id
          AND link.alert_id IS NULL AND link.contact_id = p_job.customer_contact_id
          AND link.archived_at IS NULL
      ) OR p_job.audience = 'operator' AND app.private_current_ticket_scope_allows_v1(
        permission_key, case_row.assigned_team_id, case_row.created_by_user_id,
        case_row.assignee_user_id, case_row.claimed_by_user_id
      ))
      AND (jsonb_array_length(filters -> 'states') = 0 OR case_row.state_key IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'states') AS value
      ))
      AND (jsonb_array_length(filters -> 'severities') = 0 OR case_row.severity::text IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'severities') AS value
      ))
      AND (jsonb_array_length(filters -> 'priorities') = 0 OR case_row.priority IN (
        SELECT value FROM jsonb_array_elements_text(filters -> 'priorities') AS value
      ))
      AND (NOT filters ? 'customerVisible'
        OR case_row.customer_visible = (filters ->> 'customerVisible')::boolean)
      AND (NOT filters ? 'search' OR to_tsvector(
        'simple', coalesce(case_row.number,'') || ' ' || coalesce(case_row.title,'')
          || ' ' || coalesce(case_row.description,'')
      ) @@ plainto_tsquery('simple', filters ->> 'search'))
  ), all_rows AS (
    SELECT * FROM ticket_rows
    UNION ALL
    SELECT ticket.ticket_id, comment.id, CASE comment.visibility
      WHEN 'public' THEN 1 ELSE 2 END,
      comment.id, comment.revision::bigint
    FROM ticket_rows AS ticket
    JOIN public.ticket_comments AS comment
      ON comment.tenant_id = p_job.tenant_id
     AND (p_job.kind = 'alert' AND comment.alert_id = ticket.ticket_id
       OR p_job.kind = 'case' AND comment.case_id = ticket.ticket_id)
    WHERE ticket.comment_id IS NULL
      AND (comment.visibility = 'public' AND p_job.comment_scope IN (
        'public','public_and_private'
      ) OR comment.visibility = 'private'
        AND p_job.audience = 'operator'
        AND p_job.comment_scope = 'public_and_private')
  ), ordered AS (
    SELECT row_number() OVER (
      ORDER BY ticket_id, row_rank, row_id
    ) AS absolute_position, row_data.*
    FROM all_rows AS row_data
  ), selected AS (
    SELECT * FROM ordered
    WHERE absolute_position > cursor_offset
    ORDER BY absolute_position
    LIMIT p_limit + 1
  ), projected AS (
    SELECT selected.*,
      CASE WHEN selected.comment_id IS NULL THEN 'ticket'
        WHEN selected.row_rank = 1 THEN 'public_comment'
        ELSE 'private_comment' END AS output_kind,
      (
        SELECT jsonb_agg(app.private_ticket_export_cell_v1(
          p_job, selected.ticket_id, selected.comment_id, column_item.item
        ) ORDER BY column_item.ordinal)
        FROM jsonb_array_elements(document -> 'columns')
             WITH ORDINALITY AS column_item(item, ordinal)
      ) AS cells
    FROM selected
  ), sized AS (
    SELECT projected.*,
      sum(pg_column_size(projected.cells)) OVER (
        ORDER BY projected.absolute_position
      ) AS cumulative_bytes
    FROM projected
  ), admitted AS (
    SELECT * FROM sized
    WHERE absolute_position <= cursor_offset + p_limit
      AND cumulative_bytes <= 4194304
  )
  SELECT
    coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
      'kind', admitted.output_kind,
      'snapshotKeySha256', CASE WHEN p_snapshot_keys THEN encode(sha256(
        convert_to(admitted.output_kind || ':' || admitted.row_id::text
          || ':' || admitted.row_revision::text, 'UTF8')
      ), 'hex') END,
      'cells', admitted.cells
    )) ORDER BY admitted.absolute_position), '[]'::jsonb),
    (SELECT count(*) FROM selected), count(*)
  INTO rows_document, selected_count, admitted_count
  FROM admitted;
  IF selected_count > admitted_count THEN
    next_cursor := lpad(to_hex(cursor_offset + admitted_count), 16, '0');
  END IF;
  RETURN jsonb_build_object('rows', rows_document, 'next', next_cursor);
END;
$function$;
ALTER FUNCTION app.private_ticket_export_page_document_v1(
  public.ticket_export_jobs, text, integer, boolean
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_page_document_v1(
  public.ticket_export_jobs, text, integer, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_manifest_document_v1(
  p_manifest public.ticket_export_manifests
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog, public
AS $function$
  SELECT jsonb_build_object(
    'artifactId', p_manifest.artifact_id,
    'sha256', encode(p_manifest.digest, 'hex'),
    'rows', p_manifest.rows,
    'bytes', p_manifest.bytes
  );
$function$;
ALTER FUNCTION app.private_ticket_export_manifest_document_v1(
  public.ticket_export_manifests
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_manifest_document_v1(
  public.ticket_export_manifests
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_fence_matches_v1(
  p_job public.ticket_export_jobs,
  p_binding record,
  p_worker_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RETURN p_job.tenant_id IS NOT DISTINCT FROM p_binding.tenant_id
    AND p_job.id IS NOT DISTINCT FROM p_binding.job_id
    AND p_job.kind IS NOT DISTINCT FROM p_binding.kind
    AND p_job.audience IS NOT DISTINCT FROM p_binding.audience
    AND p_job.revision IS NOT DISTINCT FROM p_binding.revision
    AND p_job.attempts IS NOT DISTINCT FROM p_binding.attempt
    AND p_job.lease_worker_id IS NOT DISTINCT FROM p_worker_id
    AND p_worker_id IS NOT DISTINCT FROM p_binding.worker_id
    AND p_job.lease_fence_digest IS NOT DISTINCT FROM p_binding.fence_digest
    AND p_job.query_digest IS NOT DISTINCT FROM p_binding.query_digest
    AND p_job.catalog_digest IS NOT DISTINCT FROM p_binding.catalog_digest
    AND p_job.projection_version IS NOT DISTINCT FROM p_binding.projection_version
    AND p_job.lease_claimed_at IS NOT DISTINCT FROM p_binding.lease_claimed_at
    AND p_job.lease_expires_at IS NOT DISTINCT FROM p_binding.lease_expires_at
    AND p_job.expires_at IS NOT DISTINCT FROM p_binding.job_expires_at;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_fence_matches_v1(
  public.ticket_export_jobs, record, uuid
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_fence_matches_v1(
  public.ticket_export_jobs, record, uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_snapshot_current_v1(
  p_job public.ticket_export_jobs
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE snapshot public.ticket_export_query_snapshots%ROWTYPE;
BEGIN
  SELECT candidate.* INTO snapshot
  FROM public.ticket_export_query_snapshots AS candidate
  WHERE candidate.tenant_id = p_job.tenant_id AND candidate.job_id = p_job.id;
  RETURN FOUND
    AND snapshot.query_digest IS NOT DISTINCT FROM p_job.query_digest
    AND snapshot.catalog_digest IS NOT DISTINCT FROM p_job.catalog_digest
    AND app.private_ticket_runtime_catalog_digest_v1(snapshot.spec_canonical)
      IS NOT DISTINCT FROM p_job.catalog_digest;
END;
$function$;
ALTER FUNCTION app.private_ticket_export_snapshot_current_v1(
  public.ticket_export_jobs
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_snapshot_current_v1(
  public.ticket_export_jobs
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_empty_page_v1(
  p_control text, p_revision bigint
)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT jsonb_build_object(
    'schemaVersion', 1,
    'control', p_control,
    'controlRevision', p_revision,
    'rows', '[]'::jsonb,
    'next', ''
  );
$function$;
ALTER FUNCTION app.private_ticket_export_empty_page_v1(text, bigint)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_empty_page_v1(text, bigint)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.read_ticket_export_page_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  job public.ticket_export_jobs%ROWTYPE;
  page jsonb;
  item_limit integer;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','binding','after','limit']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object'
     OR jsonb_typeof(request -> 'after') <> 'string' THEN
    RAISE EXCEPTION 'ticket export page request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_export_binding_v1(request -> 'binding') AS parsed;
  item_limit := app.private_ticket_runtime_js_uint_v1(
    request -> 'limit', 1, 1000
  )::integer;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR SHARE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT app.private_ticket_export_empty_page_v1('fence_lost', 0);
    RETURN;
  END IF;
  IF job.state = 'cancellation_requested'
     AND job.revision = binding.revision + 1
     AND job.lease_worker_id IS NOT DISTINCT FROM admitted_worker_id
     AND job.lease_fence_digest IS NOT DISTINCT FROM binding.fence_digest THEN
    RETURN QUERY SELECT app.private_ticket_export_empty_page_v1(
      'cancellation_requested', job.revision
    );
    RETURN;
  END IF;
  IF job.state <> 'running'
     OR NOT app.private_ticket_export_fence_matches_v1(
       job, binding, admitted_worker_id
     ) THEN
    RETURN QUERY SELECT app.private_ticket_export_empty_page_v1('fence_lost', 0);
    RETURN;
  END IF;
  IF NOT app.private_ticket_export_requester_live_v1(job) THEN
    RETURN QUERY SELECT app.private_ticket_export_empty_page_v1(
      'authorization_revoked', binding.revision
    );
    RETURN;
  END IF;
  IF NOT app.private_ticket_export_snapshot_current_v1(job) THEN
    RETURN QUERY SELECT app.private_ticket_export_empty_page_v1('snapshot_stale', 0);
    RETURN;
  END IF;
  page := app.private_ticket_export_page_document_v1(
    job, request ->> 'after', item_limit, true
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'control', 'ready',
    'controlRevision', 0,
    'rows', page -> 'rows',
    'next', page ->> 'next'
  );
END;
$function$;
ALTER FUNCTION app.read_ticket_export_page_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.read_ticket_export_page_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.read_ticket_export_page_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.record_ticket_export_manifest_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  requested_artifact_id uuid;
  requested_digest bytea;
  requested_rows integer;
  requested_bytes bigint;
  recorded_at timestamp with time zone;
  job public.ticket_export_jobs%ROWTYPE;
  manifest public.ticket_export_manifests%ROWTYPE;
  claim_proof text;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','binding','artifactId','sha256','rows','bytes','recordedAt'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object' THEN
    RAISE EXCEPTION 'ticket export manifest request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_export_binding_v1(request -> 'binding') AS parsed;
  requested_artifact_id := app.private_ticket_runtime_uuid_v1(request ->> 'artifactId');
  requested_digest := app.private_ticket_runtime_digest_v1(request ->> 'sha256');
  requested_rows := app.private_ticket_runtime_js_uint_v1(
    request -> 'rows', 0, 1000000
  )::integer;
  requested_bytes := app.private_ticket_runtime_js_uint_v1(
    request -> 'bytes', 1, 1073741824
  );
  recorded_at := app.private_ticket_runtime_instant_v1(request -> 'recordedAt');
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF job.state = 'cancellation_requested'
     AND job.revision = binding.revision + 1
     AND job.lease_worker_id IS NOT DISTINCT FROM admitted_worker_id
     AND job.lease_fence_digest IS NOT DISTINCT FROM binding.fence_digest THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','cancellation_requested',
      'currentRevision',job.revision,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF job.state <> 'running'
     OR NOT app.private_ticket_export_fence_matches_v1(
       job, binding, admitted_worker_id
     ) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF NOT app.private_ticket_export_requester_live_v1(job) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','authorization_revoked',
      'currentRevision',binding.revision,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF NOT app.private_ticket_export_snapshot_current_v1(job) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','snapshot_stale',
      'currentRevision',0,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  claim_proof := encode(sha256(binding.fence_digest), 'hex');
  IF NOT EXISTS (
    SELECT 1 FROM public.audit_events AS event
    WHERE event.tenant_id = binding.tenant_id
      AND event.resource_type = 'ticket_export_job'
      AND event.resource_id = binding.job_id
      AND event.action = 'ticket.export.claimed'
      AND event.metadata ->> 'artifactId' = requested_artifact_id::text
      AND event.metadata ->> 'fenceProofSha256' = claim_proof
      AND (event.metadata ->> 'attempt')::smallint = binding.attempt
  ) THEN
    RAISE EXCEPTION 'ticket export artifact claim is unavailable' USING ERRCODE = '42501';
  END IF;
  IF recorded_at < binding.lease_claimed_at OR recorded_at > binding.lease_expires_at
     OR requested_rows > job.maximum_rows OR requested_bytes > job.maximum_bytes THEN
    RAISE EXCEPTION 'ticket export manifest bounds are invalid' USING ERRCODE = '22023';
  END IF;
  SELECT candidate.* INTO manifest
  FROM public.ticket_export_manifests AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.job_id = binding.job_id
    AND candidate.attempt = binding.attempt;
  IF FOUND THEN
    IF manifest.artifact_id IS DISTINCT FROM requested_artifact_id
       OR manifest.job_revision IS DISTINCT FROM binding.revision
       OR manifest.projection_version IS DISTINCT FROM binding.projection_version
       OR manifest.digest IS DISTINCT FROM requested_digest
       OR manifest.rows IS DISTINCT FROM requested_rows
       OR manifest.bytes IS DISTINCT FROM requested_bytes
       OR manifest.recorded_at IS DISTINCT FROM recorded_at THEN
      RAISE EXCEPTION 'ticket export manifest replay payload mismatch' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','recorded','currentRevision',binding.revision,
      'manifest',app.private_ticket_export_manifest_document_v1(manifest)
    );
    RETURN;
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  INSERT INTO public.ticket_export_manifests(
    tenant_id,job_id,artifact_id,job_revision,attempt,projection_version,
    digest,rows,bytes,recorded_at,expires_at,published_at
  ) VALUES (
    binding.tenant_id,binding.job_id,requested_artifact_id,binding.revision,
    binding.attempt,binding.projection_version,requested_digest,requested_rows,
    requested_bytes,recorded_at,binding.job_expires_at,NULL
  ) RETURNING * INTO manifest;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'disposition','recorded','currentRevision',binding.revision,
    'manifest',app.private_ticket_export_manifest_document_v1(manifest)
  );
END;
$function$;
ALTER FUNCTION app.record_ticket_export_manifest_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.record_ticket_export_manifest_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.record_ticket_export_manifest_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_export_success_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  requested_artifact_id uuid;
  requested_digest bytea;
  requested_rows integer;
  requested_bytes bigint;
  requested_expires_at timestamp with time zone;
  completed_at timestamp with time zone;
  job public.ticket_export_jobs%ROWTYPE;
  manifest public.ticket_export_manifests%ROWTYPE;
  next_revision bigint;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','binding','artifactId','sha256','rows','bytes',
         'expiresAt','completedAt'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object' THEN
    RAISE EXCEPTION 'ticket export success request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_export_binding_v1(request -> 'binding') AS parsed;
  requested_artifact_id := app.private_ticket_runtime_uuid_v1(request ->> 'artifactId');
  requested_digest := app.private_ticket_runtime_digest_v1(request ->> 'sha256');
  requested_rows := app.private_ticket_runtime_js_uint_v1(
    request -> 'rows', 0, 1000000
  )::integer;
  requested_bytes := app.private_ticket_runtime_js_uint_v1(
    request -> 'bytes', 1, 1073741824
  );
  requested_expires_at := app.private_ticket_runtime_instant_v1(request -> 'expiresAt');
  completed_at := app.private_ticket_runtime_instant_v1(request -> 'completedAt');
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  SELECT candidate.* INTO manifest
  FROM public.ticket_export_manifests AS candidate
  WHERE candidate.tenant_id = binding.tenant_id
    AND candidate.job_id = binding.job_id
    AND candidate.artifact_id = requested_artifact_id;
  IF FOUND AND job.state = 'succeeded'
     AND job.revision = binding.revision + 1
     AND job.attempts = binding.attempt
     AND job.artifact_id IS NOT DISTINCT FROM requested_artifact_id
     AND job.artifact_digest IS NOT DISTINCT FROM requested_digest
     AND job.artifact_rows IS NOT DISTINCT FROM requested_rows
     AND job.artifact_bytes IS NOT DISTINCT FROM requested_bytes
     AND job.artifact_expires_at IS NOT DISTINCT FROM requested_expires_at
     AND job.terminal_at IS NOT DISTINCT FROM completed_at
     AND manifest.job_revision IS NOT DISTINCT FROM binding.revision
     AND manifest.attempt IS NOT DISTINCT FROM binding.attempt
     AND manifest.projection_version IS NOT DISTINCT FROM binding.projection_version
     AND manifest.digest IS NOT DISTINCT FROM requested_digest
     AND manifest.rows IS NOT DISTINCT FROM requested_rows
     AND manifest.bytes IS NOT DISTINCT FROM requested_bytes
     AND manifest.published_at IS NOT DISTINCT FROM completed_at THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','replayed','currentRevision',job.revision,
      'manifest',app.private_ticket_export_manifest_document_v1(manifest)
    );
    RETURN;
  END IF;
  IF NOT FOUND THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF job.state = 'cancellation_requested'
     AND job.revision = binding.revision + 1
     AND job.lease_worker_id IS NOT DISTINCT FROM admitted_worker_id
     AND job.lease_fence_digest IS NOT DISTINCT FROM binding.fence_digest THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','cancellation_requested',
      'currentRevision',job.revision,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF job.state <> 'running'
     OR NOT app.private_ticket_export_fence_matches_v1(
       job, binding, admitted_worker_id
     ) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF NOT app.private_ticket_export_requester_live_v1(job) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','authorization_revoked',
      'currentRevision',binding.revision,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF NOT app.private_ticket_export_snapshot_current_v1(job) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','snapshot_stale',
      'currentRevision',0,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF manifest.job_revision IS DISTINCT FROM binding.revision
     OR manifest.attempt IS DISTINCT FROM binding.attempt
     OR manifest.projection_version IS DISTINCT FROM binding.projection_version
     OR manifest.digest IS DISTINCT FROM requested_digest
     OR manifest.rows IS DISTINCT FROM requested_rows
     OR manifest.bytes IS DISTINCT FROM requested_bytes
     OR manifest.published_at IS NOT NULL
     OR requested_expires_at IS DISTINCT FROM binding.job_expires_at
     OR completed_at < manifest.recorded_at
     OR completed_at >= binding.lease_expires_at
     OR completed_at > transaction_timestamp() + interval '1 minute' THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','snapshot_stale',
      'currentRevision',0,'manifest','null'::jsonb
    );
    RETURN;
  END IF;
  IF binding.revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'ticket export revision is exhausted' USING ERRCODE = '54000';
  END IF;
  next_revision := binding.revision + 1;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_export_manifests
  SET published_at = completed_at
  WHERE tenant_id = binding.tenant_id AND job_id = binding.job_id
    AND artifact_id = requested_artifact_id AND published_at IS NULL
  RETURNING * INTO manifest;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket export manifest publication lost its fence'
      USING ERRCODE = '40001';
  END IF;
  UPDATE public.ticket_export_jobs
  SET state = 'succeeded', revision = next_revision, failure_code = 'none',
      updated_at = completed_at, available_at = completed_at,
      lease_worker_id = NULL, lease_fence_digest = NULL,
      lease_claimed_at = NULL, lease_expires_at = NULL,
      artifact_id = requested_artifact_id, artifact_digest = requested_digest,
      artifact_rows = requested_rows, artifact_bytes = requested_bytes,
      artifact_expires_at = requested_expires_at, terminal_at = completed_at
  WHERE tenant_id = binding.tenant_id AND id = binding.job_id
    AND state = 'running' AND revision = binding.revision;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket export success lost its fence' USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    binding.tenant_id,'ticket.export.succeeded','ticket_export_job',binding.job_id,
    next_revision,completed_at,'success',jsonb_build_object(
      'artifactId',requested_artifact_id,'attempt',binding.attempt,
      'rows',requested_rows,'bytes',requested_bytes,
      'fenceProofSha256',encode(sha256(binding.fence_digest),'hex')
    )
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'disposition','applied','currentRevision',next_revision,
    'manifest',app.private_ticket_export_manifest_document_v1(manifest)
  );
END;
$function$;
ALTER FUNCTION app.commit_ticket_export_success_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_export_success_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_export_success_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.report_ticket_export_failure_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  requested_code text;
  failed_at timestamp with time zone;
  requested_retry_at timestamp with time zone;
  job public.ticket_export_jobs%ROWTYPE;
  receipt public.audit_events%ROWTYPE;
  proof text;
  disposition text;
  replay_disposition text;
  next_revision bigint;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','binding','code','failedAt','retryAt']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object'
     OR request ->> 'code' NOT IN (
       'transient_storage','transient_database','authorization_revoked',
       'snapshot_stale','output_limit','lease_expired','expired','internal'
     ) OR jsonb_typeof(request -> 'retryAt') NOT IN ('null','string') THEN
    RAISE EXCEPTION 'ticket export failure request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_export_binding_v1(request -> 'binding') AS parsed;
  requested_code := request ->> 'code';
  failed_at := app.private_ticket_runtime_instant_v1(request -> 'failedAt');
  IF jsonb_typeof(request -> 'retryAt') = 'string' THEN
    requested_retry_at := app.private_ticket_runtime_instant_v1(request -> 'retryAt');
  END IF;
  IF failed_at < binding.lease_claimed_at OR failed_at >= binding.lease_expires_at
     OR failed_at > transaction_timestamp() + interval '1 minute'
     OR requested_retry_at IS NOT NULL AND (
       requested_code NOT IN ('transient_storage','transient_database','internal')
       OR requested_retry_at - failed_at NOT BETWEEN interval '1 second' AND interval '1 hour'
       OR requested_retry_at >= binding.job_expires_at
     ) THEN
    RAISE EXCEPTION 'ticket export failure bounds are invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  proof := encode(sha256(binding.fence_digest), 'hex');
  SELECT event.* INTO receipt
  FROM public.audit_events AS event
  WHERE event.tenant_id = binding.tenant_id
    AND event.resource_type = 'ticket_export_job'
    AND event.resource_id = binding.job_id
    AND event.action = 'ticket.export.failure_reported'
    AND event.metadata ->> 'fenceProofSha256' = proof
  ORDER BY event.sequence DESC LIMIT 1;
  IF FOUND THEN
    IF receipt.metadata ->> 'code' IS DISTINCT FROM requested_code
       OR (receipt.metadata ->> 'failedAt')::timestamp with time zone IS DISTINCT FROM failed_at
       OR (CASE WHEN receipt.metadata -> 'retryAt' = 'null'::jsonb THEN NULL
          ELSE (receipt.metadata ->> 'retryAt')::timestamp with time zone END)
          IS DISTINCT FROM requested_retry_at
       OR (receipt.metadata ->> 'inputRevision')::bigint IS DISTINCT FROM binding.revision
       OR (receipt.metadata ->> 'attempt')::smallint IS DISTINCT FROM binding.attempt THEN
      RAISE EXCEPTION 'ticket export failure replay payload mismatch' USING ERRCODE = '23505';
    END IF;
    replay_disposition := CASE receipt.metadata ->> 'disposition'
      WHEN 'retry_scheduled' THEN 'replay_retry' ELSE 'replay_terminal' END;
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition',replay_disposition,
      'currentRevision',(receipt.metadata ->> 'resultRevision')::bigint,
      'code',requested_code,
      'retryAt',CASE WHEN requested_retry_at IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(requested_retry_at) END
    );
    RETURN;
  END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0,
      'code','none','retryAt','null'::jsonb
    ); RETURN;
  END IF;
  IF job.state = 'cancellation_requested'
     AND job.revision = binding.revision + 1
     AND job.lease_worker_id IS NOT DISTINCT FROM admitted_worker_id
     AND job.lease_fence_digest IS NOT DISTINCT FROM binding.fence_digest THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','cancellation_requested',
      'currentRevision',job.revision,'code','none','retryAt','null'::jsonb
    ); RETURN;
  END IF;
  IF job.state <> 'running'
     OR NOT app.private_ticket_export_fence_matches_v1(
       job, binding, admitted_worker_id
     ) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0,
      'code','none','retryAt','null'::jsonb
    ); RETURN;
  END IF;
  IF NOT app.private_ticket_export_requester_live_v1(job) THEN
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion',1,'disposition','authorization_revoked',
      'currentRevision',binding.revision,'code','none','retryAt','null'::jsonb
    ); RETURN;
  END IF;
  IF binding.revision >= 9007199254740991 THEN
    RAISE EXCEPTION 'ticket export revision is exhausted' USING ERRCODE = '54000';
  END IF;
  next_revision := binding.revision + 1;
  disposition := CASE WHEN requested_retry_at IS NULL THEN 'terminal'
    ELSE 'retry_scheduled' END;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_export_jobs
  SET state = CASE WHEN disposition = 'retry_scheduled' THEN 'pending' ELSE 'failed' END,
      revision = next_revision, failure_code = requested_code,
      updated_at = failed_at,
      available_at = CASE WHEN disposition = 'retry_scheduled'
        THEN requested_retry_at ELSE failed_at END,
      lease_worker_id = NULL, lease_fence_digest = NULL,
      lease_claimed_at = NULL, lease_expires_at = NULL,
      terminal_at = CASE WHEN disposition = 'terminal' THEN failed_at END
  WHERE tenant_id = binding.tenant_id AND id = binding.job_id
    AND state = 'running' AND revision = binding.revision;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket export failure lost its fence' USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    binding.tenant_id,'ticket.export.failure_reported','ticket_export_job',
    binding.job_id,next_revision,failed_at,'failure',jsonb_build_object(
      'code',requested_code,'failedAt',failed_at,
      'retryAt',CASE WHEN requested_retry_at IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(requested_retry_at) END,
      'disposition',disposition,'inputRevision',binding.revision,
      'resultRevision',next_revision,'attempt',binding.attempt,
      'fenceProofSha256',proof
    )
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'disposition',disposition,'currentRevision',next_revision,
    'code',requested_code,
    'retryAt',CASE WHEN requested_retry_at IS NULL THEN 'null'::jsonb
      ELSE to_jsonb(requested_retry_at) END
  );
END;
$function$;
ALTER FUNCTION app.report_ticket_export_failure_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.report_ticket_export_failure_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.report_ticket_export_failure_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_control_transition_v1(
  request jsonb,
  p_mode text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  binding record;
  admitted_worker_id uuid;
  expected_revision bigint;
  transitioned_at timestamp with time zone;
  job public.ticket_export_jobs%ROWTYPE;
  receipt public.audit_events%ROWTYPE;
  proof text;
  action_name text;
  target_state text;
  target_failure text;
  next_revision bigint;
BEGIN
  IF p_mode NOT IN ('cancellation','revocation')
     OR request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','identity','binding','expectedRevision','transitionedAt'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'binding') <> 'object' THEN
    RAISE EXCEPTION 'ticket export control request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'identity', 'ticket_export'
  );
  SELECT parsed.* INTO STRICT binding
  FROM app.private_ticket_export_binding_v1(request -> 'binding') AS parsed;
  expected_revision := app.private_ticket_runtime_js_uint_v1(
    request -> 'expectedRevision', 1, 9007199254740990
  );
  transitioned_at := app.private_ticket_runtime_instant_v1(request -> 'transitionedAt');
  IF transitioned_at < binding.lease_claimed_at
     OR transitioned_at > binding.job_expires_at
     OR transitioned_at > transaction_timestamp() + interval '1 minute'
     OR p_mode = 'cancellation' AND expected_revision <> binding.revision + 1
     OR p_mode = 'revocation' AND expected_revision <> binding.revision THEN
    RAISE EXCEPTION 'ticket export control bounds are invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.tenant_id', binding.tenant_id::text, true);
  proof := encode(sha256(binding.fence_digest), 'hex');
  action_name := CASE p_mode WHEN 'cancellation'
    THEN 'ticket.export.cancellation_acknowledged'
    ELSE 'ticket.export.authorization_rejected' END;
  target_state := CASE p_mode WHEN 'cancellation' THEN 'cancelled' ELSE 'failed' END;
  target_failure := CASE p_mode WHEN 'cancellation' THEN 'none'
    ELSE 'authorization_revoked' END;
  SELECT event.* INTO receipt
  FROM public.audit_events AS event
  WHERE event.tenant_id = binding.tenant_id
    AND event.resource_type = 'ticket_export_job'
    AND event.resource_id = binding.job_id
    AND event.action = action_name
    AND event.metadata ->> 'fenceProofSha256' = proof
  ORDER BY event.sequence DESC LIMIT 1;
  IF FOUND THEN
    IF (receipt.metadata ->> 'inputRevision')::bigint IS DISTINCT FROM expected_revision
       OR (receipt.metadata ->> 'transitionedAt')::timestamp with time zone
          IS DISTINCT FROM transitioned_at
       OR (receipt.metadata ->> 'attempt')::smallint IS DISTINCT FROM binding.attempt THEN
      RAISE EXCEPTION 'ticket export control replay payload mismatch' USING ERRCODE = '23505';
    END IF;
    RETURN jsonb_build_object(
      'schemaVersion',1,'disposition','replayed',
      'currentRevision',(receipt.metadata ->> 'resultRevision')::bigint
    );
  END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = binding.tenant_id AND candidate.id = binding.job_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0
    );
  END IF;
  IF job.revision IS DISTINCT FROM expected_revision
     OR job.attempts IS DISTINCT FROM binding.attempt
     OR job.kind IS DISTINCT FROM binding.kind
     OR job.audience IS DISTINCT FROM binding.audience
     OR job.lease_worker_id IS DISTINCT FROM admitted_worker_id
     OR admitted_worker_id IS DISTINCT FROM binding.worker_id
     OR job.lease_fence_digest IS DISTINCT FROM binding.fence_digest
     OR job.query_digest IS DISTINCT FROM binding.query_digest
     OR job.catalog_digest IS DISTINCT FROM binding.catalog_digest
     OR job.projection_version IS DISTINCT FROM binding.projection_version
     OR job.lease_claimed_at IS DISTINCT FROM binding.lease_claimed_at
     OR job.lease_expires_at IS DISTINCT FROM binding.lease_expires_at
     OR job.expires_at IS DISTINCT FROM binding.job_expires_at
     OR p_mode = 'cancellation' AND job.state <> 'cancellation_requested'
     OR p_mode = 'revocation' AND (
       job.state <> 'running' OR app.private_ticket_export_requester_live_v1(job)
     ) THEN
    RETURN jsonb_build_object(
      'schemaVersion',1,'disposition','fence_lost','currentRevision',0
    );
  END IF;
  next_revision := expected_revision + 1;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  UPDATE public.ticket_export_jobs
  SET state = target_state, revision = next_revision,
      failure_code = target_failure, updated_at = transitioned_at,
      available_at = transitioned_at,
      lease_worker_id = NULL, lease_fence_digest = NULL,
      lease_claimed_at = NULL, lease_expires_at = NULL,
      terminal_at = transitioned_at
  WHERE tenant_id = binding.tenant_id AND id = binding.job_id
    AND revision = expected_revision;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket export control lost its fence' USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    binding.tenant_id,action_name,'ticket_export_job',binding.job_id,
    next_revision,transitioned_at,'success',jsonb_build_object(
      'inputRevision',expected_revision,'resultRevision',next_revision,
      'transitionedAt',transitioned_at,'attempt',binding.attempt,
      'fenceProofSha256',proof
    )
  );
  RETURN jsonb_build_object(
    'schemaVersion',1,'disposition','applied','currentRevision',next_revision
  );
END;
$function$;
ALTER FUNCTION app.private_ticket_export_control_transition_v1(jsonb, text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_control_transition_v1(jsonb, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
--> statement-breakpoint

CREATE FUNCTION app.acknowledge_ticket_export_cancellation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT app.private_ticket_export_control_transition_v1(request, 'cancellation');
$function$;
ALTER FUNCTION app.acknowledge_ticket_export_cancellation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.acknowledge_ticket_export_cancellation_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.acknowledge_ticket_export_cancellation_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.reject_ticket_export_revocation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT app.private_ticket_export_control_transition_v1(request, 'revocation');
$function$;
ALTER FUNCTION app.reject_ticket_export_revocation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.reject_ticket_export_revocation_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.reject_ticket_export_revocation_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.select_ticket_export_claim_candidate_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  admitted_worker_id uuid;
  request_tenant_id uuid;
  request_kind public.ticket_aggregate_kind;
  observed_at timestamp with time zone;
  job public.ticket_export_jobs%ROWTYPE;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 32768
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','worker','tenantId','kind','audience','capability',
         'jobId','expectedRevision','fenceSha256','now'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'capability' <> 'ticket_export.claim'
     OR request ->> 'jobId' <> '' OR request ->> 'expectedRevision' <> '0'
     OR request ->> 'fenceSha256' <> ''
     OR jsonb_typeof(request -> 'now') <> 'string' THEN
    RAISE EXCEPTION 'ticket export candidate request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'worker', 'ticket_export'
  );
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  observed_at := app.private_ticket_runtime_instant_v1(request -> 'now');
  IF observed_at < transaction_timestamp() - interval '5 minutes'
     OR observed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'ticket export candidate time is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM admitted_worker_id;
  PERFORM set_config('app.tenant_id', request_tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id
    AND candidate.kind = request_kind
    AND candidate.audience = request ->> 'audience'
    AND candidate.expires_at > observed_at
    AND candidate.attempts < candidate.maximum_attempts
    AND (candidate.state = 'pending' AND candidate.available_at <= observed_at
      OR candidate.state = 'running' AND candidate.lease_expires_at <= observed_at)
    AND app.private_ticket_export_requester_live_v1(candidate)
    AND app.private_ticket_export_snapshot_current_v1(candidate)
  ORDER BY candidate.available_at, candidate.id
  LIMIT 1;
  IF NOT FOUND THEN RETURN; END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'record',app.private_ticket_export_record_v1(job.id,true)
  );
END;
$function$;
ALTER FUNCTION app.select_ticket_export_claim_candidate_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.select_ticket_export_claim_candidate_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.select_ticket_export_claim_candidate_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_ticket_export_for_worker_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE request_tenant_id uuid;
DECLARE request_job_id uuid;
DECLARE admitted_worker_id uuid;
DECLARE job public.ticket_export_jobs%ROWTYPE;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 32768
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','worker','tenantId','kind','audience','capability',
         'jobId','expectedRevision','fenceSha256','now'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'capability' <> 'ticket_export.execute'
     OR request ->> 'expectedRevision' <> '0'
     OR request ->> 'fenceSha256' <> ''
     OR jsonb_typeof(request -> 'now') <> 'null' THEN
    RAISE EXCEPTION 'ticket export worker get request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'worker', 'ticket_export'
  );
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  PERFORM admitted_worker_id;
  PERFORM set_config('app.tenant_id', request_tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id AND candidate.id = request_job_id
    AND candidate.kind::text = request ->> 'kind'
    AND candidate.audience = request ->> 'audience';
  IF NOT FOUND OR NOT app.private_ticket_export_requester_live_v1(job)
     OR NOT app.private_ticket_export_snapshot_current_v1(job) THEN RETURN; END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'record',app.private_ticket_export_record_v1(job.id,true)
  );
END;
$function$;
ALTER FUNCTION app.get_ticket_export_for_worker_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.get_ticket_export_for_worker_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.get_ticket_export_for_worker_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_revoked_ticket_export_for_worker_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE request_tenant_id uuid;
DECLARE request_job_id uuid;
DECLARE admitted_worker_id uuid;
DECLARE job public.ticket_export_jobs%ROWTYPE;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 32768
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','worker','tenantId','kind','audience','capability',
         'jobId','expectedRevision','fenceSha256','now'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'capability' <> 'ticket_export.execute'
     OR request ->> 'expectedRevision' <> '0'
     OR request ->> 'fenceSha256' <> ''
     OR jsonb_typeof(request -> 'now') <> 'null' THEN
    RAISE EXCEPTION 'ticket export revoked get request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'worker', 'ticket_export'
  );
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  PERFORM admitted_worker_id;
  PERFORM set_config('app.tenant_id', request_tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id AND candidate.id = request_job_id
    AND candidate.kind::text = request ->> 'kind'
    AND candidate.audience = request ->> 'audience';
  IF NOT FOUND OR app.private_ticket_export_requester_live_v1(job) THEN RETURN; END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'job',app.private_ticket_export_job_document_v1(job)
  );
END;
$function$;
ALTER FUNCTION app.get_revoked_ticket_export_for_worker_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.get_revoked_ticket_export_for_worker_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.get_revoked_ticket_export_for_worker_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.read_ticket_export_application_page_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE admitted_worker_id uuid;
DECLARE request_tenant_id uuid;
DECLARE request_job_id uuid;
DECLARE expected_revision bigint;
DECLARE requested_fence bytea;
DECLARE requested_query bytea;
DECLARE requested_catalog bytea;
DECLARE item_limit integer;
DECLARE job public.ticket_export_jobs%ROWTYPE;
DECLARE page jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 65536
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','worker','tenantId','jobId','kind','audience',
         'expectedRevision','fenceSha256','querySha256','catalogSha256',
         'projectionVersion','after','limit'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'projectionVersion' <> '1'
     OR jsonb_typeof(request -> 'after') <> 'string' THEN
    RAISE EXCEPTION 'ticket export application page request is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'worker', 'ticket_export'
  );
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  expected_revision := app.private_ticket_runtime_js_uint_v1(
    request -> 'expectedRevision', 1, 9007199254740991
  );
  requested_fence := app.private_ticket_runtime_digest_v1(request ->> 'fenceSha256');
  requested_query := app.private_ticket_runtime_digest_v1(request ->> 'querySha256');
  requested_catalog := app.private_ticket_runtime_digest_v1(request ->> 'catalogSha256');
  item_limit := app.private_ticket_runtime_js_uint_v1(request -> 'limit',1,1000)::integer;
  PERFORM set_config('app.tenant_id', request_tenant_id::text, true);
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id = request_tenant_id AND candidate.id = request_job_id
  FOR SHARE;
  IF NOT FOUND OR job.kind::text <> request ->> 'kind'
     OR job.audience <> request ->> 'audience'
     OR job.state <> 'running' OR job.revision <> expected_revision
     OR job.lease_worker_id IS DISTINCT FROM admitted_worker_id
     OR job.lease_fence_digest IS DISTINCT FROM requested_fence
     OR job.query_digest IS DISTINCT FROM requested_query
     OR job.catalog_digest IS DISTINCT FROM requested_catalog
     OR job.projection_version <> 1
     OR NOT app.private_ticket_export_requester_live_v1(job)
     OR NOT app.private_ticket_export_snapshot_current_v1(job) THEN
    RAISE EXCEPTION 'ticket export application page fence is unavailable'
      USING ERRCODE = '42501';
  END IF;
  page := app.private_ticket_export_page_document_v1(
    job,request ->> 'after',item_limit,false
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'rows',page -> 'rows','next',page ->> 'next'
  );
END;
$function$;
ALTER FUNCTION app.read_ticket_export_application_page_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.read_ticket_export_application_page_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.read_ticket_export_application_page_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_export_worker_transition_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  admitted_worker_id uuid;
  request_tenant_id uuid;
  request_kind public.ticket_aggregate_kind;
  request_audience text;
  required_capability text;
  expected_revision bigint;
  next_document jsonb;
  definition jsonb;
  job public.ticket_export_jobs%ROWTYPE;
  next_state text;
  next_revision bigint;
  next_attempts smallint;
  next_failure text;
  changed_at timestamp with time zone;
  next_available_at timestamp with time zone;
  next_lease_worker uuid;
  next_fence bytea;
  next_claimed_at timestamp with time zone;
  next_lease_expires_at timestamp with time zone;
  next_artifact_id uuid;
  next_artifact_digest bytea;
  next_artifact_rows integer;
  next_artifact_bytes bigint;
  next_artifact_expires_at timestamp with time zone;
  next_terminal_at timestamp with time zone;
  valid_transition boolean := false;
  action_name text;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','worker','tenantId','kind','audience',
         'requiredCapability','expectedRevision','next','query'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'requiredCapability' NOT IN (
       'ticket_export.claim','ticket_export.execute'
     ) OR jsonb_typeof(request -> 'next') <> 'object'
     OR jsonb_typeof(request -> 'query') <> 'object' THEN
    RAISE EXCEPTION 'ticket export worker transition request is invalid'
      USING ERRCODE = '22023';
  END IF;
  next_document := request -> 'next';
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       next_document, ARRAY[
         'definition','state','revision','attempts','failureCode','requestedAt',
         'updatedAt','availableAt','expiresAt','lease','artifact','terminalAt'
       ]
     ) OR jsonb_typeof(next_document -> 'definition') <> 'object'
     OR jsonb_typeof(next_document -> 'lease') NOT IN ('object','null')
     OR jsonb_typeof(next_document -> 'artifact') NOT IN ('object','null')
     OR jsonb_typeof(next_document -> 'terminalAt') NOT IN ('string','null') THEN
    RAISE EXCEPTION 'ticket export worker projection is invalid' USING ERRCODE = '22023';
  END IF;
  admitted_worker_id := app.private_ticket_runtime_require_worker_v1(
    request -> 'worker', 'ticket_export'
  );
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  request_audience := request ->> 'audience';
  required_capability := request ->> 'requiredCapability';
  expected_revision := app.private_ticket_runtime_js_uint_v1(
    request -> 'expectedRevision',1,9007199254740990
  );
  definition := next_document -> 'definition';
  next_state := next_document ->> 'state';
  next_revision := app.private_ticket_runtime_js_uint_v1(
    next_document -> 'revision',2,9007199254740991
  );
  next_attempts := app.private_ticket_runtime_js_uint_v1(
    next_document -> 'attempts',0,100
  )::smallint;
  next_failure := next_document ->> 'failureCode';
  changed_at := app.private_ticket_runtime_instant_v1(next_document -> 'updatedAt');
  next_available_at := app.private_ticket_runtime_instant_v1(
    next_document -> 'availableAt'
  );
  IF jsonb_typeof(next_document -> 'lease') = 'object' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(
      next_document -> 'lease',ARRAY['workerId','fenceSha256','claimedAt','expiresAt']
    ) THEN RAISE EXCEPTION 'ticket export lease projection is invalid' USING ERRCODE='22023'; END IF;
    next_lease_worker := app.private_ticket_runtime_uuid_v1(
      next_document #>> '{lease,workerId}'
    );
    next_fence := app.private_ticket_runtime_digest_v1(
      next_document #>> '{lease,fenceSha256}'
    );
    next_claimed_at := app.private_ticket_runtime_instant_v1(
      next_document #> '{lease,claimedAt}'
    );
    next_lease_expires_at := app.private_ticket_runtime_instant_v1(
      next_document #> '{lease,expiresAt}'
    );
  END IF;
  IF jsonb_typeof(next_document -> 'artifact') = 'object' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(
      next_document -> 'artifact',ARRAY['id','sha256','rows','bytes','expiresAt']
    ) THEN RAISE EXCEPTION 'ticket export artifact projection is invalid' USING ERRCODE='22023'; END IF;
    next_artifact_id := app.private_ticket_runtime_uuid_v1(
      next_document #>> '{artifact,id}'
    );
    next_artifact_digest := app.private_ticket_runtime_digest_v1(
      next_document #>> '{artifact,sha256}'
    );
    next_artifact_rows := app.private_ticket_runtime_js_uint_v1(
      next_document #> '{artifact,rows}',0,1000000
    )::integer;
    next_artifact_bytes := app.private_ticket_runtime_js_uint_v1(
      next_document #> '{artifact,bytes}',1,1073741824
    );
    next_artifact_expires_at := app.private_ticket_runtime_instant_v1(
      next_document #> '{artifact,expiresAt}'
    );
  END IF;
  IF jsonb_typeof(next_document -> 'terminalAt') = 'string' THEN
    next_terminal_at := app.private_ticket_runtime_instant_v1(
      next_document -> 'terminalAt'
    );
  END IF;
  PERFORM set_config('app.tenant_id', request_tenant_id::text, true);
  SELECT candidate.* INTO job FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id=request_tenant_id
    AND candidate.id=app.private_ticket_runtime_uuid_v1(definition ->> 'id')
  FOR UPDATE;
  IF NOT FOUND OR job.kind IS DISTINCT FROM request_kind
     OR job.audience IS DISTINCT FROM request_audience
     OR job.revision IS DISTINCT FROM expected_revision THEN
    RAISE EXCEPTION 'ticket export worker revision conflict' USING ERRCODE='40001';
  END IF;
  IF definition IS DISTINCT FROM app.private_ticket_export_job_document_v1(job)->'definition'
     OR request -> 'query' IS DISTINCT FROM app.private_ticket_export_query_document_v1(job)
     OR app.private_ticket_runtime_instant_v1(next_document -> 'requestedAt')
        IS DISTINCT FROM job.requested_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'expiresAt')
        IS DISTINCT FROM job.expires_at
     OR next_revision <> expected_revision + 1
     OR changed_at < job.updated_at
     OR changed_at > transaction_timestamp()+interval '1 minute'
     OR next_state NOT IN ('pending','running','succeeded','failed','cancelled')
     OR next_failure NOT IN (
       'none','transient_storage','transient_database','authorization_revoked',
       'snapshot_stale','output_limit','lease_expired','expired','internal'
     ) THEN
    RAISE EXCEPTION 'ticket export worker transition is invalid' USING ERRCODE='22023';
  END IF;
  IF required_capability='ticket_export.claim' THEN
    valid_transition := next_state='running'
      AND (job.state='pending' AND job.available_at<=changed_at
        OR job.state='running' AND job.lease_expires_at<=changed_at)
      AND job.expires_at>changed_at AND job.attempts<job.maximum_attempts
      AND next_attempts=job.attempts+1 AND next_failure='none'
      AND next_available_at IS NOT DISTINCT FROM job.available_at
      AND next_lease_worker IS NOT DISTINCT FROM admitted_worker_id
      AND next_claimed_at IS NOT DISTINCT FROM changed_at
      AND next_lease_expires_at-changed_at BETWEEN interval '30 seconds' AND interval '15 minutes'
      AND next_lease_expires_at<=job.expires_at
      AND next_artifact_id IS NULL AND next_terminal_at IS NULL;
    action_name := 'ticket.export.claimed.legacy';
  ELSE
    IF job.state IN ('running','cancellation_requested')
       AND job.lease_worker_id IS DISTINCT FROM admitted_worker_id THEN
      RAISE EXCEPTION 'ticket export worker fence is unavailable' USING ERRCODE='42501';
    END IF;
    valid_transition := (
      job.state='running' AND next_state='running'
      AND next_attempts=job.attempts AND next_failure=job.failure_code
      AND next_lease_worker=admitted_worker_id
      AND next_fence IS NOT DISTINCT FROM job.lease_fence_digest
      AND next_claimed_at=changed_at
      AND next_lease_expires_at>job.lease_expires_at
      AND next_lease_expires_at<=job.expires_at
      AND next_available_at=job.available_at
      AND next_artifact_id IS NULL AND next_terminal_at IS NULL
    ) OR (
      job.state='running' AND next_state='succeeded'
      AND next_attempts=job.attempts AND next_failure='none'
      AND next_lease_worker IS NULL AND next_artifact_id IS NOT NULL
      AND next_artifact_rows<=job.maximum_rows
      AND next_artifact_bytes<=job.maximum_bytes
      AND next_artifact_expires_at=job.expires_at
      AND next_terminal_at=changed_at AND next_available_at=job.available_at
      AND job.lease_fence_digest IS NOT NULL
    ) OR (
      job.state='running' AND next_state='pending'
      AND next_attempts=job.attempts
      AND next_failure IN ('transient_storage','transient_database','internal')
      AND next_lease_worker IS NULL AND next_artifact_id IS NULL
      AND next_terminal_at IS NULL
      AND next_available_at-changed_at BETWEEN interval '1 second' AND interval '1 hour'
      AND next_available_at<job.expires_at
    ) OR (
      job.state='running' AND next_state='failed'
      AND next_attempts=job.attempts AND next_failure<>'none'
      AND next_lease_worker IS NULL AND next_artifact_id IS NULL
      AND next_terminal_at=changed_at AND next_available_at=job.available_at
    ) OR (
      job.state='cancellation_requested' AND next_state='cancelled'
      AND next_attempts=job.attempts AND next_failure='none'
      AND next_lease_worker IS NULL AND next_artifact_id IS NULL
      AND next_terminal_at=changed_at AND next_available_at=job.available_at
    );
    action_name := CASE next_state
      WHEN 'running' THEN 'ticket.export.lease_renewed.legacy'
      WHEN 'pending' THEN 'ticket.export.retry_scheduled.legacy'
      WHEN 'succeeded' THEN 'ticket.export.succeeded.legacy'
      WHEN 'cancelled' THEN 'ticket.export.cancelled.legacy'
      ELSE 'ticket.export.failed.legacy' END;
  END IF;
  IF NOT valid_transition OR NOT app.private_ticket_export_requester_live_v1(job)
     OR NOT app.private_ticket_export_snapshot_current_v1(job) THEN
    RAISE EXCEPTION 'ticket export worker transition is unavailable' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
  IF next_state='succeeded' THEN
    INSERT INTO public.ticket_export_manifests(
      tenant_id,job_id,artifact_id,job_revision,attempt,projection_version,
      digest,rows,bytes,recorded_at,expires_at,published_at
    ) VALUES (
      job.tenant_id,job.id,next_artifact_id,job.revision,job.attempts,
      job.projection_version,next_artifact_digest,next_artifact_rows,
      next_artifact_bytes,changed_at,job.expires_at,changed_at
    );
  END IF;
  UPDATE public.ticket_export_jobs SET
    state=next_state,revision=next_revision,attempts=next_attempts,
    failure_code=next_failure,updated_at=changed_at,available_at=next_available_at,
    lease_worker_id=next_lease_worker,lease_fence_digest=next_fence,
    lease_claimed_at=next_claimed_at,lease_expires_at=next_lease_expires_at,
    artifact_id=next_artifact_id,artifact_digest=next_artifact_digest,
    artifact_rows=next_artifact_rows,artifact_bytes=next_artifact_bytes,
    artifact_expires_at=next_artifact_expires_at,terminal_at=next_terminal_at
  WHERE tenant_id=job.tenant_id AND id=job.id AND revision=expected_revision
  RETURNING * INTO job;
  IF NOT FOUND THEN RAISE EXCEPTION 'ticket export worker transition lost its fence' USING ERRCODE='40001'; END IF;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    job.tenant_id,action_name,'ticket_export_job',job.id,next_revision,
    changed_at,'success',jsonb_build_object(
      'inputRevision',expected_revision,'attempt',next_attempts,'state',next_state
    )
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'record',app.private_ticket_export_record_v1(job.id,true)
  );
END;
$function$;
ALTER FUNCTION app.commit_ticket_export_worker_transition_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_export_worker_transition_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_export_worker_transition_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_export_revocation_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE admitted_worker_id uuid;
DECLARE request_tenant_id uuid;
DECLARE expected_revision bigint;
DECLARE next_document jsonb;
DECLARE definition jsonb;
DECLARE job public.ticket_export_jobs%ROWTYPE;
DECLARE next_revision bigint;
DECLARE changed_at timestamp with time zone;
BEGIN
  IF request IS NULL OR pg_column_size(request)>2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request,ARRAY[
         'schemaVersion','worker','tenantId','kind','audience',
         'requiredCapability','expectedRevision','next'
       ]
     ) OR request ->> 'schemaVersion'<>'1'
     OR request ->> 'kind' NOT IN ('alert','case')
     OR request ->> 'audience' NOT IN ('operator','customer')
     OR request ->> 'requiredCapability'<>'ticket_export.execute'
     OR jsonb_typeof(request -> 'next')<>'object' THEN
    RAISE EXCEPTION 'ticket export revocation request is invalid' USING ERRCODE='22023';
  END IF;
  next_document:=request -> 'next';
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       next_document,ARRAY[
         'definition','state','revision','attempts','failureCode','requestedAt',
         'updatedAt','availableAt','expiresAt','lease','artifact','terminalAt'
       ]
     ) OR jsonb_typeof(next_document -> 'definition')<>'object' THEN
    RAISE EXCEPTION 'ticket export revocation projection is invalid' USING ERRCODE='22023';
  END IF;
  admitted_worker_id:=app.private_ticket_runtime_require_worker_v1(
    request -> 'worker','ticket_export'
  );
  request_tenant_id:=app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  expected_revision:=app.private_ticket_runtime_js_uint_v1(
    request -> 'expectedRevision',1,9007199254740990
  );
  definition:=next_document -> 'definition';
  next_revision:=app.private_ticket_runtime_js_uint_v1(
    next_document -> 'revision',2,9007199254740991
  );
  changed_at:=app.private_ticket_runtime_instant_v1(next_document -> 'updatedAt');
  PERFORM admitted_worker_id;
  PERFORM set_config('app.tenant_id',request_tenant_id::text,true);
  SELECT candidate.* INTO job FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id=request_tenant_id
    AND candidate.id=app.private_ticket_runtime_uuid_v1(definition ->> 'id')
  FOR UPDATE;
  IF NOT FOUND OR job.kind::text<>request ->> 'kind'
     OR job.audience<>request ->> 'audience'
     OR job.revision<>expected_revision THEN
    RAISE EXCEPTION 'ticket export revocation revision conflict' USING ERRCODE='40001';
  END IF;
  IF app.private_ticket_export_requester_live_v1(job)
     OR next_revision<>expected_revision+1
     OR definition IS DISTINCT FROM app.private_ticket_export_job_document_v1(job)->'definition'
     OR next_document ->> 'state'<>'failed'
     OR next_document ->> 'failureCode'<>'authorization_revoked'
     OR next_document ->> 'attempts'<>job.attempts::text
     OR next_document -> 'lease'<>'null'::jsonb
     OR next_document -> 'artifact'<>'null'::jsonb
     OR jsonb_typeof(next_document -> 'terminalAt')<>'string'
     OR app.private_ticket_runtime_instant_v1(next_document -> 'terminalAt')<>changed_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'requestedAt')<>job.requested_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'availableAt')<>job.available_at
     OR app.private_ticket_runtime_instant_v1(next_document -> 'expiresAt')<>job.expires_at
     OR changed_at<job.updated_at OR changed_at>transaction_timestamp()+interval '1 minute' THEN
    RAISE EXCEPTION 'ticket export revocation transition is unavailable' USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
  UPDATE public.ticket_export_jobs SET
    state='failed',revision=next_revision,failure_code='authorization_revoked',
    updated_at=changed_at,lease_worker_id=NULL,lease_fence_digest=NULL,
    lease_claimed_at=NULL,lease_expires_at=NULL,artifact_id=NULL,
    artifact_digest=NULL,artifact_rows=NULL,artifact_bytes=NULL,
    artifact_expires_at=NULL,terminal_at=changed_at
  WHERE tenant_id=job.tenant_id AND id=job.id AND revision=expected_revision;
  IF NOT FOUND THEN RAISE EXCEPTION 'ticket export revocation lost its fence' USING ERRCODE='40001'; END IF;
  PERFORM app.private_ticket_runtime_append_system_effects_v1(
    job.tenant_id,'ticket.export.authorization_rejected.legacy',
    'ticket_export_job',job.id,next_revision,changed_at,'failure',
    jsonb_build_object('inputRevision',expected_revision,'attempt',job.attempts)
  );
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion',1,'job',app.private_ticket_export_job_document_v1(job)
  );
END;
$function$;
ALTER FUNCTION app.commit_ticket_export_revocation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.commit_ticket_export_revocation_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_export_revocation_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.ticket_bulk_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET quote_all_identifiers = off
SET TimeZone = 'UTC'
SET DateStyle = 'ISO, YMD'
SET IntervalStyle = 'postgres'
SET extra_float_digits = 3
SET bytea_output = 'hex'
SET standard_conforming_strings = on
SET lc_numeric = 'C'
AS $function$
DECLARE relation_name text;
DECLARE function_identity text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'ticket_bulk_jobs','ticket_bulk_query_snapshots','ticket_bulk_targets',
    'ticket_bulk_batches','ticket_bulk_command_receipts'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname='public' AND relation.relname=relation_name
        AND relation.relkind='r' AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner)='periapsis_ticket_runtime_owner'
    ) OR has_table_privilege('periapsis_api',format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE')
      OR has_table_privilege('periapsis_worker',format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE')
      OR has_table_privilege('periapsis_notifier',format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE') THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.resolve_ticket_bulk_access_v1(jsonb)',
    'app.resolve_ticket_bulk_query_v1(jsonb)',
    'app.lookup_ticket_bulk_replay_v1(jsonb)',
    'app.commit_ticket_bulk_request_v1(jsonb)',
    'app.get_ticket_bulk_v1(jsonb)',
    'app.commit_ticket_bulk_cancellation_v1(jsonb)',
    'app.list_ticket_bulk_results_v1(jsonb)'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid=to_regprocedure(function_identity) AND procedure.prosecdef
           AND pg_catalog.pg_get_userbyid(procedure.proowner)='periapsis_migrator')
       OR NOT has_function_privilege('periapsis_api',function_identity,'EXECUTE')
       OR has_function_privilege('periapsis_worker',function_identity,'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
         )) AS privilege WHERE procedure.oid=to_regprocedure(function_identity)
           AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.list_ticket_work_queues_v1(jsonb)',
    'app.claim_ticket_bulk_batch_v1(jsonb)',
    'app.apply_ticket_bulk_target_v1(jsonb)',
    'app.release_ticket_bulk_batch_v1(jsonb)',
    'app.report_ticket_bulk_batch_failure_v1(jsonb)',
    'app.finalize_ticket_bulk_cancellation_v1(jsonb)',
    'app.finalize_ticket_bulk_authorization_revocation_v1(jsonb)'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid=to_regprocedure(function_identity) AND procedure.prosecdef
           AND pg_catalog.pg_get_userbyid(procedure.proowner)='periapsis_migrator')
       OR NOT has_function_privilege('periapsis_worker',function_identity,'EXECUTE')
       OR has_function_privilege('periapsis_api',function_identity,'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
         )) AS privilege WHERE procedure.oid=to_regprocedure(function_identity)
           AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN EXISTS (
    SELECT 1 FROM public.ticket_runtime_service_principals AS principal
    WHERE principal.id='01890f00-0000-7000-8000-0000000000f1'::uuid
      AND principal.key='ticket_runtime' AND principal.enabled
  ) AND (SELECT count(*) FROM public.ticket_runtime_service_principals)=1
    AND (SELECT count(*) FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgname LIKE 'ticket_bulk_%_write_guard_v1'
        AND trigger.tgenabled='O' AND NOT trigger.tgisinternal)=5;
END;
$function$;
ALTER FUNCTION app.ticket_bulk_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_bulk_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor, periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.ticket_bulk_runtime_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.ticket_export_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET quote_all_identifiers = off
SET TimeZone = 'UTC'
SET DateStyle = 'ISO, YMD'
SET IntervalStyle = 'postgres'
SET extra_float_digits = 3
SET bytea_output = 'hex'
SET standard_conforming_strings = on
SET lc_numeric = 'C'
AS $function$
DECLARE relation_name text;
DECLARE function_identity text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'ticket_export_jobs','ticket_export_query_snapshots','ticket_export_manifests',
    'ticket_export_command_receipts','ticket_export_artifact_cleanups'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname='public' AND relation.relname=relation_name
        AND relation.relkind='r' AND relation.relrowsecurity AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner)='periapsis_ticket_runtime_owner'
    ) OR has_table_privilege('periapsis_api',format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE')
      OR has_table_privilege('periapsis_worker',format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE')
      OR has_table_privilege('periapsis_notifier',format('public.%I',relation_name),'SELECT,INSERT,UPDATE,DELETE') THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.resolve_ticket_export_access_v1(jsonb)',
    'app.resolve_ticket_export_query_v1(jsonb)',
    'app.lookup_ticket_export_replay_v1(jsonb)',
    'app.commit_ticket_export_request_v1(jsonb)',
    'app.get_ticket_export_v1(jsonb)',
    'app.commit_ticket_export_owner_transition_v1(jsonb)',
    'app.resolve_ticket_export_worker_access_v1(jsonb)',
    'app.select_ticket_export_claim_candidate_v1(jsonb)',
    'app.get_ticket_export_for_worker_v1(jsonb)',
    'app.get_revoked_ticket_export_for_worker_v1(jsonb)',
    'app.commit_ticket_export_worker_transition_v1(jsonb)',
    'app.commit_ticket_export_revocation_v1(jsonb)',
    'app.read_ticket_export_application_page_v1(jsonb)'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid=to_regprocedure(function_identity) AND procedure.prosecdef
           AND pg_catalog.pg_get_userbyid(procedure.proowner)='periapsis_migrator')
       OR NOT has_function_privilege('periapsis_api',function_identity,'EXECUTE')
       OR has_function_privilege('periapsis_worker',function_identity,'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
         )) AS privilege WHERE procedure.oid=to_regprocedure(function_identity)
           AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.claim_ticket_export_v1(jsonb)',
    'app.read_ticket_export_page_v1(jsonb)',
    'app.record_ticket_export_manifest_v1(jsonb)',
    'app.commit_ticket_export_success_v1(jsonb)',
    'app.report_ticket_export_failure_v1(jsonb)',
    'app.acknowledge_ticket_export_cancellation_v1(jsonb)',
    'app.reject_ticket_export_revocation_v1(jsonb)',
    'app.claim_ticket_export_artifact_reconciliation_v1(jsonb)',
    'app.finalize_ticket_export_artifact_reconciliation_v1(jsonb)',
    'app.report_ticket_export_artifact_reconciliation_failure_v1(jsonb)',
    'app.read_ticket_export_reconciliation_metrics_v1(jsonb)'
  ] LOOP
    IF to_regprocedure(function_identity) IS NULL
       OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         WHERE procedure.oid=to_regprocedure(function_identity) AND procedure.prosecdef
           AND pg_catalog.pg_get_userbyid(procedure.proowner)='periapsis_migrator')
       OR NOT has_function_privilege('periapsis_worker',function_identity,'EXECUTE')
       OR has_function_privilege('periapsis_api',function_identity,'EXECUTE')
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc AS procedure
         CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
           procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
         )) AS privilege WHERE procedure.oid=to_regprocedure(function_identity)
           AND privilege.grantee=0 AND privilege.privilege_type='EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN EXISTS (
    SELECT 1 FROM public.ticket_runtime_service_principals AS principal
    WHERE principal.id='01890f00-0000-7000-8000-0000000000f1'::uuid
      AND principal.key='ticket_runtime' AND principal.enabled
  ) AND (SELECT count(*) FROM public.ticket_runtime_service_principals)=1
    AND (SELECT count(*) FROM pg_catalog.pg_trigger AS trigger
      WHERE trigger.tgname LIKE 'ticket_export_%_write_guard_v1'
        AND trigger.tgenabled='O' AND NOT trigger.tgisinternal)=5;
END;
$function$;
ALTER FUNCTION app.ticket_export_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_export_runtime_schema_readiness_v1()
FROM PUBLIC, periapsis_notifier, periapsis_auditor, periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.ticket_export_runtime_schema_readiness_v1()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

COMMENT ON TABLE public.ticket_bulk_jobs IS
  'Tenant-scoped bounded ticket bulk commands with strong revision fences and materialized immutable target inputs.';
COMMENT ON TABLE public.ticket_export_manifests IS
  'Attempt-scoped immutable export artifact manifests; only the publication timestamp may transition once under the closed ABI.';
COMMENT ON FUNCTION app.ticket_bulk_runtime_schema_readiness_v1() IS
  'Attests the closed ticket bulk ABI, forced RLS, inert runtime owner, worker/API ACL partition, write guards, and system principal.';
COMMENT ON FUNCTION app.ticket_export_runtime_schema_readiness_v1() IS
  'Attests the closed ticket export, legacy bridge, fenced streaming, durable reconciliation, forced RLS, and ACL surfaces.';
