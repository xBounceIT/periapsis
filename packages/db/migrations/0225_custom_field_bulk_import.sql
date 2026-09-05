DO $role$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_custom_field_import_owner'
  ) THEN
    CREATE ROLE periapsis_custom_field_import_owner
      NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$role$;--> statement-breakpoint
CREATE TABLE "custom_field_import_command_receipts" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"actor_user_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"object_type" "custom_field_object_type" NOT NULL,
	"action" text NOT NULL,
	"idempotency_key_digest" "bytea" NOT NULL,
	"request_fingerprint_digest" "bytea" NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"created_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "custom_field_import_command_receipts_replay_key" UNIQUE("tenant_id","actor_user_id","owner_membership_id","object_type","action","idempotency_key_digest"),
	CONSTRAINT "custom_field_import_command_receipts_shape_check" CHECK ((uuid_extract_version("custom_field_import_command_receipts"."id") = 7) is true
        and "custom_field_import_command_receipts"."action" in ('request','cancel')
        and octet_length("custom_field_import_command_receipts"."idempotency_key_digest") = 32
        and octet_length("custom_field_import_command_receipts"."request_fingerprint_digest") = 32
        and jsonb_typeof("custom_field_import_command_receipts"."result_snapshot") = 'object'
        and octet_length("custom_field_import_command_receipts"."result_snapshot"::text) <= 34603008
        and "custom_field_import_command_receipts"."expires_at" > "custom_field_import_command_receipts"."created_at")
);
--> statement-breakpoint
ALTER TABLE "custom_field_import_command_receipts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_import_jobs" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid NOT NULL,
	"requester_user_id" uuid NOT NULL,
	"owner_membership_id" uuid NOT NULL,
	"object_type" "custom_field_object_type" NOT NULL,
	"mode" text NOT NULL,
	"manifest_snapshot" jsonb NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"projection_version" bigint NOT NULL,
	"maximum_attempts" smallint NOT NULL,
	"state" text NOT NULL,
	"revision" bigint NOT NULL,
	"attempts" smallint DEFAULT 0 NOT NULL,
	"total" integer NOT NULL,
	"dry_run_valid" integer DEFAULT 0 NOT NULL,
	"committed" integer DEFAULT 0 NOT NULL,
	"no_change" integer DEFAULT 0 NOT NULL,
	"validation_failed" integer DEFAULT 0 NOT NULL,
	"definition_changed" integer DEFAULT 0 NOT NULL,
	"version_conflict" integer DEFAULT 0 NOT NULL,
	"not_found_or_hidden" integer DEFAULT 0 NOT NULL,
	"authorization_denied" integer DEFAULT 0 NOT NULL,
	"cancelled" integer DEFAULT 0 NOT NULL,
	"authorization_revoked" integer DEFAULT 0 NOT NULL,
	"expired" integer DEFAULT 0 NOT NULL,
	"internal_failure" integer DEFAULT 0 NOT NULL,
	"request_id" uuid NOT NULL,
	"correlation_id" uuid NOT NULL,
	"ip_address" "inet" NOT NULL,
	"user_agent" text NOT NULL,
	"authentication_method" text NOT NULL,
	"requested_at" timestamp with time zone NOT NULL,
	"updated_at" timestamp with time zone NOT NULL,
	"available_at" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"fence_id" uuid,
	"lease_until" timestamp with time zone,
	"terminal_at" timestamp with time zone,
	CONSTRAINT "custom_field_import_jobs_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "custom_field_import_jobs_exact_coordinate_key" UNIQUE("tenant_id","id","requester_user_id","owner_membership_id","object_type"),
	CONSTRAINT "custom_field_import_jobs_id_uuidv7_check" CHECK ((uuid_extract_version("custom_field_import_jobs"."id") = 7) is true),
	CONSTRAINT "custom_field_import_jobs_definition_check" CHECK ("custom_field_import_jobs"."mode" in ('dry_run','commit')
        and jsonb_typeof("custom_field_import_jobs"."manifest_snapshot") = 'object'
        and octet_length("custom_field_import_jobs"."manifest_snapshot"::text) <= 34603008
        and octet_length("custom_field_import_jobs"."request_digest") = 32
        and "custom_field_import_jobs"."projection_version" = 1
        and "custom_field_import_jobs"."maximum_attempts" between 1 and 5),
	CONSTRAINT "custom_field_import_jobs_state_check" CHECK ("custom_field_import_jobs"."state" in ('pending','running','cancellation_requested','completed','failed','cancelled','authorization_revoked','expired')
        and "custom_field_import_jobs"."revision" between 1 and 2147483646
        and "custom_field_import_jobs"."attempts" between 0 and "custom_field_import_jobs"."maximum_attempts"
        and "custom_field_import_jobs"."total" between 1 and 10000
        and "custom_field_import_jobs"."dry_run_valid" >= 0 and "custom_field_import_jobs"."committed" >= 0
        and "custom_field_import_jobs"."no_change" >= 0 and "custom_field_import_jobs"."validation_failed" >= 0
        and "custom_field_import_jobs"."definition_changed" >= 0 and "custom_field_import_jobs"."version_conflict" >= 0
        and "custom_field_import_jobs"."not_found_or_hidden" >= 0 and "custom_field_import_jobs"."authorization_denied" >= 0
        and "custom_field_import_jobs"."cancelled" >= 0 and "custom_field_import_jobs"."authorization_revoked" >= 0
        and "custom_field_import_jobs"."expired" >= 0 and "custom_field_import_jobs"."internal_failure" >= 0
        and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
          + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
          + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
          + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
          + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
          + "custom_field_import_jobs"."internal_failure") <= "custom_field_import_jobs"."total"
        and "custom_field_import_jobs"."updated_at" >= "custom_field_import_jobs"."requested_at"
        and "custom_field_import_jobs"."available_at" >= "custom_field_import_jobs"."requested_at"
        and "custom_field_import_jobs"."available_at" <= "custom_field_import_jobs"."expires_at"
        and "custom_field_import_jobs"."expires_at" > "custom_field_import_jobs"."requested_at"
        and (("custom_field_import_jobs"."fence_id" is null and "custom_field_import_jobs"."lease_until" is null)
          or ("custom_field_import_jobs"."fence_id" is not null and "custom_field_import_jobs"."lease_until" is not null))
        and ("custom_field_import_jobs"."terminal_at" is null) = ("custom_field_import_jobs"."state" not in ('completed','failed','cancelled','authorization_revoked','expired'))
        and ("custom_field_import_jobs"."lease_until" is null or (
          (uuid_extract_version("custom_field_import_jobs"."fence_id") = 7) is true
          and "custom_field_import_jobs"."lease_until" > "custom_field_import_jobs"."updated_at"
          and "custom_field_import_jobs"."lease_until" <= "custom_field_import_jobs"."expires_at"
          and "custom_field_import_jobs"."lease_until" <= "custom_field_import_jobs"."updated_at" + interval '5 minutes'
        ))
        and ("custom_field_import_jobs"."terminal_at" is null or (
          "custom_field_import_jobs"."terminal_at" = "custom_field_import_jobs"."updated_at"
          and "custom_field_import_jobs"."terminal_at" >= "custom_field_import_jobs"."requested_at"
          and ("custom_field_import_jobs"."terminal_at" <= "custom_field_import_jobs"."expires_at"
            or "custom_field_import_jobs"."state" in ('expired','cancelled'))
        ))
        and case "custom_field_import_jobs"."state"
          when 'pending' then
            "custom_field_import_jobs"."revision" = 1
            and "custom_field_import_jobs"."attempts" = 0
            and "custom_field_import_jobs"."fence_id" is null
            and "custom_field_import_jobs"."terminal_at" is null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") < "custom_field_import_jobs"."total"
            and "custom_field_import_jobs"."updated_at" <= "custom_field_import_jobs"."expires_at"
            and "custom_field_import_jobs"."available_at" >= "custom_field_import_jobs"."updated_at"
          when 'running' then
            "custom_field_import_jobs"."attempts" > 0
            and "custom_field_import_jobs"."fence_id" is not null
            and "custom_field_import_jobs"."terminal_at" is null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") < "custom_field_import_jobs"."total"
            and ("custom_field_import_jobs"."cancelled" + "custom_field_import_jobs"."authorization_revoked"
              + "custom_field_import_jobs"."expired" + "custom_field_import_jobs"."internal_failure") = 0
            and "custom_field_import_jobs"."updated_at" <= "custom_field_import_jobs"."expires_at"
            and "custom_field_import_jobs"."available_at" <= "custom_field_import_jobs"."updated_at"
          when 'cancellation_requested' then
            "custom_field_import_jobs"."attempts" > 0
            and "custom_field_import_jobs"."fence_id" is not null
            and "custom_field_import_jobs"."terminal_at" is null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") < "custom_field_import_jobs"."total"
            and ("custom_field_import_jobs"."cancelled" + "custom_field_import_jobs"."authorization_revoked"
              + "custom_field_import_jobs"."expired" + "custom_field_import_jobs"."internal_failure") = 0
            and "custom_field_import_jobs"."updated_at" <= "custom_field_import_jobs"."expires_at"
          when 'completed' then
            "custom_field_import_jobs"."fence_id" is null
            and "custom_field_import_jobs"."terminal_at" is not null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") = "custom_field_import_jobs"."total"
            and ("custom_field_import_jobs"."cancelled" + "custom_field_import_jobs"."authorization_revoked"
              + "custom_field_import_jobs"."expired" + "custom_field_import_jobs"."internal_failure") = 0
          when 'failed' then
            "custom_field_import_jobs"."fence_id" is null
            and "custom_field_import_jobs"."terminal_at" is not null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") = "custom_field_import_jobs"."total"
            and "custom_field_import_jobs"."internal_failure" > 0
            and "custom_field_import_jobs"."cancelled" = 0
            and "custom_field_import_jobs"."authorization_revoked" = 0
          when 'cancelled' then
            "custom_field_import_jobs"."fence_id" is null
            and "custom_field_import_jobs"."terminal_at" is not null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") = "custom_field_import_jobs"."total"
            and "custom_field_import_jobs"."cancelled" > 0
            and "custom_field_import_jobs"."authorization_revoked" = 0
            and "custom_field_import_jobs"."internal_failure" = 0
          when 'authorization_revoked' then
            "custom_field_import_jobs"."fence_id" is null
            and "custom_field_import_jobs"."terminal_at" is not null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") = "custom_field_import_jobs"."total"
            and "custom_field_import_jobs"."authorization_revoked" > 0
            and "custom_field_import_jobs"."cancelled" = 0
            and "custom_field_import_jobs"."expired" = 0
            and "custom_field_import_jobs"."internal_failure" = 0
          when 'expired' then
            "custom_field_import_jobs"."fence_id" is null
            and "custom_field_import_jobs"."terminal_at" is not null
            and ("custom_field_import_jobs"."dry_run_valid" + "custom_field_import_jobs"."committed" + "custom_field_import_jobs"."no_change"
              + "custom_field_import_jobs"."validation_failed" + "custom_field_import_jobs"."definition_changed"
              + "custom_field_import_jobs"."version_conflict" + "custom_field_import_jobs"."not_found_or_hidden"
              + "custom_field_import_jobs"."authorization_denied" + "custom_field_import_jobs"."cancelled"
              + "custom_field_import_jobs"."authorization_revoked" + "custom_field_import_jobs"."expired"
              + "custom_field_import_jobs"."internal_failure") = "custom_field_import_jobs"."total"
            and "custom_field_import_jobs"."expired" > 0
            and "custom_field_import_jobs"."cancelled" = 0
            and "custom_field_import_jobs"."authorization_revoked" = 0
            and "custom_field_import_jobs"."internal_failure" = 0
          else false
        end),
	CONSTRAINT "custom_field_import_jobs_audit_check" CHECK (octet_length("custom_field_import_jobs"."user_agent") <= 1024
        and "custom_field_import_jobs"."user_agent" !~ '[[:cntrl:]]'
        and "custom_field_import_jobs"."authentication_method" ~ '^[a-z][a-z0-9._-]{0,63}$')
);
--> statement-breakpoint
ALTER TABLE "custom_field_import_jobs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_import_results" (
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"outcome" text NOT NULL,
	"resulting_version" bigint NOT NULL,
	"field_errors" jsonb NOT NULL,
	"command_key_digest" "bytea" NOT NULL,
	"request_fingerprint_digest" "bytea" NOT NULL,
	"recorded_at" timestamp with time zone NOT NULL,
	CONSTRAINT "custom_field_import_results_pkey" PRIMARY KEY("tenant_id","job_id","sequence"),
	CONSTRAINT "custom_field_import_results_shape_check" CHECK ("custom_field_import_results"."sequence" between 1 and 10000
        and "custom_field_import_results"."outcome" in ('dry_run_valid','committed','no_change','validation_failed','definition_changed','version_conflict','not_found_or_hidden','authorization_denied','cancelled','authorization_revoked','expired','internal_failure')
        and "custom_field_import_results"."resulting_version" between 0 and 9007199254740991
        and jsonb_typeof("custom_field_import_results"."field_errors") = 'array'
        and jsonb_array_length("custom_field_import_results"."field_errors") <= 512
        and octet_length("custom_field_import_results"."field_errors"::text) <= 1048576
        and octet_length("custom_field_import_results"."command_key_digest") = 32
        and octet_length("custom_field_import_results"."request_fingerprint_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "custom_field_import_results" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "custom_field_import_rows" (
	"tenant_id" uuid NOT NULL,
	"job_id" uuid NOT NULL,
	"sequence" integer NOT NULL,
	"target_id" uuid NOT NULL,
	"expected_version" bigint NOT NULL,
	"cells_snapshot" jsonb NOT NULL,
	"cells_digest" "bytea" NOT NULL,
	CONSTRAINT "custom_field_import_rows_pkey" PRIMARY KEY("tenant_id","job_id","sequence"),
	CONSTRAINT "custom_field_import_rows_job_target_key" UNIQUE("tenant_id","job_id","target_id"),
	CONSTRAINT "custom_field_import_rows_exact_coordinate_key" UNIQUE("tenant_id","job_id","sequence","target_id","expected_version"),
	CONSTRAINT "custom_field_import_rows_shape_check" CHECK ("custom_field_import_rows"."sequence" between 1 and 10000
        and "custom_field_import_rows"."expected_version" between 1 and 9007199254740990
        and jsonb_typeof("custom_field_import_rows"."cells_snapshot") = 'array'
        and jsonb_array_length("custom_field_import_rows"."cells_snapshot") between 0 and 512
        and octet_length("custom_field_import_rows"."cells_snapshot"::text) <= 33554432
        and octet_length("custom_field_import_rows"."cells_digest") = 32)
);
--> statement-breakpoint
ALTER TABLE "custom_field_import_rows" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "custom_field_import_command_receipts" ADD CONSTRAINT "custom_field_import_command_receipts_job_coordinate_fk" FOREIGN KEY ("tenant_id","job_id","actor_user_id","owner_membership_id","object_type") REFERENCES "public"."custom_field_import_jobs"("tenant_id","id","requester_user_id","owner_membership_id","object_type") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "custom_field_import_jobs" ADD CONSTRAINT "custom_field_import_jobs_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "custom_field_import_jobs" ADD CONSTRAINT "custom_field_import_jobs_owner_fk" FOREIGN KEY ("tenant_id","owner_membership_id","requester_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "custom_field_import_results" ADD CONSTRAINT "custom_field_import_results_row_fk" FOREIGN KEY ("tenant_id","job_id","sequence") REFERENCES "public"."custom_field_import_rows"("tenant_id","job_id","sequence") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "custom_field_import_rows" ADD CONSTRAINT "custom_field_import_rows_job_fk" FOREIGN KEY ("tenant_id","job_id") REFERENCES "public"."custom_field_import_jobs"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
CREATE INDEX "custom_field_import_command_receipts_expiry_idx" ON "custom_field_import_command_receipts" USING btree ("expires_at","tenant_id","id");--> statement-breakpoint
CREATE INDEX "custom_field_import_jobs_claim_idx" ON "custom_field_import_jobs" USING btree ("tenant_id","object_type","state","available_at","id");--> statement-breakpoint
CREATE INDEX "custom_field_import_jobs_queue_idx" ON "custom_field_import_jobs" USING btree ("state","available_at","tenant_id","id");--> statement-breakpoint
CREATE INDEX "custom_field_import_jobs_owner_idx" ON "custom_field_import_jobs" USING btree ("tenant_id","owner_membership_id","requested_at","id");--> statement-breakpoint
CREATE INDEX "custom_field_import_results_page_idx" ON "custom_field_import_results" USING btree ("tenant_id","job_id","sequence");--> statement-breakpoint
CREATE INDEX "custom_field_import_rows_sequence_idx" ON "custom_field_import_rows" USING btree ("tenant_id","job_id","sequence");--> statement-breakpoint
CREATE POLICY "custom_field_import_command_receipts_owner_access" ON "custom_field_import_command_receipts" AS PERMISSIVE FOR ALL TO "periapsis_custom_field_import_owner" USING ("custom_field_import_command_receipts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("custom_field_import_command_receipts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "custom_field_import_jobs_owner_access" ON "custom_field_import_jobs" AS PERMISSIVE FOR ALL TO "periapsis_custom_field_import_owner" USING ("custom_field_import_jobs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("custom_field_import_jobs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "custom_field_import_results_owner_access" ON "custom_field_import_results" AS PERMISSIVE FOR ALL TO "periapsis_custom_field_import_owner" USING ("custom_field_import_results"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("custom_field_import_results"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "custom_field_import_rows_owner_access" ON "custom_field_import_rows" AS PERMISSIVE FOR ALL TO "periapsis_custom_field_import_owner" USING ("custom_field_import_rows"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("custom_field_import_rows"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);
--> statement-breakpoint

-- The import queue is private. Runtime roles can invoke only the bounded ABI
-- below; its NOLOGIN owner remains subject to FORCE RLS.
ALTER ROLE periapsis_custom_field_import_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE periapsis_custom_field_import_owner
  SET search_path = pg_catalog, public, app;
REVOKE periapsis_custom_field_import_owner
  FROM periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;

ALTER TABLE public.custom_field_import_jobs OWNER TO periapsis_custom_field_import_owner;
ALTER TABLE public.custom_field_import_rows OWNER TO periapsis_custom_field_import_owner;
ALTER TABLE public.custom_field_import_results OWNER TO periapsis_custom_field_import_owner;
ALTER TABLE public.custom_field_import_command_receipts OWNER TO periapsis_custom_field_import_owner;

ALTER TABLE public.custom_field_import_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.custom_field_import_rows FORCE ROW LEVEL SECURITY;
ALTER TABLE public.custom_field_import_results FORCE ROW LEVEL SECURITY;
ALTER TABLE public.custom_field_import_command_receipts FORCE ROW LEVEL SECURITY;

CREATE TRIGGER custom_field_import_rows_immutable_v1
BEFORE UPDATE OR DELETE ON public.custom_field_import_rows
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();
CREATE TRIGGER custom_field_import_results_immutable_v1
BEFORE UPDATE OR DELETE ON public.custom_field_import_results
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();
CREATE TRIGGER custom_field_import_command_receipts_immutable_v1
BEFORE UPDATE OR DELETE ON public.custom_field_import_command_receipts
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();

REVOKE ALL ON TABLE
  public.custom_field_import_jobs,
  public.custom_field_import_rows,
  public.custom_field_import_results,
  public.custom_field_import_command_receipts
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.custom_field_import_jobs,
  public.custom_field_import_rows,
  public.custom_field_import_results,
  public.custom_field_import_command_receipts
TO periapsis_custom_field_import_owner;

-- Cross-tenant queue discovery is a separate, payload-free capability. The
-- NOLOGIN migrator owns that one bounded SECURITY DEFINER function and gets
-- only the coordinates needed to find work; the runtime worker never receives
-- table privileges and opens a tenant-scoped transaction before loading it.
GRANT SELECT (
  tenant_id, id, state, available_at, expires_at, fence_id, lease_until
) ON public.custom_field_import_jobs TO periapsis_migrator;

GRANT USAGE ON SCHEMA app, public TO periapsis_custom_field_import_owner;
GRANT SELECT ON TABLE
  public.tenants, public.tenant_memberships,
  public.custom_field_definitions, public.custom_field_definition_revisions,
  public.custom_field_options, public.custom_field_permissions,
  public.alerts, public.cases, public.custom_field_values,
  public.ticket_activities,
  public.operator_team_assignment_epochs, public.operator_team_roster_entries,
  public.tenant_authorization_sources, public.ticket_runtime_service_principals
TO periapsis_custom_field_import_owner;
-- PostgreSQL requires UPDATE privilege for SELECT ... FOR SHARE. Restrict that
-- capability to an immutable coordinate column on the internal NOLOGIN owner;
-- runtime roles still have no table privileges.
GRANT UPDATE (id) ON TABLE public.tenant_memberships
TO periapsis_custom_field_import_owner;
GRANT UPDATE (id) ON TABLE public.custom_field_definitions
TO periapsis_custom_field_import_owner;
GRANT INSERT, UPDATE, DELETE ON TABLE public.custom_field_values
TO periapsis_custom_field_import_owner;
GRANT UPDATE ON TABLE public.alerts, public.cases
TO periapsis_custom_field_import_owner;
GRANT INSERT ON TABLE public.ticket_activities, public.outbox_events
TO periapsis_custom_field_import_owner;
GRANT EXECUTE ON FUNCTION
  app.context_tenant_id(), app.context_user_id(),
  app.current_tenant_membership_id(),
  app.current_tenant_human_has_exact_permission_v3(text, public.authorization_scope),
  app.private_current_ticket_scope_allows_v1(text, uuid, uuid, uuid, uuid),
  app.private_notification_trace_context_is_safe_v1(text, text),
  app.append_tenant_authorization_audit(
    uuid, text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb, jsonb
  )
TO periapsis_custom_field_import_owner;

CREATE POLICY custom_field_import_owner_tenants_select_v1
ON public.tenants AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_memberships_select_v1
ON public.tenant_memberships AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_memberships_lock_v1
ON public.tenant_memberships AS PERMISSIVE FOR UPDATE
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (false);
CREATE POLICY custom_field_import_owner_definitions_select_v1
ON public.custom_field_definitions AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_definitions_lock_v1
ON public.custom_field_definitions AS PERMISSIVE FOR UPDATE
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (false);
CREATE POLICY custom_field_import_owner_definition_revisions_select_v1
ON public.custom_field_definition_revisions AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_options_select_v1
ON public.custom_field_options AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_permissions_select_v1
ON public.custom_field_permissions AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_alerts_v1
ON public.alerts AS PERMISSIVE FOR ALL
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_cases_v1
ON public.cases AS PERMISSIVE FOR ALL
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_values_v1
ON public.custom_field_values AS PERMISSIVE FOR ALL
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_team_assignments_v1
ON public.operator_team_assignment_epochs AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_team_roster_v1
ON public.operator_team_roster_entries AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_auth_sources_v1
ON public.tenant_authorization_sources AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_activities_insert_v1
ON public.ticket_activities AS PERMISSIVE FOR INSERT
TO periapsis_custom_field_import_owner
WITH CHECK (tenant_id = app.context_tenant_id()
  AND kind = 'custom_field.imported' AND origin = 'api');
CREATE POLICY custom_field_import_owner_activities_select_v1
ON public.ticket_activities AS PERMISSIVE FOR SELECT
TO periapsis_custom_field_import_owner
USING (tenant_id = app.context_tenant_id());
CREATE POLICY custom_field_import_owner_outbox_insert_v1
ON public.outbox_events AS PERMISSIVE FOR INSERT
TO periapsis_custom_field_import_owner
WITH CHECK (tenant_id = app.context_tenant_id()
  AND event_type LIKE 'custom_field.import.%');
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_exact_keys_v1(
  document jsonb, expected text[]
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT document IS NOT NULL
    AND jsonb_typeof(document) = 'object'
    AND (SELECT count(*) FROM jsonb_object_keys(document)) = cardinality(expected)
    AND NOT EXISTS (
      SELECT 1 FROM jsonb_object_keys(document) AS actual(key)
      WHERE NOT (actual.key = ANY(expected))
    );
$function$;
ALTER FUNCTION app.private_custom_field_import_exact_keys_v1(jsonb, text[])
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_exact_keys_v1(jsonb, text[])
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_custom_field_import_exact_keys_v1(jsonb, text[])
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_uuid_v1(value text)
RETURNS uuid
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE parsed uuid;
BEGIN
  IF value IS NULL OR value !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' THEN
    RAISE EXCEPTION 'custom-field import UUID is invalid' USING ERRCODE = '22023';
  END IF;
  parsed := value::uuid;
  IF uuid_extract_version(parsed) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'custom-field import UUID is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN parsed;
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_uuid_v1(text)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_uuid_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_custom_field_import_uuid_v1(text)
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_digest_v1(value text)
RETURNS bytea
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE parsed bytea;
BEGIN
  IF value IS NULL OR value !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'custom-field import digest is invalid' USING ERRCODE = '22023';
  END IF;
  parsed := decode(value, 'hex');
  IF octet_length(parsed) <> 32 OR parsed = decode(repeat('00', 32), 'hex') THEN
    RAISE EXCEPTION 'custom-field import digest is invalid' USING ERRCODE = '22023';
  END IF;
  RETURN parsed;
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_digest_v1(text)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_digest_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_go_quote_v1(value text)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog
AS $function$
  SELECT replace(replace(replace(replace(replace(
    to_json(value)::text,
    '&', E'\\u0026'), '<', E'\\u003c'), '>', E'\\u003e'),
    chr(8232), E'\\u2028'), chr(8233), E'\\u2029');
$function$;
ALTER FUNCTION app.private_custom_field_import_go_quote_v1(text)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_go_quote_v1(text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_canonical_json_v1(value jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog, app
AS $function$
DECLARE kind text := jsonb_typeof(value);
DECLARE projection text;
BEGIN
  IF kind = 'object' THEN
    SELECT coalesce(string_agg(
      app.private_custom_field_import_go_quote_v1(item.key) || ':' ||
      app.private_custom_field_import_canonical_json_v1(item.value),
      ',' ORDER BY item.key COLLATE "C"
    ), '') INTO projection
    FROM jsonb_each(value) AS item(key, value);
    RETURN '{' || projection || '}';
  ELSIF kind = 'array' THEN
    SELECT coalesce(string_agg(
      app.private_custom_field_import_canonical_json_v1(item.value),
      ',' ORDER BY item.ordinality
    ), '') INTO projection
    FROM jsonb_array_elements(value) WITH ORDINALITY AS item(value, ordinality);
    RETURN '[' || projection || ']';
  ELSIF kind = 'string' THEN
    RETURN app.private_custom_field_import_go_quote_v1(value #>> '{}');
  END IF;
  RETURN value::text;
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_canonical_json_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_canonical_json_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_definition_document_v1(
  p_tenant_id uuid, p_definition_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE definition public.custom_field_definitions%ROWTYPE;
DECLARE options jsonb;
DECLARE permission_count integer;
DECLARE permission_versions_match boolean;
DECLARE customer_read boolean;
DECLARE customer_create boolean;
DECLARE customer_update boolean;
DECLARE operator_read boolean;
DECLARE operator_create boolean;
DECLARE operator_update boolean;
DECLARE document jsonb;
BEGIN
  SELECT item.* INTO definition
  FROM public.custom_field_definitions AS item
  WHERE item.tenant_id = p_tenant_id AND item.id = p_definition_id;
  IF NOT FOUND THEN RETURN NULL; END IF;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'id', option.id::text, 'key', option.key, 'label', option.label,
    'position', option.position, 'archived', option.archived_at IS NOT NULL
  ) ORDER BY option.position, option.id), '[]'::jsonb)
  INTO options
  FROM public.custom_field_options AS option
  WHERE option.tenant_id = p_tenant_id AND option.definition_id = p_definition_id;

  SELECT count(*), bool_and(permission.schema_version = definition.schema_version),
    bool_or(permission.can_read) FILTER (WHERE permission.audience = 'customer'),
    bool_or(permission.can_create) FILTER (WHERE permission.audience = 'customer'),
    bool_or(permission.can_update) FILTER (WHERE permission.audience = 'customer'),
    bool_or(permission.can_read) FILTER (WHERE permission.audience = 'operator'),
    bool_or(permission.can_create) FILTER (WHERE permission.audience = 'operator'),
    bool_or(permission.can_update) FILTER (WHERE permission.audience = 'operator')
  INTO permission_count, permission_versions_match,
       customer_read, customer_create, customer_update,
       operator_read, operator_create, operator_update
  FROM public.custom_field_permissions AS permission
  WHERE permission.tenant_id = p_tenant_id
    AND permission.definition_id = p_definition_id;
  IF permission_count NOT BETWEEN 1 AND 2
     OR permission_versions_match IS NOT TRUE OR operator_read IS NULL THEN
    RETURN NULL;
  END IF;
  customer_read := coalesce(customer_read, false);
  customer_create := coalesce(customer_create, false);
  customer_update := coalesce(customer_update, false);

  document := jsonb_build_object(
    'id', definition.id::text,
    'tenantId', definition.tenant_id::text,
    'objectType', definition.object_type::text,
    'key', definition.key,
    'label', definition.label,
    'description', definition.description,
    'dataType', definition.data_type::text,
    'required', definition.required,
    'nullable', definition.nullable,
    'defaultValue', definition.default_value,
    'minimumLength', definition.minimum_length,
    'maximumLength', definition.maximum_length,
    'minimum', coalesce(definition.minimum_number, ''),
    'maximum', coalesce(definition.maximum_number, ''),
    'pattern', coalesce(definition.validation_pattern, ''),
    'options', options,
    'visibility', jsonb_build_object(
      'Customer', customer_read, 'Operator', operator_read
    ),
    'editPolicy', jsonb_build_object(
      'CustomerCreate', customer_create, 'CustomerUpdate', customer_update,
      'OperatorCreate', operator_create, 'OperatorUpdate', operator_update
    ),
    'placement', jsonb_build_object(
      'ShowInCreate', definition.show_in_create,
      'ShowInDetail', definition.show_in_detail,
      'ShowInList', definition.show_in_list,
      'ShowInExport', definition.show_in_export
    ),
    'requiredOnTransitions', to_jsonb(definition.required_on_transitions),
    'searchable', definition.searchable,
    'filterable', definition.filterable,
    'sortable', definition.sortable,
    'allowStructuredJson', definition.allow_structured_json,
    'archived', definition.archived_at IS NOT NULL,
    'schemaVersion', definition.schema_version
  );
  IF NOT definition.has_default THEN
    document := document - 'defaultValue';
  END IF;
  RETURN document;
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_definition_document_v1(uuid, uuid)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_definition_document_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_definition_pin_v1(
  p_tenant_id uuid, p_definition_id uuid
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE definition public.custom_field_definitions%ROWTYPE;
DECLARE options_text text;
DECLARE transitions_text text;
DECLARE permission_count integer;
DECLARE permission_versions_match boolean;
DECLARE customer_read boolean;
DECLARE customer_create boolean;
DECLARE customer_update boolean;
DECLARE operator_read boolean;
DECLARE operator_create boolean;
DECLARE operator_update boolean;
DECLARE fingerprint text;
BEGIN
  SELECT item.* INTO definition
  FROM public.custom_field_definitions AS item
  WHERE item.tenant_id = p_tenant_id AND item.id = p_definition_id;
  IF NOT FOUND THEN RETURN NULL; END IF;

  SELECT coalesce(string_agg(
    '{"ID":' || app.private_custom_field_import_go_quote_v1(option.id::text) ||
    ',"Key":' || app.private_custom_field_import_go_quote_v1(option.key) ||
    ',"Label":' || app.private_custom_field_import_go_quote_v1(option.label) ||
    ',"Position":' || option.position::text ||
    ',"Archived":' || (option.archived_at IS NOT NULL)::text || '}',
    ',' ORDER BY option.position, option.id
  ), '') INTO options_text
  FROM public.custom_field_options AS option
  WHERE option.tenant_id = p_tenant_id AND option.definition_id = p_definition_id;

  SELECT coalesce(string_agg(
    app.private_custom_field_import_go_quote_v1(item.value),
    ',' ORDER BY item.ordinality
  ), '') INTO transitions_text
  FROM unnest(definition.required_on_transitions) WITH ORDINALITY AS item(value, ordinality);

  SELECT count(*), bool_and(permission.schema_version = definition.schema_version),
    bool_or(permission.can_read) FILTER (WHERE permission.audience = 'customer'),
    bool_or(permission.can_create) FILTER (WHERE permission.audience = 'customer'),
    bool_or(permission.can_update) FILTER (WHERE permission.audience = 'customer'),
    bool_or(permission.can_read) FILTER (WHERE permission.audience = 'operator'),
    bool_or(permission.can_create) FILTER (WHERE permission.audience = 'operator'),
    bool_or(permission.can_update) FILTER (WHERE permission.audience = 'operator')
  INTO permission_count, permission_versions_match,
       customer_read, customer_create, customer_update,
       operator_read, operator_create, operator_update
  FROM public.custom_field_permissions AS permission
  WHERE permission.tenant_id = p_tenant_id
    AND permission.definition_id = p_definition_id;
  IF permission_count NOT BETWEEN 1 AND 2
     OR permission_versions_match IS NOT TRUE OR operator_read IS NULL THEN
    RETURN NULL;
  END IF;
  customer_read := coalesce(customer_read, false);
  customer_create := coalesce(customer_create, false);
  customer_update := coalesce(customer_update, false);

  fingerprint :=
    '{"ID":' || app.private_custom_field_import_go_quote_v1(definition.id::text) ||
    ',"Tenant":' || app.private_custom_field_import_go_quote_v1(definition.tenant_id::text) ||
    ',"ObjectType":' || app.private_custom_field_import_go_quote_v1(definition.object_type::text) ||
    ',"Key":' || app.private_custom_field_import_go_quote_v1(definition.key) ||
    ',"Label":' || app.private_custom_field_import_go_quote_v1(definition.label) ||
    ',"Description":' || app.private_custom_field_import_go_quote_v1(definition.description) ||
    ',"DataType":' || app.private_custom_field_import_go_quote_v1(definition.data_type::text) ||
    ',"Required":' || definition.required::text ||
    ',"Nullable":' || definition.nullable::text ||
    ',"DefaultPresence":' || CASE
      WHEN NOT definition.has_default THEN '0'
      WHEN definition.default_value = 'null'::jsonb THEN '1'
      ELSE '2' END ||
    ',"Default":' || CASE WHEN definition.has_default
      THEN app.private_custom_field_import_canonical_json_v1(definition.default_value)
      ELSE 'null' END ||
    ',"MinimumLength":' || coalesce(definition.minimum_length::text, 'null') ||
    ',"MaximumLength":' || coalesce(definition.maximum_length::text, 'null') ||
    ',"Minimum":' || app.private_custom_field_import_go_quote_v1(coalesce(definition.minimum_number, '')) ||
    ',"Maximum":' || app.private_custom_field_import_go_quote_v1(coalesce(definition.maximum_number, '')) ||
    ',"Pattern":' || app.private_custom_field_import_go_quote_v1(coalesce(definition.validation_pattern, '')) ||
    ',"Options":[' || options_text || ']' ||
    ',"Visibility":{"Customer":' || customer_read::text || ',"Operator":' || operator_read::text || '}' ||
    ',"EditPolicy":{"CustomerCreate":' || customer_create::text ||
      ',"CustomerUpdate":' || customer_update::text ||
      ',"OperatorCreate":' || operator_create::text ||
      ',"OperatorUpdate":' || operator_update::text || '}' ||
    ',"Placement":{"ShowInCreate":' || definition.show_in_create::text ||
      ',"ShowInDetail":' || definition.show_in_detail::text ||
      ',"ShowInList":' || definition.show_in_list::text ||
      ',"ShowInExport":' || definition.show_in_export::text || '}' ||
    ',"RequiredOnTransitions":[' || transitions_text || ']' ||
    ',"Searchable":' || definition.searchable::text ||
    ',"Filterable":' || definition.filterable::text ||
    ',"Sortable":' || definition.sortable::text ||
    ',"AllowStructuredJSON":' || definition.allow_structured_json::text ||
    ',"Archived":' || (definition.archived_at IS NOT NULL)::text ||
    ',"SchemaVersion":' || definition.schema_version::text || '}';
  RETURN encode(sha256(convert_to(fingerprint, 'UTF8')), 'hex');
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_definition_pin_v1(uuid, uuid)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_definition_pin_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_manifest_digest_v1(manifest jsonb)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
DECLARE definition_document jsonb;
DECLARE row_document jsonb;
DECLARE cell_document jsonb;
DECLARE pins_text text := '';
DECLARE rows_text text := '';
DECLARE cells_text text;
DECLARE digest_bytes bytea;
DECLARE byte_index integer;
DECLARE byte_values text;
DECLARE separator text;
DECLARE fingerprint text;
BEGIN
  FOR definition_document IN
    SELECT item.value
    FROM jsonb_array_elements(manifest -> 'definitions') WITH ORDINALITY AS item(value, ordinality)
    ORDER BY item.ordinality
  LOOP
    digest_bytes := decode(definition_document ->> 'pinSha256', 'hex');
    byte_values := '';
    FOR byte_index IN 0..31 LOOP
      byte_values := byte_values || CASE WHEN byte_index = 0 THEN '' ELSE ',' END ||
        get_byte(digest_bytes, byte_index)::text;
    END LOOP;
    separator := CASE WHEN pins_text = '' THEN '' ELSE ',' END;
    pins_text := pins_text || separator ||
      '{"ID":' || app.private_custom_field_import_go_quote_v1(definition_document ->> 'id') ||
      ',"Key":' || app.private_custom_field_import_go_quote_v1(definition_document ->> 'key') ||
      ',"Version":' || (definition_document ->> 'schemaVersion') ||
      ',"Fingerprint":[' || byte_values || ']}';
  END LOOP;

  FOR row_document IN
    SELECT item.value
    FROM jsonb_array_elements(manifest -> 'rows') WITH ORDINALITY AS item(value, ordinality)
    ORDER BY item.ordinality
  LOOP
    cells_text := '';
    FOR cell_document IN
      SELECT item.value
      FROM jsonb_array_elements(row_document -> 'cells') WITH ORDINALITY AS item(value, ordinality)
      ORDER BY item.ordinality
    LOOP
      separator := CASE WHEN cells_text = '' THEN '' ELSE ',' END;
      cells_text := cells_text || separator ||
        '{"Key":' || app.private_custom_field_import_go_quote_v1(cell_document ->> 'key') ||
        ',"Presence":' || CASE cell_document ->> 'presence'
          WHEN 'missing' THEN '0' WHEN 'null' THEN '1' ELSE '2' END ||
        ',"Value":' || CASE WHEN cell_document ->> 'presence' = 'missing'
          THEN 'null' ELSE app.private_custom_field_import_canonical_json_v1(cell_document -> 'value') END || '}';
    END LOOP;
    separator := CASE WHEN rows_text = '' THEN '' ELSE ',' END;
    rows_text := rows_text || separator ||
      '{"Sequence":' || (row_document ->> 'sequence') ||
      ',"Target":' || app.private_custom_field_import_go_quote_v1(row_document ->> 'targetId') ||
      ',"ExpectedVersion":' || (row_document ->> 'expectedVersion') ||
      ',"Cells":[' || cells_text || ']}';
  END LOOP;

  fingerprint :=
    '{"Domain":"periapsis.custom-field-import.v1"' ||
    ',"Tenant":' || app.private_custom_field_import_go_quote_v1(manifest ->> 'tenantId') ||
    ',"Requester":' || app.private_custom_field_import_go_quote_v1(manifest ->> 'requesterId') ||
    ',"OwnerMembership":' || app.private_custom_field_import_go_quote_v1(manifest ->> 'ownerMembershipId') ||
    ',"ObjectType":' || app.private_custom_field_import_go_quote_v1(manifest ->> 'objectType') ||
    ',"Mode":' || CASE manifest ->> 'mode' WHEN 'dry_run' THEN '1' ELSE '2' END ||
    ',"Pins":[' || pins_text || ']' ||
    ',"Rows":[' || rows_text || ']' ||
    ',"ProjectionVersion":' || (manifest ->> 'projectionVersion') ||
    ',"MaximumAttempts":' || (manifest ->> 'maximumAttempts') || '}';
  RETURN encode(sha256(convert_to(fingerprint, 'UTF8')), 'hex');
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_manifest_digest_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_manifest_digest_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_permission_v1(
  object_type public.custom_field_object_type
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT CASE object_type WHEN 'alert' THEN 'alert.update' WHEN 'case' THEN 'case.update' END;
$function$;
ALTER FUNCTION app.private_custom_field_import_permission_v1(public.custom_field_object_type)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_permission_v1(public.custom_field_object_type)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_require_actor_v1(
  tenant_id uuid, actor_id uuid, membership_id uuid,
  object_type public.custom_field_object_type, authority_scope text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE current_membership uuid;
BEGIN
  IF tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR actor_id IS DISTINCT FROM app.context_user_id()
     OR authority_scope NOT IN ('tenant','operator_team','assigned') THEN
    RAISE EXCEPTION 'custom-field import authority is invalid' USING ERRCODE = '42501';
  END IF;
  current_membership := app.current_tenant_membership_id();
  IF current_membership IS DISTINCT FROM membership_id
     OR NOT app.current_tenant_human_has_exact_permission_v3('custom_field.read', 'tenant')
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       app.private_custom_field_import_permission_v1(object_type),
       authority_scope::public.authorization_scope
     ) THEN
    RAISE EXCEPTION 'custom-field import authority is required' USING ERRCODE = '42501';
  END IF;
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_require_actor_v1(
  uuid, uuid, uuid, public.custom_field_object_type, text
) OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_require_actor_v1(
  uuid, uuid, uuid, public.custom_field_object_type, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_record_v1(job_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE job public.custom_field_import_jobs%ROWTYPE;
DECLARE results jsonb;
DECLARE job_document jsonb;
BEGIN
  SELECT item.* INTO job
  FROM public.custom_field_import_jobs AS item
  WHERE item.tenant_id = app.context_tenant_id() AND item.id = job_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import job was not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'sequence', result.sequence,
    'outcome', result.outcome,
    'resultingVersion', result.resulting_version,
    'fieldErrors', result.field_errors
  ) ORDER BY result.sequence), '[]'::jsonb)
  INTO results
  FROM public.custom_field_import_results AS result
  WHERE result.tenant_id = job.tenant_id AND result.job_id = job.id;

  job_document := jsonb_build_object(
    'schemaVersion', 1,
    'manifest', job.manifest_snapshot -> 'manifest',
    'state', job.state,
    'revision', job.revision,
    'attempts', job.attempts,
    'results', results,
    'requestedAt', to_char(job.requested_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'updatedAt', to_char(job.updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'availableAt', to_char(job.available_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'expiresAt', to_char(job.expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
    'fence', CASE WHEN job.fence_id IS NULL THEN 'null'::jsonb ELSE to_jsonb(job.fence_id::text) END,
    'leaseUntil', CASE WHEN job.lease_until IS NULL THEN 'null'::jsonb ELSE to_jsonb(
      to_char(job.lease_until AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    ) END,
    'terminalAt', CASE WHEN job.terminal_at IS NULL THEN 'null'::jsonb ELSE to_jsonb(
      to_char(job.terminal_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
    ) END
  );
  RETURN jsonb_build_object(
    'job', job_document,
    'audit', jsonb_build_object(
      'requestId', job.request_id,
      'correlationId', job.correlation_id,
      'ipAddress', host(job.ip_address),
      'userAgent', job.user_agent,
      'authenticationMethod', job.authentication_method
    )
  );
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_record_v1(uuid)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_record_v1(uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.lookup_custom_field_import_replay_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE tenant_id uuid;
DECLARE actor_id uuid;
DECLARE membership_id uuid;
DECLARE object_type public.custom_field_object_type;
DECLARE key_digest bytea;
DECLARE fingerprint bytea;
DECLARE stored public.custom_field_import_command_receipts%ROWTYPE;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 4096
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','tenantId','actorId','membershipId','objectType','action','keySha256','fingerprintSha256']
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'action' NOT IN ('request','cancel') THEN
    RAISE EXCEPTION 'custom-field import replay request is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_custom_field_import_uuid_v1(request ->> 'tenantId');
  actor_id := app.private_custom_field_import_uuid_v1(request ->> 'actorId');
  membership_id := app.private_custom_field_import_uuid_v1(request ->> 'membershipId');
  BEGIN object_type := (request ->> 'objectType')::public.custom_field_object_type;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'custom-field import object type is invalid' USING ERRCODE = '22023';
  END;
  key_digest := app.private_custom_field_import_digest_v1(request ->> 'keySha256');
  fingerprint := app.private_custom_field_import_digest_v1(request ->> 'fingerprintSha256');
  IF tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR actor_id IS DISTINCT FROM app.context_user_id()
     OR membership_id IS DISTINCT FROM app.current_tenant_membership_id() THEN
    RAISE EXCEPTION 'custom-field import replay authority is invalid' USING ERRCODE = '42501';
  END IF;
  SELECT receipt.* INTO stored
  FROM public.custom_field_import_command_receipts AS receipt
  WHERE receipt.tenant_id = tenant_id
    AND receipt.actor_user_id = actor_id
    AND receipt.owner_membership_id = membership_id
    AND receipt.object_type = object_type
    AND receipt.action = request ->> 'action'
    AND receipt.idempotency_key_digest = key_digest;
  IF NOT FOUND THEN RETURN 'null'::jsonb; END IF;
  IF stored.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
    RAISE EXCEPTION 'custom-field import idempotency conflict' USING ERRCODE = '23505';
  END IF;
  RETURN jsonb_set(stored.result_snapshot, '{replayed}', 'true'::jsonb, false);
END;
$function$;
ALTER FUNCTION app.lookup_custom_field_import_replay_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.lookup_custom_field_import_replay_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.lookup_custom_field_import_replay_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_custom_field_import_request_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE document jsonb;
DECLARE manifest jsonb;
DECLARE command jsonb;
DECLARE audit jsonb;
DECLARE tenant_id uuid;
DECLARE actor_id uuid;
DECLARE membership_id uuid;
DECLARE job_id uuid;
DECLARE object_type public.custom_field_object_type;
DECLARE authority_scope text;
DECLARE mode text;
DECLARE key_digest bytea;
DECLARE fingerprint bytea;
DECLARE request_digest bytea;
DECLARE requested_at timestamptz;
DECLARE expires_at timestamptz;
DECLARE row_document jsonb;
DECLARE row_ordinality bigint;
DECLARE row_sequence integer;
DECLARE row_expected_version bigint;
DECLARE cell_document jsonb;
DECLARE cell_ordinality bigint;
DECLARE previous_cell_key text;
DECLARE definition_document jsonb;
DECLARE definition_id uuid;
DECLARE expected_definition jsonb;
DECLARE result_document jsonb;
DECLARE existing public.custom_field_import_command_receipts%ROWTYPE;
DECLARE total_cells bigint;
DECLARE previous_definition_key text;
DECLARE referenced_key text;
DECLARE referenced_definition_id uuid;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 34603008
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','job','scope','command','audit']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'job') <> 'object'
     OR jsonb_typeof(request -> 'command') <> 'object'
     OR jsonb_typeof(request -> 'audit') <> 'object' THEN
    RAISE EXCEPTION 'custom-field import request is invalid' USING ERRCODE = '22023';
  END IF;
  document := request -> 'job';
  IF NOT app.private_custom_field_import_exact_keys_v1(
       document, ARRAY['schemaVersion','manifest','state','revision','attempts','results','requestedAt','updatedAt','availableAt','expiresAt','fence','leaseUntil','terminalAt']
     ) OR document ->> 'schemaVersion' <> '1' OR document ->> 'state' <> 'pending'
     OR document ->> 'revision' <> '1' OR document ->> 'attempts' <> '0'
     OR document -> 'results' <> '[]'::jsonb OR document -> 'fence' <> 'null'::jsonb
     OR document -> 'leaseUntil' <> 'null'::jsonb OR document -> 'terminalAt' <> 'null'::jsonb THEN
    RAISE EXCEPTION 'custom-field import initial job is invalid' USING ERRCODE = '22023';
  END IF;
  manifest := document -> 'manifest';
  IF NOT app.private_custom_field_import_exact_keys_v1(
       manifest, ARRAY['id','tenantId','requesterId','ownerMembershipId','objectType','mode','definitions','rows','requestSha256','projectionVersion','maximumAttempts']
     ) OR manifest ->> 'projectionVersion' <> '1'
     OR (manifest ->> 'maximumAttempts')::integer NOT BETWEEN 1 AND 5
     OR jsonb_typeof(manifest -> 'definitions') <> 'array'
     OR jsonb_array_length(manifest -> 'definitions') > 512
     OR jsonb_typeof(manifest -> 'rows') <> 'array'
     OR jsonb_array_length(manifest -> 'rows') NOT BETWEEN 1 AND 10000 THEN
    RAISE EXCEPTION 'custom-field import manifest is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_custom_field_import_uuid_v1(manifest ->> 'tenantId');
  actor_id := app.private_custom_field_import_uuid_v1(manifest ->> 'requesterId');
  membership_id := app.private_custom_field_import_uuid_v1(manifest ->> 'ownerMembershipId');
  job_id := app.private_custom_field_import_uuid_v1(manifest ->> 'id');
  BEGIN object_type := (manifest ->> 'objectType')::public.custom_field_object_type;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'custom-field import object type is invalid' USING ERRCODE = '22023';
  END;
  mode := manifest ->> 'mode';
  authority_scope := request ->> 'scope';
  IF mode NOT IN ('dry_run','commit') THEN
    RAISE EXCEPTION 'custom-field import mode is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_custom_field_import_require_actor_v1(
    tenant_id, actor_id, membership_id, object_type, authority_scope
  );
  command := request -> 'command';
  audit := request -> 'audit';
  IF NOT app.private_custom_field_import_exact_keys_v1(
       command, ARRAY['action','keySha256','fingerprintSha256']
     ) OR command ->> 'action' <> 'request'
     OR NOT app.private_custom_field_import_exact_keys_v1(
       audit, ARRAY['requestId','correlationId','ipAddress','userAgent','authenticationMethod']
     ) OR octet_length(audit ->> 'userAgent') > 1024
     OR audit ->> 'userAgent' ~ '[[:cntrl:]]'
     OR audit ->> 'authenticationMethod' !~ '^[a-z][a-z0-9._-]{0,63}$' THEN
    RAISE EXCEPTION 'custom-field import command metadata is invalid' USING ERRCODE = '22023';
  END IF;
  key_digest := app.private_custom_field_import_digest_v1(command ->> 'keySha256');
  fingerprint := app.private_custom_field_import_digest_v1(command ->> 'fingerprintSha256');
  request_digest := app.private_custom_field_import_digest_v1(manifest ->> 'requestSha256');
  BEGIN
    requested_at := (document ->> 'requestedAt')::timestamptz;
    expires_at := (document ->> 'expiresAt')::timestamptz;
  EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow THEN
    RAISE EXCEPTION 'custom-field import retention is invalid' USING ERRCODE = '22023';
  END;
  IF requested_at IS DISTINCT FROM (document ->> 'updatedAt')::timestamptz
     OR requested_at IS DISTINCT FROM (document ->> 'availableAt')::timestamptz
     OR expires_at <= requested_at
     OR expires_at - requested_at NOT BETWEEN interval '5 minutes' AND interval '30 days' THEN
    RAISE EXCEPTION 'custom-field import retention is invalid' USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    tenant_id::text || actor_id::text || membership_id::text || object_type::text || encode(key_digest,'hex'), 0
  ));
  SELECT receipt.* INTO existing
  FROM public.custom_field_import_command_receipts AS receipt
  WHERE receipt.tenant_id = tenant_id AND receipt.actor_user_id = actor_id
    AND receipt.owner_membership_id = membership_id AND receipt.object_type = object_type
    AND receipt.action = 'request' AND receipt.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF existing.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'custom-field import idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN jsonb_set(existing.result_snapshot, '{replayed}', 'true'::jsonb, false);
  END IF;

  total_cells := 0;
  FOR row_document, row_ordinality IN
    SELECT item.value, item.ordinality
    FROM jsonb_array_elements(manifest -> 'rows') WITH ORDINALITY AS item(value, ordinality)
  LOOP
    IF NOT app.private_custom_field_import_exact_keys_v1(
         row_document, ARRAY['sequence','targetId','expectedVersion','cells']
       ) OR jsonb_typeof(row_document -> 'sequence') <> 'number'
       OR jsonb_typeof(row_document -> 'expectedVersion') <> 'number'
       OR jsonb_typeof(row_document -> 'targetId') <> 'string'
       OR jsonb_typeof(row_document -> 'cells') <> 'array' THEN
      RAISE EXCEPTION 'custom-field import row is invalid' USING ERRCODE = '22023';
    END IF;
    BEGIN
      row_sequence := (row_document ->> 'sequence')::integer;
      row_expected_version := (row_document ->> 'expectedVersion')::bigint;
    EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
      RAISE EXCEPTION 'custom-field import row is invalid' USING ERRCODE = '22023';
    END;
    IF row_sequence IS DISTINCT FROM row_ordinality
       OR row_sequence NOT BETWEEN 1 AND 10000
       OR row_expected_version NOT BETWEEN 1 AND 9007199254740990
       OR jsonb_array_length(row_document -> 'cells') NOT BETWEEN 0 AND 512 THEN
      RAISE EXCEPTION 'custom-field import row is invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM app.private_custom_field_import_uuid_v1(row_document ->> 'targetId');
    total_cells := total_cells + jsonb_array_length(row_document -> 'cells');
    IF total_cells > 100000 THEN
      RAISE EXCEPTION 'custom-field import cell bound exceeded' USING ERRCODE = '22023';
    END IF;

    previous_cell_key := NULL;
    FOR cell_document, cell_ordinality IN
      SELECT item.value, item.ordinality
      FROM jsonb_array_elements(row_document -> 'cells') WITH ORDINALITY AS item(value, ordinality)
    LOOP
      IF jsonb_typeof(cell_document) <> 'object'
         OR cell_document ->> 'key' !~ '^[a-z][a-z0-9_.-]{0,63}$'
         OR cell_document ->> 'presence' NOT IN ('missing','null','present') THEN
        RAISE EXCEPTION 'custom-field import cell is invalid' USING ERRCODE = '22023';
      END IF;
      IF cell_document ->> 'presence' = 'missing' THEN
        IF NOT app.private_custom_field_import_exact_keys_v1(
          cell_document, ARRAY['key','presence']
        ) THEN
          RAISE EXCEPTION 'custom-field import missing cell is invalid' USING ERRCODE = '22023';
        END IF;
      ELSE
        IF NOT app.private_custom_field_import_exact_keys_v1(
             cell_document, ARRAY['key','presence','value']
           ) OR cell_document ->> 'presence' = 'null'
                AND jsonb_typeof(cell_document -> 'value') <> 'null'
           OR cell_document ->> 'presence' = 'present'
                AND jsonb_typeof(cell_document -> 'value') = 'null' THEN
          RAISE EXCEPTION 'custom-field import value cell is invalid' USING ERRCODE = '22023';
        END IF;
      END IF;
      IF previous_cell_key IS NOT NULL AND
         previous_cell_key COLLATE "C" >= (cell_document ->> 'key') COLLATE "C" THEN
        RAISE EXCEPTION 'custom-field import cells are not canonical' USING ERRCODE = '22023';
      END IF;
      previous_cell_key := cell_document ->> 'key';
    END LOOP;
  END LOOP;

  previous_definition_key := NULL;
  FOR definition_document IN
    SELECT value FROM jsonb_array_elements(manifest -> 'definitions') AS item(value)
  LOOP
    definition_id := app.private_custom_field_import_uuid_v1(definition_document ->> 'id');
    expected_definition := app.private_custom_field_import_definition_document_v1(
      tenant_id, definition_id
    );
    IF jsonb_typeof(definition_document) <> 'object'
       OR definition_document ->> 'tenantId' IS DISTINCT FROM tenant_id::text
       OR definition_document ->> 'objectType' IS DISTINCT FROM object_type::text
       OR definition_document ->> 'pinSha256' !~ '^[0-9a-f]{64}$'
       OR expected_definition IS NULL
       OR expected_definition ->> 'objectType' IS DISTINCT FROM object_type::text
       OR expected_definition ->> 'archived' <> 'false'
       OR expected_definition #>> '{visibility,Operator}' <> 'true'
       OR definition_document - 'pinSha256' IS DISTINCT FROM expected_definition
       OR definition_document ->> 'pinSha256' IS DISTINCT FROM
          app.private_custom_field_import_definition_pin_v1(tenant_id, definition_id)
       OR previous_definition_key IS NOT NULL
          AND previous_definition_key COLLATE "C" >= (definition_document ->> 'key') COLLATE "C"
       OR NOT EXISTS (
          SELECT 1
          FROM jsonb_array_elements(manifest -> 'rows') AS row_item(value)
          CROSS JOIN LATERAL jsonb_array_elements(row_item.value -> 'cells') AS cell_item(value)
          WHERE cell_item.value ->> 'presence' <> 'missing'
            AND cell_item.value ->> 'key' = definition_document ->> 'key'
       ) THEN
      RAISE EXCEPTION 'custom-field import definition pin is stale' USING ERRCODE = '40001';
    END IF;
    previous_definition_key := definition_document ->> 'key';
  END LOOP;
  IF (SELECT count(*) FROM jsonb_array_elements(manifest -> 'definitions')) IS DISTINCT FROM
     (SELECT count(DISTINCT value ->> 'id')
      FROM jsonb_array_elements(manifest -> 'definitions'))
     OR (SELECT count(*) FROM jsonb_array_elements(manifest -> 'definitions')) IS DISTINCT FROM
        (SELECT count(DISTINCT value ->> 'key')
         FROM jsonb_array_elements(manifest -> 'definitions')) THEN
    RAISE EXCEPTION 'custom-field import definitions are duplicated' USING ERRCODE = '22023';
  END IF;

  FOR referenced_key IN
    SELECT DISTINCT cell_item.value ->> 'key'
    FROM jsonb_array_elements(manifest -> 'rows') AS row_item(value)
    CROSS JOIN LATERAL jsonb_array_elements(row_item.value -> 'cells') AS cell_item(value)
    WHERE cell_item.value ->> 'presence' <> 'missing'
  LOOP
    SELECT definition.id INTO referenced_definition_id
    FROM public.custom_field_definitions AS definition
    WHERE definition.tenant_id = tenant_id
      AND definition.object_type = object_type
      AND definition.key = referenced_key
      AND definition.archived_at IS NULL
      AND app.private_custom_field_import_definition_document_v1(
        tenant_id, definition.id
      ) #>> '{visibility,Operator}' = 'true';
    IF FOUND AND NOT EXISTS (
      SELECT 1 FROM jsonb_array_elements(manifest -> 'definitions') AS item(value)
      WHERE item.value ->> 'id' = referenced_definition_id::text
        AND item.value ->> 'key' = referenced_key
    ) THEN
      RAISE EXCEPTION 'custom-field import definition snapshot is incomplete' USING ERRCODE = '40001';
    END IF;
  END LOOP;
  IF manifest ->> 'requestSha256' IS DISTINCT FROM
     app.private_custom_field_import_manifest_digest_v1(manifest) THEN
    RAISE EXCEPTION 'custom-field import manifest digest is stale' USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.custom_field_import_jobs(
    id, tenant_id, requester_user_id, owner_membership_id, object_type, mode,
    manifest_snapshot, request_digest, projection_version, maximum_attempts,
    state, revision, attempts, total, request_id, correlation_id, ip_address,
    user_agent, authentication_method, requested_at, updated_at, available_at, expires_at
  ) VALUES (
    job_id, tenant_id, actor_id, membership_id, object_type, mode,
    jsonb_build_object('manifest', manifest, 'authorityScope', authority_scope),
    request_digest, 1, (manifest ->> 'maximumAttempts')::smallint,
    'pending', 1, 0, jsonb_array_length(manifest -> 'rows'),
    app.private_custom_field_import_uuid_v1(audit ->> 'requestId'),
    app.private_custom_field_import_uuid_v1(audit ->> 'correlationId'),
    (audit ->> 'ipAddress')::inet, audit ->> 'userAgent',
    audit ->> 'authenticationMethod', requested_at, requested_at, requested_at, expires_at
  );

  FOR row_document, row_ordinality IN
    SELECT item.value, item.ordinality
    FROM jsonb_array_elements(manifest -> 'rows') WITH ORDINALITY AS item(value, ordinality)
  LOOP
    INSERT INTO public.custom_field_import_rows(
      tenant_id, job_id, sequence, target_id, expected_version, cells_snapshot, cells_digest
    ) VALUES (
      tenant_id, job_id, row_ordinality,
      app.private_custom_field_import_uuid_v1(row_document ->> 'targetId'),
      (row_document ->> 'expectedVersion')::bigint, row_document -> 'cells',
      sha256(convert_to((row_document -> 'cells')::text, 'UTF8'))
    );
  END LOOP;

  result_document := jsonb_build_object(
    'schemaVersion', 1,
    'record', app.private_custom_field_import_record_v1(job_id),
    'replayed', false
  );
  IF result_document #> '{record,job}' IS DISTINCT FROM document THEN
    RAISE EXCEPTION 'custom-field import durable projection diverged' USING ERRCODE = '55000';
  END IF;
  INSERT INTO public.custom_field_import_command_receipts(
    tenant_id, job_id, actor_user_id, owner_membership_id, object_type, action,
    idempotency_key_digest, request_fingerprint_digest, result_snapshot, created_at, expires_at
  ) VALUES (
    tenant_id, job_id, actor_id, membership_id, object_type, 'request',
    key_digest, fingerprint, result_document, requested_at, expires_at
  );
  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'custom_field.import.requested', 'custom_field_import', job_id,
    (audit ->> 'requestId')::uuid, (audit ->> 'correlationId')::uuid,
    (audit ->> 'ipAddress')::inet, audit ->> 'userAgent', audit ->> 'authenticationMethod',
    '{}'::jsonb,
    jsonb_build_object('objectType', object_type, 'mode', mode, 'rows', jsonb_array_length(manifest -> 'rows')),
    jsonb_build_object('projectionVersion', 1)
  );
  INSERT INTO public.outbox_events(
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version, event_type,
    schema_version, payload, deduplication_key, correlation_id, causation_id,
    actor_kind, actor_id, producer, maximum_audience
  ) VALUES (
    uuidv7(), tenant_id, 'custom_field_import', job_id, 1,
    'custom_field.import.requested', 1,
    jsonb_build_object('tenantId', tenant_id, 'jobId', job_id, 'objectType', object_type, 'mode', mode),
    'custom-field-import:request:' || job_id::text,
    (audit ->> 'correlationId')::uuid, (audit ->> 'requestId')::uuid,
    'human', actor_id, 'custom_field_import', 'operator'
  );
  RETURN result_document;
END;
$function$;
ALTER FUNCTION app.commit_custom_field_import_request_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.commit_custom_field_import_request_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.commit_custom_field_import_request_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_custom_field_import_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE tenant_id uuid;
DECLARE actor_id uuid;
DECLARE membership_id uuid;
DECLARE job_id uuid;
DECLARE object_type public.custom_field_object_type;
DECLARE authority_scope text;
DECLARE job public.custom_field_import_jobs%ROWTYPE;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 4096
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','tenantId','actorId','membershipId','objectType','capability','scope','jobId']
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'capability' NOT IN ('read','cancel') THEN
    RAISE EXCEPTION 'custom-field import get request is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_custom_field_import_uuid_v1(request ->> 'tenantId');
  actor_id := app.private_custom_field_import_uuid_v1(request ->> 'actorId');
  membership_id := app.private_custom_field_import_uuid_v1(request ->> 'membershipId');
  job_id := app.private_custom_field_import_uuid_v1(request ->> 'jobId');
  BEGIN object_type := (request ->> 'objectType')::public.custom_field_object_type;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'custom-field import object type is invalid' USING ERRCODE = '22023';
  END;
  authority_scope := request ->> 'scope';
  PERFORM app.private_custom_field_import_require_actor_v1(
    tenant_id, actor_id, membership_id, object_type, authority_scope
  );
  SELECT item.* INTO job FROM public.custom_field_import_jobs AS item
  WHERE item.tenant_id = tenant_id AND item.id = job_id
    AND item.requester_user_id = actor_id AND item.owner_membership_id = membership_id
    AND item.object_type = object_type;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import job was not found' USING ERRCODE = 'P0002';
  END IF;
  RETURN app.private_custom_field_import_record_v1(job_id);
END;
$function$;
ALTER FUNCTION app.get_custom_field_import_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.get_custom_field_import_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.get_custom_field_import_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.list_custom_field_import_results_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE tenant_id uuid;
DECLARE actor_id uuid;
DECLARE membership_id uuid;
DECLARE job_id uuid;
DECLARE object_type public.custom_field_object_type;
DECLARE authority_scope text;
DECLARE after_sequence integer;
DECLARE page_size integer;
DECLARE job public.custom_field_import_jobs%ROWTYPE;
DECLARE items jsonb;
DECLARE next_after integer;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 4096
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','tenantId','actorId','membershipId','objectType','capability','scope','jobId','after','pageSize']
     ) OR request ->> 'schemaVersion' <> '1'
     OR request ->> 'capability' <> 'read' THEN
    RAISE EXCEPTION 'custom-field import result request is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_custom_field_import_uuid_v1(request ->> 'tenantId');
  actor_id := app.private_custom_field_import_uuid_v1(request ->> 'actorId');
  membership_id := app.private_custom_field_import_uuid_v1(request ->> 'membershipId');
  job_id := app.private_custom_field_import_uuid_v1(request ->> 'jobId');
  BEGIN
    object_type := (request ->> 'objectType')::public.custom_field_object_type;
    after_sequence := (request ->> 'after')::integer;
    page_size := (request ->> 'pageSize')::integer;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'custom-field import result page is invalid' USING ERRCODE = '22023';
  END;
  IF after_sequence NOT BETWEEN 0 AND 10000 OR page_size NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'custom-field import result page is invalid' USING ERRCODE = '22023';
  END IF;
  authority_scope := request ->> 'scope';
  PERFORM app.private_custom_field_import_require_actor_v1(
    tenant_id, actor_id, membership_id, object_type, authority_scope
  );
  SELECT item.* INTO job FROM public.custom_field_import_jobs AS item
  WHERE item.tenant_id = tenant_id AND item.id = job_id
    AND item.requester_user_id = actor_id AND item.owner_membership_id = membership_id
    AND item.object_type = object_type;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import job was not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'sequence', page.sequence,
    'targetId', page.target_id,
    'expectedVersion', page.expected_version,
    'outcome', page.outcome,
    'resultingVersion', page.resulting_version,
    'fieldErrors', page.field_errors,
    'recordedAt', to_char(page.recorded_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
  ) ORDER BY page.sequence), '[]'::jsonb)
  INTO items
  FROM (
    SELECT row.sequence, row.target_id, row.expected_version,
           result.outcome, result.resulting_version, result.field_errors,
           result.recorded_at
    FROM public.custom_field_import_results AS result
    JOIN public.custom_field_import_rows AS row
      ON row.tenant_id = result.tenant_id AND row.job_id = result.job_id
     AND row.sequence = result.sequence
    WHERE result.tenant_id = tenant_id AND result.job_id = job_id
      AND result.sequence > after_sequence
    ORDER BY result.sequence
    LIMIT page_size
  ) AS page;
  SELECT max(result.sequence) INTO next_after
  FROM (
    SELECT stored.sequence
    FROM public.custom_field_import_results AS stored
    WHERE stored.tenant_id = tenant_id AND stored.job_id = job_id
      AND stored.sequence > after_sequence
    ORDER BY stored.sequence
    LIMIT page_size
  ) AS result;
  IF next_after IS NOT NULL AND NOT EXISTS (
       SELECT 1 FROM public.custom_field_import_results AS later
       WHERE later.tenant_id = tenant_id AND later.job_id = job_id
         AND later.sequence > next_after
     ) THEN
    next_after := NULL;
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object('items', items, 'nextAfter', next_after));
END;
$function$;
ALTER FUNCTION app.list_custom_field_import_results_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.list_custom_field_import_results_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_custom_field_import_owner;
GRANT EXECUTE ON FUNCTION app.list_custom_field_import_results_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_custom_field_import_cancellation_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE current_document jsonb := request -> 'current';
DECLARE next_document jsonb := request -> 'next';
DECLARE manifest jsonb;
DECLARE command jsonb := request -> 'command';
DECLARE audit jsonb := request -> 'audit';
DECLARE tenant_id uuid;
DECLARE actor_id uuid;
DECLARE membership_id uuid;
DECLARE job_id uuid;
DECLARE object_type public.custom_field_object_type;
DECLARE key_digest bytea;
DECLARE fingerprint bytea;
DECLARE existing public.custom_field_import_command_receipts%ROWTYPE;
DECLARE job public.custom_field_import_jobs%ROWTYPE;
DECLARE result_document jsonb;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 34603008
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','current','next','scope','command','audit']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(current_document) <> 'object'
     OR jsonb_typeof(next_document) <> 'object'
     OR jsonb_typeof(command) <> 'object'
     OR NOT app.private_custom_field_import_exact_keys_v1(
       command, ARRAY['action','keySha256','fingerprintSha256']
     ) OR command ->> 'action' <> 'cancel'
     OR jsonb_typeof(audit) <> 'object'
     OR NOT app.private_custom_field_import_exact_keys_v1(
       audit, ARRAY['requestId','correlationId','ipAddress','userAgent','authenticationMethod']
     ) OR octet_length(audit ->> 'userAgent') > 1024
     OR audit ->> 'userAgent' ~ '[[:cntrl:]]'
     OR audit ->> 'authenticationMethod' !~ '^[a-z][a-z0-9._-]{0,63}$' THEN
    RAISE EXCEPTION 'custom-field import cancellation is invalid' USING ERRCODE = '22023';
  END IF;
  manifest := current_document -> 'manifest';
  tenant_id := app.private_custom_field_import_uuid_v1(manifest ->> 'tenantId');
  actor_id := app.private_custom_field_import_uuid_v1(manifest ->> 'requesterId');
  membership_id := app.private_custom_field_import_uuid_v1(manifest ->> 'ownerMembershipId');
  job_id := app.private_custom_field_import_uuid_v1(manifest ->> 'id');
  BEGIN object_type := (manifest ->> 'objectType')::public.custom_field_object_type;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'custom-field import object type is invalid' USING ERRCODE = '22023';
  END;
  PERFORM app.private_custom_field_import_require_actor_v1(
    tenant_id, actor_id, membership_id, object_type, request ->> 'scope'
  );
  key_digest := app.private_custom_field_import_digest_v1(command ->> 'keySha256');
  fingerprint := app.private_custom_field_import_digest_v1(command ->> 'fingerprintSha256');
  PERFORM pg_advisory_xact_lock(hashtextextended(
    tenant_id::text || actor_id::text || membership_id::text || object_type::text || encode(key_digest,'hex'), 0
  ));
  SELECT receipt.* INTO existing
  FROM public.custom_field_import_command_receipts AS receipt
  WHERE receipt.tenant_id = tenant_id AND receipt.actor_user_id = actor_id
    AND receipt.owner_membership_id = membership_id AND receipt.object_type = object_type
    AND receipt.action = 'cancel' AND receipt.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF existing.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'custom-field import idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN jsonb_set(existing.result_snapshot, '{replayed}', 'true'::jsonb, false);
  END IF;
  SELECT item.* INTO job FROM public.custom_field_import_jobs AS item
  WHERE item.tenant_id = tenant_id AND item.id = job_id
    AND item.requester_user_id = actor_id AND item.owner_membership_id = membership_id
    AND item.object_type = object_type FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'custom-field import job was not found' USING ERRCODE = 'P0002'; END IF;
  -- Apply the same exact-prefix, transition, counter, and durable-projection
  -- checks used by the worker. A NULL worker identity selects only the two
  -- API cancellation transitions accepted by that private state machine.
  result_document := jsonb_build_object(
    'schemaVersion', 1,
    'record', app.private_custom_field_import_apply_job_v1(
      job_id, current_document, next_document, NULL, false, NULL
    ),
    'replayed', false
  );
  INSERT INTO public.custom_field_import_command_receipts(
    tenant_id, job_id, actor_user_id, owner_membership_id, object_type, action,
    idempotency_key_digest, request_fingerprint_digest, result_snapshot, created_at, expires_at
  ) VALUES (
    tenant_id, job_id, actor_id, membership_id, object_type, 'cancel',
    key_digest, fingerprint, result_document,
    (next_document ->> 'updatedAt')::timestamptz, job.expires_at
  );
  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'custom_field.import.cancellation_requested', 'custom_field_import', job_id,
    (audit ->> 'requestId')::uuid, (audit ->> 'correlationId')::uuid,
    (audit ->> 'ipAddress')::inet, audit ->> 'userAgent', audit ->> 'authenticationMethod',
    jsonb_build_object('state', job.state, 'revision', job.revision),
    jsonb_build_object('state', next_document ->> 'state', 'revision', (next_document ->> 'revision')::bigint),
    jsonb_build_object('projectionVersion', 1)
  );
  INSERT INTO public.outbox_events(
    id, tenant_id, aggregate_type, aggregate_id, aggregate_version, event_type,
    schema_version, payload, deduplication_key, correlation_id, causation_id,
    actor_kind, actor_id, producer, maximum_audience
  ) VALUES (
    uuidv7(), tenant_id, 'custom_field_import', job_id, (next_document ->> 'revision')::integer,
    'custom_field.import.cancellation_requested', 1,
    jsonb_build_object('tenantId', tenant_id, 'jobId', job_id),
    'custom-field-import:cancel:' || job_id::text || ':' || (next_document ->> 'revision'),
    (audit ->> 'correlationId')::uuid, (audit ->> 'requestId')::uuid,
    'human', actor_id, 'custom_field_import', 'operator'
  );
  RETURN result_document;
END;
$function$;
ALTER FUNCTION app.commit_custom_field_import_cancellation_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.commit_custom_field_import_cancellation_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.commit_custom_field_import_cancellation_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_append_worker_audit_v1(
  p_tenant_id uuid,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_occurred_at timestamptz,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_action <> 'custom_field.import.committed'
     OR p_resource_type NOT IN ('alert','case')
     OR p_resource_id IS NULL OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_occurred_at IS NULL OR octet_length(p_metadata::text) > 16384
     OR NOT app.private_custom_field_import_exact_keys_v1(
       p_metadata,
       ARRAY[
         'jobId','sequence','fieldCount','expectedVersion','resultingVersion',
         'requesterUserId','ownerMembershipId'
       ]
     ) THEN
    RAISE EXCEPTION 'custom-field import worker audit is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_custom_field_import_uuid_v1(p_metadata ->> 'jobId');
  PERFORM app.private_custom_field_import_uuid_v1(p_metadata ->> 'requesterUserId');
  PERFORM app.private_custom_field_import_uuid_v1(p_metadata ->> 'ownerMembershipId');
  IF jsonb_typeof(p_metadata -> 'sequence') <> 'number'
     OR jsonb_typeof(p_metadata -> 'fieldCount') <> 'number'
     OR jsonb_typeof(p_metadata -> 'expectedVersion') <> 'number'
     OR jsonb_typeof(p_metadata -> 'resultingVersion') <> 'number' THEN
    RAISE EXCEPTION 'custom-field import worker audit is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events(
    tenant_id, sequence, occurred_at, actor_type, action,
    resource_type, resource_id, request_id, correlation_id,
    authentication_method, outcome, before, after, metadata
  ) VALUES (
    p_tenant_id, 0, p_occurred_at, 'system', p_action,
    p_resource_type, p_resource_id, p_request_id, p_correlation_id,
    'system', 'success',
    jsonb_build_object('version', (p_metadata ->> 'expectedVersion')::bigint),
    jsonb_build_object('version', (p_metadata ->> 'resultingVersion')::bigint),
    p_metadata - ARRAY['expectedVersion','resultingVersion']
      || jsonb_build_object('contentRedacted', true)
  );
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_append_worker_audit_v1(
  uuid, text, text, uuid, uuid, uuid, timestamptz, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_custom_field_import_append_worker_audit_v1(
  uuid, text, text, uuid, uuid, uuid, timestamptz, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_custom_field_import_append_worker_audit_v1(
  uuid, text, text, uuid, uuid, uuid, timestamptz, jsonb
) TO periapsis_custom_field_import_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_require_worker_v1(identity jsonb)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE service_account_id uuid;
DECLARE worker_id uuid;
BEGIN
  IF identity IS NULL OR octet_length(identity::text) > 1024
     OR NOT app.private_custom_field_import_exact_keys_v1(
       identity, ARRAY['serviceAccountId','workerId','purpose']
     ) OR identity ->> 'purpose' <> 'custom_field_import' THEN
    RAISE EXCEPTION 'custom-field import worker identity is invalid' USING ERRCODE = '42501';
  END IF;
  service_account_id := app.private_custom_field_import_uuid_v1(
    identity ->> 'serviceAccountId'
  );
  worker_id := app.private_custom_field_import_uuid_v1(identity ->> 'workerId');
  PERFORM 1 FROM public.ticket_runtime_service_principals AS principal
  WHERE principal.id = service_account_id
    AND principal.key = 'ticket_runtime' AND principal.enabled
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import worker identity is unavailable' USING ERRCODE = '42501';
  END IF;
  RETURN worker_id;
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_require_worker_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_custom_field_import_require_worker_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_custom_field_import_require_worker_v1(jsonb)
TO periapsis_custom_field_import_owner;
--> statement-breakpoint

CREATE FUNCTION app.list_custom_field_import_queues_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE worker_id uuid;
DECLARE item_limit integer;
DECLARE requested_at timestamptz;
DECLARE queues jsonb;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 2048
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','now','limit']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'identity') <> 'object'
     OR jsonb_typeof(request -> 'limit') <> 'number' THEN
    RAISE EXCEPTION 'custom-field import queue request is invalid' USING ERRCODE = '22023';
  END IF;
  worker_id := app.private_custom_field_import_require_worker_v1(request -> 'identity');
  BEGIN item_limit := (request ->> 'limit')::integer;
    requested_at := (request ->> 'now')::timestamptz;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN
    RAISE EXCEPTION 'custom-field import queue bound is invalid' USING ERRCODE = '22023';
  END;
  IF item_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'custom-field import queue bound is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'tenantId', discovered.tenant_id,
    'jobId', discovered.id
  ) ORDER BY discovered.available_at, discovered.tenant_id, discovered.id), '[]'::jsonb)
  INTO queues
  FROM (
    SELECT job.tenant_id, job.id, job.available_at
    FROM public.custom_field_import_jobs AS job
    WHERE (job.state = 'pending'
        AND (job.available_at <= requested_at
          OR job.expires_at <= requested_at))
      OR (job.state IN ('running','cancellation_requested')
        AND (job.fence_id = worker_id
          OR job.lease_until <= requested_at
          OR job.expires_at <= requested_at))
    ORDER BY job.available_at, job.tenant_id, job.id
    LIMIT item_limit
  ) AS discovered;
  RETURN jsonb_build_object('schemaVersion', 1, 'queues', queues);
END;
$function$;
ALTER FUNCTION app.list_custom_field_import_queues_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.list_custom_field_import_queues_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_custom_field_import_owner;
GRANT EXECUTE ON FUNCTION app.list_custom_field_import_queues_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.load_custom_field_import_worker_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE tenant_id uuid;
DECLARE job_id uuid;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 2048
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','tenantId','jobId']
     ) OR request ->> 'schemaVersion' <> '1' THEN
    RAISE EXCEPTION 'custom-field import worker load is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_custom_field_import_require_worker_v1(request -> 'identity');
  tenant_id := app.private_custom_field_import_uuid_v1(request ->> 'tenantId');
  job_id := app.private_custom_field_import_uuid_v1(request ->> 'jobId');
  IF tenant_id IS DISTINCT FROM app.context_tenant_id() THEN
    RAISE EXCEPTION 'custom-field import tenant context is invalid' USING ERRCODE = '42501';
  END IF;
  RETURN app.private_custom_field_import_record_v1(job_id);
END;
$function$;
ALTER FUNCTION app.load_custom_field_import_worker_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.load_custom_field_import_worker_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_custom_field_import_owner;
GRANT EXECUTE ON FUNCTION app.load_custom_field_import_worker_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_apply_job_v1(
  p_job_id uuid, p_current jsonb, p_next jsonb, p_worker_id uuid,
  p_allow_row_result boolean, p_row_fingerprint bytea
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE job public.custom_field_import_jobs%ROWTYPE;
DECLARE actual jsonb;
DECLARE current_results jsonb;
DECLARE next_results jsonb;
DECLARE result_document jsonb;
DECLARE result_ordinality bigint;
DECLARE delta integer;
DECLARE required_control_outcome text;
DECLARE next_fence uuid;
DECLARE next_lease timestamptz;
DECLARE next_terminal timestamptz;
DECLARE next_updated timestamptz;
DECLARE next_available timestamptz;
BEGIN
  SELECT item.* INTO job FROM public.custom_field_import_jobs AS item
  WHERE item.tenant_id = app.context_tenant_id() AND item.id = p_job_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import job was not found' USING ERRCODE = 'P0002';
  END IF;
  actual := app.private_custom_field_import_record_v1(p_job_id) -> 'job';
  IF p_current IS DISTINCT FROM actual
     OR NOT app.private_custom_field_import_exact_keys_v1(
       p_next, ARRAY['schemaVersion','manifest','state','revision','attempts','results','requestedAt','updatedAt','availableAt','expiresAt','fence','leaseUntil','terminalAt']
     ) OR p_next ->> 'schemaVersion' <> '1'
     OR p_next -> 'manifest' IS DISTINCT FROM p_current -> 'manifest'
     OR (p_next ->> 'revision')::bigint IS DISTINCT FROM job.revision + 1
     OR p_next ->> 'requestedAt' IS DISTINCT FROM p_current ->> 'requestedAt'
     OR p_next ->> 'expiresAt' IS DISTINCT FROM p_current ->> 'expiresAt'
     OR jsonb_typeof(p_next -> 'results') <> 'array' THEN
    RAISE EXCEPTION 'custom-field import job CAS is stale' USING ERRCODE = '40001';
  END IF;
  BEGIN
    next_updated := (p_next ->> 'updatedAt')::timestamptz;
    next_available := (p_next ->> 'availableAt')::timestamptz;
    next_lease := (p_next ->> 'leaseUntil')::timestamptz;
    next_terminal := (p_next ->> 'terminalAt')::timestamptz;
    next_fence := (p_next ->> 'fence')::uuid;
  EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow THEN
    RAISE EXCEPTION 'custom-field import transition timestamp is invalid' USING ERRCODE = '22023';
  END;
  current_results := p_current -> 'results';
  next_results := p_next -> 'results';
  delta := jsonb_array_length(next_results) - jsonb_array_length(current_results);
  IF delta < 0 OR NOT (
       p_allow_row_result AND delta = 1
       OR NOT p_allow_row_result AND delta >= 0
     ) OR EXISTS (
       SELECT 1
       FROM jsonb_array_elements(current_results) WITH ORDINALITY AS old(value, ordinality)
       WHERE next_results -> (old.ordinality - 1)::integer IS DISTINCT FROM old.value
     ) THEN
    RAISE EXCEPTION 'custom-field import result prefix is invalid' USING ERRCODE = '22023';
  END IF;

  IF NOT p_allow_row_result THEN
    IF p_worker_id IS NULL AND job.state = 'pending'
       AND p_next ->> 'state' = 'cancelled' THEN
      required_control_outcome := 'cancelled';
    ELSIF p_worker_id IS NULL AND job.state = 'running'
       AND p_next ->> 'state' = 'cancelled' THEN
      IF job.lease_until IS NULL OR next_updated < job.lease_until THEN
        RAISE EXCEPTION 'custom-field import active lease cannot be cancelled directly' USING ERRCODE = '40001';
      END IF;
      required_control_outcome := 'cancelled';
    ELSIF p_worker_id IS NULL AND job.state = 'running'
       AND p_next ->> 'state' = 'cancellation_requested' THEN
      IF delta <> 0 OR (p_next ->> 'attempts')::integer <> job.attempts
         OR next_fence IS DISTINCT FROM job.fence_id
         OR next_lease IS DISTINCT FROM job.lease_until
         OR job.lease_until IS NULL OR NOT next_updated < job.lease_until THEN
        RAISE EXCEPTION 'custom-field import cancellation request is invalid' USING ERRCODE = '40001';
      END IF;
    ELSIF p_worker_id IS NOT NULL AND job.state = 'pending'
       AND p_next ->> 'state' = 'running' THEN
      IF delta <> 0 OR (p_next ->> 'attempts')::integer <> job.attempts + 1
         OR next_fence IS DISTINCT FROM p_worker_id THEN
        RAISE EXCEPTION 'custom-field import claim is invalid' USING ERRCODE = '22023';
      END IF;
    ELSIF p_worker_id IS NOT NULL AND job.state = 'running'
       AND p_next ->> 'state' = 'running' THEN
      IF delta <> 0 OR NOT (
           job.fence_id = p_worker_id
           AND (p_next ->> 'attempts')::integer = job.attempts
           AND next_fence = job.fence_id
           AND job.lease_until IS NOT NULL AND next_updated < job.lease_until
           AND next_lease IS NOT NULL AND next_lease > job.lease_until
         OR job.lease_until IS NOT NULL AND next_updated >= job.lease_until
           AND (p_next ->> 'attempts')::integer = job.attempts + 1
           AND next_fence = p_worker_id
         ) THEN
        RAISE EXCEPTION 'custom-field import heartbeat or reclaim is invalid' USING ERRCODE = '22023';
      END IF;
    ELSIF p_worker_id IS NOT NULL AND job.state = 'running'
       AND job.fence_id = p_worker_id AND job.lease_until IS NOT NULL
       AND next_updated < job.lease_until
       AND p_next ->> 'state' = 'authorization_revoked' THEN
      required_control_outcome := 'authorization_revoked';
    ELSIF p_worker_id IS NOT NULL AND job.state = 'running'
       AND job.fence_id = p_worker_id AND job.lease_until IS NOT NULL
       AND next_updated < job.lease_until
       AND p_next ->> 'state' = 'failed' THEN
      required_control_outcome := 'internal_failure';
    ELSIF p_worker_id IS NOT NULL AND job.state = 'pending'
       AND p_next ->> 'state' = 'expired' AND next_updated >= job.expires_at THEN
      required_control_outcome := 'expired';
    ELSIF p_worker_id IS NOT NULL AND job.state = 'running'
       AND p_next ->> 'state' = 'expired'
       AND job.lease_until IS NOT NULL AND next_updated >= job.lease_until
       AND next_updated >= job.expires_at THEN
      required_control_outcome := 'expired';
    ELSIF p_worker_id IS NOT NULL AND job.state = 'running'
       AND p_next ->> 'state' = 'failed'
       AND job.lease_until IS NOT NULL AND next_updated >= job.lease_until
       AND next_updated < job.expires_at
       AND job.attempts >= job.maximum_attempts THEN
      required_control_outcome := 'internal_failure';
    ELSIF p_worker_id IS NOT NULL AND job.state = 'cancellation_requested'
       AND p_next ->> 'state' = 'cancelled'
       AND job.lease_until IS NOT NULL
       AND (next_updated >= job.lease_until OR job.fence_id = p_worker_id) THEN
      required_control_outcome := 'cancelled';
    ELSE
      RAISE EXCEPTION 'custom-field import transition is invalid' USING ERRCODE = '22023';
    END IF;
    IF required_control_outcome IS NOT NULL AND (
         delta <= 0 OR (p_next ->> 'attempts')::integer <> job.attempts
         OR EXISTS (
           SELECT 1 FROM jsonb_array_elements(next_results) WITH ORDINALITY AS result(value, ordinality)
           WHERE result.ordinality > jsonb_array_length(current_results)
             AND (result.value ->> 'outcome' IS DISTINCT FROM required_control_outcome
               OR result.value ->> 'resultingVersion' <> '0'
               OR result.value -> 'fieldErrors' <> '[]'::jsonb)
         )
       ) THEN
      RAISE EXCEPTION 'custom-field import control suffix is invalid' USING ERRCODE = '22023';
    END IF;
  END IF;

  FOR result_document, result_ordinality IN
    SELECT result.value, result.ordinality
    FROM jsonb_array_elements(next_results) WITH ORDINALITY AS result(value, ordinality)
    WHERE result.ordinality > jsonb_array_length(current_results)
  LOOP
    IF NOT app.private_custom_field_import_exact_keys_v1(
         result_document, ARRAY['sequence','outcome','resultingVersion','fieldErrors']
       ) OR (result_document ->> 'sequence')::integer IS DISTINCT FROM result_ordinality
       OR jsonb_typeof(result_document -> 'fieldErrors') <> 'array' THEN
      RAISE EXCEPTION 'custom-field import result is invalid' USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.custom_field_import_results(
      tenant_id, job_id, sequence, outcome, resulting_version, field_errors,
      command_key_digest, request_fingerprint_digest, recorded_at
    ) VALUES (
      job.tenant_id, job.id, result_ordinality, result_document ->> 'outcome',
      (result_document ->> 'resultingVersion')::bigint,
      result_document -> 'fieldErrors',
      sha256(convert_to('custom-field-import:' || job.id::text || ':' || result_ordinality::text, 'UTF8')),
      coalesce(p_row_fingerprint, sha256(convert_to(result_document::text, 'UTF8'))),
      (p_next ->> 'updatedAt')::timestamptz
    );
  END LOOP;

  UPDATE public.custom_field_import_jobs AS item SET
    state = p_next ->> 'state', revision = (p_next ->> 'revision')::bigint,
    attempts = (p_next ->> 'attempts')::smallint,
    dry_run_valid = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'dry_run_valid'),
    committed = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'committed'),
    no_change = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'no_change'),
    validation_failed = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'validation_failed'),
    definition_changed = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'definition_changed'),
    version_conflict = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'version_conflict'),
    not_found_or_hidden = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'not_found_or_hidden'),
    authorization_denied = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'authorization_denied'),
    cancelled = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'cancelled'),
    authorization_revoked = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'authorization_revoked'),
    expired = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'expired'),
    internal_failure = (SELECT count(*) FROM jsonb_array_elements(next_results) AS result(value) WHERE result.value ->> 'outcome' = 'internal_failure'),
    updated_at = next_updated, available_at = next_available,
    fence_id = next_fence, lease_until = next_lease, terminal_at = next_terminal
  WHERE item.tenant_id = job.tenant_id AND item.id = job.id;
  actual := app.private_custom_field_import_record_v1(p_job_id) -> 'job';
  IF actual IS DISTINCT FROM p_next THEN
    RAISE EXCEPTION 'custom-field import durable projection diverged' USING ERRCODE = '55000';
  END IF;
  RETURN app.private_custom_field_import_record_v1(p_job_id);
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_apply_job_v1(uuid, jsonb, jsonb, uuid, boolean, bytea)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_apply_job_v1(uuid, jsonb, jsonb, uuid, boolean, bytea)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.commit_custom_field_import_transition_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE tenant_id uuid;
DECLARE job_id uuid;
DECLARE worker_id uuid;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 34603008
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','tenantId','jobId','current','next']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'current') <> 'object'
     OR jsonb_typeof(request -> 'next') <> 'object' THEN
    RAISE EXCEPTION 'custom-field import transition request is invalid' USING ERRCODE = '22023';
  END IF;
  worker_id := app.private_custom_field_import_require_worker_v1(request -> 'identity');
  tenant_id := app.private_custom_field_import_uuid_v1(request ->> 'tenantId');
  job_id := app.private_custom_field_import_uuid_v1(request ->> 'jobId');
  IF tenant_id IS DISTINCT FROM app.context_tenant_id() THEN
    RAISE EXCEPTION 'custom-field import tenant context is invalid' USING ERRCODE = '42501';
  END IF;
  RETURN app.private_custom_field_import_apply_job_v1(
    job_id, request -> 'current', request -> 'next', worker_id, false, NULL
  );
END;
$function$;
ALTER FUNCTION app.commit_custom_field_import_transition_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.commit_custom_field_import_transition_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_custom_field_import_owner;
GRANT EXECUTE ON FUNCTION app.commit_custom_field_import_transition_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.load_custom_field_import_row_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE tenant_id uuid;
DECLARE job_id uuid;
DECLARE worker_id uuid;
DECLARE fence_id uuid;
DECLARE requested_sequence integer;
DECLARE requested_revision bigint;
DECLARE job public.custom_field_import_jobs%ROWTYPE;
DECLARE import_row public.custom_field_import_rows%ROWTYPE;
DECLARE authority_scope text;
DECLARE permission_key text;
DECLARE definition_document jsonb;
DECLARE definition_id uuid;
DECLARE definition_changed boolean := false;
DECLARE found_and_visible boolean := false;
DECLARE allowed boolean := false;
DECLARE current_version bigint := 0;
DECLARE assigned_team_id uuid;
DECLARE owner_user_id uuid;
DECLARE assignee_user_id uuid;
DECLARE claimed_by_user_id uuid;
DECLARE existing_values jsonb := '[]'::jsonb;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 4096
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','tenantId','jobId','revision','fenceId','sequence']
     ) OR request ->> 'schemaVersion' <> '1' THEN
    RAISE EXCEPTION 'custom-field import row load is invalid' USING ERRCODE = '22023';
  END IF;
  worker_id := app.private_custom_field_import_require_worker_v1(request -> 'identity');
  tenant_id := app.private_custom_field_import_uuid_v1(request ->> 'tenantId');
  job_id := app.private_custom_field_import_uuid_v1(request ->> 'jobId');
  fence_id := app.private_custom_field_import_uuid_v1(request ->> 'fenceId');
  BEGIN
    requested_revision := (request ->> 'revision')::bigint;
    requested_sequence := (request ->> 'sequence')::integer;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'custom-field import row coordinate is invalid' USING ERRCODE = '22023';
  END;
  IF tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR fence_id IS DISTINCT FROM worker_id THEN
    RAISE EXCEPTION 'custom-field import tenant or fence is invalid' USING ERRCODE = '42501';
  END IF;
  SELECT item.* INTO job FROM public.custom_field_import_jobs AS item
  WHERE item.tenant_id = tenant_id AND item.id = job_id
  FOR UPDATE;
  IF NOT FOUND OR job.state <> 'running'
     OR job.revision IS DISTINCT FROM requested_revision
     OR job.fence_id IS DISTINCT FROM fence_id
     OR job.lease_until <= transaction_timestamp() THEN
    RAISE EXCEPTION 'custom-field import job fence is stale' USING ERRCODE = '40001';
  END IF;
  SELECT item.* INTO import_row FROM public.custom_field_import_rows AS item
  WHERE item.tenant_id = tenant_id AND item.job_id = job_id
    AND item.sequence = requested_sequence;
  IF NOT FOUND OR import_row.sequence IS DISTINCT FROM
       (job.dry_run_valid + job.committed + job.no_change + job.validation_failed +
        job.definition_changed + job.version_conflict + job.not_found_or_hidden +
        job.authorization_denied + job.cancelled + job.authorization_revoked +
        job.expired + job.internal_failure + 1) THEN
    RAISE EXCEPTION 'custom-field import row sequence is stale' USING ERRCODE = '40001';
  END IF;

  PERFORM set_config('app.user_id', job.requester_user_id::text, true);
  authority_scope := job.manifest_snapshot ->> 'authorityScope';
  PERFORM app.private_custom_field_import_require_actor_v1(
    tenant_id, job.requester_user_id, job.owner_membership_id,
    job.object_type, authority_scope
  );
  PERFORM 1 FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = tenant_id AND membership.id = job.owner_membership_id
    AND membership.user_id = job.requester_user_id AND membership.status = 'active'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import authority was revoked' USING ERRCODE = '42501';
  END IF;

  FOR definition_document IN
    SELECT item.value
    FROM jsonb_array_elements(job.manifest_snapshot #> '{manifest,definitions}') AS item(value)
  LOOP
    definition_id := app.private_custom_field_import_uuid_v1(definition_document ->> 'id');
    PERFORM 1 FROM public.custom_field_definitions AS definition
    WHERE definition.tenant_id = tenant_id AND definition.id = definition_id
    FOR SHARE;
    IF NOT FOUND
       OR definition_document - 'pinSha256' IS DISTINCT FROM
          app.private_custom_field_import_definition_document_v1(tenant_id, definition_id)
       OR definition_document ->> 'pinSha256' IS DISTINCT FROM
          app.private_custom_field_import_definition_pin_v1(tenant_id, definition_id) THEN
      definition_changed := true;
    END IF;
  END LOOP;

  permission_key := app.private_custom_field_import_permission_v1(job.object_type);
  IF job.object_type = 'alert' THEN
    SELECT alert.version, alert.assigned_team_id, alert.created_by,
           alert.assignee_user_id, alert.claimed_by_user_id
    INTO current_version, assigned_team_id, owner_user_id,
         assignee_user_id, claimed_by_user_id
    FROM public.alerts AS alert
    WHERE alert.tenant_id = tenant_id AND alert.id = import_row.target_id
      AND alert.deleted_at IS NULL
    FOR UPDATE;
    found_and_visible := FOUND;
  ELSE
    SELECT item.version, item.assigned_team_id, item.created_by_user_id,
           item.assignee_user_id, item.claimed_by_user_id
    INTO current_version, assigned_team_id, owner_user_id,
         assignee_user_id, claimed_by_user_id
    FROM public.cases AS item
    WHERE item.tenant_id = tenant_id AND item.id = import_row.target_id
    FOR UPDATE;
    found_and_visible := FOUND;
  END IF;
  IF found_and_visible THEN
    allowed := app.private_current_ticket_scope_allows_v1(
      permission_key, assigned_team_id, owner_user_id,
      assignee_user_id, claimed_by_user_id
    );
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'definitionId', value.definition_id::text,
      'canonicalValue', CASE value.data_type
        WHEN 'single_select' THEN to_jsonb(value.option_keys[1])
        ELSE value.canonical_value END
    ) ORDER BY value.definition_id), '[]'::jsonb)
    INTO existing_values
    FROM public.custom_field_values AS value
    WHERE value.tenant_id = tenant_id AND value.object_type = job.object_type
      AND (job.object_type = 'alert' AND value.alert_id = import_row.target_id
        OR job.object_type = 'case' AND value.case_id = import_row.target_id)
      AND EXISTS (
        SELECT 1
        FROM jsonb_array_elements(job.manifest_snapshot #> '{manifest,definitions}') AS pinned(document)
        WHERE pinned.document ->> 'id' = value.definition_id::text
      );
  END IF;
  RETURN jsonb_build_object(
    'schemaVersion', 1,
    'foundAndVisible', found_and_visible,
    'allowed', allowed,
    'definitionChanged', definition_changed,
    'currentVersion', current_version,
    'existing', existing_values
  );
END;
$function$;
ALTER FUNCTION app.load_custom_field_import_row_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.load_custom_field_import_row_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_custom_field_import_owner;
GRANT EXECUTE ON FUNCTION app.load_custom_field_import_row_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_custom_field_import_upsert_value_v1(
  p_job public.custom_field_import_jobs,
  p_row public.custom_field_import_rows,
  p_patch jsonb,
  p_recorded_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE definition public.custom_field_definitions%ROWTYPE;
DECLARE patch_definition_id uuid;
DECLARE schema_version bigint;
DECLARE presence public.custom_field_value_presence;
DECLARE canonical jsonb;
DECLARE stored_canonical jsonb;
DECLARE text_value text;
DECLARE integer_value bigint;
DECLARE decimal_value numeric;
DECLARE boolean_value boolean;
DECLARE date_value date;
DECLARE date_time_value timestamptz;
DECLARE ip_value inet;
DECLARE cidr_value cidr;
DECLARE reference_id uuid;
DECLARE option_keys text[];
DECLARE structured_value jsonb;
BEGIN
  IF NOT app.private_custom_field_import_exact_keys_v1(
       p_patch, ARRAY['definitionId','schemaVersion','presence','canonicalValue']
     ) OR p_patch ->> 'presence' NOT IN ('null','present')
     OR jsonb_typeof(p_patch -> 'schemaVersion') <> 'number' THEN
    RAISE EXCEPTION 'custom-field import patch is invalid' USING ERRCODE = '22023';
  END IF;
  patch_definition_id := app.private_custom_field_import_uuid_v1(p_patch ->> 'definitionId');
  BEGIN schema_version := (p_patch ->> 'schemaVersion')::bigint;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'custom-field import patch version is invalid' USING ERRCODE = '22023';
  END;
  presence := (p_patch ->> 'presence')::public.custom_field_value_presence;
  canonical := p_patch -> 'canonicalValue';
  IF canonical IS NULL
     OR presence = 'null' AND jsonb_typeof(canonical) <> 'null'
     OR presence = 'present' AND jsonb_typeof(canonical) = 'null' THEN
    RAISE EXCEPTION 'custom-field import patch value is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT item.* INTO definition FROM public.custom_field_definitions AS item
  WHERE item.tenant_id = p_job.tenant_id AND item.id = patch_definition_id
    AND item.object_type = p_job.object_type
    AND item.schema_version = schema_version AND item.archived_at IS NULL
  FOR SHARE;
  IF NOT FOUND OR NOT EXISTS (
       SELECT 1
       FROM jsonb_array_elements(p_job.manifest_snapshot #> '{manifest,definitions}') AS pinned(document)
        WHERE pinned.document ->> 'id' = patch_definition_id::text
         AND pinned.document ->> 'schemaVersion' = schema_version::text
         AND pinned.document #>> '{visibility,Operator}' = 'true'
         AND pinned.document #>> '{editPolicy,OperatorUpdate}' = 'true'
     ) OR NOT EXISTS (
       SELECT 1 FROM jsonb_array_elements(p_row.cells_snapshot) AS cell(document)
       WHERE cell.document ->> 'key' = definition.key
         AND cell.document ->> 'presence' <> 'missing'
     ) THEN
    RAISE EXCEPTION 'custom-field import patch definition is invalid' USING ERRCODE = '22023';
  END IF;

  stored_canonical := canonical;
  IF presence = 'present' THEN
    CASE
      WHEN definition.data_type IN ('short_text', 'long_text', 'url', 'email') THEN
        text_value := canonical #>> '{}';
      WHEN definition.data_type IN ('integer', 'duration') THEN
        integer_value := (canonical #>> '{}')::bigint;
      WHEN definition.data_type = 'decimal' THEN
        decimal_value := (canonical #>> '{}')::numeric;
      WHEN definition.data_type = 'boolean' THEN
        boolean_value := (canonical #>> '{}')::boolean;
      WHEN definition.data_type = 'date' THEN
        date_value := (canonical #>> '{}')::date;
        stored_canonical := to_jsonb(date_value);
      WHEN definition.data_type = 'datetime' THEN
        date_time_value := (canonical #>> '{}')::timestamptz;
        stored_canonical := to_jsonb(date_time_value);
      WHEN definition.data_type = 'ip' THEN
        ip_value := (canonical #>> '{}')::inet;
        stored_canonical := to_jsonb(ip_value::text);
      WHEN definition.data_type = 'cidr' THEN
        cidr_value := (canonical #>> '{}')::cidr;
        stored_canonical := to_jsonb(cidr_value::text);
      WHEN definition.data_type IN ('user', 'operator_team', 'customer_contact', 'asset_reference', 'ioc_reference') THEN
        reference_id := app.private_custom_field_import_uuid_v1(canonical #>> '{}');
        stored_canonical := to_jsonb(reference_id::text);
      WHEN definition.data_type = 'single_select' THEN
        option_keys := ARRAY[canonical #>> '{}'];
        stored_canonical := to_jsonb(option_keys);
      WHEN definition.data_type = 'multi_select' THEN
        SELECT coalesce(array_agg(item.value ORDER BY item.ordinality), ARRAY[]::text[])
        INTO option_keys
        FROM jsonb_array_elements_text(canonical) WITH ORDINALITY AS item(value, ordinality);
        stored_canonical := to_jsonb(option_keys);
      WHEN definition.data_type = 'structured_json' THEN
        structured_value := canonical;
      ELSE
        RAISE EXCEPTION 'custom-field import patch type is invalid' USING ERRCODE = '22023';
    END CASE;
  END IF;

  IF p_job.object_type = 'alert' THEN
    INSERT INTO public.custom_field_values(
      tenant_id, object_type, alert_id, case_id, definition_id,
      definition_schema_version, data_type, presence, canonical_value,
      text_value, integer_value, decimal_value, boolean_value, date_value,
      date_time_value, ip_value, cidr_value, reference_id, option_keys,
      structured_value, created_by_membership_id, updated_by_membership_id,
      created_at, updated_at
    ) VALUES (
      p_job.tenant_id, p_job.object_type, p_row.target_id, NULL, definition.id,
      definition.schema_version, definition.data_type, presence, stored_canonical,
      text_value, integer_value, decimal_value, boolean_value, date_value,
      date_time_value, ip_value, cidr_value, reference_id, option_keys,
      structured_value, p_job.owner_membership_id, p_job.owner_membership_id,
      p_recorded_at, p_recorded_at
    ) ON CONFLICT (tenant_id, alert_id, definition_id)
      WHERE alert_id IS NOT NULL
    DO UPDATE SET
      definition_schema_version = EXCLUDED.definition_schema_version,
      data_type = EXCLUDED.data_type, presence = EXCLUDED.presence,
      canonical_value = EXCLUDED.canonical_value,
      text_value = EXCLUDED.text_value, integer_value = EXCLUDED.integer_value,
      decimal_value = EXCLUDED.decimal_value, boolean_value = EXCLUDED.boolean_value,
      date_value = EXCLUDED.date_value, date_time_value = EXCLUDED.date_time_value,
      ip_value = EXCLUDED.ip_value, cidr_value = EXCLUDED.cidr_value,
      reference_id = EXCLUDED.reference_id, option_keys = EXCLUDED.option_keys,
      structured_value = EXCLUDED.structured_value,
      updated_by_membership_id = EXCLUDED.updated_by_membership_id,
      version = custom_field_values.version + 1, updated_at = EXCLUDED.updated_at;
  ELSE
    INSERT INTO public.custom_field_values(
      tenant_id, object_type, alert_id, case_id, definition_id,
      definition_schema_version, data_type, presence, canonical_value,
      text_value, integer_value, decimal_value, boolean_value, date_value,
      date_time_value, ip_value, cidr_value, reference_id, option_keys,
      structured_value, created_by_membership_id, updated_by_membership_id,
      created_at, updated_at
    ) VALUES (
      p_job.tenant_id, p_job.object_type, NULL, p_row.target_id, definition.id,
      definition.schema_version, definition.data_type, presence, stored_canonical,
      text_value, integer_value, decimal_value, boolean_value, date_value,
      date_time_value, ip_value, cidr_value, reference_id, option_keys,
      structured_value, p_job.owner_membership_id, p_job.owner_membership_id,
      p_recorded_at, p_recorded_at
    ) ON CONFLICT (tenant_id, case_id, definition_id)
      WHERE case_id IS NOT NULL
    DO UPDATE SET
      definition_schema_version = EXCLUDED.definition_schema_version,
      data_type = EXCLUDED.data_type, presence = EXCLUDED.presence,
      canonical_value = EXCLUDED.canonical_value,
      text_value = EXCLUDED.text_value, integer_value = EXCLUDED.integer_value,
      decimal_value = EXCLUDED.decimal_value, boolean_value = EXCLUDED.boolean_value,
      date_value = EXCLUDED.date_value, date_time_value = EXCLUDED.date_time_value,
      ip_value = EXCLUDED.ip_value, cidr_value = EXCLUDED.cidr_value,
      reference_id = EXCLUDED.reference_id, option_keys = EXCLUDED.option_keys,
      structured_value = EXCLUDED.structured_value,
      updated_by_membership_id = EXCLUDED.updated_by_membership_id,
      version = custom_field_values.version + 1, updated_at = EXCLUDED.updated_at;
  END IF;
EXCEPTION
  WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN
    RAISE EXCEPTION 'custom-field import typed patch is invalid' USING ERRCODE = '22023';
END;
$function$;
ALTER FUNCTION app.private_custom_field_import_upsert_value_v1(
  public.custom_field_import_jobs, public.custom_field_import_rows, jsonb, timestamptz
) OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.private_custom_field_import_upsert_value_v1(
  public.custom_field_import_jobs, public.custom_field_import_rows, jsonb, timestamptz
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.commit_custom_field_import_row_v1(request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
#variable_conflict use_variable
DECLARE tenant_id uuid;
DECLARE job_id uuid;
DECLARE worker_id uuid;
DECLARE fence_id uuid;
DECLARE requested_sequence integer;
DECLARE job public.custom_field_import_jobs%ROWTYPE;
DECLARE import_row public.custom_field_import_rows%ROWTYPE;
DECLARE actual_job jsonb;
DECLARE result_document jsonb := request -> 'result';
DECLARE patches jsonb := request -> 'patches';
DECLARE patch_document jsonb;
DECLARE error_document jsonb;
DECLARE result_outcome text;
DECLARE result_version bigint;
DECLARE fingerprint bytea;
DECLARE stored_result public.custom_field_import_results%ROWTYPE;
DECLARE definition_document jsonb;
DECLARE definition_id uuid;
DECLARE definition_changed boolean := false;
DECLARE authority_scope text;
DECLARE permission_key text;
DECLARE found_and_visible boolean := false;
DECLARE allowed boolean := false;
DECLARE current_version bigint := 0;
DECLARE assigned_team_id uuid;
DECLARE owner_user_id uuid;
DECLARE assignee_user_id uuid;
DECLARE claimed_by_user_id uuid;
DECLARE forced_outcome text;
DECLARE recorded_at timestamptz;
DECLARE activity_sequence integer;
DECLARE patch_count integer;
BEGIN
  IF request IS NULL OR octet_length(request::text) > 34603008
     OR NOT app.private_custom_field_import_exact_keys_v1(
       request, ARRAY['schemaVersion','identity','tenantId','jobId','fenceId','sequence','current','next','result','patches','recordedAt']
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'current') <> 'object'
     OR jsonb_typeof(request -> 'next') <> 'object'
     OR jsonb_typeof(result_document) <> 'object'
     OR jsonb_typeof(patches) <> 'array'
     OR jsonb_array_length(patches) > 512 THEN
    RAISE EXCEPTION 'custom-field import row commit is invalid' USING ERRCODE = '22023';
  END IF;
  worker_id := app.private_custom_field_import_require_worker_v1(request -> 'identity');
  tenant_id := app.private_custom_field_import_uuid_v1(request ->> 'tenantId');
  job_id := app.private_custom_field_import_uuid_v1(request ->> 'jobId');
  fence_id := app.private_custom_field_import_uuid_v1(request ->> 'fenceId');
  BEGIN
    requested_sequence := (request ->> 'sequence')::integer;
    recorded_at := (request ->> 'recordedAt')::timestamptz;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range OR datetime_field_overflow THEN
    RAISE EXCEPTION 'custom-field import row coordinate is invalid' USING ERRCODE = '22023';
  END;
  IF tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR fence_id IS DISTINCT FROM worker_id THEN
    RAISE EXCEPTION 'custom-field import tenant or fence is invalid' USING ERRCODE = '42501';
  END IF;
  SELECT item.* INTO job FROM public.custom_field_import_jobs AS item
  WHERE item.tenant_id = tenant_id AND item.id = job_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import job was not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT item.* INTO import_row FROM public.custom_field_import_rows AS item
  WHERE item.tenant_id = tenant_id AND item.job_id = job_id
    AND item.sequence = requested_sequence;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'custom-field import row was not found' USING ERRCODE = 'P0002';
  END IF;
  fingerprint := sha256(convert_to(jsonb_build_object(
    'domain', 'periapsis.custom-field-import-row.v1',
    'tenantId', tenant_id, 'jobId', job_id, 'sequence', requested_sequence,
    'manifestSha256', encode(job.request_digest, 'hex'),
    'cellsSha256', encode(import_row.cells_digest, 'hex'),
    'result', result_document, 'patches', patches
  )::text, 'UTF8'));
  SELECT item.* INTO stored_result FROM public.custom_field_import_results AS item
  WHERE item.tenant_id = tenant_id AND item.job_id = job_id
    AND item.sequence = requested_sequence;
  IF FOUND THEN
    IF stored_result.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'custom-field import row replay conflicts' USING ERRCODE = '23505';
    END IF;
    RETURN app.private_custom_field_import_record_v1(job_id);
  END IF;
  actual_job := app.private_custom_field_import_record_v1(job_id) -> 'job';
  IF actual_job IS DISTINCT FROM request -> 'current'
     OR job.state <> 'running' OR job.fence_id IS DISTINCT FROM fence_id
     OR job.lease_until <= recorded_at OR recorded_at < job.updated_at
     OR requested_sequence IS DISTINCT FROM
       (job.dry_run_valid + job.committed + job.no_change + job.validation_failed +
        job.definition_changed + job.version_conflict + job.not_found_or_hidden +
        job.authorization_denied + job.cancelled + job.authorization_revoked +
        job.expired + job.internal_failure + 1) THEN
    RAISE EXCEPTION 'custom-field import row CAS is stale' USING ERRCODE = '40001';
  END IF;

  IF NOT app.private_custom_field_import_exact_keys_v1(
       result_document, ARRAY['sequence','outcome','resultingVersion','fieldErrors']
     ) OR (result_document ->> 'sequence')::integer IS DISTINCT FROM requested_sequence
     OR jsonb_typeof(result_document -> 'fieldErrors') <> 'array'
     OR jsonb_array_length(result_document -> 'fieldErrors') > 512 THEN
    RAISE EXCEPTION 'custom-field import row result is invalid' USING ERRCODE = '22023';
  END IF;
  BEGIN result_version := (result_document ->> 'resultingVersion')::bigint;
  EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RAISE EXCEPTION 'custom-field import row result version is invalid' USING ERRCODE = '22023';
  END;
  result_outcome := result_document ->> 'outcome';
  IF result_outcome NOT IN (
       'dry_run_valid','committed','no_change','validation_failed',
       'definition_changed','version_conflict','not_found_or_hidden','authorization_denied'
     ) OR result_outcome IN ('dry_run_valid','no_change')
          AND result_version IS DISTINCT FROM import_row.expected_version
     OR result_outcome = 'committed'
          AND result_version IS DISTINCT FROM import_row.expected_version + 1
     OR result_outcome NOT IN ('dry_run_valid','committed','no_change')
          AND result_version <> 0
     OR result_outcome = 'validation_failed'
          AND jsonb_array_length(result_document -> 'fieldErrors') = 0
     OR result_outcome <> 'validation_failed'
          AND result_document -> 'fieldErrors' <> '[]'::jsonb THEN
    RAISE EXCEPTION 'custom-field import row result semantics are invalid' USING ERRCODE = '22023';
  END IF;
  FOR error_document IN
    SELECT item.value FROM jsonb_array_elements(result_document -> 'fieldErrors') AS item(value)
  LOOP
    IF NOT app.private_custom_field_import_exact_keys_v1(error_document, ARRAY['field','code'])
       OR error_document ->> 'field' !~ '^[a-z][a-z0-9_.-]{0,63}$'
       OR error_document ->> 'code' !~ '^[a-z][a-z0-9_]{0,63}$' THEN
      RAISE EXCEPTION 'custom-field import field error is invalid' USING ERRCODE = '22023';
    END IF;
  END LOOP;
  patch_count := jsonb_array_length(patches);
  IF result_outcome IN ('committed','dry_run_valid') AND patch_count = 0
     OR result_outcome NOT IN ('committed','dry_run_valid') AND patch_count <> 0
     OR result_outcome = 'committed' AND job.mode <> 'commit'
     OR result_outcome = 'dry_run_valid' AND job.mode <> 'dry_run'
     OR request #> '{next,results,-1}' IS DISTINCT FROM result_document
     OR (request #>> '{next,revision}')::bigint IS DISTINCT FROM job.revision + 1
     OR (jsonb_array_length(request #> '{next,results}')) IS DISTINCT FROM requested_sequence
      OR request #>> '{next,state}' IS DISTINCT FROM
         (CASE WHEN requested_sequence = job.total THEN 'completed' ELSE 'running' END) THEN
    RAISE EXCEPTION 'custom-field import row transition is invalid' USING ERRCODE = '22023';
  END IF;

  PERFORM set_config('app.user_id', job.requester_user_id::text, true);
  authority_scope := job.manifest_snapshot ->> 'authorityScope';
  PERFORM app.private_custom_field_import_require_actor_v1(
    tenant_id, job.requester_user_id, job.owner_membership_id,
    job.object_type, authority_scope
  );
  FOR definition_document IN
    SELECT item.value
    FROM jsonb_array_elements(job.manifest_snapshot #> '{manifest,definitions}') AS item(value)
  LOOP
    definition_id := app.private_custom_field_import_uuid_v1(definition_document ->> 'id');
    PERFORM 1 FROM public.custom_field_definitions AS definition
    WHERE definition.tenant_id = tenant_id AND definition.id = definition_id
    FOR SHARE;
    IF NOT FOUND
       OR definition_document - 'pinSha256' IS DISTINCT FROM
          app.private_custom_field_import_definition_document_v1(tenant_id, definition_id)
       OR definition_document ->> 'pinSha256' IS DISTINCT FROM
          app.private_custom_field_import_definition_pin_v1(tenant_id, definition_id) THEN
      definition_changed := true;
    END IF;
  END LOOP;

  permission_key := app.private_custom_field_import_permission_v1(job.object_type);
  IF job.object_type = 'alert' THEN
    SELECT alert.version, alert.assigned_team_id, alert.created_by,
           alert.assignee_user_id, alert.claimed_by_user_id
    INTO current_version, assigned_team_id, owner_user_id,
         assignee_user_id, claimed_by_user_id
    FROM public.alerts AS alert
    WHERE alert.tenant_id = tenant_id AND alert.id = import_row.target_id
      AND alert.deleted_at IS NULL
    FOR UPDATE;
    found_and_visible := FOUND;
  ELSE
    SELECT item.version, item.assigned_team_id, item.created_by_user_id,
           item.assignee_user_id, item.claimed_by_user_id
    INTO current_version, assigned_team_id, owner_user_id,
         assignee_user_id, claimed_by_user_id
    FROM public.cases AS item
    WHERE item.tenant_id = tenant_id AND item.id = import_row.target_id
    FOR UPDATE;
    found_and_visible := FOUND;
  END IF;
  IF found_and_visible THEN
    allowed := app.private_current_ticket_scope_allows_v1(
      permission_key, assigned_team_id, owner_user_id,
      assignee_user_id, claimed_by_user_id
    );
  END IF;
  forced_outcome := CASE
    WHEN NOT found_and_visible THEN 'not_found_or_hidden'
    WHEN NOT allowed THEN 'authorization_denied'
    WHEN current_version IS DISTINCT FROM import_row.expected_version THEN 'version_conflict'
    WHEN definition_changed THEN 'definition_changed'
    ELSE NULL END;
  IF forced_outcome IS NOT NULL AND result_outcome IS DISTINCT FROM forced_outcome
     OR forced_outcome IS NULL AND result_outcome IN (
       'not_found_or_hidden','authorization_denied','version_conflict','definition_changed'
     ) THEN
    RAISE EXCEPTION 'custom-field import row snapshot changed' USING ERRCODE = '40001';
  END IF;

  IF result_outcome IN ('committed','dry_run_valid') THEN
    IF (SELECT count(*) FROM jsonb_array_elements(patches)) IS DISTINCT FROM
       (SELECT count(DISTINCT value ->> 'definitionId') FROM jsonb_array_elements(patches)) THEN
      RAISE EXCEPTION 'custom-field import patches are duplicated' USING ERRCODE = '22023';
    END IF;
    FOR patch_document IN
      SELECT item.value FROM jsonb_array_elements(patches) AS item(value)
    LOOP
      IF job.mode = 'commit' THEN
        PERFORM app.private_custom_field_import_upsert_value_v1(
          job, import_row, patch_document, recorded_at
        );
      ELSE
        -- The same closed helper validates dry-run patch shape and typed
        -- projections inside a subtransaction that is always rolled back.
        BEGIN
          PERFORM app.private_custom_field_import_upsert_value_v1(
            job, import_row, patch_document, recorded_at
          );
          RAISE EXCEPTION USING ERRCODE = 'PZ001';
        EXCEPTION WHEN SQLSTATE 'PZ001' THEN NULL;
        END;
      END IF;
    END LOOP;
  END IF;

  IF result_outcome = 'committed' THEN
    IF job.object_type = 'alert' THEN
      UPDATE public.alerts AS alert SET
        version = alert.version + 1, updated_at = recorded_at
      WHERE alert.tenant_id = tenant_id AND alert.id = import_row.target_id
        AND alert.version = import_row.expected_version AND alert.deleted_at IS NULL;
    ELSE
      UPDATE public.cases AS item SET
        version = item.version + 1, updated_at = recorded_at
      WHERE item.tenant_id = tenant_id AND item.id = import_row.target_id
        AND item.version = import_row.expected_version;
    END IF;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'custom-field import ticket CAS changed' USING ERRCODE = '40001';
    END IF;
    SELECT coalesce(max(activity.sequence), 0) + 1 INTO activity_sequence
    FROM public.ticket_activities AS activity
    WHERE activity.tenant_id = tenant_id
      AND (job.object_type = 'alert' AND activity.alert_id = import_row.target_id
        OR job.object_type = 'case' AND activity.case_id = import_row.target_id);
    INSERT INTO public.ticket_activities(
      id, tenant_id, alert_id, case_id, sequence, kind, summary,
      actor_principal_kind, actor_membership_id, actor_user_id,
      actor_service_account_id, origin, details, occurred_at
    ) VALUES (
      uuidv7(), tenant_id,
      CASE WHEN job.object_type = 'alert' THEN import_row.target_id END,
      CASE WHEN job.object_type = 'case' THEN import_row.target_id END,
      activity_sequence, 'custom_field.imported', 'Custom fields imported',
      'human', job.owner_membership_id, job.requester_user_id,
      NULL, 'api', jsonb_build_object(
        'jobId', job.id, 'sequence', import_row.sequence,
        'fieldCount', patch_count, 'resultingVersion', result_version
      ), recorded_at
    );
    PERFORM app.private_custom_field_import_append_worker_audit_v1(
      tenant_id, 'custom_field.import.committed', job.object_type::text,
      import_row.target_id, job.request_id, job.correlation_id, recorded_at,
      jsonb_build_object(
        'jobId', job.id, 'sequence', import_row.sequence,
        'fieldCount', patch_count, 'expectedVersion', import_row.expected_version,
        'resultingVersion', result_version,
        'requesterUserId', job.requester_user_id,
        'ownerMembershipId', job.owner_membership_id
      )
    );
    INSERT INTO public.outbox_events(
      id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
      event_type, schema_version, payload, deduplication_key,
      correlation_id, causation_id, actor_kind, actor_id, producer,
      maximum_audience
    ) VALUES (
      uuidv7(), tenant_id, job.object_type::text, import_row.target_id,
      result_version, 'custom_field.import.committed', 1,
      jsonb_build_object(
        'tenantId', tenant_id, 'jobId', job.id,
        'objectType', job.object_type, 'targetId', import_row.target_id,
        'sequence', import_row.sequence, 'resultingVersion', result_version,
        'fieldCount', patch_count
      ), 'custom-field-import:' || job.id::text || ':' || import_row.sequence::text,
      job.correlation_id, job.request_id, 'human', job.requester_user_id,
      'custom_field_import', 'operator'
    );
  END IF;

  RETURN app.private_custom_field_import_apply_job_v1(
    job_id, request -> 'current', request -> 'next', worker_id, true, fingerprint
  );
END;
$function$;
ALTER FUNCTION app.commit_custom_field_import_row_v1(jsonb)
  OWNER TO periapsis_custom_field_import_owner;
REVOKE ALL ON FUNCTION app.commit_custom_field_import_row_v1(jsonb)
FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor,
  periapsis_custom_field_import_owner;
GRANT EXECUTE ON FUNCTION app.commit_custom_field_import_row_v1(jsonb)
TO periapsis_worker;
