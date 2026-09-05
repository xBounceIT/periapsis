ALTER TABLE "tenant_ldap_sync_runs" DROP CONSTRAINT "tenant_ldap_sync_runs_revision_check";--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" DROP CONSTRAINT "tenant_ldap_sync_runs_lifecycle_check";--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" DROP CONSTRAINT "tenant_ldap_sync_staged_observations_bounds_check";--> statement-breakpoint
CREATE INDEX "tenant_ldap_sync_runs_reclaim_idx" ON "tenant_ldap_sync_runs" USING btree ("status","claim_expires_at","queued_at","id");--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_claim_check" CHECK ((
          "tenant_ldap_sync_runs"."claim_fence" = 0
          and "tenant_ldap_sync_runs"."claim_id" is null
          and "tenant_ldap_sync_runs"."claim_receipt_digest" is null
          and "tenant_ldap_sync_runs"."claim_acquired_at" is null
          and "tenant_ldap_sync_runs"."claim_expires_at" is null
        ) or (
          "tenant_ldap_sync_runs"."claim_fence" > 0
          and (uuid_extract_version("tenant_ldap_sync_runs"."claim_id") = 7) is true
          and octet_length("tenant_ldap_sync_runs"."claim_receipt_digest") = 32
          and "tenant_ldap_sync_runs"."claim_acquired_at" >= "tenant_ldap_sync_runs"."queued_at"
          and "tenant_ldap_sync_runs"."claim_expires_at" > "tenant_ldap_sync_runs"."claim_acquired_at"
        ));--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_revision_check" CHECK ("tenant_ldap_sync_runs"."provider_version" > 0
        and "tenant_ldap_sync_runs"."configuration_version" > 0
        and "tenant_ldap_sync_runs"."binding_version" > 0
        and "tenant_ldap_sync_runs"."binding_auth_revision" > 0
        and "tenant_ldap_sync_runs"."rule_set_revision" > 0
        and "tenant_ldap_sync_runs"."authorization_revision" > 0
        and "tenant_ldap_sync_runs"."authorization_progress_revision" >= "tenant_ldap_sync_runs"."authorization_revision"
        and "tenant_ldap_sync_runs"."bind_secret_version" > 0
        and "tenant_ldap_sync_runs"."bind_secret_key_version" > 0
        and "tenant_ldap_sync_runs"."claim_fence" >= 0
        and "tenant_ldap_sync_runs"."version" between 1 and 5);--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_lifecycle_check" CHECK ((
          "tenant_ldap_sync_runs"."status" = 'queued'
          and "tenant_ldap_sync_runs"."enumeration_complete" is null
          and "tenant_ldap_sync_runs"."result_truncated" is null
          and "tenant_ldap_sync_runs"."enumeration_started_at" is null
          and "tenant_ldap_sync_runs"."enumeration_completed_at" is null
          and "tenant_ldap_sync_runs"."completed_at" is null
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."claim_fence" = 0
          and "tenant_ldap_sync_runs"."version" = 1
        ) or (
          "tenant_ldap_sync_runs"."status" = 'enumerating'
          and "tenant_ldap_sync_runs"."enumeration_complete" is null
          and "tenant_ldap_sync_runs"."result_truncated" is null
          and "tenant_ldap_sync_runs"."enumeration_started_at" >= "tenant_ldap_sync_runs"."queued_at"
          and "tenant_ldap_sync_runs"."enumeration_completed_at" is null
          and "tenant_ldap_sync_runs"."completed_at" is null
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."claim_fence" > 0
          and "tenant_ldap_sync_runs"."version" = 2
        ) or (
          "tenant_ldap_sync_runs"."status" = 'applying'
          and "tenant_ldap_sync_runs"."enumeration_complete" is true
          and "tenant_ldap_sync_runs"."result_truncated" is false
          and "tenant_ldap_sync_runs"."enumeration_started_at" >= "tenant_ldap_sync_runs"."queued_at"
          and "tenant_ldap_sync_runs"."enumeration_completed_at" >= "tenant_ldap_sync_runs"."enumeration_started_at"
          and "tenant_ldap_sync_runs"."completed_at" is null
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."claim_fence" > 0
          and "tenant_ldap_sync_runs"."version" = 3
        ) or (
          "tenant_ldap_sync_runs"."status" = 'succeeded'
          and "tenant_ldap_sync_runs"."enumeration_complete" is true
          and "tenant_ldap_sync_runs"."result_truncated" is false
          and "tenant_ldap_sync_runs"."enumeration_completed_at" >= "tenant_ldap_sync_runs"."enumeration_started_at"
          and "tenant_ldap_sync_runs"."completed_at" >= "tenant_ldap_sync_runs"."enumeration_completed_at"
          and "tenant_ldap_sync_runs"."failure_category" is null
          and "tenant_ldap_sync_runs"."applied_count" = "tenant_ldap_sync_runs"."observed_count"
          and "tenant_ldap_sync_runs"."version" = 4
        ) or (
          "tenant_ldap_sync_runs"."status" in ('failed', 'cancelled', 'stale')
          and "tenant_ldap_sync_runs"."completed_at" >= coalesce("tenant_ldap_sync_runs"."enumeration_started_at", "tenant_ldap_sync_runs"."queued_at")
          and "tenant_ldap_sync_runs"."failure_category" is not null
          and "tenant_ldap_sync_runs"."version" between 2 and 5
        ));--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" ADD CONSTRAINT "tenant_ldap_sync_staged_observations_bounds_check" CHECK ("tenant_ldap_sync_staged_observations"."ordinal" between 1 and 5000
        and "tenant_ldap_sync_staged_observations"."digest_key_version" between 1 and 32767
        and octet_length("tenant_ldap_sync_staged_observations"."subject_digest") = 32
        and octet_length("tenant_ldap_sync_staged_observations"."observation_digest") = 32
        and "tenant_ldap_sync_staged_observations"."apply_attempt" between 0 and 10
        and (("tenant_ldap_sync_staged_observations"."planning_fence" is null and "tenant_ldap_sync_staged_observations"."planning_claimed_at" is null)
          or ("tenant_ldap_sync_staged_observations"."planning_fence" > 0
            and "tenant_ldap_sync_staged_observations"."planning_claimed_at" >= "tenant_ldap_sync_staged_observations"."staged_at"))
        and ("tenant_ldap_sync_staged_observations"."applied_at" is null or "tenant_ldap_sync_staged_observations"."applied_at" >= "tenant_ldap_sync_staged_observations"."staged_at"));