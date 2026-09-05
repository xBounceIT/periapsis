ALTER TABLE "identity_keyring_versions" DROP CONSTRAINT "identity_keyring_versions_retirement_check";--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" DROP CONSTRAINT "tenant_ldap_provider_test_runs_result_semantics_check";--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" DROP CONSTRAINT "tenant_ldap_provider_test_runs_lifecycle_check";--> statement-breakpoint
ALTER TABLE "identity_keyring_versions" ADD COLUMN "is_active" boolean DEFAULT false NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "identity_keyring_versions_single_active_key" ON "identity_keyring_versions" USING btree ("is_active") WHERE "identity_keyring_versions"."is_active";--> statement-breakpoint
ALTER TABLE "identity_keyring_versions" ADD CONSTRAINT "identity_keyring_versions_retirement_check" CHECK (("identity_keyring_versions"."retired_at" is null or "identity_keyring_versions"."retired_at" >= "identity_keyring_versions"."bound_at")
        and (not "identity_keyring_versions"."is_active" or "identity_keyring_versions"."retired_at" is null));--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" ADD CONSTRAINT "tenant_ldap_provider_test_runs_result_semantics_check" CHECK ((("tenant_ldap_provider_test_runs"."outcome" is null and "tenant_ldap_provider_test_runs"."category" is null)
        or ("tenant_ldap_provider_test_runs"."outcome" = 'success'
          and "tenant_ldap_provider_test_runs"."category" = 'success'
          and "tenant_ldap_provider_test_runs"."endpoint_priority" is not null)
        or ("tenant_ldap_provider_test_runs"."outcome" = 'inconclusive' and "tenant_ldap_provider_test_runs"."category" = 'stale_configuration')
        or ("tenant_ldap_provider_test_runs"."outcome" = 'failure'
          and "tenant_ldap_provider_test_runs"."category" not in ('success', 'stale_configuration')
          and ("tenant_ldap_provider_test_runs"."category" = 'cancelled' or "tenant_ldap_provider_test_runs"."endpoint_priority" is not null)
          and ("tenant_ldap_provider_test_runs"."test_kind" = 'bind' or "tenant_ldap_provider_test_runs"."category" <> 'bind_rejected'))) is true);--> statement-breakpoint
ALTER TABLE "tenant_ldap_provider_test_runs" ADD CONSTRAINT "tenant_ldap_provider_test_runs_lifecycle_check" CHECK ((("tenant_ldap_provider_test_runs"."status" = 'started'
          and "tenant_ldap_provider_test_runs"."outcome" is null
          and "tenant_ldap_provider_test_runs"."category" is null
          and "tenant_ldap_provider_test_runs"."endpoint_priority" is null
          and "tenant_ldap_provider_test_runs"."duration_ms" is null
          and "tenant_ldap_provider_test_runs"."completed_by_membership_id" is null
          and "tenant_ldap_provider_test_runs"."completed_at" is null
          and "tenant_ldap_provider_test_runs"."version" = 1)
        or ("tenant_ldap_provider_test_runs"."status" = 'completed'
          and "tenant_ldap_provider_test_runs"."outcome" is not null
          and "tenant_ldap_provider_test_runs"."category" is not null
          and "tenant_ldap_provider_test_runs"."duration_ms" is not null
          and "tenant_ldap_provider_test_runs"."completed_by_membership_id" is not null
          and "tenant_ldap_provider_test_runs"."completed_by_membership_id" = "tenant_ldap_provider_test_runs"."started_by_membership_id"
          and "tenant_ldap_provider_test_runs"."completed_at" >= "tenant_ldap_provider_test_runs"."started_at"
          and "tenant_ldap_provider_test_runs"."version" = 2)) is true);