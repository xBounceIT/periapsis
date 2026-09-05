ALTER TABLE "tenant_ldap_sync_runs" DROP CONSTRAINT "tenant_ldap_sync_runs_revision_check";--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "authorization_progress_revision" bigint NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_revision_check" CHECK ("tenant_ldap_sync_runs"."provider_version" > 0
        and "tenant_ldap_sync_runs"."configuration_version" > 0
        and "tenant_ldap_sync_runs"."binding_version" > 0
        and "tenant_ldap_sync_runs"."binding_auth_revision" > 0
        and "tenant_ldap_sync_runs"."rule_set_revision" > 0
        and "tenant_ldap_sync_runs"."authorization_revision" > 0
        and "tenant_ldap_sync_runs"."authorization_progress_revision" >= "tenant_ldap_sync_runs"."authorization_revision"
        and "tenant_ldap_sync_runs"."version" between 1 and 5);