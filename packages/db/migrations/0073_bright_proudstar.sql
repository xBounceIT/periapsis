ALTER TABLE "tenant_ldap_sync_runs" DROP CONSTRAINT "tenant_ldap_sync_runs_revision_check";--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" DROP CONSTRAINT "tenant_ldap_sync_runs_digest_check";--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "bind_secret_id" uuid NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "bind_secret_version" integer NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "bind_secret_key_version" integer NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "bind_secret_algorithm" text NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_bind_secret_key_version_identity_keyring_versions_key_version_fk" FOREIGN KEY ("bind_secret_key_version") REFERENCES "public"."identity_keyring_versions"("key_version") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_secret_id_fk" FOREIGN KEY ("tenant_id","bind_secret_id") REFERENCES "public"."tenant_ldap_provider_secrets"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_secret_provider_fk" FOREIGN KEY ("tenant_id","provider_id") REFERENCES "public"."tenant_ldap_provider_secrets"("tenant_id","provider_id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_revision_check" CHECK ("tenant_ldap_sync_runs"."provider_version" > 0
        and "tenant_ldap_sync_runs"."configuration_version" > 0
        and "tenant_ldap_sync_runs"."binding_version" > 0
        and "tenant_ldap_sync_runs"."binding_auth_revision" > 0
        and "tenant_ldap_sync_runs"."rule_set_revision" > 0
        and "tenant_ldap_sync_runs"."authorization_revision" > 0
        and "tenant_ldap_sync_runs"."authorization_progress_revision" >= "tenant_ldap_sync_runs"."authorization_revision"
        and "tenant_ldap_sync_runs"."bind_secret_version" > 0
        and "tenant_ldap_sync_runs"."bind_secret_key_version" > 0
        and "tenant_ldap_sync_runs"."version" between 1 and 5);--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD CONSTRAINT "tenant_ldap_sync_runs_digest_check" CHECK ((uuid_extract_version("tenant_ldap_sync_runs"."bind_secret_id") = 7) is true
        and "tenant_ldap_sync_runs"."bind_secret_algorithm" = 'aes-256-gcm'
        and octet_length("tenant_ldap_sync_runs"."endpoint_snapshot_digest") = 32
        and ("tenant_ldap_sync_runs"."cursor_digest" is null or octet_length("tenant_ldap_sync_runs"."cursor_digest") = 32));