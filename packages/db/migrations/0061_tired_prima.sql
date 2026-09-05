ALTER TABLE "tenant_auth_provider_bindings" ALTER COLUMN "mapping_revision" SET DATA TYPE bigint;--> statement-breakpoint
ALTER TABLE "tenant_auth_provider_bindings" ALTER COLUMN "mapping_revision" SET DEFAULT 1;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ALTER COLUMN "rule_set_revision" SET DATA TYPE bigint;--> statement-breakpoint
ALTER TABLE "tenant_ldap_directory_operation_runs" ALTER COLUMN "authorization_revision" SET DATA TYPE bigint;