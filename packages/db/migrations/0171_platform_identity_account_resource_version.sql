ALTER TABLE "platform_federated_external_identities" DROP CONSTRAINT "platform_federated_external_identities_lifecycle_check";--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "version" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ADD COLUMN "resource_version" bigint DEFAULT 1 NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_version_check" CHECK ("users"."version" between 1 and 2147483647);--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ADD CONSTRAINT "platform_federated_external_identities_lifecycle_check" CHECK ("platform_federated_external_identities"."admitted_configuration_revision" between 1 and 9007199254740991
        and "platform_federated_external_identities"."admitted_security_revision" between 1 and 9007199254740991
        and "platform_federated_external_identities"."version" between 1 and 2147483647
        and "platform_federated_external_identities"."resource_version" between 1 and 2147483647
        and "platform_federated_external_identities"."last_observed_at" >= "platform_federated_external_identities"."created_at"
        and "platform_federated_external_identities"."updated_at" >= "platform_federated_external_identities"."created_at"
        and ("platform_federated_external_identities"."retired_at" is null or (
          "platform_federated_external_identities"."retired_at" >= "platform_federated_external_identities"."created_at"
          and "platform_federated_external_identities"."updated_at" >= "platform_federated_external_identities"."retired_at")));