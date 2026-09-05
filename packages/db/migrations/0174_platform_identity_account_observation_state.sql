ALTER TABLE "platform_federated_external_identities" ADD COLUMN "last_observation_state" text DEFAULT 'known' NOT NULL;--> statement-breakpoint
ALTER TABLE "platform_federated_external_identities" ADD CONSTRAINT "platform_federated_external_identities_observation_state_check" CHECK ("platform_federated_external_identities"."last_observation_state" in ('known', 'legacy_unknown')
        and ("platform_federated_external_identities"."last_observation_state" = 'known' or (
          "platform_federated_external_identities"."retired_at" is not null
          and "platform_federated_external_identities"."resource_version" = 1
          and "platform_federated_external_identities"."last_observed_at" = "platform_federated_external_identities"."retired_at")));