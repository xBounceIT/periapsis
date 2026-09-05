ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "claim_id" uuid;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "claim_receipt_digest" "bytea";--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "claim_fence" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "claim_acquired_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_runs" ADD COLUMN "claim_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" ADD COLUMN "planning_fence" bigint;--> statement-breakpoint
ALTER TABLE "tenant_ldap_sync_staged_observations" ADD COLUMN "planning_claimed_at" timestamp with time zone;--> statement-breakpoint
CREATE UNIQUE INDEX "tenant_ldap_sync_runs_claim_id_key" ON "tenant_ldap_sync_runs" USING btree ("claim_id") WHERE "tenant_ldap_sync_runs"."claim_id" is not null;