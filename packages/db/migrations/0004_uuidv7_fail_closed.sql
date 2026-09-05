ALTER TABLE "alerts" DROP CONSTRAINT "alerts_id_uuidv7_check";--> statement-breakpoint
ALTER TABLE "audit_chain_heads" DROP CONSTRAINT "audit_chain_heads_tenant_uuidv7_check";--> statement-breakpoint
ALTER TABLE "audit_events" DROP CONSTRAINT "audit_events_id_uuidv7_check";--> statement-breakpoint
ALTER TABLE "tenant_memberships" DROP CONSTRAINT "tenant_memberships_id_uuidv7_check";--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_id_uuidv7_check";--> statement-breakpoint
ALTER TABLE "outbox_events" DROP CONSTRAINT "outbox_events_id_uuidv7_check";--> statement-breakpoint
ALTER TABLE "tenants" DROP CONSTRAINT "tenants_id_uuidv7_check";--> statement-breakpoint
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_id_uuidv7_check" CHECK ((uuid_extract_version("alerts"."id") = 7) is true);--> statement-breakpoint
ALTER TABLE "audit_chain_heads" ADD CONSTRAINT "audit_chain_heads_tenant_uuidv7_check" CHECK ((uuid_extract_version("audit_chain_heads"."tenant_id") = 7) is true);--> statement-breakpoint
ALTER TABLE "audit_events" ADD CONSTRAINT "audit_events_id_uuidv7_check" CHECK ((uuid_extract_version("audit_events"."id") = 7) is true);--> statement-breakpoint
ALTER TABLE "tenant_memberships" ADD CONSTRAINT "tenant_memberships_id_uuidv7_check" CHECK ((uuid_extract_version("tenant_memberships"."id") = 7) is true);--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_id_uuidv7_check" CHECK ((uuid_extract_version("users"."id") = 7) is true);--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_id_uuidv7_check" CHECK ((uuid_extract_version("outbox_events"."id") = 7) is true);--> statement-breakpoint
ALTER TABLE "tenants" ADD CONSTRAINT "tenants_id_uuidv7_check" CHECK ((uuid_extract_version("tenants"."id") = 7) is true);--> statement-breakpoint
ALTER POLICY "outbox_events_notifier_access" ON "outbox_events" TO periapsis_notifier USING ("outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
        and "outbox_events"."event_type" like 'notification.%') WITH CHECK ("outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
        and "outbox_events"."event_type" like 'notification.%');