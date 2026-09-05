ALTER TABLE "alerts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "audit_chain_heads" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "audit_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenant_memberships" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "users" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "outbox_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "tenants" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "audit_events" ALTER COLUMN "sequence" DROP IDENTITY;--> statement-breakpoint
ALTER POLICY "audit_events_worker_access" ON "audit_events" TO periapsis_worker USING ("audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
ALTER POLICY "audit_events_notifier_access" ON "audit_events" TO periapsis_notifier USING ("audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
ALTER POLICY "audit_events_auditor_select" ON "audit_events" TO periapsis_auditor USING ("audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
ALTER POLICY "outbox_events_worker_access" ON "outbox_events" TO periapsis_worker USING ("outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);--> statement-breakpoint
ALTER POLICY "outbox_events_notifier_access" ON "outbox_events" TO periapsis_notifier USING ("outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid) WITH CHECK ("outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid);