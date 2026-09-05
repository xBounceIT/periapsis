CREATE ROLE "periapsis_ticket_attribution_owner" WITH NOINHERIT;--> statement-breakpoint
CREATE ROLE "periapsis_ticket_sla_projection_owner" WITH NOINHERIT;--> statement-breakpoint
CREATE INDEX "alerts_tenant_updated_idx" ON "alerts" USING btree ("tenant_id","updated_at","id");--> statement-breakpoint
CREATE INDEX "sla_materialized_projection_instant_sort_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","column_id","instant_value","object_id") WHERE "sla_materialized_column_values"."instant_value" is not null;--> statement-breakpoint
CREATE INDEX "sla_materialized_projection_duration_sort_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","column_id","duration_micros_value","object_id") WHERE "sla_materialized_column_values"."duration_micros_value" is not null;--> statement-breakpoint
CREATE INDEX "sla_materialized_projection_percent_sort_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","column_id","percentage_value","object_id") WHERE "sla_materialized_column_values"."percentage_value" is not null;--> statement-breakpoint
CREATE INDEX "sla_materialized_projection_state_sort_idx" ON "sla_materialized_column_values" USING btree ("tenant_id","column_id","state_value","object_id") WHERE "sla_materialized_column_values"."state_value" is not null;--> statement-breakpoint
CREATE POLICY "tenant_service_accounts_ticket_attribution" ON "tenant_service_accounts" AS PERMISSIVE FOR SELECT TO "periapsis_ticket_attribution_owner" USING ("tenant_service_accounts"."tenant_id" = app.context_tenant_id()
        and app.current_tenant_membership_id() is not null);--> statement-breakpoint
CREATE POLICY "sla_column_versions_ticket_projection" ON "sla_column_versions" AS PERMISSIVE FOR SELECT TO "periapsis_ticket_sla_projection_owner" USING ("sla_column_versions"."tenant_id" = app.context_tenant_id()
      and app.current_tenant_membership_id() is not null);--> statement-breakpoint
CREATE POLICY "sla_materialized_columns_ticket_projection" ON "sla_materialized_column_values" AS PERMISSIVE FOR SELECT TO "periapsis_ticket_sla_projection_owner" USING ("sla_materialized_column_values"."tenant_id" = app.context_tenant_id()
      and app.current_tenant_membership_id() is not null);