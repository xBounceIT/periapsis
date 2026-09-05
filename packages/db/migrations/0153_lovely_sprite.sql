ALTER POLICY "alerts_api_tenant" ON "alerts" TO periapsis_api USING (
  "alerts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("alerts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alerts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "alerts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("alerts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alerts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "audit_events_api_tenant" ON "audit_events" TO periapsis_api USING (
  "audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("audit_events"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "audit_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "audit_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("audit_events"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "audit_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "customer_contact_group_version_members_api_tenant" ON "customer_contact_group_version_members" TO periapsis_api USING (
  "customer_contact_group_version_members"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("customer_contact_group_version_members"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_group_version_members"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "customer_contact_group_versions_api_tenant" ON "customer_contact_group_versions" TO periapsis_api USING (
  "customer_contact_group_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("customer_contact_group_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_group_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "customer_contact_groups_api_tenant" ON "customer_contact_groups" TO periapsis_api USING (
  "customer_contact_groups"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("customer_contact_groups"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_groups"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "customer_contact_notification_windows_api_tenant" ON "customer_contact_notification_windows" TO periapsis_api USING (
  "customer_contact_notification_windows"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("customer_contact_notification_windows"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contact_notification_windows"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "customer_contacts_api_tenant" ON "customer_contacts" TO periapsis_api USING (
  "customer_contacts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("customer_contacts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "customer_contacts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "ticket_activity_author_snapshots_api_tenant" ON "ticket_activity_author_snapshots" TO periapsis_api USING (
  "ticket_activity_author_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("ticket_activity_author_snapshots"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_activity_author_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "ticket_comment_author_snapshots_api_tenant" ON "ticket_comment_author_snapshots" TO periapsis_api USING (
  "ticket_comment_author_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("ticket_comment_author_snapshots"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_comment_author_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "ticket_customer_contacts_api_tenant" ON "ticket_customer_contacts" TO periapsis_api USING (
  "ticket_customer_contacts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("ticket_customer_contacts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_customer_contacts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "custom_field_definition_revisions_api_tenant" ON "custom_field_definition_revisions" TO periapsis_api USING (
  "custom_field_definition_revisions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_definition_revisions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definition_revisions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_definition_revisions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_definition_revisions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definition_revisions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "custom_field_definitions_api_tenant" ON "custom_field_definitions" TO periapsis_api USING (
  "custom_field_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_definitions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_definitions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "custom_field_layouts_api_tenant" ON "custom_field_layouts" TO periapsis_api USING (
  "custom_field_layouts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_layouts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_layouts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_layouts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_layouts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_layouts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "custom_field_migrations_api_tenant" ON "custom_field_migrations" TO periapsis_api USING (
  "custom_field_migrations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_migrations"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_migrations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_migrations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_migrations"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_migrations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "custom_field_options_api_tenant" ON "custom_field_options" TO periapsis_api USING (
  "custom_field_options"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_options"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_options"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_options"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_options"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_options"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "custom_field_permissions_api_tenant" ON "custom_field_permissions" TO periapsis_api USING (
  "custom_field_permissions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_permissions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_permissions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_permissions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_permissions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_permissions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "custom_field_values_api_tenant" ON "custom_field_values" TO periapsis_api USING (
  "custom_field_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_values"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "custom_field_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("custom_field_values"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "custom_field_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_activities_api_tenant" ON "dfir_activities" TO periapsis_api USING (
  "dfir_activities"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_activities"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_activities"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_asset_links_api_tenant" ON "dfir_asset_links" TO periapsis_api USING (
  "dfir_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_asset_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_asset_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_assets_api_tenant" ON "dfir_assets" TO periapsis_api USING (
  "dfir_assets"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_assets"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_assets"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_assets"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_assets"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_assets"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_attachments_api_tenant" ON "dfir_attachments" TO periapsis_api USING (
  "dfir_attachments"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_attachments"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_attachments"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_attachments"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_attachments"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_attachments"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_custody_events_api_tenant" ON "dfir_custody_events" TO periapsis_api USING (
  "dfir_custody_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_custody_events"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_custody_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_evidence_api_tenant" ON "dfir_evidence" TO periapsis_api USING (
  "dfir_evidence"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_evidence"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_evidence"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_evidence"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_evidence"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_evidence"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_ioc_links_api_tenant" ON "dfir_ioc_links" TO periapsis_api USING (
  "dfir_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_ioc_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_ioc_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_iocs_api_tenant" ON "dfir_iocs" TO periapsis_api USING (
  "dfir_iocs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_iocs"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_iocs"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_iocs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_iocs"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_iocs"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_relationships_api_tenant" ON "dfir_relationships" TO periapsis_api USING (
  "dfir_relationships"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_relationships"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_relationships"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_relationships"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_relationships"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_relationships"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_storage_objects_api_tenant" ON "dfir_storage_objects" TO periapsis_api USING (
  "dfir_storage_objects"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_storage_objects"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_storage_objects"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_storage_objects"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_storage_objects"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_storage_objects"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_tasks_api_tenant" ON "dfir_tasks" TO periapsis_api USING (
  "dfir_tasks"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_tasks"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_tasks"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_tasks"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_tasks"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_tasks"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_timeline_asset_links_api_tenant" ON "dfir_timeline_asset_links" TO periapsis_api USING (
  "dfir_timeline_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_asset_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_asset_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_asset_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_asset_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_timeline_events_api_tenant" ON "dfir_timeline_events" TO periapsis_api USING (
  "dfir_timeline_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_events"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_events"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_timeline_evidence_links_api_tenant" ON "dfir_timeline_evidence_links" TO periapsis_api USING (
  "dfir_timeline_evidence_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_evidence_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_evidence_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_evidence_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_evidence_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_evidence_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "dfir_timeline_ioc_links_api_tenant" ON "dfir_timeline_ioc_links" TO periapsis_api USING (
  "dfir_timeline_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_ioc_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "dfir_timeline_ioc_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_timeline_ioc_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_timeline_ioc_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "users_api_tenant_select" ON "users" TO periapsis_api USING (app.tenant_is_active_v1(nullif(current_setting('app.tenant_id', true), '')::uuid)
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."user_id" = "users"."id"
      and "tenant_memberships"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  ));--> statement-breakpoint
ALTER POLICY "tenant_notification_commands_api_tenant" ON "tenant_notification_commands" TO periapsis_api USING (
  "tenant_notification_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_commands"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_commands"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_deliveries_api_tenant" ON "tenant_notification_deliveries" TO periapsis_api USING (
  "tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_deliveries"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_deliveries"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_deliveries"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_deliveries"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_deliveries_notifier_tenant" ON "tenant_notification_deliveries" TO periapsis_notifier USING ("tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("tenant_notification_deliveries"."tenant_id")) WITH CHECK ("tenant_notification_deliveries"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("tenant_notification_deliveries"."tenant_id"));--> statement-breakpoint
ALTER POLICY "tenant_notification_delivery_attempts_api_tenant" ON "tenant_notification_delivery_attempts" TO periapsis_api USING (
  "tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_delivery_attempts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_delivery_attempts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_delivery_attempts"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_delivery_attempts"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_delivery_attempts_notifier_tenant" ON "tenant_notification_delivery_attempts" TO periapsis_notifier USING ("tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("tenant_notification_delivery_attempts"."tenant_id")) WITH CHECK ("tenant_notification_delivery_attempts"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("tenant_notification_delivery_attempts"."tenant_id"));--> statement-breakpoint
ALTER POLICY "tenant_notification_fanout_snapshots_api_tenant" ON "tenant_notification_fanout_snapshots" TO periapsis_api USING (
  "tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_fanout_snapshots"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_fanout_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_fanout_snapshots"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_fanout_snapshots"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_fanout_snapshots_notifier_tenant" ON "tenant_notification_fanout_snapshots" TO periapsis_notifier USING ("tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("tenant_notification_fanout_snapshots"."tenant_id")) WITH CHECK ("tenant_notification_fanout_snapshots"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("tenant_notification_fanout_snapshots"."tenant_id"));--> statement-breakpoint
ALTER POLICY "tenant_notification_rule_versions_api_tenant" ON "tenant_notification_rule_versions" TO periapsis_api USING (
  "tenant_notification_rule_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_rule_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rule_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_rule_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_rule_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rule_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_rules_api_tenant" ON "tenant_notification_rules" TO periapsis_api USING (
  "tenant_notification_rules"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_rules"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rules"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_rules"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_rules"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_rules"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_secret_versions_api_tenant" ON "tenant_notification_secret_versions" TO periapsis_api USING (
  "tenant_notification_secret_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_secret_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_secret_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_secret_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_secret_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_secret_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_smtp_configuration_versions_api_tenant" ON "tenant_notification_smtp_configuration_versions" TO periapsis_api USING (
  "tenant_notification_smtp_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_smtp_configuration_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_smtp_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_smtp_configuration_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_smtp_configurations_api_tenant" ON "tenant_notification_smtp_configurations" TO periapsis_api USING (
  "tenant_notification_smtp_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_smtp_configurations"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_smtp_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_smtp_configurations"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_smtp_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_template_versions_api_tenant" ON "tenant_notification_template_versions" TO periapsis_api USING (
  "tenant_notification_template_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_template_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_template_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_template_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_template_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_template_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_templates_api_tenant" ON "tenant_notification_templates" TO periapsis_api USING (
  "tenant_notification_templates"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_templates"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_templates"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_templates"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_templates"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_templates"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_webhook_versions_api_tenant" ON "tenant_notification_webhook_configuration_versions" TO periapsis_api USING (
  "tenant_notification_webhook_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_webhook_configuration_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_webhook_configuration_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_webhook_configuration_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configuration_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "tenant_notification_webhooks_api_tenant" ON "tenant_notification_webhook_configurations" TO periapsis_api USING (
  "tenant_notification_webhook_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_webhook_configurations"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "tenant_notification_webhook_configurations"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenant_notification_webhook_configurations"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenant_notification_webhook_configurations"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "outbox_events_api_tenant" ON "outbox_events" TO periapsis_api USING (
  "outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("outbox_events"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "outbox_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "outbox_events"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("outbox_events"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "outbox_events"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_business_calendar_versions_api_tenant" ON "sla_business_calendar_versions" TO periapsis_api USING (
  "sla_business_calendar_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_business_calendar_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendar_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_business_calendar_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_business_calendar_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendar_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_business_calendars_api_tenant" ON "sla_business_calendars" TO periapsis_api USING (
  "sla_business_calendars"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_business_calendars"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendars"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_business_calendars"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_business_calendars"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_business_calendars"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_column_versions_api_tenant" ON "sla_column_versions" TO periapsis_api USING (
  "sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_column_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_column_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_column_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_column_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_column_versions_worker_tenant" ON "sla_column_versions" TO periapsis_worker USING ("sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_column_versions"."tenant_id")) WITH CHECK ("sla_column_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_column_versions"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_columns_api_tenant" ON "sla_columns" TO periapsis_api USING (
  "sla_columns"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_columns"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_columns"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_columns"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_columns"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_columns"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_configuration_commands_api_tenant" ON "sla_configuration_commands" TO periapsis_api USING (
  "sla_configuration_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_configuration_commands"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_configuration_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_configuration_commands"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_configuration_commands"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_configuration_commands"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_evaluation_jobs_worker_tenant" ON "sla_evaluation_jobs" TO periapsis_worker USING ("sla_evaluation_jobs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_evaluation_jobs"."tenant_id")) WITH CHECK ("sla_evaluation_jobs"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_evaluation_jobs"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_instances_api_tenant" ON "sla_instances" TO periapsis_api USING (
  "sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_instances"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_instances"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_instances_worker_tenant" ON "sla_instances" TO periapsis_worker USING ("sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_instances"."tenant_id")) WITH CHECK ("sla_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_instances"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_materialized_columns_api_tenant" ON "sla_materialized_column_values" TO periapsis_api USING (
  "sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_materialized_column_values"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_materialized_column_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_materialized_column_values"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_materialized_column_values"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_materialized_columns_worker_tenant" ON "sla_materialized_column_values" TO periapsis_worker USING ("sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_materialized_column_values"."tenant_id")) WITH CHECK ("sla_materialized_column_values"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_materialized_column_values"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_metric_definitions_api_tenant" ON "sla_metric_definitions" TO periapsis_api USING (
  "sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_metric_definitions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_metric_definitions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_metric_definitions_worker_tenant" ON "sla_metric_definitions" TO periapsis_worker USING ("sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_metric_definitions"."tenant_id")) WITH CHECK ("sla_metric_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_metric_definitions"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_metric_instances_api_tenant" ON "sla_metric_instances" TO periapsis_api USING (
  "sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_metric_instances"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_metric_instances"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_metric_instances"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_metric_instances_worker_tenant" ON "sla_metric_instances" TO periapsis_worker USING ("sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_metric_instances"."tenant_id")) WITH CHECK ("sla_metric_instances"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_metric_instances"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_object_event_ledger_api_tenant" ON "sla_object_event_ledger" TO periapsis_api USING (
  "sla_object_event_ledger"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_object_event_ledger"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_object_event_ledger"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_object_event_ledger"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_object_event_ledger"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_object_event_ledger"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_overrides_api_tenant" ON "sla_overrides" TO periapsis_api USING (
  "sla_overrides"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_overrides"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_overrides"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_overrides"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_overrides"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_overrides"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_policies_api_tenant" ON "sla_policies" TO periapsis_api USING (
  "sla_policies"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_policies"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policies"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_policies"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_policies"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policies"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_policy_versions_api_tenant" ON "sla_policy_versions" TO periapsis_api USING (
  "sla_policy_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_policy_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policy_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_policy_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_policy_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_policy_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_trigger_cursors_api_tenant" ON "sla_trigger_cursors" TO periapsis_api USING (
  "sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_trigger_cursors"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_cursors"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_trigger_cursors"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_cursors"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_trigger_cursors_worker_tenant" ON "sla_trigger_cursors" TO periapsis_worker USING ("sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_cursors"."tenant_id")) WITH CHECK ("sla_trigger_cursors"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_cursors"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_trigger_definitions_api_tenant" ON "sla_trigger_definitions" TO periapsis_api USING (
  "sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_trigger_definitions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_trigger_definitions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_definitions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_trigger_definitions_worker_tenant" ON "sla_trigger_definitions" TO periapsis_worker USING ("sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_definitions"."tenant_id")) WITH CHECK ("sla_trigger_definitions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_definitions"."tenant_id"));--> statement-breakpoint
ALTER POLICY "sla_trigger_occurrences_api_tenant" ON "sla_trigger_occurrences" TO periapsis_api USING (
  "sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_trigger_occurrences"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_occurrences"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
) WITH CHECK (
  "sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("sla_trigger_occurrences"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "sla_trigger_occurrences"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "sla_trigger_occurrences_worker_tenant" ON "sla_trigger_occurrences" TO periapsis_worker USING ("sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_occurrences"."tenant_id")) WITH CHECK ("sla_trigger_occurrences"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
      and app.tenant_is_active_v1("sla_trigger_occurrences"."tenant_id"));--> statement-breakpoint
ALTER POLICY "tenants_api_select_current" ON "tenants" TO periapsis_api USING (
  "tenants"."id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("tenants"."id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "tenants"."id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "ticket_workflow_versions_api_tenant" ON "ticket_workflow_versions" TO periapsis_api USING (
  "ticket_workflow_versions"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("ticket_workflow_versions"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_workflow_versions"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "ticket_workflows_api_tenant" ON "ticket_workflows" TO periapsis_api USING (
  "ticket_workflows"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("ticket_workflows"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_workflows"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "alert_case_links_api_tenant" ON "alert_case_links" TO periapsis_api USING (
  "alert_case_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("alert_case_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "alert_case_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "cases_api_tenant" ON "cases" TO periapsis_api USING (
  "cases"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("cases"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "cases"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "ticket_activities_api_tenant" ON "ticket_activities" TO periapsis_api USING (
  "ticket_activities"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("ticket_activities"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_activities"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);--> statement-breakpoint
ALTER POLICY "ticket_comments_api_tenant" ON "ticket_comments" TO periapsis_api USING (
  "ticket_comments"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("ticket_comments"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "ticket_comments"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);