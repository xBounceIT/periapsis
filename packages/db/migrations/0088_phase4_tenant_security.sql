-- Phase 4 custom-field and DFIR tenant security boundary. The generated
-- foundation in 0087 deliberately contains no runtime privileges; this
-- migration makes ownership, FORCE RLS, permission seeding, and invariants
-- explicit before any application adapter can use the tables.

ALTER TYPE public.custom_field_audience OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.custom_field_data_type OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.custom_field_migration_kind OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.custom_field_migration_status OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.custom_field_object_type OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.custom_field_value_presence OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_asset_criticality OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_custody_action OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_entity_kind OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_evidence_classification OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_indicator_type OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_malicious_state OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_scan_state OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_task_priority OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_task_status OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_temporal_precision OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_tlp OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.dfir_visibility OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.custom_field_definition_revisions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.custom_field_definitions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.custom_field_layouts OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.custom_field_migrations OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.custom_field_options OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.custom_field_permissions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.custom_field_values OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_activities OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_asset_links OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_assets OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_attachments OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_custody_events OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_evidence OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_ioc_links OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_iocs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_relationships OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_storage_objects OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_tasks OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_asset_links OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_events OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_evidence_links OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_ioc_links OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.custom_field_definition_revisions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.custom_field_definitions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.custom_field_layouts FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.custom_field_migrations FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.custom_field_options FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.custom_field_permissions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.custom_field_values FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_activities FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_asset_links FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_assets FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_attachments FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_custody_events FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_evidence FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_ioc_links FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_iocs FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_relationships FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_storage_objects FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_tasks FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_asset_links FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_events FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_evidence_links FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.dfir_timeline_ioc_links FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE
  public.custom_field_definition_revisions,
  public.custom_field_definitions,
  public.custom_field_layouts,
  public.custom_field_migrations,
  public.custom_field_options,
  public.custom_field_permissions,
  public.custom_field_values,
  public.dfir_activities,
  public.dfir_asset_links,
  public.dfir_assets,
  public.dfir_attachments,
  public.dfir_custody_events,
  public.dfir_evidence,
  public.dfir_ioc_links,
  public.dfir_iocs,
  public.dfir_relationships,
  public.dfir_storage_objects,
  public.dfir_tasks,
  public.dfir_timeline_asset_links,
  public.dfir_timeline_events,
  public.dfir_timeline_evidence_links,
  public.dfir_timeline_ioc_links
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT SELECT ON TABLE
  public.custom_field_definition_revisions,
  public.custom_field_definitions,
  public.custom_field_layouts,
  public.custom_field_migrations,
  public.custom_field_options,
  public.custom_field_permissions,
  public.custom_field_values,
  public.dfir_activities,
  public.dfir_asset_links,
  public.dfir_assets,
  public.dfir_attachments,
  public.dfir_custody_events,
  public.dfir_evidence,
  public.dfir_ioc_links,
  public.dfir_iocs,
  public.dfir_relationships,
  public.dfir_storage_objects,
  public.dfir_tasks,
  public.dfir_timeline_asset_links,
  public.dfir_timeline_events,
  public.dfir_timeline_evidence_links,
  public.dfir_timeline_ioc_links
TO periapsis_api;--> statement-breakpoint

GRANT INSERT, UPDATE ON TABLE
  public.custom_field_definitions,
  public.custom_field_layouts,
  public.custom_field_migrations,
  public.custom_field_options,
  public.custom_field_values,
  public.dfir_assets,
  public.dfir_attachments,
  public.dfir_iocs,
  public.dfir_tasks,
  public.dfir_timeline_events
TO periapsis_api;--> statement-breakpoint

GRANT INSERT ON TABLE
  public.custom_field_definition_revisions,
  public.dfir_storage_objects
TO periapsis_api;--> statement-breakpoint

GRANT INSERT, UPDATE, DELETE ON TABLE public.custom_field_permissions TO periapsis_api;--> statement-breakpoint
GRANT INSERT, DELETE ON TABLE
  public.dfir_asset_links,
  public.dfir_ioc_links,
  public.dfir_relationships,
  public.dfir_timeline_asset_links,
  public.dfir_timeline_evidence_links,
  public.dfir_timeline_ioc_links
TO periapsis_api;--> statement-breakpoint

GRANT SELECT ON TABLE
  public.dfir_activities,
  public.dfir_custody_events,
  public.dfir_evidence,
  public.dfir_storage_objects
TO periapsis_worker;--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
)
VALUES
  (uuidv7(), 'custom_field.read', 'Read custom fields', 'Read authorized tenant custom-field definitions and values.', false),
  (uuidv7(), 'custom_field.manage', 'Manage custom fields', 'Define, migrate, lay out, and write tenant custom fields.', false),
  (uuidv7(), 'dfir.ioc.read', 'Read DFIR indicators', 'Read authorized indicators of compromise.', false),
  (uuidv7(), 'dfir.ioc.manage', 'Manage DFIR indicators', 'Create, update, archive, and link indicators of compromise.', false),
  (uuidv7(), 'dfir.asset.read', 'Read DFIR assets', 'Read authorized DFIR asset inventory.', false),
  (uuidv7(), 'dfir.asset.manage', 'Manage DFIR assets', 'Create, update, archive, and link DFIR assets.', false),
  (uuidv7(), 'dfir.evidence.read', 'Read DFIR evidence', 'Read authorized evidence metadata and custody records.', false),
  (uuidv7(), 'dfir.evidence.manage', 'Manage DFIR evidence', 'Collect evidence and append custody transitions.', false),
  (uuidv7(), 'dfir.timeline.read', 'Read DFIR timeline', 'Read authorized timeline events.', false),
  (uuidv7(), 'dfir.timeline.manage', 'Manage DFIR timeline', 'Create, update, and relate timeline events.', false),
  (uuidv7(), 'dfir.task.read', 'Read DFIR tasks', 'Read authorized investigation tasks.', false),
  (uuidv7(), 'dfir.task.manage', 'Manage DFIR tasks', 'Create, assign, update, and complete investigation tasks.', false),
  (uuidv7(), 'dfir.attachment.read', 'Read DFIR attachments', 'Read authorized clean attachment metadata.', false),
  (uuidv7(), 'dfir.attachment.manage', 'Manage DFIR attachments', 'Create and classify DFIR attachments.', false),
  (uuidv7(), 'dfir.relationship.read', 'Read DFIR relationships', 'Read authorized typed investigation relationships.', false),
  (uuidv7(), 'dfir.relationship.manage', 'Manage DFIR relationships', 'Create and remove typed investigation relationships.', false)
ON CONFLICT (key) DO NOTHING;--> statement-breakpoint

INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, scope.value
FROM public.tenant_permissions AS permission
CROSS JOIN LATERAL unnest(
  CASE
    WHEN permission.key IN ('custom_field.read', 'custom_field.manage')
      THEN ARRAY['tenant'::public.authorization_scope]
    ELSE ARRAY[
      'assigned'::public.authorization_scope,
      'operator_team'::public.authorization_scope,
      'tenant'::public.authorization_scope
    ]
  END
) AS scope(value)
WHERE permission.key IN (
  'custom_field.read', 'custom_field.manage',
  'dfir.ioc.read', 'dfir.ioc.manage',
  'dfir.asset.read', 'dfir.asset.manage',
  'dfir.evidence.read', 'dfir.evidence.manage',
  'dfir.timeline.read', 'dfir.timeline.manage',
  'dfir.task.read', 'dfir.task.manage',
  'dfir.attachment.read', 'dfir.attachment.manage',
  'dfir.relationship.read', 'dfir.relationship.manage'
)
ON CONFLICT DO NOTHING;--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_phase4_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  administrator_role public.tenant_roles%ROWTYPE;
  inserted_policies integer;
  inserted_ceilings integer;
BEGIN
  PERFORM state.revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant authorization state is required for phase 4 seeding'
      USING ERRCODE = '55000';
  END IF;

  SELECT role.* INTO STRICT administrator_role
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role
    AND role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  INSERT INTO public.tenant_role_permissions (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission.id, scope.scope, NULL
  FROM public.tenant_permissions AS permission
  JOIN public.tenant_permission_scopes AS scope
    ON scope.permission_id = permission.id
  WHERE permission.key IN (
    'custom_field.read', 'custom_field.manage',
    'dfir.ioc.read', 'dfir.ioc.manage',
    'dfir.asset.read', 'dfir.asset.manage',
    'dfir.evidence.read', 'dfir.evidence.manage',
    'dfir.timeline.read', 'dfir.timeline.manage',
    'dfir.task.read', 'dfir.task.manage',
    'dfir.attachment.read', 'dfir.attachment.manage',
    'dfir.relationship.read', 'dfir.relationship.manage'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_policies = ROW_COUNT;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, administrator_role.id, permission.id, scope.scope, NULL
  FROM public.tenant_permissions AS permission
  JOIN public.tenant_permission_scopes AS scope
    ON scope.permission_id = permission.id
  WHERE permission.key IN (
    'custom_field.read', 'custom_field.manage',
    'dfir.ioc.read', 'dfir.ioc.manage',
    'dfir.asset.read', 'dfir.asset.manage',
    'dfir.evidence.read', 'dfir.evidence.manage',
    'dfir.timeline.read', 'dfir.timeline.manage',
    'dfir.task.read', 'dfir.task.manage',
    'dfir.attachment.read', 'dfir.attachment.manage',
    'dfir.relationship.read', 'dfir.relationship.manage'
  )
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_ceilings = ROW_COUNT;

  IF inserted_policies > 0 OR inserted_ceilings > 0 THEN
    IF administrator_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant administrator version is exhausted during phase 4 seeding'
        USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_roles AS role
    SET version = administrator_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE role.tenant_id = p_tenant_id
      AND role.id = administrator_role.id;

    INSERT INTO public.audit_events (
      id, tenant_id, sequence, actor_type, action, resource_type,
      resource_id, authentication_method, outcome, after, metadata
    ) VALUES (
      uuidv7(), p_tenant_id, 0, 'system',
      'tenant.authorization.phase4_enabled', 'tenant_role',
      administrator_role.id, 'database_migration', 'success',
      jsonb_build_object(
        'permission_family', 'custom_field_dfir',
        'prior_version', administrator_role.version,
        'result_version', administrator_role.version + 1
      ),
      jsonb_build_object('migration', '0088_phase4_tenant_security')
    );
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_seed_tenant_phase4_authorization_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_phase4_authorization_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

DO $phase4_permission_seed$
DECLARE
  tenant_record record;
BEGIN
  FOR tenant_record IN SELECT tenant.id FROM public.tenants AS tenant ORDER BY tenant.id LOOP
    PERFORM app.private_seed_tenant_phase4_authorization_v1(tenant_record.id);
  END LOOP;
END;
$phase4_permission_seed$;--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  RENAME TO seed_tenant_authorization_phase4_compatibility_impl;--> statement-breakpoint
DROP FUNCTION IF EXISTS app.seed_tenant_authorization(uuid, uuid);--> statement-breakpoint
ALTER FUNCTION app.seed_tenant_authorization_phase4_compatibility_impl(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization_phase4_compatibility_impl(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.seed_tenant_authorization(
  p_tenant_id uuid,
  p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_phase4_compatibility_impl(
    p_tenant_id, p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_phase4_authorization_v1(p_tenant_id);
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.guard_phase4_append_only_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'append-only phase 4 record cannot be changed'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_phase4_append_only_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_phase4_append_only_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE TRIGGER custom_field_definition_revisions_immutable_v1
BEFORE UPDATE OR DELETE ON public.custom_field_definition_revisions
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();--> statement-breakpoint
CREATE TRIGGER dfir_custody_events_immutable_v1
BEFORE UPDATE OR DELETE ON public.dfir_custody_events
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();--> statement-breakpoint
CREATE TRIGGER dfir_activities_immutable_v1
BEFORE UPDATE OR DELETE ON public.dfir_activities
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_custom_field_option_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'custom field options must be archived, not deleted'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.definition_id IS DISTINCT FROM OLD.definition_id
     OR NEW.key IS DISTINCT FROM OLD.key
     OR NEW.introduced_in_schema_version IS DISTINCT FROM OLD.introduced_in_schema_version
     OR OLD.archived_at IS NOT NULL AND (
       NEW.archived_at IS DISTINCT FROM OLD.archived_at
       OR NEW.archived_in_schema_version IS DISTINCT FROM OLD.archived_in_schema_version
     ) THEN
    RAISE EXCEPTION 'custom field option identity is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_custom_field_option_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_custom_field_option_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER custom_field_options_identity_v1
BEFORE UPDATE OR DELETE ON public.custom_field_options
FOR EACH ROW EXECUTE FUNCTION app.guard_custom_field_option_identity_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_custom_field_definition_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'custom field definitions must be archived, not deleted'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.object_type IS DISTINCT FROM OLD.object_type
     OR NEW.key IS DISTINCT FROM OLD.key
     OR NEW.created_by_membership_id IS DISTINCT FROM OLD.created_by_membership_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR OLD.archived_at IS NOT NULL AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'custom field definition identity is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW IS DISTINCT FROM OLD
     AND NEW.schema_version IS DISTINCT FROM OLD.schema_version + 1 THEN
    RAISE EXCEPTION 'custom field definition update must advance one schema revision'
      USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_custom_field_definition_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_custom_field_definition_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER custom_field_definitions_identity_v1
BEFORE UPDATE OR DELETE ON public.custom_field_definitions
FOR EACH ROW EXECUTE FUNCTION app.guard_custom_field_definition_identity_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_custom_field_migration_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.definition_id IS DISTINCT FROM OLD.definition_id
     OR NEW.kind IS DISTINCT FROM OLD.kind
     OR NEW.from_data_type IS DISTINCT FROM OLD.from_data_type
     OR NEW.to_data_type IS DISTINCT FROM OLD.to_data_type
     OR NEW.from_schema_version IS DISTINCT FROM OLD.from_schema_version
     OR NEW.to_schema_version IS DISTINCT FROM OLD.to_schema_version
     OR NEW.plan_digest IS DISTINCT FROM OLD.plan_digest
     OR NEW.reason IS DISTINCT FROM OLD.reason
     OR NEW.created_by_membership_id IS DISTINCT FROM OLD.created_by_membership_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'custom field migration plan identity is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF OLD.status IN ('completed', 'failed', 'cancelled')
     AND NEW IS DISTINCT FROM OLD THEN
    RAISE EXCEPTION 'terminal custom field migration is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF (OLD.status = 'planned' AND NEW.status NOT IN ('planned', 'running', 'cancelled'))
     OR (OLD.status = 'running' AND NEW.status NOT IN ('running', 'completed', 'failed')) THEN
    RAISE EXCEPTION 'custom field migration status transition is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_custom_field_migration_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_custom_field_migration_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER custom_field_migrations_identity_v1
BEFORE UPDATE OR DELETE ON public.custom_field_migrations
FOR EACH ROW EXECUTE FUNCTION app.guard_custom_field_migration_identity_v1();--> statement-breakpoint

CREATE FUNCTION app.validate_custom_field_value_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  definition_record public.custom_field_definitions%ROWTYPE;
  revision_snapshot jsonb;
  typed_count integer;
  missing_option boolean;
BEGIN
  SELECT definition.* INTO definition_record
  FROM public.custom_field_definitions AS definition
  WHERE definition.tenant_id = NEW.tenant_id
    AND definition.id = NEW.definition_id;
  IF NOT FOUND
     OR definition_record.archived_at IS NOT NULL
     OR definition_record.object_type IS DISTINCT FROM NEW.object_type
     OR definition_record.data_type IS DISTINCT FROM NEW.data_type
     OR definition_record.schema_version IS DISTINCT FROM NEW.definition_schema_version THEN
    RAISE EXCEPTION 'custom field definition revision is not writable'
      USING ERRCODE = '55000';
  END IF;

  SELECT revision.snapshot INTO revision_snapshot
  FROM public.custom_field_definition_revisions AS revision
  WHERE revision.tenant_id = NEW.tenant_id
    AND revision.definition_id = NEW.definition_id
    AND revision.schema_version = NEW.definition_schema_version
    AND revision.object_type = NEW.object_type;
  IF NOT FOUND
     OR revision_snapshot ->> 'dataType' IS DISTINCT FROM NEW.data_type::text THEN
    RAISE EXCEPTION 'custom field revision snapshot is invalid'
      USING ERRCODE = '55000';
  END IF;

  IF NEW.presence = 'null' THEN
    IF coalesce((revision_snapshot ->> 'nullable')::boolean, false) IS NOT TRUE THEN
      RAISE EXCEPTION 'custom field does not admit null'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  typed_count := num_nonnulls(
    NEW.text_value, NEW.integer_value, NEW.decimal_value, NEW.boolean_value,
    NEW.date_value, NEW.date_time_value, NEW.ip_value, NEW.cidr_value,
    NEW.reference_id, NEW.option_keys, NEW.structured_value
  );
  IF typed_count <> 1 THEN
    RAISE EXCEPTION 'custom field typed projection is ambiguous'
      USING ERRCODE = '23514';
  END IF;

  IF (CASE
    WHEN NEW.data_type IN ('short_text', 'long_text', 'url', 'email')
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.text_value)
    WHEN NEW.data_type IN ('integer', 'duration')
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.integer_value)
    WHEN NEW.data_type = 'decimal'
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.decimal_value)
    WHEN NEW.data_type = 'boolean'
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.boolean_value)
    WHEN NEW.data_type = 'date'
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.date_value)
    WHEN NEW.data_type = 'datetime'
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.date_time_value)
    WHEN NEW.data_type = 'ip'
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.ip_value::text)
    WHEN NEW.data_type = 'cidr'
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.cidr_value::text)
    WHEN NEW.data_type IN ('user', 'operator_team', 'customer_contact', 'asset_reference', 'ioc_reference')
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.reference_id::text)
    WHEN NEW.data_type IN ('single_select', 'multi_select')
      THEN NEW.canonical_value IS DISTINCT FROM to_jsonb(NEW.option_keys)
    WHEN NEW.data_type = 'structured_json'
      THEN NEW.canonical_value IS DISTINCT FROM NEW.structured_value
    ELSE true
  END) THEN
    RAISE EXCEPTION 'custom field canonical and typed projections differ'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.data_type IN ('single_select', 'multi_select') THEN
    SELECT EXISTS (
      SELECT 1
      FROM unnest(NEW.option_keys) AS requested(key)
      LEFT JOIN public.custom_field_options AS option
        ON option.tenant_id = NEW.tenant_id
       AND option.definition_id = NEW.definition_id
       AND option.key = requested.key
       AND option.introduced_in_schema_version <= NEW.definition_schema_version
       AND (
         option.archived_in_schema_version IS NULL
         OR option.archived_in_schema_version > NEW.definition_schema_version
       )
      WHERE option.id IS NULL
    ) OR cardinality(NEW.option_keys) <> (
      SELECT count(DISTINCT requested.key)::integer
      FROM unnest(NEW.option_keys) AS requested(key)
    ) INTO missing_option;
    IF missing_option THEN
      RAISE EXCEPTION 'custom field option selection is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSIF NEW.data_type = 'user' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_memberships AS membership
      WHERE membership.tenant_id = NEW.tenant_id
        AND membership.user_id = NEW.reference_id
    ) THEN
      RAISE EXCEPTION 'custom field reference is invalid'
        USING ERRCODE = '23503';
    END IF;
  ELSIF NEW.data_type = 'operator_team' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.operator_teams AS team
      WHERE team.tenant_id = NEW.tenant_id
        AND team.id = NEW.reference_id
        AND team.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'custom field reference is invalid'
        USING ERRCODE = '23503';
    END IF;
  ELSIF NEW.data_type = 'asset_reference' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.dfir_assets AS asset
      WHERE asset.tenant_id = NEW.tenant_id
        AND asset.id = NEW.reference_id
        AND asset.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'custom field reference is invalid'
        USING ERRCODE = '23503';
    END IF;
  ELSIF NEW.data_type = 'ioc_reference' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.dfir_iocs AS ioc
      WHERE ioc.tenant_id = NEW.tenant_id
        AND ioc.id = NEW.reference_id
        AND ioc.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'custom field reference is invalid'
        USING ERRCODE = '23503';
    END IF;
  ELSIF NEW.data_type = 'customer_contact' THEN
    RAISE EXCEPTION 'customer contact reference integration is unavailable'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.validate_custom_field_value_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_custom_field_value_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER custom_field_values_validate_v1
BEFORE INSERT OR UPDATE ON public.custom_field_values
FOR EACH ROW EXECUTE FUNCTION app.validate_custom_field_value_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_custom_field_value_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.object_type IS DISTINCT FROM OLD.object_type
     OR NEW.alert_id IS DISTINCT FROM OLD.alert_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.definition_id IS DISTINCT FROM OLD.definition_id
     OR NEW.created_by_membership_id IS DISTINCT FROM OLD.created_by_membership_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'custom field value identity is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
    RAISE EXCEPTION 'custom field value version conflict'
      USING ERRCODE = '40001';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_custom_field_value_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_custom_field_value_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER custom_field_values_identity_v1
BEFORE UPDATE ON public.custom_field_values
FOR EACH ROW EXECUTE FUNCTION app.guard_custom_field_value_identity_v1();--> statement-breakpoint

CREATE FUNCTION app.validate_custom_field_revision_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  definition_record public.custom_field_definitions%ROWTYPE;
BEGIN
  SELECT definition.* INTO definition_record
  FROM public.custom_field_definitions AS definition
  WHERE definition.tenant_id = NEW.tenant_id
    AND definition.id = NEW.definition_id;
  IF NOT FOUND
     OR definition_record.object_type IS DISTINCT FROM NEW.object_type
     OR definition_record.schema_version IS DISTINCT FROM NEW.schema_version
     OR NOT NEW.snapshot ?& ARRAY[
       'key', 'label', 'description', 'dataType', 'required', 'nullable',
       'defaultPresence', 'constraints', 'options', 'permissions', 'placement',
       'capabilities', 'requiredOnTransitions'
     ]
     OR NEW.snapshot ->> 'key' IS DISTINCT FROM definition_record.key
     OR NEW.snapshot ->> 'dataType' IS DISTINCT FROM definition_record.data_type::text
     OR jsonb_typeof(NEW.snapshot -> 'required') IS DISTINCT FROM 'boolean'
     OR jsonb_typeof(NEW.snapshot -> 'nullable') IS DISTINCT FROM 'boolean'
     OR coalesce((NEW.snapshot ->> 'required')::boolean, false) IS DISTINCT FROM definition_record.required
     OR coalesce((NEW.snapshot ->> 'nullable')::boolean, false) IS DISTINCT FROM definition_record.nullable
     OR jsonb_typeof(NEW.snapshot -> 'defaultPresence') IS DISTINCT FROM 'string'
     OR NEW.snapshot ->> 'defaultPresence' NOT IN ('missing', 'null', 'present')
     OR jsonb_typeof(NEW.snapshot -> 'constraints') IS DISTINCT FROM 'object'
     OR jsonb_typeof(NEW.snapshot -> 'options') IS DISTINCT FROM 'array'
     OR jsonb_typeof(NEW.snapshot -> 'permissions') IS DISTINCT FROM 'array'
     OR jsonb_typeof(NEW.snapshot -> 'placement') IS DISTINCT FROM 'object'
     OR jsonb_typeof(NEW.snapshot -> 'capabilities') IS DISTINCT FROM 'object'
     OR jsonb_typeof(NEW.snapshot -> 'requiredOnTransitions') IS DISTINCT FROM 'array' THEN
    RAISE EXCEPTION 'custom field revision does not match current definition'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.validate_custom_field_revision_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_custom_field_revision_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER custom_field_definition_revisions_validate_v1
BEFORE INSERT ON public.custom_field_definition_revisions
FOR EACH ROW EXECUTE FUNCTION app.validate_custom_field_revision_v1();--> statement-breakpoint

CREATE FUNCTION app.private_dfir_entity_exists_v1(
  p_tenant_id uuid,
  p_kind public.dfir_entity_kind,
  p_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_kind IS NULL OR p_id IS NULL OR p_kind = 'external' THEN
    RETURN false;
  END IF;
  RETURN CASE p_kind
    WHEN 'alert' THEN EXISTS (
      SELECT 1 FROM public.alerts WHERE tenant_id = p_tenant_id AND id = p_id
    )
    WHEN 'case' THEN EXISTS (
      SELECT 1 FROM public.cases WHERE tenant_id = p_tenant_id AND id = p_id
    )
    WHEN 'ioc' THEN EXISTS (
      SELECT 1 FROM public.dfir_iocs
      WHERE tenant_id = p_tenant_id AND id = p_id AND archived_at IS NULL
    )
    WHEN 'asset' THEN EXISTS (
      SELECT 1 FROM public.dfir_assets
      WHERE tenant_id = p_tenant_id AND id = p_id AND archived_at IS NULL
    )
    WHEN 'evidence' THEN EXISTS (
      SELECT 1 FROM public.dfir_evidence
      WHERE tenant_id = p_tenant_id AND id = p_id
    )
    WHEN 'task' THEN EXISTS (
      SELECT 1 FROM public.dfir_tasks
      WHERE tenant_id = p_tenant_id AND id = p_id
    )
    WHEN 'attachment' THEN EXISTS (
      SELECT 1 FROM public.dfir_attachments
      WHERE tenant_id = p_tenant_id AND id = p_id
    )
    ELSE false
  END;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_dfir_entity_exists_v1(uuid, public.dfir_entity_kind, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_dfir_entity_exists_v1(uuid, public.dfir_entity_kind, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.validate_dfir_relationship_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (NEW.source_kind <> 'external' AND NOT app.private_dfir_entity_exists_v1(
        NEW.tenant_id, NEW.source_kind, NEW.source_id
      ))
     OR (NEW.target_kind <> 'external' AND NOT app.private_dfir_entity_exists_v1(
        NEW.tenant_id, NEW.target_kind, NEW.target_id
      )) THEN
    RAISE EXCEPTION 'DFIR relationship endpoint is invalid'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.validate_dfir_relationship_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_dfir_relationship_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER dfir_relationships_validate_v1
BEFORE INSERT OR UPDATE ON public.dfir_relationships
FOR EACH ROW EXECUTE FUNCTION app.validate_dfir_relationship_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_dfir_storage_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.bucket IS DISTINCT FROM OLD.bucket
     OR NEW.object_key IS DISTINCT FROM OLD.object_key
     OR NEW.original_filename IS DISTINCT FROM OLD.original_filename
     OR NEW.classification IS DISTINCT FROM OLD.classification
     OR NEW.created_by_membership_id IS DISTINCT FROM OLD.created_by_membership_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR (OLD.content_sha256 IS NOT NULL AND (
       NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
       OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
       OR NEW.detected_mime IS DISTINCT FROM OLD.detected_mime
       OR NEW.verified_at IS DISTINCT FROM OLD.verified_at
     )) THEN
    RAISE EXCEPTION 'DFIR storage identity and verified content are immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_dfir_storage_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_dfir_storage_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER dfir_storage_objects_identity_v1
BEFORE UPDATE OR DELETE ON public.dfir_storage_objects
FOR EACH ROW EXECUTE FUNCTION app.guard_dfir_storage_identity_v1();--> statement-breakpoint

CREATE FUNCTION app.validate_dfir_attachment_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  storage_record public.dfir_storage_objects%ROWTYPE;
BEGIN
  SELECT storage.* INTO storage_record
  FROM public.dfir_storage_objects AS storage
  WHERE storage.tenant_id = NEW.tenant_id
    AND storage.id = NEW.storage_object_id;
  IF NOT FOUND
     OR storage_record.original_filename IS DISTINCT FROM NEW.original_filename
     OR storage_record.state IS DISTINCT FROM NEW.scan_state
     OR NEW.visibility = 'public' AND storage_record.state <> 'available' THEN
    RAISE EXCEPTION 'DFIR attachment storage projection is invalid'
      USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'UPDATE' AND (
    NEW.id IS DISTINCT FROM OLD.id
    OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
    OR NEW.subject_kind IS DISTINCT FROM OLD.subject_kind
    OR NEW.alert_id IS DISTINCT FROM OLD.alert_id
    OR NEW.case_id IS DISTINCT FROM OLD.case_id
    OR NEW.ioc_id IS DISTINCT FROM OLD.ioc_id
    OR NEW.asset_id IS DISTINCT FROM OLD.asset_id
    OR NEW.evidence_id IS DISTINCT FROM OLD.evidence_id
    OR NEW.task_id IS DISTINCT FROM OLD.task_id
    OR NEW.storage_object_id IS DISTINCT FROM OLD.storage_object_id
    OR NEW.original_filename IS DISTINCT FROM OLD.original_filename
    OR NEW.uploaded_by_membership_id IS DISTINCT FROM OLD.uploaded_by_membership_id
    OR NEW.uploaded_at IS DISTINCT FROM OLD.uploaded_at
  ) THEN
    RAISE EXCEPTION 'DFIR attachment identity is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.validate_dfir_attachment_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_dfir_attachment_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER dfir_attachments_validate_v1
BEFORE INSERT OR UPDATE ON public.dfir_attachments
FOR EACH ROW EXECUTE FUNCTION app.validate_dfir_attachment_v1();--> statement-breakpoint

CREATE FUNCTION app.validate_dfir_task_assignment_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target_membership_id uuid;
BEGIN
  IF NEW.operator_team_epoch_id IS NULL THEN
    RETURN NEW;
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS epoch
    WHERE epoch.tenant_id = NEW.tenant_id
      AND epoch.id = NEW.operator_team_epoch_id
      AND epoch.operator_team_id = NEW.operator_team_id
      AND epoch.ended_at IS NULL
  ) THEN
    RAISE EXCEPTION 'DFIR task requires the exact live operator-team epoch'
      USING ERRCODE = '23503';
  END IF;
  IF NEW.assignee_user_id IS NOT NULL THEN
    SELECT membership.id INTO target_membership_id
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.user_id = NEW.assignee_user_id
      AND membership.status = 'active';
    IF NOT FOUND OR NOT EXISTS (
      SELECT 1
      FROM public.operator_team_roster_entries AS roster
      WHERE roster.tenant_id = NEW.tenant_id
        AND roster.assignment_epoch_id = NEW.operator_team_epoch_id
        AND roster.membership_id = target_membership_id
        AND roster.revoked_at IS NULL
        AND (roster.expires_at IS NULL OR roster.expires_at > transaction_timestamp())
    ) THEN
      RAISE EXCEPTION 'DFIR task assignee is outside the exact live team epoch'
        USING ERRCODE = '23503';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.validate_dfir_task_assignment_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_dfir_task_assignment_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER dfir_tasks_assignment_validate_v1
BEFORE INSERT OR UPDATE OF assignee_user_id, operator_team_id, operator_team_epoch_id
ON public.dfir_tasks
FOR EACH ROW EXECUTE FUNCTION app.validate_dfir_task_assignment_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_dfir_evidence_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.case_id IS DISTINCT FROM OLD.case_id
     OR NEW.storage_object_id IS DISTINCT FROM OLD.storage_object_id
     OR NEW.title IS DISTINCT FROM OLD.title
     OR NEW.description IS DISTINCT FROM OLD.description
     OR NEW.evidence_type IS DISTINCT FROM OLD.evidence_type
     OR NEW.classification IS DISTINCT FROM OLD.classification
     OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
     OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
     OR NEW.detected_mime IS DISTINCT FROM OLD.detected_mime
     OR NEW.collected_at IS DISTINCT FROM OLD.collected_at
     OR NEW.collected_by_membership_id IS DISTINCT FROM OLD.collected_by_membership_id
     OR NEW.source IS DISTINCT FROM OLD.source
     OR NEW.initial_retention_until IS DISTINCT FROM OLD.initial_retention_until
     OR NEW.initial_legal_hold IS DISTINCT FROM OLD.initial_legal_hold
     OR NEW.initial_scan_state IS DISTINCT FROM OLD.initial_scan_state
     OR NEW.anchor_hash IS DISTINCT FROM OLD.anchor_hash
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'DFIR evidence provenance is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_dfir_evidence_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_dfir_evidence_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
CREATE TRIGGER dfir_evidence_identity_v1
BEFORE UPDATE OR DELETE ON public.dfir_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_dfir_evidence_identity_v1();--> statement-breakpoint
