DO $tenant_settings_owner_role$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_tenant_settings_owner'
  ) THEN
    CREATE ROLE periapsis_tenant_settings_owner WITH NOINHERIT;
  END IF;
END;
$tenant_settings_owner_role$;
--> statement-breakpoint
ALTER ROLE periapsis_tenant_settings_owner
  NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
  NOREPLICATION NOBYPASSRLS;
REVOKE periapsis_tenant_settings_owner
  FROM periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE TABLE "tenant_settings" (
  "tenant_id" uuid PRIMARY KEY NOT NULL,
  "brand_name" text NOT NULL,
  "brand_mark" text NOT NULL,
  "primary_color" char(7) NOT NULL,
  "accent_color" char(7) NOT NULL,
  "version" integer DEFAULT 1 NOT NULL,
  "updated_by_membership_id" uuid,
  "created_at" timestamp with time zone DEFAULT now() NOT NULL,
  "updated_at" timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT "tenant_settings_brand_name_check" CHECK (
    "tenant_settings"."brand_name" = btrim("tenant_settings"."brand_name")
    and char_length("tenant_settings"."brand_name") between 1 and 80
    and "tenant_settings"."brand_name" !~ '[[:cntrl:]]'
    and "tenant_settings"."brand_name" !~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
  ),
  CONSTRAINT "tenant_settings_brand_mark_check" CHECK (
    "tenant_settings"."brand_mark" ~ '^[A-Z0-9]{1,4}$'
  ),
  CONSTRAINT "tenant_settings_primary_color_check" CHECK (
    "tenant_settings"."primary_color" ~ '^#[0-9a-f]{6}$'
  ),
  CONSTRAINT "tenant_settings_accent_color_check" CHECK (
    "tenant_settings"."accent_color" ~ '^#[0-9a-f]{6}$'
  ),
  CONSTRAINT "tenant_settings_distinct_colors_check" CHECK (
    "tenant_settings"."primary_color" <> "tenant_settings"."accent_color"
  ),
  CONSTRAINT "tenant_settings_version_check" CHECK (
    "tenant_settings"."version" between 1 and 2147483647
  ),
  CONSTRAINT "tenant_settings_timestamps_check" CHECK (
    "tenant_settings"."updated_at" >= "tenant_settings"."created_at"
  )
);
--> statement-breakpoint
ALTER TABLE "tenant_settings" ENABLE ROW LEVEL SECURITY;
ALTER TABLE "tenant_settings" FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE "tenant_settings"
  ADD CONSTRAINT "tenant_settings_tenant_id_tenants_id_fk"
  FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id")
  ON DELETE restrict;
ALTER TABLE "tenant_settings"
  ADD CONSTRAINT "tenant_settings_updater_membership_fk"
  FOREIGN KEY ("tenant_id", "updated_by_membership_id")
  REFERENCES "public"."tenant_memberships"("tenant_id", "id")
  ON DELETE restrict ON UPDATE cascade;
--> statement-breakpoint
CREATE POLICY "tenant_settings_owner_access" ON "tenant_settings"
  AS PERMISSIVE FOR ALL TO "periapsis_tenant_settings_owner"
  USING (true) WITH CHECK (true);
CREATE POLICY "tenants_settings_owner_select" ON "tenants"
  AS PERMISSIVE FOR SELECT TO "periapsis_tenant_settings_owner"
  USING (
    id = nullif(current_setting('app.tenant_id', true), '')::uuid
    and status = 'active'
  );
CREATE POLICY "tenants_settings_owner_update" ON "tenants"
  AS PERMISSIVE FOR UPDATE TO "periapsis_tenant_settings_owner"
  USING (
    id = nullif(current_setting('app.tenant_id', true), '')::uuid
    and status = 'active'
  ) WITH CHECK (
    id = nullif(current_setting('app.tenant_id', true), '')::uuid
    and status = 'active'
  );
--> statement-breakpoint
ALTER TABLE public.tenant_settings OWNER TO periapsis_tenant_settings_owner;
REVOKE ALL ON TABLE public.tenant_settings
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor, periapsis_audit_reader_owner;
GRANT ALL ON TABLE public.tenant_settings TO periapsis_migrator;
GRANT SELECT, UPDATE(timezone, locale, version, updated_at)
  ON TABLE public.tenants TO periapsis_tenant_settings_owner;
GRANT USAGE ON SCHEMA public, app TO periapsis_tenant_settings_owner;
--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id, key, display_name, description, service_account_allowed
) VALUES
  (uuidv7(), 'settings.read', 'Read tenant settings',
    'Read safe tenant branding, timezone, and locale settings.', false),
  (uuidv7(), 'settings.manage', 'Manage tenant settings',
    'Change tenant branding, timezone, and locale settings.', false)
ON CONFLICT (key) DO NOTHING;
INSERT INTO public.tenant_permission_scopes (permission_id, scope)
SELECT permission.id, 'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key IN ('settings.read', 'settings.manage')
ON CONFLICT DO NOTHING;
--> statement-breakpoint
DO $tenant_settings_permission_contract$
BEGIN
  IF (SELECT count(*)
      FROM ONLY public.tenant_permissions AS permission
      WHERE permission.key IN ('settings.read', 'settings.manage')
        AND NOT permission.service_account_allowed) <> 2
     OR EXISTS (
       SELECT 1
       FROM ONLY public.tenant_permissions AS permission
       JOIN ONLY public.tenant_permission_scopes AS permission_scope
         ON permission_scope.permission_id = permission.id
       WHERE permission.key IN ('settings.read', 'settings.manage')
         AND permission_scope.scope <> 'tenant'
     )
     OR (SELECT count(*)
         FROM ONLY public.tenant_permissions AS permission
         JOIN ONLY public.tenant_permission_scopes AS permission_scope
           ON permission_scope.permission_id = permission.id
         WHERE permission.key IN ('settings.read', 'settings.manage')
           AND permission_scope.scope = 'tenant') <> 2 THEN
    RAISE EXCEPTION 'tenant settings permission catalog is ambiguous'
      USING ERRCODE = '55000';
  END IF;
END;
$tenant_settings_permission_contract$;
--> statement-breakpoint

CREATE FUNCTION app.private_default_tenant_brand_mark_v1(p_name text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT coalesce(
    nullif(substring(regexp_replace(upper(p_name), '[^A-Z0-9]', '', 'g') from 1 for 4), ''),
    'P'
  )::text;
$function$;
ALTER FUNCTION app.private_default_tenant_brand_mark_v1(text)
  OWNER TO periapsis_tenant_settings_owner;
REVOKE ALL ON FUNCTION app.private_default_tenant_brand_mark_v1(text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_default_tenant_brand_mark_v1(text)
  TO periapsis_migrator, periapsis_tenant_settings_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_default_tenant_brand_name_v1(p_name text)
RETURNS text
LANGUAGE sql
IMMUTABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT coalesce(
    nullif(
      left(
        btrim(regexp_replace(
          p_name,
          U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]|[[:cntrl:]]',
          '', 'g'
        )),
        80
      ),
      ''
    ),
    'Periapsis'
  )::text;
$function$;
ALTER FUNCTION app.private_default_tenant_brand_name_v1(text)
  OWNER TO periapsis_tenant_settings_owner;
REVOKE ALL ON FUNCTION app.private_default_tenant_brand_name_v1(text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_default_tenant_brand_name_v1(text)
  TO periapsis_migrator, periapsis_tenant_settings_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_settings_row_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  INSERT INTO public.tenant_settings (
    tenant_id, brand_name, brand_mark, primary_color, accent_color,
    version, created_at, updated_at
  ) VALUES (
    NEW.id, app.private_default_tenant_brand_name_v1(NEW.name),
    app.private_default_tenant_brand_mark_v1(NEW.name),
    '#6558d3', '#18a999', 1,
    transaction_timestamp(), transaction_timestamp()
  );
  RETURN NEW;
END;
$function$;
ALTER FUNCTION app.private_seed_tenant_settings_row_v1()
  OWNER TO periapsis_tenant_settings_owner;
REVOKE ALL ON FUNCTION app.private_seed_tenant_settings_row_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
CREATE TRIGGER tenants_seed_settings_v1
AFTER INSERT ON public.tenants
FOR EACH ROW EXECUTE FUNCTION app.private_seed_tenant_settings_row_v1();
--> statement-breakpoint

INSERT INTO public.tenant_settings (
  tenant_id, brand_name, brand_mark, primary_color, accent_color,
  version, created_at, updated_at
)
SELECT tenant.id, app.private_default_tenant_brand_name_v1(tenant.name),
       app.private_default_tenant_brand_mark_v1(tenant.name),
       '#6558d3', '#18a999', 1, tenant.created_at,
       greatest(tenant.created_at, tenant.updated_at)
FROM public.tenants AS tenant
ON CONFLICT (tenant_id) DO NOTHING;
DO $tenant_settings_seed_contract$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ONLY public.tenants AS tenant
    LEFT JOIN ONLY public.tenant_settings AS settings
      ON settings.tenant_id = tenant.id
    WHERE settings.tenant_id IS NULL
  ) THEN
    RAISE EXCEPTION 'every tenant requires a settings row'
      USING ERRCODE = '55000';
  END IF;
END;
$tenant_settings_seed_contract$;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_settings_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  role_record public.tenant_roles%ROWTYPE;
  changed_rows integer;
  delta integer;
  seeded_at timestamptz := transaction_timestamp();
BEGIN
  PERFORM state.revision
  FROM ONLY public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_tenant_id
    AND state.initialized_at IS NOT NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant authorization state is required for settings seeding'
      USING ERRCODE = '55000';
  END IF;

  FOR role_record IN
    SELECT role.*
    FROM ONLY public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id
      AND role.system_role
      AND role.principal_kind = 'human'
      AND role.archived_at IS NULL
    ORDER BY role.id
    FOR UPDATE
  LOOP
    changed_rows := 0;
    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT p_tenant_id, role_record.id, permission.id, 'tenant', NULL
    FROM ONLY public.tenant_permissions AS permission
    WHERE permission.key = 'settings.read'
       OR (
         permission.key = 'settings.manage'
         AND role_record.key = 'tenant_admin'
       )
    ON CONFLICT DO NOTHING;
    GET DIAGNOSTICS changed_rows = ROW_COUNT;

    IF role_record.key = 'tenant_admin' THEN
      INSERT INTO public.tenant_role_delegation_ceilings (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      )
      SELECT p_tenant_id, role_record.id, permission.id, 'tenant', NULL
      FROM ONLY public.tenant_permissions AS permission
      WHERE permission.key IN ('settings.read', 'settings.manage')
      ON CONFLICT DO NOTHING;
      GET DIAGNOSTICS delta = ROW_COUNT;
      changed_rows := changed_rows + delta;
    END IF;

    IF changed_rows > 0 THEN
      IF role_record.version >= 2147483647 THEN
        RAISE EXCEPTION 'tenant settings authorization version is exhausted'
          USING ERRCODE = '22003';
      END IF;
      UPDATE ONLY public.tenant_roles AS role
      SET version = role.version + 1, updated_at = seeded_at
      WHERE role.tenant_id = p_tenant_id
        AND role.id = role_record.id
        AND role.version = role_record.version;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'tenant settings authorization changed concurrently'
          USING ERRCODE = '40001';
      END IF;
      INSERT INTO public.audit_events (
        id, tenant_id, sequence, actor_type, action, resource_type,
        resource_id, authentication_method, outcome, after, metadata
      ) VALUES (
        uuidv7(), p_tenant_id, 0, 'system',
        'tenant.authorization.settings_enabled', 'tenant_role',
        role_record.id, 'database_migration', 'success',
        jsonb_build_object(
          'read', true,
          'manage', role_record.key = 'tenant_admin',
          'priorVersion', role_record.version,
          'resultVersion', role_record.version + 1
        ),
        jsonb_build_object('migration', '0214_tenant_branding_settings')
      );
    END IF;
  END LOOP;
END;
$function$;
ALTER FUNCTION app.private_seed_tenant_settings_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_seed_tenant_settings_authorization_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_tenant_settings_owner;
--> statement-breakpoint

DO $seed_existing_tenant_settings_authorization$
DECLARE
  tenant_record record;
BEGIN
  FOR tenant_record IN
    SELECT tenant.id
    FROM ONLY public.tenants AS tenant
    JOIN ONLY public.tenant_authorization_states AS state
      ON state.tenant_id = tenant.id
     AND state.initialized_at IS NOT NULL
    ORDER BY tenant.id
  LOOP
    PERFORM app.private_seed_tenant_settings_authorization_v1(tenant_record.id);
  END LOOP;
END;
$seed_existing_tenant_settings_authorization$;
--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  RENAME TO seed_tenant_authorization_settings_compatibility_impl;
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
  PERFORM app.seed_tenant_authorization_settings_compatibility_impl(
    p_tenant_id, p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_settings_authorization_v1(p_tenant_id);
END;
$function$;
ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_tenant_settings_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_append_tenant_settings_audit_v1(
  p_event_id uuid,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_before jsonb,
  p_after jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF p_event_id IS NULL OR uuid_extract_version(p_event_id) IS DISTINCT FROM 7
     OR p_reason IS NULL OR p_reason <> btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 1 AND 2048
     OR p_reason ~ '[[:cntrl:]]'
     OR p_request_id IS NULL
     OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) OR jsonb_typeof(p_before) <> 'object'
       OR jsonb_typeof(p_after) <> 'object' THEN
    RAISE EXCEPTION 'tenant settings audit envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id,
    action, resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome, reason,
    before, after, metadata
  ) VALUES (
    p_event_id, app.context_tenant_id(), 0, 'user', actor_id,
    'tenant.settings.update', 'tenant_settings', app.context_tenant_id(),
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason, p_before, p_after,
    jsonb_build_object('projectionVersion', 1)
  );
END;
$function$;
ALTER FUNCTION app.private_append_tenant_settings_audit_v1(
  uuid, text, uuid, uuid, inet, text, text, jsonb, jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_tenant_settings_audit_v1(
  uuid, text, uuid, uuid, inet, text, text, jsonb, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.private_append_tenant_settings_audit_v1(
  uuid, text, uuid, uuid, inet, text, text, jsonb, jsonb
) TO periapsis_tenant_settings_owner;
--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.require_live_audit_session_v1(uuid, uuid),
  app.context_tenant_id(),
  app.context_user_id(),
  app.current_tenant_human_has_exact_permission_v3(
    text, public.authorization_scope
  ),
  app.current_tenant_membership_id(),
  app.lock_current_tenant_authorization_state()
TO periapsis_tenant_settings_owner;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_settings_v1(
  p_session_id uuid,
  p_authentication_method text
)
RETURNS TABLE(
  tenant_id uuid,
  brand_name text,
  brand_mark text,
  primary_color text,
  accent_color text,
  timezone text,
  locale text,
  version integer,
  updated_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF app.require_live_audit_session_v1(p_session_id, context_tenant)
       IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.read', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant settings read permission is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT settings.tenant_id, settings.brand_name, settings.brand_mark,
         settings.primary_color::text, settings.accent_color::text,
         tenant.timezone, tenant.locale, settings.version,
         settings.updated_at
  FROM ONLY public.tenant_settings AS settings
  JOIN ONLY public.tenants AS tenant ON tenant.id = settings.tenant_id
  WHERE settings.tenant_id = context_tenant
    AND tenant.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant settings are unavailable'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;
ALTER FUNCTION app.get_tenant_settings_v1(uuid, text)
  OWNER TO periapsis_tenant_settings_owner;
REVOKE ALL ON FUNCTION app.get_tenant_settings_v1(uuid, text)
  FROM PUBLIC, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.get_tenant_settings_v1(uuid, text)
  TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.update_tenant_settings_v1(
  p_session_id uuid,
  p_authentication_method text,
  p_expected_version integer,
  p_brand_name text,
  p_brand_mark text,
  p_primary_color text,
  p_accent_color text,
  p_timezone text,
  p_locale text,
  p_reason text,
  p_audit_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE(
  tenant_id uuid,
  brand_name text,
  brand_mark text,
  primary_color text,
  accent_color text,
  timezone text,
  locale text,
  version integer,
  updated_at timestamptz
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  settings_record public.tenant_settings%ROWTYPE;
  tenant_record public.tenants%ROWTYPE;
  operation_at timestamptz := transaction_timestamp();
  before_projection jsonb;
  after_projection jsonb;
BEGIN
  IF p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_brand_name IS NULL OR p_brand_name <> btrim(p_brand_name)
     OR char_length(p_brand_name) NOT BETWEEN 1 AND 80
     OR p_brand_name ~ '[[:cntrl:]]'
     OR p_brand_name ~ U&'[\00AD\061C\180E\200B-\200F\202A-\202E\2060-\206F\FEFF]'
     OR p_brand_mark IS NULL OR p_brand_mark !~ '^[A-Z0-9]{1,4}$'
     OR p_primary_color IS NULL OR p_primary_color !~ '^#[0-9a-f]{6}$'
     OR p_accent_color IS NULL OR p_accent_color !~ '^#[0-9a-f]{6}$'
     OR p_primary_color = p_accent_color
     OR p_timezone IS NULL OR p_timezone = 'Local'
     OR length(p_timezone) NOT BETWEEN 1 AND 64
     OR NOT EXISTS (
       SELECT 1 FROM pg_catalog.pg_timezone_names AS zone
       WHERE zone.name = p_timezone
     )
     OR p_locale IS NULL OR length(p_locale) NOT BETWEEN 2 AND 35
     OR p_locale !~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'
     OR lower(split_part(p_locale, '-', 1)) = 'und'
     OR p_reason IS NULL OR p_reason <> btrim(p_reason)
     OR octet_length(p_reason) NOT BETWEEN 1 AND 2048
     OR p_reason ~ '[[:cntrl:]]'
     OR p_audit_id IS NULL OR uuid_extract_version(p_audit_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'tenant settings update is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  IF app.require_live_audit_session_v1(p_session_id, context_tenant)
       IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.read', 'tenant'
     ) OR NOT app.current_tenant_human_has_exact_permission_v3(
       'settings.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant settings manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':tenant.settings', 0
  ));

  SELECT settings.* INTO settings_record
  FROM ONLY public.tenant_settings AS settings
  WHERE settings.tenant_id = context_tenant
  FOR UPDATE;
  SELECT tenant.* INTO tenant_record
  FROM ONLY public.tenants AS tenant
  WHERE tenant.id = context_tenant AND tenant.status = 'active'
  FOR UPDATE;
  IF settings_record.tenant_id IS NULL OR tenant_record.id IS NULL THEN
    RAISE EXCEPTION 'tenant settings are unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF settings_record.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'tenant settings changed concurrently'
      USING ERRCODE = '40001';
  END IF;
  IF (tenant_record.timezone IS DISTINCT FROM p_timezone
      OR tenant_record.locale IS DISTINCT FROM p_locale)
     AND tenant_record.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant representation version is exhausted'
      USING ERRCODE = '22003';
  END IF;
  IF settings_record.brand_name = p_brand_name
     AND settings_record.brand_mark = p_brand_mark
     AND settings_record.primary_color::text = p_primary_color
     AND settings_record.accent_color::text = p_accent_color
     AND tenant_record.timezone = p_timezone
     AND tenant_record.locale = p_locale THEN
    RAISE EXCEPTION 'tenant settings update must change at least one field'
      USING ERRCODE = '22023';
  END IF;

  before_projection := jsonb_build_object(
    'brandName', settings_record.brand_name,
    'brandMark', settings_record.brand_mark,
    'primaryColor', settings_record.primary_color::text,
    'accentColor', settings_record.accent_color::text,
    'timezone', tenant_record.timezone,
    'locale', tenant_record.locale,
    'version', settings_record.version
  );
  UPDATE ONLY public.tenant_settings AS settings
  SET brand_name = p_brand_name,
      brand_mark = p_brand_mark,
      primary_color = p_primary_color,
      accent_color = p_accent_color,
      version = settings.version + 1,
      updated_by_membership_id = actor_membership,
      updated_at = operation_at
  WHERE settings.tenant_id = context_tenant
    AND settings.version = p_expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant settings changed concurrently'
      USING ERRCODE = '40001';
  END IF;
  IF tenant_record.timezone IS DISTINCT FROM p_timezone
     OR tenant_record.locale IS DISTINCT FROM p_locale THEN
    UPDATE ONLY public.tenants AS tenant
    SET timezone = p_timezone,
        locale = p_locale,
        version = tenant.version + 1,
        updated_at = operation_at
    WHERE tenant.id = context_tenant
      AND tenant.version = tenant_record.version
      AND tenant.status = 'active';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant representation changed concurrently'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  after_projection := before_projection || jsonb_build_object(
    'brandName', p_brand_name,
    'brandMark', p_brand_mark,
    'primaryColor', p_primary_color,
    'accentColor', p_accent_color,
    'timezone', p_timezone,
    'locale', p_locale,
    'version', p_expected_version + 1
  );
  PERFORM app.private_append_tenant_settings_audit_v1(
    p_audit_id, p_reason, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    before_projection, after_projection
  );

  RETURN QUERY
  SELECT context_tenant, p_brand_name, p_brand_mark, p_primary_color,
         p_accent_color, p_timezone, p_locale,
         p_expected_version + 1, operation_at;
END;
$function$;
ALTER FUNCTION app.update_tenant_settings_v1(
  uuid, text, integer, text, text, text, text, text, text, text,
  uuid, uuid, uuid, inet, text
) OWNER TO periapsis_tenant_settings_owner;
REVOKE ALL ON FUNCTION app.update_tenant_settings_v1(
  uuid, text, integer, text, text, text, text, text, text, text,
  uuid, uuid, uuid, inet, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.update_tenant_settings_v1(
  uuid, text, integer, text, text, text, text, text, text, text,
  uuid, uuid, uuid, inet, text
) TO periapsis_api;
--> statement-breakpoint

DO $tenant_settings_security_contract$
BEGIN
  IF pg_get_userbyid((
       SELECT relation.relowner FROM pg_catalog.pg_class AS relation
       JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
       WHERE namespace.nspname = 'public' AND relation.relname = 'tenant_settings'
     )) <> 'periapsis_tenant_settings_owner'
     OR EXISTS (
       SELECT 1 FROM pg_catalog.pg_roles AS role
       WHERE role.rolname = 'periapsis_tenant_settings_owner'
         AND (role.rolcanlogin OR role.rolsuper OR role.rolbypassrls
           OR role.rolcreaterole OR role.rolcreatedb OR role.rolreplication)
     )
     OR has_table_privilege('periapsis_api', 'public.tenant_settings', 'SELECT')
     OR has_table_privilege('periapsis_api', 'public.tenant_settings', 'INSERT')
     OR has_table_privilege('periapsis_api', 'public.tenant_settings', 'UPDATE')
     OR has_table_privilege('periapsis_api', 'public.tenant_settings', 'DELETE')
     OR NOT has_function_privilege(
       'periapsis_api', 'app.get_tenant_settings_v1(uuid,text)', 'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_api',
       'app.update_tenant_settings_v1(uuid,text,integer,text,text,text,text,text,text,text,uuid,uuid,uuid,inet,text)',
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'tenant settings security contract is incomplete'
      USING ERRCODE = '55000';
  END IF;
END;
$tenant_settings_security_contract$;
