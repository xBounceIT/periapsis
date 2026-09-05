-- Slice 9B adds an explicit, disabled-only tenant admission record for a
-- platform identity provider.  Tenant-owned and platform-owned bindings share
-- only the login-code namespace: their provider, epoch and provenance families
-- remain physically separate.

ALTER TABLE public.tenant_auth_provider_login_keys OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_auth_provider_bindings OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_identity_provider_access_epochs OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_platform_identity_binding_commands OWNER TO periapsis_migrator;
--> statement-breakpoint

ALTER TABLE public.tenant_auth_provider_login_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_auth_provider_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_identity_provider_access_epochs FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_platform_identity_binding_commands FORCE ROW LEVEL SECURITY;
--> statement-breakpoint

REVOKE ALL ON TABLE
  public.tenant_auth_provider_login_keys,
  public.tenant_platform_auth_provider_bindings,
  public.tenant_platform_identity_provider_access_epochs,
  public.tenant_platform_identity_binding_commands
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner,
  periapsis_ticket_attribution_owner, periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

-- Preserve every historical login code, including archived tenant bindings,
-- before installing the bidirectional guard.
INSERT INTO public.tenant_auth_provider_login_keys (
  tenant_id, binding_family, binding_id, key, created_at, updated_at
)
SELECT binding.tenant_id, 'tenant_provider', binding.id, binding.key,
       binding.created_at, binding.updated_at
FROM ONLY public.tenant_auth_provider_bindings AS binding
ON CONFLICT (tenant_id, key) DO NOTHING;
--> statement-breakpoint

DO $tenant_login_namespace_backfill$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_auth_provider_bindings AS binding
    LEFT JOIN ONLY public.tenant_auth_provider_login_keys AS claim
      ON claim.tenant_id = binding.tenant_id
     AND claim.binding_family = 'tenant_provider'
     AND claim.binding_id = binding.id
     AND claim.key = binding.key
    WHERE claim.tenant_id IS NULL
  ) THEN
    RAISE EXCEPTION 'tenant auth-provider login namespace backfill is not exact'
      USING ERRCODE = '23514';
  END IF;
END;
$tenant_login_namespace_backfill$;
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_auth_provider_login_key_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant auth-provider login claims are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.binding_family IS DISTINCT FROM OLD.binding_family
       OR NEW.binding_id IS DISTINCT FROM OLD.binding_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'tenant auth-provider login claim identity is immutable'
        USING ERRCODE = '55000';
    END IF;
    IF NEW.key IS DISTINCT FROM OLD.key THEN
      IF NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
        RAISE EXCEPTION 'tenant auth-provider login claim rename is invalid'
          USING ERRCODE = '23514';
      END IF;
    ELSIF NEW.updated_at IS DISTINCT FROM OLD.updated_at THEN
      RAISE EXCEPTION 'tenant auth-provider login claim timestamp is immutable without a rename'
        USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE TRIGGER tenant_auth_provider_login_keys_guard_v1
BEFORE UPDATE OR DELETE ON public.tenant_auth_provider_login_keys
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_auth_provider_login_key_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_create_tenant_auth_provider_login_claim_v1(
  p_tenant_id uuid,
  p_binding_family text,
  p_binding_id uuid,
  p_key text
)
RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  INSERT INTO public.tenant_auth_provider_login_keys (
    tenant_id, binding_family, binding_id, key
  ) VALUES (
    p_tenant_id, p_binding_family, p_binding_id, p_key
  );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_rename_tenant_auth_provider_login_claim_v1(
  p_tenant_id uuid,
  p_binding_family text,
  p_binding_id uuid,
  p_old_key text,
  p_new_key text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_new_key IS NOT DISTINCT FROM p_old_key THEN
    RETURN;
  END IF;
  UPDATE ONLY public.tenant_auth_provider_login_keys AS claim
  SET key = p_new_key,
      updated_at = transaction_timestamp()
  WHERE claim.tenant_id = p_tenant_id
    AND claim.binding_family = p_binding_family
    AND claim.binding_id = p_binding_id
    AND claim.key = p_old_key;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant auth-provider login claim does not exist'
      USING ERRCODE = '23514';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_auth_provider_login_claim_child_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  claim_tenant_id uuid;
  claim_family text;
  claim_binding_id uuid;
  claim_key text;
BEGIN
  IF TG_TABLE_NAME = 'tenant_auth_provider_login_keys' THEN
    claim_tenant_id := NEW.tenant_id;
    claim_family := NEW.binding_family;
    claim_binding_id := NEW.binding_id;
    claim_key := NEW.key;
  ELSIF TG_OP = 'DELETE' THEN
    claim_tenant_id := OLD.tenant_id;
    claim_family := OLD.binding_family;
    claim_binding_id := OLD.id;
    claim_key := OLD.key;
  ELSE
    claim_tenant_id := NEW.tenant_id;
    claim_family := NEW.binding_family;
    claim_binding_id := NEW.id;
    claim_key := NEW.key;
  END IF;

  IF claim_family = 'tenant_provider' THEN
    IF NOT EXISTS (
      SELECT 1 FROM ONLY public.tenant_auth_provider_bindings AS binding
      WHERE binding.tenant_id = claim_tenant_id
        AND binding.binding_family = claim_family
        AND binding.id = claim_binding_id
        AND binding.key = claim_key
    ) OR EXISTS (
      SELECT 1 FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
      WHERE binding.tenant_id = claim_tenant_id
        AND binding.id = claim_binding_id
    ) THEN
      RAISE EXCEPTION 'tenant auth-provider login claim has no exact tenant binding'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenant_auth_provider_login_claim_child_check';
    END IF;
  ELSIF claim_family = 'platform_provider' THEN
    IF NOT EXISTS (
      SELECT 1 FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
      WHERE binding.tenant_id = claim_tenant_id
        AND binding.binding_family = claim_family
        AND binding.id = claim_binding_id
        AND binding.key = claim_key
    ) OR EXISTS (
      SELECT 1 FROM ONLY public.tenant_auth_provider_bindings AS binding
      WHERE binding.tenant_id = claim_tenant_id
        AND binding.id = claim_binding_id
    ) THEN
      RAISE EXCEPTION 'tenant auth-provider login claim has no exact platform binding'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenant_auth_provider_login_claim_child_check';
    END IF;
  ELSE
    RAISE EXCEPTION 'tenant auth-provider login claim family is invalid'
      USING ERRCODE = '23514',
            CONSTRAINT = 'tenant_auth_provider_login_claim_child_check';
  END IF;
  RETURN NULL;
END;
$function$;
--> statement-breakpoint

CREATE CONSTRAINT TRIGGER tenant_auth_provider_login_keys_child_guard_v1
AFTER INSERT OR UPDATE ON public.tenant_auth_provider_login_keys
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_auth_provider_login_claim_child_v1();
CREATE CONSTRAINT TRIGGER tenant_auth_provider_bindings_login_claim_guard_v1
AFTER INSERT OR UPDATE OR DELETE ON public.tenant_auth_provider_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_auth_provider_login_claim_child_v1();
CREATE CONSTRAINT TRIGGER tenant_platform_auth_provider_bindings_login_claim_guard_v1
AFTER INSERT OR UPDATE OR DELETE ON public.tenant_platform_auth_provider_bindings
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_auth_provider_login_claim_child_v1();
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_tenant_auth_provider_binding_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant auth-provider bindings are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.binding_family <> 'tenant_provider'
     OR NOT EXISTS (
       SELECT 1 FROM ONLY public.tenant_auth_provider_login_keys AS claim
       WHERE claim.tenant_id = NEW.tenant_id
         AND claim.binding_family = NEW.binding_family
         AND claim.binding_id = NEW.id
         AND claim.key = NEW.key
     ) THEN
    RAISE EXCEPTION 'tenant auth-provider binding has no exact login claim'
      USING ERRCODE = '23514',
            CONSTRAINT = 'tenant_auth_provider_bindings_login_claim_fk';
  END IF;
  IF TG_OP = 'UPDATE'
     AND NEW.binding_family IS DISTINCT FROM OLD.binding_family THEN
    RAISE EXCEPTION 'tenant auth-provider binding family is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.enabled AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_identity_provider_access_epochs AS epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id AND source.id = epoch.source_id
    WHERE epoch.tenant_id = NEW.tenant_id
      AND epoch.id = NEW.current_access_epoch_id
      AND epoch.binding_id = NEW.id
      AND epoch.provider_id = NEW.provider_id
      AND epoch.ended_at IS NULL
      AND source.kind = 'identity_provider_access'
      AND source.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'enabled tenant auth-provider binding has no live access epoch'
      USING ERRCODE = '23514',
            CONSTRAINT = 'tenant_auth_provider_bindings_live_epoch_source_check';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_platform_auth_provider_binding_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant platform auth-provider bindings are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.binding_family <> 'platform_provider'
     OR NEW.enabled
     OR NEW.current_access_epoch_id IS NOT NULL
     OR NEW.auth_revision <> 1
     OR NEW.mapping_revision <> 1
     OR NOT EXISTS (
       SELECT 1 FROM ONLY public.tenant_auth_provider_login_keys AS claim
       WHERE claim.tenant_id = NEW.tenant_id
         AND claim.binding_family = NEW.binding_family
         AND claim.binding_id = NEW.id
         AND claim.key = NEW.key
     ) THEN
    RAISE EXCEPTION 'tenant platform auth-provider binding invariant is invalid'
      USING ERRCODE = '23514';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.created_by_user_id IS DISTINCT FROM NEW.updated_by_user_id
       OR NEW.archived_at IS NOT NULL THEN
      RAISE EXCEPTION 'tenant platform auth-provider binding create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.binding_family IS DISTINCT FROM OLD.binding_family
       OR NEW.platform_provider_id IS DISTINCT FROM OLD.platform_provider_id
       OR NEW.enabled IS DISTINCT FROM OLD.enabled
       OR NEW.auth_revision IS DISTINCT FROM OLD.auth_revision
       OR NEW.mapping_revision IS DISTINCT FROM OLD.mapping_revision
       OR NEW.current_access_epoch_id IS DISTINCT FROM OLD.current_access_epoch_id
       OR NEW.created_by_user_id IS DISTINCT FROM OLD.created_by_user_id
       OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
      RAISE EXCEPTION 'tenant platform auth-provider binding identity is immutable'
        USING ERRCODE = '55000';
    END IF;
    IF OLD.archived_at IS NOT NULL AND ROW(NEW.archived_at, NEW.archived_by_user_id, NEW.archive_reason)
       IS DISTINCT FROM ROW(OLD.archived_at, OLD.archived_by_user_id, OLD.archive_reason) THEN
      RAISE EXCEPTION 'tenant platform auth-provider binding archive is terminal'
        USING ERRCODE = '55000';
    END IF;
    -- ON UPDATE CASCADE performs a key-only intermediate update when the
    -- namespace parent is renamed.  The protected writer immediately follows
    -- it with the versioned metadata update in the same transaction.
    IF NEW.key IS DISTINCT FROM OLD.key
       AND NEW.version = OLD.version
       AND NEW.updated_at IS NOT DISTINCT FROM OLD.updated_at
       AND NEW.profile_priority IS NOT DISTINCT FROM OLD.profile_priority
       AND NEW.updated_by_user_id IS NOT DISTINCT FROM OLD.updated_by_user_id
       AND ROW(NEW.archived_at, NEW.archived_by_user_id, NEW.archive_reason)
           IS NOT DISTINCT FROM ROW(OLD.archived_at, OLD.archived_by_user_id, OLD.archive_reason) THEN
      RETURN NEW;
    END IF;
    IF NEW.version <> OLD.version + 1
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at < OLD.updated_at THEN
      RAISE EXCEPTION 'tenant platform auth-provider binding version transition is invalid'
        USING ERRCODE = '23514';
    END IF;
    IF OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL THEN
      IF NEW.archived_at IS DISTINCT FROM transaction_timestamp()
         OR NEW.archived_by_user_id IS NULL
         OR NEW.archive_reason IS NULL THEN
        RAISE EXCEPTION 'tenant platform auth-provider binding archive envelope is invalid'
          USING ERRCODE = '23514';
      END IF;
    ELSIF ROW(NEW.archived_at, NEW.archived_by_user_id, NEW.archive_reason)
          IS DISTINCT FROM ROW(OLD.archived_at, OLD.archived_by_user_id, OLD.archive_reason) THEN
      RAISE EXCEPTION 'tenant platform auth-provider binding archive transition is invalid'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE TRIGGER tenant_platform_auth_provider_bindings_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_platform_auth_provider_bindings
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_auth_provider_binding_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_auth_provider_binding_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
    WHERE binding.platform_provider_id = OLD.id
      AND binding.archived_at IS NULL
  ) AND (
    TG_OP = 'DELETE'
    OR NEW.enabled
    OR NEW.archived_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'platform identity provider has live tenant bindings'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
CREATE TRIGGER platform_auth_providers_binding_dependency_v1
BEFORE UPDATE OF enabled, archived_at OR DELETE ON public.platform_auth_providers
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_auth_provider_binding_dependency_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_platform_identity_provider_access_epoch_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
BEGIN
  RAISE EXCEPTION 'tenant platform identity-provider access epochs are unavailable'
    USING ERRCODE = '55000';
END;
$function$;
CREATE TRIGGER tenant_platform_identity_provider_access_epochs_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_platform_identity_provider_access_epochs
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_identity_provider_access_epoch_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_platform_identity_binding_command_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, app
AS $function$
BEGIN
  IF TG_OP = 'UPDATE' OR (TG_OP = 'DELETE' AND OLD.expires_at > transaction_timestamp()) THEN
    RAISE EXCEPTION 'tenant platform identity binding commands are immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;
CREATE TRIGGER tenant_platform_identity_binding_commands_guard_v1
BEFORE UPDATE OR DELETE ON public.tenant_platform_identity_binding_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_platform_identity_binding_command_v1();
--> statement-breakpoint

-- The tenant summary is embedded in every platform-provider binding document.
-- Keep its optimistic-concurrency component honest even if a future writer
-- bypasses the platform lifecycle ABI: any projected identity or lifecycle
-- change must advance the tenant version exactly once.
CREATE FUNCTION app.guard_tenant_platform_identity_binding_tenant_projection_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.version IS DISTINCT FROM OLD.version THEN
    IF OLD.version = 2147483647 THEN
      RAISE EXCEPTION 'tenant identity projection revision is exhausted'
        USING ERRCODE = '55000';
    END IF;
    IF NEW.version IS DISTINCT FROM OLD.version + 1 THEN
      RAISE EXCEPTION 'tenant identity projection revision is not consecutive'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenants_identity_projection_version_check';
    END IF;
  END IF;
  IF ROW(NEW.slug, NEW.name, NEW.status)
       IS DISTINCT FROM ROW(OLD.slug, OLD.name, OLD.status) THEN
    IF NEW.version IS NOT DISTINCT FROM OLD.version THEN
      RAISE EXCEPTION 'tenant identity projection must advance its revision'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenants_identity_projection_version_check';
    END IF;
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER tenants_identity_projection_version_guard_v1
BEFORE UPDATE OF slug, name, status, version ON public.tenants
FOR EACH ROW EXECUTE FUNCTION
  app.guard_tenant_platform_identity_binding_tenant_projection_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_tenant_platform_auth_provider_binding_document_v1(
  p_binding_id uuid
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'id', binding.id,
    'providerId', binding.platform_provider_id,
    'tenant', jsonb_build_object(
      'id', tenant.id,
      'slug', tenant.slug,
      'name', tenant.name,
      'status', tenant.status,
      'version', tenant.version
    ),
    'origin', 'platform',
    'loginKey', binding.key,
    'profilePriority', binding.profile_priority,
    'enabled', false,
    'activationAvailable', false,
    'authRevision', binding.auth_revision,
    'mappingRevision', binding.mapping_revision,
    'currentAccessEpochId', NULL,
    'archivedAt', binding.archived_at,
    'version', binding.version,
    'createdAt', binding.created_at,
    'updatedAt', binding.updated_at
  )
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  JOIN ONLY public.tenants AS tenant ON tenant.id = binding.tenant_id
  WHERE binding.id = p_binding_id;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_append_platform_identity_binding_tenant_audit_v1(
  p_event_id uuid,
  p_tenant_id uuid,
  p_platform_actor_user_id uuid,
  p_platform_audit_event_id uuid,
  p_platform_provider_id uuid,
  p_action text,
  p_binding_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text,
  p_before jsonb,
  p_after jsonb
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_event_id IS NULL OR uuid_extract_version(p_event_id) IS DISTINCT FROM 7
     OR p_tenant_id IS NULL OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_platform_actor_user_id IS NULL
     OR uuid_extract_version(p_platform_actor_user_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_event_id = p_platform_audit_event_id
     OR p_platform_provider_id IS NULL
     OR uuid_extract_version(p_platform_provider_id) IS DISTINCT FROM 7
     OR p_binding_id IS NULL OR uuid_extract_version(p_binding_id) IS DISTINCT FROM 7
     OR p_action NOT IN (
       'tenant.platform_identity_binding.created',
       'tenant.platform_identity_binding.updated',
       'tenant.platform_identity_binding.archived'
     )
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_authentication_method NOT IN (
       'bootstrap_totp', 'oidc', 'passkey', 'recovery_code', 'saml', 'totp'
     )
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'tenant platform identity binding audit envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM ONLY public.tenants AS tenant
    WHERE tenant.id = p_tenant_id
  ) OR NOT EXISTS (
    SELECT 1 FROM ONLY public.users AS actor
    WHERE actor.id = p_platform_actor_user_id
  ) THEN
    RAISE EXCEPTION 'tenant platform identity binding audit target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, actor_user_id,
    action, resource_type, resource_id, request_id, correlation_id,
    ip_address, user_agent, authentication_method, outcome, reason,
    before, after, metadata
  ) VALUES (
    p_event_id, p_tenant_id, 0, 'system', NULL,
    p_action, 'platform_identity_binding', p_binding_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, p_authentication_method,
    'success', p_reason, p_before, p_after,
    jsonb_build_object(
      'platform_actor_user_id', p_platform_actor_user_id,
      'platform_audit_event_id', p_platform_audit_event_id,
      'platform_provider_id', p_platform_provider_id
    )
  );
  RETURN p_event_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_tenant_platform_auth_provider_bindings_v1(
  p_session_id uuid,
  p_platform_provider_id uuid,
  p_authentication_method text,
  p_after uuid DEFAULT NULL,
  p_limit integer DEFAULT 50,
  p_include_archived boolean DEFAULT false
)
RETURNS TABLE (document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_platform_provider_id IS NULL
     OR uuid_extract_version(p_platform_provider_id) IS DISTINCT FROM 7
     OR (p_after IS NOT NULL AND uuid_extract_version(p_after) IS DISTINCT FROM 7)
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200
     OR p_include_archived IS NULL THEN
    RAISE EXCEPTION 'tenant platform identity binding list input is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.read', p_authentication_method
  );
  PERFORM 1 FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.id = p_platform_provider_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN QUERY
  SELECT app.private_tenant_platform_auth_provider_binding_document_v1(binding.id)
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.platform_provider_id = p_platform_provider_id
    AND (p_after IS NULL OR binding.id > p_after)
    AND (p_include_archived OR binding.archived_at IS NULL)
  ORDER BY binding.id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_platform_auth_provider_binding_v1(
  p_session_id uuid,
  p_platform_provider_id uuid,
  p_binding_id uuid,
  p_authentication_method text
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  result_document jsonb;
BEGIN
  IF p_platform_provider_id IS NULL
     OR uuid_extract_version(p_platform_provider_id) IS DISTINCT FROM 7
     OR p_binding_id IS NULL OR uuid_extract_version(p_binding_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'tenant platform identity binding get input is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.read', p_authentication_method
  );
  SELECT app.private_tenant_platform_auth_provider_binding_document_v1(binding.id)
  INTO result_document
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.platform_provider_id = p_platform_provider_id
    AND binding.id = p_binding_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN result_document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_tenant_platform_auth_provider_binding_v1(
  p_session_id uuid,
  p_command_id uuid,
  p_binding_id uuid,
  p_platform_provider_id uuid,
  p_tenant_id uuid,
  p_key text,
  p_profile_priority integer,
  p_key_digest bytea,
  p_request_digest bytea,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  binding_id uuid,
  version bigint,
  replayed boolean,
  document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  canonical_request_digest bytea;
  replay_command public.tenant_platform_identity_binding_commands%ROWTYPE;
  current_version bigint;
  result_document jsonb;
BEGIN
  IF p_command_id IS NULL OR uuid_extract_version(p_command_id) IS DISTINCT FROM 7
     OR p_binding_id IS NULL OR uuid_extract_version(p_binding_id) IS DISTINCT FROM 7
     OR p_platform_provider_id IS NULL
     OR uuid_extract_version(p_platform_provider_id) IS DISTINCT FROM 7
     OR p_tenant_id IS NULL OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_key IS NULL OR p_key <> lower(btrim(p_key))
     OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_profile_priority IS NULL OR p_profile_priority NOT BETWEEN 0 AND 1000000
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_tenant_audit_event_id IS NULL
     OR uuid_extract_version(p_tenant_audit_event_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_tenant_audit_event_id = p_platform_audit_event_id
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'tenant platform identity binding create input is invalid'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.manage', p_authentication_method
  );
  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.read', p_authentication_method
  );

  -- Re-bind the caller-supplied digest to the stable business payload inside
  -- the trust boundary.  A compromised caller therefore cannot replay a
  -- changed payload by repeating its original digest.  Server-generated
  -- command, binding, and audit IDs are deliberately excluded because a
  -- legitimate retry generates fresh IDs; actor_id is already part of the
  -- command-ledger key.
  SELECT sha256(
    p_request_digest || convert_to(jsonb_build_array(
      'periapsis/platform-identity-provider-tenant-binding-create/v1',
      p_platform_provider_id::text, p_tenant_id::text, p_key,
      p_profile_priority, p_reason
    )::text, 'UTF8')
  ) INTO canonical_request_digest;

  -- The platform actor's idempotency key is global across target tenants.
  -- tenant_id remains immutable command provenance, while the canonical
  -- request digest below binds the tenant and provider payload.  Namespace
  -- this one-bigint lock by operation so future command families cannot form
  -- an accidental shared key space.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'tenant_platform_identity_binding_commands:binding.create:v1:' ||
    actor_id::text || ':' || encode(p_key_digest, 'hex'), 0
  ));
  DELETE FROM ONLY public.tenant_platform_identity_binding_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = 'binding.create'
    AND command.key_digest = p_key_digest
    AND command.expires_at <= transaction_timestamp();
  IF pg_try_advisory_xact_lock(hashtextextended(
       'tenant_platform_identity_binding_commands:expiry-cleanup:v1', 0
     )) THEN
    WITH expired_command AS (
      SELECT command.id
      FROM ONLY public.tenant_platform_identity_binding_commands AS command
      WHERE command.expires_at <= transaction_timestamp()
      ORDER BY command.expires_at, command.id
      LIMIT 64
      FOR UPDATE SKIP LOCKED
    )
    DELETE FROM ONLY public.tenant_platform_identity_binding_commands AS command
    USING expired_command
    WHERE command.id = expired_command.id;
  END IF;
  SELECT command.* INTO replay_command
  FROM ONLY public.tenant_platform_identity_binding_commands AS command
  WHERE command.actor_user_id = actor_id
    AND command.operation = 'binding.create'
    AND command.key_digest = p_key_digest;
  IF FOUND THEN
    IF replay_command.request_digest <> canonical_request_digest THEN
      RAISE EXCEPTION 'tenant platform identity binding idempotency key was reused with different input'
        USING ERRCODE = '23505';
    END IF;
    SELECT binding.version,
           app.private_tenant_platform_auth_provider_binding_document_v1(binding.id)
    INTO current_version, result_document
    FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
    WHERE binding.tenant_id = p_tenant_id
      AND binding.id = replay_command.result_binding_id
      AND binding.platform_provider_id = p_platform_provider_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant platform identity binding replay result is unavailable'
        USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT replay_command.result_binding_id,
                        replay_command.result_version, true,
                        result_document;
    RETURN;
  END IF;

  -- Serialize permanent provider/tenant reservations only after an exact live
  -- idempotency replay can return.  The fixed int4 namespace keeps this
  -- two-key advisory lock disjoint from the one-bigint command locks above;
  -- hash collisions can therefore only over-serialize unrelated pairs.  Keep
  -- this fence before every provider, policy, authorization-state, and tenant
  -- row lock so lifecycle and provider writers cannot form a reverse edge.
  PERFORM pg_advisory_xact_lock(
    1346978353,
    hashtext(p_platform_provider_id::text || ':' || p_tenant_id::text)
  );

  IF EXISTS (
    SELECT 1 FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
    WHERE binding.tenant_id = p_tenant_id
      AND binding.platform_provider_id = p_platform_provider_id
  ) THEN
    RAISE EXCEPTION 'tenant platform identity binding already exists'
      USING ERRCODE = '55000';
  END IF;

  PERFORM 1
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS policy
    ON policy.provider_id = provider.id
  WHERE provider.id = p_platform_provider_id
    AND provider.archived_at IS NULL
    AND NOT provider.enabled
    AND NOT policy.enabled
    AND NOT policy.platform_login_enabled
    AND policy.account_mode = 'disabled'
  FOR SHARE OF provider, policy;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  PERFORM 1 FROM ONLY public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_tenant_id AND state.initialized_at IS NOT NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  PERFORM 1 FROM ONLY public.tenants AS tenant
  WHERE tenant.id = p_tenant_id AND tenant.status = 'active'
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  PERFORM app.private_create_tenant_auth_provider_login_claim_v1(
    p_tenant_id, 'platform_provider', p_binding_id, p_key
  );
  INSERT INTO public.tenant_platform_auth_provider_bindings (
    id, tenant_id, binding_family, platform_provider_id, key,
    enabled, profile_priority, auth_revision, mapping_revision,
    current_access_epoch_id, created_by_user_id, updated_by_user_id
  ) VALUES (
    p_binding_id, p_tenant_id, 'platform_provider', p_platform_provider_id,
    p_key, false, p_profile_priority, 1, 1, NULL, actor_id, actor_id
  );
  INSERT INTO public.tenant_platform_identity_binding_commands (
    id, tenant_id, actor_user_id, operation, key_digest, request_digest,
    result_binding_id, result_version
  ) VALUES (
    p_command_id, p_tenant_id, actor_id, 'binding.create', p_key_digest,
    canonical_request_digest, p_binding_id, 1
  );

  PERFORM app.private_append_platform_identity_binding_tenant_audit_v1(
    p_tenant_audit_event_id, p_tenant_id, actor_id,
    p_platform_audit_event_id, p_platform_provider_id,
    'tenant.platform_identity_binding.created', p_binding_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_reason, NULL,
    jsonb_build_object(
      'provider_id', p_platform_provider_id,
      'key', p_key,
      'profile_priority', p_profile_priority,
      'enabled', false,
      'auth_revision', 1,
      'mapping_revision', 1,
      'version', 1
    )
  );
  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id,
    'platform.identity_binding.created', 'platform_identity_binding',
    p_binding_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'tenant_id', p_tenant_id,
      'tenant_audit_event_id', p_tenant_audit_event_id,
      'platform_provider_id', p_platform_provider_id,
      'profile_priority', p_profile_priority,
      'enabled', false,
      'version', 1
    )
  );
  result_document := app.private_tenant_platform_auth_provider_binding_document_v1(
    p_binding_id
  );
  RETURN QUERY SELECT p_binding_id, 1::bigint, false, result_document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.update_tenant_platform_auth_provider_binding_v1(
  p_session_id uuid,
  p_platform_provider_id uuid,
  p_binding_id uuid,
  p_expected_version bigint,
  p_expected_tenant_version integer,
  p_key text,
  p_profile_priority integer,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (version bigint, document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  target_tenant_id uuid;
  tenant_record public.tenants%ROWTYPE;
  locked_binding public.tenant_platform_auth_provider_bindings%ROWTYPE;
  next_version bigint;
  result_document jsonb;
BEGIN
  IF p_platform_provider_id IS NULL
     OR uuid_extract_version(p_platform_provider_id) IS DISTINCT FROM 7
     OR p_binding_id IS NULL OR uuid_extract_version(p_binding_id) IS DISTINCT FROM 7
     OR p_expected_version IS NULL OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_expected_tenant_version IS NULL
     OR p_expected_tenant_version NOT BETWEEN 1 AND 2147483647
     OR p_key IS NULL OR p_key <> lower(btrim(p_key))
     OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_profile_priority IS NULL OR p_profile_priority NOT BETWEEN 0 AND 1000000
     OR p_tenant_audit_event_id IS NULL
     OR uuid_extract_version(p_tenant_audit_event_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_tenant_audit_event_id = p_platform_audit_event_id
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'tenant platform identity binding update input is invalid'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.manage', p_authentication_method
  );
  PERFORM app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.read', p_authentication_method
  );

  -- Resolve the immutable tenant identity without taking a row lock, then use
  -- the platform lifecycle lock order at the mutation linearization point:
  -- authorization state, tenant projection, and finally the binding.
  SELECT binding.tenant_id INTO target_tenant_id
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.id = p_binding_id
    AND binding.platform_provider_id = p_platform_provider_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  PERFORM 1
  FROM ONLY public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = target_tenant_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT tenant.* INTO tenant_record
  FROM ONLY public.tenants AS tenant
  WHERE tenant.id = target_tenant_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF tenant_record.version <> p_expected_tenant_version THEN
    RAISE EXCEPTION 'tenant platform identity binding revision conflict'
      USING ERRCODE = '40001';
  END IF;
  SELECT binding.* INTO locked_binding
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.id = p_binding_id
    AND binding.platform_provider_id = p_platform_provider_id
    AND binding.tenant_id = target_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_binding.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant platform identity binding is archived'
      USING ERRCODE = '55000';
  END IF;
  IF locked_binding.version <> p_expected_version THEN
    RAISE EXCEPTION 'tenant platform identity binding revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF locked_binding.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant platform identity binding revision is exhausted'
      USING ERRCODE = '55000';
  END IF;
  next_version := locked_binding.version + 1;
  PERFORM app.private_rename_tenant_auth_provider_login_claim_v1(
    locked_binding.tenant_id, 'platform_provider', locked_binding.id,
    locked_binding.key, p_key
  );
  UPDATE ONLY public.tenant_platform_auth_provider_bindings AS binding
  SET key = p_key,
      profile_priority = p_profile_priority,
      updated_by_user_id = actor_id,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE binding.id = p_binding_id;

  PERFORM app.private_append_platform_identity_binding_tenant_audit_v1(
    p_tenant_audit_event_id, locked_binding.tenant_id, actor_id,
    p_platform_audit_event_id, p_platform_provider_id,
    'tenant.platform_identity_binding.updated', p_binding_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_reason,
    jsonb_build_object(
      'key', locked_binding.key,
      'profile_priority', locked_binding.profile_priority,
      'enabled', false,
      'auth_revision', locked_binding.auth_revision,
      'mapping_revision', locked_binding.mapping_revision,
      'version', locked_binding.version
    ),
    jsonb_build_object(
      'key', p_key,
      'profile_priority', p_profile_priority,
      'enabled', false,
      'auth_revision', locked_binding.auth_revision,
      'mapping_revision', locked_binding.mapping_revision,
      'version', next_version
    )
  );
  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id,
    'platform.identity_binding.updated', 'platform_identity_binding',
    p_binding_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'tenant_id', locked_binding.tenant_id,
      'tenant_audit_event_id', p_tenant_audit_event_id,
      'platform_provider_id', p_platform_provider_id,
      'previous_profile_priority', locked_binding.profile_priority,
      'profile_priority', p_profile_priority,
      'enabled', false,
      'previous_version', locked_binding.version,
      'version', next_version
    )
  );
  result_document := app.private_tenant_platform_auth_provider_binding_document_v1(
    p_binding_id
  );
  RETURN QUERY SELECT next_version, result_document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.archive_tenant_platform_auth_provider_binding_v1(
  p_session_id uuid,
  p_platform_provider_id uuid,
  p_binding_id uuid,
  p_expected_version bigint,
  p_expected_tenant_version integer,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (version bigint, tenant_version integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid;
  target_tenant_id uuid;
  tenant_record public.tenants%ROWTYPE;
  locked_binding public.tenant_platform_auth_provider_bindings%ROWTYPE;
  next_version bigint;
BEGIN
  IF p_platform_provider_id IS NULL
     OR uuid_extract_version(p_platform_provider_id) IS DISTINCT FROM 7
     OR p_binding_id IS NULL OR uuid_extract_version(p_binding_id) IS DISTINCT FROM 7
     OR p_expected_version IS NULL OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_expected_tenant_version IS NULL
     OR p_expected_tenant_version NOT BETWEEN 1 AND 2147483647
     OR p_tenant_audit_event_id IS NULL
     OR uuid_extract_version(p_tenant_audit_event_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_tenant_audit_event_id = p_platform_audit_event_id
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id) IS DISTINCT FROM 7
     OR p_correlation_id IS NULL
     OR uuid_extract_version(p_correlation_id) IS DISTINCT FROM 7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR NOT app.private_platform_identity_text_is_safe_v1(p_user_agent, false)
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'tenant platform identity binding archive input is invalid'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id, 'platform.identity_binding.manage', p_authentication_method
  );
  SELECT binding.tenant_id INTO target_tenant_id
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.id = p_binding_id
    AND binding.platform_provider_id = p_platform_provider_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  PERFORM 1
  FROM ONLY public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = target_tenant_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT tenant.* INTO tenant_record
  FROM ONLY public.tenants AS tenant
  WHERE tenant.id = target_tenant_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF tenant_record.version <> p_expected_tenant_version THEN
    RAISE EXCEPTION 'tenant platform identity binding revision conflict'
      USING ERRCODE = '40001';
  END IF;
  SELECT binding.* INTO locked_binding
  FROM ONLY public.tenant_platform_auth_provider_bindings AS binding
  WHERE binding.id = p_binding_id
    AND binding.platform_provider_id = p_platform_provider_id
    AND binding.tenant_id = target_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant platform identity binding target does not exist'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_binding.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant platform identity binding is archived'
      USING ERRCODE = '55000';
  END IF;
  IF locked_binding.version <> p_expected_version THEN
    RAISE EXCEPTION 'tenant platform identity binding revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF locked_binding.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant platform identity binding revision is exhausted'
      USING ERRCODE = '55000';
  END IF;
  next_version := locked_binding.version + 1;
  UPDATE ONLY public.tenant_platform_auth_provider_bindings AS binding
  SET archived_at = transaction_timestamp(),
      archived_by_user_id = actor_id,
      archive_reason = p_reason,
      updated_by_user_id = actor_id,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE binding.id = p_binding_id;

  PERFORM app.private_append_platform_identity_binding_tenant_audit_v1(
    p_tenant_audit_event_id, locked_binding.tenant_id, actor_id,
    p_platform_audit_event_id, p_platform_provider_id,
    'tenant.platform_identity_binding.archived', p_binding_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_reason,
    jsonb_build_object(
      'archived', false,
      'enabled', false,
      'version', locked_binding.version
    ),
    jsonb_build_object(
      'archived', true,
      'enabled', false,
      'version', next_version
    )
  );
  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id, 'user', actor_id,
    'platform.identity_binding.archived', 'platform_identity_binding',
    p_binding_id, p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, 'success', p_reason,
    jsonb_build_object(
      'tenant_id', locked_binding.tenant_id,
      'tenant_audit_event_id', p_tenant_audit_event_id,
      'platform_provider_id', p_platform_provider_id,
      'enabled', false,
      'previous_version', locked_binding.version,
      'version', next_version
    )
  );
  RETURN QUERY SELECT next_version, tenant_record.version;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_auth_provider_login_key_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_create_tenant_auth_provider_login_claim_v1(uuid, text, uuid, text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_rename_tenant_auth_provider_login_claim_v1(uuid, text, uuid, text, text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_auth_provider_login_claim_child_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_auth_provider_binding_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_platform_auth_provider_binding_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_auth_provider_binding_dependency_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_platform_identity_provider_access_epoch_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_platform_identity_binding_command_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_tenant_platform_identity_binding_tenant_projection_v1() OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_tenant_platform_auth_provider_binding_document_v1(uuid) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_append_platform_identity_binding_tenant_audit_v1(uuid, uuid, uuid, uuid, uuid, text, uuid, uuid, uuid, inet, text, text, text, jsonb, jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_tenant_platform_auth_provider_bindings_v1(uuid, uuid, text, uuid, integer, boolean) OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, uuid, uuid, text, integer, bytea, bytea, uuid, uuid, uuid, uuid, inet, text, text, text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.update_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, bigint, integer, text, integer, uuid, uuid, uuid, uuid, inet, text, text, text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.archive_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, bigint, integer, uuid, uuid, uuid, uuid, inet, text, text, text) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION app.guard_tenant_auth_provider_login_key_v1(),
  app.private_create_tenant_auth_provider_login_claim_v1(uuid, text, uuid, text),
  app.private_rename_tenant_auth_provider_login_claim_v1(uuid, text, uuid, text, text),
  app.guard_tenant_auth_provider_login_claim_child_v1(),
  app.guard_tenant_platform_auth_provider_binding_v1(),
  app.guard_platform_auth_provider_binding_dependency_v1(),
  app.guard_tenant_platform_identity_provider_access_epoch_v1(),
  app.guard_tenant_platform_identity_binding_command_v1(),
  app.guard_tenant_platform_identity_binding_tenant_projection_v1(),
  app.private_tenant_platform_auth_provider_binding_document_v1(uuid),
  app.private_append_platform_identity_binding_tenant_audit_v1(uuid, uuid, uuid, uuid, uuid, text, uuid, uuid, uuid, inet, text, text, text, jsonb, jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner;
REVOKE ALL ON FUNCTION app.list_tenant_platform_auth_provider_bindings_v1(uuid, uuid, text, uuid, integer, boolean),
  app.get_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, text),
  app.create_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, uuid, uuid, text, integer, bytea, bytea, uuid, uuid, uuid, uuid, inet, text, text, text),
  app.update_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, bigint, integer, text, integer, uuid, uuid, uuid, uuid, inet, text, text, text),
  app.archive_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, bigint, integer, uuid, uuid, uuid, uuid, inet, text, text, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.list_tenant_platform_auth_provider_bindings_v1(uuid, uuid, text, uuid, integer, boolean),
  app.get_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, text),
  app.create_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, uuid, uuid, text, integer, bytea, bytea, uuid, uuid, uuid, uuid, inet, text, text, text),
  app.update_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, bigint, integer, text, integer, uuid, uuid, uuid, uuid, inet, text, text, text),
  app.archive_tenant_platform_auth_provider_binding_v1(uuid, uuid, uuid, bigint, integer, uuid, uuid, uuid, uuid, inet, text, text, text)
TO periapsis_api;
--> statement-breakpoint

-- Existing tenant-provider writers now reserve or rename the shared login
-- claim before touching their tenant-provider child.  Their HTTP-visible ABI
-- and LDAP epoch semantics remain unchanged.
CREATE OR REPLACE FUNCTION app.create_tenant_auth_provider_binding_v1(
  p_binding_id uuid,
  p_provider_id uuid,
  p_key text,
  p_enabled boolean,
  p_profile_priority integer,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (binding_id uuid, binding_version integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  new_source_id uuid;
  new_epoch_id uuid;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_binding_id IS NULL OR uuid_extract_version(p_binding_id) IS DISTINCT FROM 7
     OR p_enabled IS NULL
     OR p_key IS NULL OR p_key <> lower(btrim(p_key))
     OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_profile_priority IS NULL OR p_profile_priority NOT BETWEEN 0 AND 1000000 THEN
    RAISE EXCEPTION 'tenant auth-provider binding input is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM 1 FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
    AND provider.archived_at IS NULL
    AND (NOT p_enabled OR provider.enabled)
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'eligible tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;

  PERFORM app.private_create_tenant_auth_provider_login_claim_v1(
    context_tenant, 'tenant_provider', p_binding_id, p_key
  );
  INSERT INTO public.tenant_auth_provider_bindings (
    id, tenant_id, binding_family, provider_id, key, enabled, profile_priority,
    created_by_membership_id, updated_by_membership_id
  ) VALUES (
    p_binding_id, context_tenant, 'tenant_provider', p_provider_id, p_key,
    false, p_profile_priority, actor_membership, actor_membership
  );

  IF p_enabled THEN
    new_source_id := uuidv7();
    new_epoch_id := uuidv7();
    INSERT INTO public.tenant_authorization_sources (
      id, tenant_id, kind, key, authoritative, protected
    ) VALUES (
      new_source_id, context_tenant, 'identity_provider_access',
      format('identity_provider_access:%s:1', p_binding_id), true, false
    );
    INSERT INTO public.tenant_identity_provider_access_epochs (
      id, tenant_id, binding_id, provider_id, source_id, sequence,
      started_by_membership_id
    ) VALUES (
      new_epoch_id, context_tenant, p_binding_id, p_provider_id,
      new_source_id, 1, actor_membership
    );
    UPDATE public.tenant_auth_provider_bindings AS binding
    SET enabled = true, current_access_epoch_id = new_epoch_id
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
  END IF;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider_binding.created',
    'identity_provider_binding', p_binding_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'provider_id', p_provider_id, 'key', p_key, 'enabled', p_enabled,
      'profile_priority', p_profile_priority, 'auth_revision', 1,
      'access_epoch_sequence', CASE WHEN p_enabled THEN 1 ELSE NULL END,
      'version', 1
    ), '{}'::jsonb
  );
  RETURN QUERY SELECT p_binding_id, 1;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.create_tenant_auth_provider_binding_v2(
  p_idempotency_key_digest bytea,
  p_provider_id uuid,
  p_key text,
  p_enabled boolean,
  p_profile_priority integer,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_resource_id uuid,
  result_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  canonical_request_digest bytea;
  replay record;
  current_version integer;
  new_binding_id uuid;
  new_source_id uuid;
  new_epoch_id uuid;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32 THEN
    RAISE EXCEPTION 'idempotency key digest must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  IF p_enabled IS NULL OR p_key IS NULL OR p_key <> lower(btrim(p_key))
     OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_profile_priority IS NULL
     OR p_profile_priority NOT BETWEEN 0 AND 1000000 THEN
    RAISE EXCEPTION 'tenant auth-provider binding input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT sha256(convert_to(jsonb_build_object(
    'provider_id', p_provider_id,
    'key', p_key,
    'enabled', p_enabled,
    'profile_priority', p_profile_priority
  )::text, 'UTF8')) INTO canonical_request_digest;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || actor_membership::text ||
    encode(p_idempotency_key_digest, 'hex'), 0
  ));
  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_provider_binding.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();
  SELECT command.request_digest, command.result_resource_id
  INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'identity_provider_binding.create'
    AND command.key_digest = p_idempotency_key_digest;
  IF FOUND THEN
    IF replay.request_digest <> canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was reused with different binding input'
        USING ERRCODE = '23505';
    END IF;
    SELECT binding.version INTO current_version
    FROM public.tenant_auth_provider_bindings AS binding
    WHERE binding.tenant_id = context_tenant
      AND binding.id = replay.result_resource_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'idempotent binding result no longer exists'
        USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT replay.result_resource_id::uuid, current_version, true;
    RETURN;
  END IF;

  PERFORM 1 FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant AND provider.id = p_provider_id
    AND provider.kind = 'ldap' AND provider.archived_at IS NULL
    AND (NOT p_enabled OR provider.enabled)
  FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'eligible tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;

  new_binding_id := uuidv7();
  PERFORM app.private_create_tenant_auth_provider_login_claim_v1(
    context_tenant, 'tenant_provider', new_binding_id, p_key
  );
  INSERT INTO public.tenant_auth_provider_bindings (
    id, tenant_id, binding_family, provider_id, key, enabled,
    profile_priority, created_by_membership_id, updated_by_membership_id
  ) VALUES (
    new_binding_id, context_tenant, 'tenant_provider', p_provider_id, p_key,
    false, p_profile_priority, actor_membership, actor_membership
  );
  IF p_enabled THEN
    new_source_id := uuidv7();
    new_epoch_id := uuidv7();
    INSERT INTO public.tenant_authorization_sources (
      id, tenant_id, kind, key, authoritative, protected
    ) VALUES (
      new_source_id, context_tenant, 'identity_provider_access',
      format('identity_provider_access:%s:1', new_binding_id), true, false
    );
    INSERT INTO public.tenant_identity_provider_access_epochs (
      id, tenant_id, binding_id, provider_id, source_id, sequence,
      started_by_membership_id
    ) VALUES (
      new_epoch_id, context_tenant, new_binding_id, p_provider_id,
      new_source_id, 1, actor_membership
    );
    UPDATE public.tenant_auth_provider_bindings AS binding
    SET enabled = true, current_access_epoch_id = new_epoch_id
    WHERE binding.tenant_id = context_tenant AND binding.id = new_binding_id;
  END IF;
  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'identity_provider_binding.create',
    p_idempotency_key_digest, canonical_request_digest, new_binding_id, 1
  );
  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.identity_provider_binding.created',
    'identity_provider_binding', new_binding_id, p_request_id,
    p_correlation_id, p_ip_address, p_user_agent, p_authentication_method,
    NULL,
    jsonb_build_object(
      'provider_id', p_provider_id, 'key', p_key, 'enabled', p_enabled,
      'profile_priority', p_profile_priority, 'auth_revision', 1,
      'access_epoch_sequence', CASE WHEN p_enabled THEN 1 ELSE NULL END,
      'version', 1
    ), '{}'::jsonb
  );
  RETURN QUERY SELECT new_binding_id, 1, false;
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.update_tenant_auth_provider_binding_v1(
  p_binding_id uuid,
  p_expected_version integer,
  p_key text,
  p_enabled boolean,
  p_profile_priority integer,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_binding public.tenant_auth_provider_bindings%ROWTYPE;
  new_source_id uuid;
  new_epoch_id uuid;
  next_epoch_sequence integer;
  next_version integer;
  affected_membership_id uuid;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  SELECT binding.* INTO locked_binding
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant auth-provider binding was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_binding.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived tenant auth-provider binding cannot be changed'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_binding.version THEN
    RAISE EXCEPTION 'tenant auth-provider binding version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF p_enabled IS NULL
     OR p_key IS NULL OR p_key <> lower(btrim(p_key))
     OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_profile_priority IS NULL OR p_profile_priority NOT BETWEEN 0 AND 1000000
     OR locked_binding.version >= 2147483647
     OR locked_binding.auth_revision >= 2147483647 THEN
    RAISE EXCEPTION 'tenant auth-provider binding update is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_enabled AND NOT EXISTS (
    SELECT 1 FROM public.tenant_auth_providers AS provider
    WHERE provider.tenant_id = context_tenant
      AND provider.id = locked_binding.provider_id
      AND provider.kind = 'ldap'
      AND provider.enabled
      AND provider.archived_at IS NULL
    FOR KEY SHARE
  ) THEN
    RAISE EXCEPTION 'tenant LDAP provider is not enabled'
      USING ERRCODE = '55000';
  END IF;

  next_version := locked_binding.version + 1;
  PERFORM app.private_rename_tenant_auth_provider_login_claim_v1(
    context_tenant, 'tenant_provider', p_binding_id, locked_binding.key, p_key
  );
  IF locked_binding.enabled AND NOT p_enabled THEN
    UPDATE public.tenant_auth_provider_bindings AS binding
    SET key = p_key, enabled = false, profile_priority = p_profile_priority,
        auth_revision = binding.auth_revision + 1,
        current_access_epoch_id = NULL,
        updated_by_membership_id = actor_membership,
        version = next_version, updated_at = transaction_timestamp()
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
    PERFORM app.private_close_tenant_identity_access_epoch_v1(
      context_tenant, locked_binding.current_access_epoch_id,
      actor_membership, 'binding_disabled'
    );
  ELSIF NOT locked_binding.enabled AND p_enabled THEN
    SELECT coalesce(max(epoch.sequence), 0) + 1 INTO next_epoch_sequence
    FROM public.tenant_identity_provider_access_epochs AS epoch
    WHERE epoch.tenant_id = context_tenant AND epoch.binding_id = p_binding_id;
    new_source_id := uuidv7();
    new_epoch_id := uuidv7();
    INSERT INTO public.tenant_authorization_sources (
      id, tenant_id, kind, key, authoritative, protected
    ) VALUES (
      new_source_id, context_tenant, 'identity_provider_access',
      format('identity_provider_access:%s:%s', p_binding_id, next_epoch_sequence),
      true, false
    );
    INSERT INTO public.tenant_identity_provider_access_epochs (
      id, tenant_id, binding_id, provider_id, source_id, sequence,
      started_by_membership_id
    ) VALUES (
      new_epoch_id, context_tenant, p_binding_id, locked_binding.provider_id,
      new_source_id, next_epoch_sequence, actor_membership
    );
    UPDATE public.tenant_auth_provider_bindings AS binding
    SET key = p_key, enabled = true, profile_priority = p_profile_priority,
        auth_revision = binding.auth_revision + 1,
        current_access_epoch_id = new_epoch_id,
        updated_by_membership_id = actor_membership,
        version = next_version, updated_at = transaction_timestamp()
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
  ELSE
    UPDATE public.tenant_auth_provider_bindings AS binding
    SET key = p_key, profile_priority = p_profile_priority,
        auth_revision = binding.auth_revision + 1,
        updated_by_membership_id = actor_membership,
        version = next_version, updated_at = transaction_timestamp()
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
  END IF;

  IF p_profile_priority IS DISTINCT FROM locked_binding.profile_priority THEN
    FOR affected_membership_id IN
      SELECT DISTINCT access_grant.membership_id
      FROM public.tenant_ldap_provider_access_grants AS access_grant
      WHERE access_grant.tenant_id = context_tenant
        AND access_grant.binding_id = p_binding_id
        AND access_grant.ended_at IS NULL
    LOOP
      PERFORM app.private_materialize_tenant_user_profile_v1(
        context_tenant, affected_membership_id
      );
    END LOOP;
  END IF;
  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider_binding.updated',
    'identity_provider_binding', p_binding_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'key', locked_binding.key, 'enabled', locked_binding.enabled,
      'profile_priority', locked_binding.profile_priority,
      'auth_revision', locked_binding.auth_revision,
      'version', locked_binding.version
    ),
    jsonb_build_object(
      'key', p_key, 'enabled', p_enabled,
      'profile_priority', p_profile_priority,
      'auth_revision', locked_binding.auth_revision + 1,
      'access_epoch_sequence', next_epoch_sequence,
      'version', next_version
    ), '{}'::jsonb
  );
  RETURN next_version;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.create_tenant_auth_provider_binding_v1(uuid, uuid, text, boolean, integer, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_tenant_auth_provider_binding_v2(bytea, uuid, text, boolean, integer, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;
ALTER FUNCTION app.update_tenant_auth_provider_binding_v1(uuid, integer, text, boolean, integer, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.create_tenant_auth_provider_binding_v1(uuid, uuid, text, boolean, integer, uuid, uuid, inet, text, text),
  app.create_tenant_auth_provider_binding_v2(bytea, uuid, text, boolean, integer, uuid, uuid, uuid, inet, text, text),
  app.update_tenant_auth_provider_binding_v1(uuid, integer, text, boolean, integer, uuid, uuid, inet, text, text)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner;
GRANT EXECUTE ON FUNCTION app.create_tenant_auth_provider_binding_v1(uuid, uuid, text, boolean, integer, uuid, uuid, inet, text, text),
  app.create_tenant_auth_provider_binding_v2(bytea, uuid, text, boolean, integer, uuid, uuid, uuid, inet, text, text),
  app.update_tenant_auth_provider_binding_v1(uuid, integer, text, boolean, integer, uuid, uuid, inet, text, text)
TO periapsis_api;
