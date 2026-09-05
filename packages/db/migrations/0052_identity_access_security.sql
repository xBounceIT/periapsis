-- Tenant LDAP admission is intentionally inaccessible through direct table
-- privileges. Every runtime mutation goes through a bounded SECURITY DEFINER
-- ABI that rechecks the tenant human permission and owns the source epoch.
ALTER TYPE public.authorization_source_kind OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_auth_provider_bindings OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_identity_provider_access_epochs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_external_identities OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_external_identity_subject_aliases OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_access_grants OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_profile_contributions OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_user_manual_profile_overrides OWNER TO periapsis_migrator;--> statement-breakpoint

ALTER TABLE public.tenant_auth_provider_bindings FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_identity_provider_access_epochs FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_external_identities FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_external_identity_subject_aliases FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_access_grants FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_profile_contributions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.tenant_user_manual_profile_overrides FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TABLE public.tenant_auth_provider_bindings FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_identity_provider_access_epochs FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_external_identities FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_external_identity_subject_aliases FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_provider_access_grants FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_provider_profile_contributions FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_user_manual_profile_overrides FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

-- An enabled binding must point at its own exact, live epoch and source. The
-- source kind is checked here because a composite FK alone cannot constrain an
-- enum discriminator in tenant_authorization_sources.
CREATE FUNCTION app.guard_tenant_auth_provider_binding_v1()
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

  IF NEW.enabled AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_identity_provider_access_epochs AS epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = epoch.tenant_id
     AND source.id = epoch.source_id
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
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_auth_provider_bindings_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_auth_provider_bindings
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_auth_provider_binding_v1();--> statement-breakpoint

-- Epoch identity, order, provider and source never change. The only legal
-- update is the single terminal transition from live version 1 to ended
-- version 2, after the binding has detached the epoch.
CREATE FUNCTION app.guard_tenant_identity_provider_access_epoch_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'identity-provider access epochs are append-only'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_authorization_sources AS source
      WHERE source.tenant_id = NEW.tenant_id
        AND source.id = NEW.source_id
        AND source.kind = 'identity_provider_access'
        AND source.authoritative
        AND NOT source.protected
        AND source.retired_at IS NULL
        AND source.key = format(
          'identity_provider_access:%s:%s', NEW.binding_id, NEW.sequence
        )
    ) THEN
      RAISE EXCEPTION 'identity-provider access epoch source is invalid'
        USING ERRCODE = '23514',
              CONSTRAINT = 'tenant_identity_provider_access_epochs_source_kind_check';
    END IF;
    RETURN NEW;
  END IF;

  IF ROW(
    NEW.id, NEW.tenant_id, NEW.binding_id, NEW.provider_id, NEW.source_id,
    NEW.sequence, NEW.started_by_membership_id, NEW.started_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.binding_id, OLD.provider_id, OLD.source_id,
    OLD.sequence, OLD.started_by_membership_id, OLD.started_at
  ) OR OLD.ended_at IS NOT NULL
    OR NEW.ended_at IS NULL
    OR NEW.ended_by_membership_id IS NULL
    OR NEW.end_reason IS NULL
    OR NEW.version <> 2
    OR EXISTS (
      SELECT 1
      FROM public.tenant_auth_provider_bindings AS binding
      WHERE binding.tenant_id = OLD.tenant_id
        AND binding.id = OLD.binding_id
        AND binding.current_access_epoch_id = OLD.id
    ) THEN
    RAISE EXCEPTION 'identity-provider access epoch transition is invalid'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_identity_provider_access_epochs_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_identity_provider_access_epochs
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_identity_provider_access_epoch_v1();--> statement-breakpoint

-- Provider shutdown may not strand a live binding/source epoch. Administrators
-- close or archive the binding first; all operations remain in one transaction.
CREATE FUNCTION app.guard_tenant_auth_provider_binding_dependency_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF (TG_OP = 'DELETE'
      OR (OLD.enabled AND NOT NEW.enabled)
      OR (OLD.archived_at IS NULL AND NEW.archived_at IS NOT NULL))
     AND EXISTS (
       SELECT 1
       FROM public.tenant_auth_provider_bindings AS binding
       WHERE binding.tenant_id = OLD.tenant_id
         AND binding.provider_id = OLD.id
         AND binding.enabled
     ) THEN
    RAISE EXCEPTION 'disable the tenant auth-provider binding before disabling or archiving its provider'
      USING ERRCODE = '55000';
  END IF;
  RETURN CASE WHEN TG_OP = 'DELETE' THEN OLD ELSE NEW END;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_auth_providers_binding_dependency_v1
BEFORE UPDATE OF enabled, archived_at OR DELETE ON public.tenant_auth_providers
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_auth_provider_binding_dependency_v1();--> statement-breakpoint

-- Immutable-subject linkage cannot be rewritten to another provider or User.
-- Ciphertext/key changes are retained for the later guarded lazy-rotation ABI.
CREATE FUNCTION app.guard_tenant_ldap_external_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP external identities are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.identity_keyring_versions AS keyring
      WHERE keyring.key_version = NEW.key_version
        AND keyring.is_active
        AND keyring.retired_at IS NULL
    ) OR NOT EXISTS (
      SELECT 1
      FROM public.tenant_auth_providers AS provider
      WHERE provider.tenant_id = NEW.tenant_id
        AND provider.id = NEW.provider_id
        AND provider.kind = 'ldap'
        AND provider.enabled
        AND provider.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'tenant LDAP external identity requires a live provider and active subject key'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.key_version IS DISTINCT FROM OLD.key_version
     OR NEW.subject_ciphertext IS DISTINCT FROM OLD.subject_ciphertext
     OR NEW.subject_nonce IS DISTINCT FROM OLD.subject_nonce THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.identity_keyring_versions AS keyring
      WHERE keyring.key_version = NEW.key_version
        AND keyring.is_active
        AND keyring.retired_at IS NULL
    ) THEN
      RAISE EXCEPTION 'tenant LDAP external identity must use the active subject key'
        USING ERRCODE = '55000';
    END IF;
  END IF;
  IF TG_OP = 'UPDATE' AND ROW(
    NEW.id, NEW.tenant_id, NEW.provider_id, NEW.user_id,
    NEW.subject_format, NEW.admitted_configuration_version, NEW.admitted_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.provider_id, OLD.user_id,
    OLD.subject_format, OLD.admitted_configuration_version, OLD.admitted_at
  ) THEN
    RAISE EXCEPTION 'tenant LDAP external identity linkage is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'UPDATE' AND OLD.retired_at IS NOT NULL THEN
    RAISE EXCEPTION 'retired tenant LDAP external identity cannot be changed'
      USING ERRCODE = '55000';
  END IF;
  IF OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL AND EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_access_grants AS access_grant
    WHERE access_grant.tenant_id = OLD.tenant_id
      AND access_grant.external_identity_id = OLD.id
      AND access_grant.ended_at IS NULL
  ) THEN
    RAISE EXCEPTION 'end tenant LDAP provider access before retiring its external identity'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_external_identities_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_external_identities
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_external_identity_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_subject_alias_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP subject aliases are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.identity_keyring_versions AS keyring
      WHERE keyring.key_version = NEW.digest_key_version
        AND keyring.is_active
        AND keyring.retired_at IS NULL
    ) OR NOT EXISTS (
      SELECT 1
      FROM public.tenant_ldap_external_identities AS identity
      WHERE identity.tenant_id = NEW.tenant_id
        AND identity.provider_id = NEW.provider_id
        AND identity.id = NEW.external_identity_id
        AND identity.retired_at IS NULL
    ) THEN
      RAISE EXCEPTION 'tenant LDAP subject alias has no live identity and active digest key'
        USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
    NEW.id, NEW.tenant_id, NEW.provider_id, NEW.external_identity_id,
    NEW.digest_key_version, NEW.subject_digest, NEW.created_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.provider_id, OLD.external_identity_id,
    OLD.digest_key_version, OLD.subject_digest, OLD.created_at
  ) OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL THEN
    RAISE EXCEPTION 'tenant LDAP subject alias transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_external_identity_subject_aliases_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_external_identity_subject_aliases
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_subject_alias_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_provider_access_grant_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP provider access grants are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_auth_provider_bindings AS binding
      JOIN public.tenant_identity_provider_access_epochs AS epoch
        ON epoch.tenant_id = binding.tenant_id
       AND epoch.id = binding.current_access_epoch_id
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = epoch.tenant_id
       AND source.id = epoch.source_id
      JOIN public.tenant_ldap_external_identities AS identity
        ON identity.tenant_id = NEW.tenant_id
       AND identity.provider_id = NEW.provider_id
       AND identity.id = NEW.external_identity_id
       AND identity.user_id = NEW.user_id
      JOIN public.tenant_memberships AS membership
        ON membership.tenant_id = NEW.tenant_id
       AND membership.id = NEW.membership_id
       AND membership.user_id = NEW.user_id
      JOIN public.users AS admitted_user
        ON admitted_user.id = NEW.user_id
      JOIN public.tenants AS tenant
        ON tenant.id = NEW.tenant_id
      WHERE binding.tenant_id = NEW.tenant_id
        AND binding.id = NEW.binding_id
        AND binding.provider_id = NEW.provider_id
        AND binding.enabled
        AND binding.archived_at IS NULL
        AND epoch.id = NEW.access_epoch_id
        AND epoch.source_id = NEW.source_id
        AND epoch.ended_at IS NULL
        AND source.kind = 'identity_provider_access'
        AND source.retired_at IS NULL
        AND identity.retired_at IS NULL
        AND membership.status = 'active'
        AND admitted_user.active
        AND tenant.status = 'active'
    ) THEN
      RAISE EXCEPTION 'tenant LDAP provider access grant has no live exact source path'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
    NEW.id, NEW.tenant_id, NEW.provider_id, NEW.binding_id,
    NEW.access_epoch_id, NEW.source_id, NEW.external_identity_id,
    NEW.membership_id, NEW.user_id, NEW.started_at
  ) IS DISTINCT FROM ROW(
    OLD.id, OLD.tenant_id, OLD.provider_id, OLD.binding_id,
    OLD.access_epoch_id, OLD.source_id, OLD.external_identity_id,
    OLD.membership_id, OLD.user_id, OLD.started_at
  ) OR OLD.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant LDAP provider access grant linkage is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_provider_access_grants_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_provider_access_grants
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_provider_access_grant_v1();--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_ldap_provider_profile_contribution_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP profile contributions are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_ldap_provider_access_grants AS access_grant
      JOIN public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id = access_grant.tenant_id
       AND binding.id = access_grant.binding_id
       AND binding.provider_id = access_grant.provider_id
       AND binding.current_access_epoch_id = access_grant.access_epoch_id
      JOIN public.tenant_auth_providers AS provider
        ON provider.tenant_id = binding.tenant_id
       AND provider.id = binding.provider_id
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = access_grant.tenant_id
       AND source.id = access_grant.source_id
      JOIN public.tenant_ldap_external_identities AS external_identity
        ON external_identity.tenant_id = access_grant.tenant_id
       AND external_identity.provider_id = access_grant.provider_id
       AND external_identity.id = access_grant.external_identity_id
      WHERE access_grant.tenant_id = NEW.tenant_id
        AND access_grant.id = NEW.access_grant_id
        AND access_grant.ended_at IS NULL
        AND NEW.observed_at >= access_grant.started_at
        AND binding.enabled
        AND binding.archived_at IS NULL
        AND provider.kind = 'ldap'
        AND provider.enabled
        AND provider.archived_at IS NULL
        AND source.kind = 'identity_provider_access'
        AND source.retired_at IS NULL
        AND external_identity.retired_at IS NULL
    ) THEN
      RAISE EXCEPTION 'tenant LDAP profile contribution has no live provider access path'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE' AND (
    ROW(
      NEW.id, NEW.tenant_id, NEW.access_grant_id, NEW.display_name,
      NEW.first_name, NEW.last_name, NEW.username, NEW.email,
      NEW.configuration_version, NEW.observed_at
    ) IS DISTINCT FROM ROW(
      OLD.id, OLD.tenant_id, OLD.access_grant_id, OLD.display_name,
      OLD.first_name, OLD.last_name, OLD.username, OLD.email,
      OLD.configuration_version, OLD.observed_at
    ) OR OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'tenant LDAP profile contribution transition is invalid'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_provider_profile_contributions_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.tenant_ldap_provider_profile_contributions
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_ldap_provider_profile_contribution_v1();--> statement-breakpoint

-- Effective tenant profiles are materialized field-by-field. A non-null manual
-- value wins; otherwise the lowest (profile_priority, binding_id) live provider
-- contribution wins; finally the stable global identity supplies local fallback.
CREATE FUNCTION app.private_materialize_tenant_user_profile_v1(
  p_tenant_id uuid,
  p_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target_user_id uuid;
  effective_display_name text;
  effective_first_name text;
  effective_last_name text;
  effective_username text;
  effective_email text;
BEGIN
  SELECT membership.user_id
  INTO target_user_id
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = p_tenant_id
    AND membership.id = p_membership_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant membership was not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT
    coalesce(
      manual.display_name, provider_profile.display_name, identity.display_name
    ),
    coalesce(
      manual.first_name, provider_profile.first_name, identity.first_name
    ),
    coalesce(
      manual.last_name, provider_profile.last_name, identity.last_name
    ),
    coalesce(manual.username, provider_profile.username),
    coalesce(manual.email, provider_profile.email, identity.email)
  INTO effective_display_name, effective_first_name, effective_last_name,
       effective_username, effective_email
  FROM public.users AS identity
  LEFT JOIN public.tenant_user_manual_profile_overrides AS manual
    ON manual.tenant_id = p_tenant_id
   AND manual.membership_id = p_membership_id
   AND manual.user_id = identity.id
  LEFT JOIN LATERAL (
    SELECT
      (array_agg(
        contribution.display_name
        ORDER BY binding.profile_priority, binding.id
      ) FILTER (WHERE contribution.display_name IS NOT NULL))[1] AS display_name,
      (array_agg(
        contribution.first_name
        ORDER BY binding.profile_priority, binding.id
      ) FILTER (WHERE contribution.first_name IS NOT NULL))[1] AS first_name,
      (array_agg(
        contribution.last_name
        ORDER BY binding.profile_priority, binding.id
      ) FILTER (WHERE contribution.last_name IS NOT NULL))[1] AS last_name,
      (array_agg(
        contribution.username
        ORDER BY binding.profile_priority, binding.id
      ) FILTER (WHERE contribution.username IS NOT NULL))[1] AS username,
      (array_agg(
        contribution.email
        ORDER BY binding.profile_priority, binding.id
      ) FILTER (WHERE contribution.email IS NOT NULL))[1] AS email
    FROM public.tenant_ldap_provider_profile_contributions AS contribution
    JOIN public.tenant_ldap_provider_access_grants AS access_grant
      ON access_grant.tenant_id = contribution.tenant_id
     AND access_grant.id = contribution.access_grant_id
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = access_grant.tenant_id
     AND binding.id = access_grant.binding_id
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id = binding.tenant_id
     AND provider.id = binding.provider_id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = access_grant.tenant_id
     AND source.id = access_grant.source_id
    JOIN public.tenant_ldap_external_identities AS external_identity
      ON external_identity.tenant_id = access_grant.tenant_id
     AND external_identity.provider_id = access_grant.provider_id
     AND external_identity.id = access_grant.external_identity_id
     AND external_identity.retired_at IS NULL
    WHERE access_grant.tenant_id = p_tenant_id
      AND access_grant.membership_id = p_membership_id
      AND access_grant.ended_at IS NULL
      AND contribution.retired_at IS NULL
      AND binding.enabled
      AND binding.archived_at IS NULL
      AND provider.enabled
      AND provider.archived_at IS NULL
      AND source.kind = 'identity_provider_access'
      AND source.retired_at IS NULL
  ) AS provider_profile ON true
  WHERE identity.id = target_user_id;

  INSERT INTO public.tenant_user_profiles (
    tenant_id, membership_id, user_id, display_name, first_name, last_name,
    username, email
  ) VALUES (
    p_tenant_id, p_membership_id, target_user_id, effective_display_name,
    effective_first_name, effective_last_name, effective_username, effective_email
  )
  ON CONFLICT (tenant_id, membership_id) DO UPDATE
  SET display_name = EXCLUDED.display_name,
      first_name = EXCLUDED.first_name,
      last_name = EXCLUDED.last_name,
      username = EXCLUDED.username,
      email = EXCLUDED.email,
      version = tenant_user_profiles.version + 1,
      updated_at = transaction_timestamp();
END;
$function$;--> statement-breakpoint

-- Close one exact epoch after the binding has atomically detached it. Only
-- provider-owned grants/contributions are ended; the membership aggregate and
-- every manual or unrelated source remain untouched.
CREATE FUNCTION app.private_close_tenant_identity_access_epoch_v1(
  p_tenant_id uuid,
  p_epoch_id uuid,
  p_actor_membership_id uuid,
  p_reason text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  locked_epoch public.tenant_identity_provider_access_epochs%ROWTYPE;
  affected_membership_ids uuid[];
  affected_membership_id uuid;
BEGIN
  SELECT epoch.* INTO locked_epoch
  FROM public.tenant_identity_provider_access_epochs AS epoch
  WHERE epoch.tenant_id = p_tenant_id AND epoch.id = p_epoch_id
  FOR UPDATE;
  IF NOT FOUND OR locked_epoch.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'live identity-provider access epoch was not found'
      USING ERRCODE = '55000';
  END IF;

  SELECT array_agg(DISTINCT access_grant.membership_id)
  INTO affected_membership_ids
  FROM public.tenant_ldap_provider_access_grants AS access_grant
  WHERE access_grant.tenant_id = p_tenant_id
    AND access_grant.access_epoch_id = p_epoch_id
    AND access_grant.ended_at IS NULL;

  UPDATE public.tenant_ldap_provider_profile_contributions AS contribution
  SET retired_at = transaction_timestamp(),
      retire_reason = p_reason,
      version = contribution.version + 1,
      updated_at = transaction_timestamp()
  FROM public.tenant_ldap_provider_access_grants AS access_grant
  WHERE contribution.tenant_id = p_tenant_id
    AND contribution.retired_at IS NULL
    AND access_grant.tenant_id = contribution.tenant_id
    AND access_grant.id = contribution.access_grant_id
    AND access_grant.access_epoch_id = p_epoch_id;

  UPDATE public.tenant_ldap_provider_access_grants AS access_grant
  SET ended_at = transaction_timestamp(),
      end_reason = p_reason,
      version = access_grant.version + 1,
      updated_at = transaction_timestamp()
  WHERE access_grant.tenant_id = p_tenant_id
    AND access_grant.access_epoch_id = p_epoch_id
    AND access_grant.ended_at IS NULL;

  FOREACH affected_membership_id IN ARRAY coalesce(
    affected_membership_ids, ARRAY[]::uuid[]
  ) LOOP
    PERFORM app.private_materialize_tenant_user_profile_v1(
      p_tenant_id, affected_membership_id
    );
  END LOOP;

  UPDATE public.tenant_identity_provider_access_epochs AS epoch
  SET ended_at = transaction_timestamp(),
      ended_by_membership_id = p_actor_membership_id,
      end_reason = p_reason,
      version = 2
  WHERE epoch.tenant_id = p_tenant_id AND epoch.id = p_epoch_id;

  UPDATE public.tenant_authorization_sources AS source
  SET retired_at = transaction_timestamp()
  WHERE source.tenant_id = p_tenant_id
    AND source.id = locked_epoch.source_id
    AND source.kind = 'identity_provider_access'
    AND source.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'identity-provider access source could not be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.list_tenant_auth_provider_bindings_v1(
  p_after_id uuid,
  p_include_archived boolean,
  p_limit integer
)
RETURNS TABLE (
  id uuid,
  provider_id uuid,
  key text,
  enabled boolean,
  profile_priority integer,
  auth_revision integer,
  current_access_epoch_id uuid,
  archived_at timestamptz,
  version integer,
  created_at timestamptz,
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
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_archived IS NULL
     OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 THEN
    RAISE EXCEPTION 'binding page limit is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT binding.id, binding.provider_id, binding.key, binding.enabled,
         binding.profile_priority, binding.auth_revision,
         binding.current_access_epoch_id, binding.archived_at,
         binding.version, binding.created_at, binding.updated_at
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = context_tenant
    AND (p_include_archived OR binding.archived_at IS NULL)
    AND (p_after_id IS NULL OR binding.id > p_after_id)
  ORDER BY binding.id
  LIMIT p_limit;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_auth_provider_binding_v1(p_binding_id uuid)
RETURNS TABLE (
  id uuid,
  provider_id uuid,
  key text,
  enabled boolean,
  profile_priority integer,
  auth_revision integer,
  current_access_epoch_id uuid,
  archived_at timestamptz,
  version integer,
  created_at timestamptz,
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
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.read', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.read tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT binding.id, binding.provider_id, binding.key, binding.enabled,
         binding.profile_priority, binding.auth_revision,
         binding.current_access_epoch_id, binding.archived_at,
         binding.version, binding.created_at, binding.updated_at
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_auth_provider_binding_v1(
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
  IF p_binding_id IS NULL OR (uuid_extract_version(p_binding_id) = 7) IS NOT TRUE
     OR p_enabled IS NULL
     OR p_key IS NULL OR p_key <> lower(btrim(p_key))
     OR p_key !~ '^[a-z][a-z0-9_-]{2,63}$'
     OR p_profile_priority IS NULL OR p_profile_priority NOT BETWEEN 0 AND 1000000 THEN
    RAISE EXCEPTION 'tenant auth-provider binding input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_auth_providers AS provider
    WHERE provider.tenant_id = context_tenant
      AND provider.id = p_provider_id
      AND provider.kind = 'ldap'
      AND provider.archived_at IS NULL
      AND (NOT p_enabled OR provider.enabled)
    FOR KEY SHARE
  ) THEN
    RAISE EXCEPTION 'eligible tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;

  INSERT INTO public.tenant_auth_provider_bindings (
    id, tenant_id, provider_id, key, enabled, profile_priority,
    created_by_membership_id, updated_by_membership_id
  ) VALUES (
    p_binding_id, context_tenant, p_provider_id, p_key, false,
    p_profile_priority, actor_membership, actor_membership
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
    SET enabled = true,
        current_access_epoch_id = new_epoch_id
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
  END IF;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider_binding.created',
    'identity_provider_binding', p_binding_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    NULL,
    jsonb_build_object(
      'provider_id', p_provider_id, 'key', p_key, 'enabled', p_enabled,
      'profile_priority', p_profile_priority, 'auth_revision', 1,
      'access_epoch_sequence', CASE WHEN p_enabled THEN 1 ELSE NULL END,
      'version', 1
    ),
    '{}'::jsonb
  );

  RETURN QUERY SELECT p_binding_id, 1;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.update_tenant_auth_provider_binding_v1(
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
  IF locked_binding.enabled AND NOT p_enabled THEN
    UPDATE public.tenant_auth_provider_bindings AS binding
    SET key = p_key,
        enabled = false,
        profile_priority = p_profile_priority,
        auth_revision = binding.auth_revision + 1,
        current_access_epoch_id = NULL,
        updated_by_membership_id = actor_membership,
        version = next_version,
        updated_at = transaction_timestamp()
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
    PERFORM app.private_close_tenant_identity_access_epoch_v1(
      context_tenant, locked_binding.current_access_epoch_id,
      actor_membership, 'binding_disabled'
    );
  ELSIF NOT locked_binding.enabled AND p_enabled THEN
    SELECT coalesce(max(epoch.sequence), 0) + 1
    INTO next_epoch_sequence
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
    SET key = p_key,
        enabled = true,
        profile_priority = p_profile_priority,
        auth_revision = binding.auth_revision + 1,
        current_access_epoch_id = new_epoch_id,
        updated_by_membership_id = actor_membership,
        version = next_version,
        updated_at = transaction_timestamp()
    WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;
  ELSE
    UPDATE public.tenant_auth_provider_bindings AS binding
    SET key = p_key,
        profile_priority = p_profile_priority,
        auth_revision = binding.auth_revision + 1,
        updated_by_membership_id = actor_membership,
        version = next_version,
        updated_at = transaction_timestamp()
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
    ),
    '{}'::jsonb
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.archive_tenant_auth_provider_binding_v1(
  p_binding_id uuid,
  p_expected_version integer,
  p_reason text,
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
  next_version integer;
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
    RAISE EXCEPTION 'tenant auth-provider binding is already archived'
      USING ERRCODE = '55000';
  END IF;
  IF p_expected_version IS NULL OR p_expected_version <> locked_binding.version THEN
    RAISE EXCEPTION 'tenant auth-provider binding version does not match'
      USING ERRCODE = '40001';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = '' OR char_length(p_reason) > 500
     OR p_reason ~ '[[:cntrl:]]' OR locked_binding.version >= 2147483647
     OR locked_binding.auth_revision >= 2147483647 THEN
    RAISE EXCEPTION 'tenant auth-provider binding archive input is invalid'
      USING ERRCODE = '22023';
  END IF;

  next_version := locked_binding.version + 1;
  UPDATE public.tenant_auth_provider_bindings AS binding
  SET enabled = false,
      current_access_epoch_id = NULL,
      auth_revision = binding.auth_revision + 1,
      archived_at = transaction_timestamp(),
      archived_by_membership_id = actor_membership,
      archive_reason = p_reason,
      updated_by_membership_id = actor_membership,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE binding.tenant_id = context_tenant AND binding.id = p_binding_id;

  IF locked_binding.current_access_epoch_id IS NOT NULL THEN
    PERFORM app.private_close_tenant_identity_access_epoch_v1(
      context_tenant, locked_binding.current_access_epoch_id,
      actor_membership, 'binding_archived'
    );
  END IF;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider_binding.archived',
    'identity_provider_binding', p_binding_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'enabled', locked_binding.enabled, 'archived', false,
      'auth_revision', locked_binding.auth_revision,
      'version', locked_binding.version
    ),
    jsonb_build_object(
      'enabled', false, 'archived', true,
      'auth_revision', locked_binding.auth_revision + 1,
      'version', next_version
    ),
    jsonb_build_object('reason', p_reason)
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

-- v2 binds every configured key and verifies both reversible subject
-- ciphertext and every live subject-digest alias without exposing either.
CREATE FUNCTION app.verify_identity_keyring_v2(
  p_versions integer[],
  p_verifiers bytea[],
  p_active_version integer
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  item_count integer;
  item_index integer;
  existing_verifier bytea;
  installed_active_version integer;
BEGIN
  item_count := coalesce(array_length(p_versions, 1), 0);
  IF item_count < 1 OR item_count > 16
     OR coalesce(array_length(p_verifiers, 1), 0) <> item_count
     OR p_active_version IS NULL OR NOT p_active_version = ANY(p_versions) THEN
    RETURN false;
  END IF;
  FOR item_index IN 1..item_count LOOP
    IF p_versions[item_index] IS NULL
       OR p_versions[item_index] NOT BETWEEN 1 AND 32767
       OR p_verifiers[item_index] IS NULL
       OR octet_length(p_verifiers[item_index]) <> 32
       OR (item_index > 1 AND p_versions[item_index - 1] >= p_versions[item_index]) THEN
      RETURN false;
    END IF;
  END LOOP;

  LOCK TABLE public.identity_keyring_versions IN SHARE ROW EXCLUSIVE MODE;
  FOR item_index IN 1..item_count LOOP
    INSERT INTO public.identity_keyring_versions (
      key_version, verifier, is_active, bound_at
    ) VALUES (
      p_versions[item_index], p_verifiers[item_index], false,
      transaction_timestamp()
    ) ON CONFLICT (key_version) DO NOTHING;
    SELECT keyring.verifier INTO existing_verifier
    FROM public.identity_keyring_versions AS keyring
    WHERE keyring.key_version = p_versions[item_index]
      AND keyring.retired_at IS NULL;
    IF existing_verifier IS NULL OR existing_verifier <> p_verifiers[item_index] THEN
      RETURN false;
    END IF;
  END LOOP;

  SELECT keyring.key_version INTO installed_active_version
  FROM public.identity_keyring_versions AS keyring WHERE keyring.is_active;
  IF installed_active_version IS NOT NULL
     AND installed_active_version <> p_active_version THEN
    RETURN false;
  END IF;
  IF installed_active_version IS NULL THEN
    UPDATE public.identity_keyring_versions AS keyring
    SET is_active = true
    WHERE keyring.key_version = p_active_version
      AND keyring.retired_at IS NULL;
    IF NOT FOUND THEN RETURN false; END IF;
  END IF;

  IF EXISTS (
    SELECT 1 FROM public.tenant_ldap_provider_secrets AS secret
    WHERE NOT secret.key_version = ANY(p_versions)
  ) OR EXISTS (
    SELECT 1 FROM public.tenant_ldap_external_identities AS identity
    WHERE NOT identity.key_version = ANY(p_versions)
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_external_identity_subject_aliases AS alias
    WHERE alias.retired_at IS NULL
      AND NOT alias.digest_key_version = ANY(p_versions)
  ) OR EXISTS (
    SELECT 1
    FROM public.tenant_ldap_external_identities AS identity
    WHERE identity.retired_at IS NULL
      AND NOT EXISTS (
        SELECT 1
        FROM public.tenant_ldap_external_identity_subject_aliases AS alias
        WHERE alias.tenant_id = identity.tenant_id
          AND alias.provider_id = identity.provider_id
          AND alias.external_identity_id = identity.id
          AND alias.retired_at IS NULL
          AND alias.digest_key_version = ANY(p_versions)
      )
  ) THEN
    RETURN false;
  END IF;

  RETURN EXISTS (
    SELECT 1 FROM public.identity_keyring_versions AS active_key
    WHERE active_key.key_version = p_active_version
      AND active_key.is_active
      AND active_key.retired_at IS NULL
      AND active_key.verifier = p_verifiers[
        array_position(p_versions, p_active_version)
      ]
  );
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_auth_provider_binding_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_identity_provider_access_epoch_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_auth_provider_binding_dependency_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_external_identity_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_subject_alias_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_provider_access_grant_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_ldap_provider_profile_contribution_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_materialize_tenant_user_profile_v1(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_close_tenant_identity_access_epoch_v1(uuid, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.list_tenant_auth_provider_bindings_v1(uuid, boolean, integer) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_auth_provider_binding_v1(uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_auth_provider_binding_v1(uuid, uuid, text, boolean, integer, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.update_tenant_auth_provider_binding_v1(uuid, integer, text, boolean, integer, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.archive_tenant_auth_provider_binding_v1(uuid, integer, text, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.verify_identity_keyring_v2(integer[], bytea[], integer) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.guard_tenant_auth_provider_binding_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_identity_provider_access_epoch_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_auth_provider_binding_dependency_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_external_identity_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_subject_alias_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_provider_access_grant_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_ldap_provider_profile_contribution_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_materialize_tenant_user_profile_v1(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_close_tenant_identity_access_epoch_v1(uuid, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_auth_provider_bindings_v1(uuid, boolean, integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_auth_provider_binding_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_auth_provider_binding_v1(uuid, uuid, text, boolean, integer, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.update_tenant_auth_provider_binding_v1(uuid, integer, text, boolean, integer, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.archive_tenant_auth_provider_binding_v1(uuid, integer, text, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_identity_keyring_v2(integer[], bytea[], integer) FROM PUBLIC, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.list_tenant_auth_provider_bindings_v1(uuid, boolean, integer) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_auth_provider_binding_v1(uuid) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_auth_provider_binding_v1(uuid, uuid, text, boolean, integer, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.update_tenant_auth_provider_binding_v1(uuid, integer, text, boolean, integer, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.archive_tenant_auth_provider_binding_v1(uuid, integer, text, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.verify_identity_keyring_v2(integer[], bytea[], integer) TO periapsis_api, periapsis_worker;
