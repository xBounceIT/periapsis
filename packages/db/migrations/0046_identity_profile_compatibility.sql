-- Preserve the platform tenant-creation ABI while making the new tenant
-- profile projection part of the same transaction as its membership. During
-- the rolling bridge, platform tenant creation remains local-identity-only;
-- future external platform identities will replace this wrapper with an
-- explicit profile contribution rather than inventing an email.
ALTER FUNCTION app.create_platform_tenant(
  uuid, uuid, text, text, text, text,
  uuid, uuid, uuid, inet, text, text
) RENAME TO create_platform_tenant_identity_profile_compatibility_impl;--> statement-breakpoint

ALTER FUNCTION app.create_platform_tenant_identity_profile_compatibility_impl(
  uuid, uuid, text, text, text, text,
  uuid, uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_platform_tenant_identity_profile_compatibility_impl(
  uuid, uuid, text, text, text, text,
  uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.create_platform_tenant(
  p_tenant_id uuid,
  p_membership_id uuid,
  p_slug text,
  p_name text,
  p_timezone text,
  p_locale text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  id uuid,
  slug text,
  name text,
  status public.tenant_status,
  timezone text,
  locale text,
  version integer,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RETURN QUERY
  SELECT created.*
  FROM app.create_platform_tenant_identity_profile_compatibility_impl(
    p_tenant_id,
    p_membership_id,
    p_slug,
    p_name,
    p_timezone,
    p_locale,
    p_platform_audit_event_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method
  ) AS created;

  INSERT INTO public.tenant_user_profiles (
    tenant_id,
    membership_id,
    user_id,
    display_name,
    email
  )
  SELECT membership.tenant_id,
         membership.id,
         membership.user_id,
         identity.display_name,
         coalesce(login_identifier.canonical_value, identity.email)
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity
    ON identity.id = membership.user_id
  LEFT JOIN public.user_login_identifiers AS login_identifier
    ON login_identifier.user_id = identity.id
   AND login_identifier.kind = 'local_email'
   AND login_identifier.verified_at IS NOT NULL
   AND login_identifier.retired_at IS NULL
  WHERE membership.tenant_id = p_tenant_id
    AND membership.id = p_membership_id
    AND coalesce(login_identifier.canonical_value, identity.email) IS NOT NULL;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform tenant creator has no verified local profile identity'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.create_platform_tenant(
  uuid, uuid, text, text, text, text,
  uuid, uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_platform_tenant(
  uuid, uuid, text, text, text, text,
  uuid, uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_platform_tenant(
  uuid, uuid, text, text, text, text,
  uuid, uuid, uuid, inet, text, text
) TO periapsis_api;
