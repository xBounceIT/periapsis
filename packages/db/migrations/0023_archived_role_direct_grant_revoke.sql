-- Keep manual direct-grant cleanup available after a custom role is archived.
-- Archived roles no longer contribute authority, so the caller cannot satisfy
-- the ordinary delegation-ceiling check for the role being cleaned up.
CREATE OR REPLACE FUNCTION "app"."revoke_tenant_user_role_grant"(
  p_grant_id uuid,
  p_expected_version integer,
  p_reason text,
  p_audit_event_id uuid,
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
  target_grant record;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'direct role revoke reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT role_grant.*, role.archived_at AS role_archived_at
    INTO target_grant
  FROM public.tenant_membership_role_grants AS role_grant
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = role_grant.tenant_id
   AND source.id = role_grant.source_id
  JOIN public.tenant_roles AS role
    ON role.tenant_id = role_grant.tenant_id
   AND role.id = role_grant.role_id
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.id = p_grant_id
    AND source.kind = 'manual'
  FOR UPDATE OF role_grant;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct tenant role grant was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_grant.version <> p_expected_version THEN
    RAISE EXCEPTION 'tenant role grant version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'direct tenant role grant is already revoked'
      USING ERRCODE = '55000';
  END IF;
  IF target_grant.version >= 2147483647 THEN
    RAISE EXCEPTION 'tenant role grant version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  IF target_grant.role_archived_at IS NULL
     AND (
       target_grant.expires_at IS NULL
       OR target_grant.expires_at > transaction_timestamp()
     ) THEN
    PERFORM app.assert_actor_can_grant_role(
      target_grant.role_id, target_grant.expires_at
    );
  END IF;

  next_version := target_grant.version + 1;
  UPDATE public.tenant_membership_role_grants AS role_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE role_grant.tenant_id = context_tenant
    AND role_grant.id = p_grant_id;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role_grant.revoked',
    'tenant_membership_role_grant', p_grant_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'revoked_at', NULL, 'version', target_grant.version
    ),
    jsonb_build_object(
      'revoked_at', transaction_timestamp(),
      'reason', p_reason, 'version', next_version
    ),
    jsonb_build_object('actor_membership_id', actor_membership)
  );
  RETURN next_version;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) FROM PUBLIC;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."revoke_tenant_user_role_grant"(
  uuid, integer, text, uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";
