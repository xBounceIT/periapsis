-- Return the authoritative post-mutation role representation from the same
-- protected operation that authorizes the policy replacement. A caller may
-- legitimately remove its own last role.read/role.manage/role.grant tuple, so
-- a second caller-authorized read after the mutation would incorrectly roll
-- the transaction back.
CREATE FUNCTION "app"."replace_tenant_role_policy_with_result"(
  p_role_id uuid,
  p_expected_version integer,
  p_permission_keys text[],
  p_scopes "public"."authorization_scope"[],
  p_delegation_permission_keys text[],
  p_delegation_scopes "public"."authorization_scope"[],
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  role_id uuid,
  role_key text,
  display_name text,
  description text,
  system_role boolean,
  protected_role boolean,
  version integer,
  archived_at timestamp with time zone,
  created_at timestamp with time zone,
  updated_at timestamp with time zone,
  permission_keys text[],
  permission_scopes "public"."authorization_scope"[],
  delegation_permission_keys text[],
  delegation_scopes "public"."authorization_scope"[]
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  mutated_version integer;
BEGIN
  mutated_version := app.replace_tenant_role_policy(
    p_role_id,
    p_expected_version,
    p_permission_keys,
    p_scopes,
    p_delegation_permission_keys,
    p_delegation_scopes,
    p_audit_event_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method
  );

  RETURN QUERY
  SELECT role.id,
         role.key::text,
         role.display_name::text,
         role.description::text,
         role.system_role,
         role.protected_role,
         role.version,
         role.archived_at,
         role.created_at,
         role.updated_at,
         ARRAY(
           SELECT permission.key::text
           FROM public.tenant_role_permissions AS policy
           JOIN public.tenant_permissions AS permission
             ON permission.id = policy.permission_id
           WHERE policy.tenant_id = context_tenant
             AND policy.role_id = p_role_id
           ORDER BY permission.key, policy.scope
         ),
         ARRAY(
           SELECT policy.scope
           FROM public.tenant_role_permissions AS policy
           JOIN public.tenant_permissions AS permission
             ON permission.id = policy.permission_id
           WHERE policy.tenant_id = context_tenant
             AND policy.role_id = p_role_id
           ORDER BY permission.key, policy.scope
         ),
         ARRAY(
           SELECT permission.key::text
           FROM public.tenant_role_delegation_ceilings AS ceiling
           JOIN public.tenant_permissions AS permission
             ON permission.id = ceiling.permission_id
           WHERE ceiling.tenant_id = context_tenant
             AND ceiling.role_id = p_role_id
           ORDER BY permission.key, ceiling.scope
         ),
         ARRAY(
           SELECT ceiling.scope
           FROM public.tenant_role_delegation_ceilings AS ceiling
           JOIN public.tenant_permissions AS permission
             ON permission.id = ceiling.permission_id
           WHERE ceiling.tenant_id = context_tenant
             AND ceiling.role_id = p_role_id
           ORDER BY permission.key, ceiling.scope
         )
  FROM public.tenant_roles AS role
  WHERE role.tenant_id = context_tenant
    AND role.id = p_role_id
    AND role.version = mutated_version;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant role mutation result was not found'
      USING ERRCODE = 'XX000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."replace_tenant_role_policy_with_result"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."replace_tenant_role_policy_with_result"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) FROM PUBLIC;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."replace_tenant_role_policy_with_result"(
  uuid, integer, text[], "public"."authorization_scope"[], text[],
  "public"."authorization_scope"[], uuid, uuid, uuid, inet, text, text
) TO "periapsis_api";--> statement-breakpoint
