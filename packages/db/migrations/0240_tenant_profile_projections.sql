-- Tenant user, security-group and operator-team projections use the effective
-- tenant profile. Global identities are not modified or linked by contact data.
CREATE FUNCTION app.list_tenant_users_v3(
  p_after_membership_id uuid,
  p_limit integer
)
RETURNS TABLE (
  membership_id uuid,
  user_id uuid,
  email text,
  display_name text,
  membership_status public.membership_status,
  compatibility_role public.membership_role,
  user_active boolean,
  lifecycle_revision integer,
  created_at timestamp with time zone,
  updated_at timestamp with time zone
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3('user.read','tenant') THEN
    RAISE EXCEPTION 'user.read tenant scope is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'tenant user page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF p_after_membership_id IS NOT NULL
     AND (uuid_extract_version(p_after_membership_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'tenant user page cursor is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT membership.id,identity.id,CASE WHEN profile.membership_id IS NULL THEN identity.email ELSE profile.email END,coalesce(profile.display_name,identity.display_name),
         membership.status,membership.role,identity.active,
         membership.lifecycle_revision,membership.created_at,membership.updated_at
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  LEFT JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id = membership.tenant_id
   AND profile.membership_id = membership.id
   AND profile.user_id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND (p_after_membership_id IS NULL OR membership.id > p_after_membership_id)
  ORDER BY membership.id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_tenant_users_v3(uuid,integer) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_users_v3(uuid,integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenant_users_v3(uuid,integer) TO periapsis_api;
--> statement-breakpoint
CREATE FUNCTION "app"."list_tenant_security_group_memberships_v4"(
  p_group_id uuid,
  p_after_group_membership_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  group_membership_id uuid,
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  group_archived_at timestamp with time zone,
  group_version integer,
  group_created_at timestamp with time zone,
  group_updated_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  membership_created_at timestamp with time zone,
  membership_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  grant_state text,
  version integer,
  updated_at timestamp with time zone,
  managed_by_authorization_api boolean,
  membership_lifecycle_revision integer
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT previous.group_membership_id,
         previous.group_id,
         previous.group_key,
         previous.group_name,
         previous.group_description,
         previous.group_archived_at,
         previous.group_version,
         previous.group_created_at,
         previous.group_updated_at,
         previous.membership_id,
         previous.target_user_id,
         CASE WHEN profile.membership_id IS NULL THEN previous.email ELSE profile.email END,
         coalesce(profile.display_name,previous.display_name),
         previous.membership_status,
         previous.compatibility_role,
         previous.user_active,
         previous.membership_created_at,
         previous.membership_updated_at,
         previous.source_id,
         previous.source_kind,
         previous.source_authoritative,
         previous.source_retired_at,
         previous.granted_by_membership_id,
         previous.granted_by_user_id,
         previous.grant_reason,
         previous.granted_at,
         previous.expires_at,
         previous.revoked_at,
         previous.revoked_by_membership_id,
         previous.revoked_by_user_id,
         previous.revoke_reason,
         previous.grant_state,
         previous.version,
         previous.updated_at,
         previous.managed_by_authorization_api,
         previous.membership_lifecycle_revision
  FROM app.list_tenant_security_group_memberships_v3(p_group_id, p_after_group_membership_id, p_include_revoked, p_limit) AS previous
  JOIN public.tenant_memberships AS member
    ON member.tenant_id=app.context_tenant_id()
   AND member.id=previous.membership_id
   AND member.user_id=previous.target_user_id
  LEFT JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id=member.tenant_id
   AND profile.membership_id=member.id
   AND profile.user_id=member.user_id
  ORDER BY previous.group_membership_id;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_tenant_security_group_memberships_v4(uuid,uuid,boolean,integer) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_security_group_memberships_v4(uuid,uuid,boolean,integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenant_security_group_memberships_v4(uuid,uuid,boolean,integer) TO periapsis_api;
--> statement-breakpoint
CREATE FUNCTION "app"."get_tenant_security_group_membership_v4"(
  p_group_id uuid,
  p_group_membership_id uuid
)
RETURNS TABLE (
  group_membership_id uuid,
  group_id uuid,
  group_key text,
  group_name text,
  group_description text,
  group_archived_at timestamp with time zone,
  group_version integer,
  group_created_at timestamp with time zone,
  group_updated_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  membership_created_at timestamp with time zone,
  membership_updated_at timestamp with time zone,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  grant_state text,
  version integer,
  updated_at timestamp with time zone,
  managed_by_authorization_api boolean,
  membership_lifecycle_revision integer
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT previous.group_membership_id,
         previous.group_id,
         previous.group_key,
         previous.group_name,
         previous.group_description,
         previous.group_archived_at,
         previous.group_version,
         previous.group_created_at,
         previous.group_updated_at,
         previous.membership_id,
         previous.target_user_id,
         CASE WHEN profile.membership_id IS NULL THEN previous.email ELSE profile.email END,
         coalesce(profile.display_name,previous.display_name),
         previous.membership_status,
         previous.compatibility_role,
         previous.user_active,
         previous.membership_created_at,
         previous.membership_updated_at,
         previous.source_id,
         previous.source_kind,
         previous.source_authoritative,
         previous.source_retired_at,
         previous.granted_by_membership_id,
         previous.granted_by_user_id,
         previous.grant_reason,
         previous.granted_at,
         previous.expires_at,
         previous.revoked_at,
         previous.revoked_by_membership_id,
         previous.revoked_by_user_id,
         previous.revoke_reason,
         previous.grant_state,
         previous.version,
         previous.updated_at,
         previous.managed_by_authorization_api,
         previous.membership_lifecycle_revision
  FROM app.get_tenant_security_group_membership_v3(p_group_id, p_group_membership_id) AS previous
  JOIN public.tenant_memberships AS member
    ON member.tenant_id=app.context_tenant_id()
   AND member.id=previous.membership_id
   AND member.user_id=previous.target_user_id
  LEFT JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id=member.tenant_id
   AND profile.membership_id=member.id
   AND profile.user_id=member.user_id;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_tenant_security_group_membership_v4(uuid,uuid) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_security_group_membership_v4(uuid,uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_security_group_membership_v4(uuid,uuid) TO periapsis_api;
--> statement-breakpoint
CREATE FUNCTION "app"."list_tenant_operator_team_roster_entries_v2"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_after_entry_id uuid,
  p_include_revoked boolean,
  p_limit integer
)
RETURNS TABLE (
  roster_entry_id uuid,
  operator_team_id uuid,
  team_key text,
  team_display_name text,
  team_archived_at timestamp with time zone,
  assignment_epoch_id uuid,
  assignment_ended_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_key text,
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  roster_state text,
  version integer,
  updated_at timestamp with time zone
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
  IF NOT (
    app.current_tenant_can_read_operator_team(
      p_operator_team_id, p_assignment_epoch_id
    )
    AND app.current_tenant_has_exact_permission('user.read', 'tenant')
  ) THEN
    RAISE EXCEPTION 'operator-team read authority and user.read tenant scope are required'
      USING ERRCODE = '42501';
  END IF;
  IF p_include_revoked IS NULL THEN
    RAISE EXCEPTION 'include revoked must be explicit'
      USING ERRCODE = '22023';
  END IF;
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'operator-team roster page limit must be between 1 and 101'
      USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.tenant_id = context_tenant
      AND assignment.operator_team_id = p_operator_team_id
      AND assignment.id = p_assignment_epoch_id
  ) THEN
    RAISE EXCEPTION 'tenant operator-team assignment epoch was not found'
      USING ERRCODE = 'P0002';
  END IF;

  RETURN QUERY
  SELECT roster.id,
         assignment.operator_team_id,
         operator_team.key,
         operator_team.display_name,
         operator_team.archived_at,
         assignment.id,
         assignment.ended_at,
         membership.id,
         identity.id,
         CASE WHEN profile.membership_id IS NULL THEN identity.email ELSE profile.email END,
         coalesce(profile.display_name,identity.display_name),
         membership.status,
         membership.role,
         identity.active,
         source.id,
         source.kind,
         source.key,
         source.authoritative,
         source.retired_at,
         roster.granted_by_membership_id,
         grantor.user_id,
         roster.grant_reason,
         roster.granted_at,
         roster.expires_at,
         roster.revoked_at,
         roster.revoked_by_membership_id,
         revoker.user_id,
         roster.revoke_reason,
         CASE
           WHEN roster.revoked_at IS NOT NULL THEN 'revoked'
           WHEN (roster.expires_at IS NOT NULL
             AND roster.expires_at <= transaction_timestamp())
             OR source.retired_at IS NOT NULL
             OR assignment.ended_at IS NOT NULL
             OR operator_team.archived_at IS NOT NULL
             OR membership.status <> 'active'
             OR NOT identity.active
             OR tenant.status <> 'active' THEN 'expired'
           ELSE 'active'
         END,
         roster.version,
         roster.updated_at
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.operator_team_roster_entries AS roster
    ON roster.tenant_id = assignment.tenant_id
   AND roster.assignment_epoch_id = assignment.id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = roster.tenant_id
   AND membership.id = roster.membership_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  LEFT JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id = membership.tenant_id
   AND profile.membership_id = membership.id
   AND profile.user_id = membership.user_id
  JOIN public.tenants AS tenant ON tenant.id = assignment.tenant_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = roster.tenant_id
   AND source.id = roster.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = roster.tenant_id
   AND grantor.id = roster.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = roster.tenant_id
   AND revoker.id = roster.revoked_by_membership_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
    AND (p_include_revoked OR roster.revoked_at IS NULL)
    AND (p_after_entry_id IS NULL OR roster.id > p_after_entry_id)
  ORDER BY roster.id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_tenant_operator_team_roster_entries_v2(uuid,uuid,uuid,boolean,integer) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_operator_team_roster_entries_v2(uuid,uuid,uuid,boolean,integer) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenant_operator_team_roster_entries_v2(uuid,uuid,uuid,boolean,integer) TO periapsis_api;
--> statement-breakpoint
CREATE FUNCTION "app"."get_tenant_operator_team_roster_entry_v2"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_roster_entry_id uuid
)
RETURNS TABLE (
  roster_entry_id uuid,
  operator_team_id uuid,
  team_key text,
  team_display_name text,
  team_archived_at timestamp with time zone,
  assignment_epoch_id uuid,
  assignment_ended_at timestamp with time zone,
  membership_id uuid,
  target_user_id uuid,
  email text,
  display_name text,
  membership_status "public"."membership_status",
  compatibility_role "public"."membership_role",
  user_active boolean,
  source_id uuid,
  source_kind "public"."authorization_source_kind",
  source_key text,
  source_authoritative boolean,
  source_retired_at timestamp with time zone,
  granted_by_membership_id uuid,
  granted_by_user_id uuid,
  grant_reason text,
  granted_at timestamp with time zone,
  expires_at timestamp with time zone,
  revoked_at timestamp with time zone,
  revoked_by_membership_id uuid,
  revoked_by_user_id uuid,
  revoke_reason text,
  roster_state text,
  version integer,
  updated_at timestamp with time zone
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
  IF NOT (
    (
      app.current_tenant_can_read_operator_team(
        p_operator_team_id, p_assignment_epoch_id
      )
      AND app.current_tenant_has_exact_permission('user.read', 'tenant')
    )
    OR (
      app.current_tenant_can_manage_operator_team_roster(
        p_operator_team_id, p_assignment_epoch_id
      )
      AND app.current_tenant_has_exact_permission('role.grant', 'tenant')
    )
    OR (
      app.current_tenant_has_exact_permission(
        'operator_team.manage', 'tenant'
      )
      AND app.current_tenant_has_exact_permission('role.grant', 'tenant')
    )
  ) THEN
    RAISE EXCEPTION 'operator-team roster read or management authority is required'
      USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT roster.id,
         assignment.operator_team_id,
         operator_team.key,
         operator_team.display_name,
         operator_team.archived_at,
         assignment.id,
         assignment.ended_at,
         membership.id,
         identity.id,
         CASE WHEN profile.membership_id IS NULL THEN identity.email ELSE profile.email END,
         coalesce(profile.display_name,identity.display_name),
         membership.status,
         membership.role,
         identity.active,
         source.id,
         source.kind,
         source.key,
         source.authoritative,
         source.retired_at,
         roster.granted_by_membership_id,
         grantor.user_id,
         roster.grant_reason,
         roster.granted_at,
         roster.expires_at,
         roster.revoked_at,
         roster.revoked_by_membership_id,
         revoker.user_id,
         roster.revoke_reason,
         CASE
           WHEN roster.revoked_at IS NOT NULL THEN 'revoked'
           WHEN (roster.expires_at IS NOT NULL
             AND roster.expires_at <= transaction_timestamp())
             OR source.retired_at IS NOT NULL
             OR assignment.ended_at IS NOT NULL
             OR operator_team.archived_at IS NOT NULL
             OR membership.status <> 'active'
             OR NOT identity.active
             OR tenant.status <> 'active' THEN 'expired'
           ELSE 'active'
         END,
         roster.version,
         roster.updated_at
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS operator_team
    ON operator_team.id = assignment.operator_team_id
  JOIN public.operator_team_roster_entries AS roster
    ON roster.tenant_id = assignment.tenant_id
   AND roster.assignment_epoch_id = assignment.id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = roster.tenant_id
   AND membership.id = roster.membership_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  LEFT JOIN public.tenant_user_profiles AS profile
    ON profile.tenant_id = membership.tenant_id
   AND profile.membership_id = membership.id
   AND profile.user_id = membership.user_id
  JOIN public.tenants AS tenant ON tenant.id = assignment.tenant_id
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = roster.tenant_id
   AND source.id = roster.source_id
  LEFT JOIN public.tenant_memberships AS grantor
    ON grantor.tenant_id = roster.tenant_id
   AND grantor.id = roster.granted_by_membership_id
  LEFT JOIN public.tenant_memberships AS revoker
    ON revoker.tenant_id = roster.tenant_id
   AND revoker.id = roster.revoked_by_membership_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
    AND roster.tenant_id = context_tenant
    AND roster.assignment_epoch_id = p_assignment_epoch_id
    AND roster.id = p_roster_entry_id;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant operator-team roster entry was not found'
      USING ERRCODE = 'P0002';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.get_tenant_operator_team_roster_entry_v2(uuid,uuid,uuid) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_operator_team_roster_entry_v2(uuid,uuid,uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_operator_team_roster_entry_v2(uuid,uuid,uuid) TO periapsis_api;
--> statement-breakpoint
-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V55 catalog hash.
-- V55 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v55()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v55();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    true,
    true,
    true,
    coalesce(app.platform_local_account_runtime_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_metadata_runtime_schema_readiness_v1(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.api_runtime_schema_readiness_v55() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v55()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v55()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v55()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v55();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    coalesce(app.private_sla_system_principal_catalog_ready_v1(),false),
    coalesce(app.sla_object_event_ingress_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.worker_runtime_schema_readiness_v55() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v55()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v55()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint
