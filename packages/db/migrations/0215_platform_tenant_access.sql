-- Explicit platform-super-admin tenant access. The platform role is never an
-- RLS bypass: this command creates an ordinary, attributable tenant membership
-- and canonical tenant-admin role grant before the normal tenant switch flow
-- can select the target tenant.

INSERT INTO public.platform_permissions (id,key,description)
VALUES (
  uuidv7(),
  'platform.tenant.access',
  'Explicitly authorize the current platform super-admin to enter one tenant.'
)
ON CONFLICT (key) DO NOTHING;
--> statement-breakpoint
INSERT INTO public.platform_role_permissions (role_id,permission_id)
SELECT role.id,permission.id
FROM public.platform_roles AS role
CROSS JOIN public.platform_permissions AS permission
WHERE role.key='platform_super_admin'
  AND permission.key='platform.tenant.access'
ON CONFLICT DO NOTHING;
--> statement-breakpoint

ALTER TABLE public.platform_commands
DROP CONSTRAINT platform_commands_operation_check;
--> statement-breakpoint
ALTER TABLE public.platform_commands
ADD CONSTRAINT platform_commands_operation_check CHECK (
  operation IN ('operator_team.create','platform.tenant_access.authorize')
);
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_platform_command()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  IF TG_OP='UPDATE' THEN
    RAISE EXCEPTION 'platform command rows are append-only'
      USING ERRCODE='55000';
  END IF;

  IF TG_OP='DELETE' THEN
    IF OLD.expires_at>transaction_timestamp() THEN
      RAISE EXCEPTION 'unexpired platform commands cannot be pruned'
        USING ERRCODE='55000';
    END IF;
    RETURN OLD;
  END IF;

  IF NEW.operation='operator_team.create' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.operator_teams AS resource
      WHERE resource.id=NEW.result_resource_id
        AND resource.version=NEW.result_version
    ) THEN
      RAISE EXCEPTION 'operator-team idempotency result is invalid'
        USING ERRCODE='23503',CONSTRAINT='platform_commands_result_fk';
    END IF;
  ELSIF NEW.operation='platform.tenant_access.authorize' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_memberships AS membership
      JOIN public.tenant_membership_role_grants AS role_grant
        ON role_grant.tenant_id=membership.tenant_id
       AND role_grant.membership_id=membership.id
       AND role_grant.revoked_at IS NULL
       AND (role_grant.expires_at IS NULL
         OR role_grant.expires_at>transaction_timestamp())
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id=role_grant.tenant_id
       AND source.id=role_grant.source_id
       AND source.kind='manual'
       AND source.key='platform_super_admin_access'
       AND NOT source.authoritative
       AND source.protected
       AND source.retired_at IS NULL
      JOIN public.tenant_roles AS role
        ON role.tenant_id=role_grant.tenant_id
       AND role.id=role_grant.role_id
       AND role.key='tenant_admin'
       AND role.system_role
       AND role.protected_role
       AND role.archived_at IS NULL
      WHERE membership.id=NEW.result_resource_id
        AND membership.user_id=NEW.actor_user_id
        AND membership.status='active'
        AND membership.lifecycle_revision=NEW.result_version
    ) THEN
      RAISE EXCEPTION 'platform tenant-access idempotency result is invalid'
        USING ERRCODE='23503',CONSTRAINT='platform_commands_result_fk';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported platform command operation'
      USING ERRCODE='22023';
  END IF;

  RETURN NEW;
END
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_platform_command() OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_platform_command()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.authorize_platform_tenant_access_v1(
  p_session_id uuid,
  p_tenant_id uuid,
  p_membership_id uuid,
  p_role_grant_id uuid,
  p_expected_tenant_version integer,
  p_reason text,
  p_idempotency_key_digest bytea,
  p_platform_audit_event_id uuid,
  p_tenant_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  tenant_id uuid,
  membership_id uuid,
  user_id uuid,
  tenant_version integer,
  membership_revision integer,
  authorization_revision bigint,
  authorized_at timestamp with time zone,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid:=app.context_user_id();
  canonical_request_digest bytea;
  replay public.platform_commands%ROWTYPE;
  tenant_record public.tenants%ROWTYPE;
  membership_record public.tenant_memberships%ROWTYPE;
  source_id uuid;
  tenant_admin_role_id uuid;
  current_authorization_revision bigint;
BEGIN
  IF p_session_id IS NULL OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR p_tenant_id IS NULL OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_membership_id IS NULL OR uuid_extract_version(p_membership_id) IS DISTINCT FROM 7
     OR p_role_grant_id IS NULL OR uuid_extract_version(p_role_grant_id) IS DISTINCT FROM 7
     OR p_platform_audit_event_id IS NULL
     OR uuid_extract_version(p_platform_audit_event_id) IS DISTINCT FROM 7
     OR p_tenant_audit_event_id IS NULL
     OR uuid_extract_version(p_tenant_audit_event_id) IS DISTINCT FROM 7
     OR p_request_id IS NULL
     OR p_request_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_correlation_id IS NULL
     OR p_correlation_id='00000000-0000-0000-0000-000000000000'::uuid
     OR p_expected_tenant_version NOT BETWEEN 1 AND 2147483646
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR octet_length(p_user_agent) NOT BETWEEN 1 AND 512
     OR p_user_agent~'[[:cntrl:]]'
     OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','ldap','oidc','saml','passkey'
     )
     OR p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest)<>32
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid explicit platform tenant-access command'
      USING ERRCODE='22023';
  END IF;

  -- This is a high-impact entry boundary. Lock the exact source session and
  -- actor, require fresh MFA, reject recovery-restricted sessions, and keep
  -- the user lock as the per-actor idempotency serialization point.
  PERFORM 1
  FROM public.auth_sessions AS session
  JOIN public.users AS actor ON actor.id=session.user_id
  WHERE session.id=p_session_id
    AND session.user_id=actor_id
    AND session.authentication_method=p_authentication_method
    AND session.revoked_at IS NULL
    AND session.idle_expires_at>transaction_timestamp()
    AND session.absolute_expires_at>transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.mfa_satisfied_at BETWEEN
      transaction_timestamp()-interval '15 minutes'
      AND transaction_timestamp()
    AND actor.active
    AND app.session_tenant_allowed(session.user_id,session.active_tenant_id)
  FOR SHARE OF session FOR UPDATE OF actor;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'fresh live platform session authority is required'
      USING ERRCODE='42501';
  END IF;

  PERFORM 1
  FROM public.user_platform_roles AS role_grant
  JOIN public.platform_role_permissions AS role_permission
    ON role_permission.role_id=role_grant.role_id
  JOIN public.platform_permissions AS permission
    ON permission.id=role_permission.permission_id
  JOIN public.platform_roles AS role ON role.id=role_grant.role_id
  WHERE role_grant.user_id=actor_id
    AND role_grant.revoked_at IS NULL
    AND role.key='platform_super_admin'
    AND role.system
    AND permission.key='platform.tenant.access'
  FOR SHARE OF role_grant,role_permission,permission,role;
  IF NOT FOUND
     OR NOT app.platform_user_has_permission(actor_id,'platform.tenant.access') THEN
    RAISE EXCEPTION 'platform.tenant.access permission is required'
      USING ERRCODE='42501';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'tenant_id',p_tenant_id,
    'expected_tenant_version',p_expected_tenant_version,
    'reason',p_reason
  )::text,'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.platform_commands AS command
  WHERE command.actor_user_id=actor_id
    AND command.operation='platform.tenant_access.authorize'
    AND command.key_digest=p_idempotency_key_digest
    AND command.expires_at<=transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.platform_commands AS command
  WHERE command.actor_user_id=actor_id
    AND command.operation='platform.tenant_access.authorize'
    AND command.key_digest=p_idempotency_key_digest
  FOR UPDATE;

  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was already used for a different request'
        USING ERRCODE='23505',CONSTRAINT='platform_commands_replay_key';
    END IF;

    SELECT membership.* INTO membership_record
    FROM public.tenant_memberships AS membership
    JOIN public.tenants AS tenant ON tenant.id=membership.tenant_id
    JOIN public.tenant_membership_role_grants AS role_grant
      ON role_grant.tenant_id=membership.tenant_id
     AND role_grant.membership_id=membership.id
     AND role_grant.revoked_at IS NULL
     AND (role_grant.expires_at IS NULL
       OR role_grant.expires_at>transaction_timestamp())
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id=role_grant.tenant_id
     AND source.id=role_grant.source_id
     AND source.kind='manual'
     AND source.key='platform_super_admin_access'
     AND NOT source.authoritative
     AND source.protected
     AND source.retired_at IS NULL
    JOIN public.tenant_roles AS role
      ON role.tenant_id=role_grant.tenant_id
     AND role.id=role_grant.role_id
     AND role.key='tenant_admin'
     AND role.system_role
     AND role.protected_role
     AND role.archived_at IS NULL
    WHERE membership.id=replay.result_resource_id
      AND membership.tenant_id=p_tenant_id
      AND membership.user_id=actor_id
      AND membership.status='active'
      AND membership.lifecycle_revision=replay.result_version
      AND tenant.status='active'
      AND tenant.version=p_expected_tenant_version
    FOR SHARE OF membership,tenant,role_grant,source,role;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'explicit platform tenant access is no longer live'
        USING ERRCODE='40001';
    END IF;

    SELECT state.revision INTO STRICT current_authorization_revision
    FROM public.tenant_authorization_states AS state
    WHERE state.tenant_id=p_tenant_id;

    RETURN QUERY SELECT p_tenant_id,membership_record.id,actor_id,
      p_expected_tenant_version,membership_record.lifecycle_revision,
      current_authorization_revision,membership_record.created_at,true;
    RETURN;
  END IF;

  -- Match the lifecycle command lock order so access authorization and tenant
  -- suspension linearize on the authorization-state row before the tenant row.
  SELECT state.revision INTO current_authorization_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id=p_tenant_id
    AND state.initialized_at IS NOT NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenants WHERE id=p_tenant_id) THEN
      RAISE EXCEPTION 'platform tenant does not exist' USING ERRCODE='P0002';
    END IF;
    RAISE EXCEPTION 'platform tenant authorization state is unavailable'
      USING ERRCODE='55000';
  END IF;

  SELECT tenant.* INTO tenant_record
  FROM public.tenants AS tenant
  WHERE tenant.id=p_tenant_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform tenant does not exist' USING ERRCODE='P0002';
  END IF;
  IF tenant_record.status<>'active'
     OR tenant_record.version<>p_expected_tenant_version THEN
    RAISE EXCEPTION 'platform tenant access revision conflict'
      USING ERRCODE='40001';
  END IF;

  PERFORM 1
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id=p_tenant_id
    AND membership.user_id=actor_id
  FOR UPDATE;
  IF FOUND THEN
    RAISE EXCEPTION 'the platform actor already has a tenant membership'
      USING ERRCODE='23505',CONSTRAINT='tenant_memberships_tenant_user_key';
  END IF;

  INSERT INTO public.tenant_authorization_sources(
    tenant_id,kind,key,authoritative,protected
  ) VALUES (
    p_tenant_id,'manual','platform_super_admin_access',false,true
  ) ON CONFLICT ON CONSTRAINT tenant_authorization_sources_tenant_key_key
    DO NOTHING;

  SELECT source.id INTO source_id
  FROM public.tenant_authorization_sources AS source
  WHERE source.tenant_id=p_tenant_id
    AND source.kind='manual'
    AND source.key='platform_super_admin_access'
    AND NOT source.authoritative
    AND source.protected
    AND source.retired_at IS NULL
  FOR SHARE;
  IF source_id IS NULL THEN
    RAISE EXCEPTION 'platform tenant-access authorization source is unavailable'
      USING ERRCODE='55000';
  END IF;

  SELECT role.id INTO tenant_admin_role_id
  FROM public.tenant_roles AS role
  WHERE role.tenant_id=p_tenant_id
    AND role.key='tenant_admin'
    AND role.system_role
    AND role.protected_role
    AND role.archived_at IS NULL
  FOR SHARE;
  IF tenant_admin_role_id IS NULL THEN
    RAISE EXCEPTION 'canonical tenant administrator role is unavailable'
      USING ERRCODE='55000';
  END IF;

  INSERT INTO public.tenant_memberships(
    id,tenant_id,user_id,role,status,lifecycle_revision
  ) VALUES (
    p_membership_id,p_tenant_id,actor_id,'tenant_admin','active',1
  ) RETURNING * INTO membership_record;

  INSERT INTO public.tenant_membership_role_grants(
    id,tenant_id,membership_id,role_id,source_id,
    granted_by_membership_id,grant_reason
  ) VALUES (
    p_role_grant_id,p_tenant_id,p_membership_id,tenant_admin_role_id,source_id,
    p_membership_id,'Explicit platform super-admin tenant access.'
  );

  SELECT state.revision INTO STRICT current_authorization_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id=p_tenant_id;

  INSERT INTO public.audit_events(
    id,tenant_id,sequence,actor_type,actor_user_id,impersonated_by_user_id,
    action,resource_type,resource_id,request_id,correlation_id,ip_address,
    user_agent,authentication_method,outcome,reason,before,after,metadata
  ) VALUES (
    p_tenant_audit_event_id,p_tenant_id,0,'user',actor_id,actor_id,
    'tenant.access.authorized','tenant_membership',p_membership_id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method,'success',p_reason,NULL,
    jsonb_build_object(
      'membership_id',p_membership_id,
      'role','tenant_admin',
      'status','active',
      'lifecycle_revision',membership_record.lifecycle_revision
    ),
    jsonb_build_object(
      'authorization_source','platform_super_admin_access',
      'role_grant_id',p_role_grant_id,
      'authorization_revision',current_authorization_revision,
      'explicit_platform_access',true
    )
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,'user',actor_id,
    'platform.tenant_access.authorized','tenant',p_tenant_id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method,'success',p_reason,
    jsonb_build_object(
      'membership_id',p_membership_id,
      'role_grant_id',p_role_grant_id,
      'tenant_version',p_expected_tenant_version,
      'authorization_revision',current_authorization_revision,
      'tenant_audit_event_id',p_tenant_audit_event_id
    )
  );

  INSERT INTO public.platform_commands(
    actor_user_id,operation,key_digest,request_digest,
    result_resource_id,result_version
  ) VALUES (
    actor_id,'platform.tenant_access.authorize',p_idempotency_key_digest,
    canonical_request_digest,p_membership_id,membership_record.lifecycle_revision
  );

  RETURN QUERY SELECT p_tenant_id,p_membership_id,actor_id,
    p_expected_tenant_version,membership_record.lifecycle_revision,
    current_authorization_revision,membership_record.created_at,false;
END
$function$;
--> statement-breakpoint
ALTER FUNCTION app.authorize_platform_tenant_access_v1(
  uuid,uuid,uuid,uuid,integer,text,bytea,uuid,uuid,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.authorize_platform_tenant_access_v1(
  uuid,uuid,uuid,uuid,integer,text,bytea,uuid,uuid,uuid,uuid,inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.authorize_platform_tenant_access_v1(
  uuid,uuid,uuid,uuid,integer,text,bytea,uuid,uuid,uuid,uuid,inet,text,text
) TO periapsis_api;
--> statement-breakpoint

-- This attribution trigger deliberately runs before the existing immutable
-- audit seal.  Keep attribution separate so this slice cannot silently replace
-- tamper-evidence behavior established by earlier migrations.
CREATE FUNCTION app.attribute_platform_tenant_access_audit_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  invoker_role text;
  context_user uuid;
BEGIN
  IF TG_TABLE_SCHEMA<>'public' OR TG_TABLE_NAME<>'audit_events'
     OR TG_OP<>'INSERT' THEN
    RAISE EXCEPTION 'platform tenant-access audit attribution rejected relation %.%/%',
      TG_TABLE_SCHEMA,TG_TABLE_NAME,TG_OP
      USING ERRCODE='55000';
  END IF;

  invoker_role:=nullif(current_setting('role',true),'');
  IF invoker_role IS NULL OR invoker_role='none' THEN
    invoker_role:=session_user::text;
  END IF;

  IF NEW.actor_type='user'
     AND NEW.impersonated_by_user_id IS NULL
     AND invoker_role IN ('periapsis_api','periapsis_api_login') THEN
    context_user:=nullif(current_setting('app.user_id',true),'')::uuid;
    IF context_user IS NOT NULL
       AND NEW.actor_user_id=context_user
       AND EXISTS (
         SELECT 1
         FROM public.tenant_memberships AS membership
         JOIN public.tenant_membership_role_grants AS role_grant
           ON role_grant.tenant_id=membership.tenant_id
          AND role_grant.membership_id=membership.id
         JOIN public.tenant_authorization_sources AS source
           ON source.tenant_id=role_grant.tenant_id
          AND source.id=role_grant.source_id
          AND source.kind='manual'
          AND source.key='platform_super_admin_access'
          AND NOT source.authoritative
          AND source.protected
         JOIN public.tenant_roles AS role
           ON role.tenant_id=role_grant.tenant_id
          AND role.id=role_grant.role_id
          AND role.key='tenant_admin'
          AND role.system_role
          AND role.protected_role
         WHERE membership.tenant_id=NEW.tenant_id
           AND membership.user_id=context_user
       ) THEN
      -- Provenance is intentionally historical: retaining it after a grant is
      -- revoked, a source is retired, or the membership is suspended ensures
      -- that the revocation/suspension audit itself cannot lose attribution.
      NEW.impersonated_by_user_id:=context_user;
    END IF;
  END IF;

  RETURN NEW;
END
$function$;
--> statement-breakpoint
ALTER FUNCTION app.attribute_platform_tenant_access_audit_v1()
OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.attribute_platform_tenant_access_audit_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER audit_events_platform_access_attribution_before_insert
BEFORE INSERT ON public.audit_events
FOR EACH ROW
EXECUTE FUNCTION app.attribute_platform_tenant_access_audit_v1();
