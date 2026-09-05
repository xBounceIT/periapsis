CREATE TABLE "mfa_policy_commands" (
	"id" uuid PRIMARY KEY NOT NULL,
	"tenant_id" uuid,
	"actor_user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result_policy_id" uuid NOT NULL,
	"result_policy_revision" bigint NOT NULL,
	"result_snapshot" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "mfa_policy_commands_id_uuidv7_check" CHECK ((uuid_extract_version("mfa_policy_commands"."id") = 7) is true),
	CONSTRAINT "mfa_policy_commands_operation_check" CHECK ("mfa_policy_commands"."operation" in ('platform.publish', 'platform.retire', 'tenant.publish', 'tenant.retire')),
	CONSTRAINT "mfa_policy_commands_digest_check" CHECK (octet_length("mfa_policy_commands"."request_digest") = 32
        and encode("mfa_policy_commands"."request_digest", 'hex') <> repeat('00', 32)),
	CONSTRAINT "mfa_policy_commands_result_check" CHECK ("mfa_policy_commands"."result_policy_revision" between 1 and 9007199254740991
        and jsonb_typeof("mfa_policy_commands"."result_snapshot") = 'object'
        and pg_column_size("mfa_policy_commands"."result_snapshot") between 2 and 65536)
);
--> statement-breakpoint
ALTER TABLE "mfa_policy_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" DROP CONSTRAINT "mfa_policy_revisions_revision_check";--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" DROP CONSTRAINT "mfa_policy_revisions_requirement_check";--> statement-breakpoint
ALTER TABLE "mfa_policy_commands" ADD CONSTRAINT "mfa_policy_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_policy_commands" ADD CONSTRAINT "mfa_policy_commands_actor_user_id_users_id_fk" FOREIGN KEY ("actor_user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "mfa_policy_commands" ADD CONSTRAINT "mfa_policy_commands_result_fk" FOREIGN KEY ("result_policy_id","result_policy_revision") REFERENCES "public"."mfa_policy_revisions"("id","revision") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "mfa_policy_commands_result_idx" ON "mfa_policy_commands" USING btree ("result_policy_id","result_policy_revision","id");--> statement-breakpoint
CREATE INDEX "mfa_policy_commands_tenant_created_idx" ON "mfa_policy_commands" USING btree ("tenant_id","created_at","id");--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" ADD CONSTRAINT "mfa_policy_revisions_revision_check" CHECK ("mfa_policy_revisions"."revision" between 1 and 9007199254740991);--> statement-breakpoint
ALTER TABLE "mfa_policy_revisions" ADD CONSTRAINT "mfa_policy_revisions_requirement_check" CHECK ("mfa_policy_revisions"."level" in ('primary', 'mfa', 'phishing_resistant')
        and "mfa_policy_revisions"."freshness_nanoseconds" between 0 and 31536000000000000
        and mod("mfa_policy_revisions"."freshness_nanoseconds", 1000000000) = 0
        and ("mfa_policy_revisions"."enrollment_deadline" is null
          or "mfa_policy_revisions"."enrollment_deadline" > "mfa_policy_revisions"."created_at"));
--> statement-breakpoint

-- Immutable, payload-bound MFA-policy administration. No policy is seeded:
-- an existing administrator must explicitly publish the first platform floor
-- and each tenant baseline through the protected ABI below.

LOCK TABLE public.mfa_policy_revisions IN SHARE ROW EXCLUSIVE MODE;
DO $mfa_policy_preflight$
BEGIN
  IF EXISTS (
    SELECT 1 FROM ONLY public.mfa_policy_revisions AS policy
    WHERE policy.revision NOT BETWEEN 1 AND 9007199254740991
       OR policy.freshness_nanoseconds NOT BETWEEN 0 AND 31536000000000000
       OR mod(policy.freshness_nanoseconds,1000000000) <> 0
  ) THEN
    RAISE EXCEPTION 'existing MFA policy cannot be represented safely'
      USING ERRCODE = '22003';
  END IF;
END;
$mfa_policy_preflight$;
--> statement-breakpoint

ALTER TABLE public.mfa_policy_commands OWNER TO periapsis_migrator;
ALTER TABLE public.mfa_policy_revisions OWNER TO periapsis_migrator;
ALTER TABLE public.mfa_policy_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE public.mfa_policy_revisions FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.mfa_policy_commands,public.mfa_policy_revisions
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner;
--> statement-breakpoint

INSERT INTO public.tenant_permissions (
  id,key,display_name,description,service_account_allowed
) VALUES
  (uuidv7(),'identity_policy.read','Read identity policies',
    'Read safe tenant MFA policy revisions and simulations.',false),
  (uuidv7(),'identity_policy.manage','Manage identity policies',
    'Publish, replace, and retire tenant MFA policy revisions.',false)
ON CONFLICT (key) DO NOTHING;
INSERT INTO public.tenant_permission_scopes (permission_id,scope)
SELECT permission.id,'tenant'::public.authorization_scope
FROM public.tenant_permissions AS permission
WHERE permission.key IN ('identity_policy.read','identity_policy.manage')
ON CONFLICT DO NOTHING;
DO $assert_mfa_policy_permission_catalog$
BEGIN
  IF (SELECT count(*) FROM ONLY public.tenant_permissions AS permission
      WHERE permission.key IN (
        'identity_policy.read','identity_policy.manage'
      ) AND NOT permission.service_account_allowed) <> 2
     OR EXISTS (
       SELECT 1
       FROM ONLY public.tenant_permissions AS permission
       JOIN ONLY public.tenant_permission_scopes AS permission_scope
         ON permission_scope.permission_id = permission.id
       WHERE permission.key IN (
         'identity_policy.read','identity_policy.manage'
       ) AND permission_scope.scope <> 'tenant'
     ) OR (SELECT count(*)
       FROM ONLY public.tenant_permissions AS permission
       JOIN ONLY public.tenant_permission_scopes AS permission_scope
         ON permission_scope.permission_id = permission.id
       WHERE permission.key IN (
         'identity_policy.read','identity_policy.manage'
       ) AND permission_scope.scope = 'tenant') <> 2 THEN
    RAISE EXCEPTION 'MFA policy permission catalog is ambiguous'
      USING ERRCODE = '55000';
  END IF;
END;
$assert_mfa_policy_permission_catalog$;
--> statement-breakpoint

CREATE FUNCTION app.private_seed_tenant_mfa_policy_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  administrator public.tenant_roles%ROWTYPE;
  inserted_permissions integer;
  inserted_ceilings integer;
  seeded_at timestamptz := transaction_timestamp();
BEGIN
  PERFORM state.revision
  FROM ONLY public.tenant_authorization_states AS state
  WHERE state.tenant_id = p_tenant_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant authorization state is required for MFA policy seeding'
      USING ERRCODE = '55000';
  END IF;

  SELECT role.* INTO STRICT administrator
  FROM ONLY public.tenant_roles AS role
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role AND role.protected_role
    AND role.archived_at IS NULL
  FOR UPDATE;

  INSERT INTO public.tenant_role_permissions (
    tenant_id,role_id,permission_id,scope,created_by_membership_id
  )
  SELECT p_tenant_id,administrator.id,permission.id,'tenant',NULL
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN ('identity_policy.read','identity_policy.manage')
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_permissions = ROW_COUNT;

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id,role_id,permission_id,scope,created_by_membership_id
  )
  SELECT p_tenant_id,administrator.id,permission.id,'tenant',NULL
  FROM public.tenant_permissions AS permission
  WHERE permission.key IN ('identity_policy.read','identity_policy.manage')
  ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted_ceilings = ROW_COUNT;

  IF inserted_permissions > 0 OR inserted_ceilings > 0 THEN
    IF administrator.version >= 2147483647 THEN
      RAISE EXCEPTION 'tenant administrator version is exhausted'
        USING ERRCODE = '22003';
    END IF;
    UPDATE ONLY public.tenant_roles AS role
    SET version = role.version + 1,updated_at = seeded_at
    WHERE role.tenant_id = p_tenant_id AND role.id = administrator.id;
    INSERT INTO public.audit_events (
      id,tenant_id,sequence,actor_type,action,resource_type,resource_id,
      authentication_method,outcome,after,metadata
    ) VALUES (
      uuidv7(),p_tenant_id,0,'system',
      'tenant.authorization.mfa_policy_administration_enabled',
      'tenant_role',administrator.id,'database_migration','success',
      jsonb_build_object(
        'permissions',jsonb_build_array(
          'identity_policy.read','identity_policy.manage'
        ),
        'scope','tenant','prior_version',administrator.version,
        'result_version',administrator.version + 1
      ),
      jsonb_build_object(
        'migration','0182_mfa_policy_administration',
        'principal_kind','human'
      )
    );
  END IF;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'protected tenant administrator is unavailable or ambiguous'
    USING ERRCODE = '55000';
END;
$function$;
ALTER FUNCTION app.private_seed_tenant_mfa_policy_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_seed_tenant_mfa_policy_authorization_v1(uuid)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner;
--> statement-breakpoint

DO $seed_existing_tenant_mfa_policy_authorization$
DECLARE
  tenant_record record;
BEGIN
  FOR tenant_record IN
    SELECT tenant.id FROM ONLY public.tenants AS tenant ORDER BY tenant.id
  LOOP
    PERFORM app.private_seed_tenant_mfa_policy_authorization_v1(
      tenant_record.id
    );
  END LOOP;
END;
$seed_existing_tenant_mfa_policy_authorization$;
--> statement-breakpoint

ALTER FUNCTION app.seed_tenant_authorization(uuid,uuid)
  RENAME TO seed_tenant_authorization_mfa_policy_predecessor;
-- sqlc does not update its disposable function catalog for ALTER FUNCTION
-- ... RENAME. PostgreSQL sees this as a no-op after the rename; sqlc uses it
-- to forget the predecessor name before parsing the successor definition.
DROP FUNCTION IF EXISTS app.seed_tenant_authorization(uuid,uuid);
ALTER FUNCTION app.seed_tenant_authorization_mfa_policy_predecessor(uuid,uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.seed_tenant_authorization_mfa_policy_predecessor(uuid,uuid)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner;
CREATE FUNCTION app.seed_tenant_authorization(
  p_tenant_id uuid,p_initial_admin_membership_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  PERFORM app.seed_tenant_authorization_mfa_policy_predecessor(
    p_tenant_id,p_initial_admin_membership_id
  );
  PERFORM app.private_seed_tenant_mfa_policy_authorization_v1(p_tenant_id);
END;
$function$;
ALTER FUNCTION app.seed_tenant_authorization(uuid,uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seed_tenant_authorization(uuid,uuid)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_audit_reader_owner;
--> statement-breakpoint

CREATE FUNCTION app.guard_mfa_policy_command_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'MFA policy command receipts are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF NOT EXISTS (
    SELECT 1
    FROM ONLY public.mfa_policy_revisions AS policy
    WHERE policy.id = NEW.result_policy_id
      AND policy.revision = NEW.result_policy_revision
      AND policy.tenant_id IS NOT DISTINCT FROM NEW.tenant_id
  ) THEN
    RAISE EXCEPTION 'MFA policy command result scope is inconsistent'
      USING ERRCODE = '23503',
            CONSTRAINT = 'mfa_policy_commands_result_scope_fk';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER mfa_policy_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.mfa_policy_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_mfa_policy_command_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_mfa_policy_revision_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  capability text := current_setting('app.mfa_policy_write_v1',true);
  expected_capability text;
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'MFA policy revisions are immutable'
      USING ERRCODE = '55000';
  ELSIF TG_OP = 'UPDATE' THEN
    IF NEW.id IS DISTINCT FROM OLD.id
       OR NEW.revision IS DISTINCT FROM OLD.revision
       OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
       OR NEW.scope IS DISTINCT FROM OLD.scope
       OR NEW.role_id IS DISTINCT FROM OLD.role_id
       OR NEW.security_group_id IS DISTINCT FROM OLD.security_group_id
       OR NEW.action IS DISTINCT FROM OLD.action
       OR NEW.level IS DISTINCT FROM OLD.level
       OR NEW.local_required IS DISTINCT FROM OLD.local_required
       OR NEW.freshness_nanoseconds IS DISTINCT FROM OLD.freshness_nanoseconds
       OR NEW.enrollment_deadline IS DISTINCT FROM OLD.enrollment_deadline
       OR NEW.created_at IS DISTINCT FROM OLD.created_at
       OR OLD.retired_at IS NOT NULL
       OR NEW.retired_at IS NULL
       OR NEW.retired_at < OLD.created_at THEN
      RAISE EXCEPTION 'MFA policy revision meaning is immutable'
        USING ERRCODE = '55000';
    END IF;
    expected_capability := format(
      'retire:%s:%s',OLD.id::text,OLD.revision::text
    );
  ELSE
    IF NEW.retired_at IS NOT NULL THEN
      RAISE EXCEPTION 'new MFA policy revisions must be live'
        USING ERRCODE = '55000';
    END IF;
    expected_capability := format(
      'insert:%s:%s',NEW.id::text,NEW.revision::text
    );
  END IF;
  IF session_user <> 'periapsis_migrator'
     AND capability IS DISTINCT FROM expected_capability THEN
    RAISE EXCEPTION 'MFA policy revision writer capability is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER mfa_policy_revisions_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.mfa_policy_revisions
FOR EACH ROW EXECUTE FUNCTION app.guard_mfa_policy_revision_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_reason_valid_v1(p_reason text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT p_reason IS NOT NULL
     AND btrim(p_reason) = p_reason
     AND char_length(p_reason) BETWEEN 1 AND 2048
     AND position(',' IN p_reason) = 0
     AND NOT EXISTS (
       SELECT 1
       FROM regexp_split_to_table(p_reason,'') AS character(value)
       WHERE ascii(character.value) NOT BETWEEN 32 AND 126
     );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_instant_v1(p_value timestamptz)
RETURNS jsonb
LANGUAGE sql
IMMUTABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT to_jsonb(to_char(
    date_trunc('milliseconds',p_value AT TIME ZONE 'UTC'),
    'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
  ));
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_requirement_v1(p_requirement jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  level_value text;
  local_required_value boolean;
  freshness_seconds bigint;
  enrollment_deadline timestamptz;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_requirement,
    ARRAY['level','localRequired','freshnessSeconds','enrollmentDeadline'],
    ARRAY['level','localRequired','freshnessSeconds'],8192
  );
  IF NOT p_requirement ? 'enrollmentDeadline'
     OR jsonb_typeof(p_requirement -> 'level') <> 'string'
     OR p_requirement ->> 'level' NOT IN (
       'primary','mfa','phishing_resistant'
     )
     OR jsonb_typeof(p_requirement -> 'localRequired') <> 'boolean'
     OR jsonb_typeof(p_requirement -> 'freshnessSeconds') <> 'number'
     OR p_requirement ->> 'freshnessSeconds' !~ '^(0|[1-9][0-9]{0,7})$' THEN
    RAISE EXCEPTION 'invalid MFA policy requirement'
      USING ERRCODE = '22023';
  END IF;
  level_value := p_requirement ->> 'level';
  local_required_value := (p_requirement ->> 'localRequired')::boolean;
  freshness_seconds := (p_requirement ->> 'freshnessSeconds')::bigint;
  IF freshness_seconds NOT BETWEEN 0 AND 31536000 THEN
    RAISE EXCEPTION 'invalid MFA policy freshness'
      USING ERRCODE = '22023';
  END IF;
  IF p_requirement -> 'enrollmentDeadline' <> 'null'::jsonb THEN
    IF jsonb_typeof(p_requirement -> 'enrollmentDeadline') <> 'string'
       OR p_requirement ->> 'enrollmentDeadline' !~
         '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{3})?Z$' THEN
      RAISE EXCEPTION 'invalid MFA policy enrollment deadline'
        USING ERRCODE = '22023';
    END IF;
    enrollment_deadline :=
      (p_requirement ->> 'enrollmentDeadline')::timestamptz;
    IF NOT isfinite(enrollment_deadline)
       OR date_trunc('milliseconds',enrollment_deadline) <> enrollment_deadline
       OR enrollment_deadline <= transaction_timestamp() THEN
      RAISE EXCEPTION 'invalid MFA policy enrollment deadline'
        USING ERRCODE = '22023';
    END IF;
  END IF;
  RETURN jsonb_build_object(
    'level',level_value,
    'localRequired',local_required_value,
    'freshnessSeconds',freshness_seconds,
    'enrollmentDeadline',CASE WHEN enrollment_deadline IS NULL
      THEN 'null'::jsonb
      ELSE app.private_mfa_policy_instant_v1(enrollment_deadline) END
  );
EXCEPTION WHEN invalid_text_representation OR datetime_field_overflow THEN
  RAISE EXCEPTION 'invalid MFA policy requirement'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_target_v1(
  p_target jsonb,p_platform boolean,p_tenant_id uuid,p_require_live boolean
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  scope_value text;
  tenant_value uuid;
  target_id uuid;
  action_value text;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_target,
    ARRAY['scope','tenantId','roleId','securityGroupId','action'],
    ARRAY['scope'],8192
  );
  IF p_platform IS NULL OR p_require_live IS NULL
     OR jsonb_typeof(p_target -> 'scope') <> 'string' THEN
    RAISE EXCEPTION 'invalid MFA policy target' USING ERRCODE = '22023';
  END IF;
  scope_value := p_target ->> 'scope';
  IF p_platform THEN
    IF p_tenant_id IS NOT NULL OR scope_value <> 'platform_floor'
       OR (SELECT count(*) FROM jsonb_object_keys(p_target)) <> 1 THEN
      RAISE EXCEPTION 'invalid platform MFA policy target'
        USING ERRCODE = '22023';
    END IF;
    RETURN jsonb_build_object('scope','platform_floor');
  END IF;

  IF p_tenant_id IS NULL
     OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR NOT p_target ? 'tenantId'
     OR jsonb_typeof(p_target -> 'tenantId') <> 'string' THEN
    RAISE EXCEPTION 'invalid tenant MFA policy target'
      USING ERRCODE = '22023';
  END IF;
  tenant_value := app.private_mfa_require_uuidv7_v1(
    p_target ->> 'tenantId'
  );
  IF tenant_value IS DISTINCT FROM p_tenant_id THEN
    RAISE EXCEPTION 'cross-tenant MFA policy target is forbidden'
      USING ERRCODE = '42501';
  END IF;
  PERFORM 1 FROM ONLY public.tenants AS tenant
  WHERE tenant.id = p_tenant_id AND tenant.status = 'active';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant MFA policy target does not exist'
      USING ERRCODE = 'P0002';
  END IF;

  IF scope_value = 'tenant_baseline' THEN
    IF (SELECT count(*) FROM jsonb_object_keys(p_target)) <> 2 THEN
      RAISE EXCEPTION 'invalid tenant baseline target'
        USING ERRCODE = '22023';
    END IF;
    RETURN jsonb_build_object(
      'scope',scope_value,'tenantId',p_tenant_id::text
    );
  ELSIF scope_value = 'role' THEN
    IF (SELECT count(*) FROM jsonb_object_keys(p_target)) <> 3
       OR jsonb_typeof(p_target -> 'roleId') <> 'string' THEN
      RAISE EXCEPTION 'invalid tenant role MFA target'
        USING ERRCODE = '22023';
    END IF;
    target_id := app.private_mfa_require_uuidv7_v1(p_target ->> 'roleId');
    PERFORM 1 FROM ONLY public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id AND role.id = target_id
      AND role.principal_kind = 'human'
      AND (NOT p_require_live OR role.archived_at IS NULL);
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant role MFA target does not exist'
        USING ERRCODE = 'P0002';
    END IF;
    RETURN jsonb_build_object(
      'scope',scope_value,'tenantId',p_tenant_id::text,
      'roleId',target_id::text
    );
  ELSIF scope_value = 'security_group' THEN
    IF (SELECT count(*) FROM jsonb_object_keys(p_target)) <> 3
       OR jsonb_typeof(p_target -> 'securityGroupId') <> 'string' THEN
      RAISE EXCEPTION 'invalid tenant security-group MFA target'
        USING ERRCODE = '22023';
    END IF;
    target_id := app.private_mfa_require_uuidv7_v1(
      p_target ->> 'securityGroupId'
    );
    PERFORM 1 FROM ONLY public.tenant_security_groups AS security_group
    WHERE security_group.tenant_id = p_tenant_id
      AND security_group.id = target_id
      AND (NOT p_require_live OR security_group.archived_at IS NULL);
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant security-group MFA target does not exist'
        USING ERRCODE = 'P0002';
    END IF;
    RETURN jsonb_build_object(
      'scope',scope_value,'tenantId',p_tenant_id::text,
      'securityGroupId',target_id::text
    );
  ELSIF scope_value = 'action' THEN
    IF (SELECT count(*) FROM jsonb_object_keys(p_target)) <> 3
       OR jsonb_typeof(p_target -> 'action') <> 'string'
       OR NOT app.private_mfa_safe_text_v1(p_target ->> 'action',256) THEN
      RAISE EXCEPTION 'invalid tenant action MFA target'
        USING ERRCODE = '22023';
    END IF;
    action_value := p_target ->> 'action';
    PERFORM 1
    FROM ONLY public.tenant_permissions AS permission
    JOIN ONLY public.tenant_permission_scopes AS permission_scope
      ON permission_scope.permission_id = permission.id
    WHERE permission.key = action_value
      AND permission_scope.scope = 'tenant';
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant action MFA target does not exist'
        USING ERRCODE = 'P0002';
    END IF;
    RETURN jsonb_build_object(
      'scope',scope_value,'tenantId',p_tenant_id::text,
      'action',action_value
    );
  END IF;
  RAISE EXCEPTION 'unsupported MFA policy target scope'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_document_v1(
  p_policy public.mfa_policy_revisions
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT jsonb_build_object(
    'id',p_policy.id::text,
    'revision',p_policy.revision,
    'target',jsonb_strip_nulls(jsonb_build_object(
      'scope',p_policy.scope,
      'tenantId',p_policy.tenant_id::text,
      'roleId',p_policy.role_id::text,
      'securityGroupId',p_policy.security_group_id::text,
      'action',p_policy.action
    )),
    'requirement',jsonb_build_object(
      'level',p_policy.level,
      'localRequired',p_policy.local_required,
      'freshnessSeconds',p_policy.freshness_nanoseconds / 1000000000,
      'enrollmentDeadline',CASE WHEN p_policy.enrollment_deadline IS NULL
        THEN 'null'::jsonb ELSE app.private_mfa_policy_instant_v1(
          p_policy.enrollment_deadline
        ) END
    ),
    'status',CASE WHEN p_policy.retired_at IS NULL
      THEN 'live' ELSE 'retired' END,
    'createdAt',app.private_mfa_policy_instant_v1(p_policy.created_at),
    'retiredAt',CASE WHEN p_policy.retired_at IS NULL
      THEN 'null'::jsonb ELSE
        app.private_mfa_policy_instant_v1(p_policy.retired_at) END
  );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_require_recent_local_mfa_policy_session_v1(
  p_session_id uuid,p_tenant_id uuid,p_authentication_method text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  active_tenant_id uuid;
  local_assurance boolean := false;
BEGIN
  IF p_session_id IS NULL
     OR uuid_extract_version(p_session_id) IS DISTINCT FROM 7
     OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','passkey','oidc','saml'
     ) THEN
    RAISE EXCEPTION 'recent local MFA session is required'
      USING ERRCODE = '42501';
  END IF;
  SELECT session.active_tenant_id INTO active_tenant_id
  FROM ONLY public.auth_sessions AS session
  JOIN ONLY public.users AS local_user ON local_user.id = session.user_id
  WHERE session.id = p_session_id
    AND session.user_id = actor_id
    AND session.authentication_method = p_authentication_method
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at BETWEEN
      transaction_timestamp() - interval '5 minutes'
      AND transaction_timestamp() + interval '30 seconds'
    AND local_user.active
  FOR SHARE OF session,local_user;
  IF NOT FOUND OR (p_tenant_id IS NOT NULL
    AND active_tenant_id IS DISTINCT FROM p_tenant_id) THEN
    RAISE EXCEPTION 'recent local MFA session is required'
      USING ERRCODE = '42501';
  END IF;

  IF active_tenant_id IS NOT NULL THEN
    SELECT EXISTS (
      SELECT 1
      FROM ONLY public.auth_session_mfa_states AS state
      JOIN ONLY public.auth_session_mfa_evidence AS evidence
        ON evidence.tenant_id = state.tenant_id
       AND evidence.session_id = state.session_id
      LEFT JOIN ONLY public.tenant_totp_factors AS totp_factor
        ON evidence.kind = 'totp'
       AND totp_factor.tenant_id = evidence.tenant_id
       AND totp_factor.user_id = state.user_id
       AND totp_factor.id = evidence.totp_factor_id
       AND totp_factor.security_revision = evidence.factor_revision
       AND totp_factor.status = 'active'
       AND totp_factor.revoked_at IS NULL
      LEFT JOIN ONLY public.tenant_webauthn_credentials AS webauthn_credential
        ON evidence.kind = 'webauthn'
       AND webauthn_credential.tenant_id = evidence.tenant_id
       AND webauthn_credential.user_id = state.user_id
       AND webauthn_credential.id = evidence.webauthn_credential_id
       AND webauthn_credential.security_revision = evidence.factor_revision
       AND webauthn_credential.status = 'active'
       AND webauthn_credential.revoked_at IS NULL
       AND webauthn_credential.user_verification
      WHERE state.session_id = p_session_id
        AND state.tenant_id = active_tenant_id
        AND state.user_id = actor_id
        AND NOT state.recovery_restricted
        AND state.issued_at <= transaction_timestamp() + interval '30 seconds'
        AND evidence.kind IN ('totp','webauthn')
        AND evidence.level IN ('mfa','phishing_resistant')
        AND evidence.authenticated_at BETWEEN
          transaction_timestamp() - interval '5 minutes'
          AND transaction_timestamp() + interval '30 seconds'
        AND evidence.authenticated_at <= state.issued_at + interval '30 seconds'
        AND (evidence.expires_at IS NULL
          OR evidence.expires_at > transaction_timestamp())
        AND ((evidence.kind = 'totp' AND totp_factor.id IS NOT NULL)
          OR (evidence.kind = 'webauthn'
            AND webauthn_credential.id IS NOT NULL))
    ) INTO local_assurance;
  ELSE
    SELECT EXISTS (
      SELECT 1
      FROM ONLY public.auth_session_platform_oidc_states AS state
      JOIN ONLY public.auth_session_platform_oidc_evidence AS evidence
        ON evidence.session_id = state.session_id
       AND evidence.user_id = state.user_id
       AND evidence.kind = 'totp'
       AND evidence.level = 'mfa'
      JOIN ONLY public.totp_credentials AS factor
        ON factor.id = evidence.totp_credential_id
       AND factor.user_id = state.user_id
       AND factor.security_revision = evidence.factor_revision
       AND factor.confirmed_at IS NOT NULL
       AND factor.disabled_at IS NULL
       AND factor.last_accepted_counter IS NOT NULL
      WHERE state.session_id = p_session_id
        AND state.user_id = actor_id
        AND NOT state.recovery_restricted
        AND state.issued_at <= transaction_timestamp() + interval '30 seconds'
        AND evidence.authenticated_at BETWEEN
          transaction_timestamp() - interval '5 minutes'
          AND transaction_timestamp() + interval '30 seconds'
        AND evidence.authenticated_at <= state.issued_at + interval '30 seconds'
        AND (evidence.expires_at IS NULL
          OR evidence.expires_at > transaction_timestamp())
    ) INTO local_assurance;

    IF NOT local_assurance THEN
      SELECT EXISTS (
        SELECT 1
        FROM ONLY public.local_break_glass_credentials AS credential
        JOIN ONLY public.user_login_identifiers AS identifier
          ON identifier.id = credential.login_identifier_id
         AND identifier.user_id = credential.user_id
         AND identifier.kind = 'local_email'
         AND identifier.verified_at IS NOT NULL
         AND identifier.retired_at IS NULL
        JOIN ONLY public.totp_credentials AS factor
          ON factor.user_id = credential.user_id
         AND factor.confirmed_at IS NOT NULL
         AND factor.disabled_at IS NULL
         AND factor.last_accepted_counter IS NOT NULL
         AND factor.updated_at = (
           SELECT session.mfa_satisfied_at
           FROM ONLY public.auth_sessions AS session
           WHERE session.id = p_session_id
         )
        WHERE credential.user_id = actor_id
          AND credential.disabled_at IS NULL
          AND NOT credential.must_rotate
          AND p_authentication_method IN ('bootstrap_totp','totp')
      ) INTO local_assurance;
    END IF;
  END IF;

  IF NOT local_assurance THEN
    RAISE EXCEPTION 'recent exact local MFA assurance is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN actor_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_require_platform_mfa_policy_authority_v1(
  p_session_id uuid,p_permission text,p_authentication_method text,
  p_require_recent_local boolean
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid;
BEGIN
  IF p_permission NOT IN (
    'platform.identity_policy.read','platform.identity_policy.manage'
  ) OR p_require_recent_local IS NULL THEN
    RAISE EXCEPTION 'invalid platform MFA policy authority request'
      USING ERRCODE = '22023';
  END IF;
  actor_id := app.private_require_platform_identity_permission_v1(
    p_session_id,p_permission,p_authentication_method
  );
  IF p_require_recent_local AND actor_id IS DISTINCT FROM
    app.private_require_recent_local_mfa_policy_session_v1(
      p_session_id,NULL,p_authentication_method
    ) THEN
    RAISE EXCEPTION 'recent platform MFA policy authority is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN actor_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_require_tenant_mfa_policy_authority_v1(
  p_session_id uuid,p_tenant_id uuid,p_permission text,
  p_authentication_method text,p_require_recent_local boolean
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  live_method text;
BEGIN
  IF p_tenant_id IS NULL
     OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7
     OR p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_permission NOT IN ('identity_policy.read','identity_policy.manage')
     OR p_require_recent_local IS NULL THEN
    RAISE EXCEPTION 'invalid tenant MFA policy authority request'
      USING ERRCODE = '42501';
  END IF;
  live_method := app.require_live_audit_session_v1(
    p_session_id,p_tenant_id
  );
  IF live_method IS DISTINCT FROM p_authentication_method
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       p_permission,'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant MFA policy permission is required'
      USING ERRCODE = '42501';
  END IF;
  PERFORM 1
  FROM ONLY public.tenant_authorization_states AS state
  JOIN ONLY public.tenants AS tenant ON tenant.id = state.tenant_id
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = state.tenant_id
   AND membership.user_id = actor_id
  WHERE state.tenant_id = p_tenant_id
    AND state.initialized_at IS NOT NULL
    AND tenant.status = 'active'
    AND membership.status = 'active'
  FOR SHARE OF state,tenant,membership;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant MFA policy authority is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_require_recent_local AND actor_id IS DISTINCT FROM
    app.private_require_recent_local_mfa_policy_session_v1(
      p_session_id,p_tenant_id,p_authentication_method
    ) THEN
    RAISE EXCEPTION 'recent tenant MFA policy authority is required'
      USING ERRCODE = '42501';
  END IF;
  RETURN actor_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_simulation_context_v1(
  p_context jsonb,p_tenant_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  role_ids uuid[];
  security_group_ids uuid[];
  action_value text;
  role_count integer;
  security_group_count integer;
BEGIN
  IF p_tenant_id IS NULL
     OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7 THEN
    RAISE EXCEPTION 'invalid tenant MFA simulation context'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_mfa_assert_json_object_v1(
    p_context,ARRAY['roleIds','securityGroupIds','action'],
    ARRAY['roleIds','securityGroupIds','action'],65536
  );
  IF jsonb_typeof(p_context -> 'roleIds') <> 'array'
     OR jsonb_typeof(p_context -> 'securityGroupIds') <> 'array'
     OR jsonb_typeof(p_context -> 'action') <> 'string'
     OR jsonb_array_length(p_context -> 'roleIds') > 512
     OR jsonb_array_length(p_context -> 'securityGroupIds') > 512
     OR NOT app.private_mfa_safe_text_v1(p_context ->> 'action',256) THEN
    RAISE EXCEPTION 'invalid tenant MFA simulation context'
      USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM jsonb_array_elements(p_context -> 'roleIds') AS item(value)
    WHERE jsonb_typeof(item.value) <> 'string'
  ) OR EXISTS (
    SELECT 1
    FROM jsonb_array_elements(p_context -> 'securityGroupIds') AS item(value)
    WHERE jsonb_typeof(item.value) <> 'string'
  ) THEN
    RAISE EXCEPTION 'invalid tenant MFA simulation context identifiers'
      USING ERRCODE = '22023';
  END IF;

  SELECT coalesce(array_agg(parsed.id ORDER BY parsed.id),'{}'::uuid[]),
         count(*)::integer
    INTO STRICT role_ids,role_count
  FROM (
    SELECT app.private_mfa_require_uuidv7_v1(item.value #>> '{}') AS id
    FROM jsonb_array_elements(p_context -> 'roleIds') AS item(value)
  ) AS parsed;
  IF role_count <> (SELECT count(DISTINCT role_id) FROM unnest(role_ids) AS role_id)
     OR role_count <> (
       SELECT count(*)
       FROM ONLY public.tenant_roles AS role
       WHERE role.tenant_id = p_tenant_id
         AND role.id = ANY(role_ids)
         AND role.principal_kind = 'human'
     ) THEN
    RAISE EXCEPTION 'tenant MFA simulation roles are duplicate or unavailable'
      USING ERRCODE = '22023';
  END IF;

  SELECT coalesce(array_agg(parsed.id ORDER BY parsed.id),'{}'::uuid[]),
         count(*)::integer
    INTO STRICT security_group_ids,security_group_count
  FROM (
    SELECT app.private_mfa_require_uuidv7_v1(item.value #>> '{}') AS id
    FROM jsonb_array_elements(
      p_context -> 'securityGroupIds'
    ) AS item(value)
  ) AS parsed;
  IF security_group_count <> (
       SELECT count(DISTINCT group_id)
       FROM unnest(security_group_ids) AS group_id
     ) OR security_group_count <> (
       SELECT count(*)
       FROM ONLY public.tenant_security_groups AS security_group
       WHERE security_group.tenant_id = p_tenant_id
         AND security_group.id = ANY(security_group_ids)
     ) THEN
    RAISE EXCEPTION 'tenant MFA simulation groups are duplicate or unavailable'
      USING ERRCODE = '22023';
  END IF;

  action_value := p_context ->> 'action';
  PERFORM 1
  FROM ONLY public.tenant_permissions AS permission
  JOIN ONLY public.tenant_permission_scopes AS permission_scope
    ON permission_scope.permission_id = permission.id
  WHERE permission.key = action_value
    AND permission_scope.scope = 'tenant';
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant MFA simulation action is unavailable'
      USING ERRCODE = '22023';
  END IF;
  RETURN jsonb_build_object(
    'roleIds',to_jsonb(role_ids::text[]),
    'securityGroupIds',to_jsonb(security_group_ids::text[]),
    'action',action_value
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_matches_target_v1(
  p_policy public.mfa_policy_revisions,p_target jsonb
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT p_policy.scope = p_target ->> 'scope'
     AND CASE p_policy.scope
       WHEN 'platform_floor' THEN p_policy.tenant_id IS NULL
       WHEN 'tenant_baseline' THEN
         p_policy.tenant_id::text = p_target ->> 'tenantId'
       WHEN 'role' THEN p_policy.tenant_id::text = p_target ->> 'tenantId'
         AND p_policy.role_id::text = p_target ->> 'roleId'
       WHEN 'security_group' THEN
         p_policy.tenant_id::text = p_target ->> 'tenantId'
         AND p_policy.security_group_id::text =
           p_target ->> 'securityGroupId'
       WHEN 'action' THEN p_policy.tenant_id::text = p_target ->> 'tenantId'
         AND p_policy.action = p_target ->> 'action'
       ELSE false
     END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_effective_v1(
  p_tenant_id uuid,p_context jsonb,p_changed_target jsonb,
  p_candidate_requirement jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  policy_count integer;
  baseline_count integer;
  requirement_result jsonb;
  source_result jsonb;
BEGIN
  IF p_tenant_id IS NULL THEN
    IF p_context IS NOT NULL
       OR p_changed_target ->> 'scope' <> 'platform_floor' THEN
      RAISE EXCEPTION 'invalid platform MFA effective-policy request'
        USING ERRCODE = '22023';
    END IF;
  ELSIF p_context IS NULL
     OR p_changed_target ->> 'scope' = 'platform_floor' THEN
    RAISE EXCEPTION 'invalid tenant MFA effective-policy request'
      USING ERRCODE = '22023';
  END IF;

  WITH applicable AS (
    SELECT policy.id,policy.revision,policy.scope,policy.tenant_id,
      policy.role_id,policy.security_group_id,policy.action,policy.level,
      policy.local_required,
      policy.freshness_nanoseconds / 1000000000 AS freshness_seconds,
      policy.enrollment_deadline,false AS candidate
    FROM ONLY public.mfa_policy_revisions AS policy
    WHERE policy.retired_at IS NULL
      AND NOT app.private_mfa_policy_matches_target_v1(
        policy,p_changed_target
      )
      AND (
        (p_tenant_id IS NULL AND policy.scope = 'platform_floor')
        OR (p_tenant_id IS NOT NULL AND (
          policy.scope = 'platform_floor'
          OR (policy.tenant_id = p_tenant_id AND (
            policy.scope = 'tenant_baseline'
            OR (policy.scope = 'role' AND (p_context -> 'roleIds') @>
              jsonb_build_array(policy.role_id::text))
            OR (policy.scope = 'security_group'
              AND (p_context -> 'securityGroupIds') @>
                jsonb_build_array(policy.security_group_id::text))
            OR (policy.scope = 'action'
              AND policy.action = p_context ->> 'action')
          ))
        ))
      )
    UNION ALL
    SELECT NULL::uuid,NULL::bigint,p_changed_target ->> 'scope',
      CASE WHEN p_tenant_id IS NULL THEN NULL ELSE p_tenant_id END,
      CASE WHEN p_changed_target ->> 'scope' = 'role'
        THEN (p_changed_target ->> 'roleId')::uuid END,
      CASE WHEN p_changed_target ->> 'scope' = 'security_group'
        THEN (p_changed_target ->> 'securityGroupId')::uuid END,
      CASE WHEN p_changed_target ->> 'scope' = 'action'
        THEN p_changed_target ->> 'action' END,
      p_candidate_requirement ->> 'level',
      (p_candidate_requirement ->> 'localRequired')::boolean,
      (p_candidate_requirement ->> 'freshnessSeconds')::bigint,
      CASE WHEN p_candidate_requirement -> 'enrollmentDeadline' =
        'null'::jsonb THEN NULL ELSE
        (p_candidate_requirement ->> 'enrollmentDeadline')::timestamptz END,
      true
    WHERE p_candidate_requirement IS NOT NULL
      AND (
        p_tenant_id IS NULL
        OR p_changed_target ->> 'scope' = 'tenant_baseline'
        OR (p_changed_target ->> 'scope' = 'role'
          AND (p_context -> 'roleIds') @>
            jsonb_build_array(p_changed_target ->> 'roleId'))
        OR (p_changed_target ->> 'scope' = 'security_group'
          AND (p_context -> 'securityGroupIds') @>
            jsonb_build_array(p_changed_target ->> 'securityGroupId'))
        OR (p_changed_target ->> 'scope' = 'action'
          AND p_changed_target ->> 'action' = p_context ->> 'action')
      )
  ), inventory AS (
    SELECT count(*)::integer AS policy_count,
      count(*) FILTER (WHERE scope = 'tenant_baseline')::integer
        AS baseline_count
    FROM applicable
  ), folded AS (
    SELECT inventory.policy_count,inventory.baseline_count,
      CASE WHEN inventory.policy_count = 0 THEN NULL ELSE jsonb_build_object(
        'level',CASE max(CASE applicable.level WHEN 'primary' THEN 1
          WHEN 'mfa' THEN 2 WHEN 'phishing_resistant' THEN 3 END)
          WHEN 1 THEN 'primary' WHEN 2 THEN 'mfa'
          WHEN 3 THEN 'phishing_resistant' END,
        'localRequired',coalesce(bool_or(applicable.local_required),false),
        'freshnessSeconds',coalesce(min(applicable.freshness_seconds)
          FILTER (WHERE applicable.freshness_seconds > 0),0),
        'enrollmentDeadline',CASE WHEN min(applicable.enrollment_deadline)
          IS NULL THEN 'null'::jsonb
          ELSE app.private_mfa_policy_instant_v1(
            min(applicable.enrollment_deadline)
          ) END
      ) END AS requirement,
      coalesce(jsonb_agg(
        CASE WHEN applicable.candidate THEN jsonb_build_object(
          'source','candidate','target',jsonb_strip_nulls(jsonb_build_object(
            'scope',applicable.scope,
            'tenantId',applicable.tenant_id::text,
            'roleId',applicable.role_id::text,
            'securityGroupId',applicable.security_group_id::text,
            'action',applicable.action
          )),'requirement',jsonb_build_object(
            'level',applicable.level,
            'localRequired',applicable.local_required,
            'freshnessSeconds',applicable.freshness_seconds,
            'enrollmentDeadline',CASE
              WHEN applicable.enrollment_deadline IS NULL THEN 'null'::jsonb
              ELSE app.private_mfa_policy_instant_v1(
                applicable.enrollment_deadline
              ) END
          )
        ) ELSE jsonb_build_object(
          'source','current','policyId',applicable.id::text,
          'revision',applicable.revision,
          'target',jsonb_strip_nulls(jsonb_build_object(
            'scope',applicable.scope,
            'tenantId',applicable.tenant_id::text,
            'roleId',applicable.role_id::text,
            'securityGroupId',applicable.security_group_id::text,
            'action',applicable.action
          )),'requirement',jsonb_build_object(
            'level',applicable.level,
            'localRequired',applicable.local_required,
            'freshnessSeconds',applicable.freshness_seconds,
            'enrollmentDeadline',CASE
              WHEN applicable.enrollment_deadline IS NULL THEN 'null'::jsonb
              ELSE app.private_mfa_policy_instant_v1(
                applicable.enrollment_deadline
              ) END
          )
        ) END ORDER BY
          CASE applicable.scope WHEN 'platform_floor' THEN 1
            WHEN 'tenant_baseline' THEN 2 WHEN 'security_group' THEN 3
            WHEN 'role' THEN 4 WHEN 'action' THEN 5 END,
          coalesce(applicable.role_id::text,
            applicable.security_group_id::text,applicable.action,''),
          applicable.id::text NULLS LAST,applicable.revision
      ) FILTER (WHERE applicable.scope IS NOT NULL),'[]'::jsonb) AS sources
    FROM inventory LEFT JOIN applicable ON true
    GROUP BY inventory.policy_count,inventory.baseline_count
  )
  SELECT folded.policy_count,folded.baseline_count,folded.requirement,
         folded.sources
    INTO STRICT policy_count,baseline_count,requirement_result,source_result
  FROM folded;
  IF policy_count > 1024
     OR (p_tenant_id IS NULL AND policy_count > 1)
     OR (p_tenant_id IS NOT NULL AND baseline_count <> 1) THEN
    RAISE EXCEPTION 'MFA effective-policy set is unavailable or ambiguous'
      USING ERRCODE = '55000';
  END IF;
  RETURN jsonb_build_object(
    'requirement',coalesce(requirement_result,'null'::jsonb),
    'sources',source_result
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_recovery_capable_v1(
  p_user_id uuid,p_tenant_id uuid,p_requirement jsonb
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  requirement_level text := coalesce(
    p_requirement ->> 'level','primary'
  );
  has_local_primary boolean := false;
  has_global_local_mfa boolean := false;
  has_local_mfa boolean := false;
  has_local_phishing_resistant boolean := false;
BEGIN
  IF p_user_id IS NULL
     OR uuid_extract_version(p_user_id) IS DISTINCT FROM 7
     OR requirement_level NOT IN ('primary','mfa','phishing_resistant') THEN
    RAISE EXCEPTION 'invalid MFA recovery-capability request'
      USING ERRCODE = '22023';
  END IF;
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.local_break_glass_credentials AS credential
    JOIN ONLY public.user_login_identifiers AS identifier
      ON identifier.id = credential.login_identifier_id
     AND identifier.user_id = credential.user_id
     AND identifier.kind = 'local_email'
     AND identifier.verified_at IS NOT NULL
     AND identifier.retired_at IS NULL
    WHERE credential.user_id = p_user_id
      AND credential.disabled_at IS NULL
      AND NOT credential.must_rotate
    FOR SHARE OF credential,identifier
  ) INTO has_local_primary;
  IF NOT has_local_primary THEN
    RETURN false;
  END IF;

  -- A break-glass account is usable only when its global local-login TOTP is
  -- confirmed and live.  This is a prerequisite even for an authored
  -- `primary` requirement: recovery must never rely on a password alone.
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.totp_credentials AS factor
    WHERE factor.user_id = p_user_id
      AND factor.confirmed_at IS NOT NULL
      AND factor.disabled_at IS NULL
      AND factor.last_accepted_counter IS NOT NULL
    FOR SHARE OF factor
  ) INTO has_global_local_mfa;
  IF NOT has_global_local_mfa THEN
    RETURN false;
  END IF;

  IF p_tenant_id IS NULL THEN
    IF requirement_level = 'phishing_resistant' THEN
      RETURN false;
    END IF;
    RETURN true;
  END IF;

  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_totp_factors AS factor
    WHERE factor.tenant_id = p_tenant_id
      AND factor.user_id = p_user_id
      AND factor.status = 'active'
      AND factor.revoked_at IS NULL
    FOR SHARE OF factor
  ) OR EXISTS (
    SELECT 1
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = p_tenant_id
      AND credential.user_id = p_user_id
      AND credential.status = 'active'
      AND credential.revoked_at IS NULL
      AND credential.user_verification
    FOR SHARE OF credential
  ) INTO has_local_mfa;
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = p_tenant_id
      AND credential.user_id = p_user_id
      AND credential.status = 'active'
      AND credential.revoked_at IS NULL
      AND credential.user_verification
    FOR SHARE OF credential
  ) INTO has_local_phishing_resistant;
  RETURN CASE requirement_level
    WHEN 'primary' THEN CASE
      WHEN coalesce((p_requirement ->> 'localRequired')::boolean,false)
        THEN has_local_mfa
      ELSE true
    END
    WHEN 'mfa' THEN has_local_mfa
    WHEN 'phishing_resistant' THEN has_local_phishing_resistant
    ELSE false
  END;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_recovery_v1(
  p_tenant_id uuid,p_changed_target jsonb,p_candidate_requirement jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  administrator record;
  role_ids uuid[];
  security_group_ids uuid[];
  recovery_action text;
  recovery_context jsonb;
  effective jsonb;
  effective_requirement jsonb;
  eligible_count bigint := 0;
  ready_count bigint := 0;
  failure_reason text;
  failure_reasons text[] := '{}'::text[];
  seen_membership_ids uuid[] := '{}'::uuid[];
  reason_codes jsonb := '[]'::jsonb;
BEGIN
  IF p_tenant_id IS NULL THEN
    effective := app.private_mfa_policy_effective_v1(
      NULL,NULL,p_changed_target,p_candidate_requirement
    );
    effective_requirement := effective -> 'requirement';
    IF effective_requirement = 'null'::jsonb THEN
      effective_requirement := jsonb_build_object(
        'level','primary','localRequired',true,'freshnessSeconds',0,
        'enrollmentDeadline','null'::jsonb
      );
    END IF;
    FOR administrator IN
      SELECT identity.id AS user_id
      FROM ONLY public.user_platform_roles AS role_grant
      JOIN ONLY public.platform_roles AS role
        ON role.id = role_grant.role_id
       AND role.key = 'platform_super_admin'
      JOIN ONLY public.users AS identity
        ON identity.id = role_grant.user_id AND identity.active
      WHERE role_grant.revoked_at IS NULL
      ORDER BY identity.id
      FOR SHARE OF role_grant,role,identity
    LOOP
      eligible_count := eligible_count + 1;
      IF app.private_mfa_policy_recovery_capable_v1(
        administrator.user_id,NULL,effective_requirement
      ) THEN
        ready_count := ready_count + 1;
      ELSE
        failure_reasons := array_append(
          failure_reasons,CASE effective_requirement ->> 'level'
            WHEN 'primary' THEN 'no_ready_local_primary'
            WHEN 'mfa' THEN 'no_ready_local_mfa'
            WHEN 'phishing_resistant' THEN
              'no_ready_local_phishing_resistant' END
        );
      END IF;
    END LOOP;
  ELSE
    recovery_action := CASE WHEN p_changed_target ->> 'scope' = 'action'
      THEN p_changed_target ->> 'action' ELSE 'identity_policy.manage' END;
    FOR administrator IN
      SELECT membership.id AS membership_id,membership.user_id
      FROM ONLY public.tenant_membership_role_grants AS role_grant
      JOIN ONLY public.tenant_authorization_sources AS source
        ON source.tenant_id = role_grant.tenant_id
       AND source.id = role_grant.source_id
       AND source.kind IN ('tenant_creation','manual','platform_recovery')
       AND source.retired_at IS NULL
      JOIN ONLY public.tenant_roles AS role
        ON role.tenant_id = role_grant.tenant_id
       AND role.id = role_grant.role_id
       AND role.key = 'tenant_admin'
       AND role.system_role AND role.protected_role
       AND role.principal_kind = 'human' AND role.archived_at IS NULL
      JOIN ONLY public.tenant_memberships AS membership
        ON membership.tenant_id = role_grant.tenant_id
       AND membership.id = role_grant.membership_id
       AND membership.status = 'active'
      JOIN ONLY public.users AS identity
        ON identity.id = membership.user_id AND identity.active
      WHERE role_grant.tenant_id = p_tenant_id
        AND role_grant.revoked_at IS NULL
        AND role_grant.expires_at IS NULL
      ORDER BY membership.id,membership.user_id
      FOR SHARE OF role_grant,source,role,membership,identity
    LOOP
      IF administrator.membership_id = ANY(seen_membership_ids) THEN
        CONTINUE;
      END IF;
      seen_membership_ids := array_append(
        seen_membership_ids,administrator.membership_id
      );
      eligible_count := eligible_count + 1;
      -- Freeze every direct and group-derived recovery-authority input before
      -- folding the effective policy. Tenant authorization writers already
      -- serialize on tenant_authorization_states; these row locks additionally
      -- serialize user/membership/source lifecycle changes with this proof.
      PERFORM 1
      FROM ONLY public.tenant_membership_role_grants AS role_grant
      JOIN ONLY public.tenant_authorization_sources AS source
        ON source.tenant_id = role_grant.tenant_id
       AND source.id = role_grant.source_id
       AND source.kind IN ('tenant_creation','manual','platform_recovery')
       AND source.retired_at IS NULL
      JOIN ONLY public.tenant_roles AS role
        ON role.tenant_id = role_grant.tenant_id
       AND role.id = role_grant.role_id
       AND role.principal_kind = 'human' AND role.archived_at IS NULL
      WHERE role_grant.tenant_id = p_tenant_id
        AND role_grant.membership_id = administrator.membership_id
        AND role_grant.revoked_at IS NULL
        AND (role_grant.expires_at IS NULL
          OR role_grant.expires_at > transaction_timestamp())
      FOR SHARE OF role_grant,source,role;
      PERFORM 1
      FROM ONLY public.tenant_security_group_memberships AS group_member
      JOIN ONLY public.tenant_authorization_sources AS member_source
        ON member_source.tenant_id = group_member.tenant_id
       AND member_source.id = group_member.source_id
       AND member_source.kind IN (
         'tenant_creation','manual','platform_recovery'
       ) AND member_source.retired_at IS NULL
      JOIN ONLY public.tenant_security_groups AS security_group
        ON security_group.tenant_id = group_member.tenant_id
       AND security_group.id = group_member.group_id
       AND security_group.archived_at IS NULL
      WHERE group_member.tenant_id = p_tenant_id
        AND group_member.membership_id = administrator.membership_id
        AND group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp())
      FOR SHARE OF group_member,member_source,security_group;
      PERFORM 1
      FROM ONLY public.tenant_security_group_memberships AS group_member
      JOIN ONLY public.tenant_security_group_role_grants AS group_role
        ON group_role.tenant_id = group_member.tenant_id
       AND group_role.group_id = group_member.group_id
       AND group_role.revoked_at IS NULL
       AND (group_role.expires_at IS NULL
         OR group_role.expires_at > transaction_timestamp())
      JOIN ONLY public.tenant_authorization_sources AS role_source
        ON role_source.tenant_id = group_role.tenant_id
       AND role_source.id = group_role.source_id
       AND role_source.kind IN (
         'tenant_creation','manual','platform_recovery'
       ) AND role_source.retired_at IS NULL
      JOIN ONLY public.tenant_roles AS role
        ON role.tenant_id = group_role.tenant_id
       AND role.id = group_role.role_id
       AND role.principal_kind = 'human' AND role.archived_at IS NULL
      WHERE group_member.tenant_id = p_tenant_id
        AND group_member.membership_id = administrator.membership_id
        AND group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp())
      FOR SHARE OF group_role,role_source,role;
      SELECT coalesce(array_agg(DISTINCT candidate.role_id
        ORDER BY candidate.role_id),'{}'::uuid[])
        INTO STRICT role_ids
      FROM (
        SELECT role_grant.role_id
        FROM ONLY public.tenant_membership_role_grants AS role_grant
        JOIN ONLY public.tenant_authorization_sources AS source
          ON source.tenant_id = role_grant.tenant_id
         AND source.id = role_grant.source_id
         AND source.kind IN (
           'tenant_creation','manual','platform_recovery'
         ) AND source.retired_at IS NULL
        JOIN ONLY public.tenant_roles AS role
          ON role.tenant_id = role_grant.tenant_id
         AND role.id = role_grant.role_id
         AND role.principal_kind = 'human' AND role.archived_at IS NULL
        WHERE role_grant.tenant_id = p_tenant_id
          AND role_grant.membership_id = administrator.membership_id
          AND role_grant.revoked_at IS NULL
          AND (role_grant.expires_at IS NULL
            OR role_grant.expires_at > transaction_timestamp())
        UNION
        SELECT group_role.role_id
        FROM ONLY public.tenant_security_group_memberships AS group_member
        JOIN ONLY public.tenant_authorization_sources AS member_source
          ON member_source.tenant_id = group_member.tenant_id
         AND member_source.id = group_member.source_id
         AND member_source.kind IN (
           'tenant_creation','manual','platform_recovery'
         ) AND member_source.retired_at IS NULL
        JOIN ONLY public.tenant_security_groups AS security_group
          ON security_group.tenant_id = group_member.tenant_id
         AND security_group.id = group_member.group_id
         AND security_group.archived_at IS NULL
        JOIN ONLY public.tenant_security_group_role_grants AS group_role
          ON group_role.tenant_id = group_member.tenant_id
         AND group_role.group_id = group_member.group_id
         AND group_role.revoked_at IS NULL
         AND (group_role.expires_at IS NULL
           OR group_role.expires_at > transaction_timestamp())
        JOIN ONLY public.tenant_authorization_sources AS role_source
          ON role_source.tenant_id = group_role.tenant_id
         AND role_source.id = group_role.source_id
         AND role_source.kind IN (
           'tenant_creation','manual','platform_recovery'
         ) AND role_source.retired_at IS NULL
        JOIN ONLY public.tenant_roles AS role
          ON role.tenant_id = group_role.tenant_id
         AND role.id = group_role.role_id
         AND role.principal_kind = 'human' AND role.archived_at IS NULL
        WHERE group_member.tenant_id = p_tenant_id
          AND group_member.membership_id = administrator.membership_id
          AND group_member.revoked_at IS NULL
          AND (group_member.expires_at IS NULL
            OR group_member.expires_at > transaction_timestamp())
      ) AS candidate;
      SELECT coalesce(array_agg(DISTINCT group_member.group_id
        ORDER BY group_member.group_id),'{}'::uuid[])
        INTO STRICT security_group_ids
      FROM ONLY public.tenant_security_group_memberships AS group_member
      JOIN ONLY public.tenant_authorization_sources AS source
        ON source.tenant_id = group_member.tenant_id
       AND source.id = group_member.source_id
       AND source.kind IN ('tenant_creation','manual','platform_recovery')
       AND source.retired_at IS NULL
      JOIN ONLY public.tenant_security_groups AS security_group
        ON security_group.tenant_id = group_member.tenant_id
       AND security_group.id = group_member.group_id
       AND security_group.archived_at IS NULL
      WHERE group_member.tenant_id = p_tenant_id
        AND group_member.membership_id = administrator.membership_id
        AND group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp());
      IF cardinality(role_ids) <= 512
         AND cardinality(security_group_ids) <= 512 THEN
        recovery_context := jsonb_build_object(
          'roleIds',to_jsonb(role_ids::text[]),
          'securityGroupIds',to_jsonb(security_group_ids::text[]),
          'action',recovery_action
        );
        effective := app.private_mfa_policy_effective_v1(
          p_tenant_id,recovery_context,p_changed_target,
          p_candidate_requirement
        );
        effective_requirement := effective -> 'requirement';
        IF effective_requirement <> 'null'::jsonb
           AND app.private_mfa_policy_recovery_capable_v1(
             administrator.user_id,p_tenant_id,effective_requirement
           ) THEN
          ready_count := ready_count + 1;
        ELSE
          failure_reasons := array_append(
          failure_reasons,CASE coalesce(
              effective_requirement ->> 'level','primary'
            ) WHEN 'primary' THEN CASE WHEN coalesce(
                (effective_requirement ->> 'localRequired')::boolean,false
              ) THEN 'no_ready_local_mfa' ELSE 'no_ready_local_primary' END
              WHEN 'mfa' THEN 'no_ready_local_mfa'
              WHEN 'phishing_resistant' THEN
                'no_ready_local_phishing_resistant' END
          );
        END IF;
      ELSE
        failure_reasons := array_append(
          failure_reasons,'no_ready_local_primary'
        );
      END IF;
    END LOOP;
  END IF;

  IF eligible_count = 0 THEN
    reason_codes := jsonb_build_array('no_eligible_direct_administrator');
  ELSIF ready_count = 0 THEN
    SELECT coalesce(jsonb_agg(DISTINCT reason ORDER BY reason),'[]'::jsonb)
      INTO STRICT reason_codes
    FROM unnest(failure_reasons) AS reason
    WHERE reason IS NOT NULL;
  END IF;
  RETURN jsonb_build_object(
    'safe',ready_count > 0,
    'eligibleDirectAdministrators',eligible_count,
    'readyDirectAdministrators',ready_count,
    'reasonCodes',reason_codes
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_simulate_mfa_policy_change_v1(
  p_platform boolean,p_tenant_id uuid,p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  operation_value text;
  expected_revision bigint;
  expected_policy_id uuid;
  target_value jsonb;
  requirement_value jsonb;
  context_value jsonb;
  current_policy public.mfa_policy_revisions%ROWTYPE;
  current_found boolean := false;
  current_document jsonb := 'null'::jsonb;
  candidate_document jsonb := 'null'::jsonb;
  effective_document jsonb;
  recovery_document jsonb;
BEGIN
  IF p_platform IS NULL OR (p_platform AND p_tenant_id IS NOT NULL)
     OR (NOT p_platform AND (p_tenant_id IS NULL
       OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7)) THEN
    RAISE EXCEPTION 'invalid MFA simulation authority boundary'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_mfa_assert_json_object_v1(
    p_request,
    ARRAY['operation','target','expectedRevision','expectedPolicyId',
      'requirement','context'],
    ARRAY['operation','target','expectedRevision'],131072
  );
  IF jsonb_typeof(p_request -> 'operation') <> 'string'
     OR p_request ->> 'operation' NOT IN ('publish','retire')
     OR jsonb_typeof(p_request -> 'expectedRevision') <> 'number'
     OR p_request ->> 'expectedRevision' !~ '^(0|[1-9][0-9]{0,15})$' THEN
    RAISE EXCEPTION 'invalid MFA simulation operation or revision'
      USING ERRCODE = '22023';
  END IF;
  operation_value := p_request ->> 'operation';
  expected_revision := (p_request ->> 'expectedRevision')::bigint;
  IF expected_revision NOT BETWEEN 0 AND 9007199254740991 THEN
    RAISE EXCEPTION 'invalid MFA simulation expected revision'
      USING ERRCODE = '22023';
  END IF;
  target_value := app.private_mfa_policy_target_v1(
    p_request -> 'target',p_platform,p_tenant_id,
    operation_value = 'publish'
  );

  IF p_platform THEN
    IF p_request ? 'context' THEN
      RAISE EXCEPTION 'platform MFA simulation context must be absent'
        USING ERRCODE = '22023';
    END IF;
  ELSE
    IF NOT p_request ? 'context' THEN
      RAISE EXCEPTION 'tenant MFA simulation context is required'
        USING ERRCODE = '22023';
    END IF;
    context_value := app.private_mfa_policy_simulation_context_v1(
      p_request -> 'context',p_tenant_id
    );
    IF (target_value ->> 'scope' = 'role'
        AND NOT (context_value -> 'roleIds') @>
          jsonb_build_array(target_value ->> 'roleId'))
       OR (target_value ->> 'scope' = 'security_group'
        AND NOT (context_value -> 'securityGroupIds') @>
          jsonb_build_array(target_value ->> 'securityGroupId'))
       OR (target_value ->> 'scope' = 'action'
        AND context_value ->> 'action' <> target_value ->> 'action') THEN
      RAISE EXCEPTION 'tenant MFA simulation context omits changed target'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  SELECT policy.* INTO current_policy
  FROM ONLY public.mfa_policy_revisions AS policy
  WHERE policy.retired_at IS NULL
    AND app.private_mfa_policy_matches_target_v1(policy,target_value);
  current_found := FOUND;
  IF current_found THEN
    current_document := app.private_mfa_policy_document_v1(current_policy);
  END IF;

  IF expected_revision = 0 THEN
    IF p_request ? 'expectedPolicyId' OR current_found
       OR operation_value <> 'publish' THEN
      RAISE EXCEPTION 'MFA policy simulation create conflict'
        USING ERRCODE = '40001';
    END IF;
  ELSE
    IF NOT p_request ? 'expectedPolicyId'
       OR jsonb_typeof(p_request -> 'expectedPolicyId') <> 'string' THEN
      RAISE EXCEPTION 'MFA policy simulation expected policy is required'
        USING ERRCODE = '22023';
    END IF;
    expected_policy_id := app.private_mfa_require_uuidv7_v1(
      p_request ->> 'expectedPolicyId'
    );
    IF NOT current_found
       OR current_policy.id IS DISTINCT FROM expected_policy_id
       OR current_policy.revision IS DISTINCT FROM expected_revision THEN
      RAISE EXCEPTION 'MFA policy simulation revision conflict'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF operation_value = 'publish' THEN
    IF NOT p_request ? 'requirement' THEN
      RAISE EXCEPTION 'MFA policy simulation requirement is required'
        USING ERRCODE = '22023';
    END IF;
    requirement_value := app.private_mfa_policy_requirement_v1(
      p_request -> 'requirement'
    );
    candidate_document := jsonb_build_object(
      'target',target_value,'requirement',requirement_value
    );
  ELSE
    IF p_request ? 'requirement' THEN
      RAISE EXCEPTION 'retirement simulation cannot carry a requirement'
        USING ERRCODE = '22023';
    END IF;
  END IF;

  effective_document := app.private_mfa_policy_effective_v1(
    p_tenant_id,context_value,target_value,requirement_value
  );
  recovery_document := app.private_mfa_policy_recovery_v1(
    p_tenant_id,target_value,requirement_value
  );
  RETURN jsonb_build_object(
    'operation',operation_value,
    'target',target_value,
    'context',CASE WHEN p_platform THEN 'null'::jsonb ELSE context_value END,
    'current',current_document,
    'candidate',candidate_document,
    'effective',effective_document,
    'recovery',recovery_document
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mfa_policy_audit_v1(p_audit jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  event_id uuid;
  request_id uuid;
  correlation_id uuid;
  ip_address inet;
  user_agent text;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_audit,
    ARRAY['eventId','requestId','correlationId','ipAddress','userAgent'],
    ARRAY['eventId','requestId','correlationId'],8192
  );
  IF jsonb_typeof(p_audit -> 'eventId') <> 'string'
     OR jsonb_typeof(p_audit -> 'requestId') <> 'string'
     OR jsonb_typeof(p_audit -> 'correlationId') <> 'string' THEN
    RAISE EXCEPTION 'invalid MFA policy audit identifiers'
      USING ERRCODE = '22023';
  END IF;
  event_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'eventId');
  request_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'requestId');
  correlation_id := app.private_mfa_require_uuidv7_v1(
    p_audit ->> 'correlationId'
  );
  IF p_audit ? 'ipAddress' THEN
    IF jsonb_typeof(p_audit -> 'ipAddress') <> 'string'
       OR char_length(p_audit ->> 'ipAddress') NOT BETWEEN 2 AND 64 THEN
      RAISE EXCEPTION 'invalid MFA policy audit IP address'
        USING ERRCODE = '22023';
    END IF;
    ip_address := (p_audit ->> 'ipAddress')::inet;
  END IF;
  IF p_audit ? 'userAgent' THEN
    IF jsonb_typeof(p_audit -> 'userAgent') <> 'string'
       OR char_length(p_audit ->> 'userAgent') NOT BETWEEN 1 AND 1024
       OR p_audit ->> 'userAgent' ~ '[[:cntrl:]]' THEN
      RAISE EXCEPTION 'invalid MFA policy audit user agent'
        USING ERRCODE = '22023';
    END IF;
    user_agent := p_audit ->> 'userAgent';
  END IF;
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'eventId',event_id::text,
    'requestId',request_id::text,
    'correlationId',correlation_id::text,
    'ipAddress',ip_address::text,
    'userAgent',user_agent
  ));
EXCEPTION WHEN invalid_text_representation THEN
  RAISE EXCEPTION 'invalid MFA policy audit envelope'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_append_mfa_policy_tenant_audit_v1(
  p_audit jsonb,p_action text,p_policy_id uuid,
  p_authentication_method text,p_before jsonb,p_after jsonb,
  p_reason text,p_command_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  tenant_id uuid := app.context_tenant_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF p_action NOT IN (
       'tenant.identity_policy.published','tenant.identity_policy.retired'
     ) OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','passkey','oidc','saml'
     ) OR NOT app.private_mfa_policy_reason_valid_v1(p_reason) THEN
    RAISE EXCEPTION 'invalid tenant MFA policy audit event'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.audit_events (
    id,tenant_id,sequence,actor_type,actor_user_id,action,
    resource_type,resource_id,request_id,correlation_id,ip_address,
    user_agent,authentication_method,outcome,before,after,metadata
  ) VALUES (
    (p_audit ->> 'eventId')::uuid,tenant_id,0,'user',actor_id,p_action,
    'mfa_policy',p_policy_id,(p_audit ->> 'requestId')::uuid,
    (p_audit ->> 'correlationId')::uuid,
    CASE WHEN p_audit ? 'ipAddress'
      THEN (p_audit ->> 'ipAddress')::inet END,
    p_audit ->> 'userAgent',p_authentication_method,'success',
    p_before,p_after,jsonb_build_object(
      'command_id',p_command_id::text,'reason',p_reason
    )
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_append_mfa_policy_platform_audit_v1(
  p_audit jsonb,p_action text,p_policy_id uuid,
  p_authentication_method text,p_before jsonb,p_after jsonb,
  p_reason text,p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF p_action NOT IN (
       'platform.identity_policy.published',
       'platform.identity_policy.retired'
     ) OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','passkey','oidc','saml'
     ) OR NOT app.private_mfa_policy_reason_valid_v1(p_reason)
     OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_metadata) > 8192 THEN
    RAISE EXCEPTION 'invalid platform MFA policy audit event'
      USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.platform_audit_events (
    id,sequence,actor_type,actor_user_id,action,resource_type,resource_id,
    request_id,correlation_id,ip_address,user_agent,
    authentication_method,outcome,reason,before,after,metadata
  ) VALUES (
    (p_audit ->> 'eventId')::uuid,1,'user',app.context_user_id(),p_action,
    'mfa_policy',p_policy_id,(p_audit ->> 'requestId')::uuid,
    (p_audit ->> 'correlationId')::uuid,
    CASE WHEN p_audit ? 'ipAddress'
      THEN (p_audit ->> 'ipAddress')::inet END,
    p_audit ->> 'userAgent',p_authentication_method,'success',p_reason,
    p_before,p_after,p_metadata
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_platform_mfa_policies_v1(
  p_session_id uuid,p_authentication_method text,p_after_id uuid DEFAULT NULL,
  p_after_revision bigint DEFAULT NULL,p_limit integer DEFAULT 50,
  p_include_retired boolean DEFAULT false
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101
     OR p_include_retired IS NULL
     OR ((p_after_id IS NULL) <> (p_after_revision IS NULL))
     OR (p_after_id IS NOT NULL
       AND uuid_extract_version(p_after_id) IS DISTINCT FROM 7)
     OR (p_after_revision IS NOT NULL
       AND p_after_revision NOT BETWEEN 1 AND 9007199254740991) THEN
    RAISE EXCEPTION 'invalid platform MFA policy list request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_mfa_policy_authority_v1(
    p_session_id,'platform.identity_policy.read',
    p_authentication_method,false
  );
  RETURN QUERY
  SELECT app.private_mfa_policy_document_v1(policy)
  FROM ONLY public.mfa_policy_revisions AS policy
  WHERE policy.scope = 'platform_floor' AND policy.tenant_id IS NULL
    AND (p_include_retired OR policy.retired_at IS NULL)
    AND (p_after_id IS NULL OR ROW(policy.id,policy.revision) >
      ROW(p_after_id,p_after_revision))
  ORDER BY policy.id,policy.revision
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.list_tenant_mfa_policies_v1(
  p_session_id uuid,p_tenant_id uuid,p_authentication_method text,
  p_after_id uuid DEFAULT NULL,p_after_revision bigint DEFAULT NULL,
  p_limit integer DEFAULT 50,p_include_retired boolean DEFAULT false
)
RETURNS TABLE(document jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 101
     OR p_include_retired IS NULL
     OR ((p_after_id IS NULL) <> (p_after_revision IS NULL))
     OR (p_after_id IS NOT NULL
       AND uuid_extract_version(p_after_id) IS DISTINCT FROM 7)
     OR (p_after_revision IS NOT NULL
       AND p_after_revision NOT BETWEEN 1 AND 9007199254740991) THEN
    RAISE EXCEPTION 'invalid tenant MFA policy list request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_tenant_mfa_policy_authority_v1(
    p_session_id,p_tenant_id,'identity_policy.read',
    p_authentication_method,false
  );
  RETURN QUERY
  SELECT app.private_mfa_policy_document_v1(policy)
  FROM ONLY public.mfa_policy_revisions AS policy
  WHERE policy.tenant_id = p_tenant_id
    AND (p_include_retired OR policy.retired_at IS NULL)
    AND (p_after_id IS NULL OR ROW(policy.id,policy.revision) >
      ROW(p_after_id,p_after_revision))
  ORDER BY policy.id,policy.revision
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_platform_mfa_policy_v1(
  p_session_id uuid,p_authentication_method text,p_policy_id uuid,
  p_revision bigint DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  policy_record public.mfa_policy_revisions%ROWTYPE;
BEGIN
  IF p_policy_id IS NULL
     OR uuid_extract_version(p_policy_id) IS DISTINCT FROM 7
     OR (p_revision IS NOT NULL
       AND p_revision NOT BETWEEN 1 AND 9007199254740991) THEN
    RAISE EXCEPTION 'invalid platform MFA policy lookup'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_platform_mfa_policy_authority_v1(
    p_session_id,'platform.identity_policy.read',
    p_authentication_method,false
  );
  SELECT policy.* INTO STRICT policy_record
  FROM ONLY public.mfa_policy_revisions AS policy
  WHERE policy.id = p_policy_id AND policy.scope = 'platform_floor'
    AND policy.tenant_id IS NULL
    AND (p_revision IS NULL OR policy.revision = p_revision)
  ORDER BY policy.revision DESC LIMIT 1;
  RETURN app.private_mfa_policy_document_v1(policy_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'platform MFA policy not found' USING ERRCODE = 'P0002';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.get_tenant_mfa_policy_v1(
  p_session_id uuid,p_tenant_id uuid,p_authentication_method text,
  p_policy_id uuid,p_revision bigint DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  policy_record public.mfa_policy_revisions%ROWTYPE;
BEGIN
  IF p_policy_id IS NULL
     OR uuid_extract_version(p_policy_id) IS DISTINCT FROM 7
     OR (p_revision IS NOT NULL
       AND p_revision NOT BETWEEN 1 AND 9007199254740991) THEN
    RAISE EXCEPTION 'invalid tenant MFA policy lookup'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_require_tenant_mfa_policy_authority_v1(
    p_session_id,p_tenant_id,'identity_policy.read',
    p_authentication_method,false
  );
  SELECT policy.* INTO STRICT policy_record
  FROM ONLY public.mfa_policy_revisions AS policy
  WHERE policy.id = p_policy_id AND policy.tenant_id = p_tenant_id
    AND (p_revision IS NULL OR policy.revision = p_revision)
  ORDER BY policy.revision DESC LIMIT 1;
  RETURN app.private_mfa_policy_document_v1(policy_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'tenant MFA policy not found' USING ERRCODE = 'P0002';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.simulate_platform_mfa_policy_change_v1(
  p_session_id uuid,p_authentication_method text,p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  PERFORM app.private_require_platform_mfa_policy_authority_v1(
    p_session_id,'platform.identity_policy.read',
    p_authentication_method,false
  );
  RETURN app.private_simulate_mfa_policy_change_v1(
    true,NULL,p_request
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.simulate_tenant_mfa_policy_change_v1(
  p_session_id uuid,p_tenant_id uuid,p_authentication_method text,
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  PERFORM app.private_require_tenant_mfa_policy_authority_v1(
    p_session_id,p_tenant_id,'identity_policy.read',
    p_authentication_method,false
  );
  RETURN app.private_simulate_mfa_policy_change_v1(
    false,p_tenant_id,p_request
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_mutate_mfa_policy_v1(
  p_platform boolean,p_tenant_id uuid,p_session_id uuid,
  p_authentication_method text,p_operation text,p_command jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid;
  read_actor_id uuid;
  command_id uuid;
  expected_revision bigint;
  expected_policy_id uuid;
  operation_key text;
  reason_value text;
  semantic_command jsonb;
  request_digest bytea;
  receipt public.mfa_policy_commands%ROWTYPE;
  target_value jsonb;
  requirement_value jsonb;
  audit_value jsonb;
  current_policy public.mfa_policy_revisions%ROWTYPE;
  current_found boolean := false;
  current_document jsonb;
  result_policy public.mfa_policy_revisions%ROWTYPE;
  result_document jsonb;
  recovery_document jsonb;
  changed_at timestamptz := date_trunc(
    'milliseconds',transaction_timestamp()
  );
  result_policy_id uuid;
  result_revision bigint;
  update_count integer;
BEGIN
  IF p_platform IS NULL OR p_operation NOT IN ('publish','retire')
     OR (p_platform AND p_tenant_id IS NOT NULL)
     OR (NOT p_platform AND (p_tenant_id IS NULL
       OR uuid_extract_version(p_tenant_id) IS DISTINCT FROM 7)) THEN
    RAISE EXCEPTION 'invalid MFA policy mutation boundary'
      USING ERRCODE = '22023';
  END IF;
  operation_key := CASE WHEN p_platform THEN 'platform.' ELSE 'tenant.' END
    || p_operation;

  IF p_platform THEN
    actor_id := app.private_require_platform_mfa_policy_authority_v1(
      p_session_id,'platform.identity_policy.manage',
      p_authentication_method,true
    );
    read_actor_id := app.private_require_platform_mfa_policy_authority_v1(
      p_session_id,'platform.identity_policy.read',
      p_authentication_method,false
    );
  ELSE
    actor_id := app.private_require_tenant_mfa_policy_authority_v1(
      p_session_id,p_tenant_id,'identity_policy.manage',
      p_authentication_method,true
    );
    read_actor_id := app.private_require_tenant_mfa_policy_authority_v1(
      p_session_id,p_tenant_id,'identity_policy.read',
      p_authentication_method,false
    );
  END IF;
  IF actor_id IS DISTINCT FROM read_actor_id THEN
    RAISE EXCEPTION 'live MFA policy read and manage authority is required'
      USING ERRCODE = '42501';
  END IF;

  PERFORM app.private_mfa_assert_json_object_v1(
    p_command,
    ARRAY['commandId','target','expectedRevision','expectedPolicyId',
      'requirement','reason','audit'],
    ARRAY['commandId','target','expectedRevision','reason','audit'],131072
  );
  IF jsonb_typeof(p_command -> 'commandId') <> 'string'
     OR jsonb_typeof(p_command -> 'expectedRevision') <> 'number'
     OR p_command ->> 'expectedRevision' !~ '^(0|[1-9][0-9]{0,15})$'
     OR jsonb_typeof(p_command -> 'reason') <> 'string'
     OR jsonb_typeof(p_command -> 'target') <> 'object'
     OR jsonb_typeof(p_command -> 'audit') <> 'object' THEN
    RAISE EXCEPTION 'invalid MFA policy mutation command'
      USING ERRCODE = '22023';
  END IF;
  command_id := app.private_mfa_require_uuidv7_v1(
    p_command ->> 'commandId'
  );
  expected_revision := (p_command ->> 'expectedRevision')::bigint;
  reason_value := p_command ->> 'reason';
  IF expected_revision NOT BETWEEN 0 AND 9007199254740991
     OR NOT app.private_mfa_policy_reason_valid_v1(reason_value) THEN
    RAISE EXCEPTION 'invalid MFA policy mutation CAS or reason'
      USING ERRCODE = '22023';
  END IF;
  IF expected_revision = 0 THEN
    IF p_command ? 'expectedPolicyId' OR p_operation <> 'publish' THEN
      RAISE EXCEPTION 'invalid MFA policy create CAS'
        USING ERRCODE = '22023';
    END IF;
  ELSE
    IF NOT p_command ? 'expectedPolicyId'
       OR jsonb_typeof(p_command -> 'expectedPolicyId') <> 'string' THEN
      RAISE EXCEPTION 'expected MFA policy id is required'
        USING ERRCODE = '22023';
    END IF;
    expected_policy_id := app.private_mfa_require_uuidv7_v1(
      p_command ->> 'expectedPolicyId'
    );
  END IF;
  IF (p_operation = 'publish' AND NOT p_command ? 'requirement')
     OR (p_operation = 'retire' AND p_command ? 'requirement') THEN
    RAISE EXCEPTION 'invalid MFA policy mutation requirement shape'
      USING ERRCODE = '22023';
  END IF;

  semantic_command := jsonb_build_object(
    'actorUserId',actor_id::text,
    'authority',CASE WHEN p_platform THEN 'platform' ELSE 'tenant' END,
    'tenantId',CASE WHEN p_tenant_id IS NULL THEN 'null'::jsonb
      ELSE to_jsonb(p_tenant_id::text) END,
    'operation',p_operation,
    'target',p_command -> 'target',
    'expectedRevision',expected_revision,
    'expectedPolicyId',CASE WHEN expected_policy_id IS NULL
      THEN 'null'::jsonb ELSE to_jsonb(expected_policy_id::text) END,
    'requirement',CASE WHEN p_operation = 'publish'
      THEN p_command -> 'requirement' ELSE 'null'::jsonb END,
    'reason',reason_value
  );
  request_digest := pg_catalog.sha256(pg_catalog.convert_to(
    semantic_command::text,'UTF8'
  ));
  PERFORM pg_advisory_xact_lock(
    1346457933,hashtext(command_id::text)
  );
  SELECT command.* INTO receipt
  FROM ONLY public.mfa_policy_commands AS command
  WHERE command.id = command_id
  FOR UPDATE;
  IF FOUND THEN
    IF receipt.actor_user_id IS DISTINCT FROM actor_id
       OR receipt.tenant_id IS DISTINCT FROM p_tenant_id THEN
      RAISE EXCEPTION 'MFA policy command belongs to another authority'
        USING ERRCODE = '42501';
    END IF;
    IF receipt.operation IS DISTINCT FROM operation_key
       OR receipt.request_digest IS DISTINCT FROM request_digest THEN
      RAISE EXCEPTION 'MFA policy command replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    RETURN jsonb_build_object(
      'policy',receipt.result_snapshot,'replayed',true
    );
  END IF;

  target_value := app.private_mfa_policy_target_v1(
    p_command -> 'target',p_platform,p_tenant_id,p_operation = 'publish'
  );
  IF p_operation = 'publish' THEN
    requirement_value := app.private_mfa_policy_requirement_v1(
      p_command -> 'requirement'
    );
  END IF;
  audit_value := app.private_mfa_policy_audit_v1(p_command -> 'audit');

  PERFORM pg_advisory_xact_lock(
    hashtextextended(target_value::text,1346457933)
  );
  IF p_platform THEN
    PERFORM pg_advisory_xact_lock(1346457933,35);
  ELSE
    PERFORM 1
    FROM ONLY public.tenant_authorization_states AS state
    WHERE state.tenant_id = p_tenant_id
      AND state.initialized_at IS NOT NULL
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant MFA policy authority is unavailable'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  SELECT policy.* INTO current_policy
  FROM ONLY public.mfa_policy_revisions AS policy
  WHERE policy.retired_at IS NULL
    AND app.private_mfa_policy_matches_target_v1(policy,target_value)
  FOR UPDATE;
  current_found := FOUND;
  IF current_found THEN
    current_document := app.private_mfa_policy_document_v1(current_policy);
  END IF;
  IF expected_revision = 0 THEN
    IF current_found THEN
      RAISE EXCEPTION 'MFA policy create revision conflict'
        USING ERRCODE = '40001';
    END IF;
  ELSIF NOT current_found
     OR current_policy.id IS DISTINCT FROM expected_policy_id
     OR current_policy.revision IS DISTINCT FROM expected_revision THEN
    RAISE EXCEPTION 'MFA policy revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF current_found AND current_policy.revision >= 9007199254740991
     AND p_operation = 'publish' THEN
    RAISE EXCEPTION 'MFA policy revision is exhausted'
      USING ERRCODE = '22003';
  END IF;
  IF p_operation = 'retire' THEN
    IF target_value ->> 'scope' = 'tenant_baseline' THEN
      RAISE EXCEPTION 'tenant baseline MFA policy cannot be retired'
        USING ERRCODE = '55000';
    END IF;
    IF p_platform AND EXISTS (
      SELECT 1
      FROM ONLY public.platform_oidc_login_policies AS direct_policy
      WHERE direct_policy.enabled
        AND direct_policy.account_mode = 'existing_identity'
    ) THEN
      RAISE EXCEPTION 'active direct platform login requires its MFA floor'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  recovery_document := app.private_mfa_policy_recovery_v1(
    p_tenant_id,target_value,requirement_value
  );
  IF NOT (recovery_document ->> 'safe')::boolean THEN
    RAISE EXCEPTION 'MFA policy would violate direct recovery safety'
      USING ERRCODE = '55000',
        DETAIL = recovery_document -> 'reasonCodes' ->> 0;
  END IF;

  IF expected_revision = 0 THEN
    result_policy_id := uuidv7();
    result_revision := 1;
  ELSE
    result_policy_id := current_policy.id;
    result_revision := current_policy.revision +
      CASE WHEN p_operation = 'publish' THEN 1 ELSE 0 END;
  END IF;

  IF p_operation = 'publish' AND current_found THEN
    PERFORM set_config(
      'app.mfa_policy_write_v1',format(
        'retire:%s:%s',current_policy.id,current_policy.revision
      ),true
    );
    UPDATE ONLY public.mfa_policy_revisions AS policy
    SET retired_at = changed_at
    WHERE policy.id = current_policy.id
      AND policy.revision = current_policy.revision
      AND policy.retired_at IS NULL;
    GET DIAGNOSTICS update_count = ROW_COUNT;
    PERFORM set_config('app.mfa_policy_write_v1','',true);
    IF update_count <> 1 THEN
      RAISE EXCEPTION 'MFA policy revision conflict'
        USING ERRCODE = '40001';
    END IF;
  END IF;

  IF p_operation = 'publish' THEN
    PERFORM set_config(
      'app.mfa_policy_write_v1',format(
        'insert:%s:%s',result_policy_id,result_revision
      ),true
    );
    INSERT INTO public.mfa_policy_revisions (
      id,revision,tenant_id,scope,role_id,security_group_id,action,
      level,local_required,freshness_nanoseconds,enrollment_deadline,
      created_at,retired_at
    ) VALUES (
      result_policy_id,result_revision,p_tenant_id,target_value ->> 'scope',
      CASE WHEN target_value ->> 'scope' = 'role'
        THEN (target_value ->> 'roleId')::uuid END,
      CASE WHEN target_value ->> 'scope' = 'security_group'
        THEN (target_value ->> 'securityGroupId')::uuid END,
      CASE WHEN target_value ->> 'scope' = 'action'
        THEN target_value ->> 'action' END,
      requirement_value ->> 'level',
      (requirement_value ->> 'localRequired')::boolean,
      (requirement_value ->> 'freshnessSeconds')::bigint * 1000000000,
      CASE WHEN requirement_value -> 'enrollmentDeadline' = 'null'::jsonb
        THEN NULL ELSE
          (requirement_value ->> 'enrollmentDeadline')::timestamptz END,
      changed_at,NULL
    ) RETURNING * INTO result_policy;
    PERFORM set_config('app.mfa_policy_write_v1','',true);
  ELSE
    PERFORM set_config(
      'app.mfa_policy_write_v1',format(
        'retire:%s:%s',current_policy.id,current_policy.revision
      ),true
    );
    UPDATE ONLY public.mfa_policy_revisions AS policy
    SET retired_at = changed_at
    WHERE policy.id = current_policy.id
      AND policy.revision = current_policy.revision
      AND policy.retired_at IS NULL
    RETURNING * INTO result_policy;
    GET DIAGNOSTICS update_count = ROW_COUNT;
    PERFORM set_config('app.mfa_policy_write_v1','',true);
    IF update_count <> 1 THEN
      RAISE EXCEPTION 'MFA policy revision conflict'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  result_document := app.private_mfa_policy_document_v1(result_policy);

  IF p_platform THEN
    PERFORM app.private_append_mfa_policy_platform_audit_v1(
      audit_value,
      CASE WHEN p_operation = 'publish'
        THEN 'platform.identity_policy.published'
        ELSE 'platform.identity_policy.retired' END,
      result_policy.id,p_authentication_method,current_document,
      result_document,reason_value,
      jsonb_build_object(
        'command_id',command_id::text,
        'operation',p_operation,
        'target',target_value,
        'previous_revision',CASE WHEN current_found
          THEN current_policy.revision END,
        'revision',result_policy.revision
      )
    );
  ELSE
    PERFORM app.private_append_mfa_policy_tenant_audit_v1(
      audit_value,CASE WHEN p_operation = 'publish'
        THEN 'tenant.identity_policy.published'
        ELSE 'tenant.identity_policy.retired' END,
      result_policy.id,p_authentication_method,current_document,
      result_document,reason_value,command_id
    );
  END IF;
  INSERT INTO public.mfa_policy_commands (
    id,tenant_id,actor_user_id,operation,request_digest,
    result_policy_id,result_policy_revision,result_snapshot,created_at
  ) VALUES (
    command_id,p_tenant_id,actor_id,operation_key,request_digest,
    result_policy.id,result_policy.revision,result_document,changed_at
  );
  RETURN jsonb_build_object(
    'policy',result_document,'replayed',false
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.publish_platform_mfa_policy_v1(
  p_session_id uuid,p_authentication_method text,p_command jsonb
)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT app.private_mutate_mfa_policy_v1(
    true,NULL,p_session_id,p_authentication_method,'publish',p_command
  );
$function$;
CREATE FUNCTION app.retire_platform_mfa_policy_v1(
  p_session_id uuid,p_authentication_method text,p_command jsonb
)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT app.private_mutate_mfa_policy_v1(
    true,NULL,p_session_id,p_authentication_method,'retire',p_command
  );
$function$;
CREATE FUNCTION app.publish_tenant_mfa_policy_v1(
  p_session_id uuid,p_tenant_id uuid,p_authentication_method text,
  p_command jsonb
)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT app.private_mutate_mfa_policy_v1(
    false,p_tenant_id,p_session_id,p_authentication_method,'publish',p_command
  );
$function$;
CREATE FUNCTION app.retire_tenant_mfa_policy_v1(
  p_session_id uuid,p_tenant_id uuid,p_authentication_method text,
  p_command jsonb
)
RETURNS jsonb
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
  SELECT app.private_mutate_mfa_policy_v1(
    false,p_tenant_id,p_session_id,p_authentication_method,'retire',p_command
  );
$function$;
--> statement-breakpoint

DO $seal_mfa_policy_function_ownership$
DECLARE
  function_signature text;
BEGIN
  FOREACH function_signature IN ARRAY ARRAY[
    'app.guard_mfa_policy_command_v1()',
    'app.guard_mfa_policy_revision_v1()',
    'app.private_mfa_policy_reason_valid_v1(text)',
    'app.private_mfa_policy_instant_v1(timestamp with time zone)',
    'app.private_mfa_policy_requirement_v1(jsonb)',
    'app.private_mfa_policy_target_v1(jsonb,boolean,uuid,boolean)',
    'app.private_mfa_policy_document_v1(public.mfa_policy_revisions)',
    'app.private_require_recent_local_mfa_policy_session_v1(uuid,uuid,text)',
    'app.private_require_platform_mfa_policy_authority_v1(uuid,text,text,boolean)',
    'app.private_require_tenant_mfa_policy_authority_v1(uuid,uuid,text,text,boolean)',
    'app.private_mfa_policy_simulation_context_v1(jsonb,uuid)',
    'app.private_mfa_policy_matches_target_v1(public.mfa_policy_revisions,jsonb)',
    'app.private_mfa_policy_effective_v1(uuid,jsonb,jsonb,jsonb)',
    'app.private_mfa_policy_recovery_capable_v1(uuid,uuid,jsonb)',
    'app.private_mfa_policy_recovery_v1(uuid,jsonb,jsonb)',
    'app.private_simulate_mfa_policy_change_v1(boolean,uuid,jsonb)',
    'app.private_mfa_policy_audit_v1(jsonb)',
    'app.private_append_mfa_policy_tenant_audit_v1(jsonb,text,uuid,text,jsonb,jsonb,text,uuid)',
    'app.private_append_mfa_policy_platform_audit_v1(jsonb,text,uuid,text,jsonb,jsonb,text,jsonb)',
    'app.private_mutate_mfa_policy_v1(boolean,uuid,uuid,text,text,jsonb)',
    'app.list_platform_mfa_policies_v1(uuid,text,uuid,bigint,integer,boolean)',
    'app.list_tenant_mfa_policies_v1(uuid,uuid,text,uuid,bigint,integer,boolean)',
    'app.get_platform_mfa_policy_v1(uuid,text,uuid,bigint)',
    'app.get_tenant_mfa_policy_v1(uuid,uuid,text,uuid,bigint)',
    'app.simulate_platform_mfa_policy_change_v1(uuid,text,jsonb)',
    'app.simulate_tenant_mfa_policy_change_v1(uuid,uuid,text,jsonb)',
    'app.publish_platform_mfa_policy_v1(uuid,text,jsonb)',
    'app.retire_platform_mfa_policy_v1(uuid,text,jsonb)',
    'app.publish_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)',
    'app.retire_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)'
  ] LOOP
    EXECUTE format(
      'ALTER FUNCTION %s OWNER TO periapsis_migrator',function_signature
    );
    EXECUTE format(
      'REVOKE ALL ON FUNCTION %s FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor,periapsis_audit_reader_owner',
      function_signature
    );
  END LOOP;
END;
$seal_mfa_policy_function_ownership$;
GRANT EXECUTE ON FUNCTION
  app.list_platform_mfa_policies_v1(uuid,text,uuid,bigint,integer,boolean),
  app.list_tenant_mfa_policies_v1(uuid,uuid,text,uuid,bigint,integer,boolean),
  app.get_platform_mfa_policy_v1(uuid,text,uuid,bigint),
  app.get_tenant_mfa_policy_v1(uuid,uuid,text,uuid,bigint),
  app.simulate_platform_mfa_policy_change_v1(uuid,text,jsonb),
  app.simulate_tenant_mfa_policy_change_v1(uuid,uuid,text,jsonb),
  app.publish_platform_mfa_policy_v1(uuid,text,jsonb),
  app.retire_platform_mfa_policy_v1(uuid,text,jsonb),
  app.publish_tenant_mfa_policy_v1(uuid,uuid,text,jsonb),
  app.retire_tenant_mfa_policy_v1(uuid,uuid,text,jsonb)
TO periapsis_api;

COMMENT ON TABLE public.mfa_policy_revisions IS
  'Immutable platform and tenant MFA-policy revision chains. Protected writers retire meaning and append successor revisions; no runtime role has direct DML.';
COMMENT ON TABLE public.mfa_policy_commands IS
  'Payload-bound MFA-policy idempotency receipts. Semantic command digest excludes volatile audit attribution so exact retries return the first audited result.';
COMMENT ON COLUMN public.mfa_policy_revisions.freshness_nanoseconds IS
  'Internal runtime duration stored as exact whole seconds; administration wire projections expose freshnessSeconds.';
