-- Tenant membership lifecycle is a protected command boundary. A monotonic
-- revision is maintained for every status writer, including legacy provider
-- flows, while runtime callers receive only the guarded v1 command ABI.
ALTER TABLE public.tenant_memberships
  ADD COLUMN lifecycle_revision integer DEFAULT 1 NOT NULL;
--> statement-breakpoint
ALTER TABLE public.tenant_memberships
  ADD CONSTRAINT tenant_memberships_lifecycle_revision_check
  CHECK (lifecycle_revision BETWEEN 1 AND 2147483647);
--> statement-breakpoint

CREATE TABLE public.tenant_membership_lifecycle_commands (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  tenant_id uuid NOT NULL,
  actor_membership_id uuid NOT NULL,
  target_membership_id uuid NOT NULL,
  target_user_id uuid NOT NULL,
  operation text NOT NULL,
  key_digest bytea NOT NULL,
  request_digest bytea NOT NULL,
  expected_revision integer NOT NULL,
  previous_status public.membership_status NOT NULL,
  result_status public.membership_status NOT NULL,
  result_revision integer NOT NULL,
  result_updated_at timestamp with time zone NOT NULL,
  revoked_session_count integer DEFAULT 0 NOT NULL,
  revoked_continuation_count integer DEFAULT 0 NOT NULL,
  created_at timestamp with time zone DEFAULT now() NOT NULL,
  expires_at timestamp with time zone DEFAULT (now() + interval '24 hours') NOT NULL,
  CONSTRAINT tenant_membership_lifecycle_commands_tenant_id_key
    UNIQUE (tenant_id,id),
  CONSTRAINT tenant_membership_lifecycle_commands_replay_key
    UNIQUE (tenant_id,actor_membership_id,key_digest),
  CONSTRAINT tenant_membership_lifecycle_commands_id_uuidv7_check
    CHECK ((uuid_extract_version(id) = 7) IS TRUE),
  CONSTRAINT tenant_membership_lifecycle_commands_digest_check
    CHECK (octet_length(key_digest) = 32 AND octet_length(request_digest) = 32),
  CONSTRAINT tenant_membership_lifecycle_commands_transition_check
    CHECK (
      (operation = 'tenant_membership.suspend'
        AND previous_status = 'active' AND result_status = 'suspended')
      OR
      (operation = 'tenant_membership.reactivate'
        AND previous_status = 'suspended' AND result_status = 'active')
    ),
  CONSTRAINT tenant_membership_lifecycle_commands_revision_check
    CHECK (expected_revision BETWEEN 1 AND 2147483646
      AND result_revision = expected_revision + 1),
  CONSTRAINT tenant_membership_lifecycle_commands_consequence_check
    CHECK (revoked_session_count >= 0 AND revoked_continuation_count >= 0
      AND (operation = 'tenant_membership.suspend'
        OR (revoked_session_count = 0 AND revoked_continuation_count = 0))),
  CONSTRAINT tenant_membership_lifecycle_commands_retention_check
    CHECK (result_updated_at >= created_at
      AND expires_at > created_at
      AND expires_at <= created_at + interval '7 days')
);
--> statement-breakpoint
ALTER TABLE public.tenant_membership_lifecycle_commands
  ADD CONSTRAINT tenant_membership_lifecycle_commands_tenant_fk
  FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)
  ON DELETE RESTRICT;
--> statement-breakpoint
ALTER TABLE public.tenant_membership_lifecycle_commands
  ADD CONSTRAINT tenant_membership_lifecycle_commands_actor_fk
  FOREIGN KEY (tenant_id,actor_membership_id)
  REFERENCES public.tenant_memberships(tenant_id,id)
  ON UPDATE CASCADE ON DELETE RESTRICT;
--> statement-breakpoint
ALTER TABLE public.tenant_membership_lifecycle_commands
  ADD CONSTRAINT tenant_membership_lifecycle_commands_target_fk
  FOREIGN KEY (tenant_id,target_membership_id,target_user_id)
  REFERENCES public.tenant_memberships(tenant_id,id,user_id)
  ON UPDATE CASCADE ON DELETE RESTRICT;
--> statement-breakpoint
CREATE INDEX tenant_membership_lifecycle_commands_expiry_idx
  ON public.tenant_membership_lifecycle_commands(expires_at);
--> statement-breakpoint
ALTER TABLE public.tenant_membership_lifecycle_commands
  OWNER TO periapsis_migrator;
--> statement-breakpoint
ALTER TABLE public.tenant_membership_lifecycle_commands ENABLE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.tenant_membership_lifecycle_commands FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_membership_lifecycle_commands
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_membership_lifecycle_revision_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF TG_TABLE_SCHEMA <> 'public'
     OR TG_TABLE_NAME <> 'tenant_memberships'
     OR TG_OP <> 'UPDATE' THEN
    RAISE EXCEPTION 'tenant membership lifecycle revision guard rejected relation %.%/%',
      TG_TABLE_SCHEMA,TG_TABLE_NAME,TG_OP
      USING ERRCODE = '55000';
  END IF;

  IF NEW.status IS DISTINCT FROM OLD.status THEN
    IF OLD.lifecycle_revision >= 2147483647 THEN
      RAISE EXCEPTION 'tenant membership lifecycle revision is exhausted'
        USING ERRCODE = '55000';
    END IF;
    IF NEW.lifecycle_revision IS DISTINCT FROM OLD.lifecycle_revision
       AND NEW.lifecycle_revision IS DISTINCT FROM OLD.lifecycle_revision + 1 THEN
      RAISE EXCEPTION 'tenant membership lifecycle revision cannot be chosen by a writer'
        USING ERRCODE = '55000';
    END IF;
    NEW.lifecycle_revision := OLD.lifecycle_revision + 1;
  ELSIF NEW.lifecycle_revision IS DISTINCT FROM OLD.lifecycle_revision THEN
    RAISE EXCEPTION 'tenant membership lifecycle revision requires a status change'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_membership_lifecycle_revision_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_membership_lifecycle_revision_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER tenant_memberships_lifecycle_revision_v1
BEFORE UPDATE ON public.tenant_memberships
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_membership_lifecycle_revision_v1();
--> statement-breakpoint

-- Every tenant session or post-primary continuation must cross the same
-- authorization-state row before it can become live.  Membership lifecycle
-- changes take that row FOR UPDATE first, so a concurrent creator either
-- finishes before the suspension scan (and is revoked by it) or observes the
-- suspended membership after the scan.  This is also a database-level fence
-- for future writers that do not yet have a typed provider-specific planner.
CREATE FUNCTION app.lock_live_tenant_session_subject_v1(
  p_tenant_id uuid,
  p_user_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF p_tenant_id IS NULL
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR p_user_id IS NULL
     OR (uuid_extract_version(p_user_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'invalid tenant session subject'
      USING ERRCODE = '22023';
  END IF;

  PERFORM 1
  FROM public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id = p_tenant_id
    AND authorization_state.initialized_at IS NOT NULL
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant session authorization state is unavailable'
      USING ERRCODE = '42501';
  END IF;

  PERFORM 1
  FROM public.tenants AS tenant
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = tenant.id
   AND membership.user_id = p_user_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE tenant.id = p_tenant_id
    AND tenant.status = 'active'
    AND membership.status = 'active'
    AND identity.active
  FOR SHARE OF tenant,membership,identity;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active tenant membership is required for session authority'
      USING ERRCODE = '42501';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.lock_live_tenant_session_subject_v1(uuid,uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lock_live_tenant_session_subject_v1(uuid,uuid)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.guard_live_tenant_session_subject_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF TG_TABLE_SCHEMA <> 'public'
     OR TG_TABLE_NAME NOT IN ('auth_sessions','tenant_post_primary_continuations')
     OR TG_OP NOT IN ('INSERT','UPDATE') THEN
    RAISE EXCEPTION 'tenant session subject guard rejected relation %.%/%',
      TG_TABLE_SCHEMA,TG_TABLE_NAME,TG_OP
      USING ERRCODE = '55000';
  END IF;

  IF TG_TABLE_NAME = 'auth_sessions' THEN
    IF NEW.active_tenant_id IS NULL OR NEW.revoked_at IS NOT NULL
       OR (TG_OP = 'UPDATE' AND ROW(
         NEW.user_id,NEW.active_tenant_id,NEW.revoked_at
       ) IS NOT DISTINCT FROM ROW(
         OLD.user_id,OLD.active_tenant_id,OLD.revoked_at
       )) THEN
      RETURN NEW;
    END IF;
    PERFORM app.lock_live_tenant_session_subject_v1(
      NEW.active_tenant_id,NEW.user_id
    );
    RETURN NEW;
  END IF;

  IF NEW.state <> 'pending'
     OR (TG_OP = 'UPDATE' AND ROW(
       NEW.tenant_id,NEW.user_id,NEW.state
     ) IS NOT DISTINCT FROM ROW(
       OLD.tenant_id,OLD.user_id,OLD.state
     )) THEN
    RETURN NEW;
  END IF;
  PERFORM app.lock_live_tenant_session_subject_v1(
    NEW.tenant_id,NEW.user_id
  );
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_live_tenant_session_subject_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_live_tenant_session_subject_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER auth_sessions_tenant_membership_fence_v1
BEFORE INSERT OR UPDATE ON public.auth_sessions
FOR EACH ROW EXECUTE FUNCTION app.guard_live_tenant_session_subject_v1();
--> statement-breakpoint
CREATE TRIGGER tenant_post_primary_membership_fence_v1
BEFORE INSERT OR UPDATE ON public.tenant_post_primary_continuations
FOR EACH ROW EXECUTE FUNCTION app.guard_live_tenant_session_subject_v1();
--> statement-breakpoint

-- Pre-v35 tenant sessions have no typed MFA state and therefore cannot prove
-- that a provider/session successor participates in the common fence.  Do not
-- infer provenance during an upgrade: revoke those live rows once, preserving
-- platform sessions and every typed tenant session.
UPDATE public.auth_sessions AS session
SET revoked_at = greatest(transaction_timestamp(),session.created_at),
    revoke_reason = 'inactive_tenant_membership_fence_upgrade'
WHERE session.active_tenant_id IS NOT NULL
  AND session.revoked_at IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM public.tenants AS tenant
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = tenant.id
     AND membership.user_id = session.user_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE tenant.id = session.active_tenant_id
      AND tenant.status = 'active'
      AND membership.status = 'active'
      AND identity.active
  );
--> statement-breakpoint
DO $block$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.state = 'pending'
      AND continuation.version = 9223372036854775807
      AND NOT EXISTS (
        SELECT 1
        FROM public.tenants AS tenant
        JOIN public.tenant_memberships AS membership
          ON membership.tenant_id = tenant.id
         AND membership.user_id = continuation.user_id
        JOIN public.users AS identity ON identity.id = membership.user_id
        WHERE tenant.id = continuation.tenant_id
          AND tenant.status = 'active'
          AND membership.status = 'active'
          AND identity.active
      )
  ) THEN
    RAISE EXCEPTION 'inactive membership continuation version is exhausted'
      USING ERRCODE = '55000';
  END IF;
END;
$block$;
--> statement-breakpoint
UPDATE public.tenant_post_primary_continuations AS continuation
SET state = 'revoked',
    version = continuation.version + 1,
    revoked_at = greatest(transaction_timestamp(),continuation.created_at),
    revoke_reason = 'inactive_tenant_membership_fence_upgrade'
WHERE continuation.state = 'pending'
  AND NOT EXISTS (
    SELECT 1
    FROM public.tenants AS tenant
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = tenant.id
     AND membership.user_id = continuation.user_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE tenant.id = continuation.tenant_id
      AND tenant.status = 'active'
      AND membership.status = 'active'
      AND identity.active
  );
--> statement-breakpoint
UPDATE public.auth_sessions AS session
SET revoked_at = greatest(transaction_timestamp(),session.created_at),
    revoke_reason = 'untyped_tenant_session_membership_fence_upgrade'
WHERE session.active_tenant_id IS NOT NULL
  AND session.revoked_at IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM public.auth_session_mfa_states AS state
    WHERE state.tenant_id = session.active_tenant_id
      AND state.session_id = session.id
      AND state.user_id = session.user_id
  );
--> statement-breakpoint

-- The original local rotation locks the source session before it can know the
-- tenant fence.  Keep its wire ABI, but put an owner-only predecessor behind a
-- wrapper that locks the tenant authorization state and live membership first.
ALTER FUNCTION app.rotate_auth_session(
  bytea,uuid,bytea,bytea,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) RENAME TO private_unfenced_rotate_auth_session_v1;
DROP FUNCTION IF EXISTS app.rotate_auth_session(
  bytea,uuid,bytea,bytea,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
);
--> statement-breakpoint
CREATE FUNCTION app.rotate_auth_session(
  p_old_token_digest bytea,
  p_new_session_id uuid,
  p_new_token_digest bytea,
  p_new_csrf_secret_digest bytea,
  p_new_idle_expires_at timestamptz,
  p_new_absolute_expires_at timestamptz,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  source_tenant_id uuid;
  source_user_id uuid;
BEGIN
  SELECT session.active_tenant_id,session.user_id
    INTO source_tenant_id,source_user_id
  FROM public.auth_sessions AS session
  WHERE session.token_digest = p_old_token_digest;
  IF FOUND AND source_tenant_id IS NOT NULL THEN
    PERFORM app.lock_live_tenant_session_subject_v1(
      source_tenant_id,source_user_id
    );
  END IF;
  RETURN app.private_unfenced_rotate_auth_session_v1(
    p_old_token_digest,p_new_session_id,p_new_token_digest,
    p_new_csrf_secret_digest,p_new_idle_expires_at,p_new_absolute_expires_at,
    p_platform_audit_event_id,p_request_id,p_correlation_id,p_ip_address,
    p_user_agent
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_unfenced_rotate_auth_session_v1(
  bytea,uuid,bytea,bytea,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.rotate_auth_session(
  bytea,uuid,bytea,bytea,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_unfenced_rotate_auth_session_v1(
  bytea,uuid,bytea,bytea,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
REVOKE ALL ON FUNCTION app.rotate_auth_session(
  bytea,uuid,bytea,bytea,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.rotate_auth_session(
  bytea,uuid,bytea,bytea,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

-- Tenant switching must fence both the source and destination tenants before
-- the predecessor can lock the source session. UUID ordering prevents two
-- opposite cross-tenant switches from introducing a lock cycle.
ALTER FUNCTION app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) RENAME TO private_unfenced_rotate_auth_session_tenant_v2;
DROP FUNCTION IF EXISTS app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
);
--> statement-breakpoint
CREATE FUNCTION app.rotate_auth_session_tenant(
  p_old_token_digest bytea,
  p_new_session_id uuid,
  p_new_token_digest bytea,
  p_new_csrf_secret_digest bytea,
  p_tenant_id uuid,
  p_new_idle_expires_at timestamptz,
  p_new_absolute_expires_at timestamptz,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  source_tenant_id uuid;
BEGIN
  SELECT session.active_tenant_id INTO source_tenant_id
  FROM public.auth_sessions AS session
  WHERE session.token_digest = p_old_token_digest
    AND session.user_id = actor_id;

  IF source_tenant_id IS NOT NULL AND source_tenant_id < p_tenant_id THEN
    PERFORM app.lock_live_tenant_session_subject_v1(
      source_tenant_id,actor_id
    );
    PERFORM app.lock_live_tenant_session_subject_v1(p_tenant_id,actor_id);
  ELSE
    PERFORM app.lock_live_tenant_session_subject_v1(p_tenant_id,actor_id);
    IF source_tenant_id IS NOT NULL
       AND source_tenant_id IS DISTINCT FROM p_tenant_id THEN
      PERFORM app.lock_live_tenant_session_subject_v1(
        source_tenant_id,actor_id
      );
    END IF;
  END IF;

  RETURN app.private_unfenced_rotate_auth_session_tenant_v2(
    p_old_token_digest,p_new_session_id,p_new_token_digest,
    p_new_csrf_secret_digest,p_tenant_id,p_new_idle_expires_at,
    p_new_absolute_expires_at,p_platform_audit_event_id,p_request_id,
    p_correlation_id,p_ip_address,p_user_agent
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_unfenced_rotate_auth_session_tenant_v2(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_unfenced_rotate_auth_session_tenant_v2(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
REVOKE ALL ON FUNCTION app.private_unprovenanced_rotate_auth_session_tenant_v1(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
REVOKE ALL ON FUNCTION app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.rotate_auth_session_tenant(
  bytea,uuid,bytea,bytea,uuid,timestamptz,timestamptz,
  uuid,uuid,uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.guard_tenant_membership_lifecycle_command_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
BEGIN
  IF TG_TABLE_SCHEMA <> 'public'
     OR TG_TABLE_NAME <> 'tenant_membership_lifecycle_commands' THEN
    RAISE EXCEPTION 'tenant membership lifecycle command guard rejected relation %.%',
      TG_TABLE_SCHEMA,TG_TABLE_NAME
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'tenant membership lifecycle command rows are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at > transaction_timestamp() THEN
      RAISE EXCEPTION 'unexpired tenant membership lifecycle commands cannot be pruned'
        USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.target_membership_id
      AND membership.user_id = NEW.target_user_id
      AND membership.status = NEW.result_status
      AND membership.lifecycle_revision = NEW.result_revision
      AND membership.updated_at = NEW.result_updated_at
  ) THEN
    RAISE EXCEPTION 'tenant membership lifecycle receipt is not the current same-tenant result'
      USING ERRCODE = '23503',
            CONSTRAINT = 'tenant_membership_lifecycle_commands_result_fk';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_membership_lifecycle_command_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_membership_lifecycle_command_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
CREATE TRIGGER tenant_membership_lifecycle_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE
ON public.tenant_membership_lifecycle_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_tenant_membership_lifecycle_command_v1();
--> statement-breakpoint

-- Worker-only retention keeps keys that are never retried from accumulating.
-- Tenant and identifier both participate in the delete join so the owner ABI
-- cannot turn an identifier collision into a cross-tenant deletion.
CREATE FUNCTION app.prune_expired_tenant_membership_lifecycle_commands_v1(
  p_batch_size integer
)
RETURNS TABLE (tenant_membership_lifecycle_commands_deleted integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  deleted_commands integer := 0;
BEGIN
  IF p_batch_size IS NULL OR p_batch_size NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'tenant membership lifecycle cleanup batch must be between 1 and 1000'
      USING ERRCODE = '22023';
  END IF;

  WITH candidates AS (
    SELECT command.tenant_id,command.id
    FROM public.tenant_membership_lifecycle_commands AS command
    WHERE command.expires_at <= transaction_timestamp()
    ORDER BY command.expires_at,command.tenant_id,command.id
    LIMIT p_batch_size
    FOR UPDATE SKIP LOCKED
  )
  DELETE FROM public.tenant_membership_lifecycle_commands AS command
  USING candidates
  WHERE command.tenant_id = candidates.tenant_id
    AND command.id = candidates.id
    AND command.expires_at <= transaction_timestamp();
  GET DIAGNOSTICS deleted_commands = ROW_COUNT;

  RETURN QUERY SELECT deleted_commands;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.prune_expired_tenant_membership_lifecycle_commands_v1(integer)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.prune_expired_tenant_membership_lifecycle_commands_v1(integer)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.prune_expired_tenant_membership_lifecycle_commands_v1(integer)
  TO periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.list_tenant_users_v2(
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
  SELECT membership.id,identity.id,identity.email,identity.display_name,
         membership.status,membership.role,identity.active,
         membership.lifecycle_revision,membership.created_at,membership.updated_at
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND (p_after_membership_id IS NULL OR membership.id > p_after_membership_id)
  ORDER BY membership.id
  LIMIT p_limit;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.list_tenant_users_v2(uuid,integer) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_users_v2(uuid,integer)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenant_users_v2(uuid,integer) TO periapsis_api;
--> statement-breakpoint

-- Membership lifecycle reasons are first-class redacted audit data, not an
-- untyped metadata convention. This helper is deliberately private and
-- accepts only the two lifecycle actions emitted by the guarded command ABI.
CREATE FUNCTION app.append_tenant_membership_lifecycle_audit_v1(
  p_event_id uuid,
  p_action text,
  p_resource_id uuid,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_before jsonb,
  p_after jsonb,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
BEGIN
  PERFORM app.current_tenant_membership_id();
  IF p_event_id IS NULL
     OR (uuid_extract_version(p_event_id) = 7) IS NOT TRUE
     OR p_action NOT IN (
       'tenant.membership.suspended','tenant.membership.reactivated'
     )
     OR p_resource_id IS NULL
     OR (uuid_extract_version(p_resource_id) = 7) IS NOT TRUE
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason)
     OR p_request_id IS NULL
     OR p_request_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_correlation_id IS NULL
     OR p_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_user_agent ~ '[[:cntrl:]]'
     OR p_authentication_method IS NULL
     OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','recovery_code','ldap','oidc','saml','passkey'
     )
     OR pg_column_size(coalesce(p_before,'null'::jsonb)) > 8192
     OR pg_column_size(coalesce(p_after,'null'::jsonb)) > 8192
     OR pg_column_size(coalesce(p_metadata,'{}'::jsonb)) > 8192 THEN
    RAISE EXCEPTION 'invalid tenant membership lifecycle audit event'
      USING ERRCODE = '22023';
  END IF;

  INSERT INTO public.audit_events (
    id,tenant_id,sequence,actor_type,actor_user_id,action,
    resource_type,resource_id,request_id,correlation_id,ip_address,
    user_agent,authentication_method,outcome,reason,before,after,metadata
  ) VALUES (
    p_event_id,context_tenant,0,'user',actor_id,p_action,
    'tenant_membership',p_resource_id,p_request_id,p_correlation_id,p_ip_address,
    p_user_agent,p_authentication_method,'success',p_reason,p_before,p_after,
    coalesce(p_metadata,'{}'::jsonb)
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.append_tenant_membership_lifecycle_audit_v1(
  uuid,text,uuid,text,uuid,uuid,inet,text,text,jsonb,jsonb,jsonb
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_tenant_membership_lifecycle_audit_v1(
  uuid,text,uuid,text,uuid,uuid,inet,text,text,jsonb,jsonb,jsonb
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.change_tenant_membership_lifecycle_v1(
  p_actor_session_id uuid,
  p_target_user_id uuid,
  p_target_status public.membership_status,
  p_expected_revision integer,
  p_reason text,
  p_idempotency_key_digest bytea,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  tenant_id uuid,
  membership_id uuid,
  target_user_id uuid,
  previous_status public.membership_status,
  status public.membership_status,
  lifecycle_revision integer,
  updated_at timestamp with time zone,
  revoked_session_count integer,
  revoked_continuation_count integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_id uuid := app.context_user_id();
  actor_membership uuid;
  target_membership public.tenant_memberships%ROWTYPE;
  replay public.tenant_membership_lifecycle_commands%ROWTYPE;
  role_grant record;
  checked_count integer := 0;
  canonical_operation text;
  canonical_request_digest bytea;
  changed_at timestamp with time zone;
  next_revision integer;
  session_count integer := 0;
  continuation_count integer := 0;
BEGIN
  IF p_actor_session_id IS NULL
     OR (uuid_extract_version(p_actor_session_id) = 7) IS NOT TRUE
     OR p_target_user_id IS NULL
     OR (uuid_extract_version(p_target_user_id) = 7) IS NOT TRUE
     OR p_target_status IS NULL
     OR p_target_status NOT IN ('active','suspended')
     OR p_expected_revision IS NULL
     OR p_expected_revision NOT BETWEEN 1 AND 2147483646
     OR p_reason IS NULL
     OR NOT app.private_platform_lifecycle_reason_is_valid_v1(p_reason)
     OR p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32
     OR p_audit_event_id IS NULL
     OR (uuid_extract_version(p_audit_event_id) = 7) IS NOT TRUE
     OR p_request_id IS NULL
     OR p_request_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_correlation_id IS NULL
     OR p_correlation_id = '00000000-0000-0000-0000-000000000000'::uuid
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL
     OR octet_length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_user_agent ~ '[[:cntrl:]]'
     OR p_authentication_method IS NULL
     OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','recovery_code','ldap','oidc','saml','passkey'
     ) THEN
    RAISE EXCEPTION 'invalid tenant membership lifecycle command'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();

  -- Bind the mutation to the exact live browser session. Platform sessions and
  -- sessions selected into another tenant cannot exercise this tenant ABI.
  PERFORM 1
  FROM public.auth_sessions AS session
  JOIN public.users AS identity ON identity.id = session.user_id
  WHERE session.id = p_actor_session_id
    AND session.user_id = actor_id
    AND session.active_tenant_id = context_tenant
    AND session.authentication_method = p_authentication_method
    AND session.revoked_at IS NULL
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND identity.active
    AND app.session_tenant_allowed(session.user_id,session.active_tenant_id)
  FOR SHARE OF session,identity;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'live tenant human session authority is required'
      USING ERRCODE = '42501';
  END IF;

  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'membership.manage','tenant'
  ) THEN
    RAISE EXCEPTION 'membership.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;

  canonical_operation := CASE p_target_status
    WHEN 'suspended' THEN 'tenant_membership.suspend'
    ELSE 'tenant_membership.reactivate'
  END;
  canonical_request_digest := sha256(convert_to(jsonb_build_object(
    'operation',canonical_operation,
    'target_user_id',p_target_user_id,
    'target_status',p_target_status,
    'expected_revision',p_expected_revision,
    'reason',p_reason
  )::text,'UTF8'));

  -- Serialize the full actor-scoped retry identity before pruning or reading
  -- the ledger. Hash collisions only add harmless serialization; the unique
  -- full digest and request comparison remain the correctness boundary.
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':' ||
      encode(p_idempotency_key_digest,'hex'),
    0
  ));

  DELETE FROM public.tenant_membership_lifecycle_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_membership_lifecycle_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.key_digest = p_idempotency_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.operation IS DISTINCT FROM canonical_operation
       OR replay.request_digest IS DISTINCT FROM canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was already used for a different membership lifecycle request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_membership_lifecycle_commands_replay_key';
    END IF;
    RETURN QUERY SELECT
      replay.tenant_id,replay.target_membership_id,replay.target_user_id,
      replay.previous_status,replay.result_status,replay.result_revision,
      replay.result_updated_at,replay.revoked_session_count,
      replay.revoked_continuation_count,true;
    RETURN;
  END IF;

  SELECT membership.* INTO target_membership
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = context_tenant
    AND membership.user_id = p_target_user_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant user membership was not found' USING ERRCODE = 'P0002';
  END IF;
  IF target_membership.lifecycle_revision <> p_expected_revision THEN
    RAISE EXCEPTION 'tenant membership lifecycle revision conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_membership.status = p_target_status
     OR target_membership.status NOT IN ('active','suspended') THEN
    RAISE EXCEPTION 'tenant membership lifecycle transition is not applicable'
      USING ERRCODE = '55000';
  END IF;
  IF p_target_status = 'active' AND NOT EXISTS (
    SELECT 1 FROM public.users AS identity
    WHERE identity.id = target_membership.user_id AND identity.active
  ) THEN
    RAISE EXCEPTION 'inactive global user cannot be reactivated in a tenant'
      USING ERRCODE = '55000';
  END IF;

  -- Status changes activate or remove every direct and group-derived path.
  -- Reuse the established exact delegation/lifetime consequence boundary.
  FOR role_grant IN
    SELECT path.role_id,path.effective_expires_at
    FROM (
      SELECT direct_grant.role_id,
             direct_grant.expires_at AS effective_expires_at,
             direct_grant.id AS ordering_id
      FROM public.tenant_membership_role_grants AS direct_grant
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = direct_grant.tenant_id
       AND source.id = direct_grant.source_id
      JOIN public.tenant_roles AS role
        ON role.tenant_id = direct_grant.tenant_id
       AND role.id = direct_grant.role_id
      WHERE direct_grant.tenant_id = context_tenant
        AND direct_grant.membership_id = target_membership.id
        AND direct_grant.revoked_at IS NULL
        AND (direct_grant.expires_at IS NULL
          OR direct_grant.expires_at > transaction_timestamp())
        AND source.retired_at IS NULL
        AND role.archived_at IS NULL

      UNION ALL

      SELECT group_grant.role_id,
             app.earliest_authorization_expiry(
               group_member.expires_at,group_grant.expires_at
             ),
             group_member.id
      FROM public.tenant_security_group_memberships AS group_member
      JOIN public.tenant_authorization_sources AS member_source
        ON member_source.tenant_id = group_member.tenant_id
       AND member_source.id = group_member.source_id
      JOIN public.tenant_security_groups AS security_group
        ON security_group.tenant_id = group_member.tenant_id
       AND security_group.id = group_member.group_id
      JOIN public.tenant_security_group_role_grants AS group_grant
        ON group_grant.tenant_id = group_member.tenant_id
       AND group_grant.group_id = group_member.group_id
      JOIN public.tenant_authorization_sources AS grant_source
        ON grant_source.tenant_id = group_grant.tenant_id
       AND grant_source.id = group_grant.source_id
      JOIN public.tenant_roles AS role
        ON role.tenant_id = group_grant.tenant_id
       AND role.id = group_grant.role_id
      WHERE group_member.tenant_id = context_tenant
        AND group_member.membership_id = target_membership.id
        AND group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp())
        AND member_source.retired_at IS NULL
        AND security_group.archived_at IS NULL
        AND group_grant.revoked_at IS NULL
        AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
        AND grant_source.retired_at IS NULL
        AND role.archived_at IS NULL
    ) AS path
    ORDER BY path.ordering_id,path.role_id
    LIMIT 501
  LOOP
    checked_count := checked_count + 1;
    IF checked_count > 500 THEN
      RAISE EXCEPTION 'membership authority consequence limit exceeded'
        USING ERRCODE = '54000';
    END IF;
    -- A human is always allowed to remove their own authority. Applying the
    -- delegation ceiling to a self-suspension would make protected recovery
    -- roles impossible to relinquish and would bypass the deferred
    -- last-live-administrator invariant entirely. Other suspensions and every
    -- reactivation remain bounded by the exact consequence ceiling.
    IF target_membership.id IS DISTINCT FROM actor_membership
       OR p_target_status IS DISTINCT FROM 'suspended' THEN
      PERFORM app.assert_actor_can_grant_role(
        role_grant.role_id,role_grant.effective_expires_at
      );
    END IF;
  END LOOP;

  -- transaction_timestamp() may predate a creator that won the authorization
  -- fence while this transaction was waiting. Establish one result instant
  -- only after the fence and target lock are held, and never move any affected
  -- row backwards even if historical data carries a later timestamp.
  changed_at := greatest(clock_timestamp(),target_membership.updated_at);
  next_revision := target_membership.lifecycle_revision + 1;
  IF p_target_status = 'suspended' THEN
    SELECT greatest(
      changed_at,
      coalesce((
        SELECT max(session.created_at)
        FROM public.auth_sessions AS session
        WHERE session.user_id = target_membership.user_id
          AND session.active_tenant_id = context_tenant
          AND session.revoked_at IS NULL
      ),changed_at),
      coalesce((
        SELECT max(continuation.created_at)
        FROM public.tenant_post_primary_continuations AS continuation
        WHERE continuation.tenant_id = context_tenant
          AND continuation.user_id = target_membership.user_id
          AND continuation.state = 'pending'
      ),changed_at),
      coalesce((
        SELECT subject.updated_at
        FROM public.tenant_mfa_subjects AS subject
        WHERE subject.tenant_id = context_tenant
          AND subject.user_id = target_membership.user_id
      ),changed_at)
    ) INTO changed_at;

    -- Fail before any counter wraps. A missing subject is valid for a member
    -- who has never established tenant MFA state; pending continuations cannot
    -- exist without that subject because of their composite foreign key.
    IF EXISTS (
      SELECT 1 FROM public.tenant_mfa_subjects AS subject
      WHERE subject.tenant_id = context_tenant
        AND subject.user_id = target_membership.user_id
        AND (subject.session_invalidation_epoch >= 9223372036854775807
          OR subject.version >= 9223372036854775807)
    ) OR EXISTS (
      SELECT 1 FROM public.tenant_post_primary_continuations AS continuation
      WHERE continuation.tenant_id = context_tenant
        AND continuation.user_id = target_membership.user_id
        AND continuation.state = 'pending'
        AND continuation.version >= 9223372036854775807
    ) THEN
      RAISE EXCEPTION 'tenant membership session invalidation state is exhausted'
        USING ERRCODE = '55000';
    END IF;

    UPDATE public.auth_sessions AS session
    SET revoked_at = greatest(changed_at,session.created_at),
        revoke_reason = 'tenant_membership_suspended'
    WHERE session.user_id = target_membership.user_id
      AND session.active_tenant_id = context_tenant
      AND session.revoked_at IS NULL;
    GET DIAGNOSTICS session_count = ROW_COUNT;

    UPDATE public.tenant_post_primary_continuations AS continuation
    SET state = 'revoked',version = continuation.version + 1,
        revoked_at = greatest(changed_at,continuation.created_at),
        revoke_reason = 'tenant_membership_suspended'
    WHERE continuation.tenant_id = context_tenant
      AND continuation.user_id = target_membership.user_id
      AND continuation.state = 'pending';
    GET DIAGNOSTICS continuation_count = ROW_COUNT;

    UPDATE public.tenant_mfa_subjects AS subject
    SET session_invalidation_epoch = subject.session_invalidation_epoch + 1,
        version = subject.version + 1,
        updated_at = greatest(changed_at,subject.updated_at)
    WHERE subject.tenant_id = context_tenant
      AND subject.user_id = target_membership.user_id;
  END IF;

  -- Emit audit while a self-suspending actor is still an active membership.
  -- Every preceding consequence and this event roll back with the deferred
  -- recovery-admin constraint if the transition would remove the last admin.
  PERFORM app.append_tenant_membership_lifecycle_audit_v1(
    p_audit_event_id,
    CASE p_target_status
      WHEN 'suspended' THEN 'tenant.membership.suspended'
      ELSE 'tenant.membership.reactivated'
    END,target_membership.id,p_reason,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'status',target_membership.status,
      'lifecycle_revision',target_membership.lifecycle_revision
    ),
    jsonb_build_object(
      'status',p_target_status,
      'lifecycle_revision',next_revision
    ),
    jsonb_build_object(
      'target_user_id',target_membership.user_id,
      'actor_membership_id',actor_membership,
      'authority_paths_checked',checked_count,
      'revoked_session_count',session_count,
      'revoked_continuation_count',continuation_count
    )
  );

  UPDATE public.tenant_memberships AS membership
  SET status = p_target_status,
      updated_at = greatest(changed_at,membership.updated_at)
  WHERE membership.tenant_id = context_tenant
    AND membership.id = target_membership.id
  RETURNING membership.lifecycle_revision,membership.updated_at
    INTO next_revision,changed_at;
  IF next_revision <> target_membership.lifecycle_revision + 1 THEN
    RAISE EXCEPTION 'tenant membership lifecycle revision guard returned an unexpected revision'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO public.tenant_membership_lifecycle_commands (
    tenant_id,actor_membership_id,target_membership_id,target_user_id,
    operation,key_digest,request_digest,expected_revision,previous_status,
    result_status,result_revision,result_updated_at,revoked_session_count,
    revoked_continuation_count
  ) VALUES (
    context_tenant,actor_membership,target_membership.id,target_membership.user_id,
    canonical_operation,p_idempotency_key_digest,canonical_request_digest,
    target_membership.lifecycle_revision,target_membership.status,p_target_status,
    next_revision,changed_at,session_count,continuation_count
  );

  RETURN QUERY SELECT
    context_tenant,target_membership.id,target_membership.user_id,
    target_membership.status,p_target_status,next_revision,changed_at,
    session_count,continuation_count,false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.change_tenant_membership_lifecycle_v1(
  uuid,uuid,public.membership_status,integer,text,bytea,
  uuid,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.change_tenant_membership_lifecycle_v1(
  uuid,uuid,public.membership_status,integer,text,bytea,
  uuid,uuid,uuid,inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.change_tenant_membership_lifecycle_v1(
  uuid,uuid,public.membership_status,integer,text,bytea,
  uuid,uuid,uuid,inet,text,text
) TO periapsis_api;
--> statement-breakpoint

-- The predecessor remains for migration history only. Runtime roles must not
-- bypass revision, reason, idempotency, session fencing, or atomic audit.
REVOKE ALL ON FUNCTION app.set_tenant_user_membership_status(
  uuid,public.membership_status,uuid,uuid,uuid,inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
