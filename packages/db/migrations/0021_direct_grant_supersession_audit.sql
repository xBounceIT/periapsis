-- Preserve audit traceability when a new manual direct grant supersedes an
-- expired-but-unrevoked predecessor. This forward replacement intentionally
-- leaves the already-applied Phase 2B.1 migration immutable.
CREATE OR REPLACE FUNCTION "app"."grant_tenant_user_role"(
  p_grant_id uuid,
  p_idempotency_key_digest bytea,
  p_target_user_id uuid,
  p_role_id uuid,
  p_reason text,
  p_expires_at timestamp with time zone,
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
  target_membership uuid;
  manual_source uuid;
  canonical_request_digest bytea;
  replay record;
  superseded_role_grants jsonb := '[]'::jsonb;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_idempotency_key_digest IS NULL
     OR octet_length(p_idempotency_key_digest) <> 32 THEN
    RAISE EXCEPTION 'idempotency key digest must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'direct role grant reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT sha256(convert_to(jsonb_build_object(
    'target_user_id', p_target_user_id,
    'role_id', p_role_id,
    'reason', p_reason,
    'expires_at', p_expires_at
  )::text, 'UTF8')) INTO canonical_request_digest;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_role_grant.create'
    AND command.key_digest = p_idempotency_key_digest
    AND command.expires_at <= transaction_timestamp();

  SELECT command.* INTO replay
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'tenant_role_grant.create'
    AND command.key_digest = p_idempotency_key_digest
  FOR UPDATE;

  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM canonical_request_digest THEN
      RAISE EXCEPTION 'idempotency key was already used for a different request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_authorization_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT replay.result_resource_id, replay.result_version, true;
    RETURN;
  END IF;

  SELECT membership.id INTO target_membership
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id = membership.user_id
  WHERE membership.tenant_id = context_tenant
    AND membership.user_id = p_target_user_id
    AND membership.status IN ('active', 'invited', 'suspended')
    AND identity.active
  FOR UPDATE OF membership;

  IF target_membership IS NULL THEN
    RAISE EXCEPTION 'tenant user membership was not found'
      USING ERRCODE = 'P0002';
  END IF;

  PERFORM app.assert_actor_can_grant_role(p_role_id, p_expires_at);

  SELECT source.id INTO STRICT manual_source
  FROM public.tenant_authorization_sources AS source
  WHERE source.tenant_id = context_tenant
    AND source.key = 'manual'
    AND source.kind = 'manual'
    AND source.protected
    AND source.retired_at IS NULL;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'role_grant_id', old_grant.id,
           'prior_version', old_grant.version,
           'result_version', old_grant.version + 1
         ) ORDER BY old_grant.id), '[]'::jsonb)
    INTO superseded_role_grants
  FROM public.tenant_membership_role_grants AS old_grant
  WHERE old_grant.tenant_id = context_tenant
    AND old_grant.membership_id = target_membership
    AND old_grant.role_id = p_role_id
    AND old_grant.source_id = manual_source
    AND old_grant.revoked_at IS NULL
    AND old_grant.expires_at <= transaction_timestamp()
    AND old_grant.version < 2147483647;

  UPDATE public.tenant_membership_role_grants AS old_grant
  SET revoked_at = transaction_timestamp(),
      revoked_by_membership_id = actor_membership,
      revoke_reason = 'Superseded after the prior direct grant expired.',
      version = old_grant.version + 1,
      updated_at = transaction_timestamp()
  WHERE old_grant.tenant_id = context_tenant
    AND old_grant.membership_id = target_membership
    AND old_grant.role_id = p_role_id
    AND old_grant.source_id = manual_source
    AND old_grant.revoked_at IS NULL
    AND old_grant.expires_at <= transaction_timestamp()
    AND old_grant.version < 2147483647;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_membership_role_grants AS existing
    WHERE existing.tenant_id = context_tenant
      AND existing.membership_id = target_membership
      AND existing.role_id = p_role_id
      AND existing.source_id = manual_source
      AND existing.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'an active direct role grant already exists'
      USING ERRCODE = '23505', CONSTRAINT = 'tenant_membership_role_grants_active_key';
  END IF;

  INSERT INTO public.tenant_membership_role_grants (
    id, tenant_id, membership_id, role_id, source_id,
    granted_by_membership_id, grant_reason, expires_at
  ) VALUES (
    p_grant_id, context_tenant, target_membership, p_role_id, manual_source,
    actor_membership, p_reason, p_expires_at
  );

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, 'tenant.role_grant.created',
    'tenant_membership_role_grant', p_grant_id,
    p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'target_user_id', p_target_user_id,
      'target_membership_id', target_membership,
      'role_id', p_role_id,
      'source_type', 'direct',
      'reason', p_reason,
      'expires_at', p_expires_at,
      'version', 1
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'superseded_role_grants', superseded_role_grants
    )
  );

  INSERT INTO public.tenant_authorization_commands (
    tenant_id, actor_membership_id, operation, key_digest, request_digest,
    result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, 'tenant_role_grant.create',
    p_idempotency_key_digest, canonical_request_digest, p_grant_id, 1
  );
  RETURN QUERY SELECT p_grant_id, 1::integer, false;
END;
$function$;
