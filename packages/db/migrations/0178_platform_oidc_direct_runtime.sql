-- Direct platform OIDC is physically separate from every tenant-bound
-- authentication family. This release deliberately backfills every policy as
-- disabled and exposes no writer that can enable it.
INSERT INTO public.platform_oidc_login_policies (
  provider_id, provider_kind, account_mode, enabled, revision,
  created_at, updated_at
)
SELECT provider.id, 'oidc', 'disabled', false, 1,
       transaction_timestamp(), transaction_timestamp()
FROM ONLY public.platform_auth_providers AS provider
JOIN ONLY public.platform_oidc_provider_configurations AS configuration
  ON configuration.provider_id = provider.id
JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
  ON runtime_policy.provider_id = provider.id
 AND runtime_policy.provider_kind = 'oidc'
WHERE provider.kind = 'oidc'
ON CONFLICT (provider_id) DO NOTHING;
--> statement-breakpoint

DO $verify_platform_oidc_login_policy_backfill$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_oidc_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
    WHERE provider.kind = 'oidc'
      AND NOT EXISTS (
        SELECT 1 FROM ONLY public.platform_oidc_login_policies AS policy
        WHERE policy.provider_id = provider.id
          AND policy.provider_kind = 'oidc'
          AND policy.account_mode = 'disabled'
          AND NOT policy.enabled
          AND policy.revision = 1
      )
  ) OR EXISTS (
    SELECT 1 FROM ONLY public.platform_federated_provider_policies AS policy
    WHERE policy.platform_login_enabled
  ) THEN
    RAISE EXCEPTION 'direct platform OIDC disabled-policy backfill failed'
      USING ERRCODE = '55000';
  END IF;
END;
$verify_platform_oidc_login_policy_backfill$;
--> statement-breakpoint

COMMENT ON TABLE public.platform_oidc_login_policies IS
  'Independent direct-login policy. V39 backfills disabled and has no runtime/public enable writer.';
COMMENT ON COLUMN public.users.authentication_revision IS
  'Direct-auth authority revision. A local users trigger increments it only when active changes.';
COMMENT ON COLUMN public.totp_credentials.security_revision IS
  'Security-material/lifecycle revision. Counter replay advancement never increments it.';
--> statement-breakpoint

ALTER TABLE ONLY public.platform_oidc_login_policies
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_oidc_authentication_transactions
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_oidc_authentication_applications
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_post_primary_continuations
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_post_primary_continuation_evidence
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_post_primary_continuation_policy_pins
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_post_primary_totp_challenges
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.auth_session_platform_oidc_states
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.auth_session_platform_oidc_provenance
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.auth_session_platform_oidc_evidence
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.auth_session_platform_oidc_policy_pins
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_oidc_session_revalidation_commands
  FORCE ROW LEVEL SECURITY;
ALTER TABLE ONLY public.platform_oidc_tenant_switch_commands
  FORCE ROW LEVEL SECURITY;
--> statement-breakpoint

ALTER TABLE public.platform_oidc_login_policies OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_authentication_transactions OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_authentication_applications OWNER TO periapsis_migrator;
ALTER TABLE public.platform_post_primary_continuations OWNER TO periapsis_migrator;
ALTER TABLE public.platform_post_primary_continuation_evidence OWNER TO periapsis_migrator;
ALTER TABLE public.platform_post_primary_continuation_policy_pins OWNER TO periapsis_migrator;
ALTER TABLE public.platform_post_primary_totp_challenges OWNER TO periapsis_migrator;
ALTER TABLE public.auth_session_platform_oidc_states OWNER TO periapsis_migrator;
ALTER TABLE public.auth_session_platform_oidc_provenance OWNER TO periapsis_migrator;
ALTER TABLE public.auth_session_platform_oidc_evidence OWNER TO periapsis_migrator;
ALTER TABLE public.auth_session_platform_oidc_policy_pins OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_session_revalidation_commands OWNER TO periapsis_migrator;
ALTER TABLE public.platform_oidc_tenant_switch_commands OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON TABLE
  public.platform_oidc_login_policies,
  public.platform_oidc_authentication_transactions,
  public.platform_oidc_authentication_applications,
  public.platform_post_primary_continuations,
  public.platform_post_primary_continuation_evidence,
  public.platform_post_primary_continuation_policy_pins,
  public.platform_post_primary_totp_challenges,
  public.auth_session_platform_oidc_states,
  public.auth_session_platform_oidc_provenance,
  public.auth_session_platform_oidc_evidence,
  public.auth_session_platform_oidc_policy_pins,
  public.platform_oidc_session_revalidation_commands,
  public.platform_oidc_tenant_switch_commands
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner,
  periapsis_ticket_saved_view_owner, periapsis_ticket_attribution_owner,
  periapsis_ticket_sla_projection_owner;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_oidc_login_policy_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.provider_kind <> 'oidc' OR NEW.account_mode <> 'disabled'
       OR NEW.enabled OR NEW.revision <> 1
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'direct platform OIDC policy creation is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'direct platform OIDC policy has no v39 mutation ABI'
    USING ERRCODE = '55000';
END;
$function$;
CREATE TRIGGER platform_oidc_login_policies_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_oidc_login_policies
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_login_policy_v1();
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.guard_user_platform_identity_projection_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  projection_changed boolean;
  active_changed boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 OR NEW.authentication_revision <> 1 THEN
      RAISE EXCEPTION 'user projection create revisions are invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  projection_changed :=
    ROW(NEW.display_name, NEW.email, NEW.active)
      IS DISTINCT FROM ROW(OLD.display_name, OLD.email, OLD.active);
  active_changed := NEW.active IS DISTINCT FROM OLD.active;
  IF projection_changed THEN
    IF OLD.version >= 2147483647
       OR NEW.version NOT IN (OLD.version, OLD.version + 1) THEN
      RAISE EXCEPTION 'user projection revision is exhausted or invalid'
        USING ERRCODE = '55000';
    END IF;
    NEW.version := OLD.version + 1;
    NEW.updated_at := transaction_timestamp();
  ELSIF NEW.version IS DISTINCT FROM OLD.version THEN
    RAISE EXCEPTION 'user projection version changed without its representation'
      USING ERRCODE = '23514';
  END IF;

  IF active_changed THEN
    IF OLD.authentication_revision >= 9007199254740991
       OR NEW.authentication_revision NOT IN (
         OLD.authentication_revision, OLD.authentication_revision + 1
       ) THEN
      RAISE EXCEPTION 'user authentication revision is exhausted or invalid'
        USING ERRCODE = '55000';
    END IF;
    NEW.authentication_revision := OLD.authentication_revision + 1;
  ELSIF NEW.authentication_revision IS DISTINCT FROM OLD.authentication_revision THEN
    RAISE EXCEPTION 'user authentication revision changed without active state'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
DROP TRIGGER users_platform_identity_projection_update_guard_v1
  ON public.users;
CREATE TRIGGER users_platform_identity_projection_update_guard_v1
BEFORE UPDATE OF display_name, email, active, version, authentication_revision
ON public.users
FOR EACH ROW EXECUTE FUNCTION app.guard_user_platform_identity_projection_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_totp_credential_security_revision_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  security_changed boolean;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.security_revision <> 1 THEN
      RAISE EXCEPTION 'TOTP security revision must begin at one'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  security_changed := ROW(
    NEW.secret_ciphertext, NEW.secret_nonce, NEW.secret_aad, NEW.key_version,
    NEW.encryption_algorithm, NEW.otp_algorithm, NEW.digits,
    NEW.period_seconds, NEW.confirmed_at, NEW.disabled_at
  ) IS DISTINCT FROM ROW(
    OLD.secret_ciphertext, OLD.secret_nonce, OLD.secret_aad, OLD.key_version,
    OLD.encryption_algorithm, OLD.otp_algorithm, OLD.digits,
    OLD.period_seconds, OLD.confirmed_at, OLD.disabled_at
  );
  IF security_changed THEN
    IF OLD.security_revision >= 9007199254740991
       OR NEW.security_revision NOT IN (
         OLD.security_revision, OLD.security_revision + 1
       ) THEN
      RAISE EXCEPTION 'TOTP security revision is exhausted or invalid'
        USING ERRCODE = '55000';
    END IF;
    NEW.security_revision := OLD.security_revision + 1;
    NEW.updated_at := transaction_timestamp();
  ELSIF NEW.security_revision IS DISTINCT FROM OLD.security_revision THEN
    RAISE EXCEPTION 'TOTP security revision changed without security material'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER totp_credentials_security_revision_guard_v1
BEFORE INSERT OR UPDATE ON public.totp_credentials
FOR EACH ROW EXECUTE FUNCTION app.guard_totp_credential_security_revision_v1();
--> statement-breakpoint

-- A successful direct callback may rotate the encrypted representation of the
-- same exact subject while the identity security revision remains pinned. The
-- retained-key aliases prove semantic continuity; retirement still cannot
-- rewrite subject material.
CREATE OR REPLACE FUNCTION app.guard_platform_federated_external_identity_v4()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'platform federated identities are archival records'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.version <> 1 OR NEW.resource_version <> 1
       OR NEW.last_observation_state <> 'known'
       OR NEW.retired_at IS NOT NULL
       OR NEW.created_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity create envelope is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;

  IF ROW(NEW.id, NEW.platform_provider_id, NEW.provider_kind, NEW.user_id,
         NEW.last_observation_state,
         NEW.admitted_configuration_revision,
         NEW.admitted_security_revision, NEW.created_at)
     IS DISTINCT FROM
     ROW(OLD.id, OLD.platform_provider_id, OLD.provider_kind, OLD.user_id,
         OLD.last_observation_state,
         OLD.admitted_configuration_revision,
         OLD.admitted_security_revision, OLD.created_at)
     OR NEW.updated_at IS DISTINCT FROM transaction_timestamp()
     OR NEW.last_observed_at < OLD.last_observed_at
     OR OLD.retired_at IS NOT NULL
     OR OLD.resource_version >= 2147483647
     OR NEW.resource_version NOT IN (
       OLD.resource_version, OLD.resource_version + 1
     ) THEN
    RAISE EXCEPTION 'platform federated identity transition is invalid'
      USING ERRCODE = '23514';
  END IF;

  IF NEW.retired_at IS NULL THEN
    IF NEW.version <> OLD.version
       OR NEW.last_observation_state <> 'known'
       OR NEW.last_observed_at IS DISTINCT FROM transaction_timestamp() THEN
      RAISE EXCEPTION 'platform federated identity observation is invalid'
        USING ERRCODE = '23514';
    END IF;
  ELSE
    IF ROW(NEW.subject_format, NEW.subject_ciphertext, NEW.subject_nonce,
           NEW.key_version)
       IS DISTINCT FROM
       ROW(OLD.subject_format, OLD.subject_ciphertext, OLD.subject_nonce,
           OLD.key_version)
       OR OLD.version >= 2147483647
       OR NEW.version <> OLD.version + 1
       OR NEW.retired_at IS DISTINCT FROM transaction_timestamp()
       OR (
         NEW.last_observed_at IS DISTINCT FROM OLD.last_observed_at
         AND NEW.last_observed_at IS DISTINCT FROM transaction_timestamp()
       ) THEN
      RAISE EXCEPTION 'platform federated identity retirement is invalid'
        USING ERRCODE = '23514';
    END IF;
    NEW.last_observed_at := OLD.last_observed_at;
    NEW.last_observation_state := OLD.last_observation_state;
  END IF;
  NEW.resource_version := OLD.resource_version + 1;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_oidc_runtime_write_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF current_setting('app.platform_oidc_runtime_write_v1', true) <> 'on' THEN
    RAISE EXCEPTION 'direct platform OIDC runtime rows require a protected ABI'
      USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'direct platform OIDC runtime rows are archival'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'UPDATE' AND TG_TABLE_NAME IN (
    'platform_oidc_authentication_applications',
    'platform_post_primary_continuation_evidence',
    'platform_post_primary_continuation_policy_pins',
    'auth_session_platform_oidc_provenance',
    'auth_session_platform_oidc_evidence',
    'auth_session_platform_oidc_policy_pins',
    'platform_oidc_session_revalidation_commands',
    'platform_oidc_tenant_switch_commands'
  ) THEN
    RAISE EXCEPTION 'direct platform OIDC evidence and replay rows are immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_assurance_v1(
  p_session_id uuid,
  p_observed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  provider_count integer;
  totp_count integer;
  assurance_level text;
  assurance_authenticated_at timestamptz;
  assurance_expires_at timestamptz;
BEGIN
  SELECT count(*) FILTER (WHERE evidence.kind = 'platform_provider')::integer,
    count(*) FILTER (WHERE evidence.kind = 'totp')::integer
    INTO provider_count,totp_count
  FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
  WHERE evidence.session_id = p_session_id;
  IF provider_count <> 1 OR totp_count NOT BETWEEN 0 AND 1 THEN
    RETURN NULL;
  END IF;
  SELECT ranked.level,ranked.authenticated_at,ranked.expires_at
    INTO STRICT assurance_level,assurance_authenticated_at,
      assurance_expires_at
  FROM (
    SELECT evidence.level,evidence.authenticated_at,evidence.expires_at,
      CASE evidence.level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
        WHEN 'phishing_resistant' THEN 3 ELSE 0 END AS level_rank,
      evidence.id
    FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
    WHERE evidence.session_id = p_session_id
      AND (evidence.expires_at IS NULL OR evidence.expires_at > p_observed_at)
    ORDER BY level_rank DESC,evidence.authenticated_at DESC,evidence.id
    LIMIT 1
  ) AS ranked;
  RETURN jsonb_build_object(
    'level',assurance_level,
    'authenticatedAt',to_jsonb(assurance_authenticated_at),
    'expiresAt',to_jsonb(assurance_expires_at),
    'localSatisfied',totp_count = 1
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_oidc_tenant_switch_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  source_session_id uuid;
  target_tenant_id uuid;
  observed_at timestamptz;
  source_snapshot jsonb;
  target_snapshot jsonb;
  command_pins jsonb;
  policy_snapshot jsonb;
  assurance_snapshot jsonb;
  revalidation_snapshot jsonb;
  source_ready boolean;
  revalidation_ready boolean;
  user_id uuid;
  provider_id uuid;
  external_identity_id uuid;
  alias_key_version integer;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,
    ARRAY['sourceSessionId','targetTenantId','observedAt'],
    ARRAY['sourceSessionId','targetTenantId','observedAt'],8192
  );
  source_session_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'sourceSessionId'
  );
  target_tenant_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'targetTenantId'
  );
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  IF observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC tenant switch lookup'
      USING ERRCODE = '22023';
  END IF;

  -- Project the complete source facts even when they deny. The application
  -- planner must never need an adapter to invent a live edge.
  SELECT jsonb_build_object(
    'sessionId',session.id::text,
    'rotationFamilyId',session.rotation_family_id::text,
    'userId',session.user_id::text,
    'providerId',provenance.platform_provider_id::text,
    'externalIdentityId',provenance.external_identity_id::text,
    'activeTenantId',session.active_tenant_id,
    'authenticationMethod',session.authentication_method,
    'primaryKind',state.primary_kind,
    'directStateCount',(
      SELECT count(*)::integer
      FROM ONLY public.auth_session_platform_oidc_states AS counted_state
      WHERE counted_state.session_id = session.id
    ),
    'directProvenanceCount',(
      SELECT count(*)::integer
      FROM ONLY public.auth_session_platform_oidc_provenance AS counted_provenance
      WHERE counted_provenance.session_id = session.id
    ),
    'tenantProvenanceCount',(
      (SELECT count(*) FROM ONLY public.auth_session_mfa_states AS tenant_state
       WHERE tenant_state.session_id = session.id) +
      (SELECT count(*) FROM ONLY public.auth_session_federated_provenance
         AS tenant_provenance
       WHERE tenant_provenance.session_id = session.id) +
      (SELECT count(*)
       FROM ONLY public.auth_session_tenant_platform_federated_provenance
         AS tenant_platform_provenance
       WHERE tenant_platform_provenance.session_id = session.id)
    )::integer,
    'expectedVersion',state.session_version,
    'currentVersion',state.session_version,
    'idleExpiresAt',to_jsonb(session.idle_expires_at),
    'absoluteExpiresAt',to_jsonb(session.absolute_expires_at),
    'sessionActive',session.revoked_at IS NULL
      AND session.idle_expires_at > observed_at
      AND session.absolute_expires_at > observed_at,
    'rotationFamilyLive',EXISTS (
      SELECT 1 FROM ONLY public.auth_sessions AS family_session
      WHERE family_session.user_id = session.user_id
        AND family_session.rotation_family_id = session.rotation_family_id
        AND family_session.revoked_at IS NULL
        AND family_session.idle_expires_at > observed_at
        AND family_session.absolute_expires_at > observed_at
    ),
    'userActive',coalesce(local_user.active,false),
    'providerEnabled',coalesce(
      provider.kind = 'oidc' AND provider.enabled
        AND provider.archived_at IS NULL,false
    ),
    'platformLoginLive',coalesce(
      runtime_policy.provider_kind = 'oidc' AND runtime_policy.enabled
        AND NOT runtime_policy.platform_login_enabled
        AND login_policy.provider_kind = 'oidc' AND login_policy.enabled,false
    ),
    'accountMode',login_policy.account_mode,
    'identityLive',coalesce(
      identity.provider_kind = 'oidc'
        AND identity.platform_provider_id = provenance.platform_provider_id
        AND identity.user_id = session.user_id
        AND identity.retired_at IS NULL,false
    ),
    'subjectAliasLive',coalesce(
      alias.platform_provider_id = provenance.platform_provider_id
        AND alias.external_identity_id = provenance.external_identity_id
        AND alias.retired_at IS NULL,false
    ),
    'revisions',jsonb_build_object(
      'provider',jsonb_build_object(
        'pinned',provenance.provider_revision,'current',provider.version
      ),
      'security',jsonb_build_object(
        'pinned',provenance.security_revision,
        'current',runtime_policy.security_revision
      ),
      'platformLogin',jsonb_build_object(
        'pinned',provenance.login_policy_revision,
        'current',login_policy.revision
      ),
      'externalIdentity',jsonb_build_object(
        'pinned',provenance.identity_version,'current',identity.version
      ),
      'subjectAliasKey',jsonb_build_object(
        'pinned',provenance.alias_key_version,'current',alias.key_version
      )
    )
  ) INTO source_snapshot
  FROM ONLY public.auth_sessions AS session
  LEFT JOIN ONLY public.auth_session_platform_oidc_states AS state
    ON state.session_id = session.id AND state.user_id = session.user_id
  LEFT JOIN ONLY public.auth_session_platform_oidc_provenance AS provenance
    ON provenance.session_id = session.id
   AND provenance.user_id = session.user_id
   AND provenance.primary_kind = state.primary_kind
  LEFT JOIN ONLY public.users AS local_user ON local_user.id = session.user_id
  LEFT JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = provenance.platform_provider_id
  LEFT JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider.id
   AND runtime_policy.provider_kind = 'oidc'
  LEFT JOIN ONLY public.platform_oidc_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.provider_kind = 'oidc'
  LEFT JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id = provenance.external_identity_id
   AND identity.platform_provider_id = provenance.platform_provider_id
   AND identity.user_id = session.user_id
  LEFT JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = provenance.platform_provider_id
   AND alias.external_identity_id = provenance.external_identity_id
   AND alias.key_version = provenance.alias_key_version
  WHERE session.id = source_session_id;
  IF source_snapshot IS NULL THEN RETURN NULL; END IF;

  revalidation_snapshot := app.load_platform_oidc_session_revalidation_v1(
    jsonb_build_object(
      'sessionId',source_session_id::text,
      'observedAt',to_jsonb(observed_at)
    )
  );
  revalidation_ready := coalesce(
    revalidation_snapshot IS NOT NULL
    AND revalidation_snapshot #>> '{session,activeTenantId}' IS NULL
    AND revalidation_snapshot #>> '{session,authenticationMethod}' = 'oidc'
    AND revalidation_snapshot #>> '{session,audience}' = 'api'
    AND revalidation_snapshot #>> '{session,primaryKind}' =
      'platform_provider'
    AND NOT (revalidation_snapshot #>>
      '{session,recoveryRestricted}')::boolean
    AND (revalidation_snapshot #>>
      '{session,directStateCount}')::integer = 1
    AND (revalidation_snapshot #>>
      '{session,directProvenanceCount}')::integer = 1
    AND (revalidation_snapshot #>>
      '{session,tenantProvenanceCount}')::integer = 0
    AND (revalidation_snapshot #>>
      '{session,providerEvidenceCount}')::integer = 1
    AND (revalidation_snapshot #>>
      '{session,totpEvidenceCount}')::integer BETWEEN 0 AND 1
    AND (revalidation_snapshot #>> '{session,active}')::boolean
    AND (revalidation_snapshot #>>
      '{session,rotationFamilyLive}')::boolean
    AND revalidation_snapshot #>> '{authority,providerKind}' = 'oidc'
    AND (revalidation_snapshot #>>
      '{authority,runtimePolicyEnabled}')::boolean
    AND NOT (revalidation_snapshot #>>
      '{authority,legacyPlatformLoginEnabled}')::boolean
    AND (revalidation_snapshot #>>
      '{authority,loginPolicyEnabled}')::boolean
    AND revalidation_snapshot #>> '{authority,accountMode}' =
      'existing_identity'
    AND (revalidation_snapshot #>>
      '{authority,providerRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,providerRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,securityRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,securityRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,loginPolicyRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,loginPolicyRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,userAuthenticationRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,userAuthenticationRevision,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,identityVersion,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,identityVersion,current}')::bigint
    AND (revalidation_snapshot #>>
      '{authority,aliasKeyVersion,pinned}')::integer =
      (revalidation_snapshot #>>
      '{authority,aliasKeyVersion,current}')::integer
    AND (revalidation_snapshot #>>
      '{authority,assurancePolicyRevision,pinned}')::bigint =
      (revalidation_snapshot #>>
      '{authority,assurancePolicyRevision,current}')::bigint
    AND revalidation_snapshot #>> '{authority,platformFloor,pinnedId}' =
      revalidation_snapshot #>> '{authority,platformFloor,currentId}'
    AND (revalidation_snapshot #>>
      '{authority,platformFloor,pinnedRevision}')::bigint =
      (revalidation_snapshot #>>
      '{authority,platformFloor,currentRevision}')::bigint
    AND revalidation_snapshot #>>
      '{authority,platformFloor,currentScope}' = 'platform_floor'
    AND revalidation_snapshot #>
      '{authority,platformFloor,currentTenantId}' = 'null'::jsonb
    AND revalidation_snapshot #>
      '{authority,platformFloor,currentRetiredAt}' = 'null'::jsonb
    AND (revalidation_snapshot #>>
      '{authority,platformFloor,currentCount}')::integer = 1
    AND (revalidation_snapshot #>> '{authority,providerEnabled}')::boolean
    AND (revalidation_snapshot #>> '{authority,platformLoginLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,userActive}')::boolean
    AND (revalidation_snapshot #>> '{authority,identityLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,subjectAliasLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,factorEvidenceLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,trustEvidenceLive}')::boolean
    AND (revalidation_snapshot #>> '{authority,evidenceFresh}')::boolean
    AND (revalidation_snapshot #>> '{authority,policyPinsExact}')::boolean
    AND jsonb_array_length(
      revalidation_snapshot -> 'factorAuthorities'
    ) = (revalidation_snapshot #>> '{session,totpEvidenceCount}')::integer
    AND jsonb_array_length(
      revalidation_snapshot -> 'trustAuthorities'
    ) BETWEEN 0 AND 1,
    false
  );
  source_ready := coalesce(
    revalidation_ready
    AND source_snapshot ->> 'activeTenantId' IS NULL
    AND source_snapshot ->> 'authenticationMethod' = 'oidc'
    AND source_snapshot ->> 'primaryKind' = 'platform_provider'
    AND (source_snapshot ->> 'directStateCount')::integer = 1
    AND (source_snapshot ->> 'directProvenanceCount')::integer = 1
    AND (source_snapshot ->> 'tenantProvenanceCount')::integer = 0
    AND (source_snapshot ->> 'expectedVersion')::bigint BETWEEN 1 AND 2147483647
    AND (source_snapshot ->> 'expectedVersion')::bigint =
      (source_snapshot ->> 'currentVersion')::bigint
    AND (source_snapshot ->> 'sessionActive')::boolean
    AND (source_snapshot ->> 'rotationFamilyLive')::boolean
    AND (source_snapshot ->> 'userActive')::boolean
    AND (source_snapshot ->> 'providerEnabled')::boolean
    AND (source_snapshot ->> 'platformLoginLive')::boolean
    AND source_snapshot ->> 'accountMode' = 'existing_identity'
    AND (source_snapshot ->> 'identityLive')::boolean
    AND (source_snapshot ->> 'subjectAliasLive')::boolean
    AND (source_snapshot #>> '{revisions,provider,pinned}')::bigint =
      (source_snapshot #>> '{revisions,provider,current}')::bigint
    AND (source_snapshot #>> '{revisions,security,pinned}')::bigint =
      (source_snapshot #>> '{revisions,security,current}')::bigint
    AND (source_snapshot #>> '{revisions,platformLogin,pinned}')::bigint =
      (source_snapshot #>> '{revisions,platformLogin,current}')::bigint
    AND (source_snapshot #>> '{revisions,externalIdentity,pinned}')::bigint =
      (source_snapshot #>> '{revisions,externalIdentity,current}')::bigint
    AND (source_snapshot #>> '{revisions,subjectAliasKey,pinned}')::integer =
      (source_snapshot #>> '{revisions,subjectAliasKey,current}')::integer,
    false
  );

  user_id := (source_snapshot ->> 'userId')::uuid;
  provider_id := nullif(source_snapshot ->> 'providerId','')::uuid;
  external_identity_id :=
    nullif(source_snapshot ->> 'externalIdentityId','')::uuid;
  alias_key_version :=
    (source_snapshot #>> '{revisions,subjectAliasKey,current}')::integer;
  assurance_snapshot := app.private_platform_oidc_direct_assurance_v1(
    source_session_id,observed_at
  );
  IF assurance_snapshot IS NOT NULL AND revalidation_snapshot IS NOT NULL THEN
    -- The aggregate remains a compact diagnostic, but callers evaluate the
    -- exact normalized rows.  In particular, a trusted upstream level and an
    -- unrelated local TOTP must never be combined into one synthetic proof.
    assurance_snapshot := assurance_snapshot || jsonb_build_object(
      'evidence',revalidation_snapshot -> 'evidence'
    );
  END IF;

  SELECT jsonb_build_object(
    'tenantExecutionLive',coalesce(
      runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled,
      false
    ),
    'tenant',jsonb_build_object(
      'id',tenant.id::text,'version',tenant.version,
      'active',tenant.status = 'active'
    ),
    'membership',jsonb_build_object(
      'id',membership.id::text,'tenantId',membership.tenant_id::text,
      'userId',membership.user_id::text,
      'active',coalesce(membership.status = 'active',false)
    ),
    'binding',jsonb_build_object(
      'id',binding.id::text,'tenantId',binding.tenant_id::text,
      'providerId',binding.platform_provider_id::text,
      'version',binding.version,'mappingRevision',binding.mapping_revision,
      'authorizationRevision',binding.auth_revision,
      'currentAccessEpochId',binding.current_access_epoch_id::text,
      'enabled',coalesce(
        binding.enabled AND binding.archived_at IS NULL,false
      )
    ),
    'accessEpoch',jsonb_build_object(
      'id',epoch.id::text,'tenantId',epoch.tenant_id::text,
      'bindingId',epoch.binding_id::text,
      'providerId',epoch.platform_provider_id::text,
      'sourceId',epoch.source_id::text,'version',epoch.version,
      'live',coalesce(
        epoch.started_at <= observed_at AND epoch.ended_at IS NULL,false
      )
    ),
    'accessSource',jsonb_build_object(
      'id',authorization_source.id::text,
      'tenantId',authorization_source.tenant_id::text,
      'platformProvider',coalesce(
        authorization_source.kind = 'identity_provider_access'
        AND authorization_source.key = format(
          'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
        ),false
      ),
      'authoritative',coalesce(authorization_source.authoritative,false),
      'live',coalesce(
        NOT authorization_source.protected
        AND authorization_source.retired_at IS NULL,false
      )
    ),
    'externalIdentity',jsonb_build_object(
      'id',identity.id::text,
      'providerId',identity.platform_provider_id::text,
      'userId',identity.user_id::text,'version',identity.version,
      'live',coalesce(
        identity.provider_kind = 'oidc' AND identity.retired_at IS NULL,false
      )
    ),
    'subjectAlias',jsonb_build_object(
      'externalIdentityId',alias.external_identity_id::text,
      'keyVersion',alias.key_version,
      'live',coalesce(alias.retired_at IS NULL,false)
    ),
    'accessGrant',jsonb_build_object(
      'id',grant_row.id::text,'tenantId',grant_row.tenant_id::text,
      'providerId',grant_row.platform_provider_id::text,
      'bindingId',grant_row.binding_id::text,
      'accessEpochId',grant_row.access_epoch_id::text,
      'accessSourceId',grant_row.source_id::text,
      'externalIdentityId',grant_row.external_identity_id::text,
      'membershipId',grant_row.membership_id::text,
      'userId',grant_row.user_id::text,'version',grant_row.version,
      'live',coalesce(
        grant_row.started_at <= observed_at AND grant_row.ended_at IS NULL,
        false
      )
    ),
    'mfaSubject',jsonb_build_object(
      'version',subject.version,'identityEpoch',subject.identity_epoch,
      'sessionInvalidationEpoch',subject.session_invalidation_epoch
    )
  ) INTO target_snapshot
  FROM ONLY public.tenants AS tenant
  LEFT JOIN ONLY public.tenant_memberships AS membership
    ON membership.tenant_id = tenant.id AND membership.user_id = user_id
  LEFT JOIN ONLY public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = tenant.id AND subject.user_id = user_id
  LEFT JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider_id
   AND runtime_policy.provider_kind = 'oidc'
  LEFT JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.tenant_id = tenant.id
   AND binding.platform_provider_id = provider_id
  LEFT JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    ON epoch.tenant_id = binding.tenant_id
   AND epoch.id = binding.current_access_epoch_id
   AND epoch.binding_id = binding.id
   AND epoch.platform_provider_id = provider_id
  LEFT JOIN ONLY public.tenant_authorization_sources AS authorization_source
    ON authorization_source.tenant_id = epoch.tenant_id
   AND authorization_source.id = epoch.source_id
  LEFT JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.platform_provider_id = provider_id
   AND identity.id = external_identity_id
   AND identity.user_id = user_id
  LEFT JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = identity.platform_provider_id
   AND alias.external_identity_id = identity.id
   AND alias.key_version = alias_key_version
  LEFT JOIN LATERAL (
    SELECT candidate.*
    FROM ONLY public.tenant_platform_federated_provider_access_grants
      AS candidate
    WHERE candidate.tenant_id = tenant.id
      AND candidate.platform_provider_id = provider_id
      AND candidate.binding_id = binding.id
      AND candidate.access_epoch_id = epoch.id
      AND candidate.source_id = authorization_source.id
      AND candidate.external_identity_id = external_identity_id
      AND candidate.membership_id = membership.id
      AND candidate.user_id = user_id
    ORDER BY (candidate.ended_at IS NULL) DESC,
      candidate.started_at DESC,candidate.id
    LIMIT 1
  ) AS grant_row ON true
  WHERE tenant.id = target_tenant_id;

  -- commandPins are a capability, unlike the raw planner projection. They are
  -- emitted only for a completely revalidated source and exact live target.
  IF source_ready THEN
    SELECT jsonb_build_object(
      'tenantId',tenant.id::text,'tenantVersion',tenant.version,
      'membershipId',membership.id::text,
      'mfaSubjectVersion',subject.version,
      'identityEpoch',subject.identity_epoch,
      'sessionInvalidationEpoch',subject.session_invalidation_epoch,
      'bindingId',binding.id::text,'bindingVersion',binding.version,
      'mappingRevision',binding.mapping_revision,
      'authorizationRevision',binding.auth_revision,
      'accessEpochId',epoch.id::text,'accessEpochVersion',epoch.version,
      'accessSourceId',authorization_source.id::text,
      'accessGrantId',grant_row.id::text,
      'accessGrantVersion',grant_row.version,
      'platformProviderId',provider.id::text,
      'providerRevision',provider.version,
      'securityRevision',runtime_policy.security_revision,
      'externalIdentityId',identity.id::text,
      'identityVersion',identity.version,
      'aliasKeyVersion',alias.key_version
    ) INTO command_pins
    FROM ONLY public.tenants AS tenant
    JOIN ONLY public.tenant_memberships AS membership
      ON membership.tenant_id = tenant.id AND membership.user_id = user_id
     AND membership.status = 'active'
    JOIN ONLY public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = tenant.id AND subject.user_id = user_id
    JOIN ONLY public.platform_auth_providers AS provider
      ON provider.id = provider_id AND provider.kind = 'oidc'
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
     AND runtime_policy.provider_kind = 'oidc'
     AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
      ON binding.tenant_id = tenant.id
     AND binding.platform_provider_id = provider.id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
      ON epoch.tenant_id = binding.tenant_id
     AND epoch.id = binding.current_access_epoch_id
     AND epoch.binding_id = binding.id
     AND epoch.platform_provider_id = provider.id
     AND epoch.started_at <= observed_at AND epoch.ended_at IS NULL
    JOIN ONLY public.tenant_authorization_sources AS authorization_source
      ON authorization_source.tenant_id = epoch.tenant_id
     AND authorization_source.id = epoch.source_id
     AND authorization_source.kind = 'identity_provider_access'
     AND authorization_source.authoritative
     AND NOT authorization_source.protected
     AND authorization_source.key = format(
       'identity_provider_access:%s:%s',epoch.binding_id,epoch.sequence
     ) AND authorization_source.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.platform_provider_id = provider.id
     AND identity.id = external_identity_id
     AND identity.user_id = user_id
     AND identity.version =
       (source_snapshot #>> '{revisions,externalIdentity,current}')::bigint
     AND identity.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = identity.platform_provider_id
     AND alias.external_identity_id = identity.id
     AND alias.key_version =
       (source_snapshot #>> '{revisions,subjectAliasKey,current}')::integer
     AND alias.retired_at IS NULL
    JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
      ON grant_row.tenant_id = tenant.id
     AND grant_row.platform_provider_id = provider.id
     AND grant_row.binding_id = binding.id
     AND grant_row.access_epoch_id = epoch.id
     AND grant_row.source_id = authorization_source.id
     AND grant_row.external_identity_id = identity.id
     AND grant_row.membership_id = membership.id
     AND grant_row.user_id = user_id
     AND grant_row.started_at <= observed_at AND grant_row.ended_at IS NULL
    WHERE tenant.id = target_tenant_id AND tenant.status = 'active'
      AND provider.version =
        (source_snapshot #>> '{revisions,provider,current}')::bigint
      AND runtime_policy.security_revision =
        (source_snapshot #>> '{revisions,security,current}')::bigint;
    IF command_pins IS NOT NULL THEN
      policy_snapshot := app.private_mfa_policy_snapshot_v1(
        target_tenant_id,user_id,'session.create',observed_at
      );
      IF policy_snapshot IS NULL THEN
        command_pins := NULL;
      ELSE
        command_pins := command_pins || jsonb_build_object(
          'policySnapshot',policy_snapshot
        );
      END IF;
    END IF;
  END IF;
  RETURN jsonb_build_object(
    'source',source_snapshot,
    'assurance',assurance_snapshot,
    'target',target_snapshot,
    'commandPins',command_pins
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC tenant switch lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_oidc_tenant_switch_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  source_session_id uuid;
  expected_version bigint;
  target jsonb;
  target_tenant_id uuid;
  request_digest bytea;
  requested_decision text;
  observed_at timestamptz;
  live_snapshot jsonb;
  source_snapshot jsonb;
  assurance_snapshot jsonb;
  session_request jsonb;
  source_session public.auth_sessions%ROWTYPE;
  source_state public.auth_session_platform_oidc_states%ROWTYPE;
  existing public.platform_oidc_tenant_switch_commands%ROWTYPE;
  new_session_id uuid;
  rotation_family_id uuid;
  token_digest bytea;
  csrf_digest bytea;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  audience text;
  recovery_restricted boolean;
  required_level text;
  source_level text;
  local_required boolean;
  freshness_nanoseconds bigint;
  source_authenticated_at timestamptz;
  source_expires_at timestamptz;
  user_id uuid;
  provider_id uuid;
  external_identity_id uuid;
  policy_entry jsonb;
  result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_command,
    ARRAY['sourceSessionId','expectedVersion','target','requestDigest',
      'decision','session','observedAt','audit'],
    ARRAY['sourceSessionId','expectedVersion','target','requestDigest',
      'decision','observedAt','audit'],262144
  );
  source_session_id := app.private_mfa_require_uuidv7_v1(
    p_command ->> 'sourceSessionId'
  );
  expected_version := (p_command ->> 'expectedVersion')::bigint;
  target := p_command -> 'target';
  PERFORM app.private_platform_oidc_direct_json_v1(
    target,
    ARRAY['tenantId','tenantVersion','membershipId','mfaSubjectVersion',
      'identityEpoch','sessionInvalidationEpoch','bindingId','bindingVersion',
      'mappingRevision','authorizationRevision','accessEpochId',
      'accessEpochVersion','accessSourceId','accessGrantId',
      'accessGrantVersion','platformProviderId','providerRevision',
      'securityRevision','externalIdentityId','identityVersion',
      'aliasKeyVersion','policySnapshot'],
    ARRAY['tenantId','tenantVersion','membershipId','mfaSubjectVersion',
      'identityEpoch','sessionInvalidationEpoch','bindingId','bindingVersion',
      'mappingRevision','authorizationRevision','accessEpochId',
      'accessEpochVersion','accessSourceId','accessGrantId',
      'accessGrantVersion','platformProviderId','providerRevision',
      'securityRevision','externalIdentityId','identityVersion',
      'aliasKeyVersion','policySnapshot'],196608
  );
  target_tenant_id := app.private_mfa_require_uuidv7_v1(
    target ->> 'tenantId'
  );
  request_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'requestDigest',32,32
  );
  requested_decision := p_command ->> 'decision';
  observed_at := (p_command ->> 'observedAt')::timestamptz;
  IF requested_decision NOT IN ('rotate','deny')
     OR expected_version NOT BETWEEN 1 AND 2147483647
     OR request_digest = decode(repeat('00',32),'hex')
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds'
     OR (requested_decision = 'rotate' AND NOT p_command ? 'session')
     OR (requested_decision = 'deny' AND p_command ? 'session') THEN
    RAISE EXCEPTION 'invalid direct platform OIDC tenant switch command'
      USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO existing
  FROM ONLY public.platform_oidc_tenant_switch_commands AS command
  WHERE command.source_session_id = source_session_id
    AND command.expected_version = expected_version
    AND command.target_tenant_id = target_tenant_id;
  IF FOUND THEN
    IF existing.request_digest <> request_digest
       OR existing.decision <> (CASE requested_decision
         WHEN 'rotate' THEN 'rotated' ELSE 'denied' END) THEN
      RAISE EXCEPTION 'direct platform OIDC tenant switch replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN existing.result_snapshot;
  END IF;

  SELECT session.* INTO STRICT source_session
  FROM ONLY public.auth_sessions AS session
  WHERE session.id = source_session_id FOR UPDATE;
  SELECT state.* INTO STRICT source_state
  FROM ONLY public.auth_session_platform_oidc_states AS state
  WHERE state.session_id = source_session_id FOR UPDATE;
  PERFORM 1
  FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
  WHERE evidence.session_id = source_session_id FOR SHARE;
  PERFORM 1
  FROM ONLY public.totp_credentials AS factor
  JOIN ONLY public.auth_session_platform_oidc_evidence AS evidence
    ON evidence.session_id = source_session_id
   AND evidence.kind = 'totp' AND evidence.totp_credential_id = factor.id
  WHERE factor.user_id = source_state.user_id FOR SHARE OF factor;

  -- Hold every source and target authority row through rotation. Recomputing
  -- the graph without these locks would leave a disable/retirement TOCTOU
  -- window between the live snapshot and the tenant-session inserts.
  PERFORM 1
  FROM ONLY public.users AS local_user
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'platformProviderId'
    )
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider.id
   AND runtime_policy.provider_kind = 'oidc'
  JOIN ONLY public.platform_oidc_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.provider_kind = 'oidc'
  JOIN ONLY public.auth_session_platform_oidc_provenance AS provenance
    ON provenance.session_id = source_session_id
   AND provenance.user_id = local_user.id
   AND provenance.platform_provider_id = provider.id
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'externalIdentityId'
    )
   AND identity.platform_provider_id = provider.id
   AND identity.user_id = local_user.id
  JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = provider.id
   AND alias.external_identity_id = identity.id
   AND alias.key_version = (target ->> 'aliasKeyVersion')::integer
  JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.id = provenance.platform_floor_policy_id
   AND platform_floor.revision = provenance.platform_floor_policy_revision
  JOIN ONLY public.tenants AS tenant
    ON tenant.id = target_tenant_id
  JOIN ONLY public.tenant_memberships AS membership
    ON membership.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'membershipId'
    )
   AND membership.tenant_id = tenant.id
   AND membership.user_id = local_user.id
  JOIN ONLY public.tenant_mfa_subjects AS subject
    ON subject.tenant_id = tenant.id AND subject.user_id = local_user.id
  JOIN ONLY public.tenant_platform_auth_provider_bindings AS binding
    ON binding.id = app.private_mfa_require_uuidv7_v1(target ->> 'bindingId')
   AND binding.tenant_id = tenant.id
   AND binding.platform_provider_id = provider.id
  JOIN ONLY public.tenant_platform_identity_provider_access_epochs AS epoch
    ON epoch.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'accessEpochId'
    )
   AND epoch.tenant_id = tenant.id
   AND epoch.binding_id = binding.id
   AND epoch.platform_provider_id = provider.id
  JOIN ONLY public.tenant_authorization_sources AS authorization_source
    ON authorization_source.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'accessSourceId'
    )
   AND authorization_source.tenant_id = tenant.id
  JOIN ONLY public.tenant_platform_federated_provider_access_grants AS grant_row
    ON grant_row.id = app.private_mfa_require_uuidv7_v1(
      target ->> 'accessGrantId'
    )
   AND grant_row.tenant_id = tenant.id
   AND grant_row.platform_provider_id = provider.id
   AND grant_row.binding_id = binding.id
   AND grant_row.access_epoch_id = epoch.id
   AND grant_row.source_id = authorization_source.id
   AND grant_row.external_identity_id = identity.id
   AND grant_row.membership_id = membership.id
   AND grant_row.user_id = local_user.id
  WHERE local_user.id = source_state.user_id
  FOR SHARE OF local_user,provider,runtime_policy,login_policy,provenance,
    identity,alias,platform_floor,tenant,membership,subject,binding,epoch,
    authorization_source,grant_row;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  PERFORM 1
  FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
  JOIN ONLY public.platform_federated_trust_rules AS trust
    ON trust.id = evidence.trust_rule_id
  WHERE evidence.session_id = source_session_id
    AND evidence.kind = 'platform_provider'
  FOR SHARE OF trust;

  live_snapshot := app.load_platform_oidc_tenant_switch_v1(
    jsonb_build_object(
      'sourceSessionId',source_session_id::text,
      'targetTenantId',target_tenant_id::text,
      'observedAt',to_jsonb(observed_at)
    )
  );
  IF live_snapshot IS NULL
     OR live_snapshot -> 'commandPins' IS DISTINCT FROM target
     OR live_snapshot -> 'assurance' IS NULL
     OR source_state.session_version <> expected_version
     OR source_session.revoked_at IS NOT NULL
     OR source_session.active_tenant_id IS NOT NULL
     OR source_session.authentication_method <> 'oidc' THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  source_snapshot := live_snapshot -> 'source';
  assurance_snapshot := live_snapshot -> 'assurance';
  required_level := target #>> '{policySnapshot,requirement,level}';
  local_required :=
    (target #>> '{policySnapshot,requirement,localRequired}')::boolean;
  freshness_nanoseconds :=
    (target #>> '{policySnapshot,requirement,freshnessNanoseconds}')::bigint;
  -- A direct global TOTP cannot be represented by the tenant-local factor
  -- evidence family.  Select the one exact provider proof and transfer only
  -- its level and temporal bounds.  Target policies that require a local
  -- proof fail closed and must use the tenant-local step-up flow instead.
  SELECT evidence.level,evidence.authenticated_at,evidence.expires_at
    INTO STRICT source_level,source_authenticated_at,source_expires_at
  FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
  WHERE evidence.session_id = source_session_id
    AND evidence.kind = 'platform_provider';
  IF required_level NOT IN ('primary','mfa','phishing_resistant')
     OR source_level NOT IN ('primary','mfa','phishing_resistant')
     OR (CASE source_level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
       WHEN 'phishing_resistant' THEN 3 END) <
       (CASE required_level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
       WHEN 'phishing_resistant' THEN 3 END)
     OR local_required
     OR (freshness_nanoseconds > 0 AND source_authenticated_at +
       (freshness_nanoseconds::numeric / 1000000000) * interval '1 second'
       <= observed_at)
     OR (source_expires_at IS NOT NULL AND source_expires_at <= observed_at) THEN
    RETURN jsonb_build_object('applied',false,'category','denied');
  END IF;
  user_id := app.private_mfa_require_uuidv7_v1(
    source_snapshot ->> 'userId'
  );
  provider_id := app.private_mfa_require_uuidv7_v1(
    target ->> 'platformProviderId'
  );
  external_identity_id := app.private_mfa_require_uuidv7_v1(
    target ->> 'externalIdentityId'
  );
  IF requested_decision = 'deny' THEN
    result := jsonb_build_object(
      'applied',true,'decision','denied',
      'sourceSessionId',source_session_id::text,
      'targetTenantId',target_tenant_id::text
    );
  ELSE
    session_request := p_command -> 'session';
    PERFORM app.private_platform_oidc_direct_json_v1(
      session_request,
      ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest','audience',
        'idleExpiresAt','absoluteExpiresAt','sessionVersion',
        'recoveryRestricted'],
      ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest','audience',
        'idleExpiresAt','absoluteExpiresAt','sessionVersion',
        'recoveryRestricted'],32768
    );
    new_session_id := app.private_mfa_require_uuidv7_v1(
      session_request ->> 'id'
    );
    rotation_family_id := app.private_mfa_require_uuidv7_v1(
      session_request ->> 'rotationFamilyId'
    );
    token_digest := app.private_mfa_decode_base64_v1(
      session_request ->> 'tokenDigest',32,32
    );
    csrf_digest := app.private_mfa_decode_base64_v1(
      session_request ->> 'csrfSecretDigest',32,32
    );
    audience := session_request ->> 'audience';
    idle_expires_at := (session_request ->> 'idleExpiresAt')::timestamptz;
    absolute_expires_at :=
      (session_request ->> 'absoluteExpiresAt')::timestamptz;
    recovery_restricted :=
      (session_request ->> 'recoveryRestricted')::boolean;
    IF new_session_id = source_session_id
       OR rotation_family_id <> source_session.rotation_family_id
       OR absolute_expires_at <> source_session.absolute_expires_at
       OR (session_request ->> 'sessionVersion')::bigint <>
         expected_version + 1
       OR token_digest = csrf_digest
       OR encode(token_digest,'hex') = repeat('00',32)
       OR encode(csrf_digest,'hex') = repeat('00',32)
       OR idle_expires_at <= observed_at
       OR idle_expires_at > absolute_expires_at
       OR absolute_expires_at <= observed_at
       OR audience <> 'api'
       OR audience <> source_state.audience
       OR recovery_restricted <> source_state.recovery_restricted
       OR recovery_restricted THEN
      RAISE EXCEPTION 'invalid direct platform OIDC tenant session envelope'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'platform-oidc-switch:token:' || encode(token_digest,'hex'),3900178
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'platform-oidc-switch:csrf:' || encode(csrf_digest,'hex'),3900178
    ));
    IF EXISTS (
      SELECT 1 FROM ONLY public.auth_sessions AS collision
      WHERE collision.token_digest IN (token_digest,csrf_digest)
         OR collision.csrf_secret_digest IN (token_digest,csrf_digest)
    ) THEN
      RAISE EXCEPTION 'direct platform OIDC tenant session digest collision'
        USING ERRCODE = '23505';
    END IF;
    UPDATE ONLY public.auth_sessions AS session
    SET revoked_at = observed_at,
        revoke_reason = 'platform_oidc_tenant_switch_rotated'
    WHERE session.id = source_session_id AND session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'direct platform OIDC tenant switch lost source CAS'
        USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
    ) VALUES (
      new_session_id,user_id,rotation_family_id,target_tenant_id,token_digest,
      csrf_digest,'oidc',CASE WHEN source_level = 'primary' THEN NULL
        ELSE source_authenticated_at END,observed_at,idle_expires_at,
      absolute_expires_at,source_session_id,observed_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,
      session_invalidation_epoch,issued_at
    ) VALUES (
      new_session_id,target_tenant_id,user_id,expected_version + 1,
      (target ->> 'identityEpoch')::bigint,recovery_restricted,audience,
      'tenant_platform_provider',
      (target ->> 'sessionInvalidationEpoch')::bigint,observed_at
    );
    INSERT INTO public.auth_session_tenant_platform_federated_provenance (
      tenant_id,session_id,user_id,primary_kind,authentication_method,
      platform_provider_id,binding_id,access_epoch_id,access_source_id,
      access_grant_id,membership_id,external_identity_id,
      external_identity_revision,provider_revision,binding_revision,
      security_revision,mapping_revision,authorization_revision,
      subject_alias_key_version,trust_rule_revision,authenticated_at
    ) VALUES (
      target_tenant_id,new_session_id,user_id,'tenant_platform_provider','oidc',
      provider_id,app.private_mfa_require_uuidv7_v1(target ->> 'bindingId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'accessEpochId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'accessSourceId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'accessGrantId'),
      app.private_mfa_require_uuidv7_v1(target ->> 'membershipId'),
      external_identity_id,(target ->> 'identityVersion')::bigint,
      (target ->> 'providerRevision')::bigint,
      (target ->> 'bindingVersion')::bigint,
      (target ->> 'securityRevision')::bigint,
      (target ->> 'mappingRevision')::bigint,
      (target ->> 'authorizationRevision')::bigint,
      (target ->> 'aliasKeyVersion')::integer,
      (target ->> 'securityRevision')::bigint,source_authenticated_at
    );
    FOR policy_entry IN
      SELECT entry.value
      FROM jsonb_array_elements(target #> '{policySnapshot,policies}')
        AS entry(value)
    LOOP
      INSERT INTO public.auth_session_mfa_policy_pins (
        tenant_id,session_id,policy_id,policy_revision
      ) VALUES (
        target_tenant_id,new_session_id,
        app.private_mfa_require_uuidv7_v1(
          policy_entry #>> '{policy,id}'
        ),
        (policy_entry #>> '{policy,revision}')::bigint
      );
    END LOOP;
    INSERT INTO public.auth_session_tenant_platform_federated_evidence (
      id,tenant_id,session_id,user_id,platform_provider_id,binding_id,
      external_identity_id,level,authenticated_at,expires_at,
      trust_rule_revision
    ) VALUES (
      uuidv7(),target_tenant_id,new_session_id,user_id,provider_id,
      app.private_mfa_require_uuidv7_v1(target ->> 'bindingId'),
      external_identity_id,source_level,source_authenticated_at,
      source_expires_at,(target ->> 'securityRevision')::bigint
    );
    result := jsonb_build_object(
      'applied',true,'decision','rotated',
      'sourceSessionId',source_session_id::text,
      'sessionId',new_session_id::text,
      'targetTenantId',target_tenant_id::text,
      'sessionVersion',expected_version + 1
    );
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  INSERT INTO public.platform_oidc_tenant_switch_commands (
    source_session_id,expected_version,target_tenant_id,target_tenant_version,
    membership_id,binding_id,binding_version,mapping_revision,
    authorization_revision,access_epoch_id,access_epoch_version,
    access_source_id,access_grant_id,access_grant_version,request_digest,
    decision,rotated_session_id,result_snapshot,applied_at
  ) VALUES (
    source_session_id,expected_version,target_tenant_id,
    (target ->> 'tenantVersion')::bigint,
    app.private_mfa_require_uuidv7_v1(target ->> 'membershipId'),
    app.private_mfa_require_uuidv7_v1(target ->> 'bindingId'),
    (target ->> 'bindingVersion')::bigint,
    (target ->> 'mappingRevision')::bigint,
    (target ->> 'authorizationRevision')::bigint,
    app.private_mfa_require_uuidv7_v1(target ->> 'accessEpochId'),
    (target ->> 'accessEpochVersion')::bigint,
    app.private_mfa_require_uuidv7_v1(target ->> 'accessSourceId'),
    app.private_mfa_require_uuidv7_v1(target ->> 'accessGrantId'),
    (target ->> 'accessGrantVersion')::bigint,request_digest,
    CASE requested_decision WHEN 'rotate' THEN 'rotated' ELSE 'denied' END,
    CASE WHEN requested_decision = 'rotate' THEN new_session_id END,
    result,observed_at
  );
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_command -> 'audit','platform.oidc.session.tenant_switched',
    'auth_session',source_session_id,'success',jsonb_build_object(
      'provider_id',provider_id,'user_id',user_id,
      'target_tenant_id',target_tenant_id,
      'decision',CASE requested_decision
        WHEN 'rotate' THEN 'rotated' ELSE 'denied' END,
      'expected_version',expected_version
    )
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN jsonb_build_object('applied',false,'category','stale');
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC tenant switch command'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_oidc_session_revalidation_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  session_id uuid;
  observed_at timestamptz;
  result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,ARRAY['sessionId','observedAt'],
    ARRAY['sessionId','observedAt'],8192
  );
  session_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'sessionId');
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  IF observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC session revalidation lookup'
      USING ERRCODE = '22023';
  END IF;
  SELECT jsonb_build_object(
    'session',jsonb_build_object(
      'id',session.id::text,'rotationFamilyId',session.rotation_family_id::text,
      'userId',session.user_id::text,'activeTenantId',session.active_tenant_id,
      'authenticationMethod',session.authentication_method,
      'audience',state.audience,'primaryKind',state.primary_kind,
      'issuedAt',to_jsonb(state.issued_at),
      'recoveryRestricted',state.recovery_restricted,
      'userAuthenticationRevision',state.user_authentication_revision,
      'directStateCount',(
        SELECT count(*)::integer
        FROM ONLY public.auth_session_platform_oidc_states AS counted_state
        WHERE counted_state.session_id = session.id
      ),
      'directProvenanceCount',(
        SELECT count(*)::integer
        FROM ONLY public.auth_session_platform_oidc_provenance
          AS counted_provenance
        WHERE counted_provenance.session_id = session.id
      ),
      'tenantProvenanceCount',(
        (SELECT count(*) FROM ONLY public.auth_session_mfa_states
          AS tenant_state WHERE tenant_state.session_id = session.id) +
        (SELECT count(*) FROM ONLY public.auth_session_federated_provenance
          AS tenant_provenance
          WHERE tenant_provenance.session_id = session.id) +
        (SELECT count(*)
          FROM ONLY public.auth_session_tenant_platform_federated_provenance
            AS tenant_platform_provenance
          WHERE tenant_platform_provenance.session_id = session.id)
      )::integer,
      'providerEvidenceCount',(
        SELECT count(*)::integer
        FROM ONLY public.auth_session_platform_oidc_evidence AS counted_evidence
        WHERE counted_evidence.session_id = session.id
          AND counted_evidence.kind = 'platform_provider'
      ),
      'totpEvidenceCount',(
        SELECT count(*)::integer
        FROM ONLY public.auth_session_platform_oidc_evidence AS counted_evidence
        WHERE counted_evidence.session_id = session.id
          AND counted_evidence.kind = 'totp'
      ),
      'currentVersion',state.session_version,
      'idleExpiresAt',to_jsonb(session.idle_expires_at),
      'absoluteExpiresAt',to_jsonb(session.absolute_expires_at),
      'active',session.revoked_at IS NULL
        AND session.idle_expires_at > observed_at
        AND session.absolute_expires_at > observed_at,
      'rotationFamilyLive',EXISTS (
        SELECT 1 FROM ONLY public.auth_sessions AS family_session
        WHERE family_session.user_id = session.user_id
          AND family_session.rotation_family_id = session.rotation_family_id
          AND family_session.revoked_at IS NULL
          AND family_session.idle_expires_at > observed_at
          AND family_session.absolute_expires_at > observed_at
      )
    ),
    'authority',jsonb_build_object(
      'providerId',provenance.platform_provider_id::text,
      'externalIdentityId',provenance.external_identity_id::text,
      'providerKind',provider.kind,
      'runtimePolicyEnabled',runtime_policy.enabled,
      'legacyPlatformLoginEnabled',runtime_policy.platform_login_enabled,
      'loginPolicyEnabled',login_policy.enabled,
      'accountMode',login_policy.account_mode,
      'identityCurrentProviderId',identity.platform_provider_id::text,
      'identityCurrentUserId',identity.user_id::text,
      'identityProviderKind',identity.provider_kind,
      'identityRetiredAt',to_jsonb(identity.retired_at),
      'aliasCurrentProviderId',alias.platform_provider_id::text,
      'aliasCurrentIdentityId',alias.external_identity_id::text,
      'aliasRetiredAt',to_jsonb(alias.retired_at),
      'providerRevision',jsonb_build_object(
        'pinned',provenance.provider_revision,'current',provider.version
      ),
      'securityRevision',jsonb_build_object(
        'pinned',provenance.security_revision,
        'current',runtime_policy.security_revision
      ),
      'loginPolicyRevision',jsonb_build_object(
        'pinned',provenance.login_policy_revision,
        'current',login_policy.revision
      ),
      'userAuthenticationRevision',jsonb_build_object(
        'pinned',provenance.user_authentication_revision,
        'current',local_user.authentication_revision
      ),
      'identityVersion',jsonb_build_object(
        'pinned',provenance.identity_version,'current',identity.version
      ),
      'aliasKeyVersion',jsonb_build_object(
        'pinned',provenance.alias_key_version,'current',alias.key_version
      ),
      'assurancePolicyRevision',jsonb_build_object(
        'pinned',provenance.assurance_policy_revision,
        'current',runtime_policy.assurance_policy_revision
      ),
      'platformFloor',jsonb_build_object(
        'pinnedId',provenance.platform_floor_policy_id::text,
        'pinnedRevision',provenance.platform_floor_policy_revision,
        'currentId',platform_floor.id::text,
        'currentRevision',platform_floor.revision,
        'level',platform_floor.level,
        'localRequired',platform_floor.local_required,
        'freshnessNanoseconds',platform_floor.freshness_nanoseconds,
        'enrollmentDeadline',to_jsonb(platform_floor.enrollment_deadline),
        'currentScope',platform_floor.scope,
        'currentTenantId',platform_floor.tenant_id,
        'currentRetiredAt',to_jsonb(platform_floor.retired_at),
        'currentCount',(
          SELECT count(*)::integer
          FROM ONLY public.mfa_policy_revisions AS counted_floor
          WHERE counted_floor.scope = 'platform_floor'
            AND counted_floor.tenant_id IS NULL
            AND counted_floor.retired_at IS NULL
        )
      ),
      'trustRuleId',provenance.trust_rule_id,
      'trustRuleRevision',provenance.trust_rule_revision,
      'providerEnabled',coalesce(
        provider.kind = 'oidc' AND provider.enabled
          AND provider.archived_at IS NULL,false
      ),
      'platformLoginLive',coalesce(
        runtime_policy.provider_kind = 'oidc' AND runtime_policy.enabled
          AND NOT runtime_policy.platform_login_enabled
          AND login_policy.provider_kind = 'oidc' AND login_policy.enabled
          AND login_policy.account_mode = 'existing_identity',false
      ),
      'userActive',coalesce(local_user.active,false),
      'identityLive',coalesce(
        identity.provider_kind = 'oidc'
          AND identity.platform_provider_id = provenance.platform_provider_id
          AND identity.user_id = session.user_id
          AND identity.retired_at IS NULL,false
      ),
      'subjectAliasLive',coalesce(
        alias.platform_provider_id = provenance.platform_provider_id
          AND alias.external_identity_id = provenance.external_identity_id
          AND alias.key_version = provenance.alias_key_version
          AND alias.retired_at IS NULL,false
      ),
      'factorEvidenceLive',NOT EXISTS (
        SELECT 1
        FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
        LEFT JOIN ONLY public.totp_credentials AS factor
          ON factor.id = evidence.totp_credential_id
         AND factor.user_id = state.user_id
        WHERE evidence.session_id = session.id AND evidence.kind = 'totp'
          AND (factor.id IS NULL OR factor.disabled_at IS NOT NULL
            OR factor.confirmed_at IS NULL
            OR factor.security_revision <> evidence.factor_revision)
      ),
      'evidenceFresh',NOT EXISTS (
        SELECT 1
        FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
        WHERE evidence.session_id = session.id
          AND evidence.expires_at IS NOT NULL
          AND evidence.expires_at <= observed_at
      ),
      'policyPinsExact',(
        SELECT count(*) = 3
          AND bool_and(
            (pin.policy_kind = 'login'
              AND pin.policy_id = provenance.platform_provider_id
              AND pin.policy_revision = provenance.login_policy_revision)
            OR (pin.policy_kind = 'assurance'
              AND pin.policy_id = provenance.platform_provider_id
              AND pin.policy_revision = provenance.assurance_policy_revision)
            OR (pin.policy_kind = 'platform_floor'
              AND pin.policy_id = provenance.platform_floor_policy_id
              AND pin.policy_revision = provenance.platform_floor_policy_revision)
          )
        FROM ONLY public.auth_session_platform_oidc_policy_pins AS pin
        WHERE pin.session_id = session.id
      ),
      'trustEvidenceLive',NOT EXISTS (
        SELECT 1
        FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
        LEFT JOIN ONLY public.platform_federated_trust_rules AS trust
          ON trust.id = evidence.trust_rule_id
         AND trust.retired_at IS NULL
        WHERE evidence.session_id = session.id
          AND evidence.kind = 'platform_provider'
          AND (
            evidence.user_id <> session.user_id
            OR evidence.platform_provider_id IS DISTINCT FROM
              provenance.platform_provider_id
            OR evidence.external_identity_id IS DISTINCT FROM
              provenance.external_identity_id
            OR evidence.trust_rule_id IS DISTINCT FROM
              provenance.trust_rule_id
            OR evidence.trust_rule_revision IS DISTINCT FROM
              provenance.trust_rule_revision
            OR (evidence.trust_rule_id IS NOT NULL AND (
              trust.id IS NULL
              OR trust.provider_id <> provenance.platform_provider_id
              OR trust.provider_kind <> 'oidc'
              OR trust.revision <> evidence.trust_rule_revision
              OR trust.level <> evidence.level
              OR NOT trust.enabled
            ))
          )
      )
    ),
    'evidence',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'id',evidence.id::text,'userId',evidence.user_id::text,
        'kind',evidence.kind,'level',evidence.level,
        'platformProviderId',evidence.platform_provider_id::text,
        'externalIdentityId',evidence.external_identity_id::text,
        'authenticatedAt',to_jsonb(evidence.authenticated_at),
        'expiresAt',to_jsonb(evidence.expires_at),
        'totpCredentialId',evidence.totp_credential_id::text,
        'factorRevision',evidence.factor_revision,
        'trustRuleId',evidence.trust_rule_id::text,
        'trustRuleRevision',evidence.trust_rule_revision
      ) ORDER BY evidence.kind,evidence.id)
      FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
      WHERE evidence.session_id = session.id
    ),'[]'::jsonb),
    'factorAuthorities',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'evidenceId',evidence.id::text,
        'evidenceUserId',evidence.user_id::text,
        'totpCredentialId',evidence.totp_credential_id::text,
        'pinnedSecurityRevision',evidence.factor_revision,
        'currentUserId',factor.user_id::text,
        'currentSecurityRevision',factor.security_revision,
        'confirmedAt',to_jsonb(factor.confirmed_at),
        'disabledAt',to_jsonb(factor.disabled_at)
      ) ORDER BY evidence.id)
      FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
      LEFT JOIN ONLY public.totp_credentials AS factor
        ON factor.id = evidence.totp_credential_id
      WHERE evidence.session_id = session.id AND evidence.kind = 'totp'
    ),'[]'::jsonb),
    'trustAuthorities',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'evidenceId',evidence.id::text,
        'trustRuleId',evidence.trust_rule_id::text,
        'pinnedRevision',evidence.trust_rule_revision,
        'currentProviderId',trust.provider_id::text,
        'currentProviderKind',trust.provider_kind,
        'currentRevision',trust.revision,
        'currentLevel',trust.level,
        'enabled',trust.enabled,
        'retiredAt',to_jsonb(trust.retired_at)
      ) ORDER BY evidence.id)
      FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
      LEFT JOIN ONLY public.platform_federated_trust_rules AS trust
        ON trust.id = evidence.trust_rule_id
      WHERE evidence.session_id = session.id
        AND evidence.kind = 'platform_provider'
        AND evidence.trust_rule_id IS NOT NULL
    ),'[]'::jsonb),
    'policyPins',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'kind',pin.policy_kind,'id',pin.policy_id::text,
        'revision',pin.policy_revision
      ) ORDER BY pin.policy_kind,pin.policy_id)
      FROM ONLY public.auth_session_platform_oidc_policy_pins AS pin
      WHERE pin.session_id = session.id
    ),'[]'::jsonb)
  ) INTO result
  FROM ONLY public.auth_sessions AS session
  LEFT JOIN ONLY public.auth_session_platform_oidc_states AS state
    ON state.session_id = session.id AND state.user_id = session.user_id
  LEFT JOIN ONLY public.auth_session_platform_oidc_provenance AS provenance
    ON provenance.session_id = state.session_id
   AND provenance.user_id = state.user_id
   AND provenance.primary_kind = state.primary_kind
  LEFT JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = provenance.platform_provider_id
  LEFT JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider.id
   AND runtime_policy.provider_kind = 'oidc'
  LEFT JOIN ONLY public.platform_oidc_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.provider_kind = 'oidc'
  LEFT JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.scope = 'platform_floor'
   AND platform_floor.tenant_id IS NULL
   AND platform_floor.retired_at IS NULL
  LEFT JOIN ONLY public.users AS local_user ON local_user.id = session.user_id
  LEFT JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id = provenance.external_identity_id
  LEFT JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = provenance.platform_provider_id
   AND alias.external_identity_id = provenance.external_identity_id
   AND alias.key_version = provenance.alias_key_version
  WHERE session.id = session_id;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC session revalidation lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_oidc_session_revalidation_v1(
  p_command jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  session_id uuid;
  expected_version bigint;
  request_digest bytea;
  observed_at timestamptz;
  decision text;
  reason text;
  session_record public.auth_sessions%ROWTYPE;
  state_record public.auth_session_platform_oidc_states%ROWTYPE;
  provenance_record public.auth_session_platform_oidc_provenance%ROWTYPE;
  provider_evidence public.auth_session_platform_oidc_evidence%ROWTYPE;
  totp_evidence public.auth_session_platform_oidc_evidence%ROWTYPE;
  selected_totp_record public.totp_credentials%ROWTYPE;
  existing public.platform_oidc_session_revalidation_commands%ROWTYPE;
  authority jsonb;
  authority_live boolean;
  result jsonb;
  new_session_id uuid;
  continuation_id uuid;
  continuation_receipt_digest bytea;
  continuation_expires_at timestamptz;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_command,
    ARRAY['sessionId','expectedVersion','requestDigest','decision','reason',
      'observedAt','session','continuation'],
    ARRAY['sessionId','expectedVersion','requestDigest','decision','reason',
      'observedAt'],131072
  );
  session_id := app.private_mfa_require_uuidv7_v1(p_command ->> 'sessionId');
  expected_version := (p_command ->> 'expectedVersion')::bigint;
  request_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'requestDigest',32,32
  );
  observed_at := (p_command ->> 'observedAt')::timestamptz;
  decision := p_command ->> 'decision';
  reason := p_command ->> 'reason';
  IF expected_version NOT BETWEEN 1 AND 2147483647
     OR request_digest = decode(repeat('00',32),'hex')
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                                AND statement_timestamp() + interval '30 seconds'
     OR decision NOT IN ('usable','rotate','step_up','revoke','deny')
     OR btrim(reason) = '' OR char_length(reason) > 500
     OR reason ~ '[[:cntrl:]]'
     OR (decision = 'rotate' AND NOT p_command ? 'session')
     OR (decision <> 'rotate' AND p_command ? 'session')
     OR (decision = 'step_up' AND NOT p_command ? 'continuation')
     OR (decision <> 'step_up' AND p_command ? 'continuation') THEN
    RAISE EXCEPTION 'invalid direct platform OIDC revalidation command'
      USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO existing
  FROM ONLY public.platform_oidc_session_revalidation_commands AS command
  WHERE command.session_id = session_id
    AND command.expected_version = expected_version;
  IF FOUND THEN
    IF existing.request_digest <> request_digest
       OR existing.decision <> decision THEN
      RAISE EXCEPTION 'direct platform OIDC revalidation replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN existing.result_snapshot;
  END IF;
  SELECT session.* INTO STRICT session_record
  FROM ONLY public.auth_sessions AS session
  WHERE session.id = session_id FOR UPDATE;
  SELECT state.* INTO STRICT state_record
  FROM ONLY public.auth_session_platform_oidc_states AS state
  WHERE state.session_id = session_id FOR UPDATE;
  SELECT provenance.* INTO STRICT provenance_record
  FROM ONLY public.auth_session_platform_oidc_provenance AS provenance
  WHERE provenance.session_id = session_id FOR SHARE;
  SELECT evidence.* INTO STRICT provider_evidence
  FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
  WHERE evidence.session_id = session_id AND evidence.kind = 'platform_provider';
  SELECT evidence.* INTO totp_evidence
  FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
  WHERE evidence.session_id = session_id AND evidence.kind = 'totp';
  authority := app.load_platform_oidc_session_revalidation_v1(jsonb_build_object(
    'sessionId',session_id::text,'observedAt',to_jsonb(observed_at)
  ));
  IF state_record.session_version <> expected_version THEN
    RAISE EXCEPTION 'direct platform OIDC revalidation lost session CAS'
      USING ERRCODE = '40001';
  END IF;
  authority_live := coalesce(
    authority IS NOT NULL
    AND authority #>> '{session,activeTenantId}' IS NULL
    AND authority #>> '{session,authenticationMethod}' = 'oidc'
    AND authority #>> '{session,audience}' = 'api'
    AND authority #>> '{session,primaryKind}' = 'platform_provider'
    AND NOT (authority #>> '{session,recoveryRestricted}')::boolean
    AND (authority #>> '{session,directStateCount}')::integer = 1
    AND (authority #>> '{session,directProvenanceCount}')::integer = 1
    AND (authority #>> '{session,tenantProvenanceCount}')::integer = 0
    AND (authority #>> '{session,providerEvidenceCount}')::integer = 1
    AND (authority #>> '{session,totpEvidenceCount}')::integer BETWEEN 0 AND 1
    AND (authority #>> '{session,userAuthenticationRevision}')::bigint =
      state_record.user_authentication_revision
    AND (authority #>> '{session,issuedAt}')::timestamptz =
      state_record.issued_at
    AND state_record.issued_at BETWEEN provenance_record.authenticated_at
                                   AND observed_at
    AND (authority #>> '{session,currentVersion}')::bigint = expected_version
    AND (authority #>> '{session,active}')::boolean
    AND (authority #>> '{session,rotationFamilyLive}')::boolean
    AND authority #>> '{session,userId}' = state_record.user_id::text
    AND authority #>> '{authority,providerId}' =
      provenance_record.platform_provider_id::text
    AND authority #>> '{authority,externalIdentityId}' =
      provenance_record.external_identity_id::text
    AND authority #>> '{authority,providerKind}' = 'oidc'
    AND (authority #>> '{authority,runtimePolicyEnabled}')::boolean
    AND NOT (authority #>>
      '{authority,legacyPlatformLoginEnabled}')::boolean
    AND (authority #>> '{authority,loginPolicyEnabled}')::boolean
    AND authority #>> '{authority,accountMode}' = 'existing_identity'
    AND authority #>> '{authority,identityCurrentProviderId}' =
      provenance_record.platform_provider_id::text
    AND authority #>> '{authority,identityCurrentUserId}' =
      state_record.user_id::text
    AND authority #>> '{authority,identityProviderKind}' = 'oidc'
    AND authority #> '{authority,identityRetiredAt}' = 'null'::jsonb
    AND authority #>> '{authority,aliasCurrentProviderId}' =
      provenance_record.platform_provider_id::text
    AND authority #>> '{authority,aliasCurrentIdentityId}' =
      provenance_record.external_identity_id::text
    AND authority #> '{authority,aliasRetiredAt}' = 'null'::jsonb
    AND (authority #>> '{authority,providerRevision,pinned}')::bigint
       = (authority #>> '{authority,providerRevision,current}')::bigint
    AND (authority #>> '{authority,securityRevision,pinned}')::bigint
       = (authority #>> '{authority,securityRevision,current}')::bigint
    AND (authority #>> '{authority,loginPolicyRevision,pinned}')::bigint
       = (authority #>> '{authority,loginPolicyRevision,current}')::bigint
    AND (authority #>>
      '{authority,userAuthenticationRevision,pinned}')::bigint
       = (authority #>>
      '{authority,userAuthenticationRevision,current}')::bigint
    AND (authority #>> '{authority,userAuthenticationRevision,pinned}')::bigint
       = (authority #>> '{session,userAuthenticationRevision}')::bigint
    AND (authority #>> '{authority,identityVersion,pinned}')::bigint
       = (authority #>> '{authority,identityVersion,current}')::bigint
    AND (authority #>> '{authority,aliasKeyVersion,pinned}')::integer
       = (authority #>> '{authority,aliasKeyVersion,current}')::integer
    AND (authority #>> '{authority,assurancePolicyRevision,pinned}')::bigint
       = (authority #>>
      '{authority,assurancePolicyRevision,current}')::bigint
    AND authority #>> '{authority,platformFloor,pinnedId}'
       = authority #>> '{authority,platformFloor,currentId}'
    AND (authority #>>
      '{authority,platformFloor,pinnedRevision}')::bigint
       = (authority #>>
      '{authority,platformFloor,currentRevision}')::bigint
    AND authority #>> '{authority,platformFloor,currentScope}' =
      'platform_floor'
    AND authority #> '{authority,platformFloor,currentTenantId}' =
      'null'::jsonb
    AND authority #> '{authority,platformFloor,currentRetiredAt}' =
      'null'::jsonb
    AND (authority #>> '{authority,platformFloor,currentCount}')::integer = 1
    AND (authority #>> '{authority,providerEnabled}')::boolean
    AND (authority #>> '{authority,platformLoginLive}')::boolean
    AND (authority #>> '{authority,userActive}')::boolean
    AND (authority #>> '{authority,identityLive}')::boolean
    AND (authority #>> '{authority,subjectAliasLive}')::boolean
    AND (authority #>> '{authority,factorEvidenceLive}')::boolean
    AND (authority #>> '{authority,evidenceFresh}')::boolean
    AND EXISTS (
      SELECT 1
      FROM ONLY public.auth_session_platform_oidc_evidence AS floor_evidence
      WHERE floor_evidence.session_id = session_id
        AND (CASE floor_evidence.level
          WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
          WHEN 'phishing_resistant' THEN 3 ELSE 0 END) >=
          (CASE authority #>> '{authority,platformFloor,level}'
            WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
            WHEN 'phishing_resistant' THEN 3 ELSE 4 END)
        AND (NOT (authority #>>
          '{authority,platformFloor,localRequired}')::boolean
          OR floor_evidence.kind = 'totp')
        AND ((authority #>>
          '{authority,platformFloor,freshnessNanoseconds}')::bigint = 0
          OR floor_evidence.authenticated_at +
            ((authority #>>
              '{authority,platformFloor,freshnessNanoseconds}')::numeric /
              1000000000) * interval '1 second' > observed_at)
    )
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
      LEFT JOIN ONLY public.platform_federated_trust_rules AS trust
        ON trust.id = evidence.trust_rule_id
      WHERE evidence.session_id = session_id
        AND (
          evidence.authenticated_at > state_record.issued_at
          OR (evidence.trust_rule_id IS NOT NULL AND (
            trust.id IS NULL
            OR evidence.expires_at IS NULL
            OR evidence.authenticated_at + make_interval(
              secs => trust.maximum_authentication_age_seconds
            ) <= observed_at
            OR evidence.expires_at > evidence.authenticated_at + make_interval(
              secs => trust.maximum_authentication_age_seconds
            )
          ))
        )
    )
    AND (authority #>> '{authority,policyPinsExact}')::boolean
    AND (authority #>> '{authority,trustEvidenceLive}')::boolean
    AND jsonb_array_length(authority -> 'factorAuthorities') =
      (authority #>> '{session,totpEvidenceCount}')::integer
    AND jsonb_array_length(authority -> 'trustAuthorities') =
      CASE WHEN provider_evidence.trust_rule_id IS NULL THEN 0 ELSE 1 END,
    false
  );
  IF decision IN ('usable','rotate','step_up') AND NOT authority_live THEN
    RAISE EXCEPTION 'direct platform OIDC revalidation authority is stale'
      USING ERRCODE = '40001';
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  IF decision = 'usable' THEN
    UPDATE ONLY public.auth_session_platform_oidc_states AS state
    SET session_version = state.session_version + 1
    WHERE state.session_id = session_id
      AND state.session_version = expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'direct platform OIDC revalidation lost session CAS'
        USING ERRCODE = '40001';
    END IF;
    result := jsonb_build_object(
      'applied',true,'decision','usable','sessionId',session_id::text,
      'userId',state_record.user_id::text,
      'expectedVersion',expected_version,'newVersion',expected_version + 1
    );
  ELSIF decision = 'rotate' THEN
    IF app.private_mfa_require_uuidv7_v1(
      p_command #>> '{session,rotationFamilyId}'
    ) <> session_record.rotation_family_id THEN
      RAISE EXCEPTION 'direct platform OIDC rotation family changed'
        USING ERRCODE = '22023';
    END IF;
    new_session_id := app.private_platform_oidc_create_direct_session_v1(
      p_command -> 'session',state_record.user_id,
      provenance_record.platform_provider_id,
      provenance_record.external_identity_id,
      provenance_record.provider_revision,provenance_record.security_revision,
      provenance_record.login_policy_revision,
      provenance_record.user_authentication_revision,
      provenance_record.identity_version,provenance_record.alias_key_version,
      provenance_record.assurance_policy_revision,
      provenance_record.platform_floor_policy_id,
      provenance_record.platform_floor_policy_revision,
      provenance_record.trust_rule_id,provenance_record.trust_rule_revision,
      CASE WHEN provider_evidence.level = 'phishing_resistant'
        THEN 'phishing_resistant'
        WHEN totp_evidence.id IS NOT NULL THEN 'mfa'
        ELSE provider_evidence.level END,
      provenance_record.authenticated_at,observed_at,
      totp_evidence.totp_credential_id,totp_evidence.factor_revision,
      totp_evidence.authenticated_at,session_id
    );
    UPDATE ONLY public.auth_sessions AS session
    SET revoked_at = observed_at,revoke_reason = 'session_revalidation_rotated'
    WHERE session.id = session_id AND session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'direct platform OIDC rotation lost source CAS'
        USING ERRCODE = '40001';
    END IF;
    result := jsonb_build_object(
      'applied',true,'decision','rotate','sessionId',session_id::text,
      'userId',state_record.user_id::text,'expectedVersion',expected_version,
      'newVersion',0,'newSessionId',new_session_id::text
    );
  ELSIF decision = 'step_up' THEN
    SELECT factor.* INTO STRICT selected_totp_record
    FROM ONLY public.totp_credentials AS factor
    WHERE factor.user_id = state_record.user_id
      AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    ORDER BY factor.id
    LIMIT 1
    FOR SHARE;
    PERFORM app.private_platform_oidc_direct_json_v1(
      p_command -> 'continuation',
      ARRAY['id','receiptDigest','audience','expiresAt'],
      ARRAY['id','receiptDigest','audience','expiresAt'],16384
    );
    continuation_id := app.private_mfa_require_uuidv7_v1(
      p_command #>> '{continuation,id}'
    );
    continuation_receipt_digest := app.private_mfa_decode_base64_v1(
      p_command #>> '{continuation,receiptDigest}',32,32
    );
    continuation_expires_at :=
      (p_command #>> '{continuation,expiresAt}')::timestamptz;
    IF continuation_receipt_digest = decode(repeat('00',32),'hex')
       OR p_command #>> '{continuation,audience}' <> state_record.audience
       OR state_record.audience <> 'api'
       OR continuation_expires_at NOT BETWEEN observed_at + interval '1 minute'
                                          AND observed_at + interval '10 minutes'
       OR continuation_expires_at > session_record.absolute_expires_at THEN
      RAISE EXCEPTION 'invalid direct platform OIDC revalidation continuation'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.platform_post_primary_continuations (
      id,user_id,receipt_digest,action,audience,platform_provider_id,
      external_identity_id,provider_revision,login_policy_revision,
      security_revision,user_authentication_revision,identity_version,
      alias_key_version,assurance_policy_revision,platform_floor_policy_id,
      platform_floor_policy_revision,selected_totp_credential_id,
      selected_totp_security_revision,trust_rule_id,trust_rule_revision,
      origin,source_session_id,source_session_family_id,
      source_session_version,source_absolute_expires_at,state,version,
      created_at,expires_at
    ) VALUES (
      continuation_id,state_record.user_id,continuation_receipt_digest,
      'session.revalidate',p_command #>> '{continuation,audience}',
      provenance_record.platform_provider_id,
      provenance_record.external_identity_id,
      provenance_record.provider_revision,provenance_record.login_policy_revision,
      provenance_record.security_revision,
      provenance_record.user_authentication_revision,
      provenance_record.identity_version,provenance_record.alias_key_version,
      provenance_record.assurance_policy_revision,
      provenance_record.platform_floor_policy_id,
      provenance_record.platform_floor_policy_revision,
      selected_totp_record.id,selected_totp_record.security_revision,
      provenance_record.trust_rule_id,provenance_record.trust_rule_revision,
      'session_revalidation',session_id,session_record.rotation_family_id,
      expected_version + 1,session_record.absolute_expires_at,
      'pending',1,observed_at,continuation_expires_at
    );
    INSERT INTO public.platform_post_primary_continuation_evidence (
      id,continuation_id,user_id,kind,level,platform_provider_id,
      external_identity_id,totp_credential_id,factor_revision,trust_rule_id,
      trust_rule_revision,authenticated_at,expires_at
    ) SELECT uuidv7(),continuation_id,evidence.user_id,evidence.kind,
      evidence.level,evidence.platform_provider_id,evidence.external_identity_id,
      evidence.totp_credential_id,evidence.factor_revision,evidence.trust_rule_id,
      evidence.trust_rule_revision,evidence.authenticated_at,evidence.expires_at
    FROM ONLY public.auth_session_platform_oidc_evidence AS evidence
    WHERE evidence.session_id = session_id
      AND evidence.kind = 'platform_provider';
    INSERT INTO public.platform_post_primary_continuation_policy_pins (
      continuation_id,policy_kind,policy_id,policy_revision
    ) SELECT continuation_id,pin.policy_kind,pin.policy_id,pin.policy_revision
    FROM ONLY public.auth_session_platform_oidc_policy_pins AS pin
    WHERE pin.session_id = session_id;
    UPDATE ONLY public.auth_session_platform_oidc_states AS state
    SET session_version = state.session_version + 1
    WHERE state.session_id = session_id
      AND state.session_version = expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'direct platform OIDC revalidation lost session CAS'
        USING ERRCODE = '40001';
    END IF;
    result := jsonb_build_object(
      'applied',true,'decision','step_up','sessionId',session_id::text,
      'userId',state_record.user_id::text,'expectedVersion',expected_version,
      'continuationId',continuation_id::text,'newVersion',expected_version + 1
    );
  ELSE
    UPDATE ONLY public.auth_sessions AS family
    SET revoked_at = observed_at,
        revoke_reason = left('platform_oidc_revalidation_' || reason,500)
    WHERE family.user_id = session_record.user_id
      AND family.rotation_family_id = session_record.rotation_family_id
      AND family.revoked_at IS NULL;
    UPDATE ONLY public.platform_post_primary_continuations AS continuation
    SET state = 'revoked',version = continuation.version + 1,
        revoked_at = observed_at,
        revoke_reason = left('session_revalidation_' || reason,500)
    WHERE continuation.user_id = state_record.user_id
      AND continuation.platform_provider_id = provenance_record.platform_provider_id
      AND continuation.external_identity_id = provenance_record.external_identity_id
      AND continuation.state = 'pending';
    result := jsonb_build_object(
      'applied',true,'decision',decision,'sessionId',session_id::text,
      'userId',state_record.user_id::text,'expectedVersion',expected_version,
      'newVersion',0
    );
  END IF;
  INSERT INTO public.platform_oidc_session_revalidation_commands (
    session_id,expected_version,request_digest,decision,result_snapshot,applied_at
  ) VALUES (
    session_id,expected_version,request_digest,decision,result,observed_at
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN jsonb_strip_nulls(jsonb_build_object(
    'applied',false,'category','stale','sessionId',session_id::text,
    'userId',coalesce(state_record.user_id,session_record.user_id)::text,
    'decision',decision,'expectedVersion',expected_version,'newVersion',0
  ));
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC session revalidation command'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_continuation_source_live_v1(
  p_continuation public.platform_post_primary_continuations,
  p_observed_at timestamp with time zone
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT p_continuation.audience = 'api'
    AND pg_catalog.encode(p_continuation.receipt_digest,'hex') <>
      pg_catalog.repeat('00',32)
    AND p_continuation.action = CASE p_continuation.origin
      WHEN 'initial_login' THEN 'session.create'
      WHEN 'session_revalidation' THEN 'session.revalidate'
      ELSE ''
    END
    AND (
      SELECT count(*) = 1 AND coalesce(bool_and(
        evidence.kind = 'platform_provider'
        AND evidence.user_id = p_continuation.user_id
        AND evidence.platform_provider_id =
          p_continuation.platform_provider_id
        AND evidence.external_identity_id =
          p_continuation.external_identity_id
        AND evidence.totp_credential_id IS NULL
        AND evidence.factor_revision IS NULL
        AND evidence.trust_rule_id IS NOT DISTINCT FROM
          p_continuation.trust_rule_id
        AND evidence.trust_rule_revision IS NOT DISTINCT FROM
          p_continuation.trust_rule_revision
        AND evidence.authenticated_at <= p_observed_at + interval '30 seconds'
        AND (evidence.expires_at IS NULL
          OR evidence.expires_at > p_observed_at)
        AND (
          (p_continuation.trust_rule_id IS NULL
            AND evidence.level = 'primary')
          OR EXISTS (
            SELECT 1
            FROM ONLY public.platform_federated_trust_rules AS trust
            WHERE trust.id = p_continuation.trust_rule_id
              AND trust.provider_id = p_continuation.platform_provider_id
              AND trust.provider_kind = 'oidc'
              AND trust.revision = p_continuation.trust_rule_revision
              AND trust.level = evidence.level
              AND trust.enabled AND trust.retired_at IS NULL
              AND evidence.authenticated_at + make_interval(
                secs => trust.maximum_authentication_age_seconds
              ) > p_observed_at
          )
        )
        AND EXISTS (
          SELECT 1
          FROM ONLY public.mfa_policy_revisions AS platform_floor
          WHERE platform_floor.id = p_continuation.platform_floor_policy_id
            AND platform_floor.revision =
              p_continuation.platform_floor_policy_revision
            AND platform_floor.scope = 'platform_floor'
            AND platform_floor.tenant_id IS NULL
            AND platform_floor.retired_at IS NULL
            -- The pending local TOTP, not necessarily the provider proof,
            -- must be capable of satisfying the exact platform floor.
            AND platform_floor.level IN ('primary','mfa')
        )
      ),false)
      FROM ONLY public.platform_post_primary_continuation_evidence AS evidence
      WHERE evidence.continuation_id = p_continuation.id
    )
    AND (
      SELECT count(*) = 3 AND coalesce(bool_and(
        (pin.policy_kind = 'login'
          AND pin.policy_id = p_continuation.platform_provider_id
          AND pin.policy_revision = p_continuation.login_policy_revision)
        OR (pin.policy_kind = 'assurance'
          AND pin.policy_id = p_continuation.platform_provider_id
          AND pin.policy_revision = p_continuation.assurance_policy_revision)
        OR (pin.policy_kind = 'platform_floor'
          AND pin.policy_id = p_continuation.platform_floor_policy_id
          AND pin.policy_revision =
            p_continuation.platform_floor_policy_revision)
      ),false)
      FROM ONLY public.platform_post_primary_continuation_policy_pins AS pin
      WHERE pin.continuation_id = p_continuation.id
    )
    AND (p_continuation.origin = 'initial_login' OR (
      p_continuation.origin = 'session_revalidation' AND EXISTS (
      SELECT 1
      FROM ONLY public.auth_sessions AS source_session
      JOIN ONLY public.auth_session_platform_oidc_states AS source_state
        ON source_state.session_id = source_session.id
       AND source_state.user_id = source_session.user_id
       AND source_state.primary_kind = 'platform_provider'
      JOIN ONLY public.auth_session_platform_oidc_provenance AS provenance
        ON provenance.session_id = source_state.session_id
       AND provenance.user_id = source_state.user_id
       AND provenance.primary_kind = source_state.primary_kind
      WHERE source_session.id = p_continuation.source_session_id
        AND source_session.user_id = p_continuation.user_id
        AND source_session.rotation_family_id =
          p_continuation.source_session_family_id
        AND source_session.active_tenant_id IS NULL
        AND source_session.authentication_method = 'oidc'
        AND source_session.revoked_at IS NULL
        AND source_session.idle_expires_at > p_observed_at
        AND source_session.absolute_expires_at > p_observed_at
        AND source_session.absolute_expires_at =
          p_continuation.source_absolute_expires_at
        AND source_state.session_version = p_continuation.source_session_version
        AND source_state.user_authentication_revision =
          p_continuation.user_authentication_revision
        AND provenance.platform_provider_id =
          p_continuation.platform_provider_id
        AND provenance.external_identity_id =
          p_continuation.external_identity_id
        AND provenance.provider_revision = p_continuation.provider_revision
        AND provenance.login_policy_revision =
          p_continuation.login_policy_revision
        AND provenance.security_revision = p_continuation.security_revision
        AND provenance.user_authentication_revision =
          p_continuation.user_authentication_revision
        AND provenance.identity_version = p_continuation.identity_version
        AND provenance.alias_key_version = p_continuation.alias_key_version
        AND provenance.assurance_policy_revision =
          p_continuation.assurance_policy_revision
        AND provenance.platform_floor_policy_id =
          p_continuation.platform_floor_policy_id
        AND provenance.platform_floor_policy_revision =
          p_continuation.platform_floor_policy_revision
        AND provenance.trust_rule_id IS NOT DISTINCT FROM
          p_continuation.trust_rule_id
        AND provenance.trust_rule_revision IS NOT DISTINCT FROM
          p_continuation.trust_rule_revision
        AND NOT EXISTS (
          SELECT 1 FROM ONLY public.auth_session_mfa_states AS tenant_state
          WHERE tenant_state.session_id = source_session.id
        )
        AND NOT EXISTS (
          SELECT 1
          FROM ONLY public.auth_session_federated_provenance AS tenant_provenance
          WHERE tenant_provenance.session_id = source_session.id
        )
        AND NOT EXISTS (
          SELECT 1
          FROM ONLY public.auth_session_tenant_platform_federated_provenance
            AS tenant_platform_provenance
          WHERE tenant_platform_provenance.session_id = source_session.id
        )
        AND (
          SELECT count(*) = 3 AND bool_and(
            (pin.policy_kind = 'login'
              AND pin.policy_id = p_continuation.platform_provider_id
              AND pin.policy_revision = p_continuation.login_policy_revision)
            OR (pin.policy_kind = 'assurance'
              AND pin.policy_id = p_continuation.platform_provider_id
              AND pin.policy_revision =
                p_continuation.assurance_policy_revision)
            OR (pin.policy_kind = 'platform_floor'
              AND pin.policy_id = p_continuation.platform_floor_policy_id
              AND pin.policy_revision =
                p_continuation.platform_floor_policy_revision)
          )
          FROM ONLY public.auth_session_platform_oidc_policy_pins AS pin
          WHERE pin.session_id = source_session.id
        )
      )
    ));
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_post_primary_totp_projection_v1(
  p_challenge public.platform_post_primary_totp_challenges
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'challengeId',replace(encode(p_challenge.id,'base64'),E'\n',''),
    'continuationId',p_challenge.continuation_id::text,
    'userId',p_challenge.user_id::text,
    'totpCredentialId',p_challenge.totp_credential_id::text,
    'userAuthenticationRevision',p_challenge.user_authentication_revision,
    'totpSecurityRevision',p_challenge.totp_security_revision,
    'failureCount',p_challenge.failure_count,'state',p_challenge.state,
    'version',p_challenge.version,'expiresAt',to_jsonb(p_challenge.expires_at),
    'result',p_challenge.result_snapshot
  ));
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_platform_post_primary_totp_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  challenge jsonb;
  continuation_id uuid;
  receipt_digest bytea;
  expected_version bigint;
  challenge_id bytea;
  browser_digest bytea;
  created_at timestamptz;
  expires_at timestamptz;
  observed_at timestamptz;
  continuation_record public.platform_post_primary_continuations%ROWTYPE;
  factor_record public.totp_credentials%ROWTYPE;
  challenge_record public.platform_post_primary_totp_challenges%ROWTYPE;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['continuationId','receiptDigest','expectedVersion','challenge',
      'observedAt','audit'],
    ARRAY['continuationId','receiptDigest','expectedVersion','challenge',
      'observedAt','audit'],32768
  );
  challenge := p_request -> 'challenge';
  PERFORM app.private_platform_oidc_direct_json_v1(
    challenge,ARRAY['id','browserDigest','createdAt','expiresAt'],
    ARRAY['id','browserDigest','createdAt','expiresAt'],8192
  );
  continuation_id := app.private_mfa_require_uuidv7_v1(
    p_request ->> 'continuationId'
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'receiptDigest',32,32
  );
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  challenge_id := app.private_mfa_decode_base64_v1(challenge ->> 'id',32,32);
  browser_digest := app.private_mfa_decode_base64_v1(
    challenge ->> 'browserDigest',32,32
  );
  created_at := (challenge ->> 'createdAt')::timestamptz;
  expires_at := (challenge ->> 'expiresAt')::timestamptz;
  observed_at := (p_request ->> 'observedAt')::timestamptz;
  IF expected_version <> 1
     OR receipt_digest = decode(repeat('00',32),'hex')
     OR challenge_id = decode(repeat('00',32),'hex')
     OR browser_digest = decode(repeat('00',32),'hex')
     OR challenge_id = browser_digest
     OR created_at <> observed_at
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds'
     OR expires_at NOT BETWEEN created_at + interval '1 minute'
                           AND created_at + interval '10 minutes' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC TOTP begin request'
      USING ERRCODE = '22023';
  END IF;
  SELECT continuation.* INTO STRICT continuation_record
  FROM ONLY public.platform_post_primary_continuations AS continuation
  WHERE continuation.id = continuation_id
    AND continuation.receipt_digest = receipt_digest
  FOR UPDATE;
  IF continuation_record.state <> 'pending'
     OR continuation_record.version <> expected_version
     OR continuation_record.expires_at <= observed_at
     OR expires_at > continuation_record.expires_at
     OR NOT app.private_platform_oidc_direct_continuation_source_live_v1(
       continuation_record,observed_at
     )
     OR NOT app.private_platform_oidc_direct_authority_live_v1(
       continuation_record.platform_provider_id,continuation_record.user_id,
       continuation_record.external_identity_id,
       continuation_record.provider_revision,
       continuation_record.security_revision,
       continuation_record.login_policy_revision,
       continuation_record.user_authentication_revision,
       continuation_record.identity_version,
       continuation_record.alias_key_version,
       continuation_record.assurance_policy_revision,
       continuation_record.platform_floor_policy_id,
       continuation_record.platform_floor_policy_revision,
       continuation_record.trust_rule_id,
       continuation_record.trust_rule_revision
     ) THEN
    RETURN NULL;
  END IF;
  SELECT factor.* INTO STRICT factor_record
  FROM ONLY public.totp_credentials AS factor
  WHERE factor.id = continuation_record.selected_totp_credential_id
    AND factor.user_id = continuation_record.user_id
    AND factor.security_revision =
      continuation_record.selected_totp_security_revision
    AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
  FOR SHARE;
  SELECT existing.* INTO challenge_record
  FROM ONLY public.platform_post_primary_totp_challenges AS existing
  WHERE existing.continuation_id = continuation_id;
  IF FOUND THEN
    IF challenge_record.id <> challenge_id
       OR challenge_record.browser_digest <> browser_digest THEN
      RAISE EXCEPTION 'direct platform OIDC TOTP begin replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  INSERT INTO public.platform_post_primary_totp_challenges (
    id,continuation_id,user_id,totp_credential_id,browser_digest,
    expected_continuation_version,user_authentication_revision,
    totp_security_revision,failure_count,state,version,created_at,expires_at
  ) VALUES (
    challenge_id,continuation_id,continuation_record.user_id,factor_record.id,
    browser_digest,expected_version,
    continuation_record.user_authentication_revision,
    factor_record.security_revision,0,'pending',1,created_at,expires_at
  ) RETURNING * INTO challenge_record;
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.totp_started',
    'platform_identity_account',continuation_record.external_identity_id,
    'success',jsonb_build_object(
      'provider_id',continuation_record.platform_provider_id,
      'user_id',continuation_record.user_id,
      'totp_security_revision',factor_record.security_revision
    )
  );
  RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC TOTP begin request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_post_primary_totp_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  challenge_id bytea;
  browser_digest bytea;
  continuation_id uuid;
  receipt_digest bytea;
  observed_at timestamptz;
  result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,ARRAY['challengeId','browserDigest','continuationId',
      'receiptDigest','observedAt'],
    ARRAY['challengeId','browserDigest','continuationId',
      'receiptDigest','observedAt'],16384
  );
  challenge_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'challengeId',32,32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'browserDigest',32,32
  );
  continuation_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'continuationId'
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'receiptDigest',32,32
  );
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  IF challenge_id = decode(repeat('00',32),'hex')
     OR browser_digest = decode(repeat('00',32),'hex')
     OR receipt_digest = decode(repeat('00',32),'hex')
     OR challenge_id = browser_digest
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC TOTP lookup'
      USING ERRCODE = '22023';
  END IF;
  SELECT jsonb_build_object(
    'authority','direct_platform_oidc',
    'challengeId',replace(encode(challenge.id,'base64'),E'\n',''),
    'continuationId',continuation.id::text,'userId',continuation.user_id::text,
    'receiptDigest',replace(encode(continuation.receipt_digest,'base64'),E'\n',''),
    'totpCredentialId',factor.id::text,
    'secretCiphertext',replace(encode(factor.secret_ciphertext,'base64'),E'\n',''),
    'secretNonce',replace(encode(factor.secret_nonce,'base64'),E'\n',''),
    'secretAad',replace(encode(factor.secret_aad,'base64'),E'\n',''),
    'keyVersion',factor.key_version,
    'encryptionAlgorithm',factor.encryption_algorithm,
    'otpAlgorithm',factor.otp_algorithm,'digits',factor.digits,
    'periodSeconds',factor.period_seconds,
    'lastAcceptedCounter',factor.last_accepted_counter,
    'userAuthenticationRevision',local_user.authentication_revision,
    'totpSecurityRevision',factor.security_revision,
    'expiresAt',to_jsonb(challenge.expires_at),'version',challenge.version
  ) INTO result
  FROM ONLY public.platform_post_primary_totp_challenges AS challenge
  JOIN ONLY public.platform_post_primary_continuations AS continuation
    ON continuation.id = challenge.continuation_id
   AND continuation.user_id = challenge.user_id
  JOIN ONLY public.users AS local_user
    ON local_user.id = continuation.user_id AND local_user.active
  JOIN ONLY public.totp_credentials AS factor
    ON factor.id = challenge.totp_credential_id
   AND factor.user_id = continuation.user_id
   AND factor.id = continuation.selected_totp_credential_id
   AND factor.security_revision =
     continuation.selected_totp_security_revision
   AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
  WHERE challenge.id = challenge_id
    AND challenge.browser_digest = browser_digest
    AND challenge.continuation_id = continuation_id
    AND challenge.state = 'pending' AND challenge.expires_at > observed_at
    AND continuation.id = continuation_id
    AND continuation.receipt_digest = receipt_digest
    AND continuation.state = 'pending' AND continuation.expires_at > observed_at
    AND app.private_platform_oidc_direct_continuation_source_live_v1(
      continuation,observed_at
    )
    AND local_user.authentication_revision = challenge.user_authentication_revision
    AND factor.security_revision = challenge.totp_security_revision
    AND app.private_platform_oidc_direct_authority_live_v1(
      continuation.platform_provider_id,continuation.user_id,
      continuation.external_identity_id,continuation.provider_revision,
      continuation.security_revision,continuation.login_policy_revision,
      continuation.user_authentication_revision,continuation.identity_version,
      continuation.alias_key_version,continuation.assurance_policy_revision,
      continuation.platform_floor_policy_id,
      continuation.platform_floor_policy_revision,
      continuation.trust_rule_id,continuation.trust_rule_revision
    )
  FOR SHARE OF challenge,continuation,local_user,factor;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC TOTP lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.record_platform_post_primary_totp_failure_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  challenge_id bytea;
  browser_digest bytea;
  continuation_id uuid;
  receipt_digest bytea;
  expected_version bigint;
  observed_at timestamptz;
  challenge_record public.platform_post_primary_totp_challenges%ROWTYPE;
  continuation_record public.platform_post_primary_continuations%ROWTYPE;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['challengeId','browserDigest','continuationId','receiptDigest',
      'expectedVersion','observedAt','audit'],
    ARRAY['challengeId','browserDigest','continuationId','receiptDigest',
      'expectedVersion','observedAt','audit'],24576
  );
  challenge_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'challengeId',32,32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest',32,32
  );
  continuation_id := app.private_mfa_require_uuidv7_v1(
    p_request ->> 'continuationId'
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'receiptDigest',32,32
  );
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  observed_at := (p_request ->> 'observedAt')::timestamptz;
  IF expected_version NOT BETWEEN 1 AND 2147483647
     OR challenge_id = decode(repeat('00',32),'hex')
     OR browser_digest = decode(repeat('00',32),'hex')
     OR receipt_digest = decode(repeat('00',32),'hex')
     OR challenge_id = browser_digest
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC TOTP failure request'
      USING ERRCODE = '22023';
  END IF;
  SELECT challenge.* INTO STRICT challenge_record
  FROM ONLY public.platform_post_primary_totp_challenges AS challenge
  WHERE challenge.id = challenge_id AND challenge.browser_digest = browser_digest
  FOR UPDATE;
  SELECT continuation.* INTO STRICT continuation_record
  FROM ONLY public.platform_post_primary_continuations AS continuation
  WHERE continuation.id = continuation_id
    AND continuation.id = challenge_record.continuation_id
    AND continuation.receipt_digest = receipt_digest
    AND continuation.state = 'pending'
    AND continuation.version = challenge_record.expected_continuation_version
    AND continuation.expires_at > observed_at
  FOR UPDATE;
  IF challenge_record.state <> 'pending'
     OR challenge_record.version <> expected_version
     OR challenge_record.expires_at <= observed_at THEN
    RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
  END IF;
  IF NOT app.private_platform_oidc_direct_authority_live_v1(
       continuation_record.platform_provider_id,continuation_record.user_id,
       continuation_record.external_identity_id,
       continuation_record.provider_revision,
       continuation_record.security_revision,
       continuation_record.login_policy_revision,
       continuation_record.user_authentication_revision,
       continuation_record.identity_version,
       continuation_record.alias_key_version,
       continuation_record.assurance_policy_revision,
       continuation_record.platform_floor_policy_id,
       continuation_record.platform_floor_policy_revision,
       continuation_record.trust_rule_id,
       continuation_record.trust_rule_revision
     ) OR NOT app.private_platform_oidc_direct_continuation_source_live_v1(
       continuation_record,observed_at
     ) OR NOT EXISTS (
       SELECT 1 FROM ONLY public.totp_credentials AS factor
       WHERE factor.id = continuation_record.selected_totp_credential_id
         AND factor.user_id = continuation_record.user_id
         AND factor.security_revision =
           continuation_record.selected_totp_security_revision
         AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
     ) THEN
    RETURN NULL;
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_post_primary_totp_challenges AS challenge
  SET failure_count = challenge.failure_count + 1,
      version = challenge.version + 1,
      state = CASE WHEN challenge.failure_count + 1 >= 5
        THEN 'failed' ELSE 'pending' END,
      abandoned_at = CASE WHEN challenge.failure_count + 1 >= 5
        THEN observed_at ELSE NULL END
  WHERE challenge.id = challenge_id
    AND challenge.continuation_id = continuation_id
    AND challenge.state = 'pending'
    AND challenge.version = expected_version
    AND EXISTS (
      SELECT 1
      FROM ONLY public.platform_post_primary_continuations AS continuation
      WHERE continuation.id = continuation_id
        AND continuation.receipt_digest = receipt_digest
        AND continuation.state = 'pending'
        AND continuation.version = challenge.expected_continuation_version
    )
  RETURNING challenge.* INTO STRICT challenge_record;
  IF challenge_record.state = 'failed' THEN
    UPDATE ONLY public.platform_post_primary_continuations AS continuation
    SET state = 'revoked',version = continuation.version + 1,
        revoked_at = observed_at,revoke_reason = 'totp_attempts_exhausted'
    WHERE continuation.id = continuation_id
      AND continuation.receipt_digest = receipt_digest
      AND continuation.state = 'pending';
  END IF;
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.totp_failed',
    'platform_identity_account',continuation_record.external_identity_id,
    'failure',jsonb_build_object(
      'provider_id',continuation_record.platform_provider_id,
      'user_id',continuation_record.user_id,
      'failure_count',challenge_record.failure_count,
      'attempts_exhausted',challenge_record.state = 'failed'
    )
  );
  RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC TOTP failure request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_post_primary_totp_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  challenge_id bytea;
  browser_digest bytea;
  continuation_id uuid;
  receipt_digest bytea;
  completion_request_digest bytea;
  expected_version bigint;
  accepted_counter bigint;
  observed_at timestamptz;
  challenge_record public.platform_post_primary_totp_challenges%ROWTYPE;
  continuation_record public.platform_post_primary_continuations%ROWTYPE;
  factor_record public.totp_credentials%ROWTYPE;
  provider_evidence public.platform_post_primary_continuation_evidence%ROWTYPE;
  session_id uuid;
  result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['challengeId','browserDigest','continuationId','receiptDigest',
      'expectedVersion','acceptedCounter','completionRequestDigest','session',
      'observedAt','audit'],
    ARRAY['challengeId','browserDigest','continuationId','receiptDigest',
      'expectedVersion','acceptedCounter','completionRequestDigest','session',
      'observedAt','audit'],65536
  );
  challenge_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'challengeId',32,32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest',32,32
  );
  continuation_id := app.private_mfa_require_uuidv7_v1(
    p_request ->> 'continuationId'
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'receiptDigest',32,32
  );
  completion_request_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'completionRequestDigest',32,32
  );
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  accepted_counter := (p_request ->> 'acceptedCounter')::bigint;
  observed_at := (p_request ->> 'observedAt')::timestamptz;
  IF expected_version NOT BETWEEN 1 AND 2147483647
     OR accepted_counter < 0
     OR challenge_id = decode(repeat('00',32),'hex')
     OR browser_digest = decode(repeat('00',32),'hex')
     OR receipt_digest = decode(repeat('00',32),'hex')
     OR completion_request_digest = decode(repeat('00',32),'hex')
     OR challenge_id = browser_digest
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC TOTP apply request'
      USING ERRCODE = '22023';
  END IF;
  SELECT challenge.* INTO STRICT challenge_record
  FROM ONLY public.platform_post_primary_totp_challenges AS challenge
  WHERE challenge.id = challenge_id
    AND challenge.browser_digest = browser_digest
    AND challenge.continuation_id = continuation_id
  FOR UPDATE;
  SELECT continuation.* INTO STRICT continuation_record
  FROM ONLY public.platform_post_primary_continuations AS continuation
  WHERE continuation.id = continuation_id
    AND continuation.id = challenge_record.continuation_id
    AND continuation.receipt_digest = receipt_digest
  FOR UPDATE;
  IF challenge_record.state = 'completed' THEN
    IF challenge_record.completion_request_digest <> completion_request_digest THEN
      RAISE EXCEPTION 'direct platform OIDC TOTP apply replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN challenge_record.result_snapshot;
  END IF;
  SELECT factor.* INTO STRICT factor_record
  FROM ONLY public.totp_credentials AS factor
  WHERE factor.id = challenge_record.totp_credential_id
    AND factor.user_id = continuation_record.user_id
  FOR UPDATE;
  SELECT evidence.* INTO STRICT provider_evidence
  FROM ONLY public.platform_post_primary_continuation_evidence AS evidence
  WHERE evidence.continuation_id = continuation_record.id
    AND evidence.kind = 'platform_provider';
  IF challenge_record.state <> 'pending'
     OR challenge_record.version <> expected_version
     OR challenge_record.expires_at <= observed_at
     OR continuation_record.state <> 'pending'
     OR continuation_record.version <> challenge_record.expected_continuation_version
     OR continuation_record.receipt_digest <> receipt_digest
     OR continuation_record.expires_at <= observed_at
     OR NOT app.private_platform_oidc_direct_continuation_source_live_v1(
       continuation_record,observed_at
     )
     OR challenge_record.totp_credential_id <>
       continuation_record.selected_totp_credential_id
     OR challenge_record.totp_security_revision <>
       continuation_record.selected_totp_security_revision
     OR factor_record.security_revision <> challenge_record.totp_security_revision
     OR factor_record.confirmed_at IS NULL OR factor_record.disabled_at IS NOT NULL
     OR NOT app.private_platform_oidc_direct_authority_live_v1(
       continuation_record.platform_provider_id,continuation_record.user_id,
       continuation_record.external_identity_id,
       continuation_record.provider_revision,continuation_record.security_revision,
       continuation_record.login_policy_revision,
       continuation_record.user_authentication_revision,
       continuation_record.identity_version,continuation_record.alias_key_version,
       continuation_record.assurance_policy_revision,
       continuation_record.platform_floor_policy_id,
       continuation_record.platform_floor_policy_revision,
       continuation_record.trust_rule_id,continuation_record.trust_rule_revision
     ) THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  UPDATE ONLY public.totp_credentials AS factor
  SET last_accepted_counter = accepted_counter,updated_at = transaction_timestamp()
  WHERE factor.id = factor_record.id
    AND factor.security_revision = challenge_record.totp_security_revision
    AND (factor.last_accepted_counter IS NULL
      OR factor.last_accepted_counter < accepted_counter);
  IF NOT FOUND THEN
    RETURN jsonb_build_object('applied',false,'category','replay');
  END IF;
  session_id := app.private_platform_oidc_create_direct_session_v1(
    p_request -> 'session',continuation_record.user_id,
    continuation_record.platform_provider_id,
    continuation_record.external_identity_id,
    continuation_record.provider_revision,continuation_record.security_revision,
    continuation_record.login_policy_revision,
    continuation_record.user_authentication_revision,
    continuation_record.identity_version,continuation_record.alias_key_version,
    continuation_record.assurance_policy_revision,
    continuation_record.platform_floor_policy_id,
    continuation_record.platform_floor_policy_revision,
    continuation_record.trust_rule_id,continuation_record.trust_rule_revision,
    CASE WHEN provider_evidence.level = 'phishing_resistant'
      THEN 'phishing_resistant' ELSE 'mfa' END,
    provider_evidence.authenticated_at,observed_at,factor_record.id,
    factor_record.security_revision,observed_at,
    CASE WHEN continuation_record.origin = 'session_revalidation'
      THEN continuation_record.source_session_id ELSE NULL END
  );
  result := jsonb_build_object(
    'applied',true,'category','success','sessionId',session_id::text,
    'userId',continuation_record.user_id::text,
    'externalIdentityId',continuation_record.external_identity_id::text,
    'acceptedCounter',accepted_counter,
    'totpCredentialId',factor_record.id::text,
    'totpSecurityRevision',factor_record.security_revision
  );
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_post_primary_continuations AS continuation
  SET state = 'consumed',version = continuation.version + 1,
      consumed_at = observed_at
  WHERE continuation.id = continuation_id
    AND continuation.receipt_digest = receipt_digest
    AND continuation.state = 'pending'
    AND continuation.version = challenge_record.expected_continuation_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct platform OIDC continuation lost CAS'
      USING ERRCODE = '40001';
  END IF;
  IF continuation_record.origin = 'session_revalidation' THEN
    UPDATE ONLY public.auth_sessions AS source_session
    SET revoked_at = observed_at,
        revoke_reason = 'platform_oidc_step_up_rotated'
    WHERE source_session.id = continuation_record.source_session_id
      AND source_session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'direct platform OIDC step-up source lost CAS'
        USING ERRCODE = '40001';
    END IF;
  END IF;
  UPDATE ONLY public.platform_post_primary_totp_challenges AS challenge
  SET state = 'completed',version = challenge.version + 1,
      completion_request_digest = completion_request_digest,
      result_snapshot = result,completed_at = observed_at
  WHERE challenge.id = challenge_id
    AND challenge.continuation_id = continuation_id
    AND challenge.state = 'pending'
    AND challenge.version = expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct platform OIDC TOTP challenge lost CAS'
      USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.totp_succeeded',
    'platform_identity_account',continuation_record.external_identity_id,
    'success',jsonb_build_object(
      'provider_id',continuation_record.platform_provider_id,
      'user_id',continuation_record.user_id,
      'totp_security_revision',factor_record.security_revision
    )
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN jsonb_build_object('applied',false,'category','stale');
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC TOTP apply request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.abandon_platform_post_primary_totp_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  challenge_id bytea;
  browser_digest bytea;
  continuation_id uuid;
  receipt_digest bytea;
  expected_version bigint;
  observed_at timestamptz;
  reason text;
  challenge_record public.platform_post_primary_totp_challenges%ROWTYPE;
  continuation_record public.platform_post_primary_continuations%ROWTYPE;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['challengeId','browserDigest','continuationId','receiptDigest',
      'expectedVersion','observedAt','reason','audit'],
    ARRAY['challengeId','browserDigest','continuationId','receiptDigest',
      'expectedVersion','observedAt','reason','audit'],24576
  );
  challenge_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'challengeId',32,32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest',32,32
  );
  continuation_id := app.private_mfa_require_uuidv7_v1(
    p_request ->> 'continuationId'
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'receiptDigest',32,32
  );
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  observed_at := (p_request ->> 'observedAt')::timestamptz;
  reason := p_request ->> 'reason';
  IF expected_version NOT BETWEEN 1 AND 2147483647
     OR challenge_id = decode(repeat('00',32),'hex')
     OR browser_digest = decode(repeat('00',32),'hex')
     OR receipt_digest = decode(repeat('00',32),'hex')
     OR challenge_id = browser_digest
     OR reason NOT IN ('cancelled','expired','superseded')
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC TOTP abandon reason'
      USING ERRCODE = '22023';
  END IF;
  SELECT challenge.* INTO STRICT challenge_record
  FROM ONLY public.platform_post_primary_totp_challenges AS challenge
  WHERE challenge.id = challenge_id
    AND challenge.browser_digest = browser_digest
    AND challenge.continuation_id = continuation_id
  FOR UPDATE;
  SELECT continuation.* INTO STRICT continuation_record
  FROM ONLY public.platform_post_primary_continuations AS continuation
  WHERE continuation.id = continuation_id
    AND continuation.id = challenge_record.continuation_id
    AND continuation.receipt_digest = receipt_digest
    AND continuation.state = 'pending'
    AND continuation.version = challenge_record.expected_continuation_version
  FOR UPDATE;
  IF challenge_record.state <> 'pending'
     OR challenge_record.version <> expected_version THEN
    RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
  END IF;
  IF NOT app.private_platform_oidc_direct_authority_live_v1(
       continuation_record.platform_provider_id,continuation_record.user_id,
       continuation_record.external_identity_id,
       continuation_record.provider_revision,
       continuation_record.security_revision,
       continuation_record.login_policy_revision,
       continuation_record.user_authentication_revision,
       continuation_record.identity_version,
       continuation_record.alias_key_version,
       continuation_record.assurance_policy_revision,
       continuation_record.platform_floor_policy_id,
       continuation_record.platform_floor_policy_revision,
       continuation_record.trust_rule_id,
       continuation_record.trust_rule_revision
     ) OR NOT app.private_platform_oidc_direct_continuation_source_live_v1(
       continuation_record,observed_at
     ) OR NOT EXISTS (
       SELECT 1 FROM ONLY public.totp_credentials AS factor
       WHERE factor.id = continuation_record.selected_totp_credential_id
         AND factor.user_id = continuation_record.user_id
         AND factor.security_revision =
           continuation_record.selected_totp_security_revision
         AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
     ) THEN
    RETURN NULL;
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_post_primary_totp_challenges AS challenge
  SET state = CASE WHEN reason = 'expired' THEN 'expired' ELSE 'abandoned' END,
      version = challenge.version + 1,abandoned_at = observed_at
  WHERE challenge.id = challenge_id
    AND challenge.continuation_id = continuation_id
    AND challenge.state = 'pending'
    AND challenge.version = expected_version
  RETURNING challenge.* INTO STRICT challenge_record;
  UPDATE ONLY public.platform_post_primary_continuations AS continuation
  SET state = CASE WHEN reason = 'expired' THEN 'expired' ELSE 'revoked' END,
      version = continuation.version + 1,revoked_at = observed_at,
      revoke_reason = reason
  WHERE continuation.id = continuation_id
    AND continuation.receipt_digest = receipt_digest
    AND continuation.state = 'pending';
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.totp_abandoned',
    'platform_identity_account',continuation_record.external_identity_id,
    'failure',jsonb_build_object(
      'provider_id',continuation_record.platform_provider_id,
      'user_id',continuation_record.user_id,'category',reason
    )
  );
  RETURN app.private_platform_post_primary_totp_projection_v1(challenge_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC TOTP abandon request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_authority_live_v1(
  p_provider_id uuid,
  p_user_id uuid,
  p_external_identity_id uuid,
  p_provider_revision bigint,
  p_security_revision bigint,
  p_login_policy_revision bigint,
  p_user_authentication_revision bigint,
  p_identity_version bigint,
  p_alias_key_version integer,
  p_assurance_policy_revision bigint,
  p_platform_floor_policy_id uuid,
  p_platform_floor_policy_revision bigint,
  p_trust_rule_id uuid,
  p_trust_rule_revision bigint
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT EXISTS (
    SELECT 1
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
     AND runtime_policy.provider_kind = 'oidc'
     AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
     AND login_policy.provider_kind = 'oidc'
     AND login_policy.enabled
     AND login_policy.account_mode = 'existing_identity'
    JOIN ONLY public.mfa_policy_revisions AS platform_floor
      ON platform_floor.id = p_platform_floor_policy_id
     AND platform_floor.revision = p_platform_floor_policy_revision
     AND platform_floor.scope = 'platform_floor'
     AND platform_floor.tenant_id IS NULL
     AND platform_floor.retired_at IS NULL
    JOIN ONLY public.users AS local_user
      ON local_user.id = p_user_id AND local_user.active
    JOIN ONLY public.platform_federated_external_identities AS identity
      ON identity.id = p_external_identity_id
     AND identity.platform_provider_id = provider.id
     AND identity.user_id = local_user.id
     AND identity.provider_kind = 'oidc'
     AND identity.retired_at IS NULL
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = provider.id
     AND alias.external_identity_id = identity.id
     AND alias.key_version = p_alias_key_version
     AND alias.retired_at IS NULL
    WHERE provider.id = p_provider_id AND provider.kind = 'oidc'
      AND provider.enabled AND provider.archived_at IS NULL
      AND provider.version = p_provider_revision
      AND runtime_policy.security_revision = p_security_revision
      AND runtime_policy.assurance_policy_revision = p_assurance_policy_revision
      AND login_policy.revision = p_login_policy_revision
      AND local_user.authentication_revision = p_user_authentication_revision
      AND identity.version = p_identity_version
      AND ((p_trust_rule_id IS NULL AND p_trust_rule_revision IS NULL)
        OR EXISTS (
          SELECT 1 FROM ONLY public.platform_federated_trust_rules AS trust
          WHERE trust.id = p_trust_rule_id
            AND trust.provider_id = provider.id
            AND trust.provider_kind = 'oidc'
            AND trust.revision = p_trust_rule_revision
            AND trust.enabled AND trust.retired_at IS NULL
        ))
  );
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_create_direct_session_v1(
  p_session jsonb,
  p_user_id uuid,
  p_provider_id uuid,
  p_external_identity_id uuid,
  p_provider_revision bigint,
  p_security_revision bigint,
  p_login_policy_revision bigint,
  p_user_authentication_revision bigint,
  p_identity_version bigint,
  p_alias_key_version integer,
  p_assurance_policy_revision bigint,
  p_platform_floor_policy_id uuid,
  p_platform_floor_policy_revision bigint,
  p_trust_rule_id uuid,
  p_trust_rule_revision bigint,
  p_assurance_level text,
  p_authenticated_at timestamptz,
  p_issued_at timestamptz,
  p_totp_credential_id uuid DEFAULT NULL,
  p_totp_security_revision bigint DEFAULT NULL,
  p_totp_authenticated_at timestamptz DEFAULT NULL,
  p_rotated_from_session_id uuid DEFAULT NULL
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  session_id uuid;
  rotation_family_id uuid;
  token_digest bytea;
  csrf_secret_digest bytea;
  idle_expires_at timestamptz;
  absolute_expires_at timestamptz;
  audience text;
  platform_floor_level text;
  platform_floor_local_required boolean;
  platform_floor_freshness_nanoseconds bigint;
  trust_level text;
  trust_maximum_age_seconds integer;
  provider_evidence_expires_at timestamptz;
  provider_floor_eligible boolean;
  totp_floor_eligible boolean;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_session,
    ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest','audience',
      'idleExpiresAt','absoluteExpiresAt','sessionVersion'],
    ARRAY['id','rotationFamilyId','tokenDigest','csrfSecretDigest','audience',
      'idleExpiresAt','absoluteExpiresAt','sessionVersion'],32768
  );
  session_id := app.private_mfa_require_uuidv7_v1(p_session ->> 'id');
  rotation_family_id := app.private_mfa_require_uuidv7_v1(
    p_session ->> 'rotationFamilyId'
  );
  token_digest := app.private_mfa_decode_base64_v1(
    p_session ->> 'tokenDigest',32,32
  );
  csrf_secret_digest := app.private_mfa_decode_base64_v1(
    p_session ->> 'csrfSecretDigest',32,32
  );
  audience := p_session ->> 'audience';
  idle_expires_at := (p_session ->> 'idleExpiresAt')::timestamptz;
  absolute_expires_at := (p_session ->> 'absoluteExpiresAt')::timestamptz;
  IF session_id = rotation_family_id
     OR (p_session ->> 'sessionVersion')::bigint <> 1
     OR p_assurance_level NOT IN ('primary','mfa','phishing_resistant')
     OR p_issued_at < p_authenticated_at
     OR idle_expires_at <= p_issued_at
     OR absolute_expires_at <= idle_expires_at
     OR absolute_expires_at > p_issued_at + interval '30 days'
     OR audience <> 'api'
     OR (p_assurance_level = 'primary' AND (
       p_trust_rule_id IS NOT NULL OR p_trust_rule_revision IS NOT NULL
     )) OR ((p_trust_rule_id IS NULL) <> (p_trust_rule_revision IS NULL))
     OR (p_assurance_level = 'phishing_resistant'
       AND p_trust_rule_id IS NULL)
     OR (p_assurance_level = 'mfa' AND p_trust_rule_id IS NULL
       AND p_totp_credential_id IS NULL)
     OR ((p_totp_credential_id IS NULL) <> (p_totp_security_revision IS NULL))
     OR ((p_totp_credential_id IS NULL) <> (p_totp_authenticated_at IS NULL))
     OR (p_totp_authenticated_at IS NOT NULL AND
       p_totp_authenticated_at NOT BETWEEN p_authenticated_at AND p_issued_at) THEN
    RAISE EXCEPTION 'invalid direct platform OIDC session envelope'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.private_platform_oidc_direct_authority_live_v1(
    p_provider_id,p_user_id,p_external_identity_id,p_provider_revision,
    p_security_revision,p_login_policy_revision,
    p_user_authentication_revision,p_identity_version,p_alias_key_version,
    p_assurance_policy_revision,p_platform_floor_policy_id,
    p_platform_floor_policy_revision,p_trust_rule_id,p_trust_rule_revision
  ) THEN
    RAISE EXCEPTION 'direct platform OIDC session authority is stale'
      USING ERRCODE = '40001';
  END IF;
  SELECT floor.level,floor.local_required,floor.freshness_nanoseconds
    INTO STRICT platform_floor_level,platform_floor_local_required,
      platform_floor_freshness_nanoseconds
  FROM ONLY public.mfa_policy_revisions AS floor
  WHERE floor.id = p_platform_floor_policy_id
    AND floor.revision = p_platform_floor_policy_revision
    AND floor.scope = 'platform_floor' AND floor.tenant_id IS NULL
    AND floor.retired_at IS NULL
  FOR SHARE;
  IF p_trust_rule_id IS NOT NULL THEN
    SELECT trust.level,trust.maximum_authentication_age_seconds
      INTO STRICT trust_level,trust_maximum_age_seconds
    FROM ONLY public.platform_federated_trust_rules AS trust
    WHERE trust.id = p_trust_rule_id AND trust.provider_id = p_provider_id
      AND trust.provider_kind = 'oidc'
      AND trust.revision = p_trust_rule_revision
      AND trust.enabled AND trust.retired_at IS NULL
    FOR SHARE;
    IF trust_level <> p_assurance_level
       OR (trust_maximum_age_seconds > 0 AND
         p_authenticated_at + make_interval(secs => trust_maximum_age_seconds)
           <= p_issued_at) THEN
      RAISE EXCEPTION 'direct platform OIDC trust evidence is stale'
        USING ERRCODE = '42501';
    END IF;
    IF trust_maximum_age_seconds > 0 THEN
      provider_evidence_expires_at := p_authenticated_at +
        make_interval(secs => trust_maximum_age_seconds);
    END IF;
  END IF;
  IF p_totp_credential_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM ONLY public.totp_credentials AS factor
    WHERE factor.id = p_totp_credential_id AND factor.user_id = p_user_id
      AND factor.security_revision = p_totp_security_revision
      AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
  ) THEN
    RAISE EXCEPTION 'direct platform OIDC TOTP authority is stale'
      USING ERRCODE = '40001';
  END IF;
  provider_floor_eligible := NOT platform_floor_local_required
    AND (CASE WHEN p_trust_rule_id IS NULL THEN 1
          WHEN p_assurance_level = 'mfa' THEN 2
          WHEN p_assurance_level = 'phishing_resistant' THEN 3 ELSE 0 END) >=
        (CASE platform_floor_level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
          WHEN 'phishing_resistant' THEN 3 ELSE 4 END);
  totp_floor_eligible := p_totp_credential_id IS NOT NULL
    AND 2 >= (CASE platform_floor_level WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
      WHEN 'phishing_resistant' THEN 3 ELSE 4 END);
  IF NOT provider_floor_eligible AND NOT totp_floor_eligible THEN
    RAISE EXCEPTION 'direct platform OIDC platform floor is not satisfied'
      USING ERRCODE = '42501';
  END IF;
  IF platform_floor_freshness_nanoseconds > 0
     AND NOT (
       (provider_floor_eligible AND p_authenticated_at +
         (platform_floor_freshness_nanoseconds::numeric / 1000000000) *
           interval '1 second' > p_issued_at)
       OR (totp_floor_eligible AND p_totp_authenticated_at +
         (platform_floor_freshness_nanoseconds::numeric / 1000000000) *
           interval '1 second' > p_issued_at)
     ) THEN
    RAISE EXCEPTION 'direct platform OIDC platform floor evidence is stale'
      USING ERRCODE = '40001';
  END IF;
  IF p_rotated_from_session_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM ONLY public.auth_sessions AS source_session
    WHERE source_session.id = p_rotated_from_session_id
      AND source_session.user_id = p_user_id
      AND source_session.rotation_family_id = rotation_family_id
      AND source_session.absolute_expires_at = absolute_expires_at
      AND source_session.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'direct platform OIDC rotation source is stale'
      USING ERRCODE = '40001';
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  INSERT INTO public.auth_sessions (
    id,user_id,rotation_family_id,active_tenant_id,token_digest,
    csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
    idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
  ) VALUES (
    session_id,p_user_id,rotation_family_id,NULL,token_digest,
    csrf_secret_digest,'oidc',CASE WHEN p_assurance_level = 'primary'
      THEN NULL ELSE p_issued_at END,p_issued_at,
    idle_expires_at,absolute_expires_at,p_rotated_from_session_id,p_issued_at
  );
  INSERT INTO public.auth_session_platform_oidc_states (
    session_id,user_id,session_version,user_authentication_revision,
    recovery_restricted,audience,primary_kind,issued_at
  ) VALUES (
    session_id,p_user_id,1,p_user_authentication_revision,false,audience,
    'platform_provider',p_issued_at
  );
  INSERT INTO public.auth_session_platform_oidc_provenance (
    session_id,user_id,primary_kind,platform_provider_id,
    external_identity_id,provider_revision,login_policy_revision,
    security_revision,user_authentication_revision,identity_version,
    alias_key_version,assurance_policy_revision,platform_floor_policy_id,
    platform_floor_policy_revision,trust_rule_id,trust_rule_revision,
    authenticated_at
  ) VALUES (
    session_id,p_user_id,'platform_provider',p_provider_id,
    p_external_identity_id,p_provider_revision,p_login_policy_revision,
    p_security_revision,p_user_authentication_revision,p_identity_version,
    p_alias_key_version,p_assurance_policy_revision,p_platform_floor_policy_id,
    p_platform_floor_policy_revision,p_trust_rule_id,p_trust_rule_revision,
    p_authenticated_at
  );
  INSERT INTO public.auth_session_platform_oidc_evidence (
    id,session_id,user_id,kind,level,platform_provider_id,
    external_identity_id,totp_credential_id,factor_revision,trust_rule_id,
    trust_rule_revision,authenticated_at,expires_at
  ) VALUES (
    uuidv7(),session_id,p_user_id,'platform_provider',
    CASE WHEN p_trust_rule_id IS NULL THEN 'primary' ELSE p_assurance_level END,
    p_provider_id,p_external_identity_id,NULL,NULL,p_trust_rule_id,
    p_trust_rule_revision,p_authenticated_at,provider_evidence_expires_at
  );
  IF p_totp_credential_id IS NOT NULL THEN
    INSERT INTO public.auth_session_platform_oidc_evidence (
      id,session_id,user_id,kind,level,platform_provider_id,
      external_identity_id,totp_credential_id,factor_revision,trust_rule_id,
      trust_rule_revision,authenticated_at,expires_at
    ) VALUES (
      uuidv7(),session_id,p_user_id,'totp','mfa',NULL,NULL,
      p_totp_credential_id,p_totp_security_revision,NULL,NULL,
      p_totp_authenticated_at,
      CASE WHEN platform_floor_freshness_nanoseconds > 0 THEN
        p_totp_authenticated_at +
          (platform_floor_freshness_nanoseconds::numeric / 1000000000) *
            interval '1 second'
      ELSE NULL END
    );
  END IF;
  INSERT INTO public.auth_session_platform_oidc_policy_pins (
    session_id,policy_kind,policy_id,policy_revision
  ) VALUES
    (session_id,'login',p_provider_id,p_login_policy_revision),
    (session_id,'assurance',p_provider_id,p_assurance_policy_revision),
    (session_id,'platform_floor',p_platform_floor_policy_id,
      p_platform_floor_policy_revision);
  RETURN session_id;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_platform_oidc_authentication_v1(p_command jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  subject jsonb;
  assurance jsonb;
  observation jsonb;
  observation_envelope jsonb;
  observation_aliases jsonb;
  observation_alias jsonb;
  transaction_id bytea;
  claim_attempt_id bytea;
  operation_digest bytea;
  browser_capability_digest bytea;
  observation_nonce bytea;
  observation_ciphertext bytea;
  expected_version bigint;
  observed_at timestamptz;
  disposition text;
  return_path text;
  provider_id uuid;
  user_id uuid;
  external_identity_id uuid;
  observation_external_identity_id uuid;
  provider_revision bigint;
  security_revision bigint;
  login_policy_revision bigint;
  user_authentication_revision bigint;
  identity_version bigint;
  alias_key_version integer;
  observation_key_version integer;
  observation_alias_count integer;
  observation_alias_index integer;
  observation_alias_key_versions integer[] := ARRAY[]::integer[];
  observation_alias_subject_digests bytea[] := ARRAY[]::bytea[];
  assurance_policy_revision bigint;
  platform_floor_policy_id uuid;
  platform_floor_policy_revision bigint;
  selected_totp_credential_id uuid;
  selected_totp_security_revision bigint;
  trust_rule_id uuid;
  trust_rule_revision bigint;
  assurance_level text;
  authenticated_at timestamptz;
  transaction_record public.platform_oidc_authentication_transactions%ROWTYPE;
  existing public.platform_oidc_authentication_applications%ROWTYPE;
  result jsonb;
  session_id uuid;
  continuation_id uuid;
  continuation_receipt_digest bytea;
  continuation_expires_at timestamptz;
  totp_record public.totp_credentials%ROWTYPE;
  continuation_floor_record public.mfa_policy_revisions%ROWTYPE;
  continuation_trust_record public.platform_federated_trust_rules%ROWTYPE;
  continuation_provider_expires_at timestamptz;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_command,
    ARRAY['transactionId','claimAttemptId','expectedVersion','operationDigest',
      'browserCapabilityDigest','returnPath','subject','observation',
      'assurance','disposition','session','continuation','observedAt','audit'],
    ARRAY['transactionId','claimAttemptId','expectedVersion','operationDigest',
      'browserCapabilityDigest','returnPath','subject','observation',
      'assurance','disposition','observedAt','audit'],2097152
  );
  subject := p_command -> 'subject';
  observation := p_command -> 'observation';
  observation_envelope := observation -> 'envelope';
  observation_aliases := observation -> 'aliases';
  assurance := p_command -> 'assurance';
  PERFORM app.private_platform_oidc_direct_json_v1(
    subject,
    ARRAY['providerId','userId','externalIdentityId','providerRevision',
      'securityRevision','loginPolicyRevision','userAuthenticationRevision',
      'identityVersion','aliasKeyVersion','assurancePolicyRevision',
      'platformFloorPolicyId','platformFloorPolicyRevision',
      'totpCredentialId','totpSecurityRevision'],
    ARRAY['providerId','userId','externalIdentityId','providerRevision',
      'securityRevision','loginPolicyRevision','userAuthenticationRevision',
      'identityVersion','aliasKeyVersion','assurancePolicyRevision',
      'platformFloorPolicyId','platformFloorPolicyRevision'],32768
  );
  PERFORM app.private_platform_oidc_direct_json_v1(
    assurance,
    ARRAY['level','authenticatedAt','trustRuleId','trustRuleRevision'],
    ARRAY['level','authenticatedAt'],16384
  );
  PERFORM app.private_platform_oidc_direct_json_v1(
    observation,
    ARRAY['externalIdentityId','format','envelope','aliases'],
    ARRAY['externalIdentityId','format','envelope','aliases'],65536
  );
  PERFORM app.private_platform_oidc_direct_json_v1(
    observation_envelope,
    ARRAY['keyVersion','format','nonce','ciphertext'],
    ARRAY['keyVersion','format','nonce','ciphertext'],16384
  );
  transaction_id := app.private_mfa_decode_base64_v1(
    p_command ->> 'transactionId',32,32
  );
  claim_attempt_id := app.private_mfa_decode_base64_v1(
    p_command ->> 'claimAttemptId',32,32
  );
  operation_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'operationDigest',32,32
  );
  browser_capability_digest := app.private_mfa_decode_base64_v1(
    p_command ->> 'browserCapabilityDigest',32,32
  );
  return_path := p_command ->> 'returnPath';
  expected_version := (p_command ->> 'expectedVersion')::bigint;
  observed_at := (p_command ->> 'observedAt')::timestamptz;
  disposition := p_command ->> 'disposition';
  provider_id := app.private_mfa_require_uuidv7_v1(subject ->> 'providerId');
  user_id := app.private_mfa_require_uuidv7_v1(subject ->> 'userId');
  external_identity_id := app.private_mfa_require_uuidv7_v1(
    subject ->> 'externalIdentityId'
  );
  observation_external_identity_id := app.private_mfa_require_uuidv7_v1(
    observation ->> 'externalIdentityId'
  );
  observation_key_version :=
    (observation_envelope ->> 'keyVersion')::integer;
  observation_nonce := app.private_mfa_decode_base64_v1(
    observation_envelope ->> 'nonce',12,12
  );
  observation_ciphertext := app.private_mfa_decode_base64_v1(
    observation_envelope ->> 'ciphertext',17,4112
  );
  IF jsonb_typeof(observation_aliases) <> 'array' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC subject observation aliases'
      USING ERRCODE = '22023';
  END IF;
  observation_alias_count := jsonb_array_length(observation_aliases);
  IF observation_alias_count NOT BETWEEN 1 AND 16 THEN
    RAISE EXCEPTION 'invalid direct platform OIDC subject observation aliases'
      USING ERRCODE = '22023';
  END IF;
  FOR observation_alias_index IN 0..observation_alias_count - 1 LOOP
    observation_alias := observation_aliases -> observation_alias_index;
    PERFORM app.private_platform_oidc_direct_json_v1(
      observation_alias,ARRAY['keyVersion','digest'],
      ARRAY['keyVersion','digest'],4096
    );
    observation_alias_key_versions := array_append(
      observation_alias_key_versions,
      (observation_alias ->> 'keyVersion')::integer
    );
    observation_alias_subject_digests := array_append(
      observation_alias_subject_digests,
      app.private_mfa_decode_base64_v1(
        observation_alias ->> 'digest',32,32
      )
    );
    IF observation_alias_key_versions[observation_alias_index + 1]
         NOT BETWEEN 1 AND 32767
       OR (observation_alias_index > 0 AND
         observation_alias_key_versions[observation_alias_index] >=
         observation_alias_key_versions[observation_alias_index + 1])
       OR encode(
         observation_alias_subject_digests[observation_alias_index + 1],
         'hex'
       ) = repeat('00',32) THEN
      RAISE EXCEPTION 'invalid direct platform OIDC subject observation aliases'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;
  provider_revision := (subject ->> 'providerRevision')::bigint;
  security_revision := (subject ->> 'securityRevision')::bigint;
  login_policy_revision := (subject ->> 'loginPolicyRevision')::bigint;
  user_authentication_revision :=
    (subject ->> 'userAuthenticationRevision')::bigint;
  identity_version := (subject ->> 'identityVersion')::bigint;
  alias_key_version := (subject ->> 'aliasKeyVersion')::integer;
  assurance_policy_revision :=
    (subject ->> 'assurancePolicyRevision')::bigint;
  platform_floor_policy_id := app.private_mfa_require_uuidv7_v1(
    subject ->> 'platformFloorPolicyId'
  );
  platform_floor_policy_revision :=
    (subject ->> 'platformFloorPolicyRevision')::bigint;
  IF subject ? 'totpCredentialId' THEN
    selected_totp_credential_id := app.private_mfa_require_uuidv7_v1(
      subject ->> 'totpCredentialId'
    );
  END IF;
  IF subject ? 'totpSecurityRevision' THEN
    selected_totp_security_revision :=
      (subject ->> 'totpSecurityRevision')::bigint;
  END IF;
  assurance_level := assurance ->> 'level';
  authenticated_at := (assurance ->> 'authenticatedAt')::timestamptz;
  IF assurance ? 'trustRuleId' THEN
    trust_rule_id := app.private_mfa_require_uuidv7_v1(
      assurance ->> 'trustRuleId'
    );
  END IF;
  IF assurance ? 'trustRuleRevision' THEN
    trust_rule_revision := (assurance ->> 'trustRuleRevision')::bigint;
  END IF;
  IF expected_version <> 2 OR disposition NOT IN ('session','continuation')
     OR encode(operation_digest,'hex') = repeat('00',32)
     OR encode(browser_capability_digest,'hex') = repeat('00',32)
     OR observation_external_identity_id <> external_identity_id
     OR observation ->> 'format' <> 'utf8_exact'
     OR observation_envelope ->> 'format' <> 'utf8_exact'
     OR observation_envelope ->> 'format' <> observation ->> 'format'
     OR observation_key_version NOT BETWEEN 1 AND 32767
     OR NOT observation_key_version = ANY(observation_alias_key_versions)
     OR encode(observation_nonce,'hex') = repeat('00',12)
     OR return_path !~ '^/[^[:cntrl:]]*$' OR left(return_path,2) = '//'
     OR char_length(return_path) > 2048
     OR assurance_level NOT IN ('primary','mfa','phishing_resistant')
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds'
     OR authenticated_at > observed_at + interval '30 seconds'
     OR authenticated_at < observed_at - interval '30 days'
     OR (assurance_level = 'primary' AND (
       trust_rule_id IS NOT NULL OR trust_rule_revision IS NOT NULL
     )) OR (assurance_level IN ('mfa','phishing_resistant') AND (
       trust_rule_id IS NULL OR trust_rule_revision IS NULL
     )) OR (disposition = 'session' AND NOT p_command ? 'session')
     OR (disposition = 'session' AND p_command ? 'continuation')
     OR (disposition = 'continuation' AND NOT p_command ? 'continuation')
     OR (disposition = 'continuation' AND p_command ? 'session')
     OR (disposition = 'session' AND (
       selected_totp_credential_id IS NOT NULL
       OR selected_totp_security_revision IS NOT NULL
     )) OR (disposition = 'continuation' AND (
       selected_totp_credential_id IS NULL
       OR selected_totp_security_revision IS NULL
     )) OR ((selected_totp_credential_id IS NULL) <>
       (selected_totp_security_revision IS NULL)) THEN
    RAISE EXCEPTION 'invalid direct platform OIDC apply command'
      USING ERRCODE = '22023';
  END IF;
  SELECT transaction.* INTO STRICT transaction_record
  FROM ONLY public.platform_oidc_authentication_transactions AS transaction
  WHERE transaction.transaction_id = transaction_id
  FOR UPDATE;
  SELECT application.* INTO existing
  FROM ONLY public.platform_oidc_authentication_applications AS application
  WHERE application.transaction_id = transaction_id;
  IF FOUND THEN
    IF existing.operation_digest IS DISTINCT FROM operation_digest
       OR existing.request_snapshot ->> 'requestDigest'
          IS DISTINCT FROM encode(
            sha256(convert_to(p_command::text,'UTF8')),'hex'
          )
       OR existing.request_snapshot ->> 'browserCapabilityDigest'
          IS DISTINCT FROM replace(
            encode(browser_capability_digest,'base64'),E'\n',''
          )
       OR existing.request_snapshot ->> 'returnPath'
          IS DISTINCT FROM return_path THEN
      RAISE EXCEPTION 'direct platform OIDC apply replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN existing.result_snapshot;
  END IF;
  IF transaction_record.state <> 'claimed'
     OR transaction_record.version <> expected_version
     OR transaction_record.claim_attempt_id <> claim_attempt_id
     OR transaction_record.browser_capability_digest <>
       browser_capability_digest
     OR transaction_record.return_path <> return_path
     OR transaction_record.platform_provider_id <> provider_id
     OR transaction_record.provider_revision <> provider_revision
     OR transaction_record.security_revision <> security_revision
     OR transaction_record.login_policy_revision <> login_policy_revision
     OR transaction_record.assurance_policy_revision <> assurance_policy_revision
     OR transaction_record.platform_floor_policy_id <> platform_floor_policy_id
     OR transaction_record.platform_floor_policy_revision <>
       platform_floor_policy_revision
     OR transaction_record.expires_at <= observed_at
     OR NOT app.private_platform_oidc_direct_authority_live_v1(
       provider_id,user_id,external_identity_id,provider_revision,
       security_revision,login_policy_revision,user_authentication_revision,
       identity_version,alias_key_version,assurance_policy_revision,
       platform_floor_policy_id,platform_floor_policy_revision,
       trust_rule_id,trust_rule_revision
     ) THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  -- Lock all authority rows before observing or issuing a credential.
  PERFORM 1
  FROM ONLY public.platform_auth_providers AS provider
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider.id
  JOIN ONLY public.platform_oidc_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
  JOIN ONLY public.users AS local_user ON local_user.id = user_id
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id = external_identity_id
   AND identity.platform_provider_id = provider.id
   AND identity.user_id = local_user.id
  JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = provider.id
   AND alias.external_identity_id = identity.id
   AND alias.key_version = alias_key_version
  WHERE provider.id = provider_id
  FOR UPDATE OF provider,runtime_policy,login_policy,local_user,identity,alias;
  IF NOT FOUND OR NOT app.private_platform_oidc_direct_authority_live_v1(
    provider_id,user_id,external_identity_id,provider_revision,
    security_revision,login_policy_revision,user_authentication_revision,
    identity_version,alias_key_version,assurance_policy_revision,
    platform_floor_policy_id,platform_floor_policy_revision,
    trust_rule_id,trust_rule_revision
  ) THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  -- The exact-subject namespace is serialized in the same provider-first,
  -- alias-order, dependency-before-keyring order as administrative prelink.
  -- Every retained key must be represented and no retired-key alias may be
  -- reintroduced by a successful observation.
  FOR observation_alias_index IN 1..observation_alias_count LOOP
    PERFORM pg_advisory_xact_lock(hashtextextended(
      provider_id::text || ':' ||
        observation_alias_key_versions[observation_alias_index]::text || ':' ||
        encode(
          observation_alias_subject_digests[observation_alias_index],'hex'
        ),81460322
    ));
  END LOOP;
  LOCK TABLE ONLY public.platform_federated_external_identities,
    public.platform_federated_external_identity_aliases IN ROW EXCLUSIVE MODE;
  PERFORM 1
  FROM ONLY public.identity_keyring_versions AS keyring
  WHERE keyring.retired_at IS NULL
  ORDER BY keyring.key_version
  FOR SHARE;
  IF (SELECT count(*)
      FROM ONLY public.identity_keyring_versions AS keyring
      WHERE keyring.retired_at IS NULL) <> observation_alias_count
     OR EXISTS (
       SELECT 1
       FROM unnest(observation_alias_key_versions) AS wanted(key_version)
       LEFT JOIN ONLY public.identity_keyring_versions AS keyring
         ON keyring.key_version = wanted.key_version
        AND keyring.retired_at IS NULL
       WHERE keyring.key_version IS NULL
     ) OR NOT EXISTS (
       SELECT 1
       FROM ONLY public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = observation_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RETURN jsonb_build_object('applied',false,'category','stale');
  END IF;
  -- The alias used to resolve the prelinked identity must be one member of the
  -- observation, and every retained-key alias must either be absent or already
  -- name this same identity with the same digest. Tombstones remain reserved.
  IF NOT EXISTS (
    SELECT 1
    FROM unnest(
      observation_alias_key_versions,observation_alias_subject_digests
    ) AS wanted(key_version,subject_digest)
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = provider_id
     AND alias.external_identity_id = external_identity_id
     AND alias.key_version = wanted.key_version
     AND alias.subject_digest = wanted.subject_digest
     AND alias.retired_at IS NULL
    WHERE wanted.key_version = alias_key_version
  ) OR EXISTS (
    SELECT 1
    FROM unnest(
      observation_alias_key_versions,observation_alias_subject_digests
    ) AS wanted(key_version,subject_digest)
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = provider_id
     AND alias.key_version = wanted.key_version
    WHERE alias.subject_digest = wanted.subject_digest
      AND (alias.external_identity_id <> external_identity_id
        OR alias.retired_at IS NOT NULL)
  ) OR EXISTS (
    SELECT 1
    FROM unnest(
      observation_alias_key_versions,observation_alias_subject_digests
    ) AS wanted(key_version,subject_digest)
    JOIN ONLY public.platform_federated_external_identity_aliases AS alias
      ON alias.platform_provider_id = provider_id
     AND alias.external_identity_id = external_identity_id
     AND alias.key_version = wanted.key_version
    WHERE alias.subject_digest <> wanted.subject_digest
       OR alias.retired_at IS NOT NULL
  ) THEN
    RETURN jsonb_build_object(
      'applied',false,'category','identity_collision'
    );
  END IF;
  IF disposition = 'session' THEN
    IF assurance_level = 'primary' THEN
      RETURN jsonb_build_object('applied',false,'category','denied');
    END IF;
    session_id := app.private_platform_oidc_create_direct_session_v1(
      p_command -> 'session',user_id,provider_id,external_identity_id,
      provider_revision,security_revision,login_policy_revision,
      user_authentication_revision,identity_version,alias_key_version,
      assurance_policy_revision,platform_floor_policy_id,
      platform_floor_policy_revision,trust_rule_id,trust_rule_revision,
      assurance_level,authenticated_at,observed_at,NULL,NULL
    );
    result := jsonb_build_object(
      'applied',true,'category','success','disposition','session',
      'sessionId',session_id::text,'userId',user_id::text,
      'externalIdentityId',external_identity_id::text
    );
  ELSE
    SELECT factor.* INTO STRICT totp_record
    FROM ONLY public.totp_credentials AS factor
    WHERE factor.id = selected_totp_credential_id
      AND factor.user_id = user_id
      AND factor.security_revision = selected_totp_security_revision
      AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
    FOR SHARE;
    SELECT floor.* INTO STRICT continuation_floor_record
    FROM ONLY public.mfa_policy_revisions AS floor
    WHERE floor.id = platform_floor_policy_id
      AND floor.revision = platform_floor_policy_revision
      AND floor.scope = 'platform_floor' AND floor.tenant_id IS NULL
      AND floor.retired_at IS NULL
    FOR SHARE;
    IF continuation_floor_record.level NOT IN ('primary','mfa') THEN
      RETURN jsonb_build_object('applied',false,'category','denied');
    END IF;
    IF trust_rule_id IS NOT NULL THEN
      SELECT trust.* INTO STRICT continuation_trust_record
      FROM ONLY public.platform_federated_trust_rules AS trust
      WHERE trust.id = trust_rule_id AND trust.provider_id = provider_id
        AND trust.provider_kind = 'oidc'
        AND trust.revision = trust_rule_revision
        AND trust.enabled AND trust.retired_at IS NULL
      FOR SHARE;
      IF continuation_trust_record.level <> assurance_level
         OR (continuation_trust_record.maximum_authentication_age_seconds > 0
           AND authenticated_at + make_interval(
             secs => continuation_trust_record.maximum_authentication_age_seconds
           ) <= observed_at) THEN
        RETURN jsonb_build_object('applied',false,'category','stale');
      END IF;
      IF continuation_trust_record.maximum_authentication_age_seconds > 0 THEN
        continuation_provider_expires_at := authenticated_at + make_interval(
          secs => continuation_trust_record.maximum_authentication_age_seconds
        );
      END IF;
    END IF;
    PERFORM app.private_platform_oidc_direct_json_v1(
      p_command -> 'continuation',
      ARRAY['id','receiptDigest','audience','expiresAt'],
      ARRAY['id','receiptDigest','audience','expiresAt'],16384
    );
    continuation_id := app.private_mfa_require_uuidv7_v1(
      p_command #>> '{continuation,id}'
    );
    continuation_receipt_digest := app.private_mfa_decode_base64_v1(
      p_command #>> '{continuation,receiptDigest}',32,32
    );
    continuation_expires_at :=
      (p_command #>> '{continuation,expiresAt}')::timestamptz;
    IF continuation_receipt_digest = decode(repeat('00',32),'hex')
       OR p_command #>> '{continuation,audience}' <> 'api'
       OR continuation_expires_at NOT BETWEEN observed_at + interval '1 minute'
                                          AND observed_at + interval '10 minutes' THEN
      RAISE EXCEPTION 'invalid direct platform OIDC continuation expiry'
        USING ERRCODE = '22023';
    END IF;
    PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
    INSERT INTO public.platform_post_primary_continuations (
      id,user_id,receipt_digest,action,audience,platform_provider_id,
      external_identity_id,provider_revision,login_policy_revision,
      security_revision,user_authentication_revision,identity_version,
      alias_key_version,assurance_policy_revision,platform_floor_policy_id,
      platform_floor_policy_revision,selected_totp_credential_id,
      selected_totp_security_revision,trust_rule_id,trust_rule_revision,
      state,version,created_at,expires_at
    ) VALUES (
      continuation_id,user_id,continuation_receipt_digest,'session.create',
      p_command #>> '{continuation,audience}',provider_id,
      external_identity_id,provider_revision,login_policy_revision,
      security_revision,user_authentication_revision,identity_version,
      alias_key_version,assurance_policy_revision,platform_floor_policy_id,
      platform_floor_policy_revision,selected_totp_credential_id,
      selected_totp_security_revision,trust_rule_id,trust_rule_revision,
      'pending',1,observed_at,continuation_expires_at
    );
    INSERT INTO public.platform_post_primary_continuation_evidence (
      id,continuation_id,user_id,kind,level,platform_provider_id,
      external_identity_id,totp_credential_id,factor_revision,trust_rule_id,
      trust_rule_revision,authenticated_at,expires_at
    ) VALUES (
      uuidv7(),continuation_id,user_id,'platform_provider',assurance_level,
      provider_id,external_identity_id,NULL,NULL,trust_rule_id,
      trust_rule_revision,authenticated_at,continuation_provider_expires_at
    );
    INSERT INTO public.platform_post_primary_continuation_policy_pins (
      continuation_id,policy_kind,policy_id,policy_revision
    ) VALUES
      (continuation_id,'login',provider_id,login_policy_revision),
      (continuation_id,'assurance',provider_id,assurance_policy_revision),
      (continuation_id,'platform_floor',platform_floor_policy_id,
        platform_floor_policy_revision);
    result := jsonb_build_object(
      'applied',true,'category','success','disposition','continuation',
      'continuationId',continuation_id::text,'userId',user_id::text,
      'externalIdentityId',external_identity_id::text,
      'totpCredentialId',selected_totp_credential_id::text,
      'totpSecurityRevision',totp_record.security_revision
    );
  END IF;
  FOR observation_alias_index IN 1..observation_alias_count LOOP
    INSERT INTO public.platform_federated_external_identity_aliases (
      id,platform_provider_id,external_identity_id,key_version,
      subject_digest,created_at
    ) SELECT uuidv7(),provider_id,external_identity_id,
      observation_alias_key_versions[observation_alias_index],
      observation_alias_subject_digests[observation_alias_index],
      transaction_timestamp()
    WHERE NOT EXISTS (
      SELECT 1
      FROM ONLY public.platform_federated_external_identity_aliases AS alias
      WHERE alias.platform_provider_id = provider_id
        AND alias.external_identity_id = external_identity_id
        AND alias.key_version =
          observation_alias_key_versions[observation_alias_index]
        AND alias.subject_digest =
          observation_alias_subject_digests[observation_alias_index]
        AND alias.retired_at IS NULL
    );
  END LOOP;
  UPDATE ONLY public.platform_federated_external_identities AS identity
  SET subject_format = 'utf8_exact',
      subject_ciphertext = observation_ciphertext,
      subject_nonce = observation_nonce,
      key_version = observation_key_version,
      last_observed_at = transaction_timestamp(),
      last_observation_state = 'known',
      updated_at = transaction_timestamp()
  WHERE identity.id = external_identity_id
    AND identity.platform_provider_id = provider_id
    AND identity.user_id = user_id
    AND identity.version = identity_version
    AND identity.retired_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct platform OIDC identity observation lost CAS'
      USING ERRCODE = '40001';
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_oidc_authentication_transactions AS transaction
  SET state = 'completed',version = transaction.version + 1,
      completed_at = observed_at,failure_reason = NULL
  WHERE transaction.transaction_id = transaction_id
    AND transaction.state = 'claimed' AND transaction.version = expected_version;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'direct platform OIDC apply lost transaction CAS'
      USING ERRCODE = '40001';
  END IF;
  INSERT INTO public.platform_oidc_authentication_applications (
    id,transaction_id,operation_digest,platform_provider_id,
    external_identity_id,category,primary_kind,user_id,session_id,
    continuation_id,request_snapshot,result_snapshot,applied_at
  ) VALUES (
    uuidv7(),transaction_id,operation_digest,provider_id,
    external_identity_id,'success','platform_provider',user_id,session_id,
    continuation_id,jsonb_build_object(
      'requestDigest',encode(sha256(convert_to(p_command::text,'UTF8')),'hex'),
      'browserCapabilityDigest',replace(
        encode(browser_capability_digest,'base64'),E'\n',''
      ),
      'returnPath',return_path
    ),result,observed_at
  );
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_command -> 'audit','platform.oidc.login.succeeded',
    'platform_identity_account',external_identity_id,'success',
    jsonb_build_object(
      'provider_id',provider_id,'user_id',user_id,
      'disposition',disposition,'identity_version',identity_version,
      'login_policy_revision',login_policy_revision,
      'security_revision',security_revision
    )
  );
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN jsonb_build_object('applied',false,'category','stale');
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC apply command'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.claim_platform_oidc_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  state_digest bytea;
  browser_digest bytea;
  authorization_code_digest bytea;
  claim_attempt_id bytea;
  claimed_at timestamptz;
  expected_version bigint;
  replay_event_id uuid;
  replay_request_id uuid;
  replay_correlation_id uuid;
  replay_ip_address inet;
  transaction_record public.platform_oidc_authentication_transactions%ROWTYPE;
  pins jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['stateDigest','browserDigest','authorizationCodeDigest',
      'claimAttemptId','claimedAt','expectedVersion','audit'],
    ARRAY['stateDigest','browserDigest','authorizationCodeDigest',
      'claimAttemptId','claimedAt','expectedVersion','audit'],40960
  );
  state_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'stateDigest',32,32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserDigest',32,32
  );
  authorization_code_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'authorizationCodeDigest',32,32
  );
  claim_attempt_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'claimAttemptId',32,32
  );
  claimed_at := (p_request ->> 'claimedAt')::timestamptz;
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  IF expected_version <> 1
     OR claimed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds'
     OR encode(state_digest,'hex') = repeat('00',32)
     OR encode(browser_digest,'hex') = repeat('00',32)
     OR encode(authorization_code_digest,'hex') = repeat('00',32)
     OR encode(claim_attempt_id,'hex') = repeat('00',32)
     OR state_digest = browser_digest
     OR authorization_code_digest = ANY(
       ARRAY[state_digest,browser_digest,claim_attempt_id]::bytea[]
     )
     OR claim_attempt_id = ANY(
       ARRAY[state_digest,browser_digest]::bytea[]
     ) THEN
    RAISE EXCEPTION 'invalid direct platform OIDC claim request'
      USING ERRCODE = '22023';
  END IF;
  SELECT transaction.* INTO STRICT transaction_record
  FROM ONLY public.platform_oidc_authentication_transactions AS transaction
  WHERE transaction.state_digest = state_digest
    AND transaction.browser_digest = browser_digest
  FOR UPDATE;
  IF transaction_record.state = 'claimed' THEN
    PERFORM app.private_platform_oidc_direct_json_v1(
      p_request -> 'audit',
      ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
        'authenticationMethod','reason'],
      ARRAY['eventId','requestId','correlationId','authenticationMethod'],8192
    );
    replay_event_id := app.private_mfa_require_uuidv7_v1(
      p_request #>> '{audit,eventId}'
    );
    replay_request_id := app.private_mfa_require_uuidv7_v1(
      p_request #>> '{audit,requestId}'
    );
    replay_correlation_id := app.private_mfa_require_uuidv7_v1(
      p_request #>> '{audit,correlationId}'
    );
    IF p_request #> '{audit,ipAddress}' IS NOT NULL
       AND p_request #>> '{audit,ipAddress}' <> '' THEN
      replay_ip_address := (p_request #>> '{audit,ipAddress}')::inet;
    END IF;
    IF transaction_record.claim_attempt_id <> claim_attempt_id
       OR transaction_record.authorization_code_digest <>
         authorization_code_digest
       OR transaction_record.claimed_at IS DISTINCT FROM claimed_at
       OR transaction_record.version <> expected_version + 1
       OR p_request #>> '{audit,authenticationMethod}' <> 'oidc'
       OR NOT EXISTS (
         SELECT 1
         FROM ONLY public.platform_audit_events AS audit_event
         WHERE audit_event.id = replay_event_id
           AND audit_event.actor_type = 'system'
           AND audit_event.actor_user_id IS NULL
           AND audit_event.action = 'platform.oidc.login.claimed'
           AND audit_event.resource_type = 'platform_identity_provider'
           AND audit_event.resource_id =
             transaction_record.platform_provider_id
           AND audit_event.request_id = replay_request_id
           AND audit_event.correlation_id = replay_correlation_id
           AND audit_event.ip_address IS NOT DISTINCT FROM replay_ip_address
           AND audit_event.user_agent IS NOT DISTINCT FROM
             p_request #>> '{audit,userAgent}'
           AND audit_event.authentication_method = 'oidc'
           AND audit_event.outcome = 'success'
           AND audit_event.reason IS NOT DISTINCT FROM
             p_request #>> '{audit,reason}'
           AND audit_event.metadata = jsonb_build_object(
             'transaction_version',transaction_record.version
           )
       ) THEN
      RAISE EXCEPTION 'direct platform OIDC claim replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN app.private_platform_oidc_direct_projection_v1(transaction_record);
  END IF;
  IF transaction_record.state <> 'pending'
     OR transaction_record.version <> expected_version
     OR transaction_record.expires_at <= claimed_at THEN
    RETURN NULL;
  END IF;
  pins := jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','platform','providerId',transaction_record.platform_provider_id::text
    ),
    'providerRevision',transaction_record.provider_revision,
    'loginPolicyRevision',transaction_record.login_policy_revision,
    'configurationRevision',transaction_record.configuration_revision,
    'securityRevision',transaction_record.security_revision,
    'planRevision',transaction_record.plan_revision,
    'assurancePolicyRevision',transaction_record.assurance_policy_revision,
    'platformFloorPolicyId',transaction_record.platform_floor_policy_id::text,
    'platformFloorPolicyRevision',
      transaction_record.platform_floor_policy_revision,
    'clientSecretRevision',transaction_record.client_secret_revision,
    'discoveryRevision',transaction_record.discovery_revision,
    'discoveryDigest',replace(encode(transaction_record.discovery_digest,'base64'),E'\n',''),
    'jwksRevision',transaction_record.jwks_revision,
    'jwksDigest',replace(encode(transaction_record.jwks_digest,'base64'),E'\n','')
  );
  IF app.private_platform_oidc_direct_configuration_v1(
       transaction_record.platform_provider_id,pins
     ) IS NULL THEN
    RETURN NULL;
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_oidc_authentication_transactions AS transaction
  SET state = 'claimed',version = transaction.version + 1,
      claim_attempt_id = claim_attempt_id,
      authorization_code_digest = authorization_code_digest,
      claimed_at = claimed_at
  WHERE transaction.transaction_id = transaction_record.transaction_id
    AND transaction.state_digest = state_digest
    AND transaction.browser_digest = browser_digest
    AND transaction.state = 'pending'
    AND transaction.version = expected_version
  RETURNING transaction.* INTO STRICT transaction_record;
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.claimed',
    'platform_identity_provider',transaction_record.platform_provider_id,
    'success',jsonb_build_object(
      'transaction_version',transaction_record.version
    )
  );
  RETURN app.private_platform_oidc_direct_projection_v1(transaction_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC claim request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_platform_oidc_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  transaction_id bytea;
  claim_attempt_id bytea;
  provider jsonb;
  subject_alias jsonb;
  provider_id uuid;
  alias_key_version integer;
  alias_digest bytea;
  observed_at timestamptz;
  transaction_record public.platform_oidc_authentication_transactions%ROWTYPE;
  result jsonb;
  pins jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,
    ARRAY['transactionId','claimAttemptId','provider','subjectAlias','observedAt'],
    ARRAY['transactionId','claimAttemptId','provider','subjectAlias','observedAt'],32768
  );
  provider := p_lookup -> 'provider';
  subject_alias := p_lookup -> 'subjectAlias';
  PERFORM app.private_platform_oidc_direct_json_v1(
    provider,ARRAY['scope','providerId'],ARRAY['scope','providerId'],4096
  );
  PERFORM app.private_platform_oidc_direct_json_v1(
    subject_alias,ARRAY['keyVersion','digest'],ARRAY['keyVersion','digest'],4096
  );
  IF provider ->> 'scope' <> 'platform' THEN
    RAISE EXCEPTION 'direct platform OIDC resolve scope is invalid'
      USING ERRCODE = '22023';
  END IF;
  transaction_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'transactionId',32,32
  );
  claim_attempt_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'claimAttemptId',32,32
  );
  provider_id := app.private_mfa_require_uuidv7_v1(provider ->> 'providerId');
  alias_key_version := (subject_alias ->> 'keyVersion')::integer;
  alias_digest := app.private_mfa_decode_base64_v1(
    subject_alias ->> 'digest',32,32
  );
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  IF alias_key_version NOT BETWEEN 1 AND 32767
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC resolve lookup'
      USING ERRCODE = '22023';
  END IF;
  SELECT transaction.* INTO STRICT transaction_record
  FROM ONLY public.platform_oidc_authentication_transactions AS transaction
  WHERE transaction.transaction_id = transaction_id
    AND transaction.platform_provider_id = provider_id
    AND transaction.state = 'claimed'
    AND transaction.claim_attempt_id = claim_attempt_id
    AND transaction.expires_at > observed_at;
  pins := jsonb_build_object(
    'provider',provider,
    'providerRevision',transaction_record.provider_revision,
    'loginPolicyRevision',transaction_record.login_policy_revision,
    'configurationRevision',transaction_record.configuration_revision,
    'securityRevision',transaction_record.security_revision,
    'planRevision',transaction_record.plan_revision,
    'assurancePolicyRevision',transaction_record.assurance_policy_revision,
    'platformFloorPolicyId',transaction_record.platform_floor_policy_id::text,
    'platformFloorPolicyRevision',
      transaction_record.platform_floor_policy_revision,
    'clientSecretRevision',transaction_record.client_secret_revision,
    'discoveryRevision',transaction_record.discovery_revision,
    'discoveryDigest',replace(encode(transaction_record.discovery_digest,'base64'),E'\n',''),
    'jwksRevision',transaction_record.jwks_revision,
    'jwksDigest',replace(encode(transaction_record.jwks_digest,'base64'),E'\n','')
  );
  IF app.private_platform_oidc_direct_configuration_v1(provider_id,pins) IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT jsonb_build_object(
    'provider',provider,
    'externalIdentityId',identity.id::text,
    'userId',identity.user_id::text,
    'identityVersion',identity.version,
    'aliasKeyVersion',alias.key_version,
    'userAuthenticationRevision',local_user.authentication_revision,
    'accountMode','existing_identity',
    'pins',pins
  ) INTO result
  FROM ONLY public.platform_federated_external_identity_aliases AS alias
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.platform_provider_id = alias.platform_provider_id
   AND identity.id = alias.external_identity_id
   AND identity.provider_kind = 'oidc'
   AND identity.retired_at IS NULL
  JOIN ONLY public.users AS local_user
    ON local_user.id = identity.user_id AND local_user.active
  WHERE alias.platform_provider_id = provider_id
    AND alias.key_version = alias_key_version
    AND alias.subject_digest = alias_digest
    AND alias.retired_at IS NULL;
  RETURN result;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC resolve lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_audit_v1(
  p_audit jsonb,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_outcome public.audit_outcome,
  p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  event_id uuid;
  request_id uuid;
  correlation_id uuid;
  ip_address inet;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_audit,
    ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
      'authenticationMethod','reason'],
    ARRAY['eventId','requestId','correlationId','authenticationMethod'],8192
  );
  event_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'eventId');
  request_id := app.private_mfa_require_uuidv7_v1(p_audit ->> 'requestId');
  correlation_id := app.private_mfa_require_uuidv7_v1(
    p_audit ->> 'correlationId'
  );
  IF p_audit ? 'ipAddress' AND p_audit ->> 'ipAddress' <> '' THEN
    ip_address := (p_audit ->> 'ipAddress')::inet;
  END IF;
  IF p_audit ->> 'authenticationMethod' <> 'oidc'
     OR coalesce(p_metadata,'{}'::jsonb) ?| ARRAY[
       'authorizationCode','authorizationCodeDigest','state','stateDigest',
       'nonce','nonceDigest','browserDigest','browserCapabilityDigest',
       'token','tokenDigest','secret',
       'secretCiphertext','receiptDigest','subject','subjectDigest'
     ] THEN
    RAISE EXCEPTION 'direct platform OIDC audit envelope is unsafe'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.append_platform_audit_event(
    event_id,'system',NULL,p_action,p_resource_type,p_resource_id,
    request_id,correlation_id,ip_address,p_audit ->> 'userAgent','oidc',
    p_outcome,p_audit ->> 'reason',coalesce(p_metadata,'{}'::jsonb)
  );
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.fail_platform_oidc_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  transaction_id bytea;
  expected_version bigint;
  completed_at timestamptz;
  target_state text;
  failure_reason text;
  replay_event_id uuid;
  replay_request_id uuid;
  replay_correlation_id uuid;
  replay_ip_address inet;
  transaction_record public.platform_oidc_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['transactionId','expectedVersion','state','failureReason','completedAt','audit'],
    ARRAY['transactionId','expectedVersion','state','failureReason','completedAt','audit'],32768
  );
  transaction_id := app.private_mfa_decode_base64_v1(
    p_request ->> 'transactionId',32,32
  );
  expected_version := (p_request ->> 'expectedVersion')::bigint;
  target_state := p_request ->> 'state';
  failure_reason := p_request ->> 'failureReason';
  completed_at := (p_request ->> 'completedAt')::timestamptz;
  IF expected_version NOT BETWEEN 1 AND 2147483646
     OR target_state NOT IN ('failed','expired')
     OR failure_reason NOT IN (
       'provider_response','expired','token_exchange','token_validation',
       'identity_application','stale_configuration','superseded'
     ) OR completed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                                AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC failure request'
      USING ERRCODE = '22023';
  END IF;
  SELECT transaction.* INTO STRICT transaction_record
  FROM ONLY public.platform_oidc_authentication_transactions AS transaction
  WHERE transaction.transaction_id = transaction_id
  FOR UPDATE;
  IF transaction_record.state IN ('failed','expired') THEN
    PERFORM app.private_platform_oidc_direct_json_v1(
      p_request -> 'audit',
      ARRAY['eventId','requestId','correlationId','ipAddress','userAgent',
        'authenticationMethod','reason'],
      ARRAY['eventId','requestId','correlationId','authenticationMethod'],8192
    );
    replay_event_id := app.private_mfa_require_uuidv7_v1(
      p_request #>> '{audit,eventId}'
    );
    replay_request_id := app.private_mfa_require_uuidv7_v1(
      p_request #>> '{audit,requestId}'
    );
    replay_correlation_id := app.private_mfa_require_uuidv7_v1(
      p_request #>> '{audit,correlationId}'
    );
    IF p_request #> '{audit,ipAddress}' IS NOT NULL
       AND p_request #>> '{audit,ipAddress}' <> '' THEN
      replay_ip_address := (p_request #>> '{audit,ipAddress}')::inet;
    END IF;
    IF transaction_record.state <> target_state
       OR transaction_record.failure_reason <> failure_reason
       OR transaction_record.completed_at IS DISTINCT FROM completed_at
       OR transaction_record.version <> expected_version + 1
       OR p_request #>> '{audit,authenticationMethod}' <> 'oidc'
       OR NOT EXISTS (
         SELECT 1
         FROM ONLY public.platform_audit_events AS audit_event
         WHERE audit_event.id = replay_event_id
           AND audit_event.actor_type = 'system'
           AND audit_event.actor_user_id IS NULL
           AND audit_event.action = 'platform.oidc.login.failed'
           AND audit_event.resource_type = 'platform_identity_provider'
           AND audit_event.resource_id =
             transaction_record.platform_provider_id
           AND audit_event.request_id = replay_request_id
           AND audit_event.correlation_id = replay_correlation_id
           AND audit_event.ip_address IS NOT DISTINCT FROM replay_ip_address
           AND audit_event.user_agent IS NOT DISTINCT FROM
             p_request #>> '{audit,userAgent}'
           AND audit_event.authentication_method = 'oidc'
           AND audit_event.outcome = 'failure'
           AND audit_event.reason IS NOT DISTINCT FROM
             p_request #>> '{audit,reason}'
           AND audit_event.metadata = jsonb_build_object(
             'failure_category',failure_reason,
             'transaction_version',transaction_record.version
           )
       ) THEN
      RAISE EXCEPTION 'direct platform OIDC failure replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN app.private_platform_oidc_direct_projection_v1(transaction_record);
  END IF;
  IF transaction_record.state NOT IN ('pending','claimed')
     OR transaction_record.version <> expected_version THEN
    RETURN NULL;
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_oidc_authentication_transactions AS transaction
  SET state = target_state,version = transaction.version + 1,
      completed_at = completed_at,failure_reason = failure_reason
  WHERE transaction.transaction_id = transaction_id
    AND transaction.version = expected_version
    AND transaction.state IN ('pending','claimed')
  RETURNING transaction.* INTO STRICT transaction_record;
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.failed',
    'platform_identity_provider',transaction_record.platform_provider_id,
    'failure',jsonb_build_object(
      'failure_category',failure_reason,'transaction_version',transaction_record.version
    )
  );
  RETURN app.private_platform_oidc_direct_projection_v1(transaction_record);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC failure request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_oidc_client_secret_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  provider jsonb;
  pins jsonb;
  provider_id uuid;
  result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,ARRAY['provider','pins'],ARRAY['provider','pins'],32768
  );
  provider := p_lookup -> 'provider';
  pins := p_lookup -> 'pins';
  PERFORM app.private_platform_oidc_direct_json_v1(
    provider,ARRAY['scope','providerId'],ARRAY['scope','providerId'],4096
  );
  IF provider ->> 'scope' <> 'platform' THEN
    RAISE EXCEPTION 'direct platform OIDC secret scope is invalid'
      USING ERRCODE = '22023';
  END IF;
  provider_id := app.private_mfa_require_uuidv7_v1(provider ->> 'providerId');
  IF app.private_platform_oidc_direct_configuration_v1(provider_id,pins) IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT jsonb_build_object(
    'provider',provider,'pins',pins,
    'secretId',secret.id::text,'revision',secret.revision,
    'keyVersion',secret.key_version,
    'nonce',replace(encode(secret.nonce,'base64'),E'\n',''),
    'ciphertext',replace(encode(secret.ciphertext,'base64'),E'\n','')
  ) INTO result
  FROM ONLY public.platform_oidc_client_secrets AS secret
  JOIN ONLY public.identity_keyring_versions AS keyring
    ON keyring.key_version = secret.key_version
   AND keyring.retired_at IS NULL
  WHERE secret.provider_id = provider_id
    AND secret.revision = (pins ->> 'clientSecretRevision')::bigint
    AND secret.retired_at IS NULL;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC secret lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_oidc_trust_snapshot_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  provider jsonb;
  pins jsonb;
  provider_id uuid;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,ARRAY['provider','pins'],ARRAY['provider','pins'],32768
  );
  provider := p_lookup -> 'provider';
  pins := p_lookup -> 'pins';
  PERFORM app.private_platform_oidc_direct_json_v1(
    provider,ARRAY['scope','providerId'],ARRAY['scope','providerId'],4096
  );
  IF provider ->> 'scope' <> 'platform' THEN
    RAISE EXCEPTION 'direct platform OIDC trust scope is invalid'
      USING ERRCODE = '22023';
  END IF;
  provider_id := app.private_mfa_require_uuidv7_v1(provider ->> 'providerId');
  IF app.private_platform_oidc_direct_configuration_v1(provider_id,pins) IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'provider',provider,
    'assurancePolicyRevision',(pins ->> 'assurancePolicyRevision')::bigint,
    'rules',coalesce((
      SELECT jsonb_agg(jsonb_build_object(
        'id',rule.id::text,'revision',rule.revision,'level',rule.level,
        'exactValue',rule.exact_value,'requiredValues',to_jsonb(rule.required_values),
        'maximumAuthenticationAgeSeconds',rule.maximum_authentication_age_seconds
      ) ORDER BY rule.id,rule.revision)
      FROM ONLY public.platform_federated_trust_rules AS rule
      WHERE rule.provider_id = provider_id AND rule.provider_kind = 'oidc'
        AND rule.enabled AND rule.retired_at IS NULL
    ),'[]'::jsonb)
  );
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC trust lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.load_platform_oidc_planning_state_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  transaction_id bytea;
  claim_attempt_id bytea;
  external_identity_id uuid;
  user_id uuid;
  alias_key_version integer;
  observed_at timestamptz;
  result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,
    ARRAY['transactionId','claimAttemptId','externalIdentityId','userId',
      'identityVersion','aliasKeyVersion','userAuthenticationRevision','observedAt'],
    ARRAY['transactionId','claimAttemptId','externalIdentityId','userId',
      'identityVersion','aliasKeyVersion','userAuthenticationRevision','observedAt'],32768
  );
  transaction_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'transactionId',32,32
  );
  claim_attempt_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'claimAttemptId',32,32
  );
  external_identity_id := app.private_mfa_require_uuidv7_v1(
    p_lookup ->> 'externalIdentityId'
  );
  user_id := app.private_mfa_require_uuidv7_v1(p_lookup ->> 'userId');
  alias_key_version := (p_lookup ->> 'aliasKeyVersion')::integer;
  observed_at := (p_lookup ->> 'observedAt')::timestamptz;
  IF observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC planning lookup'
      USING ERRCODE = '22023';
  END IF;
  SELECT jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','platform','providerId',transaction.platform_provider_id::text
    ),
    'externalIdentityId',identity.id::text,'userId',local_user.id::text,
    'identityVersion',identity.version,
    'aliasKeyVersion',alias.key_version,
    'userAuthenticationRevision',local_user.authentication_revision,
    'providerRevision',provider.version,
    'loginPolicyRevision',login_policy.revision,
    'configurationRevision',runtime_policy.configuration_revision,
    'securityRevision',runtime_policy.security_revision,
    'planRevision',runtime_policy.plan_revision,
    'assurancePolicyRevision',runtime_policy.assurance_policy_revision,
    'platformFloor',jsonb_build_object(
      'id',platform_floor.id::text,
      'revision',platform_floor.revision,
      'level',platform_floor.level,
      'localRequired',platform_floor.local_required,
      'freshnessNanoseconds',platform_floor.freshness_nanoseconds,
      'enrollmentDeadline',to_jsonb(platform_floor.enrollment_deadline)
    ),
    'accountMode',login_policy.account_mode,
    'requiresLocalTotp',platform_floor.local_required,
    'selectedTotp',(
      SELECT jsonb_build_object(
        'id',factor.id::text,
        'userId',factor.user_id::text,
        'securityRevision',factor.security_revision,
        'active',factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL,
        'confirmedAt',to_jsonb(factor.confirmed_at)
      )
      FROM ONLY public.totp_credentials AS factor
      WHERE factor.user_id = local_user.id
        AND factor.confirmed_at IS NOT NULL AND factor.disabled_at IS NULL
      ORDER BY factor.id
      LIMIT 1
    )
  ) INTO result
  FROM ONLY public.platform_oidc_authentication_transactions AS transaction
  JOIN ONLY public.platform_auth_providers AS provider
    ON provider.id = transaction.platform_provider_id
   AND provider.enabled AND provider.archived_at IS NULL
  JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
    ON runtime_policy.provider_id = provider.id
   AND runtime_policy.provider_kind = 'oidc'
   AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
  JOIN ONLY public.platform_oidc_login_policies AS login_policy
    ON login_policy.provider_id = provider.id
   AND login_policy.enabled AND login_policy.account_mode = 'existing_identity'
  JOIN ONLY public.mfa_policy_revisions AS platform_floor
    ON platform_floor.id = transaction.platform_floor_policy_id
   AND platform_floor.revision = transaction.platform_floor_policy_revision
   AND platform_floor.scope = 'platform_floor'
   AND platform_floor.tenant_id IS NULL
   AND platform_floor.retired_at IS NULL
  JOIN ONLY public.platform_federated_external_identities AS identity
    ON identity.id = external_identity_id
   AND identity.platform_provider_id = provider.id
   AND identity.user_id = user_id AND identity.retired_at IS NULL
  JOIN ONLY public.platform_federated_external_identity_aliases AS alias
    ON alias.platform_provider_id = provider.id
   AND alias.external_identity_id = identity.id
   AND alias.key_version = alias_key_version AND alias.retired_at IS NULL
  JOIN ONLY public.users AS local_user
    ON local_user.id = identity.user_id AND local_user.active
  WHERE transaction.transaction_id = transaction_id
    AND transaction.state = 'claimed'
    AND transaction.claim_attempt_id = claim_attempt_id
    AND transaction.expires_at > observed_at
    AND transaction.provider_revision = provider.version
    AND transaction.login_policy_revision = login_policy.revision
    AND transaction.configuration_revision = runtime_policy.configuration_revision
    AND transaction.security_revision = runtime_policy.security_revision
    AND transaction.plan_revision = runtime_policy.plan_revision
    AND transaction.assurance_policy_revision = runtime_policy.assurance_policy_revision
    AND transaction.platform_floor_policy_id = platform_floor.id
    AND transaction.platform_floor_policy_revision = platform_floor.revision
    AND identity.version = (p_lookup ->> 'identityVersion')::bigint
    AND local_user.authentication_revision =
      (p_lookup ->> 'userAuthenticationRevision')::bigint;
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC planning lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.guard_platform_oidc_transaction_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF current_setting('app.platform_oidc_runtime_write_v1', true) <> 'on' THEN
    RAISE EXCEPTION 'direct platform OIDC transaction requires a protected ABI'
      USING ERRCODE = '42501';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'direct platform OIDC transactions are archival'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'INSERT' THEN
    IF NEW.state <> 'pending' OR NEW.version <> 1
       OR NEW.code_challenge_method <> 'S256'
       OR NEW.authorization_code_digest IS NOT NULL THEN
      RAISE EXCEPTION 'direct platform OIDC transaction create is invalid'
        USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
      NEW.transaction_id, NEW.platform_provider_id, NEW.provider_kind,
      NEW.protocol, NEW.operation_run_id, NEW.operation_digest,
      NEW.receipt_digest, NEW.network_digest, NEW.account_digest,
      NEW.provider_digest, NEW.state_digest, NEW.browser_digest,
      NEW.browser_capability_digest,
      NEW.nonce_digest, NEW.code_challenge_method, NEW.provider_revision,
      NEW.login_policy_revision, NEW.configuration_revision,
      NEW.security_revision, NEW.plan_revision,
      NEW.assurance_policy_revision, NEW.platform_floor_policy_id,
      NEW.platform_floor_policy_revision, NEW.client_secret_revision,
      NEW.discovery_revision, NEW.discovery_digest, NEW.jwks_revision,
      NEW.jwks_digest, NEW.verifier_key_version, NEW.verifier_ciphertext,
      NEW.client_id, NEW.redirect_uri, NEW.post_logout_redirect_uri,
      NEW.scopes, NEW.allow_refresh_token, NEW.use_user_info,
      NEW.return_path, NEW.created_at, NEW.expires_at
    ) IS DISTINCT FROM ROW(
      OLD.transaction_id, OLD.platform_provider_id, OLD.provider_kind,
      OLD.protocol, OLD.operation_run_id, OLD.operation_digest,
      OLD.receipt_digest, OLD.network_digest, OLD.account_digest,
      OLD.provider_digest, OLD.state_digest, OLD.browser_digest,
      OLD.browser_capability_digest,
      OLD.nonce_digest, OLD.code_challenge_method, OLD.provider_revision,
      OLD.login_policy_revision, OLD.configuration_revision,
      OLD.security_revision, OLD.plan_revision,
      OLD.assurance_policy_revision, OLD.platform_floor_policy_id,
      OLD.platform_floor_policy_revision, OLD.client_secret_revision,
      OLD.discovery_revision, OLD.discovery_digest, OLD.jwks_revision,
      OLD.jwks_digest, OLD.verifier_key_version, OLD.verifier_ciphertext,
      OLD.client_id, OLD.redirect_uri, OLD.post_logout_redirect_uri,
      OLD.scopes, OLD.allow_refresh_token, OLD.use_user_info,
      OLD.return_path, OLD.created_at, OLD.expires_at
    ) OR NEW.version <> OLD.version + 1 OR OLD.state NOT IN ('pending','claimed')
      OR (OLD.state = 'pending' AND NEW.state = 'claimed' AND (
        NEW.claim_attempt_id IS NULL OR NEW.authorization_code_digest IS NULL
        OR NEW.claimed_at IS NULL OR NEW.completed_at IS NOT NULL
      ))
      OR (NEW.state IN ('completed','failed','expired')
        AND NEW.completed_at IS NULL) THEN
    RAISE EXCEPTION 'direct platform OIDC transaction transition is invalid'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_oidc_authentication_transactions_guard_v1
BEFORE INSERT OR UPDATE OR DELETE
ON public.platform_oidc_authentication_transactions
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_transaction_v1();
--> statement-breakpoint

CREATE TRIGGER platform_oidc_authentication_applications_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_oidc_authentication_applications
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER platform_post_primary_continuations_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_post_primary_continuations
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER platform_post_primary_continuation_evidence_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_post_primary_continuation_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER platform_post_primary_continuation_policy_pins_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_post_primary_continuation_policy_pins
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER platform_post_primary_totp_challenges_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_post_primary_totp_challenges
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER auth_session_platform_oidc_states_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_oidc_states
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER auth_session_platform_oidc_provenance_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_oidc_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER auth_session_platform_oidc_evidence_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_oidc_evidence
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER auth_session_platform_oidc_policy_pins_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.auth_session_platform_oidc_policy_pins
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER platform_oidc_session_revalidation_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_oidc_session_revalidation_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
CREATE TRIGGER platform_oidc_tenant_switch_commands_guard_v1
BEFORE INSERT OR UPDATE OR DELETE ON public.platform_oidc_tenant_switch_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_platform_oidc_runtime_write_v1();
--> statement-breakpoint

CREATE FUNCTION app.assert_platform_oidc_direct_session_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  checked_session_id uuid;
BEGIN
  IF TG_TABLE_NAME = 'auth_sessions' THEN
    checked_session_id := coalesce(NEW.id, OLD.id);
  ELSE
    checked_session_id := coalesce(NEW.session_id, OLD.session_id);
  END IF;
  IF EXISTS (
    SELECT 1 FROM ONLY public.auth_session_platform_oidc_states AS state
    WHERE state.session_id = checked_session_id
  ) OR EXISTS (
    SELECT 1 FROM ONLY public.auth_session_platform_oidc_provenance AS provenance
    WHERE provenance.session_id = checked_session_id
  ) THEN
    IF NOT EXISTS (
      SELECT 1
      FROM ONLY public.auth_sessions AS session
      JOIN ONLY public.auth_session_platform_oidc_states AS state
        ON state.session_id = session.id AND state.user_id = session.user_id
      JOIN ONLY public.auth_session_platform_oidc_provenance AS provenance
        ON provenance.session_id = state.session_id
       AND provenance.user_id = state.user_id
       AND provenance.primary_kind = state.primary_kind
      WHERE session.id = checked_session_id
        AND session.active_tenant_id IS NULL
        AND session.authentication_method = 'oidc'
        AND state.audience = 'api'
        AND NOT state.recovery_restricted
        AND state.primary_kind = 'platform_provider'
        AND NOT EXISTS (
          SELECT 1 FROM ONLY public.auth_session_mfa_states AS tenant_state
          WHERE tenant_state.session_id = session.id
        )
        AND NOT EXISTS (
          SELECT 1 FROM ONLY public.auth_session_federated_provenance AS tenant_provenance
          WHERE tenant_provenance.session_id = session.id
        )
        AND NOT EXISTS (
          SELECT 1
          FROM ONLY public.auth_session_tenant_platform_federated_provenance
            AS tenant_platform_provenance
          WHERE tenant_platform_provenance.session_id = session.id
        )
    ) THEN
      RAISE EXCEPTION 'direct platform OIDC session provenance is incomplete'
        USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NULL;
END;
$function$;
CREATE CONSTRAINT TRIGGER auth_session_platform_oidc_states_assert_v1
AFTER INSERT OR UPDATE OR DELETE ON public.auth_session_platform_oidc_states
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.assert_platform_oidc_direct_session_v1();
CREATE CONSTRAINT TRIGGER auth_session_platform_oidc_provenance_assert_v1
AFTER INSERT OR UPDATE OR DELETE ON public.auth_session_platform_oidc_provenance
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.assert_platform_oidc_direct_session_v1();
CREATE CONSTRAINT TRIGGER auth_sessions_platform_oidc_direct_assert_v1
AFTER INSERT OR UPDATE OR DELETE ON public.auth_sessions
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.assert_platform_oidc_direct_session_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_json_v1(
  p_value jsonb,
  p_allowed text[],
  p_required text[],
  p_maximum_size integer
)
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_value IS NULL OR jsonb_typeof(p_value) <> 'object'
     OR pg_column_size(p_value) NOT BETWEEN 2 AND p_maximum_size
     OR EXISTS (
       SELECT 1 FROM jsonb_object_keys(p_value) AS key(name)
       WHERE NOT key.name = ANY(p_allowed)
     ) OR EXISTS (
       SELECT 1 FROM unnest(p_required) AS required(name)
       WHERE NOT p_value ? required.name
     ) THEN
    RAISE EXCEPTION 'invalid direct platform OIDC JSON envelope'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_projection_v1(
  p_transaction public.platform_oidc_authentication_transactions
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_strip_nulls(jsonb_build_object(
    'id', replace(encode(p_transaction.transaction_id, 'base64'), E'\n', ''),
    'stateDigest', replace(encode(p_transaction.state_digest, 'base64'), E'\n', ''),
    'browserDigest', replace(encode(p_transaction.browser_digest, 'base64'), E'\n', ''),
    'nonceDigest', replace(encode(p_transaction.nonce_digest, 'base64'), E'\n', ''),
    'authorizationCodeDigest', CASE WHEN p_transaction.authorization_code_digest IS NULL
      THEN NULL ELSE replace(encode(p_transaction.authorization_code_digest, 'base64'), E'\n', '') END,
    'codeChallengeMethod', p_transaction.code_challenge_method,
    'verifierKeyVersion', p_transaction.verifier_key_version,
    'verifierCiphertext', replace(encode(p_transaction.verifier_ciphertext, 'base64'), E'\n', ''),
    'pins', jsonb_build_object(
      'provider', jsonb_build_object(
        'scope','platform','providerId',p_transaction.platform_provider_id::text
      ),
      'providerRevision',p_transaction.provider_revision,
      'loginPolicyRevision',p_transaction.login_policy_revision,
      'configurationRevision',p_transaction.configuration_revision,
      'securityRevision',p_transaction.security_revision,
      'planRevision',p_transaction.plan_revision,
      'assurancePolicyRevision',p_transaction.assurance_policy_revision,
      'platformFloorPolicyId',p_transaction.platform_floor_policy_id::text,
      'platformFloorPolicyRevision',p_transaction.platform_floor_policy_revision,
      'clientSecretRevision',p_transaction.client_secret_revision,
      'discoveryRevision',p_transaction.discovery_revision,
      'discoveryDigest',replace(encode(p_transaction.discovery_digest,'base64'),E'\n',''),
      'jwksRevision',p_transaction.jwks_revision,
      'jwksDigest',replace(encode(p_transaction.jwks_digest,'base64'),E'\n','')
    ),
    'clientId',p_transaction.client_id,
    'redirectUri',p_transaction.redirect_uri,
    'postLogoutRedirectUri',p_transaction.post_logout_redirect_uri,
    'returnPath',p_transaction.return_path,
    'scopes',to_jsonb(p_transaction.scopes),
    'allowRefreshToken',p_transaction.allow_refresh_token,
    'useUserInfo',p_transaction.use_user_info,
    'state',p_transaction.state,'version',p_transaction.version,
    'claimAttemptId',CASE WHEN p_transaction.claim_attempt_id IS NULL THEN NULL
      ELSE replace(encode(p_transaction.claim_attempt_id,'base64'),E'\n','') END,
    'createdAt',to_jsonb(p_transaction.created_at),
    'expiresAt',to_jsonb(p_transaction.expires_at),
    'claimedAt',to_jsonb(p_transaction.claimed_at),
    'completedAt',to_jsonb(p_transaction.completed_at),
    'failureReason',p_transaction.failure_reason
  ));
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_configuration_v1(
  p_provider_id uuid,
  p_expected_pins jsonb DEFAULT NULL
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH live AS (
    SELECT provider.id AS provider_id, provider.version AS provider_revision,
      runtime_policy.configuration_revision,
      runtime_policy.security_revision, runtime_policy.plan_revision,
      runtime_policy.assurance_policy_revision,
      login_policy.revision AS login_policy_revision,
      login_policy.account_mode,
      platform_floor.id AS platform_floor_policy_id,
      platform_floor.revision AS platform_floor_policy_revision,
      platform_floor.level AS platform_floor_level,
      platform_floor.local_required AS platform_floor_local_required,
      platform_floor.freshness_nanoseconds AS platform_floor_freshness_nanoseconds,
      platform_floor.enrollment_deadline AS platform_floor_enrollment_deadline,
      configuration.issuer, configuration.client_id,
      configuration.redirect_uri, configuration.post_logout_redirect_uri,
      configuration.extra_scopes, configuration.allow_refresh_token,
      configuration.use_user_info, configuration.client_secret_revision,
      configuration.discovery_revision,
      discovery.document AS discovery_document,
      discovery.document_digest AS discovery_digest,
      discovery.retrieved_at AS discovery_retrieved_at,
      discovery.fresh_until AS discovery_fresh_until,
      discovery.cacheable AS discovery_cacheable,
      discovery.must_revalidate AS discovery_must_revalidate,
      discovery.client_authentication, discovery.signing_algorithms,
      configuration.jwks_revision, jwks.document AS jwks_document,
      jwks.document_digest AS jwks_digest,
      jwks.retrieved_at AS jwks_retrieved_at,
      jwks.fresh_until AS jwks_fresh_until,
      jwks.cacheable AS jwks_cacheable,
      jwks.must_revalidate AS jwks_must_revalidate
    FROM ONLY public.platform_auth_providers AS provider
    JOIN ONLY public.platform_federated_provider_policies AS runtime_policy
      ON runtime_policy.provider_id = provider.id
     AND runtime_policy.provider_kind = 'oidc'
     AND runtime_policy.enabled AND NOT runtime_policy.platform_login_enabled
    JOIN ONLY public.platform_oidc_login_policies AS login_policy
      ON login_policy.provider_id = provider.id
     AND login_policy.provider_kind = 'oidc'
     AND login_policy.enabled
     AND login_policy.account_mode = 'existing_identity'
    JOIN ONLY public.mfa_policy_revisions AS platform_floor
      ON platform_floor.scope = 'platform_floor'
     AND platform_floor.tenant_id IS NULL
     AND platform_floor.retired_at IS NULL
    JOIN ONLY public.platform_oidc_provider_configurations AS configuration
      ON configuration.provider_id = provider.id
     AND configuration.version = runtime_policy.configuration_revision
     AND NOT configuration.allow_refresh_token
     AND configuration.redirect_uri ~
       '^https://[^/?#@]+/api/v1/auth/platform/oidc/callback$'
    JOIN ONLY public.platform_oidc_client_secrets AS secret
      ON secret.provider_id = configuration.provider_id
     AND secret.revision = configuration.client_secret_revision
     AND secret.retired_at IS NULL
    JOIN ONLY public.identity_keyring_versions AS secret_key
      ON secret_key.key_version = secret.key_version
     AND secret_key.retired_at IS NULL
    JOIN ONLY public.platform_oidc_discovery_snapshots AS discovery
      ON discovery.provider_id = configuration.provider_id
     AND discovery.revision = configuration.discovery_revision
     AND discovery.issuer = configuration.issuer
     AND discovery.cacheable AND discovery.fresh_until > statement_timestamp()
    JOIN ONLY public.platform_oidc_jwks_snapshots AS jwks
      ON jwks.provider_id = configuration.provider_id
     AND jwks.revision = configuration.jwks_revision
     AND jwks.cacheable AND jwks.fresh_until > statement_timestamp()
    WHERE provider.id = p_provider_id AND provider.kind = 'oidc'
      AND provider.enabled AND provider.archived_at IS NULL
      AND (
        SELECT count(*)
        FROM ONLY public.mfa_policy_revisions AS counted_floor
        WHERE counted_floor.scope = 'platform_floor'
          AND counted_floor.tenant_id IS NULL
          AND counted_floor.retired_at IS NULL
      ) = 1
  ), projected AS (
    SELECT live.*, jsonb_build_object(
      'provider',jsonb_build_object(
        'scope','platform','providerId',live.provider_id::text
      ),
      'providerRevision',live.provider_revision,
      'loginPolicyRevision',live.login_policy_revision,
      'configurationRevision',live.configuration_revision,
      'securityRevision',live.security_revision,
      'planRevision',live.plan_revision,
      'assurancePolicyRevision',live.assurance_policy_revision,
      'platformFloorPolicyId',live.platform_floor_policy_id::text,
      'platformFloorPolicyRevision',live.platform_floor_policy_revision,
      'clientSecretRevision',live.client_secret_revision,
      'discoveryRevision',live.discovery_revision,
      'discoveryDigest',replace(encode(live.discovery_digest,'base64'),E'\n',''),
      'jwksRevision',live.jwks_revision,
      'jwksDigest',replace(encode(live.jwks_digest,'base64'),E'\n','')
    ) AS pins
    FROM live
  )
  SELECT jsonb_build_object(
    'authorization',jsonb_build_object(
      'provider',projected.pins -> 'provider',
      'providerRevision',projected.provider_revision,
      'loginPolicyRevision',projected.login_policy_revision,
      'configurationRevision',projected.configuration_revision,
      'securityRevision',projected.security_revision,
      'assurancePolicyRevision',projected.assurance_policy_revision,
      'platformFloorPolicyId',projected.platform_floor_policy_id::text,
      'platformFloorPolicyRevision',projected.platform_floor_policy_revision,
      'clientSecretRevision',projected.client_secret_revision,
      'clientId',projected.client_id,
      'redirectUri',projected.redirect_uri,
      'postLogoutRedirectUri',projected.post_logout_redirect_uri,
      'extraScopes',to_jsonb(projected.extra_scopes),
      'allowRefreshToken',projected.allow_refresh_token,
      'useUserInfo',projected.use_user_info
    ),
    'issuer',projected.issuer,
    'discoveryRevision',projected.discovery_revision,
    'discoveryDocument',replace(encode(projected.discovery_document,'base64'),E'\n',''),
    'discoveryDigest',replace(encode(projected.discovery_digest,'base64'),E'\n',''),
    'discoveryCache',jsonb_build_object(
      'retrievedAt',to_jsonb(projected.discovery_retrieved_at),
      'freshUntil',to_jsonb(projected.discovery_fresh_until),
      'cacheable',projected.discovery_cacheable,
      'mustRevalidate',projected.discovery_must_revalidate
    ),
    'discoveryPolicy',jsonb_build_object(
      'clientAuthentication',projected.client_authentication,
      'signingAlgorithms',to_jsonb(projected.signing_algorithms)
    ),
    'jwksDocument',replace(encode(projected.jwks_document,'base64'),E'\n',''),
    'jwksDigest',replace(encode(projected.jwks_digest,'base64'),E'\n',''),
    'jwksRevision',projected.jwks_revision,
    'jwksCache',jsonb_build_object(
      'retrievedAt',to_jsonb(projected.jwks_retrieved_at),
      'freshUntil',to_jsonb(projected.jwks_fresh_until),
      'cacheable',projected.jwks_cacheable,
      'mustRevalidate',projected.jwks_must_revalidate
    ),
    'idTokenClaims',app.private_platform_oidc_claim_policy_v1(
      projected.provider_id,'id_token'
    ),
    'userInfoClaims',app.private_platform_oidc_claim_policy_v1(
      projected.provider_id,'userinfo'
    ),
    'pins',projected.pins,
    'platformFloor',jsonb_build_object(
      'id',projected.platform_floor_policy_id::text,
      'revision',projected.platform_floor_policy_revision,
      'level',projected.platform_floor_level,
      'localRequired',projected.platform_floor_local_required,
      'freshnessNanoseconds',projected.platform_floor_freshness_nanoseconds,
      'enrollmentDeadline',to_jsonb(projected.platform_floor_enrollment_deadline)
    ),
    'runtimeAdmissionPolicy',jsonb_build_object(
      'accountMode',projected.account_mode
    )
  )
  FROM projected
  WHERE p_expected_pins IS NULL OR projected.pins = p_expected_pins;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.begin_platform_oidc_authentication_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  login_key text;
  provider_id uuid;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,ARRAY['loginKey'],ARRAY['loginKey'],4096
  );
  login_key := p_lookup ->> 'loginKey';
  IF login_key IS NULL OR login_key <> lower(btrim(login_key))
     OR login_key !~ '^[a-z][a-z0-9_-]{2,63}$' THEN
    RAISE EXCEPTION 'direct platform OIDC login key is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT provider.id INTO STRICT provider_id
  FROM ONLY public.platform_auth_providers AS provider
  WHERE provider.key = login_key AND provider.kind = 'oidc';
  RETURN app.private_platform_oidc_direct_configuration_v1(provider_id,NULL);
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC begin lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.resolve_platform_oidc_authentication_configuration_v1(
  p_lookup jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  transaction_id bytea;
  browser_capability_digest bytea;
  expected_version bigint;
  pins jsonb;
  provider jsonb;
  provider_id uuid;
  transaction_record public.platform_oidc_authentication_transactions%ROWTYPE;
  configuration jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_lookup,
    ARRAY['transactionId','expectedVersion','pins','browserCapabilityDigest'],
    ARRAY['transactionId','expectedVersion','pins','browserCapabilityDigest'],
    65536
  );
  pins := p_lookup -> 'pins';
  PERFORM app.private_platform_oidc_direct_json_v1(
    pins,
    ARRAY['provider','providerRevision','loginPolicyRevision',
      'configurationRevision','securityRevision','planRevision',
      'assurancePolicyRevision','platformFloorPolicyId',
      'platformFloorPolicyRevision','clientSecretRevision','discoveryRevision',
      'discoveryDigest','jwksRevision','jwksDigest'],
    ARRAY['provider','providerRevision','loginPolicyRevision',
      'configurationRevision','securityRevision','planRevision',
      'assurancePolicyRevision','platformFloorPolicyId',
      'platformFloorPolicyRevision','clientSecretRevision','discoveryRevision',
      'discoveryDigest','jwksRevision','jwksDigest'],32768
  );
  provider := pins -> 'provider';
  PERFORM app.private_platform_oidc_direct_json_v1(
    provider,ARRAY['scope','providerId'],ARRAY['scope','providerId'],4096
  );
  IF provider ->> 'scope' <> 'platform' THEN
    RAISE EXCEPTION 'direct platform OIDC callback provider scope is invalid'
      USING ERRCODE = '22023';
  END IF;
  transaction_id := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'transactionId',32,32
  );
  browser_capability_digest := app.private_mfa_decode_base64_v1(
    p_lookup ->> 'browserCapabilityDigest',32,32
  );
  expected_version := (p_lookup ->> 'expectedVersion')::bigint;
  provider_id := app.private_mfa_require_uuidv7_v1(provider ->> 'providerId');
  IF expected_version <> 2
     OR encode(transaction_id,'hex') = repeat('00',32)
     OR encode(browser_capability_digest,'hex') = repeat('00',32) THEN
    RAISE EXCEPTION 'invalid direct platform OIDC callback configuration lookup'
      USING ERRCODE = '22023';
  END IF;
  SELECT transaction.* INTO STRICT transaction_record
  FROM ONLY public.platform_oidc_authentication_transactions AS transaction
  WHERE transaction.transaction_id = transaction_id
    AND transaction.platform_provider_id = provider_id
    AND transaction.version = expected_version
    AND transaction.state = 'claimed'
    AND transaction.claim_attempt_id IS NOT NULL
    AND encode(transaction.claim_attempt_id,'hex') <> repeat('00',32)
    AND transaction.authorization_code_digest IS NOT NULL
    AND encode(transaction.authorization_code_digest,'hex') <> repeat('00',32)
    AND transaction.browser_capability_digest = browser_capability_digest
    AND transaction.return_path ~ '^/[^[:cntrl:]]*$'
    AND left(transaction.return_path,2) <> '//'
    AND transaction.expires_at > statement_timestamp();
  IF app.private_platform_oidc_direct_projection_v1(transaction_record)
       -> 'pins' IS DISTINCT FROM pins THEN
    RETURN NULL;
  END IF;
  configuration := app.private_platform_oidc_direct_configuration_v1(
    provider_id,pins
  );
  IF configuration IS NULL THEN
    RETURN NULL;
  END IF;
  RETURN jsonb_build_object(
    'pins',pins,
    'returnPath',transaction_record.return_path,
    'configuration',configuration
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC callback configuration lookup'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_platform_oidc_authentication_transaction_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  begin_request jsonb;
  current_request jsonb;
  pins jsonb;
  provider jsonb;
  live_record jsonb;
  transaction_id bytea;
  operation_run_id uuid;
  provider_id uuid;
  operation_digest bytea;
  receipt_digest bytea;
  network_digest bytea;
  account_digest bytea;
  provider_digest bytea;
  state_digest bytea;
  browser_digest bytea;
  browser_capability_digest bytea;
  nonce_digest bytea;
  previous_browser_digest bytea;
  verifier_ciphertext bytea;
  discovery_digest bytea;
  jwks_digest bytea;
  verifier_key_version integer;
  scopes text[];
  created_at timestamptz;
  expires_at timestamptz;
  admission record;
  existing public.platform_oidc_authentication_transactions%ROWTYPE;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,
    ARRAY['begin','current','previousBrowserDigest','browserCapabilityDigest',
      'audit'],
    ARRAY['begin','current','browserCapabilityDigest','audit'],139264
  );
  begin_request := p_request -> 'begin';
  current_request := p_request -> 'current';
  PERFORM app.private_platform_oidc_direct_json_v1(
    begin_request,
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],
    ARRAY['operationRunId','receiptDigest','networkDigest','accountDigest','providerDigest'],8192
  );
  PERFORM app.private_platform_oidc_direct_json_v1(
    current_request,
    ARRAY['id','stateDigest','browserDigest','nonceDigest','codeChallengeMethod',
      'verifierKeyVersion','verifierCiphertext','pins','clientId','redirectUri',
      'postLogoutRedirectUri','returnPath','scopes','allowRefreshToken',
      'useUserInfo','createdAt','expiresAt','state','version'],
    ARRAY['id','stateDigest','browserDigest','nonceDigest','codeChallengeMethod',
      'verifierKeyVersion','verifierCiphertext','pins','clientId','redirectUri',
      'postLogoutRedirectUri','returnPath','scopes','allowRefreshToken',
      'useUserInfo','createdAt','expiresAt','state','version'],65536
  );
  pins := current_request -> 'pins';
  PERFORM app.private_platform_oidc_direct_json_v1(
    pins,
    ARRAY['provider','providerRevision','loginPolicyRevision',
      'configurationRevision','securityRevision','planRevision',
      'assurancePolicyRevision','platformFloorPolicyId',
      'platformFloorPolicyRevision','clientSecretRevision','discoveryRevision',
      'discoveryDigest','jwksRevision','jwksDigest'],
    ARRAY['provider','providerRevision','loginPolicyRevision',
      'configurationRevision','securityRevision','planRevision',
      'assurancePolicyRevision','platformFloorPolicyId',
      'platformFloorPolicyRevision','clientSecretRevision','discoveryRevision',
      'discoveryDigest','jwksRevision','jwksDigest'],32768
  );
  provider := pins -> 'provider';
  PERFORM app.private_platform_oidc_direct_json_v1(
    provider,ARRAY['scope','providerId'],ARRAY['scope','providerId'],4096
  );
  IF provider ->> 'scope' <> 'platform'
     OR current_request ->> 'codeChallengeMethod' <> 'S256'
     OR current_request ->> 'state' <> 'pending'
     OR (current_request ->> 'version')::bigint <> 1
     OR jsonb_typeof(current_request -> 'scopes') <> 'array'
     OR jsonb_typeof(current_request -> 'allowRefreshToken') <> 'boolean'
     OR jsonb_typeof(current_request -> 'useUserInfo') <> 'boolean' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC transaction request'
      USING ERRCODE = '22023';
  END IF;
  operation_run_id := app.private_mfa_require_uuidv7_v1(
    begin_request ->> 'operationRunId'
  );
  provider_id := app.private_mfa_require_uuidv7_v1(provider ->> 'providerId');
  transaction_id := app.private_mfa_decode_base64_v1(
    current_request ->> 'id',32,32
  );
  receipt_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'receiptDigest',32,32
  );
  network_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'networkDigest',32,32
  );
  account_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'accountDigest',32,32
  );
  provider_digest := app.private_mfa_decode_base64_v1(
    begin_request ->> 'providerDigest',32,32
  );
  state_digest := app.private_mfa_decode_base64_v1(
    current_request ->> 'stateDigest',32,32
  );
  browser_digest := app.private_mfa_decode_base64_v1(
    current_request ->> 'browserDigest',32,32
  );
  browser_capability_digest := app.private_mfa_decode_base64_v1(
    p_request ->> 'browserCapabilityDigest',32,32
  );
  nonce_digest := app.private_mfa_decode_base64_v1(
    current_request ->> 'nonceDigest',32,32
  );
  verifier_ciphertext := app.private_mfa_decode_base64_v1(
    current_request ->> 'verifierCiphertext',16,4096
  );
  discovery_digest := app.private_mfa_decode_base64_v1(
    pins ->> 'discoveryDigest',32,32
  );
  jwks_digest := app.private_mfa_decode_base64_v1(
    pins ->> 'jwksDigest',32,32
  );
  IF p_request ? 'previousBrowserDigest' THEN
    previous_browser_digest := app.private_mfa_decode_base64_v1(
      p_request ->> 'previousBrowserDigest',32,32
    );
  END IF;
  verifier_key_version := (current_request ->> 'verifierKeyVersion')::integer;
  SELECT array_agg(item.value #>> '{}' ORDER BY item.ordinality)
    INTO scopes
  FROM jsonb_array_elements(current_request -> 'scopes') WITH ORDINALITY
    AS item(value,ordinality);
  created_at := (current_request ->> 'createdAt')::timestamptz;
  expires_at := (current_request ->> 'expiresAt')::timestamptz;
  IF encode(transaction_id,'hex') = repeat('00',32)
     OR encode(receipt_digest,'hex') = repeat('00',32)
     OR encode(network_digest,'hex') = repeat('00',32)
     OR encode(account_digest,'hex') = repeat('00',32)
     OR encode(provider_digest,'hex') = repeat('00',32)
     OR encode(state_digest,'hex') = repeat('00',32)
     OR encode(browser_digest,'hex') = repeat('00',32)
     OR encode(browser_capability_digest,'hex') = repeat('00',32)
     OR encode(nonce_digest,'hex') = repeat('00',32)
     OR receipt_digest = ANY(ARRAY[
       network_digest,account_digest,provider_digest,state_digest,
       browser_digest,browser_capability_digest,nonce_digest
     ]::bytea[])
     OR network_digest = ANY(ARRAY[
       account_digest,provider_digest,state_digest,browser_digest,
       browser_capability_digest,nonce_digest
     ]::bytea[])
     OR account_digest = ANY(ARRAY[
       provider_digest,state_digest,browser_digest,
       browser_capability_digest,nonce_digest
     ]::bytea[])
     OR provider_digest = ANY(ARRAY[
       state_digest,browser_digest,browser_capability_digest,nonce_digest
     ]::bytea[])
     OR state_digest = ANY(ARRAY[
       browser_digest,browser_capability_digest,nonce_digest
     ]::bytea[])
     OR browser_digest = ANY(ARRAY[browser_capability_digest,nonce_digest]::bytea[])
     OR browser_capability_digest = nonce_digest
     OR previous_browser_digest = ANY(
       ARRAY[browser_digest,browser_capability_digest]::bytea[]
     )
     OR encode(previous_browser_digest,'hex') = repeat('00',32)
     OR verifier_key_version NOT BETWEEN 1 AND 32767
     OR created_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                              AND statement_timestamp() + interval '30 seconds'
     OR expires_at - created_at NOT BETWEEN interval '1 minute' AND interval '15 minutes'
     OR cardinality(scopes) NOT BETWEEN 1 AND 64 OR scopes[1] <> 'openid'
     OR cardinality(scopes) <> (
       SELECT count(DISTINCT value) FROM unnest(scopes) AS scope(value)
     ) OR current_request ->> 'returnPath' !~ '^/[^[:cntrl:]]*$'
     OR left(current_request ->> 'returnPath',2) = '//' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC transaction request'
      USING ERRCODE = '22023';
  END IF;
  operation_digest := sha256(convert_to(p_request::text,'UTF8'));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-oidc-direct:operation:' || operation_run_id::text,3900178
  ));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-oidc-direct:receipt:' || encode(receipt_digest,'hex'),3900178
  ));
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'platform-oidc-direct:state:' || encode(state_digest,'hex'),3900178
  ));
  IF previous_browser_digest IS NOT NULL THEN
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'platform-oidc-direct:browser:' || encode(previous_browser_digest,'hex'),3900178
    ));
  END IF;
  SELECT transaction.* INTO existing
  FROM ONLY public.platform_oidc_authentication_transactions AS transaction
  WHERE transaction.operation_run_id = operation_run_id
     OR transaction.receipt_digest = receipt_digest
     OR transaction.state_digest = state_digest
     OR transaction.transaction_id = transaction_id
  FOR UPDATE;
  IF FOUND THEN
    IF existing.operation_run_id <> operation_run_id
       OR existing.operation_digest <> operation_digest
       OR existing.transaction_id <> transaction_id
       OR existing.receipt_digest <> receipt_digest
       OR existing.state_digest <> state_digest THEN
      RAISE EXCEPTION 'direct platform OIDC transaction replay collision'
        USING ERRCODE = '23505';
    END IF;
    RETURN app.private_platform_oidc_direct_projection_v1(existing);
  END IF;
  SELECT * INTO STRICT admission
  FROM app.admit_auth_attempts(
    ARRAY[
      'platform_oidc_network','platform_oidc_account','platform_oidc_provider'
    ]::public.auth_rate_limit_scope[],
    ARRAY[network_digest,account_digest,provider_digest]::bytea[],
    ARRAY[60,900,60]::integer[],
    ARRAY[30,10,100]::integer[],
    ARRAY[300,900,300]::integer[]
  );
  IF NOT admission.admitted THEN
    RETURN NULL;
  END IF;
  live_record := app.private_platform_oidc_direct_configuration_v1(
    provider_id,pins
  );
  IF live_record IS NULL
     OR live_record #>> '{authorization,clientId}'
        IS DISTINCT FROM current_request ->> 'clientId'
     OR live_record #>> '{authorization,redirectUri}'
        IS DISTINCT FROM current_request ->> 'redirectUri'
     OR live_record #>> '{authorization,postLogoutRedirectUri}'
        IS DISTINCT FROM current_request ->> 'postLogoutRedirectUri'
     OR to_jsonb(ARRAY['openid']::text[] || ARRAY(
       SELECT value #>> '{}'
       FROM jsonb_array_elements(live_record #> '{authorization,extraScopes}')
         WITH ORDINALITY AS scope(value,ordinality)
       ORDER BY ordinality
     )) IS DISTINCT FROM current_request -> 'scopes'
     OR (live_record #>> '{authorization,allowRefreshToken}')::boolean
        IS DISTINCT FROM (current_request ->> 'allowRefreshToken')::boolean
     OR (live_record #>> '{authorization,useUserInfo}')::boolean
        IS DISTINCT FROM (current_request ->> 'useUserInfo')::boolean
     OR NOT EXISTS (
       SELECT 1 FROM ONLY public.identity_keyring_versions AS keyring
       WHERE keyring.key_version = verifier_key_version
         AND keyring.is_active AND keyring.retired_at IS NULL
     ) THEN
    RETURN NULL;
  END IF;
  IF previous_browser_digest IS NOT NULL THEN
    PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
    UPDATE ONLY public.platform_oidc_authentication_transactions AS previous
    SET state = 'failed',version = previous.version + 1,
        completed_at = created_at,failure_reason = 'superseded'
    WHERE previous.browser_digest = previous_browser_digest
      AND previous.state IN ('pending','claimed');
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  INSERT INTO public.platform_oidc_authentication_transactions (
    transaction_id,platform_provider_id,provider_kind,protocol,
    operation_run_id,operation_digest,receipt_digest,network_digest,
    account_digest,provider_digest,state_digest,browser_digest,
    browser_capability_digest,nonce_digest,
    code_challenge_method,provider_revision,login_policy_revision,
    configuration_revision,security_revision,plan_revision,
    assurance_policy_revision,platform_floor_policy_id,
    platform_floor_policy_revision,client_secret_revision,discovery_revision,
    discovery_digest,jwks_revision,jwks_digest,verifier_key_version,
    verifier_ciphertext,client_id,redirect_uri,post_logout_redirect_uri,
    scopes,allow_refresh_token,use_user_info,return_path,state,version,
    created_at,expires_at
  ) VALUES (
    transaction_id,provider_id,'oidc','oidc',operation_run_id,
    operation_digest,receipt_digest,network_digest,account_digest,
    provider_digest,state_digest,browser_digest,browser_capability_digest,
    nonce_digest,'S256',
    (pins ->> 'providerRevision')::bigint,
    (pins ->> 'loginPolicyRevision')::bigint,
    (pins ->> 'configurationRevision')::bigint,
    (pins ->> 'securityRevision')::bigint,
    (pins ->> 'planRevision')::bigint,
    (pins ->> 'assurancePolicyRevision')::bigint,
    app.private_mfa_require_uuidv7_v1(pins ->> 'platformFloorPolicyId'),
    (pins ->> 'platformFloorPolicyRevision')::bigint,
    (pins ->> 'clientSecretRevision')::bigint,
    (pins ->> 'discoveryRevision')::bigint,discovery_digest,
    (pins ->> 'jwksRevision')::bigint,jwks_digest,verifier_key_version,
    verifier_ciphertext,current_request ->> 'clientId',
    current_request ->> 'redirectUri',
    current_request ->> 'postLogoutRedirectUri',scopes,
    (current_request ->> 'allowRefreshToken')::boolean,
    (current_request ->> 'useUserInfo')::boolean,
    current_request ->> 'returnPath','pending',1,created_at,expires_at
  ) RETURNING * INTO existing;
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.login.started',
    'platform_identity_provider',existing.platform_provider_id,
    'success',jsonb_build_object('transaction_version',existing.version)
  );
  RETURN app.private_platform_oidc_direct_projection_v1(existing);
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC transaction request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.cleanup_platform_oidc_authentication_runtime_v1(
  p_request jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  observed_at timestamptz;
  batch_size integer;
  transaction_count integer;
  continuation_count integer;
  challenge_count integer;
  audit_resource_id uuid;
  result jsonb;
BEGIN
  PERFORM app.private_platform_oidc_direct_json_v1(
    p_request,ARRAY['observedAt','batchSize','audit'],
    ARRAY['observedAt','batchSize','audit'],16384
  );
  observed_at := (p_request ->> 'observedAt')::timestamptz;
  batch_size := (p_request ->> 'batchSize')::integer;
  audit_resource_id := app.private_mfa_require_uuidv7_v1(
    p_request #>> '{audit,eventId}'
  );
  IF batch_size NOT BETWEEN 1 AND 1000
     OR observed_at NOT BETWEEN statement_timestamp() - interval '5 minutes'
                             AND statement_timestamp() + interval '30 seconds' THEN
    RAISE EXCEPTION 'invalid direct platform OIDC cleanup request'
      USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  WITH candidates AS (
    SELECT transaction.transaction_id
    FROM ONLY public.platform_oidc_authentication_transactions AS transaction
    WHERE transaction.state IN ('pending','claimed')
      AND transaction.expires_at <= observed_at
    ORDER BY transaction.expires_at,transaction.transaction_id
    LIMIT batch_size FOR UPDATE SKIP LOCKED
  ), expired AS (
    UPDATE ONLY public.platform_oidc_authentication_transactions AS transaction
    SET state = 'expired',version = transaction.version + 1,
        completed_at = observed_at,failure_reason = 'expired'
    FROM candidates
    WHERE transaction.transaction_id = candidates.transaction_id
      AND transaction.state IN ('pending','claimed')
    RETURNING 1
  ) SELECT count(*)::integer INTO transaction_count FROM expired;
  WITH candidates AS (
    SELECT challenge.id
    FROM ONLY public.platform_post_primary_totp_challenges AS challenge
    WHERE challenge.state = 'pending' AND challenge.expires_at <= observed_at
    ORDER BY challenge.expires_at,challenge.id
    LIMIT batch_size FOR UPDATE SKIP LOCKED
  ), expired AS (
    UPDATE ONLY public.platform_post_primary_totp_challenges AS challenge
    SET state = 'expired',version = challenge.version + 1,
        abandoned_at = observed_at
    FROM candidates
    WHERE challenge.id = candidates.id AND challenge.state = 'pending'
    RETURNING 1
  ) SELECT count(*)::integer INTO challenge_count FROM expired;
  WITH candidates AS (
    SELECT continuation.id
    FROM ONLY public.platform_post_primary_continuations AS continuation
    WHERE continuation.state = 'pending'
      AND continuation.expires_at <= observed_at
    ORDER BY continuation.expires_at,continuation.id
    LIMIT batch_size FOR UPDATE SKIP LOCKED
  ), expired AS (
    UPDATE ONLY public.platform_post_primary_continuations AS continuation
    SET state = 'expired',version = continuation.version + 1,
        revoked_at = observed_at,revoke_reason = 'expired'
    FROM candidates
    WHERE continuation.id = candidates.id AND continuation.state = 'pending'
    RETURNING 1
  ) SELECT count(*)::integer INTO continuation_count FROM expired;
  result := jsonb_build_object(
    'transactionsExpired',transaction_count,
    'continuationsExpired',continuation_count,
    'totpChallengesExpired',challenge_count,
    'observedAt',to_jsonb(observed_at)
  );
  PERFORM app.private_platform_oidc_direct_audit_v1(
    p_request -> 'audit','platform.oidc.runtime.cleaned',
    'platform_oidc_runtime',audit_resource_id,'success',result
  );
  RETURN result;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid direct platform OIDC cleanup request'
    USING ERRCODE = '22023';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.create_platform_oidc_auth_provider_v3(
  p_session_id uuid,
  p_command_id uuid,
  p_provider_id uuid,
  p_key text,
  p_display_name text,
  p_description text,
  p_configuration jsonb,
  p_tenant_redirect_uri text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  provider_id uuid,
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
  created record;
BEGIN
  SELECT result.provider_id,result.version,result.replayed,result.document
    INTO STRICT created
  FROM app.create_platform_oidc_auth_provider_v2(
    p_session_id,p_command_id,p_provider_id,p_key,p_display_name,
    p_description,p_configuration,p_tenant_redirect_uri,p_key_digest,
    p_request_digest,p_audit_event_id,p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,p_reason
  ) AS result;
  INSERT INTO public.platform_oidc_login_policies (
    provider_id,provider_kind,account_mode,enabled,revision,created_at,updated_at
  ) VALUES (
    created.provider_id,'oidc','disabled',false,1,
    transaction_timestamp(),transaction_timestamp()
  ) ON CONFLICT ON CONSTRAINT platform_oidc_login_policies_pkey DO NOTHING;
  IF NOT EXISTS (
    SELECT 1 FROM ONLY public.platform_oidc_login_policies AS policy
    WHERE policy.provider_id = created.provider_id
      AND policy.provider_kind = 'oidc'
      AND policy.account_mode = 'disabled' AND NOT policy.enabled
      AND policy.revision = 1
  ) THEN
    RAISE EXCEPTION 'direct platform OIDC login policy creation drifted'
      USING ERRCODE = '40001';
  END IF;
  RETURN QUERY SELECT created.provider_id,created.version,created.replayed,
    created.document;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.retire_platform_identity_account_v4(
  p_session_id uuid,
  p_provider_id uuid,
  p_account_id uuid,
  p_expected_version bigint,
  p_expected_user_version bigint,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_reason text
)
RETURNS TABLE (
  account_id uuid,
  version bigint,
  document jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target_user_id uuid;
  retired record;
  observed_at timestamptz := transaction_timestamp();
BEGIN
  SELECT identity.user_id INTO STRICT target_user_id
  FROM ONLY public.platform_federated_external_identities AS identity
  WHERE identity.platform_provider_id = p_provider_id
    AND identity.id = p_account_id
  FOR UPDATE;
  SELECT result.account_id,result.version,result.document INTO STRICT retired
  FROM app.retire_platform_identity_account_v3(
    p_session_id,p_provider_id,p_account_id,p_expected_version,
    p_expected_user_version,p_audit_event_id,p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,p_reason
  ) AS result;
  PERFORM set_config('app.platform_oidc_runtime_write_v1','on',true);
  UPDATE ONLY public.platform_post_primary_totp_challenges AS challenge
  SET state = 'abandoned',version = challenge.version + 1,
      abandoned_at = observed_at
  FROM ONLY public.platform_post_primary_continuations AS continuation
  WHERE challenge.continuation_id = continuation.id
    AND continuation.platform_provider_id = p_provider_id
    AND continuation.external_identity_id = p_account_id
    AND challenge.state = 'pending';
  UPDATE ONLY public.platform_post_primary_continuations AS continuation
  SET state = 'revoked',version = continuation.version + 1,
      revoked_at = observed_at,revoke_reason = 'identity_retired'
  WHERE continuation.platform_provider_id = p_provider_id
    AND continuation.external_identity_id = p_account_id
    AND continuation.state = 'pending';
  UPDATE ONLY public.tenant_post_primary_continuations AS continuation
  SET state = 'revoked',version = continuation.version + 1,
      revoked_at = observed_at,revoke_reason = 'identity_retired'
  FROM ONLY public.tenant_post_primary_platform_federated_provenance
    AS provenance
  WHERE provenance.tenant_id = continuation.tenant_id
    AND provenance.continuation_id = continuation.id
    AND provenance.platform_provider_id = p_provider_id
    AND provenance.external_identity_id = p_account_id
    AND continuation.state = 'pending';
  WITH affected_families AS (
    SELECT session.rotation_family_id
    FROM ONLY public.auth_sessions AS session
    JOIN ONLY public.auth_session_platform_oidc_provenance AS direct
      ON direct.session_id = session.id
    WHERE direct.platform_provider_id = p_provider_id
      AND direct.external_identity_id = p_account_id
      AND direct.user_id = target_user_id
    UNION
    SELECT session.rotation_family_id
    FROM ONLY public.auth_sessions AS session
    JOIN ONLY public.auth_session_tenant_platform_federated_provenance
      AS tenant_provenance ON tenant_provenance.session_id = session.id
    WHERE tenant_provenance.platform_provider_id = p_provider_id
      AND tenant_provenance.external_identity_id = p_account_id
      AND tenant_provenance.user_id = target_user_id
  )
  UPDATE ONLY public.auth_sessions AS session
  SET revoked_at = observed_at,revoke_reason = 'platform_identity_retired'
  WHERE session.user_id = target_user_id AND session.revoked_at IS NULL
    AND session.rotation_family_id IN (
      SELECT family.rotation_family_id FROM affected_families AS family
    );
  RETURN QUERY SELECT retired.account_id,retired.version,retired.document;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.guard_platform_oidc_login_policy_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_totp_credential_security_revision_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_oidc_runtime_write_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.guard_platform_oidc_transaction_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.assert_platform_oidc_direct_session_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_assurance_v1(
  uuid,timestamp with time zone
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_continuation_source_live_v1(
  public.platform_post_primary_continuations,timestamp with time zone
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_post_primary_totp_projection_v1(
  public.platform_post_primary_totp_challenges
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_authority_live_v1(
  uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,integer,bigint,
  uuid,bigint,uuid,bigint
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_create_direct_session_v1(
  jsonb,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,integer,
  bigint,uuid,bigint,uuid,bigint,text,timestamp with time zone,
  timestamp with time zone,uuid,bigint,timestamp with time zone,uuid
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_audit_v1(
  jsonb,text,text,uuid,public.audit_outcome,jsonb
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_json_v1(
  jsonb,text[],text[],integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_projection_v1(
  public.platform_oidc_authentication_transactions
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_oidc_direct_configuration_v1(uuid,jsonb)
  OWNER TO periapsis_migrator;

ALTER FUNCTION app.begin_platform_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_platform_oidc_authentication_configuration_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_platform_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_platform_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_platform_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.fail_platform_oidc_authentication_transaction_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_platform_oidc_client_secret_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_platform_oidc_trust_snapshot_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_platform_oidc_planning_state_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_platform_oidc_authentication_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.begin_platform_post_primary_totp_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_platform_post_primary_totp_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.record_platform_post_primary_totp_failure_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_platform_post_primary_totp_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.abandon_platform_post_primary_totp_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_platform_oidc_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_platform_oidc_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_platform_oidc_tenant_switch_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_platform_oidc_tenant_switch_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_platform_oidc_auth_provider_v3(
  uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,
  inet,text,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.retire_platform_identity_account_v4(
  uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text
) OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.guard_platform_oidc_login_policy_v1(),
  app.guard_totp_credential_security_revision_v1(),
  app.guard_platform_oidc_runtime_write_v1(),
  app.guard_platform_oidc_transaction_v1(),
  app.assert_platform_oidc_direct_session_v1(),
  app.private_platform_oidc_direct_assurance_v1(
    uuid,timestamp with time zone
  ),
  app.private_platform_oidc_direct_continuation_source_live_v1(
    public.platform_post_primary_continuations,timestamp with time zone
  ),
  app.private_platform_post_primary_totp_projection_v1(
    public.platform_post_primary_totp_challenges
  ),
  app.private_platform_oidc_direct_authority_live_v1(
    uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,integer,bigint,
    uuid,bigint,uuid,bigint
  ),
  app.private_platform_oidc_create_direct_session_v1(
    jsonb,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,integer,
    bigint,uuid,bigint,uuid,bigint,text,timestamp with time zone,
    timestamp with time zone,uuid,bigint,timestamp with time zone,uuid
  ),
  app.private_platform_oidc_direct_audit_v1(
    jsonb,text,text,uuid,public.audit_outcome,jsonb
  ),
  app.private_platform_oidc_direct_json_v1(jsonb,text[],text[],integer),
  app.private_platform_oidc_direct_projection_v1(
    public.platform_oidc_authentication_transactions
  ),
  app.private_platform_oidc_direct_configuration_v1(uuid,jsonb)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor;
GRANT EXECUTE ON FUNCTION
  app.guard_platform_oidc_login_policy_v1(),
  app.guard_totp_credential_security_revision_v1(),
  app.guard_platform_oidc_runtime_write_v1(),
  app.guard_platform_oidc_transaction_v1(),
  app.assert_platform_oidc_direct_session_v1(),
  app.private_platform_oidc_direct_assurance_v1(
    uuid,timestamp with time zone
  ),
  app.private_platform_oidc_direct_continuation_source_live_v1(
    public.platform_post_primary_continuations,timestamp with time zone
  ),
  app.private_platform_post_primary_totp_projection_v1(
    public.platform_post_primary_totp_challenges
  ),
  app.private_platform_oidc_direct_authority_live_v1(
    uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,integer,bigint,
    uuid,bigint,uuid,bigint
  ),
  app.private_platform_oidc_create_direct_session_v1(
    jsonb,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,integer,
    bigint,uuid,bigint,uuid,bigint,text,timestamp with time zone,
    timestamp with time zone,uuid,bigint,timestamp with time zone,uuid
  ),
  app.private_platform_oidc_direct_audit_v1(
    jsonb,text,text,uuid,public.audit_outcome,jsonb
  ),
  app.private_platform_oidc_direct_json_v1(jsonb,text[],text[],integer),
  app.private_platform_oidc_direct_projection_v1(
    public.platform_oidc_authentication_transactions
  ),
  app.private_platform_oidc_direct_configuration_v1(uuid,jsonb)
TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.create_platform_oidc_auth_provider_v2(
    uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,
    inet,text,text,text
  ),
  app.retire_platform_identity_account_v3(
    uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text
  )
FROM periapsis_api;
REVOKE ALL ON FUNCTION
  app.begin_platform_oidc_authentication_v1(jsonb),
  app.resolve_platform_oidc_authentication_configuration_v1(jsonb),
  app.create_platform_oidc_authentication_transaction_v1(jsonb),
  app.claim_platform_oidc_authentication_transaction_v1(jsonb),
  app.resolve_platform_oidc_authentication_v1(jsonb),
  app.fail_platform_oidc_authentication_transaction_v1(jsonb),
  app.load_platform_oidc_client_secret_v1(jsonb),
  app.load_platform_oidc_trust_snapshot_v1(jsonb),
  app.load_platform_oidc_planning_state_v1(jsonb),
  app.apply_platform_oidc_authentication_v1(jsonb),
  app.begin_platform_post_primary_totp_v1(jsonb),
  app.load_platform_post_primary_totp_v1(jsonb),
  app.record_platform_post_primary_totp_failure_v1(jsonb),
  app.apply_platform_post_primary_totp_v1(jsonb),
  app.abandon_platform_post_primary_totp_v1(jsonb),
  app.load_platform_oidc_session_revalidation_v1(jsonb),
  app.apply_platform_oidc_session_revalidation_v1(jsonb),
  app.load_platform_oidc_tenant_switch_v1(jsonb),
  app.apply_platform_oidc_tenant_switch_v1(jsonb),
  app.cleanup_platform_oidc_authentication_runtime_v1(jsonb),
  app.create_platform_oidc_auth_provider_v3(
    uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,
    inet,text,text,text
  ),
  app.retire_platform_identity_account_v4(
    uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION
  app.begin_platform_oidc_authentication_v1(jsonb),
  app.resolve_platform_oidc_authentication_configuration_v1(jsonb),
  app.create_platform_oidc_authentication_transaction_v1(jsonb),
  app.claim_platform_oidc_authentication_transaction_v1(jsonb),
  app.resolve_platform_oidc_authentication_v1(jsonb),
  app.fail_platform_oidc_authentication_transaction_v1(jsonb),
  app.load_platform_oidc_client_secret_v1(jsonb),
  app.load_platform_oidc_trust_snapshot_v1(jsonb),
  app.load_platform_oidc_planning_state_v1(jsonb),
  app.apply_platform_oidc_authentication_v1(jsonb),
  app.begin_platform_post_primary_totp_v1(jsonb),
  app.load_platform_post_primary_totp_v1(jsonb),
  app.record_platform_post_primary_totp_failure_v1(jsonb),
  app.apply_platform_post_primary_totp_v1(jsonb),
  app.abandon_platform_post_primary_totp_v1(jsonb),
  app.load_platform_oidc_session_revalidation_v1(jsonb),
  app.apply_platform_oidc_session_revalidation_v1(jsonb),
  app.load_platform_oidc_tenant_switch_v1(jsonb),
  app.apply_platform_oidc_tenant_switch_v1(jsonb),
  app.create_platform_oidc_auth_provider_v3(
    uuid,uuid,uuid,text,text,text,jsonb,text,bytea,bytea,uuid,uuid,uuid,
    inet,text,text,text
  ),
  app.retire_platform_identity_account_v4(
    uuid,uuid,uuid,bigint,bigint,uuid,uuid,uuid,inet,text,text,text
  )
TO periapsis_api;
GRANT EXECUTE ON FUNCTION
  app.cleanup_platform_oidc_authentication_runtime_v1(jsonb)
TO periapsis_worker;
--> statement-breakpoint
