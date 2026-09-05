-- Interactive LDAP authentication.  LDAP primary provenance is physically
-- separate from OIDC/SAML federation and contains no password, login name,
-- directory attribute, DN, filter, or raw immutable subject.

ALTER TABLE public.auth_sessions
  DROP CONSTRAINT auth_sessions_method_check;
ALTER TABLE public.auth_sessions
  ADD CONSTRAINT auth_sessions_method_check CHECK (
    authentication_method IN (
      'bootstrap_totp','passkey','totp','recovery_code','oidc','saml','ldap'
    )
  );
--> statement-breakpoint

ALTER TABLE public.tenant_post_primary_continuations
  DROP CONSTRAINT tenant_post_primary_continuations_primary_check;
ALTER TABLE public.tenant_post_primary_continuations
  ADD CONSTRAINT tenant_post_primary_continuations_primary_check CHECK (
    (primary_kind = 'local_credential'
      AND local_credential_id IS NOT NULL AND passkey_credential_id IS NULL
      AND provider_id IS NULL AND platform_provider_id IS NULL
      AND binding_id IS NULL AND provider_kind IS NULL
      AND external_identity_id IS NULL)
    OR (primary_kind = 'passkey'
      AND local_credential_id IS NULL AND passkey_credential_id IS NOT NULL
      AND provider_id IS NULL AND platform_provider_id IS NULL
      AND binding_id IS NULL AND provider_kind IS NULL
      AND external_identity_id IS NULL)
    OR (primary_kind = 'tenant_provider'
      AND local_credential_id IS NULL AND passkey_credential_id IS NULL
      AND provider_id IS NOT NULL AND platform_provider_id IS NULL
      AND binding_id IS NOT NULL AND provider_kind IN ('oidc','saml','ldap')
      AND external_identity_id IS NOT NULL)
    OR (primary_kind = 'tenant_platform_provider'
      AND local_credential_id IS NULL AND passkey_credential_id IS NULL
      AND provider_id IS NULL AND platform_provider_id IS NOT NULL
      AND binding_id IS NOT NULL AND provider_kind = 'oidc'
      AND external_identity_id IS NOT NULL)
  );
--> statement-breakpoint

CREATE TABLE public.auth_session_ldap_provenance (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  session_id uuid NOT NULL,
  user_id uuid NOT NULL,
  jit_run_id uuid NOT NULL,
  primary_kind text NOT NULL DEFAULT 'tenant_provider',
  authentication_method text NOT NULL DEFAULT 'ldap',
  provider_id uuid NOT NULL,
  binding_id uuid NOT NULL,
  external_identity_id uuid NOT NULL,
  external_identity_revision bigint NOT NULL,
  provider_version integer NOT NULL,
  configuration_revision integer NOT NULL,
  binding_version integer NOT NULL,
  binding_auth_revision integer NOT NULL,
  rule_set_revision bigint NOT NULL,
  authorization_revision bigint NOT NULL,
  authenticated_at timestamptz NOT NULL,
  CONSTRAINT auth_session_ldap_provenance_pkey
    PRIMARY KEY (tenant_id,session_id),
  CONSTRAINT auth_session_ldap_provenance_jit_run_key
    UNIQUE (tenant_id,jit_run_id),
  CONSTRAINT auth_session_ldap_provenance_state_fk
    FOREIGN KEY (tenant_id,session_id,primary_kind,user_id)
    REFERENCES public.auth_session_mfa_states(
      tenant_id,session_id,primary_kind,user_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT auth_session_ldap_provenance_jit_fk
    FOREIGN KEY (tenant_id,jit_run_id)
    REFERENCES public.tenant_ldap_jit_authentication_runs(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT auth_session_ldap_provenance_binding_fk
    FOREIGN KEY (tenant_id,binding_id,provider_id)
    REFERENCES public.tenant_auth_provider_bindings(tenant_id,id,provider_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT auth_session_ldap_provenance_identity_fk
    FOREIGN KEY (tenant_id,provider_id,external_identity_id,user_id)
    REFERENCES public.tenant_ldap_external_identities(
      tenant_id,provider_id,id,user_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT auth_session_ldap_provenance_kind_check CHECK (
    primary_kind = 'tenant_provider' AND authentication_method = 'ldap'
  ),
  CONSTRAINT auth_session_ldap_provenance_revision_check CHECK (
    external_identity_revision > 0 AND provider_version > 0
    AND configuration_revision > 0 AND binding_version > 0
    AND binding_auth_revision > 0 AND rule_set_revision > 0
    AND authorization_revision > 0
  )
);
ALTER TABLE public.auth_session_ldap_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_session_ldap_provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE public.auth_session_ldap_provenance OWNER TO periapsis_migrator;
REVOKE ALL ON TABLE public.auth_session_ldap_provenance
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
CREATE POLICY auth_session_ldap_provenance_migrator_all
ON public.auth_session_ldap_provenance FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);
--> statement-breakpoint

CREATE TABLE public.tenant_post_primary_ldap_provenance (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  continuation_id uuid NOT NULL,
  user_id uuid NOT NULL,
  jit_run_id uuid NOT NULL,
  provider_id uuid NOT NULL,
  binding_id uuid NOT NULL,
  external_identity_id uuid NOT NULL,
  external_identity_revision bigint NOT NULL,
  provider_version integer NOT NULL,
  configuration_revision integer NOT NULL,
  binding_version integer NOT NULL,
  binding_auth_revision integer NOT NULL,
  rule_set_revision bigint NOT NULL,
  authorization_revision bigint NOT NULL,
  authenticated_at timestamptz NOT NULL,
  CONSTRAINT tenant_post_primary_ldap_provenance_pkey
    PRIMARY KEY (tenant_id,continuation_id),
  CONSTRAINT tenant_post_primary_ldap_provenance_jit_run_key
    UNIQUE (tenant_id,jit_run_id),
  CONSTRAINT tenant_post_primary_ldap_provenance_continuation_fk
    FOREIGN KEY (tenant_id,continuation_id,user_id)
    REFERENCES public.tenant_post_primary_continuations(tenant_id,id,user_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_post_primary_ldap_provenance_jit_fk
    FOREIGN KEY (tenant_id,jit_run_id)
    REFERENCES public.tenant_ldap_jit_authentication_runs(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_post_primary_ldap_provenance_binding_fk
    FOREIGN KEY (tenant_id,binding_id,provider_id)
    REFERENCES public.tenant_auth_provider_bindings(tenant_id,id,provider_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_post_primary_ldap_provenance_identity_fk
    FOREIGN KEY (tenant_id,provider_id,external_identity_id,user_id)
    REFERENCES public.tenant_ldap_external_identities(
      tenant_id,provider_id,id,user_id
    ) ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_post_primary_ldap_provenance_revision_check CHECK (
    external_identity_revision > 0 AND provider_version > 0
    AND configuration_revision > 0 AND binding_version > 0
    AND binding_auth_revision > 0 AND rule_set_revision > 0
    AND authorization_revision > 0
  )
);
ALTER TABLE public.tenant_post_primary_ldap_provenance ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_post_primary_ldap_provenance FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_post_primary_ldap_provenance OWNER TO periapsis_migrator;
REVOKE ALL ON TABLE public.tenant_post_primary_ldap_provenance
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
CREATE POLICY tenant_post_primary_ldap_provenance_migrator_all
ON public.tenant_post_primary_ldap_provenance FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);
--> statement-breakpoint

CREATE FUNCTION app.guard_ldap_primary_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'LDAP primary provenance is immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER auth_session_ldap_provenance_immutable_v1
BEFORE UPDATE OR DELETE ON public.auth_session_ldap_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_ldap_primary_provenance_v1();
CREATE TRIGGER tenant_post_primary_ldap_provenance_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_post_primary_ldap_provenance
FOR EACH ROW EXECUTE FUNCTION app.guard_ldap_primary_provenance_v1();
CREATE FUNCTION app.validate_ldap_primary_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_jit_authentication_runs AS run
    JOIN public.tenant_ldap_identity_plan_applications AS application
      ON application.tenant_id=run.tenant_id
     AND application.id=run.application_id
     AND application.apply_mode='jit' AND application.decision='admitted'
     AND application.provider_id=run.provider_id
     AND application.binding_id=run.binding_id
     AND application.external_identity_id=NEW.external_identity_id
     AND application.user_id=NEW.user_id
    JOIN public.tenant_ldap_external_identities AS identity
      ON identity.tenant_id=application.tenant_id
     AND identity.provider_id=application.provider_id
     AND identity.id=application.external_identity_id
     AND identity.user_id=application.user_id
     AND identity.version=NEW.external_identity_revision
     AND identity.retired_at IS NULL
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id=run.tenant_id AND provider.id=run.provider_id
     AND provider.kind='ldap' AND provider.version=NEW.provider_version
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN public.tenant_ldap_provider_configs AS configuration
      ON configuration.tenant_id=provider.tenant_id
     AND configuration.provider_id=provider.id
     AND configuration.version=NEW.configuration_revision
     AND configuration.jit_mode<>'disabled'
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id=run.tenant_id AND binding.id=run.binding_id
     AND binding.provider_id=run.provider_id
     AND binding.version=NEW.binding_version
     AND binding.auth_revision=NEW.binding_auth_revision
     AND binding.mapping_revision=NEW.rule_set_revision
     AND binding.current_access_epoch_id=run.binding_access_epoch_id
     AND binding.enabled AND binding.archived_at IS NULL
    JOIN public.tenant_authorization_states AS authorization_state
      ON authorization_state.tenant_id=run.tenant_id
     AND authorization_state.revision=NEW.authorization_revision
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id=application.tenant_id
     AND membership.id=application.membership_id
     AND membership.user_id=application.user_id
     AND membership.status='active'
    JOIN public.tenant_ldap_provider_access_grants AS access_grant
      ON access_grant.tenant_id=application.tenant_id
     AND access_grant.id=application.access_grant_id
     AND access_grant.provider_id=application.provider_id
     AND access_grant.binding_id=application.binding_id
     AND access_grant.access_epoch_id=run.binding_access_epoch_id
     AND access_grant.external_identity_id=application.external_identity_id
     AND access_grant.membership_id=application.membership_id
     AND access_grant.user_id=application.user_id
     AND access_grant.ended_at IS NULL
    WHERE run.tenant_id=NEW.tenant_id AND run.id=NEW.jit_run_id
      AND run.status='succeeded' AND run.provider_id=NEW.provider_id
      AND run.binding_id=NEW.binding_id
      AND run.provider_version=NEW.provider_version
      AND run.configuration_version=NEW.configuration_revision
      AND run.binding_version=NEW.binding_version
      AND run.binding_auth_revision=NEW.binding_auth_revision
      AND run.rule_set_revision=NEW.rule_set_revision
      AND run.authorization_revision=NEW.authorization_revision
      AND NEW.authenticated_at>=run.started_at
      AND NEW.authenticated_at<=run.completed_at
  ) THEN
    RAISE EXCEPTION 'LDAP primary provenance is inconsistent'
      USING ERRCODE='23514';
  END IF;
  IF TG_TABLE_NAME='auth_session_ldap_provenance' AND NOT EXISTS (
    SELECT 1 FROM public.auth_sessions AS session
    JOIN public.auth_session_mfa_states AS state
      ON state.tenant_id=NEW.tenant_id AND state.session_id=session.id
     AND state.user_id=NEW.user_id AND state.primary_kind='tenant_provider'
    WHERE session.id=NEW.session_id AND session.user_id=NEW.user_id
      AND session.active_tenant_id=NEW.tenant_id
      AND session.authentication_method='ldap'
  ) THEN
    RAISE EXCEPTION 'LDAP session provenance owner is inconsistent'
      USING ERRCODE='23514';
  ELSIF TG_TABLE_NAME='tenant_post_primary_ldap_provenance' AND NOT EXISTS (
    SELECT 1 FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id=NEW.tenant_id
      AND continuation.id=NEW.continuation_id
      AND continuation.user_id=NEW.user_id
      AND continuation.primary_kind='tenant_provider'
      AND continuation.provider_kind='ldap'
      AND continuation.provider_id=NEW.provider_id
      AND continuation.binding_id=NEW.binding_id
      AND continuation.external_identity_id=NEW.external_identity_id
      AND continuation.primary_revision=NEW.external_identity_revision
  ) THEN
    RAISE EXCEPTION 'LDAP continuation provenance owner is inconsistent'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$function$;
CREATE TRIGGER auth_session_ldap_provenance_guard_v1
BEFORE INSERT ON public.auth_session_ldap_provenance
FOR EACH ROW EXECUTE FUNCTION app.validate_ldap_primary_provenance_v1();
CREATE TRIGGER tenant_post_primary_ldap_provenance_guard_v1
BEFORE INSERT ON public.tenant_post_primary_ldap_provenance
FOR EACH ROW EXECUTE FUNCTION app.validate_ldap_primary_provenance_v1();
CREATE CONSTRAINT TRIGGER auth_session_ldap_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE ON public.auth_session_ldap_provenance
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();
--> statement-breakpoint

-- Conservative pre-apply assurance: every live role/group target in the
-- pinned LDAP mapping snapshot participates.  This may over-challenge before
-- matching, but a mapping can never create an under-assured session.
CREATE FUNCTION app.tenant_ldap_jit_assurance_snapshot_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea,
  p_user_id uuid,
  p_evaluated_at timestamptz
)
RETURNS TABLE (requirement jsonb, has_enrollable_factor boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_run public.tenant_ldap_jit_authentication_runs%ROWTYPE;
  v_base jsonb;
  v_requirement jsonb;
  v_count integer;
BEGIN
  IF p_operation_run_id IS NULL OR p_receipt_digest IS NULL
     OR octet_length(p_receipt_digest) <> 32 OR p_evaluated_at IS NULL THEN
    RAISE EXCEPTION 'LDAP assurance snapshot input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT run.* INTO v_run
  FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.id = p_operation_run_id
    AND run.receipt_digest = p_receipt_digest
    AND run.status IN ('planning','succeeded')
    AND run.expires_at > p_evaluated_at;
  IF NOT FOUND OR NOT app.private_tenant_ldap_jit_run_is_current_v1(
    v_run.tenant_id,v_run.id
  ) THEN
    RETURN;
  END IF;
  PERFORM set_config('app.tenant_id',v_run.tenant_id::text,true);
  v_base := app.private_mfa_policy_snapshot_v1(
    v_run.tenant_id,p_user_id,'session.create',p_evaluated_at
  );

  WITH target_groups AS (
    SELECT DISTINCT epoch.tenant_security_group_id AS id
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
     AND epoch.mapping_rule_id = pinned.mapping_rule_id
     AND epoch.binding_id = pinned.binding_id
    WHERE pinned.tenant_id = v_run.tenant_id
      AND pinned.jit_run_id = v_run.id
  ), target_roles AS (
    SELECT DISTINCT target.role_id AS id
    FROM public.tenant_ldap_jit_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id = pinned.tenant_id
     AND epoch.id = pinned.source_epoch_id
     AND epoch.mapping_rule_id = pinned.mapping_rule_id
     AND epoch.binding_id = pinned.binding_id
    JOIN public.tenant_ldap_mapping_rule_role_targets AS target
      ON target.tenant_id = epoch.tenant_id
     AND target.mapping_rule_id = epoch.mapping_rule_id
     AND target.configuration_revision = epoch.configuration_revision
    WHERE pinned.tenant_id = v_run.tenant_id
      AND pinned.jit_run_id = v_run.id
  ), base_policies AS (
    SELECT entry -> 'policy' AS policy
    FROM jsonb_array_elements(v_base -> 'policies') AS entry
  ), extra_policies AS (
    SELECT jsonb_build_object(
      'id',revision.id::text,'revision',revision.revision,
      'level',revision.level,'localRequired',revision.local_required,
      'freshnessNanoseconds',revision.freshness_nanoseconds,
      'enrollmentDeadline',revision.enrollment_deadline
    ) AS policy
    FROM public.mfa_policy_revisions AS revision
    WHERE revision.tenant_id = v_run.tenant_id
      AND revision.retired_at IS NULL
      AND ((revision.scope = 'role'
            AND revision.role_id IN (SELECT id FROM target_roles))
        OR (revision.scope = 'security_group'
            AND revision.security_group_id IN (SELECT id FROM target_groups)))
  ), policies AS (
    SELECT DISTINCT ON (policy ->> 'id') policy
    FROM (
      SELECT policy FROM base_policies
      UNION ALL SELECT policy FROM extra_policies
    ) AS combined
    ORDER BY policy ->> 'id',(policy ->> 'revision')::bigint DESC
  )
  SELECT count(*)::integer,jsonb_build_object(
    'level',CASE max(CASE policy ->> 'level'
      WHEN 'primary' THEN 1 WHEN 'mfa' THEN 2
      WHEN 'phishing_resistant' THEN 3 END)
      WHEN 1 THEN 'primary' WHEN 2 THEN 'mfa'
      WHEN 3 THEN 'phishing_resistant' END,
    'localRequired',coalesce(bool_or((policy ->> 'localRequired')::boolean),false),
    'freshnessNanoseconds',coalesce(min(
      (policy ->> 'freshnessNanoseconds')::bigint
    ) FILTER (WHERE (policy ->> 'freshnessNanoseconds')::bigint > 0),0),
    'enrollmentDeadline',min(nullif(
      policy ->> 'enrollmentDeadline',''
    )::timestamptz),
    'policyRevisions',coalesce(jsonb_agg(jsonb_build_object(
      'policyId',policy ->> 'id',
      'revision',(policy ->> 'revision')::bigint
    ) ORDER BY policy ->> 'id'),'[]'::jsonb)
  ) INTO v_count,v_requirement
  FROM policies;
  IF v_count NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP assurance policy set is unavailable'
      USING ERRCODE = '42501';
  END IF;
  RETURN QUERY SELECT v_requirement,CASE WHEN p_user_id IS NULL THEN false ELSE EXISTS (
    SELECT 1 FROM public.tenant_totp_factors AS factor
    WHERE factor.tenant_id = v_run.tenant_id AND factor.user_id = p_user_id
      AND factor.status = 'active'
    UNION ALL
    SELECT 1 FROM public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id = v_run.tenant_id
      AND credential.user_id = p_user_id AND credential.status = 'active'
  ) END;
END;
$function$;
--> statement-breakpoint

-- Called in the same database transaction immediately after
-- apply_tenant_ldap_jit_identity_plan_v1.  If authority creation fails, the
-- JIT reconciliation and its audit/outbox work roll back with it.
CREATE FUNCTION app.issue_tenant_ldap_jit_authority_v1(
  p_operation_run_id uuid,
  p_receipt_digest bytea,
  p_application_id uuid,
  p_disposition text,
  p_assurance text,
  p_authenticated_at timestamptz,
  p_applied_at timestamptz,
  p_return_path text,
  p_session jsonb,
  p_continuation jsonb,
  p_audit_event_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_run public.tenant_ldap_jit_authentication_runs%ROWTYPE;
  v_application public.tenant_ldap_identity_plan_applications%ROWTYPE;
  v_identity public.tenant_ldap_external_identities%ROWTYPE;
  v_subject public.tenant_mfa_subjects%ROWTYPE;
  v_requirement jsonb;
  v_has_factor boolean;
  v_evidence jsonb;
  v_decision text;
  v_reservation jsonb;
  v_session_id uuid;
  v_family_id uuid;
  v_continuation_id uuid;
  v_token_digest bytea;
  v_csrf_digest bytea;
  v_receipt_digest bytea;
  v_idle_expires_at timestamptz;
  v_absolute_expires_at timestamptz;
  v_continuation_expires_at timestamptz;
  v_policy jsonb;
BEGIN
  IF p_operation_run_id IS NULL OR p_receipt_digest IS NULL
     OR octet_length(p_receipt_digest) <> 32 OR p_application_id IS NULL
     OR p_disposition NOT IN ('session','continuation')
     OR p_assurance NOT IN ('satisfied','step_up_required','enrollment_only')
     OR p_authenticated_at IS NULL OR p_applied_at IS NULL
     OR p_authenticated_at > p_applied_at
     OR date_trunc('microseconds',p_authenticated_at) <> p_authenticated_at
     OR date_trunc('microseconds',p_applied_at) <> p_applied_at
     OR abs(extract(epoch FROM (transaction_timestamp()-p_applied_at))) > 300
     OR p_return_path IS NULL OR char_length(p_return_path) NOT BETWEEN 1 AND 2048
     OR p_return_path ~ '[[:cntrl:]]' OR left(p_return_path,1) <> '/'
     OR left(p_return_path,2) = '//' OR p_return_path ~ '#'
     OR p_audit_event_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP authority input is invalid' USING ERRCODE = '22023';
  END IF;
  SELECT run.* INTO STRICT v_run
  FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.id = p_operation_run_id AND run.receipt_digest = p_receipt_digest
  FOR UPDATE;
  PERFORM set_config('app.tenant_id',v_run.tenant_id::text,true);

  IF EXISTS (
    SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
    WHERE provenance.tenant_id = v_run.tenant_id
      AND provenance.jit_run_id = v_run.id
  ) THEN
    SELECT provenance.session_id INTO STRICT v_session_id
    FROM public.auth_session_ldap_provenance AS provenance
    WHERE provenance.tenant_id = v_run.tenant_id
      AND provenance.jit_run_id = v_run.id;
    RETURN jsonb_build_object(
      'category','success','disposition','session',
      'userId',(SELECT user_id::text FROM public.auth_session_ldap_provenance
        WHERE tenant_id=v_run.tenant_id AND jit_run_id=v_run.id),
      'sessionId',v_session_id::text,'returnPath',p_return_path,'replayed',true
    );
  ELSIF EXISTS (
    SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
    WHERE provenance.tenant_id = v_run.tenant_id
      AND provenance.jit_run_id = v_run.id
  ) THEN
    SELECT provenance.continuation_id INTO STRICT v_continuation_id
    FROM public.tenant_post_primary_ldap_provenance AS provenance
    WHERE provenance.tenant_id = v_run.tenant_id
      AND provenance.jit_run_id = v_run.id;
    RETURN jsonb_build_object(
      'category','success','disposition','continuation',
      'userId',(SELECT user_id::text FROM public.tenant_post_primary_ldap_provenance
        WHERE tenant_id=v_run.tenant_id AND jit_run_id=v_run.id),
      'continuationId',v_continuation_id::text,
      'returnPath',p_return_path,'replayed',true
    );
  END IF;

  IF v_run.status <> 'succeeded' OR v_run.application_id <> p_application_id
     OR transaction_timestamp() > v_run.expires_at
     OR NOT app.private_tenant_ldap_jit_run_is_current_v1(v_run.tenant_id,v_run.id) THEN
    RAISE EXCEPTION 'LDAP authority snapshot is stale' USING ERRCODE = '40001';
  END IF;
  SELECT application.* INTO STRICT v_application
  FROM public.tenant_ldap_identity_plan_applications AS application
  WHERE application.tenant_id = v_run.tenant_id
    AND application.id = p_application_id
    AND application.apply_mode = 'jit' AND application.decision = 'admitted'
    AND application.provider_id = v_run.provider_id
    AND application.binding_id = v_run.binding_id
    AND application.external_identity_id IS NOT NULL
    AND application.user_id IS NOT NULL AND application.membership_id IS NOT NULL
    AND application.access_grant_id IS NOT NULL;
  SELECT identity.* INTO STRICT v_identity
  FROM public.tenant_ldap_external_identities AS identity
  JOIN public.users AS local_user
    ON local_user.id = identity.user_id AND local_user.active
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = identity.tenant_id
   AND membership.id = v_application.membership_id
   AND membership.user_id = identity.user_id AND membership.status = 'active'
  JOIN public.tenant_ldap_provider_access_grants AS access_grant
    ON access_grant.tenant_id = identity.tenant_id
   AND access_grant.id = v_application.access_grant_id
   AND access_grant.provider_id = identity.provider_id
   AND access_grant.binding_id = v_run.binding_id
   AND access_grant.access_epoch_id = v_run.binding_access_epoch_id
   AND access_grant.external_identity_id = identity.id
   AND access_grant.membership_id = membership.id
   AND access_grant.user_id = identity.user_id
   AND access_grant.ended_at IS NULL
  WHERE identity.tenant_id = v_run.tenant_id
    AND identity.provider_id = v_run.provider_id
    AND identity.id = v_application.external_identity_id
    AND identity.user_id = v_application.user_id
    AND identity.retired_at IS NULL;

  INSERT INTO public.tenant_mfa_subjects (
    tenant_id,user_id,webauthn_user_handle,identity_epoch,
    session_invalidation_epoch,version,created_at,updated_at
  ) VALUES (
    v_run.tenant_id,v_identity.user_id,gen_random_bytes(32),1,1,1,
    p_applied_at,p_applied_at
  ) ON CONFLICT (tenant_id,user_id) DO NOTHING;
  SELECT subject.* INTO STRICT v_subject
  FROM public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id = v_run.tenant_id
    AND subject.user_id = v_identity.user_id;

  SELECT snapshot.requirement,snapshot.has_enrollable_factor
    INTO STRICT v_requirement,v_has_factor
  FROM app.tenant_ldap_jit_assurance_snapshot_v1(
    v_run.id,p_receipt_digest,v_identity.user_id,p_applied_at
  ) AS snapshot;
  v_evidence := jsonb_build_array(jsonb_build_object(
    'level','primary','kind','factor','local',false,
    'providerId',v_run.provider_id::text,'bindingId',v_run.binding_id::text,
    'authenticatedAt',p_authenticated_at,'expiresAt',v_run.expires_at,
    'factorRevision',NULL,'trustRuleRevision',v_run.binding_auth_revision
  ));
  v_decision := app.private_federated_assurance_decision_v1(
    v_requirement,v_evidence,v_has_factor,p_applied_at
  );
  IF v_decision <> p_assurance
     OR (p_disposition = 'session' AND v_decision <> 'satisfied')
     OR (p_disposition = 'continuation'
       AND v_decision NOT IN ('step_up_required','enrollment_only')) THEN
    RAISE EXCEPTION 'LDAP assurance decision drifted' USING ERRCODE = '40001';
  END IF;

  IF p_disposition = 'session' THEN
    IF p_continuation IS NOT NULL OR p_session IS NULL THEN
      RAISE EXCEPTION 'LDAP session reservation is invalid' USING ERRCODE = '22023';
    END IF;
    v_reservation := p_session;
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],16384
    );
    v_session_id := app.private_mfa_require_uuidv7_v1(v_reservation->>'sessionId');
    v_family_id := app.private_mfa_require_uuidv7_v1(v_reservation->>'familyId');
    v_token_digest := app.private_mfa_decode_base64_v1(v_reservation->>'tokenDigest',32,32);
    v_csrf_digest := app.private_mfa_decode_base64_v1(v_reservation->>'csrfDigest',32,32);
    v_idle_expires_at := (v_reservation->>'idleExpiresAt')::timestamptz;
    v_absolute_expires_at := (v_reservation->>'absoluteExpiresAt')::timestamptz;
    IF v_reservation->>'authenticationMethod' <> 'ldap'
       OR v_session_id = v_family_id OR v_token_digest = v_csrf_digest
       OR encode(v_token_digest,'hex')=repeat('00',32)
       OR encode(v_csrf_digest,'hex')=repeat('00',32)
       OR v_idle_expires_at <= p_applied_at
       OR v_absolute_expires_at < v_idle_expires_at
       OR v_idle_expires_at > p_applied_at+interval '24 hours'
       OR v_absolute_expires_at > p_applied_at+interval '31 days'
       OR date_trunc('milliseconds',v_idle_expires_at)<>v_idle_expires_at
       OR date_trunc('milliseconds',v_absolute_expires_at)<>v_absolute_expires_at THEN
      RAISE EXCEPTION 'LDAP session reservation is invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      least(encode(v_token_digest,'hex'),encode(v_csrf_digest,'hex')),73124201
    ));
    PERFORM pg_advisory_xact_lock(hashtextextended(
      greatest(encode(v_token_digest,'hex'),encode(v_csrf_digest,'hex')),73124201
    ));
    IF EXISTS (SELECT 1 FROM public.auth_sessions AS session
      WHERE session.token_digest IN (v_token_digest,v_csrf_digest)
         OR session.csrf_secret_digest IN (v_token_digest,v_csrf_digest)) THEN
      RAISE EXCEPTION 'LDAP session digest collision' USING ERRCODE = '40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,created_at
    ) VALUES (
      v_session_id,v_identity.user_id,v_family_id,v_run.tenant_id,
      v_token_digest,v_csrf_digest,'ldap',p_applied_at,p_applied_at,
      v_idle_expires_at,v_absolute_expires_at,p_applied_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,session_invalidation_epoch,issued_at
    ) VALUES (
      v_session_id,v_run.tenant_id,v_identity.user_id,1,v_subject.identity_epoch,
      false,'api','tenant_provider',v_subject.session_invalidation_epoch,p_applied_at
    );
    INSERT INTO public.auth_session_ldap_provenance (
      tenant_id,session_id,user_id,jit_run_id,provider_id,binding_id,
      external_identity_id,external_identity_revision,provider_version,
      configuration_revision,binding_version,binding_auth_revision,
      rule_set_revision,authorization_revision,authenticated_at
    ) VALUES (
      v_run.tenant_id,v_session_id,v_identity.user_id,v_run.id,
      v_run.provider_id,v_run.binding_id,v_identity.id,v_identity.version,
      v_run.provider_version,v_run.configuration_version,v_run.binding_version,
      v_run.binding_auth_revision,v_run.rule_set_revision,
      v_run.authorization_revision,p_authenticated_at
    );
  ELSE
    IF p_session IS NOT NULL OR p_continuation IS NULL THEN
      RAISE EXCEPTION 'LDAP continuation reservation is invalid' USING ERRCODE = '22023';
    END IF;
    v_reservation := p_continuation;
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,ARRAY['continuationId','receiptDigest','expiresAt'],
      ARRAY['continuationId','receiptDigest','expiresAt'],8192
    );
    v_continuation_id := app.private_mfa_require_uuidv7_v1(v_reservation->>'continuationId');
    v_receipt_digest := app.private_mfa_decode_base64_v1(v_reservation->>'receiptDigest',32,32);
    v_continuation_expires_at := (v_reservation->>'expiresAt')::timestamptz;
    IF encode(v_receipt_digest,'hex')=repeat('00',32)
       OR v_continuation_expires_at <= p_applied_at
       OR v_continuation_expires_at > p_applied_at+interval '15 minutes'
       OR date_trunc('microseconds',v_continuation_expires_at)
          <> v_continuation_expires_at THEN
      RAISE EXCEPTION 'LDAP continuation reservation is invalid' USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      encode(v_receipt_digest,'hex'),77191203
    ));
    INSERT INTO public.tenant_post_primary_continuations (
      id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
      primary_kind,provider_id,binding_id,provider_kind,external_identity_id,
      primary_revision,session_invalidation_epoch,state,version,created_at,expires_at
    ) VALUES (
      v_continuation_id,v_run.tenant_id,v_identity.user_id,v_receipt_digest,
      v_subject.identity_epoch,'session.create','api','tenant_provider',
      v_run.provider_id,v_run.binding_id,'ldap',v_identity.id,v_identity.version,
      v_subject.session_invalidation_epoch,'pending',1,p_applied_at,
      v_continuation_expires_at
    );
    INSERT INTO public.tenant_post_primary_ldap_provenance (
      tenant_id,continuation_id,user_id,jit_run_id,provider_id,binding_id,
      external_identity_id,external_identity_revision,provider_version,
      configuration_revision,binding_version,binding_auth_revision,
      rule_set_revision,authorization_revision,authenticated_at
    ) VALUES (
      v_run.tenant_id,v_continuation_id,v_identity.user_id,v_run.id,
      v_run.provider_id,v_run.binding_id,v_identity.id,v_identity.version,
      v_run.provider_version,v_run.configuration_version,v_run.binding_version,
      v_run.binding_auth_revision,v_run.rule_set_revision,
      v_run.authorization_revision,p_authenticated_at
    );
  END IF;

  FOR v_policy IN SELECT value FROM jsonb_array_elements(v_requirement->'policyRevisions')
  LOOP
    IF p_disposition='session' THEN
      INSERT INTO public.auth_session_mfa_policy_pins(
        tenant_id,session_id,policy_id,policy_revision
      ) VALUES (
        v_run.tenant_id,v_session_id,(v_policy->>'policyId')::uuid,
        (v_policy->>'revision')::bigint
      );
    ELSE
      INSERT INTO public.tenant_post_primary_continuation_policy_pins(
        tenant_id,continuation_id,policy_id,policy_revision
      ) VALUES (
        v_run.tenant_id,v_continuation_id,(v_policy->>'policyId')::uuid,
        (v_policy->>'revision')::bigint
      );
    END IF;
  END LOOP;
  IF p_disposition='session' THEN
    INSERT INTO public.auth_session_mfa_evidence(
      id,tenant_id,session_id,level,kind,provider_id,binding_id,
      authenticated_at,expires_at,trust_rule_revision
    ) VALUES (
      uuidv7(),v_run.tenant_id,v_session_id,'primary','provider',
      v_run.provider_id,v_run.binding_id,p_authenticated_at,v_run.expires_at,
      v_run.binding_auth_revision
    );
  ELSE
    INSERT INTO public.tenant_post_primary_continuation_evidence(
      id,tenant_id,continuation_id,level,kind,provider_id,binding_id,
      authenticated_at,expires_at,trust_rule_revision
    ) VALUES (
      uuidv7(),v_run.tenant_id,v_continuation_id,'primary','provider',
      v_run.provider_id,v_run.binding_id,p_authenticated_at,v_run.expires_at,
      v_run.binding_auth_revision
    );
  END IF;
  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id,v_run.tenant_id,
    CASE WHEN p_disposition='session' THEN 'tenant.identity.ldap_session_created'
      ELSE 'tenant.identity.ldap_mfa_continuation_created' END,
    CASE WHEN p_disposition='session' THEN 'auth_session'
      ELSE 'tenant_post_primary_continuation' END,
    coalesce(v_session_id,v_continuation_id),v_application.request_id,
    v_application.correlation_id,p_ip_address,p_user_agent,'ldap','success',NULL,
    jsonb_build_object(
      'provider_id',v_run.provider_id,'binding_id',v_run.binding_id,
      'jit_run_id',v_run.id,'disposition',p_disposition,
      'assurance',p_assurance
    )
  );
  RETURN jsonb_build_object(
    'category','success','disposition',p_disposition,
    'userId',v_identity.user_id::text,
    'sessionId',CASE WHEN v_session_id IS NULL THEN NULL ELSE v_session_id::text END,
    'continuationId',CASE WHEN v_continuation_id IS NULL THEN NULL ELSE v_continuation_id::text END,
    'returnPath',p_return_path,'replayed',false
  );
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.assert_auth_session_mfa_provenance_v1(uuid,uuid)
  RENAME TO assert_auth_session_mfa_provenance_pre_ldap_v1;
CREATE FUNCTION app.assert_auth_session_mfa_provenance_v1(
  p_tenant_id uuid,p_session_id uuid
)
RETURNS void
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_lookup record;
  v_method text;
  v_ldap_count integer;
  v_other_count integer;
BEGIN
  SELECT state AS mfa_state,session.authentication_method AS method
    INTO v_lookup
  FROM public.auth_session_mfa_states AS state
  JOIN public.auth_sessions AS session
    ON session.id=state.session_id AND session.user_id=state.user_id
   AND session.active_tenant_id=state.tenant_id
  WHERE state.tenant_id=p_tenant_id AND state.session_id=p_session_id;
  IF NOT FOUND THEN RETURN; END IF;
  v_state:=v_lookup.mfa_state;
  v_method:=v_lookup.method;
  IF v_state.primary_kind='tenant_provider' AND v_method='ldap' THEN
    SELECT count(*)::integer INTO v_ldap_count
    FROM public.auth_session_ldap_provenance AS provenance
    JOIN public.tenant_ldap_external_identities AS identity
      ON identity.tenant_id=provenance.tenant_id
     AND identity.provider_id=provenance.provider_id
     AND identity.id=provenance.external_identity_id
     AND identity.user_id=provenance.user_id
     AND identity.version=provenance.external_identity_revision
     AND identity.retired_at IS NULL
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id=provenance.tenant_id
     AND provider.id=provenance.provider_id AND provider.kind='ldap'
     AND provider.version=provenance.provider_version
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id=provenance.tenant_id
     AND binding.id=provenance.binding_id
     AND binding.provider_id=provenance.provider_id
     AND binding.version=provenance.binding_version
     AND binding.auth_revision=provenance.binding_auth_revision
     AND binding.mapping_revision=provenance.rule_set_revision
     AND binding.enabled AND binding.archived_at IS NULL
    JOIN public.tenant_ldap_provider_configs AS configuration
      ON configuration.tenant_id=provenance.tenant_id
     AND configuration.provider_id=provenance.provider_id
     AND configuration.version=provenance.configuration_revision
     AND configuration.jit_mode<>'disabled'
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id=provenance.tenant_id
     AND membership.user_id=provenance.user_id
     AND membership.status='active'
    JOIN public.tenant_ldap_provider_access_grants AS access_grant
      ON access_grant.tenant_id=provenance.tenant_id
     AND access_grant.provider_id=provenance.provider_id
     AND access_grant.binding_id=provenance.binding_id
     AND access_grant.external_identity_id=provenance.external_identity_id
     AND access_grant.user_id=provenance.user_id
     AND access_grant.membership_id=membership.id
     AND access_grant.access_epoch_id=binding.current_access_epoch_id
     AND access_grant.ended_at IS NULL
    JOIN public.tenant_authorization_states AS authorization_state
      ON authorization_state.tenant_id=provenance.tenant_id
     AND authorization_state.revision=provenance.authorization_revision
    WHERE provenance.tenant_id=p_tenant_id
      AND provenance.session_id=p_session_id
      AND provenance.user_id=v_state.user_id;
    SELECT
      (SELECT count(*) FROM public.auth_session_local_credential_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*) FROM public.auth_session_passkey_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*) FROM public.auth_session_federated_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*) FROM public.auth_session_tenant_platform_federated_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      INTO v_other_count;
    IF v_ldap_count<>1 OR v_other_count<>0 THEN
      RAISE EXCEPTION 'LDAP session has invalid typed primary provenance'
        USING ERRCODE='23514';
    END IF;
    RETURN;
  END IF;
  PERFORM app.assert_auth_session_mfa_provenance_pre_ldap_v1(
    p_tenant_id,p_session_id
  );
END;
$function$;
--> statement-breakpoint

-- The parent continuation guard runs before the separate provenance child is
-- inserted.  Validate LDAP through its exact identity/access pins here and
-- retain the deployed OIDC/SAML branch unchanged.
CREATE OR REPLACE FUNCTION app.validate_federated_continuation_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.primary_kind='tenant_provider' AND NEW.provider_kind='ldap' THEN
    IF NOT EXISTS (
      SELECT 1
      FROM public.tenant_ldap_external_identities AS identity
      JOIN public.tenants AS tenant
        ON tenant.id=identity.tenant_id AND tenant.status='active'
      JOIN public.tenant_auth_providers AS provider
        ON provider.tenant_id=identity.tenant_id
       AND provider.id=identity.provider_id AND provider.kind='ldap'
       AND provider.enabled AND provider.archived_at IS NULL
      JOIN public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id=identity.tenant_id
       AND binding.id=NEW.binding_id AND binding.provider_id=identity.provider_id
       AND binding.enabled AND binding.archived_at IS NULL
       AND binding.current_access_epoch_id IS NOT NULL
      JOIN public.tenant_ldap_provider_configs AS configuration
        ON configuration.tenant_id=identity.tenant_id
       AND configuration.provider_id=identity.provider_id
       AND configuration.jit_mode<>'disabled'
      JOIN public.tenant_mfa_subjects AS subject
        ON subject.tenant_id=identity.tenant_id AND subject.user_id=identity.user_id
       AND subject.identity_epoch=NEW.identity_epoch
       AND subject.session_invalidation_epoch=NEW.session_invalidation_epoch
      JOIN public.tenant_memberships AS membership
        ON membership.tenant_id=identity.tenant_id
       AND membership.user_id=identity.user_id AND membership.status='active'
      JOIN public.tenant_ldap_provider_access_grants AS access_grant
        ON access_grant.tenant_id=identity.tenant_id
       AND access_grant.provider_id=identity.provider_id
       AND access_grant.binding_id=binding.id
       AND access_grant.access_epoch_id=binding.current_access_epoch_id
       AND access_grant.external_identity_id=identity.id
       AND access_grant.membership_id=membership.id
       AND access_grant.user_id=identity.user_id
       AND access_grant.ended_at IS NULL
      JOIN public.tenant_identity_provider_access_epochs AS access_epoch
        ON access_epoch.tenant_id=access_grant.tenant_id
       AND access_epoch.id=access_grant.access_epoch_id
       AND access_epoch.binding_id=access_grant.binding_id
       AND access_epoch.provider_id=access_grant.provider_id
       AND access_epoch.source_id=access_grant.source_id
       AND access_epoch.started_at<=transaction_timestamp()
       AND access_epoch.ended_at IS NULL
      JOIN public.tenant_authorization_sources AS access_source
        ON access_source.tenant_id=access_grant.tenant_id
       AND access_source.id=access_grant.source_id
       AND access_source.retired_at IS NULL
      WHERE identity.tenant_id=NEW.tenant_id
        AND identity.provider_id=NEW.provider_id
        AND identity.id=NEW.external_identity_id
        AND identity.user_id=NEW.user_id
        AND identity.version=NEW.primary_revision
        AND identity.retired_at IS NULL
    ) THEN
      RAISE EXCEPTION 'continuation has invalid LDAP primary provenance'
        USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF NEW.primary_kind='tenant_provider' AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_federated_external_identities AS identity
    JOIN public.tenants AS tenant
      ON tenant.id=identity.tenant_id AND tenant.status='active'
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id=identity.tenant_id
     AND provider.id=identity.provider_id AND provider.kind=NEW.provider_kind
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id=identity.tenant_id
     AND binding.id=identity.binding_id AND binding.provider_id=identity.provider_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id=identity.tenant_id
     AND policy.provider_id=identity.provider_id
     AND policy.binding_id=NEW.binding_id
     AND policy.provider_kind=NEW.provider_kind AND policy.enabled
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id=identity.tenant_id AND subject.user_id=identity.user_id
     AND subject.identity_epoch=NEW.identity_epoch
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id=identity.tenant_id
     AND membership.user_id=identity.user_id AND membership.status='active'
    JOIN public.tenant_federated_provider_access_grants AS access_grant
      ON access_grant.tenant_id=identity.tenant_id
     AND access_grant.provider_id=identity.provider_id
     AND access_grant.binding_id=identity.binding_id
     AND access_grant.access_epoch_id=binding.current_access_epoch_id
     AND access_grant.external_identity_id=identity.id
     AND access_grant.membership_id=membership.id
     AND access_grant.user_id=identity.user_id
     AND access_grant.started_at<=transaction_timestamp()
     AND access_grant.ended_at IS NULL
    JOIN public.tenant_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id=access_grant.tenant_id
     AND access_epoch.id=access_grant.access_epoch_id
     AND access_epoch.binding_id=access_grant.binding_id
     AND access_epoch.provider_id=access_grant.provider_id
     AND access_epoch.source_id=access_grant.source_id
     AND access_epoch.started_at<=transaction_timestamp()
     AND access_epoch.ended_at IS NULL
    JOIN public.tenant_authorization_sources AS access_source
      ON access_source.tenant_id=access_grant.tenant_id
     AND access_source.id=access_grant.source_id
     AND access_source.retired_at IS NULL
    WHERE identity.tenant_id=NEW.tenant_id
      AND identity.provider_id=NEW.provider_id
      AND identity.binding_id=NEW.binding_id
      AND identity.id=NEW.external_identity_id
      AND identity.user_id=NEW.user_id
      AND identity.version=NEW.primary_revision
      AND identity.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'continuation has invalid federated primary provenance'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.enforce_tenant_federated_continuation_provenance_v1()
  RENAME TO enforce_tenant_federated_continuation_provenance_pre_ldap_v1;
CREATE FUNCTION app.enforce_tenant_federated_continuation_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_continuation_id uuid;
  v_primary_kind text;
  v_provider_kind public.auth_provider_kind;
  v_state text;
  v_ldap_count integer;
  v_generic_count integer;
BEGIN
  IF TG_TABLE_NAME='tenant_post_primary_continuations' THEN
    v_tenant_id:=coalesce(NEW.tenant_id,OLD.tenant_id);
    v_continuation_id:=coalesce(NEW.id,OLD.id);
  ELSE
    v_tenant_id:=coalesce(NEW.tenant_id,OLD.tenant_id);
    v_continuation_id:=coalesce(NEW.continuation_id,OLD.continuation_id);
  END IF;
  SELECT continuation.primary_kind,continuation.provider_kind,continuation.state
    INTO v_primary_kind,v_provider_kind,v_state
  FROM public.tenant_post_primary_continuations AS continuation
  WHERE continuation.tenant_id=v_tenant_id AND continuation.id=v_continuation_id;
  IF v_primary_kind='tenant_provider' AND v_provider_kind='ldap' THEN
    SELECT count(*)::integer INTO v_ldap_count
    FROM public.tenant_post_primary_ldap_provenance
    WHERE tenant_id=v_tenant_id AND continuation_id=v_continuation_id;
    SELECT count(*)::integer INTO v_generic_count
    FROM public.tenant_post_primary_federated_provenance
    WHERE tenant_id=v_tenant_id AND continuation_id=v_continuation_id;
    IF ((v_state='pending' OR v_ldap_count>0) AND v_ldap_count<>1)
       OR v_generic_count<>0 THEN
      RAISE EXCEPTION 'LDAP continuation requires exact provenance'
        USING ERRCODE='23514';
    END IF;
    RETURN NULL;
  END IF;
  SELECT count(*)::integer INTO v_generic_count
  FROM public.tenant_post_primary_federated_provenance
  WHERE tenant_id=v_tenant_id AND continuation_id=v_continuation_id;
  SELECT count(*)::integer INTO v_ldap_count
  FROM public.tenant_post_primary_ldap_provenance
  WHERE tenant_id=v_tenant_id AND continuation_id=v_continuation_id;
  IF (v_primary_kind='tenant_provider'
       AND (v_state='pending' OR v_generic_count>0)
       AND v_generic_count<>1)
     OR (v_primary_kind IS DISTINCT FROM 'tenant_provider'
       AND v_generic_count<>0)
     OR v_ldap_count<>0 THEN
    RAISE EXCEPTION 'tenant-provider continuation requires exact provenance'
      USING ERRCODE='23514';
  END IF;
  RETURN NULL;
END;
$function$;
DROP TRIGGER tenant_post_primary_continuations_federated_child_v1
  ON public.tenant_post_primary_continuations;
DROP TRIGGER tenant_post_primary_federated_provenance_parent_v1
  ON public.tenant_post_primary_federated_provenance;
CREATE CONSTRAINT TRIGGER tenant_post_primary_continuations_federated_child_v1
AFTER INSERT OR UPDATE ON public.tenant_post_primary_continuations
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION
  app.enforce_tenant_federated_continuation_provenance_v1();
CREATE CONSTRAINT TRIGGER tenant_post_primary_federated_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE
ON public.tenant_post_primary_federated_provenance
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION
  app.enforce_tenant_federated_continuation_provenance_v1();
CREATE CONSTRAINT TRIGGER tenant_post_primary_ldap_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE
ON public.tenant_post_primary_ldap_provenance
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION
  app.enforce_tenant_federated_continuation_provenance_v1();
--> statement-breakpoint

ALTER FUNCTION app.guard_ldap_primary_provenance_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_ldap_primary_provenance_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.tenant_ldap_jit_assurance_snapshot_v1(uuid,bytea,uuid,timestamptz)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.issue_tenant_ldap_jit_authority_v1(
  uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,uuid,inet,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.assert_auth_session_mfa_provenance_v1(uuid,uuid)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.validate_federated_continuation_provenance_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.enforce_tenant_federated_continuation_provenance_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.guard_ldap_primary_provenance_v1(),
  app.validate_ldap_primary_provenance_v1(),
  app.tenant_ldap_jit_assurance_snapshot_v1(uuid,bytea,uuid,timestamptz),
  app.issue_tenant_ldap_jit_authority_v1(
    uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,uuid,inet,text
  ),
  app.assert_auth_session_mfa_provenance_v1(uuid,uuid),
  app.assert_auth_session_mfa_provenance_pre_ldap_v1(uuid,uuid),
  app.validate_federated_continuation_provenance_v1(),
  app.enforce_tenant_federated_continuation_provenance_v1(),
  app.enforce_tenant_federated_continuation_provenance_pre_ldap_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION
  app.tenant_ldap_jit_assurance_snapshot_v1(uuid,bytea,uuid,timestamptz),
  app.issue_tenant_ldap_jit_authority_v1(
    uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,uuid,inet,text
  )
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.tenant_ldap_interactive_auth_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_function record;
  v_oid regprocedure;
  v_owner name;
  v_configuration text[];
  v_volatility "char";
  v_security_definer boolean;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles AS role
    WHERE role.rolname = ANY(ARRAY[
      'periapsis_api','periapsis_worker','periapsis_notifier','periapsis_auditor'
    ]::name[]) AND (role.rolsuper OR role.rolbypassrls)
  ) THEN
    RETURN false;
  END IF;

  IF (SELECT count(*) FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname='public'
        AND relation.relname IN (
          'auth_session_ldap_provenance','tenant_post_primary_ldap_provenance'
        ) AND relation.relkind='r' AND relation.relrowsecurity
        AND relation.relforcerowsecurity
        AND pg_catalog.pg_get_userbyid(relation.relowner)='periapsis_migrator'
        AND NOT pg_catalog.has_table_privilege('public',relation.oid,'SELECT,INSERT,UPDATE,DELETE')
        AND NOT pg_catalog.has_table_privilege('periapsis_api',relation.oid,'SELECT,INSERT,UPDATE,DELETE')
        AND NOT pg_catalog.has_table_privilege('periapsis_worker',relation.oid,'SELECT,INSERT,UPDATE,DELETE')
  ) <> 2 THEN
    RETURN false;
  END IF;

  IF (SELECT count(*) FROM pg_catalog.pg_policies AS policy
      WHERE policy.schemaname='public'
        AND policy.tablename IN (
          'auth_session_ldap_provenance','tenant_post_primary_ldap_provenance'
        )) <> 2
     OR (SELECT count(*) FROM pg_catalog.pg_policies AS policy
         WHERE (policy.tablename,policy.policyname) IN (
           ('auth_session_ldap_provenance',
             'auth_session_ldap_provenance_migrator_all'),
           ('tenant_post_primary_ldap_provenance',
             'tenant_post_primary_ldap_provenance_migrator_all')
         ) AND policy.schemaname='public' AND policy.permissive='PERMISSIVE'
           AND policy.roles=ARRAY['periapsis_migrator']::name[]
           AND policy.cmd='ALL' AND policy.qual='true'
           AND policy.with_check='true') <> 2 THEN
    RETURN false;
  END IF;

  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_attribute AS attribute
    WHERE attribute.attrelid = ANY(ARRAY[
      'public.auth_session_ldap_provenance'::regclass,
      'public.tenant_post_primary_ldap_provenance'::regclass
    ]) AND NOT attribute.attisdropped
      AND attribute.attname = ANY(ARRAY[
        'password','username','email','bind_dn','subject_value','directory_value',
        'distinguished_name','raw_entry','raw_groups','token','receipt'
      ])
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid='public.auth_sessions'::regclass
      AND constraint_row.conname='auth_sessions_method_check'
      AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%ldap%'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid='public.tenant_post_primary_continuations'::regclass
      AND constraint_row.conname='tenant_post_primary_continuations_primary_check'
      AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE '%ldap%'
  ) THEN
    RETURN false;
  END IF;

  IF (SELECT count(*) FROM (VALUES
      ('auth_session_ldap_provenance_immutable_v1'::name,
        'public.auth_session_ldap_provenance'::regclass),
      ('auth_session_ldap_provenance_parent_v1'::name,
        'public.auth_session_ldap_provenance'::regclass),
      ('auth_session_ldap_provenance_guard_v1'::name,
        'public.auth_session_ldap_provenance'::regclass),
      ('tenant_post_primary_ldap_provenance_immutable_v1'::name,
        'public.tenant_post_primary_ldap_provenance'::regclass),
      ('tenant_post_primary_ldap_provenance_parent_v1'::name,
        'public.tenant_post_primary_ldap_provenance'::regclass),
      ('tenant_post_primary_ldap_provenance_guard_v1'::name,
        'public.tenant_post_primary_ldap_provenance'::regclass)
    ) AS expected(trigger_name,relation_id)
    JOIN pg_catalog.pg_trigger AS trigger_row
      ON trigger_row.tgrelid=expected.relation_id
     AND trigger_row.tgname=expected.trigger_name
     AND trigger_row.tgenabled='O' AND NOT trigger_row.tgisinternal
  ) <> 6 THEN
    RETURN false;
  END IF;

  FOR v_function IN SELECT * FROM (VALUES
    ('app.begin_tenant_ldap_jit_authentication_v1(uuid,bytea,text,text,bytea,bytea,bytea,uuid,uuid,uuid,inet,text)', 'v'::"char", true),
    ('app.claim_tenant_ldap_jit_planning_v1(uuid,bytea,integer[],bytea[],uuid,uuid,uuid,inet,text)', 'v'::"char", true),
    ('app.apply_tenant_ldap_jit_identity_plan_v1(uuid,bytea,uuid,bytea,public.ldap_identity_apply_decision,text,uuid,uuid,uuid,uuid,uuid,public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],text,text,text,text,text,uuid[],timestamp with time zone,uuid,uuid,uuid,inet,text)', 'v'::"char", true),
    ('app.complete_tenant_ldap_jit_authentication_v1(uuid,bytea,text,uuid,uuid,uuid,inet,text)', 'v'::"char", true),
    ('app.guard_ldap_primary_provenance_v1()', 'v'::"char", false),
    ('app.validate_ldap_primary_provenance_v1()', 'v'::"char", false),
    ('app.tenant_ldap_jit_assurance_snapshot_v1(uuid,bytea,uuid,timestamp with time zone)', 's'::"char", true),
    ('app.issue_tenant_ldap_jit_authority_v1(uuid,bytea,uuid,text,text,timestamp with time zone,timestamp with time zone,text,jsonb,jsonb,uuid,inet,text)', 'v'::"char", true),
    ('app.assert_auth_session_mfa_provenance_v1(uuid,uuid)', 's'::"char", false),
    ('app.validate_federated_continuation_provenance_v1()', 'v'::"char", false),
    ('app.enforce_tenant_federated_continuation_provenance_v1()', 'v'::"char", false)
  ) AS expected(signature,volatility,api_execute)
  LOOP
    v_oid := pg_catalog.to_regprocedure(v_function.signature);
    IF v_oid IS NULL THEN RETURN false; END IF;
    SELECT pg_catalog.pg_get_userbyid(procedure.proowner),procedure.proconfig,
           procedure.provolatile,procedure.prosecdef
      INTO v_owner,v_configuration,v_volatility,v_security_definer
    FROM pg_catalog.pg_proc AS procedure WHERE procedure.oid=v_oid;
    IF v_owner IS DISTINCT FROM 'periapsis_migrator'
       OR v_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR v_volatility IS DISTINCT FROM v_function.volatility
       OR NOT v_security_definer
       OR pg_catalog.has_function_privilege('public',v_oid,'EXECUTE')
       OR pg_catalog.has_function_privilege('periapsis_api',v_oid,'EXECUTE')
            IS DISTINCT FROM v_function.api_execute
       OR pg_catalog.has_function_privilege('periapsis_worker',v_oid,'EXECUTE')
       OR pg_catalog.has_function_privilege('periapsis_notifier',v_oid,'EXECUTE')
       OR pg_catalog.has_function_privilege('periapsis_auditor',v_oid,'EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.tenant_ldap_interactive_auth_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.tenant_ldap_interactive_auth_schema_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.tenant_ldap_interactive_auth_schema_readiness_v1()
TO periapsis_api;
--> statement-breakpoint
