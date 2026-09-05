-- A denied LDAP mapping decision may carry only source-owned revocations.
-- This ABI keeps that proof separate from admission material, re-derives the
-- exact authoritative sources from the pinned sync snapshot, and couples the
-- mapping/access/session consequences to the plan ledger and audit event.

-- The pre-network authorization revision is an immutable input fence. Mapping
-- application can legitimately advance tenant authorization in the same
-- transaction, so root authority issuance needs a distinct write-once result
-- fence captured by the planning -> terminal transition.
ALTER TABLE public.tenant_ldap_jit_authentication_runs
  ADD COLUMN result_authorization_revision bigint;
ALTER TABLE public.tenant_ldap_jit_authentication_runs
  DISABLE TRIGGER tenant_ldap_jit_runs_guard;
UPDATE public.tenant_ldap_jit_authentication_runs AS run
SET result_authorization_revision=coalesce(
  (SELECT provenance.authorization_revision
   FROM public.auth_session_ldap_provenance AS provenance
   WHERE provenance.tenant_id=run.tenant_id AND provenance.jit_run_id=run.id),
  (SELECT provenance.authorization_revision
   FROM public.tenant_post_primary_ldap_provenance AS provenance
   WHERE provenance.tenant_id=run.tenant_id AND provenance.jit_run_id=run.id),
  run.authorization_revision
)
FROM public.tenant_ldap_identity_plan_applications AS application
WHERE run.tenant_id=application.tenant_id AND run.application_id=application.id
  AND run.status IN ('succeeded','denied');
ALTER TABLE public.tenant_ldap_jit_authentication_runs
  ENABLE TRIGGER tenant_ldap_jit_runs_guard;
ALTER TABLE public.tenant_ldap_jit_authentication_runs
  ADD CONSTRAINT tenant_ldap_jit_runs_result_authorization_revision_check
  CHECK (
    (status IN ('succeeded','denied')
      AND result_authorization_revision>0)
    OR (status NOT IN ('succeeded','denied')
      AND result_authorization_revision IS NULL)
  );

-- Bind the complete authority-issuance request to its first committed result.
-- Runtime roles have no relation privileges; the public ABI is the only writer
-- and serializes callers on the parent JIT run before consulting this ledger.
CREATE TABLE public.tenant_ldap_jit_authority_issuance_receipts (
  tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
  jit_run_id uuid NOT NULL,
  request_digest bytea NOT NULL,
  result_snapshot jsonb NOT NULL,
  created_at timestamptz NOT NULL,
  CONSTRAINT tenant_ldap_jit_authority_issuance_receipts_pkey
    PRIMARY KEY (tenant_id,jit_run_id),
  CONSTRAINT tenant_ldap_jit_authority_issuance_receipts_run_fk
    FOREIGN KEY (tenant_id,jit_run_id)
    REFERENCES public.tenant_ldap_jit_authentication_runs(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_ldap_jit_authority_issuance_receipts_value_check CHECK (
    octet_length(request_digest)=32
    AND jsonb_typeof(result_snapshot)='object'
    AND pg_column_size(result_snapshot) BETWEEN 2 AND 65536
  )
);
ALTER TABLE public.tenant_ldap_jit_authority_issuance_receipts
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_ldap_jit_authority_issuance_receipts
  FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_ldap_jit_authority_issuance_receipts
  OWNER TO periapsis_migrator;
CREATE POLICY tenant_ldap_jit_authority_issuance_receipts_migrator_v1
ON public.tenant_ldap_jit_authority_issuance_receipts
FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE public.tenant_ldap_jit_authority_issuance_receipts
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
    periapsis_auditor,periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
    periapsis_sla_worker_owner,periapsis_sla_readiness_owner;
CREATE TRIGGER tenant_ldap_jit_authority_issuance_receipts_immutable_v1
BEFORE UPDATE OR DELETE
ON public.tenant_ldap_jit_authority_issuance_receipts
FOR EACH ROW EXECUTE FUNCTION app.guard_federated_immutable_ledger_v1();

-- Owner-only, transaction-scoped authority to omit exactly the recovery
-- evidence whose set was retired by recovery-code replacement. No runtime
-- role can mint or retain this capability and the LDAP writer consumes it in
-- the same transaction that rotates the session.
CREATE TABLE public.tenant_mfa_ldap_recovery_replacement_capabilities (
  tenant_id uuid NOT NULL,
  source_anchor_id uuid NOT NULL,
  source_evidence_id uuid NOT NULL,
  replaced_recovery_set_id uuid NOT NULL,
  destination_session_id uuid NOT NULL,
  backend_pid integer NOT NULL,
  transaction_id bigint NOT NULL,
  completed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
  CONSTRAINT tenant_mfa_ldap_recovery_replacement_capabilities_pkey
    PRIMARY KEY (
      backend_pid,transaction_id,tenant_id,source_anchor_id,
      replaced_recovery_set_id
    ),
  CONSTRAINT tenant_mfa_ldap_recovery_replacement_capabilities_destination_key
    UNIQUE (backend_pid,transaction_id,tenant_id,destination_session_id),
  CONSTRAINT tenant_mfa_ldap_recovery_replacement_capabilities_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)
    ON UPDATE NO ACTION ON DELETE RESTRICT,
  CONSTRAINT tenant_mfa_ldap_recovery_replacement_capabilities_source_fk
    FOREIGN KEY (tenant_id,source_anchor_id,source_evidence_id)
    REFERENCES public.tenant_mfa_authority_evidence(tenant_id,anchor_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_mfa_ldap_recovery_replacement_capabilities_set_fk
    FOREIGN KEY (tenant_id,replaced_recovery_set_id)
    REFERENCES public.tenant_recovery_code_sets(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  CONSTRAINT tenant_mfa_ldap_recovery_replacement_capabilities_value_check
    CHECK (
      backend_pid>0 AND transaction_id>0
      AND (uuid_extract_version(destination_session_id)=7) IS TRUE
      AND abs(extract(epoch FROM(created_at-completed_at)))<=300
    )
);
ALTER TABLE public.tenant_mfa_ldap_recovery_replacement_capabilities
  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_mfa_ldap_recovery_replacement_capabilities
  FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_mfa_ldap_recovery_replacement_capabilities
  OWNER TO periapsis_migrator;
CREATE POLICY tenant_mfa_ldap_recovery_replacement_capabilities_migrator_v1
ON public.tenant_mfa_ldap_recovery_replacement_capabilities
FOR ALL TO periapsis_migrator
USING (true) WITH CHECK (true);
REVOKE ALL ON TABLE
  public.tenant_mfa_ldap_recovery_replacement_capabilities
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
    periapsis_auditor,periapsis_audit_reader_owner,
    periapsis_notification_dispatch_owner,periapsis_sla_api_owner,
    periapsis_sla_worker_owner,periapsis_sla_readiness_owner;
--> statement-breakpoint

-- The 0207 issuer introduced two audit actions/resources but did not extend
-- the shared LDAP audit gate. Keep the gate closed and enumerate them here.
CREATE OR REPLACE FUNCTION app.private_append_tenant_ldap_runtime_audit_v1(
  p_event_id uuid,p_tenant_id uuid,p_action text,p_resource_type text,
  p_resource_id uuid,p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text,p_outcome public.audit_outcome,
  p_reason text,p_metadata jsonb
)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  safe_metadata jsonb := coalesce(p_metadata,'{}'::jsonb);
BEGIN
  IF p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_action NOT IN (
       'tenant.identity.ldap_plan_applied',
       'tenant.identity.ldap_plan_denied',
       'tenant.identity.ldap_jit_started',
       'tenant.identity.ldap_jit_failed',
       'tenant.identity.ldap_jit_stale',
       'tenant.identity.ldap_jit_expired',
       'tenant.identity.ldap_sync_queued',
       'tenant.identity.ldap_sync_claimed',
       'tenant.identity.ldap_sync_reclaimed',
       'tenant.identity.ldap_sync_stale',
       'tenant.identity.ldap_sync_failed',
       'tenant.identity.ldap_sync_cancelled',
       'tenant.identity.ldap_sync_enumeration_completed',
       'tenant.identity.ldap_sync_completed',
       'tenant.identity.ldap_sync_absence_applied',
       'tenant.identity.ldap_session_created',
       'tenant.identity.ldap_mfa_continuation_created'
     )
     OR p_resource_type NOT IN (
       'ldap_identity_plan_application','ldap_jit_authentication_run',
       'ldap_sync_run','auth_session','tenant_post_primary_continuation'
     )
     OR p_authentication_method NOT IN ('ldap','ldap_sync')
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR octet_length(convert_to(safe_metadata::text,'UTF8'))>8192
     OR safe_metadata::text ~* (
       'subject|ciphertext|nonce|password|secret|bind_dn|distinguished_name|'
       'directory_value|profile|email|username|first_name|last_name|display_name|'
       'filter|cursor'
     )
     OR (p_reason IS NOT NULL AND (
       btrim(p_reason)='' OR char_length(p_reason)>500
       OR p_reason ~ '[[:cntrl:]]'
     )) THEN
    RAISE EXCEPTION 'LDAP runtime audit input is unsafe'
      USING ERRCODE='22023';
  END IF;
  INSERT INTO public.audit_events(
    id,tenant_id,sequence,actor_type,action,resource_type,resource_id,
    request_id,correlation_id,ip_address,user_agent,
    authentication_method,outcome,reason,metadata
  ) VALUES (
    p_event_id,p_tenant_id,0,'system',p_action,p_resource_type,p_resource_id,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method,p_outcome,p_reason,safe_metadata
  );
END;
$function$;

CREATE OR REPLACE FUNCTION app.guard_tenant_ldap_jit_run_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP JIT authentication runs are append-only'
      USING ERRCODE='42501';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'network_pending' OR NEW.version<>1
       OR NEW.result_authorization_revision IS NOT NULL THEN
      RAISE EXCEPTION 'tenant LDAP JIT authentication run must begin pending'
        USING ERRCODE='23514';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(
    NEW.id,NEW.tenant_id,NEW.receipt_digest,NEW.provider_id,
    NEW.provider_kind,NEW.binding_id,NEW.provider_version,
    NEW.configuration_version,NEW.bind_secret_id,NEW.bind_secret_version,
    NEW.bind_secret_key_version,NEW.bind_secret_algorithm,
    NEW.endpoint_snapshot_digest,NEW.binding_version,
    NEW.binding_auth_revision,NEW.binding_access_epoch_id,
    NEW.rule_set_revision,NEW.authorization_revision,
    NEW.network_rate_key_digest,NEW.account_rate_key_digest,
    NEW.provider_rate_key_digest,NEW.begin_audit_event_id,NEW.request_id,
    NEW.correlation_id,NEW.started_at,NEW.expires_at
  ) IS DISTINCT FROM ROW(
    OLD.id,OLD.tenant_id,OLD.receipt_digest,OLD.provider_id,
    OLD.provider_kind,OLD.binding_id,OLD.provider_version,
    OLD.configuration_version,OLD.bind_secret_id,OLD.bind_secret_version,
    OLD.bind_secret_key_version,OLD.bind_secret_algorithm,
    OLD.endpoint_snapshot_digest,OLD.binding_version,
    OLD.binding_auth_revision,OLD.binding_access_epoch_id,
    OLD.rule_set_revision,OLD.authorization_revision,
    OLD.network_rate_key_digest,OLD.account_rate_key_digest,
    OLD.provider_rate_key_digest,OLD.begin_audit_event_id,OLD.request_id,
    OLD.correlation_id,OLD.started_at,OLD.expires_at
  ) OR NEW.version<>OLD.version+1 OR NOT (
    (OLD.status='network_pending' AND NEW.status='planning'
      AND OLD.result_authorization_revision IS NULL
      AND NEW.result_authorization_revision IS NULL)
    OR (OLD.status IN ('network_pending','planning')
      AND NEW.status IN ('failed','stale','expired')
      AND OLD.result_authorization_revision IS NULL
      AND NEW.result_authorization_revision IS NULL)
    OR (OLD.status='planning' AND NEW.status IN ('succeeded','denied')
      AND OLD.result_authorization_revision IS NULL
      AND NEW.result_authorization_revision>0)
  ) THEN
    RAISE EXCEPTION 'tenant LDAP JIT authentication transition is invalid'
      USING ERRCODE='23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint

DO $function$
DECLARE
  v_definition text;
  v_old constant text:='AND authorization_state.revision = run.authorization_revision';
  v_new constant text:=$replacement$AND authorization_state.revision = CASE
        WHEN run.status IN ('succeeded','denied')
          THEN run.result_authorization_revision
        ELSE run.authorization_revision
      END$replacement$;
BEGIN
  v_definition:=pg_get_functiondef(
    'app.private_tenant_ldap_jit_run_is_current_v1(uuid,uuid)'::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM length(v_old) THEN
    RAISE EXCEPTION 'LDAP JIT currentness result pin patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

DO $function$
DECLARE
  v_definition text;
  v_old constant text:=$old$application_id = p_application_id, plan_digest = p_plan_digest,
      terminal_audit_event_id = p_audit_event_id,
      completed_at = transaction_timestamp(), version = run.version + 1$old$;
  v_new constant text:=$new$application_id = p_application_id, plan_digest = p_plan_digest,
      terminal_audit_event_id = p_audit_event_id,
      result_authorization_revision = (
        SELECT state.revision
        FROM public.tenant_authorization_states AS state
        WHERE state.tenant_id = locked_run.tenant_id
          AND state.initialized_at IS NOT NULL
        FOR UPDATE
      ),
      completed_at = transaction_timestamp(), version = run.version + 1$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    ('app.apply_tenant_ldap_jit_identity_plan_v1(uuid,bytea,uuid,bytea,'
    ||'public.ldap_identity_apply_decision,text,uuid,uuid,uuid,uuid,uuid,'
    ||'public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],'
    ||'bytea[],text,text,text,text,text,uuid[],timestamp with time zone,uuid,'
    ||'uuid,uuid,inet,text)')::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM length(v_old) THEN
    RAISE EXCEPTION 'LDAP JIT terminal result pin patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

ALTER TABLE public.tenant_ldap_identity_plan_applications
  DROP CONSTRAINT tenant_ldap_identity_plan_applications_decision_check;
ALTER TABLE public.tenant_ldap_identity_plan_applications
  ADD CONSTRAINT tenant_ldap_identity_plan_applications_decision_check CHECK (
    (decision='denied' AND denial_category IS NOT NULL
      AND external_identity_id IS NULL AND user_id IS NULL
      AND membership_id IS NULL AND access_grant_id IS NULL
      AND ensured_edge_count=0)
    OR (decision='admitted' AND denial_category IS NULL
      AND external_identity_id IS NOT NULL AND user_id IS NOT NULL
      AND membership_id IS NOT NULL AND access_grant_id IS NOT NULL)
  );
--> statement-breakpoint

-- Root LDAP login provenance remains unique by JIT run. Session rotation and
-- post-primary step-up create immutable descendants instead of pretending that
-- the original directory bind happened again. Keeping jit_run_id NULL on a
-- descendant also preserves the original login result's replay key.
DROP TRIGGER auth_session_ldap_provenance_immutable_v1
  ON public.auth_session_ldap_provenance;
DROP TRIGGER tenant_post_primary_ldap_provenance_immutable_v1
  ON public.tenant_post_primary_ldap_provenance;
ALTER TABLE public.auth_session_ldap_provenance
  ALTER COLUMN jit_run_id DROP NOT NULL,
  ADD COLUMN root_jit_run_id uuid,
  ADD COLUMN source_session_id uuid,
  ADD COLUMN source_session_family_id uuid,
  ADD COLUMN source_session_version bigint,
  ADD COLUMN source_absolute_expires_at timestamptz;
ALTER TABLE public.tenant_post_primary_ldap_provenance
  ALTER COLUMN jit_run_id DROP NOT NULL,
  ADD COLUMN root_jit_run_id uuid,
  ADD COLUMN source_session_id uuid,
  ADD COLUMN source_session_family_id uuid,
  ADD COLUMN source_session_version bigint,
  ADD COLUMN source_absolute_expires_at timestamptz;
UPDATE public.auth_session_ldap_provenance
SET root_jit_run_id=jit_run_id;
UPDATE public.tenant_post_primary_ldap_provenance
SET root_jit_run_id=jit_run_id;
ALTER TABLE public.auth_session_ldap_provenance
  ALTER COLUMN root_jit_run_id SET NOT NULL,
  ADD CONSTRAINT auth_session_ldap_provenance_root_jit_fk
    FOREIGN KEY (tenant_id,root_jit_run_id)
    REFERENCES public.tenant_ldap_jit_authentication_runs(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  ADD CONSTRAINT auth_session_ldap_provenance_source_fk
    FOREIGN KEY (tenant_id,source_session_id)
    REFERENCES public.auth_session_ldap_provenance(tenant_id,session_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  ADD CONSTRAINT auth_session_ldap_provenance_lineage_check CHECK (
    (jit_run_id IS NOT NULL AND root_jit_run_id=jit_run_id
      AND source_session_id IS NULL AND source_session_family_id IS NULL
      AND source_session_version IS NULL AND source_absolute_expires_at IS NULL)
    OR (jit_run_id IS NULL AND source_session_id IS NOT NULL
      AND source_session_id<>session_id
      AND source_session_family_id IS NOT NULL
      AND (uuid_extract_version(source_session_family_id)=7) IS TRUE
      AND source_session_version BETWEEN 1 AND 9007199254740991
      AND source_absolute_expires_at>authenticated_at)
  );
ALTER TABLE public.tenant_post_primary_ldap_provenance
  ALTER COLUMN root_jit_run_id SET NOT NULL,
  ADD CONSTRAINT tenant_post_primary_ldap_provenance_root_jit_fk
    FOREIGN KEY (tenant_id,root_jit_run_id)
    REFERENCES public.tenant_ldap_jit_authentication_runs(tenant_id,id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  ADD CONSTRAINT tenant_post_primary_ldap_provenance_source_fk
    FOREIGN KEY (tenant_id,source_session_id)
    REFERENCES public.auth_session_ldap_provenance(tenant_id,session_id)
    ON UPDATE CASCADE ON DELETE RESTRICT,
  ADD CONSTRAINT tenant_post_primary_ldap_provenance_lineage_check CHECK (
    (jit_run_id IS NOT NULL AND root_jit_run_id=jit_run_id
      AND source_session_id IS NULL AND source_session_family_id IS NULL
      AND source_session_version IS NULL AND source_absolute_expires_at IS NULL)
    OR (jit_run_id IS NULL AND source_session_id IS NOT NULL
      AND source_session_family_id IS NOT NULL
      AND (uuid_extract_version(source_session_family_id)=7) IS TRUE
      AND source_session_version BETWEEN 2 AND 9007199254740991
      AND source_absolute_expires_at>authenticated_at)
  );
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.validate_ldap_primary_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.jit_run_id IS NOT NULL AND NEW.root_jit_run_id IS NULL THEN
    NEW.root_jit_run_id:=NEW.jit_run_id;
  END IF;
  IF NEW.root_jit_run_id IS NULL THEN
    RAISE EXCEPTION 'LDAP primary provenance root is required'
      USING ERRCODE='23514';
  END IF;

  IF NEW.source_session_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM public.auth_session_ldap_provenance AS source_provenance
    JOIN public.auth_sessions AS source_session
      ON source_session.id=source_provenance.session_id
     AND source_session.user_id=source_provenance.user_id
     AND source_session.active_tenant_id=source_provenance.tenant_id
     AND source_session.authentication_method='ldap'
     AND source_session.rotation_family_id=NEW.source_session_family_id
     AND source_session.absolute_expires_at=NEW.source_absolute_expires_at
    JOIN public.auth_session_mfa_states AS source_state
      ON source_state.tenant_id=source_provenance.tenant_id
     AND source_state.session_id=source_provenance.session_id
     AND source_state.user_id=source_provenance.user_id
     AND source_state.primary_kind='tenant_provider'
     AND source_state.session_version=NEW.source_session_version
    WHERE source_provenance.tenant_id=NEW.tenant_id
      AND source_provenance.session_id=NEW.source_session_id
      AND source_provenance.user_id=NEW.user_id
      AND source_provenance.root_jit_run_id=NEW.root_jit_run_id
      AND source_provenance.provider_id=NEW.provider_id
      AND source_provenance.binding_id=NEW.binding_id
      AND source_provenance.external_identity_id=NEW.external_identity_id
      AND source_provenance.external_identity_revision=NEW.external_identity_revision
      AND source_provenance.provider_version=NEW.provider_version
      AND source_provenance.configuration_revision=NEW.configuration_revision
      AND source_provenance.binding_version=NEW.binding_version
      AND source_provenance.binding_auth_revision=NEW.binding_auth_revision
      AND source_provenance.rule_set_revision=NEW.rule_set_revision
      AND source_provenance.authorization_revision<=NEW.authorization_revision
      AND source_provenance.authenticated_at=NEW.authenticated_at
  ) THEN
    RAISE EXCEPTION 'LDAP primary provenance lineage is inconsistent'
      USING ERRCODE='23514';
  END IF;

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
    WHERE run.tenant_id=NEW.tenant_id AND run.id=NEW.root_jit_run_id
      AND run.status='succeeded' AND run.provider_id=NEW.provider_id
      AND run.binding_id=NEW.binding_id
      AND run.provider_version=NEW.provider_version
      AND run.configuration_version=NEW.configuration_revision
      AND run.binding_version=NEW.binding_version
      AND run.binding_auth_revision=NEW.binding_auth_revision
      AND run.rule_set_revision=NEW.rule_set_revision
      AND (
        (NEW.jit_run_id IS NOT NULL
          AND run.result_authorization_revision=NEW.authorization_revision)
        OR (NEW.jit_run_id IS NULL
          AND run.result_authorization_revision<=NEW.authorization_revision)
      )
      AND NEW.authenticated_at>=run.started_at
      AND NEW.authenticated_at<=run.completed_at
  ) THEN
    RAISE EXCEPTION 'LDAP primary provenance is inconsistent'
      USING ERRCODE='23514';
  END IF;
  IF TG_TABLE_NAME='auth_session_ldap_provenance' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.auth_sessions AS session
      JOIN public.auth_session_mfa_states AS state
        ON state.tenant_id=NEW.tenant_id AND state.session_id=session.id
       AND state.user_id=NEW.user_id AND state.primary_kind='tenant_provider'
      WHERE session.id=NEW.session_id AND session.user_id=NEW.user_id
        AND session.active_tenant_id=NEW.tenant_id
        AND session.authentication_method='ldap'
        AND (NEW.source_session_id IS NULL
          OR session.rotated_from_session_id=NEW.source_session_id)
    ) THEN
      RAISE EXCEPTION 'LDAP session provenance owner is inconsistent'
        USING ERRCODE='23514';
    END IF;
  ELSIF TG_TABLE_NAME='tenant_post_primary_ldap_provenance' THEN
    IF NOT EXISTS (
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
  ELSE
    RAISE EXCEPTION 'LDAP primary provenance trigger target is invalid'
      USING ERRCODE='55000';
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
--> statement-breakpoint

-- The cross-table session trigger is a structural typed-provenance check, not
-- a live-authority check. Provider, policy and authorization revisions may
-- legitimately advance while an existing session is being revalidated or
-- revoked. New LDAP provenance is fenced against live authority by the
-- dedicated insert trigger above and every consuming ABI re-locks it.
CREATE OR REPLACE FUNCTION app.assert_auth_session_mfa_provenance_v1(
  p_tenant_id uuid,p_session_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
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
    WHERE provenance.tenant_id=p_tenant_id
      AND provenance.session_id=p_session_id
      AND provenance.user_id=v_state.user_id
      AND provenance.primary_kind='tenant_provider'
      AND provenance.authentication_method='ldap';
    SELECT
      (SELECT count(*) FROM public.auth_session_local_credential_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*) FROM public.auth_session_passkey_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*) FROM public.auth_session_federated_provenance
        WHERE tenant_id=p_tenant_id AND session_id=p_session_id)
      +(SELECT count(*)
        FROM public.auth_session_tenant_platform_federated_provenance
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

-- The pre-LDAP continuation guard proves live authority on every UPDATE.
-- Terminal revocation must remain possible after authority has drifted, while
-- still proving that this is the exact typed LDAP continuation and that no
-- immutable parent material changed. Patch only that one terminal branch and
-- preserve the OIDC/SAML/live LDAP validation verbatim.
DO $block$
DECLARE
  function_definition text;
  patch_needle constant text:=$needle$BEGIN
  IF NEW.primary_kind='tenant_provider' AND NEW.provider_kind='ldap' THEN$needle$;
  patch_replacement constant text:=$replacement$BEGIN
  IF TG_OP='UPDATE'
     AND OLD.primary_kind='tenant_provider' AND OLD.provider_kind='ldap'
     AND OLD.state='pending' AND NEW.state IN ('revoked','expired')
     AND NEW.version=OLD.version+1
     AND (to_jsonb(NEW)-ARRAY['state','version','revoked_at','revoke_reason']::text[])
         IS NOT DISTINCT FROM
         (to_jsonb(OLD)-ARRAY['state','version','revoked_at','revoke_reason']::text[])
     AND EXISTS (
       SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
       WHERE provenance.tenant_id=OLD.tenant_id
         AND provenance.continuation_id=OLD.id
         AND provenance.user_id=OLD.user_id
         AND provenance.provider_id=OLD.provider_id
         AND provenance.binding_id=OLD.binding_id
         AND provenance.external_identity_id=OLD.external_identity_id
         AND provenance.external_identity_revision=OLD.primary_revision
     ) THEN
    RETURN NEW;
  END IF;
  IF NEW.primary_kind='tenant_provider' AND NEW.provider_kind='ldap' THEN$replacement$;
BEGIN
  SELECT pg_get_functiondef(
    'app.validate_federated_continuation_provenance_v1()'::regprocedure
  ) INTO STRICT function_definition;
  IF function_definition NOT LIKE '%'||patch_needle||'%'
     OR replace(function_definition,patch_needle,'') LIKE '%'||patch_needle||'%' THEN
    RAISE EXCEPTION 'LDAP continuation terminal patch point is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(function_definition,patch_needle,patch_replacement);
END;
$block$;
--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_ldap_sync_identity_plan_v3(
  p_sync_run_id uuid,
  p_sync_observation_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_application_id uuid,
  p_plan_digest bytea,
  p_binding_id uuid,
  p_provider_version integer,
  p_configuration_version integer,
  p_binding_version integer,
  p_binding_auth_revision integer,
  p_access_epoch_id uuid,
  p_rule_set_revision bigint,
  p_authorization_revision bigint,
  p_decision public.ldap_identity_apply_decision,
  p_denial_category text,
  p_existing_external_identity_id uuid,
  p_existing_user_id uuid,
  p_existing_membership_id uuid,
  p_existing_access_grant_id uuid,
  p_revocation_epoch_ids uuid[],
  p_external_identity_id uuid,
  p_user_id uuid,
  p_membership_id uuid,
  p_access_grant_id uuid,
  p_profile_contribution_id uuid,
  p_subject_format public.identity_subject_format,
  p_subject_ciphertext bytea,
  p_subject_nonce bytea,
  p_subject_key_version integer,
  p_alias_ids uuid[],
  p_alias_key_versions integer[],
  p_alias_digests bytea[],
  p_display_name text,
  p_first_name text,
  p_last_name text,
  p_username text,
  p_email text,
  p_matched_mapping_epoch_ids uuid[],
  p_observed_at timestamptz,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text
)
RETURNS TABLE (
  application_id uuid,
  decision public.ldap_identity_apply_decision,
  external_identity_id uuid,
  user_id uuid,
  membership_id uuid,
  access_grant_id uuid,
  ensured_edge_count integer,
  revoked_edge_count integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  existing_application public.tenant_ldap_identity_plan_applications%ROWTYPE;
  locked_run public.tenant_ldap_sync_runs%ROWTYPE;
  locked_binding public.tenant_auth_provider_bindings%ROWTYPE;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  locked_config public.tenant_ldap_provider_configs%ROWTYPE;
  locked_identity public.tenant_ldap_external_identities%ROWTYPE;
  locked_membership public.tenant_memberships%ROWTYPE;
  locked_access public.tenant_ldap_provider_access_grants%ROWTYPE;
  absence_record public.tenant_ldap_sync_absences%ROWTYPE;
  current_authorization_revision bigint;
  expected_revocation_epochs uuid[];
  reconciliation_digest text;
  replay_digest text;
  changed_count integer;
  revoked_count integer := 0;
  sessions_revoked integer := 0;
  continuations_revoked integer := 0;
  access_revoked boolean := false;
  membership_suspended boolean := false;
  should_deprovision boolean := false;
  delegated_result record;
BEGIN
  context_tenant := app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id,p_claim_id,p_claim_receipt_digest,p_claim_fence,false
  );

  IF p_decision = 'admitted' THEN
    IF p_existing_external_identity_id IS NOT NULL
       OR p_existing_user_id IS NOT NULL OR p_existing_membership_id IS NOT NULL
       OR p_existing_access_grant_id IS NOT NULL
       OR cardinality(coalesce(p_revocation_epoch_ids,ARRAY[]::uuid[])) <> 0 THEN
      RAISE EXCEPTION 'admitted LDAP plan carried denied reconciliation proof'
        USING ERRCODE = '22023';
    END IF;
    SELECT * INTO STRICT delegated_result
    FROM app.apply_tenant_ldap_sync_identity_plan_v2(
      p_sync_run_id,p_sync_observation_id,p_claim_id,p_claim_receipt_digest,
      p_claim_fence,p_application_id,p_plan_digest,p_binding_id,
      p_provider_version,p_configuration_version,p_binding_version,
      p_binding_auth_revision,p_access_epoch_id,p_rule_set_revision,
      p_authorization_revision,p_decision,p_denial_category,
      p_external_identity_id,p_user_id,p_membership_id,p_access_grant_id,
      p_profile_contribution_id,p_subject_format,p_subject_ciphertext,
      p_subject_nonce,p_subject_key_version,p_alias_ids,p_alias_key_versions,
      p_alias_digests,p_display_name,p_first_name,p_last_name,p_username,
      p_email,p_matched_mapping_epoch_ids,p_observed_at,p_audit_event_id,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent
    );
    IF NOT delegated_result.replayed
       AND delegated_result.external_identity_id IS NOT NULL THEN
      UPDATE public.tenant_ldap_sync_absences AS absence
      SET status='cleared',resolved_at=transaction_timestamp(),
          latest_missing_run_id=p_sync_run_id,version=absence.version+1
      WHERE absence.tenant_id=context_tenant AND absence.binding_id=p_binding_id
        AND absence.external_identity_id=delegated_result.external_identity_id
        AND absence.status='pending';
    END IF;
    RETURN QUERY SELECT delegated_result.application_id,
      delegated_result.decision,delegated_result.external_identity_id,
      delegated_result.user_id,delegated_result.membership_id,
      delegated_result.access_grant_id,delegated_result.ensured_edge_count,
      delegated_result.revoked_edge_count,delegated_result.replayed;
    RETURN;
  END IF;

  IF p_decision IS DISTINCT FROM 'denied' OR p_denial_category IS NULL
     OR p_denial_category !~ '^[a-z][a-z0-9_]{1,63}$'
     OR p_plan_digest IS NULL OR octet_length(p_plan_digest) <> 32
     OR p_observed_at IS NULL
     OR p_observed_at > transaction_timestamp() + interval '5 minutes'
     OR p_observed_at < transaction_timestamp() - interval '24 hours'
     OR p_user_agent IS NULL OR length(p_user_agent) NOT BETWEEN 1 AND 1024
     OR p_revocation_epoch_ids IS NULL
     OR cardinality(p_revocation_epoch_ids) > 1000
     OR EXISTS (
       SELECT 1 FROM unnest(p_revocation_epoch_ids) AS epoch(id)
       WHERE epoch.id IS NULL OR (uuid_extract_version(epoch.id)=7) IS NOT TRUE
     )
     OR cardinality(p_revocation_epoch_ids) IS DISTINCT FROM (
       SELECT count(DISTINCT epoch.id)::integer
       FROM unnest(p_revocation_epoch_ids) AS epoch(id)
     )
     OR p_revocation_epoch_ids IS DISTINCT FROM coalesce((
       SELECT array_agg(epoch.id ORDER BY epoch.id::text)
       FROM unnest(p_revocation_epoch_ids) AS epoch(id)
     ),ARRAY[]::uuid[])
     OR p_external_identity_id IS NOT NULL OR p_user_id IS NOT NULL
     OR p_membership_id IS NOT NULL OR p_access_grant_id IS NOT NULL
     OR p_profile_contribution_id IS NOT NULL OR p_subject_format IS NOT NULL
     OR p_subject_ciphertext IS NOT NULL OR p_subject_nonce IS NOT NULL
     OR p_subject_key_version IS NOT NULL
     OR cardinality(coalesce(p_alias_ids,ARRAY[]::uuid[])) <> 0
     OR cardinality(coalesce(p_alias_key_versions,ARRAY[]::integer[])) <> 0
     OR cardinality(coalesce(p_alias_digests,ARRAY[]::bytea[])) <> 0
     OR p_display_name IS NOT NULL OR p_first_name IS NOT NULL
     OR p_last_name IS NOT NULL OR p_username IS NOT NULL OR p_email IS NOT NULL
     OR cardinality(coalesce(p_matched_mapping_epoch_ids,ARRAY[]::uuid[])) <> 0
     OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL THEN
    RAISE EXCEPTION 'denied LDAP reconciliation input is invalid'
      USING ERRCODE = '22023';
  END IF;

  IF p_existing_external_identity_id IS NULL
     AND p_existing_user_id IS NULL AND p_existing_membership_id IS NULL
     AND p_existing_access_grant_id IS NULL THEN
    IF cardinality(p_revocation_epoch_ids) <> 0 THEN
      RAISE EXCEPTION 'denied LDAP revocations lack an existing access path'
        USING ERRCODE = '22023';
    END IF;
    RETURN QUERY SELECT * FROM app.apply_tenant_ldap_sync_identity_plan_v2(
      p_sync_run_id,p_sync_observation_id,p_claim_id,p_claim_receipt_digest,
      p_claim_fence,p_application_id,p_plan_digest,p_binding_id,
      p_provider_version,p_configuration_version,p_binding_version,
      p_binding_auth_revision,p_access_epoch_id,p_rule_set_revision,
      p_authorization_revision,p_decision,p_denial_category,
      NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,
      ARRAY[]::uuid[],ARRAY[]::integer[],ARRAY[]::bytea[],
      NULL,NULL,NULL,NULL,NULL,ARRAY[]::uuid[],p_observed_at,
      p_audit_event_id,p_request_id,p_correlation_id,p_ip_address,p_user_agent
    );
    RETURN;
  END IF;

  IF p_denial_category <> 'no_mapping'
     OR p_existing_external_identity_id IS NULL
     OR p_existing_user_id IS NULL OR p_existing_membership_id IS NULL
     OR p_existing_access_grant_id IS NULL
     OR (uuid_extract_version(p_existing_external_identity_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_existing_user_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_existing_membership_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_existing_access_grant_id)=7) IS NOT TRUE THEN
    RAISE EXCEPTION 'denied LDAP reconciliation proof is invalid'
      USING ERRCODE = '22023';
  END IF;

  reconciliation_digest := encode(pg_catalog.sha256(
    pg_catalog.convert_to('ldap-sync-denied-reconciliation-v1','UTF8')
    || '\x00'::bytea
    || pg_catalog.convert_to(p_sync_run_id::text,'UTF8') || '\x00'::bytea
    || pg_catalog.convert_to(p_sync_observation_id::text,'UTF8') || '\x00'::bytea
    || pg_catalog.convert_to(p_binding_id::text,'UTF8') || '\x00'::bytea
    || pg_catalog.convert_to(p_existing_external_identity_id::text,'UTF8') || '\x00'::bytea
    || pg_catalog.convert_to(p_existing_user_id::text,'UTF8') || '\x00'::bytea
    || pg_catalog.convert_to(p_existing_membership_id::text,'UTF8') || '\x00'::bytea
    || pg_catalog.convert_to(p_existing_access_grant_id::text,'UTF8') || '\x00'::bytea
    || pg_catalog.convert_to(array_to_string(p_revocation_epoch_ids,','),'UTF8')
  ),'hex');

  IF NOT EXISTS (
    SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
    WHERE observation.tenant_id=context_tenant
      AND observation.sync_run_id=p_sync_run_id
      AND observation.id=p_sync_observation_id
      AND observation.planning_fence=p_claim_fence
      AND observation.observation_digest=p_plan_digest
  ) THEN
    RAISE EXCEPTION 'LDAP denied reconciliation was not claimed by this fence'
      USING ERRCODE = '40001';
  END IF;

  SELECT run.* INTO locked_run
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id=context_tenant AND run.id=p_sync_run_id
  FOR UPDATE;

  SELECT application.* INTO existing_application
  FROM public.tenant_ldap_identity_plan_applications AS application
  WHERE application.tenant_id=context_tenant AND application.id=p_application_id
  FOR UPDATE;
  IF FOUND THEN
    SELECT audit.metadata->>'reconciliation_digest' INTO replay_digest
    FROM public.audit_events AS audit
    WHERE audit.tenant_id=context_tenant AND audit.id=p_audit_event_id
      AND audit.action='tenant.identity.ldap_plan_denied'
      AND audit.resource_type='ldap_identity_plan_application'
      AND audit.resource_id=p_application_id
      AND audit.request_id=p_request_id
      AND audit.correlation_id=p_correlation_id;
    IF existing_application.plan_digest IS DISTINCT FROM p_plan_digest
       OR existing_application.apply_mode IS DISTINCT FROM 'sync'
       OR existing_application.decision IS DISTINCT FROM 'denied'
       OR existing_application.denial_category IS DISTINCT FROM 'no_mapping'
       OR existing_application.binding_id IS DISTINCT FROM p_binding_id
       OR existing_application.sync_run_id IS DISTINCT FROM p_sync_run_id
       OR existing_application.sync_observation_id IS DISTINCT FROM p_sync_observation_id
       OR existing_application.provider_id IS DISTINCT FROM locked_run.provider_id
       OR existing_application.provider_version IS DISTINCT FROM p_provider_version
       OR existing_application.configuration_version IS DISTINCT FROM p_configuration_version
       OR existing_application.binding_version IS DISTINCT FROM p_binding_version
       OR existing_application.binding_auth_revision IS DISTINCT FROM p_binding_auth_revision
       OR existing_application.binding_access_epoch_id IS DISTINCT FROM p_access_epoch_id
       OR existing_application.rule_set_revision IS DISTINCT FROM p_rule_set_revision
       OR existing_application.authorization_revision IS DISTINCT FROM p_authorization_revision
       OR existing_application.observed_at IS DISTINCT FROM p_observed_at
       OR existing_application.external_identity_id IS NOT NULL
       OR existing_application.user_id IS NOT NULL
       OR existing_application.membership_id IS NOT NULL
       OR existing_application.access_grant_id IS NOT NULL
       OR existing_application.ensured_edge_count IS DISTINCT FROM 0
       OR existing_application.audit_event_id IS DISTINCT FROM p_audit_event_id
       OR existing_application.request_id IS DISTINCT FROM p_request_id
       OR existing_application.correlation_id IS DISTINCT FROM p_correlation_id
       OR replay_digest IS DISTINCT FROM reconciliation_digest THEN
      RAISE EXCEPTION 'LDAP denied reconciliation replay differs'
        USING ERRCODE = '23505',
          CONSTRAINT='tenant_ldap_identity_plan_applications_tenant_id_key';
    END IF;
    RETURN QUERY SELECT existing_application.id,existing_application.decision,
      NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,
      existing_application.ensured_edge_count,
      existing_application.revoked_edge_count,true;
    RETURN;
  END IF;

  SELECT binding.* INTO locked_binding
  FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id=context_tenant AND binding.id=p_binding_id
  FOR UPDATE;
  IF NOT FOUND OR NOT locked_binding.enabled
     OR locked_binding.archived_at IS NOT NULL
     OR locked_binding.version IS DISTINCT FROM p_binding_version
     OR locked_binding.auth_revision IS DISTINCT FROM p_binding_auth_revision
     OR locked_binding.mapping_revision IS DISTINCT FROM p_rule_set_revision
     OR locked_binding.current_access_epoch_id IS DISTINCT FROM p_access_epoch_id THEN
    RAISE EXCEPTION 'LDAP denied reconciliation binding pins are stale'
      USING ERRCODE = '40001';
  END IF;
  SELECT provider.* INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant ON tenant.id=provider.tenant_id
  WHERE provider.tenant_id=context_tenant
    AND provider.id=locked_binding.provider_id AND provider.kind='ldap'
    AND provider.enabled AND provider.archived_at IS NULL
    AND provider.version=p_provider_version AND tenant.status='active'
  FOR UPDATE OF provider;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'LDAP denied reconciliation provider pins are stale'
      USING ERRCODE = '40001';
  END IF;
  SELECT configuration.* INTO locked_config
  FROM public.tenant_ldap_provider_configs AS configuration
  WHERE configuration.tenant_id=context_tenant
    AND configuration.provider_id=locked_provider.id
    AND configuration.version=p_configuration_version
  FOR UPDATE;
  IF NOT FOUND OR locked_run.status<>'applying'
     OR locked_run.binding_id IS DISTINCT FROM p_binding_id
     OR locked_run.provider_id IS DISTINCT FROM locked_provider.id
     OR locked_run.provider_version IS DISTINCT FROM p_provider_version
     OR locked_run.configuration_version IS DISTINCT FROM p_configuration_version
     OR locked_run.binding_version IS DISTINCT FROM p_binding_version
     OR locked_run.binding_auth_revision IS DISTINCT FROM p_binding_auth_revision
     OR locked_run.binding_access_epoch_id IS DISTINCT FROM p_access_epoch_id
     OR locked_run.rule_set_revision IS DISTINCT FROM p_rule_set_revision
     OR locked_run.authorization_revision IS DISTINCT FROM p_authorization_revision
     OR NOT app.private_tenant_ldap_sync_run_is_current_v1(
       context_tenant,p_sync_run_id
     ) THEN
    RAISE EXCEPTION 'LDAP denied reconciliation run pins are stale'
      USING ERRCODE = '40001';
  END IF;

  SELECT identity.* INTO locked_identity
  FROM public.tenant_ldap_external_identities AS identity
  WHERE identity.tenant_id=context_tenant
    AND identity.provider_id=locked_provider.id
    AND identity.id=p_existing_external_identity_id
    AND identity.user_id=p_existing_user_id
    AND identity.retired_at IS NULL
  FOR UPDATE;
  SELECT membership.* INTO locked_membership
  FROM public.tenant_memberships AS membership
  JOIN public.users AS local_user
    ON local_user.id=membership.user_id AND local_user.active
  WHERE membership.tenant_id=context_tenant
    AND membership.id=p_existing_membership_id
    AND membership.user_id=p_existing_user_id
    AND membership.status='active'
  FOR UPDATE OF membership;
  SELECT access_grant.* INTO locked_access
  FROM public.tenant_ldap_provider_access_grants AS access_grant
  JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id=access_grant.tenant_id
   AND access_epoch.id=access_grant.access_epoch_id
   AND access_epoch.binding_id=access_grant.binding_id
   AND access_epoch.provider_id=access_grant.provider_id
   AND access_epoch.source_id=access_grant.source_id
   AND access_epoch.ended_at IS NULL
  JOIN public.tenant_authorization_sources AS access_source
    ON access_source.tenant_id=access_grant.tenant_id
   AND access_source.id=access_grant.source_id
   AND access_source.kind='identity_provider_access'
   AND access_source.authoritative AND NOT access_source.protected
   AND access_source.retired_at IS NULL
  WHERE access_grant.tenant_id=context_tenant
    AND access_grant.id=p_existing_access_grant_id
    AND access_grant.provider_id=locked_provider.id
    AND access_grant.binding_id=p_binding_id
    AND access_grant.access_epoch_id=p_access_epoch_id
    AND access_grant.external_identity_id=p_existing_external_identity_id
    AND access_grant.membership_id=p_existing_membership_id
    AND access_grant.user_id=p_existing_user_id
    AND access_grant.ended_at IS NULL
  FOR UPDATE OF access_grant;
  IF locked_identity.id IS NULL OR locked_membership.id IS NULL
     OR locked_access.id IS NULL THEN
    RAISE EXCEPTION 'LDAP denied reconciliation access proof is stale'
      USING ERRCODE = '40001';
  END IF;

  SELECT coalesce(array_agg(source_epoch_id ORDER BY source_epoch_id::text),
                  ARRAY[]::uuid[])
    INTO expected_revocation_epochs
  FROM (
    SELECT DISTINCT pinned.source_epoch_id
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id=pinned.tenant_id
     AND epoch.id=pinned.source_epoch_id
     AND epoch.source_id=pinned.source_id
     AND epoch.binding_id=p_binding_id
     AND epoch.reconciliation_mode='authoritative'
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id=epoch.tenant_id AND source.id=epoch.source_id
     AND source.kind='identity_mapping' AND source.authoritative
     AND NOT source.protected AND source.retired_at IS NULL
    WHERE pinned.tenant_id=context_tenant
      AND pinned.sync_run_id=p_sync_run_id
      AND (
        EXISTS (
          SELECT 1 FROM public.tenant_security_group_memberships AS member
          WHERE member.tenant_id=context_tenant
            AND member.membership_id=p_existing_membership_id
            AND member.source_id=pinned.source_id AND member.revoked_at IS NULL
        ) OR EXISTS (
          SELECT 1 FROM public.operator_team_roster_entries AS roster
          WHERE roster.tenant_id=context_tenant
            AND roster.membership_id=p_existing_membership_id
            AND roster.source_id=pinned.source_id AND roster.revoked_at IS NULL
        )
      )
  ) AS exact_epochs;
  IF expected_revocation_epochs IS DISTINCT FROM p_revocation_epoch_ids THEN
    RAISE EXCEPTION 'LDAP denied reconciliation source proof drifted'
      USING ERRCODE = '40001';
  END IF;

  WITH eligible AS (
    SELECT epoch.source_id,epoch.activated_by_membership_id
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id=pinned.tenant_id AND epoch.id=pinned.source_epoch_id
     AND epoch.source_id=pinned.source_id
     AND epoch.reconciliation_mode='authoritative'
    WHERE pinned.tenant_id=context_tenant
      AND pinned.sync_run_id=p_sync_run_id
      AND pinned.source_epoch_id=ANY(p_revocation_epoch_ids)
  )
  UPDATE public.tenant_security_group_memberships AS member
  SET revoked_at=transaction_timestamp(),
      revoked_by_membership_id=eligible.activated_by_membership_id,
      revoke_reason='identity_mapping_authoritative_absence',
      version=member.version+1,updated_at=transaction_timestamp()
  FROM eligible
  WHERE member.tenant_id=context_tenant
    AND member.membership_id=p_existing_membership_id
    AND member.source_id=eligible.source_id AND member.revoked_at IS NULL;
  GET DIAGNOSTICS changed_count=ROW_COUNT;
  revoked_count:=revoked_count+changed_count;

  WITH eligible AS (
    SELECT epoch.source_id,epoch.activated_by_membership_id
    FROM public.tenant_ldap_sync_run_mappings AS pinned
    JOIN public.tenant_ldap_mapping_rule_epochs AS epoch
      ON epoch.tenant_id=pinned.tenant_id AND epoch.id=pinned.source_epoch_id
     AND epoch.source_id=pinned.source_id
     AND epoch.reconciliation_mode='authoritative'
    WHERE pinned.tenant_id=context_tenant
      AND pinned.sync_run_id=p_sync_run_id
      AND pinned.source_epoch_id=ANY(p_revocation_epoch_ids)
  )
  UPDATE public.operator_team_roster_entries AS roster
  SET revoked_at=transaction_timestamp(),
      revoked_by_membership_id=eligible.activated_by_membership_id,
      revoke_reason='identity_mapping_authoritative_absence',
      version=roster.version+1,updated_at=transaction_timestamp()
  FROM eligible
  WHERE roster.tenant_id=context_tenant
    AND roster.membership_id=p_existing_membership_id
    AND roster.source_id=eligible.source_id AND roster.revoked_at IS NULL;
  GET DIAGNOSTICS changed_count=ROW_COUNT;
  revoked_count:=revoked_count+changed_count;

  should_deprovision:=locked_config.deprovision_mode='immediate';
  IF locked_config.deprovision_mode='grace' THEN
    SELECT absence.* INTO absence_record
    FROM public.tenant_ldap_sync_absences AS absence
    WHERE absence.tenant_id=context_tenant AND absence.binding_id=p_binding_id
      AND absence.external_identity_id=p_existing_external_identity_id
    FOR UPDATE;
    IF NOT FOUND THEN
      INSERT INTO public.tenant_ldap_sync_absences(
        tenant_id,binding_id,external_identity_id,membership_id,
        first_missing_run_id,latest_missing_run_id,first_missing_at,apply_after
      ) VALUES (
        context_tenant,p_binding_id,p_existing_external_identity_id,
        p_existing_membership_id,p_sync_run_id,p_sync_run_id,
        transaction_timestamp(),transaction_timestamp()+make_interval(
          secs=>locked_config.deprovision_grace_seconds
        )
      );
      should_deprovision:=false;
    ELSIF absence_record.status='pending' THEN
      should_deprovision:=absence_record.apply_after<=transaction_timestamp();
      UPDATE public.tenant_ldap_sync_absences AS absence
      SET membership_id=p_existing_membership_id,
          latest_missing_run_id=p_sync_run_id,
          status=CASE WHEN should_deprovision
            THEN 'applied'::public.ldap_sync_absence_status
            ELSE 'pending'::public.ldap_sync_absence_status END,
          resolved_at=CASE WHEN should_deprovision
            THEN transaction_timestamp() ELSE NULL END,
          version=absence.version+1
      WHERE absence.tenant_id=context_tenant AND absence.binding_id=p_binding_id
        AND absence.external_identity_id=p_existing_external_identity_id;
    ELSE
      should_deprovision:=false;
      UPDATE public.tenant_ldap_sync_absences AS absence
      SET membership_id=p_existing_membership_id,
          first_missing_run_id=p_sync_run_id,
          latest_missing_run_id=p_sync_run_id,
          status='pending',first_missing_at=transaction_timestamp(),
          apply_after=transaction_timestamp()+make_interval(
            secs=>locked_config.deprovision_grace_seconds
          ),resolved_at=NULL,
          version=absence.version+1
      WHERE absence.tenant_id=context_tenant AND absence.binding_id=p_binding_id
        AND absence.external_identity_id=p_existing_external_identity_id;
    END IF;
  END IF;

  IF should_deprovision THEN
    UPDATE public.tenant_ldap_provider_profile_contributions AS contribution
    SET retired_at=transaction_timestamp(),
        retire_reason='identity_sync_authoritative_absence',
        version=contribution.version+1,updated_at=transaction_timestamp()
    WHERE contribution.tenant_id=context_tenant
      AND contribution.access_grant_id=p_existing_access_grant_id
      AND contribution.retired_at IS NULL;
    UPDATE public.auth_sessions AS session
    SET revoked_at=greatest(transaction_timestamp(),session.created_at),
        revoke_reason='ldap_identity_sync_authoritative_absence'
    WHERE session.user_id=p_existing_user_id AND session.revoked_at IS NULL
      AND session.rotation_family_id IN (
        SELECT source_session.rotation_family_id
        FROM public.auth_session_ldap_provenance AS provenance
        JOIN public.auth_sessions AS source_session
          ON source_session.id=provenance.session_id
         AND source_session.user_id=provenance.user_id
        WHERE provenance.tenant_id=context_tenant
          AND provenance.provider_id=locked_provider.id
          AND provenance.binding_id=p_binding_id
          AND provenance.external_identity_id=p_existing_external_identity_id
          AND provenance.user_id=p_existing_user_id
      );
    GET DIAGNOSTICS sessions_revoked=ROW_COUNT;

    UPDATE public.tenant_post_primary_continuations AS continuation
    SET state='revoked',
        revoked_at=greatest(transaction_timestamp(),continuation.created_at),
        revoke_reason='ldap_identity_sync_authoritative_absence',
        version=continuation.version+1
    WHERE continuation.tenant_id=context_tenant
      AND continuation.user_id=p_existing_user_id
      AND continuation.state='pending' AND continuation.revoked_at IS NULL
      AND EXISTS (
        SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
        WHERE provenance.tenant_id=continuation.tenant_id
          AND provenance.continuation_id=continuation.id
          AND provenance.provider_id=locked_provider.id
          AND provenance.binding_id=p_binding_id
          AND provenance.external_identity_id=p_existing_external_identity_id
          AND provenance.user_id=p_existing_user_id
      );
    GET DIAGNOSTICS continuations_revoked=ROW_COUNT;

    -- The typed continuation guard proves the live LDAP primary on every
    -- update. Revoke all already-issued authorities before ending the access
    -- grant; the transaction and the authority locks still make the whole
    -- deprovision indivisible to concurrent issuers.
    UPDATE public.tenant_ldap_provider_access_grants AS access_grant
    SET ended_at=transaction_timestamp(),
        end_reason='identity_sync_authoritative_absence',
        version=access_grant.version+1,updated_at=transaction_timestamp()
    WHERE access_grant.tenant_id=context_tenant
      AND access_grant.id=p_existing_access_grant_id
      AND access_grant.ended_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP denied access revocation lost CAS'
        USING ERRCODE='40001';
    END IF;
    access_revoked:=true;

    UPDATE public.tenant_mfa_subjects AS subject
    SET session_invalidation_epoch=subject.session_invalidation_epoch+1,
        version=subject.version+1,updated_at=transaction_timestamp()
    WHERE subject.tenant_id=context_tenant AND subject.user_id=p_existing_user_id;

    IF locked_access.owns_membership
       AND NOT EXISTS (
         SELECT 1 FROM public.tenant_ldap_provider_access_grants AS other
         WHERE other.tenant_id=context_tenant
           AND other.membership_id=p_existing_membership_id
           AND other.id<>p_existing_access_grant_id AND other.ended_at IS NULL
       ) AND NOT EXISTS (
         SELECT 1 FROM public.tenant_federated_provider_access_grants AS other
         WHERE other.tenant_id=context_tenant
           AND other.membership_id=p_existing_membership_id
           AND other.ended_at IS NULL
       ) AND NOT EXISTS (
         SELECT 1
         FROM public.tenant_platform_federated_provider_access_grants AS other
         WHERE other.tenant_id=context_tenant
           AND other.membership_id=p_existing_membership_id
           AND other.ended_at IS NULL
       ) AND NOT EXISTS (
         SELECT 1 FROM public.user_login_identifiers AS identifier
         WHERE identifier.user_id=p_existing_user_id
           AND identifier.retired_at IS NULL
       ) THEN
      UPDATE public.tenant_memberships AS membership
      SET status='suspended',updated_at=transaction_timestamp()
      WHERE membership.tenant_id=context_tenant
        AND membership.id=p_existing_membership_id
        AND membership.status='active';
      membership_suspended:=FOUND;
    END IF;
  END IF;

  PERFORM app.private_materialize_tenant_user_profile_v1(
    context_tenant,p_existing_membership_id
  );
  UPDATE public.tenant_ldap_sync_staged_observations AS observation
  SET external_identity_id=p_existing_external_identity_id,
      applied_at=transaction_timestamp(),apply_attempt=apply_attempt+1
  WHERE observation.tenant_id=context_tenant
    AND observation.sync_run_id=p_sync_run_id
    AND observation.id=p_sync_observation_id AND observation.applied_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'LDAP denied observation was already consumed'
      USING ERRCODE='40001';
  END IF;
  SELECT state.revision INTO current_authorization_revision
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id=context_tenant AND state.initialized_at IS NOT NULL;
  IF current_authorization_revision IS NULL THEN
    RAISE EXCEPTION 'initialized tenant authorization state is required'
      USING ERRCODE='42501';
  END IF;
  UPDATE public.tenant_ldap_sync_runs AS run
  SET applied_count=run.applied_count+1,
      revoked_count=run.revoked_count+CASE WHEN access_revoked THEN 1 ELSE 0 END,
      authorization_progress_revision=current_authorization_revision
  WHERE run.tenant_id=context_tenant AND run.id=p_sync_run_id;

  INSERT INTO public.tenant_ldap_identity_plan_applications(
    id,tenant_id,plan_digest,apply_mode,decision,denial_category,
    provider_id,binding_id,sync_run_id,sync_observation_id,provider_version,
    configuration_version,binding_version,binding_auth_revision,
    binding_access_epoch_id,rule_set_revision,authorization_revision,
    ensured_edge_count,revoked_edge_count,audit_event_id,request_id,
    correlation_id,observed_at
  ) VALUES (
    p_application_id,context_tenant,p_plan_digest,'sync','denied','no_mapping',
    locked_provider.id,p_binding_id,p_sync_run_id,p_sync_observation_id,
    p_provider_version,p_configuration_version,p_binding_version,
    p_binding_auth_revision,p_access_epoch_id,p_rule_set_revision,
    p_authorization_revision,0,revoked_count,p_audit_event_id,p_request_id,
    p_correlation_id,p_observed_at
  );
  PERFORM app.private_append_tenant_ldap_runtime_audit_v1(
    p_audit_event_id,context_tenant,'tenant.identity.ldap_plan_denied',
    'ldap_identity_plan_application',p_application_id,p_request_id,
    p_correlation_id,p_ip_address,p_user_agent,'ldap_sync','denied','no_mapping',
    jsonb_build_object(
      'application_id',p_application_id,'binding_id',p_binding_id,
      'provider_id',locked_provider.id,'mode','sync',
      'configuration_version',p_configuration_version,
      'rule_set_revision',p_rule_set_revision,
      'authorization_revision',p_authorization_revision,
      'reconciliation_digest',reconciliation_digest,
      'revocation_epoch_count',cardinality(p_revocation_epoch_ids),
      'revoked_edge_count',revoked_count,
      'deprovision_mode',locked_config.deprovision_mode,
      'access_revoked',access_revoked,
      'membership_suspended',membership_suspended,
      'sessions_revoked',sessions_revoked,
      'continuations_revoked',continuations_revoked
    )
  );
  RETURN QUERY SELECT p_application_id,'denied'::public.ldap_identity_apply_decision,
    NULL::uuid,NULL::uuid,NULL::uuid,NULL::uuid,0,revoked_count,false;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.apply_tenant_ldap_sync_identity_plan_v3(
  uuid,uuid,uuid,bytea,bigint,uuid,bytea,uuid,integer,integer,integer,
  integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,
  uuid,uuid,uuid,uuid,uuid[],uuid,uuid,uuid,uuid,uuid,
  public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],
  text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.apply_tenant_ldap_sync_identity_plan_v3(
  uuid,uuid,uuid,bytea,bigint,uuid,bytea,uuid,integer,integer,integer,
  integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,
  uuid,uuid,uuid,uuid,uuid[],uuid,uuid,uuid,uuid,uuid,
  public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],
  text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_identity_plan_v3(
  uuid,uuid,uuid,bytea,bigint,uuid,bytea,uuid,integer,integer,integer,
  integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,
  uuid,uuid,uuid,uuid,uuid[],uuid,uuid,uuid,uuid,uuid,
  public.identity_subject_format,bytea,bytea,integer,uuid[],integer[],bytea[],
  text,text,text,text,text,uuid[],timestamptz,uuid,uuid,uuid,inet,text
) TO periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_identity_plan_v2(
  uuid,uuid,uuid,bytea,bigint,uuid,bytea,uuid,integer,integer,integer,
  integer,uuid,bigint,bigint,public.ldap_identity_apply_decision,text,
  uuid,uuid,uuid,uuid,uuid,public.identity_subject_format,bytea,bytea,integer,
  uuid[],integer[],bytea[],text,text,text,text,text,uuid[],timestamptz,
  uuid,uuid,uuid,inet,text
) FROM periapsis_worker;
--> statement-breakpoint

-- LDAP sessions use the shared MFA/session planner, but their primary rows are
-- physically separate from the OIDC/SAML provenance graph.
CREATE FUNCTION app.private_load_ldap_session_revalidation_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session_id uuid;
  v_tenant_id uuid;
  v_audience text;
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_ldap_provenance%ROWTYPE;
  v_live_identity_epoch bigint;
  v_live_session_epoch bigint;
  v_user_active boolean;
  v_tenant_active boolean;
  v_membership_active boolean;
  v_live_primary_revision bigint;
  v_primary_active boolean;
  v_live_authorization_revision bigint;
  v_policy_snapshot jsonb;
  v_evidence jsonb;
  v_policies jsonb;
  v_factors jsonb;
  v_trust jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_lookup,ARRAY['sessionId','tenantId','audience'],
    ARRAY['sessionId','tenantId','audience'],16384
  );
  IF jsonb_typeof(p_lookup->'sessionId')<>'string'
     OR jsonb_typeof(p_lookup->'tenantId')<>'string'
     OR jsonb_typeof(p_lookup->'audience')<>'string'
     OR NOT app.private_mfa_safe_text_v1(p_lookup->>'audience',256) THEN
    RAISE EXCEPTION 'invalid LDAP session lookup' USING ERRCODE='22023';
  END IF;
  v_session_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'sessionId');
  v_tenant_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'tenantId');
  v_audience:=p_lookup->>'audience';

  SELECT session.* INTO STRICT v_session
  FROM public.auth_sessions AS session
  WHERE session.id=v_session_id AND session.active_tenant_id=v_tenant_id
    AND session.authentication_method='ldap';
  SELECT state.* INTO STRICT v_state
  FROM public.auth_session_mfa_states AS state
  WHERE state.tenant_id=v_tenant_id AND state.session_id=v_session_id
    AND state.user_id=v_session.user_id AND state.primary_kind='tenant_provider'
    AND state.audience=v_audience;
  SELECT provenance.* INTO STRICT v_provenance
  FROM public.auth_session_ldap_provenance AS provenance
  WHERE provenance.tenant_id=v_tenant_id
    AND provenance.session_id=v_session_id
    AND provenance.user_id=v_state.user_id
    AND provenance.primary_kind='tenant_provider'
    AND provenance.authentication_method='ldap';

  SELECT subject.identity_epoch,subject.session_invalidation_epoch,
         local_user.active,tenant.status='active',membership.status='active'
    INTO STRICT v_live_identity_epoch,v_live_session_epoch,v_user_active,
      v_tenant_active,v_membership_active
  FROM public.tenant_mfa_subjects AS subject
  JOIN public.users AS local_user ON local_user.id=subject.user_id
  JOIN public.tenants AS tenant ON tenant.id=subject.tenant_id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id=subject.tenant_id
   AND membership.user_id=subject.user_id
  WHERE subject.tenant_id=v_tenant_id AND subject.user_id=v_state.user_id;

  SELECT identity.version,(
    identity.retired_at IS NULL AND provider.enabled
    AND provider.archived_at IS NULL
    AND provider.version=v_provenance.provider_version
    AND binding.enabled AND binding.archived_at IS NULL
    AND binding.version=v_provenance.binding_version
    AND binding.auth_revision=v_provenance.binding_auth_revision
    AND binding.mapping_revision=v_provenance.rule_set_revision
    AND configuration.version=v_provenance.configuration_revision
    AND configuration.jit_mode<>'disabled'
    AND access_grant.id IS NOT NULL AND access_epoch.id IS NOT NULL
    AND access_source.id IS NOT NULL
  ),authorization_state.revision
    INTO STRICT v_live_primary_revision,v_primary_active,
      v_live_authorization_revision
  FROM public.tenant_ldap_external_identities AS identity
  JOIN public.tenant_auth_providers AS provider
    ON provider.tenant_id=identity.tenant_id
   AND provider.id=identity.provider_id AND provider.kind='ldap'
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id=identity.tenant_id
   AND binding.id=v_provenance.binding_id
   AND binding.provider_id=identity.provider_id
  JOIN public.tenant_ldap_provider_configs AS configuration
    ON configuration.tenant_id=identity.tenant_id
   AND configuration.provider_id=identity.provider_id
  JOIN public.tenant_authorization_states AS authorization_state
    ON authorization_state.tenant_id=identity.tenant_id
  LEFT JOIN public.tenant_ldap_provider_access_grants AS access_grant
    ON access_grant.tenant_id=identity.tenant_id
   AND access_grant.provider_id=identity.provider_id
   AND access_grant.binding_id=binding.id
   AND access_grant.external_identity_id=identity.id
   AND access_grant.user_id=identity.user_id
   AND access_grant.access_epoch_id=binding.current_access_epoch_id
   AND access_grant.ended_at IS NULL
  LEFT JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id=access_grant.tenant_id
   AND access_epoch.id=access_grant.access_epoch_id
   AND access_epoch.binding_id=access_grant.binding_id
   AND access_epoch.provider_id=access_grant.provider_id
   AND access_epoch.source_id=access_grant.source_id
   AND access_epoch.ended_at IS NULL
  LEFT JOIN public.tenant_authorization_sources AS access_source
    ON access_source.tenant_id=access_grant.tenant_id
   AND access_source.id=access_grant.source_id
   AND access_source.kind='identity_provider_access'
   AND access_source.authoritative AND NOT access_source.protected
   AND access_source.retired_at IS NULL
  WHERE identity.tenant_id=v_tenant_id
    AND identity.provider_id=v_provenance.provider_id
    AND identity.id=v_provenance.external_identity_id
    AND identity.user_id=v_state.user_id;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'reference',jsonb_strip_nulls(jsonb_build_object(
      'localCredentialId',evidence.local_credential_id::text,
      'totpFactorId',evidence.totp_factor_id::text,
      'webAuthnCredentialId',evidence.webauthn_credential_id::text,
      'recoveryCodeSetId',evidence.recovery_code_set_id::text
    )),
    'evidence',jsonb_strip_nulls(jsonb_build_object(
      'level',evidence.level,
      'kind',CASE WHEN evidence.kind='recovery' THEN 'recovery' ELSE 'factor' END,
      'local',evidence.provider_id IS NULL,
      'providerId',evidence.provider_id::text,
      'bindingId',evidence.binding_id::text,
      'authenticatedAt',to_jsonb(evidence.authenticated_at),
      'expiresAt',CASE WHEN evidence.expires_at IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(evidence.expires_at) END,
      'factorRevision',CASE WHEN evidence.factor_revision IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(evidence.factor_revision) END,
      'trustRuleRevision',CASE WHEN evidence.trust_rule_revision IS NULL THEN 'null'::jsonb
        ELSE to_jsonb(evidence.trust_rule_revision) END
    ))
  ) ORDER BY evidence.authenticated_at,evidence.id),'[]'::jsonb)
    INTO v_evidence
  FROM public.auth_session_mfa_evidence AS evidence
  WHERE evidence.tenant_id=v_tenant_id AND evidence.session_id=v_session_id;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'policyId',pin.policy_id::text,'revision',pin.policy_revision
  ) ORDER BY pin.policy_id),'[]'::jsonb) INTO v_policies
  FROM public.auth_session_mfa_policy_pins AS pin
  WHERE pin.tenant_id=v_tenant_id AND pin.session_id=v_session_id;
  IF jsonb_array_length(v_evidence) NOT BETWEEN 1 AND 1024
     OR jsonb_array_length(v_policies) NOT BETWEEN 1 AND 1024 THEN
    RETURN NULL;
  END IF;

  WITH factor_rows AS (
    SELECT evidence.totp_factor_id AS factor_id,'totp'::text AS kind,
      factor.security_revision AS revision,factor.status='active' AS active
    FROM public.auth_session_mfa_evidence AS evidence
    JOIN public.tenant_totp_factors AS factor
      ON factor.tenant_id=evidence.tenant_id AND factor.id=evidence.totp_factor_id
    WHERE evidence.tenant_id=v_tenant_id AND evidence.session_id=v_session_id
      AND evidence.totp_factor_id IS NOT NULL
    UNION ALL
    SELECT evidence.webauthn_credential_id,'webauthn',
      credential.security_revision,
      credential.status='active'
    FROM public.auth_session_mfa_evidence AS evidence
    JOIN public.tenant_webauthn_credentials AS credential
      ON credential.tenant_id=evidence.tenant_id
     AND credential.id=evidence.webauthn_credential_id
    WHERE evidence.tenant_id=v_tenant_id AND evidence.session_id=v_session_id
      AND evidence.webauthn_credential_id IS NOT NULL
    UNION ALL
    SELECT evidence.recovery_code_set_id,'recovery',code_set.security_revision,
      code_set.status='active'
    FROM public.auth_session_mfa_evidence AS evidence
    JOIN public.tenant_recovery_code_sets AS code_set
      ON code_set.tenant_id=evidence.tenant_id
     AND code_set.id=evidence.recovery_code_set_id
    WHERE evidence.tenant_id=v_tenant_id AND evidence.session_id=v_session_id
      AND evidence.recovery_code_set_id IS NOT NULL
  )
  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'reference',jsonb_build_object(
      CASE factor.kind WHEN 'totp' THEN 'totpFactorId'
        WHEN 'webauthn' THEN 'webAuthnCredentialId'
        ELSE 'recoveryCodeSetId' END,factor.factor_id::text
    ),'revision',factor.revision,'active',factor.active
  ) ORDER BY factor.kind,factor.factor_id),'[]'::jsonb) INTO v_factors
  FROM factor_rows AS factor;

  SELECT coalesce(jsonb_agg(jsonb_build_object(
    'provider',jsonb_build_object(
      'scope','tenant','tenantId',v_tenant_id::text,
      'providerId',evidence.provider_id::text,
      'bindingId',evidence.binding_id::text
    ),'revision',evidence.trust_rule_revision,
    'active',EXISTS (
      SELECT 1 FROM public.tenant_auth_providers AS provider
      JOIN public.tenant_auth_provider_bindings AS binding
        ON binding.tenant_id=provider.tenant_id
       AND binding.provider_id=provider.id
       AND binding.id=evidence.binding_id
      JOIN public.tenant_ldap_provider_configs AS configuration
        ON configuration.tenant_id=provider.tenant_id
       AND configuration.provider_id=provider.id
      WHERE provider.tenant_id=evidence.tenant_id
        AND provider.id=evidence.provider_id AND provider.kind='ldap'
        AND provider.enabled AND provider.archived_at IS NULL
        AND binding.enabled AND binding.archived_at IS NULL
        AND binding.auth_revision=evidence.trust_rule_revision
        AND configuration.jit_mode<>'disabled'
    )
  ) ORDER BY evidence.provider_id,evidence.binding_id,evidence.trust_rule_revision),
  '[]'::jsonb) INTO v_trust
  FROM (
    SELECT DISTINCT source.tenant_id,source.provider_id,source.binding_id,
      source.trust_rule_revision
    FROM public.auth_session_mfa_evidence AS source
    WHERE source.tenant_id=v_tenant_id AND source.session_id=v_session_id
      AND source.provider_id IS NOT NULL
  ) AS evidence;

  v_policy_snapshot:=app.private_mfa_policy_snapshot_v1(
    v_tenant_id,v_state.user_id,'tenant.authentication.login',
    transaction_timestamp()
  );
  RETURN jsonb_build_object(
    'lookup',p_lookup,'authenticationMethod','ldap',
    'snapshot',jsonb_build_object(
      'sessionId',v_session.id::text,
      'rotationFamilyId',v_session.rotation_family_id::text,
      'version',v_state.session_version,'tenantId',v_tenant_id::text,
      'userId',v_state.user_id::text,'identityEpoch',v_state.identity_epoch,
      'recoveryRestricted',v_state.recovery_restricted,
      'primary',jsonb_build_object(
        'kind','tenant_provider','primaryId',v_provenance.external_identity_id::text,
        'primaryRevision',v_provenance.external_identity_revision,
        'provider',jsonb_build_object(
          'scope','tenant','tenantId',v_tenant_id::text,
          'providerId',v_provenance.provider_id::text,
          'bindingId',v_provenance.binding_id::text
        ),'externalIdentityId',v_provenance.external_identity_id::text,
        'sessionInvalidationEpoch',v_state.session_invalidation_epoch,
        'authenticatedAt',to_jsonb(v_provenance.authenticated_at)
      ),'evidence',v_evidence,'policyRevisions',v_policies,
      'issuedAt',to_jsonb(v_state.issued_at),
      'idleExpiresAt',to_jsonb(v_session.idle_expires_at),
      'absoluteExpiresAt',to_jsonb(v_session.absolute_expires_at)
    ),
    'live',jsonb_build_object(
      'tenantId',v_tenant_id::text,'userId',v_state.user_id::text,
      'audience',v_audience,
      'sessionActive',v_session.revoked_at IS NULL
        AND v_session.idle_expires_at>transaction_timestamp()
        AND v_session.absolute_expires_at>transaction_timestamp(),
      'rotationFamilyActive',EXISTS (
        SELECT 1 FROM public.auth_sessions AS family
        WHERE family.user_id=v_state.user_id
          AND family.rotation_family_id=v_session.rotation_family_id
          AND family.revoked_at IS NULL
          AND family.idle_expires_at>transaction_timestamp()
          AND family.absolute_expires_at>transaction_timestamp()
      ),'userActive',v_user_active,'tenantActive',v_tenant_active,
      'membershipActive',v_membership_active,
      'identityEpoch',v_live_identity_epoch,'primaryActive',v_primary_active,
      'primaryRevision',v_live_primary_revision,
      'authorizationRevision',v_live_authorization_revision,
      'sessionInvalidationEpoch',v_live_session_epoch,
      'factors',v_factors,'trustRules',v_trust,
      'requirement',v_policy_snapshot->'requirement'
    )
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RETURN NULL;
WHEN invalid_text_representation OR data_exception THEN
  RAISE EXCEPTION 'invalid LDAP session lookup' USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint

-- The legacy guard allowed only pending -> cleared/applied.  A grace clock
-- must also survive consecutive no-match observations and a genuinely
-- recovered identity must be able to begin a new clock if it disappears
-- again.  Keep both reopen paths tied to an exact complete inventory.
CREATE OR REPLACE FUNCTION app.guard_tenant_ldap_sync_absence_v1()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP sync absences are archival records'
      USING ERRCODE='55000';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.status<>'pending' OR NOT EXISTS (
      SELECT 1 FROM public.tenant_ldap_sync_runs AS run
      WHERE run.tenant_id=NEW.tenant_id AND run.id=NEW.latest_missing_run_id
        AND run.binding_id=NEW.binding_id AND run.status='applying'
        AND run.enumeration_complete AND NOT run.result_truncated
    ) THEN
      RAISE EXCEPTION 'tenant LDAP absence requires a complete applying run'
        USING ERRCODE='55000';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(NEW.tenant_id,NEW.binding_id,NEW.external_identity_id,
         NEW.membership_id) IS DISTINCT FROM
     ROW(OLD.tenant_id,OLD.binding_id,OLD.external_identity_id,
         OLD.membership_id)
     OR NEW.version<>OLD.version+1 THEN
    RAISE EXCEPTION 'tenant LDAP absence transition is invalid'
      USING ERRCODE='55000';
  END IF;
  IF OLD.status='pending' THEN
    IF ROW(NEW.first_missing_run_id,NEW.first_missing_at,NEW.apply_after)
         IS DISTINCT FROM
       ROW(OLD.first_missing_run_id,OLD.first_missing_at,OLD.apply_after)
       OR NEW.status NOT IN ('pending','cleared','applied')
       OR (NEW.status='pending' AND NEW.resolved_at IS NOT NULL) THEN
      RAISE EXCEPTION 'tenant LDAP absence transition is invalid'
        USING ERRCODE='55000';
    END IF;
    RETURN NEW;
  END IF;
  IF OLD.status='cleared' AND NEW.status='pending'
     AND OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS NULL
     AND EXISTS (
       SELECT 1 FROM public.tenant_ldap_sync_runs AS run
       WHERE run.tenant_id=NEW.tenant_id AND run.id=NEW.latest_missing_run_id
         AND run.binding_id=NEW.binding_id AND run.status='applying'
         AND run.enumeration_complete AND NOT run.result_truncated
     ) THEN
    IF ROW(NEW.first_missing_run_id,NEW.first_missing_at,NEW.apply_after)
         IS NOT DISTINCT FROM
       ROW(OLD.first_missing_run_id,OLD.first_missing_at,OLD.apply_after)
       AND EXISTS (
         SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
         WHERE observation.tenant_id=NEW.tenant_id
           AND observation.sync_run_id=NEW.latest_missing_run_id
           AND observation.external_identity_id=NEW.external_identity_id
           AND observation.applied_at IS NULL
       ) THEN
      RETURN NEW;
    END IF;
    IF NEW.first_missing_run_id=NEW.latest_missing_run_id
       AND NEW.first_missing_run_id<>OLD.first_missing_run_id
       AND NEW.first_missing_at>=OLD.resolved_at
       AND NEW.apply_after>=NEW.first_missing_at THEN
      RETURN NEW;
    END IF;
  END IF;
  RAISE EXCEPTION 'tenant LDAP absence transition is invalid'
    USING ERRCODE='55000';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.complete_tenant_ldap_sync_enumeration_v3(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_expected_version integer,
  p_enumeration_complete boolean,
  p_result_truncated boolean,
  p_cursor_digest bytea,
  p_failure_category text,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE(
  status public.ldap_sync_run_status,
  version integer,
  observed_count integer,
  absence_allowed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  delegated_result record;
  was_enumerating boolean:=false;
BEGIN
  -- The v2 completion owns claim validation, fencing and exact replay.  Read
  -- only whether this call can be the state transition before delegation; a
  -- replay must not be rejected merely because its lease is already closed.
  SELECT run.tenant_id,
         run.status='enumerating' AND run.version=p_expected_version
    INTO context_tenant,was_enumerating
  FROM public.tenant_ldap_sync_runs AS run WHERE run.id=p_sync_run_id;
  SELECT * INTO STRICT delegated_result
  FROM app.complete_tenant_ldap_sync_enumeration_v2(
    p_sync_run_id,p_claim_id,p_claim_receipt_digest,p_claim_fence,
    p_expected_version,p_enumeration_complete,p_result_truncated,
    p_cursor_digest,p_failure_category,p_audit_event_id,p_request_id,
    p_correlation_id,p_user_agent
  );
  IF was_enumerating AND delegated_result.status='applying' THEN
    -- v1 clears a pending absence as soon as the identity is observed. Reopen
    -- only rows changed by this exact run; admitted apply closes them after the
    -- mapping decision, while no-match preserves their original grace clock.
    UPDATE public.tenant_ldap_sync_absences AS absence
    SET status='pending',resolved_at=NULL,version=absence.version+1
    WHERE absence.tenant_id=context_tenant
      AND absence.latest_missing_run_id=p_sync_run_id
      AND absence.status='cleared'
      AND EXISTS (
        SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
        WHERE observation.tenant_id=absence.tenant_id
          AND observation.sync_run_id=p_sync_run_id
          AND observation.external_identity_id=absence.external_identity_id
          AND observation.applied_at IS NULL
      );
  END IF;
  RETURN QUERY SELECT delegated_result.status,delegated_result.version,
    delegated_result.observed_count,delegated_result.absence_allowed;
END;
$function$;
--> statement-breakpoint

-- The historical inventory-absence reconciler considered only another LDAP
-- grant before suspending a provider-owned membership. A live OIDC/SAML or
-- tenant-platform provider grant owns the same access boundary and must keep
-- that membership active. Patch the unique predicate in place so the v2
-- claim/fence wrapper retains its established ABI and audit semantics.
DO $block$
DECLARE
  function_definition text;
  patch_needle constant text:=$needle$         ) AND NOT EXISTS (
           SELECT 1 FROM public.user_login_identifiers AS identifier$needle$;
  patch_replacement constant text:=$replacement$         ) AND NOT EXISTS (
           SELECT 1 FROM public.tenant_federated_provider_access_grants AS other
           WHERE other.tenant_id = context_tenant
             AND other.membership_id = candidate.membership_id
             AND other.ended_at IS NULL
         ) AND NOT EXISTS (
           SELECT 1
           FROM public.tenant_platform_federated_provider_access_grants AS other
           WHERE other.tenant_id = context_tenant
             AND other.membership_id = candidate.membership_id
             AND other.ended_at IS NULL
         ) AND NOT EXISTS (
           SELECT 1 FROM public.user_login_identifiers AS identifier$replacement$;
BEGIN
  SELECT pg_get_functiondef(
    'app.apply_tenant_ldap_sync_absence_chunk_v1(uuid,integer,uuid,uuid,uuid,text)'::regprocedure
  ) INTO STRICT function_definition;
  IF function_definition NOT LIKE '%'||patch_needle||'%'
     OR replace(function_definition,patch_needle,'') LIKE '%'||patch_needle||'%' THEN
    RAISE EXCEPTION 'LDAP absence shared-membership patch point is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(function_definition,patch_needle,patch_replacement);
END;
$block$;
--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v3(
  p_sync_run_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_limit integer,
  p_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE(
  inspected_count integer,
  revoked_count integer,
  remaining_count integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  delegated_result record;
  run_record public.tenant_ldap_sync_runs%ROWTYPE;
  config_record public.tenant_ldap_provider_configs%ROWTYPE;
  candidate public.tenant_ldap_provider_access_grants%ROWTYPE;
  sessions_revoked integer;
  continuations_revoked integer;
  replay_exists boolean;
BEGIN
  IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200
     OR p_audit_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_user_agent IS NULL
     OR length(p_user_agent) NOT BETWEEN 1 AND 1024 THEN
    RAISE EXCEPTION 'LDAP sync absence chunk input is invalid'
      USING ERRCODE='22023';
  END IF;
  context_tenant:=app.private_lock_tenant_ldap_sync_claim_v2(
    p_sync_run_id,p_claim_id,p_claim_receipt_digest,p_claim_fence,true
  );
  SELECT EXISTS (
    SELECT 1 FROM public.audit_events AS audit
    WHERE audit.tenant_id=context_tenant AND audit.id=p_audit_event_id
      AND audit.action='tenant.identity.ldap_sync_absence_applied'
      AND audit.resource_type='ldap_sync_run'
      AND audit.resource_id=p_sync_run_id AND audit.request_id=p_request_id
      AND audit.correlation_id=p_correlation_id
      AND (audit.metadata->>'limit')::integer=p_limit
  ) INTO STRICT replay_exists;
  IF replay_exists THEN
    SELECT * INTO STRICT delegated_result
    FROM app.apply_tenant_ldap_sync_absence_chunk_v2(
      p_sync_run_id,p_claim_id,p_claim_receipt_digest,p_claim_fence,p_limit,
      p_audit_event_id,p_request_id,p_correlation_id,p_user_agent
    );
    RETURN QUERY SELECT delegated_result.inspected_count,
      delegated_result.revoked_count,delegated_result.remaining_count;
    RETURN;
  END IF;
  SELECT run.* INTO STRICT run_record
  FROM public.tenant_ldap_sync_runs AS run
  WHERE run.tenant_id=context_tenant AND run.id=p_sync_run_id
  FOR UPDATE;
  SELECT configuration.* INTO STRICT config_record
  FROM public.tenant_ldap_provider_configs AS configuration
  WHERE configuration.tenant_id=context_tenant
    AND configuration.provider_id=run_record.provider_id
    AND configuration.version=run_record.configuration_version
  FOR UPDATE;
  IF run_record.status<>'applying' OR NOT run_record.enumeration_complete
     OR run_record.result_truncated
     OR NOT app.private_tenant_ldap_sync_run_is_current_v1(
       context_tenant,p_sync_run_id
     ) THEN
    RAISE EXCEPTION 'LDAP sync absence requires a complete current run'
      USING ERRCODE='40001';
  END IF;
  -- Serialize with root issuance, revalidation and MFA finalization before
  -- selecting the exact access rows that the predecessor will retire.
  PERFORM 1 FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id=context_tenant AND binding.id=run_record.binding_id
    AND binding.provider_id=run_record.provider_id
    AND binding.version=run_record.binding_version
    AND binding.auth_revision=run_record.binding_auth_revision
    AND binding.mapping_revision=run_record.rule_set_revision
    AND binding.current_access_epoch_id=run_record.binding_access_epoch_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'LDAP sync absence binding pins are stale'
      USING ERRCODE='40001';
  END IF;
  -- A genuinely recovered identity leaves a cleared clock. If it later
  -- disappears from a complete inventory, begin a new grace interval before
  -- delegating to the established absence reconciler.
  UPDATE public.tenant_ldap_sync_absences AS absence
  SET first_missing_run_id=p_sync_run_id,latest_missing_run_id=p_sync_run_id,
      status='pending',first_missing_at=transaction_timestamp(),
      apply_after=transaction_timestamp()+make_interval(
        secs=>configuration.deprovision_grace_seconds
      ),resolved_at=NULL,version=absence.version+1
  FROM public.tenant_ldap_sync_runs AS run
  JOIN public.tenant_ldap_provider_configs AS configuration
    ON configuration.tenant_id=run.tenant_id
   AND configuration.provider_id=run.provider_id
   AND configuration.deprovision_mode='grace'
  JOIN public.tenant_ldap_provider_access_grants AS access_grant
    ON access_grant.tenant_id=run.tenant_id
   AND access_grant.binding_id=run.binding_id
   AND access_grant.ended_at IS NULL
  WHERE run.tenant_id=context_tenant AND run.id=p_sync_run_id
    AND run.status='applying' AND run.enumeration_complete
    AND NOT run.result_truncated
    AND absence.tenant_id=context_tenant
    AND absence.binding_id=run.binding_id AND absence.status='cleared'
    AND access_grant.external_identity_id=absence.external_identity_id
    AND NOT EXISTS (
      SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
      WHERE observation.tenant_id=context_tenant
        AND observation.sync_run_id=p_sync_run_id
        AND observation.external_identity_id=absence.external_identity_id
    );
  -- v1 owns the authoritative edge/profile/access/membership transition and
  -- its audit/receipt. Fence the typed LDAP authority for the exact candidate
  -- set before v1 ends each access grant, so its continuation guard can still
  -- prove the live parent. Any later v1 failure rolls these writes back.
  FOR candidate IN
    SELECT access_grant.*
    FROM public.tenant_ldap_provider_access_grants AS access_grant
    WHERE access_grant.tenant_id=context_tenant
      AND access_grant.binding_id=run_record.binding_id
      AND access_grant.provider_id=run_record.provider_id
      AND access_grant.ended_at IS NULL
      AND NOT EXISTS (
        SELECT 1 FROM public.tenant_ldap_sync_staged_observations AS observation
        WHERE observation.tenant_id=context_tenant
          AND observation.sync_run_id=p_sync_run_id
          AND observation.external_identity_id=access_grant.external_identity_id
      ) AND (
        config_record.deprovision_mode='immediate'
        OR (config_record.deprovision_mode='grace' AND EXISTS (
          SELECT 1 FROM public.tenant_ldap_sync_absences AS absence
          WHERE absence.tenant_id=context_tenant
            AND absence.binding_id=run_record.binding_id
            AND absence.external_identity_id=access_grant.external_identity_id
            AND absence.status='pending'
            AND absence.apply_after<=transaction_timestamp()
        ))
      )
    ORDER BY access_grant.id
    FOR UPDATE SKIP LOCKED
    LIMIT p_limit
  LOOP
    UPDATE public.auth_sessions AS session
    SET revoked_at=greatest(transaction_timestamp(),session.created_at),
        revoke_reason='ldap_identity_sync_authoritative_absence'
    WHERE session.user_id=candidate.user_id AND session.revoked_at IS NULL
      AND session.rotation_family_id IN (
        SELECT source_session.rotation_family_id
        FROM public.auth_session_ldap_provenance AS provenance
        JOIN public.auth_sessions AS source_session
          ON source_session.id=provenance.session_id
         AND source_session.user_id=provenance.user_id
        WHERE provenance.tenant_id=context_tenant
          AND provenance.provider_id=run_record.provider_id
          AND provenance.binding_id=run_record.binding_id
          AND provenance.external_identity_id=candidate.external_identity_id
          AND provenance.user_id=candidate.user_id
      );
    GET DIAGNOSTICS sessions_revoked=ROW_COUNT;
    UPDATE public.tenant_post_primary_continuations AS continuation
    SET state='revoked',
        revoked_at=greatest(transaction_timestamp(),continuation.created_at),
        revoke_reason='ldap_identity_sync_authoritative_absence',
        version=continuation.version+1
    WHERE continuation.tenant_id=context_tenant
      AND continuation.user_id=candidate.user_id
      AND continuation.state='pending' AND continuation.revoked_at IS NULL
      AND EXISTS (
        SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
        WHERE provenance.tenant_id=continuation.tenant_id
          AND provenance.continuation_id=continuation.id
          AND provenance.provider_id=run_record.provider_id
          AND provenance.binding_id=run_record.binding_id
          AND provenance.external_identity_id=candidate.external_identity_id
          AND provenance.user_id=candidate.user_id
      );
    GET DIAGNOSTICS continuations_revoked=ROW_COUNT;
    UPDATE public.tenant_mfa_subjects AS subject
    SET session_invalidation_epoch=subject.session_invalidation_epoch+1,
        version=subject.version+1,updated_at=transaction_timestamp()
    WHERE subject.tenant_id=context_tenant AND subject.user_id=candidate.user_id;
    IF (sessions_revoked>0 OR continuations_revoked>0) AND NOT FOUND THEN
      RAISE EXCEPTION 'LDAP absence authority subject is unavailable'
        USING ERRCODE='40001';
    END IF;
  END LOOP;
  SELECT * INTO STRICT delegated_result
  FROM app.apply_tenant_ldap_sync_absence_chunk_v2(
    p_sync_run_id,p_claim_id,p_claim_receipt_digest,p_claim_fence,p_limit,
    p_audit_event_id,p_request_id,p_correlation_id,p_user_agent
  );
  RETURN QUERY SELECT delegated_result.inspected_count,
    delegated_result.revoked_count,delegated_result.remaining_count;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.complete_tenant_ldap_sync_enumeration_v3(
  uuid,uuid,bytea,bigint,integer,boolean,boolean,bytea,text,uuid,uuid,uuid,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v3(
  uuid,uuid,bytea,bigint,integer,uuid,uuid,uuid,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v3(
  uuid,uuid,bytea,bigint,integer,boolean,boolean,bytea,text,uuid,uuid,uuid,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
REVOKE ALL ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v3(
  uuid,uuid,bytea,bigint,integer,uuid,uuid,uuid,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v3(
  uuid,uuid,bytea,bigint,integer,boolean,boolean,bytea,text,uuid,uuid,uuid,text
) TO periapsis_worker;
GRANT EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v3(
  uuid,uuid,bytea,bigint,integer,uuid,uuid,uuid,text
) TO periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.complete_tenant_ldap_sync_enumeration_v2(
  uuid,uuid,bytea,bigint,integer,boolean,boolean,bytea,text,uuid,uuid,uuid,text
) FROM periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.apply_tenant_ldap_sync_absence_chunk_v2(
  uuid,uuid,bytea,bigint,integer,uuid,uuid,uuid,text
) FROM periapsis_worker;
--> statement-breakpoint

CREATE FUNCTION app.private_apply_ldap_session_revalidation_v1(p_mutation jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_session_id uuid;
  v_tenant_id uuid;
  v_user_id uuid;
  v_audience text;
  v_expected_version bigint;
  v_observed_at timestamptz;
  v_authority_at timestamptz;
  v_decision text;
  v_reason text;
  v_request_digest bytea;
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_ldap_provenance%ROWTYPE;
  v_existing public.tenant_federated_session_revalidation_commands%ROWTYPE;
  v_projection jsonb;
  v_evidence jsonb;
  v_has_factor boolean;
  v_assurance_decision text;
  v_reservation jsonb;
  v_new_session_id uuid;
  v_new_family_id uuid;
  v_token_digest bytea;
  v_csrf_digest bytea;
  v_idle_expires_at timestamptz;
  v_absolute_expires_at timestamptz;
  v_continuation_id uuid;
  v_receipt_digest bytea;
  v_continuation_expires_at timestamptz;
  v_token_lock bigint;
  v_csrf_lock bigint;
  v_live_authorization_revision bigint;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_mutation,
    ARRAY['sessionId','tenantId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement',
      'session','continuation'],
    ARRAY['sessionId','tenantId','userId','audience','authenticationMethod',
      'expectedVersion','observedAt','decision','reason','requirement'],262144
  );
  v_session_id:=app.private_mfa_require_uuidv7_v1(p_mutation->>'sessionId');
  v_tenant_id:=app.private_mfa_require_uuidv7_v1(p_mutation->>'tenantId');
  v_user_id:=app.private_mfa_require_uuidv7_v1(p_mutation->>'userId');
  v_audience:=p_mutation->>'audience';
  v_expected_version:=(p_mutation->>'expectedVersion')::bigint;
  v_observed_at:=(p_mutation->>'observedAt')::timestamptz;
  v_authority_at:=greatest(v_observed_at,transaction_timestamp());
  v_decision:=p_mutation->>'decision';
  v_reason:=p_mutation->>'reason';
  IF NOT app.private_mfa_safe_text_v1(v_audience,256)
     OR p_mutation->>'authenticationMethod'<>'ldap'
     OR v_expected_version NOT BETWEEN 1 AND 9007199254740990
     OR (v_decision='step_up' AND v_expected_version>9007199254740989)
     OR v_observed_at IS NULL OR NOT isfinite(v_observed_at)
     OR right(p_mutation->>'observedAt',1)<>'Z'
     OR date_trunc('microseconds',v_observed_at)<>v_observed_at
     OR abs(extract(epoch FROM(transaction_timestamp()-v_observed_at)))>300
     OR jsonb_typeof(p_mutation->'requirement')<>'object'
     OR NOT (
       (v_decision='usable' AND v_reason='current')
       OR (v_decision='rotate' AND v_reason='policy_refresh')
       OR (v_decision='step_up' AND v_reason IN (
         'assurance_insufficient','recovery_restricted'
       ))
       OR (v_decision='revoke' AND v_reason IN (
         'lifecycle','identity_epoch','primary_drift','factor_drift',
         'trust_drift','expired'
       )) OR (v_decision='deny' AND v_reason='malformed')
     )
     OR (v_decision='rotate')<>(p_mutation ? 'session')
     OR (v_decision='step_up')<>(p_mutation ? 'continuation')
     OR (p_mutation ? 'session' AND p_mutation ? 'continuation') THEN
    RAISE EXCEPTION 'invalid LDAP session revalidation mutation'
      USING ERRCODE='22023';
  END IF;

  v_request_digest:=pg_catalog.sha256(pg_catalog.convert_to(
    p_mutation::text,'UTF8'
  ));
  SELECT command.* INTO v_existing
  FROM public.tenant_federated_session_revalidation_commands AS command
  WHERE command.tenant_id=v_tenant_id AND command.session_id=v_session_id
    AND command.expected_version=v_expected_version;
  IF FOUND THEN
    IF v_existing.request_digest IS DISTINCT FROM v_request_digest
       OR v_existing.decision IS DISTINCT FROM v_decision
       OR v_existing.result_snapshot->>'sessionId' IS DISTINCT FROM
            v_session_id::text
       OR v_existing.result_snapshot->>'tenantId' IS DISTINCT FROM
            v_tenant_id::text
       OR (v_existing.result_snapshot->>'expectedVersion')::bigint
            IS DISTINCT FROM v_expected_version
       OR v_existing.result_snapshot->>'decision' IS DISTINCT FROM v_decision
       OR coalesce((v_existing.result_snapshot->>'applied')::boolean,false)
            IS NOT TRUE
       OR (v_decision='rotate' AND (
         v_existing.result_snapshot->>'newSessionId' IS DISTINCT FROM
           p_mutation#>>'{session,sessionId}'
         OR v_existing.result_snapshot ? 'continuationId'
         OR NOT EXISTS (
           SELECT 1
           FROM public.auth_session_ldap_provenance AS provenance
           JOIN public.auth_sessions AS successor
             ON successor.id=provenance.session_id
            AND successor.rotated_from_session_id=v_session_id
           WHERE provenance.tenant_id=v_tenant_id
             AND provenance.session_id=
               (v_existing.result_snapshot->>'newSessionId')::uuid
             AND provenance.user_id=v_user_id
             AND provenance.jit_run_id IS NULL
             AND provenance.source_session_id=v_session_id
             AND provenance.source_session_version=v_expected_version
         )
       ))
       OR (v_decision='step_up' AND (
         v_existing.result_snapshot->>'continuationId' IS DISTINCT FROM
           p_mutation#>>'{continuation,continuationId}'
         OR v_existing.result_snapshot ? 'newSessionId'
         OR NOT EXISTS (
           SELECT 1
           FROM public.tenant_post_primary_ldap_provenance AS provenance
           WHERE provenance.tenant_id=v_tenant_id
             AND provenance.continuation_id=
               (v_existing.result_snapshot->>'continuationId')::uuid
             AND provenance.user_id=v_user_id
             AND provenance.jit_run_id IS NULL
             AND provenance.source_session_id=v_session_id
             AND provenance.source_session_version=v_expected_version+1
         )
       ))
       OR (v_decision NOT IN ('rotate','step_up') AND (
         v_existing.result_snapshot ? 'newSessionId'
         OR v_existing.result_snapshot ? 'continuationId'
       )) THEN
      RAISE EXCEPTION 'LDAP session command replay mismatch'
        USING ERRCODE='40001';
    END IF;
    RETURN v_existing.result_snapshot;
  END IF;

  SELECT provenance.* INTO STRICT v_provenance
  FROM public.auth_session_ldap_provenance AS provenance
  WHERE provenance.tenant_id=v_tenant_id
    AND provenance.session_id=v_session_id AND provenance.user_id=v_user_id;
  SELECT session.* INTO STRICT v_session
  FROM public.auth_sessions AS session
  WHERE session.id=v_session_id AND session.user_id=v_user_id
    AND session.active_tenant_id=v_tenant_id
    AND session.authentication_method='ldap';
  SELECT state.* INTO STRICT v_state
  FROM public.auth_session_mfa_states AS state
  WHERE state.tenant_id=v_tenant_id AND state.session_id=v_session_id
    AND state.user_id=v_user_id AND state.primary_kind='tenant_provider'
    AND state.audience=v_audience AND state.session_version=v_expected_version;
  -- One composite fence is shared by revalidation, MFA finalization and root
  -- issuance.  It follows the authoritative deny lock order and rechecks the
  -- exact session and subject epochs after every wait.
  PERFORM app.private_lock_ldap_primary_authority_v1(
    v_tenant_id,v_user_id,v_provenance.provider_id,v_provenance.binding_id,
    v_provenance.external_identity_id,
    v_provenance.external_identity_revision,v_provenance.provider_version,
    v_provenance.configuration_revision,v_provenance.binding_version,
    v_provenance.binding_auth_revision,v_provenance.rule_set_revision,
    v_provenance.authorization_revision,v_session.id,
    v_session.rotation_family_id,v_state.session_version,
    v_session.absolute_expires_at,v_authority_at,
    v_decision IN ('usable','rotate','step_up'),
    v_decision IN ('usable','rotate','step_up')
  );
  IF v_decision IN ('usable','rotate','step_up') THEN
    SELECT authorization_state.revision
      INTO STRICT v_live_authorization_revision
    FROM public.tenant_authorization_states AS authorization_state
    WHERE authorization_state.tenant_id=v_tenant_id;
    PERFORM app.private_assert_live_ldap_evidence_v1(
      v_tenant_id,v_user_id,'session',v_session_id,
      v_provenance.provider_id,v_provenance.binding_id,
      v_provenance.binding_auth_revision,v_provenance.authenticated_at,
      v_authority_at,NULL
    );
    v_projection:=app.private_load_ldap_session_revalidation_v1(
      jsonb_build_object('sessionId',v_session_id::text,
        'tenantId',v_tenant_id::text,'audience',v_audience)
    );
    IF v_projection IS NULL
       OR coalesce((v_projection#>>'{live,sessionActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,rotationFamilyActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,userActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,tenantActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,membershipActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,primaryActive}')::boolean,false)
            IS NOT TRUE
       OR (v_projection#>>'{live,identityEpoch}')::bigint
            IS DISTINCT FROM v_state.identity_epoch
       OR (v_projection#>>'{live,primaryRevision}')::bigint
            IS DISTINCT FROM v_provenance.external_identity_revision
       OR (v_projection#>>'{live,sessionInvalidationEpoch}')::bigint
            IS DISTINCT FROM v_state.session_invalidation_epoch
       OR jsonb_strip_nulls(p_mutation->'requirement') IS DISTINCT FROM
            jsonb_strip_nulls(v_projection#>'{live,requirement}')
       OR EXISTS (
         SELECT 1 FROM jsonb_array_elements(
           v_projection#>'{live,factors}'
         ) AS factor(value)
         WHERE coalesce((factor.value->>'active')::boolean,false) IS NOT TRUE
       ) OR EXISTS (
         SELECT 1 FROM jsonb_array_elements(
           v_projection#>'{live,trustRules}'
         ) AS trust(value)
         WHERE coalesce((trust.value->>'active')::boolean,false) IS NOT TRUE
       ) THEN
      RAISE EXCEPTION 'LDAP session live authority drifted'
        USING ERRCODE='40001';
    END IF;
    v_evidence:=app.private_mfa_evidence_projection_v1(
      v_tenant_id,'session',v_session_id
    );
    SELECT EXISTS (
      SELECT 1 FROM public.tenant_totp_factors AS factor
      WHERE factor.tenant_id=v_tenant_id AND factor.user_id=v_user_id
        AND factor.status='active'
      UNION ALL
      SELECT 1 FROM public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id=v_tenant_id AND credential.user_id=v_user_id
        AND credential.status='active'
    ) INTO STRICT v_has_factor;
    v_assurance_decision:=app.private_federated_assurance_decision_v1(
      p_mutation->'requirement',v_evidence,v_has_factor,v_authority_at
    );
    IF (v_decision='usable' AND (
          v_state.recovery_restricted
          OR v_live_authorization_revision IS DISTINCT FROM
             v_provenance.authorization_revision
          OR v_assurance_decision IS DISTINCT FROM 'satisfied'
          OR v_projection#>'{snapshot,policyRevisions}' IS DISTINCT FROM
             v_projection#>'{live,requirement,policyRevisions}'
        )) OR (v_decision='rotate' AND (
          v_state.recovery_restricted
          OR v_assurance_decision IS DISTINCT FROM 'satisfied'
          OR v_projection#>'{snapshot,policyRevisions}' IS NOT DISTINCT FROM
             v_projection#>'{live,requirement,policyRevisions}'
        )) OR (v_decision='step_up' AND v_reason='recovery_restricted'
          AND NOT v_state.recovery_restricted)
       OR (v_decision='step_up' AND v_reason='assurance_insufficient'
          AND (v_state.recovery_restricted
            OR v_assurance_decision IS NOT DISTINCT FROM 'satisfied'))
       OR (v_decision='step_up'
          AND jsonb_array_length(v_projection#>'{snapshot,evidence}')>1023) THEN
      RAISE EXCEPTION 'LDAP session decision drifted'
        USING ERRCODE='40001';
    END IF;
  END IF;

  IF v_decision='usable' THEN
    UPDATE public.auth_session_mfa_states AS state
    SET session_version=state.session_version+1
    WHERE state.tenant_id=v_tenant_id AND state.session_id=v_session_id
      AND state.session_version=v_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP session command lost CAS' USING ERRCODE='40001';
    END IF;
  ELSIF v_decision='rotate' THEN
    v_reservation:=p_mutation->'session';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
      ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
        'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],16384
    );
    v_new_session_id:=app.private_mfa_require_uuidv7_v1(
      v_reservation->>'sessionId'
    );
    v_new_family_id:=app.private_mfa_require_uuidv7_v1(
      v_reservation->>'familyId'
    );
    v_token_digest:=app.private_mfa_decode_base64_v1(
      v_reservation->>'tokenDigest',32,32
    );
    v_csrf_digest:=app.private_mfa_decode_base64_v1(
      v_reservation->>'csrfDigest',32,32
    );
    v_idle_expires_at:=(v_reservation->>'idleExpiresAt')::timestamptz;
    v_absolute_expires_at:=(v_reservation->>'absoluteExpiresAt')::timestamptz;
    IF v_new_session_id IN (v_new_family_id,v_session_id)
       OR v_new_family_id IS DISTINCT FROM v_session.rotation_family_id
       OR v_reservation->>'authenticationMethod'<>'ldap'
       OR encode(v_token_digest,'hex')=repeat('00',32)
       OR encode(v_csrf_digest,'hex')=repeat('00',32)
       OR v_token_digest=v_csrf_digest
       OR v_idle_expires_at<=v_authority_at
       OR v_absolute_expires_at IS DISTINCT FROM v_session.absolute_expires_at
       OR v_absolute_expires_at<v_idle_expires_at
       OR v_idle_expires_at>v_authority_at+interval '24 hours'
       OR date_trunc('milliseconds',v_idle_expires_at)<>v_idle_expires_at
       OR date_trunc('milliseconds',v_absolute_expires_at)
            <>v_absolute_expires_at THEN
      RAISE EXCEPTION 'invalid LDAP session rotation reservation'
        USING ERRCODE='22023';
    END IF;
    v_token_lock:=hashtextextended(encode(v_token_digest,'hex'),73124201);
    v_csrf_lock:=hashtextextended(encode(v_csrf_digest,'hex'),73124201);
    PERFORM pg_advisory_xact_lock(least(v_token_lock,v_csrf_lock));
    IF v_token_lock<>v_csrf_lock THEN
      PERFORM pg_advisory_xact_lock(greatest(v_token_lock,v_csrf_lock));
    END IF;
    IF EXISTS (
      SELECT 1 FROM public.auth_sessions AS collision
      WHERE collision.token_digest IN (v_token_digest,v_csrf_digest)
         OR collision.csrf_secret_digest IN (v_token_digest,v_csrf_digest)
    ) THEN
      RAISE EXCEPTION 'LDAP session rotation digest collision'
        USING ERRCODE='40001';
    END IF;
    UPDATE public.auth_sessions AS source_session
    SET revoked_at=v_authority_at,revoke_reason='ldap_session_rotated'
    WHERE source_session.id=v_session_id
      AND source_session.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP session rotation lost CAS' USING ERRCODE='40001';
    END IF;
    INSERT INTO public.auth_sessions (
      id,user_id,rotation_family_id,active_tenant_id,token_digest,
      csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
      idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
    ) VALUES (
      v_new_session_id,v_user_id,v_new_family_id,v_tenant_id,v_token_digest,
      v_csrf_digest,'ldap',v_session.mfa_satisfied_at,v_authority_at,
      v_idle_expires_at,v_absolute_expires_at,v_session_id,v_authority_at
    );
    INSERT INTO public.auth_session_mfa_states (
      session_id,tenant_id,user_id,session_version,identity_epoch,
      recovery_restricted,audience,primary_kind,session_invalidation_epoch,
      issued_at
    ) VALUES (
      v_new_session_id,v_tenant_id,v_user_id,v_expected_version+1,
      v_state.identity_epoch,v_state.recovery_restricted,v_audience,
      'tenant_provider',v_state.session_invalidation_epoch,v_authority_at
    );
    INSERT INTO public.auth_session_ldap_provenance (
      tenant_id,session_id,user_id,jit_run_id,root_jit_run_id,
      source_session_id,source_session_family_id,source_session_version,
      source_absolute_expires_at,primary_kind,authentication_method,
      provider_id,binding_id,external_identity_id,external_identity_revision,
      provider_version,configuration_revision,binding_version,
      binding_auth_revision,rule_set_revision,authorization_revision,
      authenticated_at
    ) VALUES (
      v_tenant_id,v_new_session_id,v_user_id,NULL,v_provenance.root_jit_run_id,
      v_session_id,v_session.rotation_family_id,v_expected_version,
      v_session.absolute_expires_at,'tenant_provider','ldap',
      v_provenance.provider_id,v_provenance.binding_id,
      v_provenance.external_identity_id,v_provenance.external_identity_revision,
      v_provenance.provider_version,v_provenance.configuration_revision,
      v_provenance.binding_version,v_provenance.binding_auth_revision,
      v_provenance.rule_set_revision,v_live_authorization_revision,
      v_provenance.authenticated_at
    );
    INSERT INTO public.auth_session_mfa_policy_pins(
      tenant_id,session_id,policy_id,policy_revision
    ) SELECT v_tenant_id,v_new_session_id,
      (policy.value->>'policyId')::uuid,(policy.value->>'revision')::bigint
    FROM jsonb_array_elements(
      v_projection#>'{live,requirement,policyRevisions}'
    ) AS policy(value);
    INSERT INTO public.auth_session_mfa_evidence(
      id,tenant_id,session_id,local_credential_id,totp_factor_id,
      webauthn_credential_id,recovery_code_set_id,level,kind,provider_id,
      binding_id,authenticated_at,expires_at,factor_revision,
      trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,v_new_session_id,
      evidence.local_credential_id,evidence.totp_factor_id,
      evidence.webauthn_credential_id,evidence.recovery_code_set_id,
      evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,evidence.expires_at,evidence.factor_revision,
      evidence.trust_rule_revision
    FROM public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id=v_tenant_id AND evidence.session_id=v_session_id;
  ELSIF v_decision='step_up' THEN
    v_reservation:=p_mutation->'continuation';
    PERFORM app.private_mfa_assert_json_object_v1(
      v_reservation,ARRAY['continuationId','receiptDigest','expiresAt'],
      ARRAY['continuationId','receiptDigest','expiresAt'],8192
    );
    v_continuation_id:=app.private_mfa_require_uuidv7_v1(
      v_reservation->>'continuationId'
    );
    v_receipt_digest:=app.private_mfa_decode_base64_v1(
      v_reservation->>'receiptDigest',32,32
    );
    v_continuation_expires_at:=(v_reservation->>'expiresAt')::timestamptz;
    IF v_continuation_id=v_session_id
       OR encode(v_receipt_digest,'hex')=repeat('00',32)
       OR v_continuation_expires_at<=v_authority_at
       OR v_continuation_expires_at>v_authority_at+interval '15 minutes'
       OR date_trunc('microseconds',v_continuation_expires_at)
            <>v_continuation_expires_at THEN
      RAISE EXCEPTION 'invalid LDAP step-up continuation reservation'
        USING ERRCODE='22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      encode(v_receipt_digest,'hex'),77191203
    ));
    INSERT INTO public.tenant_post_primary_continuations(
      id,tenant_id,user_id,receipt_digest,identity_epoch,action,audience,
      primary_kind,provider_id,binding_id,provider_kind,external_identity_id,
      primary_revision,session_invalidation_epoch,state,version,created_at,
      expires_at
    ) VALUES (
      v_continuation_id,v_tenant_id,v_user_id,v_receipt_digest,
      v_state.identity_epoch,'session.create',v_audience,'tenant_provider',
      v_provenance.provider_id,v_provenance.binding_id,'ldap',
      v_provenance.external_identity_id,v_provenance.external_identity_revision,
      v_state.session_invalidation_epoch,'pending',1,v_authority_at,
      v_continuation_expires_at
    );
    INSERT INTO public.tenant_post_primary_continuation_policy_pins(
      tenant_id,continuation_id,policy_id,policy_revision
    ) SELECT v_tenant_id,v_continuation_id,
      (policy.value->>'policyId')::uuid,(policy.value->>'revision')::bigint
    FROM jsonb_array_elements(
      v_projection#>'{live,requirement,policyRevisions}'
    ) AS policy(value);
    INSERT INTO public.tenant_post_primary_continuation_evidence(
      id,tenant_id,continuation_id,local_credential_id,totp_factor_id,
      webauthn_credential_id,recovery_code_set_id,level,kind,provider_id,
      binding_id,authenticated_at,expires_at,factor_revision,
      trust_rule_revision
    ) SELECT uuidv7(),evidence.tenant_id,v_continuation_id,
      evidence.local_credential_id,evidence.totp_factor_id,
      evidence.webauthn_credential_id,evidence.recovery_code_set_id,
      evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
      evidence.authenticated_at,
      CASE WHEN evidence.kind='provider' THEN v_continuation_expires_at
        ELSE evidence.expires_at END,
      evidence.factor_revision,
      evidence.trust_rule_revision
    FROM public.auth_session_mfa_evidence AS evidence
    WHERE evidence.tenant_id=v_tenant_id AND evidence.session_id=v_session_id;
    UPDATE public.auth_session_mfa_states AS state
    SET session_version=state.session_version+1
    WHERE state.tenant_id=v_tenant_id AND state.session_id=v_session_id
      AND state.session_version=v_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP session command lost CAS' USING ERRCODE='40001';
    END IF;
    INSERT INTO public.tenant_post_primary_ldap_provenance(
      tenant_id,continuation_id,user_id,jit_run_id,root_jit_run_id,
      source_session_id,source_session_family_id,source_session_version,
      source_absolute_expires_at,provider_id,binding_id,external_identity_id,
      external_identity_revision,provider_version,configuration_revision,
      binding_version,binding_auth_revision,rule_set_revision,
      authorization_revision,authenticated_at
    ) VALUES (
      v_tenant_id,v_continuation_id,v_user_id,NULL,
      v_provenance.root_jit_run_id,v_session_id,v_session.rotation_family_id,
      v_expected_version+1,v_session.absolute_expires_at,
      v_provenance.provider_id,v_provenance.binding_id,
      v_provenance.external_identity_id,v_provenance.external_identity_revision,
      v_provenance.provider_version,v_provenance.configuration_revision,
      v_provenance.binding_version,v_provenance.binding_auth_revision,
      v_provenance.rule_set_revision,v_live_authorization_revision,
      v_provenance.authenticated_at
    );
  ELSE
    UPDATE public.auth_session_mfa_states AS state
    SET session_version=state.session_version+1
    WHERE state.tenant_id=v_tenant_id AND state.session_id=v_session_id
      AND state.session_version=v_expected_version;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP session command lost CAS' USING ERRCODE='40001';
    END IF;
    UPDATE public.auth_sessions AS family
    SET revoked_at=v_authority_at,
        revoke_reason=left('ldap_revalidation_'||v_reason,500)
    WHERE family.user_id=v_user_id
      AND family.rotation_family_id=v_session.rotation_family_id
      AND family.revoked_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP session family is already revoked'
        USING ERRCODE='40001';
    END IF;
  END IF;

  v_result:=jsonb_strip_nulls(jsonb_build_object(
    'sessionId',v_session_id::text,'tenantId',v_tenant_id::text,
    'expectedVersion',v_expected_version,'decision',v_decision,'applied',true,
    'newSessionId',v_new_session_id::text,
    'continuationId',v_continuation_id::text
  ));
  IF pg_column_size(v_result) NOT BETWEEN 2 AND 65536 THEN
    RAISE EXCEPTION 'LDAP session result exceeds bound' USING ERRCODE='54000';
  END IF;
  INSERT INTO public.tenant_federated_session_revalidation_commands(
    tenant_id,session_id,expected_version,request_digest,decision,
    result_snapshot,applied_at
  ) VALUES (
    v_tenant_id,v_session_id,v_expected_version,v_request_digest,v_decision,
    v_result,v_authority_at
  );
  RETURN v_result;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'LDAP session authority is busy' USING ERRCODE='40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'LDAP session authority is unavailable' USING ERRCODE='40001';
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid LDAP session revalidation mutation'
    USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.load_federated_session_revalidation_v1(jsonb)
  RENAME TO load_federated_session_revalidation_pre_ldap_v1;
ALTER FUNCTION app.apply_federated_session_revalidation_v1(jsonb)
  RENAME TO apply_federated_session_revalidation_pre_ldap_v1;
--> statement-breakpoint

CREATE FUNCTION app.load_federated_session_revalidation_v1(p_lookup jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_session_id uuid;
  v_method text;
BEGIN
  v_tenant_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'tenantId');
  v_session_id:=app.private_mfa_require_uuidv7_v1(p_lookup->>'sessionId');
  SELECT session.authentication_method INTO v_method
  FROM public.auth_sessions AS session
  JOIN public.auth_session_mfa_states AS state
    ON state.tenant_id=v_tenant_id AND state.session_id=session.id
   AND state.user_id=session.user_id
   AND state.audience=p_lookup->>'audience'
  WHERE session.id=v_session_id AND session.active_tenant_id=v_tenant_id;
  IF v_method='ldap' THEN
    RETURN app.private_load_ldap_session_revalidation_v1(p_lookup);
  END IF;
  -- Compatibility evidence for the platform-OIDC readiness contract:
  -- private_v34_load_federated_session_revalidation_v1
  -- load_tenant_platform_federated_session_revalidation_v1
  RETURN app.load_federated_session_revalidation_pre_ldap_v1(p_lookup);
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.apply_federated_session_revalidation_v1(p_mutation jsonb)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_tenant_id uuid;
  v_session_id uuid;
  v_user_id uuid;
  v_method text;
BEGIN
  v_tenant_id:=app.private_mfa_require_uuidv7_v1(p_mutation->>'tenantId');
  v_session_id:=app.private_mfa_require_uuidv7_v1(p_mutation->>'sessionId');
  v_user_id:=app.private_mfa_require_uuidv7_v1(p_mutation->>'userId');
  SELECT session.authentication_method INTO v_method
  FROM public.auth_sessions AS session
  JOIN public.auth_session_mfa_states AS state
    ON state.tenant_id=v_tenant_id AND state.session_id=session.id
   AND state.user_id=v_user_id AND state.user_id=session.user_id
   AND state.audience=p_mutation->>'audience'
  WHERE session.id=v_session_id AND session.active_tenant_id=v_tenant_id;
  IF v_method='ldap' THEN
    RETURN app.private_apply_ldap_session_revalidation_v1(p_mutation);
  END IF;
  -- Compatibility evidence for the platform-OIDC readiness contract:
  -- private_v34_apply_federated_session_revalidation_v1
  -- apply_tenant_platform_federated_session_revalidation_v1
  RETURN app.apply_federated_session_revalidation_pre_ldap_v1(p_mutation);
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_load_ldap_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_apply_ldap_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_federated_session_revalidation_pre_ldap_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_federated_session_revalidation_pre_ldap_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.load_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_federated_session_revalidation_v1(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_load_ldap_session_revalidation_v1(jsonb),
  app.private_apply_ldap_session_revalidation_v1(jsonb),
  app.load_federated_session_revalidation_pre_ldap_v1(jsonb),
  app.apply_federated_session_revalidation_pre_ldap_v1(jsonb),
  app.load_federated_session_revalidation_v1(jsonb),
  app.apply_federated_session_revalidation_v1(jsonb)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.load_federated_session_revalidation_v1(jsonb),
  app.apply_federated_session_revalidation_v1(jsonb)
  TO periapsis_api;
--> statement-breakpoint

-- Mapping JIT can advance the tenant authorization revision in the same
-- transaction that admits the identity. Pin session provenance to that
-- post-apply revision, not to the pre-plan planning fence.
ALTER FUNCTION app.issue_tenant_ldap_jit_authority_v1(
  uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,
  uuid,inet,text
) RENAME TO issue_tenant_ldap_jit_authority_pre_revision_v1;
--> statement-breakpoint

DO $function$
DECLARE
  v_definition text;
  v_old constant text:='v_run.authorization_revision';
  v_new constant text:='v_run.result_authorization_revision';
  v_subject_handle_old constant text:='gen_random_bytes(32)';
  v_subject_handle_new constant text:=$new$pg_catalog.sha256(
      pg_catalog.convert_to(
        uuidv7()::text||':'||gen_random_uuid()::text,'UTF8'
      )
    )$new$;
  v_session_evidence_old constant text:=$old$INSERT INTO public.auth_session_mfa_evidence(
      id,tenant_id,session_id,level,kind,provider_id,binding_id,
      authenticated_at,expires_at,trust_rule_revision
    ) VALUES (
      uuidv7(),v_run.tenant_id,v_session_id,'primary','provider',
      v_run.provider_id,v_run.binding_id,p_authenticated_at,v_run.expires_at,
      v_run.binding_auth_revision
    );$old$;
  v_session_evidence_new constant text:=$new$INSERT INTO public.auth_session_mfa_evidence(
      id,tenant_id,session_id,level,kind,provider_id,binding_id,
      authenticated_at,expires_at,trust_rule_revision
    ) VALUES (
      uuidv7(),v_run.tenant_id,v_session_id,'primary','provider',
      v_run.provider_id,v_run.binding_id,p_authenticated_at,
      v_absolute_expires_at,v_run.binding_auth_revision
    );$new$;
  v_continuation_evidence_old constant text:=$old$INSERT INTO public.tenant_post_primary_continuation_evidence(
      id,tenant_id,continuation_id,level,kind,provider_id,binding_id,
      authenticated_at,expires_at,trust_rule_revision
    ) VALUES (
      uuidv7(),v_run.tenant_id,v_continuation_id,'primary','provider',
      v_run.provider_id,v_run.binding_id,p_authenticated_at,v_run.expires_at,
      v_run.binding_auth_revision
    );$old$;
  v_continuation_evidence_new constant text:=$new$INSERT INTO public.tenant_post_primary_continuation_evidence(
      id,tenant_id,continuation_id,level,kind,provider_id,binding_id,
      authenticated_at,expires_at,trust_rule_revision
    ) VALUES (
      uuidv7(),v_run.tenant_id,v_continuation_id,'primary','provider',
      v_run.provider_id,v_run.binding_id,p_authenticated_at,
      v_continuation_expires_at,v_run.binding_auth_revision
    );$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    ('app.issue_tenant_ldap_jit_authority_pre_revision_v1(uuid,bytea,uuid,'
    ||'text,text,timestamp with time zone,timestamp with time zone,text,jsonb,'
    ||'jsonb,uuid,inet,text)')::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM 2*length(v_old) THEN
    RAISE EXCEPTION 'LDAP JIT issuer result pin patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  IF length(v_definition)-length(replace(v_definition,v_subject_handle_old,''))
       IS DISTINCT FROM length(v_subject_handle_old) THEN
    RAISE EXCEPTION 'LDAP JIT subject handle patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  IF length(v_definition)-length(replace(v_definition,v_session_evidence_old,''))
       IS DISTINCT FROM length(v_session_evidence_old)
     OR length(v_definition)-length(replace(
       v_definition,v_continuation_evidence_old,''
     )) IS DISTINCT FROM length(v_continuation_evidence_old) THEN
    RAISE EXCEPTION 'LDAP JIT evidence lifetime patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  v_definition:=replace(v_definition,v_old,v_new);
  v_definition:=replace(
    v_definition,v_subject_handle_old,v_subject_handle_new
  );
  v_definition:=replace(
    v_definition,v_session_evidence_old,v_session_evidence_new
  );
  v_definition:=replace(
    v_definition,v_continuation_evidence_old,v_continuation_evidence_new
  );
  EXECUTE v_definition;
END;
$function$;
--> statement-breakpoint

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
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_run public.tenant_ldap_jit_authentication_runs%ROWTYPE;
  v_application public.tenant_ldap_identity_plan_applications%ROWTYPE;
  v_identity public.tenant_ldap_external_identities%ROWTYPE;
  v_receipt public.tenant_ldap_jit_authority_issuance_receipts%ROWTYPE;
  v_tenant_id uuid;
  v_current_revision bigint;
  v_request_digest bytea;
  v_result jsonb;
BEGIN
  SELECT run.* INTO v_run
  FROM public.tenant_ldap_jit_authentication_runs AS run
  WHERE run.id=p_operation_run_id AND run.receipt_digest=p_receipt_digest
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN app.issue_tenant_ldap_jit_authority_pre_revision_v1(
      p_operation_run_id,p_receipt_digest,p_application_id,p_disposition,
      p_assurance,p_authenticated_at,p_applied_at,p_return_path,p_session,
      p_continuation,p_audit_event_id,p_ip_address,p_user_agent
    );
  END IF;
  v_tenant_id:=v_run.tenant_id;
  PERFORM set_config('app.tenant_id',v_tenant_id::text,true);
  v_request_digest:=pg_catalog.sha256(pg_catalog.convert_to(
    jsonb_build_object(
      'abiVersion',1,
      'operationRunId',p_operation_run_id::text,
      'receiptDigest',encode(p_receipt_digest,'base64'),
      'applicationId',p_application_id::text,
      'disposition',p_disposition,
      'assurance',p_assurance,
      'authenticatedAt',to_jsonb(p_authenticated_at),
      'appliedAt',to_jsonb(p_applied_at),
      'returnPath',p_return_path,
      'sessionIsSqlNull',p_session IS NULL,
      'session',p_session,
      'continuationIsSqlNull',p_continuation IS NULL,
      'continuation',p_continuation,
      'auditEventId',p_audit_event_id::text,
      'ipAddress',p_ip_address::text,
      'userAgent',p_user_agent
    )::text,'UTF8'
  ));
  SELECT receipt.* INTO v_receipt
  FROM public.tenant_ldap_jit_authority_issuance_receipts AS receipt
  WHERE receipt.tenant_id=v_tenant_id
    AND receipt.jit_run_id=p_operation_run_id;
  IF FOUND THEN
    IF v_receipt.request_digest IS DISTINCT FROM v_request_digest
       OR v_receipt.result_snapshot->>'category' IS DISTINCT FROM 'success'
       OR v_receipt.result_snapshot->>'disposition'
            IS DISTINCT FROM p_disposition
       OR v_receipt.result_snapshot->>'returnPath'
            IS DISTINCT FROM p_return_path
       OR coalesce((v_receipt.result_snapshot->>'replayed')::boolean,true)
            IS NOT FALSE
       OR (p_disposition='session' AND (
         v_receipt.result_snapshot->>'sessionId' IS DISTINCT FROM
           p_session->>'sessionId'
         OR v_receipt.result_snapshot->>'continuationId' IS NOT NULL
         OR NOT EXISTS (
           SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
           WHERE provenance.tenant_id=v_tenant_id
             AND provenance.jit_run_id=p_operation_run_id
             AND provenance.session_id=
               (v_receipt.result_snapshot->>'sessionId')::uuid
         )
       )) OR (p_disposition='continuation' AND (
         v_receipt.result_snapshot->>'continuationId' IS DISTINCT FROM
           p_continuation->>'continuationId'
         OR v_receipt.result_snapshot->>'sessionId' IS NOT NULL
         OR NOT EXISTS (
           SELECT 1
           FROM public.tenant_post_primary_ldap_provenance AS provenance
           WHERE provenance.tenant_id=v_tenant_id
             AND provenance.jit_run_id=p_operation_run_id
             AND provenance.continuation_id=
               (v_receipt.result_snapshot->>'continuationId')::uuid
         )
       )) THEN
      RAISE EXCEPTION 'LDAP authority issuance replay mismatch'
        USING ERRCODE='40001';
    END IF;
    RETURN jsonb_set(
      v_receipt.result_snapshot,'{replayed}','true'::jsonb,false
    );
  END IF;
  IF EXISTS (
       SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
       WHERE provenance.tenant_id=v_tenant_id
         AND provenance.jit_run_id=p_operation_run_id
     ) OR EXISTS (
       SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
       WHERE provenance.tenant_id=v_tenant_id
         AND provenance.jit_run_id=p_operation_run_id
     ) THEN
    RAISE EXCEPTION 'LDAP authority issuance receipt is unavailable'
      USING ERRCODE='40001';
  END IF;
  IF NOT EXISTS (
       SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
       WHERE provenance.tenant_id=v_tenant_id
         AND provenance.jit_run_id=p_operation_run_id
     ) AND NOT EXISTS (
       SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
       WHERE provenance.tenant_id=v_tenant_id
         AND provenance.jit_run_id=p_operation_run_id
     ) THEN
    SELECT state.revision INTO v_current_revision
    FROM public.tenant_authorization_states AS state
    WHERE state.tenant_id=v_tenant_id AND state.initialized_at IS NOT NULL
    FOR UPDATE;
    IF v_current_revision IS NULL THEN
      RAISE EXCEPTION 'initialized tenant authorization state is required'
        USING ERRCODE='42501';
    END IF;
    IF v_current_revision IS DISTINCT FROM v_run.result_authorization_revision
       OR v_run.status<>'succeeded'
       OR v_run.application_id IS DISTINCT FROM p_application_id THEN
      RAISE EXCEPTION 'LDAP authority revision pin is stale'
        USING ERRCODE='40001';
    END IF;
    SELECT application.* INTO STRICT v_application
    FROM public.tenant_ldap_identity_plan_applications AS application
    WHERE application.tenant_id=v_tenant_id
      AND application.id=p_application_id
      AND application.apply_mode='jit' AND application.decision='admitted'
      AND application.provider_id=v_run.provider_id
      AND application.binding_id=v_run.binding_id
      AND application.external_identity_id IS NOT NULL
      AND application.user_id IS NOT NULL
      AND application.membership_id IS NOT NULL
      AND application.access_grant_id IS NOT NULL;
    SELECT identity.* INTO STRICT v_identity
    FROM public.tenant_ldap_external_identities AS identity
    WHERE identity.tenant_id=v_tenant_id
      AND identity.provider_id=v_run.provider_id
      AND identity.id=v_application.external_identity_id
      AND identity.user_id=v_application.user_id
      AND identity.retired_at IS NULL;
    PERFORM app.private_lock_ldap_primary_authority_v1(
      v_tenant_id,v_identity.user_id,v_run.provider_id,v_run.binding_id,
      v_identity.id,v_identity.version,v_run.provider_version,
      v_run.configuration_version,v_run.binding_version,
      v_run.binding_auth_revision,v_run.rule_set_revision,
      v_run.result_authorization_revision,NULL,NULL,NULL,NULL,
      greatest(p_applied_at,transaction_timestamp()),true,false
    );
  END IF;
  v_result:=app.issue_tenant_ldap_jit_authority_pre_revision_v1(
    p_operation_run_id,p_receipt_digest,p_application_id,p_disposition,
    p_assurance,p_authenticated_at,p_applied_at,p_return_path,p_session,
    p_continuation,p_audit_event_id,p_ip_address,p_user_agent
  );
  IF jsonb_typeof(v_result) IS DISTINCT FROM 'object'
     OR v_result->>'category' IS DISTINCT FROM 'success'
     OR v_result->>'disposition' IS DISTINCT FROM p_disposition
     OR v_result->>'returnPath' IS DISTINCT FROM p_return_path
     OR coalesce((v_result->>'replayed')::boolean,true) IS NOT FALSE
     OR pg_column_size(v_result) NOT BETWEEN 2 AND 65536 THEN
    RAISE EXCEPTION 'LDAP authority issuance result is invalid'
      USING ERRCODE='40001';
  END IF;
  INSERT INTO public.tenant_ldap_jit_authority_issuance_receipts(
    tenant_id,jit_run_id,request_digest,result_snapshot,created_at
  ) VALUES (
    v_tenant_id,p_operation_run_id,v_request_digest,v_result,
    transaction_timestamp()
  );
  RETURN v_result;
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.issue_tenant_ldap_jit_authority_pre_revision_v1(
  uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,
  uuid,inet,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.issue_tenant_ldap_jit_authority_v1(
  uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,
  uuid,inet,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.issue_tenant_ldap_jit_authority_pre_revision_v1(
  uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,
  uuid,inet,text
),app.issue_tenant_ldap_jit_authority_v1(
  uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,
  uuid,inet,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.issue_tenant_ldap_jit_authority_v1(
  uuid,bytea,uuid,text,text,timestamptz,timestamptz,text,jsonb,jsonb,
  uuid,inet,text
) TO periapsis_api;
--> statement-breakpoint

-- The shared MFA resolver and terminal writer historically understood only
-- OIDC/SAML tenant-provider provenance.  Keep that implementation private and
-- route the physically separate LDAP lineage without manufacturing a
-- federated row.
CREATE FUNCTION app.private_lock_ldap_primary_authority_v1(
  p_tenant_id uuid,p_user_id uuid,p_provider_id uuid,p_binding_id uuid,
  p_external_identity_id uuid,p_external_identity_revision bigint,
  p_provider_version integer,p_configuration_revision integer,
  p_binding_version integer,p_binding_auth_revision integer,
  p_rule_set_revision bigint,p_authorization_revision bigint,
  p_source_session_id uuid,p_source_session_family_id uuid,
  p_source_session_version bigint,p_source_absolute_expires_at timestamptz,
  p_authority_at timestamptz,p_require_live boolean,
  p_allow_authorization_refresh boolean
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_allow_authorization_refresh AND NOT p_require_live THEN
    RAISE EXCEPTION 'LDAP MFA authorization refresh requires live authority'
      USING ERRCODE='22023';
  END IF;
  PERFORM app.private_mfa_lock_policy_authority_v1(p_tenant_id);
  PERFORM 1 FROM public.tenant_auth_provider_bindings AS binding
  WHERE binding.tenant_id=p_tenant_id AND binding.id=p_binding_id
    AND binding.provider_id=p_provider_id
    AND (NOT p_require_live OR (
      binding.enabled AND binding.archived_at IS NULL
      AND binding.version=p_binding_version
      AND binding.auth_revision=p_binding_auth_revision
      AND binding.mapping_revision=p_rule_set_revision
    ))
  FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA binding authority is stale'
    USING ERRCODE='40001'; END IF;
  PERFORM 1 FROM public.tenant_auth_providers AS provider
  JOIN public.tenants AS tenant ON tenant.id=provider.tenant_id
  WHERE provider.tenant_id=p_tenant_id AND provider.id=p_provider_id
    AND provider.kind='ldap'
    AND (NOT p_require_live OR (
      provider.enabled AND provider.archived_at IS NULL
      AND provider.version=p_provider_version AND tenant.status='active'
    ))
  FOR SHARE OF provider,tenant NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA provider authority is stale'
    USING ERRCODE='40001'; END IF;
  PERFORM 1 FROM public.tenant_ldap_provider_configs AS configuration
  WHERE configuration.tenant_id=p_tenant_id
    AND configuration.provider_id=p_provider_id
    AND (NOT p_require_live OR (
      configuration.version=p_configuration_revision
      AND configuration.jit_mode<>'disabled'
    ))
  FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA configuration authority is stale'
    USING ERRCODE='40001'; END IF;
  PERFORM 1 FROM public.tenant_ldap_external_identities AS identity
  WHERE identity.tenant_id=p_tenant_id AND identity.provider_id=p_provider_id
    AND identity.id=p_external_identity_id AND identity.user_id=p_user_id
    AND (NOT p_require_live OR (
      identity.version=p_external_identity_revision
      AND identity.retired_at IS NULL
    ))
  FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA identity authority is stale'
    USING ERRCODE='40001'; END IF;
  PERFORM 1 FROM public.tenant_memberships AS membership
  JOIN public.users AS local_user
    ON local_user.id=membership.user_id
  WHERE membership.tenant_id=p_tenant_id AND membership.user_id=p_user_id
    AND (NOT p_require_live OR (
      membership.status='active' AND local_user.active
    ))
  FOR SHARE OF membership,local_user NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA membership authority is stale'
    USING ERRCODE='40001'; END IF;
  PERFORM 1
  FROM public.tenant_ldap_provider_access_grants AS access_grant
  JOIN public.tenant_auth_provider_bindings AS binding
    ON binding.tenant_id=access_grant.tenant_id
   AND binding.id=access_grant.binding_id
   AND binding.provider_id=access_grant.provider_id
  JOIN public.tenant_identity_provider_access_epochs AS access_epoch
    ON access_epoch.tenant_id=access_grant.tenant_id
   AND access_epoch.id=access_grant.access_epoch_id
   AND access_epoch.binding_id=access_grant.binding_id
   AND access_epoch.provider_id=access_grant.provider_id
   AND access_epoch.source_id=access_grant.source_id
  JOIN public.tenant_authorization_sources AS access_source
    ON access_source.tenant_id=access_grant.tenant_id
   AND access_source.id=access_grant.source_id
   AND access_source.kind='identity_provider_access'
  WHERE access_grant.tenant_id=p_tenant_id
    AND access_grant.provider_id=p_provider_id
    AND access_grant.binding_id=p_binding_id
    AND access_grant.external_identity_id=p_external_identity_id
    AND access_grant.user_id=p_user_id
    AND (NOT p_require_live OR (
      access_grant.ended_at IS NULL
      AND access_grant.configuration_version=p_configuration_revision
      AND access_grant.access_epoch_id=binding.current_access_epoch_id
      AND access_epoch.ended_at IS NULL
      AND access_source.authoritative AND NOT access_source.protected
      AND access_source.retired_at IS NULL
    ))
  FOR SHARE OF access_grant,access_epoch,access_source NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA access authority is stale'
    USING ERRCODE='40001'; END IF;
  PERFORM 1 FROM public.tenant_authorization_states AS authorization_state
  WHERE authorization_state.tenant_id=p_tenant_id
    AND (NOT p_require_live OR p_allow_authorization_refresh
      OR authorization_state.revision=p_authorization_revision)
  FOR SHARE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA authorization is stale'
    USING ERRCODE='40001'; END IF;
  IF p_source_session_id IS NOT NULL THEN
    PERFORM 1
    FROM public.auth_sessions AS source_session
    JOIN public.auth_session_mfa_states AS source_state
      ON source_state.tenant_id=p_tenant_id
     AND source_state.session_id=source_session.id
     AND source_state.user_id=p_user_id
     AND source_state.primary_kind='tenant_provider'
     AND source_state.session_version=p_source_session_version
    JOIN public.auth_session_ldap_provenance AS source_provenance
      ON source_provenance.tenant_id=source_state.tenant_id
     AND source_provenance.session_id=source_state.session_id
     AND source_provenance.user_id=source_state.user_id
     AND source_provenance.provider_id=p_provider_id
     AND source_provenance.binding_id=p_binding_id
     AND source_provenance.external_identity_id=p_external_identity_id
     AND source_provenance.external_identity_revision=
       p_external_identity_revision
     AND source_provenance.provider_version=p_provider_version
     AND source_provenance.configuration_revision=p_configuration_revision
     AND source_provenance.binding_version=p_binding_version
     AND source_provenance.binding_auth_revision=p_binding_auth_revision
     AND source_provenance.rule_set_revision=p_rule_set_revision
     AND source_provenance.authorization_revision=p_authorization_revision
    WHERE source_session.id=p_source_session_id
      AND source_session.user_id=p_user_id
      AND source_session.active_tenant_id=p_tenant_id
      AND source_session.authentication_method='ldap'
      AND source_session.rotation_family_id=p_source_session_family_id
      AND source_session.absolute_expires_at=p_source_absolute_expires_at
      AND (NOT p_require_live OR (
        source_session.revoked_at IS NULL
        AND source_session.idle_expires_at>p_authority_at
        AND source_session.absolute_expires_at>p_authority_at
      ))
    FOR UPDATE OF source_session,source_state NOWAIT
    FOR SHARE OF source_provenance NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA source session is stale'
      USING ERRCODE='40001'; END IF;
    PERFORM 1
    FROM public.tenant_mfa_subjects AS subject
    JOIN public.auth_session_mfa_states AS source_state
      ON source_state.tenant_id=subject.tenant_id
     AND source_state.user_id=subject.user_id
     AND source_state.session_id=p_source_session_id
     AND source_state.primary_kind='tenant_provider'
     AND source_state.session_version=p_source_session_version
     AND (NOT p_require_live OR (
       source_state.identity_epoch=subject.identity_epoch
       AND source_state.session_invalidation_epoch=
         subject.session_invalidation_epoch
     ))
    WHERE subject.tenant_id=p_tenant_id AND subject.user_id=p_user_id
    FOR SHARE OF subject NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA subject authority is stale'
      USING ERRCODE='40001'; END IF;
  ELSIF p_source_session_family_id IS NOT NULL
     OR p_source_session_version IS NOT NULL
     OR p_source_absolute_expires_at IS NOT NULL THEN
    RAISE EXCEPTION 'LDAP MFA source lineage is incomplete'
      USING ERRCODE='23514';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'LDAP MFA authority is busy' USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

-- LDAP anchors deliberately contain one provider evidence row in addition to
-- any local MFA factors.  The generic passkey assertion rejects provider
-- evidence, so validate and lock the LDAP evidence graph explicitly.  The
-- primary provider/binding/identity authority must already be locked by
-- private_lock_ldap_primary_authority_v1 before this function is called.
CREATE FUNCTION app.private_assert_live_ldap_evidence_row_v1(
  p_tenant_id uuid,p_user_id uuid,p_provider_id uuid,p_binding_id uuid,
  p_binding_auth_revision bigint,p_primary_authenticated_at timestamptz,
  p_authority_at timestamptz,p_level text,p_kind text,
  p_local_credential_id uuid,p_totp_factor_id uuid,
  p_webauthn_credential_id uuid,p_recovery_code_set_id uuid,
  p_row_provider_id uuid,p_row_binding_id uuid,
  p_authenticated_at timestamptz,p_expires_at timestamptz,
  p_factor_revision bigint,p_trust_rule_revision bigint,
  p_transition_webauthn_id uuid,p_replaced_recovery_set_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_kind='provider' THEN
    IF p_level<>'primary'
       OR p_row_provider_id IS DISTINCT FROM p_provider_id
       OR p_row_binding_id IS DISTINCT FROM p_binding_id
       OR p_trust_rule_revision IS DISTINCT FROM p_binding_auth_revision
       OR p_authenticated_at IS DISTINCT FROM p_primary_authenticated_at
       OR p_expires_at IS NULL THEN
      RAISE EXCEPTION 'LDAP MFA provider evidence drifted'
        USING ERRCODE='40001';
    END IF;
  ELSIF p_kind='local_credential' THEN
    PERFORM 1 FROM public.local_break_glass_credentials AS factor
    WHERE factor.id=p_local_credential_id AND factor.user_id=p_user_id
      AND factor.disabled_at IS NULL
      AND factor.password_version=p_factor_revision
    FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA local evidence drifted'
      USING ERRCODE='40001'; END IF;
  ELSIF p_kind='totp' THEN
    PERFORM 1 FROM public.tenant_totp_factors AS factor
    WHERE factor.tenant_id=p_tenant_id AND factor.user_id=p_user_id
      AND factor.id=p_totp_factor_id AND factor.status='active'
      AND factor.security_revision=p_factor_revision
    FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA TOTP evidence drifted'
      USING ERRCODE='40001'; END IF;
  ELSIF p_kind='webauthn' THEN
    IF p_webauthn_credential_id IS DISTINCT FROM p_transition_webauthn_id THEN
      PERFORM 1 FROM public.tenant_webauthn_credentials AS credential
      WHERE credential.tenant_id=p_tenant_id AND credential.user_id=p_user_id
        AND credential.id=p_webauthn_credential_id
        AND credential.status='active'
        AND credential.security_revision=p_factor_revision
      FOR SHARE NOWAIT;
      IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA WebAuthn evidence drifted'
        USING ERRCODE='40001'; END IF;
    END IF;
  ELSIF p_kind='recovery' THEN
    IF p_recovery_code_set_id IS DISTINCT FROM p_replaced_recovery_set_id THEN
      PERFORM 1 FROM public.tenant_recovery_code_sets AS code_set
      WHERE code_set.tenant_id=p_tenant_id AND code_set.user_id=p_user_id
        AND code_set.id=p_recovery_code_set_id AND code_set.status='active'
        AND code_set.security_revision=p_factor_revision
      FOR SHARE NOWAIT;
      IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA recovery evidence drifted'
        USING ERRCODE='40001'; END IF;
    END IF;
  ELSE
    RAISE EXCEPTION 'LDAP MFA evidence kind is unsupported'
      USING ERRCODE='40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'LDAP MFA factor evidence is busy' USING ERRCODE='40001';
END;
$function$;

CREATE FUNCTION app.private_assert_live_ldap_evidence_v1(
  p_tenant_id uuid,p_user_id uuid,p_source_kind text,p_source_id uuid,
  p_provider_id uuid,p_binding_id uuid,p_binding_auth_revision bigint,
  p_primary_authenticated_at timestamptz,p_authority_at timestamptz,
  p_transition_webauthn_id uuid DEFAULT NULL,
  p_replaced_recovery_set_id uuid DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_evidence record;
  v_evidence_count bigint;
  v_provider_count bigint;
BEGIN
  IF p_source_kind='anchor' THEN
    PERFORM 1 FROM public.tenant_mfa_authority_anchors AS anchor
    WHERE anchor.tenant_id=p_tenant_id AND anchor.id=p_source_id
      AND anchor.user_id=p_user_id
    FOR SHARE NOWAIT;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA evidence anchor is stale'
      USING ERRCODE='40001'; END IF;
    SELECT count(*),count(*) FILTER (WHERE locked.kind='provider')
      INTO STRICT v_evidence_count,v_provider_count
    FROM (
      SELECT evidence.*
      FROM public.tenant_mfa_authority_evidence AS evidence
      WHERE evidence.tenant_id=p_tenant_id AND evidence.anchor_id=p_source_id
      FOR SHARE NOWAIT
    ) AS locked;
    FOR v_evidence IN
      SELECT evidence.*
      FROM public.tenant_mfa_authority_evidence AS evidence
      WHERE evidence.tenant_id=p_tenant_id AND evidence.anchor_id=p_source_id
      ORDER BY evidence.id
    LOOP
      PERFORM app.private_assert_live_ldap_evidence_row_v1(
        p_tenant_id,p_user_id,p_provider_id,p_binding_id,
        p_binding_auth_revision,p_primary_authenticated_at,p_authority_at,
        v_evidence.level,v_evidence.kind,v_evidence.local_credential_id,
        v_evidence.totp_factor_id,v_evidence.webauthn_credential_id,
        v_evidence.recovery_code_set_id,v_evidence.provider_id,
        v_evidence.binding_id,v_evidence.authenticated_at,
        v_evidence.expires_at,v_evidence.factor_revision,
        v_evidence.trust_rule_revision,p_transition_webauthn_id,
        p_replaced_recovery_set_id
      );
    END LOOP;
  ELSIF p_source_kind='session' THEN
    SELECT count(*),count(*) FILTER (WHERE locked.kind='provider')
      INTO STRICT v_evidence_count,v_provider_count
    FROM (
      SELECT evidence.*
      FROM public.auth_session_mfa_evidence AS evidence
      WHERE evidence.tenant_id=p_tenant_id AND evidence.session_id=p_source_id
      FOR SHARE NOWAIT
    ) AS locked;
    FOR v_evidence IN
      SELECT evidence.*
      FROM public.auth_session_mfa_evidence AS evidence
      WHERE evidence.tenant_id=p_tenant_id AND evidence.session_id=p_source_id
      ORDER BY evidence.id
    LOOP
      PERFORM app.private_assert_live_ldap_evidence_row_v1(
        p_tenant_id,p_user_id,p_provider_id,p_binding_id,
        p_binding_auth_revision,p_primary_authenticated_at,p_authority_at,
        v_evidence.level,v_evidence.kind,v_evidence.local_credential_id,
        v_evidence.totp_factor_id,v_evidence.webauthn_credential_id,
        v_evidence.recovery_code_set_id,v_evidence.provider_id,
        v_evidence.binding_id,v_evidence.authenticated_at,
        v_evidence.expires_at,v_evidence.factor_revision,
        v_evidence.trust_rule_revision,p_transition_webauthn_id,
        p_replaced_recovery_set_id
      );
    END LOOP;
  ELSE
    RAISE EXCEPTION 'invalid LDAP MFA evidence source' USING ERRCODE='22023';
  END IF;
  IF v_evidence_count NOT BETWEEN 1 AND 1024 OR v_provider_count<>1 THEN
    RAISE EXCEPTION 'LDAP MFA evidence is unavailable or ambiguous'
      USING ERRCODE='40001';
  END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'LDAP MFA evidence is busy' USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_resolve_ldap_mfa_authority_v1(
  p_reference_id uuid,p_flow text,p_action text,p_audience text,
  p_evaluated_at timestamptz,p_continuation_receipt_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_result jsonb;
  v_session public.auth_sessions%ROWTYPE;
  v_state public.auth_session_mfa_states%ROWTYPE;
  v_provenance public.auth_session_ldap_provenance%ROWTYPE;
  v_continuation public.tenant_post_primary_continuations%ROWTYPE;
  v_continuation_provenance
    public.tenant_post_primary_ldap_provenance%ROWTYPE;
  v_projection jsonb;
  v_origin text;
  v_authority_at timestamptz:=greatest(p_evaluated_at,transaction_timestamp());
BEGIN
  v_result:=app.resolve_mfa_authority_v1(
    p_reference_id,p_flow,p_action,p_audience,v_authority_at
  );
  IF p_flow='session' THEN
    IF p_continuation_receipt_digest IS NOT NULL THEN
      RAISE EXCEPTION 'continuation receipt is forbidden'
        USING ERRCODE='22023';
    END IF;
    SELECT session.* INTO STRICT v_session
    FROM public.auth_sessions AS session
    WHERE session.id=p_reference_id AND session.authentication_method='ldap'
      AND session.revoked_at IS NULL
      AND session.idle_expires_at>v_authority_at
      AND session.absolute_expires_at>v_authority_at;
    SELECT state.* INTO STRICT v_state
    FROM public.auth_session_mfa_states AS state
    WHERE state.tenant_id=v_session.active_tenant_id
      AND state.session_id=v_session.id AND state.user_id=v_session.user_id
      AND state.primary_kind='tenant_provider';
    SELECT provenance.* INTO STRICT v_provenance
    FROM public.auth_session_ldap_provenance AS provenance
    WHERE provenance.tenant_id=v_session.active_tenant_id
      AND provenance.session_id=v_session.id
      AND provenance.user_id=v_session.user_id;
    v_projection:=app.private_load_ldap_session_revalidation_v1(
      jsonb_build_object('sessionId',v_session.id::text,
        'tenantId',v_session.active_tenant_id::text,'audience',p_audience)
    );
    IF v_projection IS NULL
       OR coalesce((v_projection#>>'{live,sessionActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,rotationFamilyActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,userActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,tenantActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,membershipActive}')::boolean,false)
            IS NOT TRUE
       OR coalesce((v_projection#>>'{live,primaryActive}')::boolean,false)
            IS NOT TRUE
       OR (v_projection#>>'{live,identityEpoch}')::bigint
            IS DISTINCT FROM v_state.identity_epoch
       OR (v_projection#>>'{live,sessionInvalidationEpoch}')::bigint
            IS DISTINCT FROM v_state.session_invalidation_epoch
       OR (v_projection#>>'{live,primaryRevision}')::bigint
            IS DISTINCT FROM v_provenance.external_identity_revision THEN
      RAISE EXCEPTION 'LDAP MFA live authority is unavailable'
        USING ERRCODE='42501';
    END IF;
    RETURN v_result||jsonb_build_object(
      'primaryKind','tenant_provider','continuationOrigin','session_rotation',
      'authenticationMethod','ldap','providerKind','ldap',
      'providerId',v_provenance.provider_id::text,
      'bindingId',v_provenance.binding_id::text,
      'externalIdentityId',v_provenance.external_identity_id::text,
      'externalIdentityRevision',v_provenance.external_identity_revision,
      'providerRevision',v_provenance.provider_version,
      'configurationRevision',v_provenance.configuration_revision,
      'bindingRevision',v_provenance.binding_version,
      'authorizationRevision',v_provenance.authorization_revision,
      'sourceSessionId',v_session.id::text,
      'sourceSessionFamilyId',v_session.rotation_family_id::text,
      'sourceSessionVersion',v_state.session_version,
      'sourceAbsoluteExpiresAt',v_session.absolute_expires_at
    );
  ELSIF p_flow='continuation' THEN
    IF p_continuation_receipt_digest IS NULL
       OR octet_length(p_continuation_receipt_digest)<>32
       OR encode(p_continuation_receipt_digest,'hex')=repeat('00',32) THEN
      RAISE EXCEPTION 'continuation receipt is required'
        USING ERRCODE='42501';
    END IF;
    SELECT continuation.* INTO STRICT v_continuation
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.id=p_reference_id
      AND continuation.receipt_digest=p_continuation_receipt_digest
      AND continuation.primary_kind='tenant_provider'
      AND continuation.provider_kind='ldap'
      AND continuation.state='pending'
      AND continuation.expires_at>v_authority_at;
    SELECT provenance.* INTO STRICT v_continuation_provenance
    FROM public.tenant_post_primary_ldap_provenance AS provenance
    WHERE provenance.tenant_id=v_continuation.tenant_id
      AND provenance.continuation_id=v_continuation.id
      AND provenance.user_id=v_continuation.user_id
      AND provenance.provider_id=v_continuation.provider_id
      AND provenance.binding_id=v_continuation.binding_id
      AND provenance.external_identity_id=v_continuation.external_identity_id
      AND provenance.external_identity_revision=v_continuation.primary_revision;
    v_origin:=CASE WHEN v_continuation_provenance.jit_run_id IS NULL
      THEN 'session_revalidation' ELSE 'initial_login' END;
    IF v_origin='session_revalidation' THEN
      v_projection:=app.private_load_ldap_session_revalidation_v1(
        jsonb_build_object(
          'sessionId',v_continuation_provenance.source_session_id::text,
          'tenantId',v_continuation.tenant_id::text,'audience',p_audience)
      );
      IF v_projection IS NULL
         OR (v_projection#>>'{snapshot,version}')::bigint IS DISTINCT FROM
              v_continuation_provenance.source_session_version
       OR v_projection#>>'{snapshot,rotationFamilyId}' IS DISTINCT FROM
              v_continuation_provenance.source_session_family_id::text
         OR (v_projection#>>'{snapshot,absoluteExpiresAt}')::timestamptz
              IS DISTINCT FROM
              v_continuation_provenance.source_absolute_expires_at
         OR coalesce((v_projection#>>'{live,sessionActive}')::boolean,false)
              IS NOT TRUE
         OR coalesce((v_projection#>>'{live,rotationFamilyActive}')::boolean,false)
              IS NOT TRUE
         OR coalesce((v_projection#>>'{live,userActive}')::boolean,false)
              IS NOT TRUE
         OR coalesce((v_projection#>>'{live,tenantActive}')::boolean,false)
              IS NOT TRUE
         OR coalesce((v_projection#>>'{live,membershipActive}')::boolean,false)
              IS NOT TRUE
         OR coalesce((v_projection#>>'{live,primaryActive}')::boolean,false)
              IS NOT TRUE
         OR (v_projection#>>'{live,identityEpoch}')::bigint
              IS DISTINCT FROM
                (v_projection#>>'{snapshot,identityEpoch}')::bigint
         OR (v_projection#>>'{live,sessionInvalidationEpoch}')::bigint
              IS DISTINCT FROM
                (v_projection#>>'{snapshot,primary,sessionInvalidationEpoch}')::bigint
         OR (v_projection#>>'{live,primaryRevision}')::bigint
              IS DISTINCT FROM
                v_continuation_provenance.external_identity_revision THEN
        RAISE EXCEPTION 'LDAP MFA continuation source is stale'
          USING ERRCODE='42501';
      END IF;
    ELSIF NOT EXISTS (
      SELECT 1
      FROM public.tenant_auth_provider_bindings AS binding
      JOIN public.tenant_auth_providers AS provider
        ON provider.tenant_id=binding.tenant_id
       AND provider.id=binding.provider_id AND provider.kind='ldap'
       AND provider.enabled AND provider.archived_at IS NULL
       AND provider.version=v_continuation_provenance.provider_version
      JOIN public.tenants AS tenant
        ON tenant.id=provider.tenant_id AND tenant.status='active'
      JOIN public.tenant_ldap_provider_configs AS configuration
        ON configuration.tenant_id=provider.tenant_id
       AND configuration.provider_id=provider.id
       AND configuration.version=
         v_continuation_provenance.configuration_revision
       AND configuration.jit_mode<>'disabled'
      JOIN public.tenant_ldap_external_identities AS identity
        ON identity.tenant_id=provider.tenant_id
       AND identity.provider_id=provider.id
       AND identity.id=v_continuation_provenance.external_identity_id
       AND identity.user_id=v_continuation.user_id
       AND identity.version=
         v_continuation_provenance.external_identity_revision
       AND identity.retired_at IS NULL
      JOIN public.users AS local_user
        ON local_user.id=v_continuation.user_id AND local_user.active
      JOIN public.tenant_memberships AS membership
        ON membership.tenant_id=provider.tenant_id
       AND membership.user_id=v_continuation.user_id
       AND membership.status='active'
      JOIN public.tenant_ldap_provider_access_grants AS access_grant
        ON access_grant.tenant_id=binding.tenant_id
       AND access_grant.provider_id=provider.id
       AND access_grant.binding_id=binding.id
       AND access_grant.external_identity_id=identity.id
       AND access_grant.user_id=v_continuation.user_id
       AND access_grant.configuration_version=configuration.version
       AND access_grant.ended_at IS NULL
      JOIN public.tenant_identity_provider_access_epochs AS access_epoch
        ON access_epoch.tenant_id=access_grant.tenant_id
       AND access_epoch.id=access_grant.access_epoch_id
       AND access_epoch.binding_id=access_grant.binding_id
       AND access_epoch.provider_id=access_grant.provider_id
       AND access_epoch.source_id=access_grant.source_id
       AND access_epoch.ended_at IS NULL
      JOIN public.tenant_authorization_sources AS access_source
        ON access_source.tenant_id=access_grant.tenant_id
       AND access_source.id=access_grant.source_id
       AND access_source.kind='identity_provider_access'
       AND access_source.authoritative AND NOT access_source.protected
       AND access_source.retired_at IS NULL
      JOIN public.tenant_authorization_states AS authorization_state
        ON authorization_state.tenant_id=provider.tenant_id
       AND authorization_state.revision=
         v_continuation_provenance.authorization_revision
      WHERE binding.tenant_id=v_continuation.tenant_id
        AND binding.id=v_continuation_provenance.binding_id
        AND binding.enabled AND binding.archived_at IS NULL
        AND binding.version=v_continuation_provenance.binding_version
        AND binding.auth_revision=
          v_continuation_provenance.binding_auth_revision
        AND binding.mapping_revision=
          v_continuation_provenance.rule_set_revision
        AND binding.current_access_epoch_id=access_epoch.id
    ) THEN
      RAISE EXCEPTION 'LDAP MFA continuation authority is stale'
        USING ERRCODE='42501';
    END IF;
    RETURN v_result||jsonb_strip_nulls(jsonb_build_object(
      'primaryKind','tenant_provider','continuationOrigin',v_origin,
      'authenticationMethod','ldap','providerKind','ldap',
      'providerId',v_continuation_provenance.provider_id::text,
      'bindingId',v_continuation_provenance.binding_id::text,
      'externalIdentityId',v_continuation_provenance.external_identity_id::text,
      'externalIdentityRevision',
        v_continuation_provenance.external_identity_revision,
      'providerRevision',v_continuation_provenance.provider_version,
      'configurationRevision',
        v_continuation_provenance.configuration_revision,
      'bindingRevision',v_continuation_provenance.binding_version,
      'authorizationRevision',
        v_continuation_provenance.authorization_revision,
      'sourceSessionId',v_continuation_provenance.source_session_id::text,
      'sourceSessionFamilyId',
        v_continuation_provenance.source_session_family_id::text,
      'sourceSessionVersion',
        v_continuation_provenance.source_session_version,
      'sourceAbsoluteExpiresAt',
        v_continuation_provenance.source_absolute_expires_at
    ));
  END IF;
  RAISE EXCEPTION 'invalid LDAP MFA authority flow' USING ERRCODE='22023';
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'LDAP MFA authority is unavailable or ambiguous'
    USING ERRCODE='42501';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.resolve_mfa_authority_v2(
  uuid,text,text,text,timestamptz,bytea
) RENAME TO resolve_mfa_authority_pre_ldap_v2;
CREATE FUNCTION app.resolve_mfa_authority_v2(
  p_reference_id uuid,p_flow text,p_action text,p_audience text,
  p_evaluated_at timestamptz,p_continuation_receipt_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_has_ldap_session boolean;
  v_has_ldap_continuation boolean;
  v_concrete_flow text;
BEGIN
  SELECT
    EXISTS (
      SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
      WHERE provenance.session_id=p_reference_id
    ),
    EXISTS (
      SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
      WHERE provenance.continuation_id=p_reference_id
    )
    INTO STRICT v_has_ldap_session,v_has_ldap_continuation;
  IF p_flow='enrollment'
     AND v_has_ldap_session IS DISTINCT FROM v_has_ldap_continuation THEN
    v_concrete_flow:=CASE WHEN v_has_ldap_session
      THEN 'session' ELSE 'continuation' END;
    RETURN app.private_resolve_ldap_mfa_authority_v1(
      p_reference_id,v_concrete_flow,p_action,p_audience,p_evaluated_at,
      p_continuation_receipt_digest
    );
  ELSIF p_flow='enrollment'
        AND v_has_ldap_session AND v_has_ldap_continuation THEN
    RAISE EXCEPTION 'LDAP MFA enrollment authority is ambiguous'
      USING ERRCODE='42501';
  ELSIF (p_flow='session' AND v_has_ldap_session)
        OR (p_flow='continuation' AND v_has_ldap_continuation) THEN
    RETURN app.private_resolve_ldap_mfa_authority_v1(
      p_reference_id,p_flow,p_action,p_audience,p_evaluated_at,
      p_continuation_receipt_digest
    );
  END IF;
  RETURN app.resolve_mfa_authority_pre_ldap_v2(
    p_reference_id,p_flow,p_action,p_audience,p_evaluated_at,
    p_continuation_receipt_digest
  );
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_mfa_lock_continuation_authority_v1(
  uuid,timestamptz
) RENAME TO private_mfa_lock_continuation_authority_pre_ldap_v1;
CREATE FUNCTION app.private_mfa_lock_continuation_authority_v1(
  p_continuation_id uuid,p_authority_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_provenance public.tenant_post_primary_ldap_provenance%ROWTYPE;
BEGIN
  SELECT provenance.* INTO v_provenance
  FROM public.tenant_post_primary_ldap_provenance AS provenance
  WHERE provenance.continuation_id=p_continuation_id;
  IF NOT FOUND THEN
    PERFORM app.private_mfa_lock_continuation_authority_pre_ldap_v1(
      p_continuation_id,p_authority_at
    );
    RETURN;
  END IF;
  PERFORM app.private_lock_ldap_primary_authority_v1(
    v_provenance.tenant_id,v_provenance.user_id,v_provenance.provider_id,
    v_provenance.binding_id,v_provenance.external_identity_id,
    v_provenance.external_identity_revision,v_provenance.provider_version,
    v_provenance.configuration_revision,v_provenance.binding_version,
    v_provenance.binding_auth_revision,v_provenance.rule_set_revision,
    v_provenance.authorization_revision,v_provenance.source_session_id,
    v_provenance.source_session_family_id,v_provenance.source_session_version,
    v_provenance.source_absolute_expires_at,p_authority_at,true,false
  );
  PERFORM 1
  FROM public.tenant_post_primary_continuations AS continuation
  WHERE continuation.tenant_id=v_provenance.tenant_id
    AND continuation.id=p_continuation_id
    AND continuation.user_id=v_provenance.user_id
    AND continuation.primary_kind='tenant_provider'
    AND continuation.provider_kind='ldap'
    AND continuation.provider_id=v_provenance.provider_id
    AND continuation.binding_id=v_provenance.binding_id
    AND continuation.external_identity_id=v_provenance.external_identity_id
    AND continuation.primary_revision=v_provenance.external_identity_revision
    AND continuation.state='pending' AND continuation.expires_at>p_authority_at
  FOR UPDATE NOWAIT;
  IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA continuation is stale'
    USING ERRCODE='40001'; END IF;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'LDAP MFA continuation authority is busy'
    USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_prepare_ldap_recovery_replacement_v1(
  p_anchor_id uuid,p_replaced_recovery_set_id uuid,p_session jsonb,
  p_completed_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_source public.tenant_mfa_authority_evidence%ROWTYPE;
  v_destination_session_id uuid;
BEGIN
  IF p_replaced_recovery_set_id IS NULL THEN RETURN; END IF;
  IF jsonb_typeof(p_session)<>'object'
     OR p_session->>'mutation'<>'rotate'
     OR jsonb_typeof(p_session->'reservation')<>'object'
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM(transaction_timestamp()-p_completed_at)))>300
  THEN
    RAISE EXCEPTION 'invalid LDAP recovery replacement capability'
      USING ERRCODE='22023';
  END IF;
  v_destination_session_id:=app.private_mfa_require_uuidv7_v1(
    p_session#>>'{reservation,sessionId}'
  );
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id=p_anchor_id AND anchor.flow='session'
  FOR UPDATE;
  -- The shared recovery replacement entrypoint invokes this hook for every
  -- primary kind. Only an exact typed LDAP session may mint the transaction-
  -- local omission capability; all other dispatchers must remain zero-write.
  IF NOT EXISTS (
    SELECT 1
    FROM public.auth_session_ldap_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.session_id=v_anchor.session_id
      AND provenance.user_id=v_anchor.user_id
      AND provenance.primary_kind='tenant_provider'
      AND provenance.authentication_method='ldap'
  ) THEN
    RETURN;
  END IF;
  SELECT evidence.* INTO v_source
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id=v_anchor.tenant_id
    AND evidence.anchor_id=v_anchor.id
    AND evidence.kind='recovery'
    AND evidence.recovery_code_set_id=p_replaced_recovery_set_id
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_mfa_authority_evidence AS evidence
    WHERE evidence.tenant_id=v_anchor.tenant_id
      AND evidence.anchor_id=v_anchor.id
      AND evidence.kind='recovery'
      AND evidence.recovery_code_set_id=p_replaced_recovery_set_id
      AND evidence.id<>v_source.id
  ) OR NOT EXISTS (
    SELECT 1 FROM public.tenant_recovery_code_sets AS code_set
    WHERE code_set.tenant_id=v_anchor.tenant_id
      AND code_set.user_id=v_anchor.user_id
      AND code_set.id=p_replaced_recovery_set_id
      AND code_set.status='revoked'
      AND code_set.revoked_at=p_completed_at
      AND code_set.revoke_reason='recovery_codes_replaced'
    FOR SHARE
  ) THEN
    RAISE EXCEPTION 'LDAP recovery replacement authority is ambiguous'
      USING ERRCODE='40001';
  END IF;
  INSERT INTO public.tenant_mfa_ldap_recovery_replacement_capabilities(
    tenant_id,source_anchor_id,source_evidence_id,
    replaced_recovery_set_id,destination_session_id,backend_pid,
    transaction_id,completed_at,created_at
  ) VALUES (
    v_anchor.tenant_id,v_anchor.id,v_source.id,p_replaced_recovery_set_id,
    v_destination_session_id,pg_backend_pid(),txid_current(),p_completed_at,
    transaction_timestamp()
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'LDAP recovery replacement authority is unavailable'
    USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

-- The shared recovery replacement ABI also serves local and generic
-- OIDC/SAML sessions. Their frozen writers copy the immutable anchor snapshot,
-- so give them the same unforgeable, transaction-scoped omission proof without
-- weakening the LDAP preparer's typed boundary.
CREATE FUNCTION app.private_prepare_non_ldap_recovery_replacement_v1(
  p_anchor_id uuid,p_replaced_recovery_set_id uuid,p_session jsonb,
  p_completed_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_source public.tenant_mfa_authority_evidence%ROWTYPE;
  v_destination_session_id uuid;
  v_primary_count bigint;
BEGIN
  IF p_replaced_recovery_set_id IS NULL THEN RETURN; END IF;
  IF jsonb_typeof(p_session)<>'object'
     OR p_session->>'mutation'<>'rotate'
     OR jsonb_typeof(p_session->'reservation')<>'object'
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM(transaction_timestamp()-p_completed_at)))>300
  THEN
    RAISE EXCEPTION 'invalid non-LDAP recovery replacement capability'
      USING ERRCODE='22023';
  END IF;
  v_destination_session_id:=app.private_mfa_require_uuidv7_v1(
    p_session#>>'{reservation,sessionId}'
  );
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id=p_anchor_id AND anchor.flow='session'
  FOR UPDATE;
  IF EXISTS (
    SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.session_id=v_anchor.session_id
      AND provenance.user_id=v_anchor.user_id
      AND provenance.primary_kind='tenant_provider'
      AND provenance.authentication_method='ldap'
  ) THEN
    RETURN;
  END IF;
  SELECT count(*) INTO STRICT v_primary_count
  FROM (
    SELECT provenance.session_id
    FROM public.auth_session_local_credential_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.session_id=v_anchor.session_id
      AND provenance.user_id=v_anchor.user_id
      AND provenance.primary_kind='local_credential'
    UNION ALL
    SELECT provenance.session_id
    FROM public.auth_session_passkey_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.session_id=v_anchor.session_id
      AND provenance.user_id=v_anchor.user_id
      AND provenance.primary_kind='passkey'
    UNION ALL
    SELECT provenance.session_id
    FROM public.auth_session_federated_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.session_id=v_anchor.session_id
      AND provenance.user_id=v_anchor.user_id
      AND provenance.primary_kind='tenant_provider'
      AND provenance.authentication_method IN ('oidc','saml')
    UNION ALL
    SELECT provenance.session_id
    FROM public.auth_session_tenant_platform_federated_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.session_id=v_anchor.session_id
      AND provenance.user_id=v_anchor.user_id
      AND provenance.primary_kind='tenant_platform_provider'
      AND provenance.authentication_method='oidc'
  ) AS typed_primary;
  IF v_primary_count<>1 THEN
    RAISE EXCEPTION 'non-LDAP recovery replacement authority is ambiguous'
      USING ERRCODE='40001';
  END IF;
  SELECT evidence.* INTO v_source
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id=v_anchor.tenant_id
    AND evidence.anchor_id=v_anchor.id
    AND evidence.kind='recovery'
    AND evidence.recovery_code_set_id=p_replaced_recovery_set_id
  FOR SHARE;
  IF NOT FOUND THEN RETURN; END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_mfa_authority_evidence AS evidence
    WHERE evidence.tenant_id=v_anchor.tenant_id
      AND evidence.anchor_id=v_anchor.id
      AND evidence.kind='recovery'
      AND evidence.recovery_code_set_id=p_replaced_recovery_set_id
      AND evidence.id<>v_source.id
  ) OR NOT EXISTS (
    SELECT 1 FROM public.tenant_recovery_code_sets AS code_set
    WHERE code_set.tenant_id=v_anchor.tenant_id
      AND code_set.user_id=v_anchor.user_id
      AND code_set.id=p_replaced_recovery_set_id
      AND code_set.status='revoked'
      AND code_set.revoked_at=p_completed_at
      AND code_set.revoke_reason='recovery_codes_replaced'
    FOR SHARE
  ) THEN
    RAISE EXCEPTION 'non-LDAP recovery replacement authority is stale'
      USING ERRCODE='40001';
  END IF;
  INSERT INTO public.tenant_mfa_ldap_recovery_replacement_capabilities(
    tenant_id,source_anchor_id,source_evidence_id,
    replaced_recovery_set_id,destination_session_id,backend_pid,
    transaction_id,completed_at,created_at
  ) VALUES (
    v_anchor.tenant_id,v_anchor.id,v_source.id,p_replaced_recovery_set_id,
    v_destination_session_id,pg_backend_pid(),txid_current(),p_completed_at,
    transaction_timestamp()
  );
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'non-LDAP recovery replacement authority is unavailable'
    USING ERRCODE='40001';
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_finish_non_ldap_recovery_replacement_v1(
  p_anchor_id uuid,p_replaced_recovery_set_id uuid,p_session jsonb,
  p_completed_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_destination_session_id uuid;
BEGIN
  IF p_replaced_recovery_set_id IS NULL THEN RETURN; END IF;
  v_destination_session_id:=app.private_mfa_require_uuidv7_v1(
    p_session#>>'{reservation,sessionId}'
  );
  DELETE FROM public.tenant_mfa_ldap_recovery_replacement_capabilities
    AS capability
  WHERE capability.backend_pid=pg_backend_pid()
    AND capability.transaction_id=txid_current()
    AND capability.source_anchor_id=p_anchor_id
    AND capability.replaced_recovery_set_id=p_replaced_recovery_set_id
    AND capability.destination_session_id=v_destination_session_id
    AND capability.completed_at=p_completed_at;
  IF EXISTS (
    SELECT 1
    FROM public.tenant_mfa_ldap_recovery_replacement_capabilities AS capability
    WHERE capability.backend_pid=pg_backend_pid()
      AND capability.transaction_id=txid_current()
      AND capability.source_anchor_id=p_anchor_id
      AND capability.replaced_recovery_set_id=p_replaced_recovery_set_id
  ) THEN
    RAISE EXCEPTION 'non-LDAP recovery replacement cleanup lost CAS'
      USING ERRCODE='40001';
  END IF;
END;
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_apply_ldap_mfa_session_v1(
  p_session jsonb,p_anchor_id uuid,p_primary_kind text,p_primary_id uuid,
  p_primary_revision bigint,p_evidence_kind text,p_evidence_id uuid,
  p_evidence_revision bigint,p_completed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_anchor public.tenant_mfa_authority_anchors%ROWTYPE;
  v_binding jsonb;
  v_reservation jsonb;
  v_top_level_receipt boolean:=p_session ? 'continuationReceiptDigest';
  v_reservation_receipt boolean:=coalesce(
    p_session->'reservation' ? 'continuationReceiptDigest',false
  );
  v_source_session public.auth_sessions%ROWTYPE;
  v_source_state public.auth_session_mfa_states%ROWTYPE;
  v_subject public.tenant_mfa_subjects%ROWTYPE;
  v_session_provenance public.auth_session_ldap_provenance%ROWTYPE;
  v_continuation public.tenant_post_primary_continuations%ROWTYPE;
  v_continuation_provenance
    public.tenant_post_primary_ldap_provenance%ROWTYPE;
  v_tenant_id uuid;
  v_user_id uuid;
  v_provider_id uuid;
  v_binding_id uuid;
  v_external_identity_id uuid;
  v_external_identity_revision bigint;
  v_provider_version integer;
  v_configuration_revision integer;
  v_binding_version integer;
  v_binding_auth_revision integer;
  v_rule_set_revision bigint;
  v_authorization_revision bigint;
  v_root_jit_run_id uuid;
  v_jit_run_id uuid;
  v_authenticated_at timestamptz;
  v_source_session_id uuid;
  v_source_family_id uuid;
  v_source_version bigint;
  v_source_absolute_expires_at timestamptz;
  v_new_session_id uuid;
  v_new_family_id uuid;
  v_token_digest bytea;
  v_csrf_digest bytea;
  v_idle_expires_at timestamptz;
  v_absolute_expires_at timestamptz;
  v_receipt_digest bytea;
  v_authority_at timestamptz:=greatest(p_completed_at,transaction_timestamp());
  v_token_lock bigint;
  v_csrf_lock bigint;
  v_new_version bigint;
  v_consumed_continuation_id uuid;
  v_evidence_count bigint;
  v_copy_capability_count bigint:=0;
  v_copy_source_count bigint:=0;
  v_copy_capability boolean:=false;
  v_baseline_only boolean:=p_evidence_kind IS NULL
    AND p_evidence_id IS NULL AND p_evidence_revision IS NULL;
  v_replaced_recovery_set_id uuid;
  v_replacement_capability_count bigint:=0;
  v_replacement_capability
    public.tenant_mfa_ldap_recovery_replacement_capabilities%ROWTYPE;
  v_effective_evidence_revision bigint:=p_evidence_revision;
  v_effective_evidence_level text;
  v_result jsonb;
BEGIN
  PERFORM app.private_mfa_assert_json_object_v1(
    p_session,
    ARRAY['mutation','expectedSessionId','expectedFamilyId',
      'expectedContinuationId','expectedAnchorVersion',
      'expectedIdentityEpoch','expectedAnchorExpiry','audience','requirement',
      'recoveryRestricted','reservation','continuationReceiptDigest'],
    ARRAY['mutation','expectedAnchorVersion','expectedIdentityEpoch',
      'expectedAnchorExpiry','audience','requirement','recoveryRestricted',
      'reservation'],131072
  );
  IF NOT (
       (p_primary_kind IS NULL AND p_primary_id IS NULL
         AND p_primary_revision IS NULL)
       OR (p_evidence_kind='webauthn' AND p_primary_kind='passkey'
         AND p_primary_id=p_evidence_id
         AND p_primary_revision=p_evidence_revision)
     )
     OR NOT (v_baseline_only OR (
       p_evidence_kind IN ('totp','webauthn','recovery')
       AND p_evidence_id IS NOT NULL AND p_evidence_revision>=1
     ))
     OR p_completed_at IS NULL
     OR abs(extract(epoch FROM(transaction_timestamp()-p_completed_at)))>300
  THEN
    RAISE EXCEPTION 'invalid LDAP MFA session completion'
      USING ERRCODE='22023';
  END IF;
  SELECT anchor.* INTO STRICT v_anchor
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id=p_anchor_id FOR UPDATE;
  IF v_anchor.flow NOT IN ('session','continuation')
     OR p_session->>'audience' IS DISTINCT FROM v_anchor.audience
     OR (p_session->>'expectedAnchorVersion')::bigint
          IS DISTINCT FROM v_anchor.anchor_version
     OR (p_session->>'expectedIdentityEpoch')::bigint
          IS DISTINCT FROM v_anchor.identity_epoch
     OR (p_session->>'expectedAnchorExpiry')::timestamptz
          IS DISTINCT FROM v_anchor.anchor_expires_at THEN
    RAISE EXCEPTION 'LDAP MFA session anchor drifted'
      USING ERRCODE='40001';
  END IF;
  v_binding:=app.private_mfa_anchor_binding_v1(p_anchor_id);
  IF jsonb_strip_nulls(p_session->'requirement') IS DISTINCT FROM
       jsonb_strip_nulls(v_binding->'requirement') THEN
    RAISE EXCEPTION 'LDAP MFA policy binding drifted'
      USING ERRCODE='40001';
  END IF;
  PERFORM app.private_mfa_assert_live_policy_anchor_v1(
    p_anchor_id,v_authority_at
  );
  IF v_anchor.flow='session' THEN
    IF p_session->>'mutation'<>'rotate'
       OR p_session ? 'expectedContinuationId'
       OR app.private_mfa_require_uuidv7_v1(
            p_session->>'expectedSessionId'
          ) IS DISTINCT FROM v_anchor.session_id
       OR app.private_mfa_require_uuidv7_v1(
            p_session->>'expectedFamilyId'
          ) IS DISTINCT FROM v_anchor.session_family_id
       OR v_top_level_receipt OR v_reservation_receipt
    THEN
      RAISE EXCEPTION 'invalid LDAP MFA session rotation intent'
        USING ERRCODE='22023';
    END IF;
    SELECT provenance.* INTO STRICT v_session_provenance
    FROM public.auth_session_ldap_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.session_id=v_anchor.session_id
      AND provenance.user_id=v_anchor.user_id;
    v_tenant_id:=v_session_provenance.tenant_id;
    v_user_id:=v_session_provenance.user_id;
    v_provider_id:=v_session_provenance.provider_id;
    v_binding_id:=v_session_provenance.binding_id;
    v_external_identity_id:=v_session_provenance.external_identity_id;
    v_external_identity_revision:=
      v_session_provenance.external_identity_revision;
    v_provider_version:=v_session_provenance.provider_version;
    v_configuration_revision:=v_session_provenance.configuration_revision;
    v_binding_version:=v_session_provenance.binding_version;
    v_binding_auth_revision:=v_session_provenance.binding_auth_revision;
    v_rule_set_revision:=v_session_provenance.rule_set_revision;
    v_authorization_revision:=v_session_provenance.authorization_revision;
    v_root_jit_run_id:=v_session_provenance.root_jit_run_id;
    v_authenticated_at:=v_session_provenance.authenticated_at;
    v_source_session_id:=v_anchor.session_id;
    v_source_family_id:=v_anchor.session_family_id;
    v_source_version:=v_anchor.anchor_version;
    SELECT session.* INTO STRICT v_source_session
    FROM public.auth_sessions AS session WHERE session.id=v_source_session_id;
    v_source_absolute_expires_at:=v_source_session.absolute_expires_at;
  ELSE
     IF p_session->>'mutation'<>'consume_continuation'
       OR p_session ? 'expectedSessionId' OR p_session ? 'expectedFamilyId'
       OR app.private_mfa_require_uuidv7_v1(
            p_session->>'expectedContinuationId'
          ) IS DISTINCT FROM v_anchor.continuation_id THEN
      RAISE EXCEPTION 'invalid LDAP MFA continuation intent'
        USING ERRCODE='22023';
    END IF;
    SELECT provenance.* INTO STRICT v_continuation_provenance
    FROM public.tenant_post_primary_ldap_provenance AS provenance
    WHERE provenance.tenant_id=v_anchor.tenant_id
      AND provenance.continuation_id=v_anchor.continuation_id
      AND provenance.user_id=v_anchor.user_id;
    v_tenant_id:=v_continuation_provenance.tenant_id;
    v_user_id:=v_continuation_provenance.user_id;
    v_provider_id:=v_continuation_provenance.provider_id;
    v_binding_id:=v_continuation_provenance.binding_id;
    v_external_identity_id:=v_continuation_provenance.external_identity_id;
    v_external_identity_revision:=
      v_continuation_provenance.external_identity_revision;
    v_provider_version:=v_continuation_provenance.provider_version;
    v_configuration_revision:=
      v_continuation_provenance.configuration_revision;
    v_binding_version:=v_continuation_provenance.binding_version;
    v_binding_auth_revision:=v_continuation_provenance.binding_auth_revision;
    v_rule_set_revision:=v_continuation_provenance.rule_set_revision;
    v_authorization_revision:=
      v_continuation_provenance.authorization_revision;
    v_root_jit_run_id:=v_continuation_provenance.root_jit_run_id;
    v_jit_run_id:=v_continuation_provenance.jit_run_id;
    v_authenticated_at:=v_continuation_provenance.authenticated_at;
    v_source_session_id:=v_continuation_provenance.source_session_id;
    v_source_family_id:=v_continuation_provenance.source_session_family_id;
    v_source_version:=v_continuation_provenance.source_session_version;
    v_source_absolute_expires_at:=
      v_continuation_provenance.source_absolute_expires_at;
    IF v_top_level_receipt=v_reservation_receipt THEN
      RAISE EXCEPTION 'exactly one LDAP continuation receipt is required'
        USING ERRCODE='22023';
    END IF;
    v_receipt_digest:=app.private_mfa_decode_base64_v1(
      CASE WHEN v_top_level_receipt
        THEN p_session->>'continuationReceiptDigest'
        ELSE p_session#>>'{reservation,continuationReceiptDigest}' END,32,32
    );
    IF encode(v_receipt_digest,'hex')=repeat('00',32) THEN
      RAISE EXCEPTION 'invalid LDAP MFA continuation receipt'
        USING ERRCODE='22023';
    END IF;
  END IF;

  PERFORM app.resolve_mfa_authority_v2(
    CASE WHEN v_anchor.flow='continuation' THEN v_anchor.continuation_id
      ELSE v_anchor.session_id END,v_anchor.flow,v_anchor.action,
    v_anchor.audience,v_authority_at,
    CASE WHEN v_anchor.flow='continuation' THEN v_receipt_digest
      ELSE NULL::bytea END
  );
  IF v_anchor.flow='continuation' THEN
    PERFORM app.private_mfa_lock_continuation_authority_v1(
      v_anchor.continuation_id,v_authority_at
    );
  END IF;
  PERFORM app.private_lock_ldap_primary_authority_v1(
    v_tenant_id,v_user_id,v_provider_id,v_binding_id,
    v_external_identity_id,v_external_identity_revision,v_provider_version,
    v_configuration_revision,v_binding_version,v_binding_auth_revision,
    v_rule_set_revision,v_authorization_revision,v_source_session_id,
    v_source_family_id,v_source_version,v_source_absolute_expires_at,
    v_authority_at,true,false
  );
  SELECT count(*) INTO STRICT v_replacement_capability_count
  FROM public.tenant_mfa_ldap_recovery_replacement_capabilities AS capability
  WHERE capability.backend_pid=pg_backend_pid()
    AND capability.transaction_id=txid_current()
    AND capability.tenant_id=v_tenant_id
    AND capability.source_anchor_id=p_anchor_id
    AND capability.completed_at=p_completed_at;
  IF v_replacement_capability_count>1 THEN
    RAISE EXCEPTION 'LDAP recovery replacement capability is ambiguous'
      USING ERRCODE='40001';
  ELSIF v_replacement_capability_count=1 THEN
    SELECT capability.* INTO STRICT v_replacement_capability
    FROM public.tenant_mfa_ldap_recovery_replacement_capabilities AS capability
    WHERE capability.backend_pid=pg_backend_pid()
      AND capability.transaction_id=txid_current()
      AND capability.tenant_id=v_tenant_id
      AND capability.source_anchor_id=p_anchor_id
      AND capability.completed_at=p_completed_at
    FOR UPDATE;
    v_replaced_recovery_set_id:=
      v_replacement_capability.replaced_recovery_set_id;
    IF NOT v_baseline_only OR v_anchor.flow<>'session' THEN
      RAISE EXCEPTION 'invalid LDAP recovery replacement capability use'
        USING ERRCODE='40001';
    END IF;
  END IF;
  PERFORM app.private_assert_live_ldap_evidence_v1(
    v_tenant_id,v_user_id,'anchor',p_anchor_id,v_provider_id,v_binding_id,
    v_binding_auth_revision,v_authenticated_at,v_authority_at,
    CASE WHEN p_evidence_kind='webauthn' THEN p_evidence_id END,
    v_replaced_recovery_set_id
  );
  IF v_anchor.flow='continuation' THEN
    SELECT continuation.* INTO STRICT v_continuation
    FROM public.tenant_post_primary_continuations AS continuation
    WHERE continuation.tenant_id=v_tenant_id
      AND continuation.id=v_anchor.continuation_id
      AND continuation.user_id=v_user_id
      AND continuation.primary_kind='tenant_provider'
      AND continuation.provider_kind='ldap'
      AND continuation.provider_id=v_provider_id
      AND continuation.binding_id=v_binding_id
      AND continuation.external_identity_id=v_external_identity_id
      AND continuation.primary_revision=v_external_identity_revision
      AND continuation.receipt_digest=v_receipt_digest
      AND continuation.state='pending'
      AND continuation.version=v_anchor.anchor_version
      AND continuation.expires_at=v_anchor.anchor_expires_at
      AND continuation.expires_at>v_authority_at
    FOR UPDATE NOWAIT;
  END IF;
  IF v_source_session_id IS NOT NULL THEN
    SELECT state.* INTO STRICT v_source_state
    FROM public.auth_session_mfa_states AS state
    WHERE state.tenant_id=v_tenant_id AND state.session_id=v_source_session_id
      AND state.user_id=v_user_id AND state.primary_kind='tenant_provider'
      AND state.session_version=v_source_version
    FOR UPDATE;
  END IF;
  SELECT subject.* INTO STRICT v_subject
  FROM public.tenant_mfa_subjects AS subject
  WHERE subject.tenant_id=v_tenant_id AND subject.user_id=v_user_id
    AND subject.identity_epoch=v_anchor.identity_epoch
  FOR SHARE NOWAIT;
  IF (v_source_session_id IS NOT NULL AND
        v_source_state.session_invalidation_epoch IS DISTINCT FROM
          v_subject.session_invalidation_epoch)
     OR (v_anchor.flow='continuation' AND
        v_continuation.session_invalidation_epoch IS DISTINCT FROM
          v_subject.session_invalidation_epoch) THEN
    RAISE EXCEPTION 'LDAP MFA session invalidation epoch drifted'
      USING ERRCODE='40001';
  END IF;

  v_reservation:=p_session->'reservation';
  IF v_reservation_receipt THEN
    v_reservation:=v_reservation-'continuationReceiptDigest';
  END IF;
  PERFORM app.private_mfa_assert_json_object_v1(
    v_reservation,
    ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
      'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],
    ARRAY['sessionId','familyId','tokenDigest','csrfDigest',
      'authenticationMethod','idleExpiresAt','absoluteExpiresAt'],16384
  );
  v_new_session_id:=app.private_mfa_require_uuidv7_v1(
    v_reservation->>'sessionId'
  );
  v_new_family_id:=app.private_mfa_require_uuidv7_v1(
    v_reservation->>'familyId'
  );
  v_token_digest:=app.private_mfa_decode_base64_v1(
    v_reservation->>'tokenDigest',32,32
  );
  v_csrf_digest:=app.private_mfa_decode_base64_v1(
    v_reservation->>'csrfDigest',32,32
  );
  v_idle_expires_at:=(v_reservation->>'idleExpiresAt')::timestamptz;
  v_absolute_expires_at:=(v_reservation->>'absoluteExpiresAt')::timestamptz;
  IF v_replacement_capability_count=1
     AND v_replacement_capability.destination_session_id IS DISTINCT FROM
       v_new_session_id THEN
    RAISE EXCEPTION 'LDAP recovery replacement destination drifted'
      USING ERRCODE='40001';
  END IF;
  IF v_reservation->>'authenticationMethod' IS DISTINCT FROM (CASE
       WHEN v_baseline_only THEN 'ldap'
       WHEN p_evidence_kind='totp' THEN 'totp'
       WHEN p_evidence_kind='webauthn' THEN 'passkey'
       ELSE 'recovery_code' END)
     OR v_new_session_id IN (v_new_family_id,coalesce(v_source_session_id,v_new_family_id))
     OR encode(v_token_digest,'hex')=repeat('00',32)
     OR encode(v_csrf_digest,'hex')=repeat('00',32)
     OR v_token_digest=v_csrf_digest
     OR v_idle_expires_at<=v_authority_at
     OR v_absolute_expires_at<=v_authority_at
     OR v_idle_expires_at>v_absolute_expires_at
     OR v_idle_expires_at>v_authority_at+interval '24 hours'
     OR v_absolute_expires_at>v_authority_at+interval '31 days'
     OR date_trunc('milliseconds',v_idle_expires_at)<>v_idle_expires_at
     OR date_trunc('milliseconds',v_absolute_expires_at)<>v_absolute_expires_at
     OR (v_source_session_id IS NOT NULL AND (
       v_new_family_id IS DISTINCT FROM v_source_family_id
       OR v_absolute_expires_at IS DISTINCT FROM v_source_absolute_expires_at
     )) THEN
    RAISE EXCEPTION 'invalid LDAP MFA successor reservation'
      USING ERRCODE='22023';
  END IF;
  SELECT count(*) INTO STRICT v_evidence_count
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id=v_tenant_id AND evidence.anchor_id=p_anchor_id
    AND (v_replaced_recovery_set_id IS NULL OR evidence.kind<>'recovery'
      OR evidence.recovery_code_set_id IS DISTINCT FROM
        v_replaced_recovery_set_id);
  IF v_evidence_count>1024 THEN
    RAISE EXCEPTION 'LDAP MFA evidence snapshot limit reached'
      USING ERRCODE='22023';
  END IF;
  IF v_baseline_only THEN
    v_effective_evidence_level:=NULL;
  ELSIF p_evidence_kind='webauthn' THEN
    SELECT credential.security_revision,'phishing_resistant'
      INTO STRICT v_effective_evidence_revision,v_effective_evidence_level
    FROM public.tenant_webauthn_credentials AS credential
    WHERE credential.tenant_id=v_tenant_id AND credential.user_id=v_user_id
      AND credential.id=p_evidence_id AND credential.status='active'
      AND credential.version=p_evidence_revision
      AND credential.last_used_at=p_completed_at
      AND credential.updated_at=p_completed_at
      AND credential.security_revision BETWEEN 1 AND credential.version
    FOR SHARE;
    SELECT count(*) INTO STRICT v_copy_capability_count
    FROM (
      SELECT capability.source_evidence_id
      FROM public.tenant_mfa_webauthn_evidence_copy_capabilities AS capability
      WHERE capability.backend_pid=pg_backend_pid()
        AND capability.transaction_id=txid_current()
        AND capability.tenant_id=v_tenant_id
        AND capability.source_anchor_id=p_anchor_id
        AND capability.destination_session_id=v_new_session_id
        AND capability.credential_id=p_evidence_id
        AND capability.target_revision=v_effective_evidence_revision
        AND capability.target_authenticated_at=p_completed_at
        AND capability.consumed_evidence_id IS NULL
        AND capability.consumed_at IS NULL
      FOR UPDATE
    ) AS exact_capability;
    SELECT count(*) INTO STRICT v_copy_source_count
    FROM (
      SELECT evidence.id
      FROM public.tenant_mfa_authority_evidence AS evidence
      WHERE evidence.tenant_id=v_tenant_id
        AND evidence.anchor_id=p_anchor_id
        AND evidence.kind='webauthn'
        AND evidence.webauthn_credential_id=p_evidence_id
      FOR SHARE
    ) AS exact_source;
    IF v_copy_capability_count>1 OR v_copy_source_count>1
       OR (v_copy_capability_count=1 AND v_copy_source_count<>1)
       OR (v_copy_capability_count=0 AND v_copy_source_count<>0) THEN
      RAISE EXCEPTION 'LDAP WebAuthn evidence copy authority is ambiguous'
        USING ERRCODE='40001';
    END IF;
    v_copy_capability:=v_copy_capability_count=1;
    IF v_copy_capability THEN
      SELECT capability.target_level
        INTO STRICT v_effective_evidence_level
      FROM public.tenant_mfa_webauthn_evidence_copy_capabilities AS capability
      WHERE capability.backend_pid=pg_backend_pid()
        AND capability.transaction_id=txid_current()
        AND capability.tenant_id=v_tenant_id
        AND capability.source_anchor_id=p_anchor_id
        AND capability.destination_session_id=v_new_session_id
        AND capability.credential_id=p_evidence_id
        AND capability.target_revision=v_effective_evidence_revision
        AND capability.target_authenticated_at=p_completed_at
        AND capability.consumed_evidence_id IS NULL
        AND capability.consumed_at IS NULL;
    END IF;
  ELSIF p_evidence_kind='totp' THEN
    PERFORM 1 FROM public.tenant_totp_factors AS factor
    WHERE factor.tenant_id=v_tenant_id AND factor.user_id=v_user_id
      AND factor.id=p_evidence_id AND factor.status='active'
      AND factor.security_revision=p_evidence_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA TOTP factor drifted'
      USING ERRCODE='40001'; END IF;
    v_effective_evidence_level:='mfa';
  ELSE
    PERFORM 1 FROM public.tenant_recovery_code_sets AS code_set
    WHERE code_set.tenant_id=v_tenant_id AND code_set.user_id=v_user_id
      AND code_set.id=p_evidence_id AND code_set.status='active'
      AND code_set.security_revision=p_evidence_revision;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA recovery factor drifted'
      USING ERRCODE='40001'; END IF;
    v_effective_evidence_level:='mfa';
  END IF;
  IF v_evidence_count+(CASE WHEN v_baseline_only OR v_copy_capability
       THEN 0 ELSE 1 END)>1024 THEN
    RAISE EXCEPTION 'LDAP MFA evidence snapshot limit reached'
      USING ERRCODE='22023';
  END IF;
  v_token_lock:=hashtextextended(encode(v_token_digest,'hex'),73124201);
  v_csrf_lock:=hashtextextended(encode(v_csrf_digest,'hex'),73124201);
  PERFORM pg_advisory_xact_lock(least(v_token_lock,v_csrf_lock));
  IF v_token_lock<>v_csrf_lock THEN
    PERFORM pg_advisory_xact_lock(greatest(v_token_lock,v_csrf_lock));
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.auth_sessions AS collision
    WHERE collision.token_digest IN (v_token_digest,v_csrf_digest)
       OR collision.csrf_secret_digest IN (v_token_digest,v_csrf_digest)
  ) THEN RAISE EXCEPTION 'LDAP MFA successor digest collision'
    USING ERRCODE='40001'; END IF;

  IF v_source_session_id IS NOT NULL THEN
    UPDATE public.auth_sessions AS source_session
    SET revoked_at=p_completed_at,revoke_reason='mfa_session_rotated'
    WHERE source_session.id=v_source_session_id
      AND source_session.revoked_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA source rotation lost CAS'
      USING ERRCODE='40001'; END IF;
    v_new_version:=v_source_version+1;
  ELSE
    v_new_version:=1;
  END IF;
  IF v_anchor.flow='continuation' THEN
    UPDATE public.tenant_post_primary_continuations AS continuation
    SET state='consumed',version=continuation.version+1,
        consumed_at=p_completed_at
    WHERE continuation.tenant_id=v_tenant_id
      AND continuation.id=v_anchor.continuation_id
      AND continuation.state='pending'
      AND continuation.version=v_anchor.anchor_version
      AND continuation.receipt_digest=v_receipt_digest
    RETURNING continuation.id INTO v_consumed_continuation_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'LDAP MFA continuation lost CAS'
      USING ERRCODE='40001'; END IF;
  END IF;

  INSERT INTO public.auth_sessions(
    id,user_id,rotation_family_id,active_tenant_id,token_digest,
    csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
    idle_expires_at,absolute_expires_at,rotated_from_session_id,created_at
  ) VALUES (
    v_new_session_id,v_user_id,v_new_family_id,v_tenant_id,v_token_digest,
    v_csrf_digest,'ldap',CASE WHEN v_baseline_only
      THEN v_source_session.mfa_satisfied_at ELSE p_completed_at END,
    p_completed_at,v_idle_expires_at,
    v_absolute_expires_at,v_source_session_id,p_completed_at
  );
  INSERT INTO public.auth_session_mfa_states(
    session_id,tenant_id,user_id,session_version,identity_epoch,
    recovery_restricted,audience,primary_kind,session_invalidation_epoch,
    issued_at
  ) VALUES (v_new_session_id,v_tenant_id,v_user_id,v_new_version,
    v_subject.identity_epoch,(p_session->>'recoveryRestricted')::boolean,
    v_anchor.audience,'tenant_provider',v_subject.session_invalidation_epoch,
    p_completed_at);
  INSERT INTO public.auth_session_ldap_provenance(
    tenant_id,session_id,user_id,jit_run_id,root_jit_run_id,
    source_session_id,source_session_family_id,source_session_version,
    source_absolute_expires_at,primary_kind,authentication_method,
    provider_id,binding_id,external_identity_id,external_identity_revision,
    provider_version,configuration_revision,binding_version,
    binding_auth_revision,rule_set_revision,authorization_revision,
    authenticated_at
  ) VALUES (
    v_tenant_id,v_new_session_id,v_user_id,
    CASE WHEN v_source_session_id IS NULL THEN v_jit_run_id END,
    v_root_jit_run_id,v_source_session_id,v_source_family_id,v_source_version,
    v_source_absolute_expires_at,'tenant_provider','ldap',v_provider_id,
    v_binding_id,v_external_identity_id,v_external_identity_revision,
    v_provider_version,v_configuration_revision,v_binding_version,
    v_binding_auth_revision,v_rule_set_revision,v_authorization_revision,
    v_authenticated_at
  );
  INSERT INTO public.auth_session_mfa_policy_pins(
    tenant_id,session_id,policy_id,policy_revision
  ) SELECT pin.tenant_id,v_new_session_id,pin.policy_id,pin.policy_revision
  FROM public.tenant_mfa_authority_policy_pins AS pin
  WHERE pin.tenant_id=v_tenant_id AND pin.anchor_id=p_anchor_id;

  INSERT INTO public.auth_session_mfa_evidence(
    id,tenant_id,session_id,local_credential_id,totp_factor_id,
    webauthn_credential_id,recovery_code_set_id,level,kind,provider_id,
    binding_id,authenticated_at,expires_at,factor_revision,
    trust_rule_revision
  ) SELECT uuidv7(),evidence.tenant_id,v_new_session_id,
    evidence.local_credential_id,evidence.totp_factor_id,
    evidence.webauthn_credential_id,evidence.recovery_code_set_id,
    evidence.level,evidence.kind,evidence.provider_id,evidence.binding_id,
    evidence.authenticated_at,
    CASE WHEN evidence.kind='provider' THEN v_absolute_expires_at
      ELSE evidence.expires_at END,
    evidence.factor_revision,
    evidence.trust_rule_revision
  FROM public.tenant_mfa_authority_evidence AS evidence
  WHERE evidence.tenant_id=v_tenant_id AND evidence.anchor_id=p_anchor_id
    AND (v_replaced_recovery_set_id IS NULL OR evidence.kind<>'recovery'
      OR evidence.recovery_code_set_id IS DISTINCT FROM
        v_replaced_recovery_set_id);
  IF NOT v_baseline_only AND NOT v_copy_capability THEN
    INSERT INTO public.auth_session_mfa_evidence(
      id,tenant_id,session_id,totp_factor_id,webauthn_credential_id,
      recovery_code_set_id,level,kind,authenticated_at,factor_revision
    ) VALUES (
      uuidv7(),v_tenant_id,v_new_session_id,
      CASE WHEN p_evidence_kind='totp' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind='webauthn' THEN p_evidence_id END,
      CASE WHEN p_evidence_kind='recovery' THEN p_evidence_id END,
      v_effective_evidence_level,p_evidence_kind,p_completed_at,
      v_effective_evidence_revision
    );
  END IF;
  v_result:=jsonb_strip_nulls(jsonb_build_object(
    'mutation',p_session->>'mutation','newSessionId',v_new_session_id::text,
    'newSessionFamilyId',v_new_family_id::text,
    'consumedContinuationId',v_consumed_continuation_id::text,
    'sessionVersion',v_new_version,'recoveryRestricted',
    (p_session->>'recoveryRestricted')::boolean
  ));
  IF p_evidence_kind='webauthn' THEN
    v_result:=app.private_mfa_finish_webauthn_evidence_copy_v1(
      v_result,p_anchor_id,p_evidence_id,p_completed_at
    );
  END IF;
  IF v_replacement_capability_count=1 THEN
    DELETE FROM public.tenant_mfa_ldap_recovery_replacement_capabilities
      AS capability
    WHERE capability.backend_pid=v_replacement_capability.backend_pid
      AND capability.transaction_id=v_replacement_capability.transaction_id
      AND capability.tenant_id=v_replacement_capability.tenant_id
      AND capability.source_anchor_id=
        v_replacement_capability.source_anchor_id
      AND capability.replaced_recovery_set_id=
        v_replacement_capability.replaced_recovery_set_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'LDAP recovery replacement cleanup lost CAS'
        USING ERRCODE='40001';
    END IF;
  END IF;
  RETURN v_result;
EXCEPTION WHEN lock_not_available THEN
  RAISE EXCEPTION 'LDAP MFA session authority is busy'
    USING ERRCODE='40001';
WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'LDAP MFA session authority is unavailable'
    USING ERRCODE='40001';
WHEN invalid_text_representation OR numeric_value_out_of_range
  OR data_exception THEN
  RAISE EXCEPTION 'invalid LDAP MFA session completion'
    USING ERRCODE='22023';
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_mfa_apply_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) RENAME TO private_mfa_apply_session_pre_ldap_v1;
CREATE FUNCTION app.private_mfa_apply_session_v1(
  p_session jsonb,p_anchor_id uuid,p_primary_kind text,p_primary_id uuid,
  p_primary_revision bigint,p_evidence_kind text,p_evidence_id uuid,
  p_evidence_revision bigint,p_completed_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  v_flow text;
  v_session_id uuid;
  v_continuation_id uuid;
BEGIN
  SELECT anchor.flow,anchor.session_id,anchor.continuation_id
    INTO STRICT v_flow,v_session_id,v_continuation_id
  FROM public.tenant_mfa_authority_anchors AS anchor
  WHERE anchor.id=p_anchor_id;
  IF (v_flow='session' AND p_session->>'mutation'='rotate' AND EXISTS (
      SELECT 1 FROM public.auth_session_ldap_provenance AS provenance
      WHERE provenance.session_id=v_session_id
    )) OR (v_flow='continuation'
      AND p_session->>'mutation'='consume_continuation' AND EXISTS (
      SELECT 1 FROM public.tenant_post_primary_ldap_provenance AS provenance
      WHERE provenance.continuation_id=v_continuation_id
    )) THEN
    RETURN app.private_apply_ldap_mfa_session_v1(
      p_session,p_anchor_id,p_primary_kind,p_primary_id,p_primary_revision,
      p_evidence_kind,p_evidence_id,p_evidence_revision,p_completed_at
    );
  END IF;
  RETURN app.private_mfa_apply_session_pre_ldap_v1(
    p_session,p_anchor_id,p_primary_kind,p_primary_id,p_primary_revision,
    p_evidence_kind,p_evidence_id,p_evidence_revision,p_completed_at
  );
END;
$function$;
--> statement-breakpoint

-- Generic tenant-provider MFA normally requires a freshly completed factor.
-- Recovery replacement is the one baseline-only rotation already authorized
-- by the exact internal capability above; its temporary reservation uses the
-- legacy recovery_code discriminator and the writer restores OIDC/SAML from
-- immutable provenance before returning.
DO $function$
DECLARE
  v_definition text;
  v_old constant text:=$old$expected_factor_method := CASE p_evidence_kind
      WHEN 'totp' THEN 'totp'
      WHEN 'webauthn' THEN 'passkey'
      WHEN 'recovery' THEN 'recovery_code'
    END;
    IF expected_factor_method IS NULL
       OR normalized_session -> 'reservation' ->> 'authenticationMethod'
            IS DISTINCT FROM expected_factor_method THEN$old$;
  v_new constant text:=$new$expected_factor_method := CASE p_evidence_kind
      WHEN 'totp' THEN 'totp'
      WHEN 'webauthn' THEN 'passkey'
      WHEN 'recovery' THEN 'recovery_code'
    END;
    IF expected_factor_method IS NULL AND EXISTS (
      SELECT 1
      FROM ONLY public.tenant_mfa_ldap_recovery_replacement_capabilities
        AS capability
      WHERE capability.backend_pid=pg_backend_pid()
        AND capability.transaction_id=txid_current()
        AND capability.tenant_id=anchor_tenant_id
        AND capability.source_anchor_id=p_anchor_id
        AND capability.destination_session_id=
          app.private_mfa_require_uuidv7_v1(
            normalized_session#>>'{reservation,sessionId}'
          )
        AND capability.completed_at=p_completed_at
    ) THEN
      expected_factor_method:='recovery_code';
    END IF;
    IF expected_factor_method IS NULL
       OR normalized_session -> 'reservation' ->> 'authenticationMethod'
            IS DISTINCT FROM expected_factor_method THEN$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    'app.private_mfa_apply_session_pre_ldap_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)'::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM length(v_old) THEN
    RAISE EXCEPTION 'federated recovery replacement method patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

-- The predecessor local and generic federated writers both count and copy the
-- same immutable anchor evidence projection. Exclude only the exact row named
-- by the transaction capability; every other completion remains byte-for-byte
-- on the frozen implementation.
DO $function$
DECLARE
  v_definition text;
  v_old constant text:='WHERE evidence.tenant_id = v_tenant_id AND evidence.anchor_id = v_anchor.id;';
  v_new constant text:=$new$WHERE evidence.tenant_id = v_tenant_id
    AND evidence.anchor_id = v_anchor.id
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_mfa_ldap_recovery_replacement_capabilities
        AS capability
      WHERE capability.backend_pid=pg_backend_pid()
        AND capability.transaction_id=txid_current()
        AND capability.tenant_id=evidence.tenant_id
        AND capability.source_anchor_id=evidence.anchor_id
        AND capability.source_evidence_id=evidence.id
        AND capability.replaced_recovery_set_id=
          evidence.recovery_code_set_id
        AND capability.destination_session_id=v_new_session_id
        AND capability.completed_at=p_completed_at
    );$new$;
  v_signature regprocedure;
BEGIN
  FOREACH v_signature IN ARRAY ARRAY[
    'app.private_mfa_apply_session_legacy_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)'::regprocedure,
    'app.private_mfa_apply_federated_session_v1(jsonb,uuid,text,uuid,bigint,timestamp with time zone)'::regprocedure
  ] LOOP
    v_definition:=pg_get_functiondef(v_signature);
    IF (length(v_definition)-length(replace(v_definition,v_old,'')))
         /length(v_old) IS DISTINCT FROM 2 THEN
      RAISE EXCEPTION 'recovery replacement evidence patch is ambiguous for %',
        v_signature USING ERRCODE='55000';
    END IF;
    EXECUTE replace(v_definition,v_old,v_new);
  END LOOP;
END;
$function$;
--> statement-breakpoint

-- Keep tenant-platform OIDC compatible with the same shared recovery ABI even
-- though the acceptance fixture below exercises only tenant OIDC/SAML.
DO $function$
DECLARE
  v_definition text;
  v_old constant text:='WHERE evidence.tenant_id = tenant_id AND evidence.anchor_id = anchor_record.id;';
  v_new constant text:=$new$WHERE evidence.tenant_id = tenant_id
    AND evidence.anchor_id = anchor_record.id
    AND NOT EXISTS (
      SELECT 1
      FROM ONLY public.tenant_mfa_ldap_recovery_replacement_capabilities
        AS capability
      WHERE capability.backend_pid=pg_backend_pid()
        AND capability.transaction_id=txid_current()
        AND capability.tenant_id=evidence.tenant_id
        AND capability.source_anchor_id=evidence.anchor_id
        AND capability.source_evidence_id=evidence.id
        AND capability.replaced_recovery_set_id=
          evidence.recovery_code_set_id
        AND capability.destination_session_id=new_session_id
        AND capability.completed_at=p_completed_at
    );$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    'app.private_mfa_apply_tenant_platform_federated_session_v1(jsonb,uuid,text,uuid,bigint,timestamp with time zone)'::regprocedure
  );
  IF (length(v_definition)-length(replace(v_definition,v_old,'')))
       /length(v_old) IS DISTINCT FROM 2 THEN
    RAISE EXCEPTION 'tenant-platform recovery evidence patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

-- Passkey-primary sessions perform their own live-evidence check before they
-- reach the shared session writer. Recovery replacement has already revoked
-- the old set at that point, so exclude that one row only when the same
-- transaction holds the exact unforgeable replacement capability. Ordinary
-- passkey registration and every factor completion continue to validate the
-- complete frozen evidence snapshot.
DO $function$
DECLARE
  v_definition text;
  v_old constant text:=$old$PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
    v_anchor.id,v_authority_at,
    CASE WHEN v_mutation = 'revoke' THEN 'webauthn'
      ELSE p_evidence_kind END,
    CASE WHEN v_mutation = 'revoke' THEN p_primary_id
      ELSE p_evidence_id END
  );$old$;
  v_new constant text:=$new$PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
    v_anchor.id,v_authority_at,
    CASE WHEN v_mutation = 'revoke' THEN 'webauthn'
      WHEN p_evidence_kind IS NULL AND EXISTS (
        SELECT 1
        FROM ONLY public.tenant_mfa_ldap_recovery_replacement_capabilities
          AS capability
        WHERE capability.backend_pid=pg_backend_pid()
          AND capability.transaction_id=txid_current()
          AND capability.tenant_id=v_anchor.tenant_id
          AND capability.source_anchor_id=v_anchor.id
          AND capability.destination_session_id=
            app.private_mfa_require_uuidv7_v1(
              p_session#>>'{reservation,sessionId}'
            )
          AND capability.completed_at=p_completed_at
      ) THEN 'recovery'
      ELSE p_evidence_kind END,
    CASE WHEN v_mutation = 'revoke' THEN p_primary_id
      WHEN p_evidence_kind IS NULL THEN (
        SELECT capability.replaced_recovery_set_id
        FROM ONLY public.tenant_mfa_ldap_recovery_replacement_capabilities
          AS capability
        WHERE capability.backend_pid=pg_backend_pid()
          AND capability.transaction_id=txid_current()
          AND capability.tenant_id=v_anchor.tenant_id
          AND capability.source_anchor_id=v_anchor.id
          AND capability.destination_session_id=
            app.private_mfa_require_uuidv7_v1(
              p_session#>>'{reservation,sessionId}'
            )
          AND capability.completed_at=p_completed_at
      )
      ELSE p_evidence_id END
  );$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    'app.private_mfa_apply_passkey_session_v1(jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamp with time zone)'::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM length(v_old) THEN
    RAISE EXCEPTION 'passkey recovery replacement evidence patch is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

-- Recovery-code replacement retires the prior set before rotating the
-- authenticated session. Mint exactly one typed owner-only capability after
-- that CAS, let the selected writer omit the retired evidence, and consume any
-- generic capability before audit/result persistence.
DO $function$
DECLARE
  v_definition text;
  v_old constant text:=$old$v_session_result := app.private_mfa_apply_session_v1(
    p_request -> 'session', v_anchor.id, NULL, NULL, NULL,
    NULL, NULL, NULL, (p_request ->> 'generatedAt')::timestamptz
  );$old$;
  v_new constant text:=$new$PERFORM app.private_prepare_ldap_recovery_replacement_v1(
    v_anchor.id,v_expected_set_id,p_request -> 'session',
    (p_request ->> 'generatedAt')::timestamptz
  );
  PERFORM app.private_prepare_non_ldap_recovery_replacement_v1(
    v_anchor.id,v_expected_set_id,p_request -> 'session',
    (p_request ->> 'generatedAt')::timestamptz
  );
  v_session_result := app.private_mfa_apply_session_v1(
    p_request -> 'session', v_anchor.id, NULL, NULL, NULL,
    NULL, NULL, NULL,
    (p_request ->> 'generatedAt')::timestamptz
  );
  PERFORM app.private_finish_non_ldap_recovery_replacement_v1(
    v_anchor.id,v_expected_set_id,p_request -> 'session',
    (p_request ->> 'generatedAt')::timestamptz
  );$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    'app.replace_mfa_recovery_codes_v1(jsonb)'::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM length(v_old) THEN
    RAISE EXCEPTION
      'replace_mfa_recovery_codes_v1 LDAP patch point is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

-- The completion-artifact resolver has one hard-coded typed-primary gate.
-- Patch that exact frozen v35 fragment in place; abort the migration if the
-- predecessor body is not byte-for-byte the expected ABI.  All other artifact
-- parsing, receipt, factor and replay behavior remains the shared body.
DO $function$
DECLARE
  v_definition text;
  v_old constant text:=$old$OR (v_primary_kind = 'tenant_provider' AND NOT EXISTS (
           SELECT 1
           FROM ONLY public.auth_session_federated_provenance AS provenance
           WHERE provenance.tenant_id = v_anchor.tenant_id
             AND provenance.session_id = v_anchor.session_id
             AND provenance.user_id = v_anchor.user_id
             AND provenance.primary_kind = 'tenant_provider'
             AND provenance.authentication_method =
                 v_result_authentication_method
             AND provenance.authentication_method IN ('oidc','saml')
         )) THEN
$old$;
  v_new constant text:=$new$OR (v_primary_kind = 'tenant_provider' AND NOT (
           EXISTS (
             SELECT 1
             FROM ONLY public.auth_session_federated_provenance AS provenance
             WHERE provenance.tenant_id = v_anchor.tenant_id
               AND provenance.session_id = v_anchor.session_id
               AND provenance.user_id = v_anchor.user_id
               AND provenance.primary_kind = 'tenant_provider'
               AND provenance.authentication_method =
                   v_result_authentication_method
               AND provenance.authentication_method IN ('oidc','saml')
           ) OR (
             v_result_authentication_method = 'ldap' AND EXISTS (
               SELECT 1
               FROM ONLY public.auth_session_ldap_provenance AS provenance
               WHERE provenance.tenant_id = v_anchor.tenant_id
                 AND provenance.session_id = v_anchor.session_id
                 AND provenance.user_id = v_anchor.user_id
                 AND provenance.primary_kind = 'tenant_provider'
                 AND provenance.authentication_method = 'ldap'
             )
           )
         )) THEN
$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    'app.resolve_mfa_completion_artifact_v1(jsonb)'::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM length(v_old) THEN
    RAISE EXCEPTION
      'resolve_mfa_completion_artifact_v1 LDAP patch point is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

-- The shared completion resolver validates non-primary anchors with the
-- passkey/local-factor-only evidence helper before it has resolved the typed
-- primary provenance. LDAP anchors intentionally contain one provider row, so
-- route those exact typed anchors past the incompatible generic assertion. The
-- LDAP terminal writer then locks the complete primary authority and validates
-- the same anchor with private_assert_live_ldap_evidence_v1 in the transaction
-- that consumes it. All non-LDAP anchors retain the shared assertion.
DO $function$
DECLARE
  v_definition text;
  v_old constant text:=$old$IF v_anchor.flow <> 'primary' THEN
    PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
      v_anchor.id,v_authority_at,NULL,NULL
    );
  END IF;
$old$;
  v_new constant text:=$new$IF v_anchor.flow <> 'primary'
     AND NOT (
       (v_anchor.flow = 'session' AND EXISTS (
         SELECT 1
         FROM ONLY public.auth_session_ldap_provenance AS provenance
         WHERE provenance.tenant_id = v_anchor.tenant_id
           AND provenance.session_id = v_anchor.session_id
           AND provenance.user_id = v_anchor.user_id
           AND provenance.primary_kind = 'tenant_provider'
           AND provenance.authentication_method = 'ldap'
       )) OR (v_anchor.flow = 'continuation' AND EXISTS (
         SELECT 1
         FROM ONLY public.tenant_post_primary_ldap_provenance AS provenance
         WHERE provenance.tenant_id = v_anchor.tenant_id
           AND provenance.continuation_id = v_anchor.continuation_id
           AND provenance.user_id = v_anchor.user_id
       ))
     ) THEN
    PERFORM app.private_mfa_assert_live_passkey_anchor_evidence_v1(
      v_anchor.id,v_authority_at,NULL,NULL
    );
  END IF;
$new$;
BEGIN
  v_definition:=pg_get_functiondef(
    'app.resolve_mfa_completion_artifact_v1(jsonb)'::regprocedure
  );
  IF length(v_definition)-length(replace(v_definition,v_old,''))
       IS DISTINCT FROM length(v_old) THEN
    RAISE EXCEPTION
      'resolve_mfa_completion_artifact_v1 evidence patch point is ambiguous'
      USING ERRCODE='55000';
  END IF;
  EXECUTE replace(v_definition,v_old,v_new);
END;
$function$;
--> statement-breakpoint

ALTER FUNCTION app.private_lock_ldap_primary_authority_v1(
  uuid,uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,bigint,
  bigint,uuid,uuid,bigint,timestamptz,timestamptz,boolean,boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_assert_live_ldap_evidence_row_v1(
  uuid,uuid,uuid,uuid,bigint,timestamptz,timestamptz,text,text,uuid,uuid,
  uuid,uuid,uuid,uuid,timestamptz,timestamptz,bigint,bigint,uuid,uuid
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_assert_live_ldap_evidence_v1(
  uuid,uuid,text,uuid,uuid,uuid,bigint,timestamptz,timestamptz,uuid,uuid
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_resolve_ldap_mfa_authority_v1(
  uuid,text,text,text,timestamptz,bytea
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_mfa_authority_pre_ldap_v2(
  uuid,text,text,text,timestamptz,bytea
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_mfa_authority_v2(
  uuid,text,text,text,timestamptz,bytea
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_lock_continuation_authority_pre_ldap_v1(
  uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_lock_continuation_authority_v1(
  uuid,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_prepare_ldap_recovery_replacement_v1(
  uuid,uuid,jsonb,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_prepare_non_ldap_recovery_replacement_v1(
  uuid,uuid,jsonb,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_finish_non_ldap_recovery_replacement_v1(
  uuid,uuid,jsonb,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_apply_ldap_mfa_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_apply_session_pre_ldap_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_apply_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_lock_ldap_primary_authority_v1(
  uuid,uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,bigint,
  bigint,uuid,uuid,bigint,timestamptz,timestamptz,boolean,boolean
),app.private_assert_live_ldap_evidence_row_v1(
  uuid,uuid,uuid,uuid,bigint,timestamptz,timestamptz,text,text,uuid,uuid,
  uuid,uuid,uuid,uuid,timestamptz,timestamptz,bigint,bigint,uuid,uuid
),app.private_assert_live_ldap_evidence_v1(
  uuid,uuid,text,uuid,uuid,uuid,bigint,timestamptz,timestamptz,uuid,uuid
),app.private_resolve_ldap_mfa_authority_v1(
  uuid,text,text,text,timestamptz,bytea
),app.resolve_mfa_authority_pre_ldap_v2(
  uuid,text,text,text,timestamptz,bytea
),app.private_mfa_lock_continuation_authority_pre_ldap_v1(
  uuid,timestamptz
),app.private_mfa_lock_continuation_authority_v1(
  uuid,timestamptz
),app.private_prepare_ldap_recovery_replacement_v1(
  uuid,uuid,jsonb,timestamptz
),app.private_prepare_non_ldap_recovery_replacement_v1(
  uuid,uuid,jsonb,timestamptz
),app.private_finish_non_ldap_recovery_replacement_v1(
  uuid,uuid,jsonb,timestamptz
),app.private_apply_ldap_mfa_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
),app.private_mfa_apply_session_pre_ldap_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
),app.private_mfa_apply_session_v1(
  jsonb,uuid,text,uuid,bigint,text,uuid,bigint,timestamptz
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
REVOKE ALL ON FUNCTION app.resolve_mfa_authority_v2(
  uuid,text,text,text,timestamptz,bytea
) FROM PUBLIC,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.resolve_mfa_authority_v2(
  uuid,text,text,text,timestamptz,bytea
) TO periapsis_api;
--> statement-breakpoint
