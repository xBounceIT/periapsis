-- Federated identity material is reachable only through the bounded JSON ABI.
-- Runtime roles retain no direct relation privilege, while FORCE RLS remains a
-- second fail-closed boundary for every tenant-owned relation.
DO $federated_tables$
DECLARE
  relation_name text;
BEGIN
  FOREACH relation_name IN ARRAY ARRAY[
    'auth_session_federated_provenance',
    'tenant_federated_authentication_applications',
    'tenant_federated_authentication_transactions',
    'tenant_federated_external_identities',
    'tenant_federated_external_identity_aliases',
    'tenant_federated_mapping_rule_epochs',
    'tenant_federated_mapping_rule_role_targets',
    'tenant_federated_provider_access_grants',
    'tenant_federated_provider_policies',
    'tenant_federated_provider_profile_contributions',
    'tenant_federated_session_revalidation_commands',
    'tenant_federated_trust_rules',
    'tenant_oidc_claim_rules',
    'tenant_oidc_client_secrets',
    'tenant_oidc_discovery_snapshots',
    'tenant_oidc_jwks_snapshots',
    'tenant_oidc_provider_configurations',
    'tenant_saml_attribute_rules',
    'tenant_saml_metadata_snapshots',
    'tenant_saml_provider_configurations',
    'tenant_saml_session_materials',
    'tenant_saml_sp_certificates',
    'tenant_saml_sp_keys'
  ] LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO periapsis_migrator', relation_name);
    EXECUTE format('ALTER TABLE public.%I FORCE ROW LEVEL SECURITY', relation_name);
    EXECUTE format(
      'REVOKE ALL ON TABLE public.%I FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor, periapsis_audit_reader_owner, periapsis_notification_dispatch_owner, periapsis_sla_api_owner, periapsis_sla_worker_owner, periapsis_sla_readiness_owner',
      relation_name
    );
  END LOOP;
END
$federated_tables$;
--> statement-breakpoint

-- Extend the canonical deferred MFA provenance assertion to the federated
-- discriminator.  A session must have exactly one primary provenance kind and
-- the federated row must still resolve to the exact live identity/policy pins.
CREATE OR REPLACE FUNCTION app.assert_auth_session_mfa_provenance_v1(
  p_tenant_id uuid,
  p_session_id uuid
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  state_record public.auth_session_mfa_states%ROWTYPE;
  local_count integer;
  passkey_count integer;
  federated_count integer;
BEGIN
  SELECT state.* INTO state_record
  FROM public.auth_session_mfa_states AS state
  WHERE state.tenant_id = p_tenant_id AND state.session_id = p_session_id;
  IF NOT FOUND THEN
    RETURN;
  END IF;

  SELECT count(*)::integer INTO local_count
  FROM public.auth_session_local_credential_provenance AS provenance
  JOIN public.local_break_glass_credentials AS credential
    ON credential.id = provenance.credential_id
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id
    AND credential.user_id = state_record.user_id
    AND credential.password_version::bigint = provenance.credential_revision;

  SELECT count(*)::integer INTO passkey_count
  FROM public.auth_session_passkey_provenance AS provenance
  JOIN public.tenant_webauthn_credentials AS credential
    ON credential.tenant_id = provenance.tenant_id
   AND credential.user_id = provenance.user_id
   AND credential.id = provenance.credential_id
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id
    AND credential.version = provenance.credential_revision;

  SELECT count(*)::integer INTO federated_count
  FROM public.auth_session_federated_provenance AS provenance
  JOIN public.auth_sessions AS session
    ON session.id = provenance.session_id
   AND session.user_id = provenance.user_id
   AND session.active_tenant_id = provenance.tenant_id
  JOIN public.tenant_federated_external_identities AS identity
    ON identity.tenant_id = provenance.tenant_id
   AND identity.provider_id = provenance.provider_id
   AND identity.binding_id = provenance.binding_id
   AND identity.id = provenance.external_identity_id
   AND identity.user_id = provenance.user_id
   AND identity.version = provenance.external_identity_revision
   AND identity.retired_at IS NULL
  JOIN public.tenant_federated_provider_policies AS policy
    ON policy.tenant_id = provenance.tenant_id
   AND policy.provider_id = provenance.provider_id
   AND policy.binding_id = provenance.binding_id
   AND policy.provider_kind = provenance.provider_kind
   AND provenance.provider_kind::text = provenance.authentication_method
   AND policy.security_revision = provenance.trust_rule_revision
   AND policy.enabled
  WHERE provenance.tenant_id = p_tenant_id
    AND provenance.session_id = p_session_id
    AND provenance.user_id = state_record.user_id;

  IF (state_record.primary_kind = 'local_credential'
      AND (local_count <> 1 OR passkey_count <> 0 OR federated_count <> 0))
     OR (state_record.primary_kind = 'passkey'
      AND (local_count <> 0 OR passkey_count <> 1 OR federated_count <> 0))
     OR (state_record.primary_kind = 'tenant_provider'
      AND (local_count <> 0 OR passkey_count <> 0 OR federated_count <> 1)) THEN
    RAISE EXCEPTION 'auth session has invalid typed primary provenance'
      USING ERRCODE = '23514';
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.assert_auth_session_mfa_provenance_v1(uuid, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.assert_auth_session_mfa_provenance_v1(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint

CREATE CONSTRAINT TRIGGER auth_session_federated_provenance_parent_v1
AFTER INSERT OR UPDATE OR DELETE ON public.auth_session_federated_provenance
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION app.enforce_auth_session_mfa_provenance_v1();
--> statement-breakpoint

-- The pre-existing continuation table cannot express the four-column external
-- identity relationship without a circular schema dependency. Enforce it at
-- write time, including the live policy/security revision pin.
CREATE FUNCTION app.validate_federated_continuation_provenance_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NEW.primary_kind = 'tenant_provider' AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_federated_external_identities AS identity
    JOIN public.tenants AS tenant
      ON tenant.id = identity.tenant_id
     AND tenant.status = 'active'
    JOIN public.tenant_auth_providers AS provider
      ON provider.tenant_id = identity.tenant_id
     AND provider.id = identity.provider_id
     AND provider.kind = NEW.provider_kind
     AND provider.enabled AND provider.archived_at IS NULL
    JOIN public.tenant_auth_provider_bindings AS binding
      ON binding.tenant_id = identity.tenant_id
     AND binding.id = identity.binding_id
     AND binding.provider_id = identity.provider_id
     AND binding.enabled AND binding.archived_at IS NULL
     AND binding.current_access_epoch_id IS NOT NULL
    JOIN public.tenant_federated_provider_policies AS policy
      ON policy.tenant_id = identity.tenant_id
     AND policy.provider_id = identity.provider_id
     AND policy.binding_id = NEW.binding_id
     AND policy.provider_kind = NEW.provider_kind
     AND policy.enabled
    JOIN public.tenant_mfa_subjects AS subject
      ON subject.tenant_id = identity.tenant_id
     AND subject.user_id = identity.user_id
     AND subject.identity_epoch = NEW.identity_epoch
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = identity.tenant_id
     AND membership.user_id = identity.user_id
     AND membership.status = 'active'
    JOIN public.tenant_federated_provider_access_grants AS access_grant
      ON access_grant.tenant_id = identity.tenant_id
     AND access_grant.provider_id = identity.provider_id
     AND access_grant.binding_id = identity.binding_id
     AND access_grant.access_epoch_id = binding.current_access_epoch_id
     AND access_grant.external_identity_id = identity.id
     AND access_grant.membership_id = membership.id
     AND access_grant.user_id = identity.user_id
     AND access_grant.started_at <= transaction_timestamp()
     AND access_grant.ended_at IS NULL
    JOIN public.tenant_identity_provider_access_epochs AS access_epoch
      ON access_epoch.tenant_id = access_grant.tenant_id
     AND access_epoch.id = access_grant.access_epoch_id
     AND access_epoch.binding_id = access_grant.binding_id
     AND access_epoch.provider_id = access_grant.provider_id
     AND access_epoch.source_id = access_grant.source_id
     AND access_epoch.started_at <= transaction_timestamp()
     AND access_epoch.ended_at IS NULL
    JOIN public.tenant_authorization_sources AS access_source
      ON access_source.tenant_id = access_grant.tenant_id
     AND access_source.id = access_grant.source_id
     AND access_source.retired_at IS NULL
    WHERE identity.tenant_id = NEW.tenant_id
      AND identity.provider_id = NEW.provider_id
      AND identity.binding_id = NEW.binding_id
      AND identity.id = NEW.external_identity_id
      AND identity.user_id = NEW.user_id
      AND identity.version = NEW.primary_revision
      AND identity.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'continuation has invalid federated primary provenance'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.validate_federated_continuation_provenance_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_federated_continuation_provenance_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER tenant_post_primary_continuations_federated_provenance_v1
BEFORE INSERT OR UPDATE ON public.tenant_post_primary_continuations
FOR EACH ROW EXECUTE FUNCTION app.validate_federated_continuation_provenance_v1();
--> statement-breakpoint

-- Arrays are canonical operation inputs in Go. Enforce the same ordering,
-- uniqueness and byte bounds in storage so a configuration cannot acquire two
-- digests or interpretation orders across runtimes.
CREATE FUNCTION app.validate_saml_configuration_canonical_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  canonical_key_versions integer[];
  canonical_contexts text[];
BEGIN
  SELECT coalesce(array_agg(value ORDER BY value), ARRAY[]::integer[])
    INTO canonical_key_versions
  FROM (SELECT DISTINCT unnest(NEW.decryption_key_versions) AS value) AS values;
  SELECT coalesce(array_agg(value ORDER BY value COLLATE "C"), ARRAY[]::text[])
    INTO canonical_contexts
  FROM (SELECT DISTINCT unnest(NEW.requested_authn_contexts) AS value) AS values;

  IF NEW.decryption_key_versions IS DISTINCT FROM canonical_key_versions
     OR EXISTS (
       SELECT 1 FROM unnest(NEW.decryption_key_versions) AS value
       WHERE value < 1
     )
     OR NEW.requested_authn_contexts IS DISTINCT FROM canonical_contexts
     OR EXISTS (
       SELECT 1 FROM unnest(NEW.requested_authn_contexts) AS value
       WHERE octet_length(convert_to(value, 'UTF8')) NOT BETWEEN 1 AND 2048
          OR value ~ '[[:cntrl:]]'
     ) THEN
    RAISE EXCEPTION 'SAML configuration arrays are not canonical'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.validate_saml_configuration_canonical_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.validate_saml_configuration_canonical_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER tenant_saml_provider_configurations_canonical_v1
BEFORE INSERT OR UPDATE ON public.tenant_saml_provider_configurations
FOR EACH ROW EXECUTE FUNCTION app.validate_saml_configuration_canonical_v1();
--> statement-breakpoint

-- Browser transaction authority pins and protocol payloads are immutable.
-- Only the closed lifecycle fields may advance under exact CAS.
CREATE FUNCTION app.guard_federated_authentication_transaction_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'federated authentication transactions are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF (to_jsonb(NEW) - ARRAY[
        'state','version','claim_attempt_id','claimed_at','completed_at','failure_reason'
      ]) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY[
        'state','version','claim_attempt_id','claimed_at','completed_at','failure_reason'
      ]) THEN
    RAISE EXCEPTION 'federated authentication transaction authority is immutable'
      USING ERRCODE = '55000';
  END IF;
  IF NEW.version <> OLD.version + 1 THEN
    RAISE EXCEPTION 'federated authentication transaction version must advance once'
      USING ERRCODE = '40001';
  END IF;
  IF NOT (
    (OLD.protocol = 'oidc' AND OLD.state = 'pending'
      AND NEW.state IN ('claimed','failed','expired'))
    OR (OLD.protocol = 'oidc' AND OLD.state = 'claimed'
      AND NEW.state IN ('completed','failed','expired'))
    OR (OLD.protocol = 'saml' AND OLD.state = 'pending'
      AND NEW.state IN ('completed','failed','expired'))
  ) THEN
    RAISE EXCEPTION 'invalid federated authentication transaction transition'
      USING ERRCODE = '23514';
  END IF;
  IF OLD.protocol = 'saml' AND NEW.state = 'claimed' THEN
    RAISE EXCEPTION 'SAML transactions cannot enter claimed state'
      USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_federated_authentication_transaction_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_federated_authentication_transaction_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER tenant_federated_authentication_transactions_guard_v1
BEFORE UPDATE OR DELETE ON public.tenant_federated_authentication_transactions
FOR EACH ROW EXECUTE FUNCTION app.guard_federated_authentication_transaction_v1();
--> statement-breakpoint

CREATE FUNCTION app.guard_federated_immutable_ledger_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'federated authentication replay ledgers are immutable'
    USING ERRCODE = '55000';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_federated_immutable_ledger_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_federated_immutable_ledger_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_audit_reader_owner,
       periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
       periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
--> statement-breakpoint
CREATE TRIGGER tenant_federated_authentication_applications_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_federated_authentication_applications
FOR EACH ROW EXECUTE FUNCTION app.guard_federated_immutable_ledger_v1();
--> statement-breakpoint
CREATE TRIGGER tenant_federated_session_revalidation_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.tenant_federated_session_revalidation_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_federated_immutable_ledger_v1();
