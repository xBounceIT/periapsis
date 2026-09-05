ALTER TYPE public.ldap_provider_test_category OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_provider_test_kind OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_provider_test_outcome OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TYPE public.ldap_provider_test_status OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_test_runs OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.tenant_ldap_provider_test_runs FORCE ROW LEVEL SECURITY;--> statement-breakpoint

REVOKE ALL ON TYPE public.ldap_provider_test_category FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TYPE public.ldap_provider_test_kind FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TYPE public.ldap_provider_test_outcome FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TYPE public.ldap_provider_test_status FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON TABLE public.tenant_ldap_provider_test_runs FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT USAGE ON TYPE public.ldap_provider_test_category TO periapsis_api;--> statement-breakpoint
GRANT USAGE ON TYPE public.ldap_provider_test_kind TO periapsis_api;--> statement-breakpoint
GRANT USAGE ON TYPE public.ldap_provider_test_outcome TO periapsis_api;--> statement-breakpoint

-- 0045 exposed the envelope as a temporary foundation ABI. Test admission is
-- now the only supported reader: it pins revisions, rate-limits, and audits
-- before returning ciphertext to the API process.
REVOKE ALL ON FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
DROP FUNCTION app.get_tenant_ldap_bind_secret_envelope_v1(uuid);--> statement-breakpoint

-- Test runs are append-once, complete-once records. The only permitted update
-- is the exact started -> completed transition performed by the definer API.
CREATE FUNCTION app.guard_tenant_ldap_provider_test_run_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'tenant LDAP provider test runs cannot be deleted'
      USING ERRCODE = '55000';
  END IF;

  IF OLD.status <> 'started'
     OR NEW.status <> 'completed'
     OR NEW.version <> 2
     OR (
       to_jsonb(NEW) - ARRAY[
         'status', 'outcome', 'category', 'endpoint_priority',
         'duration_ms', 'completed_by_membership_id', 'completed_at',
         'version'
       ]::text[]
     ) IS DISTINCT FROM (
       to_jsonb(OLD) - ARRAY[
         'status', 'outcome', 'category', 'endpoint_priority',
         'duration_ms', 'completed_by_membership_id', 'completed_at',
         'version'
       ]::text[]
     ) THEN
    RAISE EXCEPTION 'tenant LDAP provider test run transition is invalid'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER tenant_ldap_provider_test_runs_guard_update_delete
BEFORE UPDATE OR DELETE ON public.tenant_ldap_provider_test_runs
FOR EACH ROW
EXECUTE FUNCTION app.guard_tenant_ldap_provider_test_run_v1();--> statement-breakpoint

-- Admit and pin one exact provider/configuration/secret snapshot. The caller
-- must commit before DNS or LDAP I/O. A connection-only test never receives
-- the encrypted bind envelope.
CREATE FUNCTION app.begin_tenant_ldap_provider_test_v1(
  p_test_run_id uuid,
  p_provider_id uuid,
  p_test_kind public.ldap_provider_test_kind,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  test_run_id uuid,
  provider_id uuid,
  provider_version integer,
  configuration_version integer,
  secret_version integer,
  configuration jsonb,
  endpoints jsonb,
  secret_id uuid,
  secret_ciphertext bytea,
  secret_nonce bytea,
  secret_key_version integer,
  encryption_algorithm text,
  started_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_provider public.tenant_auth_providers%ROWTYPE;
  locked_configuration public.tenant_ldap_provider_configs%ROWTYPE;
  locked_secret public.tenant_ldap_provider_secrets%ROWTYPE;
  recent_actor_provider_test_count integer;
  recent_provider_test_count integer;
  recent_tenant_test_count integer;
  test_started_at timestamp with time zone := transaction_timestamp();
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.test', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.test tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_test_run_id IS NULL
     OR (uuid_extract_version(p_test_run_id) = 7) IS NOT TRUE
     OR p_test_kind IS NULL
     OR p_request_id IS NULL
     OR p_correlation_id IS NULL THEN
    RAISE EXCEPTION 'invalid tenant LDAP provider test request'
      USING ERRCODE = '22023';
  END IF;

  SELECT provider.*
  INTO locked_provider
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = p_provider_id
    AND provider.kind = 'ldap'
  FOR SHARE;
  IF NOT FOUND OR locked_provider.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'tenant LDAP provider was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT provider_configuration.*
  INTO locked_configuration
  FROM public.tenant_ldap_provider_configs AS provider_configuration
  WHERE provider_configuration.tenant_id = context_tenant
    AND provider_configuration.provider_id = p_provider_id
  FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider configuration is unavailable'
      USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1
    FROM public.tenant_ldap_provider_urls AS endpoint
    WHERE endpoint.tenant_id = context_tenant
      AND endpoint.provider_id = p_provider_id
      AND endpoint.enabled
  ) THEN
    RAISE EXCEPTION 'tenant LDAP provider has no enabled endpoint'
      USING ERRCODE = '55000';
  END IF;

  IF p_test_kind = 'bind' THEN
    SELECT provider_secret.*
    INTO locked_secret
    FROM public.tenant_ldap_provider_secrets AS provider_secret
    WHERE provider_secret.tenant_id = context_tenant
      AND provider_secret.provider_id = p_provider_id
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'tenant LDAP provider bind secret is unavailable'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  SELECT
    count(*) FILTER (
      WHERE recent_test.provider_id = p_provider_id
        AND recent_test.started_by_membership_id = actor_membership
    )::integer,
    count(*) FILTER (
      WHERE recent_test.provider_id = p_provider_id
    )::integer,
    count(*)::integer
  INTO
    recent_actor_provider_test_count,
    recent_provider_test_count,
    recent_tenant_test_count
  FROM public.tenant_ldap_provider_test_runs AS recent_test
  WHERE recent_test.tenant_id = context_tenant
    -- The enum is sealed to these two exhaustive values. Keeping the predicate
    -- explicit lets PostgreSQL use the tenant/status/time rate-limit index.
    AND recent_test.status IN ('started', 'completed')
    AND recent_test.started_at >= test_started_at - interval '1 minute';
  IF recent_actor_provider_test_count >= 5
     OR recent_provider_test_count >= 20
     OR recent_tenant_test_count >= 50 THEN
    RAISE EXCEPTION 'tenant LDAP provider tests are temporarily rate limited'
      USING ERRCODE = '53300';
  END IF;

  INSERT INTO public.tenant_ldap_provider_test_runs (
    id, tenant_id, provider_id, provider_kind, test_kind,
    provider_version, configuration_version, secret_version,
    started_by_membership_id, request_id, correlation_id, started_at
  ) VALUES (
    p_test_run_id, context_tenant, p_provider_id, 'ldap', p_test_kind,
    locked_provider.version, locked_configuration.version,
    CASE WHEN p_test_kind = 'bind' THEN locked_secret.version ELSE NULL END,
    actor_membership, p_request_id, p_correlation_id, test_started_at
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.test_started',
    'identity_provider_test', p_test_run_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method, NULL,
    jsonb_build_object(
      'provider_id', p_provider_id,
      'test_kind', p_test_kind,
      'provider_version', locked_provider.version,
      'configuration_version', locked_configuration.version,
      'bind_secret_configured', p_test_kind = 'bind'
    ),
    '{}'::jsonb
  );

  RETURN QUERY
  SELECT p_test_run_id,
         p_provider_id,
         locked_provider.version,
         locked_configuration.version,
         CASE WHEN p_test_kind = 'bind' THEN locked_secret.version ELSE NULL END,
         jsonb_build_object(
           'template', locked_configuration.template,
           'verifyCertificate', locked_configuration.verify_certificate,
           'customCaPem', locked_configuration.custom_ca_pem,
           'connectTimeoutMs', locked_configuration.connect_timeout_ms,
           'operationTimeoutMs', locked_configuration.operation_timeout_ms,
           'bindDn', locked_configuration.bind_dn,
           'userBaseDn', locked_configuration.user_base_dn,
           'groupBaseDn', locked_configuration.group_base_dn,
           'userSearchFilter', locked_configuration.user_search_filter,
           'groupSearchFilter', locked_configuration.group_search_filter,
           'userDnTemplate', locked_configuration.user_dn_template,
           'pageSize', locked_configuration.page_size,
           'maxPages', locked_configuration.max_pages,
           'maxEntries', locked_configuration.max_entries,
           'maxResponseBytes', locked_configuration.max_response_bytes,
           'referralMode', locked_configuration.referral_mode,
           'maxReferralHops', locked_configuration.max_referral_hops,
           'nestedGroupMode', locked_configuration.nested_group_mode,
           'maxNestedGroupDepth', locked_configuration.max_nested_group_depth,
           'maxGroups', locked_configuration.max_groups,
           'firstNameAttribute', locked_configuration.first_name_attribute,
           'lastNameAttribute', locked_configuration.last_name_attribute,
           'displayNameAttribute', locked_configuration.display_name_attribute,
           'usernameAttribute', locked_configuration.username_attribute,
           'alternateUsernameAttribute', locked_configuration.alternate_username_attribute,
           'emailAttribute', locked_configuration.email_attribute,
           'immutableSubjectAttribute', locked_configuration.immutable_subject_attribute,
           'immutableSubjectFormat', locked_configuration.immutable_subject_format,
           'groupMembershipAttribute', locked_configuration.group_membership_attribute,
           'posixMemberUidAttribute', locked_configuration.posix_member_uid_attribute,
           'posixGidNumberAttribute', locked_configuration.posix_gid_number_attribute,
           'accountStatusMode', locked_configuration.account_status_mode,
           'accountStatusAttribute', locked_configuration.account_status_attribute,
           'accountDisabledValue', locked_configuration.account_disabled_value,
           'jitMode', locked_configuration.jit_mode,
           'noMatchPolicy', locked_configuration.no_match_policy,
           'deprovisionMode', locked_configuration.deprovision_mode,
           'deprovisionGraceSeconds', locked_configuration.deprovision_grace_seconds,
           'syncIntervalSeconds', locked_configuration.sync_interval_seconds
         ),
         (
           SELECT jsonb_agg(
             jsonb_build_object(
               'priority', endpoint.priority,
               'host', endpoint.host,
               'port', endpoint.port,
               'transport', endpoint.transport,
               'tlsServerName', endpoint.tls_server_name,
               'referralAllowed', endpoint.referral_allowed,
               'enabled', endpoint.enabled
             ) ORDER BY endpoint.priority
           )
           FROM public.tenant_ldap_provider_urls AS endpoint
           WHERE endpoint.tenant_id = context_tenant
             AND endpoint.provider_id = p_provider_id
             AND endpoint.enabled
         ),
         CASE WHEN p_test_kind = 'bind' THEN locked_secret.id ELSE NULL END,
         CASE WHEN p_test_kind = 'bind' THEN locked_secret.secret_ciphertext ELSE NULL END,
         CASE WHEN p_test_kind = 'bind' THEN locked_secret.secret_nonce ELSE NULL END,
         CASE WHEN p_test_kind = 'bind' THEN locked_secret.key_version ELSE NULL END,
         CASE WHEN p_test_kind = 'bind' THEN locked_secret.encryption_algorithm ELSE NULL END,
         test_started_at;
END;
$function$;--> statement-breakpoint

-- Complete in a new transaction. A revision or lifecycle change wins over an
-- upstream result and makes the diagnostic inconclusive/stale.
CREATE FUNCTION app.complete_tenant_ldap_provider_test_v1(
  p_test_run_id uuid,
  p_reported_outcome public.ldap_provider_test_outcome,
  p_reported_category public.ldap_provider_test_category,
  p_endpoint_priority integer,
  p_duration_ms integer,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  test_run_id uuid,
  outcome public.ldap_provider_test_outcome,
  category public.ldap_provider_test_category,
  endpoint_priority integer,
  duration_ms integer,
  stale boolean,
  completed_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  locked_run public.tenant_ldap_provider_test_runs%ROWTYPE;
  current_provider_version integer;
  current_provider_archived_at timestamp with time zone;
  current_configuration_version integer;
  current_secret_version integer;
  result_is_stale boolean := false;
  result_is_expired boolean := false;
  effective_outcome public.ldap_provider_test_outcome;
  effective_category public.ldap_provider_test_category;
  test_completed_at timestamp with time zone := transaction_timestamp();
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'identity_provider.test', 'tenant'
  ) THEN
    RAISE EXCEPTION 'identity_provider.test tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reported_outcome IS NULL
     OR p_reported_category IS NULL
     OR p_duration_ms IS NULL
     OR p_request_id IS NULL
     OR p_correlation_id IS NULL
     OR p_duration_ms NOT BETWEEN 0 AND 120000
     OR (p_endpoint_priority IS NOT NULL AND p_endpoint_priority NOT BETWEEN 1 AND 8)
     OR (p_reported_category <> 'cancelled' AND p_endpoint_priority IS NULL)
     OR NOT (
       (
         p_reported_outcome = 'success'
         AND p_reported_category = 'success'
         AND p_endpoint_priority IS NOT NULL
       )
       OR (
         p_reported_outcome = 'failure'
         AND p_reported_category NOT IN ('success', 'stale_configuration')
       )
     ) THEN
    RAISE EXCEPTION 'invalid tenant LDAP provider test result'
      USING ERRCODE = '22023';
  END IF;

  SELECT test_run.*
  INTO locked_run
  FROM public.tenant_ldap_provider_test_runs AS test_run
  WHERE test_run.tenant_id = context_tenant
    AND test_run.id = p_test_run_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant LDAP provider test run was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked_run.status <> 'started' THEN
    RAISE EXCEPTION 'tenant LDAP provider test run is already completed'
      USING ERRCODE = '55000';
  END IF;
  IF locked_run.started_by_membership_id <> actor_membership THEN
    RAISE EXCEPTION 'tenant LDAP provider test run belongs to another actor'
      USING ERRCODE = '42501';
  END IF;
  IF locked_run.request_id IS DISTINCT FROM p_request_id
     OR locked_run.correlation_id IS DISTINCT FROM p_correlation_id THEN
    RAISE EXCEPTION 'tenant LDAP provider test correlation does not match'
      USING ERRCODE = '22023';
  END IF;
  IF locked_run.test_kind = 'connection'
     AND p_reported_category = 'bind_rejected' THEN
    RAISE EXCEPTION 'connection-only LDAP tests cannot report a bind result'
      USING ERRCODE = '22023';
  END IF;

  result_is_expired :=
    test_completed_at > locked_run.started_at + interval '2 minutes';

  SELECT provider.version, provider.archived_at
  INTO current_provider_version, current_provider_archived_at
  FROM public.tenant_auth_providers AS provider
  WHERE provider.tenant_id = context_tenant
    AND provider.id = locked_run.provider_id
    AND provider.kind = 'ldap'
  FOR SHARE;
  IF NOT FOUND THEN
    result_is_stale := true;
  END IF;

  SELECT provider_configuration.version
  INTO current_configuration_version
  FROM public.tenant_ldap_provider_configs AS provider_configuration
  WHERE provider_configuration.tenant_id = context_tenant
    AND provider_configuration.provider_id = locked_run.provider_id
  FOR SHARE;
  IF NOT FOUND THEN
    result_is_stale := true;
  END IF;

  IF locked_run.test_kind = 'bind' THEN
    SELECT provider_secret.version
    INTO current_secret_version
    FROM public.tenant_ldap_provider_secrets AS provider_secret
    WHERE provider_secret.tenant_id = context_tenant
      AND provider_secret.provider_id = locked_run.provider_id
    FOR SHARE;
    IF NOT FOUND THEN
      result_is_stale := true;
    END IF;
  END IF;

  result_is_stale := result_is_stale
    OR current_provider_archived_at IS NOT NULL
    OR current_provider_version IS DISTINCT FROM locked_run.provider_version
    OR current_configuration_version IS DISTINCT FROM locked_run.configuration_version
    OR (
      locked_run.test_kind = 'bind'
      AND current_secret_version IS DISTINCT FROM locked_run.secret_version
    );

  IF NOT result_is_stale
     AND p_endpoint_priority IS NOT NULL
     AND NOT EXISTS (
       SELECT 1
       FROM public.tenant_ldap_provider_urls AS endpoint
       WHERE endpoint.tenant_id = context_tenant
         AND endpoint.provider_id = locked_run.provider_id
         AND endpoint.priority = p_endpoint_priority
         AND endpoint.enabled
     ) THEN
    RAISE EXCEPTION 'tenant LDAP provider test endpoint is not in the current enabled configuration'
      USING ERRCODE = '22023';
  END IF;

  IF result_is_stale THEN
    effective_outcome := 'inconclusive';
    effective_category := 'stale_configuration';
  ELSIF result_is_expired THEN
    effective_outcome := 'failure';
    effective_category := 'cancelled';
  ELSE
    effective_outcome := p_reported_outcome;
    effective_category := p_reported_category;
  END IF;

  UPDATE public.tenant_ldap_provider_test_runs AS test_run
  SET status = 'completed',
      outcome = effective_outcome,
      category = effective_category,
      endpoint_priority = p_endpoint_priority,
      duration_ms = p_duration_ms,
      completed_by_membership_id = actor_membership,
      completed_at = test_completed_at,
      version = 2
  WHERE test_run.tenant_id = context_tenant
    AND test_run.id = p_test_run_id;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.identity_provider.test_completed',
    'identity_provider_test', p_test_run_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method,
    jsonb_build_object(
      'provider_id', locked_run.provider_id,
      'test_kind', locked_run.test_kind,
      'status', 'started',
      'provider_version', locked_run.provider_version,
      'configuration_version', locked_run.configuration_version
    ),
    jsonb_build_object(
      'status', 'completed',
      'outcome', effective_outcome,
      'category', effective_category,
      'endpoint_priority', p_endpoint_priority,
      'duration_ms', p_duration_ms
    ),
    jsonb_build_object(
      'stale_configuration', result_is_stale,
      'expired_test', result_is_expired
    )
  );

  RETURN QUERY
  SELECT p_test_run_id,
         effective_outcome,
         effective_category,
         p_endpoint_priority,
         p_duration_ms,
         result_is_stale,
         test_completed_at;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.guard_tenant_ldap_provider_test_run_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.begin_tenant_ldap_provider_test_v1(uuid, uuid, public.ldap_provider_test_kind, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.complete_tenant_ldap_provider_test_v1(uuid, public.ldap_provider_test_outcome, public.ldap_provider_test_category, integer, integer, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.guard_tenant_ldap_provider_test_run_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.begin_tenant_ldap_provider_test_v1(uuid, uuid, public.ldap_provider_test_kind, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.complete_tenant_ldap_provider_test_v1(uuid, public.ldap_provider_test_outcome, public.ldap_provider_test_category, integer, integer, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.begin_tenant_ldap_provider_test_v1(uuid, uuid, public.ldap_provider_test_kind, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.complete_tenant_ldap_provider_test_v1(uuid, public.ldap_provider_test_outcome, public.ldap_provider_test_category, integer, integer, uuid, uuid, inet, text, text) TO periapsis_api;
