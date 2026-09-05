-- The v2 planning claim projected whether provider access was live but omitted
-- the grant identifier required by the canonical atomic apply ABI. This
-- successor resolves that identifier under the same claim lock/fence and
-- refuses any inconsistent or ambiguous live-access projection.
CREATE FUNCTION app.claim_tenant_ldap_sync_observation_planning_v3(
  p_sync_run_id uuid,
  p_observation_id uuid,
  p_claim_id uuid,
  p_claim_receipt_digest bytea,
  p_claim_fence bigint,
  p_digest_key_versions integer[],
  p_subject_digests bytea[]
)
RETURNS TABLE (
  sync_run_id uuid,
  observation_id uuid,
  tenant_id uuid,
  claim_fence bigint,
  provider_id uuid,
  provider_version integer,
  binding_id uuid,
  binding_version integer,
  binding_auth_revision integer,
  binding_access_epoch_id uuid,
  configuration_revision integer,
  rule_set_revision bigint,
  authorization_revision bigint,
  jit_mode public.identity_jit_mode,
  no_match_policy public.identity_no_match_policy,
  provider_access_source_id uuid,
  external_identity_id uuid,
  user_id uuid,
  membership_id uuid,
  access_grant_id uuid,
  external_identity_exists boolean,
  user_active boolean,
  tenant_membership_exists boolean,
  tenant_membership_active boolean,
  access_grant_live boolean,
  rules jsonb,
  security_groups jsonb,
  live_assignments jsonb,
  role_policies jsonb,
  existing_effective_role_ids uuid[],
  delegation jsonb,
  live_owned_edges jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  planning record;
  matched_access_grant_ids uuid[];
  matched_access_grant_id uuid;
BEGIN
  SELECT * INTO STRICT planning
  FROM app.claim_tenant_ldap_sync_observation_planning_v2(
    p_sync_run_id, p_observation_id, p_claim_id,
    p_claim_receipt_digest, p_claim_fence,
    p_digest_key_versions, p_subject_digests
  );

  SELECT array_agg(access_grant.id ORDER BY access_grant.id)
  INTO matched_access_grant_ids
  FROM public.tenant_ldap_provider_access_grants AS access_grant
  WHERE access_grant.tenant_id = planning.tenant_id
    AND access_grant.provider_id = planning.provider_id
    AND access_grant.binding_id = planning.binding_id
    AND access_grant.access_epoch_id = planning.binding_access_epoch_id
    AND access_grant.source_id = planning.provider_access_source_id
    AND access_grant.external_identity_id = planning.external_identity_id
    AND access_grant.membership_id = planning.membership_id
    AND access_grant.user_id = planning.user_id
    AND access_grant.ended_at IS NULL;

  IF coalesce(cardinality(matched_access_grant_ids), 0) > 1 THEN
    RAISE EXCEPTION 'tenant LDAP provider access grant is ambiguous'
      USING ERRCODE = '23505';
  END IF;
  matched_access_grant_id := matched_access_grant_ids[1];
  IF planning.access_grant_live IS DISTINCT FROM
       (matched_access_grant_id IS NOT NULL)
     OR (matched_access_grant_id IS NOT NULL AND (
       planning.external_identity_id IS NULL
       OR planning.user_id IS NULL
       OR planning.membership_id IS NULL
     )) THEN
    RAISE EXCEPTION 'tenant LDAP provider access projection is inconsistent'
      USING ERRCODE = '55000';
  END IF;

  RETURN QUERY SELECT
    planning.sync_run_id, planning.observation_id, planning.tenant_id,
    planning.claim_fence, planning.provider_id, planning.provider_version,
    planning.binding_id, planning.binding_version,
    planning.binding_auth_revision, planning.binding_access_epoch_id,
    planning.configuration_revision, planning.rule_set_revision,
    planning.authorization_revision, planning.jit_mode,
    planning.no_match_policy, planning.provider_access_source_id,
    planning.external_identity_id, planning.user_id, planning.membership_id,
    matched_access_grant_id, planning.external_identity_exists,
    planning.user_active, planning.tenant_membership_exists,
    planning.tenant_membership_active, planning.access_grant_live,
    planning.rules, planning.security_groups, planning.live_assignments,
    planning.role_policies, planning.existing_effective_role_ids,
    planning.delegation, planning.live_owned_edges;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.claim_tenant_ldap_sync_observation_planning_v3(
  uuid, uuid, uuid, bytea, bigint, integer[], bytea[]
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_tenant_ldap_sync_observation_planning_v3(
  uuid, uuid, uuid, bytea, bigint, integer[], bytea[]
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_tenant_ldap_sync_observation_planning_v3(
  uuid, uuid, uuid, bytea, bigint, integer[], bytea[]
) TO periapsis_worker;--> statement-breakpoint

-- v2 updates the observation planning fence and is therefore a superseded
-- mutation surface, not merely an obsolete read projection.
REVOKE ALL ON FUNCTION app.claim_tenant_ldap_sync_observation_planning_v2(
  uuid, uuid, uuid, bytea, bigint, integer[], bytea[]
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;
