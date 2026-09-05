-- Keep every operator-team lifecycle path on one lock order:
-- tenant authorization states (tenant order), global team, assignment epoch,
-- then roster rows. Platform metadata changes need the state pre-lock because
-- their representation-version fan-out updates tenant assignment rows.
CREATE FUNCTION "app"."lock_operator_team_assignment_states"(
  p_operator_team_id uuid
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  affected record;
  locked_count integer := 0;
BEGIN
  FOR affected IN
    SELECT state.tenant_id
    FROM public.tenant_authorization_states AS state
    WHERE EXISTS (
      SELECT 1
      FROM public.operator_team_assignment_epochs AS assignment
      WHERE assignment.tenant_id = state.tenant_id
        AND assignment.operator_team_id = p_operator_team_id
    )
    ORDER BY state.tenant_id
    FOR UPDATE
  LOOP
    locked_count := locked_count + 1;
  END LOOP;

  RETURN locked_count;
END;
$function$;--> statement-breakpoint

-- Assignment epochs are historical facts. Their identity and assignment
-- provenance never change, and their end tuple may transition exactly once
-- from wholly open to wholly closed. Representation-version maintenance is
-- intentionally left available to the bounded lifecycle functions and team
-- summary trigger.
CREATE FUNCTION "app"."guard_operator_team_assignment_epoch_immutability"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF OLD.id IS DISTINCT FROM NEW.id
     OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id
     OR OLD.operator_team_id IS DISTINCT FROM NEW.operator_team_id
     OR OLD.assigned_by_membership_id IS DISTINCT FROM NEW.assigned_by_membership_id
     OR OLD.assignment_reason IS DISTINCT FROM NEW.assignment_reason
     OR OLD.assigned_at IS DISTINCT FROM NEW.assigned_at THEN
    RAISE EXCEPTION 'operator-team assignment epoch identity and provenance are immutable'
      USING ERRCODE = '55000';
  END IF;

  IF OLD.ended_at IS NULL THEN
    IF NEW.ended_at IS NULL
       AND NEW.ended_by_membership_id IS NULL
       AND NEW.end_reason IS NULL THEN
      RETURN NEW;
    END IF;
    IF NEW.ended_at IS NOT NULL
       AND NEW.ended_by_membership_id IS NOT NULL
       AND NEW.end_reason IS NOT NULL THEN
      RETURN NEW;
    END IF;

    RAISE EXCEPTION 'operator-team assignment epoch end must be an atomic transition'
      USING ERRCODE = '55000';
  END IF;

  IF OLD.ended_at IS DISTINCT FROM NEW.ended_at
     OR OLD.ended_by_membership_id IS DISTINCT FROM NEW.ended_by_membership_id
     OR OLD.end_reason IS DISTINCT FROM NEW.end_reason THEN
    RAISE EXCEPTION 'ended operator-team assignment epoch history is immutable'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER "operator_team_assignment_epochs_immutable_guard"
BEFORE UPDATE
ON "public"."operator_team_assignment_epochs"
FOR EACH ROW
EXECUTE FUNCTION "app"."guard_operator_team_assignment_epoch_immutability"();--> statement-breakpoint

-- Starting or ending an epoch changes active_assignment_count in the strong
-- team representation. The protected assignment writers already hold the
-- team row after the tenant state, so this trigger advances that representation
-- version in the same transaction without adding another public ABI.
CREATE FUNCTION "app"."touch_operator_team_assignment_representation"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'INSERT' AND NEW.ended_at IS NOT NULL THEN
    RETURN NEW;
  END IF;
  IF TG_OP = 'UPDATE'
     AND OLD.ended_at IS NOT DISTINCT FROM NEW.ended_at THEN
    RETURN NEW;
  END IF;

  UPDATE public.operator_teams AS operator_team
  SET version = operator_team.version + 1,
      updated_at = transaction_timestamp()
  WHERE operator_team.id = NEW.operator_team_id
    AND operator_team.version < 2147483647;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator team version is exhausted during assignment representation change'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER "operator_team_assignment_epochs_team_representation_touch"
AFTER INSERT OR UPDATE OF "ended_at"
ON "public"."operator_team_assignment_epochs"
FOR EACH ROW
EXECUTE FUNCTION "app"."touch_operator_team_assignment_representation"();--> statement-breakpoint

-- Assignment representations embed the team display name and archive state.
-- A table trigger makes the fan-out writer-complete, including an old function
-- body that crosses this migration and future protected writers. Current
-- functions pre-lock tenant states before the team row; a crossing old writer
-- that already owns the team row can only serialize or fail retryably.
CREATE FUNCTION "app"."touch_operator_team_assignment_summaries"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  affected_state record;
BEGIN
  IF OLD.display_name IS NOT DISTINCT FROM NEW.display_name
     AND OLD.archived_at IS NOT DISTINCT FROM NEW.archived_at THEN
    RETURN NEW;
  END IF;

  -- Current functions already own these rows in tenant order. A crossing old
  -- body owns the team first; it must fail retryably instead of waiting on a
  -- state-first writer and forming a deadlock cycle.
  BEGIN
    FOR affected_state IN
      SELECT state.tenant_id
      FROM public.tenant_authorization_states AS state
      WHERE EXISTS (
        SELECT 1
        FROM public.operator_team_assignment_epochs AS assignment
        WHERE assignment.tenant_id = state.tenant_id
          AND assignment.operator_team_id = NEW.id
      )
      ORDER BY state.tenant_id
      FOR UPDATE NOWAIT
    LOOP
      NULL;
    END LOOP;
  EXCEPTION WHEN lock_not_available THEN
    RAISE EXCEPTION 'operator-team representation change must be retried'
      USING ERRCODE = '40001';
  END;
  IF EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.operator_team_id = NEW.id
      AND assignment.version >= 2147483647
  ) THEN
    RAISE EXCEPTION 'operator-team assignment version is exhausted during team representation change'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.operator_team_assignment_epochs AS assignment
  SET version = assignment.version + 1,
      updated_at = transaction_timestamp()
  WHERE assignment.operator_team_id = NEW.id;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER "operator_teams_assignment_summary_touch"
AFTER UPDATE OF "display_name", "archived_at"
ON "public"."operator_teams"
FOR EACH ROW
EXECUTE FUNCTION "app"."touch_operator_team_assignment_summaries"();--> statement-breakpoint

-- A membership may hold at most 200 potentially live exact (team, epoch)
-- relationships. Reversible membership/user/tenant gates are deliberately
-- excluded so suspended or inactive principals cannot accumulate dormant
-- edges that exceed the cap when reactivated. Provenance duplicates for the
-- same epoch count once. The tenant state lock makes the check and insert
-- atomic across current and future provider writers.
CREATE FUNCTION "app"."guard_operator_team_relationship_capacity"()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  relationship_count integer := 0;
  excluded_roster_id uuid := NULL;
  locked_state_count integer := 0;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    excluded_roster_id := OLD.id;
    IF OLD.tenant_id IS DISTINCT FROM NEW.tenant_id THEN
      RAISE EXCEPTION 'operator-team roster tenant is immutable'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  PERFORM 1
  FROM public.tenant_authorization_states AS state
  WHERE state.tenant_id = NEW.tenant_id
  FOR UPDATE;

  GET DIAGNOSTICS locked_state_count = ROW_COUNT;
  IF locked_state_count <> 1 THEN
    RAISE EXCEPTION 'tenant authorization state is unavailable'
      USING ERRCODE = '55000';
  END IF;

  -- Rows outside a live relationship cannot consume the live cardinality.
  IF NEW.revoked_at IS NOT NULL
     OR (NEW.expires_at IS NOT NULL
       AND NEW.expires_at <= transaction_timestamp())
     OR NOT EXISTS (
       SELECT 1
       FROM public.operator_team_assignment_epochs AS assignment
       JOIN public.operator_teams AS operator_team
         ON operator_team.id = assignment.operator_team_id
       JOIN public.tenant_authorization_sources AS source
         ON source.tenant_id = NEW.tenant_id
        AND source.id = NEW.source_id
       WHERE assignment.tenant_id = NEW.tenant_id
         AND assignment.id = NEW.assignment_epoch_id
         AND assignment.ended_at IS NULL
         AND operator_team.archived_at IS NULL
         AND source.retired_at IS NULL
     ) THEN
    RETURN NEW;
  END IF;

  -- A second provenance row for an already-counted exact epoch cannot consume
  -- capacity. Resolve this indexed fast path before scanning the membership's
  -- other relationships; provider fan-in must not make writes quadratic.
  IF EXISTS (
    SELECT 1
    FROM public.operator_team_roster_entries AS existing
    JOIN public.tenant_authorization_sources AS existing_source
      ON existing_source.tenant_id = existing.tenant_id
     AND existing_source.id = existing.source_id
    WHERE existing.tenant_id = NEW.tenant_id
      AND existing.assignment_epoch_id = NEW.assignment_epoch_id
      AND existing.membership_id = NEW.membership_id
      AND (excluded_roster_id IS NULL OR existing.id <> excluded_roster_id)
      AND existing.revoked_at IS NULL
      AND (existing.expires_at IS NULL
        OR existing.expires_at > transaction_timestamp())
      AND existing_source.retired_at IS NULL
  ) THEN
    RETURN NEW;
  END IF;

  WITH live_relationships AS (
    SELECT DISTINCT assignment.id AS assignment_epoch_id
    FROM public.operator_team_assignment_epochs AS assignment
    JOIN public.operator_teams AS operator_team
      ON operator_team.id = assignment.operator_team_id
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = assignment.tenant_id
     AND roster.assignment_epoch_id = assignment.id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = roster.tenant_id
     AND source.id = roster.source_id
    WHERE assignment.tenant_id = NEW.tenant_id
      AND assignment.ended_at IS NULL
      AND operator_team.archived_at IS NULL
      AND roster.membership_id = NEW.membership_id
      AND (excluded_roster_id IS NULL OR roster.id <> excluded_roster_id)
      AND roster.revoked_at IS NULL
      AND (roster.expires_at IS NULL
        OR roster.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
  )
  SELECT count(*)::integer
  INTO relationship_count
  FROM live_relationships AS live_relationship;

  IF relationship_count >= 200 THEN
    RAISE EXCEPTION 'operator-team relationship limit of 200 exceeded'
      USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END;
$function$;--> statement-breakpoint

CREATE TRIGGER "operator_team_roster_entries_capacity_guard"
BEFORE INSERT OR UPDATE OF
  "tenant_id",
  "assignment_epoch_id",
  "membership_id",
  "source_id",
  "expires_at",
  "revoked_at"
ON "public"."operator_team_roster_entries"
FOR EACH ROW
EXECUTE FUNCTION "app"."guard_operator_team_relationship_capacity"();--> statement-breakpoint

-- Fail the hardening migration rather than sealing a state that current
-- replicas cannot hydrate. Duplicate provenance rows for one exact epoch are
-- deliberately collapsed by count(DISTINCT assignment.id).
DO $block$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    JOIN public.operator_teams AS operator_team
      ON operator_team.id = assignment.operator_team_id
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = assignment.tenant_id
     AND roster.assignment_epoch_id = assignment.id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = roster.tenant_id
     AND source.id = roster.source_id
    WHERE assignment.ended_at IS NULL
      AND operator_team.archived_at IS NULL
      AND roster.revoked_at IS NULL
      AND (roster.expires_at IS NULL
        OR roster.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
    GROUP BY assignment.tenant_id, roster.membership_id
    HAVING count(DISTINCT assignment.id) > 200
  ) THEN
    RAISE EXCEPTION 'existing operator-team relationship limit of 200 exceeded'
      USING ERRCODE = '54000';
  END IF;
END;
$block$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."update_platform_operator_team_metadata"(
  p_operator_team_id uuid,
  p_expected_version integer,
  p_display_name text,
  p_description text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  target_team record;
  next_version integer;
  assignment_representation_changed boolean;
  assignments_advanced integer := 0;
BEGIN
  IF NOT app.platform_user_has_permission(
    actor_id, 'platform.operator_team.manage'
  ) THEN
    RAISE EXCEPTION 'platform.operator_team.manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_authentication_method NOT IN (
    'bootstrap_totp', 'totp', 'recovery_code'
  ) THEN
    RAISE EXCEPTION 'operator-team mutation requires a live authentication method'
      USING ERRCODE = '22023';
  END IF;
  IF p_display_name IS NULL AND p_description IS NULL THEN
    RAISE EXCEPTION 'at least one operator-team metadata field is required'
      USING ERRCODE = '22023';
  END IF;
  IF p_display_name IS NOT NULL
     AND (btrim(p_display_name) = ''
       OR char_length(p_display_name) > 120
       OR p_display_name ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'operator-team display name is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_description IS NOT NULL
     AND (char_length(p_description) > 500
       OR p_description ~ '[[:cntrl:]]') THEN
    RAISE EXCEPTION 'operator-team description is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_operator_team_assignment_states(p_operator_team_id);
  SELECT operator_team.* INTO target_team
  FROM public.operator_teams AS operator_team
  WHERE operator_team.id = p_operator_team_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator team was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_team.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'operator team version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_team.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'archived operator team cannot be updated'
      USING ERRCODE = '55000';
  END IF;
  IF target_team.version >= 2147483647 THEN
    RAISE EXCEPTION 'operator team version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  assignment_representation_changed := p_display_name IS NOT NULL
    AND p_display_name IS DISTINCT FROM target_team.display_name;
  IF assignment_representation_changed THEN
    SELECT count(*)::integer INTO assignments_advanced
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.operator_team_id = p_operator_team_id;
  END IF;

  next_version := target_team.version + 1;
  UPDATE public.operator_teams AS operator_team
  SET display_name = coalesce(p_display_name, operator_team.display_name),
      description = coalesce(p_description, operator_team.description),
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE operator_team.id = p_operator_team_id;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.metadata_updated',
    'operator_team',
    p_operator_team_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    NULL,
    jsonb_build_object(
      'before', jsonb_build_object(
        'display_name', target_team.display_name,
        'description', target_team.description,
        'version', target_team.version
      ),
      'after', jsonb_build_object(
        'display_name', coalesce(p_display_name, target_team.display_name),
        'description', coalesce(p_description, target_team.description),
        'version', next_version
      ),
      'assignment_versions_advanced', assignments_advanced
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

CREATE OR REPLACE FUNCTION "app"."archive_platform_operator_team"(
  p_operator_team_id uuid,
  p_expected_version integer,
  p_reason text,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_id uuid := app.context_user_id();
  target_team record;
  next_version integer;
  assignments_advanced integer := 0;
BEGIN
  IF NOT app.platform_user_has_permission(
    actor_id, 'platform.operator_team.manage'
  ) THEN
    RAISE EXCEPTION 'platform.operator_team.manage permission is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_authentication_method NOT IN (
    'bootstrap_totp', 'totp', 'recovery_code'
  ) THEN
    RAISE EXCEPTION 'operator-team mutation requires a live authentication method'
      USING ERRCODE = '22023';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team archive reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_operator_team_assignment_states(p_operator_team_id);
  -- Assignment start takes this same global row lock after its tenant state.
  SELECT operator_team.* INTO target_team
  FROM public.operator_teams AS operator_team
  WHERE operator_team.id = p_operator_team_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'operator team was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_team.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'operator team version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_team.archived_at IS NOT NULL THEN
    RAISE EXCEPTION 'operator team is already archived'
      USING ERRCODE = '55000';
  END IF;
  IF target_team.version >= 2147483647 THEN
    RAISE EXCEPTION 'operator team version is exhausted'
      USING ERRCODE = '55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.operator_team_id = p_operator_team_id
      AND assignment.ended_at IS NULL
  ) THEN
    RAISE EXCEPTION 'operator team has active tenant assignments'
      USING ERRCODE = '23503',
            CONSTRAINT = 'operator_team_assignment_epochs_active_team';
  END IF;
  SELECT count(*)::integer INTO assignments_advanced
  FROM public.operator_team_assignment_epochs AS assignment
  WHERE assignment.operator_team_id = p_operator_team_id;

  next_version := target_team.version + 1;
  UPDATE public.operator_teams AS operator_team
  SET archived_at = transaction_timestamp(),
      archived_by_user_id = actor_id,
      archive_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE operator_team.id = p_operator_team_id;

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.archived',
    'operator_team',
    p_operator_team_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    p_reason,
    jsonb_build_object(
      'prior_version', target_team.version,
      'result_version', next_version,
      'archived_by_user_id', actor_id,
      'assignment_versions_advanced', assignments_advanced
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

-- Ending an epoch may affect any number of roster provenance rows. Aggregate
-- their effective operator_team tuples in SQL and recheck each distinct
-- catalog permission once at the maximum required lifetime.
CREATE OR REPLACE FUNCTION "app"."end_tenant_operator_team_assignment"(
  p_operator_team_id uuid,
  p_assignment_epoch_id uuid,
  p_expected_version integer,
  p_reason text,
  p_tenant_audit_event_id uuid,
  p_platform_audit_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS integer
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_id uuid := app.context_user_id();
  target_assignment record;
  consequence record;
  roster_entries_checked bigint := 0;
  consequences_checked integer := 0;
  target_team_version integer;
  next_version integer;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_has_exact_permission(
    'operator_team.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'operator_team.manage tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF NOT app.current_tenant_has_exact_permission('role.grant', 'tenant') THEN
    RAISE EXCEPTION 'role.grant tenant scope is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 500 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'operator-team assignment end reason is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- Match start/archive ordering: state, then team, then exact assignment.
  SELECT operator_team.version INTO target_team_version
  FROM public.operator_teams AS operator_team
  WHERE operator_team.id = p_operator_team_id
    AND EXISTS (
      SELECT 1
      FROM public.operator_team_assignment_epochs AS tenant_assignment
      WHERE tenant_assignment.tenant_id = context_tenant
        AND tenant_assignment.operator_team_id = operator_team.id
        AND tenant_assignment.id = p_assignment_epoch_id
    )
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant operator-team assignment epoch was not found'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT assignment.* INTO target_assignment
  FROM public.operator_team_assignment_epochs AS assignment
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'tenant operator-team assignment epoch was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target_assignment.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'operator-team assignment version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target_assignment.ended_at IS NOT NULL THEN
    RAISE EXCEPTION 'operator-team assignment is already ended'
      USING ERRCODE = '55000';
  END IF;
  IF target_assignment.version >= 2147483647 THEN
    RAISE EXCEPTION 'operator-team assignment version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  SELECT count(*)::bigint INTO roster_entries_checked
  FROM public.operator_team_roster_entries AS roster
  JOIN public.tenant_authorization_sources AS source
    ON source.tenant_id = roster.tenant_id
   AND source.id = roster.source_id
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = roster.tenant_id
   AND membership.id = roster.membership_id
  JOIN public.users AS identity ON identity.id = membership.user_id
  JOIN public.tenants AS tenant ON tenant.id = roster.tenant_id
  WHERE roster.tenant_id = context_tenant
    AND roster.assignment_epoch_id = p_assignment_epoch_id
    AND roster.revoked_at IS NULL
    AND (roster.expires_at IS NULL
      OR roster.expires_at > transaction_timestamp())
    AND source.retired_at IS NULL
    AND membership.status = 'active'
    AND identity.active
    AND tenant.status = 'active';

  FOR consequence IN
    WITH live_roster AS MATERIALIZED (
      SELECT roster.membership_id, roster.expires_at
      FROM public.operator_team_roster_entries AS roster
      JOIN public.tenant_authorization_sources AS roster_source
        ON roster_source.tenant_id = roster.tenant_id
       AND roster_source.id = roster.source_id
      JOIN public.tenant_memberships AS membership
        ON membership.tenant_id = roster.tenant_id
       AND membership.id = roster.membership_id
      JOIN public.users AS identity ON identity.id = membership.user_id
      JOIN public.tenants AS tenant ON tenant.id = roster.tenant_id
      WHERE roster.tenant_id = context_tenant
        AND roster.assignment_epoch_id = p_assignment_epoch_id
        AND roster.revoked_at IS NULL
        AND (roster.expires_at IS NULL
          OR roster.expires_at > transaction_timestamp())
        AND roster_source.retired_at IS NULL
        AND membership.status = 'active'
        AND identity.active
        AND tenant.status = 'active'
    ), role_paths AS (
      SELECT direct_grant.role_id,
             app.earliest_authorization_expiry(
               direct_grant.expires_at, live_roster.expires_at
             ) AS effective_expires_at
      FROM live_roster
      JOIN public.tenant_membership_role_grants AS direct_grant
        ON direct_grant.tenant_id = context_tenant
       AND direct_grant.membership_id = live_roster.membership_id
      JOIN public.tenant_authorization_sources AS direct_source
        ON direct_source.tenant_id = direct_grant.tenant_id
       AND direct_source.id = direct_grant.source_id
      WHERE direct_grant.revoked_at IS NULL
        AND (direct_grant.expires_at IS NULL
          OR direct_grant.expires_at > transaction_timestamp())
        AND direct_source.retired_at IS NULL

      UNION ALL

      SELECT group_grant.role_id,
             app.earliest_authorization_expiry(
               app.earliest_authorization_expiry(
                 group_member.expires_at, group_grant.expires_at
               ),
               live_roster.expires_at
             )
      FROM live_roster
      JOIN public.tenant_security_group_memberships AS group_member
        ON group_member.tenant_id = context_tenant
       AND group_member.membership_id = live_roster.membership_id
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
      WHERE group_member.revoked_at IS NULL
        AND (group_member.expires_at IS NULL
          OR group_member.expires_at > transaction_timestamp())
        AND member_source.retired_at IS NULL
        AND security_group.archived_at IS NULL
        AND group_grant.revoked_at IS NULL
        AND (group_grant.expires_at IS NULL
          OR group_grant.expires_at > transaction_timestamp())
        AND grant_source.retired_at IS NULL
    ), scoped_paths AS (
      SELECT permission.key AS permission_key,
             role_path.effective_expires_at
      FROM role_paths AS role_path
      JOIN public.tenant_roles AS role
        ON role.tenant_id = context_tenant
       AND role.id = role_path.role_id
      JOIN public.tenant_role_permissions AS policy
        ON policy.tenant_id = role.tenant_id
       AND policy.role_id = role.id
       AND policy.scope = 'operator_team'
      JOIN public.tenant_permissions AS permission
        ON permission.id = policy.permission_id
      WHERE role.archived_at IS NULL
    )
    SELECT scoped_path.permission_key,
           CASE
             WHEN bool_or(scoped_path.effective_expires_at IS NULL) THEN NULL
             ELSE max(scoped_path.effective_expires_at)
           END AS required_expires_at
    FROM scoped_paths AS scoped_path
    GROUP BY scoped_path.permission_key
    ORDER BY scoped_path.permission_key
  LOOP
    consequences_checked := consequences_checked + 1;
    IF NOT app.tenant_user_can_delegate_exact_permission(
      context_tenant,
      actor_id,
      consequence.permission_key,
      'operator_team',
      consequence.required_expires_at
    ) THEN
      RAISE EXCEPTION 'operator-team roster change exceeds the exact delegation ceiling or lifetime'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;

  next_version := target_assignment.version + 1;
  UPDATE public.operator_team_assignment_epochs AS assignment
  SET ended_at = transaction_timestamp(),
      ended_by_membership_id = actor_membership,
      end_reason = p_reason,
      version = next_version,
      updated_at = transaction_timestamp()
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_operator_team_id
    AND assignment.id = p_assignment_epoch_id;

  PERFORM app.append_tenant_authorization_audit(
    p_tenant_audit_event_id,
    'tenant.operator_team.assignment_ended',
    'operator_team_assignment_epoch',
    p_assignment_epoch_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    jsonb_build_object(
      'ended_at', NULL,
      'version', target_assignment.version
    ),
    jsonb_build_object(
      'ended_at', transaction_timestamp(),
      'reason', p_reason,
      'version', next_version
    ),
    jsonb_build_object(
      'operator_team_id', p_operator_team_id,
      'actor_membership_id', actor_membership,
      'roster_entries_checked', roster_entries_checked,
      'operator_team_consequences_checked', consequences_checked,
      'operator_team_prior_version', target_team_version,
      'operator_team_result_version', target_team_version + 1,
      'platform_audit_event_id', p_platform_audit_event_id
    )
  );

  PERFORM app.append_platform_audit_event(
    p_platform_audit_event_id,
    'user',
    actor_id,
    'platform.operator_team.assignment_ended',
    'operator_team_assignment_epoch',
    p_assignment_epoch_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    p_user_agent,
    p_authentication_method,
    'success',
    p_reason,
    jsonb_build_object(
      'tenant_id', context_tenant,
      'operator_team_id', p_operator_team_id,
      'prior_version', target_assignment.version,
      'result_version', next_version,
      'operator_team_prior_version', target_team_version,
      'operator_team_result_version', target_team_version + 1,
      'tenant_audit_event_id', p_tenant_audit_event_id,
      'actor_membership_id', actor_membership
    )
  );

  RETURN next_version;
END;
$function$;--> statement-breakpoint

-- Strong ETags emitted before this migration were row-version based even
-- though their representations already included joined assignment/team
-- fields. Invalidate every possibly cached team and assignment representation
-- exactly once. Lock every tenant state first, then every global team, then
-- every assignment so pre-hardening writers either finish before this sweep or
-- resume against the installed triggers/functions after it commits.
DO $block$
DECLARE
  target_state record;
  target_team record;
  target_assignment record;
BEGIN
  FOR target_state IN
    SELECT state.tenant_id
    FROM public.tenant_authorization_states AS state
    ORDER BY state.tenant_id
    FOR UPDATE
  LOOP
    NULL;
  END LOOP;

  FOR target_team IN
    SELECT operator_team.id
    FROM public.operator_teams AS operator_team
    ORDER BY operator_team.id
    FOR UPDATE
  LOOP
    NULL;
  END LOOP;

  FOR target_assignment IN
    SELECT assignment.id
    FROM public.operator_team_assignment_epochs AS assignment
    ORDER BY assignment.operator_team_id, assignment.tenant_id, assignment.id
    FOR UPDATE
  LOOP
    NULL;
  END LOOP;

  IF EXISTS (
    SELECT 1
    FROM public.operator_teams AS operator_team
    WHERE operator_team.version >= 2147483647
  ) OR EXISTS (
    SELECT 1
    FROM public.operator_team_assignment_epochs AS assignment
    WHERE assignment.version >= 2147483647
  ) THEN
    RAISE EXCEPTION 'operator-team representation version is exhausted during hardening'
      USING ERRCODE = '54000';
  END IF;

  UPDATE public.operator_teams AS operator_team
  SET version = operator_team.version + 1,
      updated_at = transaction_timestamp();

  UPDATE public.operator_team_assignment_epochs AS assignment
  SET version = assignment.version + 1,
      updated_at = transaction_timestamp();
END;
$block$;--> statement-breakpoint

-- The worker removes expired replay state in two independently bounded
-- SKIP LOCKED batches so one command class cannot starve the other.
CREATE FUNCTION "app"."prune_expired_authorization_commands"(
  p_per_class_batch_size integer
)
RETURNS TABLE (
  platform_commands_deleted integer,
  tenant_commands_deleted integer
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  deleted_platform_commands integer := 0;
  deleted_tenant_commands integer := 0;
BEGIN
  IF p_per_class_batch_size IS NULL
     OR p_per_class_batch_size NOT BETWEEN 1 AND 1000 THEN
    RAISE EXCEPTION 'authorization command cleanup per-class batch must be between 1 and 1000'
      USING ERRCODE = '22023';
  END IF;

  WITH candidates AS (
    SELECT stale.id
    FROM public.platform_commands AS stale
    WHERE stale.expires_at <= transaction_timestamp()
    ORDER BY stale.expires_at, stale.id
    LIMIT p_per_class_batch_size
    FOR UPDATE SKIP LOCKED
  )
  DELETE FROM public.platform_commands AS stale
  USING candidates
  WHERE stale.id = candidates.id;
  GET DIAGNOSTICS deleted_platform_commands = ROW_COUNT;

  WITH candidates AS (
    SELECT stale.id
    FROM public.tenant_authorization_commands AS stale
    WHERE stale.expires_at <= transaction_timestamp()
    ORDER BY stale.expires_at, stale.id
    LIMIT p_per_class_batch_size
    FOR UPDATE SKIP LOCKED
  )
  DELETE FROM public.tenant_authorization_commands AS stale
  USING candidates
  WHERE stale.id = candidates.id;
  GET DIAGNOSTICS deleted_tenant_commands = ROW_COUNT;

  RETURN QUERY
  SELECT deleted_platform_commands, deleted_tenant_commands;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION "app"."lock_operator_team_assignment_states"(uuid) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."guard_operator_team_assignment_epoch_immutability"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."touch_operator_team_assignment_representation"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."touch_operator_team_assignment_summaries"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."guard_operator_team_relationship_capacity"() OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."update_platform_operator_team_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."archive_platform_operator_team"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."end_tenant_operator_team_assignment"(uuid, uuid, integer, text, uuid, uuid, uuid, uuid, inet, text, text) OWNER TO "periapsis_migrator";--> statement-breakpoint
ALTER FUNCTION "app"."prune_expired_authorization_commands"(integer) OWNER TO "periapsis_migrator";--> statement-breakpoint

REVOKE ALL ON FUNCTION "app"."lock_operator_team_assignment_states"(uuid) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."guard_operator_team_assignment_epoch_immutability"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."touch_operator_team_assignment_representation"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."touch_operator_team_assignment_summaries"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."guard_operator_team_relationship_capacity"() FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."update_platform_operator_team_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."archive_platform_operator_team"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."end_tenant_operator_team_assignment"(uuid, uuid, integer, text, uuid, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint
REVOKE ALL ON FUNCTION "app"."prune_expired_authorization_commands"(integer) FROM PUBLIC, "periapsis_api", "periapsis_worker", "periapsis_notifier", "periapsis_auditor";--> statement-breakpoint

GRANT EXECUTE ON FUNCTION "app"."update_platform_operator_team_metadata"(uuid, integer, text, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."archive_platform_operator_team"(uuid, integer, text, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."end_tenant_operator_team_assignment"(uuid, uuid, integer, text, uuid, uuid, uuid, uuid, inet, text, text) TO "periapsis_api";--> statement-breakpoint
GRANT EXECUTE ON FUNCTION "app"."prune_expired_authorization_commands"(integer) TO "periapsis_worker";
