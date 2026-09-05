-- Bounded Phase 3 ticketing transaction ABI. Runtime roles retain no direct
-- mutation privilege; every write rechecks live tenant authority, workflow
-- pins, resource scope, CAS version, and replay identity in one transaction.

ALTER TABLE public.ticket_comment_commands OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER TABLE public.ticket_comment_commands FORCE ROW LEVEL SECURITY;--> statement-breakpoint
REVOKE ALL ON TABLE public.ticket_comment_commands FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.guard_ticketing_append_only_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  RAISE EXCEPTION 'ticketing evidence is append-only'
    USING ERRCODE = '55000';
END;
$function$;--> statement-breakpoint


ALTER FUNCTION app.guard_ticketing_append_only_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_ticketing_append_only_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE TRIGGER ticket_comments_immutable_v1
BEFORE UPDATE OR DELETE ON public.ticket_comments
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint
CREATE TRIGGER ticket_activities_immutable_v1
BEFORE UPDATE OR DELETE ON public.ticket_activities
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint
CREATE TRIGGER alert_case_links_immutable_v1
BEFORE UPDATE OR DELETE ON public.alert_case_links
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint
CREATE TRIGGER ticket_assignment_history_immutable_v1
BEFORE UPDATE OR DELETE ON public.ticket_assignment_history
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint
CREATE TRIGGER ticket_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.ticket_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint
CREATE TRIGGER ticket_comment_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.ticket_comment_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint

CREATE FUNCTION app.private_current_ticket_scope_allows_v1(
  p_permission_key text,
  p_assigned_team_id uuid,
  p_owner_user_id uuid,
  p_assignee_user_id uuid,
  p_claimed_by_user_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_permission_key IS NULL
     OR p_permission_key NOT LIKE 'alert.%'
        AND p_permission_key NOT LIKE 'case.%' THEN
    RETURN false;
  END IF;
  IF app.current_tenant_human_has_exact_permission_v3(
    p_permission_key, 'tenant'
  ) THEN
    RETURN true;
  END IF;
  IF app.current_tenant_human_has_exact_permission_v3(
       p_permission_key, 'own'
     ) AND actor_user IN (
       p_owner_user_id, p_assignee_user_id, p_claimed_by_user_id
     ) THEN
    RETURN true;
  END IF;
  IF app.current_tenant_human_has_exact_permission_v3(
       p_permission_key, 'assigned'
     ) AND actor_user IN (p_assignee_user_id, p_claimed_by_user_id) THEN
    RETURN true;
  END IF;
  RETURN p_assigned_team_id IS NOT NULL
    AND app.current_tenant_human_has_exact_permission_v3(
      p_permission_key, 'operator_team'
    )
    AND EXISTS (
      SELECT 1
      FROM public.operator_team_assignment_epochs AS assignment
      JOIN public.operator_team_roster_entries AS roster
        ON roster.tenant_id = assignment.tenant_id
       AND roster.assignment_epoch_id = assignment.id
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = roster.tenant_id
       AND source.id = roster.source_id
      WHERE assignment.tenant_id = context_tenant
        AND assignment.operator_team_id = p_assigned_team_id
        AND assignment.ended_at IS NULL
        AND roster.membership_id = actor_membership
        AND roster.revoked_at IS NULL
        AND (roster.expires_at IS NULL
          OR roster.expires_at > transaction_timestamp())
        AND source.retired_at IS NULL
    );
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_ticket_assignment_epoch_v1(
  p_team_id uuid,
  p_assignee_user_id uuid
)
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  selected_epoch uuid;
BEGIN
  IF p_team_id IS NULL THEN
    IF p_assignee_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'assignee requires an assigned team'
        USING ERRCODE = '22023';
    END IF;
    RETURN NULL;
  END IF;

  SELECT assignment.id INTO selected_epoch
  FROM public.operator_team_assignment_epochs AS assignment
  JOIN public.operator_teams AS team
    ON team.id = assignment.operator_team_id
  WHERE assignment.tenant_id = context_tenant
    AND assignment.operator_team_id = p_team_id
    AND assignment.ended_at IS NULL
    AND team.archived_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'assigned operator team is not live in the tenant'
      USING ERRCODE = '23503';
  END IF;

  IF p_assignee_user_id IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    JOIN public.operator_team_roster_entries AS roster
      ON roster.tenant_id = membership.tenant_id
     AND roster.membership_id = membership.id
     AND roster.assignment_epoch_id = selected_epoch
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = roster.tenant_id
     AND source.id = roster.source_id
    WHERE membership.tenant_id = context_tenant
      AND membership.user_id = p_assignee_user_id
      AND membership.status = 'active'
      AND identity.active
      AND roster.revoked_at IS NULL
      AND (roster.expires_at IS NULL
        OR roster.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
  ) THEN
    RAISE EXCEPTION 'assignee is not on the exact live team roster'
      USING ERRCODE = '23503';
  END IF;
  RETURN selected_epoch;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_validate_ticket_effects_v1(p_effects text[])
RETURNS void
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_effects IS NULL OR cardinality(p_effects) NOT BETWEEN 2 AND 4
     OR NOT p_effects @> ARRAY['activity', 'audit']::text[]
     OR EXISTS (
       SELECT 1 FROM unnest(p_effects) AS effect(value)
       WHERE effect.value NOT IN ('activity', 'audit', 'sla', 'notification')
     )
     OR cardinality(p_effects) <> (
       SELECT count(DISTINCT effect.value) FROM unnest(p_effects) AS effect(value)
     )
     OR p_effects IS DISTINCT FROM ARRAY(
       SELECT effect.value
       FROM unnest(p_effects) AS effect(value)
       ORDER BY CASE effect.value
         WHEN 'activity' THEN 1
         WHEN 'audit' THEN 2
         WHEN 'sla' THEN 3
         WHEN 'notification' THEN 4
         ELSE 5
       END
     ) THEN
    RAISE EXCEPTION 'ticket effect set is not canonical'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_ticket_state_action_effects_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_workflow_id uuid,
  p_workflow_version integer,
  p_state_key text,
  p_action text
)
RETURNS text[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  effects text[];
BEGIN
  SELECT ARRAY(
    SELECT effect.value
    FROM jsonb_array_elements_text(action.value -> 'effects')
         WITH ORDINALITY AS effect(value, ordinal)
    ORDER BY effect.ordinal
  ) INTO effects
  FROM public.ticket_workflow_versions AS workflow_version
  CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
  CROSS JOIN LATERAL jsonb_array_elements(state.value -> 'actions') AS action(value)
  WHERE workflow_version.tenant_id = app.context_tenant_id()
    AND workflow_version.aggregate_kind = p_aggregate_kind
    AND workflow_version.workflow_id = p_workflow_id
    AND workflow_version.version = p_workflow_version
    AND state.value ->> 'key' = p_state_key
    AND action.value ->> 'action' = p_action;
  IF effects IS NULL THEN
    RAISE EXCEPTION 'ticket action is not admitted by the pinned workflow state'
      USING ERRCODE = '42501';
  END IF;
  PERFORM app.private_validate_ticket_effects_v1(effects);
  RETURN effects;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_current_ticket_has_role_v1(p_role_key text)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH role_paths AS (
    SELECT grant_row.role_id
    FROM public.tenant_membership_role_grants AS grant_row
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = grant_row.tenant_id
     AND source.id = grant_row.source_id
    WHERE grant_row.tenant_id = app.context_tenant_id()
      AND grant_row.membership_id = app.current_tenant_membership_id()
      AND grant_row.revoked_at IS NULL
      AND (grant_row.expires_at IS NULL
        OR grant_row.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
    UNION
    SELECT group_grant.role_id
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
    WHERE group_member.tenant_id = app.context_tenant_id()
      AND group_member.membership_id = app.current_tenant_membership_id()
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
        OR group_member.expires_at > transaction_timestamp())
      AND member_source.retired_at IS NULL
      AND security_group.archived_at IS NULL
      AND group_grant.revoked_at IS NULL
      AND (group_grant.expires_at IS NULL
        OR group_grant.expires_at > transaction_timestamp())
      AND grant_source.retired_at IS NULL
  )
  SELECT EXISTS (
    SELECT 1
    FROM role_paths
    JOIN public.tenant_roles AS role
      ON role.tenant_id = app.context_tenant_id()
     AND role.id = role_paths.role_id
    WHERE role.key = p_role_key
      AND role.principal_kind = 'human'
      AND role.archived_at IS NULL
  );
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_ticket_transition_effects_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_workflow_id uuid,
  p_workflow_version integer,
  p_from_state text,
  p_transition_key text,
  p_to_state text,
  p_comment text,
  p_custom_fields jsonb,
  p_assigned_team_id uuid,
  p_owner_user_id uuid,
  p_assignee_user_id uuid,
  p_claimed_by_user_id uuid
)
RETURNS text[]
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  selected_transition jsonb;
  effects text[];
  required_value text;
BEGIN
  SELECT transition.value INTO selected_transition
  FROM public.ticket_workflow_versions AS workflow_version
  CROSS JOIN LATERAL jsonb_array_elements(
    workflow_version.transitions
  ) AS transition(value)
  WHERE workflow_version.tenant_id = app.context_tenant_id()
    AND workflow_version.aggregate_kind = p_aggregate_kind
    AND workflow_version.workflow_id = p_workflow_id
    AND workflow_version.version = p_workflow_version
    AND transition.value ->> 'key' = p_transition_key
    AND transition.value ->> 'from' = p_from_state
    AND transition.value ->> 'to' = p_to_state;
  IF selected_transition IS NULL THEN
    RAISE EXCEPTION 'transition does not match the pinned workflow edge'
      USING ERRCODE = '42501';
  END IF;
  IF coalesce((selected_transition ->> 'requiredComment')::boolean, false)
     AND coalesce(btrim(p_comment), '') = '' THEN
    RAISE EXCEPTION 'workflow transition requires a comment'
      USING ERRCODE = '22023';
  END IF;
  IF p_custom_fields IS NULL OR jsonb_typeof(p_custom_fields) <> 'object' THEN
    RAISE EXCEPTION 'transition custom fields must be an object'
      USING ERRCODE = '22023';
  END IF;

  FOR required_value IN
    SELECT value
    FROM jsonb_array_elements_text(
      selected_transition -> 'requiredCustomFields'
    ) AS requirement(value)
  LOOP
    IF NOT p_custom_fields ? required_value THEN
      RAISE EXCEPTION 'workflow transition requires a custom field'
        USING ERRCODE = '22023';
    END IF;
  END LOOP;

  FOR required_value IN
    SELECT value
    FROM jsonb_array_elements_text(
      selected_transition -> 'requiredRoles'
    ) AS requirement(value)
  LOOP
    IF NOT app.private_current_ticket_has_role_v1(required_value) THEN
      RAISE EXCEPTION 'workflow transition requires a live role'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;

  FOR required_value IN
    SELECT value
    FROM jsonb_array_elements_text(
      selected_transition -> 'requiredPermissions'
    ) AS requirement(value)
  LOOP
    IF NOT app.private_current_ticket_scope_allows_v1(
      required_value, p_assigned_team_id, p_owner_user_id,
      p_assignee_user_id, p_claimed_by_user_id
    ) THEN
      RAISE EXCEPTION 'workflow transition requires a live permission'
        USING ERRCODE = '42501';
    END IF;
  END LOOP;

  SELECT ARRAY(
    SELECT effect.value
    FROM jsonb_array_elements_text(selected_transition -> 'effects')
         WITH ORDINALITY AS effect(value, ordinal)
    ORDER BY effect.ordinal
  ) INTO effects;
  PERFORM app.private_validate_ticket_effects_v1(effects);
  RETURN effects;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_append_ticket_side_effects_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_aggregate_id uuid,
  p_action text,
  p_version integer,
  p_effects text[],
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
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  event_type text := p_aggregate_kind::text || '.' || p_action;
  activity_id uuid := uuidv7();
  activity_sequence bigint;
BEGIN
  PERFORM app.private_validate_ticket_effects_v1(p_effects);
  IF p_aggregate_id IS NULL OR p_version NOT BETWEEN 1 AND 2147483647
     OR p_action IS NULL OR p_action !~ '^[a-z][a-z0-9_]{1,63}$'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_before IS NOT NULL AND jsonb_typeof(p_before) <> 'object'
     OR p_after IS NOT NULL AND jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object' THEN
    RAISE EXCEPTION 'ticket side-effect input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT coalesce(max(activity.sequence), 0) + 1 INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id = context_tenant
    AND (
      p_aggregate_kind = 'alert' AND activity.alert_id = p_aggregate_id
      OR p_aggregate_kind = 'case' AND activity.case_id = p_aggregate_id
    );
  IF activity_sequence > 2147483647 THEN
    RAISE EXCEPTION 'ticket activity sequence is exhausted'
      USING ERRCODE = '54000';
  END IF;

  INSERT INTO public.ticket_activities (
    id, tenant_id, alert_id, case_id, sequence, kind, summary,
    actor_principal_kind, actor_membership_id, actor_user_id,
    origin, details
  ) VALUES (
    activity_id, context_tenant,
    CASE WHEN p_aggregate_kind = 'alert' THEN p_aggregate_id END,
    CASE WHEN p_aggregate_kind = 'case' THEN p_aggregate_id END,
    activity_sequence, event_type,
    CASE p_action
      WHEN 'created' THEN initcap(p_aggregate_kind::text) || ' created'
      WHEN 'transitioned' THEN initcap(p_aggregate_kind::text) || ' transitioned'
      ELSE initcap(p_aggregate_kind::text) || ' ' || replace(p_action, '_', ' ')
    END,
    'human', actor_membership, actor_user, 'api',
    p_metadata || jsonb_build_object('version', p_version, 'content_redacted', true)
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),
    'tenant.' || p_aggregate_kind::text || '.' || p_action,
    p_aggregate_kind::text,
    p_aggregate_id,
    p_request_id,
    p_correlation_id,
    p_ip_address,
    nullif(p_user_agent, ''),
    p_authentication_method,
    p_before,
    p_after,
    p_metadata || jsonb_build_object(
      'actor_membership_id', actor_membership,
      'content_redacted', true
    )
  );

  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
    payload, deduplication_key, correlation_id, causation_id
  ) VALUES (
    context_tenant, p_aggregate_kind::text, p_aggregate_id, event_type, 1,
    jsonb_build_object(
      p_aggregate_kind::text || '_id', p_aggregate_id,
      'version', p_version
    ),
    event_type || ':' || activity_id::text,
    p_correlation_id, p_request_id
  );

  IF p_effects @> ARRAY['sla']::text[] THEN
    INSERT INTO public.outbox_events (
      tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
      payload, deduplication_key, correlation_id, causation_id
    ) VALUES (
      context_tenant, p_aggregate_kind::text, p_aggregate_id,
      'sla.' || event_type, 1,
      jsonb_build_object(
        p_aggregate_kind::text || '_id', p_aggregate_id,
        'version', p_version, 'action', p_action
      ),
      'sla.' || event_type || ':' || activity_id::text,
      p_correlation_id, p_request_id
    );
  END IF;
  IF p_effects @> ARRAY['notification']::text[] THEN
    INSERT INTO public.outbox_events (
      tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
      payload, deduplication_key, correlation_id, causation_id
    ) VALUES (
      context_tenant, p_aggregate_kind::text, p_aggregate_id,
      'notification.' || event_type, 1,
      jsonb_build_object(
        p_aggregate_kind::text || '_id', p_aggregate_id,
        'version', p_version, 'action', p_action
      ),
      'notification.' || event_type || ':' || activity_id::text,
      p_correlation_id, p_request_id
    );
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.private_validate_full_alert_payload_v1(
  p_source text,
  p_source_type text,
  p_deduplication_key text,
  p_raw_payload jsonb,
  p_priority text,
  p_category text,
  p_classification text,
  p_detected_at timestamp with time zone,
  p_tags text[],
  p_custom_fields jsonb
)
RETURNS void
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_source IS NULL OR btrim(p_source) = '' OR char_length(p_source) > 120
     OR p_source ~ '[[:cntrl:]]'
     OR p_source_type IS NULL
     OR p_source_type !~ '^[a-z][a-z0-9_-]{0,79}$'
     OR p_deduplication_key IS NOT NULL AND (
       btrim(p_deduplication_key) = ''
       OR char_length(p_deduplication_key) > 240
       OR p_deduplication_key ~ '[[:cntrl:]]'
     )
     OR p_priority NOT IN ('low', 'medium', 'high', 'urgent', 'critical')
     OR p_category IS NULL OR btrim(p_category) = ''
     OR char_length(p_category) > 120 OR p_category ~ '[[:cntrl:]]'
     OR p_classification IS NOT NULL AND (
       char_length(p_classification) > 120
       OR p_classification ~ '[[:cntrl:]]'
     )
     OR p_detected_at IS NOT NULL AND p_detected_at > transaction_timestamp()
     OR p_raw_payload IS NULL OR jsonb_typeof(p_raw_payload) <> 'object'
     OR octet_length(p_raw_payload::text) > 262144
     OR p_custom_fields IS NULL OR jsonb_typeof(p_custom_fields) <> 'object'
     OR octet_length(p_custom_fields::text) > 65536
     OR p_tags IS NULL OR cardinality(p_tags) > 100
     OR EXISTS (
       SELECT 1 FROM unnest(p_tags) AS tag(value)
       WHERE btrim(tag.value) = '' OR char_length(tag.value) > 64
          OR tag.value ~ '[[:cntrl:]]'
     )
     OR p_tags IS DISTINCT FROM ARRAY(
       SELECT DISTINCT tag.value COLLATE "C"
       FROM unnest(p_tags) AS tag(value)
       ORDER BY tag.value COLLATE "C"
     ) THEN
    RAISE EXCEPTION 'full Alert payload violates bounded canonical form'
      USING ERRCODE = '22023';
  END IF;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_alert_as_human_v2(
  p_title text,
  p_description text,
  p_external_id text,
  p_severity public.alert_severity,
  p_source text,
  p_source_type text,
  p_deduplication_key text,
  p_raw_payload jsonb,
  p_priority text,
  p_category text,
  p_classification text,
  p_detected_at timestamp with time zone,
  p_customer_visible boolean,
  p_tags text[],
  p_custom_fields jsonb,
  p_workflow_id uuid,
  p_assigned_team_id uuid,
  p_assignee_user_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  id uuid, number text, workflow_id uuid, workflow_version integer,
  state_key text, customer_visible boolean, external_id text,
  deduplication_key text, title text, description text,
  status public.alert_status, severity public.alert_severity,
  priority text, category text, classification text, source text,
  source_type text, tags text[], custom_fields jsonb,
  customer_custom_fields jsonb, raw_payload jsonb,
  assigned_team_id uuid, assignee_user_id uuid, claimed_by_user_id uuid,
  created_by_user_id uuid, created_by_membership_id uuid,
  created_by_service_account_id uuid, detected_at timestamp with time zone,
  received_at timestamp with time zone, acknowledged_at timestamp with time zone,
  closed_at timestamp with time zone, assigned_at timestamp with time zone,
  first_response_at timestamp with time zone, resolved_at timestamp with time zone,
  claimed_at timestamp with time zone, created_at timestamp with time zone,
  updated_at timestamp with time zone, version integer, replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  base record;
  assignment_epoch uuid;
  pinned record;
  assignment_effects text[];
BEGIN
  PERFORM app.private_validate_full_alert_payload_v1(
    p_source, p_source_type, p_deduplication_key, p_raw_payload,
    p_priority, p_category, p_classification, p_detected_at,
    p_tags, p_custom_fields
  );
  IF p_customer_visible IS NULL THEN
    RAISE EXCEPTION 'Alert customer visibility is required'
      USING ERRCODE = '22023';
  END IF;
  IF p_assigned_team_id IS NOT NULL OR p_assignee_user_id IS NOT NULL THEN
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'alert.assign', 'tenant'
    ) THEN
      RAISE EXCEPTION 'tenant-scoped alert.assign is required at ingest'
        USING ERRCODE = '42501';
    END IF;
    assignment_epoch := app.private_ticket_assignment_epoch_v1(
      p_assigned_team_id, p_assignee_user_id
    );
  END IF;

  PERFORM set_config(
    'app.ticketing_alert_workflow_id', coalesce(p_workflow_id::text, ''), true
  );
  SELECT created.* INTO STRICT base
  FROM app.create_tenant_alert_as_human_v1(
    p_title, p_description, p_external_id, p_severity,
    p_key_digest, p_request_digest, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  ) AS created;

  IF NOT base.replayed THEN
    UPDATE public.alerts AS alert
    SET source = p_source,
        source_type = p_source_type,
        deduplication_key = p_deduplication_key,
        raw_payload = p_raw_payload,
        priority = p_priority,
        category = p_category,
        classification = p_classification,
        detected_at = coalesce(p_detected_at, alert.received_at),
        customer_visible = p_customer_visible,
        tags = p_tags,
        custom_fields = p_custom_fields,
        assigned_team_id = p_assigned_team_id,
        assigned_team_epoch_id = assignment_epoch,
        assignee_user_id = p_assignee_user_id,
        assigned_at = CASE WHEN p_assigned_team_id IS NULL
          THEN NULL ELSE alert.created_at END,
        version = CASE WHEN p_assigned_team_id IS NULL
          THEN alert.version ELSE alert.version + 1 END,
        updated_at = CASE WHEN p_assigned_team_id IS NULL
          THEN alert.updated_at ELSE transaction_timestamp() END
    WHERE alert.tenant_id = app.context_tenant_id()
      AND alert.id = base.id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'fresh Alert result disappeared'
        USING ERRCODE = '55000';
    END IF;
    IF p_assigned_team_id IS NOT NULL THEN
      SELECT alert.workflow_id, alert.workflow_version, alert.state_key,
             alert.created_by_membership_id, alert.created_by
        INTO STRICT pinned
      FROM public.alerts AS alert
      WHERE alert.tenant_id = app.context_tenant_id()
        AND alert.id = base.id;
      assignment_effects := app.private_ticket_state_action_effects_v1(
        'alert', pinned.workflow_id, pinned.workflow_version,
        pinned.state_key, 'assign'
      );
      INSERT INTO public.ticket_assignment_history (
        tenant_id, alert_id, version, action, resulting_team_id,
        resulting_assignee_user_id, actor_membership_id, actor_user_id
      ) VALUES (
        app.context_tenant_id(), base.id, 2, 'assign', p_assigned_team_id,
        p_assignee_user_id, pinned.created_by_membership_id,
        pinned.created_by
      );
      PERFORM app.private_append_ticket_side_effects_v1(
        'alert', base.id, 'assigned', 2, assignment_effects,
        p_request_id, p_correlation_id, p_ip_address, p_user_agent,
        p_authentication_method, NULL,
        jsonb_build_object(
          'version', 2, 'assigned_team_id', p_assigned_team_id,
          'assignee_user_id', p_assignee_user_id
        ),
        jsonb_build_object('assignment_changed', true)
      );
    END IF;
  END IF;

  RETURN QUERY
  SELECT alert.id, alert.number, alert.workflow_id, alert.workflow_version,
         alert.state_key, alert.customer_visible, alert.external_id,
         alert.deduplication_key, alert.title, alert.description,
         alert.status, alert.severity, alert.priority, alert.category,
         alert.classification, alert.source, alert.source_type, alert.tags,
         alert.custom_fields, alert.customer_custom_fields,
         alert.raw_payload, alert.assigned_team_id, alert.assignee_user_id,
         alert.claimed_by_user_id, alert.created_by,
         alert.created_by_membership_id, alert.created_by_service_account_id,
         alert.detected_at, alert.received_at, alert.acknowledged_at,
         alert.closed_at, alert.assigned_at, alert.first_response_at,
         alert.resolved_at, alert.claimed_at, alert.created_at,
         alert.updated_at, alert.version, base.replayed
  FROM public.alerts AS alert
  WHERE alert.tenant_id = app.context_tenant_id()
    AND alert.id = base.id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_alert_as_service_account_v2(
  p_tenant_id uuid,
  p_locator bytea,
  p_envelope_key_version integer,
  p_secret_digest bytea,
  p_client_address inet,
  p_title text,
  p_description text,
  p_external_id text,
  p_severity public.alert_severity,
  p_source text,
  p_source_type text,
  p_deduplication_key text,
  p_raw_payload jsonb,
  p_priority text,
  p_category text,
  p_classification text,
  p_detected_at timestamp with time zone,
  p_customer_visible boolean,
  p_tags text[],
  p_custom_fields jsonb,
  p_workflow_id uuid,
  p_assigned_team_id uuid,
  p_assignee_user_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_user_agent text
)
RETURNS TABLE (
  id uuid, number text, workflow_id uuid, workflow_version integer,
  state_key text, customer_visible boolean, external_id text,
  deduplication_key text, title text, description text,
  status public.alert_status, severity public.alert_severity,
  priority text, category text, classification text, source text,
  source_type text, tags text[], custom_fields jsonb,
  customer_custom_fields jsonb, raw_payload jsonb,
  assigned_team_id uuid, assignee_user_id uuid, claimed_by_user_id uuid,
  created_by_user_id uuid, created_by_membership_id uuid,
  created_by_service_account_id uuid, detected_at timestamp with time zone,
  received_at timestamp with time zone, acknowledged_at timestamp with time zone,
  closed_at timestamp with time zone, assigned_at timestamp with time zone,
  first_response_at timestamp with time zone, resolved_at timestamp with time zone,
  claimed_at timestamp with time zone, created_at timestamp with time zone,
  updated_at timestamp with time zone, version integer, replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  base record;
BEGIN
  PERFORM app.private_validate_full_alert_payload_v1(
    p_source, p_source_type, p_deduplication_key, p_raw_payload,
    p_priority, p_category, p_classification, p_detected_at,
    p_tags, p_custom_fields
  );
  IF p_customer_visible IS NULL THEN
    RAISE EXCEPTION 'Alert customer visibility is required'
      USING ERRCODE = '22023';
  END IF;
  IF p_assigned_team_id IS NOT NULL OR p_assignee_user_id IS NOT NULL THEN
    RAISE EXCEPTION 'service accounts cannot assign Alerts at ingest'
      USING ERRCODE = '42501';
  END IF;
  PERFORM set_config(
    'app.ticketing_alert_workflow_id', coalesce(p_workflow_id::text, ''), true
  );
  SELECT created.* INTO STRICT base
  FROM app.create_tenant_alert_as_service_account_v1(
    p_tenant_id, p_locator, p_envelope_key_version, p_secret_digest,
    p_client_address, p_title, p_description, p_external_id, p_severity,
    p_key_digest, p_request_digest, p_request_id, p_correlation_id,
    p_user_agent
  ) AS created;

  IF NOT base.replayed THEN
    UPDATE public.alerts AS alert
    SET source = p_source,
        source_type = p_source_type,
        deduplication_key = p_deduplication_key,
        raw_payload = p_raw_payload,
        priority = p_priority,
        category = p_category,
        classification = p_classification,
        detected_at = coalesce(p_detected_at, alert.received_at),
        customer_visible = p_customer_visible,
        tags = p_tags,
        custom_fields = p_custom_fields
    WHERE alert.tenant_id = p_tenant_id
      AND alert.id = base.id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'fresh service-account Alert result disappeared'
        USING ERRCODE = '55000';
    END IF;
  END IF;

  RETURN QUERY
  SELECT alert.id, alert.number, alert.workflow_id, alert.workflow_version,
         alert.state_key, alert.customer_visible, alert.external_id,
         alert.deduplication_key, alert.title, alert.description,
         alert.status, alert.severity, alert.priority, alert.category,
         alert.classification, alert.source, alert.source_type, alert.tags,
         alert.custom_fields, alert.customer_custom_fields,
         alert.raw_payload, alert.assigned_team_id, alert.assignee_user_id,
         alert.claimed_by_user_id, alert.created_by,
         alert.created_by_membership_id, alert.created_by_service_account_id,
         alert.detected_at, alert.received_at, alert.acknowledged_at,
         alert.closed_at, alert.assigned_at, alert.first_response_at,
         alert.resolved_at, alert.claimed_at, alert.created_at,
         alert.updated_at, alert.version, base.replayed
  FROM public.alerts AS alert
  WHERE alert.tenant_id = p_tenant_id
    AND alert.id = base.id;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_case_v1(
  p_case_id uuid,
  p_workflow_id uuid,
  p_workflow_version integer,
  p_title text,
  p_description text,
  p_summary text,
  p_severity public.alert_severity,
  p_priority text,
  p_category text,
  p_classification text,
  p_tags text[],
  p_custom_fields jsonb,
  p_customer_visible boolean,
  p_detection_time timestamp with time zone,
  p_assigned_team_id uuid,
  p_assignee_user_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  case_id uuid,
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
  actor_user uuid := app.context_user_id();
  replay record;
  workflow record;
  initial_state text;
  create_effects text[];
  assignment_effects text[];
  assignment_epoch uuid;
  created_number text;
  final_version integer := 1;
  created_at timestamp with time zone := transaction_timestamp();
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF NOT app.current_tenant_human_has_exact_permission_v3(
    'case.create', 'tenant'
  ) THEN
    RAISE EXCEPTION 'tenant-scoped case.create is required'
      USING ERRCODE = '42501';
  END IF;
  IF p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'Case replay digests must be SHA-256'
      USING ERRCODE = '22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':case.create:'
      || encode(p_key_digest, 'hex'), 0
  ));

  SELECT command.* INTO replay
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'case.create'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM p_request_digest
       OR replay.result_case_id IS NULL THEN
      RAISE EXCEPTION 'Case idempotency key conflicts with a prior request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'ticket_commands_replay_key';
    END IF;
    RETURN QUERY SELECT replay.result_case_id, replay.result_version, true;
    RETURN;
  END IF;

  IF p_case_id IS NULL OR uuid_extract_version(p_case_id) <> 7
     OR p_title IS NULL OR btrim(p_title) = ''
     OR char_length(p_title) > 240 OR p_title ~ '[[:cntrl:]]'
     OR p_description IS NULL OR char_length(p_description) > 20000
     OR p_summary IS NULL OR char_length(p_summary) > 2000
     OR p_severity IS NULL
     OR p_priority NOT IN ('low', 'medium', 'high', 'urgent', 'critical')
     OR p_category IS NULL OR char_length(p_category) > 120
     OR p_classification IS NOT NULL AND char_length(p_classification) > 120
     OR p_tags IS NULL OR cardinality(p_tags) > 100
     OR p_custom_fields IS NULL OR jsonb_typeof(p_custom_fields) <> 'object'
     OR octet_length(p_custom_fields::text) > 65536
     OR p_customer_visible IS NULL
     OR p_detection_time IS NOT NULL AND p_detection_time > created_at
     OR p_assignee_user_id IS NOT NULL AND p_assigned_team_id IS NULL THEN
    RAISE EXCEPTION 'Case create payload violates bounded canonical form'
      USING ERRCODE = '22023';
  END IF;
  IF EXISTS (
    SELECT 1 FROM unnest(p_tags) AS tag(value)
    WHERE btrim(tag.value) = '' OR char_length(tag.value) > 64
       OR tag.value ~ '[[:cntrl:]]'
  ) OR p_tags IS DISTINCT FROM ARRAY(
    SELECT DISTINCT tag.value COLLATE "C"
    FROM unnest(p_tags) AS tag(value)
    ORDER BY tag.value COLLATE "C"
  ) THEN
    RAISE EXCEPTION 'Case tags are not canonical'
      USING ERRCODE = '22023';
  END IF;

  SELECT version.states INTO workflow
  FROM public.ticket_workflows AS definition
  JOIN public.ticket_workflow_versions AS version
    ON version.tenant_id = definition.tenant_id
   AND version.workflow_id = definition.id
   AND version.aggregate_kind = definition.aggregate_kind
   AND version.version = definition.current_version
  WHERE definition.tenant_id = context_tenant
    AND definition.id = p_workflow_id
    AND definition.aggregate_kind = 'case'
    AND definition.current_version = p_workflow_version
    AND definition.archived_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'published Case workflow pin is stale'
      USING ERRCODE = '55000';
  END IF;
  SELECT state.value ->> 'key' INTO STRICT initial_state
  FROM jsonb_array_elements(workflow.states) AS state(value)
  WHERE (state.value ->> 'initial')::boolean;
  create_effects := app.private_ticket_state_action_effects_v1(
    'case', p_workflow_id, p_workflow_version, initial_state, 'create'
  );

  IF p_assigned_team_id IS NOT NULL THEN
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'case.transfer', 'tenant'
    ) THEN
      RAISE EXCEPTION 'tenant-scoped case.transfer is required at create'
        USING ERRCODE = '42501';
    END IF;
    assignment_epoch := app.private_ticket_assignment_epoch_v1(
      p_assigned_team_id, p_assignee_user_id
    );
    assignment_effects := app.private_ticket_state_action_effects_v1(
      'case', p_workflow_id, p_workflow_version, initial_state, 'assign'
    );
    final_version := 2;
  END IF;
  created_number := app.private_next_ticket_number_v1(
    context_tenant, 'case', created_at
  );

  INSERT INTO public.cases (
    id, tenant_id, number, workflow_id, workflow_version, state_key,
    customer_visible, title, description, summary, severity, priority,
    category, classification, tags, custom_fields, customer_custom_fields,
    assigned_team_id, assigned_team_epoch_id, assignee_user_id,
    created_by_membership_id, created_by_user_id, detection_time, opened_at,
    assigned_at, created_at, updated_at, version
  ) VALUES (
    p_case_id, context_tenant, created_number, p_workflow_id,
    p_workflow_version, initial_state, p_customer_visible, p_title,
    p_description, p_summary, p_severity, p_priority, p_category,
    p_classification, p_tags, p_custom_fields, '{}'::jsonb,
    p_assigned_team_id, assignment_epoch, p_assignee_user_id,
    actor_membership, actor_user, coalesce(p_detection_time, created_at), created_at,
    CASE WHEN p_assigned_team_id IS NULL THEN NULL ELSE created_at END,
    created_at, created_at, final_version
  );

  PERFORM app.private_append_ticket_side_effects_v1(
    'case', p_case_id, 'created', 1, create_effects,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'state_key', initial_state, 'customer_visible', p_customer_visible,
      'version', 1
    ),
    jsonb_build_object('number', created_number)
  );
  IF final_version = 2 THEN
    INSERT INTO public.ticket_assignment_history (
      tenant_id, case_id, version, action, resulting_team_id,
      resulting_assignee_user_id, actor_membership_id, actor_user_id
    ) VALUES (
      context_tenant, p_case_id, 2, 'assign', p_assigned_team_id,
      p_assignee_user_id, actor_membership, actor_user
    );
    PERFORM app.private_append_ticket_side_effects_v1(
      'case', p_case_id, 'assigned', 2, assignment_effects,
      p_request_id, p_correlation_id, p_ip_address, p_user_agent,
      p_authentication_method,
      jsonb_build_object('assigned_team_id', NULL, 'version', 1),
      jsonb_build_object(
        'assigned_team_id', p_assigned_team_id,
        'assignee_user_id', p_assignee_user_id,
        'version', 2
      ),
      jsonb_build_object('assignment_changed', true)
    );
  END IF;

  INSERT INTO public.ticket_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_case_id, result_version
  ) VALUES (
    context_tenant, 'case.create', actor_membership, actor_user,
    p_key_digest, p_request_digest, p_case_id, final_version
  );
  RETURN QUERY SELECT p_case_id, final_version, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.apply_tenant_ticket_mutation_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_action text,
  p_expected_version integer,
  p_next_version integer,
  p_workflow_id uuid,
  p_workflow_version integer,
  p_from_state text,
  p_to_state text,
  p_transition_key text,
  p_customer_visible boolean,
  p_assigned_team_id uuid,
  p_assignee_user_id uuid,
  p_claimed_by_user_id uuid,
  p_reason text,
  p_comment_markdown text,
  p_comment_html text,
  p_custom_fields jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
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
  actor_user uuid := app.context_user_id();
  locked record;
  replay record;
  permission_key text;
  effects text[];
  assignment_epoch uuid;
  operation text := p_aggregate_kind::text || '.' || p_action;
  event_action text;
  target_terminal boolean;
  prior_state jsonb;
  resulting_state jsonb;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR p_action NOT IN ('assign', 'claim', 'release', 'transfer', 'transition')
     OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_next_version <> p_expected_version + 1
     OR p_workflow_id IS NULL OR p_workflow_version < 1
     OR p_customer_visible IS NULL OR p_from_state IS NULL OR p_to_state IS NULL
     OR p_reason IS NULL OR char_length(p_reason) > 2000
     OR p_custom_fields IS NULL OR jsonb_typeof(p_custom_fields) <> 'object'
     OR octet_length(p_custom_fields::text) > 65536 THEN
    RAISE EXCEPTION 'ticket mutation plan is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_action = 'transition' THEN
    IF p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
       OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
       OR p_transition_key IS NULL OR btrim(p_transition_key) = '' THEN
      RAISE EXCEPTION 'transition replay identity is required'
        USING ERRCODE = '22023';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      context_tenant::text || ':' || actor_membership::text || ':'
        || operation || ':' || encode(p_key_digest, 'hex'), 0
    ));
    SELECT command.* INTO replay
    FROM public.ticket_commands AS command
    WHERE command.tenant_id = context_tenant
      AND command.actor_membership_id = actor_membership
      AND command.operation = operation
      AND command.key_digest = p_key_digest
    FOR UPDATE;
    IF FOUND THEN
      IF replay.request_digest IS DISTINCT FROM p_request_digest
         OR p_aggregate_kind = 'alert' AND replay.result_alert_id <> p_ticket_id
         OR p_aggregate_kind = 'case' AND replay.result_case_id <> p_ticket_id THEN
        RAISE EXCEPTION 'transition idempotency key conflicts'
          USING ERRCODE = '23505',
                CONSTRAINT = 'ticket_commands_replay_key';
      END IF;
      RETURN QUERY SELECT replay.result_version, true;
      RETURN;
    END IF;
  ELSIF p_key_digest IS NOT NULL OR p_request_digest IS NOT NULL THEN
    RAISE EXCEPTION 'non-transition mutation cannot carry a replay identity'
      USING ERRCODE = '22023';
  END IF;

  IF p_aggregate_kind = 'alert' THEN
    SELECT alert.* INTO locked
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = p_ticket_id
    FOR UPDATE;
  ELSE
    SELECT case_row.* INTO locked
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF locked.version <> p_expected_version
     OR locked.workflow_id <> p_workflow_id
     OR locked.workflow_version <> p_workflow_version
     OR locked.state_key <> p_from_state
     OR locked.customer_visible <> p_customer_visible THEN
    RAISE EXCEPTION 'ticket plan pin or CAS version is stale'
      USING ERRCODE = '40001';
  END IF;

  permission_key := CASE
    WHEN p_aggregate_kind = 'alert' AND p_action IN ('assign', 'transfer') THEN 'alert.assign'
    WHEN p_aggregate_kind = 'alert' AND p_action IN ('claim', 'release') THEN 'alert.claim'
    WHEN p_aggregate_kind = 'alert' AND p_action = 'transition' THEN 'alert.update'
    WHEN p_aggregate_kind = 'case' AND p_action IN ('assign', 'transfer') THEN 'case.transfer'
    WHEN p_aggregate_kind = 'case' AND p_action IN ('claim', 'release') THEN 'case.claim'
    WHEN p_aggregate_kind = 'case' AND p_action = 'transition' THEN 'case.transition'
  END;
  IF NOT app.private_current_ticket_scope_allows_v1(
    permission_key, locked.assigned_team_id,
    CASE WHEN p_aggregate_kind = 'alert' THEN locked.created_by
         ELSE locked.created_by_user_id END,
    locked.assignee_user_id, locked.claimed_by_user_id
  ) THEN
    RAISE EXCEPTION 'live ticket mutation scope is required'
      USING ERRCODE = '42501';
  END IF;

  IF p_action = 'transition' THEN
    IF p_assigned_team_id IS DISTINCT FROM locked.assigned_team_id
       OR p_assignee_user_id IS DISTINCT FROM locked.assignee_user_id
       OR p_claimed_by_user_id IS DISTINCT FROM locked.claimed_by_user_id THEN
      RAISE EXCEPTION 'transition cannot change assignment'
        USING ERRCODE = '22023';
    END IF;
    effects := app.private_ticket_transition_effects_v1(
      p_aggregate_kind, p_workflow_id, p_workflow_version, p_from_state,
      p_transition_key, p_to_state, p_comment_markdown, p_custom_fields,
      locked.assigned_team_id,
      CASE WHEN p_aggregate_kind = 'alert' THEN locked.created_by
           ELSE locked.created_by_user_id END,
      locked.assignee_user_id, locked.claimed_by_user_id
    );
  ELSE
    IF p_to_state <> p_from_state OR p_transition_key IS NOT NULL
       OR p_comment_markdown IS NOT NULL OR p_comment_html IS NOT NULL
       OR p_custom_fields <> '{}'::jsonb THEN
      RAISE EXCEPTION 'non-transition plan carries transition-only fields'
        USING ERRCODE = '22023';
    END IF;
    effects := app.private_ticket_state_action_effects_v1(
      p_aggregate_kind, p_workflow_id, p_workflow_version,
      p_from_state, p_action
    );
  END IF;

  IF p_action IN ('assign', 'transfer') THEN
    assignment_epoch := app.private_ticket_assignment_epoch_v1(
      p_assigned_team_id, p_assignee_user_id
    );
    IF p_claimed_by_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'assign or transfer cannot preserve a claim'
        USING ERRCODE = '22023';
    END IF;
  ELSIF p_action = 'claim' THEN
    IF locked.assigned_team_id IS NULL
       OR p_assigned_team_id IS DISTINCT FROM locked.assigned_team_id
       OR p_assignee_user_id <> actor_user
       OR p_claimed_by_user_id <> actor_user
       OR locked.claimed_by_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'claim plan is not an unclaimed one-winner CAS'
        USING ERRCODE = '40001';
    END IF;
    assignment_epoch := locked.assigned_team_epoch_id;
    PERFORM app.private_ticket_assignment_epoch_v1(
      p_assigned_team_id, actor_user
    );
  ELSIF p_action = 'release' THEN
    IF locked.claimed_by_user_id IS NULL
       OR p_assigned_team_id IS DISTINCT FROM locked.assigned_team_id
       OR p_assignee_user_id IS NOT NULL
       OR p_claimed_by_user_id IS NOT NULL THEN
      RAISE EXCEPTION 'release plan does not clear a live claim'
        USING ERRCODE = '40001';
    END IF;
    assignment_epoch := locked.assigned_team_epoch_id;
  ELSE
    assignment_epoch := locked.assigned_team_epoch_id;
  END IF;

  SELECT coalesce((state.value ->> 'terminal')::boolean, false)
    INTO target_terminal
  FROM public.ticket_workflow_versions AS workflow_version
  CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
  WHERE workflow_version.tenant_id = context_tenant
    AND workflow_version.workflow_id = p_workflow_id
    AND workflow_version.aggregate_kind = p_aggregate_kind
    AND workflow_version.version = p_workflow_version
    AND state.value ->> 'key' = p_to_state;
  IF target_terminal IS NULL THEN
    RAISE EXCEPTION 'mutation target state is not pinned in the workflow'
      USING ERRCODE = '55000';
  END IF;

  prior_state := jsonb_build_object(
    'state_key', locked.state_key,
    'assigned_team_id', locked.assigned_team_id,
    'assignee_user_id', locked.assignee_user_id,
    'claimed_by_user_id', locked.claimed_by_user_id,
    'version', locked.version
  );
  resulting_state := jsonb_build_object(
    'state_key', p_to_state,
    'assigned_team_id', p_assigned_team_id,
    'assignee_user_id', p_assignee_user_id,
    'claimed_by_user_id', p_claimed_by_user_id,
    'version', p_next_version
  );

  IF p_aggregate_kind = 'alert' THEN
    UPDATE public.alerts AS alert
    SET state_key = p_to_state,
        status = CASE
          WHEN p_to_state = 'new' THEN 'new'::public.alert_status
          WHEN target_terminal THEN 'closed'::public.alert_status
          ELSE 'in_progress'::public.alert_status
        END,
        assigned_team_id = p_assigned_team_id,
        assigned_team_epoch_id = assignment_epoch,
        assignee_user_id = p_assignee_user_id,
        claimed_by_user_id = p_claimed_by_user_id,
        custom_fields = CASE WHEN p_action = 'transition'
          THEN alert.custom_fields || p_custom_fields ELSE alert.custom_fields END,
        assigned_at = CASE WHEN p_action IN ('assign', 'transfer')
          THEN transaction_timestamp() ELSE alert.assigned_at END,
        claimed_at = CASE
          WHEN p_action = 'claim' THEN transaction_timestamp()
          WHEN p_action = 'release' THEN NULL ELSE alert.claimed_at END,
        acknowledged_at = CASE
          WHEN p_action = 'transition' AND alert.acknowledged_at IS NULL
            THEN transaction_timestamp()
          ELSE alert.acknowledged_at END,
        closed_at = CASE WHEN target_terminal THEN transaction_timestamp()
          WHEN p_action = 'transition' THEN NULL ELSE alert.closed_at END,
        resolved_at = CASE WHEN target_terminal THEN transaction_timestamp()
          WHEN p_action = 'transition' THEN NULL ELSE alert.resolved_at END,
        updated_at = transaction_timestamp(),
        version = p_next_version
    WHERE alert.tenant_id = context_tenant
      AND alert.id = p_ticket_id
      AND alert.version = p_expected_version;
  ELSE
    UPDATE public.cases AS case_row
    SET state_key = p_to_state,
        assigned_team_id = p_assigned_team_id,
        assigned_team_epoch_id = assignment_epoch,
        assignee_user_id = p_assignee_user_id,
        claimed_by_user_id = p_claimed_by_user_id,
        custom_fields = CASE WHEN p_action = 'transition'
          THEN case_row.custom_fields || p_custom_fields ELSE case_row.custom_fields END,
        assigned_at = CASE WHEN p_action IN ('assign', 'transfer')
          THEN transaction_timestamp() ELSE case_row.assigned_at END,
        claimed_at = CASE
          WHEN p_action = 'claim' THEN transaction_timestamp()
          WHEN p_action = 'release' THEN NULL ELSE case_row.claimed_at END,
        acknowledged_at = CASE
          WHEN p_action = 'transition' AND case_row.acknowledged_at IS NULL
            THEN transaction_timestamp()
          ELSE case_row.acknowledged_at END,
        closed_at = CASE WHEN target_terminal THEN transaction_timestamp()
          WHEN p_action = 'transition' THEN NULL ELSE case_row.closed_at END,
        resolved_at = CASE WHEN target_terminal THEN transaction_timestamp()
          WHEN p_action = 'transition' THEN NULL ELSE case_row.resolved_at END,
        updated_at = transaction_timestamp(),
        version = p_next_version
    WHERE case_row.tenant_id = context_tenant
      AND case_row.id = p_ticket_id
      AND case_row.version = p_expected_version;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket mutation lost its CAS race'
      USING ERRCODE = '40001';
  END IF;

  IF p_action IN ('assign', 'claim', 'release', 'transfer') THEN
    INSERT INTO public.ticket_assignment_history (
      tenant_id, alert_id, case_id, version, action,
      prior_team_id, resulting_team_id, prior_assignee_user_id,
      resulting_assignee_user_id, prior_claimant_user_id,
      resulting_claimant_user_id, actor_membership_id, actor_user_id, reason
    ) VALUES (
      context_tenant,
      CASE WHEN p_aggregate_kind = 'alert' THEN p_ticket_id END,
      CASE WHEN p_aggregate_kind = 'case' THEN p_ticket_id END,
      p_next_version, p_action, locked.assigned_team_id, p_assigned_team_id,
      locked.assignee_user_id, p_assignee_user_id,
      locked.claimed_by_user_id, p_claimed_by_user_id,
      actor_membership, actor_user, p_reason
    );
  END IF;

  IF p_action = 'transition' AND coalesce(p_comment_markdown, '') <> '' THEN
    INSERT INTO public.ticket_comments (
      tenant_id, alert_id, case_id, visibility, body_markdown, body_html,
      author_membership_id, author_user_id, origin
    ) VALUES (
      context_tenant,
      CASE WHEN p_aggregate_kind = 'alert' THEN p_ticket_id END,
      CASE WHEN p_aggregate_kind = 'case' THEN p_ticket_id END,
      'private', p_comment_markdown, coalesce(p_comment_html, ''),
      actor_membership, actor_user, 'api'
    );
  END IF;

  event_action := CASE p_action
    WHEN 'assign' THEN 'assigned'
    WHEN 'claim' THEN 'claimed'
    WHEN 'release' THEN 'released'
    WHEN 'transfer' THEN 'transferred'
    ELSE 'transitioned'
  END;
  PERFORM app.private_append_ticket_side_effects_v1(
    p_aggregate_kind, p_ticket_id, event_action, p_next_version, effects,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, prior_state, resulting_state,
    jsonb_build_object(
      'reason_present', p_reason <> '',
      'transition_key', p_transition_key,
      'custom_field_keys', coalesce(
        (SELECT jsonb_agg(key ORDER BY key)
         FROM jsonb_object_keys(p_custom_fields) AS field(key)),
        '[]'::jsonb
      )
    )
  );

  IF p_action = 'transition' THEN
    INSERT INTO public.ticket_commands (
      tenant_id, operation, actor_membership_id, actor_user_id,
      key_digest, request_digest, result_alert_id, result_case_id,
      result_version
    ) VALUES (
      context_tenant, operation, actor_membership, actor_user,
      p_key_digest, p_request_digest,
      CASE WHEN p_aggregate_kind = 'alert' THEN p_ticket_id END,
      CASE WHEN p_aggregate_kind = 'case' THEN p_ticket_id END,
      p_next_version
    );
  END IF;
  RETURN QUERY SELECT p_next_version, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.create_tenant_ticket_comment_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_visibility public.ticket_comment_visibility,
  p_body_markdown text,
  p_body_html text,
  p_mentioned_user_ids uuid[],
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  comment_id uuid,
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
  actor_user uuid := app.context_user_id();
  locked record;
  replay record;
  operation text := p_aggregate_kind::text || '.comment.create';
  permission_key text := p_aggregate_kind::text || '.comment.' || p_visibility::text;
  created_comment_id uuid := uuidv7();
  principal_is_customer boolean;
  state_customer_visible boolean;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_ticket_id IS NULL OR p_visibility IS NULL
     OR p_body_markdown IS NULL OR btrim(p_body_markdown) = ''
     OR char_length(p_body_markdown) > 50000
     OR p_body_html IS NULL OR char_length(p_body_html) > 100000
     OR lower(p_body_html) LIKE '%<script%'
     OR lower(p_body_html) LIKE '%javascript:%'
     OR lower(p_body_html) ~ '<[^>]+[[:space:]]on[a-z]+[[:space:]]*='
     OR p_mentioned_user_ids IS NULL
     OR cardinality(p_mentioned_user_ids) > 64
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'ticket comment payload is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_mentioned_user_ids IS DISTINCT FROM ARRAY(
    SELECT DISTINCT mentioned.value
    FROM unnest(p_mentioned_user_ids) AS mentioned(value)
    ORDER BY mentioned.value
  ) OR EXISTS (
    SELECT 1
    FROM unnest(p_mentioned_user_ids) AS mentioned(value)
    WHERE NOT EXISTS (
      SELECT 1
      FROM public.tenant_memberships AS membership
      JOIN public.users AS identity ON identity.id = membership.user_id
      WHERE membership.tenant_id = context_tenant
        AND membership.user_id = mentioned.value
        AND membership.status = 'active'
        AND identity.active
    )
  ) THEN
    RAISE EXCEPTION 'comment mentions are not canonical live tenant users'
      USING ERRCODE = '23503';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || operation || ':' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT command.* INTO replay
  FROM public.ticket_comment_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = operation
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'comment idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'ticket_comment_commands_replay_key';
    END IF;
    RETURN QUERY SELECT replay.result_comment_id, true;
    RETURN;
  END IF;

  IF p_aggregate_kind = 'alert' THEN
    SELECT alert.* INTO locked
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = p_ticket_id
    FOR UPDATE;
  ELSE
    SELECT case_row.* INTO locked
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF NOT app.private_current_ticket_scope_allows_v1(
    permission_key, locked.assigned_team_id,
    CASE WHEN p_aggregate_kind = 'alert' THEN locked.created_by
         ELSE locked.created_by_user_id END,
    locked.assignee_user_id, locked.claimed_by_user_id
  ) THEN
    RAISE EXCEPTION 'live ticket comment scope is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT membership.role IN ('customer_manager', 'customer_user', 'read_only')
    INTO principal_is_customer
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id = context_tenant
    AND membership.id = actor_membership
    AND membership.user_id = actor_user
    AND membership.status = 'active';
  IF principal_is_customer AND p_visibility <> 'public' THEN
    RAISE EXCEPTION 'customer principals cannot create private comments'
      USING ERRCODE = '42501';
  END IF;
  SELECT locked.customer_visible
    AND coalesce((state.value ->> 'visibility') = 'customer', false)
    INTO state_customer_visible
  FROM public.ticket_workflow_versions AS workflow_version
  CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
  WHERE workflow_version.tenant_id = context_tenant
    AND workflow_version.workflow_id = locked.workflow_id
    AND workflow_version.aggregate_kind = p_aggregate_kind
    AND workflow_version.version = locked.workflow_version
    AND state.value ->> 'key' = locked.state_key;
  IF principal_is_customer AND state_customer_visible IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'ticket is not customer-projectable'
      USING ERRCODE = '42501';
  END IF;

  INSERT INTO public.ticket_comments (
    id, tenant_id, alert_id, case_id, visibility, body_markdown,
    body_html, author_membership_id, author_user_id, origin,
    mentioned_user_ids
  ) VALUES (
    created_comment_id, context_tenant,
    CASE WHEN p_aggregate_kind = 'alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind = 'case' THEN p_ticket_id END,
    p_visibility, p_body_markdown, p_body_html,
    actor_membership, actor_user, 'api', p_mentioned_user_ids
  );
  IF p_visibility = 'public' THEN
    IF p_aggregate_kind = 'alert' THEN
      UPDATE public.alerts SET first_response_at = coalesce(
        first_response_at, transaction_timestamp()
      ) WHERE tenant_id = context_tenant AND id = p_ticket_id;
    ELSE
      UPDATE public.cases SET first_response_at = coalesce(
        first_response_at, transaction_timestamp()
      ) WHERE tenant_id = context_tenant AND id = p_ticket_id;
    END IF;
  END IF;

  PERFORM app.private_append_ticket_side_effects_v1(
    p_aggregate_kind, p_ticket_id, 'commented', locked.version,
    ARRAY['activity', 'audit', 'sla', 'notification']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'comment_id', created_comment_id,
      'visibility', p_visibility,
      'ticket_version', locked.version
    ),
    jsonb_build_object(
      'comment_id', created_comment_id,
      'visibility', p_visibility,
      'content_redacted', true,
      'mention_count', cardinality(p_mentioned_user_ids)
    )
  );
  INSERT INTO public.ticket_comment_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_comment_id
  ) VALUES (
    context_tenant, operation, actor_membership, actor_user,
    p_key_digest, p_request_digest, created_comment_id
  );
  RETURN QUERY SELECT created_comment_id, false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.commit_tenant_ticket_escalation_v1(
  p_path_alert_id uuid,
  p_case_id uuid,
  p_create_case boolean,
  p_target jsonb,
  p_sources jsonb,
  p_relation text,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_effects text[],
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_case_id uuid,
  result_case_version integer,
  result_path_alert_version integer,
  result_metadata jsonb,
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
  actor_user uuid := app.context_user_id();
  replay record;
  source_value jsonb;
  source_alert record;
  target_case record;
  source_effects text[];
  case_effects text[];
  assignment_effects text[];
  source_count integer;
  path_count integer := 0;
  final_case_version integer;
  path_alert_version integer;
  initial_state text;
  assignment_epoch uuid;
  created_number text;
  link_ids jsonb := '[]'::jsonb;
  copied_snapshot jsonb;
  selected_fields text[];
  selected_custom_fields text[];
  selected_comments uuid[];
  source_items jsonb;
  source_custom_copy jsonb;
  aggregate_custom_copy jsonb := '{}'::jsonb;
  aggregate_tags text[] := ARRAY[]::text[];
  scalar_title text;
  scalar_description text;
  scalar_severity public.alert_severity;
  scalar_priority text;
  scalar_category text;
  actual_effects text[] := ARRAY[]::text[];
  operation_at timestamp with time zone := transaction_timestamp();
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_path_alert_id IS NULL OR p_case_id IS NULL OR p_create_case IS NULL
     OR p_target IS NULL OR jsonb_typeof(p_target) <> 'object'
     OR p_sources IS NULL OR jsonb_typeof(p_sources) <> 'array'
     OR jsonb_array_length(p_sources) NOT BETWEEN 1 AND 100
     OR p_relation NOT IN ('escalation', 'correlation')
     OR p_reason IS NULL OR btrim(p_reason) = ''
     OR char_length(p_reason) > 2000
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'escalation request is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_validate_ticket_effects_v1(p_effects);
  SELECT count(*), count(DISTINCT source.value ->> 'alertId')
    INTO source_count, path_count
  FROM jsonb_array_elements(p_sources) AS source(value);
  IF source_count <> path_count OR (
    SELECT count(*)
    FROM jsonb_array_elements(p_sources) AS source(value)
    WHERE source.value ->> 'alertId' = p_path_alert_id::text
  ) <> 1 THEN
    RAISE EXCEPTION 'escalation sources must be unique and include the path Alert once'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':ticket.escalate:' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT command.* INTO replay
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'ticket.escalate'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay.request_digest IS DISTINCT FROM p_request_digest
       OR replay.result_alert_id <> p_path_alert_id
       OR replay.result_case_id IS NULL THEN
      RAISE EXCEPTION 'escalation idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'ticket_commands_replay_key';
    END IF;
    RETURN QUERY
    SELECT replay.result_case_id, replay.result_version,
           (replay.result_metadata ->> 'pathAlertVersion')::integer,
           replay.result_metadata, true;
    RETURN;
  END IF;

  -- Lock every source in UUID order so overlapping multi-Alert escalations do
  -- not deadlock and every expected version is checked against one snapshot.
  PERFORM 1
  FROM public.alerts AS alert
  JOIN jsonb_array_elements(p_sources) AS source(value)
    ON alert.id = (source.value ->> 'alertId')::uuid
  WHERE alert.tenant_id = context_tenant
  ORDER BY alert.id
  FOR UPDATE OF alert;
  GET DIAGNOSTICS source_count = ROW_COUNT;
  IF source_count <> jsonb_array_length(p_sources) THEN
    RAISE EXCEPTION 'one or more escalation source Alerts are unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  IF p_create_case THEN
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'case.create', 'tenant'
    ) THEN
      RAISE EXCEPTION 'tenant-scoped case.create is required for escalation'
        USING ERRCODE = '42501';
    END IF;
    IF uuid_extract_version(p_case_id) <> 7
       OR p_target - ARRAY[
         'workflowId', 'workflowVersion', 'stateKey', 'resultVersion',
         'title', 'description', 'summary', 'severity', 'priority',
         'category', 'classification', 'tags', 'customFields',
         'customerVisible', 'detectionTime', 'assignedTeamId',
         'assigneeUserId'
       ]::text[] <> '{}'::jsonb
       OR p_target ->> 'workflowId' IS NULL
       OR (p_target ->> 'workflowVersion')::integer < 1
       OR coalesce(btrim(p_target ->> 'title'), '') = ''
       OR char_length(p_target ->> 'title') > 240
       OR coalesce(p_target ->> 'priority', '') NOT IN (
         'low', 'medium', 'high', 'urgent', 'critical'
       )
       OR coalesce(p_target ->> 'severity', '') NOT IN (
         'informational', 'low', 'medium', 'high', 'critical'
       )
       OR jsonb_typeof(p_target -> 'tags') <> 'array'
       OR jsonb_typeof(p_target -> 'customFields') <> 'object'
       OR octet_length(coalesce(p_target ->> 'description', '')) > 20000
       OR octet_length(coalesce(p_target ->> 'summary', '')) > 2000
       OR octet_length((p_target -> 'customFields')::text) > 65536
       OR jsonb_array_length(p_target -> 'tags') > 100
       OR EXISTS (
         SELECT 1
         FROM jsonb_array_elements_text(p_target -> 'tags') AS tag(value)
         WHERE btrim(tag.value) = '' OR char_length(tag.value) > 64
            OR tag.value ~ '[[:cntrl:]]'
       )
       OR p_target -> 'tags' IS DISTINCT FROM to_jsonb(ARRAY(
         SELECT DISTINCT tag.value COLLATE "C"
         FROM jsonb_array_elements_text(p_target -> 'tags') AS tag(value)
         ORDER BY tag.value COLLATE "C"
       ))
       OR coalesce(
         (p_target ->> 'detectionTime')::timestamp with time zone,
         operation_at
       ) > operation_at
       OR (p_target ->> 'customerVisible')::boolean IS NULL THEN
      RAISE EXCEPTION 'new escalation Case payload is invalid'
        USING ERRCODE = '22023';
    END IF;

    SELECT state.value ->> 'key' INTO initial_state
    FROM public.ticket_workflows AS definition
    JOIN public.ticket_workflow_versions AS version
      ON version.tenant_id = definition.tenant_id
     AND version.workflow_id = definition.id
     AND version.aggregate_kind = definition.aggregate_kind
     AND version.version = definition.current_version
    CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
    WHERE definition.tenant_id = context_tenant
      AND definition.id = (p_target ->> 'workflowId')::uuid
      AND definition.aggregate_kind = 'case'
      AND definition.current_version = (p_target ->> 'workflowVersion')::integer
      AND definition.archived_at IS NULL
      AND (state.value ->> 'initial')::boolean;
    IF initial_state IS NULL OR initial_state <> p_target ->> 'stateKey' THEN
      RAISE EXCEPTION 'new Case workflow pin is stale'
        USING ERRCODE = '55000';
    END IF;
    case_effects := app.private_ticket_state_action_effects_v1(
      'case', (p_target ->> 'workflowId')::uuid,
      (p_target ->> 'workflowVersion')::integer, initial_state, 'create'
    );
    actual_effects := ARRAY(
      SELECT effect.value
      FROM unnest(actual_effects || case_effects) AS effect(value)
      GROUP BY effect.value
      ORDER BY CASE effect.value
        WHEN 'activity' THEN 1 WHEN 'audit' THEN 2
        WHEN 'sla' THEN 3 WHEN 'notification' THEN 4
      END
    );
    final_case_version := 1;
    IF nullif(p_target ->> 'assignedTeamId', '') IS NOT NULL THEN
      IF NOT app.current_tenant_human_has_exact_permission_v3(
        'case.transfer', 'tenant'
      ) THEN
        RAISE EXCEPTION 'tenant-scoped case.transfer is required at escalation create'
          USING ERRCODE = '42501';
      END IF;
      assignment_epoch := app.private_ticket_assignment_epoch_v1(
        (p_target ->> 'assignedTeamId')::uuid,
        nullif(p_target ->> 'assigneeUserId', '')::uuid
      );
      assignment_effects := app.private_ticket_state_action_effects_v1(
        'case', (p_target ->> 'workflowId')::uuid,
        (p_target ->> 'workflowVersion')::integer, initial_state, 'assign'
      );
      actual_effects := ARRAY(
        SELECT effect.value
        FROM unnest(actual_effects || assignment_effects) AS effect(value)
        GROUP BY effect.value
        ORDER BY CASE effect.value
          WHEN 'activity' THEN 1 WHEN 'audit' THEN 2
          WHEN 'sla' THEN 3 WHEN 'notification' THEN 4
        END
      );
      final_case_version := 2;
    END IF;
    IF (p_target ->> 'resultVersion')::integer <> final_case_version THEN
      RAISE EXCEPTION 'new Case result-version pin is invalid'
        USING ERRCODE = '40001';
    END IF;
    created_number := app.private_next_ticket_number_v1(
      context_tenant, 'case', operation_at
    );
    INSERT INTO public.cases (
      id, tenant_id, number, workflow_id, workflow_version, state_key,
      customer_visible, title, description, summary, severity, priority,
      category, classification, tags, custom_fields, customer_custom_fields,
      assigned_team_id, assigned_team_epoch_id, assignee_user_id,
      created_by_membership_id, created_by_user_id, detection_time,
      opened_at, assigned_at, created_at, updated_at, version
    ) VALUES (
      p_case_id, context_tenant, created_number,
      (p_target ->> 'workflowId')::uuid,
      (p_target ->> 'workflowVersion')::integer, initial_state,
      (p_target ->> 'customerVisible')::boolean, p_target ->> 'title',
      coalesce(p_target ->> 'description', ''),
      coalesce(p_target ->> 'summary', ''),
      (p_target ->> 'severity')::public.alert_severity,
      p_target ->> 'priority', coalesce(p_target ->> 'category', 'general'),
      nullif(p_target ->> 'classification', ''),
      ARRAY(SELECT value FROM jsonb_array_elements_text(p_target -> 'tags') AS tag(value) ORDER BY value COLLATE "C"),
      p_target -> 'customFields', '{}'::jsonb,
      nullif(p_target ->> 'assignedTeamId', '')::uuid, assignment_epoch,
      nullif(p_target ->> 'assigneeUserId', '')::uuid,
      actor_membership, actor_user,
      coalesce((p_target ->> 'detectionTime')::timestamp with time zone, operation_at),
      operation_at,
      CASE WHEN assignment_epoch IS NULL THEN NULL ELSE operation_at END,
      operation_at, operation_at, final_case_version
    );
    PERFORM app.private_append_ticket_side_effects_v1(
      'case', p_case_id, 'created', 1, case_effects,
      p_request_id, p_correlation_id, p_ip_address, p_user_agent,
      p_authentication_method, NULL,
      jsonb_build_object('state_key', initial_state, 'version', 1),
      jsonb_build_object('number', created_number, 'escalation', true)
    );
    IF final_case_version = 2 THEN
      INSERT INTO public.ticket_assignment_history (
        tenant_id, case_id, version, action, resulting_team_id,
        resulting_assignee_user_id, actor_membership_id, actor_user_id
      ) VALUES (
        context_tenant, p_case_id, 2, 'assign',
        (p_target ->> 'assignedTeamId')::uuid,
        nullif(p_target ->> 'assigneeUserId', '')::uuid,
        actor_membership, actor_user
      );
      PERFORM app.private_append_ticket_side_effects_v1(
        'case', p_case_id, 'assigned', 2, assignment_effects,
        p_request_id, p_correlation_id, p_ip_address, p_user_agent,
        p_authentication_method, NULL,
        jsonb_build_object('version', 2, 'assignment_changed', true),
        jsonb_build_object('escalation', true)
      );
    END IF;
  ELSE
    IF p_target - ARRAY[
      'workflowId', 'workflowVersion', 'stateKey', 'expectedVersion',
      'resultVersion'
    ]::text[] <> '{}'::jsonb THEN
      RAISE EXCEPTION 'existing Case target contains unplanned fields'
        USING ERRCODE = '22023';
    END IF;
    SELECT case_row.* INTO target_case
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = p_case_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'target Case not found'
        USING ERRCODE = 'P0002';
    END IF;
    IF target_case.version <> (p_target ->> 'expectedVersion')::integer
       OR target_case.version + 1 <> (p_target ->> 'resultVersion')::integer
       OR target_case.workflow_id <> (p_target ->> 'workflowId')::uuid
       OR target_case.workflow_version <> (p_target ->> 'workflowVersion')::integer
       OR target_case.state_key <> p_target ->> 'stateKey'
       OR NOT app.private_current_ticket_scope_allows_v1(
         'case.update', target_case.assigned_team_id,
         target_case.created_by_user_id, target_case.assignee_user_id,
         target_case.claimed_by_user_id
       ) THEN
      RAISE EXCEPTION 'target Case pin, version, or scope is stale'
        USING ERRCODE = '40001';
    END IF;
    case_effects := app.private_ticket_state_action_effects_v1(
      'case', target_case.workflow_id, target_case.workflow_version,
      target_case.state_key, 'link'
    );
    actual_effects := ARRAY(
      SELECT effect.value
      FROM unnest(actual_effects || case_effects) AS effect(value)
      GROUP BY effect.value
      ORDER BY CASE effect.value
        WHEN 'activity' THEN 1 WHEN 'audit' THEN 2
        WHEN 'sla' THEN 3 WHEN 'notification' THEN 4
      END
    );
    final_case_version := target_case.version + 1;
    UPDATE public.cases
    SET version = final_case_version, updated_at = operation_at
    WHERE tenant_id = context_tenant AND id = p_case_id
      AND version = target_case.version;
    PERFORM app.private_append_ticket_side_effects_v1(
      'case', p_case_id, 'linked', final_case_version, case_effects,
      p_request_id, p_correlation_id, p_ip_address, p_user_agent,
      p_authentication_method,
      jsonb_build_object('version', target_case.version),
      jsonb_build_object('version', final_case_version),
      jsonb_build_object('escalation', true)
    );
  END IF;

  FOR source_value IN
    SELECT source.value
    FROM jsonb_array_elements(p_sources) WITH ORDINALITY AS source(value, ordinal)
    ORDER BY source.ordinal
  LOOP
    IF source_value - ARRAY[
      'alertId', 'linkId', 'linkedAt', 'expectedVersion', 'resultVersion',
      'workflowId', 'workflowVersion', 'stateKey', 'copyFields',
      'customFieldKeys', 'itemIds', 'publicCommentIds'
    ]::text[] <> '{}'::jsonb
       OR uuid_extract_version((source_value ->> 'linkId')::uuid) <> 7
       OR (source_value ->> 'linkedAt')::timestamp with time zone > operation_at
       OR (source_value ->> 'linkedAt')::timestamp with time zone
            < operation_at - interval '1 hour' THEN
      RAISE EXCEPTION 'escalation source contains invalid result metadata'
        USING ERRCODE = '22023';
    END IF;
    SELECT alert.* INTO STRICT source_alert
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant
      AND alert.id = (source_value ->> 'alertId')::uuid;
    IF source_alert.version <> (source_value ->> 'expectedVersion')::integer
       OR source_alert.version + 1 <> (source_value ->> 'resultVersion')::integer
       OR source_alert.workflow_id <> (source_value ->> 'workflowId')::uuid
       OR source_alert.workflow_version <> (source_value ->> 'workflowVersion')::integer
       OR source_alert.state_key <> source_value ->> 'stateKey'
       OR NOT app.private_current_ticket_scope_allows_v1(
         'alert.escalate', source_alert.assigned_team_id,
         source_alert.created_by, source_alert.assignee_user_id,
         source_alert.claimed_by_user_id
       ) THEN
      RAISE EXCEPTION 'source Alert pin, version, or scope is stale'
        USING ERRCODE = '40001';
    END IF;
    source_effects := app.private_ticket_state_action_effects_v1(
      'alert', source_alert.workflow_id, source_alert.workflow_version,
      source_alert.state_key, 'escalate'
    );
    actual_effects := ARRAY(
      SELECT effect.value
      FROM unnest(actual_effects || source_effects) AS effect(value)
      GROUP BY effect.value
      ORDER BY CASE effect.value
        WHEN 'activity' THEN 1 WHEN 'audit' THEN 2
        WHEN 'sla' THEN 3 WHEN 'notification' THEN 4
      END
    );
    selected_fields := ARRAY(
      SELECT value FROM jsonb_array_elements_text(source_value -> 'copyFields') AS field(value)
      ORDER BY value COLLATE "C"
    );
    selected_custom_fields := ARRAY(
      SELECT value FROM jsonb_array_elements_text(source_value -> 'customFieldKeys') AS field(value)
      ORDER BY value COLLATE "C"
    );
    selected_comments := ARRAY(
      SELECT value::uuid FROM jsonb_array_elements_text(source_value -> 'publicCommentIds') AS comment(value)
      ORDER BY value
    );
    source_items := coalesce(source_value -> 'itemIds', '{}'::jsonb);
    IF selected_fields IS NULL OR selected_custom_fields IS NULL
       OR selected_comments IS NULL OR jsonb_typeof(source_items) <> 'object'
       OR source_items <> '{}'::jsonb
       OR source_value -> 'copyFields' IS DISTINCT FROM to_jsonb(selected_fields)
       OR source_value -> 'customFieldKeys' IS DISTINCT FROM to_jsonb(selected_custom_fields)
       OR source_value -> 'publicCommentIds' IS DISTINCT FROM to_jsonb(selected_comments)
       OR ('custom_fields' = ANY(selected_fields))
            IS DISTINCT FROM (cardinality(selected_custom_fields) > 0)
       OR ('public_comments' = ANY(selected_fields))
            IS DISTINCT FROM (cardinality(selected_comments) > 0)
       OR EXISTS (
         SELECT 1 FROM unnest(selected_fields) AS field(value)
         WHERE field.value NOT IN (
           'title', 'description', 'severity', 'priority', 'category',
           'tags', 'custom_fields', 'public_comments'
         )
       )
       OR EXISTS (
         SELECT 1 FROM unnest(selected_custom_fields) AS field(value)
         WHERE NOT source_alert.custom_fields ? field.value
       )
       OR EXISTS (
         SELECT 1 FROM unnest(selected_comments) AS selected(id)
         WHERE NOT EXISTS (
           SELECT 1 FROM public.ticket_comments AS comment
           WHERE comment.tenant_id = context_tenant
             AND comment.alert_id = source_alert.id
             AND comment.id = selected.id
             AND comment.visibility = 'public'
         )
       ) THEN
      RAISE EXCEPTION 'escalation copy selection is not exact and public'
        USING ERRCODE = '22023';
    END IF;

    source_custom_copy := coalesce((
      SELECT jsonb_object_agg(field.value, source_alert.custom_fields -> field.value)
      FROM unnest(selected_custom_fields) AS field(value)
    ), '{}'::jsonb);
    aggregate_custom_copy := aggregate_custom_copy || source_custom_copy;
    IF 'tags' = ANY(selected_fields) THEN
      aggregate_tags := ARRAY(
        SELECT DISTINCT value COLLATE "C"
        FROM unnest(aggregate_tags || source_alert.tags) AS tag(value)
        ORDER BY value COLLATE "C"
      );
    END IF;
    IF scalar_title IS NULL AND 'title' = ANY(selected_fields) THEN
      scalar_title := source_alert.title;
    END IF;
    IF scalar_description IS NULL AND 'description' = ANY(selected_fields) THEN
      scalar_description := source_alert.description;
    END IF;
    IF scalar_severity IS NULL AND 'severity' = ANY(selected_fields) THEN
      scalar_severity := source_alert.severity;
    END IF;
    IF scalar_priority IS NULL AND 'priority' = ANY(selected_fields) THEN
      scalar_priority := source_alert.priority;
    END IF;
    IF scalar_category IS NULL AND 'category' = ANY(selected_fields) THEN
      scalar_category := source_alert.category;
    END IF;

    copied_snapshot := jsonb_strip_nulls(jsonb_build_object(
      'title', CASE WHEN 'title' = ANY(selected_fields) THEN source_alert.title END,
      'description', CASE WHEN 'description' = ANY(selected_fields) THEN source_alert.description END,
      'severity', CASE WHEN 'severity' = ANY(selected_fields) THEN source_alert.severity END,
      'priority', CASE WHEN 'priority' = ANY(selected_fields) THEN source_alert.priority END,
      'category', CASE WHEN 'category' = ANY(selected_fields) THEN source_alert.category END,
      'tags', CASE WHEN 'tags' = ANY(selected_fields) THEN to_jsonb(source_alert.tags) END,
      'customFields', source_custom_copy,
      'publicCommentIds', to_jsonb(selected_comments)
    ));

    INSERT INTO public.alert_case_links (
      id, tenant_id, alert_id, case_id, relation, reason,
      linked_by_membership_id, linked_by_user_id, source_alert_version,
      copy_fields, custom_field_keys, item_ids, public_comment_ids,
      copied_field_snapshot, linked_at
    ) VALUES (
      (source_value ->> 'linkId')::uuid, context_tenant, source_alert.id,
      p_case_id, p_relation, p_reason, actor_membership, actor_user,
      source_alert.version, selected_fields, selected_custom_fields,
      source_items, selected_comments, copied_snapshot,
      (source_value ->> 'linkedAt')::timestamp with time zone
    );
    link_ids := link_ids || jsonb_build_array(source_value ->> 'linkId');

    INSERT INTO public.ticket_comments (
      tenant_id, case_id, visibility, body_markdown, body_html,
      author_membership_id, author_user_id, origin, revision, created_at,
      updated_at
    )
    SELECT context_tenant, p_case_id, 'public', comment.body_markdown,
           comment.body_html, comment.author_membership_id,
           comment.author_user_id, 'escalation_copy', comment.revision,
           operation_at, operation_at
    FROM public.ticket_comments AS comment
    WHERE comment.tenant_id = context_tenant
      AND comment.alert_id = source_alert.id
      AND comment.id = ANY(selected_comments)
      AND comment.visibility = 'public';

    UPDATE public.alerts
    SET version = source_alert.version + 1, updated_at = operation_at
    WHERE tenant_id = context_tenant AND id = source_alert.id
      AND version = source_alert.version;
    PERFORM app.private_append_ticket_side_effects_v1(
      'alert', source_alert.id, 'escalated', source_alert.version + 1,
      source_effects, p_request_id, p_correlation_id, p_ip_address,
      p_user_agent, p_authentication_method,
      jsonb_build_object('version', source_alert.version),
      jsonb_build_object('version', source_alert.version + 1),
      jsonb_build_object('case_id', p_case_id, 'link_id', source_value ->> 'linkId')
    );
    IF source_alert.id = p_path_alert_id THEN
      path_alert_version := source_alert.version + 1;
    END IF;
  END LOOP;

  UPDATE public.cases AS case_row
  SET title = coalesce(scalar_title, case_row.title),
      description = coalesce(scalar_description, case_row.description),
      severity = coalesce(scalar_severity, case_row.severity),
      priority = coalesce(scalar_priority, case_row.priority),
      category = coalesce(scalar_category, case_row.category),
      tags = ARRAY(
        SELECT DISTINCT value COLLATE "C"
        FROM unnest(case_row.tags || aggregate_tags) AS tag(value)
        ORDER BY value COLLATE "C"
      ),
      custom_fields = case_row.custom_fields || aggregate_custom_copy,
      updated_at = operation_at
  WHERE case_row.tenant_id = context_tenant AND case_row.id = p_case_id;

  IF actual_effects IS DISTINCT FROM p_effects THEN
    RAISE EXCEPTION 'escalation effect plan is not the exact workflow union'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.ticket_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_alert_id, result_case_id,
    result_version, result_metadata
  ) VALUES (
    context_tenant, 'ticket.escalate', actor_membership, actor_user,
    p_key_digest, p_request_digest, p_path_alert_id, p_case_id,
    final_case_version,
    jsonb_build_object(
      'pathAlertVersion', path_alert_version,
      'linkIds', link_ids,
      'effects', to_jsonb(p_effects)
    )
  );
  RETURN QUERY
  SELECT p_case_id, final_case_version, path_alert_version,
         jsonb_build_object(
           'pathAlertVersion', path_alert_version,
           'linkIds', link_ids,
           'effects', to_jsonb(p_effects)
         ), false;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.resolve_current_ticket_assignment_authority_v1()
RETURNS TABLE (
  operator_team_id uuid,
  target_user_id uuid,
  team_manageable boolean,
  team_claimable boolean
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH actor AS (
    SELECT app.context_tenant_id() AS tenant_id,
           app.current_tenant_membership_id() AS membership_id
  ),
  live_teams AS (
    SELECT assignment.operator_team_id,
           assignment.id AS assignment_epoch_id,
           EXISTS (
             SELECT 1
             FROM public.operator_team_roster_entries AS actor_roster
             JOIN public.tenant_authorization_sources AS actor_source
               ON actor_source.tenant_id = actor_roster.tenant_id
              AND actor_source.id = actor_roster.source_id
             WHERE actor_roster.tenant_id = assignment.tenant_id
               AND actor_roster.assignment_epoch_id = assignment.id
               AND actor_roster.membership_id = actor.membership_id
               AND actor_roster.revoked_at IS NULL
               AND (actor_roster.expires_at IS NULL
                 OR actor_roster.expires_at > transaction_timestamp())
               AND actor_source.retired_at IS NULL
           ) AS actor_on_team
    FROM public.operator_team_assignment_epochs AS assignment
    JOIN public.operator_teams AS team
      ON team.id = assignment.operator_team_id
    CROSS JOIN actor
    WHERE assignment.tenant_id = actor.tenant_id
      AND assignment.ended_at IS NULL
      AND team.archived_at IS NULL
  ),
  admitted_teams AS (
    SELECT live_teams.*,
           (
             app.current_tenant_human_has_exact_permission_v3('alert.assign', 'tenant')
             OR app.current_tenant_human_has_exact_permission_v3('alert.assign', 'assigned')
             OR app.current_tenant_human_has_exact_permission_v3('case.transfer', 'tenant')
             OR app.current_tenant_human_has_exact_permission_v3('case.transfer', 'assigned')
             OR live_teams.actor_on_team AND (
               app.current_tenant_human_has_exact_permission_v3('alert.assign', 'operator_team')
               OR app.current_tenant_human_has_exact_permission_v3('case.transfer', 'operator_team')
             )
           ) AS team_manageable,
           live_teams.actor_on_team AND (
             app.current_tenant_human_has_exact_permission_v3('alert.claim', 'tenant')
             OR app.current_tenant_human_has_exact_permission_v3('alert.claim', 'assigned')
             OR app.current_tenant_human_has_exact_permission_v3('alert.claim', 'operator_team')
             OR app.current_tenant_human_has_exact_permission_v3('case.claim', 'tenant')
             OR app.current_tenant_human_has_exact_permission_v3('case.claim', 'assigned')
             OR app.current_tenant_human_has_exact_permission_v3('case.claim', 'operator_team')
           ) AS team_claimable
    FROM live_teams
  ),
  live_roster AS (
    SELECT roster.assignment_epoch_id, membership.user_id
    FROM public.operator_team_roster_entries AS roster
    JOIN actor ON actor.tenant_id = roster.tenant_id
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = roster.tenant_id
     AND source.id = roster.source_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = roster.tenant_id
     AND membership.id = roster.membership_id
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE roster.revoked_at IS NULL
      AND (roster.expires_at IS NULL
        OR roster.expires_at > transaction_timestamp())
      AND source.retired_at IS NULL
      AND membership.status = 'active'
      AND identity.active
  )
  SELECT team.operator_team_id, roster.user_id,
         team.team_manageable, team.team_claimable
  FROM admitted_teams AS team
  LEFT JOIN live_roster AS roster
    ON roster.assignment_epoch_id = team.assignment_epoch_id
  WHERE team.team_manageable OR team.team_claimable OR team.actor_on_team
  ORDER BY team.operator_team_id, roster.user_id
$function$;--> statement-breakpoint

CREATE FUNCTION app.lookup_tenant_ticket_mutation_replay_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_action text,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE (result_version integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  replay record;
  operation text := p_aggregate_kind::text || '.' || p_action;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR p_action <> 'transition'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'ticket replay identity is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO replay
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = operation
    AND command.key_digest = p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF replay.request_digest IS DISTINCT FROM p_request_digest
     OR p_aggregate_kind = 'alert' AND replay.result_alert_id <> p_ticket_id
     OR p_aggregate_kind = 'case' AND replay.result_case_id <> p_ticket_id THEN
    RAISE EXCEPTION 'ticket replay identity conflicts'
      USING ERRCODE = '23505', CONSTRAINT = 'ticket_commands_replay_key';
  END IF;
  RETURN QUERY SELECT replay.result_version;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.lookup_tenant_ticket_escalation_replay_v1(
  p_path_alert_id uuid,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE (
  result_case_id uuid,
  result_case_version integer,
  result_path_alert_version integer,
  result_metadata jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  replay record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_path_alert_id IS NULL
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'escalation replay identity is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO replay
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'ticket.escalate'
    AND command.key_digest = p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF replay.request_digest IS DISTINCT FROM p_request_digest
     OR replay.result_alert_id <> p_path_alert_id
     OR replay.result_case_id IS NULL THEN
    RAISE EXCEPTION 'escalation replay identity conflicts'
      USING ERRCODE = '23505', CONSTRAINT = 'ticket_commands_replay_key';
  END IF;
  RETURN QUERY SELECT replay.result_case_id, replay.result_version,
    (replay.result_metadata ->> 'pathAlertVersion')::integer,
    replay.result_metadata;
END;
$function$;--> statement-breakpoint

CREATE FUNCTION app.lookup_tenant_ticket_escalation_replay_v2(
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE (
  result_path_alert_id uuid,
  result_case_id uuid,
  result_case_version integer,
  result_path_alert_version integer,
  result_metadata jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  replay record;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'escalation replay identity is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT command.* INTO replay
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'ticket.escalate'
    AND command.key_digest = p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF replay.request_digest IS DISTINCT FROM p_request_digest
     OR replay.result_alert_id IS NULL OR replay.result_case_id IS NULL THEN
    RAISE EXCEPTION 'escalation replay identity conflicts'
      USING ERRCODE = '23505', CONSTRAINT = 'ticket_commands_replay_key';
  END IF;
  RETURN QUERY SELECT replay.result_alert_id, replay.result_case_id,
    replay.result_version,
    (replay.result_metadata ->> 'pathAlertVersion')::integer,
    replay.result_metadata;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_current_ticket_scope_allows_v1(text, uuid, uuid, uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_ticket_assignment_epoch_v1(uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_validate_ticket_effects_v1(text[]) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_ticket_state_action_effects_v1(public.ticket_aggregate_kind, uuid, integer, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_current_ticket_has_role_v1(text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_ticket_transition_effects_v1(public.ticket_aggregate_kind, uuid, integer, text, text, text, text, jsonb, uuid, uuid, uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind, uuid, text, integer, text[], uuid, uuid, inet, text, text, jsonb, jsonb, jsonb) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_validate_full_alert_payload_v1(text, text, text, jsonb, text, text, text, timestamp with time zone, text[], jsonb) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_alert_as_human_v2(text, text, text, public.alert_severity, text, text, text, jsonb, text, text, text, timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_alert_as_service_account_v2(uuid, bytea, integer, bytea, inet, text, text, text, public.alert_severity, text, text, text, jsonb, text, text, text, timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid, bytea, bytea, uuid, uuid, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_case_v1(uuid, uuid, integer, text, text, text, public.alert_severity, text, text, text, text[], jsonb, boolean, timestamp with time zone, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind, uuid, text, integer, integer, uuid, integer, text, text, text, boolean, uuid, uuid, uuid, text, text, text, jsonb, bytea, bytea, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.create_tenant_ticket_comment_v1(public.ticket_aggregate_kind, uuid, public.ticket_comment_visibility, text, text, uuid[], bytea, bytea, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.commit_tenant_ticket_escalation_v1(uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[], uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.resolve_current_ticket_assignment_authority_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.lookup_tenant_ticket_mutation_replay_v1(public.ticket_aggregate_kind, uuid, text, bytea, bytea) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.lookup_tenant_ticket_escalation_replay_v1(uuid, bytea, bytea) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.lookup_tenant_ticket_escalation_replay_v2(bytea, bytea) OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION app.private_current_ticket_scope_allows_v1(text, uuid, uuid, uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_ticket_assignment_epoch_v1(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_validate_ticket_effects_v1(text[]) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_ticket_state_action_effects_v1(public.ticket_aggregate_kind, uuid, integer, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_current_ticket_has_role_v1(text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_ticket_transition_effects_v1(public.ticket_aggregate_kind, uuid, integer, text, text, text, text, jsonb, uuid, uuid, uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind, uuid, text, integer, text[], uuid, uuid, inet, text, text, jsonb, jsonb, jsonb) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_validate_full_alert_payload_v1(text, text, text, jsonb, text, text, text, timestamp with time zone, text[], jsonb) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_alert_as_human_v2(text, text, text, public.alert_severity, text, text, text, jsonb, text, text, text, timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_alert_as_service_account_v2(uuid, bytea, integer, bytea, inet, text, text, text, public.alert_severity, text, text, text, jsonb, text, text, text, timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid, bytea, bytea, uuid, uuid, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_case_v1(uuid, uuid, integer, text, text, text, public.alert_severity, text, text, text, text[], jsonb, boolean, timestamp with time zone, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind, uuid, text, integer, integer, uuid, integer, text, text, text, boolean, uuid, uuid, uuid, text, text, text, jsonb, bytea, bytea, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_tenant_ticket_comment_v1(public.ticket_aggregate_kind, uuid, public.ticket_comment_visibility, text, text, uuid[], bytea, bytea, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_tenant_ticket_escalation_v1(uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[], uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.resolve_current_ticket_assignment_authority_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_tenant_ticket_mutation_replay_v1(public.ticket_aggregate_kind, uuid, text, bytea, bytea) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_tenant_ticket_escalation_replay_v1(uuid, bytea, bytea) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_tenant_ticket_escalation_replay_v2(bytea, bytea) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

GRANT EXECUTE ON FUNCTION app.create_tenant_alert_as_human_v2(text, text, text, public.alert_severity, text, text, text, jsonb, text, text, text, timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_alert_as_service_account_v2(uuid, bytea, integer, bytea, inet, text, text, text, public.alert_severity, text, text, text, jsonb, text, text, text, timestamp with time zone, boolean, text[], jsonb, uuid, uuid, uuid, bytea, bytea, uuid, uuid, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_case_v1(uuid, uuid, integer, text, text, text, public.alert_severity, text, text, text, text[], jsonb, boolean, timestamp with time zone, uuid, uuid, bytea, bytea, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind, uuid, text, integer, integer, uuid, integer, text, text, text, boolean, uuid, uuid, uuid, text, text, text, jsonb, bytea, bytea, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_tenant_ticket_comment_v1(public.ticket_aggregate_kind, uuid, public.ticket_comment_visibility, text, text, uuid[], bytea, bytea, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_tenant_ticket_escalation_v1(uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[], uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.resolve_current_ticket_assignment_authority_v1() TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_tenant_ticket_mutation_replay_v1(public.ticket_aggregate_kind, uuid, text, bytea, bytea) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_tenant_ticket_escalation_replay_v2(bytea, bytea) TO periapsis_api;--> statement-breakpoint

REVOKE ALL ON TABLE public.alerts, public.cases, public.ticket_workflows,
  public.ticket_workflow_versions, public.ticket_number_counters,
  public.ticket_comments, public.ticket_comment_commands,
  public.ticket_activities, public.alert_case_links,
  public.ticket_assignment_history, public.ticket_commands
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT SELECT ON TABLE public.alerts, public.cases, public.ticket_workflows,
  public.ticket_workflow_versions, public.ticket_comments,
  public.ticket_activities, public.alert_case_links TO periapsis_api;--> statement-breakpoint

DO $ticketing_transaction_boundary_assertions$
DECLARE
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_configuration text[];
  function_security_definer boolean;
  public_can_execute boolean;
  api_can_execute boolean;
  worker_can_execute boolean;
  notifier_can_execute boolean;
  auditor_can_execute boolean;
  table_name text;
BEGIN
  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_current_ticket_scope_allows_v1(text,uuid,uuid,uuid,uuid)', false),
      ('app.private_ticket_assignment_epoch_v1(uuid,uuid)', false),
      ('app.private_validate_ticket_effects_v1(text[])', false),
      ('app.private_ticket_state_action_effects_v1(public.ticket_aggregate_kind,uuid,integer,text,text)', false),
      ('app.private_current_ticket_has_role_v1(text)', false),
      ('app.private_ticket_transition_effects_v1(public.ticket_aggregate_kind,uuid,integer,text,text,text,text,jsonb,uuid,uuid,uuid,uuid)', false),
      ('app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)', false),
      ('app.private_validate_full_alert_payload_v1(text,text,text,jsonb,text,text,text,timestamp with time zone,text[],jsonb)', false),
      ('app.create_tenant_alert_as_human_v2(text,text,text,public.alert_severity,text,text,text,jsonb,text,text,text,timestamp with time zone,boolean,text[],jsonb,uuid,uuid,uuid,bytea,bytea,uuid,uuid,inet,text,text)', true),
      ('app.create_tenant_alert_as_service_account_v2(uuid,bytea,integer,bytea,inet,text,text,text,public.alert_severity,text,text,text,jsonb,text,text,text,timestamp with time zone,boolean,text[],jsonb,uuid,uuid,uuid,bytea,bytea,uuid,uuid,text)', true),
      ('app.create_tenant_case_v1(uuid,uuid,integer,text,text,text,public.alert_severity,text,text,text,text[],jsonb,boolean,timestamp with time zone,uuid,uuid,bytea,bytea,uuid,uuid,inet,text,text)', true),
      ('app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)', true),
      ('app.create_tenant_ticket_comment_v1(public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,text,text,uuid[],bytea,bytea,uuid,uuid,inet,text,text)', true),
      ('app.commit_tenant_ticket_escalation_v1(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)', true)
      ,('app.resolve_current_ticket_assignment_authority_v1()', true)
      ,('app.lookup_tenant_ticket_mutation_replay_v1(public.ticket_aggregate_kind,uuid,text,bytea,bytea)', true)
      ,('app.lookup_tenant_ticket_escalation_replay_v1(uuid,bytea,bytea)', false)
      ,('app.lookup_tenant_ticket_escalation_replay_v2(bytea,bytea)', true)
    ) AS expected(signature, api_execute)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RAISE EXCEPTION 'required ticketing ABI % is absent', expected_function.signature
        USING ERRCODE = '55000';
    END IF;
    SELECT pg_catalog.pg_get_userbyid(procedure.proowner), procedure.proconfig,
           procedure.prosecdef,
           pg_catalog.has_function_privilege('public', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_api', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_worker', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_notifier', procedure.oid, 'EXECUTE'),
           pg_catalog.has_function_privilege('periapsis_auditor', procedure.oid, 'EXECUTE')
    INTO function_owner, function_configuration, function_security_definer,
         public_can_execute, api_can_execute, worker_can_execute,
         notifier_can_execute, auditor_can_execute
    FROM pg_catalog.pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_configuration IS DISTINCT FROM
            ARRAY['search_path=pg_catalog, public, app']::text[]
       OR NOT function_security_definer OR public_can_execute
       OR api_can_execute IS DISTINCT FROM expected_function.api_execute
       OR worker_can_execute OR notifier_can_execute OR auditor_can_execute THEN
      RAISE EXCEPTION 'ticketing ABI % privilege boundary is not exact',
        expected_function.signature USING ERRCODE = '55000';
    END IF;
  END LOOP;

  FOREACH table_name IN ARRAY ARRAY[
    'alerts', 'cases', 'ticket_workflows', 'ticket_workflow_versions',
    'ticket_number_counters', 'ticket_comments', 'ticket_comment_commands',
    'ticket_activities', 'alert_case_links', 'ticket_assignment_history',
    'ticket_commands'
  ]::text[]
  LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
      WHERE namespace.nspname = 'public' AND relation.relname = table_name
        AND relation.relrowsecurity AND relation.relforcerowsecurity
    ) OR pg_catalog.has_table_privilege(
      'periapsis_api', format('public.%I', table_name), 'INSERT'
    ) OR pg_catalog.has_table_privilege(
      'periapsis_api', format('public.%I', table_name), 'UPDATE'
    ) OR pg_catalog.has_table_privilege(
      'periapsis_api', format('public.%I', table_name), 'DELETE'
    ) OR pg_catalog.has_table_privilege(
      'periapsis_api', format('public.%I', table_name), 'TRUNCATE'
    ) THEN
      RAISE EXCEPTION 'ticketing table % boundary is not exact', table_name
        USING ERRCODE = '55000';
    END IF;
  END LOOP;
END;
$ticketing_transaction_boundary_assertions$;--> statement-breakpoint
