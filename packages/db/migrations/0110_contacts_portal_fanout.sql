-- Dispatch RLS policies evaluate the bounded tenant context after the claim
-- loader pins app.tenant_id. The non-login dispatch owner needs this reader;
-- the notifier login itself remains unable to call it.
GRANT EXECUTE ON FUNCTION app.context_tenant_id()
TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- Live capability and customer-projectability checks need only these tenant
-- bounded sources. They are available to the non-login definer, never to the
-- notifier role that invokes the loader ABI.
GRANT SELECT ON TABLE
  public.tenant_authorization_states,
  public.tenant_security_group_memberships,
  public.tenant_security_groups,
  public.tenant_security_group_role_grants,
  public.operator_team_assignment_epochs,
  public.alerts,
  public.cases,
  public.ticket_workflow_versions
TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_auth_state_v1
ON public.tenant_authorization_states FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_security_memberships_v1
ON public.tenant_security_group_memberships FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_security_groups_v1
ON public.tenant_security_groups FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_security_grants_v1
ON public.tenant_security_group_role_grants FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_team_epochs_v1
ON public.operator_team_assignment_epochs FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_alerts_v1
ON public.alerts FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_cases_v1
ON public.cases FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint
CREATE POLICY contacts_fanout_dispatch_workflow_versions_v1
ON public.ticket_workflow_versions FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
--> statement-breakpoint

CREATE FUNCTION app.private_notification_human_has_canonical_tenant_admin_v1(
  p_tenant_id uuid,
  p_user_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH role_paths AS (
    SELECT direct_grant.role_id
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS direct_source
      ON direct_source.tenant_id = direct_grant.tenant_id
     AND direct_source.id = direct_grant.source_id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = direct_grant.tenant_id
     AND membership.id = direct_grant.membership_id
    WHERE membership.tenant_id = p_tenant_id
      AND membership.user_id = p_user_id
      AND membership.status = 'active'
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > transaction_timestamp())
      AND direct_source.retired_at IS NULL

    UNION ALL

    SELECT group_grant.role_id
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = group_member.tenant_id
     AND membership.id = group_member.membership_id
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
    WHERE membership.tenant_id = p_tenant_id
      AND membership.user_id = p_user_id
      AND membership.status = 'active'
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
    FROM role_paths AS role_path
    JOIN public.tenant_roles AS role
      ON role.tenant_id = p_tenant_id
     AND role.id = role_path.role_id
    JOIN public.users AS identity ON identity.id = p_user_id
    JOIN public.tenants AS tenant ON tenant.id = p_tenant_id
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = p_tenant_id AND state.initialized_at IS NOT NULL
    WHERE role.key = 'tenant_admin'
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
      AND identity.active AND tenant.status = 'active'
  );
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_notification_human_has_canonical_tenant_admin_v1(
  uuid, uuid
) OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_notification_human_has_canonical_tenant_admin_v1(
  uuid, uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_notification_ticket_is_customer_projectable_v1(
  p_tenant_id uuid,
  p_kind public.ticket_aggregate_kind,
  p_ticket_id uuid
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH ticket AS (
    SELECT alert.workflow_id, alert.workflow_version, alert.state_key,
           alert.customer_visible
    FROM public.alerts AS alert
    WHERE p_kind = 'alert' AND alert.tenant_id = p_tenant_id
      AND alert.id = p_ticket_id
    UNION ALL
    SELECT case_row.workflow_id, case_row.workflow_version,
           case_row.state_key, case_row.customer_visible
    FROM public.cases AS case_row
    WHERE p_kind = 'case' AND case_row.tenant_id = p_tenant_id
      AND case_row.id = p_ticket_id
  ), matching_states AS (
    SELECT ticket.customer_visible, state.value ->> 'visibility' AS visibility
    FROM ticket
    JOIN public.ticket_workflow_versions AS workflow
      ON workflow.tenant_id = p_tenant_id
     AND workflow.workflow_id = ticket.workflow_id
     AND workflow.version = ticket.workflow_version
     AND workflow.aggregate_kind = p_kind
    CROSS JOIN LATERAL jsonb_array_elements(workflow.states) AS state(value)
    WHERE state.value ->> 'key' = ticket.state_key
  )
  SELECT count(*) = 1
     AND coalesce(bool_and(customer_visible AND visibility = 'customer'), false)
  FROM matching_states;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_notification_ticket_is_customer_projectable_v1(
  uuid, public.ticket_aggregate_kind, uuid
) OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_notification_ticket_is_customer_projectable_v1(
  uuid, public.ticket_aggregate_kind, uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.private_notification_operator_candidates_v1(
  p_tenant_id uuid,
  p_event_id uuid
)
RETURNS TABLE(
  sort_email text,
  sort_principal uuid,
  sort_source text,
  value jsonb
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH source AS (
    SELECT event.*,
      CASE event.aggregate_type
        WHEN 'alert' THEN 'alert.read'
        WHEN 'case' THEN 'case.read'
        WHEN 'contact' THEN 'contact.read'
      END AS read_permission
    FROM public.outbox_events AS event
    WHERE event.tenant_id = p_tenant_id AND event.id = p_event_id
  ), candidates AS (
    SELECT profile.email AS sort_email,
           identity.id AS sort_principal,
           'operator'::text AS sort_source,
           source.*,
           membership.id AS membership_id,
           relation.team_related,
           capability.read_tenant,
           capability.read_own,
           capability.read_assigned,
           capability.read_team,
           identity.id::text = source.payload #>>
             '{operatorContext,routing,creatorUserId}' AS creator_related,
           identity.id::text = source.payload #>>
             '{operatorContext,routing,assigneeUserId}' AS assignee_related,
           identity.id::text = source.payload #>>
             '{operatorContext,routing,previousAssigneeUserId}'
             AS previous_assignee_related,
           source.actor_kind = 'human'
             AND identity.id = source.actor_id AS actor_related,
           app.private_notification_human_has_canonical_tenant_admin_v1(
             p_tenant_id, identity.id
           ) AS canonical_tenant_admin
    FROM source
    JOIN public.tenant_user_profiles AS profile
      ON profile.tenant_id = source.tenant_id
     AND profile.email IS NOT NULL
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id = profile.tenant_id
     AND membership.id = profile.membership_id
     AND membership.user_id = profile.user_id
     AND membership.status = 'active'
    JOIN public.users AS identity
      ON identity.id = profile.user_id AND identity.active
    CROSS JOIN LATERAL (
      SELECT EXISTS (
        SELECT 1
        FROM public.operator_team_roster_entries AS roster
        JOIN public.operator_team_assignment_epochs AS epoch
          ON epoch.tenant_id = roster.tenant_id
         AND epoch.id = roster.assignment_epoch_id
        WHERE roster.tenant_id = p_tenant_id
          AND roster.membership_id = membership.id
          AND epoch.operator_team_id::text = source.payload #>>
            '{operatorContext,routing,operatorTeamId}'
          AND roster.assignment_epoch_id::text = source.payload #>>
            '{operatorContext,routing,operatorTeamEpochId}'
          AND epoch.assigned_at <= source.occurred_at
          AND (epoch.ended_at IS NULL
            OR epoch.ended_at > source.occurred_at)
          AND (epoch.ended_at IS NULL
            OR epoch.ended_at > transaction_timestamp())
          AND roster.granted_at <= source.occurred_at
          AND (roster.expires_at IS NULL
            OR roster.expires_at > source.occurred_at)
          AND (roster.revoked_at IS NULL
            OR roster.revoked_at > source.occurred_at)
          AND roster.granted_at <= transaction_timestamp()
          AND (roster.expires_at IS NULL
            OR roster.expires_at > transaction_timestamp())
          AND (roster.revoked_at IS NULL
            OR roster.revoked_at > transaction_timestamp())
      ) AS team_related
    ) AS relation
    CROSS JOIN LATERAL (
      SELECT
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id, identity.id, source.read_permission, 'tenant'
        ) AS read_tenant,
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id, identity.id, source.read_permission, 'own'
        ) AS read_own,
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id, identity.id, source.read_permission, 'assigned'
        ) AS read_assigned,
        app.tenant_human_has_exact_permission_v3(
          p_tenant_id, identity.id, source.read_permission, 'operator_team'
        ) AS read_team
    ) AS capability
    WHERE source.read_permission IS NOT NULL
  ), projected AS (
    SELECT candidate.*,
      candidate.actor_related AND (
        candidate.read_tenant
        OR candidate.creator_related AND candidate.read_own
        OR (candidate.assignee_related OR candidate.previous_assignee_related)
          AND candidate.read_assigned
        OR candidate.team_related AND candidate.read_team
      ) AS include_actor,
      candidate.assignee_related
        AND (candidate.read_tenant OR candidate.read_assigned)
        AS include_assignee,
      candidate.previous_assignee_related
        AND (candidate.read_tenant OR candidate.read_assigned)
        AS include_previous_assignee,
      candidate.team_related
        AND (candidate.read_tenant OR candidate.read_team)
        AS include_team,
      candidate.canonical_tenant_admin AND candidate.read_tenant
        AS include_tenant_admin
    FROM candidates AS candidate
  ), shaped AS (
    SELECT projected.*,
      (CASE WHEN include_actor
        THEN jsonb_build_array('actor') ELSE '[]'::jsonb END)
      || (CASE WHEN include_assignee
        THEN jsonb_build_array('assignee') ELSE '[]'::jsonb END)
      || (CASE WHEN include_previous_assignee
        THEN jsonb_build_array('previous_assignee') ELSE '[]'::jsonb END)
      || (CASE WHEN include_team
        THEN jsonb_build_array('operator_team') ELSE '[]'::jsonb END)
      || (CASE WHEN include_tenant_admin
        THEN jsonb_build_array('tenant_admin') ELSE '[]'::jsonb END)
      AS kinds
    FROM projected
  )
  SELECT shaped.sort_email, shaped.sort_principal, shaped.sort_source,
         jsonb_build_object(
           'tenantId', p_tenant_id,
           'email', shaped.sort_email,
           'audience', 'operator',
           'kinds', shaped.kinds,
           'values', CASE WHEN shaped.include_team THEN jsonb_build_object(
             'operator_team', jsonb_build_array(
               shaped.payload #>> '{operatorContext,routing,operatorTeamId}'
             )
           ) ELSE '{}'::jsonb END,
           'principalId', shaped.sort_principal,
           'enabled', true,
           'emailAllowed', true
         ) AS value
  FROM shaped
  WHERE jsonb_array_length(shaped.kinds) > 0;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_notification_operator_candidates_v1(uuid, uuid)
  OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_notification_operator_candidates_v1(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_append_ticket_side_effects_v1(
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
  notification_type public.notification_event_type;
  notification_audience public.notification_audience := 'operator';
  customer_visible boolean := false;
  customer_context jsonb;
  routing_creator_user_id uuid;
  routing_assignee_user_id uuid;
  routing_previous_assignee_user_id uuid;
  routing_operator_team_id uuid;
  routing_operator_team_epoch_id uuid;
  activity_origin text := CASE
    WHEN p_metadata ->> 'origin' = 'customer_portal' THEN 'customer_portal'
    ELSE 'api'
  END;
BEGIN
  PERFORM app.private_validate_ticket_effects_v1(p_effects);
  IF p_aggregate_id IS NULL OR p_version NOT BETWEEN 1 AND 2147483647
     OR p_action IS NULL OR p_action !~ '^[a-z][a-z0-9_]{1,63}$'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_before IS NOT NULL AND jsonb_typeof(p_before) <> 'object'
     OR p_after IS NOT NULL AND jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR activity_origin = 'customer_portal' AND (
       p_action <> 'commented'
       OR p_metadata ->> 'visibility' <> 'public'
       OR p_metadata ->> 'author_contact_id' IS NULL
     ) THEN
    RAISE EXCEPTION 'ticket side-effect input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT coalesce(max(activity.sequence), 0) + 1 INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id = context_tenant
    AND (p_aggregate_kind = 'alert' AND activity.alert_id = p_aggregate_id
      OR p_aggregate_kind = 'case' AND activity.case_id = p_aggregate_id);
  IF activity_sequence > 2147483647 THEN
    RAISE EXCEPTION 'ticket activity sequence is exhausted'
      USING ERRCODE = '54000';
  END IF;

  INSERT INTO public.ticket_activities (
    id, tenant_id, alert_id, case_id, sequence, kind, summary,
    actor_principal_kind, actor_membership_id, actor_user_id, origin, details
  ) VALUES (
    activity_id, context_tenant,
    CASE WHEN p_aggregate_kind = 'alert' THEN p_aggregate_id END,
    CASE WHEN p_aggregate_kind = 'case' THEN p_aggregate_id END,
    activity_sequence, event_type,
    CASE p_action WHEN 'created' THEN initcap(p_aggregate_kind::text) || ' created'
      WHEN 'transitioned' THEN initcap(p_aggregate_kind::text) || ' transitioned'
      ELSE initcap(p_aggregate_kind::text) || ' ' || replace(p_action, '_', ' ') END,
    'human', actor_membership, actor_user,
    activity_origin,
    p_metadata || jsonb_build_object(
      'version', p_version, 'content_redacted', true
    )
  );

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.' || p_aggregate_kind::text || '.' || p_action,
    p_aggregate_kind::text, p_aggregate_id, p_request_id, p_correlation_id,
    p_ip_address, nullif(p_user_agent, ''), p_authentication_method,
    p_before, p_after,
    p_metadata || jsonb_build_object(
      'actor_membership_id', actor_membership, 'content_redacted', true
    )
  );

  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, event_type, schema_version,
    payload, deduplication_key, correlation_id, causation_id
  ) VALUES (
    context_tenant, p_aggregate_kind::text, p_aggregate_id, event_type, 1,
    jsonb_build_object(
      p_aggregate_kind::text || '_id', p_aggregate_id, 'version', p_version
    ),
    event_type || ':' || activity_id::text, p_correlation_id, p_request_id
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
    notification_type := CASE
      WHEN p_aggregate_kind = 'alert' AND p_action = 'created' THEN 'alert.created'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'assigned' THEN 'alert.assigned'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'claimed' THEN 'alert.claimed'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'transitioned' THEN 'alert.status_changed'::public.notification_event_type
      WHEN p_aggregate_kind = 'alert' AND p_action = 'escalated' THEN 'alert.escalated'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'created' THEN 'case.created'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'assigned' THEN 'case.assigned'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'claimed' THEN 'case.claimed'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'transferred' THEN 'case.transferred'::public.notification_event_type
      WHEN p_aggregate_kind = 'case' AND p_action = 'transitioned' THEN 'case.status_changed'::public.notification_event_type
      WHEN p_action = 'commented' AND p_metadata ->> 'visibility' = 'public' THEN 'comment.public_added'::public.notification_event_type
      WHEN p_action = 'commented' AND p_metadata ->> 'visibility' = 'private' THEN 'comment.private_added'::public.notification_event_type
      ELSE NULL
    END;
    IF notification_type IS NOT NULL THEN
      routing_previous_assignee_user_id := nullif(
        p_before ->> 'assignee_user_id', ''
      )::uuid;
      IF p_aggregate_kind = 'alert' THEN
        SELECT alert.created_by, alert.assignee_user_id,
               alert.assigned_team_id, alert.assigned_team_epoch_id,
               alert.customer_visible
                 AND state.value ->> 'visibility' = 'customer'
        INTO STRICT routing_creator_user_id, routing_assignee_user_id,
             routing_operator_team_id, routing_operator_team_epoch_id,
             customer_visible
        FROM public.alerts AS alert
        JOIN public.ticket_workflow_versions AS workflow
          ON workflow.tenant_id = alert.tenant_id
         AND workflow.workflow_id = alert.workflow_id
         AND workflow.version = alert.workflow_version
         AND workflow.aggregate_kind = 'alert'
        CROSS JOIN LATERAL jsonb_array_elements(workflow.states) AS state(value)
        WHERE alert.tenant_id = context_tenant
          AND alert.id = p_aggregate_id
          AND state.value ->> 'key' = alert.state_key;
      ELSE
        SELECT case_row.created_by_user_id, case_row.assignee_user_id,
               case_row.assigned_team_id, case_row.assigned_team_epoch_id,
               case_row.customer_visible
                 AND state.value ->> 'visibility' = 'customer'
        INTO STRICT routing_creator_user_id, routing_assignee_user_id,
             routing_operator_team_id, routing_operator_team_epoch_id,
             customer_visible
        FROM public.cases AS case_row
        JOIN public.ticket_workflow_versions AS workflow
          ON workflow.tenant_id = case_row.tenant_id
         AND workflow.workflow_id = case_row.workflow_id
         AND workflow.version = case_row.workflow_version
         AND workflow.aggregate_kind = 'case'
        CROSS JOIN LATERAL jsonb_array_elements(workflow.states) AS state(value)
        WHERE case_row.tenant_id = context_tenant
          AND case_row.id = p_aggregate_id
          AND state.value ->> 'key' = case_row.state_key;
      END IF;
      IF notification_type = 'comment.public_added' AND customer_visible THEN
        notification_audience := 'customer';
        customer_context := jsonb_build_object(
          p_aggregate_kind::text,
            jsonb_build_object('id', p_aggregate_id, 'version', p_version),
          'comment', jsonb_build_object(
            'id', p_metadata ->> 'comment_id', 'visibility', 'public'
          )
        );
      END IF;
      PERFORM app.private_append_tenant_notification_event_v2(
        uuidv7(), notification_type,
        p_aggregate_kind::text::public.notification_object_type,
        p_aggregate_id, p_version, transaction_timestamp(),
        'human', actor_user, 'ticketing', notification_audience,
        jsonb_build_object(
          p_aggregate_kind::text,
            jsonb_build_object('id', p_aggregate_id, 'version', p_version),
          'actor', jsonb_build_object('id', actor_user),
          'action', p_action,
          'metadata', p_metadata || jsonb_build_object('content_redacted', true),
          'routing', jsonb_strip_nulls(jsonb_build_object(
            'creatorUserId', routing_creator_user_id,
            'assigneeUserId', routing_assignee_user_id,
            'previousAssigneeUserId', routing_previous_assignee_user_id,
            'operatorTeamId', routing_operator_team_id,
            'operatorTeamEpochId', routing_operator_team_epoch_id
          ))
        ),
        customer_context,
        'notification:v2:' || p_aggregate_kind::text || ':'
          || p_aggregate_id::text || ':' || p_version::text || ':'
          || notification_type::text,
        p_correlation_id, p_request_id
      );
    END IF;
  END IF;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_append_ticket_side_effects_v1(
  public.ticket_aggregate_kind, uuid, text, integer, text[], uuid, uuid,
  inet, text, text, jsonb, jsonb, jsonb
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_ticket_side_effects_v1(
  public.ticket_aggregate_kind, uuid, text, integer, text[], uuid, uuid,
  inet, text, text, jsonb, jsonb, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.load_notification_fanout_inputs_v2(
  p_event_id uuid,
  p_fence_token uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  source_event public.outbox_events%ROWTYPE;
  selected_snapshot public.tenant_notification_fanout_snapshots%ROWTYPE;
  selected_rule_pins jsonb;
  selected_webhook_pins jsonb;
  selected_smtp_scope text;
  selected_smtp_id uuid;
  selected_smtp_version integer;
  snapshot_value jsonb;
  rules_value jsonb;
  templates_value jsonb;
  candidates_value jsonb;
  candidate_count integer;
BEGIN
  context_tenant := app.private_lock_notification_fanout_claim_v1(
    p_event_id, p_fence_token
  );
  SELECT event.* INTO STRICT source_event
  FROM public.outbox_events AS event
  WHERE event.id = p_event_id AND event.tenant_id = context_tenant;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant
    WHERE tenant.id = context_tenant AND tenant.status = 'active'
  ) THEN
    RAISE EXCEPTION 'notification tenant is unavailable'
      USING ERRCODE = '42501';
  END IF;

  SELECT snapshot.* INTO selected_snapshot
  FROM public.tenant_notification_fanout_snapshots AS snapshot
  WHERE snapshot.tenant_id = context_tenant AND snapshot.event_id = p_event_id;
  IF NOT FOUND THEN
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'ruleId', rule.id, 'version', version.version
    ) ORDER BY rule.id, version.version), '[]'::jsonb)
    INTO selected_rule_pins
    FROM public.tenant_notification_rules AS rule
    JOIN public.tenant_notification_rule_versions AS version
      ON version.tenant_id = rule.tenant_id
     AND version.rule_id = rule.id
     AND version.version = rule.current_version
    WHERE rule.tenant_id = context_tenant
      AND version.channel = 'email'
      AND version.enabled
      AND version.event_type::text = substring(source_event.event_type from 14)
      AND version.object_type::text = source_event.aggregate_type
      AND version.effective_from <= source_event.occurred_at
      AND (version.effective_until IS NULL
        OR version.effective_until > source_event.occurred_at);
    IF jsonb_array_length(selected_rule_pins) > 1000 THEN
      RAISE EXCEPTION 'notification rule snapshot is oversized'
        USING ERRCODE = '54000';
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'configurationId', configuration.id,
      'version', version.version
    ) ORDER BY configuration.id, version.version), '[]'::jsonb)
    INTO selected_webhook_pins
    FROM public.tenant_notification_webhook_configurations AS configuration
    JOIN public.tenant_notification_webhook_configuration_versions AS version
      ON version.tenant_id = configuration.tenant_id
     AND version.configuration_id = configuration.id
     AND version.version = configuration.current_version
    WHERE configuration.tenant_id = context_tenant
      AND configuration.revoked_at IS NULL
      AND version.enabled
      AND substring(source_event.event_type from 14)::public.notification_event_type
        = ANY(version.event_types)
      AND (version.audience = 'operator'
        OR source_event.maximum_audience = 'customer');
    IF jsonb_array_length(selected_webhook_pins) > 1000 THEN
      RAISE EXCEPTION 'notification webhook snapshot is oversized'
        USING ERRCODE = '54000';
    END IF;

    IF jsonb_array_length(selected_rule_pins) > 0 THEN
      SELECT 'tenant', configuration.id, configuration.current_version
      INTO selected_smtp_scope, selected_smtp_id, selected_smtp_version
      FROM public.tenant_notification_smtp_configurations AS configuration
      JOIN public.tenant_notification_smtp_configuration_versions AS version
        ON version.tenant_id = configuration.tenant_id
       AND version.configuration_id = configuration.id
       AND version.version = configuration.current_version
      WHERE configuration.tenant_id = context_tenant
        AND configuration.revoked_at IS NULL AND version.enabled
      ORDER BY configuration.id
      LIMIT 1;
      IF NOT FOUND THEN
        SELECT 'platform', configuration.id, configuration.current_version
        INTO selected_smtp_scope, selected_smtp_id, selected_smtp_version
        FROM public.platform_notification_smtp_configurations AS configuration
        JOIN public.platform_notification_smtp_configuration_versions AS version
          ON version.configuration_id = configuration.id
         AND version.version = configuration.current_version
        WHERE configuration.revoked_at IS NULL AND version.enabled
        ORDER BY configuration.id
        LIMIT 1;
      END IF;
    END IF;

    snapshot_value := jsonb_build_object(
      'rules', selected_rule_pins,
      'webhooks', selected_webhook_pins,
      'smtpScope', selected_smtp_scope,
      'smtpId', selected_smtp_id,
      'smtpVersion', selected_smtp_version
    );
    INSERT INTO public.tenant_notification_fanout_snapshots (
      tenant_id, event_id, rule_pins, webhook_configuration_pins,
      smtp_configuration_scope, smtp_configuration_id,
      smtp_configuration_version, snapshot_digest
    ) VALUES (
      context_tenant, p_event_id, selected_rule_pins, selected_webhook_pins,
      selected_smtp_scope, selected_smtp_id, selected_smtp_version,
      sha256(convert_to(snapshot_value::text, 'UTF8'))
    );
    SELECT snapshot.* INTO STRICT selected_snapshot
    FROM public.tenant_notification_fanout_snapshots AS snapshot
    WHERE snapshot.tenant_id = context_tenant
      AND snapshot.event_id = p_event_id;
  END IF;

  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'id', version.rule_id,
    'tenantId', version.tenant_id,
    'name', version.name,
    'description', version.description,
    'eventType', version.event_type,
    'objectType', version.object_type,
    'condition', version.condition,
    'recipients', version.recipients,
    'templateId', version.template_id,
    'templateVersion', version.template_version,
    'channel', version.channel,
    'priority', version.priority,
    'delayMs', version.delay_ms,
    'quietHours', version.quiet_hours,
    'deduplicationWindowMs', version.deduplication_window_ms,
    'grouping', version.grouping,
    'retry', version.retry,
    'enabled', version.enabled,
    'version', version.version,
    'effectiveFrom', version.effective_from,
    'effectiveUntil', version.effective_until
  )) ORDER BY version.rule_id, version.version), '[]'::jsonb)
  INTO rules_value
  FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
  JOIN public.tenant_notification_rule_versions AS version
    ON version.tenant_id = context_tenant
   AND version.rule_id = (pin.value ->> 'ruleId')::uuid
   AND version.version = (pin.value ->> 'version')::integer;

  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'id', version.template_id,
    'tenantId', version.tenant_id,
    'key', version.key,
    'name', version.name,
    'language', version.language,
    'version', version.version,
    'subject', version.subject,
    'html', version.html,
    'plainText', version.plain_text,
    'css', version.css
  )) ORDER BY version.template_id, version.version), '[]'::jsonb)
  INTO templates_value
  FROM (
    SELECT DISTINCT rule_version.template_id, rule_version.template_version
    FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
    JOIN public.tenant_notification_rule_versions AS rule_version
      ON rule_version.tenant_id = context_tenant
     AND rule_version.rule_id = (pin.value ->> 'ruleId')::uuid
     AND rule_version.version = (pin.value ->> 'version')::integer
  ) AS pinned_template
  JOIN public.tenant_notification_template_versions AS version
    ON version.tenant_id = context_tenant
   AND version.template_id = pinned_template.template_id
   AND version.version = pinned_template.template_version;

  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
    JOIN public.tenant_notification_rule_versions AS version
      ON version.tenant_id = context_tenant
     AND version.rule_id = (pin.value ->> 'ruleId')::uuid
     AND version.version = (pin.value ->> 'version')::integer
    CROSS JOIN LATERAL jsonb_array_elements(version.recipients)
         AS recipient(value)
    WHERE recipient.value ->> 'kind' NOT IN (
      'assignee', 'previous_assignee', 'operator_team', 'watcher',
      'actor', 'tenant_admin', 'platform_group', 'customer_contacts',
      'contact_group', 'contact_tag', 'explicit_email',
      'custom_email_field'
    )
  ) THEN
    RAISE EXCEPTION 'notification recipient source is unavailable'
      USING ERRCODE = '0A000';
  END IF;

  WITH operator_candidates AS (
    SELECT candidate.sort_email, candidate.sort_principal,
           candidate.sort_source, candidate.value
    FROM app.private_notification_operator_candidates_v1(
      context_tenant, p_event_id
    ) AS candidate
  ), customer_candidates AS (
    SELECT contact.email AS sort_email,
           contact.id AS sort_principal,
           'customer'::text AS sort_source,
           jsonb_strip_nulls(jsonb_build_object(
      'tenantId', contact.tenant_id,
      'email', contact.email,
      'audience', 'customer',
      'kinds', jsonb_build_array('customer_contacts')
        || CASE WHEN cardinality(matched_group.keys) > 0
          THEN jsonb_build_array('contact_group') ELSE '[]'::jsonb END
        || CASE WHEN cardinality(contact.tags) > 0
          THEN jsonb_build_array('contact_tag') ELSE '[]'::jsonb END,
      'values', jsonb_strip_nulls(jsonb_build_object(
        'contact_group', CASE WHEN cardinality(matched_group.keys) > 0
          THEN to_jsonb(matched_group.keys) END,
        'contact_tag', CASE WHEN cardinality(contact.tags) > 0
          THEN to_jsonb(contact.tags) END
      )),
      'principalId', contact.linked_user_id,
      'enabled', contact.active,
      'emailAllowed', contact.email_allowed
    )) AS value
    FROM public.customer_contacts AS contact
    LEFT JOIN LATERAL (
      SELECT array_agg(group_row.key ORDER BY group_row.key COLLATE "C") AS keys
      FROM public.customer_contact_groups AS group_row
      JOIN public.customer_contact_group_versions AS group_version
        ON group_version.tenant_id = group_row.tenant_id
       AND group_version.group_id = group_row.id
       AND group_version.version = group_row.current_version
      WHERE group_row.tenant_id = contact.tenant_id
        AND group_row.archived_at IS NULL
        AND (
          group_version.mode = 'manual' AND EXISTS (
            SELECT 1
            FROM public.customer_contact_group_version_members AS member
            WHERE member.tenant_id = group_version.tenant_id
              AND member.group_id = group_version.group_id
              AND member.group_version = group_version.version
              AND member.contact_id = contact.id
          )
          OR group_version.mode = 'dynamic'
             AND app.private_contact_rule_matches_v1(
               group_version.rule, contact
             )
        )
    ) AS matched_group ON true
    WHERE contact.tenant_id = context_tenant
      AND source_event.maximum_audience = 'customer'
      AND contact.active AND contact.archived_at IS NULL
      AND contact.email_allowed
      AND contact.linked_membership_id IS NOT NULL
      AND contact.linked_user_id IS NOT NULL
      AND EXISTS (
        SELECT 1
        FROM public.tenant_memberships AS membership
        JOIN public.users AS identity ON identity.id = membership.user_id
        WHERE membership.tenant_id = contact.tenant_id
          AND membership.id = contact.linked_membership_id
          AND membership.user_id = contact.linked_user_id
          AND membership.status = 'active' AND identity.active
      )
      AND contact.notification_categories @> ARRAY[
        substring(source_event.event_type from 14)
      ]::text[]
      AND (
        NOT EXISTS (
          SELECT 1
          FROM public.customer_contact_notification_windows AS any_window
          WHERE any_window.tenant_id = contact.tenant_id
            AND any_window.contact_id = contact.id
        )
        OR EXISTS (
          SELECT 1
          FROM public.customer_contact_notification_windows AS allowed_window
          CROSS JOIN LATERAL (
            SELECT source_event.occurred_at AT TIME ZONE contact.timezone
              AS local_time
          ) AS local_event
          WHERE allowed_window.tenant_id = contact.tenant_id
            AND allowed_window.contact_id = contact.id
            AND allowed_window.iso_weekday = extract(
              isodow FROM local_event.local_time
            )::integer
            AND extract(hour FROM local_event.local_time)::integer * 60
              + extract(minute FROM local_event.local_time)::integer
                >= allowed_window.start_minute
            AND extract(hour FROM local_event.local_time)::integer * 60
              + extract(minute FROM local_event.local_time)::integer
                < allowed_window.end_minute
        )
      )
      AND (
        source_event.aggregate_type = 'alert'
        AND app.private_notification_ticket_is_customer_projectable_v1(
          context_tenant, 'alert', source_event.aggregate_id
        )
        AND EXISTS (
          SELECT 1 FROM public.ticket_customer_contacts AS link
          WHERE link.tenant_id = context_tenant
            AND link.alert_id = source_event.aggregate_id
            AND link.contact_id = contact.id
            AND link.archived_at IS NULL
        )
        OR source_event.aggregate_type = 'case'
        AND app.private_notification_ticket_is_customer_projectable_v1(
          context_tenant, 'case', source_event.aggregate_id
        )
        AND EXISTS (
          SELECT 1 FROM public.ticket_customer_contacts AS link
          WHERE link.tenant_id = context_tenant
            AND link.case_id = source_event.aggregate_id
            AND link.contact_id = contact.id
            AND link.archived_at IS NULL
        )
      )
  ), all_candidates AS (
    SELECT * FROM operator_candidates
    UNION ALL
    SELECT * FROM customer_candidates
  )
  SELECT count(*)::integer,
         coalesce(jsonb_agg(candidate.value ORDER BY
           candidate.sort_email COLLATE "C", candidate.sort_source COLLATE "C",
           candidate.sort_principal
         ), '[]'::jsonb)
  INTO candidate_count, candidates_value
  FROM all_candidates AS candidate;
  IF candidate_count > 10000 THEN
    RAISE EXCEPTION 'notification recipient inventory is oversized'
      USING ERRCODE = '54000';
  END IF;

  RETURN jsonb_build_object(
    'rules', rules_value,
    'candidates', candidates_value,
    'templates', templates_value,
    'smtpConfiguration', CASE
      WHEN selected_snapshot.smtp_configuration_id IS NULL THEN NULL
      ELSE jsonb_build_object(
        'scope', selected_snapshot.smtp_configuration_scope,
        'id', selected_snapshot.smtp_configuration_id,
        'version', selected_snapshot.smtp_configuration_version
      ) END
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.load_notification_fanout_inputs_v2(uuid, uuid)
  OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.load_notification_fanout_inputs_v2(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v2(uuid, uuid)
  TO periapsis_notifier;
--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v1(uuid, uuid)
  FROM periapsis_notifier;
