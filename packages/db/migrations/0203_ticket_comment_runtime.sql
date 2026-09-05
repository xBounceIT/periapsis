ALTER TABLE "ticket_comment_author_snapshots" DROP CONSTRAINT "ticket_comment_author_snapshots_customer_contact_fk";
--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" DROP CONSTRAINT IF EXISTS "ticket_comment_author_snapshots_author_fk";
--> statement-breakpoint
ALTER TABLE "ticket_comment_idempotency_keys" DROP CONSTRAINT "ticket_comment_idempotency_keys_result_fk";
--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD CONSTRAINT "ticket_comment_author_snapshots_author_fk" FOREIGN KEY ("tenant_id","author_membership_id","author_user_id") REFERENCES "public"."tenant_memberships"("tenant_id","id","user_id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_author_snapshots" ADD CONSTRAINT "ticket_comment_author_snapshots_customer_contact_fk" FOREIGN KEY ("tenant_id","author_contact_id") REFERENCES "public"."customer_contacts"("tenant_id","id") ON DELETE restrict ON UPDATE restrict;--> statement-breakpoint
ALTER TABLE "ticket_comment_idempotency_keys" ADD CONSTRAINT "ticket_comment_idempotency_keys_result_fk" FOREIGN KEY ("tenant_id","result_comment_id","result_revision") REFERENCES "public"."ticket_comment_revisions"("tenant_id","comment_id","revision") ON DELETE restrict ON UPDATE restrict;
--> statement-breakpoint

-- V47 treats read_only as a customer role everywhere.  Keep the V46 helper
-- byte-for-byte sealed and use this successor from all new admission and
-- notification paths.
CREATE FUNCTION app.private_ticket_watcher_user_scope_allows_v2(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_user_id uuid,
  p_operation text
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH target AS (
    SELECT membership.id AS membership_id
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    JOIN public.tenants AS tenant ON tenant.id=membership.tenant_id
    WHERE membership.tenant_id=p_tenant_id
      AND membership.user_id=p_user_id
      AND membership.status='active'
      AND membership.role NOT IN (
        'customer_manager','customer_user','read_only'
      )
      AND identity.active AND tenant.status='active'
  ), ticket AS (
    SELECT alert.assigned_team_id, alert.assigned_team_epoch_id,
           alert.created_by AS owner_user_id, alert.assignee_user_id,
           alert.claimed_by_user_id
    FROM public.alerts AS alert
    WHERE p_aggregate_kind='alert'
      AND alert.tenant_id=p_tenant_id AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL
    UNION ALL
    SELECT case_row.assigned_team_id, case_row.assigned_team_epoch_id,
           case_row.created_by_user_id, case_row.assignee_user_id,
           case_row.claimed_by_user_id
    FROM public.cases AS case_row
    WHERE p_aggregate_kind='case'
      AND case_row.tenant_id=p_tenant_id AND case_row.id=p_ticket_id
  ), admitted AS (
    SELECT target.membership_id, ticket.*,
           p_aggregate_kind::text || '.' || p_operation AS permission_key
    FROM target CROSS JOIN ticket
    WHERE p_operation IN ('read','update')
  )
  SELECT EXISTS (
    SELECT 1
    FROM admitted
    WHERE app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'tenant'
          )
       OR app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'own'
          ) AND p_user_id IN (
            admitted.owner_user_id,admitted.assignee_user_id,
            admitted.claimed_by_user_id
          )
       OR app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'assigned'
          ) AND p_user_id IN (
            admitted.assignee_user_id,admitted.claimed_by_user_id
          )
       OR admitted.assigned_team_id IS NOT NULL
          AND admitted.assigned_team_epoch_id IS NOT NULL
          AND app.tenant_human_has_exact_permission_v3(
            p_tenant_id,p_user_id,admitted.permission_key,'operator_team'
          )
          AND EXISTS (
            SELECT 1
            FROM public.operator_team_assignment_epochs AS epoch
            JOIN public.operator_team_roster_entries AS roster
              ON roster.tenant_id=epoch.tenant_id
             AND roster.assignment_epoch_id=epoch.id
            JOIN public.tenant_authorization_sources AS source
              ON source.tenant_id=roster.tenant_id
             AND source.id=roster.source_id
            WHERE epoch.tenant_id=p_tenant_id
              AND epoch.id=admitted.assigned_team_epoch_id
              AND epoch.operator_team_id=admitted.assigned_team_id
              AND epoch.ended_at IS NULL
              AND roster.membership_id=admitted.membership_id
              AND roster.granted_at<=transaction_timestamp()
              AND roster.revoked_at IS NULL
              AND (roster.expires_at IS NULL
                OR roster.expires_at>transaction_timestamp())
              AND source.retired_at IS NULL
          )
  );
$function$;

CREATE FUNCTION app.private_ticket_comment_operator_scope_allows_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_visibility public.ticket_comment_visibility,
  p_operation text
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_user uuid := app.context_user_id();
  permission_prefix text := p_aggregate_kind::text || '.comment.';
  ticket record;
  permission_ok boolean;
BEGIN
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL OR p_visibility IS NULL
     OR p_operation NOT IN ('read','create','edit','mention') THEN
    RETURN false;
  END IF;
  IF p_aggregate_kind='alert' THEN
    SELECT alert.assigned_team_id,alert.created_by AS owner_user_id,
           alert.assignee_user_id,alert.claimed_by_user_id
    INTO ticket
    FROM public.alerts AS alert
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL;
  ELSE
    SELECT case_row.assigned_team_id,
           case_row.created_by_user_id AS owner_user_id,
           case_row.assignee_user_id,case_row.claimed_by_user_id
    INTO ticket
    FROM public.cases AS case_row
    WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id;
  END IF;
  IF NOT FOUND OR NOT app.private_ticket_watcher_user_scope_allows_v2(
    context_tenant,p_aggregate_kind,p_ticket_id,actor_user,'read'
  ) THEN
    RETURN false;
  END IF;
  permission_ok := app.private_current_ticket_scope_allows_v1(
    permission_prefix || CASE WHEN p_operation='read'
      THEN 'read' ELSE 'public' END,
    ticket.assigned_team_id,ticket.owner_user_id,
    ticket.assignee_user_id,ticket.claimed_by_user_id
  );
  IF NOT permission_ok THEN
    RETURN false;
  END IF;
  IF p_visibility='private' THEN
    RETURN app.private_current_ticket_scope_allows_v1(
      permission_prefix || 'private',ticket.assigned_team_id,
      ticket.owner_user_id,ticket.assignee_user_id,
      ticket.claimed_by_user_id
    );
  END IF;
  RETURN true;
END;
$function$;

CREATE FUNCTION app.private_ticket_comment_portal_scope_allows_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_contact_id uuid DEFAULT NULL
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH actor AS (
    SELECT membership.id AS membership_id,membership.user_id
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    WHERE membership.tenant_id=app.context_tenant_id()
      AND membership.id=app.current_tenant_membership_id()
      AND membership.user_id=app.context_user_id()
      AND membership.status='active'
      AND membership.role IN (
        'customer_manager','customer_user','read_only'
      )
      AND identity.active
  ), ticket AS (
    SELECT alert.workflow_id,alert.workflow_version,alert.state_key,
           alert.customer_visible
    FROM public.alerts AS alert
    WHERE p_aggregate_kind='alert'
      AND alert.tenant_id=app.context_tenant_id()
      AND alert.id=p_ticket_id AND alert.deleted_at IS NULL
    UNION ALL
    SELECT case_row.workflow_id,case_row.workflow_version,
           case_row.state_key,case_row.customer_visible
    FROM public.cases AS case_row
    WHERE p_aggregate_kind='case'
      AND case_row.tenant_id=app.context_tenant_id()
      AND case_row.id=p_ticket_id
  )
  SELECT EXISTS (
    SELECT 1
    FROM actor CROSS JOIN ticket
    JOIN public.customer_contacts AS contact
      ON contact.tenant_id=app.context_tenant_id()
     AND contact.linked_membership_id=actor.membership_id
     AND contact.linked_user_id=actor.user_id
     AND contact.active AND contact.archived_at IS NULL
     AND (p_contact_id IS NULL OR contact.id=p_contact_id)
    JOIN public.ticket_customer_contacts AS link
      ON link.tenant_id=contact.tenant_id
     AND link.contact_id=contact.id AND link.archived_at IS NULL
     AND (p_aggregate_kind='alert' AND link.alert_id=p_ticket_id
       OR p_aggregate_kind='case' AND link.case_id=p_ticket_id)
    JOIN public.ticket_workflow_versions AS workflow_version
      ON workflow_version.tenant_id=app.context_tenant_id()
     AND workflow_version.workflow_id=ticket.workflow_id
     AND workflow_version.aggregate_kind=p_aggregate_kind
     AND workflow_version.version=ticket.workflow_version
    CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states)
      AS state(value)
    WHERE state.value->>'key'=ticket.state_key
      AND ticket.customer_visible
      AND state.value->>'visibility'='customer'
      AND app.current_tenant_human_has_exact_permission_v3(
        'portal.comment.public','own'
      )
      AND app.current_tenant_human_has_exact_permission_v3(
        CASE p_aggregate_kind WHEN 'alert' THEN 'portal.alert.read'
          ELSE 'portal.case.read' END,'own'
      )
  );
$function$;

CREATE FUNCTION app.private_ticket_comment_time_text_v1(
  p_value timestamp with time zone
)
RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
  SELECT to_char(
    p_value AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
  )
$function$;

CREATE FUNCTION app.private_ticket_comment_projection_v1(
  p_tenant_id uuid,
  p_comment_id uuid,
  p_revision integer,
  p_customer_projection boolean,
  p_can_edit boolean
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  WITH selected AS (
    SELECT comment.id,comment.visibility,revision.body_markdown,
           revision.body_html,snapshot.author_membership_id,
           snapshot.author_contact_id,snapshot.display_name,
           snapshot.audience,snapshot.origin,revision.revision,
           snapshot.created_at,revision.edited_at,snapshot.editable_until,
           revision.id AS revision_id
    FROM public.ticket_comments AS comment
    JOIN public.ticket_comment_author_snapshots AS snapshot
      ON snapshot.tenant_id=comment.tenant_id
     AND snapshot.comment_id=comment.id
    JOIN public.ticket_comment_revisions AS revision
      ON revision.tenant_id=comment.tenant_id
     AND revision.comment_id=comment.id
     AND revision.revision=p_revision
    WHERE comment.tenant_id=p_tenant_id AND comment.id=p_comment_id
      AND (NOT p_customer_projection OR comment.visibility='public')
  ), attachment_projection AS (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
             'id',relation.attachment_id,
             'original_filename',relation.original_filename,
             'visibility',relation.visibility::text
           ) ORDER BY relation.attachment_id)
           FILTER (WHERE relation.attachment_id IS NOT NULL),
           '[]'::jsonb) AS value
    FROM selected
    LEFT JOIN public.ticket_comment_revision_attachments AS relation
      ON relation.tenant_id=p_tenant_id
     AND relation.revision_id=selected.revision_id
  ), mention_projection AS (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
             'membership_id',relation.mentioned_membership_id,
             'display_name',relation.display_name
           ) ORDER BY relation.mentioned_membership_id)
           FILTER (WHERE relation.mentioned_membership_id IS NOT NULL),
           '[]'::jsonb) AS value
    FROM selected
    LEFT JOIN public.ticket_comment_revision_mentions AS relation
      ON relation.tenant_id=p_tenant_id
     AND relation.revision_id=selected.revision_id
  )
  SELECT jsonb_build_object(
    'id',selected.id,
    'visibility',selected.visibility::text,
    'body_markdown',selected.body_markdown,
    'body_html',selected.body_html,
    'author_membership_id',selected.author_membership_id,
    'author_contact_id',selected.author_contact_id,
    'author_display_name',selected.display_name,
    'author_audience',selected.audience,
    'origin',selected.origin,
    'revision',selected.revision,
    'created_at',app.private_ticket_comment_time_text_v1(selected.created_at),
    'updated_at',app.private_ticket_comment_time_text_v1(selected.edited_at),
    'editable_until',app.private_ticket_comment_time_text_v1(
      selected.editable_until
    ),
    'can_edit',coalesce(p_can_edit,false),
    'attachments',attachment_projection.value
  ) || CASE WHEN p_customer_projection THEN '{}'::jsonb ELSE
    jsonb_build_object('mentions',mention_projection.value) END
  FROM selected CROSS JOIN attachment_projection CROSS JOIN mention_projection
$function$;

ALTER FUNCTION app.private_ticket_watcher_user_scope_allows_v2(
  uuid,public.ticket_aggregate_kind,uuid,uuid,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_operator_scope_allows_v1(
  public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_portal_scope_allows_v1(
  public.ticket_aggregate_kind,uuid,uuid
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_time_text_v1(timestamp with time zone)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_projection_v1(
  uuid,uuid,integer,boolean,boolean
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_watcher_user_scope_allows_v2(
    uuid,public.ticket_aggregate_kind,uuid,uuid,text
  ),
  app.private_ticket_comment_operator_scope_allows_v1(
    public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,text
  ),
  app.private_ticket_comment_portal_scope_allows_v1(
    public.ticket_aggregate_kind,uuid,uuid
  ),
  app.private_ticket_comment_time_text_v1(timestamp with time zone),
  app.private_ticket_comment_projection_v1(
    uuid,uuid,integer,boolean,boolean
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_write_ticket_comment_v2(
  p_customer_actor boolean,
  p_action text,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_comment_id uuid,
  p_expected_revision integer,
  p_visibility public.ticket_comment_visibility,
  p_body_markdown text,
  p_body_html text,
  p_attachment_ids uuid[],
  p_mentioned_membership_ids uuid[],
  p_reason text,
  p_author_contact_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  comment_id uuid,result_revision integer,result_item jsonb,replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  operation_value text;
  operation_at timestamp with time zone := transaction_timestamp();
  edited_at_value timestamp with time zone;
  locked_ticket record;
  comment_row record;
  replay_row public.ticket_comment_idempotency_keys%ROWTYPE;
  result_comment uuid;
  result_revision_value integer;
  revision_id uuid;
  ticket_version integer;
  display_name_value text;
  mentioned_user_ids uuid[] := ARRAY[]::uuid[];
  can_edit_value boolean;
  effective_visibility public.ticket_comment_visibility := p_visibility;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  operation_value := p_aggregate_kind::text||'.comment.'||p_action;
  IF p_customer_actor IS NULL OR p_action NOT IN ('create','edit')
     OR p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR (uuid_extract_version(p_ticket_id)=7) IS NOT TRUE
     OR NOT app.private_ticket_comment_markdown_valid_v1(p_body_markdown)
     OR NOT app.private_ticket_comment_html_valid_v1(p_body_html)
     OR NOT app.private_ticket_comment_uuid_array_valid_v1(
       p_attachment_ids,20
     )
     OR NOT app.private_ticket_comment_uuid_array_valid_v1(
       p_mentioned_membership_ids,50
     )
     OR p_key_digest IS NULL OR octet_length(p_key_digest)<>32
     OR p_key_digest=decode(repeat('00',32),'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_request_digest=decode(repeat('00',32),'hex')
     OR p_request_id IS NULL
        OR (uuid_extract_version(p_request_id)=7) IS NOT TRUE
     OR p_correlation_id IS NULL
        OR (uuid_extract_version(p_correlation_id)=7) IS NOT TRUE
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_action='create' AND (
       p_comment_id IS NOT NULL OR p_expected_revision IS NOT NULL
       OR p_visibility IS NULL OR p_reason<>'original_comment'
     )
     OR p_action='edit' AND (
       p_comment_id IS NULL
       OR (uuid_extract_version(p_comment_id)=7) IS NOT TRUE
       OR p_expected_revision NOT BETWEEN 1 AND 2147483646
       OR p_visibility IS NOT NULL
       OR NOT app.private_ticket_comment_edit_reason_valid_v1(p_reason)
     )
     OR p_customer_actor AND (
       cardinality(p_mentioned_membership_ids)<>0
       OR p_action='create' AND p_visibility<>'public'
       OR p_author_contact_id IS NULL
          OR (uuid_extract_version(p_author_contact_id)=7) IS NOT TRUE
     )
     OR NOT p_customer_actor AND p_author_contact_id IS NOT NULL THEN
    RAISE EXCEPTION 'ticket comment command envelope is invalid'
      USING ERRCODE='22023';
  END IF;

  IF p_action='edit' THEN
    SELECT comment.id,comment.visibility,comment.origin,comment.revision,
           comment.author_membership_id,comment.author_user_id,
           snapshot.author_contact_id,snapshot.audience,
           snapshot.editable_until
    INTO comment_row
    FROM public.ticket_comments AS comment
    JOIN public.ticket_comment_author_snapshots AS snapshot
      ON snapshot.tenant_id=comment.tenant_id
     AND snapshot.comment_id=comment.id
    WHERE comment.tenant_id=context_tenant AND comment.id=p_comment_id
      AND (p_aggregate_kind='alert' AND comment.alert_id=p_ticket_id
        OR p_aggregate_kind='case' AND comment.case_id=p_ticket_id)
      AND (NOT p_customer_actor OR comment.visibility='public');
    IF NOT FOUND THEN
      RAISE EXCEPTION 'ticket comment not found' USING ERRCODE='P0002';
    END IF;
    IF p_customer_actor THEN
      IF comment_row.origin<>'customer_portal'
         OR comment_row.audience<>'customer'
         OR comment_row.author_contact_id<>p_author_contact_id
         OR comment_row.author_membership_id<>actor_membership
         OR comment_row.author_user_id<>actor_user
         OR NOT app.private_ticket_comment_portal_scope_allows_v1(
           p_aggregate_kind,p_ticket_id,p_author_contact_id
         ) THEN
        RAISE EXCEPTION 'ticket comment not found' USING ERRCODE='P0002';
      END IF;
    ELSIF comment_row.origin<>'api'
       OR comment_row.audience<>'operator'
       OR comment_row.author_contact_id IS NOT NULL
       OR comment_row.author_membership_id<>actor_membership
       OR comment_row.author_user_id<>actor_user
       OR NOT app.private_ticket_comment_operator_scope_allows_v1(
         p_aggregate_kind,p_ticket_id,comment_row.visibility,'edit'
       ) THEN
      RAISE EXCEPTION 'ticket comment not found' USING ERRCODE='P0002';
    END IF;
  ELSIF p_customer_actor THEN
    IF NOT app.private_ticket_comment_portal_scope_allows_v1(
      p_aggregate_kind,p_ticket_id,p_author_contact_id
    ) THEN
      RAISE EXCEPTION 'exact portal comment relation is required'
        USING ERRCODE='42501';
    END IF;
  ELSIF NOT app.private_ticket_comment_operator_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,p_visibility,'create'
  ) THEN
    RAISE EXCEPTION 'live ticket comment create scope is required'
      USING ERRCODE='42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text||':'||actor_membership::text||':'
      ||encode(p_key_digest,'hex'),0
  ));
  SELECT key_row.* INTO replay_row
  FROM public.ticket_comment_idempotency_keys AS key_row
  WHERE key_row.tenant_id=context_tenant
    AND key_row.actor_membership_id=actor_membership
    AND key_row.key_digest=p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay_row.legacy_ambiguous OR replay_row.actor_user_id<>actor_user
       OR replay_row.source_kind<>'comment'
       OR replay_row.operation<>operation_value
       OR replay_row.request_digest IS DISTINCT FROM p_request_digest
       OR p_action='edit' AND replay_row.result_comment_id<>p_comment_id
       OR replay_row.result_comment_id IS NULL
       OR replay_row.result_revision IS NULL THEN
      RAISE EXCEPTION 'global ticket idempotency key conflicts'
        USING ERRCODE='23505',
          CONSTRAINT='ticket_comment_idempotency_keys_replay_key';
    END IF;
    SELECT comment.visibility,comment.origin,comment.revision,
           comment.author_membership_id,comment.author_user_id,
           snapshot.author_contact_id,snapshot.audience
    INTO STRICT comment_row
    FROM public.ticket_comments AS comment
    JOIN public.ticket_comment_author_snapshots AS snapshot
      ON snapshot.tenant_id=comment.tenant_id
     AND snapshot.comment_id=comment.id
    WHERE comment.tenant_id=context_tenant
      AND comment.id=replay_row.result_comment_id
      AND (p_aggregate_kind='alert' AND comment.alert_id=p_ticket_id
        OR p_aggregate_kind='case' AND comment.case_id=p_ticket_id);
    IF comment_row.author_membership_id<>actor_membership
       OR comment_row.author_user_id<>actor_user
       OR p_customer_actor AND (
         comment_row.visibility<>'public'
         OR comment_row.origin<>'customer_portal'
         OR comment_row.audience<>'customer'
         OR comment_row.author_contact_id<>p_author_contact_id
         OR NOT app.private_ticket_comment_portal_scope_allows_v1(
           p_aggregate_kind,p_ticket_id,p_author_contact_id
         )
       ) OR NOT p_customer_actor AND (
         comment_row.origin<>'api' OR comment_row.audience<>'operator'
         OR comment_row.author_contact_id IS NOT NULL
         OR NOT app.private_ticket_comment_operator_scope_allows_v1(
           p_aggregate_kind,p_ticket_id,comment_row.visibility,
           CASE p_action WHEN 'create' THEN 'create' ELSE 'edit' END
         )
       ) THEN
      RAISE EXCEPTION 'ticket comment replay authority is no longer live'
        USING ERRCODE='42501';
    END IF;
    can_edit_value := replay_row.result_revision=comment_row.revision
      AND app.private_ticket_comment_can_edit_v1(
        context_tenant,replay_row.result_comment_id,p_customer_actor
      );
    RETURN QUERY SELECT replay_row.result_comment_id,
      replay_row.result_revision,
      app.private_ticket_comment_projection_v1(
        context_tenant,replay_row.result_comment_id,
        replay_row.result_revision,p_customer_actor,can_edit_value
      ),true;
    RETURN;
  END IF;

  IF p_aggregate_kind='alert' THEN
    SELECT alert.version,alert.first_response_at
    INTO locked_ticket
    FROM public.alerts AS alert
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL
    FOR UPDATE;
  ELSE
    SELECT case_row.version,case_row.first_response_at
    INTO locked_ticket
    FROM public.cases AS case_row
    WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket not found' USING ERRCODE='P0002';
  END IF;
  ticket_version := locked_ticket.version;

  IF p_action='edit' THEN
    SELECT comment.id,comment.visibility,comment.origin,comment.revision,
           comment.author_membership_id,comment.author_user_id,
           snapshot.author_contact_id,snapshot.audience,
           snapshot.editable_until,latest.edited_at
    INTO STRICT comment_row
    FROM public.ticket_comments AS comment
    JOIN public.ticket_comment_author_snapshots AS snapshot
      ON snapshot.tenant_id=comment.tenant_id
     AND snapshot.comment_id=comment.id
    JOIN public.ticket_comment_revisions AS latest
      ON latest.tenant_id=comment.tenant_id
     AND latest.comment_id=comment.id
     AND latest.revision=comment.revision
    WHERE comment.tenant_id=context_tenant AND comment.id=p_comment_id
      AND (p_aggregate_kind='alert' AND comment.alert_id=p_ticket_id
        OR p_aggregate_kind='case' AND comment.case_id=p_ticket_id)
    FOR UPDATE OF comment;
    IF comment_row.revision<>p_expected_revision THEN
      RAISE EXCEPTION 'ticket comment revision conflict'
        USING ERRCODE='40001';
    END IF;
    IF p_customer_actor THEN
      IF comment_row.visibility<>'public'
         OR comment_row.origin<>'customer_portal'
         OR comment_row.audience<>'customer'
         OR comment_row.author_contact_id<>p_author_contact_id
         OR comment_row.author_membership_id<>actor_membership
         OR comment_row.author_user_id<>actor_user
         OR NOT app.private_ticket_comment_portal_scope_allows_v1(
           p_aggregate_kind,p_ticket_id,p_author_contact_id
         ) THEN
        RAISE EXCEPTION 'exact portal comment author relation is required'
          USING ERRCODE='42501';
      END IF;
    ELSIF comment_row.origin<>'api'
       OR comment_row.audience<>'operator'
       OR comment_row.author_contact_id IS NOT NULL
       OR comment_row.author_membership_id<>actor_membership
       OR comment_row.author_user_id<>actor_user
       OR NOT app.private_ticket_comment_operator_scope_allows_v1(
         p_aggregate_kind,p_ticket_id,comment_row.visibility,'edit'
       ) THEN
      RAISE EXCEPTION 'exact operator comment author scope is required'
        USING ERRCODE='42501';
    END IF;
    IF operation_at>=comment_row.editable_until THEN
      RAISE EXCEPTION 'ticket comment edit window is closed'
        USING ERRCODE='42501';
    END IF;
    effective_visibility := comment_row.visibility;
    edited_at_value := greatest(
      operation_at,comment_row.edited_at+interval '1 microsecond'
    );
    IF edited_at_value>=comment_row.editable_until THEN
      RAISE EXCEPTION 'ticket comment edit window is closed'
        USING ERRCODE='42501';
    END IF;
  ELSE
    IF p_customer_actor THEN
      IF NOT app.private_ticket_comment_portal_scope_allows_v1(
        p_aggregate_kind,p_ticket_id,p_author_contact_id
      ) THEN
        RAISE EXCEPTION 'exact portal comment relation is required'
          USING ERRCODE='42501';
      END IF;
    ELSIF NOT app.private_ticket_comment_operator_scope_allows_v1(
      p_aggregate_kind,p_ticket_id,p_visibility,'create'
    ) THEN
      RAISE EXCEPTION 'live ticket comment create scope is required'
        USING ERRCODE='42501';
    END IF;
    edited_at_value := operation_at;
  END IF;

  PERFORM app.private_ticket_comment_attachment_preview_v1(
    p_aggregate_kind,p_ticket_id,effective_visibility,p_attachment_ids
  );
  IF NOT p_customer_actor THEN
    PERFORM app.private_ticket_comment_mention_preview_v1(
      p_aggregate_kind,p_ticket_id,p_mentioned_membership_ids
    );
  END IF;
  SELECT coalesce(array_agg(membership.user_id ORDER BY membership.user_id),
                  ARRAY[]::uuid[])
  INTO mentioned_user_ids
  FROM public.tenant_memberships AS membership
  WHERE membership.tenant_id=context_tenant
    AND membership.id=ANY(p_mentioned_membership_ids);
  SELECT identity.display_name INTO STRICT display_name_value
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=context_tenant
    AND membership.id=actor_membership AND membership.user_id=actor_user
    AND membership.status='active' AND identity.active
    AND app.private_ticket_comment_display_name_valid_v1(
      identity.display_name
    );
  PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);

  IF p_action='create' THEN
    result_comment := uuidv7();
    result_revision_value := 1;
    revision_id := uuidv7();
    INSERT INTO public.ticket_comments(
      id,tenant_id,alert_id,case_id,visibility,body_markdown,body_html,
      author_membership_id,author_user_id,origin,revision,
      mentioned_user_ids,created_at,updated_at
    ) VALUES (
      result_comment,context_tenant,
      CASE WHEN p_aggregate_kind='alert' THEN p_ticket_id END,
      CASE WHEN p_aggregate_kind='case' THEN p_ticket_id END,
      p_visibility,p_body_markdown,p_body_html,actor_membership,actor_user,
      CASE WHEN p_customer_actor THEN 'customer_portal' ELSE 'api' END,
      1,mentioned_user_ids,operation_at,operation_at
    );
    INSERT INTO public.ticket_comment_author_snapshots(
      tenant_id,comment_id,audience,author_membership_id,author_user_id,
      author_contact_id,display_name,origin,created_at,editable_until
    ) VALUES (
      context_tenant,result_comment,
      CASE WHEN p_customer_actor THEN 'customer' ELSE 'operator' END,
      actor_membership,actor_user,p_author_contact_id,display_name_value,
      CASE WHEN p_customer_actor THEN 'customer_portal' ELSE 'api' END,
      operation_at,operation_at+interval '15 minutes'
    );
    INSERT INTO public.ticket_comment_revisions(
      id,tenant_id,comment_id,revision,body_markdown,body_html,reason,
      edited_by_membership_id,edited_by_user_id,edited_at
    ) VALUES (
      revision_id,context_tenant,result_comment,1,p_body_markdown,p_body_html,
      'original_comment',actor_membership,actor_user,operation_at
    );
    IF NOT p_customer_actor AND p_visibility='public'
       AND locked_ticket.first_response_at IS NULL THEN
      IF p_aggregate_kind='alert' THEN
        UPDATE public.alerts AS alert
        SET first_response_at=operation_at,version=alert.version+1,
            updated_at=operation_at
        WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
          AND alert.version=locked_ticket.version
          AND alert.first_response_at IS NULL;
      ELSE
        UPDATE public.cases AS case_row
        SET first_response_at=operation_at,version=case_row.version+1,
            updated_at=operation_at
        WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id
          AND case_row.version=locked_ticket.version
          AND case_row.first_response_at IS NULL;
      END IF;
      IF FOUND THEN ticket_version := ticket_version+1; END IF;
    END IF;
  ELSE
    result_comment := p_comment_id;
    result_revision_value := p_expected_revision+1;
    revision_id := uuidv7();
    INSERT INTO public.ticket_comment_revisions(
      id,tenant_id,comment_id,revision,body_markdown,body_html,reason,
      edited_by_membership_id,edited_by_user_id,edited_at
    ) VALUES (
      revision_id,context_tenant,result_comment,result_revision_value,
      p_body_markdown,p_body_html,p_reason,actor_membership,actor_user,
      edited_at_value
    );
    UPDATE public.ticket_comments AS comment
    SET body_markdown=p_body_markdown,body_html=p_body_html,
        revision=result_revision_value,mentioned_user_ids=mentioned_user_ids,
        updated_at=edited_at_value
    WHERE comment.tenant_id=context_tenant AND comment.id=result_comment
      AND comment.revision=p_expected_revision;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'ticket comment revision conflict'
        USING ERRCODE='40001';
    END IF;
  END IF;

  INSERT INTO public.ticket_comment_revision_attachments(
    tenant_id,revision_id,attachment_id,original_filename,visibility
  )
  SELECT context_tenant,revision_id,attachment.id,
         attachment.original_filename,
         attachment.visibility::text::public.ticket_comment_visibility
  FROM public.dfir_attachments AS attachment
  WHERE attachment.tenant_id=context_tenant
    AND attachment.id=ANY(p_attachment_ids)
  ORDER BY attachment.id;
  INSERT INTO public.ticket_comment_revision_mentions(
    tenant_id,revision_id,mentioned_membership_id,mentioned_user_id,
    display_name
  )
  SELECT context_tenant,revision_id,membership.id,membership.user_id,
         identity.display_name
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=context_tenant
    AND membership.id=ANY(p_mentioned_membership_ids)
  ORDER BY membership.id;

  INSERT INTO public.ticket_comment_idempotency_keys(
    tenant_id,actor_membership_id,actor_user_id,key_digest,source_kind,
    operation,request_digest,result_comment_id,result_revision,
    legacy_ambiguous,created_at
  ) VALUES (
    context_tenant,actor_membership,actor_user,p_key_digest,'comment',
    operation_value,p_request_digest,result_comment,result_revision_value,
    false,operation_at
  );
  PERFORM app.private_append_ticket_comment_side_effects_v1(
    p_aggregate_kind,p_ticket_id,ticket_version,result_comment,
    result_revision_value,effective_visibility,
    CASE WHEN p_customer_actor THEN 'customer_portal' ELSE 'api' END,
    p_author_contact_id,
    CASE p_action WHEN 'create' THEN 'commented' ELSE 'comment_edited' END,
    edited_at_value,p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method
  );
  RETURN QUERY SELECT result_comment,result_revision_value,
    app.private_ticket_comment_projection_v1(
      context_tenant,result_comment,result_revision_value,p_customer_actor,
      app.private_ticket_comment_can_edit_v1(
        context_tenant,result_comment,p_customer_actor
      )
    ),false;
END;
$function$;

CREATE FUNCTION app.create_tenant_ticket_comment_v2(
  p_aggregate_kind public.ticket_aggregate_kind,p_ticket_id uuid,
  p_visibility public.ticket_comment_visibility,p_body_markdown text,
  p_body_html text,p_attachment_ids uuid[],
  p_mentioned_membership_ids uuid[],p_key_digest bytea,
  p_request_digest bytea,p_request_id uuid,p_correlation_id uuid,
  p_ip_address inet,p_user_agent text,p_authentication_method text
)
RETURNS TABLE(
  comment_id uuid,result_revision integer,result_item jsonb,replayed boolean
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_write_ticket_comment_v2(
    false,'create',p_aggregate_kind,p_ticket_id,NULL,NULL,p_visibility,
    p_body_markdown,p_body_html,p_attachment_ids,
    p_mentioned_membership_ids,'original_comment',NULL,p_key_digest,
    p_request_digest,p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method
  )
$function$;

CREATE FUNCTION app.create_customer_portal_ticket_comment_v2(
  p_aggregate_kind public.ticket_aggregate_kind,p_ticket_id uuid,
  p_author_contact_id uuid,p_body_markdown text,p_body_html text,
  p_attachment_ids uuid[],p_key_digest bytea,p_request_digest bytea,
  p_request_id uuid,p_correlation_id uuid,p_ip_address inet,
  p_user_agent text,p_authentication_method text
)
RETURNS TABLE(
  comment_id uuid,result_revision integer,result_item jsonb,replayed boolean
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_write_ticket_comment_v2(
    true,'create',p_aggregate_kind,p_ticket_id,NULL,NULL,'public',
    p_body_markdown,p_body_html,p_attachment_ids,ARRAY[]::uuid[],
    'original_comment',p_author_contact_id,p_key_digest,p_request_digest,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method
  )
$function$;

CREATE FUNCTION app.edit_tenant_ticket_comment_v2(
  p_aggregate_kind public.ticket_aggregate_kind,p_ticket_id uuid,
  p_comment_id uuid,p_expected_revision integer,p_body_markdown text,
  p_body_html text,p_attachment_ids uuid[],
  p_mentioned_membership_ids uuid[],p_reason text,p_key_digest bytea,
  p_request_digest bytea,p_request_id uuid,p_correlation_id uuid,
  p_ip_address inet,p_user_agent text,p_authentication_method text
)
RETURNS TABLE(
  comment_id uuid,result_revision integer,result_item jsonb,replayed boolean
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_write_ticket_comment_v2(
    false,'edit',p_aggregate_kind,p_ticket_id,p_comment_id,
    p_expected_revision,NULL,p_body_markdown,p_body_html,p_attachment_ids,
    p_mentioned_membership_ids,p_reason,NULL,p_key_digest,p_request_digest,
    p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method
  )
$function$;

CREATE FUNCTION app.edit_customer_portal_ticket_comment_v2(
  p_aggregate_kind public.ticket_aggregate_kind,p_ticket_id uuid,
  p_comment_id uuid,p_expected_revision integer,p_author_contact_id uuid,
  p_body_markdown text,p_body_html text,p_attachment_ids uuid[],
  p_key_digest bytea,p_request_digest bytea,p_request_id uuid,
  p_correlation_id uuid,p_ip_address inet,p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  comment_id uuid,result_revision integer,result_item jsonb,replayed boolean
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_write_ticket_comment_v2(
    true,'edit',p_aggregate_kind,p_ticket_id,p_comment_id,
    p_expected_revision,NULL,p_body_markdown,p_body_html,p_attachment_ids,
    ARRAY[]::uuid[],'author_correction',p_author_contact_id,p_key_digest,
    p_request_digest,p_request_id,p_correlation_id,p_ip_address,p_user_agent,
    p_authentication_method
  )
$function$;

ALTER FUNCTION app.private_write_ticket_comment_v2(
  boolean,text,public.ticket_aggregate_kind,uuid,uuid,integer,
  public.ticket_comment_visibility,text,text,uuid[],uuid[],text,uuid,bytea,
  bytea,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_tenant_ticket_comment_v2(
  public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,text,text,
  uuid[],uuid[],bytea,bytea,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.create_customer_portal_ticket_comment_v2(
  public.ticket_aggregate_kind,uuid,uuid,text,text,uuid[],bytea,bytea,uuid,
  uuid,inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.edit_tenant_ticket_comment_v2(
  public.ticket_aggregate_kind,uuid,uuid,integer,text,text,uuid[],uuid[],text,
  bytea,bytea,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.edit_customer_portal_ticket_comment_v2(
  public.ticket_aggregate_kind,uuid,uuid,integer,uuid,text,text,uuid[],bytea,
  bytea,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_write_ticket_comment_v2(
  boolean,text,public.ticket_aggregate_kind,uuid,uuid,integer,
  public.ticket_comment_visibility,text,text,uuid[],uuid[],text,uuid,bytea,
  bytea,uuid,uuid,inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION
  app.create_tenant_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,text,
    text,uuid[],uuid[],bytea,bytea,uuid,uuid,inet,text,text
  ),
  app.create_customer_portal_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,uuid,text,text,uuid[],bytea,bytea,uuid,
    uuid,inet,text,text
  ),
  app.edit_tenant_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer,text,text,uuid[],uuid[],
    text,bytea,bytea,uuid,uuid,inet,text,text
  ),
  app.edit_customer_portal_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer,uuid,text,text,uuid[],bytea,
    bytea,uuid,uuid,inet,text,text
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION
  app.create_tenant_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,text,
    text,uuid[],uuid[],bytea,bytea,uuid,uuid,inet,text,text
  ),
  app.create_customer_portal_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,uuid,text,text,uuid[],bytea,bytea,uuid,
    uuid,inet,text,text
  ),
  app.edit_tenant_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer,text,text,uuid[],uuid[],
    text,bytea,bytea,uuid,uuid,inet,text,text
  ),
  app.edit_customer_portal_ticket_comment_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer,uuid,text,text,uuid[],bytea,
    bytea,uuid,uuid,inet,text,text
  )
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_can_edit_v1(
  p_tenant_id uuid,
  p_comment_id uuid,
  p_customer_actor boolean
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  comment_row record;
  kind_value public.ticket_aggregate_kind;
  ticket_id uuid;
BEGIN
  SELECT comment.visibility,comment.origin,comment.author_membership_id,
         comment.author_user_id,comment.revision,snapshot.author_contact_id,
         snapshot.audience,snapshot.editable_until,comment.alert_id,
         comment.case_id
  INTO comment_row
  FROM public.ticket_comments AS comment
  JOIN public.ticket_comment_author_snapshots AS snapshot
    ON snapshot.tenant_id=comment.tenant_id
   AND snapshot.comment_id=comment.id
  WHERE comment.tenant_id=p_tenant_id AND comment.id=p_comment_id;
  IF NOT FOUND
     OR comment_row.author_membership_id<>
          app.current_tenant_membership_id()
     OR comment_row.author_user_id<>app.context_user_id()
     OR transaction_timestamp()>=comment_row.editable_until THEN
    RETURN false;
  END IF;
  kind_value := CASE WHEN comment_row.alert_id IS NOT NULL
    THEN 'alert'::public.ticket_aggregate_kind
    ELSE 'case'::public.ticket_aggregate_kind END;
  ticket_id := coalesce(comment_row.alert_id,comment_row.case_id);
  IF p_customer_actor THEN
    RETURN comment_row.origin='customer_portal'
      AND comment_row.audience='customer'
      AND comment_row.visibility='public'
      AND comment_row.author_contact_id IS NOT NULL
      AND app.private_ticket_comment_portal_scope_allows_v1(
        kind_value,ticket_id,comment_row.author_contact_id
      );
  END IF;
  RETURN comment_row.origin='api'
    AND comment_row.audience='operator'
    AND comment_row.author_contact_id IS NULL
    AND app.private_ticket_comment_operator_scope_allows_v1(
      kind_value,ticket_id,comment_row.visibility,'edit'
    );
END;
$function$;

CREATE FUNCTION app.list_tenant_ticket_comments_v2(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_after uuid,
  p_limit integer
)
RETURNS TABLE(result_items jsonb,next_cursor uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR (uuid_extract_version(p_ticket_id)=7) IS NOT TRUE
     OR p_after IS NOT NULL AND (uuid_extract_version(p_after)=7) IS NOT TRUE
     OR p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'ticket comment page is invalid' USING ERRCODE='22023';
  END IF;
  IF NOT app.private_ticket_comment_operator_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,'public','read'
  ) THEN
    RAISE EXCEPTION 'live ticket comment read scope is required'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  WITH eligible AS (
    SELECT comment.id,comment.revision
    FROM public.ticket_comments AS comment
    WHERE comment.tenant_id=context_tenant
      AND (p_aggregate_kind='alert' AND comment.alert_id=p_ticket_id
        OR p_aggregate_kind='case' AND comment.case_id=p_ticket_id)
      AND (p_after IS NULL OR comment.id>p_after)
      AND (comment.visibility='public'
        OR app.private_ticket_comment_operator_scope_allows_v1(
          p_aggregate_kind,p_ticket_id,'private','read'
        ))
    ORDER BY comment.id
    LIMIT p_limit+1
  ), page AS (
    SELECT eligible.* FROM eligible ORDER BY eligible.id LIMIT p_limit
  )
  SELECT coalesce(jsonb_agg(
           app.private_ticket_comment_projection_v1(
             context_tenant,page.id,page.revision,false,
             app.private_ticket_comment_can_edit_v1(
               context_tenant,page.id,false
             )
           ) ORDER BY page.id
         ),'[]'::jsonb),
         CASE WHEN (SELECT count(*) FROM eligible)>p_limit
           THEN (SELECT max(id) FROM page) END
  FROM page;
END;
$function$;

CREATE FUNCTION app.list_customer_portal_ticket_comments_v2(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_after uuid,
  p_limit integer
)
RETURNS TABLE(result_items jsonb,next_cursor uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR (uuid_extract_version(p_ticket_id)=7) IS NOT TRUE
     OR p_after IS NOT NULL AND (uuid_extract_version(p_after)=7) IS NOT TRUE
     OR p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'portal comment page is invalid' USING ERRCODE='22023';
  END IF;
  IF NOT app.private_ticket_comment_portal_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,NULL
  ) THEN
    RAISE EXCEPTION 'exact portal comment read relation is required'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  WITH eligible AS (
    SELECT comment.id,comment.revision
    FROM public.ticket_comments AS comment
    WHERE comment.tenant_id=context_tenant
      AND (p_aggregate_kind='alert' AND comment.alert_id=p_ticket_id
        OR p_aggregate_kind='case' AND comment.case_id=p_ticket_id)
      AND comment.visibility='public'
      AND (p_after IS NULL OR comment.id>p_after)
    ORDER BY comment.id
    LIMIT p_limit+1
  ), page AS (
    SELECT eligible.* FROM eligible ORDER BY eligible.id LIMIT p_limit
  )
  SELECT coalesce(jsonb_agg(
           app.private_ticket_comment_projection_v1(
             context_tenant,page.id,page.revision,true,
             app.private_ticket_comment_can_edit_v1(
               context_tenant,page.id,true
             )
           ) ORDER BY page.id
         ),'[]'::jsonb),
         CASE WHEN (SELECT count(*) FROM eligible)>p_limit
           THEN (SELECT max(id) FROM page) END
  FROM page;
END;
$function$;

CREATE FUNCTION app.private_ticket_comment_edit_state_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_comment_id uuid,
  p_key_digest bytea,
  p_request_digest bytea,
  p_customer_actor boolean
)
RETURNS TABLE(
  result_visibility public.ticket_comment_visibility,
  result_author_membership_id uuid,
  result_author_contact_id uuid,
  result_revision integer,
  result_created_at timestamp with time zone,
  result_editable_until timestamp with time zone,
  result_origin text,
  result_author_audience text,
  result_replayed boolean,
  result_replay_revision integer
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  comment_row record;
  replay public.ticket_comment_idempotency_keys%ROWTYPE;
  operation_value text := p_aggregate_kind::text || '.comment.edit';
BEGIN
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL OR p_comment_id IS NULL
     OR (uuid_extract_version(p_ticket_id)=7) IS NOT TRUE
     OR (uuid_extract_version(p_comment_id)=7) IS NOT TRUE
     OR p_key_digest IS NULL OR octet_length(p_key_digest)<>32
     OR p_key_digest=decode(repeat('00',32),'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_request_digest=decode(repeat('00',32),'hex') THEN
    RAISE EXCEPTION 'ticket comment edit preflight is invalid'
      USING ERRCODE='22023';
  END IF;
  SELECT comment.visibility,comment.author_membership_id,
         snapshot.author_contact_id,comment.revision,comment.created_at,
         snapshot.editable_until,comment.origin,snapshot.audience,
         comment.author_user_id
  INTO comment_row
  FROM public.ticket_comments AS comment
  JOIN public.ticket_comment_author_snapshots AS snapshot
    ON snapshot.tenant_id=comment.tenant_id
   AND snapshot.comment_id=comment.id
  WHERE comment.tenant_id=context_tenant AND comment.id=p_comment_id
    AND (p_aggregate_kind='alert' AND comment.alert_id=p_ticket_id
      OR p_aggregate_kind='case' AND comment.case_id=p_ticket_id);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket comment not found' USING ERRCODE='P0002';
  END IF;
  IF p_customer_actor THEN
    IF comment_row.visibility<>'public'
       OR comment_row.origin<>'customer_portal'
       OR comment_row.audience<>'customer'
       OR comment_row.author_contact_id IS NULL
       OR comment_row.author_membership_id<>actor_membership
       OR comment_row.author_user_id<>actor_user
       OR NOT app.private_ticket_comment_portal_scope_allows_v1(
         p_aggregate_kind,p_ticket_id,comment_row.author_contact_id
       ) THEN
      RAISE EXCEPTION 'ticket comment not found' USING ERRCODE='P0002';
    END IF;
  ELSE
    IF comment_row.origin<>'api' OR comment_row.audience<>'operator'
       OR comment_row.author_contact_id IS NOT NULL
       OR comment_row.author_membership_id<>actor_membership
       OR comment_row.author_user_id<>actor_user
       OR NOT app.private_ticket_comment_operator_scope_allows_v1(
         p_aggregate_kind,p_ticket_id,comment_row.visibility,'edit'
       ) THEN
      RAISE EXCEPTION 'ticket comment not found' USING ERRCODE='P0002';
    END IF;
  END IF;

  SELECT key_row.* INTO replay
  FROM public.ticket_comment_idempotency_keys AS key_row
  WHERE key_row.tenant_id=context_tenant
    AND key_row.actor_membership_id=actor_membership
    AND key_row.key_digest=p_key_digest;
  IF FOUND THEN
    IF replay.legacy_ambiguous OR replay.actor_user_id<>actor_user
       OR replay.source_kind<>'comment'
       OR replay.operation<>operation_value
       OR replay.request_digest IS DISTINCT FROM p_request_digest
       OR replay.result_comment_id<>p_comment_id THEN
      RAISE EXCEPTION 'global ticket idempotency key conflicts'
        USING ERRCODE='23505',
          CONSTRAINT='ticket_comment_idempotency_keys_replay_key';
    END IF;
  END IF;
  RETURN QUERY SELECT comment_row.visibility,
    comment_row.author_membership_id,comment_row.author_contact_id,
    comment_row.revision,comment_row.created_at,comment_row.editable_until,
    comment_row.origin,comment_row.audience,FOUND,
    CASE WHEN FOUND THEN replay.result_revision END;
END;
$function$;

CREATE FUNCTION app.get_tenant_ticket_comment_edit_state_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,p_comment_id uuid,p_key_digest bytea,p_request_digest bytea
)
RETURNS TABLE(
  result_visibility public.ticket_comment_visibility,
  result_author_membership_id uuid,result_author_contact_id uuid,
  result_revision integer,result_created_at timestamp with time zone,
  result_editable_until timestamp with time zone,result_origin text,
  result_author_audience text,result_replayed boolean,
  result_replay_revision integer
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_ticket_comment_edit_state_v1(
    p_aggregate_kind,p_ticket_id,p_comment_id,p_key_digest,p_request_digest,
    false
  )
$function$;

CREATE FUNCTION app.get_customer_portal_ticket_comment_edit_state_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,p_comment_id uuid,p_key_digest bytea,p_request_digest bytea
)
RETURNS TABLE(
  result_visibility public.ticket_comment_visibility,
  result_author_membership_id uuid,result_author_contact_id uuid,
  result_revision integer,result_created_at timestamp with time zone,
  result_editable_until timestamp with time zone,result_origin text,
  result_author_audience text,result_replayed boolean,
  result_replay_revision integer
)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_ticket_comment_edit_state_v1(
    p_aggregate_kind,p_ticket_id,p_comment_id,p_key_digest,p_request_digest,
    true
  )
$function$;

ALTER FUNCTION app.private_ticket_comment_can_edit_v1(uuid,uuid,boolean)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_tenant_ticket_comments_v2(
  public.ticket_aggregate_kind,uuid,uuid,integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_customer_portal_ticket_comments_v2(
  public.ticket_aggregate_kind,uuid,uuid,integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_edit_state_v1(
  public.ticket_aggregate_kind,uuid,uuid,bytea,bytea,boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_tenant_ticket_comment_edit_state_v1(
  public.ticket_aggregate_kind,uuid,uuid,bytea,bytea
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_customer_portal_ticket_comment_edit_state_v1(
  public.ticket_aggregate_kind,uuid,uuid,bytea,bytea
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_comment_can_edit_v1(uuid,uuid,boolean),
  app.private_ticket_comment_edit_state_v1(
    public.ticket_aggregate_kind,uuid,uuid,bytea,bytea,boolean
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION
  app.list_tenant_ticket_comments_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
  ),
  app.list_customer_portal_ticket_comments_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
  ),
  app.get_tenant_ticket_comment_edit_state_v1(
    public.ticket_aggregate_kind,uuid,uuid,bytea,bytea
  ),
  app.get_customer_portal_ticket_comment_edit_state_v1(
    public.ticket_aggregate_kind,uuid,uuid,bytea,bytea
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION
  app.list_tenant_ticket_comments_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
  ),
  app.list_customer_portal_ticket_comments_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
  ),
  app.get_tenant_ticket_comment_edit_state_v1(
    public.ticket_aggregate_kind,uuid,uuid,bytea,bytea
  ),
  app.get_customer_portal_ticket_comment_edit_state_v1(
    public.ticket_aggregate_kind,uuid,uuid,bytea,bytea
  )
TO periapsis_api;
--> statement-breakpoint

-- Activity author audience follows the authenticated route, never a mutable
-- membership role.  The customer contact pinned by the writer is rechecked
-- against the same ticket before the frozen activity snapshot is appended.
CREATE OR REPLACE FUNCTION app.capture_ticket_activity_author_snapshot_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  contact_id uuid;
  audience_value text := 'operator';
BEGIN
  IF NEW.actor_principal_kind='human' AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    WHERE membership.tenant_id=NEW.tenant_id
      AND membership.id=NEW.actor_membership_id
      AND membership.user_id=NEW.actor_user_id
      AND membership.status='active' AND identity.active
  ) THEN
    RAISE EXCEPTION 'activity author is not a live tenant identity'
      USING ERRCODE='42501';
  END IF;
  IF NEW.origin='customer_portal' THEN
    IF NEW.actor_principal_kind<>'human' THEN
      RAISE EXCEPTION 'customer activity must have a human actor'
        USING ERRCODE='42501';
    END IF;
    contact_id := nullif(
      current_setting('app.ticket_comment_author_contact_id',true),''
    )::uuid;
    IF contact_id IS NULL OR NOT EXISTS (
      SELECT 1
      FROM public.customer_contacts AS contact
      JOIN public.ticket_customer_contacts AS link
        ON link.tenant_id=contact.tenant_id
       AND link.contact_id=contact.id AND link.archived_at IS NULL
       AND (link.alert_id=NEW.alert_id OR link.case_id=NEW.case_id)
      WHERE contact.tenant_id=NEW.tenant_id AND contact.id=contact_id
        AND contact.linked_membership_id=NEW.actor_membership_id
        AND contact.linked_user_id=NEW.actor_user_id
        AND contact.active AND contact.archived_at IS NULL
    ) THEN
      RAISE EXCEPTION 'customer activity lacks its exact active contact link'
        USING ERRCODE='42501';
    END IF;
    audience_value := 'customer';
  ELSIF NEW.origin NOT IN ('api','system','escalation_copy') THEN
    RAISE EXCEPTION 'ticket activity origin is invalid'
      USING ERRCODE='22023';
  END IF;
  INSERT INTO public.ticket_activity_author_snapshots(
    tenant_id,activity_id,audience,author_contact_id,created_at
  ) VALUES (
    NEW.tenant_id,NEW.id,audience_value,contact_id,NEW.occurred_at
  );
  RETURN NEW;
END;
$function$;

CREATE FUNCTION app.private_append_ticket_comment_side_effects_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_ticket_version integer,
  p_comment_id uuid,
  p_comment_revision integer,
  p_visibility public.ticket_comment_visibility,
  p_origin text,
  p_author_contact_id uuid,
  p_action text,
  p_operation_at timestamp with time zone,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  activity_id uuid := uuidv7();
  activity_sequence bigint;
  notification_type public.notification_event_type := CASE
    WHEN p_action='commented' AND p_visibility='public'
      THEN 'comment.public_added'::public.notification_event_type
    WHEN p_action='commented' AND p_visibility='private'
      THEN 'comment.private_added'::public.notification_event_type
    END;
  maximum_audience public.notification_audience := 'operator';
  customer_visible boolean := false;
  customer_context jsonb;
  creator_user_id uuid;
  assignee_user_id uuid;
  operator_team_id uuid;
  operator_team_epoch_id uuid;
  metadata_value jsonb;
BEGIN
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR p_ticket_version NOT BETWEEN 1 AND 2147483647
     OR p_comment_id IS NULL
     OR (uuid_extract_version(p_comment_id)=7) IS NOT TRUE
     OR p_comment_revision NOT BETWEEN 1 AND 2147483647
     OR p_visibility IS NULL
     OR p_origin NOT IN ('api','customer_portal','system','escalation_copy')
     OR p_action NOT IN ('commented','comment_edited')
     OR p_operation_at IS NULL
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_origin IN ('api','system') AND p_author_contact_id IS NOT NULL
     OR p_origin='customer_portal' AND p_author_contact_id IS NULL
     OR p_origin='customer_portal' AND p_visibility<>'public'
     OR p_visibility='private' AND p_origin IN (
       'customer_portal','escalation_copy'
     ) THEN
    RAISE EXCEPTION 'ticket comment side-effect envelope is invalid'
      USING ERRCODE='22023';
  END IF;
  metadata_value := jsonb_build_object(
    'comment_id',p_comment_id,
    'comment_revision',p_comment_revision,
    'visibility',p_visibility::text,
    'origin',p_origin,
    'content_redacted',true
  );
  SELECT coalesce(max(activity.sequence),0)+1 INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id=context_tenant
    AND (p_aggregate_kind='alert' AND activity.alert_id=p_ticket_id
      OR p_aggregate_kind='case' AND activity.case_id=p_ticket_id);
  IF activity_sequence>2147483647 THEN
    RAISE EXCEPTION 'ticket activity sequence is exhausted'
      USING ERRCODE='54000';
  END IF;
  PERFORM set_config(
    'app.ticket_comment_author_contact_id',
    coalesce(p_author_contact_id::text,''),true
  );
  INSERT INTO public.ticket_activities(
    id,tenant_id,alert_id,case_id,sequence,kind,summary,
    actor_principal_kind,actor_membership_id,actor_user_id,origin,details,
    occurred_at
  ) VALUES (
    activity_id,context_tenant,
    CASE WHEN p_aggregate_kind='alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind='case' THEN p_ticket_id END,
    activity_sequence,p_aggregate_kind::text||'.'||p_action,
    CASE p_action WHEN 'commented' THEN 'Comment added'
      ELSE 'Comment corrected' END,
    'human',actor_membership,actor_user,p_origin,
    metadata_value||jsonb_build_object('version',p_ticket_version),
    p_operation_at
  );
  PERFORM app.append_tenant_authorization_audit(
    uuidv7(),'tenant.'||p_aggregate_kind::text||'.'||p_action,
    p_aggregate_kind::text,p_ticket_id,p_request_id,p_correlation_id,
    p_ip_address,nullif(p_user_agent,''),p_authentication_method,
    NULL,jsonb_build_object(
      'comment_id',p_comment_id,'comment_revision',p_comment_revision,
      'visibility',p_visibility::text
    ),metadata_value||jsonb_build_object(
      'actor_membership_id',actor_membership
    )
  );

  IF p_action='commented' THEN
    IF p_aggregate_kind='alert' THEN
      SELECT alert.created_by,alert.assignee_user_id,alert.assigned_team_id,
             alert.assigned_team_epoch_id,
             alert.customer_visible AND state.value->>'visibility'='customer'
      INTO STRICT creator_user_id,assignee_user_id,operator_team_id,
        operator_team_epoch_id,customer_visible
      FROM public.alerts AS alert
      JOIN public.ticket_workflow_versions AS workflow
        ON workflow.tenant_id=alert.tenant_id
       AND workflow.workflow_id=alert.workflow_id
       AND workflow.version=alert.workflow_version
       AND workflow.aggregate_kind='alert'
      CROSS JOIN LATERAL jsonb_array_elements(workflow.states) AS state(value)
      WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
        AND state.value->>'key'=alert.state_key;
    ELSE
      SELECT case_row.created_by_user_id,case_row.assignee_user_id,
             case_row.assigned_team_id,case_row.assigned_team_epoch_id,
             case_row.customer_visible
               AND state.value->>'visibility'='customer'
      INTO STRICT creator_user_id,assignee_user_id,operator_team_id,
        operator_team_epoch_id,customer_visible
      FROM public.cases AS case_row
      JOIN public.ticket_workflow_versions AS workflow
        ON workflow.tenant_id=case_row.tenant_id
       AND workflow.workflow_id=case_row.workflow_id
       AND workflow.version=case_row.workflow_version
       AND workflow.aggregate_kind='case'
      CROSS JOIN LATERAL jsonb_array_elements(workflow.states) AS state(value)
      WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id
        AND state.value->>'key'=case_row.state_key;
    END IF;
    IF p_visibility='public' AND customer_visible THEN
      maximum_audience := 'customer';
      customer_context := jsonb_build_object(
        p_aggregate_kind::text,jsonb_build_object(
          'id',p_ticket_id,'version',p_ticket_version
        ),
        'comment',jsonb_build_object(
          'id',p_comment_id,'revision',p_comment_revision,
          'visibility','public'
        ),
        'action',p_action,
        'metadata',jsonb_build_object('content_redacted',true)
      );
    END IF;
    PERFORM app.private_append_tenant_notification_event_v2(
      uuidv7(),notification_type,
      p_aggregate_kind::text::public.notification_object_type,
      p_ticket_id,p_ticket_version,p_operation_at,
      'human',actor_user,'ticketing',maximum_audience,
      jsonb_build_object(
        p_aggregate_kind::text,jsonb_build_object(
          'id',p_ticket_id,'version',p_ticket_version
        ),
        'comment',jsonb_build_object(
          'id',p_comment_id,'revision',p_comment_revision,
          'visibility',p_visibility::text
        ),
        'actor',jsonb_build_object('id',actor_user),
        'action',p_action,
        'metadata',metadata_value,
        'routing',jsonb_strip_nulls(jsonb_build_object(
          'creatorUserId',creator_user_id,
          'assigneeUserId',assignee_user_id,
          'operatorTeamId',operator_team_id,
          'operatorTeamEpochId',operator_team_epoch_id
        ))
      ),customer_context,
      'notification:v47:'||p_comment_id::text||':'
        ||p_comment_revision::text||':'||notification_type::text,
      p_correlation_id,p_request_id
    );
  END IF;
  INSERT INTO public.outbox_events(
    tenant_id,aggregate_type,aggregate_id,event_type,schema_version,payload,
    deduplication_key,correlation_id,causation_id,occurred_at,available_at
  ) VALUES (
    context_tenant,p_aggregate_kind::text,p_ticket_id,
    p_aggregate_kind::text||'.'||p_action,1,
    jsonb_build_object(
      p_aggregate_kind::text||'_id',p_ticket_id,
      'version',p_ticket_version,
      'comment_id',p_comment_id,
      'comment_revision',p_comment_revision,
      'content_redacted',true
    ),
    'ticket:v47:'||p_comment_id::text||':'||p_comment_revision::text||':'
      ||p_action,p_correlation_id,p_request_id,p_operation_at,p_operation_at
  );
END;
$function$;

ALTER FUNCTION app.capture_ticket_activity_author_snapshot_v1()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_append_ticket_comment_side_effects_v1(
  public.ticket_aggregate_kind,uuid,integer,uuid,integer,
  public.ticket_comment_visibility,text,uuid,text,timestamp with time zone,
  uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.capture_ticket_activity_author_snapshot_v1(),
  app.private_append_ticket_comment_side_effects_v1(
    public.ticket_aggregate_kind,uuid,integer,uuid,integer,
    public.ticket_comment_visibility,text,uuid,text,timestamp with time zone,
    uuid,uuid,inet,text,text
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_comment_attachment_preview_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_visibility public.ticket_comment_visibility,
  p_attachment_ids uuid[]
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  result_value jsonb;
  result_count integer;
BEGIN
  IF NOT app.private_ticket_comment_uuid_array_valid_v1(p_attachment_ids,20)
     OR p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR p_visibility IS NULL THEN
    RAISE EXCEPTION 'ticket comment attachment selection is invalid'
      USING ERRCODE='22023';
  END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'id',attachment.id,
           'original_filename',attachment.original_filename,
           'visibility',attachment.visibility::text
         ) ORDER BY attachment.id),'[]'::jsonb),count(*)
  INTO result_value,result_count
  FROM public.dfir_attachments AS attachment
  JOIN public.dfir_storage_objects AS storage
    ON storage.tenant_id=attachment.tenant_id
   AND storage.id=attachment.storage_object_id
  WHERE attachment.tenant_id=context_tenant
    AND attachment.id=ANY(p_attachment_ids)
    AND attachment.scan_state IN ('available','retained')
    AND storage.state IN ('available','retained')
    AND storage.content_sha256 IS NOT NULL
    AND storage.size_bytes IS NOT NULL
    AND (storage.legal_hold OR storage.retention_until IS NULL
      OR storage.retention_until>transaction_timestamp())
    AND (p_visibility='private' OR attachment.visibility='public')
    AND (
      p_aggregate_kind='alert' AND attachment.subject_kind='alert'
        AND attachment.alert_id=p_ticket_id
      OR p_aggregate_kind='case' AND (
        attachment.subject_kind='case' AND attachment.case_id=p_ticket_id
        OR attachment.subject_kind='alert' AND EXISTS (
          SELECT 1 FROM public.dfir_attachment_case_links AS link
          WHERE link.tenant_id=context_tenant
            AND link.attachment_id=attachment.id
            AND link.case_id=p_ticket_id
            AND link.source_alert_id=attachment.alert_id
        )
      )
    );
  IF result_count<>cardinality(p_attachment_ids) THEN
    RAISE EXCEPTION 'ticket comment attachment selection is unavailable'
      USING ERRCODE='23503';
  END IF;
  RETURN result_value;
END;
$function$;

CREATE FUNCTION app.private_ticket_comment_mention_preview_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_membership_ids uuid[]
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  result_value jsonb;
  result_count integer;
BEGIN
  IF NOT app.private_ticket_comment_uuid_array_valid_v1(p_membership_ids,50)
     OR p_aggregate_kind IS NULL OR p_ticket_id IS NULL THEN
    RAISE EXCEPTION 'ticket comment mention selection is invalid'
      USING ERRCODE='22023';
  END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'membership_id',membership.id,
           'display_name',identity.display_name
         ) ORDER BY membership.id),'[]'::jsonb),count(*)
  INTO result_value,result_count
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=context_tenant
    AND membership.id=ANY(p_membership_ids)
    AND membership.status='active' AND identity.active
    AND membership.role NOT IN (
      'customer_manager','customer_user','read_only'
    )
    AND app.private_ticket_comment_display_name_valid_v1(
      identity.display_name
    )
    AND app.private_ticket_watcher_user_scope_allows_v2(
      context_tenant,p_aggregate_kind,p_ticket_id,membership.user_id,'read'
    );
  IF result_count<>cardinality(p_membership_ids) THEN
    RAISE EXCEPTION 'ticket comment mention selection is unavailable'
      USING ERRCODE='23503';
  END IF;
  RETURN result_value;
END;
$function$;

CREATE FUNCTION app.preview_tenant_ticket_comment_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_visibility public.ticket_comment_visibility,
  p_attachment_ids uuid[],
  p_mentioned_membership_ids uuid[]
)
RETURNS TABLE(result_attachments jsonb,result_mentions jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  IF NOT app.private_ticket_comment_operator_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,p_visibility,'create'
  ) THEN
    RAISE EXCEPTION 'live ticket comment create scope is required'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT
    app.private_ticket_comment_attachment_preview_v1(
      p_aggregate_kind,p_ticket_id,p_visibility,p_attachment_ids
    ),
    app.private_ticket_comment_mention_preview_v1(
      p_aggregate_kind,p_ticket_id,p_mentioned_membership_ids
    );
END;
$function$;

CREATE FUNCTION app.preview_customer_portal_ticket_comment_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_attachment_ids uuid[]
)
RETURNS TABLE(result_attachments jsonb,result_mentions jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  IF NOT app.private_ticket_comment_portal_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,NULL
  ) THEN
    RAISE EXCEPTION 'exact portal comment relation is required'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT
    app.private_ticket_comment_attachment_preview_v1(
      p_aggregate_kind,p_ticket_id,'public',p_attachment_ids
    ),'[]'::jsonb;
END;
$function$;

CREATE FUNCTION app.list_tenant_ticket_comment_mention_candidates_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_search text,
  p_limit integer
)
RETURNS TABLE(result_items jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_search IS NULL OR p_limit NOT BETWEEN 1 AND 100
     OR p_search<>'' AND (
       char_length(p_search) NOT BETWEEN 1 AND 100
       OR NOT app.private_ticket_comment_scalars_valid_v1(p_search,false)
       OR p_search ~ '[<>]'
       OR NOT EXISTS (
         SELECT 1
         FROM generate_series(1,char_length(p_search)) AS position(index)
         WHERE NOT app.private_ticket_comment_go_space_codepoint_v1(
           ascii(substr(p_search,position.index,1))
         )
       )
     ) THEN
    RAISE EXCEPTION 'ticket comment mention query is invalid'
      USING ERRCODE='22023';
  END IF;
  IF NOT app.private_ticket_comment_operator_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,'public','mention'
  ) THEN
    RAISE EXCEPTION 'live ticket comment read scope is required'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY
  SELECT coalesce(jsonb_agg(jsonb_build_object(
           'membership_id',candidate.membership_id,
           'display_name',candidate.display_name
         ) ORDER BY candidate.display_name COLLATE "C",candidate.membership_id),
         '[]'::jsonb)
  FROM (
    SELECT membership.id AS membership_id,identity.display_name
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    WHERE membership.tenant_id=context_tenant
      AND membership.status='active' AND identity.active
      AND membership.role NOT IN (
        'customer_manager','customer_user','read_only'
      )
      AND app.private_ticket_comment_display_name_valid_v1(
        identity.display_name
      )
      AND (p_search='' OR strpos(
        lower(identity.display_name),lower(p_search)
      )>0)
      AND app.private_ticket_watcher_user_scope_allows_v2(
        context_tenant,p_aggregate_kind,p_ticket_id,membership.user_id,'read'
      )
    ORDER BY identity.display_name COLLATE "C",membership.id
    LIMIT p_limit
  ) AS candidate;
END;
$function$;

CREATE FUNCTION app.private_ticket_comment_revision_projection_v1(
  p_tenant_id uuid,
  p_revision_id uuid,
  p_customer_projection boolean
)
RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
  WITH selected AS (
    SELECT revision.id,revision.revision,revision.body_markdown,
           revision.body_html,revision.reason,revision.edited_at
    FROM public.ticket_comment_revisions AS revision
    WHERE revision.tenant_id=p_tenant_id AND revision.id=p_revision_id
  ), attachments AS (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
             'id',relation.attachment_id,
             'original_filename',relation.original_filename,
             'visibility',relation.visibility::text
           ) ORDER BY relation.attachment_id)
           FILTER (WHERE relation.attachment_id IS NOT NULL),
           '[]'::jsonb) AS value
    FROM selected
    LEFT JOIN public.ticket_comment_revision_attachments AS relation
      ON relation.tenant_id=p_tenant_id
     AND relation.revision_id=selected.id
  ), mentions AS (
    SELECT coalesce(jsonb_agg(jsonb_build_object(
             'membership_id',relation.mentioned_membership_id,
             'display_name',relation.display_name
           ) ORDER BY relation.mentioned_membership_id)
           FILTER (WHERE relation.mentioned_membership_id IS NOT NULL),
           '[]'::jsonb) AS value
    FROM selected
    LEFT JOIN public.ticket_comment_revision_mentions AS relation
      ON relation.tenant_id=p_tenant_id
     AND relation.revision_id=selected.id
  )
  SELECT jsonb_build_object(
    'revision',selected.revision,
    'body_markdown',selected.body_markdown,
    'body_html',selected.body_html,
    'edited_at',app.private_ticket_comment_time_text_v1(selected.edited_at),
    'attachments',attachments.value
  ) || CASE WHEN p_customer_projection THEN '{}'::jsonb ELSE
    jsonb_build_object('reason',selected.reason,'mentions',mentions.value) END
  FROM selected CROSS JOIN attachments CROSS JOIN mentions
$function$;

CREATE FUNCTION app.private_list_ticket_comment_revisions_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_comment_id uuid,
  p_after_revision integer,
  p_limit integer,
  p_customer_projection boolean
)
RETURNS TABLE(result_items jsonb,next_after_revision integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  visibility_value public.ticket_comment_visibility;
BEGIN
  IF p_comment_id IS NULL OR (uuid_extract_version(p_comment_id)=7) IS NOT TRUE
     OR p_after_revision IS NOT NULL
        AND p_after_revision NOT BETWEEN 1 AND 2147483647
     OR p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'ticket comment revision page is invalid'
      USING ERRCODE='22023';
  END IF;
  SELECT comment.visibility INTO visibility_value
  FROM public.ticket_comments AS comment
  WHERE comment.tenant_id=context_tenant AND comment.id=p_comment_id
    AND (p_aggregate_kind='alert' AND comment.alert_id=p_ticket_id
      OR p_aggregate_kind='case' AND comment.case_id=p_ticket_id)
    AND (NOT p_customer_projection OR comment.visibility='public');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket comment not found' USING ERRCODE='P0002';
  END IF;
  IF p_customer_projection THEN
    IF NOT app.private_ticket_comment_portal_scope_allows_v1(
         p_aggregate_kind,p_ticket_id,NULL
       ) THEN
      RAISE EXCEPTION 'ticket comment not found'
        USING ERRCODE='P0002';
    END IF;
  ELSIF NOT app.private_ticket_comment_operator_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,visibility_value,'read'
  ) THEN
    -- Hidden private comments and absent UUIDs deliberately have the same
    -- database outcome so revision history cannot become an existence oracle.
    RAISE EXCEPTION 'ticket comment not found'
      USING ERRCODE='P0002';
  END IF;
  RETURN QUERY
  WITH eligible AS (
    SELECT revision.id,revision.revision
    FROM public.ticket_comment_revisions AS revision
    WHERE revision.tenant_id=context_tenant
      AND revision.comment_id=p_comment_id
      AND (p_after_revision IS NULL OR revision.revision<p_after_revision)
    ORDER BY revision.revision DESC
    LIMIT p_limit+1
  ), page AS (
    SELECT eligible.* FROM eligible
    ORDER BY eligible.revision DESC LIMIT p_limit
  )
  SELECT coalesce(jsonb_agg(
           app.private_ticket_comment_revision_projection_v1(
             context_tenant,page.id,p_customer_projection
           ) ORDER BY page.revision DESC
         ),'[]'::jsonb),
         CASE WHEN (SELECT count(*) FROM eligible)>p_limit
           THEN (SELECT min(revision) FROM page) END
  FROM page;
END;
$function$;

CREATE FUNCTION app.list_tenant_ticket_comment_revisions_v1(
  p_aggregate_kind public.ticket_aggregate_kind,p_ticket_id uuid,
  p_comment_id uuid,p_after_revision integer,p_limit integer
)
RETURNS TABLE(result_items jsonb,next_after_revision integer)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_list_ticket_comment_revisions_v1(
    p_aggregate_kind,p_ticket_id,p_comment_id,p_after_revision,p_limit,false
  )
$function$;

CREATE FUNCTION app.list_customer_portal_ticket_comment_revisions_v1(
  p_aggregate_kind public.ticket_aggregate_kind,p_ticket_id uuid,
  p_comment_id uuid,p_after_revision integer,p_limit integer
)
RETURNS TABLE(result_items jsonb,next_after_revision integer)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_list_ticket_comment_revisions_v1(
    p_aggregate_kind,p_ticket_id,p_comment_id,p_after_revision,p_limit,true
  )
$function$;

ALTER FUNCTION app.private_ticket_comment_attachment_preview_v1(
  public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,uuid[]
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_mention_preview_v1(
  public.ticket_aggregate_kind,uuid,uuid[]
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.preview_tenant_ticket_comment_v1(
  public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,uuid[],uuid[]
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.preview_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind,uuid,uuid[]
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_tenant_ticket_comment_mention_candidates_v1(
  public.ticket_aggregate_kind,uuid,text,integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_comment_revision_projection_v1(
  uuid,uuid,boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_list_ticket_comment_revisions_v1(
  public.ticket_aggregate_kind,uuid,uuid,integer,integer,boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_tenant_ticket_comment_revisions_v1(
  public.ticket_aggregate_kind,uuid,uuid,integer,integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_customer_portal_ticket_comment_revisions_v1(
  public.ticket_aggregate_kind,uuid,uuid,integer,integer
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_comment_attachment_preview_v1(
    public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,uuid[]
  ),
  app.private_ticket_comment_mention_preview_v1(
    public.ticket_aggregate_kind,uuid,uuid[]
  ),
  app.private_ticket_comment_revision_projection_v1(uuid,uuid,boolean),
  app.private_list_ticket_comment_revisions_v1(
    public.ticket_aggregate_kind,uuid,uuid,integer,integer,boolean
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION
  app.preview_tenant_ticket_comment_v1(
    public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,uuid[],uuid[]
  ),
  app.preview_customer_portal_ticket_comment_v1(
    public.ticket_aggregate_kind,uuid,uuid[]
  ),
  app.list_tenant_ticket_comment_mention_candidates_v1(
    public.ticket_aggregate_kind,uuid,text,integer
  ),
  app.list_tenant_ticket_comment_revisions_v1(
    public.ticket_aggregate_kind,uuid,uuid,integer,integer
  ),
  app.list_customer_portal_ticket_comment_revisions_v1(
    public.ticket_aggregate_kind,uuid,uuid,integer,integer
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION
  app.preview_tenant_ticket_comment_v1(
    public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,uuid[],uuid[]
  ),
  app.preview_customer_portal_ticket_comment_v1(
    public.ticket_aggregate_kind,uuid,uuid[]
  ),
  app.list_tenant_ticket_comment_mention_candidates_v1(
    public.ticket_aggregate_kind,uuid,text,integer
  ),
  app.list_tenant_ticket_comment_revisions_v1(
    public.ticket_aggregate_kind,uuid,uuid,integer,integer
  ),
  app.list_customer_portal_ticket_comment_revisions_v1(
    public.ticket_aggregate_kind,uuid,uuid,integer,integer
  )
TO periapsis_api;
--> statement-breakpoint

-- Closed projections used by consumers that formerly joined the mutable
-- aggregate tables directly. Both are installed before direct-table cutover.
CREATE FUNCTION app.get_customer_portal_ticket_export_v2(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_author_contact_id uuid,
  p_comment_limit integer
)
RETURNS TABLE(
  result_reference text,result_title text,result_summary text,
  result_description text,result_state text,result_severity text,
  result_priority text,result_category text,
  result_occurred_at timestamp with time zone,
  result_updated_at timestamp with time zone,result_version integer,
  result_public_comments jsonb
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
BEGIN
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR (uuid_extract_version(p_ticket_id)=7) IS NOT TRUE
     OR p_author_contact_id IS NULL
     OR (uuid_extract_version(p_author_contact_id)=7) IS NOT TRUE
     OR p_comment_limit NOT BETWEEN 1 AND 201 THEN
    RAISE EXCEPTION 'customer ticket export input is invalid'
      USING ERRCODE='22023';
  END IF;
  IF NOT app.private_ticket_comment_portal_scope_allows_v1(
    p_aggregate_kind,p_ticket_id,p_author_contact_id
  ) THEN
    RAISE EXCEPTION 'customer ticket export is unavailable'
      USING ERRCODE='P0002';
  END IF;
  IF p_aggregate_kind='alert' THEN
    RETURN QUERY
    SELECT alert.number,alert.title,''::text,
           coalesce(alert.description,''),alert.state_key,
           alert.severity::text,alert.priority,alert.category,
           alert.detected_at,alert.updated_at,alert.version,
           coalesce(comment_projection.value,'[]'::jsonb)
    FROM public.alerts AS alert
    CROSS JOIN LATERAL (
      SELECT jsonb_agg(jsonb_build_object(
        'id',selected.id,'visibility','public',
        'bodyMarkdown',selected.body_markdown,
        'author',CASE selected.audience
          WHEN 'customer' THEN 'Customer' ELSE 'Support team' END,
        'audience',selected.audience,'createdAt',selected.created_at
      ) ORDER BY selected.created_at,selected.id) AS value
      FROM (
        SELECT comment.id,revision.body_markdown,snapshot.audience,
               comment.created_at
        FROM public.ticket_comments AS comment
        JOIN public.ticket_comment_revisions AS revision
          ON revision.tenant_id=comment.tenant_id
         AND revision.comment_id=comment.id
         AND revision.revision=comment.revision
        JOIN public.ticket_comment_author_snapshots AS snapshot
          ON snapshot.tenant_id=comment.tenant_id
         AND snapshot.comment_id=comment.id
        WHERE comment.tenant_id=context_tenant
          AND comment.alert_id=p_ticket_id
          AND comment.visibility='public'
        ORDER BY comment.created_at,comment.id
        LIMIT p_comment_limit
      ) AS selected
    ) AS comment_projection
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL;
  ELSE
    RETURN QUERY
    SELECT case_row.number,case_row.title,case_row.summary,
           coalesce(case_row.description,''),case_row.state_key,
           case_row.severity::text,case_row.priority,case_row.category,
           case_row.detection_time,case_row.updated_at,case_row.version,
           coalesce(comment_projection.value,'[]'::jsonb)
    FROM public.cases AS case_row
    CROSS JOIN LATERAL (
      SELECT jsonb_agg(jsonb_build_object(
        'id',selected.id,'visibility','public',
        'bodyMarkdown',selected.body_markdown,
        'author',CASE selected.audience
          WHEN 'customer' THEN 'Customer' ELSE 'Support team' END,
        'audience',selected.audience,'createdAt',selected.created_at
      ) ORDER BY selected.created_at,selected.id) AS value
      FROM (
        SELECT comment.id,revision.body_markdown,snapshot.audience,
               comment.created_at
        FROM public.ticket_comments AS comment
        JOIN public.ticket_comment_revisions AS revision
          ON revision.tenant_id=comment.tenant_id
         AND revision.comment_id=comment.id
         AND revision.revision=comment.revision
        JOIN public.ticket_comment_author_snapshots AS snapshot
          ON snapshot.tenant_id=comment.tenant_id
         AND snapshot.comment_id=comment.id
        WHERE comment.tenant_id=context_tenant
          AND comment.case_id=p_ticket_id
          AND comment.visibility='public'
        ORDER BY comment.created_at,comment.id
        LIMIT p_comment_limit
      ) AS selected
    ) AS comment_projection
    WHERE case_row.tenant_id=context_tenant AND case_row.id=p_ticket_id;
  END IF;
END;
$function$;

CREATE FUNCTION app.list_tenant_ticket_escalation_comment_selection_v1(
  p_alert_id uuid,p_comment_ids uuid[]
)
RETURNS TABLE(result_comment_id uuid)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  alert_row public.alerts%ROWTYPE;
  matching_count integer;
BEGIN
  IF p_alert_id IS NULL OR (uuid_extract_version(p_alert_id)=7) IS NOT TRUE
     OR NOT app.private_ticket_comment_uuid_array_valid_v1(
       p_comment_ids,100
     ) THEN
    RAISE EXCEPTION 'escalation comment selection input is invalid'
      USING ERRCODE='22023';
  END IF;
  SELECT alert.* INTO alert_row
  FROM public.alerts AS alert
  WHERE alert.tenant_id=context_tenant AND alert.id=p_alert_id
    AND alert.deleted_at IS NULL;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
       'alert.escalate',alert_row.assigned_team_id,alert_row.created_by,
       alert_row.assignee_user_id,alert_row.claimed_by_user_id
     ) OR NOT app.private_ticket_comment_operator_scope_allows_v1(
       'alert',p_alert_id,'public','read'
     ) THEN
    RAISE EXCEPTION 'escalation comment selection is unavailable'
      USING ERRCODE='P0002';
  END IF;
  SELECT count(*) INTO matching_count
  FROM public.ticket_comments AS comment
  JOIN public.ticket_comment_revisions AS revision
    ON revision.tenant_id=comment.tenant_id
   AND revision.comment_id=comment.id
   AND revision.revision=comment.revision
  WHERE comment.tenant_id=context_tenant AND comment.alert_id=p_alert_id
    AND comment.visibility='public' AND comment.id=ANY(p_comment_ids);
  IF matching_count<>cardinality(p_comment_ids) THEN
    RAISE EXCEPTION 'escalation comment selection is not exact and public'
      USING ERRCODE='22023';
  END IF;
  RETURN QUERY
  SELECT comment.id
  FROM public.ticket_comments AS comment
  JOIN public.ticket_comment_revisions AS revision
    ON revision.tenant_id=comment.tenant_id
   AND revision.comment_id=comment.id
   AND revision.revision=comment.revision
  WHERE comment.tenant_id=context_tenant AND comment.alert_id=p_alert_id
    AND comment.visibility='public' AND comment.id=ANY(p_comment_ids)
  ORDER BY comment.id;
END;
$function$;

ALTER FUNCTION app.get_customer_portal_ticket_export_v2(
  public.ticket_aggregate_kind,uuid,uuid,integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_tenant_ticket_escalation_comment_selection_v1(
  uuid,uuid[]
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.get_customer_portal_ticket_export_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
  ),
  app.list_tenant_ticket_escalation_comment_selection_v1(uuid,uuid[])
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION
  app.get_customer_portal_ticket_export_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
  ),
  app.list_tenant_ticket_escalation_comment_selection_v1(uuid,uuid[])
TO periapsis_api;
--> statement-breakpoint
