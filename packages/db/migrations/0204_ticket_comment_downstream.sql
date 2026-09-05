-- V47 downstream ticket-comment boundaries.  The persistence and HTTP ABI
-- installed by 0202/0203 remain the only direct application write surface;
-- this migration closes notification, escalation, transition and export
-- consumers over immutable revision snapshots.

CREATE FUNCTION app.private_ticket_comment_user_scope_allows_v1(
  p_tenant_id uuid,
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_user_id uuid,
  p_visibility public.ticket_comment_visibility
)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  WITH target AS (
    SELECT membership.id AS membership_id
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    WHERE membership.tenant_id=p_tenant_id
      AND membership.user_id=p_user_id
      AND membership.status='active'
      AND membership.role NOT IN (
        'customer_manager','customer_user','read_only'
      )
      AND identity.active
  ), ticket AS (
    SELECT alert.assigned_team_id,alert.assigned_team_epoch_id,
           alert.created_by AS owner_user_id,alert.assignee_user_id,
           alert.claimed_by_user_id
    FROM public.alerts AS alert
    WHERE p_aggregate_kind='alert'
      AND alert.tenant_id=p_tenant_id AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL
    UNION ALL
    SELECT case_row.assigned_team_id,case_row.assigned_team_epoch_id,
           case_row.created_by_user_id,case_row.assignee_user_id,
           case_row.claimed_by_user_id
    FROM public.cases AS case_row
    WHERE p_aggregate_kind='case'
      AND case_row.tenant_id=p_tenant_id AND case_row.id=p_ticket_id
  ), scoped AS (
    SELECT target.membership_id,ticket.*,
      app.private_ticket_watcher_user_scope_allows_v2(
        p_tenant_id,p_aggregate_kind,p_ticket_id,p_user_id,'read'
      ) AS can_read
    FROM target CROSS JOIN ticket
  ), permissions AS (
    SELECT scoped.*,
      permission.permission_key,
      app.tenant_human_has_exact_permission_v3(
        p_tenant_id,p_user_id,permission.permission_key,'tenant'
      ) OR app.tenant_human_has_exact_permission_v3(
        p_tenant_id,p_user_id,permission.permission_key,'own'
      ) AND p_user_id IN (
        scoped.owner_user_id,scoped.assignee_user_id,
        scoped.claimed_by_user_id
      ) OR app.tenant_human_has_exact_permission_v3(
        p_tenant_id,p_user_id,permission.permission_key,'assigned'
      ) AND p_user_id IN (
        scoped.assignee_user_id,scoped.claimed_by_user_id
      ) OR app.tenant_human_has_exact_permission_v3(
        p_tenant_id,p_user_id,permission.permission_key,'operator_team'
      ) AND scoped.assigned_team_id IS NOT NULL
        AND scoped.assigned_team_epoch_id IS NOT NULL
        AND EXISTS (
          SELECT 1
          FROM public.operator_team_assignment_epochs AS epoch
          JOIN public.operator_team_roster_entries AS roster
            ON roster.tenant_id=epoch.tenant_id
           AND roster.assignment_epoch_id=epoch.id
          JOIN public.tenant_authorization_sources AS source
            ON source.tenant_id=roster.tenant_id
           AND source.id=roster.source_id
           AND source.retired_at IS NULL
          WHERE epoch.tenant_id=p_tenant_id
            AND epoch.id=scoped.assigned_team_epoch_id
            AND epoch.operator_team_id=scoped.assigned_team_id
            AND epoch.ended_at IS NULL
            AND roster.membership_id=scoped.membership_id
            AND roster.granted_at<=transaction_timestamp()
            AND roster.revoked_at IS NULL
            AND (roster.expires_at IS NULL
              OR roster.expires_at>transaction_timestamp())
        ) AS permission_allows
    FROM scoped
    CROSS JOIN LATERAL (
      VALUES (p_aggregate_kind::text||'.comment.read'),
        (CASE WHEN p_visibility='private'
          THEN p_aggregate_kind::text||'.comment.private' END)
    ) AS permission(permission_key)
    WHERE permission.permission_key IS NOT NULL
  )
  SELECT p_visibility IN ('public','private')
    AND coalesce(bool_and(can_read AND permission_allows),false)
    AND count(*)=CASE p_visibility WHEN 'private' THEN 2 ELSE 1 END
  FROM permissions
$function$;

ALTER FUNCTION app.private_ticket_comment_user_scope_allows_v1(
  uuid,public.ticket_aggregate_kind,uuid,uuid,
  public.ticket_comment_visibility
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_comment_user_scope_allows_v1(
  uuid,public.ticket_aggregate_kind,uuid,uuid,
  public.ticket_comment_visibility
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_comment_user_scope_allows_v1(
  uuid,public.ticket_aggregate_kind,uuid,uuid,
  public.ticket_comment_visibility
) TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- Merge predecessor routing candidates with exact revision mentions.  The
-- base pool is re-filtered because a historical operator may have since been
-- reclassified into any of the three customer roles.
CREATE FUNCTION app.private_notification_operator_candidates_v2(
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
SET search_path=pg_catalog,public,app
AS $function$
  WITH source AS (
    SELECT event.*,
      event.payload #>> '{operatorContext,comment,id}' AS comment_id_text,
      event.payload #>> '{operatorContext,comment,revision}'
        AS revision_text,
      event.payload #>> '{operatorContext,comment,visibility}'
        AS visibility_text
    FROM public.outbox_events AS event
    WHERE event.tenant_id=p_tenant_id AND event.id=p_event_id
  ), base AS (
    SELECT candidate.sort_email,candidate.sort_principal,
           candidate.sort_source,candidate.value
    FROM source
    JOIN LATERAL app.private_notification_operator_candidates_v1(
      p_tenant_id,p_event_id
    ) AS candidate ON true
    LEFT JOIN public.ticket_comments AS comment
      ON comment.tenant_id=source.tenant_id
     AND comment.id::text=source.comment_id_text
     AND comment.visibility::text=source.visibility_text
     AND (source.aggregate_type='alert'
       AND comment.alert_id=source.aggregate_id
       OR source.aggregate_type='case'
       AND comment.case_id=source.aggregate_id)
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id=p_tenant_id
     AND membership.user_id=candidate.sort_principal
     AND membership.status='active'
     AND membership.role NOT IN (
       'customer_manager','customer_user','read_only'
     )
    WHERE CASE WHEN source.event_type IN (
      'notification.comment.public_added',
      'notification.comment.private_added'
    ) THEN source.aggregate_type IN ('alert','case')
      AND comment.id IS NOT NULL
      AND app.private_ticket_comment_user_scope_allows_v1(
        source.tenant_id,
        CASE source.aggregate_type WHEN 'alert'
          THEN 'alert'::public.ticket_aggregate_kind
          ELSE 'case'::public.ticket_aggregate_kind END,
        source.aggregate_id,candidate.sort_principal,comment.visibility
      )
    ELSE true END
  ), mentioned AS (
    SELECT profile.email AS sort_email,identity.id AS sort_principal,
           'operator'::text AS sort_source,
           jsonb_build_object(
             'tenantId',p_tenant_id,
             'email',profile.email,
             'audience','operator',
             'kinds',jsonb_build_array('mentioned'),
             'values','{}'::jsonb,
             'principalId',identity.id,
             'enabled',true,
             'emailAllowed',true
           ) AS value
    FROM source
    JOIN public.ticket_comments AS comment
      ON comment.tenant_id=source.tenant_id
     AND comment.id::text=source.comment_id_text
     AND comment.visibility::text=source.visibility_text
     AND (source.aggregate_type='alert'
       AND comment.alert_id=source.aggregate_id
       OR source.aggregate_type='case'
       AND comment.case_id=source.aggregate_id)
    JOIN public.ticket_comment_revisions AS revision
      ON revision.tenant_id=comment.tenant_id
     AND revision.comment_id=comment.id
     AND revision.revision::text=source.revision_text
    JOIN public.ticket_comment_revision_mentions AS mention
      ON mention.tenant_id=revision.tenant_id
     AND mention.revision_id=revision.id
    JOIN public.tenant_memberships AS membership
      ON membership.tenant_id=mention.tenant_id
     AND membership.id=mention.mentioned_membership_id
     AND membership.user_id=mention.mentioned_user_id
     AND membership.status='active'
     AND membership.role NOT IN (
       'customer_manager','customer_user','read_only'
     )
    JOIN public.users AS identity
      ON identity.id=membership.user_id AND identity.active
    JOIN public.tenant_user_profiles AS profile
      ON profile.tenant_id=membership.tenant_id
     AND profile.membership_id=membership.id
     AND profile.user_id=identity.id
     AND profile.email IS NOT NULL
    WHERE CASE WHEN source.event_type IN (
      'notification.comment.public_added',
      'notification.comment.private_added'
    ) AND source.aggregate_type IN ('alert','case') THEN
      app.private_ticket_comment_user_scope_allows_v1(
        source.tenant_id,
        CASE source.aggregate_type WHEN 'alert'
          THEN 'alert'::public.ticket_aggregate_kind
          ELSE 'case'::public.ticket_aggregate_kind END,
        source.aggregate_id,identity.id,comment.visibility
      ) ELSE false END
  ), principals AS (
    SELECT base.sort_email,base.sort_principal,base.sort_source
    FROM base
    UNION
    SELECT mentioned.sort_email,mentioned.sort_principal,
           mentioned.sort_source
    FROM mentioned
  )
  SELECT principal.sort_email,principal.sort_principal,
         principal.sort_source,
    CASE WHEN base.value IS NULL THEN mentioned.value
      WHEN mentioned.value IS NULL THEN base.value
      WHEN base.value->'kinds' ? 'mentioned' THEN base.value
      ELSE jsonb_set(
        base.value,'{kinds}',base.value->'kinds'||jsonb_build_array('mentioned'),
        false
      ) END AS value
  FROM principals AS principal
  LEFT JOIN base
    ON base.sort_email=principal.sort_email
   AND base.sort_principal=principal.sort_principal
   AND base.sort_source=principal.sort_source
  LEFT JOIN mentioned
    ON mentioned.sort_email=principal.sort_email
   AND mentioned.sort_principal=principal.sort_principal
   AND mentioned.sort_source=principal.sort_source
$function$;

ALTER FUNCTION app.private_notification_operator_candidates_v2(uuid,uuid)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_notification_operator_candidates_v2(
  uuid,uuid
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.private_notification_operator_candidates_v1(
  uuid,uuid
) TO periapsis_migrator;
GRANT EXECUTE ON FUNCTION app.private_notification_operator_candidates_v2(
  uuid,uuid
) TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- The loader successor preserves the established snapshot/claim semantics,
-- admits the new selector, and routes candidate construction through V47.
DO $derive_notification_loader_v3$
DECLARE
  predecessor_definition text;
  successor_definition text;
  legacy_customer_account_gate constant text := $old$
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
$old$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(
    'app.load_notification_fanout_inputs_v2(uuid,uuid)'::regprocedure
  ) INTO predecessor_definition;
  IF encode(sha256(convert_to(predecessor_definition,'UTF8')),'hex') <>
       '2a1f61f83bf976274a7de79ec1a466c06cf7e979fad6db0d4bca8296438cd17e'
     OR pg_catalog.strpos(
       predecessor_definition,
       '''operator_team'', ''watcher'','
     )=0
     OR pg_catalog.strpos(
       predecessor_definition,
       'private_notification_operator_candidates_v1'
     )=0
     OR pg_catalog.strpos(
       predecessor_definition,
       btrim(legacy_customer_account_gate,E'\r\n')
     )=0 THEN
    RAISE EXCEPTION 'notification loader predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;
  successor_definition := pg_catalog.replace(
    predecessor_definition,'load_notification_fanout_inputs_v2',
    'load_notification_fanout_inputs_v3'
  );
  successor_definition := pg_catalog.replace(
    successor_definition,'''operator_team'', ''watcher'',',
    '''operator_team'', ''watcher'', ''mentioned'','
  );
  successor_definition := pg_catalog.replace(
    successor_definition,'private_notification_operator_candidates_v1',
    'private_notification_operator_candidates_v2'
  );
  -- A ticket-linked CustomerContact is itself the notification principal.
  -- An optional account enriches principalId but is never required for a
  -- customer-safe public notification.
  successor_definition := pg_catalog.replace(
    successor_definition,
    btrim(legacy_customer_account_gate,E'\r\n'),''
  );
  IF successor_definition IS NOT DISTINCT FROM predecessor_definition
     OR pg_catalog.strpos(successor_definition,'''mentioned''')=0
     OR pg_catalog.strpos(
       successor_definition,'private_notification_operator_candidates_v1'
     )<>0
     OR pg_catalog.strpos(
       successor_definition,'contact.linked_membership_id IS NOT NULL'
     )<>0 THEN
    RAISE EXCEPTION 'notification loader V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$derive_notification_loader_v3$;

ALTER FUNCTION app.load_notification_fanout_inputs_v3(uuid,uuid)
  OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION app.load_notification_fanout_inputs_v3(uuid,uuid)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v3(uuid,uuid)
TO periapsis_notifier;
--> statement-breakpoint

-- Email planning is untrusted input.  Require the exact frozen audience
-- projection that was claimed: operator deliveries receive operator context
-- plus the nested customer projection when present; customer deliveries get
-- only the customer-safe projection.
CREATE FUNCTION app.commit_notification_fanout_v2(
  p_event_id uuid,
  p_fence_token uuid,
  p_deliveries jsonb,
  p_committed_at timestamp with time zone
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  source_event public.outbox_events%ROWTYPE;
  selected_rule public.tenant_notification_rule_versions%ROWTYPE;
  delivery_value jsonb;
  fanout_inputs jsonb;
  expected_context jsonb;
  committed_result jsonb;
BEGIN
  IF p_deliveries IS NULL OR jsonb_typeof(p_deliveries)<>'array'
     OR jsonb_array_length(p_deliveries)>10000 THEN
    RAISE EXCEPTION 'notification fanout commit input is invalid'
      USING ERRCODE='22023';
  END IF;
  SELECT event.* INTO STRICT source_event
  FROM public.outbox_events AS event
  WHERE event.id=p_event_id
    AND event.event_type LIKE 'notification.%'
    AND event.schema_version=2
  FOR UPDATE;
  IF source_event.processed_at IS NULL THEN
    -- Reuse the same fenced, server-authenticated inventory returned to the
    -- planner.  This also creates or verifies immutable rule/candidate pins
    -- before any fresh client-supplied delivery is considered.  Exact commit
    -- replays skip this claim-only loader and are verified by V1's digest.
    fanout_inputs := app.load_notification_fanout_inputs_v3(
      p_event_id,p_fence_token
    );
    FOR delivery_value IN
      SELECT item.value
      FROM jsonb_array_elements(p_deliveries) WITH ORDINALITY
        AS item(value,ordinal)
      ORDER BY item.ordinal
    LOOP
      IF jsonb_typeof(delivery_value)<>'object'
         OR delivery_value->>'audience' NOT IN ('operator','customer') THEN
        RAISE EXCEPTION 'planned notification delivery is invalid'
          USING ERRCODE='22023';
      END IF;
      expected_context := CASE delivery_value->>'audience'
        WHEN 'customer' THEN source_event.payload->'customerContext'
        ELSE source_event.payload->'operatorContext'
          || CASE WHEN source_event.payload?'customerContext'
            THEN jsonb_build_object(
              'customer',source_event.payload->'customerContext'
            ) ELSE '{}'::jsonb END
        END;
      IF expected_context IS NULL OR jsonb_typeof(expected_context)<>'object'
         OR delivery_value->'context' IS DISTINCT FROM expected_context THEN
        RAISE EXCEPTION 'notification audience projection does not match'
          USING ERRCODE='42501';
      END IF;
      SELECT version.* INTO selected_rule
      FROM public.tenant_notification_rule_versions AS version
      WHERE version.tenant_id=source_event.tenant_id
        AND version.rule_id=(delivery_value->>'ruleId')::uuid
        AND version.version=(delivery_value->>'ruleVersion')::integer
        AND version.channel='email';
      IF NOT FOUND OR NOT EXISTS (
        SELECT 1
        FROM jsonb_array_elements(selected_rule.recipients) AS selector(value)
        WHERE selector.value->>'audience'=delivery_value->>'audience'
          AND (
            selector.value->>'kind'='explicit_email'
              AND selector.value->'authorized'='true'::jsonb
              AND selector.value->>'value'=delivery_value->>'recipient'
            OR selector.value->>'kind'='custom_email_field'
              AND expected_context #>> ARRAY[
                source_event.aggregate_type,'custom',selector.value->>'value'
              ]=delivery_value->>'recipient'
            OR selector.value->>'kind' NOT IN (
                'explicit_email','custom_email_field'
              )
              AND EXISTS (
                SELECT 1
                FROM jsonb_array_elements(
                  coalesce(fanout_inputs->'candidates','[]'::jsonb)
                ) AS candidate(value)
                WHERE candidate.value->>'email'=delivery_value->>'recipient'
                  AND candidate.value->>'audience'=delivery_value->>'audience'
                  AND candidate.value->'enabled'='true'::jsonb
                  AND candidate.value->'emailAllowed'='true'::jsonb
                  AND candidate.value->'kinds' ? (selector.value->>'kind')
                  AND (
                    NOT (selector.value?'value')
                    OR candidate.value->'values'->(selector.value->>'kind')
                         ? (selector.value->>'value')
                  )
              )
          )
      ) THEN
        RAISE EXCEPTION 'notification delivery recipient is not authorized'
          USING ERRCODE='42501';
      END IF;
    END LOOP;
  END IF;
  committed_result := app.commit_notification_fanout_v1(
    p_event_id,p_fence_token,p_deliveries,p_committed_at
  );
  -- V1 constructed webhook operator context without the nested customer-safe
  -- projection.  Correct every newly committed/replayed webhook atomically so
  -- email and webhook channels persist the same frozen audience envelope.
  UPDATE public.tenant_notification_deliveries AS delivery
  SET context=CASE delivery.audience
        WHEN 'customer' THEN source_event.payload->'customerContext'
        ELSE source_event.payload->'operatorContext'
          || CASE WHEN source_event.payload?'customerContext'
            THEN jsonb_build_object(
              'customer',source_event.payload->'customerContext'
            ) ELSE '{}'::jsonb END
      END,
      webhook_payload=jsonb_set(
        delivery.webhook_payload,'{context}',
        CASE delivery.audience
          WHEN 'customer' THEN source_event.payload->'customerContext'
          ELSE source_event.payload->'operatorContext'
            || CASE WHEN source_event.payload?'customerContext'
              THEN jsonb_build_object(
                'customer',source_event.payload->'customerContext'
              ) ELSE '{}'::jsonb END
        END,
        false
      )
  WHERE delivery.tenant_id=source_event.tenant_id
    AND delivery.event_id=p_event_id
    AND delivery.channel='webhook'
    AND delivery.parent_delivery_id IS NULL
    AND (
      delivery.context IS DISTINCT FROM CASE delivery.audience
        WHEN 'customer' THEN source_event.payload->'customerContext'
        ELSE source_event.payload->'operatorContext'
          || CASE WHEN source_event.payload?'customerContext'
            THEN jsonb_build_object(
              'customer',source_event.payload->'customerContext'
            ) ELSE '{}'::jsonb END
        END
      OR delivery.webhook_payload->'context' IS DISTINCT FROM
        CASE delivery.audience
          WHEN 'customer' THEN source_event.payload->'customerContext'
          ELSE source_event.payload->'operatorContext'
            || CASE WHEN source_event.payload?'customerContext'
              THEN jsonb_build_object(
                'customer',source_event.payload->'customerContext'
              ) ELSE '{}'::jsonb END
        END
    );
  RETURN committed_result;
END;
$function$;

ALTER FUNCTION app.commit_notification_fanout_v2(
  uuid,uuid,jsonb,timestamp with time zone
) OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION app.commit_notification_fanout_v2(
  uuid,uuid,jsonb,timestamp with time zone
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.commit_notification_fanout_v2(
  uuid,uuid,jsonb,timestamp with time zone
) TO periapsis_notifier;
--> statement-breakpoint

-- Transition notes are system-owned immutable comments with a frozen human
-- author. They are materialized in the same transaction as the state change.
CREATE FUNCTION app.private_append_ticket_transition_comment_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_body_markdown text,
  p_body_html text
)
RETURNS uuid
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  operation_at timestamp with time zone := transaction_timestamp();
  result_comment uuid := uuidv7();
  result_revision uuid := uuidv7();
  display_name_value text;
BEGIN
  IF p_aggregate_kind IS NULL OR p_ticket_id IS NULL
     OR (uuid_extract_version(p_ticket_id)=7) IS NOT TRUE
     OR NOT app.private_ticket_comment_markdown_valid_v1(p_body_markdown)
     OR NOT app.private_ticket_comment_html_valid_v1(p_body_html) THEN
    RAISE EXCEPTION 'transition comment is invalid' USING ERRCODE='22023';
  END IF;
  SELECT identity.display_name INTO STRICT display_name_value
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=context_tenant
    AND membership.id=actor_membership
    AND membership.user_id=actor_user
    AND membership.status='active' AND identity.active
    AND app.private_ticket_comment_display_name_valid_v1(
      identity.display_name
    );
  PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
  INSERT INTO public.ticket_comments(
    id,tenant_id,alert_id,case_id,visibility,body_markdown,body_html,
    author_membership_id,author_user_id,origin,revision,
    mentioned_user_ids,created_at,updated_at
  ) VALUES (
    result_comment,context_tenant,
    CASE WHEN p_aggregate_kind='alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind='case' THEN p_ticket_id END,
    'private',p_body_markdown,p_body_html,actor_membership,actor_user,
    'system',1,ARRAY[]::uuid[],operation_at,operation_at
  );
  INSERT INTO public.ticket_comment_author_snapshots(
    tenant_id,comment_id,audience,author_membership_id,author_user_id,
    author_contact_id,display_name,origin,created_at,editable_until
  ) VALUES (
    context_tenant,result_comment,'operator',actor_membership,actor_user,
    NULL,display_name_value,'system',operation_at,
    operation_at+interval '15 minutes'
  );
  INSERT INTO public.ticket_comment_revisions(
    id,tenant_id,comment_id,revision,body_markdown,body_html,reason,
    edited_by_membership_id,edited_by_user_id,edited_at
  ) VALUES (
    result_revision,context_tenant,result_comment,1,p_body_markdown,
    p_body_html,'original_comment',actor_membership,actor_user,operation_at
  );
  RETURN result_comment;
END;
$function$;

ALTER FUNCTION app.private_append_ticket_transition_comment_v1(
  public.ticket_aggregate_kind,uuid,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_ticket_transition_comment_v1(
  public.ticket_aggregate_kind,uuid,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

DO $derive_ticket_mutation_v2$
DECLARE
  public_definition text;
  bulk_definition text;
  target_definition text;
  successor_definition text;
  old_block constant text := $old$
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
$old$;
  new_block constant text := $new$
  IF p_action = 'transition' AND coalesce(p_comment_markdown, '') <> '' THEN
    transition_comment_id := app.private_append_ticket_transition_comment_v1(
      p_aggregate_kind,p_ticket_id,p_comment_markdown,
      coalesce(p_comment_html,'')
    );
    PERFORM app.private_append_ticket_comment_side_effects_v1(
      p_aggregate_kind,p_ticket_id,p_next_version,transition_comment_id,1,
      'private','system',NULL,'commented',transaction_timestamp(),
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,
      p_authentication_method
    );
  END IF;
$new$;
BEGIN
  SELECT pg_get_functiondef(
    'app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure
  ) INTO public_definition;
  SELECT pg_get_functiondef(
    'app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure
  ) INTO bulk_definition;
  SELECT pg_get_functiondef(
    'app.apply_ticket_bulk_target_v1(jsonb)'::regprocedure
  ) INTO target_definition;
  IF encode(sha256(convert_to(public_definition,'UTF8')),'hex')<>
       '4cb31ff7a6147a494ff014b89b8d5d03ccd21058fcc60259bb04771b431973c6'
     OR encode(sha256(convert_to(bulk_definition,'UTF8')),'hex')<>
       'dc5a2dc1747baa9a0ccd813e87ec1c521d894f9bcca203001aa064d5f91306c9'
     OR encode(sha256(convert_to(target_definition,'UTF8')),'hex')<>
       '62f40c0552913515ea5da9d535b593423025c532641e73975b83a07d520377b0'
     OR strpos(public_definition,old_block)=0
     OR strpos(bulk_definition,old_block)=0 THEN
    RAISE EXCEPTION 'ticket mutation predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;
  successor_definition := replace(
    replace(public_definition,'apply_tenant_ticket_mutation_v1',
      'apply_tenant_ticket_mutation_v2'),old_block,new_block
  );
  successor_definition := replace(
    successor_definition,'  event_action text;',
    E'  event_action text;\n  transition_comment_id uuid;'
  );
  EXECUTE successor_definition;
  successor_definition := replace(
    replace(bulk_definition,'private_apply_ticket_bulk_mutation_v1',
      'private_apply_ticket_bulk_mutation_v2'),old_block,new_block
  );
  successor_definition := replace(
    successor_definition,'  event_action text;',
    E'  event_action text;\n  transition_comment_id uuid;'
  );
  EXECUTE successor_definition;
  successor_definition := replace(
    replace(target_definition,'apply_ticket_bulk_target_v1',
      'apply_ticket_bulk_target_v2'),
    'private_apply_ticket_bulk_mutation_v1',
    'private_apply_ticket_bulk_mutation_v2'
  );
  IF strpos(successor_definition,'private_apply_ticket_bulk_mutation_v1')<>0
  THEN
    RAISE EXCEPTION 'ticket bulk mutation V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$derive_ticket_mutation_v2$;

ALTER FUNCTION app.apply_tenant_ticket_mutation_v2(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,
  text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,
  uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_apply_ticket_bulk_mutation_v2(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,
  text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,
  uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.apply_ticket_bulk_target_v2(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.apply_tenant_ticket_mutation_v2(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,
  text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,
  uuid,uuid,inet,text,text
),app.private_apply_ticket_bulk_mutation_v2(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,
  text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,
  uuid,uuid,inet,text,text
),app.apply_ticket_bulk_target_v2(jsonb)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.apply_tenant_ticket_mutation_v2(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,
  text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,
  uuid,uuid,inet,text,text
) TO periapsis_api;
GRANT EXECUTE ON FUNCTION app.apply_ticket_bulk_target_v2(jsonb)
TO periapsis_worker;
--> statement-breakpoint

-- Copy a source comment's exact current immutable revision while the source
-- aggregate is locked.  The copied aggregate always starts at revision 1;
-- source revision provenance remains separate and append-only.
CREATE FUNCTION app.private_copy_ticket_escalation_comments_v1(
  p_source_alert_id uuid,
  p_destination_case_id uuid,
  p_source_alert_version integer,
  p_destination_case_version integer,
  p_escalation_link_id uuid,
  p_source_comment_ids uuid[],
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
  source_row record;
  copied_comment_id uuid;
  copied_revision_id uuid;
  selected_count integer := 0;
  mentioned_users uuid[];
BEGIN
  IF p_source_alert_id IS NULL OR p_destination_case_id IS NULL
     OR p_escalation_link_id IS NULL
     OR p_source_alert_version NOT BETWEEN 1 AND 2147483647
     OR p_destination_case_version NOT BETWEEN 1 AND 2147483647
     OR NOT app.private_ticket_comment_uuid_array_valid_v1(
       p_source_comment_ids,100
     ) OR NOT app.private_ticket_comment_timestamp_valid_v1(p_operation_at)
  THEN
    RAISE EXCEPTION 'escalation comment copy input is invalid'
      USING ERRCODE='22023';
  END IF;
  IF NOT app.private_ticket_comment_operator_scope_allows_v1(
    'alert',p_source_alert_id,'public','read'
  ) THEN
    RAISE EXCEPTION 'escalation comment copy is not authorized'
      USING ERRCODE='42501';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1','enabled',true);
  FOR source_row IN
    SELECT comment.id AS source_comment_id,
           comment.revision AS source_revision,
           revision.id AS source_revision_id,
           revision.body_markdown,revision.body_html,
           snapshot.audience,snapshot.author_membership_id,
           snapshot.author_user_id,snapshot.author_contact_id,
           snapshot.display_name
    FROM public.ticket_comments AS comment
    JOIN public.ticket_comment_revisions AS revision
      ON revision.tenant_id=comment.tenant_id
     AND revision.comment_id=comment.id
     AND revision.revision=comment.revision
    JOIN public.ticket_comment_author_snapshots AS snapshot
      ON snapshot.tenant_id=comment.tenant_id
     AND snapshot.comment_id=comment.id
    WHERE comment.tenant_id=context_tenant
      AND comment.alert_id=p_source_alert_id
      AND comment.case_id IS NULL AND comment.visibility='public'
      AND comment.id=ANY(p_source_comment_ids)
    ORDER BY comment.id
    FOR UPDATE OF comment
  LOOP
    selected_count := selected_count+1;
    copied_comment_id := uuidv7();
    copied_revision_id := uuidv7();
    SELECT coalesce(array_agg(
             mention.mentioned_user_id ORDER BY mention.mentioned_user_id
           ),ARRAY[]::uuid[])
    INTO mentioned_users
    FROM public.ticket_comment_revision_mentions AS mention
    WHERE mention.tenant_id=context_tenant
      AND mention.revision_id=source_row.source_revision_id;
    INSERT INTO public.ticket_comments(
      id,tenant_id,case_id,visibility,body_markdown,body_html,
      author_membership_id,author_user_id,origin,revision,
      mentioned_user_ids,created_at,updated_at
    ) VALUES (
      copied_comment_id,context_tenant,p_destination_case_id,'public',
      source_row.body_markdown,source_row.body_html,
      source_row.author_membership_id,source_row.author_user_id,
      'escalation_copy',1,mentioned_users,p_operation_at,p_operation_at
    );
    INSERT INTO public.ticket_comment_author_snapshots(
      tenant_id,comment_id,audience,author_membership_id,author_user_id,
      author_contact_id,display_name,origin,created_at,editable_until
    ) VALUES (
      context_tenant,copied_comment_id,source_row.audience,
      source_row.author_membership_id,source_row.author_user_id,
      source_row.author_contact_id,source_row.display_name,'escalation_copy',
      p_operation_at,p_operation_at+interval '15 minutes'
    );
    INSERT INTO public.ticket_comment_revisions(
      id,tenant_id,comment_id,revision,body_markdown,body_html,reason,
      edited_by_membership_id,edited_by_user_id,edited_at
    ) VALUES (
      copied_revision_id,context_tenant,copied_comment_id,1,
      source_row.body_markdown,source_row.body_html,'original_comment',
      source_row.author_membership_id,source_row.author_user_id,p_operation_at
    );
    INSERT INTO public.dfir_attachment_case_links(
      id,tenant_id,attachment_id,case_id,source_alert_id,
      source_alert_version,escalation_link_id,created_by_membership_id,
      created_at
    )
    SELECT uuidv7(),context_tenant,relation.attachment_id,
           p_destination_case_id,p_source_alert_id,p_source_alert_version,
           p_escalation_link_id,actor_membership,p_operation_at
    FROM public.ticket_comment_revision_attachments AS relation
    WHERE relation.tenant_id=context_tenant
      AND relation.revision_id=source_row.source_revision_id
    ORDER BY relation.attachment_id
    ON CONFLICT (tenant_id,attachment_id,case_id) DO NOTHING;
    INSERT INTO public.ticket_comment_revision_attachments(
      id,tenant_id,revision_id,attachment_id,original_filename,visibility
    )
    SELECT uuidv7(),context_tenant,copied_revision_id,
           relation.attachment_id,relation.original_filename,
           relation.visibility
    FROM public.ticket_comment_revision_attachments AS relation
    WHERE relation.tenant_id=context_tenant
      AND relation.revision_id=source_row.source_revision_id
    ORDER BY relation.attachment_id;
    INSERT INTO public.ticket_comment_escalation_sources(
      id,tenant_id,copied_comment_id,source_comment_id,source_revision,
      source_alert_id,destination_case_id,legacy_unresolved,created_at
    ) VALUES (
      uuidv7(),context_tenant,copied_comment_id,
      source_row.source_comment_id,source_row.source_revision,
      p_source_alert_id,p_destination_case_id,false,p_operation_at
    );
    INSERT INTO public.ticket_comment_revision_mentions(
      id,tenant_id,revision_id,mentioned_membership_id,mentioned_user_id,
      display_name
    )
    SELECT uuidv7(),context_tenant,copied_revision_id,
           mention.mentioned_membership_id,mention.mentioned_user_id,
           mention.display_name
    FROM public.ticket_comment_revision_mentions AS mention
    WHERE mention.tenant_id=context_tenant
      AND mention.revision_id=source_row.source_revision_id
    ORDER BY mention.mentioned_membership_id;
    PERFORM app.private_append_ticket_comment_side_effects_v1(
      'case',p_destination_case_id,p_destination_case_version,
      copied_comment_id,1,'public','escalation_copy',
      source_row.author_contact_id,'commented',p_operation_at,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,
      p_authentication_method
    );
  END LOOP;
  IF selected_count<>cardinality(p_source_comment_ids) THEN
    RAISE EXCEPTION 'escalation comment selection is not exact and public'
      USING ERRCODE='22023';
  END IF;
END;
$function$;

ALTER FUNCTION app.private_copy_ticket_escalation_comments_v1(
  uuid,uuid,integer,integer,uuid,uuid[],timestamp with time zone,
  uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_copy_ticket_escalation_comments_v1(
  uuid,uuid,integer,integer,uuid,uuid[],timestamp with time zone,
  uuid,uuid,inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

DO $derive_ticket_escalation_v4$
DECLARE
  v1_definition text;
  v2_definition text;
  v3_definition text;
  successor_definition text;
  old_copy constant text := $old$
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
$old$;
  new_copy constant text := $new$
    PERFORM app.private_copy_ticket_escalation_comments_v1(
      source_alert.id,p_case_id,source_alert.version,final_case_version,
      (source_value ->> 'linkId')::uuid,selected_comments,operation_at,
      p_request_id,p_correlation_id,p_ip_address,p_user_agent,
      p_authentication_method
    );
$new$;
  replay_marker constant text := $marker$
    RETURN QUERY SELECT replay_command.result_case_id,
$marker$;
  replay_guard constant text := $guard$
    FOR source_value IN
      SELECT source.value
      FROM jsonb_array_elements(p_sources) WITH ORDINALITY
           AS source(value,ordinal)
      ORDER BY source.ordinal
    LOOP
      selected_comments := ARRAY(
        SELECT value::uuid
        FROM jsonb_array_elements_text(
          source_value -> 'publicCommentIds'
        ) AS selected(value)
        ORDER BY value::uuid
      );
      link_id := (source_value ->> 'linkId')::uuid;
      IF NOT EXISTS (
        SELECT 1
        FROM public.alert_case_links AS link
        WHERE link.tenant_id=context_tenant AND link.id=link_id
          AND link.alert_id=(source_value ->> 'alertId')::uuid
          AND link.case_id=replay_command.result_case_id
          AND link.public_comment_ids IS NOT DISTINCT FROM selected_comments
      ) OR (
        SELECT count(*)
        FROM public.ticket_comment_escalation_sources AS provenance
        JOIN public.ticket_comments AS copied
          ON copied.tenant_id=provenance.tenant_id
         AND copied.id=provenance.copied_comment_id
         AND copied.case_id=replay_command.result_case_id
         AND copied.origin='escalation_copy'
         AND copied.visibility='public' AND copied.revision=1
        JOIN public.ticket_comment_revisions AS source_revision
          ON source_revision.tenant_id=provenance.tenant_id
         AND source_revision.comment_id=provenance.source_comment_id
         AND source_revision.revision=provenance.source_revision
        WHERE provenance.tenant_id=context_tenant
          AND provenance.source_alert_id=(source_value ->> 'alertId')::uuid
          AND provenance.destination_case_id=replay_command.result_case_id
          AND NOT provenance.legacy_unresolved
          AND provenance.source_comment_id=ANY(selected_comments)
      ) IS DISTINCT FROM cardinality(selected_comments) THEN
        RAISE EXCEPTION 'replayed comment escalation provenance drifted'
          USING ERRCODE='55000';
      END IF;
    END LOOP;

    RETURN QUERY SELECT replay_command.result_case_id,
$guard$;
BEGIN
  SELECT pg_get_functiondef(
    'app.commit_tenant_ticket_escalation_v1(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure
  ) INTO v1_definition;
  SELECT pg_get_functiondef(
    'app.commit_tenant_ticket_escalation_v2(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure
  ) INTO v2_definition;
  SELECT pg_get_functiondef(
    'app.commit_tenant_ticket_escalation_v3(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure
  ) INTO v3_definition;
  IF encode(sha256(convert_to(v1_definition,'UTF8')),'hex')<>
       'df2c78da51ffcd80117ffc77a83d9859f06a343edaf40d63102cfde9bf32834c'
     OR encode(sha256(convert_to(v2_definition,'UTF8')),'hex')<>
       'b5b1b029351772e63f1ef424b05a3ddf093b6af25898d3269de560bef55523f0'
     OR encode(sha256(convert_to(v3_definition,'UTF8')),'hex')<>
       '2ea75f43598a6b9f1508a93d140a4befdf9e7bb3bd2d7dae88b59d6b99e9c21a'
     OR strpos(v1_definition,old_copy)=0
     OR strpos(v3_definition,replay_marker)=0 THEN
    RAISE EXCEPTION 'ticket escalation predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;
  successor_definition := replace(
    replace(v1_definition,'commit_tenant_ticket_escalation_v1',
      'private_commit_tenant_ticket_escalation_v4_base'),
    old_copy,new_copy
  );
  EXECUTE successor_definition;
  successor_definition := replace(
    replace(v2_definition,'commit_tenant_ticket_escalation_v2',
      'private_commit_tenant_ticket_escalation_v4_contacts'),
    'commit_tenant_ticket_escalation_v1',
    'private_commit_tenant_ticket_escalation_v4_base'
  );
  EXECUTE successor_definition;
  successor_definition := replace(
    replace(
      replace(v3_definition,'commit_tenant_ticket_escalation_v3',
        'commit_tenant_ticket_escalation_v4'),
      'commit_tenant_ticket_escalation_v2',
      'private_commit_tenant_ticket_escalation_v4_contacts'
    ),replay_marker,replay_guard
  );
  successor_definition := replace(
    successor_definition,'  selected_contacts uuid[];',
    E'  selected_contacts uuid[];\n  selected_comments uuid[];'
  );
  IF strpos(successor_definition,'commit_tenant_ticket_escalation_v2')<>0
     OR strpos(successor_definition,
       'replayed comment escalation provenance drifted')=0 THEN
    RAISE EXCEPTION 'ticket escalation V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$derive_ticket_escalation_v4$;

ALTER FUNCTION app.private_commit_tenant_ticket_escalation_v4_base(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_commit_tenant_ticket_escalation_v4_contacts(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.commit_tenant_ticket_escalation_v4(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_commit_tenant_ticket_escalation_v4_base(
    uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
    inet,text,text
  ),
  app.private_commit_tenant_ticket_escalation_v4_contacts(
    uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
    inet,text,text
  ),
  app.commit_tenant_ticket_escalation_v4(
    uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
    inet,text,text
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.commit_tenant_ticket_escalation_v4(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) TO periapsis_api;
--> statement-breakpoint

-- The API performs this lookup before invoking the write ABI.  Therefore the
-- replay lookup itself must attest every frozen V47 copy; otherwise an early
-- return could bypass commit_v4's replay guard.
CREATE FUNCTION app.lookup_tenant_ticket_escalation_replay_v3(
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE(
  result_path_alert_id uuid,
  result_case_id uuid,
  result_case_version integer,
  result_path_alert_version integer,
  result_metadata jsonb
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  replay public.ticket_commands%ROWTYPE;
  destination_case record;
  link_ids uuid[];
  expected_copy_count bigint;
  attested_copy_count bigint;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_key_digest IS NULL OR octet_length(p_key_digest)<>32
     OR p_key_digest=decode(repeat('00',32),'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_request_digest=decode(repeat('00',32),'hex') THEN
    RAISE EXCEPTION 'escalation replay identity is invalid'
      USING ERRCODE='22023';
  END IF;
  SELECT command.* INTO replay
  FROM public.ticket_commands AS command
  WHERE command.tenant_id=context_tenant
    AND command.actor_membership_id=actor_membership
    AND command.operation='ticket.escalate'
    AND command.key_digest=p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF replay.request_digest IS DISTINCT FROM p_request_digest
     OR replay.result_alert_id IS NULL OR replay.result_case_id IS NULL THEN
    RAISE EXCEPTION 'escalation replay identity conflicts'
      USING ERRCODE='23505',CONSTRAINT='ticket_commands_replay_key';
  END IF;
  SELECT case_row.assigned_team_id,
         case_row.created_by_user_id AS owner_user_id,
         case_row.assignee_user_id,case_row.claimed_by_user_id
  INTO destination_case
  FROM public.cases AS case_row
  WHERE case_row.tenant_id=context_tenant
    AND case_row.id=replay.result_case_id
  FOR SHARE;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
       'case.read',destination_case.assigned_team_id,
       destination_case.owner_user_id,destination_case.assignee_user_id,
       destination_case.claimed_by_user_id
     ) THEN
    -- Missing and live-hidden destinations are deliberately indistinguishable.
    RAISE EXCEPTION 'ticket escalation replay is unavailable'
      USING ERRCODE='P0002';
  END IF;
  IF jsonb_typeof(replay.result_metadata->'linkIds')<>'array' THEN
    RAISE EXCEPTION 'replayed comment escalation provenance drifted'
      USING ERRCODE='55000';
  END IF;
  BEGIN
    SELECT coalesce(array_agg(link_id ORDER BY link_id),ARRAY[]::uuid[])
    INTO link_ids
    FROM (
      SELECT value::uuid AS link_id
      FROM jsonb_array_elements_text(replay.result_metadata->'linkIds')
    ) AS parsed;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'replayed comment escalation provenance drifted'
      USING ERRCODE='55000';
  END;
  IF cardinality(link_ids)<>jsonb_array_length(
       replay.result_metadata->'linkIds'
     )
     OR cardinality(link_ids)<>(
       SELECT count(DISTINCT id) FROM unnest(link_ids) AS selected(id)
     )
     OR EXISTS (
       SELECT 1 FROM unnest(link_ids) AS selected(id)
       WHERE (uuid_extract_version(selected.id)=7) IS NOT TRUE
     )
     OR (
       SELECT count(*) FROM public.alert_case_links AS link
       WHERE link.tenant_id=context_tenant AND link.id=ANY(link_ids)
         AND link.case_id=replay.result_case_id
     )<>cardinality(link_ids) THEN
    RAISE EXCEPTION 'replayed comment escalation provenance drifted'
      USING ERRCODE='55000';
  END IF;
  IF EXISTS (
    SELECT 1
    FROM public.alert_case_links AS link
    JOIN public.alerts AS alert
      ON alert.tenant_id=link.tenant_id AND alert.id=link.alert_id
    WHERE link.tenant_id=context_tenant AND link.id=ANY(link_ids)
      AND (
        alert.deleted_at IS NOT NULL
        OR NOT app.private_current_ticket_scope_allows_v1(
          'alert.escalate',alert.assigned_team_id,alert.created_by,
          alert.assignee_user_id,alert.claimed_by_user_id
        )
        OR NOT app.private_ticket_comment_operator_scope_allows_v1(
          'alert',alert.id,'public','read'
        )
      )
  ) THEN
    RAISE EXCEPTION 'ticket escalation replay is unavailable'
      USING ERRCODE='P0002';
  END IF;

  WITH selected AS MATERIALIZED (
    SELECT link.alert_id,source_comment.id AS source_comment_id
    FROM public.alert_case_links AS link
    CROSS JOIN LATERAL unnest(link.public_comment_ids)
      AS source_comment(id)
    WHERE link.tenant_id=context_tenant AND link.id=ANY(link_ids)
      AND link.case_id=replay.result_case_id
  ), attested AS MATERIALIZED (
    SELECT selected.alert_id,selected.source_comment_id,
           count(*) AS matching_rows
    FROM selected
    JOIN public.ticket_comment_escalation_sources AS provenance
      ON provenance.tenant_id=context_tenant
     AND provenance.source_alert_id=selected.alert_id
     AND provenance.source_comment_id=selected.source_comment_id
     AND provenance.destination_case_id=replay.result_case_id
     AND provenance.created_at=replay.created_at
     AND NOT provenance.legacy_unresolved
    JOIN public.ticket_comments AS source_comment
      ON source_comment.tenant_id=provenance.tenant_id
     AND source_comment.id=provenance.source_comment_id
     AND source_comment.alert_id=provenance.source_alert_id
     AND source_comment.visibility='public'
    JOIN public.ticket_comment_revisions AS source_revision
      ON source_revision.tenant_id=provenance.tenant_id
     AND source_revision.comment_id=provenance.source_comment_id
     AND source_revision.revision=provenance.source_revision
    JOIN public.ticket_comment_author_snapshots AS source_author
      ON source_author.tenant_id=source_comment.tenant_id
     AND source_author.comment_id=source_comment.id
    JOIN public.ticket_comments AS copied_comment
      ON copied_comment.tenant_id=provenance.tenant_id
     AND copied_comment.id=provenance.copied_comment_id
     AND copied_comment.case_id=replay.result_case_id
     AND copied_comment.visibility='public'
     AND copied_comment.origin='escalation_copy'
     AND copied_comment.revision=1
     AND copied_comment.created_at=provenance.created_at
    JOIN public.ticket_comment_revisions AS copied_revision
      ON copied_revision.tenant_id=copied_comment.tenant_id
     AND copied_revision.comment_id=copied_comment.id
     AND copied_revision.revision=1
     AND copied_revision.body_markdown=source_revision.body_markdown
     AND copied_revision.body_html=source_revision.body_html
     AND copied_revision.edited_at=provenance.created_at
    JOIN public.ticket_comment_author_snapshots AS copied_author
      ON copied_author.tenant_id=copied_comment.tenant_id
     AND copied_author.comment_id=copied_comment.id
     AND copied_author.audience=source_author.audience
     AND copied_author.author_membership_id=source_author.author_membership_id
     AND copied_author.author_user_id=source_author.author_user_id
     AND copied_author.author_contact_id IS NOT DISTINCT FROM
         source_author.author_contact_id
     AND copied_author.display_name=source_author.display_name
     AND copied_author.origin='escalation_copy'
     AND copied_author.created_at=provenance.created_at
    WHERE NOT EXISTS (
      (SELECT relation.attachment_id,relation.original_filename,
              relation.visibility
       FROM public.ticket_comment_revision_attachments AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=source_revision.id
       EXCEPT
       SELECT relation.attachment_id,relation.original_filename,
              relation.visibility
       FROM public.ticket_comment_revision_attachments AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=copied_revision.id)
      UNION ALL
      (SELECT relation.attachment_id,relation.original_filename,
              relation.visibility
       FROM public.ticket_comment_revision_attachments AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=copied_revision.id
       EXCEPT
       SELECT relation.attachment_id,relation.original_filename,
              relation.visibility
       FROM public.ticket_comment_revision_attachments AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=source_revision.id)
    ) AND NOT EXISTS (
      (SELECT relation.mentioned_membership_id,
              relation.mentioned_user_id,relation.display_name
       FROM public.ticket_comment_revision_mentions AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=source_revision.id
       EXCEPT
       SELECT relation.mentioned_membership_id,
              relation.mentioned_user_id,relation.display_name
       FROM public.ticket_comment_revision_mentions AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=copied_revision.id)
      UNION ALL
      (SELECT relation.mentioned_membership_id,
              relation.mentioned_user_id,relation.display_name
       FROM public.ticket_comment_revision_mentions AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=copied_revision.id
       EXCEPT
       SELECT relation.mentioned_membership_id,
              relation.mentioned_user_id,relation.display_name
       FROM public.ticket_comment_revision_mentions AS relation
       WHERE relation.tenant_id=context_tenant
         AND relation.revision_id=source_revision.id)
    )
    GROUP BY selected.alert_id,selected.source_comment_id
  )
  SELECT (SELECT count(*) FROM selected),
         (SELECT count(*) FROM attested WHERE matching_rows=1)
  INTO expected_copy_count,attested_copy_count;
  IF expected_copy_count<>attested_copy_count OR EXISTS (
    SELECT 1
    FROM public.ticket_comment_escalation_sources AS provenance
    WHERE provenance.tenant_id=context_tenant
      AND provenance.destination_case_id=replay.result_case_id
      AND provenance.created_at=replay.created_at
      AND NOT provenance.legacy_unresolved
      AND NOT EXISTS (
        SELECT 1
        FROM public.alert_case_links AS link
        WHERE link.tenant_id=provenance.tenant_id
          AND link.id=ANY(link_ids)
          AND link.alert_id=provenance.source_alert_id
          AND provenance.source_comment_id=ANY(link.public_comment_ids)
      )
  ) THEN
    RAISE EXCEPTION 'replayed comment escalation provenance drifted'
      USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT replay.result_alert_id,replay.result_case_id,
    replay.result_version,
    (replay.result_metadata->>'pathAlertVersion')::integer,
    replay.result_metadata;
END;
$function$;

ALTER FUNCTION app.lookup_tenant_ticket_escalation_replay_v3(bytea,bytea)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.lookup_tenant_ticket_escalation_replay_v3(
  bytea,bytea
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.lookup_tenant_ticket_escalation_replay_v3(
  bytea,bytea
) TO periapsis_api;
--> statement-breakpoint

-- Fresh direct mentions are rechecked against the V47 operator-only scope at
-- relation insert time.  The escalation-copy branch remains historical and
-- exact through immutable source-revision provenance.
DO $harden_ticket_comment_mention_guard_v47$
DECLARE
  predecessor_definition text;
  successor_definition text;
BEGIN
  SELECT pg_get_functiondef(
    'app.guard_ticket_comment_mention_relation_v1()'::regprocedure
  ) INTO predecessor_definition;
  IF encode(sha256(convert_to(predecessor_definition,'UTF8')),'hex')<>
       '2ddca8992a1888fd843826d41f2c29eba5c3130566beeb97e7c67fa4d3636c45'
     OR strpos(
       predecessor_definition,'private_ticket_watcher_user_scope_allows_v1'
     )=0 THEN
    RAISE EXCEPTION 'ticket comment mention guard predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;
  successor_definition := replace(
    predecessor_definition,'private_ticket_watcher_user_scope_allows_v1',
    'private_ticket_watcher_user_scope_allows_v2'
  );
  IF successor_definition IS NOT DISTINCT FROM predecessor_definition
     OR strpos(
       successor_definition,'private_ticket_watcher_user_scope_allows_v1'
     )<>0 THEN
    RAISE EXCEPTION 'ticket comment mention guard V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$harden_ticket_comment_mention_guard_v47$;
--> statement-breakpoint

-- Async export authorization is repeated at ingress and for every worker
-- claim/page/terminal transition.  Comment scope is independent from generic
-- ticket read: public rows require comment.read and private rows additionally
-- require comment.private.  Customer exports require a real customer role,
-- one exact active contact, portal ticket read and portal.comment.public.
CREATE FUNCTION app.private_ticket_export_require_human_v2(
  p_actor jsonb,
  p_tenant_id uuid,
  p_kind public.ticket_aggregate_kind,
  p_audience text,
  p_capability text
)
RETURNS TABLE(
  actor_id uuid,membership_id uuid,principal text,
  customer_contact_id uuid,public_comments boolean,
  private_comments boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  contact_count integer;
  membership_role text;
BEGIN
  IF p_audience NOT IN ('operator','customer')
     OR p_capability NOT IN (
       'ticket_export.request','ticket_export.read','ticket_export.cancel'
     ) THEN
    RAISE EXCEPTION 'ticket export capability is invalid'
      USING ERRCODE='22023';
  END IF;
  membership_id := app.private_ticket_runtime_require_human_v1(
    p_actor,p_tenant_id
  );
  actor_id := app.context_user_id();
  PERFORM app.lock_current_tenant_authorization_state();
  SELECT membership.role INTO STRICT membership_role
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=p_tenant_id AND membership.id=membership_id
    AND membership.user_id=actor_id AND membership.status='active'
    AND identity.active;
  IF p_audience='operator' THEN
    IF membership_role IN (
         'customer_manager','customer_user','read_only'
       ) OR NOT app.private_ticket_runtime_has_any_scope_v1(
         app.private_ticket_runtime_permission_v1(p_kind,'read')
       ) THEN
      RAISE EXCEPTION 'ticket export permission is required'
        USING ERRCODE='42501';
    END IF;
    principal := 'operator';
    customer_contact_id := NULL;
    public_comments := app.private_ticket_runtime_has_any_scope_v1(
      p_kind::text||'.comment.read'
    );
    private_comments := public_comments
      AND app.private_ticket_runtime_has_any_scope_v1(
        p_kind::text||'.comment.private'
      );
  ELSE
    IF membership_role NOT IN (
      'customer_manager','customer_user','read_only'
    ) OR NOT app.current_tenant_human_has_exact_permission_v3(
      'portal.comment.public','own'
    ) OR NOT app.current_tenant_human_has_exact_permission_v3(
      CASE p_kind WHEN 'alert' THEN 'portal.alert.read'
        ELSE 'portal.case.read' END,'own'
    ) THEN
      RAISE EXCEPTION 'customer ticket export authority is required'
        USING ERRCODE='42501';
    END IF;
    SELECT count(*),min(contact.id)
    INTO contact_count,customer_contact_id
    FROM public.customer_contacts AS contact
    WHERE contact.tenant_id=p_tenant_id
      AND contact.linked_membership_id=membership_id
      AND contact.linked_user_id=actor_id
      AND contact.active AND contact.archived_at IS NULL;
    IF contact_count<>1 THEN
      RAISE EXCEPTION 'customer ticket export authority is required'
        USING ERRCODE='42501';
    END IF;
    principal := 'customer';
    public_comments := true;
    private_comments := false;
  END IF;
  RETURN NEXT;
END;
$function$;

CREATE FUNCTION app.private_ticket_export_requester_live_v2(
  p_job public.ticket_export_jobs
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  membership_role text;
BEGIN
  IF p_job.tenant_id IS DISTINCT FROM app.context_tenant_id() THEN
    RETURN false;
  END IF;
  PERFORM set_config('app.user_id',p_job.requester_user_id::text,true);
  PERFORM app.lock_current_tenant_authorization_state();
  SELECT membership.role INTO membership_role
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=p_job.tenant_id
    AND membership.id=p_job.owner_membership_id
    AND membership.user_id=p_job.requester_user_id
    AND membership.status='active' AND identity.active;
  IF NOT FOUND THEN RETURN false; END IF;
  IF app.current_tenant_membership_id()
       IS DISTINCT FROM p_job.owner_membership_id THEN
    RETURN false;
  END IF;
  IF p_job.audience='operator' THEN
    RETURN membership_role NOT IN (
      'customer_manager','customer_user','read_only'
    ) AND app.private_ticket_runtime_has_any_scope_v1(
      app.private_ticket_runtime_permission_v1(p_job.kind,'read')
    ) AND (p_job.comment_scope='none'
      OR app.private_ticket_runtime_has_any_scope_v1(
        p_job.kind::text||'.comment.read'
      )) AND (p_job.comment_scope<>'public_and_private'
      OR app.private_ticket_runtime_has_any_scope_v1(
        p_job.kind::text||'.comment.private'
      ));
  END IF;
  RETURN p_job.audience='customer'
    AND membership_role IN (
      'customer_manager','customer_user','read_only'
    ) AND p_job.comment_scope IN ('none','public')
    AND app.current_tenant_human_has_exact_permission_v3(
      'portal.comment.public','own'
    ) AND app.current_tenant_human_has_exact_permission_v3(
      CASE p_job.kind WHEN 'alert' THEN 'portal.alert.read'
        ELSE 'portal.case.read' END,'own'
    ) AND EXISTS (
      SELECT 1 FROM public.customer_contacts AS contact
      WHERE contact.tenant_id=p_job.tenant_id
        AND contact.id=p_job.customer_contact_id
        AND contact.linked_membership_id=p_job.owner_membership_id
        AND contact.linked_user_id=p_job.requester_user_id
        AND contact.active AND contact.archived_at IS NULL
    );
END;
$function$;

CREATE FUNCTION app.private_ticket_export_comment_visible_v1(
  p_job public.ticket_export_jobs,
  p_ticket_id uuid,
  p_visibility public.ticket_comment_visibility
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  IF p_job.tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_ticket_id IS NULL OR p_visibility IS NULL THEN
    RETURN false;
  END IF;
  IF p_job.audience='operator' THEN
    RETURN app.private_ticket_comment_user_scope_allows_v1(
      p_job.tenant_id,p_job.kind,p_ticket_id,p_job.requester_user_id,
      p_visibility
    );
  END IF;
  RETURN p_job.audience='customer' AND p_visibility='public'
    AND app.private_ticket_comment_portal_scope_allows_v1(
      p_job.kind,p_ticket_id,p_job.customer_contact_id
    );
END;
$function$;

ALTER FUNCTION app.private_ticket_export_require_human_v2(
  jsonb,uuid,public.ticket_aggregate_kind,text,text
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_export_requester_live_v2(
  public.ticket_export_jobs
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_export_comment_visible_v1(
  public.ticket_export_jobs,uuid,public.ticket_comment_visibility
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_require_human_v2(
  jsonb,uuid,public.ticket_aggregate_kind,text,text
),app.private_ticket_export_requester_live_v2(public.ticket_export_jobs),
app.private_ticket_export_comment_visible_v1(
  public.ticket_export_jobs,uuid,public.ticket_comment_visibility
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- All predecessor public JSON ABIs still call these private V1 names.  During
-- the quiesced, transactional V47 cutover the names become narrow forwarders
-- to the hardened successors, so no authorization branch can remain stale.
CREATE OR REPLACE FUNCTION app.private_ticket_export_require_human_v1(
  p_actor jsonb,p_tenant_id uuid,p_kind public.ticket_aggregate_kind,
  p_audience text,p_capability text
)
RETURNS TABLE(
  actor_id uuid,membership_id uuid,principal text,
  customer_contact_id uuid,public_comments boolean,
  private_comments boolean
)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.private_ticket_export_require_human_v2(
    p_actor,p_tenant_id,p_kind,p_audience,p_capability
  )
$function$;

CREATE OR REPLACE FUNCTION app.private_ticket_export_requester_live_v1(
  p_job public.ticket_export_jobs
)
RETURNS boolean
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT app.private_ticket_export_requester_live_v2(p_job)
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_cell_v2(
  p_job public.ticket_export_jobs,
  p_ticket_id uuid,
  p_comment_id uuid,
  p_column jsonb
)
RETURNS text
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  value text := '';
  core_key text;
BEGIN
  IF p_comment_id IS NULL THEN
    RETURN app.private_ticket_export_cell_v1(
      p_job,p_ticket_id,NULL,p_column
    );
  END IF;
  IF p_column->>'source'='core' THEN
    core_key := p_column->>'coreKey';
    SELECT CASE core_key
      WHEN 'ticket' THEN revision.body_markdown
      WHEN 'customer_visibility' THEN comment.visibility::text
      WHEN 'created' THEN to_char(snapshot.created_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      WHEN 'updated' THEN to_char(revision.edited_at AT TIME ZONE 'UTC',
        'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      ELSE '' END
    INTO value
    FROM public.ticket_comments AS comment
    JOIN public.ticket_comment_revisions AS revision
      ON revision.tenant_id=comment.tenant_id
     AND revision.comment_id=comment.id
     AND revision.revision=comment.revision
    JOIN public.ticket_comment_author_snapshots AS snapshot
      ON snapshot.tenant_id=comment.tenant_id
     AND snapshot.comment_id=comment.id
    WHERE comment.tenant_id=p_job.tenant_id AND comment.id=p_comment_id
      AND (p_job.kind='alert' AND comment.alert_id=p_ticket_id
        OR p_job.kind='case' AND comment.case_id=p_ticket_id)
      AND app.private_ticket_export_comment_visible_v1(
        p_job,p_ticket_id,comment.visibility
      );
  END IF;
  value := coalesce(value,'');
  value := replace(replace(value,chr(8234),''),chr(8235),'');
  RETURN left(value,32768);
END;
$function$;

DO $derive_ticket_export_page_v2$
DECLARE
  predecessor_definition text;
  successor_definition text;
  old_alert_customer constant text := $old$
p_job.audience = 'customer' AND alert.customer_visible AND EXISTS (
        SELECT 1 FROM public.ticket_customer_contacts AS link
        WHERE link.tenant_id = p_job.tenant_id AND link.alert_id = alert.id
          AND link.case_id IS NULL AND link.contact_id = p_job.customer_contact_id
          AND link.archived_at IS NULL
      )
$old$;
  new_alert_customer constant text := $new$
p_job.audience = 'customer'
        AND app.private_ticket_comment_portal_scope_allows_v1(
          'alert',alert.id,p_job.customer_contact_id
        )
$new$;
  old_case_customer constant text := $old$
p_job.audience = 'customer' AND case_row.customer_visible AND EXISTS (
        SELECT 1 FROM public.ticket_customer_contacts AS link
        WHERE link.tenant_id = p_job.tenant_id AND link.case_id = case_row.id
          AND link.alert_id IS NULL AND link.contact_id = p_job.customer_contact_id
          AND link.archived_at IS NULL
      )
$old$;
  new_case_customer constant text := $new$
p_job.audience = 'customer'
        AND app.private_ticket_comment_portal_scope_allows_v1(
          'case',case_row.id,p_job.customer_contact_id
        )
$new$;
  old_comment_filter constant text := $old$
        AND p_job.comment_scope = 'public_and_private')
  ), ordered AS (
$old$;
  new_comment_filter constant text := $new$
        AND p_job.comment_scope = 'public_and_private')
      AND app.private_ticket_export_comment_visible_v1(
        p_job,ticket.ticket_id,comment.visibility
      )
  ), ordered AS (
$new$;
BEGIN
  SELECT pg_get_functiondef(
    'app.private_ticket_export_page_document_v1(public.ticket_export_jobs,text,integer,boolean)'::regprocedure
  ) INTO predecessor_definition;
  IF encode(sha256(convert_to(predecessor_definition,'UTF8')),'hex')<>
       'c1fb00a3e265ea25030584c1bb59331e5c4fe42ba38eb8b66541aff5e949c608'
     OR strpos(predecessor_definition,btrim(old_alert_customer,E'\r\n'))=0
     OR strpos(predecessor_definition,btrim(old_case_customer,E'\r\n'))=0
     OR strpos(predecessor_definition,btrim(old_comment_filter,E'\r\n'))=0 THEN
    RAISE EXCEPTION 'ticket export page predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;
  successor_definition := replace(
    predecessor_definition,'private_ticket_export_page_document_v1',
    'private_ticket_export_page_document_v2'
  );
  successor_definition := replace(
    successor_definition,'private_ticket_export_cell_v1',
    'private_ticket_export_cell_v2'
  );
  successor_definition := replace(
    successor_definition,btrim(old_alert_customer,E'\r\n'),
    btrim(new_alert_customer,E'\r\n')
  );
  successor_definition := replace(
    successor_definition,btrim(old_case_customer,E'\r\n'),
    btrim(new_case_customer,E'\r\n')
  );
  successor_definition := replace(
    successor_definition,btrim(old_comment_filter,E'\r\n'),
    btrim(new_comment_filter,E'\r\n')
  );
  IF strpos(successor_definition,'private_ticket_export_cell_v1')<>0
     OR strpos(
       successor_definition,'private_ticket_export_comment_visible_v1'
     )=0 THEN
    RAISE EXCEPTION 'ticket export page V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$derive_ticket_export_page_v2$;

ALTER FUNCTION app.private_ticket_export_cell_v2(
  public.ticket_export_jobs,uuid,uuid,jsonb
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_ticket_export_page_document_v2(
  public.ticket_export_jobs,text,integer,boolean
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_cell_v2(
  public.ticket_export_jobs,uuid,uuid,jsonb
),app.private_ticket_export_page_document_v2(
  public.ticket_export_jobs,text,integer,boolean
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;

CREATE OR REPLACE FUNCTION app.private_ticket_export_page_document_v1(
  p_job public.ticket_export_jobs,p_after text,p_limit integer,
  p_snapshot_keys boolean
)
RETURNS jsonb
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT app.private_ticket_export_page_document_v2(
    p_job,p_after,p_limit,p_snapshot_keys
  )
$function$;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_export_scope_allowed_v1(
  p_comment_scope text,p_public_comments boolean,p_private_comments boolean
)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path=pg_catalog
AS $function$
  SELECT p_comment_scope IN ('none','public','public_and_private')
    AND (p_comment_scope='none' OR p_public_comments)
    AND (p_comment_scope<>'public_and_private' OR p_private_comments)
$function$;

CREATE FUNCTION app.commit_ticket_export_request_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
DECLARE
  definition jsonb := request #> '{next,definition}';
  authority record;
  request_tenant uuid;
  request_kind public.ticket_aggregate_kind;
BEGIN
  request_tenant := app.private_ticket_runtime_uuid_v1(
    definition->>'tenantId'
  );
  BEGIN
    request_kind := (definition->>'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket export request kind is invalid'
      USING ERRCODE='22023';
  END;
  SELECT admitted.* INTO STRICT authority
  FROM app.private_ticket_export_require_human_v2(
    request->'actor',request_tenant,request_kind,definition->>'audience',
    'ticket_export.request'
  ) AS admitted;
  IF NOT app.private_ticket_export_scope_allowed_v1(
    definition->>'commentScope',authority.public_comments,
    authority.private_comments
  ) THEN
    RAISE EXCEPTION 'ticket export comment scope is not authorized'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT legacy.response
  FROM app.commit_ticket_export_request_v1(request) AS legacy;
END;
$function$;

CREATE FUNCTION app.lookup_ticket_export_replay_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
DECLARE
  legacy_response jsonb;
  job public.ticket_export_jobs%ROWTYPE;
BEGIN
  SELECT legacy.response INTO legacy_response
  FROM app.lookup_ticket_export_replay_v1(request) AS legacy;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id=app.context_tenant_id()
    AND candidate.id=(legacy_response #>> '{record,definition,id}')::uuid;
  IF NOT FOUND OR NOT app.private_ticket_export_requester_live_v2(job) THEN
    RAISE EXCEPTION 'ticket export replay authority is required'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT legacy_response;
END;
$function$;

CREATE FUNCTION app.get_ticket_export_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
DECLARE
  legacy_response jsonb;
  job public.ticket_export_jobs%ROWTYPE;
BEGIN
  SELECT legacy.response INTO legacy_response
  FROM app.get_ticket_export_v1(request) AS legacy;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id=app.context_tenant_id()
    AND candidate.id=(legacy_response #>> '{record,definition,id}')::uuid;
  IF NOT FOUND OR NOT app.private_ticket_export_requester_live_v2(job) THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT legacy_response;
END;
$function$;

CREATE FUNCTION app.commit_ticket_export_owner_transition_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
DECLARE
  legacy_response jsonb;
  job public.ticket_export_jobs%ROWTYPE;
  job_id uuid := app.private_ticket_runtime_uuid_v1(
    request #>> '{next,definition,id}'
  );
BEGIN
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id=app.context_tenant_id()
    AND candidate.id=job_id;
  IF NOT FOUND OR NOT app.private_ticket_export_requester_live_v2(job) THEN
    RAISE EXCEPTION 'ticket export job is unavailable'
      USING ERRCODE='P0002';
  END IF;
  SELECT legacy.response INTO STRICT legacy_response
  FROM app.commit_ticket_export_owner_transition_v1(request) AS legacy;
  RETURN QUERY SELECT legacy_response;
END;
$function$;

CREATE FUNCTION app.resolve_ticket_export_access_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.resolve_ticket_export_access_v1(request)
$function$;

CREATE FUNCTION app.resolve_ticket_export_query_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.resolve_ticket_export_query_v1(request)
$function$;

ALTER FUNCTION app.private_ticket_export_scope_allowed_v1(
  text,boolean,boolean
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.commit_ticket_export_request_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.lookup_ticket_export_replay_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_ticket_export_v2(jsonb) OWNER TO periapsis_migrator;
ALTER FUNCTION app.commit_ticket_export_owner_transition_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_ticket_export_access_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.resolve_ticket_export_query_v2(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_export_scope_allowed_v1(
  text,boolean,boolean
),app.commit_ticket_export_request_v2(jsonb),
app.lookup_ticket_export_replay_v2(jsonb),app.get_ticket_export_v2(jsonb),
app.commit_ticket_export_owner_transition_v2(jsonb),
app.resolve_ticket_export_access_v2(jsonb),
app.resolve_ticket_export_query_v2(jsonb)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_export_request_v2(jsonb),
  app.lookup_ticket_export_replay_v2(jsonb),app.get_ticket_export_v2(jsonb),
  app.commit_ticket_export_owner_transition_v2(jsonb),
  app.resolve_ticket_export_access_v2(jsonb),
  app.resolve_ticket_export_query_v2(jsonb)
TO periapsis_api;
--> statement-breakpoint

-- The remaining application and worker surfaces keep their stable JSON
-- envelopes.  Their V1 implementations now enter only through the hardened
-- V47 private authorization/page helpers above, while the public V2 names make
-- the cutover explicit and allow every predecessor grant to be retired.
CREATE FUNCTION app.resolve_ticket_export_worker_access_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.resolve_ticket_export_worker_access_v1(request)
$function$;

CREATE FUNCTION app.select_ticket_export_claim_candidate_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.select_ticket_export_claim_candidate_v1(request)
$function$;

CREATE FUNCTION app.get_ticket_export_for_worker_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.get_ticket_export_for_worker_v1(request)
$function$;

CREATE FUNCTION app.get_revoked_ticket_export_for_worker_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.get_revoked_ticket_export_for_worker_v1(request)
$function$;

CREATE FUNCTION app.commit_ticket_export_worker_transition_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.commit_ticket_export_worker_transition_v1(request)
$function$;

CREATE FUNCTION app.commit_ticket_export_revocation_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.commit_ticket_export_revocation_v1(request)
$function$;

CREATE FUNCTION app.read_ticket_export_application_page_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.read_ticket_export_application_page_v1(request)
$function$;

ALTER FUNCTION app.resolve_ticket_export_worker_access_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.select_ticket_export_claim_candidate_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_ticket_export_for_worker_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.get_revoked_ticket_export_for_worker_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.commit_ticket_export_worker_transition_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.commit_ticket_export_revocation_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.read_ticket_export_application_page_v2(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.resolve_ticket_export_worker_access_v2(jsonb),
  app.select_ticket_export_claim_candidate_v2(jsonb),
  app.get_ticket_export_for_worker_v2(jsonb),
  app.get_revoked_ticket_export_for_worker_v2(jsonb),
  app.commit_ticket_export_worker_transition_v2(jsonb),
  app.commit_ticket_export_revocation_v2(jsonb),
  app.read_ticket_export_application_page_v2(jsonb)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION
  app.resolve_ticket_export_worker_access_v2(jsonb),
  app.select_ticket_export_claim_candidate_v2(jsonb),
  app.get_ticket_export_for_worker_v2(jsonb),
  app.get_revoked_ticket_export_for_worker_v2(jsonb),
  app.commit_ticket_export_worker_transition_v2(jsonb),
  app.commit_ticket_export_revocation_v2(jsonb),
  app.read_ticket_export_application_page_v2(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.claim_ticket_export_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.claim_ticket_export_v1(request)
$function$;

CREATE FUNCTION app.read_ticket_export_page_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.read_ticket_export_page_v1(request)
$function$;

CREATE FUNCTION app.record_ticket_export_manifest_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.record_ticket_export_manifest_v1(request)
$function$;

CREATE FUNCTION app.commit_ticket_export_success_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.commit_ticket_export_success_v1(request)
$function$;

CREATE FUNCTION app.report_ticket_export_failure_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.report_ticket_export_failure_v1(request)
$function$;

CREATE FUNCTION app.acknowledge_ticket_export_cancellation_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.acknowledge_ticket_export_cancellation_v1(request)
$function$;

CREATE FUNCTION app.reject_ticket_export_revocation_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.reject_ticket_export_revocation_v1(request)
$function$;

CREATE FUNCTION app.claim_ticket_export_artifact_reconciliation_v2(
  request jsonb
)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.claim_ticket_export_artifact_reconciliation_v1(request)
$function$;

CREATE FUNCTION app.finalize_ticket_export_artifact_reconciliation_v2(
  request jsonb
)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.finalize_ticket_export_artifact_reconciliation_v1(request)
$function$;

CREATE FUNCTION app.report_ticket_export_artifact_reconciliation_failure_v2(
  request jsonb
)
RETURNS TABLE(response jsonb)
LANGUAGE sql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT *
  FROM app.report_ticket_export_artifact_reconciliation_failure_v1(request)
$function$;

CREATE FUNCTION app.read_ticket_export_reconciliation_metrics_v2(
  request jsonb
)
RETURNS TABLE(response jsonb)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
  SELECT * FROM app.read_ticket_export_reconciliation_metrics_v1(request)
$function$;

ALTER FUNCTION app.claim_ticket_export_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.read_ticket_export_page_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.record_ticket_export_manifest_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.commit_ticket_export_success_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.report_ticket_export_failure_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.acknowledge_ticket_export_cancellation_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.reject_ticket_export_revocation_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.claim_ticket_export_artifact_reconciliation_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.finalize_ticket_export_artifact_reconciliation_v2(jsonb)
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.report_ticket_export_artifact_reconciliation_failure_v2(
  jsonb
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.read_ticket_export_reconciliation_metrics_v2(jsonb)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.claim_ticket_export_v2(jsonb),
  app.read_ticket_export_page_v2(jsonb),
  app.record_ticket_export_manifest_v2(jsonb),
  app.commit_ticket_export_success_v2(jsonb),
  app.report_ticket_export_failure_v2(jsonb),
  app.acknowledge_ticket_export_cancellation_v2(jsonb),
  app.reject_ticket_export_revocation_v2(jsonb),
  app.claim_ticket_export_artifact_reconciliation_v2(jsonb),
  app.finalize_ticket_export_artifact_reconciliation_v2(jsonb),
  app.report_ticket_export_artifact_reconciliation_failure_v2(jsonb),
  app.read_ticket_export_reconciliation_metrics_v2(jsonb)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.claim_ticket_export_v2(jsonb),
  app.read_ticket_export_page_v2(jsonb),
  app.record_ticket_export_manifest_v2(jsonb),
  app.commit_ticket_export_success_v2(jsonb),
  app.report_ticket_export_failure_v2(jsonb),
  app.acknowledge_ticket_export_cancellation_v2(jsonb),
  app.reject_ticket_export_revocation_v2(jsonb),
  app.claim_ticket_export_artifact_reconciliation_v2(jsonb),
  app.finalize_ticket_export_artifact_reconciliation_v2(jsonb),
  app.report_ticket_export_artifact_reconciliation_failure_v2(jsonb),
  app.read_ticket_export_reconciliation_metrics_v2(jsonb)
TO periapsis_worker;
--> statement-breakpoint

-- Derive the broad notification catalog/role checks from the last sealed
-- readiness, but make the dispatch ABI generation explicit: the V47 loader
-- and commit are required and both predecessors must be absent from the
-- notifier's effective privileges.
DO $derive_notification_schema_readiness_v3_base$
DECLARE
  predecessor_definition text;
  successor_definition text;
  old_loader constant text :=
    '(''app.load_notification_fanout_inputs_v2(uuid,uuid)'', ''periapsis_notification_dispatch_owner'', false, true),';
  new_loader constant text :=
    '(''app.load_notification_fanout_inputs_v2(uuid,uuid)'', ''periapsis_notification_dispatch_owner'', false, false),' || chr(10) ||
    '      (''app.load_notification_fanout_inputs_v3(uuid,uuid)'', ''periapsis_notification_dispatch_owner'', false, true),';
  old_commit constant text :=
    '(''app.commit_notification_fanout_v1(uuid,uuid,jsonb,timestamp with time zone)'', ''periapsis_notification_dispatch_owner'', false, true),';
  new_commit constant text :=
    '(''app.commit_notification_fanout_v1(uuid,uuid,jsonb,timestamp with time zone)'', ''periapsis_notification_dispatch_owner'', false, false),' || chr(10) ||
    '      (''app.commit_notification_fanout_v2(uuid,uuid,jsonb,timestamp with time zone)'', ''periapsis_notification_dispatch_owner'', false, true),';
BEGIN
  SELECT pg_get_functiondef(
    'app.notification_schema_readiness_v2()'::regprocedure
  ) INTO predecessor_definition;
  IF encode(sha256(convert_to(predecessor_definition,'UTF8')),'hex')<>
       '169670b74c6f87271e4be0c0c3a7b7dcc3afe81844e85fe9fb3be148e1322089'
     OR strpos(predecessor_definition,old_loader)=0
     OR strpos(predecessor_definition,old_commit)=0 THEN
    RAISE EXCEPTION 'notification readiness predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;
  successor_definition := replace(
    predecessor_definition,'notification_schema_readiness_v2',
    'private_notification_schema_readiness_v3_base'
  );
  successor_definition := replace(
    successor_definition,old_loader,new_loader
  );
  successor_definition := replace(
    successor_definition,old_commit,new_commit
  );
  IF strpos(successor_definition,old_loader)<>0
     OR strpos(successor_definition,old_commit)<>0
     OR strpos(successor_definition,'load_notification_fanout_inputs_v3')=0
     OR strpos(successor_definition,'commit_notification_fanout_v2')=0 THEN
    RAISE EXCEPTION 'notification readiness V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$derive_notification_schema_readiness_v3_base$;

CREATE FUNCTION app.notification_schema_readiness_v3()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  expected record;
  function_oid regprocedure;
  relation_name text;
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_notification_admin_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_notification_readiness_owner'
    ) AND (role.rolcanlogin OR role.rolsuper OR role.rolcreatedb
      OR role.rolcreaterole OR role.rolinherit OR role.rolreplication
      OR role.rolbypassrls)
  ) OR (
    SELECT count(*) FROM pg_roles AS role
    WHERE role.rolname IN (
      'periapsis_notification_admin_owner',
      'periapsis_notification_dispatch_owner',
      'periapsis_notification_readiness_owner'
    )
  )<>3 THEN
    RETURN false;
  END IF;
  FOREACH relation_name IN ARRAY ARRAY[
    'tenant_notification_templates','tenant_notification_template_versions',
    'tenant_notification_rules','tenant_notification_rule_versions',
    'tenant_notification_secret_versions',
    'tenant_notification_smtp_configurations',
    'tenant_notification_smtp_configuration_versions',
    'tenant_notification_webhook_configurations',
    'tenant_notification_webhook_configuration_versions',
    'tenant_notification_fanout_snapshots','tenant_notification_deliveries',
    'tenant_notification_delivery_attempts','tenant_notification_commands'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid=class.relnamespace
      WHERE namespace.nspname='public' AND class.relname=relation_name
        AND class.relkind='r' AND class.relrowsecurity
        AND class.relforcerowsecurity
        AND pg_get_userbyid(class.relowner)='periapsis_migrator'
    ) OR has_table_privilege(
      'periapsis_api',format('public.%I',relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_notifier',format('public.%I',relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) THEN RETURN false; END IF;
  END LOOP;
  FOR expected IN
    SELECT * FROM (VALUES
      ('app.claim_notification_fanout_batch_v1(text,integer,integer,timestamp with time zone)','periapsis_notification_dispatch_owner',false,true),
      ('app.load_notification_fanout_inputs_v1(uuid,uuid)','periapsis_notification_dispatch_owner',false,false),
      ('app.load_notification_fanout_inputs_v2(uuid,uuid)','periapsis_notification_dispatch_owner',false,false),
      ('app.load_notification_fanout_inputs_v3(uuid,uuid)','periapsis_notification_dispatch_owner',false,true),
      ('app.commit_notification_fanout_v1(uuid,uuid,jsonb,timestamp with time zone)','periapsis_notification_dispatch_owner',false,false),
      ('app.commit_notification_fanout_v2(uuid,uuid,jsonb,timestamp with time zone)','periapsis_notification_dispatch_owner',false,true),
      ('app.claim_notification_delivery_batch_v1(text,integer,integer,timestamp with time zone)','periapsis_notification_dispatch_owner',false,true),
      ('app.claim_notification_webhook_delivery_batch_v1(text,integer,integer,timestamp with time zone)','periapsis_notification_dispatch_owner',false,true),
      ('app.load_pinned_smtp_configuration_v1(uuid,text,uuid,integer)','periapsis_notification_dispatch_owner',false,true),
      ('app.private_require_notification_admin_v1()','periapsis_notification_admin_owner',false,false),
      ('app.verify_notification_keyring_v1(smallint[])','periapsis_notification_readiness_owner',true,false)
    ) AS functions(signature,expected_owner,api_execute,notifier_execute)
  LOOP
    function_oid:=to_regprocedure(expected.signature);
    IF function_oid IS NULL OR (
      SELECT pg_get_userbyid(procedure.proowner)
          IS DISTINCT FROM expected.expected_owner
        OR procedure.prosecdef IS NOT TRUE
        OR procedure.proconfig[1] NOT LIKE 'search_path=pg_catalog%'
      FROM pg_proc AS procedure WHERE procedure.oid=function_oid
    ) OR EXISTS (
      SELECT 1 FROM pg_proc AS procedure
      CROSS JOIN LATERAL aclexplode(coalesce(
        procedure.proacl,acldefault('f',procedure.proowner)
      )) AS privilege
      WHERE procedure.oid=function_oid AND privilege.grantee=0
        AND privilege.privilege_type='EXECUTE'
    )
      OR has_function_privilege('periapsis_api',function_oid,'EXECUTE')
           IS DISTINCT FROM expected.api_execute
      OR has_function_privilege('periapsis_notifier',function_oid,'EXECUTE')
           IS DISTINCT FROM expected.notifier_execute THEN
      RETURN false;
    END IF;
  END LOOP;
  FOR expected IN
    SELECT * FROM (VALUES
      ('app.private_ticket_comment_user_scope_allows_v1(uuid,public.ticket_aggregate_kind,uuid,uuid,public.ticket_comment_visibility)',
       'c89fb89b17f150308cd756f42bc5b375e71e00ade5de72226b28f11d09edc11e',
       'periapsis_migrator','periapsis_notification_dispatch_owner'),
      ('app.private_notification_operator_candidates_v2(uuid,uuid)',
       'cbd91c42e30ff5022a677cdc0651a7c3381d5df8cf264faa4b8c9ad807c0b1cf',
       'periapsis_migrator','periapsis_notification_dispatch_owner'),
      ('app.load_notification_fanout_inputs_v3(uuid,uuid)',
       '8df9d4fbb3a72957036c97e28a75ec712953f3086b0ff9c796c182e71a64b7c2',
       'periapsis_notification_dispatch_owner','periapsis_notifier'),
      ('app.commit_notification_fanout_v2(uuid,uuid,jsonb,timestamp with time zone)',
       '1ab4c4a5d6cbfffa5f689a020a33d743c9a711f8451334114e666f53cb20b62d',
       'periapsis_notification_dispatch_owner','periapsis_notifier')
    ) AS functions(signature,definition_hash,expected_owner,execute_role)
  LOOP
    function_oid := to_regprocedure(expected.signature);
    IF function_oid IS NULL OR (
      SELECT pg_get_userbyid(procedure.proowner)
        IS DISTINCT FROM expected.expected_owner
        OR procedure.prosecdef IS NOT TRUE
        OR procedure.proconfig[1] NOT LIKE 'search_path=pg_catalog%'
        OR encode(sha256(convert_to(
             pg_get_functiondef(procedure.oid),'UTF8'
           )),'hex') IS DISTINCT FROM expected.definition_hash
      FROM pg_proc AS procedure WHERE procedure.oid=function_oid
    ) OR NOT has_function_privilege(
      expected.execute_role,function_oid,'EXECUTE'
    ) OR EXISTS (
      SELECT 1 FROM pg_proc AS procedure
      CROSS JOIN LATERAL aclexplode(coalesce(
        procedure.proacl,acldefault('f',procedure.proowner)
      )) AS privilege
      WHERE procedure.oid=function_oid AND privilege.grantee=0
        AND privilege.privilege_type='EXECUTE'
    ) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN NOT has_function_privilege(
      'periapsis_notifier',
      'app.load_notification_fanout_inputs_v2(uuid,uuid)'::regprocedure,
      'EXECUTE'
    ) AND NOT has_function_privilege(
      'periapsis_notifier',
      'app.commit_notification_fanout_v1(uuid,uuid,jsonb,timestamp with time zone)'::regprocedure,
      'EXECUTE'
    );
END;
$function$;

CREATE FUNCTION app.notification_dispatch_readiness_v3()
RETURNS TABLE(
  queue_depth bigint,role_safe boolean,schema_safe boolean,
  oldest_pending_seconds bigint
)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  SELECT readiness.queue_depth,readiness.role_safe
  INTO queue_depth,role_safe
  FROM app.notification_dispatch_readiness_v1() AS readiness;
  schema_safe := app.notification_schema_readiness_v3();
  SELECT coalesce(greatest(0,floor(extract(epoch FROM
    transaction_timestamp()-min(event.occurred_at))))::bigint,0::bigint)
  INTO oldest_pending_seconds
  FROM public.outbox_events AS event
  WHERE event.event_type LIKE 'notification.%'
    AND event.schema_version=2 AND event.processed_at IS NULL
    AND event.dead_lettered_at IS NULL
    AND event.available_at<=transaction_timestamp()
    AND event.attempts<event.max_attempts
    AND (event.lease_until IS NULL
      OR event.lease_until<=transaction_timestamp());
  RETURN NEXT;
END;
$function$;

ALTER FUNCTION app.private_notification_schema_readiness_v3_base()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.notification_schema_readiness_v3()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.notification_dispatch_readiness_v3()
  OWNER TO periapsis_notification_readiness_owner;
REVOKE ALL ON FUNCTION app.private_notification_schema_readiness_v3_base(),
  app.notification_schema_readiness_v3(),
  app.notification_dispatch_readiness_v3()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.private_notification_schema_readiness_v3_base()
TO periapsis_notification_readiness_owner;
GRANT EXECUTE ON FUNCTION app.notification_schema_readiness_v3()
TO periapsis_api,periapsis_worker,periapsis_notification_readiness_owner;
GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v3()
TO periapsis_notifier;
--> statement-breakpoint

DO $derive_ticket_export_readiness_v2_base$
DECLARE
  predecessor_definition text;
  successor_definition text;
  function_name text;
BEGIN
  SELECT pg_get_functiondef(
    'app.ticket_export_runtime_schema_readiness_v1()'::regprocedure
  ) INTO predecessor_definition;
  IF encode(sha256(convert_to(predecessor_definition,'UTF8')),'hex')<>
       'a3c6d33333dc90cf8ccdf09906d4650313095a5966ed0e140545f2aee52a9642'
  THEN
    RAISE EXCEPTION 'ticket export readiness predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;
  successor_definition := replace(
    predecessor_definition,'ticket_export_runtime_schema_readiness_v1',
    'private_ticket_export_runtime_schema_readiness_v2_base'
  );
  FOREACH function_name IN ARRAY ARRAY[
    'resolve_ticket_export_access','resolve_ticket_export_query',
    'lookup_ticket_export_replay','commit_ticket_export_request',
    'get_ticket_export','commit_ticket_export_owner_transition',
    'resolve_ticket_export_worker_access',
    'select_ticket_export_claim_candidate','get_ticket_export_for_worker',
    'get_revoked_ticket_export_for_worker',
    'commit_ticket_export_worker_transition',
    'commit_ticket_export_revocation','read_ticket_export_application_page',
    'claim_ticket_export','read_ticket_export_page',
    'record_ticket_export_manifest','commit_ticket_export_success',
    'report_ticket_export_failure',
    'acknowledge_ticket_export_cancellation',
    'reject_ticket_export_revocation',
    'claim_ticket_export_artifact_reconciliation',
    'finalize_ticket_export_artifact_reconciliation',
    'report_ticket_export_artifact_reconciliation_failure',
    'read_ticket_export_reconciliation_metrics'
  ] LOOP
    successor_definition := replace(
      successor_definition,function_name||'_v1(jsonb)',
      function_name||'_v2(jsonb)'
    );
  END LOOP;
  IF strpos(successor_definition,
       '''app.commit_ticket_export_request_v1(jsonb)''')<>0
     OR strpos(successor_definition,
       '''app.read_ticket_export_page_v1(jsonb)''')<>0 THEN
    RAISE EXCEPTION 'ticket export readiness V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$derive_ticket_export_readiness_v2_base$;

ALTER FUNCTION app.private_ticket_export_runtime_schema_readiness_v2_base()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_export_runtime_schema_readiness_v2_base()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.ticket_export_runtime_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  expected record;
  function_oid regprocedure;
  legacy_name text;
  relation_name text;
  function_identity text;
BEGIN
  IF has_function_privilege(
       'periapsis_api',
       'app.ticket_export_runtime_schema_readiness_v1()'::regprocedure,
       'EXECUTE'
     ) OR has_function_privilege(
       'periapsis_worker',
       'app.ticket_export_runtime_schema_readiness_v1()'::regprocedure,
       'EXECUTE'
     ) THEN
    RETURN false;
  END IF;
  FOREACH relation_name IN ARRAY ARRAY[
    'ticket_export_jobs','ticket_export_query_snapshots',
    'ticket_export_manifests','ticket_export_command_receipts',
    'ticket_export_artifact_cleanups'
  ] LOOP
    IF NOT EXISTS (
      SELECT 1 FROM pg_class AS relation
      JOIN pg_namespace AS namespace ON namespace.oid=relation.relnamespace
      WHERE namespace.nspname='public' AND relation.relname=relation_name
        AND relation.relkind='r' AND relation.relrowsecurity
        AND relation.relforcerowsecurity
        AND pg_get_userbyid(relation.relowner)=
            'periapsis_ticket_runtime_owner'
    ) OR has_table_privilege(
      'periapsis_api',format('public.%I',relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_worker',format('public.%I',relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) OR has_table_privilege(
      'periapsis_notifier',format('public.%I',relation_name),
      'SELECT,INSERT,UPDATE,DELETE'
    ) THEN RETURN false; END IF;
  END LOOP;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.resolve_ticket_export_access_v2(jsonb)',
    'app.resolve_ticket_export_query_v2(jsonb)',
    'app.lookup_ticket_export_replay_v2(jsonb)',
    'app.commit_ticket_export_request_v2(jsonb)',
    'app.get_ticket_export_v2(jsonb)',
    'app.commit_ticket_export_owner_transition_v2(jsonb)',
    'app.resolve_ticket_export_worker_access_v2(jsonb)',
    'app.select_ticket_export_claim_candidate_v2(jsonb)',
    'app.get_ticket_export_for_worker_v2(jsonb)',
    'app.get_revoked_ticket_export_for_worker_v2(jsonb)',
    'app.commit_ticket_export_worker_transition_v2(jsonb)',
    'app.commit_ticket_export_revocation_v2(jsonb)',
    'app.read_ticket_export_application_page_v2(jsonb)'
  ] LOOP
    function_oid:=to_regprocedure(function_identity);
    IF function_oid IS NULL OR NOT EXISTS (
      SELECT 1 FROM pg_proc AS procedure WHERE procedure.oid=function_oid
        AND procedure.prosecdef
        AND pg_get_userbyid(procedure.proowner)='periapsis_migrator'
    ) OR NOT has_function_privilege('periapsis_api',function_oid,'EXECUTE')
      OR has_function_privilege('periapsis_worker',function_oid,'EXECUTE')
      OR EXISTS (
        SELECT 1 FROM pg_proc AS procedure
        CROSS JOIN LATERAL aclexplode(coalesce(
          procedure.proacl,acldefault('f',procedure.proowner)
        )) AS privilege
        WHERE procedure.oid=function_oid AND privilege.grantee=0
          AND privilege.privilege_type='EXECUTE'
      ) THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH function_identity IN ARRAY ARRAY[
    'app.claim_ticket_export_v2(jsonb)',
    'app.read_ticket_export_page_v2(jsonb)',
    'app.record_ticket_export_manifest_v2(jsonb)',
    'app.commit_ticket_export_success_v2(jsonb)',
    'app.report_ticket_export_failure_v2(jsonb)',
    'app.acknowledge_ticket_export_cancellation_v2(jsonb)',
    'app.reject_ticket_export_revocation_v2(jsonb)',
    'app.claim_ticket_export_artifact_reconciliation_v2(jsonb)',
    'app.finalize_ticket_export_artifact_reconciliation_v2(jsonb)',
    'app.report_ticket_export_artifact_reconciliation_failure_v2(jsonb)',
    'app.read_ticket_export_reconciliation_metrics_v2(jsonb)'
  ] LOOP
    function_oid:=to_regprocedure(function_identity);
    IF function_oid IS NULL OR NOT EXISTS (
      SELECT 1 FROM pg_proc AS procedure WHERE procedure.oid=function_oid
        AND procedure.prosecdef
        AND pg_get_userbyid(procedure.proowner)='periapsis_migrator'
    ) OR NOT has_function_privilege('periapsis_worker',function_oid,'EXECUTE')
      OR has_function_privilege('periapsis_api',function_oid,'EXECUTE')
      OR EXISTS (
        SELECT 1 FROM pg_proc AS procedure
        CROSS JOIN LATERAL aclexplode(coalesce(
          procedure.proacl,acldefault('f',procedure.proowner)
        )) AS privilege
        WHERE procedure.oid=function_oid AND privilege.grantee=0
          AND privilege.privilege_type='EXECUTE'
      ) THEN
      RETURN false;
    END IF;
  END LOOP;
  FOR expected IN
    SELECT * FROM (VALUES
      ('app.private_ticket_export_require_human_v2(jsonb,uuid,public.ticket_aggregate_kind,text,text)',
       'acb19d1ff0e2b4d9f56f09a3ffc5d000731a9b278708e9b8382c9ba39a453a54',true),
      ('app.private_ticket_export_requester_live_v2(public.ticket_export_jobs)',
       '920953f85788bc39acf199ca6e72aaf23d83237268f5958d46e2f3ae2e70152d',true),
      ('app.private_ticket_export_comment_visible_v1(public.ticket_export_jobs,uuid,public.ticket_comment_visibility)',
       '03d72e7f16d64280c3b84532adaa13e1650cf97609544c0be10aba579484b795',true),
      ('app.private_ticket_export_cell_v2(public.ticket_export_jobs,uuid,uuid,jsonb)',
       '5dad4fe486265ba4a4c741eddd69554b4e2e8872c800567d6666abc9d2dc3bd3',true),
      ('app.private_ticket_export_page_document_v2(public.ticket_export_jobs,text,integer,boolean)',
       'b0c28d6e5bcf99e13a70a9eeafe73c2632422b95149a83b0de79257e4e285762',true),
      ('app.private_ticket_export_scope_allowed_v1(text,boolean,boolean)',
       '09b16425ec9a521b24423119f8e25563dac63627237901c766e171b03b3d8795',false),
      ('app.private_ticket_export_require_human_v1(jsonb,uuid,public.ticket_aggregate_kind,text,text)',
       '39819b82c09829ea8658977f4cb77fd54f55ba02a40f9687d89d68f30f1da812',true),
      ('app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)',
       '60721258a7931898c69c609d61075595cd1925bf6182640f35283f819613e09d',true),
      ('app.private_ticket_export_page_document_v1(public.ticket_export_jobs,text,integer,boolean)',
       'fdee12f30e59f9caea116f105c9d2cee6fd713582ab266c7f6addaa67f26adeb',true)
    ) AS functions(signature,definition_hash,security_definer)
  LOOP
    function_oid := to_regprocedure(expected.signature);
    IF function_oid IS NULL OR (
      SELECT pg_get_userbyid(procedure.proowner)<>'periapsis_migrator'
        OR procedure.prosecdef IS DISTINCT FROM expected.security_definer
        OR encode(sha256(convert_to(
             pg_get_functiondef(procedure.oid),'UTF8'
           )),'hex') IS DISTINCT FROM expected.definition_hash
      FROM pg_proc AS procedure WHERE procedure.oid=function_oid
    ) OR EXISTS (
      SELECT 1 FROM pg_proc AS procedure
      CROSS JOIN LATERAL aclexplode(coalesce(
        procedure.proacl,acldefault('f',procedure.proowner)
      )) AS privilege
      WHERE procedure.oid=function_oid AND privilege.grantee=0
        AND privilege.privilege_type='EXECUTE'
    )
      OR has_function_privilege('periapsis_api',function_oid,'EXECUTE')
      OR has_function_privilege('periapsis_worker',function_oid,'EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;
  FOREACH legacy_name IN ARRAY ARRAY[
    'resolve_ticket_export_access','resolve_ticket_export_query',
    'lookup_ticket_export_replay','commit_ticket_export_request',
    'get_ticket_export','commit_ticket_export_owner_transition',
    'resolve_ticket_export_worker_access',
    'select_ticket_export_claim_candidate','get_ticket_export_for_worker',
    'get_revoked_ticket_export_for_worker',
    'commit_ticket_export_worker_transition',
    'commit_ticket_export_revocation','read_ticket_export_application_page',
    'claim_ticket_export','read_ticket_export_page',
    'record_ticket_export_manifest','commit_ticket_export_success',
    'report_ticket_export_failure',
    'acknowledge_ticket_export_cancellation',
    'reject_ticket_export_revocation',
    'claim_ticket_export_artifact_reconciliation',
    'finalize_ticket_export_artifact_reconciliation',
    'report_ticket_export_artifact_reconciliation_failure',
    'read_ticket_export_reconciliation_metrics'
  ] LOOP
    function_oid := to_regprocedure('app.'||legacy_name||'_v1(jsonb)');
    IF function_oid IS NULL
       OR has_function_privilege('periapsis_api',function_oid,'EXECUTE')
       OR has_function_privilege('periapsis_worker',function_oid,'EXECUTE')
    THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN EXISTS (
    SELECT 1 FROM public.ticket_runtime_service_principals AS principal
    WHERE principal.id='01890f00-0000-7000-8000-0000000000f1'::uuid
      AND principal.key='ticket_runtime' AND principal.enabled
  ) AND (SELECT count(*) FROM public.ticket_runtime_service_principals)=1
    AND (SELECT count(*) FROM pg_trigger AS trigger
      WHERE trigger.tgname LIKE 'ticket_export_%_write_guard_v1'
        AND trigger.tgenabled='O' AND NOT trigger.tgisinternal)=5;
END;
$function$;

ALTER FUNCTION app.ticket_export_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_export_runtime_schema_readiness_v2()
FROM PUBLIC,periapsis_notifier,periapsis_auditor,
  periapsis_ticket_runtime_owner,periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.ticket_export_runtime_schema_readiness_v2()
TO periapsis_api,periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.ticket_export_runtime_schema_readiness_v1()
FROM periapsis_api,periapsis_worker;
--> statement-breakpoint

-- Absolute V47 cutover tail.  Every successor, caller and readiness probe is
-- installed above this point.  Production applies the migration under the
-- repository migration transaction and with V46 writers quiesced; therefore
-- there is no externally observable interval with half-closed consumers.

DROP TRIGGER ticket_comments_capture_v47_compat_v1
ON public.ticket_comments;

ALTER TABLE public.ticket_comment_author_snapshots
  DISABLE TRIGGER ticket_comment_author_snapshots_write_guard_v1;
ALTER TABLE public.ticket_comments
  DISABLE TRIGGER ticket_comments_immutable_v1;

-- A direct legacy create has a ticket_comment_commands result.  The only
-- other canonical API aggregate is the inline private transition note, which
-- shares actor, ticket and transaction timestamp with one ticket transition
-- command.  Anything else is ambiguous and aborts the whole migration.
DO $repair_legacy_transition_comment_origins_v47$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.ticket_comments AS comment
    WHERE comment.origin='api'
      AND NOT EXISTS (
        SELECT 1 FROM public.ticket_comment_commands AS command
        WHERE command.tenant_id=comment.tenant_id
          AND command.result_comment_id=comment.id
      )
      AND (
        SELECT count(*)
        FROM public.ticket_commands AS command
        WHERE command.tenant_id=comment.tenant_id
          AND command.actor_membership_id=comment.author_membership_id
          AND command.actor_user_id=comment.author_user_id
          AND command.created_at=comment.created_at
          AND command.operation=CASE WHEN comment.alert_id IS NOT NULL
            THEN 'alert.transition' ELSE 'case.transition' END
          AND command.result_alert_id IS NOT DISTINCT FROM comment.alert_id
          AND command.result_case_id IS NOT DISTINCT FROM comment.case_id
      )<>1
  ) THEN
    RAISE EXCEPTION 'legacy API comment origin is ambiguous'
      USING ERRCODE='P47O1';
  END IF;

  UPDATE public.ticket_comments AS comment
  SET origin='system'
  WHERE comment.origin='api'
    AND NOT EXISTS (
      SELECT 1 FROM public.ticket_comment_commands AS command
      WHERE command.tenant_id=comment.tenant_id
        AND command.result_comment_id=comment.id
    );
  UPDATE public.ticket_comment_author_snapshots AS snapshot
  SET origin='system',audience='operator',author_contact_id=NULL
  FROM public.ticket_comments AS comment
  WHERE comment.tenant_id=snapshot.tenant_id
    AND comment.id=snapshot.comment_id AND comment.origin='system'
    AND snapshot.origin='api';
END;
$repair_legacy_transition_comment_origins_v47$;

ALTER TABLE public.ticket_comment_author_snapshots
  ENABLE TRIGGER ticket_comment_author_snapshots_write_guard_v1;
DROP TRIGGER ticket_comments_immutable_v1 ON public.ticket_comments;

CREATE FUNCTION app.guard_ticket_comment_current_v1()
RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  IF current_setting('app.ticket_runtime_write_v1',true)
       IS DISTINCT FROM 'enabled' THEN
    RAISE EXCEPTION 'ticket comment mutation requires the closed ABI'
      USING ERRCODE='42501';
  END IF;
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'ticket comment aggregate is append-only'
      USING ERRCODE='55000';
  END IF;
  IF (to_jsonb(NEW)-ARRAY[
        'body_markdown','body_html','revision','mentioned_user_ids','updated_at'
      ]::text[]) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY[
        'body_markdown','body_html','revision','mentioned_user_ids','updated_at'
      ]::text[])
     OR NEW.revision<>OLD.revision+1
     OR NEW.updated_at<=OLD.updated_at THEN
    RAISE EXCEPTION 'ticket comment current row update is invalid'
      USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$function$;
ALTER FUNCTION app.guard_ticket_comment_current_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_ticket_comment_current_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
CREATE TRIGGER ticket_comments_current_guard_v1
BEFORE UPDATE OR DELETE ON public.ticket_comments
FOR EACH ROW EXECUTE FUNCTION app.guard_ticket_comment_current_v1();
--> statement-breakpoint

ALTER TABLE public.ticket_comments
  DROP CONSTRAINT IF EXISTS ticket_comments_body_check;
ALTER TABLE public.ticket_comments
  ADD CONSTRAINT ticket_comments_body_check CHECK (
    app.private_ticket_comment_markdown_valid_v1(body_markdown)
    AND app.private_ticket_comment_html_valid_v1(body_html)
  );
ALTER TABLE public.ticket_comments
  DROP CONSTRAINT IF EXISTS ticket_comments_origin_check;
ALTER TABLE public.ticket_comments
  ADD CONSTRAINT ticket_comments_origin_check CHECK (
    origin IN ('api','customer_portal','escalation_copy','system')
  );
ALTER TABLE public.ticket_comments
  DROP CONSTRAINT IF EXISTS ticket_comments_origin_visibility_check;
ALTER TABLE public.ticket_comments
  ADD CONSTRAINT ticket_comments_origin_visibility_check CHECK (
    origin NOT IN ('customer_portal','escalation_copy')
    OR visibility='public'
  );
ALTER TABLE public.ticket_comments
  DROP CONSTRAINT IF EXISTS ticket_comments_revision_check;
ALTER TABLE public.ticket_comments
  ADD CONSTRAINT ticket_comments_revision_check CHECK (
    revision BETWEEN 1 AND 2147483647
  );
ALTER TABLE public.ticket_comments
  DROP CONSTRAINT IF EXISTS ticket_comments_mentions_check;
ALTER TABLE public.ticket_comments
  ADD CONSTRAINT ticket_comments_mentions_check CHECK (
    app.private_ticket_comment_uuid_array_valid_v1(mentioned_user_ids,50)
  );
ALTER TABLE public.ticket_comments
  DROP CONSTRAINT IF EXISTS ticket_comments_timestamps_check;
ALTER TABLE public.ticket_comments
  ADD CONSTRAINT ticket_comments_timestamps_check CHECK (
    app.private_ticket_comment_timestamp_valid_v1(created_at)
    AND app.private_ticket_comment_timestamp_valid_v1(updated_at)
    AND updated_at>=created_at
  );
--> statement-breakpoint

DROP POLICY ticket_comments_api_tenant ON public.ticket_comments;
DROP POLICY ticket_comment_author_snapshots_api_tenant
ON public.ticket_comment_author_snapshots;
CREATE POLICY ticket_comments_owner_access
ON public.ticket_comments AS PERMISSIVE FOR ALL
TO periapsis_ticket_runtime_owner USING (true) WITH CHECK (true);
CREATE POLICY ticket_comment_author_snapshots_owner_access
ON public.ticket_comment_author_snapshots AS PERMISSIVE FOR ALL
TO periapsis_ticket_runtime_owner USING (true) WITH CHECK (true);
ALTER TABLE public.ticket_comments FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_comment_author_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE public.ticket_comments OWNER TO periapsis_ticket_runtime_owner;
ALTER TABLE public.ticket_comment_author_snapshots
  OWNER TO periapsis_ticket_runtime_owner;
REVOKE ALL ON TABLE public.ticket_comments
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_notification_dispatch_owner;
REVOKE ALL ON TABLE public.ticket_comment_author_snapshots
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_notification_dispatch_owner;
GRANT ALL ON TABLE public.ticket_comments,
  public.ticket_comment_author_snapshots TO periapsis_migrator;
--> statement-breakpoint

REVOKE EXECUTE ON FUNCTION app.create_tenant_ticket_comment_v1(
  public.ticket_aggregate_kind,uuid,public.ticket_comment_visibility,
  text,text,uuid[],bytea,bytea,uuid,uuid,inet,text,text
),app.create_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind,uuid,uuid,text,text,bytea,bytea,
  uuid,uuid,inet,text,text
) FROM periapsis_api;
REVOKE EXECUTE ON FUNCTION app.apply_tenant_ticket_mutation_v1(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,
  text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,
  uuid,uuid,inet,text,text
) FROM periapsis_api;
REVOKE EXECUTE ON FUNCTION app.apply_ticket_bulk_target_v1(jsonb)
FROM periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.commit_tenant_ticket_escalation_v3(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
),app.lookup_tenant_ticket_escalation_replay_v2(bytea,bytea)
FROM periapsis_api;
--> statement-breakpoint

REVOKE EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v2(uuid,uuid),
  app.commit_notification_fanout_v1(
    uuid,uuid,jsonb,timestamp with time zone
  ),app.notification_dispatch_readiness_v2()
FROM periapsis_notifier;
REVOKE EXECUTE ON FUNCTION app.notification_schema_readiness_v2()
FROM periapsis_api,periapsis_worker;
--> statement-breakpoint

REVOKE EXECUTE ON FUNCTION
  app.resolve_ticket_export_access_v1(jsonb),
  app.resolve_ticket_export_query_v1(jsonb),
  app.lookup_ticket_export_replay_v1(jsonb),
  app.commit_ticket_export_request_v1(jsonb),
  app.get_ticket_export_v1(jsonb),
  app.commit_ticket_export_owner_transition_v1(jsonb),
  app.resolve_ticket_export_worker_access_v1(jsonb),
  app.select_ticket_export_claim_candidate_v1(jsonb),
  app.get_ticket_export_for_worker_v1(jsonb),
  app.get_revoked_ticket_export_for_worker_v1(jsonb),
  app.commit_ticket_export_worker_transition_v1(jsonb),
  app.commit_ticket_export_revocation_v1(jsonb),
  app.read_ticket_export_application_page_v1(jsonb)
FROM periapsis_api;
REVOKE EXECUTE ON FUNCTION
  app.claim_ticket_export_v1(jsonb),
  app.read_ticket_export_page_v1(jsonb),
  app.record_ticket_export_manifest_v1(jsonb),
  app.commit_ticket_export_success_v1(jsonb),
  app.report_ticket_export_failure_v1(jsonb),
  app.acknowledge_ticket_export_cancellation_v1(jsonb),
  app.reject_ticket_export_revocation_v1(jsonb),
  app.claim_ticket_export_artifact_reconciliation_v1(jsonb),
  app.finalize_ticket_export_artifact_reconciliation_v1(jsonb),
  app.report_ticket_export_artifact_reconciliation_failure_v1(jsonb),
  app.read_ticket_export_reconciliation_metrics_v1(jsonb)
FROM periapsis_worker;
--> statement-breakpoint

-- The two successor readiness roots are intentionally evaluated only after
-- every predecessor privilege has been retired.
DO $ticket_comment_v47_cutover_ready$
BEGIN
  IF NOT app.notification_schema_readiness_v3()
     OR NOT app.ticket_export_runtime_schema_readiness_v2() THEN
    RAISE EXCEPTION 'ticket comment V47 downstream cutover is not ready'
      USING ERRCODE='55000';
  END IF;
END;
$ticket_comment_v47_cutover_ready$;
--> statement-breakpoint

-- Contacts/portal readiness predates the immutable V47 comment runtime.  Keep
-- the old function as predecessor evidence, derive a private successor over
-- the exact attested source, and retire its public runtime grant rather than
-- reopening either the legacy comment writer or direct table ownership.
DO $derive_contacts_portal_readiness_v2$
DECLARE
  definition text;
  source_hash text;
  old_membership_guard constant text :=
    'IF function_definition LIKE ''%membership.role%''' || chr(10) ||
    '       OR function_definition LIKE ''%contact.group.read%''';
  new_membership_guard constant text :=
    'IF function_definition LIKE ''%contact.group.read%''';
  legacy_manifest_tail constant text := $old$
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v23() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v22() AS compatibility;
  SELECT compatibility.applied_count INTO rolling_count
  FROM app.schema_compatibility_v21() AS compatibility;
  RETURN current_count = 116 AND predecessor_count = 113
    AND rolling_count = 0;
$old$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         encode(sha256(convert_to(function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.contacts_portal_schema_readiness_v1()'::regprocedure;
  IF source_hash<>
       '60b151cef51b4adf73de2ef5fa115f61a4c05114935bcfb8368749c326063c29'
     OR strpos(definition,btrim(legacy_manifest_tail,E'\r\n'))=0 THEN
    RAISE EXCEPTION 'contacts portal readiness predecessor drifted'
      USING ERRCODE='55000';
  END IF;

  definition:=replace(
    definition,'contacts_portal_schema_readiness_v1',
    'private_contacts_portal_schema_readiness_v2'
  );
  definition:=replace(
    definition,
    'AND pg_get_userbyid(class.relowner) = ''periapsis_migrator''',
    'AND pg_get_userbyid(class.relowner) = CASE relation_name ' ||
    'WHEN ''ticket_comment_author_snapshots'' THEN ' ||
    '''periapsis_ticket_runtime_owner'' ELSE ''periapsis_migrator'' END'
  );
  definition:=replace(
    definition,
    '''ticket_comments_capture_author_snapshot_v1'',',
    '''ticket_comments_current_guard_v1'',' || chr(10) ||
    '        ''ticket_comment_author_snapshots_write_guard_v1'','
  );
  definition:=replace(definition,') <> 4 OR EXISTS (',') <> 5 OR EXISTS (');
  definition:=replace(
    definition,
    'app.create_customer_portal_ticket_comment_v1(public.ticket_aggregate_kind,uuid,uuid,text,text,bytea,bytea,uuid,uuid,inet,text,text)',
    'app.create_customer_portal_ticket_comment_v2(public.ticket_aggregate_kind,uuid,uuid,text,text,uuid[],bytea,bytea,uuid,uuid,inet,text,text)'
  );
  definition:=replace(
    definition,'create_customer_portal_ticket_comment_v1',
    'create_customer_portal_ticket_comment_v2'
  );
  definition:=replace(
    definition,'private_notification_operator_candidates_v1',
    'private_notification_operator_candidates_v2'
  );
  definition:=replace(
    definition,'load_notification_fanout_inputs_v2',
    'load_notification_fanout_inputs_v3'
  );
  definition:=replace(
    definition,
    '(''app.private_notification_operator_candidates_v2(uuid,uuid)'', ' ||
      '''periapsis_notification_dispatch_owner''',
    '(''app.private_notification_operator_candidates_v2(uuid,uuid)'', ' ||
      '''periapsis_migrator'''
  );
  definition:=replace(
    definition,old_membership_guard,new_membership_guard
  );
  definition:=replace(
    definition,
    'OR function_definition NOT LIKE ''%linked_membership_id%''',
    'OR function_definition NOT LIKE ''%ticket_customer_contacts%'''
  );
  definition:=replace(
    definition,
    'OR has_function_privilege(' || chr(10) ||
    '       ''periapsis_notifier'',' || chr(10) ||
    '       ''app.load_notification_fanout_inputs_v1(uuid,uuid)'', ''EXECUTE''' ||
    chr(10) || '     ) THEN',
    'OR has_function_privilege(' || chr(10) ||
    '       ''periapsis_notifier'',' || chr(10) ||
    '       ''app.load_notification_fanout_inputs_v1(uuid,uuid)'', ''EXECUTE''' ||
    chr(10) || '     ) OR has_function_privilege(' || chr(10) ||
    '       ''periapsis_notifier'',' || chr(10) ||
    '       ''app.load_notification_fanout_inputs_v2(uuid,uuid)'', ''EXECUTE''' ||
    chr(10) || '     ) THEN'
  );
  definition:=replace(
    definition,btrim(legacy_manifest_tail,E'\r\n'),'  RETURN true;'
  );

  IF strpos(definition,'create_customer_portal_ticket_comment_v1')<>0
     OR strpos(definition,'private_notification_operator_candidates_v1')<>0
     OR strpos(definition,'ticket_comments_capture_author_snapshot_v1')<>0
     OR strpos(definition,'private_contacts_portal_schema_readiness_v2')=0
     OR strpos(definition,'periapsis_ticket_runtime_owner')=0
     OR strpos(definition,'ticket_customer_contacts')=0
     OR strpos(definition,'schema_compatibility_v23')<>0
     OR strpos(
       definition,
       '(''app.private_notification_operator_candidates_v2(uuid,uuid)'', ' ||
         '''periapsis_migrator'''
     )=0 THEN
    RAISE EXCEPTION 'contacts portal readiness V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE definition;
END;
$derive_contacts_portal_readiness_v2$;

ALTER FUNCTION app.private_contacts_portal_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_contacts_portal_schema_readiness_v2()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_notification_dispatch_owner,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.private_contacts_portal_schema_readiness_v2()
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.contacts_portal_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  RETURN app.private_contacts_portal_schema_readiness_v2()
    AND app.notification_schema_readiness_v3();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.contacts_portal_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.contacts_portal_schema_readiness_v2()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_notification_dispatch_owner,
  periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.contacts_portal_schema_readiness_v2()
TO periapsis_api,periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.contacts_portal_schema_readiness_v1()
FROM periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $contacts_portal_v47_cutover_ready$
BEGIN
  IF NOT app.contacts_portal_schema_readiness_v2()
     OR pg_catalog.has_function_privilege(
       'periapsis_api',
       'app.contacts_portal_schema_readiness_v1()'::regprocedure,
       'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',
       'app.contacts_portal_schema_readiness_v1()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'contacts portal V47 cutover is not ready'
      USING ERRCODE='55000';
  END IF;
END;
$contacts_portal_v47_cutover_ready$;
--> statement-breakpoint

-- Bulk execution now emits immutable comment revisions through the V2 target
-- ABI.  The V1 readiness root intentionally fails after that predecessor is
-- revoked, so derive a catalog successor and pin the only changed worker
-- definition explicitly.
DO $derive_ticket_bulk_readiness_v2_base$
DECLARE
  definition text;
  source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         encode(sha256(convert_to(function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_bulk_runtime_schema_readiness_v1()'::regprocedure;
  IF source_hash<>
       '720ac628734386423164c9fe9b57b29d73b5d0c8604d99123a46c8b731ff0cab'
     OR strpos(definition,'apply_ticket_bulk_target_v1')=0
     OR strpos(
       definition,
       'OR NOT app.private_v45_ticket_runtime_repairs_ready(''bulk'')'
     )=0 THEN
    RAISE EXCEPTION 'ticket bulk readiness predecessor drifted'
      USING ERRCODE='55000';
  END IF;
  definition:=replace(
    definition,'ticket_bulk_runtime_schema_readiness_v1',
    'private_ticket_bulk_runtime_schema_readiness_v2_base'
  );
  definition:=replace(
    definition,'apply_ticket_bulk_target_v1','apply_ticket_bulk_target_v2'
  );
  definition:=replace(
    definition,
    'OR NOT app.private_v45_ticket_runtime_repairs_ready(''bulk'')',''
  );
  IF strpos(definition,'apply_ticket_bulk_target_v1')<>0
     OR strpos(
       definition,'private_ticket_bulk_runtime_schema_readiness_v2_base'
     )=0
     OR strpos(
       definition,
       'OR NOT app.private_v45_ticket_runtime_repairs_ready(''bulk'')'
     )<>0 THEN
    RAISE EXCEPTION 'ticket bulk readiness V47 derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE definition;
END;
$derive_ticket_bulk_readiness_v2_base$;

ALTER FUNCTION app.private_ticket_bulk_runtime_schema_readiness_v2_base()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_bulk_runtime_schema_readiness_v2_base()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION
  app.private_ticket_bulk_runtime_schema_readiness_v2_base()
TO periapsis_migrator;
--> statement-breakpoint

CREATE FUNCTION app.ticket_bulk_runtime_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  target_definition_hash text;
BEGIN
  IF NOT app.private_ticket_bulk_runtime_schema_readiness_v2_base() THEN
    RETURN false;
  END IF;
  SELECT encode(sha256(convert_to(
           pg_catalog.pg_get_functiondef(function_row.oid),'UTF8'
         )),'hex')
    INTO STRICT target_definition_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid='app.apply_ticket_bulk_target_v2(jsonb)'::regprocedure
    AND pg_catalog.pg_get_userbyid(function_row.proowner)='periapsis_migrator'
    AND function_row.prosecdef
    AND function_row.proconfig[1] LIKE 'search_path=pg_catalog%';
  RETURN target_definition_hash=
      '05365f9a9ff92a05fd17e5b38626ab14fa4fec6bc745384be2ba054c4f3fb0a7'
    AND pg_catalog.has_function_privilege(
      'periapsis_worker',
      'app.apply_ticket_bulk_target_v2(jsonb)'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api',
      'app.apply_ticket_bulk_target_v2(jsonb)'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker',
      'app.apply_ticket_bulk_target_v1(jsonb)'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api',
      'app.ticket_bulk_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE'
    )
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_worker',
      'app.ticket_bulk_runtime_schema_readiness_v1()'::regprocedure,'EXECUTE'
    );
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.ticket_bulk_runtime_schema_readiness_v2()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_bulk_runtime_schema_readiness_v2()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.ticket_bulk_runtime_schema_readiness_v2()
TO periapsis_api,periapsis_worker;
REVOKE EXECUTE ON FUNCTION app.ticket_bulk_runtime_schema_readiness_v1()
FROM periapsis_api,periapsis_worker;
--> statement-breakpoint

DO $ticket_bulk_v47_cutover_ready$
BEGIN
  IF NOT app.ticket_bulk_runtime_schema_readiness_v2() THEN
    RAISE EXCEPTION 'ticket bulk V47 cutover is not ready'
      USING ERRCODE='55000';
  END IF;
END;
$ticket_bulk_v47_cutover_ready$;
--> statement-breakpoint
