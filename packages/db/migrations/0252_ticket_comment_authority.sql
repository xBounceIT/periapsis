-- Preserve live explicit comment authority and the UUID-safe customer export aggregate.
-- Definitions are based on the currently installed V60 catalog.
CREATE OR REPLACE FUNCTION app.private_ticket_export_require_human_v2(p_actor jsonb, p_tenant_id uuid, p_kind ticket_aggregate_kind, p_audience text, p_capability text)
 RETURNS TABLE(actor_id uuid, membership_id uuid, principal text, customer_contact_id uuid, public_comments boolean, private_comments boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
AS $function$
DECLARE
  contact_count integer;
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
  PERFORM 1
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity ON identity.id=membership.user_id
  WHERE membership.tenant_id=p_tenant_id AND membership.id=membership_id
    AND membership.user_id=actor_id AND membership.status='active'
    AND identity.active;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket export membership is required' USING ERRCODE='42501';
  END IF;
  IF p_audience='operator' THEN
    IF NOT app.private_ticket_runtime_has_any_scope_v1(
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
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'portal.comment.public','own'
    ) OR NOT app.current_tenant_human_has_exact_permission_v3(
      CASE p_kind WHEN 'alert' THEN 'portal.alert.read'
        ELSE 'portal.case.read' END,'own'
    ) THEN
      RAISE EXCEPTION 'customer ticket export authority is required'
        USING ERRCODE='42501';
    END IF;
    SELECT count(*),(array_agg(contact.id ORDER BY contact.id))[1]
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
$function$
;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ticket_watcher_user_scope_allows_v2(p_tenant_id uuid, p_aggregate_kind ticket_aggregate_kind, p_ticket_id uuid, p_user_id uuid, p_operation text)
 RETURNS boolean
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
AS $function$
  WITH target AS (
    SELECT membership.id AS membership_id
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id=membership.user_id
    JOIN public.tenants AS tenant ON tenant.id=membership.tenant_id
    WHERE membership.tenant_id=p_tenant_id
      AND membership.user_id=p_user_id
      AND membership.status='active'
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
$function$
;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.ticket_export_runtime_schema_readiness_v2()
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
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
       'c9d958e1a600379be03030ca875552bfc1d7855f5bc39c3791a624d9c89bf0d5',true),
      ('app.private_ticket_export_requester_live_v2(public.ticket_export_jobs)',
       '64aae467d3c199e88ee61a405c793910248092f2edca8cf7e174d9b0eab5d2d1',true),
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
$function$
;
--> statement-breakpoint

-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V61 catalog hash.
-- V61 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v61()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v61();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    true,
    true,
    true,
    coalesce(app.platform_local_account_runtime_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_metadata_runtime_schema_readiness_v1(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.api_runtime_schema_readiness_v61() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v61()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v61()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v61()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v61();
  IF release_ready IS DISTINCT FROM true THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
  END IF;
  RETURN ARRAY[
    true,
    coalesce(app.private_sla_system_principal_catalog_ready_v1(),false),
    coalesce(app.sla_object_event_ingress_schema_readiness_v1(),false),
    coalesce(app.ticket_bulk_runtime_schema_readiness_v2(),false),
    coalesce(app.ticket_export_runtime_schema_readiness_v2(),false)
  ]::boolean[];
EXCEPTION
  WHEN undefined_table OR undefined_function OR insufficient_privilege
    OR invalid_schema_name OR cardinality_violation OR data_exception THEN
    RETURN ARRAY[false,false,false,false,false]::boolean[];
END;
$function$;
ALTER FUNCTION app.worker_runtime_schema_readiness_v61() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v61()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v61()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint


--> statement-breakpoint

-- Keep mention discovery, preview, and exact relation admission on live permission scopes.
CREATE OR REPLACE FUNCTION app.guard_ticket_comment_mention_relation_v1()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
AS $function$
DECLARE
  comment_row public.ticket_comments%ROWTYPE;
  direct_candidate boolean;
  copied_candidate boolean;
BEGIN
  SELECT comment.* INTO STRICT comment_row
  FROM public.ticket_comment_revisions AS revision
  JOIN public.ticket_comments AS comment
    ON comment.tenant_id = revision.tenant_id
   AND comment.id = revision.comment_id
  WHERE revision.tenant_id = NEW.tenant_id
    AND revision.id = NEW.revision_id;

  IF (
    SELECT count(*)
    FROM public.ticket_comment_revision_mentions AS relation
    WHERE relation.tenant_id = NEW.tenant_id
      AND relation.revision_id = NEW.revision_id
  ) >= 50 THEN
    RAISE EXCEPTION 'ticket comment mention limit exceeded'
      USING ERRCODE = '22023';
  END IF;

  IF comment_row.origin = 'api' THEN
    SELECT membership.status = 'active'
           AND identity.active
           AND identity.display_name = NEW.display_name
           AND app.private_ticket_watcher_user_scope_allows_v2(
             NEW.tenant_id,
             CASE WHEN comment_row.alert_id IS NOT NULL
               THEN 'alert'::public.ticket_aggregate_kind
               ELSE 'case'::public.ticket_aggregate_kind END,
             coalesce(comment_row.alert_id,comment_row.case_id),
             NEW.mentioned_user_id,'read'
           )
    INTO direct_candidate
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.mentioned_membership_id
      AND membership.user_id = NEW.mentioned_user_id;
  ELSIF comment_row.origin = 'escalation_copy' THEN
    SELECT EXISTS (
      SELECT 1
      FROM public.ticket_comment_escalation_sources AS source
      LEFT JOIN public.ticket_comment_revisions AS source_revision
        ON source_revision.tenant_id = source.tenant_id
       AND source_revision.comment_id = source.source_comment_id
       AND source_revision.revision = source.source_revision
      LEFT JOIN public.ticket_comment_revision_mentions AS source_mention
        ON source_mention.tenant_id = source_revision.tenant_id
       AND source_mention.revision_id = source_revision.id
      WHERE source.tenant_id = NEW.tenant_id
        AND source.copied_comment_id = comment_row.id
        AND (source.legacy_unresolved AND EXISTS (
          SELECT 1
          FROM public.tenant_memberships AS membership
          JOIN public.users AS identity ON identity.id = membership.user_id
          WHERE membership.tenant_id = NEW.tenant_id
            AND membership.id = NEW.mentioned_membership_id
            AND membership.user_id = NEW.mentioned_user_id
            AND identity.display_name = NEW.display_name
        ) OR NOT source.legacy_unresolved
          AND source_mention.mentioned_membership_id = NEW.mentioned_membership_id
          AND source_mention.mentioned_user_id = NEW.mentioned_user_id
          AND source_mention.display_name = NEW.display_name)
    ) INTO copied_candidate;
  END IF;
  IF coalesce(direct_candidate,copied_candidate,false) IS NOT TRUE THEN
    RAISE EXCEPTION 'ticket comment mention is not an exact live candidate'
      USING ERRCODE = '23503';
  END IF;
  RETURN NEW;
END;
$function$
;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.list_tenant_ticket_comment_mention_candidates_v1(p_aggregate_kind ticket_aggregate_kind, p_ticket_id uuid, p_search text, p_limit integer)
 RETURNS TABLE(result_items jsonb)
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
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
$function$
;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ticket_comment_mention_preview_v1(p_aggregate_kind ticket_aggregate_kind, p_ticket_id uuid, p_membership_ids uuid[])
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
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
$function$
;
