-- Membership role labels are compatibility metadata (ADR-0006).
-- Authorize export audiences using live explicit permissions and customer links.
CREATE OR REPLACE FUNCTION app.private_ticket_export_require_human_v2(
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
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ticket_export_requester_live_v2(
  p_job public.ticket_export_jobs
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  IF p_job.tenant_id IS DISTINCT FROM app.context_tenant_id() THEN
    RETURN false;
  END IF;
  PERFORM set_config('app.user_id',p_job.requester_user_id::text,true);
  PERFORM app.lock_current_tenant_authorization_state();
  PERFORM 1
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
    RETURN app.private_ticket_runtime_has_any_scope_v1(
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
    AND p_job.comment_scope IN ('none','public')
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
--> statement-breakpoint

-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V60 catalog hash.
-- V60 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v60()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v60();
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
ALTER FUNCTION app.api_runtime_schema_readiness_v60() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v60()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v60()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v60()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v60();
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
ALTER FUNCTION app.worker_runtime_schema_readiness_v60() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v60()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v60()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint

--> statement-breakpoint

-- Exact function-definition hashes independently read from PostgreSQL 18.6.
CREATE OR REPLACE FUNCTION app.ticket_export_runtime_schema_readiness_v2()
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
       '22c7c6316b90f4525825cb2addfc260c07dbadff02022a1c2b58bec2e1e5db38',true),
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
$function$;

--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ticket_comment_user_scope_allows_v1(
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
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_notification_operator_candidates_v2(
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

--> statement-breakpoint

-- Preserve exact PostgreSQL definition checks for permission-based comment visibility.
CREATE OR REPLACE FUNCTION app.notification_schema_readiness_v3()
 RETURNS boolean
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'public', 'app'
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
       'a320354a3fcd09f5fa07292768a124aec61aa191276025eda603e87baa18898b',
       'periapsis_migrator','periapsis_notification_dispatch_owner'),
      ('app.private_notification_operator_candidates_v2(uuid,uuid)',
       '597972ce66c12f2d07aae7fa81f9d324227b9f6b8b4f37b11741167852f9f237',
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
$function$
;
