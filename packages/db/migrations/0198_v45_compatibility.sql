-- V45 is a coordinated fail-closed cutover. V44 remains immutable predecessor
-- evidence, but it does not attest the v45 ticket metadata, ticket mutation, SLA action,
-- local-account, bulk/export, and Alert DFIR runtime surfaces. Old binaries
-- reject the advanced journal before any v45 writer becomes admissible.
-- The SLA action definer traverses forced-RLS policies that resolve the tenant
-- through this helper. Keep the edge on the isolated NOLOGIN owner rather than
-- broadening the worker login or making the policy helper public.
GRANT EXECUTE ON FUNCTION app.context_tenant_id()
  TO periapsis_sla_worker_owner;
--> statement-breakpoint

-- Repair two latent branches that could not complete a successful SLA action:
-- pgcrypto is intentionally absent, chr(0) is invalid PostgreSQL text, and an
-- uncast CASE expression cannot target the audit_outcome enum. Both functions
-- are derived from attested predecessors so unexpected drift fails migration.
DO $repair_sla_trigger_action_audit_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    'CASE WHEN p_action = ''executed'' THEN ''success'' ELSE ''failure'' END,';
  new_expression constant text :=
    '(CASE WHEN p_action = ''executed'' THEN ''success'' ELSE ''failure'' END)::public.audit_outcome,';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    '0ebbaba464790c09ca7a2f7abb0f27b58c54a73081b00fcda3b09984fa448763' THEN
    RAISE EXCEPTION 'SLA trigger action audit v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'SLA trigger action audit v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_sla_trigger_action_audit_v1$;
--> statement-breakpoint

DO $repair_sla_trigger_action_execution_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_digest constant text := $old_digest$
    effect_digest := digest(convert_to(
      'periapsis/sla-action/effect/v1' || chr(0)
      || occurrence.id::text || chr(0) || occurrence.action_kind::text
      || chr(0) || effect_kind || chr(0)
      || coalesce(effect_id::text, '') || chr(0)
      || coalesce(effect_version::text, ''), 'UTF8'), 'sha256');
$old_digest$;
  new_digest constant text := $new_digest$
    effect_digest := pg_catalog.sha256(
      pg_catalog.convert_to('periapsis/sla-action/effect/v1', 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(occurrence.id::text, 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(occurrence.action_kind::text, 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(effect_kind, 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(coalesce(effect_id::text, ''), 'UTF8')
      || '\x00'::bytea
      || pg_catalog.convert_to(coalesce(effect_version::text, ''), 'UTF8')
    );
$new_digest$;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)'::regprocedure;
  IF predecessor_source_hash<>
    'af1c513f046bb3a5c096e70283cdbdcd08ad81d68304be8e1ecf32b6148310bf' THEN
    RAISE EXCEPTION 'SLA trigger action execution v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_digest)=0 THEN
    RAISE EXCEPTION 'SLA trigger action execution v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_digest,new_digest
  );
  EXECUTE repaired_definition;
END;
$repair_sla_trigger_action_execution_v1$;
--> statement-breakpoint

CREATE FUNCTION app.private_v45_sla_action_repairs_ready()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
  function_row record;
BEGIN
  IF NOT pg_catalog.has_function_privilege(
    'periapsis_sla_worker_owner','app.context_tenant_id()','EXECUTE'
  ) THEN
    RETURN false;
  END IF;
  FOR function_row IN
    SELECT expected.identity,expected.source_hash
    FROM (VALUES
      ('app.execute_sla_trigger_action_v1(uuid,uuid,uuid,bigint,bytea,public.sla_trigger_action_kind,timestamp with time zone)',
       'a40dc874f364e73b9602bdae04a3c2ee714839b8b1cadfc873fa8ad03e61fd3c'),
      ('app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)',
       'f9e4e780e13e39d191e7f5068c6e3b8272d7df2f1c4e57c4dec5fb1813f2bbbb')
    ) AS expected(identity,source_hash)
  LOOP
    IF pg_catalog.to_regprocedure(function_row.identity) IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM pg_catalog.pg_proc AS procedure
         JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner
         WHERE procedure.oid=pg_catalog.to_regprocedure(function_row.identity)
           AND owner.rolname='periapsis_sla_worker_owner'
           AND procedure.prosecdef AND procedure.provolatile='v'
           AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
             procedure.prosrc,'UTF8')),'hex')=function_row.source_hash
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN (
    SELECT count(*)=1 AND coalesce(bool_and(
      privilege.grantor=procedure.proowner
      AND privilege.grantee=procedure.proowner
      AND privilege.privilege_type='EXECUTE'
      AND NOT privilege.is_grantable
    ),false)
    FROM pg_catalog.pg_proc AS procedure
    CROSS JOIN LATERAL pg_catalog.aclexplode(coalesce(
      procedure.proacl,pg_catalog.acldefault('f',procedure.proowner)
    )) AS privilege
    WHERE procedure.oid=
      'app.private_append_sla_action_audit_v1(uuid,uuid,text,timestamp with time zone,jsonb)'::regprocedure
  );
END;
$function$;
ALTER FUNCTION app.private_v45_sla_action_repairs_ready()
  OWNER TO periapsis_sla_readiness_owner;
REVOKE ALL ON FUNCTION app.private_v45_sla_action_repairs_ready()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_migrator,periapsis_sla_api_owner,
  periapsis_sla_worker_owner;
--> statement-breakpoint

-- Harden the existing readiness root so a catalog can no longer seal while
-- action execution is guaranteed to fail behind forced RLS. Derive from the
-- attested predecessor instead of duplicating its large catalog contract.
DO $harden_sla_trigger_action_readiness_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  hardened_definition text;
  marker constant text := '  RETURN EXISTS (';
  prerequisite constant text :=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_proc AS procedure' || chr(10) ||
    '    JOIN pg_catalog.pg_roles AS owner' || chr(10) ||
    '      ON owner.oid=procedure.proowner' || chr(10) ||
    '    WHERE procedure.oid=' || chr(10) ||
    '      ''app.private_v45_sla_action_repairs_ready()''::regprocedure' ||
    chr(10) ||
    '      AND owner.rolname=''periapsis_sla_readiness_owner''' || chr(10) ||
    '      AND procedure.prosecdef AND procedure.provolatile=''s''' ||
    chr(10) ||
    '      AND pg_catalog.encode(pg_catalog.sha256(' || chr(10) ||
    '        pg_catalog.convert_to(procedure.prosrc,''UTF8'')' || chr(10) ||
    '      ),''hex'')=' || chr(10) ||
    '        ''16a8f24a57c37700e9f104d47a467cafb4e0ae54f9b1c76e0e305b4c644cfe00''' ||
    chr(10) ||
    '      AND (SELECT count(*)=1 AND coalesce(bool_and(' || chr(10) ||
    '        privilege.grantor=procedure.proowner' || chr(10) ||
    '        AND privilege.grantee=procedure.proowner' || chr(10) ||
    '        AND privilege.privilege_type=''EXECUTE''' || chr(10) ||
    '        AND NOT privilege.is_grantable' || chr(10) ||
    '      ),false) FROM pg_catalog.aclexplode(coalesce(' || chr(10) ||
    '        procedure.proacl,pg_catalog.acldefault(''f'',procedure.proowner)' ||
    chr(10) || '      )) AS privilege)' || chr(10) ||
    '  ) OR NOT app.private_v45_sla_action_repairs_ready() THEN' || chr(10) ||
    '    RETURN false;' || chr(10) ||
    '  END IF;' || chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.sla_trigger_action_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
    '718a00b46945270c0cede9d1684daf22fd72b290bd485106a901f4f0a062576d' THEN
    RAISE EXCEPTION 'SLA trigger action readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,marker)=0 THEN
    RAISE EXCEPTION 'SLA trigger action readiness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  hardened_definition:=pg_catalog.replace(
    predecessor_definition,marker,prerequisite || marker
  );
  EXECUTE hardened_definition;
END;
$harden_sla_trigger_action_readiness_v1$;
--> statement-breakpoint

-- Human ticket-runtime effects must use the ticket principal enum's canonical
-- `human` value; `operator` is an audience, not a principal kind.
DO $repair_ticket_runtime_human_effects_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    '''operator'', actor_id, ''ticket-runtime'', ''operator'',';
  new_expression constant text :=
    '''human'', actor_id, ''ticket-runtime'', ''operator'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    '04b98c297f6b032640b7fe8e3f20eddc397204409e03ef24f802c665a636f7a7' THEN
    RAISE EXCEPTION 'ticket runtime human effects v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'ticket runtime human effects v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_runtime_human_effects_v1$;
--> statement-breakpoint

-- COLLATE binds more tightly than the jsonb extraction operator. Parenthesize
-- both DISTINCT ON and ORDER BY expressions so PostgreSQL accepts the pinned,
-- deterministic catalog projection.
DO $repair_ticket_runtime_catalog_digest_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_distinct constant text :=
    'SELECT DISTINCT ON (source, definition ->> ''id'')';
  new_distinct constant text :=
    'SELECT DISTINCT ON (source COLLATE "C", (definition ->> ''id'') COLLATE "C")';
  old_order constant text :=
    'ORDER BY source COLLATE "C", definition ->> ''id'' COLLATE "C"';
  new_order constant text :=
    'ORDER BY source COLLATE "C", (definition ->> ''id'') COLLATE "C"';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_runtime_catalog_digest_v1(text)'::regprocedure;
  IF predecessor_source_hash<>
    '7a22822bfed67da318ee4e6f5cc497648ddb4778c24641e2f208321808b5b869' THEN
    RAISE EXCEPTION 'ticket runtime catalog digest v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_distinct)=0
     OR pg_catalog.strpos(predecessor_definition,old_order)=0 THEN
    RAISE EXCEPTION 'ticket runtime catalog digest v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_distinct,new_distinct
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,old_order,new_order
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_runtime_catalog_digest_v1$;
--> statement-breakpoint

-- Bulk execution is an isolated system actor operating a previously authorized
-- immutable target set. It must not forge a live human authentication method
-- merely to reuse the synchronous side-effect writer.
CREATE FUNCTION app.private_append_ticket_bulk_mutation_effects_v1(
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
  event_type text := p_aggregate_kind::text || '.' || p_action;
  activity_id uuid := uuidv7();
  activity_sequence bigint;
  notification_type public.notification_event_type;
  routing_creator_user_id uuid;
  routing_assignee_user_id uuid;
  routing_previous_assignee_user_id uuid;
  routing_operator_team_id uuid;
  routing_operator_team_epoch_id uuid;
BEGIN
  PERFORM app.private_validate_ticket_effects_v1(p_effects);
  IF context_tenant IS NULL
     OR p_aggregate_id IS NULL
     OR p_version NOT BETWEEN 1 AND 2147483647
     OR p_action IS NULL OR p_action !~ '^[a-z][a-z0-9_]{1,63}$'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NOT NULL
     OR p_user_agent IS DISTINCT FROM 'ticket-bulk-worker'
     OR p_authentication_method IS DISTINCT FROM 'system'
     OR p_before IS NOT NULL AND jsonb_typeof(p_before) <> 'object'
     OR p_after IS NOT NULL AND jsonb_typeof(p_after) <> 'object'
     OR p_metadata IS NULL OR jsonb_typeof(p_metadata) <> 'object'
     OR pg_column_size(p_metadata) > 16384 THEN
    RAISE EXCEPTION 'ticket bulk mutation effects are invalid'
      USING ERRCODE='22023';
  END IF;

  SELECT coalesce(max(activity.sequence),0)+1 INTO activity_sequence
  FROM public.ticket_activities AS activity
  WHERE activity.tenant_id=context_tenant
    AND (p_aggregate_kind='alert' AND activity.alert_id=p_aggregate_id
      OR p_aggregate_kind='case' AND activity.case_id=p_aggregate_id);
  IF activity_sequence NOT BETWEEN 1 AND 2147483647 THEN
    RAISE EXCEPTION 'ticket bulk activity sequence is exhausted'
      USING ERRCODE='54000';
  END IF;

  INSERT INTO public.ticket_activities(
    id,tenant_id,alert_id,case_id,sequence,kind,summary,
    actor_principal_kind,origin,details,occurred_at
  ) VALUES (
    activity_id,context_tenant,
    CASE WHEN p_aggregate_kind='alert' THEN p_aggregate_id END,
    CASE WHEN p_aggregate_kind='case' THEN p_aggregate_id END,
    activity_sequence,event_type,
    initcap(p_aggregate_kind::text) || ' ' || replace(p_action,'_',' '),
    'system','system',p_metadata || jsonb_build_object(
      'version',p_version,'contentRedacted',true
    ),transaction_timestamp()
  );

  INSERT INTO public.audit_events(
    id,tenant_id,sequence,occurred_at,actor_type,action,
    resource_type,resource_id,request_id,correlation_id,
    authentication_method,outcome,before,after,metadata
  ) VALUES (
    uuidv7(),context_tenant,0,transaction_timestamp(),'system',
    'tenant.' || event_type,p_aggregate_kind::text,p_aggregate_id,
    p_request_id,p_correlation_id,'system','success',p_before,p_after,
    p_metadata || jsonb_build_object('contentRedacted',true)
  );

  INSERT INTO public.outbox_events(
    id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
    schema_version,payload,deduplication_key,correlation_id,causation_id,
    actor_kind,producer,maximum_audience,occurred_at,available_at
  ) VALUES (
    uuidv7(),context_tenant,p_aggregate_kind::text,p_aggregate_id,p_version,
    event_type,1,jsonb_build_object(
      p_aggregate_kind::text || '_id',p_aggregate_id,
      'version',p_version,'contentRedacted',true
    ),event_type || ':' || activity_id::text,p_correlation_id,p_request_id,
    'system','ticket-bulk-worker','operator',
    transaction_timestamp(),transaction_timestamp()
  );

  IF p_effects @> ARRAY['sla']::text[] THEN
    INSERT INTO public.outbox_events(
      id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
      schema_version,payload,deduplication_key,correlation_id,causation_id,
      actor_kind,producer,maximum_audience,occurred_at,available_at
    ) VALUES (
      uuidv7(),context_tenant,p_aggregate_kind::text,p_aggregate_id,p_version,
      'sla.' || event_type,1,jsonb_build_object(
        p_aggregate_kind::text || '_id',p_aggregate_id,
        'version',p_version,'action',p_action,'contentRedacted',true
      ),'sla.' || event_type || ':' || activity_id::text,
      p_correlation_id,p_request_id,'system','ticket-bulk-worker','operator',
      transaction_timestamp(),transaction_timestamp()
    );
  END IF;
  IF p_effects @> ARRAY['notification']::text[] THEN
    notification_type:=CASE
      WHEN p_aggregate_kind='alert' AND p_action='created'
        THEN 'alert.created'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='assigned'
        THEN 'alert.assigned'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='claimed'
        THEN 'alert.claimed'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='transitioned'
        THEN 'alert.status_changed'::public.notification_event_type
      WHEN p_aggregate_kind='alert' AND p_action='escalated'
        THEN 'alert.escalated'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='created'
        THEN 'case.created'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='assigned'
        THEN 'case.assigned'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='claimed'
        THEN 'case.claimed'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='transferred'
        THEN 'case.transferred'::public.notification_event_type
      WHEN p_aggregate_kind='case' AND p_action='transitioned'
        THEN 'case.status_changed'::public.notification_event_type
      ELSE NULL
    END;
    IF notification_type IS NOT NULL THEN
      routing_previous_assignee_user_id:=nullif(
        p_before ->> 'assignee_user_id',''
      )::uuid;
      IF p_aggregate_kind='alert' THEN
        SELECT alert.created_by,alert.assignee_user_id,
               alert.assigned_team_id,alert.assigned_team_epoch_id
        INTO STRICT routing_creator_user_id,routing_assignee_user_id,
             routing_operator_team_id,routing_operator_team_epoch_id
        FROM public.alerts AS alert
        WHERE alert.tenant_id=context_tenant AND alert.id=p_aggregate_id;
      ELSE
        SELECT case_row.created_by_user_id,case_row.assignee_user_id,
               case_row.assigned_team_id,case_row.assigned_team_epoch_id
        INTO STRICT routing_creator_user_id,routing_assignee_user_id,
             routing_operator_team_id,routing_operator_team_epoch_id
        FROM public.cases AS case_row
        WHERE case_row.tenant_id=context_tenant AND case_row.id=p_aggregate_id;
      END IF;
      PERFORM app.private_append_tenant_notification_event_v2(
        uuidv7(),notification_type,
        p_aggregate_kind::text::public.notification_object_type,
        p_aggregate_id,p_version,transaction_timestamp(),
        'system',NULL,'ticket-bulk-worker','operator',
        jsonb_build_object(
          p_aggregate_kind::text,jsonb_build_object(
            'id',p_aggregate_id,'version',p_version
          ),
          'actor',jsonb_build_object('kind','system'),
          'action',p_action,
          'metadata',p_metadata || jsonb_build_object(
            'content_redacted',true
          ),
          'routing',jsonb_strip_nulls(jsonb_build_object(
            'creatorUserId',routing_creator_user_id,
            'assigneeUserId',routing_assignee_user_id,
            'previousAssigneeUserId',routing_previous_assignee_user_id,
            'operatorTeamId',routing_operator_team_id,
            'operatorTeamEpochId',routing_operator_team_epoch_id
          ))
        ),
        NULL,
        'notification:v2:' || p_aggregate_kind::text || ':' ||
          p_aggregate_id::text || ':' || p_version::text || ':' ||
          notification_type::text,
        p_correlation_id,p_request_id
      );
    END IF;
  END IF;
END;
$function$;
ALTER FUNCTION app.private_append_ticket_bulk_mutation_effects_v1(
  public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,
  text,jsonb,jsonb,jsonb
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_append_ticket_bulk_mutation_effects_v1(
  public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,
  text,jsonb,jsonb,jsonb
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
--> statement-breakpoint

-- Repair the synchronous mutation implementation for PostgreSQL's strict
-- variable/column resolution and heterogeneous alert/case row descriptors,
-- then derive a private bulk-only copy with system-attributed side effects.
DO $repair_and_derive_ticket_mutation_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  bulk_definition text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure;
  IF predecessor_source_hash<>
    'dd6faddd70c6155af88c610679ca69305e073cb8a2dce5adb982293f08de5202' THEN
    RAISE EXCEPTION 'tenant ticket mutation v1 drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,'operation text :=','operation_name text :='
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'|| operation ||','|| operation_name ||'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'command.operation = operation',
    'command.operation = operation_name'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'context_tenant, operation, actor_membership',
    'context_tenant, operation_name, actor_membership'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'SELECT alert.* INTO locked',
    'SELECT alert.*, alert.created_by AS creator_user_id INTO locked'
  );
  repaired_definition:=pg_catalog.replace(
    repaired_definition,'SELECT case_row.* INTO locked',
    'SELECT case_row.*, case_row.created_by_user_id AS creator_user_id INTO locked'
  );
  repaired_definition:=pg_catalog.regexp_replace(
    repaired_definition,
    'CASE WHEN p_aggregate_kind = ''alert'' THEN locked[.]created_by[[:space:]]+ELSE locked[.]created_by_user_id END',
    'locked.creator_user_id','g'
  );
  IF pg_catalog.strpos(repaired_definition,'operation text :=')<>0
     OR pg_catalog.strpos(repaired_definition,'locked.created_by_user_id')<>0
     OR pg_catalog.strpos(repaired_definition,'locked.creator_user_id')=0 THEN
    RAISE EXCEPTION 'tenant ticket mutation v1 repair markers drifted'
      USING ERRCODE='55000';
  END IF;
  EXECUTE repaired_definition;

  bulk_definition:=pg_catalog.replace(
    repaired_definition,'apply_tenant_ticket_mutation_v1',
    'private_apply_ticket_bulk_mutation_v1'
  );
  bulk_definition:=pg_catalog.replace(
    bulk_definition,'private_append_ticket_side_effects_v1',
    'private_append_ticket_bulk_mutation_effects_v1'
  );
  IF bulk_definition IS NOT DISTINCT FROM repaired_definition THEN
    RAISE EXCEPTION 'private ticket bulk mutation v1 derivation drifted'
      USING ERRCODE='55000';
  END IF;
  EXECUTE bulk_definition;
END;
$repair_and_derive_ticket_mutation_v1$;
ALTER FUNCTION app.private_apply_ticket_bulk_mutation_v1(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,
  text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_apply_ticket_bulk_mutation_v1(
  public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,
  text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,
  inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
--> statement-breakpoint

DO $repair_ticket_bulk_target_apply_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_call constant text := 'FROM app.apply_tenant_ticket_mutation_v1(';
  new_call constant text :=
    'FROM app.private_apply_ticket_bulk_mutation_v1(';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid='app.apply_ticket_bulk_target_v1(jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    '3bfb09f886577a72d24b77b21dd3643a60aba6ef543050b34722e6214e618e80' THEN
    RAISE EXCEPTION 'ticket bulk target apply v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_call)=0 THEN
    RAISE EXCEPTION 'ticket bulk target apply v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_call,new_call
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_bulk_target_apply_v1$;
--> statement-breakpoint

DO $repair_ticket_runtime_system_effects_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    'p_resource_type, p_resource_id, ''system'', p_outcome,';
  new_expression constant text :=
    'p_resource_type, p_resource_id, ''system'', p_outcome::public.audit_outcome,';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)'::regprocedure;
  IF predecessor_source_hash<>
    'b7fbd12df80d522fcbf7fc699fc7f10e47e849b57f4b72654fad1a3692ad8375' THEN
    RAISE EXCEPTION 'ticket runtime system effects v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'ticket runtime system effects v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_runtime_system_effects_v1$;
--> statement-breakpoint

DO $repair_ticket_export_requester_live_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  repaired_definition text;
  old_expression constant text :=
    'membership.status = ''active'' AND account.status = ''active''';
  new_expression constant text :=
    'membership.status = ''active'' AND account.active';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)'::regprocedure;
  IF predecessor_source_hash<>
    'b6e60a4d7947834e13ce543b4c2f3c0e439c43942a124f8cc78ba04867897ac8' THEN
    RAISE EXCEPTION 'ticket export requester liveness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,old_expression)=0 THEN
    RAISE EXCEPTION 'ticket export requester liveness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  repaired_definition:=pg_catalog.replace(
    predecessor_definition,old_expression,new_expression
  );
  EXECUTE repaired_definition;
END;
$repair_ticket_export_requester_live_v1$;
--> statement-breakpoint

-- The original bulk/export readiness roots predate the v45 forward repairs.
-- Bind them to every repaired/private dependency and its exact executable ACL,
-- otherwise a latent mutation/audit/export defect could still report ready.
CREATE FUNCTION app.private_v45_ticket_runtime_repairs_ready(p_surface text)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog
AS $function$
DECLARE
  expected_function record;
BEGIN
  IF p_surface IS NULL OR p_surface NOT IN ('bulk','export') THEN
    RETURN false;
  END IF;
  FOR expected_function IN
    SELECT expected.identity,expected.source_hash,
           expected.security_definer,expected.volatility,
           expected.execute_roles
    FROM (VALUES
      (ARRAY['bulk']::text[],
       'app.apply_tenant_ticket_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)',
       '5e14daab242f4d66ac6193cfce0e7ff1653eb8d0bed956ebba730403ff100e15',
       true,'v',ARRAY['periapsis_api','periapsis_migrator']::text[]),
      (ARRAY['bulk']::text[],
       'app.apply_ticket_bulk_target_v1(jsonb)',
       '2b0ce5ef907aed6ee53fe8bf3f23a8fae939304185752d80a526b22ccac487f6',
       true,'v',ARRAY['periapsis_migrator','periapsis_worker']::text[]),
      (ARRAY['bulk']::text[],
       'app.private_apply_ticket_bulk_mutation_v1(public.ticket_aggregate_kind,uuid,text,integer,integer,uuid,integer,text,text,text,boolean,uuid,uuid,uuid,text,text,text,jsonb,bytea,bytea,uuid,uuid,inet,text,text)',
       '5fef80c1851843719bdfbe83f61feed2eebf5e31156ec3a929d70420f60b9fb2',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk']::text[],
       'app.private_append_ticket_bulk_mutation_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)',
       'e1a56ad722b603d2a0c6c67b2350bf99069f1fa60267f6a1c17132c32e1d9f1a',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk','export']::text[],
       'app.private_ticket_runtime_append_human_effects_v1(uuid,jsonb,jsonb,text,text,uuid,bigint,timestamp with time zone,jsonb)',
       'c171f2fc279b6e6deae34a258d58ac45e1f63421f8c6e896987a870d8a2e0695',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk','export']::text[],
       'app.private_ticket_runtime_catalog_digest_v1(text)',
       'ca5fcd0dd6313ae9c087fd9374a21912fc4b39039e6b196076bc278f2411db23',
       false,'i',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['bulk','export']::text[],
       'app.private_ticket_runtime_append_system_effects_v1(uuid,text,text,uuid,bigint,timestamp with time zone,text,jsonb)',
       '43dbd715c96c3ce908a980bb96c1840ce69edd5c2cffa11e1287b43c565eb941',
       true,'v',ARRAY['periapsis_migrator']::text[]),
      (ARRAY['export']::text[],
       'app.private_ticket_export_requester_live_v1(public.ticket_export_jobs)',
       'd36935995ea90ca8150dde407eae130096b1aa30a5ab89fd6364cbaea4877f41',
       true,'v',ARRAY['periapsis_migrator']::text[])
    ) AS expected(
      surfaces,identity,source_hash,security_definer,volatility,execute_roles
    )
    WHERE p_surface=ANY(expected.surfaces)
  LOOP
    IF pg_catalog.to_regprocedure(expected_function.identity) IS NULL
       OR NOT EXISTS (
         SELECT 1
         FROM pg_catalog.pg_proc AS procedure
         JOIN pg_catalog.pg_roles AS owner ON owner.oid=procedure.proowner
         WHERE procedure.oid=
           pg_catalog.to_regprocedure(expected_function.identity)
           AND owner.rolname='periapsis_migrator'
           AND procedure.prosecdef=expected_function.security_definer
           AND procedure.provolatile=expected_function.volatility
           AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
             procedure.prosrc,'UTF8')),'hex')=expected_function.source_hash
           AND (
             SELECT pg_catalog.array_agg(
                      grantee.rolname::text ORDER BY grantee.rolname
                    )=expected_function.execute_roles
                    AND pg_catalog.bool_and(
                      privilege.grantor=procedure.proowner
                      AND privilege.privilege_type='EXECUTE'
                      AND NOT privilege.is_grantable
                    )
             FROM pg_catalog.aclexplode(coalesce(
               procedure.proacl,
               pg_catalog.acldefault('f',procedure.proowner)
             )) AS privilege
             LEFT JOIN pg_catalog.pg_roles AS grantee
               ON grantee.oid=privilege.grantee
           )
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END;
$function$;
ALTER FUNCTION app.private_v45_ticket_runtime_repairs_ready(text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_v45_ticket_runtime_repairs_ready(text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner;
--> statement-breakpoint

DO $harden_ticket_bulk_runtime_readiness_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  hardened_definition text;
  marker constant text := '  RETURN EXISTS (';
  prerequisite constant text :=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_proc AS procedure' || chr(10) ||
    '    JOIN pg_catalog.pg_roles AS owner' || chr(10) ||
    '      ON owner.oid=procedure.proowner' || chr(10) ||
    '    WHERE procedure.oid=' || chr(10) ||
    '      ''app.private_v45_ticket_runtime_repairs_ready(text)''::regprocedure' ||
    chr(10) ||
    '      AND owner.rolname=''periapsis_migrator''' || chr(10) ||
    '      AND procedure.prosecdef AND procedure.provolatile=''s''' ||
    chr(10) ||
    '      AND pg_catalog.encode(pg_catalog.sha256(' || chr(10) ||
    '        pg_catalog.convert_to(procedure.prosrc,''UTF8'')' || chr(10) ||
    '      ),''hex'')=' || chr(10) ||
    '        ''ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a''' ||
    chr(10) ||
    '      AND (SELECT count(*)=1 AND coalesce(bool_and(' || chr(10) ||
    '        privilege.grantor=procedure.proowner' || chr(10) ||
    '        AND privilege.grantee=procedure.proowner' || chr(10) ||
    '        AND privilege.privilege_type=''EXECUTE''' || chr(10) ||
    '        AND NOT privilege.is_grantable' || chr(10) ||
    '      ),false) FROM pg_catalog.aclexplode(coalesce(' || chr(10) ||
    '        procedure.proacl,pg_catalog.acldefault(''f'',procedure.proowner)' ||
    chr(10) || '      )) AS privilege)' || chr(10) ||
    '  ) OR NOT app.private_v45_ticket_runtime_repairs_ready(''bulk'') THEN' ||
    chr(10) || '    RETURN false;' || chr(10) || '  END IF;' ||
    chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_bulk_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
    '934430d5c3711a8959cac382ae6626b97c32418cf0b53a75e1a48ee603d8a5c6' THEN
    RAISE EXCEPTION 'ticket bulk runtime readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,marker)=0 THEN
    RAISE EXCEPTION 'ticket bulk runtime readiness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  hardened_definition:=pg_catalog.replace(
    predecessor_definition,marker,prerequisite || marker
  );
  EXECUTE hardened_definition;
END;
$harden_ticket_bulk_runtime_readiness_v1$;
--> statement-breakpoint

DO $harden_ticket_export_runtime_readiness_v1$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  hardened_definition text;
  marker constant text := '  RETURN EXISTS (';
  prerequisite constant text :=
    '  IF NOT EXISTS (' || chr(10) ||
    '    SELECT 1 FROM pg_catalog.pg_proc AS procedure' || chr(10) ||
    '    JOIN pg_catalog.pg_roles AS owner' || chr(10) ||
    '      ON owner.oid=procedure.proowner' || chr(10) ||
    '    WHERE procedure.oid=' || chr(10) ||
    '      ''app.private_v45_ticket_runtime_repairs_ready(text)''::regprocedure' ||
    chr(10) ||
    '      AND owner.rolname=''periapsis_migrator''' || chr(10) ||
    '      AND procedure.prosecdef AND procedure.provolatile=''s''' ||
    chr(10) ||
    '      AND pg_catalog.encode(pg_catalog.sha256(' || chr(10) ||
    '        pg_catalog.convert_to(procedure.prosrc,''UTF8'')' || chr(10) ||
    '      ),''hex'')=' || chr(10) ||
    '        ''ad0ed7a40341483fd04a45efddb83d4f2523ba295dc80d8abaf90da4d38c304a''' ||
    chr(10) ||
    '      AND (SELECT count(*)=1 AND coalesce(bool_and(' || chr(10) ||
    '        privilege.grantor=procedure.proowner' || chr(10) ||
    '        AND privilege.grantee=procedure.proowner' || chr(10) ||
    '        AND privilege.privilege_type=''EXECUTE''' || chr(10) ||
    '        AND NOT privilege.is_grantable' || chr(10) ||
    '      ),false) FROM pg_catalog.aclexplode(coalesce(' || chr(10) ||
    '        procedure.proacl,pg_catalog.acldefault(''f'',procedure.proowner)' ||
    chr(10) || '      )) AS privilege)' || chr(10) ||
    '  ) OR NOT app.private_v45_ticket_runtime_repairs_ready(''export'') THEN' ||
    chr(10) || '    RETURN false;' || chr(10) || '  END IF;' ||
    chr(10) || chr(10);
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.ticket_export_runtime_schema_readiness_v1()'::regprocedure;
  IF predecessor_source_hash<>
    'd490814bd4c9e1ecef70fc9abaddd8205ce45e27df6cf49174e7d1f816e49c26' THEN
    RAISE EXCEPTION 'ticket export runtime readiness v1 drifted'
      USING ERRCODE='55000';
  END IF;
  IF pg_catalog.strpos(predecessor_definition,marker)=0 THEN
    RAISE EXCEPTION 'ticket export runtime readiness v1 marker drifted'
      USING ERRCODE='55000';
  END IF;
  hardened_definition:=pg_catalog.replace(
    predecessor_definition,marker,prerequisite || marker
  );
  EXECUTE hardened_definition;
END;
$harden_ticket_export_runtime_readiness_v1$;
--> statement-breakpoint

CREATE FUNCTION app.schema_compatibility_v45()
RETURNS TABLE(
  applied_count bigint,latest_created_at bigint,latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  latest_rows bigint;
  journal_fingerprint text;
  self_catalog_ready boolean;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint,max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1788128702258
           )::bigint,
           string_agg(
             migration.created_at::text || '@' || lower(migration.hash::text),
             ':' ORDER BY migration.created_at,migration.id
           )
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,latest_rows,
                journal_fingerprint;
  SELECT count(*)=1 INTO self_catalog_ready
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_namespace AS namespace
    ON namespace.oid=function_row.pronamespace
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  JOIN pg_catalog.pg_language AS language ON language.oid=function_row.prolang
  WHERE function_row.oid='app.schema_compatibility_v45()'::regprocedure
    AND namespace.nspname='app' AND owner.rolname='periapsis_migrator'
    AND language.lanname='plpgsql' AND function_row.prokind='f'
    AND function_row.provolatile='s' AND function_row.prosecdef
    AND NOT function_row.proisstrict AND NOT function_row.proleakproof
    AND function_row.proparallel='u' AND function_row.pronargs=0
    AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
      'search_path=pg_catalog',
      'app.schema_compatibility_fingerprint=' || journal_fingerprint
    ]::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid)=
      'TABLE(applied_count bigint, latest_created_at bigint, latest_hash text, migration_fingerprint text)'
    AND (
      SELECT count(*)=3 AND coalesce(bool_and(
        function_acl.grantor=function_row.proowner
        AND function_acl.grantee IN (
          function_row.proowner,
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname='periapsis_api'),
          (SELECT role.oid FROM pg_catalog.pg_roles AS role
           WHERE role.rolname='periapsis_worker')
        ) AND function_acl.privilege_type='EXECUTE'
        AND NOT function_acl.is_grantable
      ),false)
      FROM pg_catalog.aclexplode(CASE WHEN pg_catalog.cardinality(coalesce(
        function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
      ))>0 THEN coalesce(
        function_row.proacl,pg_catalog.acldefault('f',function_row.proowner)
      ) ELSE NULL::pg_catalog.aclitem[] END) AS function_acl
    );
  IF journal_count=199 AND journal_latest_created_at=1788128702258
     AND latest_rows=1 AND self_catalog_ready
     AND journal_fingerprint=current_setting(
       'app.schema_compatibility_fingerprint',true
     ) THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint,max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at,migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint,0::bigint,
    'UNSUPPORTED'::text,'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v45() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v45()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v45()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

-- The SLA readiness root is deliberately owned by the isolated readiness
-- role and callable at runtime only by the worker. The NOLOGIN migration role
-- receives the narrow execute edge needed by the compatibility sealer; no
-- application login or role membership is broadened.
GRANT EXECUTE ON FUNCTION app.sla_trigger_action_runtime_schema_readiness_v1()
  TO periapsis_migrator;
--> statement-breakpoint

-- Install the final sealer source before deriving the v45 dependency surface,
-- so every private readiness root binds the post-seal catalog in one pass.
CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,p_expected_latest_created_at bigint,
  p_expected_latest_hash text,p_expected_migration_fingerprint text
)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  journal_latest_hash text;
  journal_fingerprint text;
  sealed_count bigint;
BEGIN
  IF p_expected_count IS DISTINCT FROM 199
     OR p_expected_latest_created_at IS DISTINCT FROM 1788128702258
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint !~
       '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){198}$' THEN
    RAISE EXCEPTION 'schema compatibility v45 seal input is invalid'
      USING ERRCODE='55000';
  END IF;
  EXECUTE $query$
    SELECT count(*)::bigint,max(migration.created_at)::bigint,
      (SELECT lower(latest.hash::text)
       FROM drizzle.__drizzle_migrations AS latest
       ORDER BY latest.created_at DESC,latest.id DESC LIMIT 1),
      string_agg(migration.created_at::text || '@' || lower(migration.hash::text),
        ':' ORDER BY migration.created_at,migration.id)
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count,journal_latest_created_at,journal_latest_hash,
                journal_fingerprint;
  IF ROW(journal_count,journal_latest_created_at,journal_latest_hash,
         journal_fingerprint) IS DISTINCT FROM
     ROW(p_expected_count,p_expected_latest_created_at,p_expected_latest_hash,
         p_expected_migration_fingerprint)
     OR NOT app.private_mfa_policy_administration_schema_readiness_v5()
     OR NOT app.private_platform_identity_runtime_schema_readiness_v11()
     OR NOT app.private_platform_oidc_direct_runtime_schema_readiness_v7()
     OR NOT app.private_platform_saml_direct_runtime_schema_readiness_v4()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v1()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v1()
     OR NOT app.ticket_export_runtime_schema_readiness_v1()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v1() THEN
    RAISE EXCEPTION 'schema compatibility v45 pre-seal verification failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE pg_catalog.format(
    'ALTER FUNCTION app.schema_compatibility_v45() SET app.schema_compatibility_fingerprint = %L',
    p_expected_migration_fingerprint
  );
  ALTER FUNCTION app.schema_compatibility_v44()
    SET app.schema_compatibility_fingerprint='RETIRED';
  REVOKE ALL ON FUNCTION app.schema_compatibility_v44()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v10()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v6()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v3()
    FROM periapsis_api,periapsis_worker;
  REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v4()
    FROM periapsis_api,periapsis_worker;
  SELECT compatibility.applied_count INTO sealed_count
  FROM app.schema_compatibility_v45() AS compatibility;
  IF sealed_count<>199
     OR NOT app.mfa_policy_administration_schema_readiness_v5()
     OR NOT app.platform_identity_runtime_schema_readiness_v11()
     OR NOT app.platform_oidc_direct_runtime_schema_readiness_v7()
     OR NOT app.platform_saml_direct_runtime_schema_readiness_v4()
     OR NOT app.ticket_mutation_runtime_schema_readiness_v1()
     OR NOT app.sla_trigger_action_runtime_schema_readiness_v1()
     OR NOT app.platform_local_account_runtime_schema_readiness_v1()
     OR NOT app.ticket_bulk_runtime_schema_readiness_v1()
     OR NOT app.ticket_export_runtime_schema_readiness_v1()
     OR NOT app.alert_dfir_runtime_schema_readiness_v1()
     OR NOT app.ticket_metadata_runtime_schema_readiness_v1()
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.schema_compatibility_v44()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.schema_compatibility_v44()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_identity_runtime_schema_readiness_v10()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_identity_runtime_schema_readiness_v10()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v6()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_oidc_direct_runtime_schema_readiness_v6()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v3()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.platform_saml_direct_runtime_schema_readiness_v3()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_api','app.mfa_policy_administration_schema_readiness_v4()'::regprocedure,'EXECUTE')
     OR pg_catalog.has_function_privilege(
       'periapsis_worker','app.mfa_policy_administration_schema_readiness_v4()'::regprocedure,'EXECUTE') THEN
    RAISE EXCEPTION 'schema compatibility v45 seal verification failed'
      USING ERRCODE='55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.seal_schema_compatibility_manifest(bigint,bigint,text,text)
  TO periapsis_migrator;
--> statement-breakpoint

DO $derive_platform_identity_dependency_surface_v11$
DECLARE
  predecessor_definition text;
  predecessor_source_hash text;
  derived_definition text;
  marker constant text := '        ''schema_compatibility_v45'',';
  exclusions constant text :=
    '        ''private_platform_identity_dependency_surface_hash_v10'',' || chr(10) ||
    '        ''private_platform_identity_runtime_schema_readiness_v10'',' || chr(10) ||
    '        ''platform_identity_runtime_schema_readiness_v10'',' || chr(10) ||
    '        ''schema_compatibility_v44'',' || chr(10) ||
    '        ''private_platform_oidc_direct_dependency_surface_hash_v7'',' || chr(10) ||
    '        ''private_platform_oidc_direct_runtime_schema_readiness_v7'',' || chr(10) ||
    '        ''platform_oidc_direct_runtime_schema_readiness_v7'',' || chr(10) ||
    '        ''private_platform_saml_direct_dependency_surface_hash_v4'',' || chr(10) ||
    '        ''private_platform_saml_direct_runtime_schema_readiness_v4'',' || chr(10) ||
    '        ''platform_saml_direct_runtime_schema_readiness_v4'',' || chr(10) ||
    '        ''private_mfa_policy_administration_dependency_surface_hash_v5'',' || chr(10) ||
    '        ''private_mfa_policy_administration_schema_readiness_v5'',' || chr(10) ||
    '        ''mfa_policy_administration_schema_readiness_v5'',';
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT predecessor_definition,predecessor_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v10()'::regprocedure;
  IF predecessor_source_hash<>
    '7dfc42e5dd59ab9fc99f901dbd1a3c1825dc7afa713d52a3258d1b28f16328dc' THEN
    RAISE EXCEPTION 'platform identity dependency v10 drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    predecessor_definition,
    'private_platform_identity_dependency_surface_hash_v10',
    'private_platform_identity_dependency_surface_hash_v11'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'private_platform_identity_runtime_schema_readiness_v10',
    'private_platform_identity_runtime_schema_readiness_v11'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'platform_identity_runtime_schema_readiness_v10',
    'platform_identity_runtime_schema_readiness_v11'
  );
  derived_definition:=pg_catalog.replace(
    derived_definition,'schema_compatibility_v44','schema_compatibility_v45'
  );
  IF pg_catalog.strpos(derived_definition,marker)=0 THEN
    RAISE EXCEPTION 'platform identity dependency v11 marker drifted'
      USING ERRCODE='55000';
  END IF;
  derived_definition:=pg_catalog.replace(
    derived_definition,marker,marker || chr(10) || exclusions
  );
  EXECUTE derived_definition;
END;
$derive_platform_identity_dependency_surface_v11$;
ALTER FUNCTION app.private_platform_identity_dependency_surface_hash_v11()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_dependency_surface_hash_v11()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v7()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v11();
$function$;
CREATE FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v4()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v11();
$function$;
CREATE FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v5()
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off SET TimeZone='UTC' SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres' SET extra_float_digits=3 SET bytea_output='hex'
SET standard_conforming_strings=on SET lc_numeric='C'
AS $function$
  SELECT app.private_platform_identity_dependency_surface_hash_v11();
$function$;
ALTER FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v7()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v4()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_dependency_surface_hash_v7()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_dependency_surface_hash_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_dependency_surface_hash_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_mfa_policy_private_readiness_v5$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_schema_readiness_v4()'::regprocedure;
  IF predecessor_hash<>
    '75ab3316475e5c86a04c358a535997c9de7f281651abbcd243c465d81b26ef2f' THEN
    RAISE EXCEPTION 'MFA policy private readiness v4 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_mfa_policy_administration_dependency_surface_hash_v5()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_mfa_policy_administration_dependency_surface_hash_v5()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v4',
    'private_mfa_policy_administration_dependency_surface_hash_v5');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v4',
    'private_mfa_policy_administration_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    '''app.mfa_policy_administration_schema_readiness_v4()''::regprocedure',
    '''app.mfa_policy_administration_schema_readiness_v4()''::regprocedure,' ||
    chr(10) ||
    '        ''app.mfa_policy_administration_schema_readiness_v5()''::regprocedure'
  );
  definition:=pg_catalog.replace(definition,
    '99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_mfa_policy_private_readiness_v5$;
ALTER FUNCTION app.private_mfa_policy_administration_schema_readiness_v5()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_mfa_policy_administration_schema_readiness_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_identity_private_readiness_v11$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_runtime_schema_readiness_v10()'::regprocedure;
  IF predecessor_hash<>
    '9c9ce8499400ac88c11ac7d58feb5b55bcc0cd70adc699bfcd0265ed6e3bf8c3' THEN
    RAISE EXCEPTION 'platform identity private readiness v10 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_identity_dependency_surface_hash_v11()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_identity_dependency_surface_hash_v11()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v10',
    'private_platform_identity_dependency_surface_hash_v11');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v10',
    'private_platform_identity_runtime_schema_readiness_v11');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v10',
    'platform_identity_runtime_schema_readiness_v11');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v44','schema_compatibility_v45');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v6',
    'private_platform_oidc_direct_dependency_surface_hash_v7');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v6',
    'private_platform_oidc_direct_runtime_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v6',
    'platform_oidc_direct_runtime_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v3',
    'private_platform_saml_direct_dependency_surface_hash_v4');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v3',
    'private_platform_saml_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v3',
    'platform_saml_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_dependency_surface_hash_v4',
    'private_mfa_policy_administration_dependency_surface_hash_v5');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v4',
    'private_mfa_policy_administration_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'mfa_policy_administration_schema_readiness_v4',
    'mfa_policy_administration_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    '7dfc42e5dd59ab9fc99f901dbd1a3c1825dc7afa713d52a3258d1b28f16328dc',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_identity_private_readiness_v11$;
ALTER FUNCTION app.private_platform_identity_runtime_schema_readiness_v11()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_identity_runtime_schema_readiness_v11()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_oidc_private_readiness_v7$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_runtime_schema_readiness_v6()'::regprocedure;
  IF predecessor_hash<>
    '6f5be706877b3307302a20a66d5365fa1ab1f3e6d1380ac524ecde6f6356c640' THEN
    RAISE EXCEPTION 'direct platform OIDC private readiness v6 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_oidc_direct_dependency_surface_hash_v7()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_oidc_direct_dependency_surface_hash_v7()'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_dependency_surface_hash_v6',
    'private_platform_oidc_direct_dependency_surface_hash_v7');
  definition:=pg_catalog.replace(definition,
    'private_platform_oidc_direct_runtime_schema_readiness_v6',
    'private_platform_oidc_direct_runtime_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    'platform_oidc_direct_runtime_schema_readiness_v6',
    'platform_oidc_direct_runtime_schema_readiness_v7');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_dependency_surface_hash_v10',
    'private_platform_identity_dependency_surface_hash_v11');
  definition:=pg_catalog.replace(definition,
    'private_platform_identity_runtime_schema_readiness_v10',
    'private_platform_identity_runtime_schema_readiness_v11');
  definition:=pg_catalog.replace(definition,
    'platform_identity_runtime_schema_readiness_v10',
    'platform_identity_runtime_schema_readiness_v11');
  definition:=pg_catalog.replace(definition,
    'private_mfa_policy_administration_schema_readiness_v4',
    'private_mfa_policy_administration_schema_readiness_v5');
  definition:=pg_catalog.replace(definition,
    'schema_compatibility_v44','schema_compatibility_v45');
  definition:=pg_catalog.replace(definition,
    '99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3',
    dependency_result_hash);
  EXECUTE definition;
END;
$derive_platform_oidc_private_readiness_v7$;
ALTER FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v7()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_oidc_direct_runtime_schema_readiness_v7()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

DO $derive_platform_saml_private_readiness_v4$
DECLARE
  definition text;
  predecessor_hash text;
  dependency_source_hash text;
  dependency_result_hash text;
  metadata_source_hash text;
BEGIN
  SELECT pg_catalog.pg_get_functiondef(function_row.oid),
         pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT definition,predecessor_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_runtime_schema_readiness_v3()'::regprocedure;
  IF predecessor_hash<>
    '4ade58979d5209e33d46871049c7b65d06b25fd6bc7b752c7b54b72431774099' THEN
    RAISE EXCEPTION 'direct platform SAML private readiness v3 drifted'
      USING ERRCODE='55000';
  END IF;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex'),
         app.private_platform_saml_direct_dependency_surface_hash_v4()
    INTO STRICT dependency_source_hash,dependency_result_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.private_platform_saml_direct_dependency_surface_hash_v4()'::regprocedure;
  SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
           function_row.prosrc,'UTF8')),'hex')
    INTO STRICT metadata_source_hash
  FROM pg_catalog.pg_proc AS function_row
  WHERE function_row.oid=
    'app.load_platform_saml_metadata_projection_v1(text)'::regprocedure;
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_dependency_surface_hash_v3',
    'private_platform_saml_direct_dependency_surface_hash_v4');
  definition:=pg_catalog.replace(definition,
    'private_platform_saml_direct_runtime_schema_readiness_v3',
    'private_platform_saml_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    'platform_saml_direct_runtime_schema_readiness_v3',
    'platform_saml_direct_runtime_schema_readiness_v4');
  definition:=pg_catalog.replace(definition,
    '99afa4cb8d70b7cbe41c70cc6c46c8a55c6d80c0cca8fb6676aa1e0b3f4a5598',
    dependency_source_hash);
  definition:=pg_catalog.replace(definition,
    '4489ff02510e0f26cda34fa52a8c146f6e1ef1e6a1f430648b4131032e241be3',
    dependency_result_hash);
  definition:=pg_catalog.replace(definition,
    'f3af6d609094cbd7a563b8465bc2560bc6bec1926e7b43945e122da3152db989',
    metadata_source_hash);
  EXECUTE definition;
END;
$derive_platform_saml_private_readiness_v4$;
ALTER FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_platform_saml_direct_runtime_schema_readiness_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
--> statement-breakpoint

CREATE FUNCTION app.mfa_policy_administration_schema_readiness_v5()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v45() AS compatibility;
  RETURN current_count=199
    AND app.private_mfa_policy_administration_schema_readiness_v5();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_identity_runtime_schema_readiness_v11()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v45() AS compatibility;
  RETURN current_count=199
    AND app.mfa_policy_administration_schema_readiness_v5()
    AND app.private_platform_identity_runtime_schema_readiness_v11();
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v7()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v45() AS compatibility;
  RETURN current_count=199
    AND app.platform_identity_runtime_schema_readiness_v11()
    AND app.private_platform_oidc_direct_runtime_schema_readiness_v7()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_oidc_direct_runtime_schema_readiness_v6()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
CREATE FUNCTION app.platform_saml_direct_runtime_schema_readiness_v4()
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app AS $function$
DECLARE current_count bigint;
BEGIN
  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v45() AS compatibility;
  RETURN current_count=199
    AND app.platform_identity_runtime_schema_readiness_v11()
    AND app.private_platform_saml_direct_runtime_schema_readiness_v4()
    AND NOT pg_catalog.has_function_privilege(
      'periapsis_api','app.platform_saml_direct_runtime_schema_readiness_v3()'::regprocedure,'EXECUTE');
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.mfa_policy_administration_schema_readiness_v5()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_identity_runtime_schema_readiness_v11()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v7()
  OWNER TO periapsis_migrator;
ALTER FUNCTION app.platform_saml_direct_runtime_schema_readiness_v4()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.mfa_policy_administration_schema_readiness_v5()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_identity_runtime_schema_readiness_v11()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v7()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
REVOKE ALL ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v4()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier;
GRANT EXECUTE ON FUNCTION app.mfa_policy_administration_schema_readiness_v5()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_identity_runtime_schema_readiness_v11()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_oidc_direct_runtime_schema_readiness_v7()
  TO periapsis_api,periapsis_worker;
GRANT EXECUTE ON FUNCTION app.platform_saml_direct_runtime_schema_readiness_v4()
  TO periapsis_api,periapsis_worker;
