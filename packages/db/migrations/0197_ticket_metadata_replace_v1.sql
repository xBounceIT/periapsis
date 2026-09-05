-- A single human-only ABI owns mutable Alert/Case metadata. The immutable
-- ticket_commands receipt binds actor, aggregate kind/id, expected version,
-- canonical payload, and the historical post-commit projection.
CREATE FUNCTION app.replace_tenant_ticket_metadata_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_expected_version bigint,
  p_title text,
  p_description text,
  p_summary text,
  p_severity text,
  p_priority text,
  p_category text,
  p_classification text,
  p_customer_visible boolean,
  p_tags text[],
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(
  result_version bigint,
  result_updated_at timestamp with time zone,
  result_metadata jsonb,
  replayed boolean
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
  actor_user uuid;
  operation text := p_aggregate_kind::text || '.metadata.replace';
  permission_key text := p_aggregate_kind::text || '.update';
  command_record public.ticket_commands%ROWTYPE;
  command_found boolean;
  current_version integer;
  current_title text;
  current_description text;
  current_summary text;
  current_severity text;
  current_priority text;
  current_category text;
  current_classification text;
  current_customer_visible boolean;
  current_tags text[];
  current_assigned_team uuid;
  current_owner_user uuid;
  current_assignee_user uuid;
  current_claimant_user uuid;
  operation_at timestamp with time zone := transaction_timestamp();
  committed_version integer;
  committed_updated_at timestamp with time zone;
  canonical_summary text := coalesce(p_summary,'');
  canonical_result jsonb;
  changed_fields text[];
  edge_whitespace constant text := E' \t\n\r\v\f'
    || U&'\0085\00A0\1680\2000\2001\2002\2003\2004\2005\2006\2007\2008\2009\200A\2028\2029\202F\205F\3000';
BEGIN
  IF p_aggregate_kind IS NULL
     OR p_ticket_id IS NULL OR uuid_extract_version(p_ticket_id)<>7
     OR p_expected_version IS NULL
        OR p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_title IS NULL OR btrim(p_title,edge_whitespace)=''
     OR p_title<>btrim(p_title,edge_whitespace)
     OR char_length(p_title)>240
     OR p_title ~ '[[:cntrl:]]'
     OR p_description IS NULL
     OR p_aggregate_kind='alert' AND (
       char_length(p_description)>10000
        OR p_description<>btrim(p_description,edge_whitespace)
       OR regexp_replace(p_description,E'[\t\n\r]','','g') ~ '[[:cntrl:]]'
     )
     OR p_aggregate_kind='case' AND (
       char_length(p_description)>20000
        OR p_description<>btrim(p_description,edge_whitespace)
       OR regexp_replace(p_description,E'[\t\n\r]','','g') ~ '[[:cntrl:]]'
     )
     OR p_aggregate_kind='alert' AND p_summary IS NOT NULL
     OR p_aggregate_kind='case' AND (
       p_summary IS NULL OR char_length(p_summary)>2000
        OR p_summary<>btrim(p_summary,edge_whitespace)
       OR regexp_replace(p_summary,E'[\t\n\r]','','g') ~ '[[:cntrl:]]'
     )
     OR p_severity IS NULL OR p_severity NOT IN (
       'informational','low','medium','high','critical'
     )
     OR p_priority IS NULL
        OR p_priority NOT IN ('low','medium','high','urgent','critical')
     OR p_category IS NULL OR btrim(p_category,edge_whitespace)=''
     OR p_category<>btrim(p_category,edge_whitespace)
     OR char_length(p_category)>120 OR p_category ~ '[[:cntrl:]]'
     OR p_classification IS NOT NULL AND (
        btrim(p_classification,edge_whitespace)=''
        OR p_classification<>btrim(p_classification,edge_whitespace)
       OR char_length(p_classification)>120
       OR p_classification ~ '[[:cntrl:]]'
     )
     OR p_customer_visible IS NULL
     OR p_tags IS NULL OR cardinality(p_tags)>100
     OR EXISTS (
       SELECT 1 FROM unnest(p_tags) AS tag(value)
       WHERE tag.value IS NULL
          OR tag.value !~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$'
     )
     OR p_tags IS DISTINCT FROM ARRAY(
       SELECT DISTINCT tag.value COLLATE "C"
       FROM unnest(p_tags) AS tag(value)
       ORDER BY tag.value COLLATE "C"
     )
     OR p_key_digest IS NULL OR octet_length(p_key_digest)<>32
     OR p_key_digest=decode(repeat('00',32),'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest)<>32
     OR p_request_digest=decode(repeat('00',32),'hex')
     OR p_request_id IS NULL OR uuid_extract_version(p_request_id)<>7
     OR p_correlation_id IS NULL
        OR uuid_extract_version(p_correlation_id)<>7
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR btrim(p_user_agent)=''
     OR char_length(p_user_agent)>1024 OR p_user_agent ~ '[[:cntrl:]]'
     OR p_authentication_method IS NULL
        OR p_authentication_method NOT IN (
       'bootstrap_totp','totp','recovery_code','ldap','oidc','saml','passkey'
     ) THEN
    RAISE EXCEPTION 'ticket metadata replacement input is invalid'
      USING ERRCODE='22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership:=app.current_tenant_membership_id();
  actor_user:=app.context_user_id();

  IF p_aggregate_kind='alert' THEN
    SELECT alert.version,alert.title,coalesce(alert.description,''),''::text,
           alert.severity::text,alert.priority,alert.category,
           alert.classification,alert.customer_visible,alert.tags,
           alert.assigned_team_id,alert.created_by,alert.assignee_user_id,
           alert.claimed_by_user_id
      INTO current_version,current_title,current_description,current_summary,
           current_severity,current_priority,current_category,
           current_classification,current_customer_visible,current_tags,
           current_assigned_team,current_owner_user,current_assignee_user,
           current_claimant_user
    FROM public.alerts AS alert
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL
    FOR UPDATE;
  ELSE
    SELECT case_record.version,case_record.title,case_record.description,
           case_record.summary,case_record.severity::text,
           case_record.priority,case_record.category,
           case_record.classification,case_record.customer_visible,
           case_record.tags,case_record.assigned_team_id,
           case_record.created_by_user_id,case_record.assignee_user_id,
           case_record.claimed_by_user_id
      INTO current_version,current_title,current_description,current_summary,
           current_severity,current_priority,current_category,
           current_classification,current_customer_visible,current_tags,
           current_assigned_team,current_owner_user,current_assignee_user,
           current_claimant_user
    FROM public.cases AS case_record
    WHERE case_record.tenant_id=context_tenant
      AND case_record.id=p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
    permission_key,current_assigned_team,current_owner_user,
    current_assignee_user,current_claimant_user
  ) THEN
    RAISE EXCEPTION 'ticket metadata replacement is unauthorized'
      USING ERRCODE='42501';
  END IF;

  -- Resolve idempotency only after the ticket lock and live authorization.
  -- A concurrent identical writer can commit while this call is waiting;
  -- the post-lock statement snapshot must observe and replay that receipt.
  SELECT command.* INTO command_record
  FROM public.ticket_commands AS command
  WHERE command.tenant_id=context_tenant
    AND command.actor_membership_id=actor_membership
    AND command.operation=operation
    AND command.key_digest=p_key_digest;
  command_found:=FOUND;

  IF command_found THEN
    canonical_result:=jsonb_build_object(
      'schema_version',1,
      'tenant_id',context_tenant,
      'ticket_id',p_ticket_id,
      'aggregate_kind',p_aggregate_kind::text,
      'title',p_title,
      'description',p_description,
      'summary',canonical_summary,
      'severity',p_severity,
      'priority',p_priority,
      'category',p_category,
      'classification',p_classification,
      'customer_visible',p_customer_visible,
      'tags',to_jsonb(p_tags),
      'version',command_record.result_version,
      'updated_at',command_record.created_at
    );
    IF command_record.request_digest IS DISTINCT FROM p_request_digest
       OR command_record.actor_user_id IS DISTINCT FROM actor_user
       OR command_record.result_version IS DISTINCT FROM
          (p_expected_version+1)::integer
       OR p_aggregate_kind='alert' AND (
         command_record.result_alert_id IS DISTINCT FROM p_ticket_id
         OR command_record.result_case_id IS NOT NULL
       )
       OR p_aggregate_kind='case' AND (
         command_record.result_case_id IS DISTINCT FROM p_ticket_id
         OR command_record.result_alert_id IS NOT NULL
       )
       OR command_record.result_metadata IS DISTINCT FROM canonical_result THEN
      RAISE EXCEPTION 'ticket metadata idempotency key conflicts'
        USING ERRCODE='23505',CONSTRAINT='ticket_commands_replay_key';
    END IF;
    RETURN QUERY SELECT command_record.result_version::bigint,
      command_record.created_at,command_record.result_metadata,true;
    RETURN;
  END IF;

  IF current_version IS DISTINCT FROM p_expected_version::integer THEN
    RAISE EXCEPTION 'ticket metadata version conflict'
      USING ERRCODE='40001';
  END IF;

  SELECT ARRAY(
    SELECT changed.name
    FROM (VALUES
      (1,'title',current_title IS DISTINCT FROM p_title),
      (2,'description',current_description IS DISTINCT FROM p_description),
      (3,'summary',p_aggregate_kind='case'
        AND current_summary IS DISTINCT FROM canonical_summary),
      (4,'severity',current_severity IS DISTINCT FROM p_severity),
      (5,'priority',current_priority IS DISTINCT FROM p_priority),
      (6,'category',current_category IS DISTINCT FROM p_category),
      (7,'classification',current_classification IS DISTINCT FROM
        p_classification),
      (8,'customer_visible',current_customer_visible IS DISTINCT FROM
        p_customer_visible),
      (9,'tags',current_tags IS DISTINCT FROM p_tags)
    ) AS changed(ordinal,name,is_changed)
    WHERE changed.is_changed
    ORDER BY changed.ordinal
  ) INTO changed_fields;
  IF cardinality(changed_fields)=0 THEN
    RAISE EXCEPTION 'ticket metadata replacement is a no-op'
      USING ERRCODE='23514';
  END IF;

  IF p_aggregate_kind='alert' THEN
    UPDATE public.alerts AS alert
    SET title=p_title,
        description=p_description,
        severity=p_severity::public.alert_severity,
        priority=p_priority,
        category=p_category,
        classification=p_classification,
        customer_visible=p_customer_visible,
        tags=p_tags,
        updated_at=operation_at,
        version=alert.version+1
    WHERE alert.tenant_id=context_tenant AND alert.id=p_ticket_id
      AND alert.deleted_at IS NULL AND alert.version=p_expected_version
      AND alert.version<2147483647
    RETURNING alert.version,alert.updated_at
      INTO committed_version,committed_updated_at;
  ELSE
    UPDATE public.cases AS case_record
    SET title=p_title,
        description=p_description,
        summary=canonical_summary,
        severity=p_severity::public.alert_severity,
        priority=p_priority,
        category=p_category,
        classification=p_classification,
        customer_visible=p_customer_visible,
        tags=p_tags,
        updated_at=operation_at,
        version=case_record.version+1
    WHERE case_record.tenant_id=context_tenant
      AND case_record.id=p_ticket_id
      AND case_record.version=p_expected_version
      AND case_record.version<2147483647
    RETURNING case_record.version,case_record.updated_at
      INTO committed_version,committed_updated_at;
  END IF;
  IF committed_version IS NULL THEN
    RAISE EXCEPTION 'ticket metadata version conflict'
      USING ERRCODE='40001';
  END IF;

  canonical_result:=jsonb_build_object(
    'schema_version',1,
    'tenant_id',context_tenant,
    'ticket_id',p_ticket_id,
    'aggregate_kind',p_aggregate_kind::text,
    'title',p_title,
    'description',p_description,
    'summary',canonical_summary,
    'severity',p_severity,
    'priority',p_priority,
    'category',p_category,
    'classification',p_classification,
    'customer_visible',p_customer_visible,
    'tags',to_jsonb(p_tags),
    'version',committed_version,
    'updated_at',committed_updated_at
  );

  INSERT INTO public.ticket_commands(
    id,tenant_id,operation,actor_membership_id,actor_user_id,
    key_digest,request_digest,result_alert_id,result_case_id,
    result_version,result_metadata,created_at
  ) VALUES (
    uuidv7(),context_tenant,operation,actor_membership,actor_user,
    p_key_digest,p_request_digest,
    CASE WHEN p_aggregate_kind='alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind='case' THEN p_ticket_id END,
    committed_version,canonical_result,committed_updated_at
  );

  PERFORM app.private_append_ticket_side_effects_v1(
    p_aggregate_kind,p_ticket_id,'metadata_updated',committed_version,
    ARRAY['activity','audit']::text[],p_request_id,p_correlation_id,
    p_ip_address,p_user_agent,p_authentication_method,
    jsonb_build_object(
      'version',current_version,'content_redacted',true
    ),
    jsonb_build_object(
      'version',committed_version,'content_redacted',true
    ),
    jsonb_build_object('changed_fields',to_jsonb(changed_fields))
  );

  RETURN QUERY SELECT committed_version::bigint,committed_updated_at,
    canonical_result,false;
END;
$function$;
ALTER FUNCTION app.replace_tenant_ticket_metadata_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,
  boolean,text[],bytea,bytea,uuid,uuid,inet,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.replace_tenant_ticket_metadata_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,
  boolean,text[],bytea,bytea,uuid,uuid,inet,text,text
) FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.replace_tenant_ticket_metadata_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,
  boolean,text[],bytea,bytea,uuid,uuid,inet,text,text
) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.ticket_metadata_runtime_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET quote_all_identifiers=off
SET TimeZone='UTC'
SET DateStyle='ISO, YMD'
SET IntervalStyle='postgres'
SET extra_float_digits=3
SET bytea_output='hex'
SET standard_conforming_strings=on
SET lc_numeric='C'
AS $function$
DECLARE
  function_record pg_catalog.pg_proc%ROWTYPE;
BEGIN
  SELECT function_row.* INTO function_record
  FROM pg_catalog.pg_proc AS function_row
  JOIN pg_catalog.pg_roles AS owner ON owner.oid=function_row.proowner
  WHERE function_row.oid=
    'app.replace_tenant_ticket_metadata_v1(public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,boolean,text[],bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure
    AND owner.rolname='periapsis_migrator'
    AND function_row.prokind='f' AND function_row.provolatile='v'
    AND function_row.prosecdef AND NOT function_row.proisstrict
    AND NOT function_row.proleakproof AND function_row.proparallel='u'
    AND function_row.proconfig IS NOT DISTINCT FROM
      ARRAY['search_path=pg_catalog, public, app']::text[]
    AND pg_catalog.pg_get_function_result(function_row.oid)=
      'TABLE(result_version bigint, result_updated_at timestamp with time zone, result_metadata jsonb, replayed boolean)';
  IF NOT FOUND
     OR NOT pg_catalog.has_function_privilege(
       'periapsis_api',function_record.oid,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_worker',function_record.oid,'EXECUTE'
     )
     OR pg_catalog.has_function_privilege(
       'periapsis_notifier',function_record.oid,'EXECUTE'
     )
     OR EXISTS (
       SELECT 1
       FROM pg_catalog.aclexplode(coalesce(
         function_record.proacl,
         pg_catalog.acldefault('f',function_record.proowner)
       )) AS privilege
       WHERE privilege.grantee=0 AND privilege.privilege_type='EXECUTE'
     ) THEN
    RETURN false;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_roles AS owner ON owner.oid=relation.relowner
    WHERE relation.oid='public.ticket_commands'::regclass
      AND relation.relkind='r' AND relation.relrowsecurity
      AND relation.relforcerowsecurity
      AND owner.rolname='periapsis_migrator'
      AND NOT pg_catalog.has_table_privilege(
        'periapsis_api',relation.oid,'SELECT,INSERT,UPDATE,DELETE'
      )
      AND NOT pg_catalog.has_table_privilege(
        'periapsis_worker',relation.oid,'SELECT,INSERT,UPDATE,DELETE'
      )
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid='public.ticket_commands'::regclass
      AND constraint_row.conname='ticket_commands_replay_key'
      AND constraint_row.contype='u' AND constraint_row.convalidated
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
    WHERE constraint_row.conrelid='public.ticket_commands'::regclass
      AND constraint_row.conname='ticket_commands_metadata_check'
      AND constraint_row.contype='c' AND constraint_row.convalidated
      AND pg_catalog.pg_get_constraintdef(constraint_row.oid) LIKE
        '%jsonb_typeof(result_metadata)%object%'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_trigger AS trigger_row
    WHERE trigger_row.tgrelid='public.ticket_commands'::regclass
      AND trigger_row.tgname='ticket_commands_immutable_v1'
      AND NOT trigger_row.tgisinternal AND trigger_row.tgenabled='O'
      AND trigger_row.tgfoid=
        'app.guard_ticketing_append_only_v1()'::regprocedure
  ) THEN
    RETURN false;
  END IF;
  RETURN true;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.ticket_metadata_runtime_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_metadata_runtime_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.ticket_metadata_runtime_schema_readiness_v1()
  TO periapsis_api,periapsis_worker;
--> statement-breakpoint

COMMENT ON FUNCTION app.replace_tenant_ticket_metadata_v1(
  public.ticket_aggregate_kind,uuid,bigint,text,text,text,text,text,text,text,
  boolean,text[],bytea,bytea,uuid,uuid,inet,text,text
) IS
  'Human-only CAS/idempotent Alert or Case metadata replacement with a stable immutable receipt and atomic redacted activity/audit/outbox effects.';
