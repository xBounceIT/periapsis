-- PostgreSQL binds NEW and OLD as table-shaped records for a trigger call.
-- A CASE expression that mentions columns from multiple trigger relations can
-- therefore fail before selecting the intended arm. Dispatch in PL/pgSQL
-- control flow so every branch references only columns present on that table.
CREATE OR REPLACE FUNCTION app.guard_ticket_comment_aggregate_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid;
  comment_id uuid;
BEGIN
  IF TG_TABLE_SCHEMA <> 'public' THEN
    RAISE EXCEPTION 'ticket comment aggregate guard rejected relation %.%',
      TG_TABLE_SCHEMA,TG_TABLE_NAME
      USING ERRCODE = '55000';
  ELSIF TG_TABLE_NAME = 'ticket_comments' THEN
    IF TG_OP = 'DELETE' THEN
      tenant_id := OLD.tenant_id;
      comment_id := OLD.id;
    ELSE
      tenant_id := NEW.tenant_id;
      comment_id := NEW.id;
    END IF;
  ELSIF TG_TABLE_NAME = 'ticket_comment_revisions' THEN
    IF TG_OP = 'DELETE' THEN
      tenant_id := OLD.tenant_id;
      comment_id := OLD.comment_id;
    ELSE
      tenant_id := NEW.tenant_id;
      comment_id := NEW.comment_id;
    END IF;
  ELSIF TG_TABLE_NAME = 'ticket_comment_author_snapshots' THEN
    IF TG_OP = 'DELETE' THEN
      tenant_id := OLD.tenant_id;
      comment_id := OLD.comment_id;
    ELSE
      tenant_id := NEW.tenant_id;
      comment_id := NEW.comment_id;
    END IF;
  ELSIF TG_TABLE_NAME = 'ticket_comment_escalation_sources' THEN
    IF TG_OP = 'DELETE' THEN
      tenant_id := OLD.tenant_id;
      comment_id := OLD.copied_comment_id;
    ELSE
      tenant_id := NEW.tenant_id;
      comment_id := NEW.copied_comment_id;
    END IF;
  ELSIF TG_TABLE_NAME = 'ticket_comment_revision_attachments' THEN
    IF TG_OP = 'DELETE' THEN
      tenant_id := OLD.tenant_id;
      SELECT revision.comment_id INTO STRICT comment_id
      FROM public.ticket_comment_revisions AS revision
      WHERE revision.tenant_id = OLD.tenant_id
        AND revision.id = OLD.revision_id;
    ELSE
      tenant_id := NEW.tenant_id;
      SELECT revision.comment_id INTO STRICT comment_id
      FROM public.ticket_comment_revisions AS revision
      WHERE revision.tenant_id = NEW.tenant_id
        AND revision.id = NEW.revision_id;
    END IF;
  ELSIF TG_TABLE_NAME = 'ticket_comment_revision_mentions' THEN
    IF TG_OP = 'DELETE' THEN
      tenant_id := OLD.tenant_id;
      SELECT revision.comment_id INTO STRICT comment_id
      FROM public.ticket_comment_revisions AS revision
      WHERE revision.tenant_id = OLD.tenant_id
        AND revision.id = OLD.revision_id;
    ELSE
      tenant_id := NEW.tenant_id;
      SELECT revision.comment_id INTO STRICT comment_id
      FROM public.ticket_comment_revisions AS revision
      WHERE revision.tenant_id = NEW.tenant_id
        AND revision.id = NEW.revision_id;
    END IF;
  ELSE
    RAISE EXCEPTION 'ticket comment aggregate guard rejected relation %.%',
      TG_TABLE_SCHEMA,TG_TABLE_NAME
      USING ERRCODE = '55000';
  END IF;

  IF tenant_id IS NULL OR comment_id IS NULL THEN
    RAISE EXCEPTION 'ticket comment aggregate guard resolved an incomplete identity'
      USING ERRCODE = '23514';
  END IF;
  PERFORM app.private_ticket_comment_assert_consistent_v1(
    tenant_id,comment_id
  );
  RETURN NULL;
END;
$function$;
ALTER FUNCTION app.guard_ticket_comment_aggregate_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.guard_ticket_comment_aggregate_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor,periapsis_ticket_runtime_owner;
--> statement-breakpoint

-- PostgreSQL 18 does not define max(uuid). Preserve UUIDv7 keyset ordering by
-- selecting the final row from the already bounded page instead of casting.
DO $repair_ticket_comment_page_cursor_v1$
DECLARE
  definition text;
  source_hash text;
  expected record;
  predecessor_expression constant text := '(SELECT max(id) FROM page)';
  successor_expression constant text :=
    '(SELECT id FROM page ORDER BY id DESC LIMIT 1)';
BEGIN
  FOR expected IN
    SELECT * FROM (VALUES
      ('app.list_tenant_ticket_comments_v2(public.ticket_aggregate_kind,uuid,uuid,integer)',
       'c7f102189bd2fb0ae6084d82a437164d87bcec38db176aa9c1a976450fe064a0'),
      ('app.list_customer_portal_ticket_comments_v2(public.ticket_aggregate_kind,uuid,uuid,integer)',
       '793ae58572424af2c14b63419179b20e0264ec160969f7f53093f7ec2fa7967b')
    ) AS value(function_identity,predecessor_hash)
  LOOP
    SELECT pg_catalog.pg_get_functiondef(function_row.oid),
           pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
             function_row.prosrc,'UTF8'
           )),'hex')
      INTO STRICT definition,source_hash
    FROM pg_catalog.pg_proc AS function_row
    WHERE function_row.oid=expected.function_identity::regprocedure;

    IF source_hash <> expected.predecessor_hash
       OR pg_catalog.strpos(definition,predecessor_expression) = 0
       OR pg_catalog.strpos(definition,successor_expression) <> 0 THEN
      RAISE EXCEPTION 'ticket comment list ABI drifted: %',
        expected.function_identity
        USING ERRCODE = '55000';
    END IF;
    definition := pg_catalog.replace(
      definition,predecessor_expression,successor_expression
    );
    IF pg_catalog.strpos(definition,predecessor_expression) <> 0
       OR pg_catalog.strpos(definition,successor_expression) = 0 THEN
      RAISE EXCEPTION 'ticket comment page cursor repair failed: %',
        expected.function_identity
        USING ERRCODE = '55000';
    END IF;
    EXECUTE definition;
  END LOOP;
END;
$repair_ticket_comment_page_cursor_v1$;
ALTER FUNCTION app.list_tenant_ticket_comments_v2(
  public.ticket_aggregate_kind,uuid,uuid,integer
) OWNER TO periapsis_migrator;
ALTER FUNCTION app.list_customer_portal_ticket_comments_v2(
  public.ticket_aggregate_kind,uuid,uuid,integer
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.list_tenant_ticket_comments_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
  ),
  app.list_customer_portal_ticket_comments_v2(
    public.ticket_aggregate_kind,uuid,uuid,integer
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
  )
TO periapsis_api;
--> statement-breakpoint

-- The legacy and current export authorization helpers are both reachable.
-- Fail closed if either predecessor source moved, then replace min(uuid) with
-- an exact count followed by deterministic UUID ordering.
DO $verify_ticket_export_customer_contact_sources_v1$
DECLARE
  expected record;
BEGIN
  FOR expected IN
    SELECT * FROM (VALUES
      ('app.private_ticket_export_require_human_v1(jsonb,uuid,public.ticket_aggregate_kind,text,text)',
       'f2a3acb742662362357692566247c7eaeff6d332b028d989d71eaf8b3fed3052'),
      ('app.private_ticket_export_require_human_v2(jsonb,uuid,public.ticket_aggregate_kind,text,text)',
       '5707314bf8bd446e49f100a1635929bcde46dd8ac02ff98795d3c693abf9bdf0')
    ) AS value(function_identity,source_hash)
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_proc AS function_row
      JOIN pg_catalog.pg_roles AS owner
        ON owner.oid=function_row.proowner
      WHERE function_row.oid=expected.function_identity::regprocedure
        AND owner.rolname='periapsis_migrator'
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          function_row.prosrc,'UTF8'
        )),'hex')=expected.source_hash
    ) THEN
      RAISE EXCEPTION 'ticket export customer authority ABI drifted: %',
        expected.function_identity
        USING ERRCODE='55000';
    END IF;
  END LOOP;
END;
$verify_ticket_export_customer_contact_sources_v1$;
--> statement-breakpoint

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
$function$;
ALTER FUNCTION app.private_ticket_export_require_human_v2(
  jsonb,uuid,public.ticket_aggregate_kind,text,text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION
  app.private_ticket_export_require_human_v2(
    jsonb,uuid,public.ticket_aggregate_kind,text,text
  )
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- This root is intentionally independent of a compatibility-count wrapper so
-- it remains callable while 0209, 0210 and the platform LDAP slice are applied
-- in sequence. The next compatibility seal binds it to the final journal.
CREATE FUNCTION app.ticket_comment_runtime_repair_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  expected record;
  relation_oid regclass;
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_proc AS function_row
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = function_row.pronamespace
    JOIN pg_catalog.pg_roles AS owner
      ON owner.oid = function_row.proowner
    JOIN pg_catalog.pg_language AS language
      ON language.oid = function_row.prolang
    WHERE function_row.oid =
      'app.guard_ticket_comment_aggregate_v1()'::regprocedure
      AND namespace.nspname = 'app'
      AND owner.rolname = 'periapsis_migrator'
      AND language.lanname = 'plpgsql'
      AND function_row.prokind = 'f'
      AND function_row.provolatile = 'v'
      AND function_row.prosecdef
      AND NOT function_row.proisstrict
      AND NOT function_row.proleakproof
      AND function_row.proparallel = 'u'
      AND function_row.pronargs = 0
      AND function_row.prorettype = 'trigger'::regtype
      AND function_row.proconfig IS NOT DISTINCT FROM
        ARRAY['search_path=pg_catalog, public, app']::text[]
      AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
        function_row.prosrc,'UTF8'
      )),'hex') =
        '1a8784d7831eb3eb2ac471967e2251546bfb009d16a06edf2e24d8b86df533e7'
      AND (
        SELECT count(*) = 1 AND coalesce(bool_and(
          privilege.grantor = function_row.proowner
          AND privilege.grantee = function_row.proowner
          AND privilege.privilege_type = 'EXECUTE'
          AND NOT privilege.is_grantable
        ),false)
        FROM pg_catalog.aclexplode(coalesce(
          function_row.proacl,
          pg_catalog.acldefault('f',function_row.proowner)
        )) AS privilege
      )
  ) THEN
    RETURN false;
  END IF;

  FOR expected IN
    SELECT * FROM (VALUES
      ('app.list_tenant_ticket_comments_v2(public.ticket_aggregate_kind,uuid,uuid,integer)',
       '6aa816195c40e630cb337c8af0ba161b305f9db7478012c8b09e3937a7d89106'),
      ('app.list_customer_portal_ticket_comments_v2(public.ticket_aggregate_kind,uuid,uuid,integer)',
       'ff5e75cfa0a78df943963fc48bcd64704642dd5647f924f2ca5c04b032e5f5e4')
    ) AS value(function_identity,source_hash)
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_proc AS function_row
      JOIN pg_catalog.pg_roles AS owner
        ON owner.oid = function_row.proowner
      WHERE function_row.oid = expected.function_identity::regprocedure
        AND owner.rolname = 'periapsis_migrator'
        AND function_row.prokind = 'f'
        AND function_row.provolatile = 's'
        AND function_row.prosecdef
        AND NOT function_row.proisstrict
        AND NOT function_row.proleakproof
        AND function_row.proparallel = 'u'
        AND function_row.pronargs = 4
        AND function_row.proconfig IS NOT DISTINCT FROM ARRAY[
          'search_path=pg_catalog, public, app','TimeZone=UTC'
        ]::text[]
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          function_row.prosrc,'UTF8'
        )),'hex') = expected.source_hash
        AND (
          SELECT count(*) = 2 AND coalesce(bool_and(
            privilege.grantor = function_row.proowner
            AND privilege.grantee IN (
              function_row.proowner,
              (SELECT role.oid FROM pg_catalog.pg_roles AS role
               WHERE role.rolname = 'periapsis_api')
            )
            AND privilege.privilege_type = 'EXECUTE'
            AND NOT privilege.is_grantable
          ),false)
          FROM pg_catalog.aclexplode(coalesce(
            function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner)
          )) AS privilege
        )
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR expected IN
    SELECT * FROM (VALUES
      ('app.private_ticket_export_require_human_v1(jsonb,uuid,public.ticket_aggregate_kind,text,text)',
       'f2a3acb742662362357692566247c7eaeff6d332b028d989d71eaf8b3fed3052'),
      ('app.private_ticket_export_require_human_v2(jsonb,uuid,public.ticket_aggregate_kind,text,text)',
       'fee31ac38c6d410b9dcfa39bf1327acfaea350c2c429aa4ad20f9cc647bd9d29')
    ) AS value(function_identity,source_hash)
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_proc AS function_row
      JOIN pg_catalog.pg_roles AS owner
        ON owner.oid = function_row.proowner
      WHERE function_row.oid = expected.function_identity::regprocedure
        AND owner.rolname = 'periapsis_migrator'
        AND function_row.prokind = 'f'
        AND function_row.provolatile = 'v'
        AND function_row.prosecdef
        AND NOT function_row.proisstrict
        AND NOT function_row.proleakproof
        AND function_row.proparallel = 'u'
        AND function_row.pronargs = 5
        AND function_row.proconfig IS NOT DISTINCT FROM
          ARRAY['search_path=pg_catalog, public, app']::text[]
        AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(
          function_row.prosrc,'UTF8'
        )),'hex') = expected.source_hash
        AND (
          SELECT count(*) = 1 AND coalesce(bool_and(
            privilege.grantor = function_row.proowner
            AND privilege.grantee = function_row.proowner
            AND privilege.privilege_type = 'EXECUTE'
            AND NOT privilege.is_grantable
          ),false)
          FROM pg_catalog.aclexplode(coalesce(
            function_row.proacl,
            pg_catalog.acldefault('f',function_row.proowner)
          )) AS privilege
        )
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR expected IN
    SELECT * FROM (VALUES
      ('ticket_comments','ticket_comments_consistency_v1'),
      ('ticket_comment_revisions','ticket_comment_revisions_consistency_v1'),
      ('ticket_comment_author_snapshots',
       'ticket_comment_author_snapshots_consistency_v1'),
      ('ticket_comment_escalation_sources',
       'ticket_comment_escalation_sources_consistency_v1'),
      ('ticket_comment_revision_attachments',
       'ticket_comment_revision_attachments_consistency_v1'),
      ('ticket_comment_revision_mentions',
       'ticket_comment_revision_mentions_consistency_v1')
    ) AS value(table_name,trigger_name)
  LOOP
    relation_oid := pg_catalog.to_regclass(
      pg_catalog.format('public.%I',expected.table_name)
    );
    IF relation_oid IS NULL OR NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_trigger AS trigger_row
      WHERE trigger_row.tgrelid = relation_oid
        AND trigger_row.tgname = expected.trigger_name
        AND trigger_row.tgfoid =
          'app.guard_ticket_comment_aggregate_v1()'::regprocedure
        AND trigger_row.tgtype = 29
        AND trigger_row.tgenabled = 'O'
        AND NOT trigger_row.tgisinternal
        AND trigger_row.tgdeferrable
        AND trigger_row.tginitdeferred
        AND trigger_row.tgnargs = 0
        AND trigger_row.tgqual IS NULL
    ) OR (
      SELECT count(*) <> 1
      FROM pg_catalog.pg_trigger AS trigger_row
      WHERE trigger_row.tgrelid = relation_oid
        AND trigger_row.tgname = expected.trigger_name
        AND NOT trigger_row.tgisinternal
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  RETURN true;
EXCEPTION WHEN undefined_table OR undefined_function OR insufficient_privilege
  OR invalid_schema_name OR cardinality_violation OR data_exception THEN
  RETURN false;
END;
$function$;
ALTER FUNCTION app.ticket_comment_runtime_repair_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_comment_runtime_repair_schema_readiness_v1()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
       periapsis_auditor,periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION app.ticket_comment_runtime_repair_schema_readiness_v1()
  TO periapsis_api,periapsis_worker;
