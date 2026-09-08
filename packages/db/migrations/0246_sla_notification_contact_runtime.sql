-- Row-level locks require UPDATE privilege on at least one column. Grant it
-- only on the immutable identifier; existing tenant-scoped SELECT policies
-- permit visibility. UPDATE USING permits row locks, while WITH CHECK (false)
-- rejects every attempted mutation, including an unchanged identifier.
GRANT UPDATE(id) ON public.tenant_notification_smtp_configurations,
  public.tenant_notification_webhook_configurations
TO periapsis_sla_worker_owner;
--> statement-breakpoint
CREATE POLICY tenant_smtp_sla_action_lock_v1
ON public.tenant_notification_smtp_configurations AS PERMISSIVE FOR UPDATE
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND revoked_at IS NULL)
WITH CHECK (false);
--> statement-breakpoint
CREATE POLICY tenant_webhook_sla_action_lock_v1
ON public.tenant_notification_webhook_configurations AS PERMISSIVE FOR UPDATE
TO periapsis_sla_worker_owner
USING (tenant_id = app.context_tenant_id() AND revoked_at IS NULL)
WITH CHECK (false);
--> statement-breakpoint

-- Both ticket variants expose the same authorization record shape. PostgreSQL
-- resolves record fields before evaluating CASE, including the untaken branch.
CREATE OR REPLACE FUNCTION app.replay_customer_contact_command_v1(
  p_operation text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_resource_id uuid,
  p_ticket_kind public.ticket_aggregate_kind,
  p_ticket_id uuid
)
RETURNS TABLE(
  resource_id uuid,
  version integer,
  projection text,
  resource jsonb
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
  command_record public.customer_contact_commands%ROWTYPE;
  ticket_record record;
  ticket_permission text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN (
       'contact.create', 'contact.replace', 'contact.archive',
       'portal.preference.replace',
       'contact_group.create', 'contact_group.version',
       'contact_group.archive', 'ticket_contact.link',
       'ticket_contact.archive'
     )
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_operation NOT IN ('contact.create', 'contact_group.create',
                            'ticket_contact.link')
        AND p_resource_id IS NULL
     OR p_operation LIKE 'ticket_contact.%' AND (
       p_ticket_kind IS NULL OR p_ticket_id IS NULL
       OR (uuid_extract_version(p_ticket_id) = 7) IS NOT TRUE
     )
     OR p_operation NOT LIKE 'ticket_contact.%' AND (
       p_ticket_kind IS NOT NULL OR p_ticket_id IS NOT NULL
     ) THEN
    RAISE EXCEPTION 'customer contact replay envelope is invalid'
      USING ERRCODE = '22023';
  END IF;

  IF p_operation = 'portal.preference.replace' THEN
    IF NOT app.current_tenant_human_has_exact_permission_v3(
         'portal.contact.preference.manage', 'own'
       ) OR NOT EXISTS (
         SELECT 1
         FROM public.tenant_memberships AS membership
         JOIN public.users AS identity ON identity.id = membership.user_id
         JOIN public.customer_contacts AS contact
           ON contact.tenant_id = membership.tenant_id
          AND contact.linked_membership_id = membership.id
          AND contact.linked_user_id = membership.user_id
         WHERE membership.tenant_id = context_tenant
           AND membership.id = actor_membership
           AND membership.user_id = actor_user
           AND membership.status = 'active' AND identity.active
           AND contact.id = p_resource_id
           AND contact.active AND contact.archived_at IS NULL
       ) THEN
      RAISE EXCEPTION 'portal preference replay is forbidden'
        USING ERRCODE = '42501';
    END IF;
  ELSIF p_operation LIKE 'contact_group.%' THEN
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'contact_group.manage', 'tenant'
    ) THEN
      RAISE EXCEPTION 'contact-group replay is forbidden'
        USING ERRCODE = '42501';
    END IF;
  ELSIF p_operation LIKE 'contact.%' THEN
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'contact.manage', 'tenant'
    ) THEN
      RAISE EXCEPTION 'contact replay is forbidden'
        USING ERRCODE = '42501';
    END IF;
  ELSE
    IF NOT app.current_tenant_human_has_exact_permission_v3(
      'contact.read', 'tenant'
    ) THEN
      RAISE EXCEPTION 'ticket-contact replay is forbidden'
        USING ERRCODE = '42501';
    END IF;
    ticket_permission := CASE p_ticket_kind
      WHEN 'alert' THEN 'alert.update' ELSE 'case.update' END;
    IF p_ticket_kind = 'alert' THEN
      SELECT alert.assigned_team_id, alert.created_by AS creator_user_id,
      alert.assignee_user_id, alert.claimed_by_user_id, alert.version,
      alert.workflow_id, alert.workflow_version, alert.state_key
      INTO ticket_record
      FROM public.alerts AS alert
      WHERE alert.tenant_id = context_tenant AND alert.id = p_ticket_id;
    ELSE
      SELECT case_row.assigned_team_id, case_row.created_by_user_id AS creator_user_id,
      case_row.assignee_user_id, case_row.claimed_by_user_id, case_row.version,
      case_row.workflow_id, case_row.workflow_version, case_row.state_key
      INTO ticket_record
      FROM public.cases AS case_row
      WHERE case_row.tenant_id = context_tenant AND case_row.id = p_ticket_id;
    END IF;
    IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
      ticket_permission, ticket_record.assigned_team_id,
      ticket_record.creator_user_id,
      ticket_record.assignee_user_id, ticket_record.claimed_by_user_id
    ) THEN
      RAISE EXCEPTION 'ticket-contact replay is forbidden'
        USING ERRCODE = '42501';
    END IF;
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || p_operation || ':' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT command.* INTO command_record
  FROM public.customer_contact_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.actor_user_id = actor_user
    AND command.operation = p_operation
    AND command.key_digest = p_key_digest
    AND command.expires_at > transaction_timestamp()
  FOR UPDATE;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF command_record.request_digest IS DISTINCT FROM p_request_digest
     OR p_resource_id IS NOT NULL
        AND command_record.result_resource_id IS DISTINCT FROM p_resource_id
     OR command_record.result_snapshot ->> 'operation' IS DISTINCT FROM p_operation
     OR p_operation LIKE 'ticket_contact.%' AND (
       command_record.result_snapshot #>> '{resource,ticketKind}'
         IS DISTINCT FROM p_ticket_kind::text
       OR command_record.result_snapshot #>> '{resource,ticketId}'
         IS DISTINCT FROM p_ticket_id::text
     )
     OR command_record.result_snapshot ->> 'projection' = 'unavailable' THEN
    RAISE EXCEPTION 'customer contact idempotency key conflicts'
      USING ERRCODE = '23505',
            CONSTRAINT = 'customer_contact_commands_replay_key';
  END IF;
  RETURN QUERY SELECT command_record.result_resource_id,
                      command_record.result_version,
                      command_record.result_snapshot ->> 'projection',
                      command_record.result_snapshot -> 'resource';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.replay_customer_contact_command_v1(
  text, bytea, bytea, uuid, public.ticket_aggregate_kind, uuid
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.replay_customer_contact_command_v1(
  text, bytea, bytea, uuid, public.ticket_aggregate_kind, uuid
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.replay_customer_contact_command_v1(
  text, bytea, bytea, uuid, public.ticket_aggregate_kind, uuid
) TO periapsis_api;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.commit_ticket_customer_contact_v1(
  p_operation text,
  p_link_id uuid,
  p_expected_link_version bigint,
  p_expected_ticket_version bigint,
  p_payload jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_reason text,
  p_request_id uuid,
  p_correlation_id uuid,
  p_actor_membership_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(link_id uuid, version integer, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  replay_resource_id uuid;
  replay_version integer;
  locked_link public.ticket_customer_contacts%ROWTYPE;
  ticket_record record;
  next_kind text;
  next_ticket_id uuid;
  next_contact_id uuid;
  next_role text;
  next_origin text;
  next_source_alert_id uuid;
  next_source_alert_version integer;
  next_version integer;
  next_archived_at timestamp with time zone;
  ticket_permission text;
  ticket_action text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN ('ticket_contact.link','ticket_contact.archive')
     OR p_link_id IS NULL
     OR (uuid_extract_version(p_link_id) = 7) IS NOT TRUE
     OR p_expected_link_version NOT BETWEEN 0 AND 2147483646
     OR p_expected_ticket_version NOT BETWEEN 1 AND 2147483647
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 10
     OR NOT p_payload ?& ARRAY[
       'ticketKind','ticketId','contactId','role','origin',
       'sourceAlertId','sourceAlertVersion','version','createdAt','archivedAt'
     ]
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_actor_membership_id IS DISTINCT FROM actor_membership
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_reason IS NULL OR char_length(p_reason) > 2000
     OR p_operation = 'ticket_contact.archive' AND btrim(p_reason) = ''
     OR p_operation = 'ticket_contact.link' AND p_reason <> '' THEN
    RAISE EXCEPTION 'ticket-contact command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  next_kind := p_payload ->> 'ticketKind';
  next_ticket_id := (p_payload ->> 'ticketId')::uuid;
  next_contact_id := (p_payload ->> 'contactId')::uuid;
  next_role := p_payload ->> 'role';
  next_origin := p_payload ->> 'origin';
  next_source_alert_id := (p_payload ->> 'sourceAlertId')::uuid;
  next_source_alert_version := (p_payload ->> 'sourceAlertVersion')::integer;
  next_version := (p_payload ->> 'version')::integer;
  next_archived_at := (p_payload ->> 'archivedAt')::timestamp with time zone;
  IF next_kind NOT IN ('alert','case')
     OR (uuid_extract_version(next_ticket_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(next_contact_id) = 7) IS NOT TRUE
     OR next_role NOT IN ('primary','escalation','watcher')
     OR next_origin <> 'manual'
     OR next_source_alert_id IS NOT NULL
     OR next_source_alert_version IS NOT NULL
     OR next_version NOT BETWEEN 1 AND 2147483647
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'contact.read', 'tenant'
     ) THEN
    RAISE EXCEPTION 'ticket-contact payload or contact-read capability is invalid'
      USING ERRCODE = '42501';
  END IF;

  ticket_permission := CASE next_kind
    WHEN 'alert' THEN 'alert.update' ELSE 'case.update' END;
  IF next_kind = 'alert' THEN
    SELECT alert.assigned_team_id, alert.created_by AS creator_user_id,
      alert.assignee_user_id, alert.claimed_by_user_id, alert.version,
      alert.workflow_id, alert.workflow_version, alert.state_key
      INTO ticket_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = next_ticket_id;
  ELSE
    SELECT case_row.assigned_team_id, case_row.created_by_user_id AS creator_user_id,
      case_row.assignee_user_id, case_row.claimed_by_user_id, case_row.version,
      case_row.workflow_id, case_row.workflow_version, case_row.state_key
      INTO ticket_record
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = next_ticket_id;
  END IF;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
       ticket_permission, ticket_record.assigned_team_id,
       ticket_record.creator_user_id,
       ticket_record.assignee_user_id, ticket_record.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'ticket-contact resource is forbidden'
      USING ERRCODE = '42501';
  END IF;

  DELETE FROM public.customer_contact_commands AS command
  WHERE command.expires_at <= transaction_timestamp();
  SELECT replay.resource_id, replay.version
    INTO replay_resource_id, replay_version
  FROM app.replay_customer_contact_command_v1(
    p_operation, p_key_digest, p_request_digest, p_link_id,
    next_kind::public.ticket_aggregate_kind, next_ticket_id
  ) AS replay;
  IF FOUND THEN
    RETURN QUERY SELECT replay_resource_id, replay_version, true;
    RETURN;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = context_tenant
      AND contact.id = next_contact_id
      AND contact.active AND contact.archived_at IS NULL
  ) THEN
    RAISE EXCEPTION 'contact is unavailable' USING ERRCODE = 'P0002';
  END IF;
  IF next_kind = 'alert' THEN
    SELECT alert.assigned_team_id, alert.created_by AS creator_user_id,
      alert.assignee_user_id, alert.claimed_by_user_id, alert.version,
      alert.workflow_id, alert.workflow_version, alert.state_key
      INTO ticket_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = next_ticket_id
    FOR UPDATE;
  ELSE
    SELECT case_row.assigned_team_id, case_row.created_by_user_id AS creator_user_id,
      case_row.assignee_user_id, case_row.claimed_by_user_id, case_row.version,
      case_row.workflow_id, case_row.workflow_version, case_row.state_key
      INTO ticket_record
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = next_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'ticket not found' USING ERRCODE = 'P0002';
  END IF;
  IF ticket_record.version IS DISTINCT FROM p_expected_ticket_version
     OR NOT app.private_current_ticket_scope_allows_v1(
       ticket_permission, ticket_record.assigned_team_id,
       ticket_record.creator_user_id,
       ticket_record.assignee_user_id, ticket_record.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'ticket-contact ticket scope is stale'
      USING ERRCODE = '40001';
  END IF;
  -- Contact links are metadata governed by the exact ticket update capability
  -- checked above. The workflow 'link' action belongs to Alert-to-Case linking
  -- and does not exist in built-in Alert workflows.

  IF p_operation = 'ticket_contact.link' THEN
    IF p_expected_link_version <> 0 OR next_version <> 1
       OR next_archived_at IS NOT NULL THEN
      RAISE EXCEPTION 'ticket-contact create state is invalid'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.ticket_customer_contacts (
      id, tenant_id, alert_id, case_id, contact_id, role, origin,
      version, created_by_membership_id, created_by_user_id, created_at
    ) VALUES (
      p_link_id, context_tenant,
      CASE WHEN next_kind = 'alert' THEN next_ticket_id END,
      CASE WHEN next_kind = 'case' THEN next_ticket_id END,
      next_contact_id, next_role, 'manual', 1,
      actor_membership, actor_user, transaction_timestamp()
    );
    ticket_action := 'linked';
  ELSE
    SELECT link.* INTO locked_link
    FROM public.ticket_customer_contacts AS link
    WHERE link.tenant_id = context_tenant AND link.id = p_link_id
      AND (next_kind = 'alert' AND link.alert_id = next_ticket_id
        OR next_kind = 'case' AND link.case_id = next_ticket_id)
      AND link.contact_id = next_contact_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'ticket-contact link not found' USING ERRCODE = 'P0002';
    END IF;
    IF locked_link.archived_at IS NOT NULL
       OR locked_link.version IS DISTINCT FROM p_expected_link_version
       OR next_version IS DISTINCT FROM locked_link.version + 1
       OR next_archived_at IS NULL
       OR next_archived_at < locked_link.created_at
       OR next_archived_at > transaction_timestamp() + interval '1 minute'
       OR next_role IS DISTINCT FROM locked_link.role
       OR next_origin IS DISTINCT FROM locked_link.origin THEN
      RAISE EXCEPTION 'ticket-contact link precondition failed'
        USING ERRCODE = '40001';
    END IF;
    UPDATE public.ticket_customer_contacts
    SET version = next_version, archived_at = next_archived_at
    WHERE tenant_id = context_tenant AND id = p_link_id;
    ticket_action := 'unlinked';
  END IF;

  PERFORM app.private_append_ticket_side_effects_v1(
    next_kind::public.ticket_aggregate_kind, next_ticket_id,
    ticket_action, ticket_record.version,
    ARRAY['activity','audit']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    NULL,
    jsonb_build_object(
      'ticket_version', ticket_record.version,
      'contact_link_id', p_link_id,
      'contact_id', next_contact_id,
      'link_version', next_version
    ),
    jsonb_build_object(
      'contact_link_id', p_link_id,
      'contact_id', next_contact_id,
      'role', next_role,
      'reason_present', btrim(p_reason) <> '',
      'pii_redacted', true
    )
  );
  INSERT INTO public.customer_contact_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, actor_user, p_operation,
    p_key_digest, p_request_digest, p_link_id, next_version
  );
  RETURN QUERY SELECT p_link_id, next_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.commit_ticket_customer_contact_v1(
  text, uuid, bigint, bigint, jsonb, bytea, bytea, text, uuid, uuid,
  uuid, inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_ticket_customer_contact_v1(
  text, uuid, bigint, bigint, jsonb, bytea, bytea, text, uuid, uuid,
  uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_ticket_customer_contact_v1(
  text, uuid, bigint, bigint, jsonb, bytea, bytea, text, uuid, uuid,
  uuid, inet, text, text
) TO periapsis_api;
--> statement-breakpoint

-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V58 catalog hash.
-- V58 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v58()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v58();
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
ALTER FUNCTION app.api_runtime_schema_readiness_v58() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v58()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v58()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v58()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v58();
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
ALTER FUNCTION app.worker_runtime_schema_readiness_v58() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v58()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v58()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint
