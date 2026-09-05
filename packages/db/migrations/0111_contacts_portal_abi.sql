CREATE FUNCTION app.capture_customer_contact_command_result_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  resource_value jsonb;
BEGIN
  IF NEW.operation LIKE 'contact.%'
     OR NEW.operation = 'portal.preference.replace' THEN
    IF NEW.operation = 'portal.preference.replace' THEN
      SELECT jsonb_build_object(
        'id', contact.id,
        'firstName', contact.first_name,
        'lastName', contact.last_name,
        'email', contact.email,
        'phone', contact.phone,
        'function', contact.function,
        'language', contact.language,
        'timezone', contact.timezone,
        'notificationCategories', to_jsonb(contact.notification_categories),
        'notificationWindows', coalesce(windows.value, '[]'::jsonb),
        'emailAllowed', contact.email_allowed,
        'active', contact.active,
        'version', contact.version
      ) INTO STRICT resource_value
      FROM public.customer_contacts AS contact
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(jsonb_build_object(
          'isoWeekday', notification_window.iso_weekday,
          'startMinute', notification_window.start_minute,
          'endMinute', notification_window.end_minute
        ) ORDER BY notification_window.iso_weekday,
          notification_window.start_minute, notification_window.end_minute)
          AS value
        FROM public.customer_contact_notification_windows AS notification_window
        WHERE notification_window.tenant_id = contact.tenant_id
          AND notification_window.contact_id = contact.id
      ) AS windows ON true
      WHERE contact.tenant_id = NEW.tenant_id
        AND contact.id = NEW.result_resource_id
        AND contact.version = NEW.result_version
        AND contact.active AND contact.archived_at IS NULL
        AND contact.linked_membership_id = NEW.actor_membership_id
        AND contact.linked_user_id = NEW.actor_user_id;
      NEW.result_snapshot := jsonb_build_object(
        'schemaVersion', 1,
        'operation', NEW.operation,
        'projection', 'customer',
        'resource', resource_value
      );
    ELSE
      SELECT jsonb_build_object(
        'firstName', contact.first_name,
        'lastName', contact.last_name,
        'email', contact.email,
        'phone', contact.phone,
        'function', contact.function,
        'language', contact.language,
        'timezone', contact.timezone,
        'escalationPriority', contact.escalation_priority,
        'contactClass', contact.contact_class,
        'notificationCategories', to_jsonb(contact.notification_categories),
        'notificationWindows', coalesce(windows.value, '[]'::jsonb),
        'emailAllowed', contact.email_allowed,
        'active', contact.active,
        'tags', to_jsonb(contact.tags),
        'linkedMembershipId', contact.linked_membership_id,
        'linkedUserId', contact.linked_user_id,
        'version', contact.version,
        'createdAt', contact.created_at,
        'updatedAt', contact.updated_at,
        'archivedAt', contact.archived_at
      ) INTO STRICT resource_value
      FROM public.customer_contacts AS contact
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(jsonb_build_object(
          'isoWeekday', notification_window.iso_weekday,
          'startMinute', notification_window.start_minute,
          'endMinute', notification_window.end_minute
        ) ORDER BY notification_window.iso_weekday,
          notification_window.start_minute, notification_window.end_minute)
          AS value
        FROM public.customer_contact_notification_windows AS notification_window
        WHERE notification_window.tenant_id = contact.tenant_id
          AND notification_window.contact_id = contact.id
      ) AS windows ON true
      WHERE contact.tenant_id = NEW.tenant_id
        AND contact.id = NEW.result_resource_id
        AND contact.version = NEW.result_version;
      NEW.result_snapshot := jsonb_build_object(
        'schemaVersion', 1,
        'operation', NEW.operation,
        'projection', 'operator',
        'resource', resource_value
      );
    END IF;
  ELSIF NEW.operation LIKE 'contact_group.%' THEN
    SELECT jsonb_build_object(
      'key', group_record.key,
      'version', version.version,
      'name', version.name,
      'description', version.description,
      'mode', version.mode,
      'ruleSchemaVersion', version.rule_schema_version,
      'rule', version.rule,
      'memberIds', coalesce(members.value, '[]'::jsonb),
      'createdAt', jsonb_build_object(
        'group', group_record.created_at,
        'version', version.created_at
      ),
      'updatedAt', group_record.updated_at,
      'archivedAt', group_record.archived_at
    ) INTO STRICT resource_value
    FROM public.customer_contact_groups AS group_record
    JOIN public.customer_contact_group_versions AS version
      ON version.tenant_id = group_record.tenant_id
     AND version.group_id = group_record.id
     AND version.version = NEW.result_version
    LEFT JOIN LATERAL (
      SELECT jsonb_agg(member.contact_id ORDER BY member.contact_id) AS value
      FROM public.customer_contact_group_version_members AS member
      WHERE member.tenant_id = version.tenant_id
        AND member.group_id = version.group_id
        AND member.group_version = version.version
    ) AS members ON true
    WHERE group_record.tenant_id = NEW.tenant_id
      AND group_record.id = NEW.result_resource_id
      AND group_record.current_version = NEW.result_version;
    NEW.result_snapshot := jsonb_build_object(
      'schemaVersion', 1,
      'operation', NEW.operation,
      'projection', 'operator',
      'resource', resource_value
    );
  ELSIF NEW.operation LIKE 'ticket_contact.%' THEN
    SELECT jsonb_build_object(
      'ticketKind', CASE WHEN link.alert_id IS NOT NULL
        THEN 'alert' ELSE 'case' END,
      'ticketId', coalesce(link.alert_id, link.case_id),
      'contactId', link.contact_id,
      'role', link.role,
      'origin', link.origin,
      'sourceAlertId', link.source_alert_id,
      'sourceAlertVersion', link.source_alert_version,
      'version', link.version,
      'createdAt', link.created_at,
      'archivedAt', link.archived_at
    ) INTO STRICT resource_value
    FROM public.ticket_customer_contacts AS link
    WHERE link.tenant_id = NEW.tenant_id
      AND link.id = NEW.result_resource_id
      AND link.version = NEW.result_version;
    NEW.result_snapshot := jsonb_build_object(
      'schemaVersion', 1,
      'operation', NEW.operation,
      'projection', 'operator',
      'resource', resource_value
    );
  ELSE
    RAISE EXCEPTION 'customer contact command operation is unsupported'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.capture_customer_contact_command_result_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.capture_customer_contact_command_result_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_notification_dispatch_owner;
--> statement-breakpoint
CREATE TRIGGER customer_contact_commands_capture_result_v1
BEFORE INSERT ON public.customer_contact_commands
FOR EACH ROW EXECUTE FUNCTION app.capture_customer_contact_command_result_v1();
--> statement-breakpoint

CREATE FUNCTION app.replay_customer_contact_command_v1(
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
      SELECT alert.* INTO ticket_record
      FROM public.alerts AS alert
      WHERE alert.tenant_id = context_tenant AND alert.id = p_ticket_id;
    ELSE
      SELECT case_row.* INTO ticket_record
      FROM public.cases AS case_row
      WHERE case_row.tenant_id = context_tenant AND case_row.id = p_ticket_id;
    END IF;
    IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
      ticket_permission, ticket_record.assigned_team_id,
      CASE p_ticket_kind WHEN 'alert' THEN ticket_record.created_by
                         ELSE ticket_record.created_by_user_id END,
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

CREATE OR REPLACE FUNCTION app.commit_customer_contact_v1(
  p_operation text,
  p_contact_id uuid,
  p_expected_version bigint,
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
RETURNS TABLE(contact_id uuid, version integer, replayed boolean)
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
  locked public.customer_contacts%ROWTYPE;
  next_version integer;
  next_first_name text;
  next_last_name text;
  next_email text;
  next_phone text;
  next_function text;
  next_language text;
  next_timezone text;
  next_priority integer;
  next_class text;
  next_categories text[];
  next_windows jsonb;
  next_email_allowed boolean;
  next_active boolean;
  next_tags text[];
  next_linked_membership uuid;
  next_linked_user uuid;
  next_archived_at timestamp with time zone;
  side_effect_action text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN (
       'contact.create','contact.replace','contact.archive',
       'portal.preference.replace'
     )
     OR p_contact_id IS NULL
     OR (uuid_extract_version(p_contact_id) = 7) IS NOT TRUE
     OR p_expected_version NOT BETWEEN 0 AND 2147483646
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 20
     OR NOT p_payload ?& ARRAY[
       'firstName','lastName','email','phone','function','language',
       'timezone','escalationPriority','contactClass',
       'notificationCategories','notificationWindows','emailAllowed',
       'active','tags','linkedMembershipId','linkedUserId','version',
       'createdAt','updatedAt','archivedAt'
     ]
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_actor_membership_id IS DISTINCT FROM actor_membership
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR p_reason IS NULL OR char_length(p_reason) > 2000
     OR p_operation = 'contact.archive' AND btrim(p_reason) = ''
     OR p_operation <> 'contact.archive' AND p_reason <> '' THEN
    RAISE EXCEPTION 'contact command envelope is invalid'
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
           AND contact.id = p_contact_id
           AND contact.active AND contact.archived_at IS NULL
       ) THEN
      RAISE EXCEPTION 'portal preference relation is required'
        USING ERRCODE = '42501';
    END IF;
  ELSIF NOT app.current_tenant_human_has_exact_permission_v3(
    'contact.manage', 'tenant'
  ) THEN
    RAISE EXCEPTION 'contact management permission is required'
      USING ERRCODE = '42501';
  END IF;

  IF jsonb_typeof(p_payload -> 'notificationCategories') <> 'array'
     OR jsonb_typeof(p_payload -> 'notificationWindows') <> 'array'
     OR jsonb_typeof(p_payload -> 'tags') <> 'array'
     OR jsonb_typeof(p_payload -> 'emailAllowed') <> 'boolean'
     OR jsonb_typeof(p_payload -> 'active') <> 'boolean'
     OR NOT app.private_contact_windows_are_valid_v1(
       p_payload -> 'notificationWindows'
     ) THEN
    RAISE EXCEPTION 'contact payload collections are invalid'
      USING ERRCODE = '22023';
  END IF;

  next_first_name := p_payload ->> 'firstName';
  next_last_name := p_payload ->> 'lastName';
  next_email := p_payload ->> 'email';
  next_phone := p_payload ->> 'phone';
  next_function := p_payload ->> 'function';
  next_language := p_payload ->> 'language';
  next_timezone := p_payload ->> 'timezone';
  next_priority := (p_payload ->> 'escalationPriority')::integer;
  next_class := p_payload ->> 'contactClass';
  next_email_allowed := (p_payload ->> 'emailAllowed')::boolean;
  next_active := (p_payload ->> 'active')::boolean;
  next_version := (p_payload ->> 'version')::integer;
  next_linked_membership := (p_payload ->> 'linkedMembershipId')::uuid;
  next_linked_user := (p_payload ->> 'linkedUserId')::uuid;
  next_archived_at := (p_payload ->> 'archivedAt')::timestamp with time zone;
  next_windows := p_payload -> 'notificationWindows';
  SELECT coalesce(array_agg(item.value ORDER BY item.ordinality), ARRAY[]::text[])
    INTO next_categories
  FROM jsonb_array_elements_text(p_payload -> 'notificationCategories')
       WITH ORDINALITY AS item(value, ordinality);
  SELECT coalesce(array_agg(item.value ORDER BY item.ordinality), ARRAY[]::text[])
    INTO next_tags
  FROM jsonb_array_elements_text(p_payload -> 'tags')
       WITH ORDINALITY AS item(value, ordinality);

  IF next_first_name IS NULL OR next_last_name IS NULL OR next_email IS NULL
     OR next_function IS NULL OR next_language IS NULL OR next_timezone IS NULL
     OR next_class IS NULL OR next_version IS NULL
     OR next_categories IS DISTINCT FROM ARRAY(
       SELECT DISTINCT value FROM unnest(next_categories) AS item(value)
       ORDER BY value
     )
     OR next_tags IS DISTINCT FROM ARRAY(
       SELECT DISTINCT value FROM unnest(next_tags) AS item(value)
       ORDER BY value
     )
     OR cardinality(next_categories) > 64 OR cardinality(next_tags) > 100
     OR (next_linked_membership IS NULL) <> (next_linked_user IS NULL)
     OR NOT EXISTS (
       SELECT 1 FROM pg_timezone_names AS timezone
       WHERE timezone.name = next_timezone
     ) THEN
    RAISE EXCEPTION 'contact payload is not canonical'
      USING ERRCODE = '22023';
  END IF;

  DELETE FROM public.customer_contact_commands AS command
  WHERE command.expires_at <= transaction_timestamp();
  SELECT replay.resource_id, replay.version
    INTO replay_resource_id, replay_version
  FROM app.replay_customer_contact_command_v1(
    p_operation, p_key_digest, p_request_digest, p_contact_id,
    NULL::public.ticket_aggregate_kind, NULL::uuid
  ) AS replay;
  IF FOUND THEN
    RETURN QUERY SELECT replay_resource_id, replay_version, true;
    RETURN;
  END IF;

  IF next_linked_membership IS NOT NULL AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE membership.tenant_id = context_tenant
      AND membership.id = next_linked_membership
      AND membership.user_id = next_linked_user
      AND membership.status = 'active' AND identity.active
  ) THEN
    RAISE EXCEPTION 'linked contact identity is unavailable'
      USING ERRCODE = '23503';
  END IF;

  IF p_operation = 'contact.create' THEN
    IF p_expected_version <> 0 OR next_version <> 1
       OR next_archived_at IS NOT NULL OR NOT next_active THEN
      RAISE EXCEPTION 'contact create state is invalid'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.customer_contacts (
      id, tenant_id, first_name, last_name, email, phone, function,
      language, timezone, escalation_priority, contact_class,
      notification_categories, email_allowed, active, tags,
      linked_membership_id, linked_user_id, version, created_at, updated_at
    ) VALUES (
      p_contact_id, context_tenant, next_first_name, next_last_name,
      next_email, next_phone, next_function, next_language, next_timezone,
      next_priority, next_class, next_categories, next_email_allowed,
      next_active, next_tags, next_linked_membership, next_linked_user,
      1, transaction_timestamp(), transaction_timestamp()
    );
    side_effect_action := 'created';
  ELSE
    SELECT contact.* INTO locked
    FROM public.customer_contacts AS contact
    WHERE contact.tenant_id = context_tenant AND contact.id = p_contact_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'contact not found' USING ERRCODE = 'P0002';
    END IF;
    IF locked.version IS DISTINCT FROM p_expected_version
       OR locked.archived_at IS NOT NULL
       OR next_version IS DISTINCT FROM locked.version + 1 THEN
      RAISE EXCEPTION 'contact version precondition failed'
        USING ERRCODE = '40001';
    END IF;
    IF p_operation = 'portal.preference.replace' THEN
      IF locked.linked_membership_id IS DISTINCT FROM actor_membership
         OR locked.linked_user_id IS DISTINCT FROM actor_user
         OR NOT locked.active
         OR next_first_name IS DISTINCT FROM locked.first_name
         OR next_last_name IS DISTINCT FROM locked.last_name
         OR next_email IS DISTINCT FROM locked.email
         OR next_phone IS DISTINCT FROM locked.phone
         OR next_function IS DISTINCT FROM locked.function
         OR next_language IS DISTINCT FROM locked.language
         OR next_timezone IS DISTINCT FROM locked.timezone
         OR next_priority IS DISTINCT FROM locked.escalation_priority
         OR next_class IS DISTINCT FROM locked.contact_class
         OR next_active IS DISTINCT FROM locked.active
         OR next_tags IS DISTINCT FROM locked.tags
         OR next_linked_membership IS DISTINCT FROM locked.linked_membership_id
         OR next_linked_user IS DISTINCT FROM locked.linked_user_id
         OR next_archived_at IS NOT NULL THEN
        RAISE EXCEPTION 'portal preference payload exceeds self scope'
          USING ERRCODE = '42501';
      END IF;
      UPDATE public.customer_contacts
      SET notification_categories = next_categories,
          email_allowed = next_email_allowed,
          version = next_version,
          updated_at = transaction_timestamp()
      WHERE tenant_id = context_tenant AND id = p_contact_id;
      side_effect_action := 'preferences_replaced';
    ELSIF p_operation = 'contact.archive' THEN
      IF next_active OR next_archived_at IS NULL
         OR next_archived_at < locked.created_at
         OR next_archived_at > transaction_timestamp() + interval '1 minute' THEN
        RAISE EXCEPTION 'contact archive state is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contacts
      SET active = false, archived_at = next_archived_at,
          version = next_version, updated_at = next_archived_at
      WHERE tenant_id = context_tenant AND id = p_contact_id;
      side_effect_action := 'archived';
    ELSE
      IF next_archived_at IS NOT NULL THEN
        RAISE EXCEPTION 'contact replacement cannot archive'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contacts
      SET first_name = next_first_name, last_name = next_last_name,
          email = next_email, phone = next_phone, function = next_function,
          language = next_language, timezone = next_timezone,
          escalation_priority = next_priority, contact_class = next_class,
          notification_categories = next_categories,
          email_allowed = next_email_allowed, active = next_active,
          tags = next_tags, linked_membership_id = next_linked_membership,
          linked_user_id = next_linked_user, version = next_version,
          updated_at = transaction_timestamp()
      WHERE tenant_id = context_tenant AND id = p_contact_id;
      side_effect_action := 'replaced';
    END IF;
  END IF;

  DELETE FROM public.customer_contact_notification_windows AS notification_window
  WHERE notification_window.tenant_id = context_tenant
    AND notification_window.contact_id = p_contact_id;
  INSERT INTO public.customer_contact_notification_windows (
    tenant_id, contact_id, iso_weekday, start_minute, end_minute
  )
  SELECT context_tenant, p_contact_id,
         (window_entry.value ->> 'isoWeekday')::integer,
         (window_entry.value ->> 'startMinute')::integer,
         (window_entry.value ->> 'endMinute')::integer
  FROM jsonb_array_elements(next_windows) AS window_entry(value);

  PERFORM app.private_append_contact_change_v1(
    side_effect_action, p_contact_id, next_version,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method,
    CASE WHEN p_operation = 'contact.create' THEN NULL
         ELSE jsonb_build_object(
           'version', locked.version,
           'active', locked.active,
           'archived', locked.archived_at IS NOT NULL
         ) END,
    jsonb_build_object(
      'version', next_version,
      'active', CASE WHEN p_operation = 'contact.archive'
                     THEN false ELSE next_active END,
      'archived', p_operation = 'contact.archive'
    ),
    jsonb_build_object(
      'reason_present', btrim(p_reason) <> '',
      'linked_identity', next_linked_membership IS NOT NULL,
      'category_count', cardinality(next_categories),
      'window_count', jsonb_array_length(next_windows),
      'tag_count', cardinality(next_tags)
    )
  );
  INSERT INTO public.customer_contact_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, actor_user, p_operation,
    p_key_digest, p_request_digest, p_contact_id, next_version
  );
  RETURN QUERY SELECT p_contact_id, next_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.commit_customer_contact_v1(
  text, uuid, bigint, jsonb, bytea, bytea, text, uuid, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_customer_contact_v1(
  text, uuid, bigint, jsonb, bytea, bytea, text, uuid, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_customer_contact_v1(
  text, uuid, bigint, jsonb, bytea, bytea, text, uuid, uuid, uuid,
  inet, text, text
) TO periapsis_api;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.commit_customer_contact_group_v1(
  p_operation text,
  p_group_id uuid,
  p_expected_version bigint,
  p_payload jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_actor_membership_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(group_id uuid, version integer, replayed boolean)
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
  locked public.customer_contact_groups%ROWTYPE;
  next_key text;
  next_version integer;
  next_name text;
  next_description text;
  next_mode text;
  next_rule_version integer;
  next_rule jsonb;
  next_member_ids uuid[];
  next_archived_at timestamp with time zone;
  action text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN (
       'contact_group.create','contact_group.version','contact_group.archive'
     )
     OR p_group_id IS NULL
     OR (uuid_extract_version(p_group_id) = 7) IS NOT TRUE
     OR p_expected_version NOT BETWEEN 0 AND 2147483646
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR (SELECT count(*) FROM jsonb_object_keys(p_payload)) <> 11
     OR NOT p_payload ?& ARRAY[
       'key','version','name','description','mode','ruleSchemaVersion',
       'rule','memberIds','createdAt','updatedAt','archivedAt'
     ]
     OR jsonb_typeof(p_payload -> 'memberIds') <> 'array'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_actor_membership_id IS DISTINCT FROM actor_membership
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'contact-group command envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(
       'contact_group.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'contact-group management permission is required'
      USING ERRCODE = '42501';
  END IF;

  next_key := p_payload ->> 'key';
  next_version := (p_payload ->> 'version')::integer;
  next_name := p_payload ->> 'name';
  next_description := p_payload ->> 'description';
  next_mode := p_payload ->> 'mode';
  next_rule_version := (p_payload ->> 'ruleSchemaVersion')::integer;
  next_rule := p_payload -> 'rule';
  next_archived_at := (p_payload ->> 'archivedAt')::timestamp with time zone;
  SELECT coalesce(array_agg(item.value::uuid ORDER BY item.ordinality), ARRAY[]::uuid[])
  INTO next_member_ids
  FROM jsonb_array_elements_text(p_payload -> 'memberIds')
       WITH ORDINALITY AS item(value, ordinality);
  IF next_key IS NULL OR next_key !~ '^[a-z][a-z0-9_.-]{0,63}$'
     OR next_version NOT BETWEEN 1 AND 2147483647
     OR next_name IS NULL OR btrim(next_name) = ''
     OR char_length(next_name) > 160 OR next_name ~ '[[:cntrl:]]'
     OR next_description IS NULL OR char_length(next_description) > 2000
     OR next_description ~ '[[:cntrl:]]'
     OR next_rule_version <> 1
     OR cardinality(next_member_ids) > 10000
     OR next_member_ids IS DISTINCT FROM ARRAY(
       SELECT DISTINCT value FROM unnest(next_member_ids) AS item(value)
       ORDER BY value
     )
     OR EXISTS (
       SELECT 1 FROM unnest(next_member_ids) AS member(id)
       WHERE (uuid_extract_version(member.id) = 7) IS NOT TRUE
     )
     OR next_mode = 'manual' AND next_rule IS DISTINCT FROM 'null'::jsonb
     OR next_mode = 'dynamic' AND (
       cardinality(next_member_ids) <> 0
       OR NOT app.private_contact_rule_is_valid_v1(next_rule)
     )
     OR next_mode NOT IN ('manual','dynamic') THEN
    RAISE EXCEPTION 'contact-group payload is invalid'
      USING ERRCODE = '22023';
  END IF;

  DELETE FROM public.customer_contact_commands AS command
  WHERE command.expires_at <= transaction_timestamp();
  SELECT replay.resource_id, replay.version
    INTO replay_resource_id, replay_version
  FROM app.replay_customer_contact_command_v1(
    p_operation, p_key_digest, p_request_digest, p_group_id,
    NULL::public.ticket_aggregate_kind, NULL::uuid
  ) AS replay;
  IF FOUND THEN
    RETURN QUERY SELECT replay_resource_id, replay_version, true;
    RETURN;
  END IF;

  IF EXISTS (
    SELECT 1 FROM unnest(next_member_ids) AS member(id)
    WHERE NOT EXISTS (
      SELECT 1 FROM public.customer_contacts AS contact
      WHERE contact.tenant_id = context_tenant
        AND contact.id = member.id
        AND contact.active AND contact.archived_at IS NULL
    )
  ) THEN
    RAISE EXCEPTION 'contact-group member is unavailable'
      USING ERRCODE = '23503';
  END IF;

  IF p_operation = 'contact_group.create' THEN
    IF p_expected_version <> 0 OR next_version <> 1
       OR next_archived_at IS NOT NULL THEN
      RAISE EXCEPTION 'contact-group create state is invalid'
        USING ERRCODE = '22023';
    END IF;
    INSERT INTO public.customer_contact_groups (
      id, tenant_id, key, current_version, created_at, updated_at
    ) VALUES (
      p_group_id, context_tenant, next_key, 1,
      transaction_timestamp(), transaction_timestamp()
    );
    action := 'created';
  ELSE
    SELECT group_record.* INTO locked
    FROM public.customer_contact_groups AS group_record
    WHERE group_record.tenant_id = context_tenant
      AND group_record.id = p_group_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'contact group not found' USING ERRCODE = 'P0002';
    END IF;
    IF locked.current_version IS DISTINCT FROM p_expected_version
       OR locked.archived_at IS NOT NULL
       OR next_key IS DISTINCT FROM locked.key THEN
      RAISE EXCEPTION 'contact-group version precondition failed'
        USING ERRCODE = '40001';
    END IF;
    IF p_operation = 'contact_group.archive' THEN
      IF next_version IS DISTINCT FROM locked.current_version
         OR next_archived_at IS NULL
         OR next_archived_at < locked.created_at
         OR next_archived_at > transaction_timestamp() + interval '1 minute' THEN
        RAISE EXCEPTION 'contact-group archive state is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contact_groups
      SET archived_at = next_archived_at, updated_at = next_archived_at
      WHERE tenant_id = context_tenant AND id = p_group_id;
      action := 'archived';
    ELSE
      IF next_version IS DISTINCT FROM locked.current_version + 1
         OR next_archived_at IS NOT NULL THEN
        RAISE EXCEPTION 'contact-group next version is invalid'
          USING ERRCODE = '22023';
      END IF;
      UPDATE public.customer_contact_groups
      SET current_version = next_version,
          updated_at = transaction_timestamp()
      WHERE tenant_id = context_tenant AND id = p_group_id;
      action := 'versioned';
    END IF;
  END IF;

  IF p_operation <> 'contact_group.archive' THEN
    INSERT INTO public.customer_contact_group_versions (
      tenant_id, group_id, version, name, description, mode,
      rule_schema_version, rule, created_by_membership_id,
      created_by_user_id, created_at
    ) VALUES (
      context_tenant, p_group_id, next_version, next_name,
      next_description, next_mode, next_rule_version,
      CASE WHEN next_mode = 'dynamic' THEN next_rule ELSE NULL END,
      actor_membership, actor_user, transaction_timestamp()
    );
    INSERT INTO public.customer_contact_group_version_members (
      tenant_id, group_id, group_version, contact_id
    )
    SELECT context_tenant, p_group_id, next_version, member.id
    FROM unnest(next_member_ids) AS member(id);
  END IF;

  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.contact_group.' || action, 'customer_contact_group',
    p_group_id, p_request_id, p_correlation_id, p_ip_address,
    nullif(p_user_agent, ''), p_authentication_method,
    CASE WHEN p_operation = 'contact_group.create' THEN NULL
         ELSE jsonb_build_object(
           'version', locked.current_version,
           'archived', locked.archived_at IS NOT NULL
         ) END,
    jsonb_build_object(
      'version', next_version,
      'mode', next_mode,
      'archived', p_operation = 'contact_group.archive'
    ),
    jsonb_build_object(
      'actor_membership_id', actor_membership,
      'member_count', cardinality(next_member_ids),
      'rule_present', next_mode = 'dynamic',
      'pii_redacted', true
    )
  );
  INSERT INTO public.outbox_events (
    tenant_id, aggregate_type, aggregate_id, aggregate_version,
    event_type, schema_version, payload, deduplication_key,
    correlation_id, causation_id, actor_kind, actor_id, producer,
    maximum_audience, occurred_at, available_at
  ) VALUES (
    context_tenant, 'contact', p_group_id, next_version,
    'contact_group.' || action, 1,
    jsonb_build_object(
      'group_id', p_group_id, 'version', next_version,
      'member_count', cardinality(next_member_ids),
      'pii_redacted', true
    ),
    'contact_group.' || action || ':' || p_group_id::text || ':' || next_version::text,
    p_correlation_id, p_request_id, 'human', actor_user,
    'api.contacts', 'operator', transaction_timestamp(),
    transaction_timestamp()
  );
  INSERT INTO public.customer_contact_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version
  ) VALUES (
    context_tenant, actor_membership, actor_user, p_operation,
    p_key_digest, p_request_digest, p_group_id, next_version
  );
  RETURN QUERY SELECT p_group_id, next_version, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.commit_customer_contact_group_v1(
  text, uuid, bigint, jsonb, bytea, bytea, uuid, uuid, uuid,
  inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_customer_contact_group_v1(
  text, uuid, bigint, jsonb, bytea, bytea, uuid, uuid, uuid,
  inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_customer_contact_group_v1(
  text, uuid, bigint, jsonb, bytea, bytea, uuid, uuid, uuid,
  inet, text, text
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
    SELECT alert.* INTO ticket_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = next_ticket_id;
  ELSE
    SELECT case_row.* INTO ticket_record
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = next_ticket_id;
  END IF;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
       ticket_permission, ticket_record.assigned_team_id,
       CASE next_kind WHEN 'alert' THEN ticket_record.created_by
                      ELSE ticket_record.created_by_user_id END,
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
    SELECT alert.* INTO ticket_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = next_ticket_id
    FOR UPDATE;
  ELSE
    SELECT case_row.* INTO ticket_record
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
       CASE next_kind WHEN 'alert' THEN ticket_record.created_by
                      ELSE ticket_record.created_by_user_id END,
       ticket_record.assignee_user_id, ticket_record.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'ticket-contact ticket scope is stale'
      USING ERRCODE = '40001';
  END IF;
  PERFORM app.private_ticket_state_action_effects_v1(
    next_kind::public.ticket_aggregate_kind,
    ticket_record.workflow_id, ticket_record.workflow_version,
    ticket_record.state_key, 'link'
  );

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

CREATE OR REPLACE FUNCTION app.create_customer_portal_ticket_comment_v1(
  p_aggregate_kind public.ticket_aggregate_kind,
  p_ticket_id uuid,
  p_contact_id uuid,
  p_body_markdown text,
  p_body_html text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(comment_id uuid, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  ticket_record record;
  replay_record public.ticket_comment_commands%ROWTYPE;
  created_comment_id uuid := uuidv7();
  customer_state_visible boolean := false;
  permission_key text;
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  permission_key := CASE p_aggregate_kind
    WHEN 'alert' THEN 'portal.alert.read'
    ELSE 'portal.case.read' END;
  IF p_aggregate_kind IS NULL
     OR p_ticket_id IS NULL
     OR (uuid_extract_version(p_ticket_id) = 7) IS NOT TRUE
     OR p_contact_id IS NULL
     OR (uuid_extract_version(p_contact_id) = 7) IS NOT TRUE
     OR p_body_markdown IS NULL OR btrim(p_body_markdown) = ''
     OR char_length(p_body_markdown) > 50000
     OR p_body_html IS NULL OR char_length(p_body_html) > 100000
     OR lower(p_body_html) LIKE '%<script%'
     OR lower(p_body_html) LIKE '%javascript:%'
     OR lower(p_body_html) ~ '<[^>]+[[:space:]]on[a-z]+[[:space:]]*='
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'portal comment envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT app.current_tenant_human_has_exact_permission_v3(
       'portal.comment.public', 'own'
     ) OR NOT app.current_tenant_human_has_exact_permission_v3(
       permission_key, 'own'
     ) OR NOT EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       JOIN public.users AS identity ON identity.id = membership.user_id
       JOIN public.customer_contacts AS contact
         ON contact.tenant_id = membership.tenant_id
        AND contact.linked_membership_id = membership.id
        AND contact.linked_user_id = membership.user_id
       JOIN public.ticket_customer_contacts AS link
         ON link.tenant_id = contact.tenant_id
        AND link.contact_id = contact.id
        AND link.archived_at IS NULL
        AND (p_aggregate_kind = 'alert' AND link.alert_id = p_ticket_id
          OR p_aggregate_kind = 'case' AND link.case_id = p_ticket_id)
       WHERE membership.tenant_id = context_tenant
         AND membership.id = actor_membership
         AND membership.user_id = actor_user
         AND membership.status = 'active' AND identity.active
         AND contact.id = p_contact_id
         AND contact.active AND contact.archived_at IS NULL
     ) THEN
    RAISE EXCEPTION 'exact portal comment relation is required'
      USING ERRCODE = '42501';
  END IF;

  IF p_aggregate_kind = 'alert' THEN
    SELECT alert.* INTO ticket_record
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant AND alert.id = p_ticket_id
    FOR UPDATE;
  ELSE
    SELECT case_row.* INTO ticket_record
    FROM public.cases AS case_row
    WHERE case_row.tenant_id = context_tenant AND case_row.id = p_ticket_id
    FOR UPDATE;
  END IF;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'portal ticket not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT count(*) = 1 AND coalesce(bool_and(
           ticket_record.customer_visible
           AND state.value ->> 'visibility' = 'customer'
         ), false)
  INTO customer_state_visible
  FROM public.ticket_workflow_versions AS workflow_version
  CROSS JOIN LATERAL jsonb_array_elements(workflow_version.states) AS state(value)
  WHERE workflow_version.tenant_id = context_tenant
    AND workflow_version.workflow_id = ticket_record.workflow_id
    AND workflow_version.aggregate_kind = p_aggregate_kind
    AND workflow_version.version = ticket_record.workflow_version
    AND state.value ->> 'key' = ticket_record.state_key;
  IF customer_state_visible IS DISTINCT FROM true THEN
    RAISE EXCEPTION 'portal ticket is not customer-projectable'
      USING ERRCODE = '42501';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || p_aggregate_kind::text || '.comment.create:'
      || encode(p_key_digest, 'hex'), 0
  ));
  SELECT command.* INTO replay_record
  FROM public.ticket_comment_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.actor_user_id = actor_user
    AND command.operation = p_aggregate_kind::text || '.comment.create'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay_record.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'portal comment idempotency key conflicts'
        USING ERRCODE = '23505',
              CONSTRAINT = 'ticket_comment_commands_replay_key';
    END IF;
    RETURN QUERY SELECT replay_record.result_comment_id, true;
    RETURN;
  END IF;

  INSERT INTO public.ticket_comments (
    id, tenant_id, alert_id, case_id, visibility, body_markdown,
    body_html, author_membership_id, author_user_id, origin,
    mentioned_user_ids, created_at, updated_at
  ) VALUES (
    created_comment_id, context_tenant,
    CASE WHEN p_aggregate_kind = 'alert' THEN p_ticket_id END,
    CASE WHEN p_aggregate_kind = 'case' THEN p_ticket_id END,
    'public', p_body_markdown, p_body_html,
    actor_membership, actor_user, 'customer_portal', ARRAY[]::uuid[],
    transaction_timestamp(), transaction_timestamp()
  );
  PERFORM app.private_append_ticket_side_effects_v1(
    p_aggregate_kind, p_ticket_id, 'commented', ticket_record.version,
    ARRAY['activity','audit','sla','notification']::text[],
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, NULL,
    jsonb_build_object(
      'comment_id', created_comment_id,
      'visibility', 'public',
      'ticket_version', ticket_record.version
    ),
    jsonb_build_object(
      'comment_id', created_comment_id,
      'author_contact_id', p_contact_id,
      'visibility', 'public',
      'content_redacted', true,
      'mention_count', 0,
      'origin', 'customer_portal'
    )
  );
  INSERT INTO public.ticket_comment_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_comment_id
  ) VALUES (
    context_tenant, p_aggregate_kind::text || '.comment.create',
    actor_membership, actor_user, p_key_digest, p_request_digest,
    created_comment_id
  );
  RETURN QUERY SELECT created_comment_id, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.create_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind, uuid, uuid, text, text, bytea, bytea,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind, uuid, uuid, text, text, bytea, bytea,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
       periapsis_notification_dispatch_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_customer_portal_ticket_comment_v1(
  public.ticket_aggregate_kind, uuid, uuid, text, text, bytea, bytea,
  uuid, uuid, inet, text, text
) TO periapsis_api;
