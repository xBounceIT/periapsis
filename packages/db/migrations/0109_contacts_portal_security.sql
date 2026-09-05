-- Canonicalize the contact-group permission keys in place so all existing
-- grants keep their immutable permission identifiers. Refuse an ambiguous
-- catalog instead of attempting to merge independently-created permissions.
DO $contacts_permission_keys$
DECLARE
  changed_role record;
BEGIN
  IF EXISTS (
    SELECT 1
    FROM public.tenant_permissions AS legacy
    JOIN public.tenant_permissions AS canonical
      ON canonical.key = replace(legacy.key, 'contact.group.', 'contact_group.')
     AND canonical.id <> legacy.id
    WHERE legacy.key IN ('contact.group.read', 'contact.group.manage')
  ) THEN
    RAISE EXCEPTION 'contact-group permission catalog is ambiguous'
      USING ERRCODE = '23505';
  END IF;

  IF EXISTS (
    SELECT 1
    FROM public.tenant_roles AS role
    JOIN public.tenant_role_permissions AS grant_row
      ON grant_row.tenant_id = role.tenant_id
     AND grant_row.role_id = role.id
    JOIN public.tenant_permissions AS permission
      ON permission.id = grant_row.permission_id
    WHERE permission.key IN ('contact.group.read', 'contact.group.manage')
      AND role.version >= 2147483647
  ) THEN
    RAISE EXCEPTION 'contact-group permission role version is exhausted'
      USING ERRCODE = '55000';
  END IF;

  UPDATE public.tenant_permissions
  SET key = CASE key
    WHEN 'contact.group.read' THEN 'contact_group.read'
    WHEN 'contact.group.manage' THEN 'contact_group.manage'
  END
  WHERE key IN ('contact.group.read', 'contact.group.manage');

  FOR changed_role IN
    SELECT role.tenant_id, role.id, role.version
    FROM public.tenant_roles AS role
    WHERE EXISTS (
      SELECT 1
      FROM public.tenant_role_permissions AS grant_row
      JOIN public.tenant_permissions AS permission
        ON permission.id = grant_row.permission_id
      WHERE grant_row.tenant_id = role.tenant_id
        AND grant_row.role_id = role.id
        AND permission.key IN ('contact_group.read', 'contact_group.manage')
    )
    ORDER BY role.tenant_id, role.id
    FOR UPDATE OF role
  LOOP
    UPDATE public.tenant_roles
    SET version = changed_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = changed_role.tenant_id
      AND id = changed_role.id;
  END LOOP;
END
$contacts_permission_keys$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_seed_tenant_contact_authorization_v1(
  p_tenant_id uuid
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  changed_role record;
  changed_role_ids uuid[] := ARRAY[]::uuid[];
  newly_changed_role_ids uuid[];
BEGIN
  IF p_tenant_id IS NULL OR NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant WHERE tenant.id = p_tenant_id
  ) THEN
    RAISE EXCEPTION 'contact authorization tenant is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  WITH inserted AS (
    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT p_tenant_id, role.id, permission.id,
           'tenant'::public.authorization_scope, NULL
    FROM public.tenant_roles AS role
    JOIN public.tenant_permissions AS permission
      ON permission.key IN (
        'contact.read', 'contact.manage', 'contact.preference.manage',
        'contact_group.read', 'contact_group.manage'
      )
    WHERE role.tenant_id = p_tenant_id
      AND role.key = 'tenant_admin'
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING role_id
  )
  SELECT coalesce(array_agg(DISTINCT inserted.role_id), ARRAY[]::uuid[])
  INTO changed_role_ids
  FROM inserted;

  WITH inserted AS (
    INSERT INTO public.tenant_role_permissions (
      tenant_id, role_id, permission_id, scope, created_by_membership_id
    )
    SELECT p_tenant_id, role.id, permission.id,
           'own'::public.authorization_scope, NULL
    FROM public.tenant_roles AS role
    JOIN public.tenant_permissions AS permission ON (
      role.key IN ('customer_manager', 'customer_user')
      AND permission.key IN (
        'portal.alert.read', 'portal.case.read', 'portal.comment.public',
        'portal.attachment.read', 'portal.contact.preference.manage'
      )
      OR role.key = 'read_only'
      AND permission.key IN (
        'portal.alert.read', 'portal.case.read', 'portal.attachment.read'
      )
    )
    WHERE role.tenant_id = p_tenant_id
      AND role.principal_kind = 'human'
      AND role.system_role AND role.archived_at IS NULL
    ON CONFLICT DO NOTHING
    RETURNING role_id
  )
  SELECT coalesce(array_agg(DISTINCT inserted.role_id), ARRAY[]::uuid[])
  INTO newly_changed_role_ids
  FROM inserted;
  changed_role_ids := ARRAY(
    SELECT DISTINCT role_id
    FROM unnest(changed_role_ids || newly_changed_role_ids) AS changed(role_id)
    ORDER BY role_id
  );

  INSERT INTO public.tenant_role_delegation_ceilings (
    tenant_id, role_id, permission_id, scope, created_by_membership_id
  )
  SELECT p_tenant_id, role.id, permission.id,
         'tenant'::public.authorization_scope, NULL
  FROM public.tenant_roles AS role
  JOIN public.tenant_permissions AS permission
    ON permission.key IN (
      'contact.read', 'contact.manage', 'contact.preference.manage',
      'contact_group.read', 'contact_group.manage'
    )
  WHERE role.tenant_id = p_tenant_id
    AND role.key = 'tenant_admin'
    AND role.principal_kind = 'human'
    AND role.system_role AND role.archived_at IS NULL
  ON CONFLICT DO NOTHING;

  FOR changed_role IN
    SELECT role.*
    FROM public.tenant_roles AS role
    WHERE role.tenant_id = p_tenant_id
      AND role.id = ANY(changed_role_ids)
    FOR UPDATE OF role
  LOOP
    IF changed_role.version >= 2147483647 THEN
      RAISE EXCEPTION 'contact authorization role version is exhausted'
        USING ERRCODE = '55000';
    END IF;
    UPDATE public.tenant_roles
    SET version = changed_role.version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = p_tenant_id AND id = changed_role.id;
  END LOOP;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_seed_tenant_contact_authorization_v1(uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_seed_tenant_contact_authorization_v1(uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- Command rows are immutable replay evidence. The owning SECURITY DEFINER
-- mutation ABIs may remove only rows whose bounded retention has elapsed.
CREATE FUNCTION app.guard_customer_contact_command_immutability_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     AND current_user = 'periapsis_migrator'
     AND OLD.expires_at <= transaction_timestamp() THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'customer contact command history is immutable'
    USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.guard_customer_contact_command_immutability_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_customer_contact_command_immutability_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_notification_dispatch_owner;
--> statement-breakpoint
CREATE TRIGGER customer_contact_commands_immutable_v1
BEFORE UPDATE OR DELETE ON public.customer_contact_commands
FOR EACH ROW EXECUTE FUNCTION app.guard_customer_contact_command_immutability_v1();
--> statement-breakpoint

-- Author audience is immutable route provenance, never an inference from a
-- legacy membership-role label. Only the customer-portal route can emit a
-- customer author snapshot, and it must resolve one exact active link.
CREATE OR REPLACE FUNCTION app.capture_ticket_comment_author_snapshot_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  customer_actor boolean := NEW.origin = 'customer_portal';
  contact_id uuid;
BEGIN
  IF NEW.origin = 'api' AND NOT EXISTS (
    SELECT 1
    FROM public.tenant_memberships AS membership
    JOIN public.users AS identity ON identity.id = membership.user_id
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.author_membership_id
      AND membership.user_id = NEW.author_user_id
      AND membership.status = 'active' AND identity.active
  ) THEN
    RAISE EXCEPTION 'comment author is not a live tenant identity'
      USING ERRCODE = '42501';
  END IF;
  IF customer_actor THEN
    IF NEW.visibility <> 'public' THEN
      RAISE EXCEPTION 'customer comments must be public'
        USING ERRCODE = '42501';
    END IF;
    SELECT contact.id INTO STRICT contact_id
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
     AND (link.alert_id = NEW.alert_id OR link.case_id = NEW.case_id)
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.author_membership_id
      AND membership.user_id = NEW.author_user_id
      AND membership.status = 'active' AND identity.active
      AND contact.active AND contact.archived_at IS NULL;
  END IF;
  INSERT INTO public.ticket_comment_author_snapshots (
    tenant_id, comment_id, audience, author_membership_id, author_user_id,
    author_contact_id, created_at
  ) VALUES (
    NEW.tenant_id, NEW.id,
    CASE WHEN customer_actor THEN 'customer' ELSE 'operator' END,
    NEW.author_membership_id, NEW.author_user_id, contact_id, NEW.created_at
  );
  RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'customer comment lacks one exact active contact link'
    USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.capture_ticket_comment_author_snapshot_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.capture_ticket_comment_author_snapshot_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.capture_ticket_activity_author_snapshot_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  customer_actor boolean := NEW.origin = 'customer_portal';
  contact_id uuid;
BEGIN
  IF NEW.actor_principal_kind = 'human' AND NEW.origin = 'api'
     AND NOT EXISTS (
       SELECT 1
       FROM public.tenant_memberships AS membership
       JOIN public.users AS identity ON identity.id = membership.user_id
       WHERE membership.tenant_id = NEW.tenant_id
         AND membership.id = NEW.actor_membership_id
         AND membership.user_id = NEW.actor_user_id
         AND membership.status = 'active' AND identity.active
     ) THEN
    RAISE EXCEPTION 'activity author is not a live tenant identity'
      USING ERRCODE = '42501';
  END IF;
  IF customer_actor THEN
    IF NEW.actor_principal_kind <> 'human' THEN
      RAISE EXCEPTION 'customer activity must have a human actor'
        USING ERRCODE = '42501';
    END IF;
    SELECT contact.id INTO STRICT contact_id
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
     AND (link.alert_id = NEW.alert_id OR link.case_id = NEW.case_id)
    WHERE membership.tenant_id = NEW.tenant_id
      AND membership.id = NEW.actor_membership_id
      AND membership.user_id = NEW.actor_user_id
      AND membership.status = 'active' AND identity.active
      AND contact.active AND contact.archived_at IS NULL;
  END IF;
  INSERT INTO public.ticket_activity_author_snapshots (
    tenant_id, activity_id, audience, author_contact_id, created_at
  ) VALUES (
    NEW.tenant_id, NEW.id,
    CASE WHEN customer_actor THEN 'customer' ELSE 'operator' END,
    contact_id, NEW.occurred_at
  );
  RETURN NEW;
EXCEPTION WHEN NO_DATA_FOUND OR TOO_MANY_ROWS THEN
  RAISE EXCEPTION 'customer activity lacks one exact active contact link'
    USING ERRCODE = '42501';
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.capture_ticket_activity_author_snapshot_v1()
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.capture_ticket_activity_author_snapshot_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_notification_dispatch_owner;
--> statement-breakpoint

-- The dispatch owner alone may evaluate another human principal's live exact
-- permission. The notifier login can only invoke its bounded fanout ABI.
REVOKE ALL ON FUNCTION app.tenant_human_has_exact_permission_v3(
  uuid, uuid, text, public.authorization_scope
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.tenant_human_has_exact_permission_v3(
  uuid, uuid, text, public.authorization_scope
) TO periapsis_notification_dispatch_owner;
