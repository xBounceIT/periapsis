CREATE TABLE "tenant_notification_inbox_commands" (
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"operation" text NOT NULL,
	"key_digest" "bytea" NOT NULL,
	"request_digest" "bytea" NOT NULL,
	"result" jsonb NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	CONSTRAINT "tenant_notification_inbox_commands_pkey" PRIMARY KEY("tenant_id","user_id","operation","key_digest"),
	CONSTRAINT "tenant_notification_inbox_commands_operation_check" CHECK ("tenant_notification_inbox_commands"."operation" in (
        'notification_inbox.set_read_state',
        'notification_inbox.mark_all_read'
      )),
	CONSTRAINT "tenant_notification_inbox_commands_digest_check" CHECK (octet_length("tenant_notification_inbox_commands"."key_digest") = 32
        and octet_length("tenant_notification_inbox_commands"."request_digest") = 32),
	CONSTRAINT "tenant_notification_inbox_commands_result_check" CHECK (jsonb_typeof("tenant_notification_inbox_commands"."result") = 'object'
        and octet_length("tenant_notification_inbox_commands"."result"::text) <= 16384
        and "tenant_notification_inbox_commands"."expires_at" > "tenant_notification_inbox_commands"."created_at")
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_commands" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_inbox_items" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"event_id" uuid NOT NULL,
	"audience" "notification_audience" NOT NULL,
	"event_type" "notification_event_type" NOT NULL,
	"resource_kind" "notification_object_type" NOT NULL,
	"resource_id" uuid NOT NULL,
	"resource_version" integer NOT NULL,
	"title" text NOT NULL,
	"summary" text DEFAULT '' NOT NULL,
	"occurred_at" timestamp with time zone NOT NULL,
	"read_at" timestamp with time zone,
	"revision" integer DEFAULT 1 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_inbox_items_tenant_id_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "tenant_notification_inbox_items_event_user_key" UNIQUE("tenant_id","event_id","user_id"),
	CONSTRAINT "tenant_notification_inbox_items_identity_check" CHECK ((uuid_extract_version("tenant_notification_inbox_items"."id") = 7) is true
        and (uuid_extract_version("tenant_notification_inbox_items"."event_id") = 7) is true
        and (uuid_extract_version("tenant_notification_inbox_items"."resource_id") = 7) is true),
	CONSTRAINT "tenant_notification_inbox_items_revision_check" CHECK ("tenant_notification_inbox_items"."resource_version" between 1 and 2147483647
        and "tenant_notification_inbox_items"."revision" between 1 and 2147483647),
	CONSTRAINT "tenant_notification_inbox_items_text_check" CHECK (btrim("tenant_notification_inbox_items"."title") <> ''
        and octet_length("tenant_notification_inbox_items"."title") <= 240
        and "tenant_notification_inbox_items"."title" !~ '[[:cntrl:]]'
        and "tenant_notification_inbox_items"."title" !~ U&'[\202A-\202E\2066-\2069\200E\200F\061C]'
        and octet_length("tenant_notification_inbox_items"."summary") <= 2000
        and "tenant_notification_inbox_items"."summary" !~ '[[:cntrl:]]'
        and "tenant_notification_inbox_items"."summary" !~ U&'[\202A-\202E\2066-\2069\200E\200F\061C]'),
	CONSTRAINT "tenant_notification_inbox_items_time_check" CHECK ("tenant_notification_inbox_items"."occurred_at" <= "tenant_notification_inbox_items"."created_at"
        and "tenant_notification_inbox_items"."updated_at" >= "tenant_notification_inbox_items"."created_at"
        and ("tenant_notification_inbox_items"."read_at" is null or (
          "tenant_notification_inbox_items"."read_at" >= "tenant_notification_inbox_items"."occurred_at"
          and "tenant_notification_inbox_items"."read_at" <= "tenant_notification_inbox_items"."updated_at"
        ))),
	CONSTRAINT "tenant_notification_inbox_items_event_resource_check" CHECK (case
        when "tenant_notification_inbox_items"."event_type" in (
          'alert.created', 'alert.assigned', 'alert.claimed',
          'alert.status_changed', 'alert.escalated', 'alert.watcher_added',
          'alert.watcher_removed'
        ) then "tenant_notification_inbox_items"."resource_kind" = 'alert'
        when "tenant_notification_inbox_items"."event_type" in (
          'case.created', 'case.assigned', 'case.claimed', 'case.transferred',
          'case.status_changed', 'case.watcher_added', 'case.watcher_removed'
        ) then "tenant_notification_inbox_items"."resource_kind" = 'case'
        when "tenant_notification_inbox_items"."event_type" in (
          'comment.public_added', 'comment.private_added',
          'sla.warning', 'sla.breached'
        ) then "tenant_notification_inbox_items"."resource_kind" in ('alert', 'case')
        when "tenant_notification_inbox_items"."event_type" = 'contact.changed'
          then "tenant_notification_inbox_items"."resource_kind" = 'contact'
        when "tenant_notification_inbox_items"."event_type" = 'task.assigned'
          then "tenant_notification_inbox_items"."resource_kind" = 'task'
        when "tenant_notification_inbox_items"."event_type" = 'evidence.added'
          then "tenant_notification_inbox_items"."resource_kind" = 'evidence'
        when "tenant_notification_inbox_items"."event_type" = 'webhook.custom' then true
        else false
      end),
	CONSTRAINT "tenant_notification_inbox_items_customer_event_check" CHECK ("tenant_notification_inbox_items"."audience" <> 'customer' or "tenant_notification_inbox_items"."event_type" not in (
        'alert.watcher_added', 'alert.watcher_removed',
        'case.watcher_added', 'case.watcher_removed',
        'comment.private_added'
      ))
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_items" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "tenant_notification_inbox_states" (
	"tenant_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"revision" integer DEFAULT 0 NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "tenant_notification_inbox_states_pkey" PRIMARY KEY("tenant_id","user_id"),
	CONSTRAINT "tenant_notification_inbox_states_revision_check" CHECK ("tenant_notification_inbox_states"."revision" between 0 and 2147483647)
);
--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_states" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "alert_relation_retractions" DROP CONSTRAINT "alert_relation_retractions_reason_check";--> statement-breakpoint
ALTER TABLE "alert_relations" DROP CONSTRAINT "alert_relations_reason_check";--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_commands" ADD CONSTRAINT "tenant_notification_inbox_commands_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_commands" ADD CONSTRAINT "tenant_notification_inbox_commands_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_commands" ADD CONSTRAINT "tenant_notification_inbox_commands_state_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_notification_inbox_states"("tenant_id","user_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_items" ADD CONSTRAINT "tenant_notification_inbox_items_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_items" ADD CONSTRAINT "tenant_notification_inbox_items_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_items" ADD CONSTRAINT "tenant_notification_inbox_items_state_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_notification_inbox_states"("tenant_id","user_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_items" ADD CONSTRAINT "tenant_notification_inbox_items_event_fk" FOREIGN KEY ("tenant_id","event_id") REFERENCES "public"."outbox_events"("tenant_id","id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_states" ADD CONSTRAINT "tenant_notification_inbox_states_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_states" ADD CONSTRAINT "tenant_notification_inbox_states_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "tenant_notification_inbox_states" ADD CONSTRAINT "tenant_notification_inbox_states_membership_fk" FOREIGN KEY ("tenant_id","user_id") REFERENCES "public"."tenant_memberships"("tenant_id","user_id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "tenant_notification_inbox_commands_expiry_idx" ON "tenant_notification_inbox_commands" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "tenant_notification_inbox_items_personal_cursor_idx" ON "tenant_notification_inbox_items" USING btree ("tenant_id","user_id","audience","id" DESC NULLS LAST);--> statement-breakpoint
CREATE INDEX "tenant_notification_inbox_items_personal_unread_cursor_idx" ON "tenant_notification_inbox_items" USING btree ("tenant_id","user_id","audience","id" DESC NULLS LAST) WHERE "tenant_notification_inbox_items"."read_at" is null;--> statement-breakpoint
ALTER TABLE "alert_relation_retractions" ADD CONSTRAINT "alert_relation_retractions_reason_check" CHECK (btrim("alert_relation_retractions"."reason") <> '' and octet_length("alert_relation_retractions"."reason") <= 2000 and "alert_relation_retractions"."reason" !~ '[[:cntrl:]]');--> statement-breakpoint
ALTER TABLE "alert_relations" ADD CONSTRAINT "alert_relations_reason_check" CHECK (btrim("alert_relations"."reason") <> '' and octet_length("alert_relations"."reason") <= 2000 and "alert_relations"."reason" !~ '[[:cntrl:]]');--> statement-breakpoint
-- Personal notification inbox security boundary. All mutation access is
-- confined to narrowly validated SECURITY DEFINER functions; API/notifier
-- roles never receive direct DML.
DO $notification_inbox_owner$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_notification_inbox_owner'
  ) THEN
    CREATE ROLE periapsis_notification_inbox_owner
      NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT
      NOREPLICATION NOBYPASSRLS;
  END IF;
  IF EXISTS (
    SELECT 1 FROM pg_catalog.pg_roles
    WHERE rolname = 'periapsis_notification_inbox_owner'
      AND (rolcanlogin OR rolsuper OR rolcreatedb OR rolcreaterole
        OR rolinherit OR rolreplication OR rolbypassrls)
  ) THEN
    RAISE EXCEPTION 'notification inbox function owner is privileged'
      USING ERRCODE = '55000';
  END IF;
END
$notification_inbox_owner$;
--> statement-breakpoint

ALTER TABLE public.tenant_notification_inbox_commands OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_notification_inbox_items OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_notification_inbox_states OWNER TO periapsis_migrator;
ALTER TABLE public.tenant_notification_inbox_commands FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_notification_inbox_items FORCE ROW LEVEL SECURITY;
ALTER TABLE public.tenant_notification_inbox_states FORCE ROW LEVEL SECURITY;
REVOKE ALL ON TABLE public.tenant_notification_inbox_commands,
  public.tenant_notification_inbox_items,
  public.tenant_notification_inbox_states
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner,
  periapsis_notification_inbox_owner;
GRANT USAGE ON SCHEMA app, public TO periapsis_notification_inbox_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.tenant_notification_inbox_commands,
  public.tenant_notification_inbox_items,
  public.tenant_notification_inbox_states
TO periapsis_notification_inbox_owner;
GRANT SELECT, INSERT, UPDATE ON TABLE
  public.tenant_notification_inbox_items,
  public.tenant_notification_inbox_states
TO periapsis_notification_dispatch_owner;
GRANT SELECT ON TABLE public.customer_contacts
TO periapsis_notification_dispatch_owner;
GRANT SELECT ON TABLE
  public.tenant_permissions,
  public.tenant_authorization_states,
  public.tenant_security_groups,
  public.tenant_security_group_memberships,
  public.tenant_security_group_role_grants
TO periapsis_notification_dispatch_owner;
GRANT SELECT ON TABLE public.auth_sessions, public.users, public.tenants,
  public.tenant_memberships, public.customer_contacts
TO periapsis_notification_inbox_owner;
GRANT EXECUTE ON FUNCTION app.context_tenant_id(), app.context_user_id(),
  app.require_live_audit_session_v1(uuid, uuid),
  app.append_tenant_authorization_audit(
    uuid, text, text, uuid, uuid, uuid, inet, text, text,
    jsonb, jsonb, jsonb
  ) TO periapsis_notification_inbox_owner;
--> statement-breakpoint

CREATE POLICY notification_inbox_owner_states_v1
ON public.tenant_notification_inbox_states AS PERMISSIVE FOR ALL
TO periapsis_notification_inbox_owner
USING (tenant_id = app.context_tenant_id()
  AND user_id = app.context_user_id())
WITH CHECK (tenant_id = app.context_tenant_id()
  AND user_id = app.context_user_id());
CREATE POLICY notification_inbox_owner_items_v1
ON public.tenant_notification_inbox_items AS PERMISSIVE FOR ALL
TO periapsis_notification_inbox_owner
USING (tenant_id = app.context_tenant_id()
  AND user_id = app.context_user_id())
WITH CHECK (tenant_id = app.context_tenant_id()
  AND user_id = app.context_user_id());
CREATE POLICY notification_inbox_owner_commands_v1
ON public.tenant_notification_inbox_commands AS PERMISSIVE FOR ALL
TO periapsis_notification_inbox_owner
USING (tenant_id = app.context_tenant_id()
  AND user_id = app.context_user_id())
WITH CHECK (tenant_id = app.context_tenant_id()
  AND user_id = app.context_user_id());
CREATE POLICY notification_dispatch_owner_inbox_states_v1
ON public.tenant_notification_inbox_states AS PERMISSIVE FOR ALL
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
CREATE POLICY notification_dispatch_owner_inbox_items_v1
ON public.tenant_notification_inbox_items AS PERMISSIVE FOR ALL
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id())
WITH CHECK (tenant_id = app.context_tenant_id());
DROP POLICY IF EXISTS customer_contacts_notification_dispatch_tenant
ON public.customer_contacts;
CREATE POLICY customer_contacts_notification_dispatch_tenant
ON public.customer_contacts AS PERMISSIVE FOR SELECT
TO periapsis_notification_dispatch_owner
USING (tenant_id = app.context_tenant_id());
DROP POLICY IF EXISTS notification_inbox_dispatch_permissions_v1
ON public.tenant_permissions;
CREATE POLICY notification_inbox_dispatch_permissions_v1
ON public.tenant_permissions AS PERMISSIVE FOR SELECT
TO periapsis_notification_dispatch_owner
USING (true);
CREATE POLICY notification_inbox_owner_sessions_v1
ON public.auth_sessions AS PERMISSIVE FOR SELECT
TO periapsis_notification_inbox_owner
USING (user_id = app.context_user_id()
  AND active_tenant_id = app.context_tenant_id());
CREATE POLICY notification_inbox_owner_users_v1
ON public.users AS PERMISSIVE FOR SELECT
TO periapsis_notification_inbox_owner
USING (id = app.context_user_id());
CREATE POLICY notification_inbox_owner_tenants_v1
ON public.tenants AS PERMISSIVE FOR SELECT
TO periapsis_notification_inbox_owner
USING (id = app.context_tenant_id());
CREATE POLICY notification_inbox_owner_memberships_v1
ON public.tenant_memberships AS PERMISSIVE FOR SELECT
TO periapsis_notification_inbox_owner
USING (tenant_id = app.context_tenant_id()
  AND user_id = app.context_user_id());
CREATE POLICY notification_inbox_owner_contacts_v1
ON public.customer_contacts AS PERMISSIVE FOR SELECT
TO periapsis_notification_inbox_owner
USING (tenant_id = app.context_tenant_id()
  AND linked_user_id = app.context_user_id());
--> statement-breakpoint

-- Principal classification is affirmative and deny-by-default. A live contact
-- link proves the customer principal; effective non-portal human RBAC proves
-- the operator principal. Dual, missing, expired, or ambiguous evidence is
-- rejected. The deprecated tenant_memberships.role value is never consulted.
CREATE FUNCTION app.private_notification_inbox_classify_principal_v1(
  p_tenant_id uuid,
  p_user_id uuid
)
RETURNS public.notification_audience
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  membership_id_value uuid;
  customer_evidence_count integer;
  operator_evidence boolean;
BEGIN
  IF p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_user_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'notification inbox principal is unavailable'
      USING ERRCODE = '42501';
  END IF;
  SELECT membership.id INTO membership_id_value
  FROM public.tenant_memberships AS membership
  JOIN public.users AS identity
    ON identity.id = membership.user_id AND identity.active
  JOIN public.tenants AS tenant
    ON tenant.id = membership.tenant_id AND tenant.status = 'active'
  JOIN public.tenant_authorization_states AS state
    ON state.tenant_id = membership.tenant_id
   AND state.initialized_at IS NOT NULL
  WHERE membership.tenant_id = p_tenant_id
    AND membership.user_id = p_user_id
    AND membership.status = 'active';
  IF membership_id_value IS NULL THEN
    RAISE EXCEPTION 'notification inbox principal is unavailable'
      USING ERRCODE = '42501';
  END IF;

  SELECT count(*)::integer INTO customer_evidence_count
  FROM public.customer_contacts AS contact
  WHERE contact.tenant_id = p_tenant_id
    AND contact.linked_membership_id = membership_id_value
    AND contact.linked_user_id = p_user_id
    AND contact.active AND contact.archived_at IS NULL;

  WITH effective_role AS (
    SELECT direct_grant.role_id
    FROM public.tenant_membership_role_grants AS direct_grant
    JOIN public.tenant_authorization_sources AS source
      ON source.tenant_id = direct_grant.tenant_id
     AND source.id = direct_grant.source_id
     AND source.retired_at IS NULL
    WHERE direct_grant.tenant_id = p_tenant_id
      AND direct_grant.membership_id = membership_id_value
      AND direct_grant.revoked_at IS NULL
      AND (direct_grant.expires_at IS NULL
        OR direct_grant.expires_at > transaction_timestamp())
    UNION
    SELECT group_grant.role_id
    FROM public.tenant_security_group_memberships AS group_member
    JOIN public.tenant_authorization_sources AS member_source
      ON member_source.tenant_id = group_member.tenant_id
     AND member_source.id = group_member.source_id
     AND member_source.retired_at IS NULL
    JOIN public.tenant_security_groups AS security_group
      ON security_group.tenant_id = group_member.tenant_id
     AND security_group.id = group_member.group_id
     AND security_group.archived_at IS NULL
    JOIN public.tenant_security_group_role_grants AS group_grant
      ON group_grant.tenant_id = group_member.tenant_id
     AND group_grant.group_id = group_member.group_id
     AND group_grant.revoked_at IS NULL
     AND (group_grant.expires_at IS NULL
       OR group_grant.expires_at > transaction_timestamp())
    JOIN public.tenant_authorization_sources AS grant_source
      ON grant_source.tenant_id = group_grant.tenant_id
     AND grant_source.id = group_grant.source_id
     AND grant_source.retired_at IS NULL
    WHERE group_member.tenant_id = p_tenant_id
      AND group_member.membership_id = membership_id_value
      AND group_member.revoked_at IS NULL
      AND (group_member.expires_at IS NULL
        OR group_member.expires_at > transaction_timestamp())
  )
  SELECT EXISTS (
    SELECT 1
    FROM effective_role
    JOIN public.tenant_roles AS role
      ON role.tenant_id = p_tenant_id
     AND role.id = effective_role.role_id
     AND role.principal_kind = 'human'
     AND role.archived_at IS NULL
    JOIN public.tenant_role_permissions AS role_permission
      ON role_permission.tenant_id = role.tenant_id
     AND role_permission.role_id = role.id
     AND role_permission.scope <> 'platform'
    JOIN public.tenant_permissions AS permission
      ON permission.id = role_permission.permission_id
    WHERE permission.key NOT LIKE 'portal.%'
  ) INTO operator_evidence;

  IF customer_evidence_count = 1 AND NOT operator_evidence THEN
    RETURN 'customer'::public.notification_audience;
  END IF;
  IF customer_evidence_count = 0 AND operator_evidence THEN
    RETURN 'operator'::public.notification_audience;
  END IF;
  RAISE EXCEPTION 'notification inbox principal is unavailable'
    USING ERRCODE = '42501';
END;
$function$;
ALTER FUNCTION app.private_notification_inbox_classify_principal_v1(uuid, uuid)
  OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION
  app.private_notification_inbox_classify_principal_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner;
GRANT EXECUTE ON FUNCTION
  app.private_notification_inbox_classify_principal_v1(uuid, uuid)
TO periapsis_notification_inbox_owner,
  periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_notification_inbox_principal_v1(
  p_tenant_id uuid,
  p_user_id uuid,
  p_session_id uuid
)
RETURNS public.notification_audience
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  result_principal public.notification_audience;
BEGIN
  IF p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR p_user_id IS DISTINCT FROM app.context_user_id()
     OR p_session_id IS NULL
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_user_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_session_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'notification inbox access is forbidden'
      USING ERRCODE = '42501';
  END IF;
  SELECT app.private_notification_inbox_classify_principal_v1(
    p_tenant_id, p_user_id
  )
  INTO result_principal
  FROM public.auth_sessions AS session
  WHERE session.id = p_session_id
    AND session.user_id = p_user_id
    AND session.active_tenant_id = p_tenant_id
    AND session.revoked_at IS NULL
    AND session.created_at <= transaction_timestamp()
    AND session.last_seen_at <= transaction_timestamp()
    AND session.idle_expires_at > transaction_timestamp()
    AND session.absolute_expires_at > transaction_timestamp()
    AND session.mfa_satisfied_at IS NOT NULL
    AND session.mfa_satisfied_at <= transaction_timestamp();
  IF result_principal IS NULL THEN
    RAISE EXCEPTION 'notification inbox access is forbidden'
      USING ERRCODE = '42501';
  END IF;
  RETURN result_principal;
END;
$function$;
ALTER FUNCTION app.private_notification_inbox_principal_v1(uuid, uuid, uuid)
  OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.private_notification_inbox_principal_v1(uuid, uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.private_notification_inbox_principal_v1(uuid, uuid, uuid)
TO periapsis_notification_inbox_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_notification_inbox_item_document_v1(
  p_item public.tenant_notification_inbox_items
)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
  SELECT jsonb_build_object(
    'id', p_item.id, 'tenantId', p_item.tenant_id,
    'userId', p_item.user_id, 'audience', p_item.audience,
    'eventType', p_item.event_type, 'resourceKind', p_item.resource_kind,
    'resourceId', p_item.resource_id,
    'resourceVersion', p_item.resource_version,
    'title', p_item.title, 'summary', p_item.summary,
    'occurredAt', p_item.occurred_at, 'readAt', p_item.read_at,
    'revision', p_item.revision
  )
$function$;
ALTER FUNCTION app.private_notification_inbox_item_document_v1(
  public.tenant_notification_inbox_items
) OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.private_notification_inbox_item_document_v1(
  public.tenant_notification_inbox_items
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.private_notification_inbox_item_document_v1(
  public.tenant_notification_inbox_items
) TO periapsis_notification_inbox_owner;
--> statement-breakpoint

CREATE FUNCTION app.resolve_notification_inbox_access_v1(p_session_id uuid)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_user uuid := app.context_user_id();
  principal public.notification_audience;
BEGIN
  principal := app.private_notification_inbox_principal_v1(
    context_tenant, context_user, p_session_id
  );
  RETURN jsonb_build_object(
    'tenantId', context_tenant, 'userId', context_user,
    'sessionId', p_session_id, 'principal', principal,
    'authenticated', true, 'active', true,
    'evaluatedAt', clock_timestamp()
  );
END;
$function$;
ALTER FUNCTION app.resolve_notification_inbox_access_v1(uuid)
  OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.resolve_notification_inbox_access_v1(uuid)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.resolve_notification_inbox_access_v1(uuid)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.list_notification_inbox_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_user uuid := app.context_user_id();
  request_tenant uuid;
  request_user uuid;
  request_session uuid;
  request_after uuid;
  request_limit integer;
  request_unread_only boolean;
  principal public.notification_audience;
  inbox_revision integer;
  projected_items jsonb;
BEGIN
  IF p_request IS NULL OR jsonb_typeof(p_request) <> 'object'
     OR NOT (p_request ?& ARRAY[
       'schemaVersion', 'tenantId', 'userId', 'sessionId',
       'after', 'limit', 'unreadOnly'
     ])
     OR p_request - ARRAY[
       'schemaVersion', 'tenantId', 'userId', 'sessionId',
       'after', 'limit', 'unreadOnly'
     ]::text[] <> '{}'::jsonb
     OR p_request->>'schemaVersion' <> '1'
     OR jsonb_typeof(p_request->'limit') <> 'number'
     OR jsonb_typeof(p_request->'unreadOnly') <> 'boolean' THEN
    RAISE EXCEPTION 'notification inbox list input is invalid'
      USING ERRCODE = '22023';
  END IF;
  request_tenant := (p_request->>'tenantId')::uuid;
  request_user := (p_request->>'userId')::uuid;
  request_session := (p_request->>'sessionId')::uuid;
  request_limit := (p_request->>'limit')::integer;
  request_unread_only := (p_request->>'unreadOnly')::boolean;
  IF p_request->'after' <> 'null'::jsonb THEN
    request_after := (p_request->>'after')::uuid;
  END IF;
  IF request_tenant IS DISTINCT FROM context_tenant
     OR request_user IS DISTINCT FROM context_user
     OR request_limit NOT BETWEEN 1 AND 101
     OR (request_after IS NOT NULL
       AND (uuid_extract_version(request_after) = 7) IS NOT TRUE) THEN
    RAISE EXCEPTION 'notification inbox list input is invalid'
      USING ERRCODE = '22023';
  END IF;
  principal := app.private_notification_inbox_principal_v1(
    request_tenant, request_user, request_session
  );
  SELECT coalesce(state.revision, 0) INTO inbox_revision
  FROM (SELECT 1) AS anchor
  LEFT JOIN public.tenant_notification_inbox_states AS state
    ON state.tenant_id = request_tenant AND state.user_id = request_user;
  SELECT coalesce(jsonb_agg(
    app.private_notification_inbox_item_document_v1(selected.item)
    ORDER BY (selected.item).id DESC
  ), '[]'::jsonb) INTO projected_items
  FROM (
    SELECT item AS item
    FROM public.tenant_notification_inbox_items AS item
    WHERE item.tenant_id = request_tenant AND item.user_id = request_user
      AND item.audience = principal
      AND (request_after IS NULL OR item.id < request_after)
      AND (NOT request_unread_only OR item.read_at IS NULL)
    ORDER BY item.id DESC LIMIT request_limit
  ) AS selected;
  RETURN jsonb_build_object(
    'tenantId', request_tenant, 'userId', request_user,
    'inboxRevision', inbox_revision, 'items', projected_items
  );
END;
$function$;
ALTER FUNCTION app.list_notification_inbox_v1(jsonb)
  OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.list_notification_inbox_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.list_notification_inbox_v1(jsonb) TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.count_notification_inbox_unread_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  context_user uuid := app.context_user_id();
  request_tenant uuid;
  request_user uuid;
  request_session uuid;
  principal public.notification_audience;
  unread_count bigint;
  inbox_revision integer;
BEGIN
  IF p_request IS NULL OR jsonb_typeof(p_request) <> 'object'
     OR NOT (p_request ?& ARRAY[
       'schemaVersion', 'tenantId', 'userId', 'sessionId'
     ])
     OR p_request - ARRAY[
       'schemaVersion', 'tenantId', 'userId', 'sessionId'
     ]::text[] <> '{}'::jsonb
     OR p_request->>'schemaVersion' <> '1' THEN
    RAISE EXCEPTION 'notification inbox count input is invalid'
      USING ERRCODE = '22023';
  END IF;
  request_tenant := (p_request->>'tenantId')::uuid;
  request_user := (p_request->>'userId')::uuid;
  request_session := (p_request->>'sessionId')::uuid;
  IF request_tenant IS DISTINCT FROM context_tenant
     OR request_user IS DISTINCT FROM context_user THEN
    RAISE EXCEPTION 'notification inbox count input is invalid'
      USING ERRCODE = '22023';
  END IF;
  principal := app.private_notification_inbox_principal_v1(
    request_tenant, request_user, request_session
  );
  SELECT count(*) INTO unread_count
  FROM public.tenant_notification_inbox_items AS item
  WHERE item.tenant_id = request_tenant AND item.user_id = request_user
    AND item.audience = principal AND item.read_at IS NULL;
  IF unread_count > 1000000 THEN
    RAISE EXCEPTION 'notification inbox unread count exceeds its bound'
      USING ERRCODE = '54000';
  END IF;
  SELECT coalesce(state.revision, 0) INTO inbox_revision
  FROM (SELECT 1) AS anchor
  LEFT JOIN public.tenant_notification_inbox_states AS state
    ON state.tenant_id = request_tenant AND state.user_id = request_user;
  RETURN jsonb_build_object(
    'tenantId', request_tenant, 'userId', request_user,
    'count', unread_count, 'inboxRevision', inbox_revision
  );
END;
$function$;
ALTER FUNCTION app.count_notification_inbox_unread_v1(jsonb)
  OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.count_notification_inbox_unread_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.count_notification_inbox_unread_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.private_notification_inbox_audit_method_v1(
  p_session_id uuid,
  p_audit jsonb
)
RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_id uuid;
  correlation_id uuid;
  remote_address inet;
  user_agent text;
BEGIN
  IF p_audit IS NULL OR jsonb_typeof(p_audit) <> 'object'
     OR NOT (p_audit ?& ARRAY[
       'requestId', 'correlationId', 'remoteAddress', 'userAgent'
     ])
     OR p_audit - ARRAY[
       'requestId', 'correlationId', 'remoteAddress', 'userAgent'
     ]::text[] <> '{}'::jsonb
     OR jsonb_typeof(p_audit->'requestId') <> 'string'
     OR jsonb_typeof(p_audit->'correlationId') <> 'string'
     OR jsonb_typeof(p_audit->'remoteAddress') <> 'string'
     OR jsonb_typeof(p_audit->'userAgent') <> 'string' THEN
    RAISE EXCEPTION 'notification inbox audit input is invalid'
      USING ERRCODE = '22023';
  END IF;
  request_id := (p_audit->>'requestId')::uuid;
  correlation_id := (p_audit->>'correlationId')::uuid;
  remote_address := (p_audit->>'remoteAddress')::inet;
  user_agent := p_audit->>'userAgent';
  IF (uuid_extract_version(request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(correlation_id) = 7) IS NOT TRUE
     OR btrim(user_agent) IS DISTINCT FROM user_agent
     OR octet_length(user_agent) NOT BETWEEN 1 AND 512
     OR user_agent ~ '[[:cntrl:]]'
     OR user_agent ~ U&'[\202A-\202E\2066-\2069\200E\200F\061C]' THEN
    RAISE EXCEPTION 'notification inbox audit input is invalid'
      USING ERRCODE = '22023';
  END IF;
  RETURN app.require_live_audit_session_v1(
    p_session_id, app.context_tenant_id()
  );
EXCEPTION WHEN invalid_text_representation THEN
  RAISE EXCEPTION 'notification inbox audit input is invalid'
    USING ERRCODE = '22023';
END;
$function$;
ALTER FUNCTION app.private_notification_inbox_audit_method_v1(uuid, jsonb)
  OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.private_notification_inbox_audit_method_v1(uuid, jsonb)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.private_notification_inbox_audit_method_v1(uuid, jsonb)
TO periapsis_notification_inbox_owner;
--> statement-breakpoint

CREATE FUNCTION app.set_notification_inbox_read_state_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant uuid;
  request_user uuid;
  request_session uuid;
  request_item uuid;
  request_read boolean;
  expected_revision integer;
  operation_value text;
  key_digest_value bytea;
  request_digest_value bytea;
  principal public.notification_audience;
  authentication_method text;
  selected_item public.tenant_notification_inbox_items%ROWTYPE;
  inbox_revision integer;
  changed_value boolean;
  result_value jsonb;
  previous_command record;
  operation_at timestamp with time zone := transaction_timestamp();
  item_update_at timestamp with time zone;
BEGIN
  IF p_request IS NULL OR jsonb_typeof(p_request) <> 'object'
     OR NOT (p_request ?& ARRAY[
       'schemaVersion','tenantId','userId','sessionId','itemId','read',
       'expectedRevision','operation','keyDigest','requestDigest','audit'
     ])
     OR p_request - ARRAY[
       'schemaVersion','tenantId','userId','sessionId','itemId','read',
       'expectedRevision','operation','keyDigest','requestDigest','audit'
     ]::text[] <> '{}'::jsonb
     OR p_request->>'schemaVersion' <> '1'
     OR jsonb_typeof(p_request->'read') <> 'boolean'
     OR jsonb_typeof(p_request->'expectedRevision') <> 'number'
     OR p_request->>'operation' <> 'notification_inbox.set_read_state'
     OR p_request->>'keyDigest' !~ '^[0-9a-f]{64}$'
     OR p_request->>'requestDigest' !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'notification inbox read-state input is invalid'
      USING ERRCODE = '22023';
  END IF;
  request_tenant := (p_request->>'tenantId')::uuid;
  request_user := (p_request->>'userId')::uuid;
  request_session := (p_request->>'sessionId')::uuid;
  request_item := (p_request->>'itemId')::uuid;
  request_read := (p_request->>'read')::boolean;
  expected_revision := (p_request->>'expectedRevision')::integer;
  operation_value := p_request->>'operation';
  key_digest_value := decode(p_request->>'keyDigest', 'hex');
  request_digest_value := decode(p_request->>'requestDigest', 'hex');
  IF request_tenant IS DISTINCT FROM app.context_tenant_id()
     OR request_user IS DISTINCT FROM app.context_user_id()
     OR (uuid_extract_version(request_tenant) = 7) IS NOT TRUE
     OR (uuid_extract_version(request_user) = 7) IS NOT TRUE
     OR (uuid_extract_version(request_item) = 7) IS NOT TRUE
     OR expected_revision NOT BETWEEN 1 AND 2147483646 THEN
    RAISE EXCEPTION 'notification inbox read-state input is invalid'
      USING ERRCODE = '22023';
  END IF;
  principal := app.private_notification_inbox_principal_v1(
    request_tenant, request_user, request_session
  );
  authentication_method := app.private_notification_inbox_audit_method_v1(
    request_session, p_request->'audit'
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    request_tenant::text || ':' || request_user::text || ':' ||
    operation_value || ':' || encode(key_digest_value, 'hex'), 0
  ));
  DELETE FROM public.tenant_notification_inbox_commands AS command
  WHERE command.tenant_id = request_tenant
    AND command.user_id = request_user
    AND command.operation = operation_value
    AND command.key_digest = key_digest_value
    AND command.expires_at <= operation_at;
  SELECT command.request_digest, command.result
  INTO previous_command
  FROM public.tenant_notification_inbox_commands AS command
  WHERE command.tenant_id = request_tenant
    AND command.user_id = request_user
    AND command.operation = operation_value
    AND command.key_digest = key_digest_value;
  IF FOUND THEN
    IF previous_command.request_digest IS DISTINCT FROM request_digest_value THEN
      RAISE EXCEPTION 'notification inbox idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    IF previous_command.result->>'principal' IS DISTINCT FROM principal::text
    THEN
      RAISE EXCEPTION 'notification inbox replay audience is forbidden'
        USING ERRCODE = '42501';
    END IF;
    RETURN (previous_command.result - 'principal')
      || jsonb_build_object('replayed', true);
  END IF;
  SELECT state.revision INTO inbox_revision
  FROM public.tenant_notification_inbox_states AS state
  WHERE state.tenant_id = request_tenant AND state.user_id = request_user
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification inbox item was not found'
      USING ERRCODE = 'P0002';
  END IF;
  SELECT item.* INTO selected_item
  FROM public.tenant_notification_inbox_items AS item
  WHERE item.tenant_id = request_tenant AND item.user_id = request_user
    AND item.id = request_item AND item.audience = principal
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification inbox item was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF selected_item.revision <> expected_revision THEN
    RAISE EXCEPTION 'notification inbox item revision changed'
      USING ERRCODE = '40001';
  END IF;
  item_update_at := greatest(
    operation_at,
    selected_item.occurred_at,
    selected_item.created_at,
    selected_item.updated_at
  );
  changed_value := (selected_item.read_at IS NULL) = request_read;
  IF changed_value THEN
    UPDATE public.tenant_notification_inbox_items AS item
    SET read_at = CASE WHEN request_read THEN item_update_at ELSE NULL END,
        revision = item.revision + 1,
        updated_at = item_update_at
    WHERE item.tenant_id = request_tenant AND item.user_id = request_user
      AND item.id = request_item
    RETURNING item.* INTO STRICT selected_item;
    UPDATE public.tenant_notification_inbox_states AS state
    SET revision = state.revision + 1,
        updated_at = greatest(state.updated_at, item_update_at)
    WHERE state.tenant_id = request_tenant AND state.user_id = request_user
      AND state.revision < 2147483647
    RETURNING state.revision INTO inbox_revision;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'notification inbox revision is exhausted'
        USING ERRCODE = '22023';
    END IF;
    PERFORM app.append_tenant_authorization_audit(
      uuidv7(), 'notification_inbox.read_state_set',
      'notification_inbox_item', request_item,
      (p_request#>>'{audit,requestId}')::uuid,
      (p_request#>>'{audit,correlationId}')::uuid,
      (p_request#>>'{audit,remoteAddress}')::inet,
      p_request#>>'{audit,userAgent}', authentication_method,
      jsonb_build_object('read', NOT request_read,
        'revision', expected_revision),
      jsonb_build_object('read', request_read,
        'revision', selected_item.revision),
      jsonb_build_object('inboxRevision', inbox_revision)
    );
  END IF;
  result_value := jsonb_build_object(
    'item', app.private_notification_inbox_item_document_v1(selected_item),
    'inboxRevision', inbox_revision, 'changed', changed_value,
    'replayed', false
  );
  INSERT INTO public.tenant_notification_inbox_commands(
    tenant_id,user_id,operation,key_digest,request_digest,result,
    created_at,expires_at
  ) VALUES (
    request_tenant,request_user,operation_value,key_digest_value,
    request_digest_value,
    result_value || jsonb_build_object('principal', principal),
    operation_at,operation_at + interval '24 hours'
  );
  RETURN result_value;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
  RAISE EXCEPTION 'notification inbox read-state input is invalid'
    USING ERRCODE = '22023';
END;
$function$;
ALTER FUNCTION app.set_notification_inbox_read_state_v1(jsonb)
  OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.set_notification_inbox_read_state_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.set_notification_inbox_read_state_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.mark_all_notification_inbox_read_v1(p_request jsonb)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant uuid;
  request_user uuid;
  request_session uuid;
  expected_revision integer;
  operation_value text;
  key_digest_value bytea;
  request_digest_value bytea;
  principal public.notification_audience;
  authentication_method text;
  inbox_revision integer;
  affected_value integer;
  changed_value boolean;
  result_value jsonb;
  previous_command record;
  operation_at timestamp with time zone := transaction_timestamp();
BEGIN
  IF p_request IS NULL OR jsonb_typeof(p_request) <> 'object'
     OR NOT (p_request ?& ARRAY[
       'schemaVersion','tenantId','userId','sessionId','expectedRevision',
       'operation','keyDigest','requestDigest','audit'
     ])
     OR p_request - ARRAY[
       'schemaVersion','tenantId','userId','sessionId','expectedRevision',
       'operation','keyDigest','requestDigest','audit'
     ]::text[] <> '{}'::jsonb
     OR p_request->>'schemaVersion' <> '1'
     OR jsonb_typeof(p_request->'expectedRevision') <> 'number'
     OR p_request->>'operation' <> 'notification_inbox.mark_all_read'
     OR p_request->>'keyDigest' !~ '^[0-9a-f]{64}$'
     OR p_request->>'requestDigest' !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'notification inbox mark-all input is invalid'
      USING ERRCODE = '22023';
  END IF;
  request_tenant := (p_request->>'tenantId')::uuid;
  request_user := (p_request->>'userId')::uuid;
  request_session := (p_request->>'sessionId')::uuid;
  expected_revision := (p_request->>'expectedRevision')::integer;
  operation_value := p_request->>'operation';
  key_digest_value := decode(p_request->>'keyDigest', 'hex');
  request_digest_value := decode(p_request->>'requestDigest', 'hex');
  IF request_tenant IS DISTINCT FROM app.context_tenant_id()
     OR request_user IS DISTINCT FROM app.context_user_id()
     OR (uuid_extract_version(request_tenant) = 7) IS NOT TRUE
     OR (uuid_extract_version(request_user) = 7) IS NOT TRUE
     OR expected_revision NOT BETWEEN 0 AND 2147483646 THEN
    RAISE EXCEPTION 'notification inbox mark-all input is invalid'
      USING ERRCODE = '22023';
  END IF;
  principal := app.private_notification_inbox_principal_v1(
    request_tenant, request_user, request_session
  );
  authentication_method := app.private_notification_inbox_audit_method_v1(
    request_session, p_request->'audit'
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    request_tenant::text || ':' || request_user::text || ':' ||
    operation_value || ':' || encode(key_digest_value, 'hex'), 0
  ));
  INSERT INTO public.tenant_notification_inbox_states(
    tenant_id,user_id,revision,updated_at
  ) VALUES (request_tenant,request_user,0,operation_at)
  ON CONFLICT (tenant_id,user_id) DO NOTHING;
  DELETE FROM public.tenant_notification_inbox_commands AS command
  WHERE command.tenant_id = request_tenant
    AND command.user_id = request_user
    AND command.operation = operation_value
    AND command.key_digest = key_digest_value
    AND command.expires_at <= operation_at;
  SELECT command.request_digest, command.result
  INTO previous_command
  FROM public.tenant_notification_inbox_commands AS command
  WHERE command.tenant_id = request_tenant
    AND command.user_id = request_user
    AND command.operation = operation_value
    AND command.key_digest = key_digest_value;
  IF FOUND THEN
    IF previous_command.request_digest IS DISTINCT FROM request_digest_value THEN
      RAISE EXCEPTION 'notification inbox idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    IF previous_command.result->>'principal' IS DISTINCT FROM principal::text
    THEN
      RAISE EXCEPTION 'notification inbox replay audience is forbidden'
        USING ERRCODE = '42501';
    END IF;
    RETURN (previous_command.result - 'principal')
      || jsonb_build_object('replayed', true);
  END IF;
  SELECT state.revision INTO STRICT inbox_revision
  FROM public.tenant_notification_inbox_states AS state
  WHERE state.tenant_id = request_tenant AND state.user_id = request_user
  FOR UPDATE;
  IF inbox_revision <> expected_revision THEN
    RAISE EXCEPTION 'notification inbox revision changed'
      USING ERRCODE = '40001';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.tenant_notification_inbox_items AS item
    WHERE item.tenant_id = request_tenant AND item.user_id = request_user
      AND item.audience = principal AND item.read_at IS NULL
      AND item.revision >= 2147483647
  ) THEN
    RAISE EXCEPTION 'notification inbox item revision is exhausted'
      USING ERRCODE = '22023';
  END IF;
  UPDATE public.tenant_notification_inbox_items AS item
  SET read_at = greatest(
        operation_at, item.occurred_at, item.created_at, item.updated_at
      ),
      revision = item.revision + 1,
      updated_at = greatest(
        operation_at, item.occurred_at, item.created_at, item.updated_at
      )
  WHERE item.tenant_id = request_tenant AND item.user_id = request_user
    AND item.audience = principal AND item.read_at IS NULL;
  GET DIAGNOSTICS affected_value = ROW_COUNT;
  changed_value := affected_value > 0;
  IF affected_value > 1000000 THEN
    RAISE EXCEPTION 'notification inbox mark-all result exceeds its bound'
      USING ERRCODE = '54000';
  END IF;
  IF changed_value THEN
    UPDATE public.tenant_notification_inbox_states AS state
    SET revision = state.revision + 1,
        updated_at = greatest(
          state.updated_at,
          operation_at,
          coalesce((
            SELECT max(item.updated_at)
            FROM public.tenant_notification_inbox_items AS item
            WHERE item.tenant_id = request_tenant
              AND item.user_id = request_user
              AND item.audience = principal
          ), operation_at)
        )
    WHERE state.tenant_id = request_tenant AND state.user_id = request_user
      AND state.revision < 2147483647
    RETURNING state.revision INTO inbox_revision;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'notification inbox revision is exhausted'
        USING ERRCODE = '22023';
    END IF;
    PERFORM app.append_tenant_authorization_audit(
      uuidv7(), 'notification_inbox.marked_all_read',
      'notification_inbox', request_user,
      (p_request#>>'{audit,requestId}')::uuid,
      (p_request#>>'{audit,correlationId}')::uuid,
      (p_request#>>'{audit,remoteAddress}')::inet,
      p_request#>>'{audit,userAgent}', authentication_method,
      jsonb_build_object('inboxRevision', expected_revision),
      jsonb_build_object('inboxRevision', inbox_revision),
      jsonb_build_object('affected', affected_value)
    );
  END IF;
  result_value := jsonb_build_object(
    'tenantId', request_tenant, 'userId', request_user,
    'affected', affected_value, 'inboxRevision', inbox_revision,
    'changed', changed_value, 'replayed', false
  );
  INSERT INTO public.tenant_notification_inbox_commands(
    tenant_id,user_id,operation,key_digest,request_digest,result,
    created_at,expires_at
  ) VALUES (
    request_tenant,request_user,operation_value,key_digest_value,
    request_digest_value,
    result_value || jsonb_build_object('principal', principal),
    operation_at,operation_at + interval '24 hours'
  );
  RETURN result_value;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
  RAISE EXCEPTION 'notification inbox mark-all input is invalid'
    USING ERRCODE = '22023';
END;
$function$;
ALTER FUNCTION app.mark_all_notification_inbox_read_v1(jsonb)
  OWNER TO periapsis_notification_inbox_owner;
REVOKE ALL ON FUNCTION app.mark_all_notification_inbox_read_v1(jsonb)
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_dispatch_owner;
GRANT EXECUTE ON FUNCTION app.mark_all_notification_inbox_read_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

-- Classify an account solely from current live relationships. The deprecated
-- tenant_memberships.role field is intentionally absent from this function.
CREATE FUNCTION app.private_notification_inbox_live_principal_v1(
  p_tenant_id uuid,
  p_user_id uuid
)
RETURNS public.notification_audience
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  result_principal public.notification_audience;
BEGIN
  IF p_tenant_id IS DISTINCT FROM app.context_tenant_id()
     OR (uuid_extract_version(p_tenant_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(p_user_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'notification inbox principal is invalid'
      USING ERRCODE = '42501';
  END IF;
  result_principal := app.private_notification_inbox_classify_principal_v1(
    p_tenant_id, p_user_id
  );
  RETURN result_principal;
END;
$function$;
ALTER FUNCTION app.private_notification_inbox_live_principal_v1(uuid, uuid)
  OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION app.private_notification_inbox_live_principal_v1(uuid, uuid)
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_inbox_owner;
GRANT EXECUTE ON FUNCTION app.private_notification_inbox_live_principal_v1(uuid, uuid)
TO periapsis_notification_dispatch_owner;
--> statement-breakpoint

CREATE FUNCTION app.commit_notification_fanout_v3(
  p_event_id uuid,
  p_fence_token uuid,
  p_deliveries jsonb,
  p_committed_at timestamp with time zone
)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path = pg_catalog, public, app SET TimeZone = 'UTC'
AS $function$
DECLARE
  source_event public.outbox_events%ROWTYPE;
  selected_rule public.tenant_notification_rule_versions%ROWTYPE;
  delivery_value jsonb;
  fanout_inputs jsonb;
  clean_deliveries jsonb;
  supplied_principal uuid;
  live_principal public.notification_audience;
  matching_candidate_count integer;
  authorized_principal_count integer;
  candidate_principals_complete boolean;
  committed_result jsonb;
  event_type_value public.notification_event_type;
  resource_kind_value public.notification_object_type;
  title_value text;
  principal_row record;
  inserted_count integer;
BEGIN
  IF p_deliveries IS NULL OR jsonb_typeof(p_deliveries) <> 'array'
     OR jsonb_array_length(p_deliveries) > 10000
     OR octet_length(p_deliveries::text) > 8388608 THEN
    RAISE EXCEPTION 'notification fanout commit input is invalid'
      USING ERRCODE = '22023';
  END IF;
  SELECT event.* INTO source_event
  FROM public.outbox_events AS event
  WHERE event.id = p_event_id
    AND event.event_type LIKE 'notification.%'
    AND event.schema_version = 2
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification event not found' USING ERRCODE = 'P0002';
  END IF;
  PERFORM set_config('app.tenant_id', source_event.tenant_id::text, true);
  event_type_value := substring(source_event.event_type from 14)
    ::public.notification_event_type;
  resource_kind_value := source_event.aggregate_type
    ::public.notification_object_type;
  IF NOT (CASE
    WHEN event_type_value IN (
      'alert.created','alert.assigned','alert.claimed',
      'alert.status_changed','alert.escalated','alert.watcher_added',
      'alert.watcher_removed'
    ) THEN resource_kind_value = 'alert'
    WHEN event_type_value IN (
      'case.created','case.assigned','case.claimed','case.transferred',
      'case.status_changed','case.watcher_added','case.watcher_removed'
    ) THEN resource_kind_value = 'case'
    WHEN event_type_value IN (
      'comment.public_added','comment.private_added',
      'sla.warning','sla.breached'
    ) THEN resource_kind_value IN ('alert','case')
    WHEN event_type_value = 'contact.changed'
      THEN resource_kind_value = 'contact'
    WHEN event_type_value = 'task.assigned'
      THEN resource_kind_value = 'task'
    WHEN event_type_value = 'evidence.added'
      THEN resource_kind_value = 'evidence'
    WHEN event_type_value = 'webhook.custom' THEN true
    ELSE false END) THEN
    RAISE EXCEPTION 'notification event resource mapping is invalid'
      USING ERRCODE = '42501';
  END IF;
  SELECT coalesce(jsonb_agg(item.value - 'principalId'
      ORDER BY item.ordinal), '[]'::jsonb)
  INTO clean_deliveries
  FROM jsonb_array_elements(p_deliveries) WITH ORDINALITY
    AS item(value, ordinal);
  IF source_event.processed_at IS NULL THEN
    fanout_inputs := app.load_notification_fanout_inputs_v3(
      p_event_id, p_fence_token
    );
    IF EXISTS (
      SELECT 1
      FROM jsonb_array_elements(p_deliveries) AS item(value)
      WHERE item.value ? 'principalId'
      GROUP BY item.value->>'principalId'
      HAVING count(DISTINCT item.value->>'audience') > 1
    ) THEN
      RAISE EXCEPTION 'notification principal audience is ambiguous'
        USING ERRCODE = '42501';
    END IF;
    FOR delivery_value IN
      SELECT item.value
      FROM jsonb_array_elements(p_deliveries) WITH ORDINALITY
        AS item(value, ordinal)
      ORDER BY item.ordinal
    LOOP
      IF jsonb_typeof(delivery_value) <> 'object'
         OR (delivery_value ? 'principalId' AND
           jsonb_typeof(delivery_value->'principalId') <> 'string') THEN
        RAISE EXCEPTION 'planned notification delivery is invalid'
          USING ERRCODE = '22023';
      END IF;
      IF delivery_value ? 'principalId' THEN
        supplied_principal := (delivery_value->>'principalId')::uuid;
        IF (uuid_extract_version(supplied_principal) = 7) IS NOT TRUE THEN
          RAISE EXCEPTION 'planned notification principal is invalid'
            USING ERRCODE = '22023';
        END IF;
        SELECT count(*)::integer,
               count(DISTINCT candidate.value->>'principalId')::integer,
               bool_and(
                 candidate.value ? 'principalId'
                 AND jsonb_typeof(candidate.value->'principalId') = 'string'
                 AND candidate.value->>'principalId' = supplied_principal::text
               )
        INTO matching_candidate_count, authorized_principal_count,
             candidate_principals_complete
        FROM jsonb_array_elements(
          coalesce(fanout_inputs->'candidates', '[]'::jsonb)
        ) AS candidate(value)
        WHERE candidate.value->>'email' = delivery_value->>'recipient'
          AND candidate.value->>'audience' = delivery_value->>'audience'
          AND candidate.value->'enabled' = 'true'::jsonb
          AND candidate.value->'emailAllowed' = 'true'::jsonb;
        SELECT version.* INTO selected_rule
        FROM public.tenant_notification_rule_versions AS version
        WHERE version.tenant_id = source_event.tenant_id
          AND version.rule_id = (delivery_value->>'ruleId')::uuid
          AND version.version = (delivery_value->>'ruleVersion')::integer
          AND version.channel = 'email';
        IF matching_candidate_count < 1
           OR authorized_principal_count <> 1
           OR candidate_principals_complete IS NOT TRUE
           OR NOT FOUND OR NOT EXISTS (
          SELECT 1
          FROM jsonb_array_elements(selected_rule.recipients)
            AS selector(value)
          JOIN LATERAL jsonb_array_elements(
            coalesce(fanout_inputs->'candidates', '[]'::jsonb)
          ) AS candidate(value) ON true
          WHERE selector.value->>'kind' NOT IN (
              'explicit_email', 'custom_email_field'
            )
            AND selector.value->>'audience' = delivery_value->>'audience'
            AND candidate.value->>'email' = delivery_value->>'recipient'
            AND candidate.value->>'audience' = delivery_value->>'audience'
            AND candidate.value->>'principalId' = supplied_principal::text
            AND candidate.value->'enabled' = 'true'::jsonb
            AND candidate.value->'emailAllowed' = 'true'::jsonb
            AND candidate.value->'kinds' ? (selector.value->>'kind')
            AND (NOT (selector.value ? 'value') OR
              candidate.value->'values'->(selector.value->>'kind')
                ? (selector.value->>'value'))
        ) THEN
          RAISE EXCEPTION 'notification inbox principal is not authorized'
            USING ERRCODE = '42501';
        END IF;
        live_principal := app.private_notification_inbox_live_principal_v1(
          source_event.tenant_id, supplied_principal
        );
        IF live_principal::text <> delivery_value->>'audience'
           OR (live_principal = 'customer' AND (
             source_event.maximum_audience <> 'customer'
             OR substring(source_event.event_type from 14) IN (
               'alert.watcher_added', 'alert.watcher_removed',
               'case.watcher_added', 'case.watcher_removed',
               'comment.private_added'
             )
           )) THEN
          RAISE EXCEPTION 'notification inbox audience is forbidden'
            USING ERRCODE = '42501';
        END IF;
      END IF;
    END LOOP;
  END IF;
  committed_result := app.commit_notification_fanout_v2(
    p_event_id, p_fence_token, clean_deliveries, p_committed_at
  );
  IF committed_result->>'outcome' <> 'committed' THEN
    RETURN committed_result;
  END IF;
  title_value := CASE event_type_value
    WHEN 'alert.created' THEN 'Alert created'
    WHEN 'alert.assigned' THEN 'Alert assigned'
    WHEN 'alert.claimed' THEN 'Alert claimed'
    WHEN 'alert.status_changed' THEN 'Alert status changed'
    WHEN 'alert.escalated' THEN 'Alert escalated'
    WHEN 'alert.watcher_added' THEN 'Alert watcher added'
    WHEN 'alert.watcher_removed' THEN 'Alert watcher removed'
    WHEN 'case.created' THEN 'Case created'
    WHEN 'case.assigned' THEN 'Case assigned'
    WHEN 'case.claimed' THEN 'Case claimed'
    WHEN 'case.transferred' THEN 'Case transferred'
    WHEN 'case.status_changed' THEN 'Case status changed'
    WHEN 'case.watcher_added' THEN 'Case watcher added'
    WHEN 'case.watcher_removed' THEN 'Case watcher removed'
    WHEN 'comment.public_added' THEN 'New public comment'
    WHEN 'comment.private_added' THEN 'New private comment'
    WHEN 'contact.changed' THEN 'Contact changed'
    WHEN 'sla.warning' THEN 'SLA warning'
    WHEN 'sla.breached' THEN 'SLA breached'
    WHEN 'task.assigned' THEN 'Task assigned'
    WHEN 'evidence.added' THEN 'Evidence added'
    WHEN 'webhook.custom' THEN 'Resource updated'
  END;
  FOR principal_row IN
    SELECT (item.value->>'principalId')::uuid AS user_id,
           min(item.value->>'audience')::public.notification_audience
             AS audience
    FROM jsonb_array_elements(p_deliveries) AS item(value)
    WHERE item.value ? 'principalId'
    GROUP BY (item.value->>'principalId')::uuid
    HAVING count(DISTINCT item.value->>'audience') = 1
    ORDER BY (item.value->>'principalId')::uuid
  LOOP
    INSERT INTO public.tenant_notification_inbox_states(
      tenant_id,user_id,revision,updated_at
    ) VALUES (
      source_event.tenant_id,principal_row.user_id,0,p_committed_at
    ) ON CONFLICT (tenant_id,user_id) DO NOTHING;
    INSERT INTO public.tenant_notification_inbox_items(
      tenant_id,user_id,event_id,audience,event_type,resource_kind,
      resource_id,resource_version,title,summary,occurred_at,revision,
      created_at,updated_at
    ) VALUES (
      source_event.tenant_id,principal_row.user_id,p_event_id,
      principal_row.audience,event_type_value,resource_kind_value,
      source_event.aggregate_id,source_event.aggregate_version,
      title_value,'',source_event.occurred_at,1,
      greatest(p_committed_at,source_event.occurred_at),
      greatest(p_committed_at,source_event.occurred_at)
    ) ON CONFLICT (tenant_id,event_id,user_id) DO NOTHING;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count = 1 THEN
      UPDATE public.tenant_notification_inbox_states AS state
      SET revision = state.revision + 1,
          updated_at = greatest(
            state.updated_at,
            p_committed_at,
            source_event.occurred_at
          )
      WHERE state.tenant_id = source_event.tenant_id
        AND state.user_id = principal_row.user_id
        AND state.revision < 2147483647;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'notification inbox revision is exhausted'
          USING ERRCODE = '22023';
      END IF;
    END IF;
  END LOOP;
  RETURN committed_result;
EXCEPTION WHEN invalid_text_representation THEN
  RAISE EXCEPTION 'notification fanout principal input is invalid'
    USING ERRCODE = '22023';
END;
$function$;
ALTER FUNCTION app.commit_notification_fanout_v3(
  uuid, uuid, jsonb, timestamp with time zone
) OWNER TO periapsis_notification_dispatch_owner;
REVOKE ALL ON FUNCTION app.commit_notification_fanout_v2(
  uuid, uuid, jsonb, timestamp with time zone
) FROM periapsis_notifier;
REVOKE ALL ON FUNCTION app.commit_notification_fanout_v3(
  uuid, uuid, jsonb, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor,
  periapsis_ticket_runtime_owner, periapsis_notification_inbox_owner;
GRANT EXECUTE ON FUNCTION app.commit_notification_fanout_v3(
  uuid, uuid, jsonb, timestamp with time zone
) TO periapsis_notifier;
--> statement-breakpoint

-- Alert relation reasons are byte-bounded at every layer. Replace the two
-- established guards without changing signatures, owners, grants, or bodies.
DO $alert_relation_reason_byte_guards$
DECLARE
  function_name regprocedure;
  predecessor_definition text;
  successor_definition text;
BEGIN
  FOREACH function_name IN ARRAY ARRAY[
    'app.commit_tenant_alert_relation_create_v1(uuid,uuid,text,integer,integer,text,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure,
    'app.commit_tenant_alert_relation_retract_v1(uuid,uuid,uuid,integer,integer,text,bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure
  ] LOOP
    SELECT pg_catalog.pg_get_functiondef(function_name)
    INTO predecessor_definition;
    IF pg_catalog.strpos(
      predecessor_definition, 'char_length(p_reason) > 2000'
    ) = 0 OR pg_catalog.strpos(
      predecessor_definition, 'octet_length(p_reason) > 2000'
    ) <> 0 THEN
      RAISE EXCEPTION 'Alert relation reason guard is not canonical'
        USING ERRCODE = '55000';
    END IF;
    successor_definition := pg_catalog.replace(
      predecessor_definition,
      'char_length(p_reason) > 2000',
      'octet_length(p_reason) > 2000'
    );
    IF successor_definition IS NOT DISTINCT FROM predecessor_definition
       OR pg_catalog.strpos(
         successor_definition, 'char_length(p_reason) > 2000'
       ) <> 0
       OR pg_catalog.strpos(
         successor_definition, 'octet_length(p_reason) > 2000'
       ) = 0 THEN
      RAISE EXCEPTION 'Alert relation byte guard derivation failed'
        USING ERRCODE = '55000';
    END IF;
    EXECUTE successor_definition;
  END LOOP;
END
$alert_relation_reason_byte_guards$;
