-- Versioned JSONB ABI for private operator saved ticket views. All entry
-- points re-authorize a live owner before touching identifiers or replay rows.

CREATE FUNCTION app.private_ticket_saved_view_record_v1(
  p_record public.ticket_saved_views
)
RETURNS jsonb
LANGUAGE sql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'id', p_record.id::text,
    'tenantId', p_record.tenant_id::text,
    'ownerMembershipId', p_record.owner_membership_id::text,
    'aggregateKind', p_record.aggregate_kind::text,
    'name', p_record.name,
    'specCanonicalBase64',
      app.private_ticket_saved_view_base64_v1(p_record.spec_canonical),
    'specSha256', encode(p_record.spec_digest, 'hex'),
    'status', p_record.status,
    'revision', p_record.revision,
    'createdAt', to_char(
      p_record.created_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    'updatedAt', to_char(
      p_record.updated_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    'archivedAt', CASE WHEN p_record.archived_at IS NULL THEN NULL ELSE to_char(
      p_record.archived_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ) END
  );
$function$;
ALTER FUNCTION app.private_ticket_saved_view_record_v1(
  public.ticket_saved_views
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_record_v1(
  public.ticket_saved_views
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_record_v1(
  public.ticket_saved_views
) TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.private_ticket_saved_view_command_record_v1(
  p_command public.ticket_saved_view_commands
)
RETURNS jsonb
LANGUAGE sql
STABLE
STRICT
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT jsonb_build_object(
    'id', p_command.result_view_id::text,
    'tenantId', p_command.tenant_id::text,
    'ownerMembershipId', p_command.owner_membership_id::text,
    'aggregateKind', p_command.aggregate_kind::text,
    'name', p_command.result_name,
    'specCanonicalBase64',
      app.private_ticket_saved_view_base64_v1(
        p_command.result_spec_canonical
      ),
    'specSha256', encode(p_command.result_spec_digest, 'hex'),
    'status', p_command.result_status,
    'revision', p_command.next_revision,
    'createdAt', to_char(
      p_command.result_created_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    'updatedAt', to_char(
      p_command.result_updated_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ),
    'archivedAt', CASE WHEN p_command.result_archived_at IS NULL THEN NULL ELSE to_char(
      p_command.result_archived_at AT TIME ZONE 'UTC',
      'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
    ) END
  );
$function$;
ALTER FUNCTION app.private_ticket_saved_view_command_record_v1(
  public.ticket_saved_view_commands
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.private_ticket_saved_view_command_record_v1(
  public.ticket_saved_view_commands
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.private_ticket_saved_view_command_record_v1(
  public.ticket_saved_view_commands
) TO periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE FUNCTION app.resolve_ticket_saved_view_spec_v1(p_request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE sql
VOLATILE
ROWS 1
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  SELECT app.private_resolve_ticket_saved_view_spec_v1(p_request);
$function$;
ALTER FUNCTION app.resolve_ticket_saved_view_spec_v1(jsonb)
  OWNER TO periapsis_ticket_saved_view_owner;
REVOKE ALL ON FUNCTION app.resolve_ticket_saved_view_spec_v1(jsonb)
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.resolve_ticket_saved_view_spec_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.list_ticket_saved_views_v1(p_request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
ROWS 1
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_membership_id uuid;
  aggregate_kind public.ticket_aggregate_kind;
  after_id uuid;
  limit_value integer;
  include_archived boolean;
  records jsonb;
  record_count integer;
BEGIN
  IF p_request IS NULL OR pg_column_size(p_request) > 4096
     OR NOT app.private_ticket_saved_view_exact_keys_v1(
       p_request,
       ARRAY[
         'schemaVersion', 'tenantId', 'actorId', 'ownerMembershipId',
         'aggregateKind', 'afterId', 'limit', 'includeArchived'
       ]
     )
     OR jsonb_typeof(p_request -> 'schemaVersion') <> 'number'
     OR p_request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(p_request -> 'tenantId') <> 'string'
     OR jsonb_typeof(p_request -> 'actorId') <> 'string'
     OR jsonb_typeof(p_request -> 'ownerMembershipId') <> 'string'
     OR jsonb_typeof(p_request -> 'aggregateKind') <> 'string'
     OR jsonb_typeof(p_request -> 'afterId') <> 'string'
     OR jsonb_typeof(p_request -> 'limit') <> 'number'
     OR p_request ->> 'limit' !~ '^[1-9][0-9]{0,2}$'
     OR jsonb_typeof(p_request -> 'includeArchived') <> 'boolean' THEN
    RAISE EXCEPTION 'saved-view list request is invalid'
      USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'tenantId', false
  );
  actor_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'actorId', false
  );
  owner_membership_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'ownerMembershipId', false
  );
  after_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'afterId', true
  );
  BEGIN
    aggregate_kind := (p_request ->> 'aggregateKind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'saved-view list kind is invalid'
      USING ERRCODE = '22023';
  END;
  limit_value := (p_request ->> 'limit')::integer;
  include_archived := (p_request ->> 'includeArchived')::boolean;
  IF limit_value NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'saved-view list limit is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_ticket_saved_view_assert_authority_v1(
    tenant_id, actor_id, owner_membership_id, aggregate_kind, false
  );
  WITH selected AS MATERIALIZED (
    SELECT view_record
    FROM public.ticket_saved_views AS view_record
    WHERE view_record.tenant_id = tenant_id
      AND view_record.owner_membership_id = owner_membership_id
      AND view_record.aggregate_kind = aggregate_kind
      AND (include_archived OR view_record.status = 'active')
      AND (after_id IS NULL OR view_record.id > after_id)
    ORDER BY view_record.id
    LIMIT limit_value + 1
  ), projected AS (
    SELECT (view_record).id AS id,
           app.private_ticket_saved_view_record_v1(view_record) AS record
    FROM selected
    ORDER BY (view_record).id
    LIMIT limit_value
  )
  SELECT coalesce(jsonb_agg(projected.record ORDER BY projected.id), '[]'::jsonb),
         (SELECT count(*)::integer FROM selected)
  INTO records, record_count
  FROM projected;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'records', records,
    'hasMore', record_count > limit_value
  );
END;
$function$;
ALTER FUNCTION app.list_ticket_saved_views_v1(jsonb)
  OWNER TO periapsis_ticket_saved_view_owner;
REVOKE ALL ON FUNCTION app.list_ticket_saved_views_v1(jsonb)
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.list_ticket_saved_views_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.get_ticket_saved_view_v1(p_request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
ROWS 1
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_membership_id uuid;
  aggregate_kind public.ticket_aggregate_kind;
  view_id uuid;
  found_view public.ticket_saved_views%ROWTYPE;
BEGIN
  IF p_request IS NULL OR pg_column_size(p_request) > 2048
     OR NOT app.private_ticket_saved_view_exact_keys_v1(
       p_request,
       ARRAY[
         'schemaVersion', 'tenantId', 'actorId', 'ownerMembershipId',
         'aggregateKind', 'viewId'
       ]
     )
     OR jsonb_typeof(p_request -> 'schemaVersion') <> 'number'
     OR p_request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(p_request -> 'tenantId') <> 'string'
     OR jsonb_typeof(p_request -> 'actorId') <> 'string'
     OR jsonb_typeof(p_request -> 'ownerMembershipId') <> 'string'
     OR jsonb_typeof(p_request -> 'aggregateKind') <> 'string'
     OR jsonb_typeof(p_request -> 'viewId') <> 'string' THEN
    RAISE EXCEPTION 'saved-view get request is invalid'
      USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'tenantId', false
  );
  actor_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'actorId', false
  );
  owner_membership_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'ownerMembershipId', false
  );
  view_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'viewId', false
  );
  BEGIN
    aggregate_kind := (p_request ->> 'aggregateKind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'saved-view get kind is invalid'
      USING ERRCODE = '22023';
  END;
  PERFORM app.private_ticket_saved_view_assert_authority_v1(
    tenant_id, actor_id, owner_membership_id, aggregate_kind, false
  );
  SELECT view_record.* INTO found_view
  FROM public.ticket_saved_views AS view_record
  WHERE view_record.tenant_id = tenant_id
    AND view_record.owner_membership_id = owner_membership_id
    AND view_record.aggregate_kind = aggregate_kind
    AND view_record.id = view_id;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'record', app.private_ticket_saved_view_record_v1(found_view)
  );
END;
$function$;
ALTER FUNCTION app.get_ticket_saved_view_v1(jsonb)
  OWNER TO periapsis_ticket_saved_view_owner;
REVOKE ALL ON FUNCTION app.get_ticket_saved_view_v1(jsonb)
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.get_ticket_saved_view_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.lookup_ticket_saved_view_replay_v1(p_request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
ROWS 1
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_membership_id uuid;
  aggregate_kind public.ticket_aggregate_kind;
  action_value text;
  key_digest bytea;
  command_record public.ticket_saved_view_commands%ROWTYPE;
BEGIN
  IF p_request IS NULL OR pg_column_size(p_request) > 4096
     OR NOT app.private_ticket_saved_view_exact_keys_v1(
       p_request,
       ARRAY[
         'schemaVersion', 'tenantId', 'actorId', 'ownerMembershipId',
         'aggregateKind', 'action', 'idempotencyKeySha256'
       ]
     )
     OR jsonb_typeof(p_request -> 'schemaVersion') <> 'number'
     OR p_request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(p_request -> 'tenantId') <> 'string'
     OR jsonb_typeof(p_request -> 'actorId') <> 'string'
     OR jsonb_typeof(p_request -> 'ownerMembershipId') <> 'string'
     OR jsonb_typeof(p_request -> 'aggregateKind') <> 'string'
     OR jsonb_typeof(p_request -> 'action') <> 'string'
     OR p_request ->> 'action' NOT IN ('create', 'replace', 'archive', 'restore')
     OR jsonb_typeof(p_request -> 'idempotencyKeySha256') <> 'string'
     OR p_request ->> 'idempotencyKeySha256' !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'saved-view replay request is invalid'
      USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'tenantId', false
  );
  actor_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'actorId', false
  );
  owner_membership_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'ownerMembershipId', false
  );
  BEGIN
    aggregate_kind := (p_request ->> 'aggregateKind')::public.ticket_aggregate_kind;
    key_digest := decode(p_request ->> 'idempotencyKeySha256', 'hex');
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'saved-view replay value is invalid'
      USING ERRCODE = '22023';
  END;
  action_value := p_request ->> 'action';
  PERFORM app.private_ticket_saved_view_assert_authority_v1(
    tenant_id, actor_id, owner_membership_id, aggregate_kind, false
  );
  SELECT command_row.* INTO command_record
  FROM public.ticket_saved_view_commands AS command_row
  WHERE command_row.tenant_id = tenant_id
    AND command_row.actor_user_id = actor_id
    AND command_row.owner_membership_id = owner_membership_id
    AND command_row.aggregate_kind = aggregate_kind
    AND command_row.action = action_value
    AND command_row.idempotency_key_digest = key_digest
    AND command_row.expires_at > clock_timestamp();
  IF NOT FOUND THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'actorId', actor_id::text,
    'ownerMembershipId', owner_membership_id::text,
    'action', action_value,
    'requestFingerprintSha256',
      encode(command_record.request_fingerprint_digest, 'hex'),
    'record',
      app.private_ticket_saved_view_command_record_v1(command_record)
  );
END;
$function$;
ALTER FUNCTION app.lookup_ticket_saved_view_replay_v1(jsonb)
  OWNER TO periapsis_ticket_saved_view_owner;
REVOKE ALL ON FUNCTION app.lookup_ticket_saved_view_replay_v1(jsonb)
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.lookup_ticket_saved_view_replay_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

CREATE FUNCTION app.commit_ticket_saved_view_v1(p_request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
ROWS 1
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_membership_id uuid;
  aggregate_kind public.ticket_aggregate_kind;
  action_value text;
  view_id uuid;
  expected_revision integer;
  next_revision integer;
  name_value text;
  status_value text;
  spec_canonical text;
  spec_digest bytea;
  key_digest bytea;
  fingerprint_digest bytea;
  command_id uuid;
  audit_event_id uuid;
  outbox_event_id uuid;
  request_id uuid;
  correlation_id uuid;
  remote_address inet;
  user_agent text;
  authentication_method text;
  audit_document jsonb;
  changed_at timestamp with time zone;
  command_record public.ticket_saved_view_commands%ROWTYPE;
  current_view public.ticket_saved_views%ROWTYPE;
  result_view public.ticket_saved_views%ROWTYPE;
BEGIN
  IF p_request IS NULL OR pg_column_size(p_request) > 524288
     OR NOT app.private_ticket_saved_view_exact_keys_v1(
       p_request,
       ARRAY[
         'schemaVersion', 'tenantId', 'actorId', 'ownerMembershipId',
         'aggregateKind', 'requiredCapability', 'action', 'viewId',
         'expectedRevision', 'nextRevision', 'name', 'status',
         'specCanonicalBase64', 'specSha256', 'idempotencyKeySha256',
         'requestFingerprintSha256', 'commandId', 'auditEventId',
         'outboxEventId', 'audit'
       ]
     )
     OR jsonb_typeof(p_request -> 'schemaVersion') <> 'number'
     OR p_request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(p_request -> 'tenantId') <> 'string'
     OR jsonb_typeof(p_request -> 'actorId') <> 'string'
     OR jsonb_typeof(p_request -> 'ownerMembershipId') <> 'string'
     OR jsonb_typeof(p_request -> 'aggregateKind') <> 'string'
     OR jsonb_typeof(p_request -> 'requiredCapability') <> 'string'
     OR p_request ->> 'requiredCapability' <> 'saved_view.manage'
     OR jsonb_typeof(p_request -> 'action') <> 'string'
     OR p_request ->> 'action' NOT IN ('create', 'replace', 'archive', 'restore')
     OR jsonb_typeof(p_request -> 'viewId') <> 'string'
     OR jsonb_typeof(p_request -> 'expectedRevision') <> 'number'
     OR p_request ->> 'expectedRevision' !~ '^(0|[1-9][0-9]{0,9})$'
     OR jsonb_typeof(p_request -> 'nextRevision') <> 'number'
     OR p_request ->> 'nextRevision' !~ '^[1-9][0-9]{0,9}$'
     OR jsonb_typeof(p_request -> 'name') <> 'string'
     OR jsonb_typeof(p_request -> 'status') <> 'string'
     OR p_request ->> 'status' NOT IN ('active', 'archived')
     OR jsonb_typeof(p_request -> 'specCanonicalBase64') <> 'string'
     OR jsonb_typeof(p_request -> 'specSha256') <> 'string'
     OR p_request ->> 'specSha256' !~ '^[0-9a-f]{64}$'
     OR jsonb_typeof(p_request -> 'idempotencyKeySha256') <> 'string'
     OR p_request ->> 'idempotencyKeySha256' !~ '^[0-9a-f]{64}$'
     OR jsonb_typeof(p_request -> 'requestFingerprintSha256') <> 'string'
     OR p_request ->> 'requestFingerprintSha256' !~ '^[0-9a-f]{64}$'
     OR jsonb_typeof(p_request -> 'commandId') <> 'string'
     OR jsonb_typeof(p_request -> 'auditEventId') <> 'string'
     OR jsonb_typeof(p_request -> 'outboxEventId') <> 'string'
     OR jsonb_typeof(p_request -> 'audit') <> 'object' THEN
    RAISE EXCEPTION 'saved-view commit request is invalid'
      USING ERRCODE = '22023';
  END IF;
  audit_document := p_request -> 'audit';
  IF NOT app.private_ticket_saved_view_exact_keys_v1(
       audit_document,
       ARRAY[
         'requestId', 'correlationId', 'remoteAddress', 'userAgent',
         'authenticationMethod'
       ]
     )
     OR jsonb_typeof(audit_document -> 'requestId') <> 'string'
     OR jsonb_typeof(audit_document -> 'correlationId') <> 'string'
     OR jsonb_typeof(audit_document -> 'remoteAddress') <> 'string'
     OR jsonb_typeof(audit_document -> 'userAgent') <> 'string'
     OR jsonb_typeof(audit_document -> 'authenticationMethod') <> 'string' THEN
    RAISE EXCEPTION 'saved-view commit audit envelope is invalid'
      USING ERRCODE = '22023';
  END IF;

  tenant_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'tenantId', false
  );
  actor_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'actorId', false
  );
  owner_membership_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'ownerMembershipId', false
  );
  view_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'viewId', false
  );
  command_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'commandId', false
  );
  audit_event_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'auditEventId', false
  );
  outbox_event_id := app.private_ticket_saved_view_uuid_v1(
    p_request ->> 'outboxEventId', false
  );
  BEGIN
    aggregate_kind := (p_request ->> 'aggregateKind')::public.ticket_aggregate_kind;
    spec_digest := decode(p_request ->> 'specSha256', 'hex');
    key_digest := decode(p_request ->> 'idempotencyKeySha256', 'hex');
    fingerprint_digest := decode(
      p_request ->> 'requestFingerprintSha256', 'hex'
    );
    request_id := (audit_document ->> 'requestId')::uuid;
    correlation_id := (audit_document ->> 'correlationId')::uuid;
    remote_address := (audit_document ->> 'remoteAddress')::inet;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'saved-view commit value is invalid'
      USING ERRCODE = '22023';
  END;
  IF request_id::text IS DISTINCT FROM audit_document ->> 'requestId'
     OR correlation_id::text IS DISTINCT FROM audit_document ->> 'correlationId'
     OR (uuid_extract_version(request_id) = 7) IS NOT TRUE
     OR (uuid_extract_version(correlation_id) = 7) IS NOT TRUE
     OR command_id IN (audit_event_id, outbox_event_id)
     OR audit_event_id = outbox_event_id
     OR key_digest = decode(repeat('00', 32), 'hex')
     OR fingerprint_digest = decode(repeat('00', 32), 'hex') THEN
    RAISE EXCEPTION 'saved-view commit identifiers are invalid'
      USING ERRCODE = '22023';
  END IF;
  expected_revision := (p_request ->> 'expectedRevision')::integer;
  next_revision := (p_request ->> 'nextRevision')::integer;
  action_value := p_request ->> 'action';
  name_value := p_request ->> 'name';
  status_value := p_request ->> 'status';
  user_agent := audit_document ->> 'userAgent';
  authentication_method := audit_document ->> 'authenticationMethod';
  spec_canonical := app.private_ticket_saved_view_decode_base64_v1(
    p_request ->> 'specCanonicalBase64'
  );
  IF next_revision NOT BETWEEN 1 AND 2147483647
     OR expected_revision NOT BETWEEN 0 AND 2147483646
     OR next_revision <> expected_revision + 1
     OR (action_value = 'create') IS DISTINCT FROM (expected_revision = 0)
     OR (action_value = 'archive') IS DISTINCT FROM (status_value = 'archived')
     OR btrim(name_value) = '' OR btrim(name_value) IS DISTINCT FROM name_value
     OR octet_length(name_value) > 120
     OR name_value ~ '[[:cntrl:]\u200e\u200f\u202a-\u202e\u2066-\u2069]'
     OR pg_catalog.sha256(convert_to(spec_canonical, 'UTF8'))
          IS DISTINCT FROM spec_digest
     OR user_agent = '' OR btrim(user_agent) IS DISTINCT FROM user_agent
     OR octet_length(user_agent) > 512
     OR user_agent ~ '[[:cntrl:]\u200e\u200f\u202a-\u202e\u2066-\u2069]'
     OR authentication_method NOT IN (
       'bootstrap_totp', 'totp', 'recovery_code', 'ldap',
       'oidc', 'saml', 'passkey'
     ) THEN
    RAISE EXCEPTION 'saved-view commit document is invalid'
      USING ERRCODE = '22023';
  END IF;

  -- Authorization is locked before replay or resource lookup. A revoked,
  -- inactive, cross-owner, or customer-linked caller learns no lineage state.
  PERFORM app.private_ticket_saved_view_assert_authority_v1(
    tenant_id, actor_id, owner_membership_id, aggregate_kind, true
  );
  PERFORM pg_advisory_xact_lock(hashtextextended(
    tenant_id::text || ':' || actor_id::text || ':' ||
    owner_membership_id::text || ':' || aggregate_kind::text || ':' ||
    action_value || ':' || encode(key_digest, 'hex'),
    0
  ));
  DELETE FROM public.ticket_saved_view_commands AS expired
  WHERE expired.tenant_id = tenant_id
    AND expired.actor_user_id = actor_id
    AND expired.owner_membership_id = owner_membership_id
    AND expired.aggregate_kind = aggregate_kind
    AND expired.action = action_value
    AND expired.idempotency_key_digest = key_digest
    AND expired.expires_at <= clock_timestamp();
  SELECT stored.* INTO command_record
  FROM public.ticket_saved_view_commands AS stored
  WHERE stored.tenant_id = tenant_id
    AND stored.actor_user_id = actor_id
    AND stored.owner_membership_id = owner_membership_id
    AND stored.aggregate_kind = aggregate_kind
    AND stored.action = action_value
    AND stored.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF command_record.request_fingerprint_digest
         IS DISTINCT FROM fingerprint_digest THEN
      RAISE EXCEPTION 'saved-view idempotency key was reused'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT jsonb_build_object(
      'schemaVersion', 1,
      'actorId', actor_id::text,
      'ownerMembershipId', owner_membership_id::text,
      'action', action_value,
      'requestFingerprintSha256', encode(fingerprint_digest, 'hex'),
      'replayed', true,
      'record',
        app.private_ticket_saved_view_command_record_v1(command_record)
    );
    RETURN;
  END IF;

  changed_at := clock_timestamp();
  IF action_value = 'create' THEN
    PERFORM app.private_ticket_saved_view_spec_pins_current_v1(
      tenant_id, actor_id, owner_membership_id,
      aggregate_kind, spec_canonical
    );
    INSERT INTO public.ticket_saved_views (
      id, tenant_id, owner_membership_id, aggregate_kind, name,
      spec_canonical, spec_digest, status, revision,
      created_at, updated_at, archived_at
    ) VALUES (
      view_id, tenant_id, owner_membership_id, aggregate_kind, name_value,
      spec_canonical, spec_digest, 'active', 1,
      changed_at, changed_at, NULL
    ) RETURNING * INTO result_view;
  ELSE
    SELECT stored.* INTO current_view
    FROM public.ticket_saved_views AS stored
    WHERE stored.tenant_id = tenant_id
      AND stored.owner_membership_id = owner_membership_id
      AND stored.aggregate_kind = aggregate_kind
      AND stored.id = view_id
    FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'saved view was not found' USING ERRCODE = 'P0002';
    END IF;
    IF current_view.revision <> expected_revision THEN
      RAISE EXCEPTION 'saved-view revision is stale' USING ERRCODE = '40001';
    END IF;
    IF action_value = 'replace' THEN
      IF current_view.status <> 'active'
         OR status_value <> 'active'
         OR (
           current_view.name IS NOT DISTINCT FROM name_value
           AND current_view.spec_canonical IS NOT DISTINCT FROM spec_canonical
           AND current_view.spec_digest IS NOT DISTINCT FROM spec_digest
         ) THEN
        RAISE EXCEPTION 'saved-view replace has no valid change'
          USING ERRCODE = '55000';
      END IF;
      PERFORM app.private_ticket_saved_view_spec_pins_current_v1(
        tenant_id, actor_id, owner_membership_id,
        aggregate_kind, spec_canonical
      );
      UPDATE public.ticket_saved_views AS target
      SET name = name_value,
          spec_canonical = spec_canonical,
          spec_digest = spec_digest,
          revision = next_revision,
          updated_at = changed_at
      WHERE target.tenant_id = tenant_id AND target.id = view_id
      RETURNING * INTO result_view;
    ELSIF action_value = 'archive' THEN
      IF current_view.status <> 'active'
         OR status_value <> 'archived'
         OR name_value IS DISTINCT FROM current_view.name
         OR spec_canonical IS DISTINCT FROM current_view.spec_canonical
         OR spec_digest IS DISTINCT FROM current_view.spec_digest THEN
        RAISE EXCEPTION 'saved-view archive snapshot is inconsistent'
          USING ERRCODE = '55000';
      END IF;
      UPDATE public.ticket_saved_views AS target
      SET status = 'archived', revision = next_revision,
          updated_at = changed_at, archived_at = changed_at
      WHERE target.tenant_id = tenant_id AND target.id = view_id
      RETURNING * INTO result_view;
    ELSE
      IF current_view.status <> 'archived'
         OR status_value <> 'active'
         OR name_value IS DISTINCT FROM current_view.name
         OR spec_canonical IS DISTINCT FROM current_view.spec_canonical
         OR spec_digest IS DISTINCT FROM current_view.spec_digest THEN
        RAISE EXCEPTION 'saved-view restore snapshot is inconsistent'
          USING ERRCODE = '55000';
      END IF;
      PERFORM app.private_ticket_saved_view_spec_pins_current_v1(
        tenant_id, actor_id, owner_membership_id,
        aggregate_kind, spec_canonical
      );
      UPDATE public.ticket_saved_views AS target
      SET status = 'active', revision = next_revision,
          updated_at = changed_at, archived_at = NULL
      WHERE target.tenant_id = tenant_id AND target.id = view_id
      RETURNING * INTO result_view;
    END IF;
  END IF;

  PERFORM app.private_append_ticket_saved_view_effects_v1(
    tenant_id, actor_id, owner_membership_id, aggregate_kind,
    action_value, result_view.id, result_view.revision,
    result_view.status, command_id, audit_event_id, outbox_event_id,
    request_id, correlation_id, remote_address, user_agent,
    authentication_method, changed_at
  );
  INSERT INTO public.ticket_saved_view_commands (
    id, tenant_id, actor_user_id, owner_membership_id, aggregate_kind,
    action, idempotency_key_digest, request_fingerprint_digest,
    expected_revision, next_revision, result_view_id, result_name,
    result_spec_canonical, result_spec_digest, result_status,
    result_created_at, result_updated_at, result_archived_at,
    created_at, expires_at
  ) VALUES (
    command_id, tenant_id, actor_id, owner_membership_id, aggregate_kind,
    action_value, key_digest, fingerprint_digest,
    expected_revision, next_revision, result_view.id, result_view.name,
    result_view.spec_canonical, result_view.spec_digest, result_view.status,
    result_view.created_at, result_view.updated_at, result_view.archived_at,
    changed_at, changed_at + interval '30 days'
  ) RETURNING * INTO command_record;
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'actorId', actor_id::text,
    'ownerMembershipId', owner_membership_id::text,
    'action', action_value,
    'requestFingerprintSha256', encode(fingerprint_digest, 'hex'),
    'replayed', false,
    'record', app.private_ticket_saved_view_record_v1(result_view)
  );
END;
$function$;
ALTER FUNCTION app.commit_ticket_saved_view_v1(jsonb)
  OWNER TO periapsis_ticket_saved_view_owner;
REVOKE ALL ON FUNCTION app.commit_ticket_saved_view_v1(jsonb)
FROM PUBLIC, periapsis_migrator, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner, periapsis_sla_api_owner,
  periapsis_sla_worker_owner, periapsis_sla_readiness_owner;
GRANT EXECUTE ON FUNCTION app.commit_ticket_saved_view_v1(jsonb)
TO periapsis_api;
--> statement-breakpoint

-- V29 is the exact Saved Views state. V28 exposes the sealed 0135 prefix to
-- the one supported rolling predecessor binary; V27 is retired.
CREATE FUNCTION app.schema_compatibility_v29()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  journal_count bigint;
  journal_latest_created_at bigint;
  latest_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787741355171
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, latest_rows;
  IF journal_count = 139
     AND journal_latest_created_at = 1787741355171
     AND latest_rows = 1 THEN
    RETURN QUERY EXECUTE $query$
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT lower(latest.hash::text)
              FROM drizzle.__drizzle_migrations AS latest
              ORDER BY latest.created_at DESC, latest.id DESC LIMIT 1),
             string_agg(
               migration.created_at::text || '@' || lower(migration.hash::text),
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM drizzle.__drizzle_migrations AS migration
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v29()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v29()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v29()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v28()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
SET app.schema_compatibility_fingerprint = 'UNSEALED'
AS $function$
DECLARE
  full_count bigint;
  full_latest_created_at bigint;
  full_fingerprint text;
BEGIN
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.migration_fingerprint
  INTO full_count, full_latest_created_at, full_fingerprint
  FROM app.schema_compatibility_v29() AS compatibility;
  IF full_count = 139
     AND full_latest_created_at = 1787741355171
     AND full_fingerprint = current_setting(
       'app.schema_compatibility_fingerprint', true
     ) THEN
    RETURN QUERY EXECUTE $query$
      WITH ordered_migrations AS (
        SELECT migration.id, migration.created_at,
               lower(migration.hash::text) AS migration_hash,
               row_number() OVER (
                 ORDER BY migration.created_at, migration.id
               ) AS migration_ordinal
        FROM drizzle.__drizzle_migrations AS migration
      )
      SELECT count(*)::bigint, max(migration.created_at)::bigint,
             (SELECT prefix.migration_hash
              FROM ordered_migrations AS prefix
              WHERE prefix.migration_ordinal = 136),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 136
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v28()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v28()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v28()
TO periapsis_api, periapsis_worker;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v27()
RETURNS TABLE(
  applied_count bigint,
  latest_created_at bigint,
  latest_hash text,
  migration_fingerprint text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;
ALTER FUNCTION app.schema_compatibility_v27()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.schema_compatibility_v27()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.seal_schema_compatibility_manifest(
  p_expected_count bigint,
  p_expected_latest_created_at bigint,
  p_expected_latest_hash text,
  p_expected_migration_fingerprint text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
  fingerprint_entries text[];
  appended_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 139
     OR p_expected_latest_created_at IS DISTINCT FROM 1787741355171
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 139
     OR fingerprint_entries[139] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v29 manifest'
      USING ERRCODE = '22023';
  END IF;
  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO appended_created_at
  FROM unnest(fingerprint_entries[137:139]) WITH ORDINALITY
       AS entry(value, ordinality);
  IF appended_created_at IS DISTINCT FROM ARRAY[
       1787741353171, 1787741354171, 1787741355171
     ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v29 appended sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v29() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v29 manifest does not match the journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v28()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:136], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v28() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 136
     OR predecessor_latest_created_at IS DISTINCT FROM 1787737707040
     OR predecessor_latest_hash IS DISTINCT FROM
          '3f4ccd0e67f21c3e3b72ab76b1cbe0c7265a9fa8d872af8c4a8f00047cd976aa'
     OR predecessor_fingerprint IS DISTINCT FROM
          expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v28 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v27() AS compatibility;
  IF retired_count IS DISTINCT FROM 0
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v29()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v29()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v28()'::regprocedure,
       'EXECUTE'
     )
     OR NOT has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v28()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_api', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     )
     OR has_function_privilege(
       'periapsis_worker', 'app.schema_compatibility_v27()'::regprocedure,
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'schema compatibility v27 remains active'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_audit_reader_owner,
  periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner;
--> statement-breakpoint

-- Rebind the established structural readiness surfaces without weakening any
-- of their domain-specific checks.
DO $migration$
DECLARE
  readiness_function regprocedure;
  original_definition text;
  rewritten_definition text;
BEGIN
  FOREACH readiness_function IN ARRAY ARRAY[
    'app.federated_authentication_schema_readiness_v1()'::regprocedure,
    'app.identity_mfa_device_management_readiness_v1()'::regprocedure,
    'app.identity_mfa_schema_readiness_v1()'::regprocedure,
    'app.private_sla_schema_readiness_core_v1()'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(readiness_function)
    INTO original_definition;
    IF original_definition NOT LIKE '%app.schema_compatibility_v28()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v27()%'
       OR original_definition NOT LIKE '%app.schema_compatibility_v26()%'
       OR original_definition NOT LIKE
            '%current_count = 136 AND predecessor_count = 135%' THEN
      RAISE EXCEPTION 'unexpected 0135 readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    rewritten_definition := replace(
      original_definition,
      'app.schema_compatibility_v28()',
      'app.schema_compatibility_v29()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v27()',
      'app.schema_compatibility_v28()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'app.schema_compatibility_v26()',
      'app.schema_compatibility_v27()'
    );
    rewritten_definition := replace(
      rewritten_definition,
      'current_count = 136 AND predecessor_count = 135',
      'current_count = 139 AND predecessor_count = 136'
    );
    IF rewritten_definition IS NOT DISTINCT FROM original_definition
       OR rewritten_definition NOT LIKE '%app.schema_compatibility_v29()%'
       OR rewritten_definition LIKE '%app.schema_compatibility_v26()%'
       OR rewritten_definition NOT LIKE
            '%current_count = 139 AND predecessor_count = 136%' THEN
      RAISE EXCEPTION 'failed to rebind readiness definition: %',
        readiness_function::text USING ERRCODE = '55000';
    END IF;
    EXECUTE rewritten_definition;
  END LOOP;
END;
$migration$;
--> statement-breakpoint

CREATE FUNCTION app.ticket_saved_views_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  saved_owner oid := to_regrole('periapsis_ticket_saved_view_owner');
  role_record record;
  relation_record record;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_volatility "char";
  function_rows real;
  function_configuration text[];
  function_result text;
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
BEGIN
  IF saved_owner IS NULL THEN
    RETURN false;
  END IF;
  IF NOT has_function_privilege(
       'periapsis_ticket_saved_view_owner',
       'app.context_tenant_id()', 'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_ticket_saved_view_owner',
       'app.context_user_id()', 'EXECUTE'
     ) OR NOT has_function_privilege(
       'periapsis_ticket_saved_view_owner',
       'app.current_tenant_membership_id()', 'EXECUTE'
     ) THEN
    RETURN false;
  END IF;
  SELECT role_record_source.rolsuper, role_record_source.rolinherit,
         role_record_source.rolcreaterole, role_record_source.rolcreatedb,
         role_record_source.rolcanlogin, role_record_source.rolreplication,
         role_record_source.rolbypassrls,
         role_record_source.rolconfig
  INTO role_record
  FROM pg_roles AS role_record_source
  WHERE role_record_source.oid = saved_owner;
  IF role_record.rolsuper OR role_record.rolinherit
     OR role_record.rolcreaterole OR role_record.rolcreatedb
     OR role_record.rolcanlogin OR role_record.rolreplication
     OR role_record.rolbypassrls
     OR NOT ('search_path=pg_catalog, public, app' = ANY(role_record.rolconfig)) THEN
    RETURN false;
  END IF;

  FOR relation_record IN
    SELECT class_record.oid, class_record.relname,
           pg_get_userbyid(class_record.relowner) AS owner_name,
           class_record.relrowsecurity, class_record.relforcerowsecurity
    FROM pg_class AS class_record
    WHERE class_record.oid IN (
      'public.ticket_saved_views'::regclass,
      'public.ticket_saved_view_commands'::regclass
    )
  LOOP
    IF relation_record.owner_name IS DISTINCT FROM
         'periapsis_ticket_saved_view_owner'
       OR NOT relation_record.relrowsecurity
       OR NOT relation_record.relforcerowsecurity
       OR has_table_privilege(
         'periapsis_api', relation_record.oid, 'SELECT,INSERT,UPDATE,DELETE'
       )
       OR has_table_privilege(
         'periapsis_worker', relation_record.oid, 'SELECT,INSERT,UPDATE,DELETE'
       )
       OR has_table_privilege(
         'periapsis_notifier', relation_record.oid, 'SELECT,INSERT,UPDATE,DELETE'
       )
       OR has_table_privilege(
         'periapsis_auditor', relation_record.oid, 'SELECT,INSERT,UPDATE,DELETE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;
  IF (
       SELECT count(*)
       FROM pg_policy AS policy_record
       WHERE policy_record.polrelid IN (
         'public.ticket_saved_views'::regclass,
         'public.ticket_saved_view_commands'::regclass
       )
         AND policy_record.polcmd = '*'
         AND policy_record.polroles = ARRAY[saved_owner]::oid[]
         AND pg_get_expr(
           policy_record.polqual, policy_record.polrelid
         ) = 'true'
         AND pg_get_expr(
           policy_record.polwithcheck, policy_record.polrelid
         ) = 'true'
     ) <> 2 OR (
       SELECT count(*)
       FROM pg_policy AS policy_record
       WHERE policy_record.polrelid IN (
         'public.ticket_saved_views'::regclass,
         'public.ticket_saved_view_commands'::regclass
       )
     ) <> 2 THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.resolve_ticket_saved_view_spec_v1(jsonb)'),
      ('app.list_ticket_saved_views_v1(jsonb)'),
      ('app.get_ticket_saved_view_v1(jsonb)'),
      ('app.lookup_ticket_saved_view_replay_v1(jsonb)'),
      ('app.commit_ticket_saved_view_v1(jsonb)')
    ) AS expected(signature)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.provolatile, procedure.prorows, procedure.proconfig,
           pg_get_function_result(procedure.oid)
    INTO function_owner, function_security_definer, function_volatility,
         function_rows, function_configuration, function_result
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_ticket_saved_view_owner'
       OR NOT function_security_definer
       OR function_volatility <> 'v'
       OR function_rows <> 1
       OR function_configuration[1] IS DISTINCT FROM
            'search_path=pg_catalog, public, app'
       OR function_result IS DISTINCT FROM 'TABLE(response jsonb)'
       OR NOT has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_worker', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_notifier', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_auditor', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_migrator', function_oid, 'EXECUTE'
       )
       OR EXISTS (
         SELECT 1
         FROM aclexplode(
           coalesce(
             (SELECT procedure.proacl FROM pg_proc AS procedure
              WHERE procedure.oid = function_oid),
             acldefault('f', saved_owner)
           )
         ) AS privilege
         WHERE privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_ticket_saved_view_assert_authority_v1(uuid,uuid,uuid,public.ticket_aggregate_kind,boolean)'),
      ('app.private_resolve_ticket_saved_view_spec_v1(jsonb)'),
      ('app.private_ticket_saved_view_spec_pins_current_v1(uuid,uuid,uuid,public.ticket_aggregate_kind,text)'),
      ('app.private_append_ticket_saved_view_effects_v1(uuid,uuid,uuid,public.ticket_aggregate_kind,text,uuid,integer,text,uuid,uuid,uuid,uuid,uuid,inet,text,text,timestamp with time zone)'),
      ('app.private_ticket_saved_view_record_v1(public.ticket_saved_views)'),
      ('app.private_ticket_saved_view_command_record_v1(public.ticket_saved_view_commands)')
    ) AS expected(signature)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR NOT function_security_definer
       OR function_configuration[1] IS DISTINCT FROM
            'search_path=pg_catalog, public, app'
       OR NOT has_function_privilege(
         'periapsis_ticket_saved_view_owner', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_worker', function_oid, 'EXECUTE'
       )
       OR EXISTS (
         SELECT 1
         FROM aclexplode(
           coalesce(
             (SELECT procedure.proacl FROM pg_proc AS procedure
              WHERE procedure.oid = function_oid),
             acldefault('f',
               (SELECT procedure.proowner FROM pg_proc AS procedure
                WHERE procedure.oid = function_oid))
           )
         ) AS privilege
         WHERE privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_ticket_saved_view_exact_keys_v1(jsonb,text[])'),
      ('app.private_ticket_saved_view_uuid_v1(text,boolean)'),
      ('app.private_ticket_saved_view_base64_v1(text)'),
      ('app.private_ticket_saved_view_decode_base64_v1(text)')
    ) AS expected(signature)
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_security_definer
       OR function_configuration[1] IS DISTINCT FROM
            'search_path=pg_catalog'
       OR NOT has_function_privilege(
         'periapsis_ticket_saved_view_owner', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       )
       OR has_function_privilege(
         'periapsis_worker', function_oid, 'EXECUTE'
       )
       OR EXISTS (
         SELECT 1
         FROM aclexplode(
           coalesce(
             (SELECT procedure.proacl FROM pg_proc AS procedure
              WHERE procedure.oid = function_oid),
             acldefault('f',
               (SELECT procedure.proowner FROM pg_proc AS procedure
                WHERE procedure.oid = function_oid))
           )
         ) AS privilege
         WHERE privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF NOT EXISTS (
       SELECT 1 FROM pg_trigger AS trigger_record
       WHERE trigger_record.tgrelid = 'public.ticket_saved_views'::regclass
         AND trigger_record.tgname = 'ticket_saved_views_guard_v1'
         AND NOT trigger_record.tgisinternal
         AND trigger_record.tgenabled = 'O'
     ) OR NOT EXISTS (
       SELECT 1 FROM pg_trigger AS trigger_record
       WHERE trigger_record.tgrelid =
               'public.ticket_saved_view_commands'::regclass
         AND trigger_record.tgname = 'ticket_saved_view_commands_guard_v1'
         AND NOT trigger_record.tgisinternal
         AND trigger_record.tgenabled = 'O'
     ) OR (
       SELECT count(*) FROM pg_constraint AS constraint_record
       WHERE constraint_record.conname IN (
         'ticket_saved_views_owner_fk',
         'ticket_saved_view_commands_actor_owner_fk',
         'ticket_saved_view_commands_result_fk',
         'ticket_saved_view_commands_replay_key'
       )
     ) <> 4 THEN
    RETURN false;
  END IF;
  IF to_regclass('public.ticket_saved_views_owner_list_idx') IS NULL
     OR to_regclass('public.ticket_saved_view_commands_replay_key') IS NULL
     OR to_regclass('public.ticket_saved_view_commands_expiry_idx') IS NULL
     OR to_regclass('public.custom_field_values_saved_sort_boolean_idx') IS NULL
     OR to_regclass('public.custom_field_values_saved_sort_date_idx') IS NULL
     OR to_regclass('public.custom_field_values_saved_sort_ip_idx') IS NULL
     OR to_regclass('public.custom_field_values_saved_sort_cidr_idx') IS NULL
     OR to_regclass('public.custom_field_values_saved_sort_reference_idx') IS NULL
     OR to_regclass(
       'public.custom_field_values_saved_sort_single_select_idx'
     ) IS NULL
     OR pg_get_indexdef(to_regclass(
       'public.custom_field_values_saved_sort_single_select_idx'
     )) NOT LIKE '%(option_keys[1])%' THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v29() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v28() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v27() AS compatibility;
  RETURN current_count = 139 AND predecessor_count = 136
    AND retired_count = 0;
END;
$function$;
ALTER FUNCTION app.ticket_saved_views_schema_readiness_v1()
  OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.ticket_saved_views_schema_readiness_v1()
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor,
  periapsis_audit_reader_owner, periapsis_notification_dispatch_owner,
  periapsis_sla_api_owner, periapsis_sla_worker_owner,
  periapsis_sla_readiness_owner, periapsis_ticket_saved_view_owner;
GRANT EXECUTE ON FUNCTION app.ticket_saved_views_schema_readiness_v1()
TO periapsis_api;
--> statement-breakpoint
