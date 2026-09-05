ALTER TABLE "tenant_authorization_commands" DROP CONSTRAINT "tenant_authorization_commands_operation_check";--> statement-breakpoint
ALTER TABLE "dfir_attachments" DROP CONSTRAINT "dfir_attachments_state_check";--> statement-breakpoint
ALTER TABLE "dfir_evidence" DROP CONSTRAINT "dfir_evidence_content_check";--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" DROP CONSTRAINT "dfir_storage_objects_content_shape_check";--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD COLUMN "expected_size_bytes" bigint;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD COLUMN "upload_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD COLUMN "cleanup_fence" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD COLUMN "cleanup_claimed_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD COLUMN "cleanup_lease_expires_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD COLUMN "cleanup_attempt_count" bigint DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD COLUMN "cleanup_last_failure_code" text;--> statement-breakpoint
-- Rows prepared before exact-size signing cannot acquire an authoritative
-- expected size after the fact. Preserve verified projections exactly; mark
-- unverified legacy uploads with the fail-closed sentinel 0 and keep their
-- cleanup horizon beyond the maximum historical one-hour presign lifetime.
UPDATE "dfir_storage_objects"
SET "expected_size_bytes" = coalesce("size_bytes", 0),
    "upload_expires_at" = "created_at" + interval '1 hour';--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ALTER COLUMN "expected_size_bytes" SET NOT NULL;--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ALTER COLUMN "upload_expires_at" SET NOT NULL;--> statement-breakpoint
CREATE INDEX "dfir_storage_objects_cleanup_queue_idx" ON "dfir_storage_objects" USING btree ("tenant_id","upload_expires_at","cleanup_lease_expires_at","id") WHERE "dfir_storage_objects"."state" = 'pending_upload';--> statement-breakpoint
ALTER TABLE "tenant_authorization_commands" ADD CONSTRAINT "tenant_authorization_commands_operation_check" CHECK ("tenant_authorization_commands"."operation" in (
        'tenant_role.create',
        'tenant_role_grant.create',
        'tenant_security_group.create',
        'tenant_security_group_membership.create',
        'tenant_security_group_role_grant.create',
        'operator_team_assignment.create',
        'operator_team_roster_entry.create',
        'identity_provider.create',
        'identity_provider_binding.create',
        'identity_mapping.create',
        'identity_sync.run',
        'dfir.attachment.prepare'
      ));--> statement-breakpoint
ALTER TABLE "dfir_attachments" ADD CONSTRAINT "dfir_attachments_state_check" CHECK ("dfir_attachments"."version" > 0 and ("dfir_attachments"."scan_state" <> 'deleted' or "dfir_attachments"."visibility" = 'private'));--> statement-breakpoint
ALTER TABLE "dfir_evidence" ADD CONSTRAINT "dfir_evidence_content_check" CHECK (octet_length("dfir_evidence"."content_sha256") = 32 and "dfir_evidence"."size_bytes" between 1 and 5000000000 and octet_length("dfir_evidence"."detected_mime") between 3 and 512);--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD CONSTRAINT "dfir_storage_objects_upload_expiry_check" CHECK ("dfir_storage_objects"."upload_expires_at" > "dfir_storage_objects"."created_at"
        and "dfir_storage_objects"."upload_expires_at" <= "dfir_storage_objects"."created_at" + interval '1 hour');--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD CONSTRAINT "dfir_storage_objects_cleanup_check" CHECK ("dfir_storage_objects"."cleanup_fence" between 0 and 9223372036854775806
        and "dfir_storage_objects"."cleanup_attempt_count" = "dfir_storage_objects"."cleanup_fence"
        and ("dfir_storage_objects"."cleanup_last_failure_code" is null or "dfir_storage_objects"."cleanup_last_failure_code" ~ '^[a-z][a-z0-9_.-]{0,63}$')
        and (("dfir_storage_objects"."cleanup_claimed_at" is null and "dfir_storage_objects"."cleanup_lease_expires_at" is null)
          or ("dfir_storage_objects"."state" = 'pending_upload' and "dfir_storage_objects"."cleanup_claimed_at" >= "dfir_storage_objects"."created_at"
            and "dfir_storage_objects"."cleanup_lease_expires_at" > "dfir_storage_objects"."cleanup_claimed_at"
            and "dfir_storage_objects"."cleanup_lease_expires_at" <= "dfir_storage_objects"."cleanup_claimed_at" + interval '15 minutes'))
        and ("dfir_storage_objects"."state" <> 'deleted' or ("dfir_storage_objects"."cleanup_claimed_at" is null and "dfir_storage_objects"."cleanup_lease_expires_at" is null)));--> statement-breakpoint
ALTER TABLE "dfir_storage_objects" ADD CONSTRAINT "dfir_storage_objects_content_shape_check" CHECK ((("dfir_storage_objects"."expected_size_bytes" = 0 and "dfir_storage_objects"."state" in ('pending_upload','rejected','deleted')
          and "dfir_storage_objects"."content_sha256" is null and "dfir_storage_objects"."size_bytes" is null
          and "dfir_storage_objects"."detected_mime" is null and "dfir_storage_objects"."verified_at" is null)
        or ("dfir_storage_objects"."expected_size_bytes" between 1 and 5000000000
          and (("dfir_storage_objects"."content_sha256" is null and "dfir_storage_objects"."size_bytes" is null and "dfir_storage_objects"."detected_mime" is null and "dfir_storage_objects"."verified_at" is null)
            or (octet_length("dfir_storage_objects"."content_sha256") = 32 and "dfir_storage_objects"."size_bytes" = "dfir_storage_objects"."expected_size_bytes"
              and octet_length("dfir_storage_objects"."detected_mime") between 3 and 512 and "dfir_storage_objects"."verified_at" is not null)))));
--> statement-breakpoint

-- Keep the trigger-enforced command result allowlist in lockstep with the
-- table constraint. Prepare is deliberately reserved before its storage row
-- exists, so its result is limited to a UUIDv7/version-1 proposal and the
-- enclosing application transaction must persist the resource or roll back.
CREATE OR REPLACE FUNCTION app.guard_tenant_authorization_command()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'tenant authorization command rows are append-only'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN
    IF OLD.expires_at > transaction_timestamp() THEN
      RAISE EXCEPTION 'unexpired tenant authorization commands cannot be pruned'
        USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF NEW.operation = 'tenant_role.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_roles r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant role idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_role_grant.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_membership_role_grants r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant role grant idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_security_groups r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant security group idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_membership.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_security_group_memberships r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant security group membership idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'tenant_security_group_role_grant.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_security_group_role_grants r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'tenant security group role grant idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_assignment.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.operator_team_assignment_epochs r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'operator-team assignment idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'operator_team_roster_entry.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.operator_team_roster_entries r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'operator-team roster idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_provider.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_auth_providers r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'identity-provider idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_provider_binding.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_auth_provider_bindings r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'identity-provider binding idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_mapping.create' THEN
    IF NOT EXISTS (SELECT 1 FROM public.tenant_ldap_mapping_rules r WHERE r.tenant_id = NEW.tenant_id AND r.id = NEW.result_resource_id AND r.version = NEW.result_version) THEN
      RAISE EXCEPTION 'identity-mapping idempotency result is invalid' USING ERRCODE = '23503', CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'identity_sync.run' THEN
    IF NOT EXISTS (
      SELECT 1 FROM public.tenant_ldap_sync_runs r
      WHERE r.tenant_id = NEW.tenant_id
        AND r.id = NEW.result_resource_id
        AND r.version = NEW.result_version
        AND r.trigger = 'manual'
        AND r.started_by_membership_id = NEW.actor_membership_id
    ) THEN
      RAISE EXCEPTION 'identity-sync idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSIF NEW.operation = 'dfir.attachment.prepare' THEN
    IF NEW.result_version IS DISTINCT FROM 1
       OR (uuid_extract_version(NEW.result_resource_id) = 7) IS NOT TRUE THEN
      RAISE EXCEPTION 'DFIR attachment prepare idempotency result is invalid'
        USING ERRCODE = '23503',
              CONSTRAINT = 'tenant_authorization_commands_result_fk';
    END IF;
  ELSE
    RAISE EXCEPTION 'unsupported tenant authorization command operation'
      USING ERRCODE = '22023';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_tenant_authorization_command()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_tenant_authorization_command()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_ldap_administration_owner;--> statement-breakpoint

-- Exact-size and upload-expiry identity are immutable. Cleanup bookkeeping is
-- mutable only through the worker-only SECURITY DEFINER functions below; the
-- runtime roles retain no direct UPDATE privilege on storage rows.
CREATE OR REPLACE FUNCTION app.guard_dfir_storage_identity_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF TG_OP = 'DELETE'
     OR NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.bucket IS DISTINCT FROM OLD.bucket
     OR NEW.object_key IS DISTINCT FROM OLD.object_key
     OR NEW.original_filename IS DISTINCT FROM OLD.original_filename
     OR NEW.classification IS DISTINCT FROM OLD.classification
     OR NEW.expected_size_bytes IS DISTINCT FROM OLD.expected_size_bytes
     OR NEW.upload_expires_at IS DISTINCT FROM OLD.upload_expires_at
     OR NEW.created_by_membership_id IS DISTINCT FROM OLD.created_by_membership_id
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR (OLD.content_sha256 IS NOT NULL AND (
       NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
       OR NEW.size_bytes IS DISTINCT FROM OLD.size_bytes
       OR NEW.detected_mime IS DISTINCT FROM OLD.detected_mime
       OR NEW.verified_at IS DISTINCT FROM OLD.verified_at
     )) THEN
    RAISE EXCEPTION 'DFIR storage identity and verified content are immutable'
      USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_dfir_storage_identity_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_dfir_storage_identity_v1()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

-- Reserve the human prepare command before any storage/attachment/effect row
-- is inserted. The request and key digests are computed over the canonical
-- application payload; the unique replay key serializes concurrent retries.
CREATE FUNCTION app.reserve_dfir_attachment_prepare_v1(
  p_command_id uuid,
  p_storage_object_id uuid,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE(
  result_resource_id uuid,
  result_version integer,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  inserted_rows bigint;
  command_record public.tenant_authorization_commands%ROWTYPE;
BEGIN
  IF p_command_id IS NULL
     OR (uuid_extract_version(p_command_id) = 7) IS NOT TRUE
     OR p_storage_object_id IS NULL
     OR (uuid_extract_version(p_storage_object_id) = 7) IS NOT TRUE
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'DFIR attachment prepare command binding is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF NOT (
    app.current_tenant_has_exact_permission(
      'dfir.attachment.manage', 'tenant'::public.authorization_scope
    ) OR app.current_tenant_has_exact_permission(
      'dfir.attachment.manage', 'operator_team'::public.authorization_scope
    ) OR app.current_tenant_has_exact_permission(
      'dfir.attachment.manage', 'assigned'::public.authorization_scope
    )
  ) THEN
    RAISE EXCEPTION 'DFIR attachment management permission is required'
      USING ERRCODE = '42501';
  END IF;

  DELETE FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'dfir.attachment.prepare'
    AND command.key_digest = p_key_digest
    AND command.expires_at <= transaction_timestamp();

  INSERT INTO public.tenant_authorization_commands (
    id, tenant_id, actor_membership_id, operation, key_digest,
    request_digest, result_resource_id, result_version
  ) VALUES (
    p_command_id, context_tenant, actor_membership,
    'dfir.attachment.prepare', p_key_digest, p_request_digest,
    p_storage_object_id, 1
  )
  ON CONFLICT (tenant_id, actor_membership_id, operation, key_digest)
  DO NOTHING;
  GET DIAGNOSTICS inserted_rows = ROW_COUNT;

  SELECT command.* INTO STRICT command_record
  FROM public.tenant_authorization_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'dfir.attachment.prepare'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF command_record.request_digest IS DISTINCT FROM p_request_digest
     OR command_record.result_resource_id IS DISTINCT FROM p_storage_object_id
     OR command_record.result_version IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'DFIR attachment prepare idempotency payload conflicts'
      USING ERRCODE = '23505',
            CONSTRAINT = 'tenant_authorization_commands_replay_key';
  END IF;
  RETURN QUERY SELECT command_record.result_resource_id,
                      command_record.result_version,
                      inserted_rows = 0;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.reserve_dfir_attachment_prepare_v1(uuid, uuid, bytea, bytea)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.reserve_dfir_attachment_prepare_v1(
  uuid, uuid, bytea, bytea
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.reserve_dfir_attachment_prepare_v1(
  uuid, uuid, bytea, bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.advance_dfir_storage_object_as_worker_v2(
  p_storage_object_id uuid,
  p_expected_version bigint,
  p_next_state public.dfir_scan_state,
  p_content_sha256 bytea,
  p_size_bytes bigint,
  p_detected_mime text,
  p_transitioned_at timestamp with time zone,
  p_audit_event_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid
)
RETURNS TABLE(storage_object_id uuid, storage_version bigint, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  target public.dfir_storage_objects%ROWTYPE;
  next_version bigint;
  attachment_rows bigint;
BEGIN
  IF NOT pg_has_role(session_user, 'periapsis_worker', 'member') THEN
    RAISE EXCEPTION 'DFIR storage transition requires worker role'
      USING ERRCODE = '42501';
  END IF;
  IF p_storage_object_id IS NULL OR p_expected_version IS NULL
     OR p_expected_version <= 0 OR p_next_state IS NULL
     OR p_transitioned_at IS NULL OR p_audit_event_id IS NULL
     OR p_outbox_event_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL THEN
    RAISE EXCEPTION 'DFIR storage transition input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_transitioned_at > transaction_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'DFIR storage transition time is in the future'
      USING ERRCODE = '22023';
  END IF;

  SELECT storage.* INTO target
  FROM public.dfir_storage_objects AS storage
  WHERE storage.tenant_id = context_tenant
    AND storage.id = p_storage_object_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DFIR storage object was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF target.version = p_expected_version + 1
     AND target.state = p_next_state
     AND target.updated_at = p_transitioned_at
     AND target.content_sha256 IS NOT DISTINCT FROM p_content_sha256
     AND target.size_bytes IS NOT DISTINCT FROM p_size_bytes
     AND target.detected_mime IS NOT DISTINCT FROM p_detected_mime THEN
    RETURN QUERY SELECT target.id, target.version, true;
    RETURN;
  END IF;
  IF target.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'DFIR storage object version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target.version >= 9223372036854775806
     OR target.expected_size_bytes NOT BETWEEN 1 AND 5000000000
     OR p_transitioned_at < target.updated_at
     OR EXISTS (
       SELECT 1 FROM public.dfir_evidence AS evidence
       WHERE evidence.tenant_id = context_tenant
         AND evidence.storage_object_id = target.id
     ) THEN
    RAISE EXCEPTION 'DFIR storage object must transition through a current exact-size projection'
      USING ERRCODE = '55000';
  END IF;
  IF NOT (CASE target.state
    WHEN 'pending_upload' THEN p_next_state = 'uploaded'
    WHEN 'uploaded' THEN p_next_state = 'verifying'
    WHEN 'verifying' THEN p_next_state IN ('quarantined', 'rejected')
    WHEN 'quarantined' THEN p_next_state = 'scanning'
    WHEN 'scanning' THEN p_next_state IN ('available', 'rejected', 'scan_failed')
    WHEN 'scan_failed' THEN p_next_state = 'scanning'
    WHEN 'available' THEN p_next_state = 'deleted'
    ELSE false
  END) THEN
    RAISE EXCEPTION 'DFIR storage state transition is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF p_next_state = 'deleted' AND (
    target.legal_hold OR target.retention_until > p_transitioned_at
  ) THEN
    RAISE EXCEPTION 'DFIR storage object is retained'
      USING ERRCODE = '55000';
  END IF;

  IF target.state = 'verifying' AND p_next_state = 'quarantined' THEN
    IF p_content_sha256 IS NULL OR octet_length(p_content_sha256) <> 32
       OR p_size_bytes IS DISTINCT FROM target.expected_size_bytes
       OR p_size_bytes NOT BETWEEN 1 AND 5000000000
       OR p_detected_mime IS NULL
       OR octet_length(p_detected_mime) NOT BETWEEN 3 AND 512 THEN
      RAISE EXCEPTION 'DFIR verified content projection is invalid'
        USING ERRCODE = '22023';
    END IF;
  ELSIF p_content_sha256 IS DISTINCT FROM target.content_sha256
        OR p_size_bytes IS DISTINCT FROM target.size_bytes
        OR p_detected_mime IS DISTINCT FROM target.detected_mime THEN
    RAISE EXCEPTION 'DFIR storage transition cannot replace content metadata'
      USING ERRCODE = '55000';
  END IF;

  next_version := target.version + 1;
  UPDATE public.dfir_storage_objects AS storage
  SET state = p_next_state,
      content_sha256 = CASE
        WHEN target.state = 'verifying' AND p_next_state = 'quarantined'
          THEN p_content_sha256
        ELSE storage.content_sha256
      END,
      size_bytes = CASE
        WHEN target.state = 'verifying' AND p_next_state = 'quarantined'
          THEN p_size_bytes
        ELSE storage.size_bytes
      END,
      detected_mime = CASE
        WHEN target.state = 'verifying' AND p_next_state = 'quarantined'
          THEN p_detected_mime
        ELSE storage.detected_mime
      END,
      verified_at = CASE
        WHEN target.state = 'verifying' AND p_next_state = 'quarantined'
          THEN p_transitioned_at
        ELSE storage.verified_at
      END,
      version = next_version,
      updated_at = p_transitioned_at
  WHERE storage.tenant_id = context_tenant
    AND storage.id = target.id;

  UPDATE public.dfir_attachments AS attachment
  SET scan_state = p_next_state,
      visibility = CASE
        WHEN p_next_state = 'available' THEN attachment.visibility
        ELSE 'private'::public.dfir_visibility
      END,
      version = attachment.version + 1
  WHERE attachment.tenant_id = context_tenant
    AND attachment.storage_object_id = target.id;
  GET DIAGNOSTICS attachment_rows = ROW_COUNT;
  IF attachment_rows <> 1 THEN
    RAISE EXCEPTION 'DFIR storage attachment projection is incomplete'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, action, resource_type,
    resource_id, request_id, correlation_id, authentication_method,
    outcome, before, after, metadata
  ) VALUES (
    p_audit_event_id, context_tenant, 0, 'system',
    'dfir.storage.state_changed', 'dfir_storage_object', target.id,
    p_request_id, p_correlation_id, 'worker', 'success',
    jsonb_build_object('state', target.state, 'version', target.version),
    jsonb_build_object('state', p_next_state, 'version', next_version),
    jsonb_build_object('phase', 4, 'contentMetadataRedacted', true)
  );

  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, event_type,
    schema_version, payload, deduplication_key, correlation_id,
    causation_id, traceparent, tracestate, occurred_at
  ) VALUES (
    p_outbox_event_id, context_tenant, 'dfir_storage_object', target.id,
    'dfir.storage.state_changed', 1,
    jsonb_build_object(
      'tenantId', context_tenant,
      'resourceId', target.id,
      'resourceVersion', next_version,
      'state', p_next_state
    ),
    concat('phase4:', p_request_id::text, ':dfir.storage.state_changed:', target.id::text),
    p_correlation_id, p_request_id,
    nullif(current_setting('app.traceparent', true), ''),
    nullif(current_setting('app.tracestate', true), ''),
    p_transitioned_at
  );

  RETURN QUERY SELECT target.id, next_version, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.advance_dfir_storage_object_as_worker_v2(
  uuid, bigint, public.dfir_scan_state, bytea, bigint, text,
  timestamp with time zone, uuid, uuid, uuid, uuid
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.advance_dfir_storage_object_as_worker_v2(
  uuid, bigint, public.dfir_scan_state, bytea, bigint, text,
  timestamp with time zone, uuid, uuid, uuid, uuid
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v2(
  uuid, bigint, public.dfir_scan_state, bytea, bigint, text,
  timestamp with time zone, uuid, uuid, uuid, uuid
) TO periapsis_worker;--> statement-breakpoint
REVOKE EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v1(
  uuid, bigint, public.dfir_scan_state, bytea, bigint, text,
  timestamp with time zone, uuid, uuid, uuid, uuid
) FROM periapsis_worker;--> statement-breakpoint

-- Claim only uploads whose signed session is certainly expired. The fence is
-- monotonically increased under SKIP LOCKED; the returned location is the only
-- API that exposes the real object key and is executable solely by workers.
CREATE FUNCTION app.claim_dfir_orphan_uploads_v1(
  p_limit integer,
  p_lease_seconds integer,
  p_now timestamp with time zone
)
RETURNS TABLE(
  tenant_id uuid,
  storage_object_id uuid,
  cleanup_fence bigint,
  bucket text,
  object_key text,
  expected_size_bytes bigint,
  upload_expires_at timestamp with time zone,
  cleanup_lease_expires_at timestamp with time zone
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF NOT pg_has_role(session_user, 'periapsis_worker', 'member') THEN
    RAISE EXCEPTION 'DFIR orphan cleanup claim requires worker role'
      USING ERRCODE = '42501';
  END IF;
  IF p_limit NOT BETWEEN 1 AND 100
     OR p_lease_seconds NOT BETWEEN 30 AND 900
     OR p_now IS NULL
     OR p_now < transaction_timestamp() - interval '1 minute'
     OR p_now > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'DFIR orphan cleanup claim input is invalid'
      USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH candidate AS (
    SELECT storage.id
    FROM public.dfir_storage_objects AS storage
    WHERE storage.state = 'pending_upload'
      AND storage.content_sha256 IS NULL
      AND storage.upload_expires_at + interval '5 minutes' <= p_now
      AND (storage.cleanup_lease_expires_at IS NULL
        OR storage.cleanup_lease_expires_at <= p_now)
      AND storage.cleanup_fence < 9223372036854775806
    ORDER BY storage.upload_expires_at, storage.id
    LIMIT p_limit
    FOR UPDATE SKIP LOCKED
  ), claimed AS (
    UPDATE public.dfir_storage_objects AS storage
    SET cleanup_fence = storage.cleanup_fence + 1,
        cleanup_attempt_count = storage.cleanup_attempt_count + 1,
        cleanup_claimed_at = p_now,
        cleanup_lease_expires_at = p_now + make_interval(secs => p_lease_seconds),
        cleanup_last_failure_code = NULL
    FROM candidate
    WHERE storage.id = candidate.id
    RETURNING storage.*
  )
  SELECT claimed.tenant_id, claimed.id, claimed.cleanup_fence,
         claimed.bucket, claimed.object_key, claimed.expected_size_bytes,
         claimed.upload_expires_at, claimed.cleanup_lease_expires_at
  FROM claimed
  ORDER BY claimed.upload_expires_at, claimed.id;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.claim_dfir_orphan_uploads_v1(
  integer, integer, timestamp with time zone
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.claim_dfir_orphan_uploads_v1(
  integer, integer, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.claim_dfir_orphan_uploads_v1(
  integer, integer, timestamp with time zone
) TO periapsis_worker;--> statement-breakpoint

CREATE FUNCTION app.retry_dfir_orphan_upload_cleanup_v1(
  p_storage_object_id uuid,
  p_cleanup_fence bigint,
  p_failure_code text,
  p_failed_at timestamp with time zone,
  p_retry_at timestamp with time zone
)
RETURNS boolean
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target public.dfir_storage_objects%ROWTYPE;
BEGIN
  IF NOT pg_has_role(session_user, 'periapsis_worker', 'member') THEN
    RAISE EXCEPTION 'DFIR orphan cleanup retry requires worker role'
      USING ERRCODE = '42501';
  END IF;
  IF p_storage_object_id IS NULL
     OR (uuid_extract_version(p_storage_object_id) = 7) IS NOT TRUE
     OR p_cleanup_fence NOT BETWEEN 1 AND 9223372036854775806
     OR p_failure_code IS NULL
     OR p_failure_code !~ '^[a-z][a-z0-9_.-]{0,63}$'
     OR p_failed_at IS NULL OR p_retry_at IS NULL
     OR p_failed_at < transaction_timestamp() - interval '5 minutes'
     OR p_failed_at > transaction_timestamp() + interval '1 minute'
     OR p_retry_at < p_failed_at + interval '1 second'
     OR p_retry_at > p_failed_at + interval '15 minutes' THEN
    RAISE EXCEPTION 'DFIR orphan cleanup retry input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT storage.* INTO target
  FROM public.dfir_storage_objects AS storage
  WHERE storage.id = p_storage_object_id
  FOR UPDATE;
  IF NOT FOUND OR target.cleanup_fence IS DISTINCT FROM p_cleanup_fence THEN
    RAISE EXCEPTION 'DFIR orphan cleanup fence is stale'
      USING ERRCODE = '40001';
  END IF;
  IF target.state = 'deleted' THEN
    RETURN true;
  END IF;
  IF target.state <> 'pending_upload'
     OR target.cleanup_claimed_at IS NULL
     OR target.cleanup_lease_expires_at IS NULL THEN
    RAISE EXCEPTION 'DFIR orphan cleanup claim is not retryable'
      USING ERRCODE = '55000';
  END IF;
  UPDATE public.dfir_storage_objects AS storage
  SET cleanup_claimed_at = p_failed_at,
      cleanup_lease_expires_at = p_retry_at,
      cleanup_last_failure_code = p_failure_code
  WHERE storage.id = target.id;
  RETURN false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.retry_dfir_orphan_upload_cleanup_v1(
  uuid, bigint, text, timestamp with time zone, timestamp with time zone
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.retry_dfir_orphan_upload_cleanup_v1(
  uuid, bigint, text, timestamp with time zone, timestamp with time zone
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.retry_dfir_orphan_upload_cleanup_v1(
  uuid, bigint, text, timestamp with time zone, timestamp with time zone
) TO periapsis_worker;--> statement-breakpoint

CREATE FUNCTION app.finalize_dfir_orphan_upload_cleanup_v1(
  p_storage_object_id uuid,
  p_cleanup_fence bigint,
  p_deleted_at timestamp with time zone,
  p_audit_event_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid
)
RETURNS TABLE(storage_object_id uuid, storage_version bigint, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  target public.dfir_storage_objects%ROWTYPE;
  next_version bigint;
  attachment_rows bigint;
BEGIN
  IF NOT pg_has_role(session_user, 'periapsis_worker', 'member') THEN
    RAISE EXCEPTION 'DFIR orphan cleanup finalize requires worker role'
      USING ERRCODE = '42501';
  END IF;
  IF p_storage_object_id IS NULL
     OR (uuid_extract_version(p_storage_object_id) = 7) IS NOT TRUE
     OR p_cleanup_fence NOT BETWEEN 1 AND 9223372036854775806
     OR p_deleted_at IS NULL
     OR p_deleted_at < transaction_timestamp() - interval '5 minutes'
     OR p_deleted_at > transaction_timestamp() + interval '1 minute'
     OR p_audit_event_id IS NULL OR (uuid_extract_version(p_audit_event_id) = 7) IS NOT TRUE
     OR p_outbox_event_id IS NULL OR (uuid_extract_version(p_outbox_event_id) = 7) IS NOT TRUE
     OR p_request_id IS NULL OR (uuid_extract_version(p_request_id) = 7) IS NOT TRUE
     OR p_correlation_id IS NULL OR (uuid_extract_version(p_correlation_id) = 7) IS NOT TRUE THEN
    RAISE EXCEPTION 'DFIR orphan cleanup finalize input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT storage.* INTO target
  FROM public.dfir_storage_objects AS storage
  WHERE storage.id = p_storage_object_id
  FOR UPDATE;
  IF NOT FOUND OR target.cleanup_fence IS DISTINCT FROM p_cleanup_fence THEN
    RAISE EXCEPTION 'DFIR orphan cleanup fence is stale'
      USING ERRCODE = '40001';
  END IF;
  IF target.state = 'deleted' THEN
    SELECT count(*) INTO attachment_rows
    FROM public.dfir_attachments AS attachment
    WHERE attachment.tenant_id = target.tenant_id
      AND attachment.storage_object_id = target.id
      AND attachment.scan_state = 'deleted'
      AND attachment.visibility = 'private';
    IF attachment_rows <> 1 THEN
      RAISE EXCEPTION 'DFIR orphan cleanup replay projection is incomplete'
        USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT target.id, target.version, true;
    RETURN;
  END IF;
  IF target.state <> 'pending_upload'
     OR target.content_sha256 IS NOT NULL
     OR target.cleanup_claimed_at IS NULL
     OR target.cleanup_lease_expires_at IS NULL
     OR target.cleanup_lease_expires_at <= transaction_timestamp()
     OR target.upload_expires_at + interval '5 minutes' > p_deleted_at
     OR p_deleted_at < target.updated_at
     OR target.version >= 9223372036854775806 THEN
    RAISE EXCEPTION 'DFIR orphan cleanup claim is no longer finalizable'
      USING ERRCODE = '40001';
  END IF;

  next_version := target.version + 1;
  UPDATE public.dfir_storage_objects AS storage
  SET state = 'deleted',
      cleanup_claimed_at = NULL,
      cleanup_lease_expires_at = NULL,
      cleanup_last_failure_code = NULL,
      version = next_version,
      updated_at = p_deleted_at
  WHERE storage.id = target.id;

  UPDATE public.dfir_attachments AS attachment
  SET scan_state = 'deleted',
      visibility = 'private',
      version = attachment.version + 1
  WHERE attachment.tenant_id = target.tenant_id
    AND attachment.storage_object_id = target.id;
  GET DIAGNOSTICS attachment_rows = ROW_COUNT;
  IF attachment_rows <> 1 THEN
    RAISE EXCEPTION 'DFIR orphan cleanup attachment projection is incomplete'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO public.audit_events (
    id, tenant_id, sequence, actor_type, action, resource_type,
    resource_id, request_id, correlation_id, authentication_method,
    outcome, before, after, metadata
  ) VALUES (
    p_audit_event_id, target.tenant_id, 0, 'system',
    'dfir.storage.orphan_deleted', 'dfir_storage_object', target.id,
    p_request_id, p_correlation_id, 'worker', 'success',
    jsonb_build_object('state', target.state, 'version', target.version),
    jsonb_build_object('state', 'deleted', 'version', next_version),
    jsonb_build_object(
      'phase', 4,
      'cleanupFence', p_cleanup_fence,
      'objectLocationRedacted', true,
      'contentMetadataRedacted', true
    )
  );

  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, event_type,
    schema_version, payload, deduplication_key, correlation_id,
    causation_id, traceparent, tracestate, occurred_at
  ) VALUES (
    p_outbox_event_id, target.tenant_id, 'dfir_storage_object', target.id,
    'dfir.storage.orphan_deleted', 1,
    jsonb_build_object(
      'tenantId', target.tenant_id,
      'resourceId', target.id,
      'resourceVersion', next_version,
      'state', 'deleted',
      'cleanupFence', p_cleanup_fence
    ),
    concat('phase4:', p_request_id::text, ':dfir.storage.orphan_deleted:', target.id::text),
    p_correlation_id, p_request_id,
    nullif(current_setting('app.traceparent', true), ''),
    nullif(current_setting('app.tracestate', true), ''),
    p_deleted_at
  );
  RETURN QUERY SELECT target.id, next_version, false;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.finalize_dfir_orphan_upload_cleanup_v1(
  uuid, bigint, timestamp with time zone, uuid, uuid, uuid, uuid
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.finalize_dfir_orphan_upload_cleanup_v1(
  uuid, bigint, timestamp with time zone, uuid, uuid, uuid, uuid
) FROM PUBLIC, periapsis_api, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.finalize_dfir_orphan_upload_cleanup_v1(
  uuid, bigint, timestamp with time zone, uuid, uuid, uuid, uuid
) TO periapsis_worker;--> statement-breakpoint

-- Phase 4 exact-size storage advances compatibility while preserving the
-- sealed 100-row v16 journal as the sole rolling predecessor.
CREATE FUNCTION app.schema_compatibility_v17()
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
  migration_0100_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787686749137
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0100_rows;
  IF journal_count = 101
     AND journal_latest_created_at = 1787686749137
     AND migration_0100_rows = 1 THEN
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
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v17()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v17()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v17()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v16()
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
  FROM app.schema_compatibility_v17() AS compatibility;
  IF full_count = 101
     AND full_latest_created_at = 1787686749137
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
              WHERE prefix.migration_ordinal = 100),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 100
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v16()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v16()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v16()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v15()
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
$function$;--> statement-breakpoint
ALTER FUNCTION app.schema_compatibility_v15()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v15()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v15()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

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
  fingerprint_created_at bigint[];
  actual_count bigint;
  actual_latest_created_at bigint;
  actual_latest_hash text;
  actual_fingerprint text;
  predecessor_count bigint;
  predecessor_latest_created_at bigint;
  predecessor_latest_hash text;
  predecessor_fingerprint text;
  expected_predecessor_hash text;
  expected_predecessor_fingerprint text;
  retired_count bigint;
BEGIN
  fingerprint_entries := string_to_array(
    p_expected_migration_fingerprint, ':'
  );
  IF p_expected_count IS DISTINCT FROM 101
     OR p_expected_latest_created_at IS DISTINCT FROM 1787686749137
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 101
     OR fingerprint_entries[101] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v17 manifest'
      USING ERRCODE = '22023';
  END IF;

  SELECT array_agg(
    split_part(entry.value, '@', 1)::bigint ORDER BY entry.ordinality
  ) INTO fingerprint_created_at
  FROM unnest(fingerprint_entries) WITH ORDINALITY
       AS entry(value, ordinality);
  IF fingerprint_created_at IS DISTINCT FROM ARRAY[
    1787472409685, 1787472415216, 1787473527702, 1787473536723,
    1787474082034, 1787474089267, 1787475027656, 1787475184077,
    1787488565252, 1787488569966, 1787492910536, 1787493031146,
    1787494284382, 1787495115125, 1787495293635, 1787495819997,
    1787495999394, 1787496124539, 1787496880587, 1787496982733,
    1787496987011, 1787501702276, 1787506296280, 1787507888755,
    1787508523197, 1787516694668, 1787571776845, 1787581350373,
    1787581530382, 1787582150087, 1787591930962, 1787591938733,
    1787592230466, 1787612620574, 1787613580320, 1787613592459,
    1787613744526, 1787613746038, 1787613747552, 1787613749000,
    1787635396524, 1787635417084, 1787635433516, 1787635452090,
    1787635459707, 1787635471570, 1787635525474, 1787635788324,
    1787635828723, 1787637794128, 1787637795761, 1787643146844,
    1787643153628, 1787643609827, 1787648180127, 1787648190820,
    1787648201836, 1787648215689, 1787648225321, 1787649465766,
    1787649478666, 1787649523649, 1787649541586, 1787650610199,
    1787650730983, 1787653130160, 1787653143051, 1787653149806,
    1787653151267, 1787653305313, 1787655186569, 1787655192148,
    1787655197869, 1787655813403, 1787655819028, 1787655824109,
    1787657661213, 1787657666680, 1787658281433, 1787658434202,
    1787659622481, 1787659623982, 1787664581262, 1787664767505,
    1787664955067, 1787665119323, 1787665128173, 1787672101246,
    1787672114811, 1787672134042, 1787673489517, 1787677373554,
    1787677383849, 1787677403239, 1787677416302, 1787677427915,
    1787679172524, 1787680410777, 1787680424626, 1787682162037,
    1787686749137
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v17 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v17() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v17 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v16()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[100], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:100], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v16() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 100
     OR predecessor_latest_created_at IS DISTINCT FROM 1787682162037
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v16 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v15() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v15 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(
  bigint, bigint, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.phase4_schema_readiness_v2()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  current_count bigint;
  predecessor_count bigint;
  retired_count bigint;
  function_oid regprocedure;
  expected record;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_class AS class
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = 'dfir_storage_objects'
      AND class.relkind = 'r'
      AND pg_get_userbyid(class.relowner) = 'periapsis_migrator'
      AND class.relrowsecurity
      AND class.relforcerowsecurity
  ) OR EXISTS (
    SELECT 1
    FROM unnest(ARRAY[
      'expected_size_bytes', 'upload_expires_at', 'cleanup_fence',
      'cleanup_attempt_count'
    ]) AS required(column_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_attribute AS attribute
      JOIN pg_class AS class ON class.oid = attribute.attrelid
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      WHERE namespace.nspname = 'public'
        AND class.relname = 'dfir_storage_objects'
        AND attribute.attname = required.column_name
        AND attribute.attnotnull
        AND NOT attribute.attisdropped
    )
  ) OR EXISTS (
    SELECT 1
    FROM unnest(ARRAY[
      'dfir_storage_objects_content_shape_check',
      'dfir_storage_objects_upload_expiry_check',
      'dfir_storage_objects_cleanup_check'
    ]) AS required(constraint_name)
    WHERE NOT EXISTS (
      SELECT 1
      FROM pg_constraint AS constraint_record
      JOIN pg_class AS class ON class.oid = constraint_record.conrelid
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      WHERE namespace.nspname = 'public'
        AND class.relname = 'dfir_storage_objects'
        AND constraint_record.conname = required.constraint_name
        AND constraint_record.convalidated
    )
  ) THEN
    RETURN false;
  END IF;

  IF has_table_privilege(
       'periapsis_api', 'public.dfir_storage_objects', 'UPDATE,DELETE'
     ) OR has_table_privilege(
       'periapsis_worker', 'public.dfir_storage_objects', 'INSERT,UPDATE,DELETE'
     ) OR NOT has_table_privilege(
       'periapsis_api', 'public.dfir_storage_objects', 'SELECT,INSERT'
     ) OR NOT has_table_privilege(
       'periapsis_worker', 'public.dfir_storage_objects', 'SELECT'
     ) THEN
    RETURN false;
  END IF;

  FOR expected IN
    SELECT * FROM (VALUES
      ('app.reserve_dfir_attachment_prepare_v1(uuid,uuid,bytea,bytea)', true, false, false),
      ('app.advance_dfir_storage_object_as_worker_v1(uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,uuid,uuid,uuid,uuid)', false, false, false),
      ('app.advance_dfir_storage_object_as_worker_v2(uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,uuid,uuid,uuid,uuid)', false, true, false),
      ('app.claim_dfir_orphan_uploads_v1(integer,integer,timestamp with time zone)', false, true, false),
      ('app.retry_dfir_orphan_upload_cleanup_v1(uuid,bigint,text,timestamp with time zone,timestamp with time zone)', false, true, false),
      ('app.finalize_dfir_orphan_upload_cleanup_v1(uuid,bigint,timestamp with time zone,uuid,uuid,uuid,uuid)', false, true, false),
      ('app.schema_compatibility_v17()', true, true, false),
      ('app.schema_compatibility_v16()', true, true, true),
      ('app.schema_compatibility_v15()', true, true, false)
    ) AS expected(signature, api_execute, worker_execute, allow_fingerprint)
  LOOP
    function_oid := to_regprocedure(expected.signature);
    IF function_oid IS NULL THEN
      RETURN false;
    END IF;
    SELECT pg_get_userbyid(procedure.proowner), procedure.prosecdef,
           procedure.proconfig
    INTO function_owner, function_security_definer, function_configuration
    FROM pg_proc AS procedure
    WHERE procedure.oid = function_oid;
    IF function_owner IS DISTINCT FROM 'periapsis_migrator'
       OR function_security_definer IS NOT TRUE
       OR function_configuration[1] NOT LIKE 'search_path=pg_catalog%'
       OR NOT expected.allow_fingerprint
          AND cardinality(function_configuration) IS DISTINCT FROM 1
       OR expected.allow_fingerprint AND (
         cardinality(function_configuration) IS DISTINCT FROM 2
         OR function_configuration[2] !~
           '^app\.schema_compatibility_fingerprint=(UNSEALED|[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*)$'
       ) OR EXISTS (
         SELECT 1
         FROM pg_proc AS procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(procedure.proacl, acldefault('f', procedure.proowner))
         ) AS privilege
         WHERE procedure.oid = function_oid
           AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       ) OR has_function_privilege(
         'periapsis_api', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected.api_execute
       OR has_function_privilege(
         'periapsis_worker', function_oid, 'EXECUTE'
       ) IS DISTINCT FROM expected.worker_execute
       OR has_function_privilege('periapsis_notifier', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_auditor', function_oid, 'EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;

  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger AS trigger
    JOIN pg_class AS class ON class.oid = trigger.tgrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = 'dfir_storage_objects'
      AND trigger.tgname = 'dfir_storage_objects_identity_v1'
      AND NOT trigger.tgisinternal
      AND trigger.tgenabled = 'O'
  ) OR NOT EXISTS (
    SELECT 1 FROM pg_constraint AS constraint_record
    JOIN pg_class AS class ON class.oid = constraint_record.conrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = 'tenant_authorization_commands'
      AND constraint_record.conname = 'tenant_authorization_commands_operation_check'
      AND pg_get_constraintdef(constraint_record.oid) LIKE '%dfir.attachment.prepare%'
  ) OR position(
    'dfir.attachment.prepare' IN pg_get_functiondef(
      'app.guard_tenant_authorization_command()'::regprocedure
    )
  ) = 0 THEN
    RETURN false;
  END IF;

  SELECT compatibility.applied_count INTO current_count
  FROM app.schema_compatibility_v17() AS compatibility;
  SELECT compatibility.applied_count INTO predecessor_count
  FROM app.schema_compatibility_v16() AS compatibility;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v15() AS compatibility;
  RETURN current_count = 101 AND predecessor_count = 100
    AND retired_count = 0;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.phase4_schema_readiness_v2()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.phase4_schema_readiness_v2()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.phase4_schema_readiness_v2()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint
