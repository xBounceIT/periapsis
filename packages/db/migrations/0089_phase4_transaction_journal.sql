-- Phase 4 transaction journal and evidence chain ABI. Application mutations
-- call these entry points inside the same PostgreSQL transaction as their row
-- changes, so the redacted audit, activity, and outbox records commit or roll
-- back together.

CREATE FUNCTION app.private_current_dfir_scope_allows_v1(
  p_permission_key text,
  p_case_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  actor_user uuid := app.context_user_id();
  actor_membership uuid := app.current_tenant_membership_id();
  context_tenant uuid := app.context_tenant_id();
  target_case public.cases%ROWTYPE;
BEGIN
  IF p_permission_key IS NULL OR p_permission_key NOT LIKE 'dfir.%' THEN
    RETURN false;
  END IF;
  IF app.current_tenant_human_has_exact_permission_v3(
    p_permission_key, 'tenant'
  ) THEN
    RETURN true;
  END IF;
  IF p_case_id IS NULL THEN
    RETURN false;
  END IF;

  SELECT target.* INTO target_case
  FROM public.cases AS target
  WHERE target.tenant_id = context_tenant
    AND target.id = p_case_id;
  IF NOT FOUND THEN
    RETURN false;
  END IF;

  IF app.current_tenant_human_has_exact_permission_v3(
       p_permission_key, 'assigned'
     ) AND actor_user IN (
       target_case.assignee_user_id, target_case.claimed_by_user_id
     ) THEN
    RETURN true;
  END IF;

  RETURN target_case.assigned_team_id IS NOT NULL
    AND target_case.assigned_team_epoch_id IS NOT NULL
    AND app.current_tenant_human_has_exact_permission_v3(
      p_permission_key, 'operator_team'
    )
    AND EXISTS (
      SELECT 1
      FROM public.operator_team_assignment_epochs AS assignment
      JOIN public.operator_team_roster_entries AS roster
        ON roster.tenant_id = assignment.tenant_id
       AND roster.assignment_epoch_id = assignment.id
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = roster.tenant_id
       AND source.id = roster.source_id
      WHERE assignment.tenant_id = context_tenant
        AND assignment.id = target_case.assigned_team_epoch_id
        AND assignment.operator_team_id = target_case.assigned_team_id
        AND assignment.ended_at IS NULL
        AND roster.membership_id = actor_membership
        AND roster.revoked_at IS NULL
        AND (roster.expires_at IS NULL
          OR roster.expires_at > transaction_timestamp())
        AND source.retired_at IS NULL
    );
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_current_dfir_scope_allows_v1(text, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_current_dfir_scope_allows_v1(text, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.private_dfir_resource_belongs_to_case_v1(
  p_tenant_id uuid,
  p_case_id uuid,
  p_kind public.dfir_entity_kind,
  p_resource_id uuid
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_tenant_id IS NULL OR p_case_id IS NULL
     OR p_kind IS NULL OR p_resource_id IS NULL OR p_kind = 'external' THEN
    RETURN false;
  END IF;
  RETURN CASE p_kind
    WHEN 'case' THEN p_resource_id = p_case_id AND EXISTS (
      SELECT 1 FROM public.cases
      WHERE tenant_id = p_tenant_id AND id = p_case_id
    )
    WHEN 'alert' THEN EXISTS (
      SELECT 1 FROM public.alert_case_links
      WHERE tenant_id = p_tenant_id
        AND case_id = p_case_id
        AND alert_id = p_resource_id
    )
    WHEN 'ioc' THEN EXISTS (
      SELECT 1 FROM public.dfir_ioc_links
      WHERE tenant_id = p_tenant_id
        AND case_id = p_case_id
        AND ioc_id = p_resource_id
    )
    WHEN 'asset' THEN EXISTS (
      SELECT 1 FROM public.dfir_asset_links
      WHERE tenant_id = p_tenant_id
        AND case_id = p_case_id
        AND asset_id = p_resource_id
    )
    WHEN 'evidence' THEN EXISTS (
      SELECT 1 FROM public.dfir_evidence
      WHERE tenant_id = p_tenant_id
        AND case_id = p_case_id
        AND id = p_resource_id
    )
    WHEN 'task' THEN EXISTS (
      SELECT 1 FROM public.dfir_tasks
      WHERE tenant_id = p_tenant_id
        AND case_id = p_case_id
        AND id = p_resource_id
    )
    WHEN 'attachment' THEN EXISTS (
      SELECT 1
      FROM public.dfir_attachments AS attachment
      LEFT JOIN public.dfir_evidence AS evidence
        ON evidence.tenant_id = attachment.tenant_id
       AND evidence.id = attachment.evidence_id
      LEFT JOIN public.dfir_tasks AS task
        ON task.tenant_id = attachment.tenant_id
       AND task.id = attachment.task_id
      LEFT JOIN public.dfir_ioc_links AS ioc_link
        ON ioc_link.tenant_id = attachment.tenant_id
       AND ioc_link.ioc_id = attachment.ioc_id
       AND ioc_link.case_id = p_case_id
      LEFT JOIN public.dfir_asset_links AS asset_link
        ON asset_link.tenant_id = attachment.tenant_id
       AND asset_link.asset_id = attachment.asset_id
       AND asset_link.case_id = p_case_id
      WHERE attachment.tenant_id = p_tenant_id
        AND attachment.id = p_resource_id
        AND (
          attachment.case_id = p_case_id
          OR evidence.case_id = p_case_id
          OR task.case_id = p_case_id
          OR ioc_link.id IS NOT NULL
          OR asset_link.id IS NOT NULL
        )
    )
    ELSE false
  END;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.private_dfir_resource_belongs_to_case_v1(uuid, uuid, public.dfir_entity_kind, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_dfir_resource_belongs_to_case_v1(uuid, uuid, public.dfir_entity_kind, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.append_phase4_mutation_effects_v1(
  p_permission_key text,
  p_action text,
  p_resource_type text,
  p_resource_id uuid,
  p_resource_version bigint,
  p_case_id uuid,
  p_activity_id uuid,
  p_activity_resource_kind public.dfir_entity_kind,
  p_activity_resource_id uuid,
  p_summary text,
  p_before jsonb,
  p_after jsonb,
  p_metadata jsonb,
  p_audit_event_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  expected_permission text;
BEGIN
  expected_permission := CASE
    WHEN p_action LIKE 'custom_field.%' THEN 'custom_field.manage'
    WHEN p_action LIKE 'dfir.ioc.%' THEN 'dfir.ioc.manage'
    WHEN p_action LIKE 'dfir.asset.%' THEN 'dfir.asset.manage'
    WHEN p_action LIKE 'dfir.evidence.%' THEN 'dfir.evidence.manage'
    WHEN p_action LIKE 'dfir.timeline.%' THEN 'dfir.timeline.manage'
    WHEN p_action LIKE 'dfir.task.%' THEN 'dfir.task.manage'
    WHEN p_action LIKE 'dfir.attachment.%' THEN 'dfir.attachment.manage'
    WHEN p_action LIKE 'dfir.relationship.%' THEN 'dfir.relationship.manage'
    ELSE NULL
  END;
  IF expected_permission IS NULL
     OR p_permission_key IS DISTINCT FROM expected_permission
     OR p_resource_type IS NULL
     OR p_resource_type !~ '^(custom_field|dfir)_[a-z][a-z0-9_]{1,63}$'
     OR p_action !~ '^(custom_field|dfir)\.[a-z][a-z0-9_.-]{1,63}$'
     OR p_resource_id IS NULL
     OR p_resource_version IS NULL OR p_resource_version <= 0
     OR p_audit_event_id IS NULL OR p_outbox_event_id IS NULL
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_summary IS NULL OR octet_length(p_summary) NOT BETWEEN 1 AND 512
     OR p_summary ~ '[[:cntrl:]]'
     OR coalesce(jsonb_typeof(p_before), 'object') <> 'object'
     OR coalesce(jsonb_typeof(p_after), 'object') <> 'object'
     OR coalesce(jsonb_typeof(p_metadata), 'object') <> 'object'
     OR pg_column_size(coalesce(p_before, '{}'::jsonb)) > 32768
     OR pg_column_size(coalesce(p_after, '{}'::jsonb)) > 32768
     OR pg_column_size(coalesce(p_metadata, '{}'::jsonb)) > 32768 THEN
    RAISE EXCEPTION 'phase 4 mutation journal input is invalid'
      USING ERRCODE = '22023';
  END IF;

  IF expected_permission = 'custom_field.manage' THEN
    IF p_case_id IS NOT NULL OR p_activity_id IS NOT NULL
       OR p_activity_resource_kind IS NOT NULL OR p_activity_resource_id IS NOT NULL
       OR NOT app.current_tenant_human_has_exact_permission_v3(
         expected_permission, 'tenant'
       ) THEN
      RAISE EXCEPTION 'custom field management requires tenant scope'
        USING ERRCODE = '42501';
    END IF;
  ELSIF NOT app.private_current_dfir_scope_allows_v1(
    expected_permission, p_case_id
  ) THEN
    RAISE EXCEPTION 'DFIR mutation scope is not authorized'
      USING ERRCODE = '42501';
  END IF;

  IF p_case_id IS NOT NULL THEN
    IF p_activity_id IS NULL OR p_activity_resource_kind IS NULL
       OR p_activity_resource_id IS NULL
       OR NOT app.private_dfir_resource_belongs_to_case_v1(
         context_tenant, p_case_id, p_activity_resource_kind,
         p_activity_resource_id
       ) THEN
      RAISE EXCEPTION 'DFIR activity resource does not belong to case'
        USING ERRCODE = '23503';
    END IF;
    INSERT INTO public.dfir_activities (
      id, tenant_id, case_id, resource_kind, resource_id,
      action, summary, actor_principal_kind, actor_membership_id,
      actor_user_id, actor_service_account_id, details, occurred_at
    ) VALUES (
      p_activity_id, context_tenant, p_case_id,
      p_activity_resource_kind, p_activity_resource_id,
      p_action, p_summary, 'human', actor_membership,
      actor_user, NULL,
      jsonb_build_object('resourceVersion', p_resource_version),
      transaction_timestamp()
    );
  ELSIF p_activity_id IS NOT NULL OR p_activity_resource_kind IS NOT NULL
        OR p_activity_resource_id IS NOT NULL THEN
    RAISE EXCEPTION 'tenant-level mutation cannot emit case activity'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.append_tenant_authorization_audit(
    p_audit_event_id, p_action, p_resource_type, p_resource_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, p_before, p_after,
    coalesce(p_metadata, '{}'::jsonb) || jsonb_build_object(
      'phase', 4,
      'resourceVersion', p_resource_version
    )
  );

  INSERT INTO public.outbox_events (
    id, tenant_id, aggregate_type, aggregate_id, event_type,
    schema_version, payload, deduplication_key, correlation_id,
    causation_id, occurred_at
  ) VALUES (
    p_outbox_event_id, context_tenant, p_resource_type, p_resource_id,
    p_action, 1,
    jsonb_build_object(
      'tenantId', context_tenant,
      'resourceId', p_resource_id,
      'resourceVersion', p_resource_version
    ),
    concat('phase4:', p_request_id::text, ':', p_action, ':', p_resource_id::text),
    p_correlation_id, p_request_id, transaction_timestamp()
  );
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.append_phase4_mutation_effects_v1(text, text, text, uuid, bigint, uuid, uuid, public.dfir_entity_kind, uuid, text, jsonb, jsonb, jsonb, uuid, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_phase4_mutation_effects_v1(text, text, text, uuid, bigint, uuid, uuid, public.dfir_entity_kind, uuid, text, jsonb, jsonb, jsonb, uuid, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_phase4_mutation_effects_v1(text, text, text, uuid, bigint, uuid, uuid, public.dfir_entity_kind, uuid, text, jsonb, jsonb, jsonb, uuid, uuid, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.create_dfir_evidence_v1(
  p_evidence_id uuid,
  p_case_id uuid,
  p_storage_object_id uuid,
  p_title text,
  p_description text,
  p_evidence_type text,
  p_classification public.dfir_evidence_classification,
  p_collected_at timestamp with time zone,
  p_source text,
  p_retention_until timestamp with time zone,
  p_legal_hold boolean,
  p_custody_event_id uuid,
  p_anchor_hash bytea,
  p_event_hash bytea,
  p_audit_event_id uuid,
  p_activity_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (evidence_id uuid, evidence_version bigint, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  storage_record public.dfir_storage_objects%ROWTYPE;
  existing_evidence public.dfir_evidence%ROWTYPE;
  existing_event public.dfir_custody_events%ROWTYPE;
BEGIN
  IF NOT app.private_current_dfir_scope_allows_v1(
    'dfir.evidence.manage', p_case_id
  ) THEN
    RAISE EXCEPTION 'DFIR evidence mutation scope is not authorized'
      USING ERRCODE = '42501';
  END IF;
  IF p_evidence_id IS NULL OR p_case_id IS NULL OR p_storage_object_id IS NULL
     OR p_custody_event_id IS NULL OR p_collected_at IS NULL
     OR p_classification IS NULL OR p_legal_hold IS NULL
     OR p_collected_at > transaction_timestamp() + interval '5 minutes'
     OR p_anchor_hash IS NULL OR octet_length(p_anchor_hash) <> 32
     OR p_event_hash IS NULL OR octet_length(p_event_hash) <> 32 THEN
    RAISE EXCEPTION 'DFIR evidence input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT evidence.* INTO existing_evidence
  FROM public.dfir_evidence AS evidence
  WHERE evidence.tenant_id = context_tenant
    AND evidence.id = p_evidence_id;
  IF FOUND THEN
    SELECT event.* INTO existing_event
    FROM public.dfir_custody_events AS event
    WHERE event.tenant_id = context_tenant
      AND event.id = p_custody_event_id;
    IF NOT FOUND
       OR existing_evidence.case_id IS DISTINCT FROM p_case_id
       OR existing_evidence.storage_object_id IS DISTINCT FROM p_storage_object_id
       OR existing_evidence.title IS DISTINCT FROM p_title
       OR existing_evidence.description IS DISTINCT FROM p_description
       OR existing_evidence.evidence_type IS DISTINCT FROM p_evidence_type
       OR existing_evidence.classification IS DISTINCT FROM p_classification
       OR existing_evidence.collected_at IS DISTINCT FROM p_collected_at
       OR existing_evidence.source IS DISTINCT FROM p_source
       OR existing_evidence.initial_retention_until IS DISTINCT FROM p_retention_until
       OR existing_evidence.initial_legal_hold IS DISTINCT FROM p_legal_hold
       OR existing_evidence.anchor_hash IS DISTINCT FROM p_anchor_hash
       OR existing_event.evidence_id IS DISTINCT FROM p_evidence_id
       OR existing_event.sequence <> 1
       OR existing_event.action <> 'collected'
       OR existing_event.actor_membership_id IS DISTINCT FROM actor_membership
       OR existing_event.actor_user_id IS DISTINCT FROM actor_user
       OR existing_event.previous_hash IS DISTINCT FROM p_anchor_hash
       OR existing_event.event_hash IS DISTINCT FROM p_event_hash
       OR existing_event.occurred_at IS DISTINCT FROM p_collected_at THEN
      RAISE EXCEPTION 'DFIR evidence replay payload conflicts with existing evidence'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_evidence.id, existing_evidence.version, true;
    RETURN;
  END IF;

  SELECT storage.* INTO storage_record
  FROM public.dfir_storage_objects AS storage
  WHERE storage.tenant_id = context_tenant
    AND storage.id = p_storage_object_id
  FOR UPDATE;
  IF NOT FOUND
     OR storage_record.state NOT IN (
       'quarantined', 'scanning', 'available', 'rejected', 'scan_failed', 'retained'
     )
     OR storage_record.content_sha256 IS NULL
     OR storage_record.size_bytes IS NULL
     OR storage_record.detected_mime IS NULL
     OR storage_record.verified_at IS NULL
     OR storage_record.classification IS DISTINCT FROM p_classification
     OR storage_record.retention_until IS DISTINCT FROM p_retention_until
     OR storage_record.legal_hold IS DISTINCT FROM p_legal_hold
     OR storage_record.state = 'retained'
        AND NOT storage_record.legal_hold
        AND NOT coalesce(storage_record.retention_until > p_collected_at, false) THEN
    RAISE EXCEPTION 'verified DFIR storage object is not collectable'
      USING ERRCODE = '55000';
  END IF;

  INSERT INTO public.dfir_evidence (
    id, tenant_id, case_id, storage_object_id, title, description,
    evidence_type, classification, content_sha256, size_bytes,
    detected_mime, collected_at, collected_by_membership_id, source,
    initial_retention_until, retention_until, initial_legal_hold,
    legal_hold, initial_scan_state, scan_state, sealed, destroyed,
    anchor_hash, custody_head_hash, custody_count, version,
    created_at, updated_at
  ) VALUES (
    p_evidence_id, context_tenant, p_case_id, p_storage_object_id,
    p_title, p_description, p_evidence_type, p_classification,
    storage_record.content_sha256, storage_record.size_bytes,
    storage_record.detected_mime, p_collected_at, actor_membership, p_source,
    p_retention_until, p_retention_until, p_legal_hold, p_legal_hold,
    storage_record.state, storage_record.state, false, false,
    p_anchor_hash, p_event_hash, 1, 1,
    transaction_timestamp(), transaction_timestamp()
  );

  INSERT INTO public.dfir_custody_events (
    id, tenant_id, evidence_id, sequence, action,
    actor_principal_kind, actor_id, actor_membership_id, actor_user_id,
    actor_service_account_id, reason, state_value, previous_hash,
    event_hash, occurred_at
  ) VALUES (
    p_custody_event_id, context_tenant, p_evidence_id, 1, 'collected',
    'human', actor_user, actor_membership, actor_user, NULL,
    'initial collection', '', p_anchor_hash, p_event_hash, p_collected_at
  );

  PERFORM app.append_phase4_mutation_effects_v1(
    'dfir.evidence.manage', 'dfir.evidence.collected', 'dfir_evidence',
    p_evidence_id, 1, p_case_id, p_activity_id, 'evidence', p_evidence_id,
    'Evidence collected', NULL,
    jsonb_build_object(
      'classification', p_classification,
      'scanState', storage_record.state,
      'version', 1
    ),
    jsonb_build_object('custodyCount', 1),
    p_audit_event_id, p_outbox_event_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  );

  RETURN QUERY SELECT p_evidence_id, 1::bigint, false;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.create_dfir_evidence_v1(uuid, uuid, uuid, text, text, text, public.dfir_evidence_classification, timestamp with time zone, text, timestamp with time zone, boolean, uuid, bytea, bytea, uuid, uuid, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.create_dfir_evidence_v1(uuid, uuid, uuid, text, text, text, public.dfir_evidence_classification, timestamp with time zone, text, timestamp with time zone, boolean, uuid, bytea, bytea, uuid, uuid, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.create_dfir_evidence_v1(uuid, uuid, uuid, text, text, text, public.dfir_evidence_classification, timestamp with time zone, text, timestamp with time zone, boolean, uuid, bytea, bytea, uuid, uuid, uuid, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.append_dfir_custody_event_v1(
  p_evidence_id uuid,
  p_expected_version bigint,
  p_custody_event_id uuid,
  p_action public.dfir_custody_action,
  p_reason text,
  p_state_value text,
  p_previous_hash bytea,
  p_event_hash bytea,
  p_occurred_at timestamp with time zone,
  p_audit_event_id uuid,
  p_activity_id uuid,
  p_outbox_event_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (evidence_id uuid, evidence_version bigint, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid := app.current_tenant_membership_id();
  actor_user uuid := app.context_user_id();
  target public.dfir_evidence%ROWTYPE;
  existing_event public.dfir_custody_events%ROWTYPE;
  previous_occurred_at timestamp with time zone;
  next_scan_state public.dfir_scan_state;
  next_retention timestamp with time zone;
  next_version bigint;
  storage_rows integer;
BEGIN
  IF p_evidence_id IS NULL OR p_expected_version IS NULL
     OR p_expected_version <= 0 OR p_custody_event_id IS NULL
     OR p_action IS NULL OR p_action = 'collected'
     OR p_reason IS NULL OR p_state_value IS NULL OR p_occurred_at IS NULL
     OR p_previous_hash IS NULL OR octet_length(p_previous_hash) <> 32
     OR p_event_hash IS NULL OR octet_length(p_event_hash) <> 32 THEN
    RAISE EXCEPTION 'DFIR custody input is invalid'
      USING ERRCODE = '22023';
  END IF;

  SELECT evidence.* INTO target
  FROM public.dfir_evidence AS evidence
  WHERE evidence.tenant_id = context_tenant
    AND evidence.id = p_evidence_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'DFIR evidence was not found'
      USING ERRCODE = 'P0002';
  END IF;
  IF NOT app.private_current_dfir_scope_allows_v1(
    'dfir.evidence.manage', target.case_id
  ) THEN
    RAISE EXCEPTION 'DFIR evidence mutation scope is not authorized'
      USING ERRCODE = '42501';
  END IF;

  SELECT event.* INTO existing_event
  FROM public.dfir_custody_events AS event
  WHERE event.tenant_id = context_tenant
    AND event.id = p_custody_event_id;
  IF FOUND THEN
    IF existing_event.evidence_id IS DISTINCT FROM p_evidence_id
       OR existing_event.sequence IS DISTINCT FROM p_expected_version + 1
       OR existing_event.action IS DISTINCT FROM p_action
       OR existing_event.actor_membership_id IS DISTINCT FROM actor_membership
       OR existing_event.actor_user_id IS DISTINCT FROM actor_user
       OR existing_event.reason IS DISTINCT FROM p_reason
       OR existing_event.state_value IS DISTINCT FROM p_state_value
       OR existing_event.previous_hash IS DISTINCT FROM p_previous_hash
       OR existing_event.event_hash IS DISTINCT FROM p_event_hash
       OR existing_event.occurred_at IS DISTINCT FROM p_occurred_at THEN
      RAISE EXCEPTION 'DFIR custody replay payload conflicts with existing event'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT target.id, target.version, true;
    RETURN;
  END IF;

  IF target.version IS DISTINCT FROM p_expected_version THEN
    RAISE EXCEPTION 'DFIR evidence version conflict'
      USING ERRCODE = '40001';
  END IF;
  IF target.version >= 9223372036854775807 OR target.destroyed
     OR target.custody_head_hash IS DISTINCT FROM p_previous_hash THEN
    RAISE EXCEPTION 'DFIR evidence custody chain cannot advance'
      USING ERRCODE = '55000';
  END IF;
  SELECT event.occurred_at INTO STRICT previous_occurred_at
  FROM public.dfir_custody_events AS event
  WHERE event.tenant_id = context_tenant
    AND event.evidence_id = target.id
    AND event.sequence = target.custody_count;
  IF p_occurred_at < previous_occurred_at THEN
    RAISE EXCEPTION 'DFIR custody event time precedes chain head'
      USING ERRCODE = '22023';
  END IF;
  IF p_occurred_at > transaction_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'DFIR custody event time is in the future'
      USING ERRCODE = '22023';
  END IF;

  CASE p_action
    WHEN 'accessed', 'transferred' THEN
      IF p_state_value <> '' THEN
        RAISE EXCEPTION 'DFIR custody state is invalid' USING ERRCODE = '22023';
      END IF;
    WHEN 'sealed' THEN
      IF target.sealed OR p_state_value <> '' THEN
        RAISE EXCEPTION 'DFIR custody state is invalid' USING ERRCODE = '22023';
      END IF;
    WHEN 'unsealed' THEN
      IF NOT target.sealed OR p_state_value <> '' THEN
        RAISE EXCEPTION 'DFIR custody state is invalid' USING ERRCODE = '22023';
      END IF;
    WHEN 'legal_hold_placed' THEN
      IF target.legal_hold OR p_state_value <> 'true' THEN
        RAISE EXCEPTION 'DFIR custody state is invalid' USING ERRCODE = '22023';
      END IF;
    WHEN 'legal_hold_released' THEN
      IF NOT target.legal_hold OR p_state_value <> 'false' THEN
        RAISE EXCEPTION 'DFIR custody state is invalid' USING ERRCODE = '22023';
      END IF;
    WHEN 'retention_changed' THEN
      IF p_state_value = 'none' THEN
        next_retention := NULL;
      ELSE
        BEGIN
          next_retention := p_state_value::timestamp with time zone;
        EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
          RAISE EXCEPTION 'DFIR custody retention value is invalid'
            USING ERRCODE = '22023';
        END;
        IF next_retention < target.collected_at THEN
          RAISE EXCEPTION 'DFIR custody retention value is invalid'
            USING ERRCODE = '22023';
        END IF;
      END IF;
      IF next_retention IS NOT DISTINCT FROM target.retention_until THEN
        RAISE EXCEPTION 'DFIR custody retention is unchanged'
          USING ERRCODE = '22023';
      END IF;
    WHEN 'scan_state_changed' THEN
      BEGIN
        next_scan_state := p_state_value::public.dfir_scan_state;
      EXCEPTION WHEN invalid_text_representation THEN
        RAISE EXCEPTION 'DFIR custody scan state is invalid'
          USING ERRCODE = '22023';
      END;
      IF NOT (CASE target.scan_state
        WHEN 'pending_upload' THEN next_scan_state = 'uploaded'
        WHEN 'uploaded' THEN next_scan_state = 'verifying'
        WHEN 'verifying' THEN next_scan_state IN ('quarantined', 'rejected')
        WHEN 'quarantined' THEN next_scan_state = 'scanning'
        WHEN 'scanning' THEN next_scan_state IN ('available', 'rejected', 'scan_failed')
        WHEN 'scan_failed' THEN next_scan_state = 'scanning'
        WHEN 'available' THEN next_scan_state IN ('retained', 'deleted')
        WHEN 'retained' THEN next_scan_state = 'available'
        ELSE false
      END) THEN
        RAISE EXCEPTION 'DFIR custody scan transition is invalid'
          USING ERRCODE = '22023';
      END IF;
      IF next_scan_state = 'deleted' AND (
           target.legal_hold OR target.sealed
           OR target.retention_until > p_occurred_at
         )
         OR next_scan_state = 'retained' AND NOT target.legal_hold
            AND NOT coalesce(target.retention_until > p_occurred_at, false)
         OR target.scan_state = 'retained' AND next_scan_state = 'available'
            AND (target.legal_hold OR coalesce(target.retention_until > p_occurred_at, false)) THEN
        RAISE EXCEPTION 'DFIR custody transition violates retention policy'
          USING ERRCODE = '55000';
      END IF;
    WHEN 'destroyed' THEN
      IF p_state_value <> '' OR target.scan_state <> 'available'
         OR target.legal_hold OR target.sealed
         OR target.retention_until > p_occurred_at THEN
        RAISE EXCEPTION 'DFIR evidence cannot be destroyed'
          USING ERRCODE = '55000';
      END IF;
      next_scan_state := 'deleted';
    ELSE
      RAISE EXCEPTION 'DFIR custody action is invalid'
        USING ERRCODE = '22023';
  END CASE;

  next_version := target.version + 1;
  INSERT INTO public.dfir_custody_events (
    id, tenant_id, evidence_id, sequence, action,
    actor_principal_kind, actor_id, actor_membership_id, actor_user_id,
    actor_service_account_id, reason, state_value, previous_hash,
    event_hash, occurred_at
  ) VALUES (
    p_custody_event_id, context_tenant, target.id, next_version, p_action,
    'human', actor_user, actor_membership, actor_user, NULL,
    p_reason, p_state_value, p_previous_hash, p_event_hash, p_occurred_at
  );

  UPDATE public.dfir_evidence AS evidence
  SET scan_state = CASE
        WHEN p_action IN ('scan_state_changed', 'destroyed') THEN next_scan_state
        ELSE evidence.scan_state
      END,
      retention_until = CASE
        WHEN p_action = 'retention_changed' THEN next_retention
        ELSE evidence.retention_until
      END,
      legal_hold = CASE
        WHEN p_action = 'legal_hold_placed' THEN true
        WHEN p_action = 'legal_hold_released' THEN false
        ELSE evidence.legal_hold
      END,
      sealed = CASE
        WHEN p_action = 'sealed' THEN true
        WHEN p_action = 'unsealed' THEN false
        ELSE evidence.sealed
      END,
      destroyed = evidence.destroyed OR p_action = 'destroyed'
        OR p_action = 'scan_state_changed' AND next_scan_state = 'deleted',
      custody_head_hash = p_event_hash,
      custody_count = next_version,
      version = next_version,
      updated_at = greatest(transaction_timestamp(), p_occurred_at)
  WHERE evidence.tenant_id = context_tenant
    AND evidence.id = target.id;

  IF p_action IN (
    'scan_state_changed', 'destroyed', 'retention_changed',
    'legal_hold_placed', 'legal_hold_released'
  ) THEN
    UPDATE public.dfir_storage_objects AS storage
    SET state = CASE
          WHEN p_action IN ('scan_state_changed', 'destroyed') THEN next_scan_state
          ELSE storage.state
        END,
        retention_until = CASE
          WHEN p_action = 'retention_changed' THEN next_retention
          ELSE storage.retention_until
        END,
        legal_hold = CASE
          WHEN p_action = 'legal_hold_placed' THEN true
          WHEN p_action = 'legal_hold_released' THEN false
          ELSE storage.legal_hold
        END,
        version = storage.version + 1,
        updated_at = greatest(transaction_timestamp(), p_occurred_at)
    WHERE storage.tenant_id = context_tenant
      AND storage.id = target.storage_object_id
      AND storage.version < 9223372036854775807
      AND storage.state = target.scan_state
      AND storage.retention_until IS NOT DISTINCT FROM target.retention_until
      AND storage.legal_hold IS NOT DISTINCT FROM target.legal_hold;
    GET DIAGNOSTICS storage_rows = ROW_COUNT;
    IF storage_rows <> 1 THEN
      RAISE EXCEPTION 'DFIR storage and evidence projections have drifted'
        USING ERRCODE = '55000';
    END IF;

    IF p_action IN ('scan_state_changed', 'destroyed') THEN
      IF next_scan_state = 'deleted' THEN
        DELETE FROM public.dfir_attachments AS attachment
        WHERE attachment.tenant_id = context_tenant
          AND attachment.storage_object_id = target.storage_object_id;
      ELSE
        UPDATE public.dfir_attachments AS attachment
        SET scan_state = next_scan_state,
            visibility = CASE
              WHEN next_scan_state = 'available' THEN attachment.visibility
              ELSE 'private'::public.dfir_visibility
            END,
            version = attachment.version + 1
        WHERE attachment.tenant_id = context_tenant
          AND attachment.storage_object_id = target.storage_object_id;
      END IF;
    END IF;
  END IF;

  PERFORM app.append_phase4_mutation_effects_v1(
    'dfir.evidence.manage', 'dfir.evidence.custody_appended',
    'dfir_evidence', target.id, next_version, target.case_id,
    p_activity_id, 'evidence', target.id, 'Evidence custody updated',
    jsonb_build_object(
      'version', target.version,
      'scanState', target.scan_state,
      'legalHold', target.legal_hold,
      'sealed', target.sealed,
      'destroyed', target.destroyed
    ),
    jsonb_build_object(
      'version', next_version,
      'scanState', coalesce(next_scan_state, target.scan_state),
      'legalHold', CASE
        WHEN p_action = 'legal_hold_placed' THEN true
        WHEN p_action = 'legal_hold_released' THEN false
        ELSE target.legal_hold
      END,
      'sealed', CASE
        WHEN p_action = 'sealed' THEN true
        WHEN p_action = 'unsealed' THEN false
        ELSE target.sealed
      END,
      'destroyed', target.destroyed OR p_action = 'destroyed'
        OR p_action = 'scan_state_changed' AND next_scan_state = 'deleted'
    ),
    jsonb_build_object('custodyAction', p_action),
    p_audit_event_id, p_outbox_event_id, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  );

  RETURN QUERY SELECT target.id, next_version, false;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.append_dfir_custody_event_v1(uuid, bigint, uuid, public.dfir_custody_action, text, text, bytea, bytea, timestamp with time zone, uuid, uuid, uuid, uuid, uuid, inet, text, text) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.append_dfir_custody_event_v1(uuid, bigint, uuid, public.dfir_custody_action, text, text, bytea, bytea, timestamp with time zone, uuid, uuid, uuid, uuid, uuid, inet, text, text) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.append_dfir_custody_event_v1(uuid, bigint, uuid, public.dfir_custody_action, text, text, bytea, bytea, timestamp with time zone, uuid, uuid, uuid, uuid, uuid, inet, text, text) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.advance_dfir_storage_object_as_worker_v1(
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
RETURNS TABLE (storage_object_id uuid, storage_version bigint, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  target public.dfir_storage_objects%ROWTYPE;
  next_version bigint;
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
     OR p_transitioned_at < target.updated_at
     OR EXISTS (
       SELECT 1 FROM public.dfir_evidence AS evidence
       WHERE evidence.tenant_id = context_tenant
         AND evidence.storage_object_id = target.id
     ) THEN
    RAISE EXCEPTION 'DFIR storage object must transition through custody'
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
       OR p_size_bytes IS NULL OR p_size_bytes NOT BETWEEN 0 AND 5497558138880
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

  IF p_next_state = 'deleted' THEN
    DELETE FROM public.dfir_attachments AS attachment
    WHERE attachment.tenant_id = context_tenant
      AND attachment.storage_object_id = target.id;
  ELSE
    UPDATE public.dfir_attachments AS attachment
    SET scan_state = p_next_state,
        visibility = CASE
          WHEN p_next_state = 'available' THEN attachment.visibility
          ELSE 'private'::public.dfir_visibility
        END,
        version = attachment.version + 1
    WHERE attachment.tenant_id = context_tenant
      AND attachment.storage_object_id = target.id;
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
    causation_id, occurred_at
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
    p_correlation_id, p_request_id, p_transitioned_at
  );

  RETURN QUERY SELECT target.id, next_version, false;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.advance_dfir_storage_object_as_worker_v1(uuid, bigint, public.dfir_scan_state, bytea, bigint, text, timestamp with time zone, uuid, uuid, uuid, uuid) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.advance_dfir_storage_object_as_worker_v1(uuid, bigint, public.dfir_scan_state, bytea, bigint, text, timestamp with time zone, uuid, uuid, uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.advance_dfir_storage_object_as_worker_v1(uuid, bigint, public.dfir_scan_state, bytea, bigint, text, timestamp with time zone, uuid, uuid, uuid, uuid) TO periapsis_worker;--> statement-breakpoint

-- Phase 4 advances the exact schema projection while preserving only v13 as
-- the rolling predecessor. The manifest sealer binds v13 to the verified
-- 82-row prefix only after the complete 90-row journal has been authenticated.
CREATE FUNCTION app.schema_compatibility_v14()
RETURNS TABLE (
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
  migration_0089_rows bigint;
BEGIN
  EXECUTE $query$
    SELECT count(*)::bigint, max(migration.created_at)::bigint,
           count(*) FILTER (
             WHERE migration.created_at = 1787672134042
           )::bigint
    FROM drizzle.__drizzle_migrations AS migration
  $query$ INTO journal_count, journal_latest_created_at, migration_0089_rows;
  IF journal_count = 90
     AND journal_latest_created_at = 1787672134042
     AND migration_0089_rows = 1 THEN
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

ALTER FUNCTION app.schema_compatibility_v14() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v14()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v14()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v13()
RETURNS TABLE (
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
  FROM app.schema_compatibility_v14() AS compatibility;
  IF full_count = 90
     AND full_latest_created_at = 1787672134042
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
              WHERE prefix.migration_ordinal = 82),
             string_agg(
               migration.created_at::text || '@' || migration.migration_hash,
               ':' ORDER BY migration.created_at, migration.id
             )
      FROM ordered_migrations AS migration
      WHERE migration.migration_ordinal <= 82
    $query$;
    RETURN;
  END IF;
  RETURN QUERY SELECT 0::bigint, 0::bigint,
                      'UNSUPPORTED'::text, 'UNSUPPORTED'::text;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.schema_compatibility_v13() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v13()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v13()
  TO periapsis_api, periapsis_worker;--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.schema_compatibility_v12()
RETURNS TABLE (
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

ALTER FUNCTION app.schema_compatibility_v12() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.schema_compatibility_v12()
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.schema_compatibility_v12()
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
  IF p_expected_count IS DISTINCT FROM 90
     OR p_expected_latest_created_at IS DISTINCT FROM 1787672134042
     OR p_expected_latest_hash IS NULL
     OR p_expected_latest_hash !~ '^[0-9a-f]{64}$'
     OR p_expected_migration_fingerprint IS NULL
     OR p_expected_migration_fingerprint !~
          '^[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*$'
     OR cardinality(fingerprint_entries) IS DISTINCT FROM 90
     OR fingerprint_entries[90] IS DISTINCT FROM (
       p_expected_latest_created_at::text || '@' || p_expected_latest_hash
     ) THEN
    RAISE EXCEPTION 'invalid schema compatibility v14 manifest'
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
    1787672114811, 1787672134042
  ]::bigint[] THEN
    RAISE EXCEPTION 'invalid schema compatibility v14 timestamp sequence'
      USING ERRCODE = '22023';
  END IF;

  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO actual_count, actual_latest_created_at, actual_latest_hash,
       actual_fingerprint
  FROM app.schema_compatibility_v14() AS compatibility;
  IF actual_count IS DISTINCT FROM p_expected_count
     OR actual_latest_created_at IS DISTINCT FROM p_expected_latest_created_at
     OR actual_latest_hash IS DISTINCT FROM p_expected_latest_hash
     OR actual_fingerprint IS DISTINCT FROM p_expected_migration_fingerprint THEN
    RAISE EXCEPTION 'schema compatibility v14 manifest does not match the applied journal'
      USING ERRCODE = '55000';
  END IF;

  PERFORM set_config(
    'app.schema_compatibility_fingerprint',
    p_expected_migration_fingerprint, true
  );
  EXECUTE $statement$
    ALTER FUNCTION app.schema_compatibility_v13()
      SET app.schema_compatibility_fingerprint FROM CURRENT
  $statement$;
  expected_predecessor_hash := split_part(fingerprint_entries[82], '@', 2);
  expected_predecessor_fingerprint := array_to_string(
    fingerprint_entries[1:82], ':'
  );
  SELECT compatibility.applied_count, compatibility.latest_created_at,
         compatibility.latest_hash, compatibility.migration_fingerprint
  INTO predecessor_count, predecessor_latest_created_at,
       predecessor_latest_hash, predecessor_fingerprint
  FROM app.schema_compatibility_v13() AS compatibility;
  IF predecessor_count IS DISTINCT FROM 82
     OR predecessor_latest_created_at IS DISTINCT FROM 1787659623982
     OR predecessor_latest_hash IS DISTINCT FROM expected_predecessor_hash
     OR predecessor_fingerprint IS DISTINCT FROM expected_predecessor_fingerprint THEN
    RAISE EXCEPTION 'sealed schema compatibility v13 prefix is not exact'
      USING ERRCODE = '55000';
  END IF;
  SELECT compatibility.applied_count INTO retired_count
  FROM app.schema_compatibility_v12() AS compatibility;
  IF retired_count IS DISTINCT FROM 0 THEN
    RAISE EXCEPTION 'schema compatibility v12 must be retired'
      USING ERRCODE = '55000';
  END IF;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.seal_schema_compatibility_manifest(bigint, bigint, text, text)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint

CREATE FUNCTION app.phase4_schema_readiness_v1()
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  table_name text;
  table_owner text;
  row_rls boolean;
  force_rls boolean;
  expected_function record;
  function_oid regprocedure;
  function_owner text;
  function_security_definer boolean;
  function_configuration text[];
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'custom_field_definition_revisions',
    'custom_field_definitions',
    'custom_field_layouts',
    'custom_field_migrations',
    'custom_field_options',
    'custom_field_permissions',
    'custom_field_values',
    'dfir_activities',
    'dfir_asset_links',
    'dfir_assets',
    'dfir_attachments',
    'dfir_custody_events',
    'dfir_evidence',
    'dfir_ioc_links',
    'dfir_iocs',
    'dfir_relationships',
    'dfir_storage_objects',
    'dfir_tasks',
    'dfir_timeline_asset_links',
    'dfir_timeline_events',
    'dfir_timeline_evidence_links',
    'dfir_timeline_ioc_links'
  ] LOOP
    SELECT pg_get_userbyid(class.relowner), class.relrowsecurity,
           class.relforcerowsecurity
    INTO table_owner, row_rls, force_rls
    FROM pg_class AS class
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND class.relname = table_name
      AND class.relkind = 'r';
    IF NOT FOUND OR table_owner IS DISTINCT FROM 'periapsis_migrator'
       OR row_rls IS NOT TRUE
       OR force_rls IS NOT TRUE THEN
      RETURN false;
    END IF;
    IF NOT EXISTS (
      SELECT 1
      FROM pg_attribute AS attribute
      JOIN pg_class AS class ON class.oid = attribute.attrelid
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      WHERE namespace.nspname = 'public'
        AND class.relname = table_name
        AND attribute.attname = 'tenant_id'
        AND attribute.attnotnull
        AND NOT attribute.attisdropped
    ) THEN
      RETURN false;
    END IF;
    IF NOT has_table_privilege(
      'periapsis_api', format('public.%I', table_name), 'SELECT'
    ) THEN
      RETURN false;
    END IF;
    IF EXISTS (
      SELECT 1
      FROM pg_class AS class
      JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
      CROSS JOIN LATERAL aclexplode(
        coalesce(class.relacl, acldefault('r', class.relowner))
      ) AS privilege
      WHERE namespace.nspname = 'public'
        AND class.relname = table_name
        AND privilege.grantee = 0
        AND privilege.privilege_type IN (
          'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER'
        )
    ) THEN
      RETURN false;
    END IF;
  END LOOP;

  IF has_table_privilege('periapsis_api', 'public.dfir_evidence', 'INSERT')
     OR has_table_privilege('periapsis_api', 'public.dfir_evidence', 'UPDATE')
     OR has_table_privilege('periapsis_api', 'public.dfir_evidence', 'DELETE')
     OR has_table_privilege('periapsis_api', 'public.dfir_custody_events', 'INSERT')
     OR has_table_privilege('periapsis_api', 'public.dfir_activities', 'INSERT')
     OR has_table_privilege('periapsis_api', 'public.dfir_storage_objects', 'UPDATE')
     OR has_table_privilege('periapsis_worker', 'public.dfir_storage_objects', 'UPDATE')
     OR has_table_privilege('periapsis_worker', 'public.dfir_evidence', 'UPDATE')
     OR has_table_privilege('periapsis_worker', 'public.dfir_custody_events', 'INSERT') THEN
    RETURN false;
  END IF;

  FOR expected_function IN
    SELECT * FROM (VALUES
      ('app.private_current_dfir_scope_allows_v1(text,uuid)', false, false, 'search_path=pg_catalog, public, app', false),
      ('app.private_dfir_resource_belongs_to_case_v1(uuid,uuid,public.dfir_entity_kind,uuid)', false, false, 'search_path=pg_catalog, public, app', false),
      ('app.append_phase4_mutation_effects_v1(text,text,text,uuid,bigint,uuid,uuid,public.dfir_entity_kind,uuid,text,jsonb,jsonb,jsonb,uuid,uuid,uuid,uuid,inet,text,text)', true, false, 'search_path=pg_catalog, public, app', false),
      ('app.create_dfir_evidence_v1(uuid,uuid,uuid,text,text,text,public.dfir_evidence_classification,timestamp with time zone,text,timestamp with time zone,boolean,uuid,bytea,bytea,uuid,uuid,uuid,uuid,uuid,inet,text,text)', true, false, 'search_path=pg_catalog, public, app', false),
      ('app.append_dfir_custody_event_v1(uuid,bigint,uuid,public.dfir_custody_action,text,text,bytea,bytea,timestamp with time zone,uuid,uuid,uuid,uuid,uuid,inet,text,text)', true, false, 'search_path=pg_catalog, public, app', false),
      ('app.advance_dfir_storage_object_as_worker_v1(uuid,bigint,public.dfir_scan_state,bytea,bigint,text,timestamp with time zone,uuid,uuid,uuid,uuid)', false, true, 'search_path=pg_catalog, public, app', false),
      ('app.schema_compatibility_v14()', true, true, 'search_path=pg_catalog', false),
      ('app.schema_compatibility_v13()', true, true, 'search_path=pg_catalog', true),
      ('app.schema_compatibility_v12()', true, true, 'search_path=pg_catalog', false),
      ('app.seal_schema_compatibility_manifest(bigint,bigint,text,text)', false, false, 'search_path=pg_catalog', false)
    ) AS expected(
      signature, api_execute, worker_execute, expected_search_path,
      allow_fingerprint
    )
  LOOP
    function_oid := to_regprocedure(expected_function.signature);
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
       OR function_configuration[1] IS DISTINCT FROM expected_function.expected_search_path
       OR NOT expected_function.allow_fingerprint
          AND cardinality(function_configuration) IS DISTINCT FROM 1
       OR expected_function.allow_fingerprint
          AND (
            cardinality(function_configuration) IS DISTINCT FROM 2
            OR function_configuration[2] !~
               '^app\.schema_compatibility_fingerprint=(UNSEALED|[1-9][0-9]*@[0-9a-f]{64}(:[1-9][0-9]*@[0-9a-f]{64})*)$'
          ) THEN
      RETURN false;
    END IF;
    IF EXISTS (
         SELECT 1
         FROM pg_proc AS procedure
         CROSS JOIN LATERAL aclexplode(
           coalesce(procedure.proacl, acldefault('f', procedure.proowner))
         ) AS privilege
         WHERE procedure.oid = function_oid
           AND privilege.grantee = 0
           AND privilege.privilege_type = 'EXECUTE'
       )
       OR has_function_privilege('periapsis_api', function_oid, 'EXECUTE')
          IS DISTINCT FROM expected_function.api_execute
       OR has_function_privilege('periapsis_worker', function_oid, 'EXECUTE')
          IS DISTINCT FROM expected_function.worker_execute
       OR has_function_privilege('periapsis_notifier', function_oid, 'EXECUTE')
       OR has_function_privilege('periapsis_auditor', function_oid, 'EXECUTE') THEN
      RETURN false;
    END IF;
  END LOOP;

  IF (
    SELECT count(*)
    FROM public.tenant_permissions AS permission
    WHERE permission.key IN (
      'custom_field.read', 'custom_field.manage',
      'dfir.ioc.read', 'dfir.ioc.manage',
      'dfir.asset.read', 'dfir.asset.manage',
      'dfir.evidence.read', 'dfir.evidence.manage',
      'dfir.timeline.read', 'dfir.timeline.manage',
      'dfir.task.read', 'dfir.task.manage',
      'dfir.attachment.read', 'dfir.attachment.manage',
      'dfir.relationship.read', 'dfir.relationship.manage'
    )
  ) <> 16 THEN
    RETURN false;
  END IF;
  IF (
    SELECT count(*)
    FROM pg_trigger AS trigger
    JOIN pg_class AS class ON class.oid = trigger.tgrelid
    JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
    WHERE namespace.nspname = 'public'
      AND trigger.tgname IN (
        'custom_field_definitions_identity_v1',
        'custom_field_definition_revisions_immutable_v1',
        'custom_field_definition_revisions_validate_v1',
        'custom_field_options_identity_v1',
        'custom_field_migrations_identity_v1',
        'custom_field_values_validate_v1',
        'custom_field_values_identity_v1',
        'dfir_relationships_validate_v1',
        'dfir_storage_objects_identity_v1',
        'dfir_attachments_validate_v1',
        'dfir_tasks_assignment_validate_v1',
        'dfir_evidence_identity_v1',
        'dfir_custody_events_immutable_v1',
        'dfir_activities_immutable_v1'
      )
      AND NOT trigger.tgisinternal
  ) <> 14 THEN
    RETURN false;
  END IF;
  RETURN true;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.phase4_schema_readiness_v1() OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.phase4_schema_readiness_v1() FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.phase4_schema_readiness_v1() TO periapsis_api, periapsis_worker;--> statement-breakpoint

DO $phase4_readiness_assertion$
BEGIN
  IF NOT app.phase4_schema_readiness_v1() THEN
    RAISE EXCEPTION 'phase 4 schema readiness invariants are incomplete'
      USING ERRCODE = '55000';
  END IF;
END;
$phase4_readiness_assertion$;--> statement-breakpoint
