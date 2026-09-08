-- Ticket queries use the same canonical unpadded Base64 as saved views and Go.
-- Reuse the bounded strict codec for inline queries, saved queries and snapshots.
CREATE OR REPLACE FUNCTION app.private_ticket_bulk_query_document_v1(
  p_job public.ticket_bulk_jobs
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE snapshot public.ticket_bulk_query_snapshots%ROWTYPE;
BEGIN
  IF p_job.selection_source = 'explicit' THEN RETURN 'null'::jsonb; END IF;
  SELECT query.* INTO STRICT snapshot
  FROM public.ticket_bulk_query_snapshots AS query
  WHERE query.tenant_id = p_job.tenant_id AND query.job_id = p_job.id;
  RETURN jsonb_build_object(
    'source', snapshot.source,
    'specCanonicalBase64', app.private_ticket_saved_view_base64_v1(snapshot.spec_canonical),
    'querySha256', encode(snapshot.query_digest, 'hex'),
    'catalogSha256', encode(snapshot.catalog_digest, 'hex'),
    'savedView', CASE WHEN snapshot.source = 'inline' THEN 'null'::jsonb ELSE
      jsonb_build_object(
        'id', snapshot.saved_view_id,
        'ownerId', snapshot.saved_view_owner_id,
        'revision', snapshot.saved_view_revision,
        'specSha256', encode(snapshot.saved_view_digest, 'hex')
      ) END
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ticket_export_query_document_v1(
  p_job public.ticket_export_jobs
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE snapshot public.ticket_export_query_snapshots%ROWTYPE;
BEGIN
  SELECT query.* INTO STRICT snapshot
  FROM public.ticket_export_query_snapshots AS query
  WHERE query.tenant_id = p_job.tenant_id AND query.job_id = p_job.id;
  RETURN jsonb_build_object(
    'source', p_job.query_source,
    'specCanonicalBase64', app.private_ticket_saved_view_base64_v1(snapshot.spec_canonical),
    'querySha256', encode(snapshot.query_digest, 'hex'),
    'catalogSha256', encode(snapshot.catalog_digest, 'hex'),
    'savedView', CASE WHEN p_job.query_source = 'inline' THEN 'null'::jsonb ELSE
      jsonb_build_object(
        'id', p_job.saved_view_id,
        'ownerId', p_job.saved_view_owner_id,
        'revision', p_job.saved_view_revision,
        'specSha256', encode(p_job.saved_view_digest, 'hex')
      ) END
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.resolve_ticket_bulk_query_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  tenant_id uuid;
  actor_id uuid;
  owner_id uuid;
  kind public.ticket_aggregate_kind;
  source jsonb;
  source_mode text;
  view_record public.ticket_saved_views%ROWTYPE;
  resolved jsonb;
  spec_base64 text;
  spec_canonical text;
  query_digest bytea;
  catalog_digest bytea;
  saved_view jsonb := 'null'::jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY['schemaVersion','actor','tenantId','kind','membershipId','source']
     )
     OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'source') <> 'object' THEN
    RAISE EXCEPTION 'ticket bulk query request is invalid' USING ERRCODE = '22023';
  END IF;
  tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  owner_id := app.private_ticket_runtime_uuid_v1(request ->> 'membershipId');
  BEGIN kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk kind is invalid' USING ERRCODE = '22023';
  END;
  IF app.private_ticket_runtime_require_human_v1(request -> 'actor', tenant_id)
       IS DISTINCT FROM owner_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(
       app.private_ticket_runtime_permission_v1(kind, 'read')
     ) THEN
    RAISE EXCEPTION 'ticket bulk query authority is required' USING ERRCODE = '42501';
  END IF;
  actor_id := app.context_user_id();
  source := request -> 'source';
  source_mode := source ->> 'mode';
  IF source_mode = 'inline' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(source, ARRAY['mode','spec'])
       OR jsonb_typeof(source -> 'spec') <> 'object' THEN
      RAISE EXCEPTION 'inline ticket bulk source is invalid' USING ERRCODE = '22023';
    END IF;
    resolved := app.private_resolve_ticket_saved_view_spec_v1(source -> 'spec');
    spec_base64 := resolved ->> 'specCanonicalBase64';
  ELSIF source_mode = 'saved_view' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(
         source, ARRAY['mode','id','revision','specSha256']
       ) OR source ->> 'revision' !~ '^[1-9][0-9]{0,15}$' THEN
      RAISE EXCEPTION 'saved ticket bulk source is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT view.* INTO view_record
    FROM public.ticket_saved_views AS view
    WHERE view.tenant_id = tenant_id
      AND view.id = app.private_ticket_runtime_uuid_v1(source ->> 'id')
      AND view.owner_membership_id = owner_id
      AND view.aggregate_kind = kind
      AND view.status = 'active'
      AND view.revision = (source ->> 'revision')::bigint
      AND view.spec_digest = app.private_ticket_runtime_digest_v1(source ->> 'specSha256')
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'saved ticket bulk source is unavailable' USING ERRCODE = 'P0002';
    END IF;
    spec_canonical := view_record.spec_canonical;
    PERFORM app.private_ticket_saved_view_spec_pins_current_v1(
      tenant_id, actor_id, owner_id, kind, spec_canonical
    );
    spec_base64 := app.private_ticket_saved_view_base64_v1(spec_canonical);
    saved_view := jsonb_build_object(
      'id', view_record.id, 'ownerId', owner_id,
      'revision', view_record.revision,
      'specSha256', encode(view_record.spec_digest, 'hex')
    );
  ELSE
    RAISE EXCEPTION 'ticket bulk source mode is invalid' USING ERRCODE = '22023';
  END IF;
  IF spec_canonical IS NULL THEN
    BEGIN
      spec_canonical := app.private_ticket_saved_view_decode_base64_v1(spec_base64);
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'ticket bulk canonical source is invalid' USING ERRCODE = '55000';
    END;
  END IF;
  query_digest := sha256(convert_to(spec_canonical, 'UTF8'));
  catalog_digest := app.private_ticket_runtime_catalog_digest_v1(spec_canonical);
  RETURN QUERY SELECT jsonb_build_object(
    'schemaVersion', 1,
    'query', jsonb_build_object(
      'source', source_mode,
      'specCanonicalBase64', spec_base64,
      'querySha256', encode(query_digest, 'hex'),
      'catalogSha256', encode(catalog_digest, 'hex'),
      'savedView', saved_view
    )
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.commit_ticket_bulk_request_v1(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
SET TimeZone = 'UTC'
AS $function$
DECLARE
  request_tenant_id uuid;
  request_actor_id uuid;
  request_owner_id uuid;
  request_job_id uuid;
  request_kind public.ticket_aggregate_kind;
  requested_at timestamp with time zone;
  expires_at timestamp with time zone;
  key_digest bytea;
  fingerprint bytea;
  mutation_action text;
  permission_key text;
  explicit_targets jsonb;
  query_document jsonb;
  query_source text;
  query_spec text;
  query_digest bytea;
  catalog_digest bytea;
  saved_view_id uuid;
  saved_view_revision bigint;
  saved_view_digest bytea;
  target_count integer;
  target_digest bytea;
  result_document jsonb;
  prior public.ticket_bulk_command_receipts%ROWTYPE;
  target jsonb;
BEGIN
  IF request IS NULL OR pg_column_size(request) > 2097152
     OR NOT app.private_ticket_runtime_exact_keys_v1(
       request, ARRAY[
         'schemaVersion','actor','audit','tenantId','ownerMembershipId','kind',
         'requiredCapability','jobId','explicitTargets','query','mutation',
         'requestedAt','expiresAt','action','idempotencyKeySha256',
         'requestFingerprintSha256'
       ]
     ) OR request ->> 'schemaVersion' <> '1'
     OR jsonb_typeof(request -> 'actor') <> 'object'
     OR jsonb_typeof(request -> 'audit') <> 'object'
     OR NOT app.private_ticket_runtime_audit_is_valid_v1(request -> 'audit')
     OR request ->> 'requiredCapability' <> 'ticket.bulk.request'
     OR request ->> 'action' <> 'request'
     OR jsonb_typeof(request -> 'mutation') <> 'object'
     OR (jsonb_typeof(request -> 'explicitTargets') = 'array')
        = (jsonb_typeof(request -> 'query') = 'object') THEN
    RAISE EXCEPTION 'ticket bulk request command is invalid' USING ERRCODE = '22023';
  END IF;
  request_tenant_id := app.private_ticket_runtime_uuid_v1(request ->> 'tenantId');
  request_owner_id := app.private_ticket_runtime_uuid_v1(request ->> 'ownerMembershipId');
  request_job_id := app.private_ticket_runtime_uuid_v1(request ->> 'jobId');
  BEGIN request_kind := (request ->> 'kind')::public.ticket_aggregate_kind;
  EXCEPTION WHEN invalid_text_representation THEN
    RAISE EXCEPTION 'ticket bulk request kind is invalid' USING ERRCODE = '22023';
  END;
  requested_at := app.private_ticket_runtime_instant_v1(request -> 'requestedAt');
  expires_at := app.private_ticket_runtime_instant_v1(request -> 'expiresAt');
  key_digest := app.private_ticket_runtime_digest_v1(request ->> 'idempotencyKeySha256');
  fingerprint := app.private_ticket_runtime_digest_v1(request ->> 'requestFingerprintSha256');
  mutation_action := app.private_ticket_bulk_validate_mutation_v1(request -> 'mutation');
  permission_key := app.private_ticket_runtime_permission_v1(request_kind, mutation_action);
  IF app.private_ticket_runtime_require_human_v1(
       request -> 'actor', request_tenant_id
     ) IS DISTINCT FROM request_owner_id
     OR NOT app.private_ticket_runtime_has_any_scope_v1(permission_key) THEN
    RAISE EXCEPTION 'ticket bulk request authority is required' USING ERRCODE = '42501';
  END IF;
  request_actor_id := app.context_user_id();
  SELECT receipt.* INTO prior
  FROM public.ticket_bulk_command_receipts AS receipt
  WHERE receipt.tenant_id = request_tenant_id
    AND receipt.actor_user_id = request_actor_id
    AND receipt.owner_membership_id = request_owner_id
    AND receipt.kind = request_kind
    AND receipt.action = 'request'
    AND receipt.idempotency_key_digest = key_digest;
  IF FOUND THEN
    IF prior.request_fingerprint_digest IS DISTINCT FROM fingerprint THEN
      RAISE EXCEPTION 'ticket bulk command replay payload mismatch'
        USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT jsonb_set(
      prior.result_snapshot, '{replayed}', 'true'::jsonb, false
    );
    RETURN;
  END IF;
  IF requested_at < transaction_timestamp() - interval '5 minutes'
     OR requested_at > transaction_timestamp() + interval '1 minute'
     OR expires_at - requested_at < interval '5 minutes'
     OR expires_at - requested_at > interval '30 days' THEN
    RAISE EXCEPTION 'ticket bulk request retention is invalid' USING ERRCODE = '22023';
  END IF;
  PERFORM set_config('app.ticket_runtime_write_v1', 'enabled', true);
  explicit_targets := request -> 'explicitTargets';
  query_document := request -> 'query';
  IF jsonb_typeof(explicit_targets) = 'array' THEN
    target_count := jsonb_array_length(explicit_targets);
    IF target_count NOT BETWEEN 1 AND 1000 THEN
      RAISE EXCEPTION 'ticket bulk explicit target count is invalid' USING ERRCODE = '22023';
    END IF;
  ELSE
    IF NOT app.private_ticket_runtime_exact_keys_v1(
       query_document, ARRAY[
         'source','specCanonicalBase64','querySha256','catalogSha256','savedView'
       ]
    ) OR query_document ->> 'source' NOT IN ('inline','saved_view') THEN
      RAISE EXCEPTION 'ticket bulk query snapshot is invalid' USING ERRCODE = '22023';
    END IF;
    BEGIN
      query_spec := app.private_ticket_saved_view_decode_base64_v1(query_document ->> 'specCanonicalBase64');
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'ticket bulk query snapshot is invalid' USING ERRCODE = '22023';
    END;
    IF octet_length(query_spec) NOT BETWEEN 1 AND 262144 THEN
      RAISE EXCEPTION 'ticket bulk query snapshot is invalid' USING ERRCODE = '22023';
    END IF;
    query_digest := app.private_ticket_runtime_digest_v1(query_document ->> 'querySha256');
    catalog_digest := app.private_ticket_runtime_digest_v1(query_document ->> 'catalogSha256');
    IF sha256(convert_to(query_spec, 'UTF8')) IS DISTINCT FROM query_digest
       OR app.private_ticket_runtime_catalog_digest_v1(query_spec) IS DISTINCT FROM catalog_digest THEN
      RAISE EXCEPTION 'ticket bulk query snapshot digest is stale' USING ERRCODE = '40001';
    END IF;
    query_source := query_document ->> 'source';
    IF query_source = 'inline' THEN
      IF query_document -> 'savedView' <> 'null'::jsonb THEN
        RAISE EXCEPTION 'ticket bulk inline snapshot is invalid' USING ERRCODE = '22023';
      END IF;
    ELSE
      IF NOT app.private_ticket_runtime_exact_keys_v1(
        query_document -> 'savedView', ARRAY['id','ownerId','revision','specSha256']
      ) THEN
        RAISE EXCEPTION 'ticket bulk saved-view snapshot is invalid' USING ERRCODE = '22023';
      END IF;
      saved_view_id := app.private_ticket_runtime_uuid_v1(query_document #>> '{savedView,id}');
      IF app.private_ticket_runtime_uuid_v1(query_document #>> '{savedView,ownerId}')
           IS DISTINCT FROM request_owner_id THEN
        RAISE EXCEPTION 'ticket bulk saved-view owner is invalid' USING ERRCODE = '42501';
      END IF;
      saved_view_revision := app.private_ticket_runtime_js_uint_v1(
        query_document #> '{savedView,revision}', 1, 9007199254740991
      );
      saved_view_digest := app.private_ticket_runtime_digest_v1(
        query_document #>> '{savedView,specSha256}'
      );
      PERFORM 1 FROM public.ticket_saved_views AS view
      WHERE view.tenant_id = request_tenant_id AND view.id = saved_view_id
        AND view.owner_membership_id = request_owner_id
        AND view.aggregate_kind = request_kind AND view.status = 'active'
        AND view.revision = saved_view_revision
        AND view.spec_digest = saved_view_digest
      FOR SHARE;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'ticket bulk saved-view snapshot is stale' USING ERRCODE = '40001';
      END IF;
    END IF;
  END IF;
  INSERT INTO public.ticket_bulk_jobs(
    id, tenant_id, requester_user_id, owner_membership_id, kind,
    selection_source, mutation, target_set_digest, query_digest,
    catalog_digest, saved_view_id, saved_view_revision, saved_view_digest,
    projection_version, maximum_attempts, state, revision, total,
    requested_at, updated_at, available_at, expires_at, active_batch
  ) VALUES (
    request_job_id, request_tenant_id, request_actor_id, request_owner_id,
    request_kind, CASE WHEN jsonb_typeof(explicit_targets) = 'array'
      THEN 'explicit' ELSE 'query' END,
    request -> 'mutation', decode(repeat('00', 32), 'hex'),
    query_digest, catalog_digest, saved_view_id, saved_view_revision,
    saved_view_digest, 1, 5, 'pending', 1, 1,
    requested_at, requested_at, requested_at, expires_at, false
  );
  IF jsonb_typeof(explicit_targets) = 'array' THEN
    FOR target IN SELECT value FROM jsonb_array_elements(explicit_targets) AS element(value)
    LOOP
      IF NOT app.private_ticket_runtime_exact_keys_v1(target, ARRAY['id','version']) THEN
        RAISE EXCEPTION 'ticket bulk explicit target is invalid' USING ERRCODE = '22023';
      END IF;
      PERFORM app.private_ticket_runtime_uuid_v1(target ->> 'id');
      PERFORM app.private_ticket_runtime_js_uint_v1(
        target -> 'version', 1, 9007199254740991
      );
    END LOOP;
    IF (SELECT count(DISTINCT value ->> 'id')
        FROM jsonb_array_elements(explicit_targets) AS element(value)) <> target_count THEN
      RAISE EXCEPTION 'ticket bulk explicit targets are duplicated' USING ERRCODE = '22023';
    END IF;
    IF request_kind = 'alert' THEN
      INSERT INTO public.ticket_bulk_targets(
        tenant_id, job_id, sequence, target_id, target_version
      )
      SELECT request_tenant_id, request_job_id,
        row_number() OVER (ORDER BY alert.id)::integer, alert.id, alert.version
      FROM public.alerts AS alert
      JOIN jsonb_array_elements(explicit_targets) AS element(value)
        ON alert.id = (element.value ->> 'id')::uuid
       AND alert.version = (element.value ->> 'version')::bigint
      WHERE alert.tenant_id = request_tenant_id AND alert.deleted_at IS NULL
        AND app.private_current_ticket_scope_allows_v1(
          permission_key, alert.assigned_team_id, alert.created_by,
          alert.assignee_user_id, alert.claimed_by_user_id
        )
      ORDER BY alert.id;
    ELSE
      INSERT INTO public.ticket_bulk_targets(
        tenant_id, job_id, sequence, target_id, target_version
      )
      SELECT request_tenant_id, request_job_id,
        row_number() OVER (ORDER BY case_row.id)::integer,
        case_row.id, case_row.version
      FROM public.cases AS case_row
      JOIN jsonb_array_elements(explicit_targets) AS element(value)
        ON case_row.id = (element.value ->> 'id')::uuid
       AND case_row.version = (element.value ->> 'version')::bigint
      WHERE case_row.tenant_id = request_tenant_id
        AND app.private_current_ticket_scope_allows_v1(
          permission_key, case_row.assigned_team_id, case_row.created_by_user_id,
          case_row.assignee_user_id, case_row.claimed_by_user_id
        )
      ORDER BY case_row.id;
    END IF;
    GET DIAGNOSTICS target_count = ROW_COUNT;
    IF target_count <> jsonb_array_length(explicit_targets) THEN
      RAISE EXCEPTION 'ticket bulk targets are unavailable' USING ERRCODE = '42501';
    END IF;
  ELSE
    INSERT INTO public.ticket_bulk_query_snapshots(
      tenant_id, job_id, source, spec_canonical, query_digest, catalog_digest,
      saved_view_id, saved_view_owner_id, saved_view_revision, saved_view_digest
    ) VALUES (
      request_tenant_id, request_job_id, query_source, query_spec,
      query_digest, catalog_digest, saved_view_id,
      CASE WHEN saved_view_id IS NULL THEN NULL ELSE request_owner_id END,
      saved_view_revision, saved_view_digest
    );
    target_count := app.private_ticket_bulk_materialize_query_v1(
      request_tenant_id, request_job_id, request_kind, permission_key, query_spec
    );
  END IF;
  target_digest := app.private_ticket_bulk_target_set_digest_v1(
    request_tenant_id, request_job_id
  );
  UPDATE public.ticket_bulk_jobs
  SET total = target_count, target_set_digest = target_digest
  WHERE tenant_id = request_tenant_id AND id = request_job_id;
  result_document := jsonb_build_object(
    'schemaVersion', 1,
    'replayed', false,
    'requestFingerprintSha256', encode(fingerprint, 'hex'),
    'record', app.private_ticket_bulk_record_v1(request_job_id)
  );
  INSERT INTO public.ticket_bulk_command_receipts(
    tenant_id, job_id, actor_user_id, owner_membership_id, kind, action,
    idempotency_key_digest, request_fingerprint_digest, result_snapshot,
    created_at, expires_at
  ) VALUES (
    request_tenant_id, request_job_id, request_actor_id, request_owner_id,
    request_kind, 'request', key_digest, fingerprint, result_document,
    requested_at, expires_at
  );
  PERFORM app.private_ticket_runtime_append_human_effects_v1(
    request_tenant_id, request -> 'actor', request -> 'audit',
    'ticket.bulk.requested', 'ticket_bulk_job', request_job_id, 1,
    requested_at, jsonb_build_object(
      'kind', request_kind,
      'selectionSource', CASE WHEN jsonb_typeof(explicit_targets) = 'array'
        THEN 'explicit' ELSE 'query' END,
      'targetCount', target_count,
      'mutationAction', mutation_action,
      'targetSetSha256', encode(target_digest, 'hex')
    )
  );
  RETURN QUERY SELECT result_document;
EXCEPTION WHEN unique_violation THEN
  SELECT receipt.* INTO prior
  FROM public.ticket_bulk_command_receipts AS receipt
  WHERE receipt.tenant_id = request_tenant_id
    AND receipt.actor_user_id = request_actor_id
    AND receipt.owner_membership_id = request_owner_id
    AND receipt.kind = request_kind
    AND receipt.action = 'request'
    AND receipt.idempotency_key_digest = key_digest;
  IF FOUND AND prior.request_fingerprint_digest = fingerprint THEN
    RETURN QUERY SELECT jsonb_set(
      prior.result_snapshot, '{replayed}', 'true'::jsonb, false
    );
    RETURN;
  END IF;
  RAISE EXCEPTION 'ticket bulk command replay payload mismatch'
    USING ERRCODE = '23505';
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ticket_export_resolve_query_v1(
  p_actor jsonb,
  p_tenant_id uuid,
  p_owner_id uuid,
  p_kind public.ticket_aggregate_kind,
  p_audience text,
  p_source jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  authority record;
  source_mode text;
  view_record public.ticket_saved_views%ROWTYPE;
  resolved jsonb;
  spec_base64 text;
  spec_canonical text;
  query_digest bytea;
  catalog_digest bytea;
  saved_view jsonb := 'null'::jsonb;
BEGIN
  SELECT admitted.* INTO STRICT authority
  FROM app.private_ticket_export_require_human_v1(
    p_actor, p_tenant_id, p_kind, p_audience, 'ticket_export.read'
  ) AS admitted;
  IF authority.membership_id IS DISTINCT FROM p_owner_id
     OR jsonb_typeof(p_source) <> 'object' THEN
    RAISE EXCEPTION 'ticket export query authority is required' USING ERRCODE = '42501';
  END IF;
  source_mode := p_source ->> 'mode';
  IF source_mode = 'inline' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(p_source, ARRAY['mode','spec'])
       OR jsonb_typeof(p_source -> 'spec') <> 'object' THEN
      RAISE EXCEPTION 'inline ticket export source is invalid' USING ERRCODE = '22023';
    END IF;
    resolved := app.private_resolve_ticket_saved_view_spec_v1(p_source -> 'spec');
    spec_base64 := resolved ->> 'specCanonicalBase64';
  ELSIF source_mode = 'saved_view' AND p_audience = 'operator' THEN
    IF NOT app.private_ticket_runtime_exact_keys_v1(
         p_source, ARRAY['mode','id','revision','specSha256']
       ) THEN
      RAISE EXCEPTION 'saved ticket export source is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT view.* INTO view_record
    FROM public.ticket_saved_views AS view
    WHERE view.tenant_id = p_tenant_id
      AND view.id = app.private_ticket_runtime_uuid_v1(p_source ->> 'id')
      AND view.owner_membership_id = p_owner_id
      AND view.aggregate_kind = p_kind
      AND view.status = 'active'
      AND view.revision = app.private_ticket_runtime_js_uint_v1(
        p_source -> 'revision', 1, 9007199254740991
      )
      AND view.spec_digest = app.private_ticket_runtime_digest_v1(
        p_source ->> 'specSha256'
      )
    FOR SHARE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'saved ticket export source is unavailable' USING ERRCODE = 'P0002';
    END IF;
    spec_canonical := view_record.spec_canonical;
    PERFORM app.private_ticket_saved_view_spec_pins_current_v1(
      p_tenant_id, authority.actor_id, p_owner_id, p_kind, spec_canonical
    );
    spec_base64 := app.private_ticket_saved_view_base64_v1(spec_canonical);
    saved_view := jsonb_build_object(
      'id', view_record.id, 'ownerId', p_owner_id,
      'revision', view_record.revision,
      'specSha256', encode(view_record.spec_digest, 'hex')
    );
  ELSE
    RAISE EXCEPTION 'ticket export source mode is invalid' USING ERRCODE = '22023';
  END IF;
  IF spec_canonical IS NULL THEN
    BEGIN spec_canonical := app.private_ticket_saved_view_decode_base64_v1(spec_base64);
    EXCEPTION WHEN OTHERS THEN
      RAISE EXCEPTION 'ticket export canonical source is invalid' USING ERRCODE = '55000';
    END;
  END IF;
  IF p_audience = 'customer' AND (
       (spec_canonical::jsonb #>> '{filters,customerVisible}') IS DISTINCT FROM 'true'
       OR source_mode <> 'inline'
     ) THEN
    RAISE EXCEPTION 'customer ticket export query is not customer-safe'
      USING ERRCODE = '42501';
  END IF;
  query_digest := sha256(convert_to(spec_canonical, 'UTF8'));
  catalog_digest := app.private_ticket_runtime_catalog_digest_v1(spec_canonical);
  RETURN jsonb_build_object(
    'source', source_mode,
    'specCanonicalBase64', spec_base64,
    'querySha256', encode(query_digest, 'hex'),
    'catalogSha256', encode(catalog_digest, 'hex'),
    'savedView', saved_view
  );
END;
$function$;
--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.private_ticket_export_query_input_v1(p_query jsonb)
RETURNS TABLE(
  source text,
  spec_canonical text,
  query_digest bytea,
  catalog_digest bytea,
  saved_view_id uuid,
  saved_view_owner_id uuid,
  saved_view_revision bigint,
  saved_view_digest bytea
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE saved_view jsonb;
BEGIN
  IF NOT app.private_ticket_runtime_exact_keys_v1(
       p_query, ARRAY[
         'source','specCanonicalBase64','querySha256','catalogSha256','savedView'
       ]
     ) OR p_query ->> 'source' NOT IN ('inline','saved_view')
     OR jsonb_typeof(p_query -> 'specCanonicalBase64') <> 'string'
     OR jsonb_typeof(p_query -> 'querySha256') <> 'string'
     OR jsonb_typeof(p_query -> 'catalogSha256') <> 'string'
     OR jsonb_typeof(p_query -> 'savedView') NOT IN ('null','object') THEN
    RAISE EXCEPTION 'ticket export query projection is invalid' USING ERRCODE = '22023';
  END IF;
  source := p_query ->> 'source';
  BEGIN
    spec_canonical := app.private_ticket_saved_view_decode_base64_v1(p_query ->> 'specCanonicalBase64');
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'ticket export canonical query is invalid' USING ERRCODE = '22023';
  END;
  IF octet_length(spec_canonical) NOT BETWEEN 1 AND 262144
     OR jsonb_typeof(spec_canonical::jsonb) <> 'object'
     OR jsonb_array_length(spec_canonical::jsonb -> 'columns') NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'ticket export canonical query is invalid' USING ERRCODE = '22023';
  END IF;
  query_digest := app.private_ticket_runtime_digest_v1(p_query ->> 'querySha256');
  catalog_digest := app.private_ticket_runtime_digest_v1(p_query ->> 'catalogSha256');
  IF query_digest IS DISTINCT FROM sha256(convert_to(spec_canonical, 'UTF8'))
     OR catalog_digest IS DISTINCT FROM
        app.private_ticket_runtime_catalog_digest_v1(spec_canonical) THEN
    RAISE EXCEPTION 'ticket export query digest is stale' USING ERRCODE = '40001';
  END IF;
  saved_view := p_query -> 'savedView';
  IF source = 'inline' THEN
    IF saved_view <> 'null'::jsonb THEN
      RAISE EXCEPTION 'inline ticket export saved view is invalid' USING ERRCODE = '22023';
    END IF;
  ELSE
    IF jsonb_typeof(saved_view) <> 'object'
       OR NOT app.private_ticket_runtime_exact_keys_v1(
         saved_view, ARRAY['id','ownerId','revision','specSha256']
       ) THEN
      RAISE EXCEPTION 'saved ticket export pin is invalid' USING ERRCODE = '22023';
    END IF;
    saved_view_id := app.private_ticket_runtime_uuid_v1(saved_view ->> 'id');
    saved_view_owner_id := app.private_ticket_runtime_uuid_v1(saved_view ->> 'ownerId');
    saved_view_revision := app.private_ticket_runtime_js_uint_v1(
      saved_view -> 'revision', 1, 9007199254740991
    );
    saved_view_digest := app.private_ticket_runtime_digest_v1(
      saved_view ->> 'specSha256'
    );
  END IF;
  RETURN NEXT;
END;
$function$;
--> statement-breakpoint

-- Service-specific projections perform the full release attestation once per
-- invocation. These functions are themselves included in the V59 catalog hash.
-- V59 does not exist until the next migration: this interval fails closed.
CREATE FUNCTION app.api_runtime_schema_readiness_v59()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v59();
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
ALTER FUNCTION app.api_runtime_schema_readiness_v59() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.api_runtime_schema_readiness_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.api_runtime_schema_readiness_v59()
  TO periapsis_migrator,periapsis_api;
--> statement-breakpoint
CREATE FUNCTION app.worker_runtime_schema_readiness_v59()
RETURNS boolean[]
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
DECLARE
  release_ready boolean;
BEGIN
  release_ready := app.release_runtime_schema_readiness_v59();
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
ALTER FUNCTION app.worker_runtime_schema_readiness_v59() OWNER TO periapsis_migrator;
REVOKE ALL ON FUNCTION app.worker_runtime_schema_readiness_v59()
  FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,periapsis_auditor;
GRANT EXECUTE ON FUNCTION app.worker_runtime_schema_readiness_v59()
  TO periapsis_migrator,periapsis_worker;
--> statement-breakpoint

--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.lookup_ticket_export_replay_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
DECLARE
  legacy_response jsonb;
  job public.ticket_export_jobs%ROWTYPE;
BEGIN
  SELECT legacy.response INTO legacy_response
  FROM app.lookup_ticket_export_replay_v1(request) AS legacy;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id=app.context_tenant_id()
    AND candidate.id=(legacy_response #>> '{record,job,definition,id}')::uuid;
  IF NOT FOUND OR NOT app.private_ticket_export_requester_live_v2(job) THEN
    RAISE EXCEPTION 'ticket export replay authority is required'
      USING ERRCODE='42501';
  END IF;
  RETURN QUERY SELECT legacy_response;
END;
$function$;

--> statement-breakpoint

CREATE OR REPLACE FUNCTION app.get_ticket_export_v2(request jsonb)
RETURNS TABLE(response jsonb)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER
SET search_path=pg_catalog,public,app
SET TimeZone='UTC'
AS $function$
DECLARE
  legacy_response jsonb;
  job public.ticket_export_jobs%ROWTYPE;
BEGIN
  SELECT legacy.response INTO legacy_response
  FROM app.get_ticket_export_v1(request) AS legacy;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT candidate.* INTO job
  FROM public.ticket_export_jobs AS candidate
  WHERE candidate.tenant_id=app.context_tenant_id()
    AND candidate.id=(legacy_response #>> '{record,job,definition,id}')::uuid;
  IF NOT FOUND OR NOT app.private_ticket_export_requester_live_v2(job) THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT legacy_response;
END;
$function$;
