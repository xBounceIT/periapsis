CREATE TABLE "dfir_attachment_case_links" (
	"id" uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
	"tenant_id" uuid NOT NULL,
	"attachment_id" uuid NOT NULL,
	"case_id" uuid NOT NULL,
	"source_alert_id" uuid NOT NULL,
	"source_alert_version" integer NOT NULL,
	"escalation_link_id" uuid NOT NULL,
	"created_by_membership_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "dfir_attachment_case_links_tenant_id_key" UNIQUE("tenant_id","id"),
	CONSTRAINT "dfir_attachment_case_links_exact_key" UNIQUE("tenant_id","attachment_id","case_id"),
	CONSTRAINT "dfir_attachment_case_links_id_uuidv7_check" CHECK ((uuid_extract_version("dfir_attachment_case_links"."id") = 7) is true),
	CONSTRAINT "dfir_attachment_case_links_source_version_check" CHECK ("dfir_attachment_case_links"."source_alert_version" > 0)
);
--> statement-breakpoint
ALTER TABLE "dfir_attachment_case_links" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "dfir_attachment_case_links" ADD CONSTRAINT "dfir_attachment_case_links_tenant_id_tenants_id_fk" FOREIGN KEY ("tenant_id") REFERENCES "public"."tenants"("id") ON DELETE restrict ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "dfir_attachment_case_links" ADD CONSTRAINT "dfir_attachment_case_links_attachment_fk" FOREIGN KEY ("tenant_id","attachment_id") REFERENCES "public"."dfir_attachments"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachment_case_links" ADD CONSTRAINT "dfir_attachment_case_links_case_fk" FOREIGN KEY ("tenant_id","case_id") REFERENCES "public"."cases"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachment_case_links" ADD CONSTRAINT "dfir_attachment_case_links_source_alert_fk" FOREIGN KEY ("tenant_id","source_alert_id") REFERENCES "public"."alerts"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachment_case_links" ADD CONSTRAINT "dfir_attachment_case_links_escalation_fk" FOREIGN KEY ("tenant_id","escalation_link_id") REFERENCES "public"."alert_case_links"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
ALTER TABLE "dfir_attachment_case_links" ADD CONSTRAINT "dfir_attachment_case_links_creator_fk" FOREIGN KEY ("tenant_id","created_by_membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id") ON DELETE restrict ON UPDATE cascade;--> statement-breakpoint
CREATE INDEX "dfir_attachment_case_links_case_idx" ON "dfir_attachment_case_links" USING btree ("tenant_id","case_id","created_at","id");--> statement-breakpoint
CREATE POLICY "dfir_attachment_case_links_api_tenant" ON "dfir_attachment_case_links" AS PERMISSIVE FOR SELECT TO "periapsis_api" USING (
  "dfir_attachment_case_links"."tenant_id" = nullif(current_setting('app.tenant_id', true), '')::uuid
  and app.tenant_is_active_v1("dfir_attachment_case_links"."tenant_id")
  and exists (
    select 1
    from "tenant_memberships"
    where "tenant_memberships"."tenant_id" = "dfir_attachment_case_links"."tenant_id"
      and "tenant_memberships"."user_id" = nullif(current_setting('app.user_id', true), '')::uuid
      and "tenant_memberships"."status" = 'active'
  )
);
--> statement-breakpoint

ALTER TABLE public.dfir_attachment_case_links FORCE ROW LEVEL SECURITY;
--> statement-breakpoint
ALTER TABLE public.dfir_attachment_case_links OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON TABLE public.dfir_attachment_case_links
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT SELECT ON TABLE public.dfir_attachment_case_links TO periapsis_api;
--> statement-breakpoint
CREATE TRIGGER dfir_attachment_case_links_immutable_v1
BEFORE UPDATE OR DELETE ON public.dfir_attachment_case_links
FOR EACH ROW EXECUTE FUNCTION app.guard_phase4_append_only_v1();
--> statement-breakpoint

CREATE FUNCTION app.private_current_alert_dfir_scope_allows_v1(
  p_permission_key text,
  p_alert_id uuid
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
  target_alert public.alerts%ROWTYPE;
BEGIN
  IF p_permission_key NOT IN (
       'dfir.ioc.read', 'dfir.asset.read', 'dfir.attachment.read'
     ) OR p_alert_id IS NULL THEN
    RETURN false;
  END IF;
  SELECT alert.* INTO target_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant
    AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  IF app.current_tenant_human_has_exact_permission_v3(
    p_permission_key, 'tenant'
  ) THEN
    RETURN true;
  END IF;
  IF app.current_tenant_human_has_exact_permission_v3(
       p_permission_key, 'assigned'
     ) AND actor_user IN (
       target_alert.assignee_user_id, target_alert.claimed_by_user_id
     ) THEN
    RETURN true;
  END IF;
  RETURN target_alert.assigned_team_id IS NOT NULL
    AND target_alert.assigned_team_epoch_id IS NOT NULL
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
        AND assignment.id = target_alert.assigned_team_epoch_id
        AND assignment.operator_team_id = target_alert.assigned_team_id
        AND assignment.ended_at IS NULL
        AND roster.membership_id = actor_membership
        AND roster.revoked_at IS NULL
        AND (roster.expires_at IS NULL
          OR roster.expires_at > transaction_timestamp())
        AND source.retired_at IS NULL
    );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.private_current_alert_dfir_scope_allows_v1(text, uuid)
  OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_current_alert_dfir_scope_allows_v1(text, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint

CREATE FUNCTION app.commit_tenant_ticket_escalation_v3(
  p_path_alert_id uuid,
  p_case_id uuid,
  p_create_case boolean,
  p_target jsonb,
  p_sources jsonb,
  p_relation text,
  p_reason text,
  p_key_digest bytea,
  p_request_digest bytea,
  p_effects text[],
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE (
  result_case_id uuid,
  result_case_version integer,
  result_path_alert_version integer,
  result_metadata jsonb,
  replayed boolean
)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
#variable_conflict use_variable
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  source_value jsonb;
  source_items jsonb;
  selected_fields text[];
  selected_iocs uuid[];
  selected_assets uuid[];
  selected_attachments uuid[];
  selected_contacts uuid[];
  sanitized_fields text[];
  sanitized_items jsonb;
  sanitized_sources jsonb := '[]'::jsonb;
  source_alert public.alerts%ROWTYPE;
  replay_command public.ticket_commands%ROWTYPE;
  committed_case_id uuid;
  committed_case_version integer;
  committed_path_version integer;
  committed_metadata jsonb;
  was_replayed boolean;
  matching_rows integer;
  affected_rows integer;
  link_id uuid;
  dfir_count integer;
BEGIN
  IF p_sources IS NULL OR jsonb_typeof(p_sources) <> 'array'
     OR jsonb_array_length(p_sources) NOT BETWEEN 1 AND 100
     OR pg_column_size(p_sources) > 1048576
     OR p_path_alert_id IS NULL OR uuid_extract_version(p_path_alert_id) <> 7
     OR p_case_id IS NULL OR uuid_extract_version(p_case_id) <> 7
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32 THEN
    RAISE EXCEPTION 'DFIR escalation request is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':ticket.escalate:' || encode(p_key_digest, 'hex'), 0
  ));

  FOR source_value IN
    SELECT source.value
    FROM jsonb_array_elements(p_sources) WITH ORDINALITY
         AS source(value, ordinal)
    ORDER BY source.ordinal
  LOOP
    IF jsonb_typeof(source_value) <> 'object'
       OR jsonb_typeof(source_value -> 'copyFields') <> 'array'
       OR jsonb_typeof(source_value -> 'itemIds') <> 'object'
       OR source_value ->> 'alertId' IS NULL
       OR uuid_extract_version((source_value ->> 'alertId')::uuid) <> 7 THEN
      RAISE EXCEPTION 'DFIR escalation source is invalid'
        USING ERRCODE = '22023';
    END IF;
    source_items := source_value -> 'itemIds';
    IF source_items - ARRAY[
         'iocIds', 'assetIds', 'attachmentIds', 'contactIds'
       ]::text[] <> '{}'::jsonb
       OR EXISTS (
         SELECT 1
         FROM jsonb_each(source_items) AS item(key, value)
         WHERE jsonb_typeof(item.value) <> 'array'
       ) THEN
      RAISE EXCEPTION 'DFIR escalation item selection is unsupported'
        USING ERRCODE = '22023';
    END IF;

    selected_fields := ARRAY(
      SELECT field.value
      FROM jsonb_array_elements_text(source_value -> 'copyFields')
           AS field(value)
      ORDER BY field.value COLLATE "C"
    );
    selected_iocs := ARRAY(
      SELECT item.value::uuid
      FROM jsonb_array_elements_text(
        coalesce(source_items -> 'iocIds', '[]'::jsonb)
      ) AS item(value)
      ORDER BY item.value::uuid
    );
    selected_assets := ARRAY(
      SELECT item.value::uuid
      FROM jsonb_array_elements_text(
        coalesce(source_items -> 'assetIds', '[]'::jsonb)
      ) AS item(value)
      ORDER BY item.value::uuid
    );
    selected_attachments := ARRAY(
      SELECT item.value::uuid
      FROM jsonb_array_elements_text(
        coalesce(source_items -> 'attachmentIds', '[]'::jsonb)
      ) AS item(value)
      ORDER BY item.value::uuid
    );
    selected_contacts := ARRAY(
      SELECT item.value::uuid
      FROM jsonb_array_elements_text(
        coalesce(source_items -> 'contactIds', '[]'::jsonb)
      ) AS item(value)
      ORDER BY item.value::uuid
    );

    IF source_value -> 'copyFields' IS DISTINCT FROM to_jsonb(selected_fields)
       OR cardinality(selected_fields) <> (
         SELECT count(DISTINCT field.value)
         FROM unnest(selected_fields) AS field(value)
       )
       OR EXISTS (
         SELECT 1 FROM unnest(selected_fields) AS field(value)
         WHERE field.value NOT IN (
           'title', 'description', 'severity', 'priority', 'category',
           'tags', 'custom_fields', 'iocs', 'assets', 'attachments',
           'contacts', 'public_comments'
         )
       )
       OR cardinality(selected_iocs) > 100
       OR cardinality(selected_assets) > 100
       OR cardinality(selected_attachments) > 100
       OR cardinality(selected_contacts) > 100
       OR EXISTS (
         SELECT 1
         FROM unnest(
           selected_iocs || selected_assets || selected_attachments
             || selected_contacts
         ) AS selected(id)
         WHERE uuid_extract_version(selected.id) <> 7
       )
       OR cardinality(selected_iocs) <> (
         SELECT count(DISTINCT selected.id)
         FROM unnest(selected_iocs) AS selected(id)
       )
       OR cardinality(selected_assets) <> (
         SELECT count(DISTINCT selected.id)
         FROM unnest(selected_assets) AS selected(id)
       )
       OR cardinality(selected_attachments) <> (
         SELECT count(DISTINCT selected.id)
         FROM unnest(selected_attachments) AS selected(id)
       )
       OR cardinality(selected_contacts) <> (
         SELECT count(DISTINCT selected.id)
         FROM unnest(selected_contacts) AS selected(id)
       )
       OR source_items ? 'iocIds'
          AND source_items -> 'iocIds' IS DISTINCT FROM to_jsonb(selected_iocs)
       OR source_items ? 'assetIds'
          AND source_items -> 'assetIds' IS DISTINCT FROM to_jsonb(selected_assets)
       OR source_items ? 'attachmentIds'
          AND source_items -> 'attachmentIds' IS DISTINCT FROM
              to_jsonb(selected_attachments)
       OR source_items ? 'contactIds'
          AND source_items -> 'contactIds' IS DISTINCT FROM
              to_jsonb(selected_contacts)
       OR ('iocs' = ANY(selected_fields)) IS DISTINCT FROM
          (cardinality(selected_iocs) > 0)
       OR ('assets' = ANY(selected_fields)) IS DISTINCT FROM
          (cardinality(selected_assets) > 0)
       OR ('attachments' = ANY(selected_fields)) IS DISTINCT FROM
          (cardinality(selected_attachments) > 0)
       OR ('contacts' = ANY(selected_fields)) IS DISTINCT FROM
          (cardinality(selected_contacts) > 0) THEN
      RAISE EXCEPTION 'DFIR escalation selection is not canonical'
        USING ERRCODE = '22023';
    END IF;

    SELECT alert.* INTO source_alert
    FROM public.alerts AS alert
    WHERE alert.tenant_id = context_tenant
      AND alert.id = (source_value ->> 'alertId')::uuid
      AND alert.deleted_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'DFIR escalation source Alert is unavailable'
        USING ERRCODE = 'P0002';
    END IF;
    IF NOT app.private_current_ticket_scope_allows_v1(
      'alert.escalate', source_alert.assigned_team_id,
      source_alert.created_by, source_alert.assignee_user_id,
      source_alert.claimed_by_user_id
    )
       OR cardinality(selected_iocs) > 0
          AND NOT app.private_current_alert_dfir_scope_allows_v1(
            'dfir.ioc.read', source_alert.id
          )
       OR cardinality(selected_assets) > 0
          AND NOT app.private_current_alert_dfir_scope_allows_v1(
            'dfir.asset.read', source_alert.id
          )
       OR cardinality(selected_attachments) > 0
          AND NOT app.private_current_alert_dfir_scope_allows_v1(
            'dfir.attachment.read', source_alert.id
          ) THEN
      RAISE EXCEPTION 'DFIR escalation authority is required'
        USING ERRCODE = '42501';
    END IF;

    sanitized_fields := ARRAY(
      SELECT field.value
      FROM unnest(selected_fields) AS field(value)
      WHERE field.value NOT IN ('iocs', 'assets', 'attachments')
      ORDER BY field.value COLLATE "C"
    );
    sanitized_items := CASE
      WHEN source_items ? 'contactIds'
        THEN jsonb_build_object('contactIds', source_items -> 'contactIds')
      ELSE '{}'::jsonb
    END;
    sanitized_sources := sanitized_sources || jsonb_build_array(
      jsonb_set(
        jsonb_set(
          source_value, '{copyFields}', to_jsonb(sanitized_fields), false
        ),
        '{itemIds}', sanitized_items, false
      )
    );
  END LOOP;

  SELECT command.* INTO replay_command
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'ticket.escalate'
    AND command.key_digest = p_key_digest
  FOR UPDATE;
  IF FOUND THEN
    IF replay_command.request_digest IS DISTINCT FROM p_request_digest
       OR replay_command.result_alert_id IS DISTINCT FROM p_path_alert_id
       OR replay_command.result_case_id IS NULL
       OR replay_command.result_version < 1
       OR coalesce(
         (replay_command.result_metadata ->> 'pathAlertVersion')::integer, 0
       ) < 1 THEN
      RAISE EXCEPTION 'DFIR escalation idempotency key conflicts'
        USING ERRCODE = '23505', CONSTRAINT = 'ticket_commands_replay_key';
    END IF;

    FOR source_value IN
      SELECT source.value
      FROM jsonb_array_elements(p_sources) WITH ORDINALITY
           AS source(value, ordinal)
      ORDER BY source.ordinal
    LOOP
      selected_fields := ARRAY(
        SELECT field.value
        FROM jsonb_array_elements_text(source_value -> 'copyFields')
             AS field(value)
        ORDER BY field.value COLLATE "C"
      );
      source_items := source_value -> 'itemIds';
      selected_iocs := ARRAY(
        SELECT value::uuid FROM jsonb_array_elements_text(
          coalesce(source_items -> 'iocIds', '[]'::jsonb)
        ) AS item(value) ORDER BY value::uuid
      );
      selected_assets := ARRAY(
        SELECT value::uuid FROM jsonb_array_elements_text(
          coalesce(source_items -> 'assetIds', '[]'::jsonb)
        ) AS item(value) ORDER BY value::uuid
      );
      selected_attachments := ARRAY(
        SELECT value::uuid FROM jsonb_array_elements_text(
          coalesce(source_items -> 'attachmentIds', '[]'::jsonb)
        ) AS item(value) ORDER BY value::uuid
      );
      link_id := (source_value ->> 'linkId')::uuid;
      IF NOT EXISTS (
        SELECT 1
        FROM public.alert_case_links AS link
        WHERE link.tenant_id = context_tenant
          AND link.id = link_id
          AND link.alert_id = (source_value ->> 'alertId')::uuid
          AND link.case_id = replay_command.result_case_id
          AND link.source_alert_version =
              (source_value ->> 'expectedVersion')::integer
          AND link.copy_fields IS NOT DISTINCT FROM selected_fields
          AND link.item_ids IS NOT DISTINCT FROM source_items
      ) OR (
        SELECT count(*)
        FROM public.dfir_ioc_links AS case_link
        WHERE case_link.tenant_id = context_tenant
          AND case_link.case_id = replay_command.result_case_id
          AND case_link.ioc_id = ANY(selected_iocs)
      ) IS DISTINCT FROM cardinality(selected_iocs)
        OR (
          SELECT count(*)
          FROM public.dfir_asset_links AS case_link
          WHERE case_link.tenant_id = context_tenant
            AND case_link.case_id = replay_command.result_case_id
            AND case_link.asset_id = ANY(selected_assets)
        ) IS DISTINCT FROM cardinality(selected_assets)
        OR (
          SELECT count(*)
          FROM public.dfir_attachment_case_links AS case_link
          WHERE case_link.tenant_id = context_tenant
            AND case_link.case_id = replay_command.result_case_id
            AND case_link.attachment_id = ANY(selected_attachments)
            AND case_link.source_alert_id =
                (source_value ->> 'alertId')::uuid
            AND case_link.source_alert_version =
                (source_value ->> 'expectedVersion')::integer
            AND case_link.escalation_link_id = link_id
        ) IS DISTINCT FROM cardinality(selected_attachments) THEN
        RAISE EXCEPTION 'replayed DFIR escalation provenance drifted'
          USING ERRCODE = '55000';
      END IF;
    END LOOP;

    RETURN QUERY SELECT replay_command.result_case_id,
      replay_command.result_version,
      (replay_command.result_metadata ->> 'pathAlertVersion')::integer,
      replay_command.result_metadata, true;
    RETURN;
  END IF;

  SELECT committed.result_case_id, committed.result_case_version,
         committed.result_path_alert_version, committed.result_metadata,
         committed.replayed
  INTO committed_case_id, committed_case_version, committed_path_version,
       committed_metadata, was_replayed
  FROM app.commit_tenant_ticket_escalation_v2(
    p_path_alert_id, p_case_id, p_create_case, p_target,
    sanitized_sources, p_relation, p_reason, p_key_digest,
    p_request_digest, p_effects, p_request_id, p_correlation_id,
    p_ip_address, p_user_agent, p_authentication_method
  ) AS committed;
  IF committed_case_id IS NULL OR was_replayed IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'DFIR escalation result is unavailable'
      USING ERRCODE = '55000';
  END IF;

  FOR source_value IN
    SELECT source.value
    FROM jsonb_array_elements(p_sources) WITH ORDINALITY
         AS source(value, ordinal)
    ORDER BY source.ordinal
  LOOP
    source_items := source_value -> 'itemIds';
    selected_fields := ARRAY(
      SELECT field.value
      FROM jsonb_array_elements_text(source_value -> 'copyFields')
           AS field(value)
      ORDER BY field.value COLLATE "C"
    );
    selected_iocs := ARRAY(
      SELECT value::uuid FROM jsonb_array_elements_text(
        coalesce(source_items -> 'iocIds', '[]'::jsonb)
      ) AS item(value) ORDER BY value::uuid
    );
    selected_assets := ARRAY(
      SELECT value::uuid FROM jsonb_array_elements_text(
        coalesce(source_items -> 'assetIds', '[]'::jsonb)
      ) AS item(value) ORDER BY value::uuid
    );
    selected_attachments := ARRAY(
      SELECT value::uuid FROM jsonb_array_elements_text(
        coalesce(source_items -> 'attachmentIds', '[]'::jsonb)
      ) AS item(value) ORDER BY value::uuid
    );
    link_id := (source_value ->> 'linkId')::uuid;

    PERFORM 1
    FROM public.dfir_iocs AS ioc
    JOIN public.dfir_ioc_links AS source_link
      ON source_link.tenant_id = ioc.tenant_id
     AND source_link.ioc_id = ioc.id
    WHERE ioc.tenant_id = context_tenant
      AND ioc.id = ANY(selected_iocs)
      AND ioc.archived_at IS NULL
      AND source_link.alert_id = (source_value ->> 'alertId')::uuid
    ORDER BY ioc.id
    FOR SHARE OF ioc, source_link;
    GET DIAGNOSTICS matching_rows = ROW_COUNT;
    IF matching_rows IS DISTINCT FROM cardinality(selected_iocs) THEN
      RAISE EXCEPTION 'source Alert IOC selection is not exact and live'
        USING ERRCODE = '22023';
    END IF;

    PERFORM 1
    FROM public.dfir_assets AS asset
    JOIN public.dfir_asset_links AS source_link
      ON source_link.tenant_id = asset.tenant_id
     AND source_link.asset_id = asset.id
    WHERE asset.tenant_id = context_tenant
      AND asset.id = ANY(selected_assets)
      AND asset.archived_at IS NULL
      AND source_link.alert_id = (source_value ->> 'alertId')::uuid
    ORDER BY asset.id
    FOR SHARE OF asset, source_link;
    GET DIAGNOSTICS matching_rows = ROW_COUNT;
    IF matching_rows IS DISTINCT FROM cardinality(selected_assets) THEN
      RAISE EXCEPTION 'source Alert asset selection is not exact and live'
        USING ERRCODE = '22023';
    END IF;

    PERFORM 1
    FROM public.dfir_attachments AS attachment
    JOIN public.dfir_storage_objects AS storage
      ON storage.tenant_id = attachment.tenant_id
     AND storage.id = attachment.storage_object_id
    WHERE attachment.tenant_id = context_tenant
      AND attachment.id = ANY(selected_attachments)
      AND attachment.subject_kind = 'alert'
      AND attachment.alert_id = (source_value ->> 'alertId')::uuid
      AND attachment.scan_state = 'available'
      AND storage.state = 'available'
      AND storage.content_sha256 IS NOT NULL
      AND storage.size_bytes IS NOT NULL
    ORDER BY attachment.id
    FOR SHARE OF attachment, storage;
    GET DIAGNOSTICS matching_rows = ROW_COUNT;
    IF matching_rows IS DISTINCT FROM cardinality(selected_attachments) THEN
      RAISE EXCEPTION 'source Alert attachment selection is not exact and available'
        USING ERRCODE = '22023';
    END IF;

    INSERT INTO public.dfir_ioc_links (
      id, tenant_id, ioc_id, alert_id, case_id,
      created_by_membership_id, created_at
    )
    SELECT uuidv7(), context_tenant, selected.id, NULL,
           committed_case_id, actor_membership, transaction_timestamp()
    FROM unnest(selected_iocs) AS selected(id)
    ORDER BY selected.id
    ON CONFLICT DO NOTHING;

    INSERT INTO public.dfir_asset_links (
      id, tenant_id, asset_id, alert_id, case_id,
      created_by_membership_id, created_at
    )
    SELECT uuidv7(), context_tenant, selected.id, NULL,
           committed_case_id, actor_membership, transaction_timestamp()
    FROM unnest(selected_assets) AS selected(id)
    ORDER BY selected.id
    ON CONFLICT DO NOTHING;

    INSERT INTO public.dfir_attachment_case_links (
      id, tenant_id, attachment_id, case_id, source_alert_id,
      source_alert_version, escalation_link_id, created_by_membership_id,
      created_at
    )
    SELECT uuidv7(), context_tenant, selected.id, committed_case_id,
           (source_value ->> 'alertId')::uuid,
           (source_value ->> 'expectedVersion')::integer,
           link_id, actor_membership, transaction_timestamp()
    FROM unnest(selected_attachments) AS selected(id)
    ORDER BY selected.id
    ON CONFLICT DO NOTHING;

    IF (
      SELECT count(*) FROM public.dfir_ioc_links AS case_link
      WHERE case_link.tenant_id = context_tenant
        AND case_link.case_id = committed_case_id
        AND case_link.ioc_id = ANY(selected_iocs)
    ) IS DISTINCT FROM cardinality(selected_iocs)
       OR (
         SELECT count(*) FROM public.dfir_asset_links AS case_link
         WHERE case_link.tenant_id = context_tenant
           AND case_link.case_id = committed_case_id
           AND case_link.asset_id = ANY(selected_assets)
       ) IS DISTINCT FROM cardinality(selected_assets)
       OR (
         SELECT count(*) FROM public.dfir_attachment_case_links AS case_link
         WHERE case_link.tenant_id = context_tenant
           AND case_link.case_id = committed_case_id
           AND case_link.attachment_id = ANY(selected_attachments)
           AND case_link.source_alert_id =
               (source_value ->> 'alertId')::uuid
           AND case_link.source_alert_version =
               (source_value ->> 'expectedVersion')::integer
           AND case_link.escalation_link_id = link_id
       ) IS DISTINCT FROM cardinality(selected_attachments) THEN
      RAISE EXCEPTION 'DFIR escalation link provenance is unavailable'
        USING ERRCODE = '55000';
    END IF;

    UPDATE public.alert_case_links AS link
    SET copy_fields = selected_fields,
        item_ids = source_items
    WHERE link.tenant_id = context_tenant
      AND link.id = link_id
      AND link.alert_id = (source_value ->> 'alertId')::uuid
      AND link.case_id = committed_case_id;
    GET DIAGNOSTICS affected_rows = ROW_COUNT;
    IF affected_rows <> 1 THEN
      RAISE EXCEPTION 'DFIR escalation result link is unavailable'
        USING ERRCODE = '55000';
    END IF;

    dfir_count := cardinality(selected_iocs) + cardinality(selected_assets)
      + cardinality(selected_attachments);
    IF dfir_count > 0 THEN
      PERFORM app.append_tenant_authorization_audit(
        uuidv7(), 'tenant.ticket.dfir_copied', 'alert_case_link', link_id,
        p_request_id, p_correlation_id, p_ip_address,
        nullif(p_user_agent, ''), p_authentication_method, NULL,
        jsonb_build_object(
          'source_alert_version',
            (source_value ->> 'expectedVersion')::integer,
          'ioc_count', cardinality(selected_iocs),
          'asset_count', cardinality(selected_assets),
          'attachment_count', cardinality(selected_attachments),
          'content_redacted', true
        ),
        jsonb_build_object('case_id', committed_case_id)
      );
      INSERT INTO public.outbox_events (
        tenant_id, aggregate_type, aggregate_id, aggregate_version,
        event_type, schema_version, payload, deduplication_key,
        correlation_id, causation_id, actor_kind, actor_id, producer
      ) VALUES (
        context_tenant, 'case', committed_case_id, committed_case_version,
        'ticket.escalation.dfir_copied', 1,
        jsonb_build_object(
          'case_id', committed_case_id,
          'source_alert_id', (source_value ->> 'alertId')::uuid,
          'link_id', link_id,
          'ioc_count', cardinality(selected_iocs),
          'asset_count', cardinality(selected_assets),
          'attachment_count', cardinality(selected_attachments)
        ),
        'ticket.escalation.dfir_copied:' || link_id::text,
        p_correlation_id, p_request_id, 'human', actor_user, 'ticketing'
      );
    END IF;
  END LOOP;

  RETURN QUERY SELECT committed_case_id, committed_case_version,
    committed_path_version, committed_metadata, false;
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.commit_tenant_ticket_escalation_v3(
  uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_tenant_ticket_escalation_v3(
  uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_tenant_ticket_escalation_v3(
  uuid, uuid, boolean, jsonb, jsonb, text, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) TO periapsis_api;
