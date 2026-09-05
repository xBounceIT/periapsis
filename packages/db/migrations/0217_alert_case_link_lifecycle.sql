-- Explicit Alert/Case link lifecycle. Historical links and copied DFIR
-- provenance remain immutable; unlink appends one terminal retraction and
-- advances both aggregates under one live authority snapshot.

ALTER TABLE public.alert_case_links
  ADD CONSTRAINT alert_case_links_identity_key
  UNIQUE (tenant_id, id, alert_id, case_id);--> statement-breakpoint

CREATE TABLE public.alert_case_link_retractions (
  id uuid PRIMARY KEY DEFAULT uuidv7() NOT NULL,
  tenant_id uuid NOT NULL,
  link_id uuid NOT NULL,
  alert_id uuid NOT NULL,
  case_id uuid NOT NULL,
  unlinked_by_membership_id uuid NOT NULL,
  unlinked_by_user_id uuid NOT NULL,
  reason text NOT NULL,
  prior_alert_version integer NOT NULL,
  result_alert_version integer NOT NULL,
  prior_case_version integer NOT NULL,
  result_case_version integer NOT NULL,
  unlinked_at timestamp with time zone DEFAULT now() NOT NULL,
  CONSTRAINT alert_case_link_retractions_tenant_id_key
    UNIQUE (tenant_id, id),
  CONSTRAINT alert_case_link_retractions_link_key
    UNIQUE (tenant_id, link_id),
  CONSTRAINT alert_case_link_retractions_pair_key
    UNIQUE (tenant_id, alert_id, case_id),
  CONSTRAINT alert_case_link_retractions_id_uuidv7_check
    CHECK ((uuid_extract_version(id) = 7) IS TRUE),
  CONSTRAINT alert_case_link_retractions_reason_check
    CHECK (btrim(reason) <> '' AND char_length(reason) <= 2000
      AND reason !~ '[[:cntrl:]]'),
  CONSTRAINT alert_case_link_retractions_version_check
    CHECK (prior_alert_version BETWEEN 1 AND 2147483646
      AND result_alert_version = prior_alert_version + 1
      AND prior_case_version BETWEEN 1 AND 2147483646
      AND result_case_version = prior_case_version + 1),
  CONSTRAINT alert_case_link_retractions_tenant_fk
    FOREIGN KEY (tenant_id) REFERENCES public.tenants(id)
    ON DELETE RESTRICT,
  CONSTRAINT alert_case_link_retractions_link_identity_fk
    FOREIGN KEY (tenant_id, link_id, alert_id, case_id)
    REFERENCES public.alert_case_links(tenant_id, id, alert_id, case_id)
    ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT alert_case_link_retractions_actor_membership_fk
    FOREIGN KEY (tenant_id, unlinked_by_membership_id)
    REFERENCES public.tenant_memberships(tenant_id, id)
    ON DELETE RESTRICT ON UPDATE CASCADE,
  CONSTRAINT alert_case_link_retractions_actor_user_fk
    FOREIGN KEY (tenant_id, unlinked_by_user_id)
    REFERENCES public.tenant_memberships(tenant_id, user_id)
    ON DELETE RESTRICT ON UPDATE CASCADE
);--> statement-breakpoint

CREATE INDEX alert_case_link_retractions_alert_idx
  ON public.alert_case_link_retractions
  (tenant_id, alert_id, unlinked_at, id);--> statement-breakpoint
CREATE INDEX alert_case_link_retractions_case_idx
  ON public.alert_case_link_retractions
  (tenant_id, case_id, unlinked_at, id);--> statement-breakpoint

ALTER TABLE public.alert_case_link_retractions ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.alert_case_link_retractions FORCE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE public.alert_case_link_retractions OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON TABLE public.alert_case_link_retractions
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor, periapsis_ticket_runtime_owner,
       periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE POLICY alert_case_link_retractions_api_tenant
ON public.alert_case_link_retractions
AS PERMISSIVE FOR SELECT TO periapsis_api
USING (
  tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid
  AND app.tenant_is_active_v1(tenant_id)
  AND EXISTS (
    SELECT 1 FROM public.tenant_memberships AS membership
    WHERE membership.tenant_id = alert_case_link_retractions.tenant_id
      AND membership.user_id =
          nullif(current_setting('app.user_id', true), '')::uuid
      AND membership.status = 'active'
  )
);--> statement-breakpoint
GRANT SELECT ON TABLE public.alert_case_link_retractions TO periapsis_api;--> statement-breakpoint

CREATE TRIGGER alert_case_link_retractions_immutable_v1
BEFORE UPDATE OR DELETE ON public.alert_case_link_retractions
FOR EACH ROW EXECUTE FUNCTION app.guard_ticketing_append_only_v1();--> statement-breakpoint

-- Escalation V47 materializes one new link through nested trusted functions:
-- the base INSERT is enriched with contact/DFIR selection provenance before
-- the transaction commits. Permit only that same-transaction initialization;
-- a committed link remains strictly update/delete proof.
CREATE FUNCTION app.guard_alert_case_link_initialization_v1()
RETURNS trigger
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path=pg_catalog,public,app
AS $function$
BEGIN
  IF TG_OP <> 'UPDATE'
     OR OLD.xmin::text::bigint <> pg_current_xact_id()::text::bigint
     OR (to_jsonb(NEW) - ARRAY[
       'copy_fields','item_ids','copied_field_snapshot'
     ]::text[]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY[
       'copy_fields','item_ids','copied_field_snapshot'
     ]::text[])
     OR NOT NEW.copy_fields @> OLD.copy_fields
     OR NOT NEW.item_ids @> OLD.item_ids
     OR (NEW.copied_field_snapshot - 'contactIds') IS DISTINCT FROM
        (OLD.copied_field_snapshot - 'contactIds')
     OR coalesce(NEW.copied_field_snapshot->'contactIds','[]'::jsonb)
        IS DISTINCT FROM coalesce(NEW.item_ids->'contactIds','[]'::jsonb) THEN
    RAISE EXCEPTION 'Alert/Case link provenance is immutable'
      USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.guard_alert_case_link_initialization_v1()
  OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.guard_alert_case_link_initialization_v1()
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
DROP TRIGGER alert_case_links_immutable_v1
ON public.alert_case_links;--> statement-breakpoint
CREATE TRIGGER alert_case_links_immutable_v2
BEFORE UPDATE OR DELETE ON public.alert_case_links
FOR EACH ROW EXECUTE FUNCTION app.guard_alert_case_link_initialization_v1();--> statement-breakpoint

-- Keep explicit linking in its own durable command namespace and emit
-- `linked` for both aggregates. The implementation is derived from the exact
-- V47 escalation chain so workflow-effect validation, selection copying,
-- provenance attestation, locking, CAS, and replay stay byte-for-byte aligned.
DO $derive_ticket_link_v1$
DECLARE
  base_definition text;
  contacts_definition text;
  commit_definition text;
  replay_definition text;
  successor_definition text;
  begin_marker constant text := $marker$
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
$marker$;
  link_begin constant text := $replacement$
BEGIN
  IF p_create_case IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'explicit Alert/Case link cannot create a Case'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.lock_current_tenant_authorization_state();
$replacement$;
  commit_begin_marker constant text := $marker$
  dfir_count integer;
BEGIN
$marker$;
  link_commit_begin constant text := $replacement$
  dfir_count integer;
BEGIN
  IF p_create_case IS DISTINCT FROM false THEN
    RAISE EXCEPTION 'explicit Alert/Case link cannot create a Case'
      USING ERRCODE = '22023';
  END IF;
$replacement$;
  case_effect_marker constant text := $marker$
      target_case.state_key, 'link'
    );
$marker$;
  case_effect_without_notification constant text := $replacement$
      target_case.state_key, 'link'
    );
    case_effects := array_remove(case_effects,'notification');
$replacement$;
  alert_effect_marker constant text := $marker$
      source_alert.state_key, 'escalate'
    );
$marker$;
  alert_effect_without_notification constant text := $replacement$
      source_alert.state_key, 'escalate'
    );
    source_effects := array_remove(source_effects,'notification');
$replacement$;
BEGIN
  SELECT pg_get_functiondef(
    'app.private_commit_tenant_ticket_escalation_v4_base(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure
  ) INTO base_definition;
  SELECT pg_get_functiondef(
    'app.private_commit_tenant_ticket_escalation_v4_contacts(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure
  ) INTO contacts_definition;
  SELECT pg_get_functiondef(
    'app.commit_tenant_ticket_escalation_v4(uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,inet,text,text)'::regprocedure
  ) INTO commit_definition;
  SELECT pg_get_functiondef(
    'app.lookup_tenant_ticket_escalation_replay_v3(bytea,bytea)'::regprocedure
  ) INTO replay_definition;

  IF encode(sha256(convert_to(base_definition,'UTF8')),'hex')<>
       '3b19aab6bb28467ae84816974b7d20319a66fd1f1ee5adff4e654a38076d3ea6'
     OR encode(sha256(convert_to(contacts_definition,'UTF8')),'hex')<>
       '598f3ab0fba274dff445bddd3e660b56ee5582f781f0ec639dc5f30604cf602a'
     OR encode(sha256(convert_to(commit_definition,'UTF8')),'hex')<>
       '21a58c79b763b69f89e3bcbebd392b1c34a67a8926d51b5688f5403654a0b609'
     OR encode(sha256(convert_to(replay_definition,'UTF8')),'hex')<>
       '94b967a29deb6a36212d199df813d03969bdc17f4d83283148579d9525f0dec1'
     OR strpos(base_definition,begin_marker)=0
     OR strpos(commit_definition,commit_begin_marker)=0
     OR strpos(base_definition,'''escalated''')=0
     OR strpos(base_definition,case_effect_marker)=0
     OR strpos(base_definition,alert_effect_marker)=0
     OR strpos(replay_definition,'''case.read''')=0 THEN
    RAISE EXCEPTION 'ticket link predecessor is not canonical'
      USING ERRCODE='55000';
  END IF;

  successor_definition := replace(
    base_definition,
    'private_commit_tenant_ticket_escalation_v4_base',
    'private_commit_tenant_ticket_link_v1_base'
  );
  successor_definition := replace(
    successor_definition,'ticket.escalate','ticket.link'
  );
  successor_definition := replace(
    successor_definition,'''escalated''','''linked'''
  );
  successor_definition := replace(
    successor_definition,begin_marker,link_begin
  );
  successor_definition := replace(
    successor_definition,case_effect_marker,case_effect_without_notification
  );
  successor_definition := replace(
    successor_definition,alert_effect_marker,alert_effect_without_notification
  );
  IF strpos(successor_definition,
       'private_commit_tenant_ticket_escalation_v4_base')<>0
     OR strpos(successor_definition,'ticket.escalate')<>0
     OR strpos(successor_definition,'''escalated''')<>0
     OR strpos(successor_definition,
       'case_effects := array_remove(case_effects,''notification'')')=0
     OR strpos(successor_definition,
       'source_effects := array_remove(source_effects,''notification'')')=0
     OR strpos(successor_definition,
       'explicit Alert/Case link cannot create a Case')=0 THEN
    RAISE EXCEPTION 'ticket link base derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;

  successor_definition := replace(
    contacts_definition,
    'private_commit_tenant_ticket_escalation_v4_contacts',
    'private_commit_tenant_ticket_link_v1_contacts'
  );
  successor_definition := replace(
    successor_definition,
    'private_commit_tenant_ticket_escalation_v4_base',
    'private_commit_tenant_ticket_link_v1_base'
  );
  IF strpos(successor_definition,
       'private_commit_tenant_ticket_escalation_v4')<>0 THEN
    RAISE EXCEPTION 'ticket link contact derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;

  successor_definition := replace(
    commit_definition,'commit_tenant_ticket_escalation_v4',
    'commit_tenant_ticket_link_v1'
  );
  successor_definition := replace(
    successor_definition,
    'private_commit_tenant_ticket_escalation_v4_contacts',
    'private_commit_tenant_ticket_link_v1_contacts'
  );
  successor_definition := replace(
    successor_definition,'ticket.escalate','ticket.link'
  );
  successor_definition := replace(
    successor_definition,commit_begin_marker,link_commit_begin
  );
  IF strpos(successor_definition,'commit_tenant_ticket_escalation_v4')<>0
     OR strpos(successor_definition,'ticket.escalate')<>0
     OR strpos(successor_definition,
       'explicit Alert/Case link cannot create a Case')=0 THEN
    RAISE EXCEPTION 'ticket link commit derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;

  successor_definition := replace(
    replay_definition,'lookup_tenant_ticket_escalation_replay_v3',
    'lookup_tenant_ticket_link_replay_v1'
  );
  successor_definition := replace(
    successor_definition,'ticket.escalate','ticket.link'
  );
  successor_definition := replace(
    successor_definition,'''case.read''','''case.update'''
  );
  IF strpos(successor_definition,
       'lookup_tenant_ticket_escalation_replay_v3')<>0
     OR strpos(successor_definition,'ticket.escalate')<>0
     OR strpos(successor_definition,'''case.read''')<>0 THEN
    RAISE EXCEPTION 'ticket link replay derivation failed'
      USING ERRCODE='55000';
  END IF;
  EXECUTE successor_definition;
END;
$derive_ticket_link_v1$;--> statement-breakpoint

ALTER FUNCTION app.private_commit_tenant_ticket_link_v1_base(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.private_commit_tenant_ticket_link_v1_contacts(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.commit_tenant_ticket_link_v1(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) OWNER TO periapsis_migrator;--> statement-breakpoint
ALTER FUNCTION app.lookup_tenant_ticket_link_replay_v1(bytea,bytea)
  OWNER TO periapsis_migrator;--> statement-breakpoint

REVOKE ALL ON FUNCTION
  app.private_commit_tenant_ticket_link_v1_base(
    uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
    inet,text,text
  ),
  app.private_commit_tenant_ticket_link_v1_contacts(
    uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
    inet,text,text
  ),
  app.commit_tenant_ticket_link_v1(
    uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
    inet,text,text
  ),
  app.lookup_tenant_ticket_link_replay_v1(bytea,bytea)
FROM PUBLIC,periapsis_api,periapsis_worker,periapsis_notifier,
  periapsis_auditor,periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_tenant_ticket_link_v1(
  uuid,uuid,boolean,jsonb,jsonb,text,text,bytea,bytea,text[],uuid,uuid,
  inet,text,text
) TO periapsis_api;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_tenant_ticket_link_replay_v1(bytea,bytea)
TO periapsis_api;--> statement-breakpoint

-- Relationship validation must stop treating a retracted Alert/Case link as
-- live. Dedicated copied IOC/asset/attachment provenance remains independent.
CREATE OR REPLACE FUNCTION app.private_dfir_resource_belongs_to_case_v1(
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
      SELECT 1 FROM public.alert_case_links AS link
      WHERE link.tenant_id = p_tenant_id
        AND link.case_id = p_case_id
        AND link.alert_id = p_resource_id
        AND NOT EXISTS (
          SELECT 1 FROM public.alert_case_link_retractions AS retraction
          WHERE retraction.tenant_id = link.tenant_id
            AND retraction.link_id = link.id
        )
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
          OR EXISTS (
            SELECT 1
            FROM public.dfir_attachment_case_links AS copied
            WHERE copied.tenant_id = attachment.tenant_id
              AND copied.attachment_id = attachment.id
              AND copied.case_id = p_case_id
          )
        )
    )
    ELSE false
  END;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_dfir_resource_belongs_to_case_v1(
  uuid, uuid, public.dfir_entity_kind, uuid
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_dfir_resource_belongs_to_case_v1(
  uuid, uuid, public.dfir_entity_kind, uuid
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint

CREATE FUNCTION app.lookup_tenant_alert_case_unlink_replay_v1(
  p_alert_id uuid,
  p_case_id uuid,
  p_key_digest bytea,
  p_request_digest bytea
)
RETURNS TABLE (
  result_link_id uuid,
  previous_alert_version integer,
  result_alert_version integer,
  previous_case_version integer,
  result_case_version integer,
  retracted_at timestamp with time zone
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
  replay_command public.ticket_commands%ROWTYPE;
  source_alert public.alerts%ROWTYPE;
  target_case public.cases%ROWTYPE;
  retraction public.alert_case_link_retractions%ROWTYPE;
BEGIN
  IF p_alert_id IS NULL OR (uuid_extract_version(p_alert_id) = 7) IS NOT TRUE
     OR p_case_id IS NULL OR (uuid_extract_version(p_case_id) = 7) IS NOT TRUE
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_key_digest = decode(repeat('00', 32), 'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_request_digest = decode(repeat('00', 32), 'hex') THEN
    RAISE EXCEPTION 'Alert/Case unlink replay identity is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();

  SELECT command.* INTO replay_command
  FROM public.ticket_commands AS command
  WHERE command.tenant_id = context_tenant
    AND command.actor_membership_id = actor_membership
    AND command.operation = 'ticket.unlink'
    AND command.key_digest = p_key_digest;
  IF NOT FOUND THEN
    RETURN;
  END IF;
  IF replay_command.request_digest IS DISTINCT FROM p_request_digest
     OR replay_command.result_alert_id IS DISTINCT FROM p_alert_id
     OR replay_command.result_case_id IS DISTINCT FROM p_case_id THEN
    RAISE EXCEPTION 'Alert/Case unlink idempotency key conflicts'
      USING ERRCODE = '23505',
            CONSTRAINT = 'ticket_commands_replay_key';
  END IF;

  SELECT alert.* INTO source_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL
  FOR SHARE;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
       'alert.escalate', source_alert.assigned_team_id,
       source_alert.created_by, source_alert.assignee_user_id,
       source_alert.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'Alert/Case unlink replay is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT case_row.* INTO target_case
  FROM public.cases AS case_row
  WHERE case_row.tenant_id = context_tenant AND case_row.id = p_case_id
  FOR SHARE;
  IF NOT FOUND OR NOT app.private_current_ticket_scope_allows_v1(
       'case.update', target_case.assigned_team_id,
       target_case.created_by_user_id, target_case.assignee_user_id,
       target_case.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'Alert/Case unlink replay is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT withdrawn.* INTO retraction
  FROM public.alert_case_link_retractions AS withdrawn
  JOIN public.alert_case_links AS link
    ON link.tenant_id = withdrawn.tenant_id
   AND link.id = withdrawn.link_id
   AND link.alert_id = withdrawn.alert_id
   AND link.case_id = withdrawn.case_id
  WHERE withdrawn.tenant_id = context_tenant
    AND withdrawn.alert_id = p_alert_id
    AND withdrawn.case_id = p_case_id
    AND withdrawn.unlinked_by_membership_id = actor_membership
    AND withdrawn.unlinked_by_user_id = app.context_user_id()
  FOR SHARE OF withdrawn, link;
  IF NOT FOUND
     OR source_alert.version < retraction.result_alert_version
     OR target_case.version < retraction.result_case_version
     OR replay_command.result_version <> retraction.result_case_version
     OR replay_command.created_at <> retraction.unlinked_at
     OR replay_command.result_metadata IS DISTINCT FROM jsonb_build_object(
       'linkId', retraction.link_id,
       'previousAlertVersion', retraction.prior_alert_version,
       'alertVersion', retraction.result_alert_version,
       'previousCaseVersion', retraction.prior_case_version,
       'caseVersion', retraction.result_case_version,
       'retractedAt', retraction.unlinked_at
     ) THEN
    RAISE EXCEPTION 'Alert/Case unlink replay provenance drifted'
      USING ERRCODE = '55000';
  END IF;

  RETURN QUERY SELECT retraction.link_id,
    retraction.prior_alert_version, retraction.result_alert_version,
    retraction.prior_case_version, retraction.result_case_version,
    retraction.unlinked_at;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.lookup_tenant_alert_case_unlink_replay_v1(
  uuid, uuid, bytea, bytea
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.lookup_tenant_alert_case_unlink_replay_v1(
  uuid, uuid, bytea, bytea
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.lookup_tenant_alert_case_unlink_replay_v1(
  uuid, uuid, bytea, bytea
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.commit_tenant_alert_case_unlink_v1(
  p_alert_id uuid,
  p_case_id uuid,
  p_link_id uuid,
  p_alert_workflow_id uuid,
  p_alert_workflow_version integer,
  p_alert_state_key text,
  p_expected_alert_version integer,
  p_result_alert_version integer,
  p_case_workflow_id uuid,
  p_case_workflow_version integer,
  p_case_state_key text,
  p_expected_case_version integer,
  p_result_case_version integer,
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
  result_link_id uuid,
  previous_alert_version integer,
  result_alert_version integer,
  previous_case_version integer,
  result_case_version integer,
  retracted_at timestamp with time zone,
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
  source_alert public.alerts%ROWTYPE;
  target_case public.cases%ROWTYPE;
  source_link public.alert_case_links%ROWTYPE;
  replay_result record;
  operation_at timestamp with time zone := transaction_timestamp();
  alert_effects text[];
  case_effects text[];
  actual_effects text[];
  affected_rows integer;
BEGIN
  IF p_alert_id IS NULL OR (uuid_extract_version(p_alert_id) = 7) IS NOT TRUE
     OR p_case_id IS NULL OR (uuid_extract_version(p_case_id) = 7) IS NOT TRUE
     OR p_link_id IS NULL OR (uuid_extract_version(p_link_id) = 7) IS NOT TRUE
     OR p_alert_workflow_id IS NULL
        OR (uuid_extract_version(p_alert_workflow_id) = 7) IS NOT TRUE
     OR p_case_workflow_id IS NULL
        OR (uuid_extract_version(p_case_workflow_id) = 7) IS NOT TRUE
     OR p_alert_workflow_version NOT BETWEEN 1 AND 2147483647
     OR p_case_workflow_version NOT BETWEEN 1 AND 2147483647
     OR p_expected_alert_version NOT BETWEEN 1 AND 2147483646
     OR p_result_alert_version <> p_expected_alert_version + 1
     OR p_expected_case_version NOT BETWEEN 1 AND 2147483646
     OR p_result_case_version <> p_expected_case_version + 1
     OR p_alert_state_key IS NULL
        OR p_alert_state_key !~ '^[a-z][a-z0-9_.-]{0,63}$'
     OR p_case_state_key IS NULL
        OR p_case_state_key !~ '^[a-z][a-z0-9_.-]{0,63}$'
     OR p_reason IS NULL OR btrim(p_reason) = ''
        OR char_length(p_reason) > 2000 OR p_reason ~ '[[:cntrl:]]'
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
        OR p_key_digest = decode(repeat('00', 32), 'hex')
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
        OR p_request_digest = decode(repeat('00', 32), 'hex')
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL
     OR p_user_agent IS NULL OR char_length(p_user_agent) > 1000
     OR p_authentication_method IS NULL
        OR p_authentication_method !~ '^[a-z][a-z0-9_.-]{0,63}$' THEN
    RAISE EXCEPTION 'Alert/Case unlink request is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.private_validate_ticket_effects_v1(p_effects);

  PERFORM app.lock_current_tenant_authorization_state();
  actor_membership := app.current_tenant_membership_id();
  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text
      || ':ticket.unlink:' || encode(p_key_digest, 'hex'), 0
  ));

  SELECT replay.* INTO replay_result
  FROM app.lookup_tenant_alert_case_unlink_replay_v1(
    p_alert_id, p_case_id, p_key_digest, p_request_digest
  ) AS replay;
  IF FOUND THEN
    RETURN QUERY SELECT replay_result.result_link_id,
      replay_result.previous_alert_version,
      replay_result.result_alert_version,
      replay_result.previous_case_version,
      replay_result.result_case_version,
      replay_result.retracted_at, true;
    RETURN;
  END IF;

  SELECT alert.* INTO source_alert
  FROM public.alerts AS alert
  WHERE alert.tenant_id = context_tenant AND alert.id = p_alert_id
    AND alert.deleted_at IS NULL
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert/Case unlink source is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  SELECT case_row.* INTO target_case
  FROM public.cases AS case_row
  WHERE case_row.tenant_id = context_tenant AND case_row.id = p_case_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert/Case unlink target is unavailable'
      USING ERRCODE = 'P0002';
  END IF;

  IF source_alert.workflow_id <> p_alert_workflow_id
     OR source_alert.workflow_version <> p_alert_workflow_version
     OR source_alert.state_key <> p_alert_state_key
     OR source_alert.version <> p_expected_alert_version
     OR target_case.workflow_id <> p_case_workflow_id
     OR target_case.workflow_version <> p_case_workflow_version
     OR target_case.state_key <> p_case_state_key
     OR target_case.version <> p_expected_case_version THEN
    RAISE EXCEPTION 'Alert/Case unlink workflow or version pin is stale'
      USING ERRCODE = '40001';
  END IF;
  IF NOT app.private_current_ticket_scope_allows_v1(
       'alert.escalate', source_alert.assigned_team_id,
       source_alert.created_by, source_alert.assignee_user_id,
       source_alert.claimed_by_user_id
     ) OR NOT app.private_current_ticket_scope_allows_v1(
       'case.update', target_case.assigned_team_id,
       target_case.created_by_user_id, target_case.assignee_user_id,
       target_case.claimed_by_user_id
     ) THEN
    RAISE EXCEPTION 'Alert/Case unlink authority is required'
      USING ERRCODE = '42501';
  END IF;

  SELECT link.* INTO source_link
  FROM public.alert_case_links AS link
  WHERE link.tenant_id = context_tenant AND link.id = p_link_id
    AND link.alert_id = p_alert_id AND link.case_id = p_case_id
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Alert/Case link is unavailable'
      USING ERRCODE = 'P0002';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.alert_case_link_retractions AS retraction
    WHERE retraction.tenant_id = context_tenant
      AND retraction.link_id = p_link_id
  ) THEN
    RAISE EXCEPTION 'Alert/Case link retraction is terminal'
      USING ERRCODE = '23505',
            CONSTRAINT = 'alert_case_link_retractions_link_key';
  END IF;

  alert_effects := app.private_ticket_state_action_effects_v1(
    'alert', source_alert.workflow_id, source_alert.workflow_version,
    source_alert.state_key, 'escalate'
  );
  alert_effects := array_remove(alert_effects, 'notification');
  case_effects := app.private_ticket_state_action_effects_v1(
    'case', target_case.workflow_id, target_case.workflow_version,
    target_case.state_key, 'link'
  );
  case_effects := array_remove(case_effects, 'notification');
  actual_effects := ARRAY(
    SELECT effect.value
    FROM unnest(alert_effects || case_effects) AS effect(value)
    GROUP BY effect.value
    ORDER BY CASE effect.value
      WHEN 'activity' THEN 1 WHEN 'audit' THEN 2
      WHEN 'sla' THEN 3 WHEN 'notification' THEN 4
    END
  );
  IF actual_effects IS DISTINCT FROM p_effects THEN
    RAISE EXCEPTION 'Alert/Case unlink effect plan drifted'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.alerts AS alert
  SET version = p_result_alert_version, updated_at = operation_at
  WHERE alert.tenant_id = context_tenant AND alert.id = p_alert_id
    AND alert.version = p_expected_alert_version
    AND alert.deleted_at IS NULL;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'Alert unlink compare-and-swap failed'
      USING ERRCODE = '40001';
  END IF;

  UPDATE public.cases AS case_row
  SET version = p_result_case_version, updated_at = operation_at
  WHERE case_row.tenant_id = context_tenant AND case_row.id = p_case_id
    AND case_row.version = p_expected_case_version;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'Case unlink compare-and-swap failed'
      USING ERRCODE = '40001';
  END IF;

  INSERT INTO public.alert_case_link_retractions (
    tenant_id, link_id, alert_id, case_id,
    unlinked_by_membership_id, unlinked_by_user_id, reason,
    prior_alert_version, result_alert_version,
    prior_case_version, result_case_version, unlinked_at
  ) VALUES (
    context_tenant, p_link_id, p_alert_id, p_case_id,
    actor_membership, actor_user, p_reason,
    p_expected_alert_version, p_result_alert_version,
    p_expected_case_version, p_result_case_version, operation_at
  );

  PERFORM app.private_append_ticket_side_effects_v1(
    'alert', p_alert_id, 'unlinked', p_result_alert_version,
    alert_effects, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method,
    jsonb_build_object(
      'version', p_expected_alert_version, 'link_active', true
    ),
    jsonb_build_object(
      'version', p_result_alert_version, 'link_active', false
    ),
    jsonb_build_object(
      'link_id', p_link_id, 'case_id', p_case_id,
      'reason', p_reason, 'content_redacted', true
    )
  );
  PERFORM app.private_append_ticket_side_effects_v1(
    'case', p_case_id, 'unlinked', p_result_case_version,
    case_effects, p_request_id, p_correlation_id, p_ip_address,
    p_user_agent, p_authentication_method,
    jsonb_build_object(
      'version', p_expected_case_version, 'link_active', true
    ),
    jsonb_build_object(
      'version', p_result_case_version, 'link_active', false
    ),
    jsonb_build_object(
      'link_id', p_link_id, 'alert_id', p_alert_id,
      'reason', p_reason, 'content_redacted', true
    )
  );

  INSERT INTO public.ticket_commands (
    tenant_id, operation, actor_membership_id, actor_user_id,
    key_digest, request_digest, result_alert_id, result_case_id,
    result_version, result_metadata, created_at
  ) VALUES (
    context_tenant, 'ticket.unlink', actor_membership, actor_user,
    p_key_digest, p_request_digest, p_alert_id, p_case_id,
    p_result_case_version,
    jsonb_build_object(
      'linkId', p_link_id,
      'previousAlertVersion', p_expected_alert_version,
      'alertVersion', p_result_alert_version,
      'previousCaseVersion', p_expected_case_version,
      'caseVersion', p_result_case_version,
      'retractedAt', operation_at
    ), operation_at
  );

  RETURN QUERY SELECT p_link_id, p_expected_alert_version,
    p_result_alert_version, p_expected_case_version,
    p_result_case_version, operation_at, false;
END;
$function$;--> statement-breakpoint

ALTER FUNCTION app.commit_tenant_alert_case_unlink_v1(
  uuid, uuid, uuid, uuid, integer, text, integer, integer,
  uuid, integer, text, integer, integer, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) OWNER TO periapsis_migrator;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_tenant_alert_case_unlink_v1(
  uuid, uuid, uuid, uuid, integer, text, integer, integer,
  uuid, integer, text, integer, integer, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
  periapsis_auditor, periapsis_ticket_runtime_owner,
  periapsis_notification_dispatch_owner;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_tenant_alert_case_unlink_v1(
  uuid, uuid, uuid, uuid, integer, text, integer, integer,
  uuid, integer, text, integer, integer, text, bytea, bytea, text[],
  uuid, uuid, inet, text, text
) TO periapsis_api;--> statement-breakpoint
