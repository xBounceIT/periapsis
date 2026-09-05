-- Customer contacts are notification recipients independently of portal-account
-- linkage.  A complete live account link only enriches the candidate with a
-- principalId; delivery eligibility remains contact-owned and customer-safe.
CREATE OR REPLACE FUNCTION app.load_notification_fanout_inputs_v3(
  p_event_id uuid,
  p_fence_token uuid
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  source_event public.outbox_events%ROWTYPE;
  selected_snapshot public.tenant_notification_fanout_snapshots%ROWTYPE;
  selected_rule_pins jsonb;
  selected_webhook_pins jsonb;
  selected_smtp_scope text;
  selected_smtp_id uuid;
  selected_smtp_version integer;
  snapshot_value jsonb;
  rules_value jsonb;
  templates_value jsonb;
  candidates_value jsonb;
  candidate_count integer;
BEGIN
  context_tenant := app.private_lock_notification_fanout_claim_v1(
    p_event_id, p_fence_token
  );
  SELECT event.* INTO STRICT source_event
  FROM public.outbox_events AS event
  WHERE event.id = p_event_id AND event.tenant_id = context_tenant;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant
    WHERE tenant.id = context_tenant AND tenant.status = 'active'
  ) THEN
    RAISE EXCEPTION 'notification tenant is unavailable'
      USING ERRCODE = '42501';
  END IF;

  SELECT snapshot.* INTO selected_snapshot
  FROM public.tenant_notification_fanout_snapshots AS snapshot
  WHERE snapshot.tenant_id = context_tenant AND snapshot.event_id = p_event_id;
  IF NOT FOUND THEN
    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'ruleId', rule.id, 'version', version.version
    ) ORDER BY rule.id, version.version), '[]'::jsonb)
    INTO selected_rule_pins
    FROM public.tenant_notification_rules AS rule
    JOIN public.tenant_notification_rule_versions AS version
      ON version.tenant_id = rule.tenant_id
     AND version.rule_id = rule.id
     AND version.version = rule.current_version
    WHERE rule.tenant_id = context_tenant
      AND version.channel = 'email'
      AND version.enabled
      AND version.event_type::text = substring(source_event.event_type from 14)
      AND version.object_type::text = source_event.aggregate_type
      AND version.effective_from <= source_event.occurred_at
      AND (version.effective_until IS NULL
        OR version.effective_until > source_event.occurred_at);
    IF jsonb_array_length(selected_rule_pins) > 1000 THEN
      RAISE EXCEPTION 'notification rule snapshot is oversized'
        USING ERRCODE = '54000';
    END IF;

    SELECT coalesce(jsonb_agg(jsonb_build_object(
      'configurationId', configuration.id,
      'version', version.version
    ) ORDER BY configuration.id, version.version), '[]'::jsonb)
    INTO selected_webhook_pins
    FROM public.tenant_notification_webhook_configurations AS configuration
    JOIN public.tenant_notification_webhook_configuration_versions AS version
      ON version.tenant_id = configuration.tenant_id
     AND version.configuration_id = configuration.id
     AND version.version = configuration.current_version
    WHERE configuration.tenant_id = context_tenant
      AND configuration.revoked_at IS NULL
      AND version.enabled
      AND substring(source_event.event_type from 14)::public.notification_event_type
        = ANY(version.event_types)
      AND (version.audience = 'operator'
        OR source_event.maximum_audience = 'customer');
    IF jsonb_array_length(selected_webhook_pins) > 1000 THEN
      RAISE EXCEPTION 'notification webhook snapshot is oversized'
        USING ERRCODE = '54000';
    END IF;

    IF jsonb_array_length(selected_rule_pins) > 0 THEN
      SELECT 'tenant', configuration.id, configuration.current_version
      INTO selected_smtp_scope, selected_smtp_id, selected_smtp_version
      FROM public.tenant_notification_smtp_configurations AS configuration
      JOIN public.tenant_notification_smtp_configuration_versions AS version
        ON version.tenant_id = configuration.tenant_id
       AND version.configuration_id = configuration.id
       AND version.version = configuration.current_version
      WHERE configuration.tenant_id = context_tenant
        AND configuration.revoked_at IS NULL AND version.enabled
      ORDER BY configuration.id
      LIMIT 1;
      IF NOT FOUND THEN
        SELECT 'platform', configuration.id, configuration.current_version
        INTO selected_smtp_scope, selected_smtp_id, selected_smtp_version
        FROM public.platform_notification_smtp_configurations AS configuration
        JOIN public.platform_notification_smtp_configuration_versions AS version
          ON version.configuration_id = configuration.id
         AND version.version = configuration.current_version
        WHERE configuration.revoked_at IS NULL AND version.enabled
        ORDER BY configuration.id
        LIMIT 1;
      END IF;
    END IF;

    snapshot_value := jsonb_build_object(
      'rules', selected_rule_pins,
      'webhooks', selected_webhook_pins,
      'smtpScope', selected_smtp_scope,
      'smtpId', selected_smtp_id,
      'smtpVersion', selected_smtp_version
    );
    INSERT INTO public.tenant_notification_fanout_snapshots (
      tenant_id, event_id, rule_pins, webhook_configuration_pins,
      smtp_configuration_scope, smtp_configuration_id,
      smtp_configuration_version, snapshot_digest
    ) VALUES (
      context_tenant, p_event_id, selected_rule_pins, selected_webhook_pins,
      selected_smtp_scope, selected_smtp_id, selected_smtp_version,
      sha256(convert_to(snapshot_value::text, 'UTF8'))
    );
    SELECT snapshot.* INTO STRICT selected_snapshot
    FROM public.tenant_notification_fanout_snapshots AS snapshot
    WHERE snapshot.tenant_id = context_tenant
      AND snapshot.event_id = p_event_id;
  END IF;

  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'id', version.rule_id,
    'tenantId', version.tenant_id,
    'name', version.name,
    'description', version.description,
    'eventType', version.event_type,
    'objectType', version.object_type,
    'condition', version.condition,
    'recipients', version.recipients,
    'templateId', version.template_id,
    'templateVersion', version.template_version,
    'channel', version.channel,
    'priority', version.priority,
    'delayMs', version.delay_ms,
    'quietHours', version.quiet_hours,
    'deduplicationWindowMs', version.deduplication_window_ms,
    'grouping', version.grouping,
    'retry', version.retry,
    'enabled', version.enabled,
    'version', version.version,
    'effectiveFrom', version.effective_from,
    'effectiveUntil', version.effective_until
  )) ORDER BY version.rule_id, version.version), '[]'::jsonb)
  INTO rules_value
  FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
  JOIN public.tenant_notification_rule_versions AS version
    ON version.tenant_id = context_tenant
   AND version.rule_id = (pin.value ->> 'ruleId')::uuid
   AND version.version = (pin.value ->> 'version')::integer;

  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'id', version.template_id,
    'tenantId', version.tenant_id,
    'key', version.key,
    'name', version.name,
    'language', version.language,
    'version', version.version,
    'subject', version.subject,
    'html', version.html,
    'plainText', version.plain_text,
    'css', version.css
  )) ORDER BY version.template_id, version.version), '[]'::jsonb)
  INTO templates_value
  FROM (
    SELECT DISTINCT rule_version.template_id, rule_version.template_version
    FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
    JOIN public.tenant_notification_rule_versions AS rule_version
      ON rule_version.tenant_id = context_tenant
     AND rule_version.rule_id = (pin.value ->> 'ruleId')::uuid
     AND rule_version.version = (pin.value ->> 'version')::integer
  ) AS pinned_template
  JOIN public.tenant_notification_template_versions AS version
    ON version.tenant_id = context_tenant
   AND version.template_id = pinned_template.template_id
   AND version.version = pinned_template.template_version;

  IF EXISTS (
    SELECT 1
    FROM jsonb_array_elements(selected_snapshot.rule_pins) AS pin(value)
    JOIN public.tenant_notification_rule_versions AS version
      ON version.tenant_id = context_tenant
     AND version.rule_id = (pin.value ->> 'ruleId')::uuid
     AND version.version = (pin.value ->> 'version')::integer
    CROSS JOIN LATERAL jsonb_array_elements(version.recipients)
         AS recipient(value)
    WHERE recipient.value ->> 'kind' NOT IN (
      'assignee', 'previous_assignee', 'operator_team', 'watcher', 'mentioned',
      'actor', 'tenant_admin', 'platform_group', 'customer_contacts',
      'contact_group', 'contact_tag', 'explicit_email',
      'custom_email_field'
    )
  ) THEN
    RAISE EXCEPTION 'notification recipient source is unavailable'
      USING ERRCODE = '0A000';
  END IF;

  WITH operator_candidates AS (
    SELECT candidate.sort_email, candidate.sort_principal,
           candidate.sort_source, candidate.value
    FROM app.private_notification_operator_candidates_v2(
      context_tenant, p_event_id
    ) AS candidate
  ), customer_candidates AS (
    SELECT contact.email AS sort_email,
           contact.id AS sort_principal,
           'customer'::text AS sort_source,
           jsonb_strip_nulls(jsonb_build_object(
      'tenantId', contact.tenant_id,
      'email', contact.email,
      'audience', 'customer',
      'kinds', jsonb_build_array('customer_contacts')
        || CASE WHEN cardinality(matched_group.keys) > 0
          THEN jsonb_build_array('contact_group') ELSE '[]'::jsonb END
        || CASE WHEN cardinality(contact.tags) > 0
          THEN jsonb_build_array('contact_tag') ELSE '[]'::jsonb END,
      'values', jsonb_strip_nulls(jsonb_build_object(
        'contact_group', CASE WHEN cardinality(matched_group.keys) > 0
          THEN to_jsonb(matched_group.keys) END,
        'contact_tag', CASE WHEN cardinality(contact.tags) > 0
          THEN to_jsonb(contact.tags) END
      )),
      'principalId', live_account.user_id,
      'enabled', contact.active,
      'emailAllowed', contact.email_allowed
    )) AS value
    FROM public.customer_contacts AS contact
    LEFT JOIN LATERAL (
      SELECT membership.user_id
      FROM public.tenant_memberships AS membership
      JOIN public.users AS identity
        ON identity.id = membership.user_id
      WHERE contact.linked_membership_id IS NOT NULL
        AND contact.linked_user_id IS NOT NULL
        AND membership.tenant_id = contact.tenant_id
        AND membership.id = contact.linked_membership_id
        AND membership.user_id = contact.linked_user_id
        AND membership.status = 'active'
        AND identity.active
      LIMIT 1
    ) AS live_account ON true
    LEFT JOIN LATERAL (
      SELECT array_agg(group_row.key ORDER BY group_row.key COLLATE "C") AS keys
      FROM public.customer_contact_groups AS group_row
      JOIN public.customer_contact_group_versions AS group_version
        ON group_version.tenant_id = group_row.tenant_id
       AND group_version.group_id = group_row.id
       AND group_version.version = group_row.current_version
      WHERE group_row.tenant_id = contact.tenant_id
        AND group_row.archived_at IS NULL
        AND (
          group_version.mode = 'manual' AND EXISTS (
            SELECT 1
            FROM public.customer_contact_group_version_members AS member
            WHERE member.tenant_id = group_version.tenant_id
              AND member.group_id = group_version.group_id
              AND member.group_version = group_version.version
              AND member.contact_id = contact.id
          )
          OR group_version.mode = 'dynamic'
             AND app.private_contact_rule_matches_v1(
               group_version.rule, contact
             )
        )
    ) AS matched_group ON true
    WHERE contact.tenant_id = context_tenant
      AND source_event.maximum_audience = 'customer'
      AND contact.active AND contact.archived_at IS NULL
      AND contact.email_allowed
      AND contact.notification_categories @> ARRAY[
        substring(source_event.event_type from 14)
      ]::text[]
      AND (
        NOT EXISTS (
          SELECT 1
          FROM public.customer_contact_notification_windows AS any_window
          WHERE any_window.tenant_id = contact.tenant_id
            AND any_window.contact_id = contact.id
        )
        OR EXISTS (
          SELECT 1
          FROM public.customer_contact_notification_windows AS allowed_window
          CROSS JOIN LATERAL (
            SELECT source_event.occurred_at AT TIME ZONE contact.timezone
              AS local_time
          ) AS local_event
          WHERE allowed_window.tenant_id = contact.tenant_id
            AND allowed_window.contact_id = contact.id
            AND allowed_window.iso_weekday = extract(
              isodow FROM local_event.local_time
            )::integer
            AND extract(hour FROM local_event.local_time)::integer * 60
              + extract(minute FROM local_event.local_time)::integer
                >= allowed_window.start_minute
            AND extract(hour FROM local_event.local_time)::integer * 60
              + extract(minute FROM local_event.local_time)::integer
                < allowed_window.end_minute
        )
      )
      AND (
        source_event.aggregate_type = 'alert'
        AND app.private_notification_ticket_is_customer_projectable_v1(
          context_tenant, 'alert', source_event.aggregate_id
        )
        AND EXISTS (
          SELECT 1 FROM public.ticket_customer_contacts AS link
          WHERE link.tenant_id = context_tenant
            AND link.alert_id = source_event.aggregate_id
            AND link.contact_id = contact.id
            AND link.archived_at IS NULL
        )
        OR source_event.aggregate_type = 'case'
        AND app.private_notification_ticket_is_customer_projectable_v1(
          context_tenant, 'case', source_event.aggregate_id
        )
        AND EXISTS (
          SELECT 1 FROM public.ticket_customer_contacts AS link
          WHERE link.tenant_id = context_tenant
            AND link.case_id = source_event.aggregate_id
            AND link.contact_id = contact.id
            AND link.archived_at IS NULL
        )
      )
  ), all_candidates AS (
    SELECT * FROM operator_candidates
    UNION ALL
    SELECT * FROM customer_candidates
  )
  SELECT count(*)::integer,
         coalesce(jsonb_agg(candidate.value ORDER BY
           candidate.sort_email COLLATE "C", candidate.sort_source COLLATE "C",
           candidate.sort_principal
         ), '[]'::jsonb)
  INTO candidate_count, candidates_value
  FROM all_candidates AS candidate;
  IF candidate_count > 10000 THEN
    RAISE EXCEPTION 'notification recipient inventory is oversized'
      USING ERRCODE = '54000';
  END IF;

  RETURN jsonb_build_object(
    'rules', rules_value,
    'candidates', candidates_value,
    'templates', templates_value,
    'smtpConfiguration', CASE
      WHEN selected_snapshot.smtp_configuration_id IS NULL THEN NULL
      ELSE jsonb_build_object(
        'scope', selected_snapshot.smtp_configuration_scope,
        'id', selected_snapshot.smtp_configuration_id,
        'version', selected_snapshot.smtp_configuration_version
      ) END
  );
END;
$function$;
--> statement-breakpoint
ALTER FUNCTION app.load_notification_fanout_inputs_v3(uuid, uuid)
  OWNER TO periapsis_notification_dispatch_owner;
--> statement-breakpoint
REVOKE ALL ON FUNCTION app.load_notification_fanout_inputs_v3(uuid, uuid)
  FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor,
       periapsis_ticket_runtime_owner;
--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v3(uuid, uuid)
  TO periapsis_notifier;
