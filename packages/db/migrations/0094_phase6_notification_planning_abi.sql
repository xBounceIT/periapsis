CREATE FUNCTION app.load_notification_fanout_inputs_v1(
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
BEGIN
  context_tenant := app.private_lock_notification_fanout_claim_v1(p_event_id, p_fence_token);
  SELECT event.* INTO STRICT source_event
  FROM public.outbox_events AS event
  WHERE event.id = p_event_id AND event.tenant_id = context_tenant;
  IF NOT EXISTS (
    SELECT 1 FROM public.tenants AS tenant
    WHERE tenant.id = context_tenant AND tenant.status = 'active'
  ) THEN
    RAISE EXCEPTION 'notification tenant is unavailable' USING ERRCODE = '42501';
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
      AND (version.effective_until IS NULL OR version.effective_until > source_event.occurred_at);
    IF jsonb_array_length(selected_rule_pins) > 1000 THEN
      RAISE EXCEPTION 'notification rule snapshot is oversized' USING ERRCODE = '54000';
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
      AND substring(source_event.event_type from 14)::public.notification_event_type = ANY(version.event_types)
      AND (version.audience = 'operator' OR source_event.maximum_audience = 'customer');
    IF jsonb_array_length(selected_webhook_pins) > 1000 THEN
      RAISE EXCEPTION 'notification webhook snapshot is oversized' USING ERRCODE = '54000';
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
        AND configuration.revoked_at IS NULL
        AND version.enabled
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
    WHERE snapshot.tenant_id = context_tenant AND snapshot.event_id = p_event_id;
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
    CROSS JOIN LATERAL jsonb_array_elements(version.recipients) AS recipient(value)
    WHERE recipient.value ->> 'kind' NOT IN (
      'assignee', 'previous_assignee', 'operator_team', 'actor',
      'tenant_admin', 'explicit_email', 'custom_email_field'
    )
  ) THEN
    RAISE EXCEPTION 'notification recipient source is unavailable'
      USING ERRCODE = '0A000';
  END IF;

  IF (SELECT count(*) FROM public.tenant_user_profiles AS profile
      JOIN public.tenant_memberships AS membership
        ON membership.tenant_id = profile.tenant_id
       AND membership.id = profile.membership_id
      JOIN public.users AS identity ON identity.id = profile.user_id
      WHERE profile.tenant_id = context_tenant
        AND profile.email IS NOT NULL
        AND membership.status = 'active' AND identity.active) > 10000 THEN
    RAISE EXCEPTION 'notification recipient inventory is oversized' USING ERRCODE = '54000';
  END IF;
  SELECT coalesce(jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
    'tenantId', profile.tenant_id,
    'email', profile.email,
    'audience', CASE WHEN membership.role IN ('customer_manager', 'customer_user')
                     THEN 'customer' ELSE 'operator' END,
    'kinds', (CASE WHEN identity.id = source_event.actor_id
      THEN jsonb_build_array('actor') ELSE '[]'::jsonb END)
      || (CASE WHEN identity.id::text = source_event.payload #>> '{operatorContext,routing,assigneeUserId}'
        THEN jsonb_build_array('assignee') ELSE '[]'::jsonb END)
      || (CASE WHEN identity.id::text = source_event.payload #>> '{operatorContext,routing,previousAssigneeUserId}'
        THEN jsonb_build_array('previous_assignee') ELSE '[]'::jsonb END)
      || (CASE WHEN EXISTS (
        SELECT 1
        FROM public.operator_team_roster_entries AS roster
        WHERE roster.tenant_id = context_tenant
          AND roster.membership_id = membership.id
          AND roster.assignment_epoch_id::text = source_event.payload #>> '{operatorContext,routing,operatorTeamEpochId}'
          AND roster.granted_at <= source_event.occurred_at
          AND (roster.expires_at IS NULL OR roster.expires_at > source_event.occurred_at)
          AND (roster.revoked_at IS NULL OR roster.revoked_at > source_event.occurred_at)
      ) THEN jsonb_build_array('operator_team') ELSE '[]'::jsonb END)
      || (CASE WHEN membership.role = 'tenant_admin'
        THEN jsonb_build_array('tenant_admin') ELSE '[]'::jsonb END),
    'values', CASE WHEN EXISTS (
      SELECT 1
      FROM public.operator_team_roster_entries AS roster
      WHERE roster.tenant_id = context_tenant
        AND roster.membership_id = membership.id
        AND roster.assignment_epoch_id::text = source_event.payload #>> '{operatorContext,routing,operatorTeamEpochId}'
        AND roster.granted_at <= source_event.occurred_at
        AND (roster.expires_at IS NULL OR roster.expires_at > source_event.occurred_at)
        AND (roster.revoked_at IS NULL OR roster.revoked_at > source_event.occurred_at)
    ) THEN jsonb_build_object(
      'operator_team', jsonb_build_array(
        source_event.payload #>> '{operatorContext,routing,operatorTeamId}'
      )
    ) ELSE '{}'::jsonb END,
    'principalId', identity.id,
    'enabled', true,
    'emailAllowed', true
  )) ORDER BY profile.email, identity.id), '[]'::jsonb)
  INTO candidates_value
  FROM public.tenant_user_profiles AS profile
  JOIN public.tenant_memberships AS membership
    ON membership.tenant_id = profile.tenant_id
   AND membership.id = profile.membership_id
  JOIN public.users AS identity ON identity.id = profile.user_id
  WHERE profile.tenant_id = context_tenant
    AND profile.email IS NOT NULL
    AND membership.status = 'active' AND identity.active;

  RETURN jsonb_build_object(
    'rules', rules_value,
    'candidates', candidates_value,
    'templates', templates_value,
    'smtpConfiguration', CASE WHEN selected_snapshot.smtp_configuration_id IS NULL THEN NULL
      ELSE jsonb_build_object(
        'scope', selected_snapshot.smtp_configuration_scope,
        'id', selected_snapshot.smtp_configuration_id,
        'version', selected_snapshot.smtp_configuration_version
      ) END
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.load_notification_fanout_inputs_v1(uuid, uuid) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.load_notification_fanout_inputs_v1(uuid, uuid) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.load_notification_fanout_inputs_v1(uuid, uuid) TO periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.commit_notification_fanout_v1(
  p_event_id uuid,
  p_fence_token uuid,
  p_deliveries jsonb,
  p_committed_at timestamp with time zone
)
RETURNS jsonb
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  source_event public.outbox_events%ROWTYPE;
  selected_snapshot public.tenant_notification_fanout_snapshots%ROWTYPE;
  delivery_value jsonb;
  webhook_pin jsonb;
  webhook_version public.tenant_notification_webhook_configuration_versions%ROWTYPE;
  webhook_configuration public.tenant_notification_webhook_configurations%ROWTYPE;
  webhook_current public.tenant_notification_webhook_configuration_versions%ROWTYPE;
  webhook_secret public.tenant_notification_secret_versions%ROWTYPE;
  selected_rule public.tenant_notification_rule_versions%ROWTYPE;
  delivery_digest bytea;
  webhook_delivery_key text;
  selected_context jsonb;
  destination text;
  inserted_id uuid;
  webhook_payload jsonb;
  webhook_cancelled boolean;
  persisted_email_count integer;
  persisted_webhook_count integer;
  cancelled_webhook_count integer;
BEGIN
  IF p_event_id IS NULL OR p_fence_token IS NULL
     OR p_deliveries IS NULL OR jsonb_typeof(p_deliveries) <> 'array'
     OR jsonb_array_length(p_deliveries) > 10000
     OR octet_length(p_deliveries::text) > 8388608
     OR p_committed_at IS NULL
     OR p_committed_at < transaction_timestamp() - interval '5 minutes'
     OR p_committed_at > transaction_timestamp() + interval '1 minute' THEN
    RAISE EXCEPTION 'notification fanout commit input is invalid' USING ERRCODE = '22023';
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
  SELECT snapshot.* INTO selected_snapshot
  FROM public.tenant_notification_fanout_snapshots AS snapshot
  WHERE snapshot.tenant_id = source_event.tenant_id AND snapshot.event_id = p_event_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification fanout snapshot not found' USING ERRCODE = '40001';
  END IF;
  delivery_digest := sha256(selected_snapshot.snapshot_digest || convert_to(p_deliveries::text, 'UTF8'));
  IF source_event.processed_at IS NOT NULL THEN
    IF source_event.fanout_commit_digest = delivery_digest THEN
      RETURN jsonb_build_object(
        'outcome', 'already_committed',
        'emailCount', 0,
        'webhookCount', 0,
        'cancelledWebhookCount', 0,
        'totalCount', 0
      );
    END IF;
    RAISE EXCEPTION 'notification fanout replay does not match' USING ERRCODE = '40001';
  END IF;
  IF source_event.lease_token IS DISTINCT FROM p_fence_token
     OR source_event.lease_until <= transaction_timestamp() THEN
    RAISE EXCEPTION 'notification fanout claim is stale' USING ERRCODE = '40001';
  END IF;

  FOR delivery_value IN
    SELECT item.value FROM jsonb_array_elements(p_deliveries) WITH ORDINALITY AS item(value, ordinal)
    ORDER BY item.ordinal
  LOOP
    IF jsonb_typeof(delivery_value) <> 'object'
       OR delivery_value - ARRAY[
         'deliveryKey', 'tenantId', 'eventId', 'ruleId', 'ruleVersion',
         'smtpConfigurationScope', 'smtpConfigurationId',
         'smtpConfigurationVersion', 'template',
         'recipient', 'audience', 'context', 'priority', 'deliverAfter',
         'deduplicationKey', 'groupingKey', 'groupingWindowMs',
         'groupingMaximumItems', 'retry'
       ]::text[] <> '{}'::jsonb
       OR delivery_value ->> 'tenantId' <> source_event.tenant_id::text
       OR delivery_value ->> 'eventId' <> p_event_id::text
       OR delivery_value ->> 'deliveryKey' !~ '^[0-9a-f]{64}$'
       OR jsonb_typeof(delivery_value -> 'template') <> 'object'
       OR jsonb_typeof(delivery_value -> 'context') <> 'object'
       OR jsonb_typeof(delivery_value -> 'retry') <> 'object'
       OR delivery_value ->> 'audience' NOT IN ('operator', 'customer')
       OR (delivery_value ->> 'audience' = 'customer' AND source_event.maximum_audience <> 'customer')
       OR lower(btrim(delivery_value ->> 'recipient')) <> delivery_value ->> 'recipient'
       OR position('@' in (delivery_value ->> 'recipient')) <= 1
       OR char_length(delivery_value ->> 'recipient') > 320
       OR delivery_value ->> 'smtpConfigurationScope' IS DISTINCT FROM selected_snapshot.smtp_configuration_scope
       OR (delivery_value ->> 'smtpConfigurationId')::uuid IS DISTINCT FROM selected_snapshot.smtp_configuration_id
       OR (delivery_value ->> 'smtpConfigurationVersion')::integer IS DISTINCT FROM selected_snapshot.smtp_configuration_version
       OR selected_snapshot.smtp_configuration_scope NOT IN ('tenant', 'platform')
       OR NOT selected_snapshot.rule_pins @> jsonb_build_array(jsonb_build_object(
         'ruleId', delivery_value ->> 'ruleId',
         'version', (delivery_value ->> 'ruleVersion')::integer
       )) THEN
      RAISE EXCEPTION 'planned notification delivery is invalid' USING ERRCODE = '22023';
    END IF;
    SELECT version.* INTO STRICT selected_rule
    FROM public.tenant_notification_rule_versions AS version
    WHERE version.tenant_id = source_event.tenant_id
      AND version.rule_id = (delivery_value ->> 'ruleId')::uuid
      AND version.version = (delivery_value ->> 'ruleVersion')::integer
      AND version.channel = 'email'
      AND version.template_id = (delivery_value #>> '{template,id}')::uuid
      AND version.template_version = (delivery_value #>> '{template,version}')::integer;

    destination := delivery_value ->> 'recipient';
    INSERT INTO public.tenant_notification_deliveries (
      id, tenant_id, event_id, delivery_key, rule_id, rule_version,
      template_id, template_version, smtp_configuration_scope,
      smtp_configuration_id, smtp_configuration_version, channel, audience,
      recipient, destination_redacted, context, priority, deduplication_key,
      grouping_key, grouping_window_ms, grouping_maximum_items, retry,
      maximum_attempts, next_attempt_at, created_at, updated_at
    ) VALUES (
      uuidv7(), source_event.tenant_id, p_event_id,
      delivery_value ->> 'deliveryKey', selected_rule.rule_id, selected_rule.version,
      selected_rule.template_id, selected_rule.template_version,
      selected_snapshot.smtp_configuration_scope,
      selected_snapshot.smtp_configuration_id,
      selected_snapshot.smtp_configuration_version,
      'email', (delivery_value ->> 'audience')::public.notification_audience,
      destination,
      left(split_part(destination, '@', 1), 1) || '***@' || split_part(destination, '@', 2),
      delivery_value -> 'context', (delivery_value ->> 'priority')::integer,
      delivery_value ->> 'deduplicationKey', nullif(delivery_value ->> 'groupingKey', ''),
      (delivery_value ->> 'groupingWindowMs')::bigint,
      (delivery_value ->> 'groupingMaximumItems')::integer,
      delivery_value -> 'retry',
      (delivery_value #>> '{retry,maximumAttempts}')::integer,
      (delivery_value ->> 'deliverAfter')::timestamp with time zone,
      p_committed_at, p_committed_at
    )
    ON CONFLICT (tenant_id, delivery_key) DO NOTHING
    RETURNING id INTO inserted_id;
    IF inserted_id IS NULL AND NOT EXISTS (
      SELECT 1 FROM public.tenant_notification_deliveries AS existing
      WHERE existing.tenant_id = source_event.tenant_id
        AND existing.delivery_key = delivery_value ->> 'deliveryKey'
        AND existing.event_id = p_event_id
        AND existing.rule_id = selected_rule.rule_id
        AND existing.rule_version = selected_rule.version
        AND existing.template_id = selected_rule.template_id
        AND existing.template_version = selected_rule.template_version
        AND existing.smtp_configuration_scope = selected_snapshot.smtp_configuration_scope
        AND existing.smtp_configuration_id = selected_snapshot.smtp_configuration_id
        AND existing.smtp_configuration_version = selected_snapshot.smtp_configuration_version
        AND existing.recipient = destination
        AND existing.audience = (delivery_value ->> 'audience')::public.notification_audience
        AND existing.context = delivery_value -> 'context'
        AND existing.priority = (delivery_value ->> 'priority')::integer
        AND existing.deduplication_key = delivery_value ->> 'deduplicationKey'
        AND existing.grouping_key IS NOT DISTINCT FROM nullif(delivery_value ->> 'groupingKey', '')
        AND existing.grouping_window_ms = (delivery_value ->> 'groupingWindowMs')::bigint
        AND existing.grouping_maximum_items = (delivery_value ->> 'groupingMaximumItems')::integer
        AND existing.retry = delivery_value -> 'retry'
        AND existing.next_attempt_at = (delivery_value ->> 'deliverAfter')::timestamp with time zone
    ) THEN
      RAISE EXCEPTION 'notification delivery key collision' USING ERRCODE = '23505';
    END IF;
    inserted_id := NULL;
  END LOOP;

  FOR webhook_pin IN
    SELECT pin.value
    FROM jsonb_array_elements(selected_snapshot.webhook_configuration_pins) AS pin(value)
    ORDER BY pin.value ->> 'configurationId', (pin.value ->> 'version')::integer
  LOOP
    SELECT configuration.* INTO STRICT webhook_configuration
    FROM public.tenant_notification_webhook_configurations AS configuration
    WHERE configuration.tenant_id = source_event.tenant_id
      AND configuration.id = (webhook_pin ->> 'configurationId')::uuid;
    SELECT pinned.* INTO STRICT webhook_version
    FROM public.tenant_notification_webhook_configuration_versions AS pinned
    WHERE pinned.tenant_id = source_event.tenant_id
      AND pinned.configuration_id = webhook_configuration.id
      AND pinned.version = (webhook_pin ->> 'version')::integer
      AND substring(source_event.event_type from 14)::public.notification_event_type = ANY(pinned.event_types)
      AND (pinned.audience = 'operator' OR source_event.maximum_audience = 'customer');
    SELECT current_version.* INTO STRICT webhook_current
    FROM public.tenant_notification_webhook_configuration_versions AS current_version
    WHERE current_version.tenant_id = source_event.tenant_id
      AND current_version.configuration_id = webhook_configuration.id
      AND current_version.version = webhook_configuration.current_version;
    webhook_cancelled := webhook_configuration.revoked_at IS NOT NULL
      OR NOT webhook_current.enabled OR NOT webhook_version.enabled;
    SELECT secret.* INTO STRICT webhook_secret
    FROM public.tenant_notification_secret_versions AS secret
    WHERE secret.tenant_id = source_event.tenant_id
      AND secret.secret_id = webhook_version.signing_secret_id
      AND secret.version = webhook_version.signing_secret_version
      AND secret.kind = 'webhook_signing_key';

    selected_context := CASE webhook_version.audience
      WHEN 'customer' THEN source_event.payload -> 'customerContext'
      ELSE source_event.payload -> 'operatorContext' END;
    IF selected_context IS NULL OR jsonb_typeof(selected_context) <> 'object' THEN
      RAISE EXCEPTION 'webhook audience projection is unavailable' USING ERRCODE = '42501';
    END IF;
    webhook_delivery_key := encode(sha256(convert_to(
      'periapsis:notification-webhook-delivery:v1|' || source_event.tenant_id::text
      || '|' || p_event_id::text || '|' || webhook_version.configuration_id::text
      || '|' || webhook_version.version::text || '|' || webhook_version.audience::text,
      'UTF8'
    )), 'hex');
    webhook_payload := jsonb_build_object(
      'schemaVersion', 1,
      'event', jsonb_build_object(
        'id', p_event_id,
        'type', substring(source_event.event_type from 14),
        'objectType', source_event.aggregate_type,
        'objectId', source_event.aggregate_id,
        'objectVersion', source_event.aggregate_version,
        'occurredAt', source_event.occurred_at
      ),
      'context', selected_context
    );
    INSERT INTO public.tenant_notification_deliveries (
      id, tenant_id, event_id, delivery_key,
      webhook_configuration_id, webhook_configuration_version,
      webhook_signing_secret_id, webhook_signing_secret_version,
      webhook_signing_key_version, webhook_payload_version, webhook_payload,
      channel, audience, recipient, destination_redacted, context, priority,
      deduplication_key, grouping_window_ms, grouping_maximum_items, retry,
      status, maximum_attempts, next_attempt_at,
      failure_at, failure_class, failure_code, created_at, updated_at
    ) VALUES (
      uuidv7(), source_event.tenant_id, p_event_id, webhook_delivery_key,
      webhook_version.configuration_id, webhook_version.version,
      webhook_secret.secret_id, webhook_secret.version, webhook_secret.key_version,
      1, webhook_payload,
      'webhook', webhook_version.audience,
      'webhook:' || webhook_version.configuration_id::text,
      'webhook:' || left(webhook_version.configuration_id::text, 8) || '…',
      selected_context, 50, webhook_delivery_key, 0, 1,
      '{"maximumAttempts":12,"initialDelayMs":1000,"maximumDelayMs":300000,"multiplier":2,"jitterPercent":20}'::jsonb,
      CASE WHEN webhook_cancelled THEN 'dead_lettered' ELSE 'queued' END,
      12, CASE WHEN webhook_cancelled THEN NULL ELSE p_committed_at END,
      CASE WHEN webhook_cancelled THEN p_committed_at END,
      CASE WHEN webhook_cancelled THEN 'security'::public.notification_failure_class END,
      CASE WHEN webhook_cancelled THEN 'configuration_revoked' END,
      p_committed_at, p_committed_at
    ) ON CONFLICT (tenant_id, delivery_key) DO NOTHING
    RETURNING id INTO inserted_id;
    IF inserted_id IS NULL AND NOT EXISTS (
      SELECT 1 FROM public.tenant_notification_deliveries AS existing
      WHERE existing.tenant_id = source_event.tenant_id
        AND existing.delivery_key = webhook_delivery_key
        AND existing.event_id = p_event_id
        AND existing.webhook_configuration_id = webhook_version.configuration_id
        AND existing.webhook_configuration_version = webhook_version.version
        AND existing.webhook_signing_secret_id = webhook_secret.secret_id
        AND existing.webhook_signing_secret_version = webhook_secret.version
        AND existing.webhook_signing_key_version = webhook_secret.key_version
        AND existing.webhook_payload_version = 1
        AND existing.webhook_payload = webhook_payload
        AND existing.audience = webhook_version.audience
        AND existing.status = CASE WHEN webhook_cancelled THEN 'dead_lettered'::public.notification_delivery_status ELSE 'queued'::public.notification_delivery_status END
    ) THEN
      RAISE EXCEPTION 'notification webhook delivery key collision' USING ERRCODE = '23505';
    END IF;
    inserted_id := NULL;
  END LOOP;

  UPDATE public.outbox_events AS event
  SET processed_at = p_committed_at,
      fanout_commit_digest = delivery_digest,
      locked_at = NULL,
      locked_by = NULL,
      lease_token = NULL,
      lease_until = NULL,
      last_error = NULL,
      failure_category = NULL
  WHERE event.id = p_event_id
    AND event.lease_token = p_fence_token
    AND event.processed_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification fanout completion was fenced' USING ERRCODE = '40001';
  END IF;
  SELECT count(*) FILTER (WHERE delivery.channel = 'email'),
         count(*) FILTER (WHERE delivery.channel = 'webhook'),
         count(*) FILTER (WHERE delivery.channel = 'webhook' AND delivery.status = 'dead_lettered')
  INTO persisted_email_count, persisted_webhook_count, cancelled_webhook_count
  FROM public.tenant_notification_deliveries AS delivery
  WHERE delivery.tenant_id = source_event.tenant_id
    AND delivery.event_id = p_event_id
    AND delivery.parent_delivery_id IS NULL;
  RETURN jsonb_build_object(
    'outcome', 'committed',
    'emailCount', persisted_email_count,
    'webhookCount', persisted_webhook_count,
    'cancelledWebhookCount', cancelled_webhook_count,
    'totalCount', persisted_email_count + persisted_webhook_count
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.commit_notification_fanout_v1(uuid, uuid, jsonb, timestamp with time zone) OWNER TO periapsis_notification_dispatch_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.commit_notification_fanout_v1(uuid, uuid, jsonb, timestamp with time zone) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.commit_notification_fanout_v1(uuid, uuid, jsonb, timestamp with time zone) TO periapsis_notifier;--> statement-breakpoint
