-- Phase 6 notification administration ABI. The API runtime has no direct
-- access to notification tables: every read and mutation rechecks live
-- authority through this bounded tenant/platform surface.

GRANT EXECUTE ON FUNCTION app.lock_current_tenant_authorization_state()
TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE POLICY notification_admin_owner_platform_smtp_inheritance_v1
ON public.platform_notification_smtp_configurations
AS PERMISSIVE FOR SELECT TO periapsis_notification_admin_owner
USING (app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint

CREATE POLICY notification_admin_owner_platform_smtp_versions_inheritance_v1
ON public.platform_notification_smtp_configuration_versions
AS PERMISSIVE FOR SELECT TO periapsis_notification_admin_owner
USING (app.current_tenant_membership_id() IS NOT NULL);--> statement-breakpoint

CREATE FUNCTION app.private_require_notification_admin_v1()
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.lock_current_tenant_authorization_state();
  IF app.context_tenant_id() IS NULL
     OR app.context_user_id() IS NULL
     OR app.current_tenant_membership_id() IS NULL
     OR NOT app.current_tenant_human_has_exact_permission_v3(
       'notification.manage', 'tenant'
     ) THEN
    RAISE EXCEPTION 'tenant-scoped notification.manage is required'
      USING ERRCODE = '42501';
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_require_notification_admin_v1()
OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_require_notification_admin_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
     periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_require_notification_admin_v1()
TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.private_tenant_notification_projection_v1(
  p_kind text,
  p_resource_id uuid,
  p_version integer DEFAULT NULL,
  p_include_attempts boolean DEFAULT false
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  projection jsonb;
BEGIN
  IF p_kind NOT IN ('rule', 'template', 'delivery', 'webhook')
     OR p_resource_id IS NULL
     OR p_version IS NOT NULL AND p_version NOT BETWEEN 1 AND 2147483647
     OR p_include_attempts IS NULL
     OR p_kind <> 'delivery' AND p_include_attempts THEN
    RAISE EXCEPTION 'notification projection input is invalid'
      USING ERRCODE = '22023';
  END IF;

  CASE p_kind
    WHEN 'rule' THEN
      IF p_version IS NOT NULL THEN
        RAISE EXCEPTION 'rule version is selected by its identity row'
          USING ERRCODE = '22023';
      END IF;
      SELECT jsonb_strip_nulls(jsonb_build_object(
        'id', identity.id, 'tenantId', identity.tenant_id,
        'version', version.version, 'name', version.name,
        'description', version.description, 'eventType', version.event_type,
        'objectType', version.object_type, 'condition', version.condition,
        'recipients', version.recipients, 'templateId', version.template_id,
        'templateVersion', version.template_version,
        'channel', version.channel, 'priority', version.priority,
        'delayMs', version.delay_ms, 'quietHours', version.quiet_hours,
        'deduplicationWindowMs', version.deduplication_window_ms,
        'grouping', version.grouping, 'retry', version.retry,
        'enabled', version.enabled, 'effectiveFrom', version.effective_from,
        'effectiveUntil', version.effective_until,
        'createdAt', version.created_at, 'createdBy', version.created_by_user_id
      )) INTO projection
      FROM public.tenant_notification_rules AS identity
      JOIN public.tenant_notification_rule_versions AS version
        ON version.tenant_id = identity.tenant_id
       AND version.rule_id = identity.id
       AND version.version = identity.current_version
      WHERE identity.tenant_id = context_tenant
        AND identity.id = p_resource_id;
    WHEN 'template' THEN
      SELECT jsonb_strip_nulls(jsonb_build_object(
        'id', identity.id, 'tenantId', identity.tenant_id,
        'version', version.version, 'key', version.key,
        'name', version.name, 'language', version.language,
        'subject', version.subject, 'html', version.html,
        'plainText', version.plain_text, 'css', version.css,
        'sampleData', version.sample_data,
        'placeholders', to_jsonb(version.placeholders),
        'createdAt', version.created_at, 'createdBy', version.created_by_user_id
      )) INTO projection
      FROM public.tenant_notification_templates AS identity
      JOIN public.tenant_notification_template_versions AS version
        ON version.tenant_id = identity.tenant_id
       AND version.template_id = identity.id
       AND version.version = coalesce(p_version, identity.current_version)
      WHERE identity.tenant_id = context_tenant
        AND identity.id = p_resource_id;
    WHEN 'webhook' THEN
      IF p_version IS NOT NULL THEN
        RAISE EXCEPTION 'webhook version is selected by its identity row'
          USING ERRCODE = '22023';
      END IF;
      SELECT jsonb_build_object(
        'id', identity.id, 'tenantId', identity.tenant_id,
        'version', version.version, 'name', version.name,
        'endpointUrl', version.endpoint_url,
        'eventTypes', to_jsonb(version.event_types),
        'audience', version.audience,
        'signingKeyConfigured', true,
        'signingKeyVersion', secret.key_version,
        'timeoutMs', version.timeout_ms, 'enabled', version.enabled,
        'createdAt', version.created_at, 'createdBy', version.created_by_user_id
      ) INTO projection
      FROM public.tenant_notification_webhook_configurations AS identity
      JOIN public.tenant_notification_webhook_configuration_versions AS version
        ON version.tenant_id = identity.tenant_id
       AND version.configuration_id = identity.id
       AND version.version = identity.current_version
      JOIN public.tenant_notification_secret_versions AS secret
        ON secret.tenant_id = version.tenant_id
       AND secret.secret_id = version.signing_secret_id
       AND secret.version = version.signing_secret_version
       AND secret.kind = 'webhook_signing_key'
      WHERE identity.tenant_id = context_tenant
        AND identity.id = p_resource_id
        AND identity.revoked_at IS NULL;
    WHEN 'delivery' THEN
      IF p_version IS NOT NULL THEN
        RAISE EXCEPTION 'delivery does not accept a resource version'
          USING ERRCODE = '22023';
      END IF;
      SELECT jsonb_strip_nulls(jsonb_build_object(
        'id', delivery.id, 'tenantId', delivery.tenant_id,
        'eventId', delivery.event_id,
        'parentDeliveryId', delivery.parent_delivery_id,
        'ruleId', delivery.rule_id, 'ruleVersion', delivery.rule_version,
        'templateId', delivery.template_id,
        'templateVersion', delivery.template_version,
        'smtpConfigurationScope', delivery.smtp_configuration_scope,
        'smtpConfigurationId', delivery.smtp_configuration_id,
        'smtpConfigurationVersion', delivery.smtp_configuration_version,
        'webhookConfigurationId', delivery.webhook_configuration_id,
        'webhookConfigurationVersion', delivery.webhook_configuration_version,
        'webhookSigningKeyVersion', delivery.webhook_signing_key_version,
        'channel', delivery.channel, 'audience', delivery.audience,
        'status', delivery.status,
        'destinationRedacted', delivery.destination_redacted,
        'attemptCount', delivery.attempt_count,
        'maximumAttempts', delivery.maximum_attempts,
        'nextAttemptAt', delivery.next_attempt_at,
        'deliveredAt', delivery.delivered_at,
        'failureAt', delivery.failure_at,
        'failureClass', delivery.failure_class,
        'createdAt', delivery.created_at,
        'attempts', CASE WHEN p_include_attempts THEN coalesce((
          SELECT jsonb_agg(jsonb_strip_nulls(jsonb_build_object(
            'number', attempt.attempt,
            'startedAt', attempt.started_at,
            'completedAt', attempt.completed_at,
            'outcome', coalesce(attempt.outcome, 'in_progress'),
            'failureClass', attempt.failure_class,
            'providerReceipt', attempt.provider_receipt
          )) ORDER BY attempt.attempt)
          FROM public.tenant_notification_delivery_attempts AS attempt
          WHERE attempt.tenant_id = delivery.tenant_id
            AND attempt.delivery_id = delivery.id
        ), '[]'::jsonb) ELSE '[]'::jsonb END
      )) INTO projection
      FROM public.tenant_notification_deliveries AS delivery
      WHERE delivery.tenant_id = context_tenant
        AND delivery.id = p_resource_id;
  END CASE;

  IF projection IS NULL THEN
    RAISE EXCEPTION 'notification resource was not found' USING ERRCODE = 'P0002';
  END IF;
  RETURN projection;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_tenant_notification_projection_v1(
  text, uuid, integer, boolean
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_tenant_notification_projection_v1(
  text, uuid, integer, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_tenant_notification_projection_v1(
  text, uuid, integer, boolean
) TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_notification_resource_v1(
  p_kind text,
  p_resource_id uuid,
  p_version integer DEFAULT NULL,
  p_include_attempts boolean DEFAULT false
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  RETURN app.private_tenant_notification_projection_v1(
    p_kind, p_resource_id, p_version, p_include_attempts
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_notification_resource_v1(
  text, uuid, integer, boolean
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_notification_resource_v1(
  text, uuid, integer, boolean
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_notification_resource_v1(
  text, uuid, integer, boolean
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.list_tenant_notification_resources_v1(
  p_kind text,
  p_after_created_at timestamp with time zone,
  p_after_id uuid,
  p_statuses public.notification_delivery_status[],
  p_limit integer
)
RETURNS TABLE(item jsonb)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  selected record;
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  IF p_kind NOT IN ('rule', 'template', 'delivery', 'webhook')
     OR (p_after_created_at IS NULL) <> (p_after_id IS NULL)
     OR p_statuses IS NULL OR cardinality(p_statuses) > 8
     OR p_kind <> 'delivery' AND cardinality(p_statuses) <> 0
     OR p_limit NOT BETWEEN 1 AND 101 THEN
    RAISE EXCEPTION 'notification list input is invalid' USING ERRCODE = '22023';
  END IF;
  IF cardinality(p_statuses) <> (
    SELECT count(DISTINCT status) FROM unnest(p_statuses) AS status
  ) THEN
    RAISE EXCEPTION 'notification delivery statuses are not canonical'
      USING ERRCODE = '22023';
  END IF;

  IF p_kind = 'delivery' THEN
    FOR selected IN
      SELECT delivery.id
      FROM public.tenant_notification_deliveries AS delivery
      WHERE delivery.tenant_id = context_tenant
        AND (cardinality(p_statuses) = 0 OR delivery.status = ANY(p_statuses))
        AND (p_after_id IS NULL
          OR (delivery.created_at, delivery.id) < (p_after_created_at, p_after_id))
      ORDER BY delivery.created_at DESC, delivery.id DESC
      LIMIT p_limit
    LOOP
      item := app.private_tenant_notification_projection_v1(
        p_kind, selected.id, NULL, false
      );
      RETURN NEXT;
    END LOOP;
  ELSIF p_kind = 'rule' THEN
    FOR selected IN
      SELECT identity.id FROM public.tenant_notification_rules AS identity
      WHERE identity.tenant_id = context_tenant
        AND (p_after_id IS NULL
          OR (identity.created_at, identity.id) < (p_after_created_at, p_after_id))
      ORDER BY identity.created_at DESC, identity.id DESC LIMIT p_limit
    LOOP
      item := app.private_tenant_notification_projection_v1(p_kind, selected.id, NULL, false);
      RETURN NEXT;
    END LOOP;
  ELSIF p_kind = 'template' THEN
    FOR selected IN
      SELECT identity.id FROM public.tenant_notification_templates AS identity
      WHERE identity.tenant_id = context_tenant
        AND (p_after_id IS NULL
          OR (identity.created_at, identity.id) < (p_after_created_at, p_after_id))
      ORDER BY identity.created_at DESC, identity.id DESC LIMIT p_limit
    LOOP
      item := app.private_tenant_notification_projection_v1(p_kind, selected.id, NULL, false);
      RETURN NEXT;
    END LOOP;
  ELSE
    FOR selected IN
      SELECT identity.id FROM public.tenant_notification_webhook_configurations AS identity
      WHERE identity.tenant_id = context_tenant
        AND identity.revoked_at IS NULL
        AND (p_after_id IS NULL
          OR (identity.created_at, identity.id) < (p_after_created_at, p_after_id))
      ORDER BY identity.created_at DESC, identity.id DESC LIMIT p_limit
    LOOP
      item := app.private_tenant_notification_projection_v1(p_kind, selected.id, NULL, false);
      RETURN NEXT;
    END LOOP;
  END IF;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.list_tenant_notification_resources_v1(
  text, timestamp with time zone, uuid,
  public.notification_delivery_status[], integer
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.list_tenant_notification_resources_v1(
  text, timestamp with time zone, uuid,
  public.notification_delivery_status[], integer
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.list_tenant_notification_resources_v1(
  text, timestamp with time zone, uuid,
  public.notification_delivery_status[], integer
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.private_notification_smtp_projection_v1(
  p_scope text,
  p_tenant_id uuid,
  p_configuration_id uuid,
  p_version integer,
  p_inherited boolean
)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE projection jsonb;
BEGIN
  IF p_scope = 'tenant' THEN
    SELECT jsonb_strip_nulls(jsonb_build_object(
      'id', identity.id, 'tenantId', identity.tenant_id,
      'inheritedFromGlobal', false, 'version', version.version,
      'name', version.name, 'host', version.host, 'port', version.port,
      'security', version.security, 'username', version.username,
      'passwordConfigured', version.password_secret_id IS NOT NULL,
      'fromName', version.from_name, 'fromEmail', version.from_email,
      'replyToEmail', version.reply_to_email, 'timeoutMs', version.timeout_ms,
      'maximumConnections', version.maximum_connections,
      'maximumMessagesPerConnection', version.maximum_messages_per_connection,
      'rateLimitPerSecond', version.rate_limit_per_second,
      'dkim', CASE WHEN version.dkim_secret_id IS NULL THEN NULL ELSE
        jsonb_build_object('domainName', version.dkim_domain_name,
          'selector', version.dkim_selector, 'privateKeyConfigured', true) END,
      'enabled', version.enabled, 'createdAt', version.created_at,
      'createdBy', version.created_by_user_id
    )) INTO projection
    FROM public.tenant_notification_smtp_configurations AS identity
    JOIN public.tenant_notification_smtp_configuration_versions AS version
      ON version.tenant_id = identity.tenant_id
     AND version.configuration_id = identity.id
     AND version.version = p_version
    WHERE identity.tenant_id = p_tenant_id
      AND identity.id = p_configuration_id
      AND identity.revoked_at IS NULL;
  ELSIF p_scope = 'platform' THEN
    SELECT jsonb_strip_nulls(jsonb_build_object(
      'id', identity.id, 'inheritedFromGlobal', p_inherited,
      'version', version.version, 'name', version.name,
      'host', version.host, 'port', version.port, 'security', version.security,
      'username', version.username,
      'passwordConfigured', version.password_secret_id IS NOT NULL,
      'fromName', version.from_name, 'fromEmail', version.from_email,
      'replyToEmail', version.reply_to_email, 'timeoutMs', version.timeout_ms,
      'maximumConnections', version.maximum_connections,
      'maximumMessagesPerConnection', version.maximum_messages_per_connection,
      'rateLimitPerSecond', version.rate_limit_per_second,
      'dkim', CASE WHEN version.dkim_secret_id IS NULL THEN NULL ELSE
        jsonb_build_object('domainName', version.dkim_domain_name,
          'selector', version.dkim_selector, 'privateKeyConfigured', true) END,
      'enabled', version.enabled, 'createdAt', version.created_at,
      'createdBy', version.created_by_user_id
    )) INTO projection
    FROM public.platform_notification_smtp_configurations AS identity
    JOIN public.platform_notification_smtp_configuration_versions AS version
      ON version.configuration_id = identity.id
     AND version.version = p_version
    WHERE identity.id = p_configuration_id
      AND identity.revoked_at IS NULL;
  ELSE
    RAISE EXCEPTION 'notification SMTP scope is invalid' USING ERRCODE = '22023';
  END IF;
  IF projection IS NULL THEN
    RAISE EXCEPTION 'notification SMTP configuration was not found'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN projection;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_notification_smtp_projection_v1(
  text, uuid, uuid, integer, boolean
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_notification_smtp_projection_v1(
  text, uuid, uuid, integer, boolean
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_notification_smtp_projection_v1(
  text, uuid, uuid, integer, boolean
) TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.get_tenant_notification_smtp_v1()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE selected record;
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  SELECT identity.id, identity.current_version INTO selected
  FROM public.tenant_notification_smtp_configurations AS identity
  WHERE identity.tenant_id = app.context_tenant_id()
    AND identity.revoked_at IS NULL;
  IF FOUND THEN
    RETURN app.private_notification_smtp_projection_v1(
      'tenant', app.context_tenant_id(), selected.id,
      selected.current_version, false
    );
  END IF;
  SELECT identity.id, identity.current_version INTO selected
  FROM public.platform_notification_smtp_configurations AS identity
  WHERE identity.revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'notification SMTP configuration was not found'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN app.private_notification_smtp_projection_v1(
    'platform', NULL, selected.id, selected.current_version, true
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.get_tenant_notification_smtp_v1()
OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_tenant_notification_smtp_v1()
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_tenant_notification_smtp_v1()
TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.get_platform_notification_smtp_v1()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE selected record;
BEGIN
  IF app.context_user_id() IS NULL OR NOT app.platform_user_has_permission(
    app.context_user_id(), 'platform.notification.manage'
  ) THEN
    RAISE EXCEPTION 'platform.notification.manage is required'
      USING ERRCODE = '42501';
  END IF;
  SELECT identity.id, identity.current_version INTO selected
  FROM public.platform_notification_smtp_configurations AS identity
  WHERE identity.revoked_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'platform SMTP configuration was not found'
      USING ERRCODE = 'P0002';
  END IF;
  RETURN app.private_notification_smtp_projection_v1(
    'platform', NULL, selected.id, selected.current_version, false
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.get_platform_notification_smtp_v1()
OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.get_platform_notification_smtp_v1()
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.get_platform_notification_smtp_v1()
TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.private_insert_tenant_notification_secret_v1(
  p_secret jsonb,
  p_expected_kind public.notification_secret_kind
)
RETURNS TABLE(secret_id uuid, secret_version integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_secret IS NULL OR jsonb_typeof(p_secret) <> 'object'
     OR NOT (p_secret ?& ARRAY[
       'id', 'version', 'kind', 'keyVersion', 'nonce', 'ciphertext'
     ])
     OR p_secret - ARRAY[
       'id', 'version', 'kind', 'keyVersion', 'nonce', 'ciphertext'
     ]::text[] <> '{}'::jsonb
     OR p_secret ->> 'kind' <> p_expected_kind::text
     OR p_secret ->> 'version' !~ '^[0-9]+$'
     OR (p_secret ->> 'version')::integer <> 1
     OR p_secret ->> 'keyVersion' !~ '^[0-9]+$'
     OR p_secret ->> 'nonce' !~ '^[A-Za-z0-9+/]+={0,2}$'
     OR p_secret ->> 'ciphertext' !~ '^[A-Za-z0-9+/]+={0,2}$' THEN
    RAISE EXCEPTION 'notification secret envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  secret_id := (p_secret ->> 'id')::uuid;
  secret_version := (p_secret ->> 'version')::integer;
  INSERT INTO public.tenant_notification_secret_versions (
    tenant_id, secret_id, version, kind, key_version, nonce, ciphertext,
    created_by_membership_id, created_by_user_id
  ) VALUES (
    app.context_tenant_id(), secret_id, secret_version, p_expected_kind,
    (p_secret ->> 'keyVersion')::smallint,
    decode(p_secret ->> 'nonce', 'base64'),
    decode(p_secret ->> 'ciphertext', 'base64'),
    app.current_tenant_membership_id(), app.context_user_id()
  );
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_insert_tenant_notification_secret_v1(
  jsonb, public.notification_secret_kind
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_insert_tenant_notification_secret_v1(
  jsonb, public.notification_secret_kind
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_insert_tenant_notification_secret_v1(
  jsonb, public.notification_secret_kind
) TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.private_append_notification_admin_audit_v1(
  p_operation text,
  p_resource_kind text,
  p_resource_id uuid,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text,
  p_before jsonb,
  p_after jsonb
)
RETURNS void
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_operation IS NULL
     OR p_operation !~ '^(rule|template|smtp|delivery|webhook)[.][a-z]+$'
     OR p_resource_kind NOT IN (
       'notification_rule', 'notification_template',
       'notification_smtp_configuration', 'notification_delivery',
       'notification_webhook'
     )
     OR p_resource_id IS NULL OR p_request_id IS NULL
     OR p_correlation_id IS NULL OR p_ip_address IS NULL
     OR p_authentication_method IS NULL
     OR p_before IS NOT NULL AND jsonb_typeof(p_before) <> 'object'
     OR p_after IS NOT NULL AND jsonb_typeof(p_after) <> 'object' THEN
    RAISE EXCEPTION 'notification audit input is invalid'
      USING ERRCODE = '22023';
  END IF;
  PERFORM app.append_tenant_authorization_audit(
    uuidv7(), 'tenant.notification.' || replace(p_operation, '.', '_'),
    p_resource_kind, p_resource_id, p_request_id, p_correlation_id,
    p_ip_address, nullif(p_user_agent, ''), p_authentication_method,
    p_before, p_after,
    jsonb_build_object(
      'operation', p_operation,
      'content_redacted', true,
      'secret_material_included', false
    )
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_append_notification_admin_audit_v1(
  text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_append_notification_admin_audit_v1(
  text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_append_notification_admin_audit_v1(
  text, text, uuid, uuid, uuid, inet, text, text, jsonb, jsonb
) TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.mutate_tenant_notification_definition_v1(
  p_operation text,
  p_resource_id uuid,
  p_expected_version integer,
  p_payload jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_occurred_at timestamp with time zone,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(projection jsonb, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid := app.context_tenant_id();
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  command record;
  identity record;
  source_version record;
  next_version integer;
  result_id uuid := p_resource_id;
  result_version integer;
  resource_kind text;
  before_projection jsonb;
  after_projection jsonb;
  secret_pin record;
  signing_secret_id uuid;
  signing_secret_version integer;
BEGIN
  PERFORM app.private_require_notification_admin_v1();
  actor_membership := app.current_tenant_membership_id();
  IF p_operation NOT IN (
       'rule.create', 'rule.version', 'template.create',
       'template.version', 'template.duplicate', 'template.rollback',
       'webhook.create', 'webhook.version'
     )
     OR p_resource_id IS NULL OR uuid_extract_version(p_resource_id) <> 7
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR octet_length(p_payload::text) > 524288
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_occurred_at IS NULL
     OR p_occurred_at < transaction_timestamp() - interval '5 minutes'
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL
     OR char_length(p_authentication_method) NOT BETWEEN 1 AND 64 THEN
    RAISE EXCEPTION 'notification definition mutation input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF (p_operation LIKE '%.create' OR p_operation = 'template.duplicate')
       AND p_expected_version IS NOT NULL
     OR p_operation NOT LIKE '%.create'
       AND p_operation <> 'template.duplicate'
       AND p_expected_version NOT BETWEEN 1 AND 2147483646 THEN
    RAISE EXCEPTION 'notification definition version precondition is invalid'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    context_tenant::text || ':' || actor_membership::text || ':'
      || p_operation || ':' || encode(p_key_digest, 'hex'), 0
  ));
  SELECT stored.* INTO command
  FROM public.tenant_notification_commands AS stored
  WHERE stored.tenant_id = context_tenant
    AND stored.actor_membership_id = actor_membership
    AND stored.operation = p_operation
    AND stored.key_digest = p_key_digest;
  IF FOUND THEN
    IF command.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'notification idempotency key conflicts with a prior request'
        USING ERRCODE = '23505',
              CONSTRAINT = 'tenant_notification_commands_replay_key';
    END IF;
    resource_kind := split_part(p_operation, '.', 1);
    projection := app.private_tenant_notification_projection_v1(
      resource_kind, command.result_resource_id, NULL, false
    );
    replayed := true;
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_operation IN ('rule.create', 'rule.version') THEN
    resource_kind := 'rule';
    IF NOT (p_payload ?& ARRAY[
         'name', 'description', 'eventType', 'objectType', 'condition',
         'recipients', 'templateId', 'templateVersion', 'channel',
         'priority', 'delayMs', 'deduplicationWindowMs', 'grouping',
         'retry', 'enabled', 'effectiveFrom'
       ]) OR p_payload - ARRAY[
         'name', 'description', 'eventType', 'objectType', 'condition',
         'recipients', 'templateId', 'templateVersion', 'channel',
         'priority', 'delayMs', 'quietHours', 'deduplicationWindowMs',
         'grouping', 'retry', 'enabled', 'effectiveFrom', 'effectiveUntil'
       ]::text[] <> '{}'::jsonb THEN
      RAISE EXCEPTION 'notification rule payload is invalid'
        USING ERRCODE = '22023';
    END IF;
    IF p_operation = 'rule.create' THEN
      INSERT INTO public.tenant_notification_rules (
        id, tenant_id, current_version, created_at,
        created_by_membership_id, created_by_user_id, updated_at
      ) VALUES (
        p_resource_id, context_tenant, 1, p_occurred_at,
        actor_membership, actor_user, p_occurred_at
      );
      next_version := 1;
    ELSE
      SELECT current_version INTO STRICT identity
      FROM public.tenant_notification_rules
      WHERE tenant_id = context_tenant AND id = p_resource_id
      FOR UPDATE;
      IF identity.current_version <> p_expected_version THEN
        RAISE EXCEPTION 'notification rule version is stale'
          USING ERRCODE = '40001';
      END IF;
      before_projection := app.private_tenant_notification_projection_v1(
        'rule', p_resource_id, NULL, false
      );
      next_version := identity.current_version + 1;
    END IF;
    INSERT INTO public.tenant_notification_rule_versions (
      tenant_id, rule_id, version, name, description, event_type,
      object_type, condition, recipients, template_id, template_version,
      channel, priority, delay_ms, quiet_hours, deduplication_window_ms,
      grouping, retry, enabled, effective_from, effective_until,
      created_at, created_by_membership_id, created_by_user_id
    ) VALUES (
      context_tenant, p_resource_id, next_version, p_payload ->> 'name',
      p_payload ->> 'description',
      (p_payload ->> 'eventType')::public.notification_event_type,
      (p_payload ->> 'objectType')::public.notification_object_type,
      p_payload -> 'condition', p_payload -> 'recipients',
      (p_payload ->> 'templateId')::uuid,
      (p_payload ->> 'templateVersion')::integer,
      (p_payload ->> 'channel')::public.notification_channel,
      (p_payload ->> 'priority')::integer,
      (p_payload ->> 'delayMs')::bigint,
      p_payload -> 'quietHours',
      (p_payload ->> 'deduplicationWindowMs')::bigint,
      p_payload -> 'grouping', p_payload -> 'retry',
      (p_payload ->> 'enabled')::boolean,
      (p_payload ->> 'effectiveFrom')::timestamp with time zone,
      (p_payload ->> 'effectiveUntil')::timestamp with time zone,
      p_occurred_at, actor_membership, actor_user
    );
    IF next_version > 1 THEN
      UPDATE public.tenant_notification_rules
      SET current_version = next_version, updated_at = p_occurred_at
      WHERE tenant_id = context_tenant AND id = p_resource_id;
    END IF;
    result_version := next_version;

  ELSIF p_operation IN (
    'template.create', 'template.version',
    'template.duplicate', 'template.rollback'
  ) THEN
    resource_kind := 'template';
    IF p_operation IN ('template.create', 'template.version') THEN
      IF NOT (p_payload ?& ARRAY[
           'key', 'name', 'language', 'subject', 'html', 'sampleData',
           'placeholders'
         ]) OR p_payload - ARRAY[
           'key', 'name', 'language', 'subject', 'html', 'plainText',
           'css', 'sampleData', 'placeholders'
         ]::text[] <> '{}'::jsonb
         OR jsonb_typeof(p_payload -> 'placeholders') <> 'array' THEN
        RAISE EXCEPTION 'notification template payload is invalid'
          USING ERRCODE = '22023';
      END IF;
      IF p_operation = 'template.create' THEN
        INSERT INTO public.tenant_notification_templates (
          id, tenant_id, key, current_version, created_at,
          created_by_membership_id, created_by_user_id, updated_at
        ) VALUES (
          p_resource_id, context_tenant, p_payload ->> 'key', 1,
          p_occurred_at, actor_membership, actor_user, p_occurred_at
        );
        next_version := 1;
      ELSE
        SELECT current_version INTO STRICT identity
        FROM public.tenant_notification_templates
        WHERE tenant_id = context_tenant AND id = p_resource_id
        FOR UPDATE;
        IF identity.current_version <> p_expected_version THEN
          RAISE EXCEPTION 'notification template version is stale'
            USING ERRCODE = '40001';
        END IF;
        before_projection := app.private_tenant_notification_projection_v1(
          'template', p_resource_id, NULL, false
        );
        next_version := identity.current_version + 1;
      END IF;
      INSERT INTO public.tenant_notification_template_versions (
        tenant_id, template_id, version, key, name, language, subject,
        html, plain_text, css, sample_data, placeholders, created_at,
        created_by_membership_id, created_by_user_id
      ) VALUES (
        context_tenant, p_resource_id, next_version, p_payload ->> 'key',
        p_payload ->> 'name', p_payload ->> 'language',
        p_payload ->> 'subject', p_payload ->> 'html',
        p_payload ->> 'plainText', p_payload ->> 'css',
        p_payload -> 'sampleData', ARRAY(
          SELECT value FROM jsonb_array_elements_text(
            p_payload -> 'placeholders'
          ) AS placeholder(value) ORDER BY value COLLATE "C"
        ), p_occurred_at, actor_membership, actor_user
      );
      IF next_version > 1 THEN
        UPDATE public.tenant_notification_templates
        SET key = p_payload ->> 'key', current_version = next_version,
            updated_at = p_occurred_at
        WHERE tenant_id = context_tenant AND id = p_resource_id;
      END IF;
      result_version := next_version;
    ELSE
      IF p_operation = 'template.duplicate' THEN
        IF NOT (p_payload ?& ARRAY[
             'sourceTemplateId', 'sourceVersion', 'key', 'name'
           ]) OR p_payload - ARRAY[
             'sourceTemplateId', 'sourceVersion', 'key', 'name'
           ]::text[] <> '{}'::jsonb THEN
          RAISE EXCEPTION 'notification template duplicate payload is invalid'
            USING ERRCODE = '22023';
        END IF;
        SELECT version.* INTO STRICT source_version
        FROM public.tenant_notification_template_versions AS version
        WHERE version.tenant_id = context_tenant
          AND version.template_id = (p_payload ->> 'sourceTemplateId')::uuid
          AND version.version = (p_payload ->> 'sourceVersion')::integer;
        INSERT INTO public.tenant_notification_templates (
          id, tenant_id, key, current_version, created_at,
          created_by_membership_id, created_by_user_id, updated_at
        ) VALUES (
          p_resource_id, context_tenant, p_payload ->> 'key', 1,
          p_occurred_at, actor_membership, actor_user, p_occurred_at
        );
        next_version := 1;
      ELSE
        IF NOT (p_payload ? 'sourceVersion')
           OR p_payload - ARRAY['sourceVersion', 'reason']::text[] <> '{}'::jsonb THEN
          RAISE EXCEPTION 'notification template rollback payload is invalid'
            USING ERRCODE = '22023';
        END IF;
        SELECT current_version INTO STRICT identity
        FROM public.tenant_notification_templates
        WHERE tenant_id = context_tenant AND id = p_resource_id
        FOR UPDATE;
        IF identity.current_version <> p_expected_version THEN
          RAISE EXCEPTION 'notification template version is stale'
            USING ERRCODE = '40001';
        END IF;
        before_projection := app.private_tenant_notification_projection_v1(
          'template', p_resource_id, NULL, false
        );
        SELECT version.* INTO STRICT source_version
        FROM public.tenant_notification_template_versions AS version
        WHERE version.tenant_id = context_tenant
          AND version.template_id = p_resource_id
          AND version.version = (p_payload ->> 'sourceVersion')::integer;
        next_version := identity.current_version + 1;
      END IF;
      INSERT INTO public.tenant_notification_template_versions (
        tenant_id, template_id, version, key, name, language, subject,
        html, plain_text, css, sample_data, placeholders, created_at,
        created_by_membership_id, created_by_user_id
      ) VALUES (
        context_tenant, p_resource_id, next_version,
        CASE WHEN p_operation = 'template.duplicate'
          THEN p_payload ->> 'key' ELSE source_version.key END,
        CASE WHEN p_operation = 'template.duplicate'
          THEN p_payload ->> 'name' ELSE source_version.name END,
        source_version.language, source_version.subject, source_version.html,
        source_version.plain_text, source_version.css,
        source_version.sample_data, source_version.placeholders,
        p_occurred_at, actor_membership, actor_user
      );
      IF p_operation = 'template.rollback' THEN
        UPDATE public.tenant_notification_templates
        SET current_version = next_version, updated_at = p_occurred_at
        WHERE tenant_id = context_tenant AND id = p_resource_id;
      END IF;
      result_version := next_version;
    END IF;

  ELSE
    resource_kind := 'webhook';
    IF NOT (p_payload ?& ARRAY[
         'name', 'endpointUrl', 'eventTypes', 'audience', 'timeoutMs',
         'enabled', 'retainSigningKey'
       ]) OR p_payload - ARRAY[
         'name', 'endpointUrl', 'eventTypes', 'audience', 'signingKey',
         'retainSigningKey', 'timeoutMs', 'enabled'
       ]::text[] <> '{}'::jsonb
       OR jsonb_typeof(p_payload -> 'eventTypes') <> 'array'
       OR (p_payload ? 'signingKey'
         AND p_payload -> 'signingKey' <> 'null'::jsonb
         AND jsonb_typeof(p_payload -> 'signingKey') <> 'object')
       OR (p_payload ->> 'retainSigningKey')::boolean
          = (jsonb_typeof(p_payload -> 'signingKey') = 'object') THEN
      RAISE EXCEPTION 'notification webhook payload is invalid'
        USING ERRCODE = '22023';
    END IF;
    IF p_operation = 'webhook.create' THEN
      IF (p_payload ->> 'retainSigningKey')::boolean THEN
        RAISE EXCEPTION 'new webhook requires a signing key'
          USING ERRCODE = '22023';
      END IF;
      INSERT INTO public.tenant_notification_webhook_configurations (
        id, tenant_id, current_version, created_at,
        created_by_membership_id, created_by_user_id, updated_at
      ) VALUES (
        p_resource_id, context_tenant, 1, p_occurred_at,
        actor_membership, actor_user, p_occurred_at
      );
      next_version := 1;
    ELSE
      SELECT identity_row.* INTO STRICT identity
      FROM public.tenant_notification_webhook_configurations AS identity_row
      WHERE identity_row.tenant_id = context_tenant
        AND identity_row.id = p_resource_id
        AND identity_row.revoked_at IS NULL
      FOR UPDATE;
      IF identity.current_version <> p_expected_version THEN
        RAISE EXCEPTION 'notification webhook version is stale'
          USING ERRCODE = '40001';
      END IF;
      before_projection := app.private_tenant_notification_projection_v1(
        'webhook', p_resource_id, NULL, false
      );
      next_version := identity.current_version + 1;
    END IF;
    IF (p_payload ->> 'retainSigningKey')::boolean THEN
      SELECT version.signing_secret_id, version.signing_secret_version
      INTO STRICT signing_secret_id, signing_secret_version
      FROM public.tenant_notification_webhook_configuration_versions AS version
      WHERE version.tenant_id = context_tenant
        AND version.configuration_id = p_resource_id
        AND version.version = p_expected_version;
    ELSE
      SELECT secret_id, secret_version INTO STRICT secret_pin
      FROM app.private_insert_tenant_notification_secret_v1(
        p_payload -> 'signingKey', 'webhook_signing_key'
      );
      signing_secret_id := secret_pin.secret_id;
      signing_secret_version := secret_pin.secret_version;
    END IF;
    INSERT INTO public.tenant_notification_webhook_configuration_versions (
      tenant_id, configuration_id, version, name, endpoint_url,
      event_types, audience, signing_secret_id, signing_secret_version,
      timeout_ms, enabled, created_at,
      created_by_membership_id, created_by_user_id
    ) VALUES (
      context_tenant, p_resource_id, next_version, p_payload ->> 'name',
      p_payload ->> 'endpointUrl', ARRAY(
        SELECT value::public.notification_event_type
        FROM jsonb_array_elements_text(p_payload -> 'eventTypes') AS event(value)
        ORDER BY value COLLATE "C"
      ), (p_payload ->> 'audience')::public.notification_audience,
      signing_secret_id, signing_secret_version,
      (p_payload ->> 'timeoutMs')::integer,
      (p_payload ->> 'enabled')::boolean,
      p_occurred_at, actor_membership, actor_user
    );
    IF next_version > 1 THEN
      UPDATE public.tenant_notification_webhook_configurations
      SET current_version = next_version, updated_at = p_occurred_at
      WHERE tenant_id = context_tenant AND id = p_resource_id;
    END IF;
    result_version := next_version;
  END IF;

  after_projection := app.private_tenant_notification_projection_v1(
    resource_kind, result_id, NULL, false
  );
  INSERT INTO public.tenant_notification_commands (
    tenant_id, actor_membership_id, actor_user_id, operation,
    key_digest, request_digest, result_resource_id, result_version,
    created_at
  ) VALUES (
    context_tenant, actor_membership, actor_user, p_operation,
    p_key_digest, p_request_digest, result_id, result_version,
    p_occurred_at
  );
  PERFORM app.private_append_notification_admin_audit_v1(
    p_operation, 'notification_' || resource_kind, result_id,
    p_request_id, p_correlation_id, p_ip_address, p_user_agent,
    p_authentication_method, before_projection, after_projection
  );
  projection := after_projection;
  replayed := false;
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.mutate_tenant_notification_definition_v1(
  text, uuid, integer, jsonb, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.mutate_tenant_notification_definition_v1(
  text, uuid, integer, jsonb, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.mutate_tenant_notification_definition_v1(
  text, uuid, integer, jsonb, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.private_insert_platform_notification_secret_v1(
  p_secret jsonb,
  p_expected_kind public.notification_secret_kind
)
RETURNS TABLE(secret_id uuid, secret_version integer)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_secret IS NULL OR jsonb_typeof(p_secret) <> 'object'
     OR NOT (p_secret ?& ARRAY[
       'id', 'version', 'kind', 'keyVersion', 'nonce', 'ciphertext'
     ])
     OR p_secret - ARRAY[
       'id', 'version', 'kind', 'keyVersion', 'nonce', 'ciphertext'
     ]::text[] <> '{}'::jsonb
     OR p_secret ->> 'kind' <> p_expected_kind::text
     OR p_secret ->> 'version' !~ '^[0-9]+$'
     OR (p_secret ->> 'version')::integer <> 1
     OR p_secret ->> 'keyVersion' !~ '^[0-9]+$'
     OR p_secret ->> 'nonce' !~ '^[A-Za-z0-9+/]+={0,2}$'
     OR p_secret ->> 'ciphertext' !~ '^[A-Za-z0-9+/]+={0,2}$' THEN
    RAISE EXCEPTION 'platform notification secret envelope is invalid'
      USING ERRCODE = '22023';
  END IF;
  secret_id := (p_secret ->> 'id')::uuid;
  secret_version := (p_secret ->> 'version')::integer;
  INSERT INTO public.platform_notification_secret_versions (
    secret_id, version, kind, key_version, nonce, ciphertext,
    created_by_user_id
  ) VALUES (
    secret_id, secret_version, p_expected_kind,
    (p_secret ->> 'keyVersion')::smallint,
    decode(p_secret ->> 'nonce', 'base64'),
    decode(p_secret ->> 'ciphertext', 'base64'), app.context_user_id()
  );
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.private_insert_platform_notification_secret_v1(
  jsonb, public.notification_secret_kind
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.private_insert_platform_notification_secret_v1(
  jsonb, public.notification_secret_kind
) FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_notifier,
       periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.private_insert_platform_notification_secret_v1(
  jsonb, public.notification_secret_kind
) TO periapsis_notification_admin_owner;--> statement-breakpoint

CREATE FUNCTION app.mutate_notification_smtp_v1(
  p_scope text,
  p_candidate_configuration_id uuid,
  p_expected_version integer,
  p_payload jsonb,
  p_key_digest bytea,
  p_request_digest bytea,
  p_occurred_at timestamp with time zone,
  p_request_id uuid,
  p_correlation_id uuid,
  p_ip_address inet,
  p_user_agent text,
  p_authentication_method text
)
RETURNS TABLE(projection jsonb, replayed boolean)
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  context_tenant uuid;
  actor_membership uuid;
  actor_user uuid := app.context_user_id();
  command record;
  identity record;
  previous record;
  result_id uuid;
  next_version integer;
  before_projection jsonb;
  after_projection jsonb;
  password_id uuid;
  password_version integer;
  dkim_id uuid;
  dkim_version integer;
  secret_pin record;
BEGIN
  IF p_scope = 'tenant' THEN
    PERFORM app.private_require_notification_admin_v1();
    context_tenant := app.context_tenant_id();
    actor_membership := app.current_tenant_membership_id();
  ELSIF p_scope = 'platform' THEN
    IF actor_user IS NULL OR NOT app.platform_user_has_permission(
      actor_user, 'platform.notification.manage'
    ) THEN
      RAISE EXCEPTION 'platform.notification.manage is required'
        USING ERRCODE = '42501';
    END IF;
  ELSE
    RAISE EXCEPTION 'notification SMTP scope is invalid' USING ERRCODE = '22023';
  END IF;
  IF p_candidate_configuration_id IS NULL
     OR uuid_extract_version(p_candidate_configuration_id) <> 7
     OR p_expected_version IS NOT NULL
        AND p_expected_version NOT BETWEEN 1 AND 2147483646
     OR p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object'
     OR NOT (p_payload ?& ARRAY[
       'name', 'host', 'port', 'security', 'username', 'password',
       'retainPassword', 'removePassword', 'fromName', 'fromEmail',
       'replyToEmail', 'timeoutMs', 'maximumConnections',
       'maximumMessagesPerConnection', 'rateLimitPerSecond',
       'dkimDomainName', 'dkimSelector', 'dkimPrivateKey',
       'retainDKIMPrivateKey', 'removeDKIM', 'enabled'
     ])
     OR p_payload - ARRAY[
       'name', 'host', 'port', 'security', 'username', 'password',
       'retainPassword', 'removePassword', 'fromName', 'fromEmail',
       'replyToEmail', 'timeoutMs', 'maximumConnections',
       'maximumMessagesPerConnection', 'rateLimitPerSecond',
       'dkimDomainName', 'dkimSelector', 'dkimPrivateKey',
       'retainDKIMPrivateKey', 'removeDKIM', 'enabled'
     ]::text[] <> '{}'::jsonb
     OR p_key_digest IS NULL OR octet_length(p_key_digest) <> 32
     OR p_request_digest IS NULL OR octet_length(p_request_digest) <> 32
     OR p_occurred_at IS NULL
     OR p_occurred_at < transaction_timestamp() - interval '5 minutes'
     OR p_occurred_at > transaction_timestamp() + interval '1 minute'
     OR p_request_id IS NULL OR p_correlation_id IS NULL
     OR p_ip_address IS NULL OR p_authentication_method IS NULL THEN
    RAISE EXCEPTION 'notification SMTP mutation input is invalid'
      USING ERRCODE = '22023';
  END IF;
  IF (p_payload ->> 'retainPassword')::boolean
       AND (jsonb_typeof(p_payload -> 'password') = 'object'
         OR (p_payload ->> 'removePassword')::boolean)
     OR (p_payload ->> 'removePassword')::boolean
       AND jsonb_typeof(p_payload -> 'password') = 'object'
     OR (p_payload ->> 'retainDKIMPrivateKey')::boolean
       AND (jsonb_typeof(p_payload -> 'dkimPrivateKey') = 'object'
         OR (p_payload ->> 'removeDKIM')::boolean)
     OR (p_payload ->> 'removeDKIM')::boolean
       AND jsonb_typeof(p_payload -> 'dkimPrivateKey') = 'object'
     OR p_payload -> 'password' <> 'null'::jsonb
       AND jsonb_typeof(p_payload -> 'password') <> 'object'
     OR p_payload -> 'dkimPrivateKey' <> 'null'::jsonb
       AND jsonb_typeof(p_payload -> 'dkimPrivateKey') <> 'object' THEN
    RAISE EXCEPTION 'notification SMTP secret operation is ambiguous'
      USING ERRCODE = '22023';
  END IF;

  PERFORM pg_advisory_xact_lock(hashtextextended(
    coalesce(context_tenant::text, 'platform') || ':' || actor_user::text
      || ':smtp.version:' || encode(p_key_digest, 'hex'), 0
  ));
  IF p_scope = 'tenant' THEN
    SELECT stored.* INTO command
    FROM public.tenant_notification_commands AS stored
    WHERE stored.tenant_id = context_tenant
      AND stored.actor_membership_id = actor_membership
      AND stored.operation = 'smtp.version'
      AND stored.key_digest = p_key_digest;
  ELSE
    SELECT stored.* INTO command
    FROM public.platform_notification_commands AS stored
    WHERE stored.actor_user_id = actor_user
      AND stored.operation = 'smtp.version'
      AND stored.key_digest = p_key_digest;
  END IF;
  IF FOUND THEN
    IF command.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'notification SMTP idempotency key conflicts'
        USING ERRCODE = '23505';
    END IF;
    projection := app.private_notification_smtp_projection_v1(
      p_scope, context_tenant, command.result_resource_id,
      command.result_version, false
    );
    replayed := true;
    RETURN NEXT;
    RETURN;
  END IF;

  IF p_scope = 'tenant' THEN
    SELECT identity_row.* INTO identity
    FROM public.tenant_notification_smtp_configurations AS identity_row
    WHERE identity_row.tenant_id = context_tenant
      AND identity_row.revoked_at IS NULL
    FOR UPDATE;
  ELSE
    SELECT identity_row.* INTO identity
    FROM public.platform_notification_smtp_configurations AS identity_row
    WHERE identity_row.revoked_at IS NULL
    FOR UPDATE;
  END IF;
  IF FOUND THEN
    IF p_expected_version IS NULL OR identity.current_version <> p_expected_version THEN
      RAISE EXCEPTION 'notification SMTP version is stale'
        USING ERRCODE = '40001';
    END IF;
    result_id := identity.id;
    next_version := identity.current_version + 1;
    before_projection := app.private_notification_smtp_projection_v1(
      p_scope, context_tenant, result_id, identity.current_version, false
    );
    IF p_scope = 'tenant' THEN
      SELECT version.* INTO STRICT previous
      FROM public.tenant_notification_smtp_configuration_versions AS version
      WHERE version.tenant_id = context_tenant
        AND version.configuration_id = result_id
        AND version.version = identity.current_version;
    ELSE
      SELECT version.* INTO STRICT previous
      FROM public.platform_notification_smtp_configuration_versions AS version
      WHERE version.configuration_id = result_id
        AND version.version = identity.current_version;
    END IF;
  ELSE
    IF p_expected_version IS NOT NULL
       OR (p_payload ->> 'retainPassword')::boolean
       OR (p_payload ->> 'removePassword')::boolean
       OR (p_payload ->> 'retainDKIMPrivateKey')::boolean
       OR (p_payload ->> 'removeDKIM')::boolean THEN
      RAISE EXCEPTION 'new notification SMTP configuration is invalid'
        USING ERRCODE = '22023';
    END IF;
    result_id := p_candidate_configuration_id;
    next_version := 1;
    IF p_scope = 'tenant' THEN
      INSERT INTO public.tenant_notification_smtp_configurations (
        id, tenant_id, current_version, created_at,
        created_by_membership_id, created_by_user_id, updated_at
      ) VALUES (
        result_id, context_tenant, 1, p_occurred_at,
        actor_membership, actor_user, p_occurred_at
      );
    ELSE
      INSERT INTO public.platform_notification_smtp_configurations (
        id, current_version, created_at, created_by_user_id, updated_at
      ) VALUES (result_id, 1, p_occurred_at, actor_user, p_occurred_at);
    END IF;
  END IF;

  IF jsonb_typeof(p_payload -> 'password') = 'object' THEN
    IF p_scope = 'tenant' THEN
      SELECT secret_id, secret_version INTO STRICT secret_pin
      FROM app.private_insert_tenant_notification_secret_v1(
        p_payload -> 'password', 'smtp_password'
      );
    ELSE
      SELECT secret_id, secret_version INTO STRICT secret_pin
      FROM app.private_insert_platform_notification_secret_v1(
        p_payload -> 'password', 'smtp_password'
      );
    END IF;
    password_id := secret_pin.secret_id;
    password_version := secret_pin.secret_version;
  ELSIF (p_payload ->> 'retainPassword')::boolean THEN
    password_id := previous.password_secret_id;
    password_version := previous.password_secret_version;
  END IF;
  IF jsonb_typeof(p_payload -> 'dkimPrivateKey') = 'object' THEN
    IF p_scope = 'tenant' THEN
      SELECT secret_id, secret_version INTO STRICT secret_pin
      FROM app.private_insert_tenant_notification_secret_v1(
        p_payload -> 'dkimPrivateKey', 'smtp_dkim_private_key'
      );
    ELSE
      SELECT secret_id, secret_version INTO STRICT secret_pin
      FROM app.private_insert_platform_notification_secret_v1(
        p_payload -> 'dkimPrivateKey', 'smtp_dkim_private_key'
      );
    END IF;
    dkim_id := secret_pin.secret_id;
    dkim_version := secret_pin.secret_version;
  ELSIF (p_payload ->> 'retainDKIMPrivateKey')::boolean THEN
    dkim_id := previous.dkim_secret_id;
    dkim_version := previous.dkim_secret_version;
  END IF;

  IF p_scope = 'tenant' THEN
    INSERT INTO public.tenant_notification_smtp_configuration_versions (
      tenant_id, configuration_id, version, name, host, port, security,
      username, password_secret_id, password_secret_version,
      from_name, from_email, reply_to_email, timeout_ms,
      maximum_connections, maximum_messages_per_connection,
      rate_limit_per_second, dkim_domain_name, dkim_selector,
      dkim_secret_id, dkim_secret_version, enabled, created_at,
      created_by_membership_id, created_by_user_id
    ) VALUES (
      context_tenant, result_id, next_version, p_payload ->> 'name',
      p_payload ->> 'host', (p_payload ->> 'port')::integer,
      (p_payload ->> 'security')::public.notification_smtp_security,
      p_payload ->> 'username', password_id, password_version,
      p_payload ->> 'fromName', p_payload ->> 'fromEmail',
      p_payload ->> 'replyToEmail', (p_payload ->> 'timeoutMs')::integer,
      (p_payload ->> 'maximumConnections')::integer,
      (p_payload ->> 'maximumMessagesPerConnection')::integer,
      (p_payload ->> 'rateLimitPerSecond')::integer,
      CASE WHEN dkim_id IS NULL THEN NULL ELSE p_payload ->> 'dkimDomainName' END,
      CASE WHEN dkim_id IS NULL THEN NULL ELSE p_payload ->> 'dkimSelector' END,
      dkim_id, dkim_version, (p_payload ->> 'enabled')::boolean,
      p_occurred_at, actor_membership, actor_user
    );
    IF next_version > 1 THEN
      UPDATE public.tenant_notification_smtp_configurations
      SET current_version = next_version, updated_at = p_occurred_at
      WHERE tenant_id = context_tenant AND id = result_id;
    END IF;
  ELSE
    INSERT INTO public.platform_notification_smtp_configuration_versions (
      configuration_id, version, name, host, port, security,
      username, password_secret_id, password_secret_version,
      from_name, from_email, reply_to_email, timeout_ms,
      maximum_connections, maximum_messages_per_connection,
      rate_limit_per_second, dkim_domain_name, dkim_selector,
      dkim_secret_id, dkim_secret_version, enabled, created_at,
      created_by_user_id
    ) VALUES (
      result_id, next_version, p_payload ->> 'name', p_payload ->> 'host',
      (p_payload ->> 'port')::integer,
      (p_payload ->> 'security')::public.notification_smtp_security,
      p_payload ->> 'username', password_id, password_version,
      p_payload ->> 'fromName', p_payload ->> 'fromEmail',
      p_payload ->> 'replyToEmail', (p_payload ->> 'timeoutMs')::integer,
      (p_payload ->> 'maximumConnections')::integer,
      (p_payload ->> 'maximumMessagesPerConnection')::integer,
      (p_payload ->> 'rateLimitPerSecond')::integer,
      CASE WHEN dkim_id IS NULL THEN NULL ELSE p_payload ->> 'dkimDomainName' END,
      CASE WHEN dkim_id IS NULL THEN NULL ELSE p_payload ->> 'dkimSelector' END,
      dkim_id, dkim_version, (p_payload ->> 'enabled')::boolean,
      p_occurred_at, actor_user
    );
    IF next_version > 1 THEN
      UPDATE public.platform_notification_smtp_configurations
      SET current_version = next_version, updated_at = p_occurred_at
      WHERE id = result_id;
    END IF;
  END IF;

  after_projection := app.private_notification_smtp_projection_v1(
    p_scope, context_tenant, result_id, next_version, false
  );
  IF p_scope = 'tenant' THEN
    INSERT INTO public.tenant_notification_commands (
      tenant_id, actor_membership_id, actor_user_id, operation,
      key_digest, request_digest, result_resource_id, result_version,
      created_at
    ) VALUES (
      context_tenant, actor_membership, actor_user, 'smtp.version',
      p_key_digest, p_request_digest, result_id, next_version, p_occurred_at
    );
    PERFORM app.private_append_notification_admin_audit_v1(
      'smtp.version', 'notification_smtp_configuration', result_id,
      p_request_id, p_correlation_id, p_ip_address, p_user_agent,
      p_authentication_method, before_projection, after_projection
    );
  ELSE
    INSERT INTO public.platform_notification_commands (
      actor_user_id, operation, key_digest, request_digest,
      result_resource_id, result_version, created_at
    ) VALUES (
      actor_user, 'smtp.version', p_key_digest, p_request_digest,
      result_id, next_version, p_occurred_at
    );
    PERFORM app.append_platform_audit_event(
      uuidv7(), 'human', actor_user, 'platform.notification.smtp_version',
      'notification_smtp_configuration', result_id,
      p_request_id, p_correlation_id, p_ip_address, nullif(p_user_agent, ''),
      p_authentication_method, 'success', NULL,
      jsonb_build_object(
        'version', next_version, 'content_redacted', true,
        'secret_material_included', false
      )
    );
  END IF;
  projection := after_projection;
  replayed := false;
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.mutate_notification_smtp_v1(
  text, uuid, integer, jsonb, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) OWNER TO periapsis_notification_admin_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.mutate_notification_smtp_v1(
  text, uuid, integer, jsonb, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.mutate_notification_smtp_v1(
  text, uuid, integer, jsonb, bytea, bytea, timestamp with time zone,
  uuid, uuid, inet, text, text
) TO periapsis_api;

-- The readiness owner may inspect reachability but is non-login and never
-- exposes secret envelopes. FORCE RLS remains active on every source table.
GRANT SELECT ON TABLE
  public.outbox_events,
  public.tenant_notification_deliveries,
  public.tenant_notification_fanout_snapshots,
  public.tenant_notification_secret_versions,
  public.platform_notification_secret_versions,
  public.tenant_notification_smtp_configurations,
  public.tenant_notification_smtp_configuration_versions,
  public.platform_notification_smtp_configurations,
  public.platform_notification_smtp_configuration_versions,
  public.tenant_notification_webhook_configurations,
  public.tenant_notification_webhook_configuration_versions
TO periapsis_notification_readiness_owner;--> statement-breakpoint

CREATE POLICY notification_readiness_owner_outbox_v1
ON public.outbox_events AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (event_type LIKE 'notification.%');--> statement-breakpoint
CREATE POLICY notification_readiness_owner_deliveries_v1
ON public.tenant_notification_deliveries AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_snapshots_v1
ON public.tenant_notification_fanout_snapshots AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_tenant_smtp_v1
ON public.tenant_notification_smtp_configurations AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_tenant_smtp_versions_v1
ON public.tenant_notification_smtp_configuration_versions AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_platform_smtp_v1
ON public.platform_notification_smtp_configurations AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_platform_smtp_versions_v1
ON public.platform_notification_smtp_configuration_versions AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_webhooks_v1
ON public.tenant_notification_webhook_configurations AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint
CREATE POLICY notification_readiness_owner_webhook_versions_v1
ON public.tenant_notification_webhook_configuration_versions AS PERMISSIVE FOR SELECT
TO periapsis_notification_readiness_owner USING (true);--> statement-breakpoint

CREATE FUNCTION app.notification_live_key_versions_v1()
RETURNS TABLE(key_version smallint)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
  WITH live_tenant_smtp_pin AS (
    SELECT version.tenant_id, secret.secret_id, secret.secret_version
    FROM public.tenant_notification_smtp_configurations AS identity
    JOIN public.tenant_notification_smtp_configuration_versions AS version
      ON version.tenant_id = identity.tenant_id
     AND version.configuration_id = identity.id
     AND version.version = identity.current_version
    CROSS JOIN LATERAL (VALUES
      (version.password_secret_id, version.password_secret_version),
      (version.dkim_secret_id, version.dkim_secret_version)
    ) AS secret(secret_id, secret_version)
    WHERE identity.revoked_at IS NULL AND version.enabled
      AND secret.secret_id IS NOT NULL
  ), live_platform_smtp_pin AS (
    SELECT secret.secret_id, secret.secret_version
    FROM public.platform_notification_smtp_configurations AS identity
    JOIN public.platform_notification_smtp_configuration_versions AS version
      ON version.configuration_id = identity.id
     AND version.version = identity.current_version
    CROSS JOIN LATERAL (VALUES
      (version.password_secret_id, version.password_secret_version),
      (version.dkim_secret_id, version.dkim_secret_version)
    ) AS secret(secret_id, secret_version)
    WHERE identity.revoked_at IS NULL AND version.enabled
      AND secret.secret_id IS NOT NULL
  ), live_webhook_pin AS (
    SELECT version.tenant_id, version.signing_secret_id AS secret_id,
           version.signing_secret_version AS secret_version
    FROM public.tenant_notification_webhook_configurations AS identity
    JOIN public.tenant_notification_webhook_configuration_versions AS version
      ON version.tenant_id = identity.tenant_id
     AND version.configuration_id = identity.id
     AND version.version = identity.current_version
    WHERE identity.revoked_at IS NULL AND version.enabled
  ), pending_fanout_tenant_smtp_pin AS (
    SELECT snapshot.tenant_id, secret.secret_id, secret.secret_version
    FROM public.tenant_notification_fanout_snapshots AS snapshot
    JOIN public.outbox_events AS event
      ON event.tenant_id = snapshot.tenant_id
     AND event.id = snapshot.event_id
     AND event.processed_at IS NULL
     AND event.dead_lettered_at IS NULL
    JOIN public.tenant_notification_smtp_configuration_versions AS version
      ON snapshot.smtp_configuration_scope = 'tenant'
     AND version.tenant_id = snapshot.tenant_id
     AND version.configuration_id = snapshot.smtp_configuration_id
     AND version.version = snapshot.smtp_configuration_version
    CROSS JOIN LATERAL (VALUES
      (version.password_secret_id, version.password_secret_version),
      (version.dkim_secret_id, version.dkim_secret_version)
    ) AS secret(secret_id, secret_version)
    WHERE secret.secret_id IS NOT NULL
  ), pending_fanout_platform_smtp_pin AS (
    SELECT secret.secret_id, secret.secret_version
    FROM public.tenant_notification_fanout_snapshots AS snapshot
    JOIN public.outbox_events AS event
      ON event.tenant_id = snapshot.tenant_id
     AND event.id = snapshot.event_id
     AND event.processed_at IS NULL
     AND event.dead_lettered_at IS NULL
    JOIN public.platform_notification_smtp_configuration_versions AS version
      ON snapshot.smtp_configuration_scope = 'platform'
     AND version.configuration_id = snapshot.smtp_configuration_id
     AND version.version = snapshot.smtp_configuration_version
    CROSS JOIN LATERAL (VALUES
      (version.password_secret_id, version.password_secret_version),
      (version.dkim_secret_id, version.dkim_secret_version)
    ) AS secret(secret_id, secret_version)
    WHERE secret.secret_id IS NOT NULL
  ), pending_fanout_webhook_pin AS (
    SELECT snapshot.tenant_id,
           version.signing_secret_id AS secret_id,
           version.signing_secret_version AS secret_version
    FROM public.tenant_notification_fanout_snapshots AS snapshot
    JOIN public.outbox_events AS event
      ON event.tenant_id = snapshot.tenant_id
     AND event.id = snapshot.event_id
     AND event.processed_at IS NULL
     AND event.dead_lettered_at IS NULL
    CROSS JOIN LATERAL jsonb_array_elements(
      snapshot.webhook_configuration_pins
    ) AS pin(value)
    JOIN public.tenant_notification_webhook_configuration_versions AS version
      ON version.tenant_id = snapshot.tenant_id
     AND version.configuration_id = (pin.value ->> 'configurationId')::uuid
     AND version.version = (pin.value ->> 'version')::integer
  ), pending_tenant_smtp_pin AS (
    SELECT delivery.tenant_id, secret.secret_id, secret.secret_version
    FROM public.tenant_notification_deliveries AS delivery
    JOIN public.tenant_notification_smtp_configuration_versions AS version
      ON delivery.smtp_configuration_scope = 'tenant'
     AND version.tenant_id = delivery.tenant_id
     AND version.configuration_id = delivery.smtp_configuration_id
     AND version.version = delivery.smtp_configuration_version
    CROSS JOIN LATERAL (VALUES
      (version.password_secret_id, version.password_secret_version),
      (version.dkim_secret_id, version.dkim_secret_version)
    ) AS secret(secret_id, secret_version)
    WHERE delivery.status IN ('queued', 'leased', 'reserved', 'retry_scheduled')
      AND secret.secret_id IS NOT NULL
  ), pending_platform_smtp_pin AS (
    SELECT secret.secret_id, secret.secret_version
    FROM public.tenant_notification_deliveries AS delivery
    JOIN public.platform_notification_smtp_configuration_versions AS version
      ON delivery.smtp_configuration_scope = 'platform'
     AND version.configuration_id = delivery.smtp_configuration_id
     AND version.version = delivery.smtp_configuration_version
    CROSS JOIN LATERAL (VALUES
      (version.password_secret_id, version.password_secret_version),
      (version.dkim_secret_id, version.dkim_secret_version)
    ) AS secret(secret_id, secret_version)
    WHERE delivery.status IN ('queued', 'leased', 'reserved', 'retry_scheduled')
      AND secret.secret_id IS NOT NULL
  ), tenant_keys AS (
    SELECT stored.key_version
    FROM public.tenant_notification_secret_versions AS stored
    JOIN (
      SELECT * FROM live_tenant_smtp_pin
      UNION SELECT * FROM live_webhook_pin
      UNION SELECT * FROM pending_fanout_tenant_smtp_pin
      UNION SELECT * FROM pending_fanout_webhook_pin
      UNION SELECT * FROM pending_tenant_smtp_pin
      UNION
      SELECT delivery.tenant_id, delivery.webhook_signing_secret_id,
             delivery.webhook_signing_secret_version
      FROM public.tenant_notification_deliveries AS delivery
      WHERE delivery.channel = 'webhook'
        AND delivery.status IN ('queued', 'leased', 'reserved', 'retry_scheduled')
    ) AS pin(tenant_id, secret_id, secret_version)
      ON stored.tenant_id = pin.tenant_id
     AND stored.secret_id = pin.secret_id
     AND stored.version = pin.secret_version
  ), platform_keys AS (
    SELECT stored.key_version
    FROM public.platform_notification_secret_versions AS stored
    JOIN (
      SELECT * FROM live_platform_smtp_pin
      UNION SELECT * FROM pending_fanout_platform_smtp_pin
      UNION SELECT * FROM pending_platform_smtp_pin
    ) AS pin(secret_id, secret_version)
      ON stored.secret_id = pin.secret_id AND stored.version = pin.secret_version
  )
  SELECT DISTINCT required.key_version::smallint
  FROM (
    SELECT key_version FROM tenant_keys
    UNION ALL SELECT key_version FROM platform_keys
  ) AS required
  WHERE required.key_version BETWEEN 1 AND 32767
  ORDER BY required.key_version;
$function$;--> statement-breakpoint
ALTER FUNCTION app.notification_live_key_versions_v1()
OWNER TO periapsis_notification_readiness_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.notification_live_key_versions_v1()
FROM PUBLIC, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_live_key_versions_v1()
TO periapsis_api, periapsis_notifier;--> statement-breakpoint

CREATE FUNCTION app.verify_notification_keyring_v1(p_available smallint[])
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
BEGIN
  IF p_available IS NULL OR cardinality(p_available) NOT BETWEEN 1 AND 16
     OR EXISTS (SELECT 1 FROM unnest(p_available) AS item(value)
                WHERE item.value NOT BETWEEN 1 AND 32767)
     OR cardinality(p_available) <> (
       SELECT count(DISTINCT item.value) FROM unnest(p_available) AS item(value)
     ) THEN
    RETURN false;
  END IF;
  RETURN NOT EXISTS (
    SELECT required.key_version
    FROM app.notification_live_key_versions_v1() AS required
    WHERE NOT required.key_version = ANY(p_available)
  );
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.verify_notification_keyring_v1(smallint[])
OWNER TO periapsis_notification_readiness_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.verify_notification_keyring_v1(smallint[])
FROM PUBLIC, periapsis_worker, periapsis_notifier, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.verify_notification_keyring_v1(smallint[])
TO periapsis_api;--> statement-breakpoint

CREATE FUNCTION app.notification_dispatch_readiness_v1()
RETURNS TABLE(queue_depth bigint, role_safe boolean)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, public, app
AS $function$
DECLARE
  login_role pg_catalog.pg_roles%ROWTYPE;
  group_role pg_catalog.pg_roles%ROWTYPE;
  direct_memberships text[];
BEGIN
  SELECT role.* INTO login_role FROM pg_catalog.pg_roles AS role
  WHERE role.rolname = session_user;
  SELECT role.* INTO group_role FROM pg_catalog.pg_roles AS role
  WHERE role.rolname = 'periapsis_notifier';
  SELECT coalesce(array_agg(granted.rolname ORDER BY granted.rolname), ARRAY[]::text[])
  INTO direct_memberships
  FROM pg_catalog.pg_auth_members AS membership
  JOIN pg_catalog.pg_roles AS member ON member.oid = membership.member
  JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid
  WHERE member.rolname = session_user;
  role_safe := session_user = 'periapsis_notifier_login'
    AND login_role.rolcanlogin AND login_role.rolinherit
    AND NOT login_role.rolsuper AND NOT login_role.rolcreatedb
    AND NOT login_role.rolcreaterole AND NOT login_role.rolreplication
    AND NOT login_role.rolbypassrls
    AND direct_memberships = ARRAY['periapsis_notifier']::text[]
    AND group_role.rolname = 'periapsis_notifier'
    AND NOT group_role.rolcanlogin AND NOT group_role.rolsuper
    AND NOT group_role.rolcreatedb AND NOT group_role.rolcreaterole
    AND NOT group_role.rolreplication AND NOT group_role.rolbypassrls;
  SELECT
    (SELECT count(*) FROM public.outbox_events AS event
      WHERE event.event_type LIKE 'notification.%'
        AND event.schema_version = 2 AND event.processed_at IS NULL
        AND event.dead_lettered_at IS NULL)
    + (SELECT count(*) FROM public.tenant_notification_deliveries AS delivery
       WHERE delivery.status IN ('queued', 'leased', 'reserved', 'retry_scheduled'))
  INTO queue_depth;
  RETURN NEXT;
END;
$function$;--> statement-breakpoint
ALTER FUNCTION app.notification_dispatch_readiness_v1()
OWNER TO periapsis_notification_readiness_owner;--> statement-breakpoint
REVOKE ALL ON FUNCTION app.notification_dispatch_readiness_v1()
FROM PUBLIC, periapsis_api, periapsis_worker, periapsis_auditor;--> statement-breakpoint
GRANT EXECUTE ON FUNCTION app.notification_dispatch_readiness_v1()
TO periapsis_notifier;
