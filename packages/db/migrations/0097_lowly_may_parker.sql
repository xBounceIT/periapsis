ALTER TABLE "tenant_notification_deliveries" DROP CONSTRAINT "tenant_notification_deliveries_bounds_check";--> statement-breakpoint
ALTER TABLE "outbox_events" DROP CONSTRAINT "outbox_events_notification_v2_envelope_check";--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD COLUMN "template_snapshot" jsonb;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "traceparent" text;--> statement-breakpoint
ALTER TABLE "outbox_events" ADD COLUMN "tracestate" text;--> statement-breakpoint
ALTER TABLE "tenant_notification_deliveries" ADD CONSTRAINT "tenant_notification_deliveries_bounds_check" CHECK ((uuid_extract_version("tenant_notification_deliveries"."id") = 7) is true
        and "tenant_notification_deliveries"."delivery_key" ~ '^[0-9a-f]{64}$'
        and char_length("tenant_notification_deliveries"."recipient") between 3 and 320
        and char_length("tenant_notification_deliveries"."destination_redacted") between 3 and 320
        and jsonb_typeof("tenant_notification_deliveries"."context") = 'object'
        and octet_length("tenant_notification_deliveries"."context"::text) <= 65536
        and "tenant_notification_deliveries"."priority" between 0 and 100
        and char_length("tenant_notification_deliveries"."deduplication_key") between 1 and 240
        and ("tenant_notification_deliveries"."grouping_key" is null or char_length("tenant_notification_deliveries"."grouping_key") <= 240)
        and "tenant_notification_deliveries"."grouping_window_ms" between 0 and 2592000000
        and "tenant_notification_deliveries"."grouping_maximum_items" between 1 and 10000
        and jsonb_typeof("tenant_notification_deliveries"."retry") = 'object'
        and "tenant_notification_deliveries"."attempt_count" between 0 and 100
        and "tenant_notification_deliveries"."maximum_attempts" between 1 and 100
        and "tenant_notification_deliveries"."attempt_count" <= "tenant_notification_deliveries"."maximum_attempts"
        and ("tenant_notification_deliveries"."lease_owner" is null) = ("tenant_notification_deliveries"."fence_token" is null)
        and ("tenant_notification_deliveries"."fence_token" is null) = ("tenant_notification_deliveries"."lease_until" is null)
        and ("tenant_notification_deliveries"."stable_message_id" is null) = ("tenant_notification_deliveries"."reserved_at" is null)
        and ("tenant_notification_deliveries"."failure_code" is null or "tenant_notification_deliveries"."failure_code" ~ '^[a-z][a-z0-9_]{0,63}$')
        and ("tenant_notification_deliveries"."provider_receipt" is null or jsonb_typeof("tenant_notification_deliveries"."provider_receipt") = 'object')
        and ("tenant_notification_deliveries"."rule_id" is null) = ("tenant_notification_deliveries"."rule_version" is null)
        and ("tenant_notification_deliveries"."template_id" is null) = ("tenant_notification_deliveries"."template_version" is null)
        and ("tenant_notification_deliveries"."template_snapshot" is null or "tenant_notification_deliveries"."template_snapshot" =
          '{"key":"system.smtp-test","name":"Periapsis SMTP test","language":"en","version":1,"subject":"Periapsis SMTP test","html":"<p>This message verifies your Periapsis SMTP configuration.</p>","plainText":"This message verifies your Periapsis SMTP configuration.","css":""}'::jsonb)
        and (("tenant_notification_deliveries"."channel" = 'email'
          and (("tenant_notification_deliveries"."template_id" is not null) <> ("tenant_notification_deliveries"."template_snapshot" is not null))
          and "tenant_notification_deliveries"."smtp_configuration_scope" in ('tenant', 'platform')
          and "tenant_notification_deliveries"."smtp_configuration_id" is not null
          and "tenant_notification_deliveries"."smtp_configuration_version" is not null
          and "tenant_notification_deliveries"."webhook_configuration_id" is null
          and "tenant_notification_deliveries"."webhook_configuration_version" is null
          and "tenant_notification_deliveries"."webhook_signing_secret_id" is null
          and "tenant_notification_deliveries"."webhook_signing_secret_version" is null
          and "tenant_notification_deliveries"."webhook_signing_key_version" is null
          and "tenant_notification_deliveries"."webhook_payload_version" is null
          and "tenant_notification_deliveries"."webhook_payload" is null)
          or ("tenant_notification_deliveries"."channel" = 'webhook'
            and "tenant_notification_deliveries"."template_snapshot" is null
            and "tenant_notification_deliveries"."smtp_configuration_scope" is null
            and "tenant_notification_deliveries"."smtp_configuration_id" is null
            and "tenant_notification_deliveries"."smtp_configuration_version" is null
            and "tenant_notification_deliveries"."webhook_configuration_id" is not null
            and "tenant_notification_deliveries"."webhook_configuration_version" is not null
            and "tenant_notification_deliveries"."webhook_signing_secret_id" is not null
            and "tenant_notification_deliveries"."webhook_signing_secret_version" between 1 and 2147483647
            and "tenant_notification_deliveries"."webhook_signing_key_version" between 1 and 32767
            and "tenant_notification_deliveries"."webhook_payload_version" = 1
            and jsonb_typeof("tenant_notification_deliveries"."webhook_payload") = 'object'
            and octet_length("tenant_notification_deliveries"."webhook_payload"::text) <= 262144)));--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_notification_v2_envelope_check" CHECK (not ("outbox_events"."event_type" like 'notification.%' and "outbox_events"."schema_version" = 2)
        or ("outbox_events"."aggregate_version" between 1 and 2147483647
          and "outbox_events"."actor_kind" is not null
          and ("outbox_events"."actor_kind" = 'system') = ("outbox_events"."actor_id" is null)
          and "outbox_events"."producer" ~ '^[a-z][a-z0-9_.-]{1,127}$'
          and "outbox_events"."maximum_audience" is not null
          and ("outbox_events"."tracestate" is null or "outbox_events"."traceparent" is not null)
          and ("outbox_events"."traceparent" is null or (
            "outbox_events"."traceparent" ~ '^00-[0-9a-f]{32}-[0-9a-f]{16}-(00|01)$'
            and split_part("outbox_events"."traceparent", '-', 2) <> repeat('0', 32)
            and split_part("outbox_events"."traceparent", '-', 3) <> repeat('0', 16)))
          and ("outbox_events"."tracestate" is null or (
            char_length("outbox_events"."tracestate") between 1 and 512
            and "outbox_events"."tracestate" !~ '[[:cntrl:]]'))
          and jsonb_typeof("outbox_events"."payload") = 'object'
          and "outbox_events"."payload" ? 'operatorContext'
          and jsonb_typeof("outbox_events"."payload" -> 'operatorContext') = 'object'
          and ("outbox_events"."maximum_audience" = 'customer') = ("outbox_events"."payload" ? 'customerContext')
          and (not ("outbox_events"."payload" ? 'customerContext')
            or jsonb_typeof("outbox_events"."payload" -> 'customerContext') = 'object')));