ALTER TABLE "outbox_events" DROP CONSTRAINT "outbox_events_notification_v2_envelope_check";--> statement-breakpoint
ALTER TABLE "outbox_events" ADD CONSTRAINT "outbox_events_notification_v2_envelope_check" CHECK (not ("outbox_events"."event_type" like 'notification.%' and "outbox_events"."schema_version" = 2)
        or ("outbox_events"."aggregate_version" between 1 and 2147483647
          and "outbox_events"."actor_kind" is not null
          and ("outbox_events"."actor_kind" = 'system') = ("outbox_events"."actor_id" is null)
          and "outbox_events"."producer" ~ '^[a-z][a-z0-9_.-]{1,127}$'
          and "outbox_events"."maximum_audience" is not null
          and app.private_notification_trace_context_is_safe_v1(
            "outbox_events"."traceparent", "outbox_events"."tracestate"
          )
          and jsonb_typeof("outbox_events"."payload") = 'object'
          and "outbox_events"."payload" ? 'operatorContext'
          and jsonb_typeof("outbox_events"."payload" -> 'operatorContext') = 'object'
          and ("outbox_events"."maximum_audience" = 'customer') = ("outbox_events"."payload" ? 'customerContext')
          and (not ("outbox_events"."payload" ? 'customerContext')
            or jsonb_typeof("outbox_events"."payload" -> 'customerContext') = 'object')));