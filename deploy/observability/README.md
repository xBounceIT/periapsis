# Observability examples

The local collector accepts OTLP on 4317/4318, redacts known credential/content
attributes, exposes converted metrics on 8889, and deliberately discards traces/logs with
the `nop` exporter. This proves wiring without printing tenant data. Use the production
example only after setting an approved TLS OTLP backend and applying its authentication
through the platform secret mechanism.

Collector validation alone does not prove application instrumentation. The Go API and
worker and the TypeScript notifier now initialize OpenTelemetry runtimes, instrument their
HTTP/database and job boundaries, expose metrics, and carry validated W3C span context in
the transactional notification outbox. Their focused tests prove parsing, propagation,
redaction, span construction, and shutdown behavior. These deployment examples still must
not be treated as the end-to-end acceptance gate: release evidence must follow one sampled
event through the running API, database/outbox commit, notifier claim, and delivery attempt
and prove retry linking plus the absence of prohibited attributes.

The production example intentionally drops logs even when clients send them. Enable a log
exporter only after producer-side allowlisting, redaction tests, retention, and tenant-
equivalent backend access have passed review; downstream deletion rules alone are not a
safe content boundary.

Instrumentation propagates validated W3C `traceparent` and bounded `tracestate`; arbitrary
baggage is not persisted. The API span covers authorization and the database transaction;
an outbox record stores canonical trace/correlation fields, never raw headers;
worker/notifier consumers create consumer spans from that producer context. Tenant IDs may be controlled resource
attributes only where the telemetry backend enforces tenant-equivalent access. Never emit
tokens, cookies, LDAP passwords/DNs, SAML assertions, OIDC tokens, query text, private
comments, payloads, email bodies, or evidence metadata.

`prometheus.yaml`, `alert-rules.yaml`, and `grafana-dashboard.json` are runnable examples
for the documented metric contract. Prometheus rule checks should be run before rollout.
Alerts intentionally link to operational procedures rather than customer data. If a
binary does not yet expose `/metrics` or one of the named domain metrics, the missing
instrumentation is a release blocker for that alert, not a reason to weaken the scrape or
fabricate values in deployment configuration.
