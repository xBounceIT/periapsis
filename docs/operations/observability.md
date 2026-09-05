# Observability operations

Periapsis emits structured JSON logs with request, correlation, and active trace identifiers.
The API and worker initialize bounded OpenTelemetry SDK runtimes, instrument HTTP and pgx,
and expose Prometheus metrics. The notifier initializes its TypeScript telemetry runtime,
instruments database and delivery work, and exposes its own health and metrics surface.
Transactional notification outbox records persist validated W3C `traceparent`/`tracestate`
alongside application correlation and causation UUIDs; consumers validate that context and
create consumer/delivery spans without treating it as authorization evidence.

`PERIAPSIS_LOG_LEVEL` applies consistently to the API, worker, and notifier. The accepted
values are `info` and `error`; an unset value defaults to `info`, while any other value is
rejected during startup.

Unit and runtime-boundary tests cover configuration, propagation parsing, redacted error
handling, pgx/HTTP span construction, consumer continuity, metrics, and graceful flush and
shutdown. A live release acceptance gate must still prove sampled parent continuity across
the running API, transactional database/outbox write, notifier claim, and delivery attempt,
including retry-link semantics and backend-side redaction. Until that gate is recorded,
operators must not rely on a trace as the only incident or audit record. The retained run is
part of the Docker-enabled external evidence in [`TASKS.md`](../../TASKS.md), not missing
instrumentation work.

## Data minimization

Allowlist attributes; never rely only on downstream redaction. Forbidden values include
authorization/cookie headers, credentials, LDAP bind data, SAML assertions, OIDC tokens,
TOTP/recovery material, request/query bodies, raw Alert payloads, private comments, email
bodies/recipients, evidence metadata, and presigned URLs. Hashing a low-entropy identifier
does not make it anonymous.

Use bounded route templates rather than raw paths as metric labels. Tenant, actor, Alert,
Case, rule, template, and recipient IDs are high-cardinality and should not be Prometheus
labels. If a tenant dimension is operationally essential, export it only to a controlled
trace/log backend with tenant-equivalent access and retention.

## Required trace continuity

- Accept W3C trace context only after normal request validation; do not trust caller
  baggage as authorization or log metadata.
- Create server spans after authentication boundaries and add coarse outcome/status only.
- Database spans omit statements/parameters.
- Persist a trace/correlation reference with the transactional outbox. The consumer starts
  a new span linked to producer context so retries do not masquerade as one long request.
- Each delivery attempt is a child/linked span with channel/outcome, never destination or
  rendered content.

## Metrics and alerts

The example contract covers target health, API request rate/latency/errors, oldest outbox
and SLA work, notification outcomes, and authentication outcomes. Instrumentation owns the
exact counter/histogram semantics. Counters are monotonic, outcomes are closed enums, and
queue age uses server time. Missing metric series must alert rather than silently produce a
zero dashboard.

The SLA worker also publishes `periapsis_worker_sla_ready`,
`periapsis_sla_worker_runs_total{outcome="success|failure"}`, and
`periapsis_sla_worker_jobs_total{outcome="claimed|completed|retryable|dead_lettered"}`,
along with database-clock `periapsis_sla_queue_pending_jobs` and
`periapsis_sla_queue_oldest_pending_seconds` gauges. Queue gauges are absent until a valid
database snapshot exists and are cleared on observation failure; only an authoritative
empty snapshot emits zero.
Readiness is fail-closed until one bounded iteration succeeds and is cleared after any failed
iteration or shutdown. These process metrics deliberately omit tenant, object, worker, fence,
and error labels; use the server-time queue-age metric for backlog alerting rather than
deriving age from process clocks.

Ordered SLA event ingress publishes `periapsis_worker_sla_event_ingress_ready`, bounded
run and event counters, and database-clock pending, reclaimable, dead-lettered, and oldest
pending gauges under `periapsis_sla_event_ingress_*`. Queue gauges are cleared when their
snapshot is unavailable, and the missing-series alert and dashboard cover every family.

Ticket bulk actions, asynchronous exports, and export-artifact reconciliation share a
fail-closed process boundary exposed as `periapsis_worker_ticket_runtime_ready`. Their
fixed-cardinality counters are `periapsis_ticket_bulk_worker_runs_total`,
`periapsis_ticket_export_worker_runs_total`,
`periapsis_ticket_export_reconcile_worker_runs_total`, and
`periapsis_ticket_export_reconcile_artifacts_total`. Reconciliation classifies every claimed
artifact exactly once as purged, replayed, retry scheduled, dead-lettered, or fence lost;
an impossible count summary makes the iteration unhealthy rather than publishing misleading
success. These series never label tenant, job, artifact, object key, worker, or failure text.
The database also supplies one global snapshot through
`periapsis_ticket_export_reconcile_queue_pending_eligible`,
`periapsis_ticket_export_reconcile_queue_reclaimable`,
`periapsis_ticket_export_reconcile_queue_dead_lettered`, and
`periapsis_ticket_export_reconcile_queue_oldest_pending_seconds`. The gauges are absent until
the worker obtains a valid snapshot and are cleared on any runtime-readiness, storage-readiness, queue-discovery,
or observation-path failure. A queue-processing failure may still leave a valid current
database snapshot visible while the separate readiness gauge reports the unhealthy loop.
Only an authoritative database zero is rendered as zero; never use
`or vector(0)` for alerts or dashboards because that hides loss of the observation path.

Run `promtool check config` and `promtool check rules` for every change. Route alerts to an
approved incident system and keep tenant/customer data out of labels and annotations. Tune
thresholds from measured baselines and SLOs, not by disabling noisy rules.
