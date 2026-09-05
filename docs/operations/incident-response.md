# Alert response

These procedures correspond to the example Prometheus rule annotations. Before any
diagnosis, confirm environment/release, create an incident record, and preserve redacted
logs/metrics. Never copy customer payloads, assertions, credentials, comments, or email
content into the incident channel.

## Target down

Check orchestrator desired/ready replicas, readiness reason, restart count, dependency
health, and the last rollout/migration. Stop automatic rollout if failures correlate with a
new digest. Verify secret mounts exist by metadata only; never print contents. Roll back the
application only when schema compatibility is proven.

## Metrics missing

Distinguish target discovery/NetworkPolicy from an absent `/metrics` implementation.
Confirm Service labels, ServiceMonitor selection, scrape namespace label, port/path, and
Prometheus target error. Do not open broad ingress to repair discovery.

## API errors

Break down by closed route template/status class and use redacted request/correlation IDs
with database availability, authorization dependency, and recent releases. Trace IDs may
be used only after the end-to-end instrumentation release gate documented in
`observability.md` is green. Protect tenant isolation and request bounds during mitigation;
do not bypass RLS or authorization to reduce errors.

## API latency

Inspect saturation, PostgreSQL latency/locks/connection headroom, KDF concurrency, and
downstream timeouts. Scale only within database connection budgets. Preserve cancellation
and request deadlines.

## Outbox stalled

Pause unsafe rollouts, inspect oldest job metadata without payload, worker leases, database
locks, retry/dead-letter counts, and notifier availability. Consumers are idempotent; never
delete or manually mark jobs delivered to clear a graph. Resume in bounded batches and
watch duplicate protections.

## Notification failures

Check provider health, TLS/certificate changes, rate limits, tenant rule state, and retry
classification. Do not log recipients or rendered messages. Pause a failing channel rather
than rerouting private/customer content to an unapproved destination.

## SLA queue

Verify worker capacity, calendar/version availability, database contention, and queue age.
SLA calculations remain pinned to policy/calendar versions; do not recompute history with a
new policy as an emergency shortcut.

Use `periapsis_worker_sla_ready` to distinguish an unhealthy loop from an otherwise healthy
worker process, `periapsis_sla_worker_runs_total{outcome="failure"}` for sustained iteration
failures, and `periapsis_sla_worker_jobs_total{outcome="dead_lettered"}` for poison work. A
queue-age increase with ready workers points first to capacity or contention. Compare
`periapsis_sla_queue_pending_jobs` with `periapsis_sla_queue_oldest_pending_seconds`; absence
of either series means the worker could not obtain an authoritative database snapshot and
must not be interpreted as an empty queue.

Trigger side effects have an independent health boundary. Inspect
`periapsis_worker_sla_action_ready`, `periapsis_sla_action_worker_runs_total`,
`periapsis_sla_action_worker_actions_total`, and the two
`periapsis_sla_action_queue_*` series before concluding that a materialized warning or
breach produced its configured email, webhook, task, team assignment, or system Alert. An
evaluation-ready/action-unready split means deadlines are still being materialized while
side effects are fail-closed; do not replay effects manually without checking the durable
deduplication receipt and fence.

Ready `0` points first to database ABI/role readiness, bounded runtime configuration, and
migration state. Do not add tenant, object, policy, action, fence, recipient, endpoint, or
raw error labels while investigating.

## Ticket runtime

Start with `periapsis_worker_ticket_runtime_ready`, then split bulk, export, and cleanup
failures through their fixed-outcome counters. A bulk or export failure does not authorize
replaying mutations by hand: inspect the durable idempotency receipt, exact selection pin,
lease, and fence first. For an export failure, verify the canonical manifest and exact object
metadata without listing the bucket or exposing object keys and presigned URLs.

For reconciliation failures, compare claimed artifacts with the mutually exclusive purged,
replayed, retry-scheduled, dead-lettered, and fence-lost outcomes. A dead letter means cleanup
needs operator investigation; it does not make the customer artifact downloadable again.
Use `periapsis_ticket_export_reconcile_queue_pending_eligible` and
`periapsis_ticket_export_reconcile_queue_reclaimable` to distinguish new backlog from expired
leases, and use the database-clock `periapsis_ticket_export_reconcile_queue_oldest_pending_seconds`
for lag. A non-zero `periapsis_ticket_export_reconcile_queue_dead_lettered` is unresolved state,
not merely a historical counter event. Absence of any queue gauge means the worker lacks an
authoritative snapshot and must not be interpreted as an empty queue.
Resolve storage reachability, owner/SSE/checksum metadata, and database ABI readiness before
retrying through the normal fenced worker. Never delete an arbitrary object discovered by a
bucket listing, weaken conditional deletion, or edit terminal job state to clear the alert.
Keep tenant, job, artifact, object key, digest, fence, and raw storage errors out of metric
labels and incident channels.

## OIDC maintenance

Start with `periapsis_worker_oidc_maintenance_ready`. A zero value means the worker could
not attest both the purpose-bound database ABI and its authoritative queue snapshot, or a
dispatch cycle failed. Never infer an empty queue from missing gauges: the worker removes
all OIDC queue samples when the snapshot is unavailable.

Compare the fixed `logout_retry`, `refresh`, and `scrub` samples in
`periapsis_worker_oidc_maintenance_queue_due` with
`periapsis_worker_oidc_maintenance_queue_oldest_due_seconds`. Reclaimable logout or refresh
claims indicate an expired lease; inspect database latency, worker interruption, keyring
availability, and pinned IdP transport health before the normal fenced worker reclaims
them. A non-zero `periapsis_worker_oidc_maintenance_queue_dead_lettered` is authoritative
unresolved logout work and requires operator investigation. Do not edit attempts, leases,
session material, or dead-letter state by hand.

The work counters describe applied successes or the classification submitted to the
database. In particular, `safe_retry_submitted` and `terminal_failure_submitted` are not
authoritative queue state because PostgreSQL owns retry exhaustion and deadline decisions.
Use the queue gauges for current state. Keep tenant, provider, endpoint, session, material,
token, secret, and raw error values out of metrics and incident channels.

## Authentication failures

Separate provider outage/config drift from credential attack using coarse provider/outcome
metrics, rate-limit state, and audited source-network information. Preserve lockout and MFA
requirements. Suspected credential stuffing triggers security escalation and session/key
review; it does not justify disabling rate limits or MFA.
