# SLA engine contract

Phase 5 implements tenant-owned, immutable SLA policy and business-calendar revisions,
version-pinned metric instances, materialized list values, fenced timer evaluation, audited
overrides, a simulator that executes the same kernel as live processing, object-event ingress,
and a separately fenced trigger-action runtime. This document records the implemented
application/database boundary. It does not authorize a handwritten HTTP contract or an
unversioned database shortcut.

## Authorization and projections

Configuration inventory uses `sla.read`. Publishing or archiving calendar, policy, metric,
trigger, and dynamic-column revisions uses `sla.manage`; simulation uses `sla.simulate`.
Overrides are resource-scoped and symmetric: `alert.sla.override` for Alerts and
`case.sla.override` for Cases. Operator object-SLA reads reuse `alert.read` or `case.read`
and their exact own/assigned/operator-team/tenant scope. Customer reads instead require
`portal.alert.read` or `portal.case.read`, the caller's live contact linkage,
customer-visible ticket and workflow state, and an explicit customer-safe projection.

Every backend use case resolves live authority and every mutation adapter rechecks it in
the write transaction. Object authority must name the exact `(object_type, object_id)`;
tenant-manage authority must carry no resource. A customer is accepted only with `own`
scope and an empty operator-role projection. UI visibility is advisory. Customer projections include only
metrics marked both API-visible and customer-visible and columns explicitly marked
customer-visible. They never expose an internal pause state or timestamp, override reason,
actor, permission epoch, internal trigger cursor, or operator-only style. Operator
projections may include the pause timestamp but override reasons remain in the dedicated
audited history rather than list/detail SLA summaries.

The canonical HTTP surface to add after the current shared contract window is:

- `GET|POST /api/v1/tenants/{tenantId}/business-calendars`
- `GET|PUT|DELETE /api/v1/tenants/{tenantId}/business-calendars/{calendarId}`
- `GET|POST /api/v1/tenants/{tenantId}/sla-policies`
- `GET|PUT|DELETE /api/v1/tenants/{tenantId}/sla-policies/{policyId}`
- `POST /api/v1/tenants/{tenantId}/sla-policies/{policyId}/simulate`
- `GET|POST /api/v1/tenants/{tenantId}/sla-columns`
- `GET|PUT|DELETE /api/v1/tenants/{tenantId}/sla-columns/{columnId}`
- `GET /api/v1/tenants/{tenantId}/alerts/{alertId}/sla`
- `POST /api/v1/tenants/{tenantId}/alerts/{alertId}/sla/override`
- `GET /api/v1/tenants/{tenantId}/cases/{caseId}/sla`
- `POST /api/v1/tenants/{tenantId}/cases/{caseId}/sla/override`

POST creates revision 1; PUT publishes exactly `activeVersion + 1` and requires a strong
`If-Match`. DELETE is an audited terminal archive with a reason and strong precondition.
Every mutation requires a payload-bound idempotency key. Replays return the stored current
representation without duplicating activity, audit, outbox, occurrences, or jobs.
List cursors are opaque canonical base64url values over the ordered `(key, id)` tuple;
configuration pages are strictly ordered and never use mutable labels as a boundary. The
object SLA representation carries the SLA aggregate ID and aggregate version so its strong
ETag cannot be confused with a metric-version precondition.

## Kernel and transaction boundary

`modules/sla` owns the deterministic rule, calendar, metric, trigger, column, override,
and simulation semantics. Calendar intervals are half-open local-wall intervals. Exact
local instants use the earlier offset for an opening and later offset for a closing during
a repeated DST hour; nonexistent boundaries resolve to the first real instant after the
gap. Offset candidates and transition bounds are used instead of scanning wall-clock
minutes, keeping the supported 100-year horizon bounded.

`PlanEngineContext` is the single planner for ordered object events and timer observations.
It returns optimistic metric versions, durable trigger cursors, deduplicated occurrences,
typed materialized columns, and the next evaluation instant. A timer observation
checkpoints running consumption and the exact breach instant without synthesizing a domain
event. Persistence adapters must commit the entire plan or none of it.

The API application constructor is:

```text
sla.NewService(repository sla.Repository, clock func() time.Time) (*sla.Service, error)
```

The worker constructor is:

```text
slaengine.New(repository slaengine.Repository, identity slaengine.Identity,
  config slaengine.Config, clock func() time.Time) (*slaengine.Worker, error)
```

Both constructors fail closed on missing dependencies. Calls require bounded contexts.
No production no-op repository, mock clock, or ambient network client is permitted.

The event and override repositories persist a redacted receipt, not a serialized planner
result. Every receipt stores both the operation-scoped key digest and the canonical request
digest. Event receipts additionally pin event ID, tenant/object identity, an explicit
`no_policy|assigned|updated` outcome, nullable SLA aggregate ID, aggregate version, and
policy revision. Override receipts pin override ID, `metric_updated|policy_changed`
outcome, nullable metric identity, SLA aggregate and current versions, policy revision,
actor identity, permission and subject epochs, occurrence instant, and simulator digest.
An exact replay returns that receipt without invoking the callback planner; any key reuse
with a different request digest is a conflict. A malformed or authority-stale receipt is
an unavailable result, never a reason to rerun or reconstruct the plan.

An object's first domain event invokes `PlanAssignmentContext` inside the event write
transaction. The repository supplies one fact snapshot and the immutable candidate policy,
calendar, and column revisions from that same PostgreSQL snapshot. The planner either emits
one deterministic UUIDv7 SLA aggregate plus its metric instances or an explicit no-policy
decision. Both outcomes consume the payload-bound event-ledger key. Exact replay therefore
cannot create a second aggregate even if active configuration later changes.

All metric rows carry the owning `sla_instance_id`; the engine rejects input that mixes SLA
aggregate, object, tenant, policy ID, or policy version. Trigger deduplication includes the
SLA aggregate and policy revision in addition to object, metric, trigger, schedule, and
repeat window. This prevents a later assignment or explicit policy replacement from being
suppressed by an occurrence emitted under an older revision.

`change_policy` is aggregate-wide. It targets the SLA aggregate ETag, not one metric ETag,
and uses `PlanPolicyOverrideContext`. The replacement revision must have the exact same set
of stable metric keys; a rename, addition, or removal requires a separate migration product
decision. Metric instance IDs and lifecycle history remain stable, every metric changes in
one transaction, trigger cursors are recreated from the replacement revision, columns are
rematerialized, and one audited override has version-pinned before/after metric snapshots.
Calling the exported metric-level override primitive with `change_policy` fails closed.

Cancellation is propagated through assignment, event evaluation, override planning,
simulation, column materialization, and every multi-day business-calendar traversal.
Timer completion wins at the exact scheduled breach boundary. A reset begins a new trigger
run at repeat window zero while retaining append-only fire counts for limits and forensics.

## Canonical schema reservation

The SLA migration must introduce the following tenant-leading relations. Every
customer-owned row has `tenant_id NOT NULL`, composite tenant foreign keys, FORCE RLS, and
both application and database authorization. Published version rows are immutable.

- `business_calendars` and `business_calendar_versions`
- `sla_policies` and `sla_policy_versions`
- `sla_metric_definitions` and `sla_trigger_definitions`
- `sla_columns` and `sla_column_versions`
- `sla_instances` and `sla_metric_instances`
- `sla_trigger_cursors` and `sla_trigger_occurrences`
- `sla_materialized_column_values`
- `sla_object_event_ledger`
- `sla_evaluation_jobs`
- `sla_overrides`

Calendar schedules/exceptions and declarative match rules may use bounded, validated JSONB
inside immutable version rows. Metric, trigger, instance, job, occurrence, override, and
materialized sort/filter fields are typed columns. Do not use one opaque JSONB document for
runtime state. Required indexes include tenant plus active key/version, subject identity,
metric next-evaluation/state/due time, typed materialized sort values, worker availability,
and unique tenant occurrence deduplication digest.

The canonical relational shape reserved for the migration is:

- each calendar, policy, and column shell has `(tenant_id, id)`, stable key, active version,
  resource version, archive timestamp, and created/updated timestamps; immutable revision
  children use `(tenant_id, shell_id, version)`;
- `sla_instances` has tenant/object type/object ID uniqueness, selected policy ID/version,
  aggregate version, assignment event ID, and lifecycle timestamps;
- every `sla_metric_instance` has tenant, SLA instance, stable instance ID, definition ID,
  optimistic version, typed lifecycle/timestamps/durations, last event ID/key/time, and last
  override ID/digest; its policy fields must equal the owning aggregate projection;
- trigger cursors and materialized columns are version-pinned children of one metric
  instance; typed instant/duration/percentage/state columns are mutually constrained;
- event-ledger and override rows store only bounded operation metadata and SHA-256 command
  digests. Fact values and override reasons never enter list projections, logs, or outbox
  payloads;
- evaluation jobs carry SLA instance ID, expected aggregate version, due/available time,
  attempt, worker UUID, lease expiry, and monotonically increasing fence. The claimed
  projection uses the claim request time as `observed_at` and exact
  `lease_expires_at = observed_at + lease_duration`.

The append-only database ABI must provide separate functions for:

1. publishing and archiving calendar, policy, and column revisions;
2. reserving a payload-bound object-event command, locking its SLA instance set, and
   atomically committing assignment/no-policy or the planner output, audit, outbox,
   occurrence, aggregate projection, and next job;
3. applying an override with expected metric version, exact resource authority epochs,
   a reason, and the durable simulator digest;
4. claiming due evaluation jobs with `SKIP LOCKED`, worker lease owner, expiry, and a
   monotonically increasing fence;
5. finalizing a job only for the exact worker/fence, with metric/cursor/column/occurrence
   state plus next schedule in one transaction;
6. recording a bounded retry or terminal dead-letter for the exact worker/fence.

### Implemented append-only ABI v2 successor

The sealed v1 ABI remains immutable. Its runtime projections are not sufficient for the
application adapters: event and override replay was discovered only after planner-shaped
arguments have been supplied, configuration reads select only the active revision, and
worker projections omit stable shell keys and the column revision pinned by an existing
materialization. The successor migrations add the following named v2 boundary without
changing v1:

- `app.begin_sla_object_event_v2(tenant_id, event_id, object_type, object_id,
key_digest, request_digest)` takes the operation advisory transaction lock, rechecks the
  live object-read permission, and returns either `fresh` plus one version-pinned runtime
  snapshot or the exact stored event receipt. A replay must match the tenant, event,
  object, key digest, and request digest byte-for-byte. The adapter invokes the planner and
  `commit_sla_object_event_v1` only for `fresh`; the advisory lock remains held until that
  transaction commits or rolls back.
- `app.begin_sla_override_v2(tenant_id, override_id, object_type, object_id,
sla_instance_id, key_digest, request_digest)` has the same replay-first behavior, also
  rechecks the live resource-scoped override permission, and returns the exact matched
  scope, permission epoch, subject epoch, and stored receipt. Fresh writes invoke the
  planner and v1 commit in that same transaction. Replays never execute or reconstruct a
  planner result, but they still fail when current authorization no longer permits the
  resource.
- `app.read_sla_configuration_revision_v2(tenant_id, kind, resource_id, version,
capability)`
  returns exactly one immutable calendar, policy, or column revision after a live
  live `sla.read`, `sla.manage`, or `sla.simulate` check matching the caller's use case.
  `app.read_sla_metric_definition_v2(tenant_id, metric_definition_id, capability)` reads
  the immutable, tenant-unique metric definition ID used by a column revision. These
  functions never infer a stronger permission and never silently substitute an active
  shell version.
- `app.read_sla_configuration_v2(...)` retains the bounded `(key,id)` inventory and
  current-representation semantics of v1; column documents additionally embed their
  immutable metric definition so one page is restored from one database snapshot without
  an N+1 query or a mutable follow-up lookup.
- `app.read_sla_runtime_state_v2(...)` preserves the v1 authorization check and adds every
  version-pinned calendar and column required to restore an existing aggregate. Each
  projected calendar and column includes its stable shell key and immutable revision.
- `app.claim_sla_evaluation_jobs_v2(...)` retains the v1 `SKIP LOCKED` lease/fence
  semantics while projecting the same complete version-pinned runtime document used by
  the API adapter. Existing metric instances select columns by their persisted pinned
  column ID/version, never by a mutable active shell version.
- `app.read_sla_evaluation_queue_metrics_v1()` is worker-only and uses one materialized
  database-clock instant. It returns the exact count and oldest age in microseconds for
  queued or scheduled retries whose `available_at` is due plus leases whose
  `lease_expires_at` has elapsed. Future retries and live leases are excluded.

All v2 JSON documents are bounded and closed by the Go decoder. The successor owns exact
`EXECUTE` grants and readiness assertions. Upgrade tests cover both a clean install and the
supported predecessor handoff.

The event ledger is unique by tenant and event ID and stores operation-scoped key and
request digests. A changed payload under the same key is a conflict. Trigger occurrences
are unique by tenant and the kernel's SHA-256 deduplication key. Creating a system Alert
always uses source `sla-engine`, links the origin, uses that occurrence digest as the Alert
deduplication key, and cannot select another SLA unless the published policy explicitly
allows the source.

## Worker failure semantics

The Go worker claims a bounded batch and evaluates each job under a shorter operation
deadline than its lease. Malformed tenant/object/version projections are terminal poison
jobs. Timeouts retry only up to the configured attempt ceiling. Finalize errors are
ambiguous commits: the worker does not write a contradictory failure and leaves the lease
for fenced reclaim. The worker performs no email, webhook, or system-Alert network effect;
it writes idempotent occurrences/outbox actions transactionally for their owning consumer.

Platform tenant suspension dead-letters queued, retry, and leased evaluation jobs as
`tenant_suspended` in the lifecycle transaction. The dedicated worker-owner RLS policy also
requires an active tenant, closing alternate claim paths. Reactivation permits newly
scheduled work but never resurrects terminal jobs; recovery must create new version-pinned
work through an audited domain path. See
[Platform tenant lifecycle](operations/tenant-lifecycle.md).

Operational metrics and logs may include counts, durations, state, action kind, and attempt,
but never a lease fence, policy expressions, custom-field facts, override reasons, object IDs,
deduplication digests, or customer labels.

Claim projections include the expected SLA aggregate version and exact lease expiry.
Finalize compares tenant, job, SLA aggregate, expected aggregate version, worker, and fence.
The worker rejects clock rollback, a lease derived from a different observation instant,
duplicate job IDs, two jobs for the same tenant/SLA aggregate in one claim, mixed-aggregate
metric projections, and non-microsecond configuration before persistence. Claim, finalize,
and retry each receive their own bounded context so an evaluation timeout cannot cause an
unbounded repository call or suppress a separately bounded failure record.

The production worker starts this loop immediately after its database role is validated and
includes the loop in `/health/ready`. A failed or contradictory iteration clears readiness;
shutdown clears it before the process exits. The runtime accepts only bounded
`PERIAPSIS_SLA_*` settings. With the shipped defaults it claims at most 10 jobs, gives each
repository operation 5 seconds, gives the sequential batch and fence lease 2 minutes, polls
every 2 seconds, retries from 15 seconds to 15 minutes, and dead-letters after 10 attempts.
Startup rejects lease or run timeouts too short to cover the configured sequential batch.

Claim, finalize, and failure statements overwrite both transaction-local `app.traceparent`
and `app.tracestate` before invoking their mutation ABI. The mutation input depends on the
verified installed values, so the planner cannot move the producer ahead of trace-context
installation. Absent or remote-only context installs an empty pair and cannot inherit stale
pooled-session provenance; an active local worker span may flow into transactional outbox
records without becoming authorization evidence.

Prometheus exposes fixed-label readiness, run outcome, job outcome, and authoritative queue
families:
`periapsis_worker_sla_ready`, `periapsis_sla_worker_runs_total`, and
`periapsis_sla_worker_jobs_total`, plus `periapsis_sla_queue_pending_jobs` and
`periapsis_sla_queue_oldest_pending_seconds`. A successful database snapshot publishes
zero for a genuinely empty queue; a missing or invalid snapshot removes both queue series
and fails the iteration so monitoring cannot mistake unavailable evidence for an empty
queue. These metrics contain no tenant, object, policy, worker, fence, or error values.

Trigger occurrences are consumed by a separate fenced action runtime rather than inside
deadline evaluation. This preserves an immutable occurrence even when a delivery or ticket
mutation is temporarily unavailable. Each poll discovers only explicit tenant queues,
revalidates the worker-role ABI, claims a bounded batch, and applies one deduplicated effect
through a closed PostgreSQL function. Task/team mutations and no-loop system Alerts are
transactionally coupled to domain activity and redacted audit; email and webhook effects
enter the transactional outbox. Retry, dead-letter, replay, and fence-loss outcomes are
bounded and never expose recipient, endpoint, object, policy, or digest values.

The action loop is independently represented in `/health/ready`. Its
`PERIAPSIS_SLA_ACTION_*` settings bound queue discovery, claim size, operation/run duration,
lease safety, and polling. Fixed-label metrics are
`periapsis_worker_sla_action_ready`, `periapsis_sla_action_worker_runs_total`,
`periapsis_sla_action_worker_actions_total`,
`periapsis_sla_action_queue_pending_actions`, and
`periapsis_sla_action_queue_oldest_pending_seconds`. As with evaluation, an unavailable or
contradictory authoritative queue snapshot removes the queue series instead of publishing a
misleading zero.
