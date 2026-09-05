# ADR-0004: Use PostgreSQL transactional outbox and durable job queues

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Architecture, Data, Reliability, and Security
- Applies from: Phase 1 outbox foundation; extended by every asynchronous feature

## Context

Periapsis must atomically connect domain mutations to asynchronous side effects:
notifications, webhooks, SLA evaluation/triggers, identity synchronization, exports,
evidence scanning, reporting/search projection, and retention. Sending SMTP or a webhook
inside a database transaction is unsafe: external latency holds locks, rollback cannot
undo a successful send, and a process crash can leave state committed without the effect
or the effect delivered without state.

The initial product is self-hosted across Compose, Swarm, and Kubernetes. Introducing
Redis, RabbitMQ, Kafka, or another broker would add deployment, security, backup, and
operational complexity before throughput demonstrates a need. PostgreSQL is already the
durable transactional system of record and supports concurrent queue claiming.

## Decision

Use a **PostgreSQL transactional outbox** for durable events and PostgreSQL-backed job
tables for their delivery/work execution. The domain transaction writes:

```text
domain state + domain activity + append-only audit + outbox event(s)
```

All commit together or all roll back. External network work occurs only after commit.

Delivery semantics are explicitly **at least once**. Consumers must be idempotent. The
system does not claim exactly-once delivery; unique business/idempotency keys provide
exactly-one business outcome where required.

Tenant events live in `outbox_events` with `tenant_id NOT NULL` and forced RLS.
Pure platform events live in a physically separate platform outbox with platform-only
policy. Nullable tenant ownership is not used to mix both scopes.

## Event envelope

Every tenant outbox event contains at least:

- UUIDv7 event ID and non-null tenant ID;
- stable event type and positive schema version;
- aggregate type, ID, and committed version where applicable;
- occurrence time in UTC;
- actor-safe identifier/type and optional impersonation marker;
- correlation ID and causation ID;
- producer/module identifier;
- idempotency/deduplication key where the business command is retryable;
- minimal, validated JSON payload;
- availability, status, attempt count, lease owner/expiry, and terminal timestamps;
- last failure category/code in sanitized bounded form.

The event ID is the default consumer idempotency key. A recipient delivery uses a stronger
key such as `(event_id, rule_version, recipient_key, channel)`. Aggregate ordering, when
required, uses aggregate ID/version and prevents a later event from finalizing ahead of a
missing earlier version. There is no unsupported promise of global ordering.

Payloads are versioned facts, not unrestricted aggregate dumps. They exclude credentials,
tokens, SAML assertions, LDAP bind data, raw secrets, pre-signed URLs, and private content
not explicitly required by an authorized consumer. Customer-facing and operator-only
event schemas are distinct when visibility differs.

## Producer transaction

The application use case owns the transaction:

1. validate identity, tenant, permission/scope, workflow, visibility, expected version,
   and idempotency key;
2. write the conditional domain mutation;
3. append user-facing activity and security audit;
4. insert required outbox events with the same tenant and committed aggregate version;
5. store the command idempotency result if applicable;
6. commit once.

Repository helpers cannot silently publish after commit. A transaction that cannot write
its required audit/outbox record fails the domain mutation. Outbox insertion itself never
performs SMTP, HTTP, LDAP, S3 scanning, or another network side effect.

## Concurrent claim and lease protocol

Consumers claim a bounded batch using `FOR UPDATE SKIP LOCKED` ordered by eligibility and
fairness policy. Claiming sets a unique lease owner and expiry and commits quickly. The
consumer then performs work outside the claim transaction and opens a new transaction to
record success, retry, or dead-letter state.

Rules:

- only `pending` rows with `available_at <= now()` or expired recoverable leases can be
  claimed;
- each claim is tenant explicit, and domain reads execute with that transaction-local
  tenant context;
- a worker may process multiple tenants in a loop but never mixes tenant contexts in one
  domain transaction;
- external calls have strict timeout, cancellation, response-size, and concurrency limits;
- lease duration exceeds the normal bounded operation and is renewed only by the current
  lease owner when the operation supports safe renewal;
- completion uses a compare on row ID, lease owner, and expected state so a stale worker
  cannot overwrite a later attempt;
- process crash or pod eviction leaves a lease that another consumer can reclaim;
- graceful shutdown stops new claims, cancels bounded work where safe, and releases or
  allows leases to expire without marking false success.

Long exports, scans, or SLA recomputation use purpose-specific job tables/checkpoints
rather than holding a database transaction or endlessly extending a generic outbox lease.

## Consumer responsibilities

Every consumer:

- validates event type and supported schema version and dead-letters unknown/incompatible
  versions safely;
- verifies service purpose and tenant ownership before domain access;
- installs transaction-local tenant context on every database transaction;
- records its idempotency outcome durably before acknowledging completion;
- tolerates replay after crash between external effect and local success recording;
- emits structured metrics/traces without sensitive payloads;
- applies bounded exponential backoff with jitter and a configured attempt/age ceiling;
- places terminal failures in a queryable dead-letter state;
- requires permission, reason, and audit for manual retry/discard.

Where an external provider supports idempotency keys, the delivery ID is supplied. SMTP
has no universal exactly-once mechanism, so duplicate email remains a bounded residual
risk after recipient-level local idempotency and provider response reconciliation.

## Feature routing

### Domain/SLA/background work

The Go worker consumes domain jobs for SLA materialization and triggers, scheduled identity
sync, exports, webhook delivery, retention, object-scan orchestration, and other Go-owned
capabilities. Job handlers call application services rather than writing another module's
tables directly.

### Notifications

A notification-rule evaluator transforms an authorized domain event into tenant-scoped,
recipient-specific `notification_jobs`. The job pins the rule/template version and
contains only the allowlisted visibility-safe rendering context required for that
recipient/channel. It does not give the notifier broad access to raw Alert/Case/private-
comment tables.

The Node notifier uses Drizzle ORM at runtime to claim notification jobs, read published
template and SMTP configuration projections, render/sanitize HTML and plaintext, send
SMTP, and record `delivery_attempts`, success, retry, or dead-letter. Private-comment jobs
can target authorized operators only.

### Webhooks

Webhook deliveries are created per subscription using a versioned visibility-safe payload.
The Node notifier owns both email and webhook network delivery so one fenced delivery
ledger, retry/dead-letter protocol, and egress policy cover every notification channel.
It validates every DNS answer before opening a literal-IP connection, never follows a
redirect, verifies TLS against the configured hostname, signs the canonical payload with
the delivery-pinned rotatable HMAC key version, and adds a timestamp plus stable delivery
ID. Receivers are expected to enforce a replay window and idempotency by delivery ID. The
Go worker continues to own SLA/domain actions that do not cross the notification boundary.

## Retry, dead-letter, and retention policy

Failures are classified as retryable, permanent, policy-rejected, or poison/incompatible.
Backoff is exponential with jitter and bounded maximum delay. Authentication/authorization,
invalid destination, unsupported schema, sanitization, and policy failures do not retry
indefinitely. Rate-limit responses may honor a bounded provider retry hint.

Dead-letter records retain event/job identity, tenant, failure category/code, attempt
summary, first/last failure times, and a redacted response excerpt. They never retain raw
credentials or unrestricted message bodies. Manual retry creates a new audited attempt
linked to the original and preserves idempotency.

Completed events/jobs are retained long enough for investigation, replay protection, and
operational metrics, then archived/deleted according to tenant/platform policy. Audit
events and legal-hold data follow their own retention and are not deleted through outbox
cleanup. Queue cleanup is incremental and index/partition aware.

## Security and isolation requirements

- Tenant outbox/job/delivery tables have `tenant_id NOT NULL`, forced RLS, and composite
  tenant foreign keys.
- Runtime worker/notifier roles lack `BYPASSRLS`, schema modification, and audit
  update/delete privileges.
- The notifier receives least-privileged access to notification tables/projections, not a
  general incident-data reader.
- Job payload creation applies resource and recipient visibility before persistence;
  consumers cannot restore filtered private fields.
- Outbox payloads, failure text, traces, and metrics are size bounded and secret redacted.
- Template rendering is sandboxed and cannot reach DB/filesystem/network/process except
  through the notifier's explicit delivery code.
- Webhook URLs undergo SSRF validation at configuration, test, and delivery time.
- Queue APIs and manual actions are permission checked, rate limited, and audited.
- A malicious tenant cannot monopolize workers; scheduling and concurrency enforce global
  and per-tenant limits.

## Observability and service levels

Expose metrics for pending/leased/retry/dead-letter counts, oldest eligible age, claim and
processing latency, attempts by safe category, lease expirations, idempotency hits,
delivery outcomes, and per-consumer saturation. Tenant identifiers and recipients are not
high-cardinality metric labels.

Trace causation from API request to committed outbox event to derived job and consumer
attempt using request/correlation/causation/event/delivery IDs. Alerts fire on queue-age
SLO, dead-letter growth, repeated lease expiry, notification failure rate, SLA backlog,
audit/outbox insertion failure, and disk/connection saturation.

## Consequences

### Positive

- Domain state and asynchronous intent cannot diverge at commit time.
- No additional broker is required for the first self-hosted version.
- PostgreSQL transactions, RLS, backup, and operational tooling cover the queue state.
- `SKIP LOCKED` supports horizontally scaled consumers.
- Durable state makes retries, dead letters, and operational inspection explicit.

### Costs and constraints

- Polling and queue writes add PostgreSQL load and require careful indexes, batch size,
  cleanup, fairness, and connection limits.
- At-least-once semantics require idempotent consumer design for every handler.
- SMTP and some external systems cannot guarantee exactly-once effects.
- Large/high-throughput event streams may eventually exceed desirable OLTP coupling.
- Schema evolution must preserve old event versions through rolling deployments and
  retained/retryable jobs.

## Alternatives considered

### Send external effects inside the domain transaction

Rejected because network calls hold locks, cannot be rolled back, and create ambiguous
crash outcomes.

### Publish to a broker after commit without an outbox

Rejected because a crash between commit and publish loses the event.

### Redis/RabbitMQ/Kafka from the first release

Deferred. They may offer specialized throughput/routing but add a required dependency,
credentials, upgrades, backup/recovery, monitoring, and tenant-security surface before
measurements justify it.

### PostgreSQL logical decoding/CDC

Deferred. It can reduce producer writes but complicates intent selection, event schema,
RLS/visibility, operations, and replay. Explicit events are clearer domain contracts.

### Periodically scan domain tables for changes

Rejected because reconstructed intent is ambiguous, expensive, and cannot reliably retain
the actor, causation, visibility projection, or exact committed transition.

## Staged delivery

- Phase 1 creates tenant/platform outbox foundations, role/RLS policy, claim/idempotency
  primitives, audit coupling, and failure-injection tests.
- Phase 2 uses the pattern for identity sync/revocation jobs.
- Phase 3 publishes Alert/Case/comment/claim/escalation facts from atomic transactions.
- Phase 4 adds evidence scan/storage jobs.
- Phase 5 adds SLA evaluation/triggers with no-loop/idempotency controls.
- Phase 6 adds notification-rule projection, Node notifier, SMTP retries/dead letters, and
  webhook delivery.
- Phase 7 load-tests queue behavior, tunes fairness/retention, completes dashboards/alerts,
  and verifies crash/recovery in all deployment targets.

No phase may call an external effect directly from a domain transaction as a temporary
shortcut.

## Revisit criteria

Consider an external broker only after measurements show PostgreSQL queue load materially
harms OLTP objectives or a required capability (very high fan-out/throughput, long
retention/replay, independent consumer ownership, cross-region stream) cannot be met
safely. A replacement ADR must retain transactional publication (outbox/CDC), tenant and
visibility guarantees, event compatibility, idempotency, replay/dead-letter operations,
observability, self-hosted deployment support, and a zero-loss migration plan.
