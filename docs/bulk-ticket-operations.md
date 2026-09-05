# Asynchronous ticket bulk operations

Status: production-composed; external reference-performance evidence pending

Ticket bulk mutations are background commands, not a client-side loop over the rows that
happen to be visible in a table. The API first resolves the requested selection while
holding the same tenant, actor, membership, and ticket-read authority used by the list
planner. PostgreSQL materializes an immutable set of `(ticket_id, ticket_version)` targets
and commits that set together with the job, its canonical selection digest, audit event,
and outbox event.

Possession of a job or saved-view identifier grants no authority. Creation rechecks the
requested mutation capability, and every target transaction rechecks the original human
actor's current membership, permission scope, team relationships, workflow version, and
the target's expected version. Revoked authority stops new target claims. PostgreSQL RLS
and explicit tenant predicates remain active for selection, execution, progress reads,
and result downloads.

## Selection contract

Two selection modes are supported:

- an explicit, canonical set of ticket IDs and exact versions selected from loaded rows;
- an effective server query pinned by its canonical fingerprint, including a private
  saved-view ID/revision/digest when one supplied the query.

Query selection is evaluated once at job creation. A later page change, saved-view edit,
dynamic-field definition change, SLA-column change, or authority change cannot silently
add targets. The materialized target-set digest and count are stored on the job; a worker
never reruns the original list query. The maximum accepted target count is 100,000 and an
empty selection is rejected.

## Execution and failure semantics

The initial operation set is deliberately closed: transition, assign, transfer, claim,
and release. The common mutation payload is canonical and bounded. It is expanded into the
same single-ticket command used by the synchronous API, so workflow requirements,
assignment rules, authorization, activity, audit, SLA, and notification behavior cannot
drift between the two paths.

Workers claim bounded target batches with a lease and opaque fence. Each ticket mutation
commits independently with its target result and progress counters in the same database
transaction. This gives best-effort bulk semantics without reporting an uncommitted
success. Version conflicts, no-change results, hidden/not-found targets, and authorization
denials use bounded result categories; raw database errors and cross-tenant identifiers
are never exposed. Retrying a claimed target is idempotent and a stale fence cannot append
a second result. Attempt deadlines end before the lease safety boundary, while the bounded
release/failure transition may use the reserved safety window and can never run beyond the
lease expiry.

The progress snapshot returned with a claim is the transactional baseline before any
returned target is accounted. Release, failure, and control responses must be monotone for
every result category and must include every result the worker has already observed. This
prevents a structurally valid aggregate from silently replacing a success with another
category or losing a committed prefix. A target replay is valid only for a result committed
after that baseline and is included exactly once in the release receipt and progress floor.

An `ApplyTarget` error is outcome-ambiguous because its transaction may have committed
before the response was lost. The failure transition therefore re-derives target receipts.
It may schedule a retry, terminalize targets that remain pending, or explicitly reconcile
the batch/job as released/completed when every claimed target already has a durable result.
It must never manufacture `internal_failure` merely to fit an ambiguous response. Likewise,
a successful last batch reports a failed global job when an earlier batch already recorded
an internal failure; ordinary completion is valid only without cancellation, authority-
revocation, or internal-failure remainder counters.

Cancellation prevents new claims but does not roll back already committed ticket
transactions. A job becomes terminal only after every materialized target has one terminal
result, or after a cancellation/authority-revocation finalizer accounts for all remaining
targets. Aggregate counts must equal the materialized target count before completion.

## Worker adapter and wiring boundary

The repository-owned worker core, PostgreSQL adapter, and worker process wiring implement
the fenced SQL ABI from the canonical Drizzle schema and migration. The composed adapter:

- atomically claim only unaccounted targets for one explicit tenant and ticket kind, return
  their immutable pins plus the pre-batch progress baseline, and leave transition-revision
  headroom;
- install transaction-local tenant, service-purpose, original requester, and membership
  context on every call, while rechecking live authority in each target transaction;
- make `(tenant, job, batch, worker, fence, revision, lease expiry, target sequence)` part of
  every compare-and-swap and reject an expired or replaced fence;
- commit the direct-path mutation, target receipt, progress increment, activity, audit, and
  outbox atomically; a replay must return the exact stored sequence/result without a second
  increment;
- validate the release receipt digest and processed count from durable target rows, then
  return a category-monotone progress snapshot and the correct released/completed/failed
  global disposition;
- re-derive progress during failure reconciliation, echo the exact stored retry instant,
  and use the explicit reconciliation dispositions when an ambiguous target call had in
  fact completed the batch;
- finalize cancellation or authority revocation under one job lock, account the exact
  remainder atomically, and echo the exact applied control revision; partial control
  progress is invalid;
- honor every context deadline/cancellation, return only bounded dispositions and failure
  codes, clone returned pointer values, and keep raw SQL/provider errors, identifiers,
  target payloads, and authorization detail out of diagnostics.

Migration `0194_ticket_bulk_export_runtime.sql`, the PostgreSQL adapters, worker wiring,
queue metrics, OpenAPI/generated clients, and operator controls compose this contract. The
real PostgreSQL security gate is
`packages/db/tests/security/ticket-bulk-export-runtime.ts`; in-memory port tests are not used
as a substitute for its RLS, fence, replay, or crash-state checks.

## Public and UI behavior

Create, read, cancel, and bounded result-list routes use non-cacheable RFC 9457 responses,
`Idempotency-Key`, and exact optimistic concurrency where applicable. The response never
contains authority snapshots or raw failure details. The Alert and Case action bar submits
either explicit selected versions or the current effective query fingerprint; it does not
infer permission from button visibility. Progress is announced accessibly and stale
selection conflicts require review rather than an automatic retry against newer tickets.

## Verification gate

The repository gates prove direct-ID and query selection isolation, duplicate/empty/
oversized selection rejection, saved-view and catalog drift, idempotent creation and
target replay, lease/fence races, cancellation races, mid-run authority revocation, exact
counter accounting, audit/outbox coupling, customer-field non-disclosure, and PostgreSQL
18 migration behavior. The scheduled performance workflow records a 100,000-target plan
with `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` and bounded worker concurrency; one retained
green reference result for the candidate remains an external release-evidence gate.
