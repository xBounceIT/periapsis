# Asynchronous ticket exports and reporting

This document defines the implemented application and persistence boundary for bounded Alert
and Case exports. The deterministic state machine, API service, PostgreSQL repository,
streaming CSV encoder, fenced worker/reconciler, S3 artifact adapter, HTTP/generated contract,
and operator/customer controls are production-composed. Deployment-specific bucket policy,
credentials, capacity, lifecycle, and retained runtime evidence remain operator-owned.

## Security boundary

An export has an explicit `operator` or `customer` route intent. The intent is not inferred
from a built-in or legacy role name.

- An operator request requires the current `alert.read` or `case.read` capability and exact
  scope needed by the resolved query. Requesting private comments also requires the current
  `alert.comment.private` or `case.comment.private` capability.
- A customer request requires the current `portal.alert.read` or `portal.case.read` capability,
  `portal.comment.public` when comments are requested, `own` scope, and the exact active
  membership/user/contact relationship. Tickets are filtered through that contact
  relationship before pagination or limits.
- Customer requests use only an inline, fixed customer query shape. They cannot consume an
  operator saved view, assignment/team filters, dynamic custom/SLA columns, or private
  comments.
- Saved-view exports are operator-only. The current owner membership, active status, exact
  revision, canonical spec digest, and all current definition pins are checked at request,
  replay, claim, page read, and terminal commit.
- Possession of a job, saved-view, artifact, cursor, or object-storage identifier grants no
  authority. Missing, foreign, non-owned, and no-longer-authorized resources share a
  non-oracular result.

Authorization is repeated in the transaction that commits a request or cancellation and at
each worker claim, page read, renewal, retry, cancellation acknowledgement, and artifact
publication. UI visibility is not part of the decision.

When that recheck proves the original requester/resource authorization has been revoked, a
separate worker-only cleanup path may read only the job envelope: neither source rows nor the
canonical query snapshot. Its only permitted write is an exact-revision terminal transition
to `authorization_revoked`, or the normal `expired`/`cancelled` outcome when the immutable
retention deadline has already elapsed. It cannot claim, render, or publish an artifact. This
prevents both leakage and indefinitely stranded jobs.

## Immutable request snapshot

The job definition pins:

- tenant, requester user, owner membership, and optional exact customer contact;
- Alert or Case kind and operator or customer audience;
- comment scope (`none`, `public`, or operator-only `public_and_private`);
- inline or operator saved-view source;
- optional saved-view ID, owner membership, revision, and spec digest;
- canonical query digest and the digest of the ordered dynamic definition pins;
- customer/operator projection version and CSV format;
- maximum rows, maximum bytes, maximum attempts, and retention deadline.

The idempotency fingerprint covers all of these operation fields plus retention. The raw
idempotency key, filter values, search text, cursors, digests, lease fence, cell contents, and
artifact identifiers are redacted from `String` and `GoString` diagnostics.

Exact request replay happens only after current human and query authorization. Divergent key
reuse is a conflict. Exact cancellation replay also rechecks the current owner and source
authorization before returning its immutable operation-shaped result.

## State machine and fencing

The closed states are:

```text
pending ──claim──> running ──success──> succeeded
   │                  │  └──failure──> pending (bounded retry) or failed
   │                  └──cancel request──> cancellation_requested──ack/lease expiry──> cancelled
   └──cancel request──> cancelled
any nonterminal ──proven authorization revocation──> failed
```

An expired `running` lease may be reclaimed until the attempt ceiling; at the ceiling it
becomes terminal immediately rather than waiting for retention. Before every claim, the worker
creates an opaque UUIDv7 artifact ID. The claim transaction reserves that exact ID in the
attempt-artifact ledger while it creates a new cryptographically random 256-bit fence and
increments both revision and attempt count. A claim response must echo the requested artifact
ID. A collision or inability to reserve it rolls back the whole claim; it must never produce a
running job without its reservation.
Renewal, page reads, retry/failure, cancellation acknowledgement, and success compare tenant,
job ID, expected revision/state, worker ID, and the exact fence. A superseded or expired fence
cannot publish an artifact. A cancellation request prevents success and further page reads.

Claims and pages are tenant/kind/audience bounded. The current limits are:

| Limit          |                 Operator |                 Customer |
| -------------- | -----------------------: | -----------------------: |
| Rows per job   |                  100,000 |                   10,000 |
| Output bytes   |                  512 MiB |                   64 MiB |
| Attempts       |                        5 |                        5 |
| Retention      |     15 minutes to 7 days |     15 minutes to 7 days |
| Lease          | 30 seconds to 15 minutes | 30 seconds to 15 minutes |
| Retry delay    |       1 second to 1 hour |       1 second to 1 hour |
| Rows per page  |                    1,000 |                    1,000 |
| Bytes per page |                    4 MiB |                    4 MiB |
| Bytes per cell |                  128 KiB |                  128 KiB |

Unknown state, audience, source, format, projection version, row kind, comment scope, failure
code, or malformed repository projection fails closed. Failure diagnostics use a closed code;
raw provider/database messages do not enter the job.

Only transient storage, transient database, and internal failures are retryable. Snapshot drift
and output-limit failures are terminal. `authorization_revoked`, `lease_expired`, and `expired`
can be produced only by their dedicated planners; a normal worker failure report cannot assert
those outcomes or bypass the corresponding live proof/deadline check.

## Output safety

The customer query permits only visible fixed core columns `ticket`, `state`, `risk`,
`category`, `created`, and `updated`, and only `updated_at`, `created_at`, or `priority`
sorting. A request can select a subset but cannot add dynamic or operator columns. Customer
pages may contain ticket and public-comment rows only. Operator private-comment rows require
a job that pinned `public_and_private` after live authorization.

Repository pages carry an opaque, non-zero snapshot key that is unique for the canonical
ticket/comment source row within the pinned snapshot. The repository derives it from stable
source identity, never from displayed cell values. Pages are copied, UTF-8 and
control-character checked, cell/page bounded, and spreadsheet-formula neutralized before they
leave the service. The worker rejects a repeated snapshot key even when the cursor advances,
and must use RFC 4180 CSV serialization without undoing that neutralization. Artifact `rows`
counts every emitted
ticket or comment row (the header is excluded), so comments cannot bypass the job row ceiling.
Raw payloads, workflow topology, transition requirements, internal facts/policy/trigger data,
secrets, object keys, presigned URLs, HTML, mentions, and attachments are not part of the
customer projection.

An artifact result contains only a tenant-owned opaque artifact ID, SHA-256 digest, row and
byte counts, and the job's exact immutable expiry. Object keys and credentials stay behind the persistence/storage
adapter. Download authorization is a fresh resource decision, not a property of the artifact
identifier.

The shared CSV encoder writes canonical CRLF records directly to a temporary object, quotes
the otherwise ambiguous one-column empty record, canonicalizes embedded line endings,
neutralizes any still-dangerous header or cell as defense in depth, and applies row and byte
ceilings before a record can exceed the target. It returns the exact streamed byte count,
non-header row count, and SHA-256 digest only after a successful close. Storage errors,
invalid projections, and limit failures poison the stream; partial output can never be
promoted.

## Worker orchestration core

`services/worker/internal/ticketexport` owns one bounded attempt for one explicit
tenant/kind/audience queue. Its repository and artifact-store ports contain no SQL, bucket,
object key, credential, presigned URL, raw query, or row value in diagnostics.

The attempt protocol is:

1. generate an opaque artifact ID, then claim one currently authorized job through a
   tenant-explicit repository call that atomically creates the running revision, attempt,
   lease, 256-bit fence, and `reserved` attempt-artifact ledger row for that exact ID;
2. validate the echoed artifact ID, returned immutable job envelope, exact visible header,
   worker identity, lease timestamps, query/catalog digests, projection version, and configured
   bounds;
3. open a tenant-bound **local spool** and page the deterministic snapshot with every read bound
   to the exact revision, fence, digests, projection version, cursor, and page size;
4. validate the closed ticket/public-comment/private-comment row vocabulary, customer/private
   visibility, opaque unique row keys, UTF-8/control safety, page size, cursor progression, and
   total row/byte ceilings;
5. close the CSV encoder and obtain its exact row count, byte count, and SHA-256 digest;
6. call `RecordManifest` to durably bind that exact manifest to the reserved attempt. Only an
   exact manifest and current-revision echo authorizes continuation; no object-store PUT is
   permitted before this transaction commits;
7. seal the local spool by uploading a create-only temporary object, reconcile the PUT through
   checksum-enabled HEAD, and promote it idempotently to the reserved artifact ID;
8. execute the fenced, idempotent database success commit and accept success only when the
   resulting revision and the complete manifest are echoed exactly;
9. durably transition failure/cancellation/revocation state and its ledger cleanup debt before
   best-effort abort/purge. Purge is allowed only after a conclusive non-success response; an
   outcome-ambiguous success response always preserves the final object.

Page controls carry no source rows. Cancellation acknowledgement and authorization revocation
use separate purpose-specific repository transitions. A repeated cursor digest or snapshot row
key terminalizes as snapshot drift; independent row and byte ceilings still bound all work.

The cross-resource commit window is intentionally explicit. Database metadata exists from the
claim onward: the ledger first reserves the artifact ID and later records the manifest before
storage mutation. A lost claim response is therefore a transition-unknown outcome, not an idle
result. A lost `RecordManifest` response can be resolved by a fenced failure transition; that
transition marks the attempt cleanup-pending whether or not the manifest write committed.

If promotion returns an error, the final-object outcome may be ambiguous, but the durable
reservation and manifest let the reconciler prove ownership without parsing arbitrary bucket
keys. The worker records a bounded storage retry, preserves any possibly promoted object, and
reports a closed publication-unknown error. If the final database response is lost or its
manifest/revision echo is malformed, the transaction may already have committed; the core does
**not** delete the promoted object or write a contradictory failure. A later authoritative job
and ledger read determines the outcome. This is at-least-once execution with idempotent business
transitions, not a claim of distributed exactly-once commit.

Claim, local-spool open, page, manifest, control, terminal, seal, and promotion calls have strict
timeouts. A nil-error response that arrives after its context deadline is not trusted. The
temporary writer is bound to the whole attempt context so a blocked stream write must return on
cancellation; the S3 spool closes its OS file handle from an independent context callback so a
writer cannot hold the attempt open behind the session mutex. The attempt ends before a lease
safety margin, parent cancellation stops new work,
and every detached fenced transition is additionally capped by the lease expiry. Cleanup is
idempotently retried through one short detached deadline; graceful cancellation never writes a
false failure. Retryable database/storage/internal failures use bounded
exponential delay with deterministic jitter derived from the random claim fence. Public errors
and all `String`/`GoString` diagnostics use a closed, redacted taxonomy.

### S3 artifact adapter

The worker artifact port has a concrete bounded S3 implementation. It spools each attempt into
the explicitly configured writable temporary directory using an OS-created private regular
file, independently hashes and counts every byte, and uploads only after the worker's exact
manifest has been durably recorded and matches the local stream. Operator and customer byte
ceilings are rechecked at this boundary.

Temporary and final keys are derived only from the canonical tenant, job, and artifact UUIDv7
values under `ticket-exports/v1`; customer content never contributes to a key or metadata. PUT
and COPY use `If-None-Match: *`, SHA-256 checksums, exact source ETags, SSE-S3, and the configured
expected bucket owner when available. A lost PUT or COPY response is accepted only after an
exact HEAD match on content length, content type, encryption, projection, digest, row/byte
counts, tenant/job/artifact IDs, attempt, running revision, state, and ETag.

Abort and purge never issue an unconditional delete. They HEAD the derived key, prove the exact
manifest metadata, and then use an ETag-conditioned delete. A colliding or replaced object is
preserved and reported as unavailable for later reconciliation. Promotion removes only the
verified temporary object; an ambiguous database commit still leaves the verified final object
intact. Production client construction and ledger-driven orphan reconciliation consume this
adapter. Bucket policy, versioning, lifecycle, capacity, and credentials remain explicit
deployment configuration rather than hidden adapter assumptions.

Local remove failures retain the exact path for the worker's bounded in-attempt retries. The
adapter also exposes a bounded, replay-safe stale-spool sweep for crash leftovers; it recognizes
only its private `.ticket-export-<number>.partial` names, skips symlinks/non-regular/young files,
tracks and skips every in-process open spool, enforces a cutoff older than the maximum lease plus
a safety minute, and reports cleanup debt without exposing paths. Wiring must use a dedicated
temporary directory and run the sweep at startup and periodically. Unrelated directory entries
are never removed.

## Implemented PostgreSQL ABI

Migration `0194_ticket_bulk_export_runtime.sql` implements the purpose-specific tenant tables,
RLS, functions, grants, and readiness roots described below. The adapter does not reuse
notification/outbox payload JSON as the authoritative job record.

### `ticket_export_jobs`

- `tenant_id uuid NOT NULL`, `id uuid NOT NULL`, `requester_user_id uuid NOT NULL`,
  `owner_membership_id uuid NOT NULL`, `customer_contact_id uuid NULL`;
- closed `kind`, `audience`, `comment_scope`, `query_source`, `format`, `state`, and
  `failure_code` values enforced by checks;
- nullable saved-view ID plus owner/revision/digest with an all-or-none check and an operator-
  only source check;
- non-null 32-byte query/catalog digests and positive projection version;
- positive bounded row/byte/attempt limits;
- positive revision, attempt count within its ceiling, requested/updated/available/expiry
  timestamps;
- nullable lease worker/fence/claimed/expiry columns with an all-or-none check;
- nullable artifact ID/digest/row/byte/expiry columns with an all-or-none check;
- terminal timestamp and state-shape checks matching the domain constructor;
- `PRIMARY KEY (tenant_id, id)`, tenant-leading eligibility indexes, and composite tenant
  foreign keys for membership, contact, saved view, and artifact relationships.

Tenant and immutable request columns cannot change after insert. A reviewed trigger or
operation-specific functions must reject their update; generic table update grants are not
acceptable.

### `ticket_export_idempotency`

The key is `(tenant_id, actor_user_id, owner_membership_id, audience, kind, action,
key_hash)`. It stores the 32-byte fingerprint and an immutable bounded response snapshot.
Rows contain no raw key or unrestricted aggregate/query document. Same-key/different-
fingerprint lookup is a conflict. Snapshot retention is at least the accepted retry window
and has an explicit purge policy.

### `ticket_export_attempt_artifacts`

Every claim has one durable, tenant-owned attempt-artifact row. Its minimum shape is:

- `tenant_id`, `job_id`, `artifact_id`, `worker_id`, positive `attempt`, and the exact positive
  running `job_revision`;
- the exact 32-byte fence plus reservation and lease-expiry timestamps;
- nullable 32-byte SHA-256 digest, row count, byte count, and `manifest_recorded_at`, with an
  all-or-none check and job-bound limits;
- a closed monotonic state such as `reserved`, `manifest_recorded`, `committed`,
  `cleanup_pending`, and `cleaned`, plus bounded transition timestamps;
- `PRIMARY KEY (tenant_id, artifact_id)`, uniqueness for `(tenant_id, job_id, attempt)` and
  `(tenant_id, job_id, job_revision)`, and tenant-composite foreign keys.

Identity, fence, attempt, revision, and reservation time are immutable. Manifest columns are
write-once: the first valid `RecordManifest` fills them; an exact replay succeeds and any
different digest/count fails closed. The ledger contains no bucket, key, presigned URL, query,
cursor, or customer cell. Storage keys are derived only inside the storage adapter.

Claim must install the running job lease and the `reserved` row in one transaction. A unique
collision, authorization failure, or lost CAS rolls back both. `RecordManifest` compares the
tenant/job/revision/attempt/worker/fence/artifact binding and returns the exact durable manifest
and unchanged running revision. Failure, cancellation acknowledgement, authorization
revocation, and lease-expiry processing atomically mark every non-committed attempt
`cleanup_pending`. Success compares the same manifest, creates the downloadable artifact
metadata, attaches it to the job, and marks the attempt `committed` in one transaction.

The ledger is retained long enough to cover job retention, storage lifecycle lag, and the
maximum reconciliation window. Removing a ledger row before both database references and exact
storage cleanup are proven is forbidden.

### `ticket_export_query_snapshots` and artifacts

The canonical query document is tenant/job keyed, size constrained, immutable, and digest-
checked. Decoding uses one canonical schema with unknown and duplicate fields rejected.
Customer snapshots are operation-shaped and cannot contain operator-only filter or column
vocabulary.

Artifact metadata is a separate tenant-owned table with a composite `(tenant_id, id)` key,
immutable digest/size, expiry, and storage locator inaccessible to normal API queries. The
object key is tenant-prefixed as defense in depth. Artifact bytes are uploaded to a temporary
key and promoted only in the same fenced success protocol; abandoned temporary objects are
garbage-collected.

All tenant tables enable and force RLS. API and worker runtime roles have no `BYPASSRLS`, are
not table owners, and receive only operation-specific function execution. The notifier role
receives no export grants.

### Crash reconciliation

Reconciliation is ledger-driven and tenant scoped; bucket listing or key parsing is never an
ownership authority. It reads the job and attempt row first, then uses checksum-enabled HEAD on
the two derived keys. The closed decisions are:

| Durable state and exact HEAD evidence                                                                                              | Required action                                                                                                                        |
| ---------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Succeeded job references the same committed manifest and exact final object                                                        | Retain final; conditionally remove an exact temporary object.                                                                          |
| Same live running fence, recorded manifest, and exact final object                                                                 | The normal fenced success function may be replayed only after current authorization/pin checks; otherwise leave it for lease recovery. |
| Reservation or manifest belongs to an expired/superseded attempt, or job is pending/failed/cancelled/revoked without that artifact | Mark cleanup pending and conditionally delete only exact temporary/final matches.                                                      |
| Reservation has no manifest                                                                                                        | No remote object is valid; after the attempt is no longer live, mark cleaned only if both derived keys are absent.                     |
| Recorded manifest exists but both keys are absent                                                                                  | After the attempt is no longer live and no success reference exists, mark cleaned/abandoned; never synthesize success.                 |
| HEAD checksum, length, metadata, revision, attempt, ETag, or encryption differs                                                    | Preserve/quarantine, emit a redacted alert, and require operator resolution; never delete the collision.                               |

A lost DELETE response is replayed: missing is success, while a still-present object must again
pass the full manifest and ETag proof. A lost success response is reconciled from the job and
ledger; the object is never deleted merely because the caller observed a timeout. Concurrent
reconcilers CAS the ledger state, and every deletion remains idempotent and conditional.

## Transaction algorithms

Request commit performs, in one transaction:

1. install tenant/actor/request/purpose context;
2. re-resolve the live route intent, capability, scope, contact relation, saved view, and
   definition pins;
3. lock/check the idempotency identity and fingerprint;
4. insert the immutable query snapshot and pending job;
5. append a redacted audit event and immutable idempotency result;
6. commit once.

Claim uses a small tenant-scoped `FOR UPDATE SKIP LOCKED` batch ordered by eligibility and
fairness. It reauthorizes the service purpose and original request, validates the worker-supplied
artifact ID, then CASes the exact revision/state while installing a new fence and inserting the
matching `reserved` ledger row. The response echoes the artifact ID and complete running
revision. A worker never mixes tenant contexts in one transaction.

Every page cursor is authenticated and bound to job ID, exact job revision, query and catalog
digests, projection version, current fence, page size, and keyset position. Every returned row
also carries a snapshot-unique opaque source key. Cursor reuse, a repeated row key after reclaim,
query/pin drift, cancellation, or revision drift fails closed.

Manifest commit compares the full running binding and reserved artifact ID, writes digest/rows/
bytes once, and returns the same manifest plus unchanged running revision. A different replay is
snapshot drift. This transaction completes before `Seal` is allowed to perform PUT.

Terminal commit rechecks service purpose, original request authorization, query pins,
revision/state/worker/fence, the exact recorded attempt manifest, artifact bounds, digest, and
expiry before publishing the artifact metadata and marking the ledger committed. Its response
echoes the resulting revision and complete manifest. Revocation between request and claim or
between the final page and commit therefore cannot produce a downloadable result.

## Implementation and verification references

- Canonical schema and ABI: `packages/db/src/schema/ticket-runtime.ts` and migration 0194.
- PostgreSQL tenant/fence/replay gate:
  `packages/db/tests/security/ticket-bulk-export-runtime.ts`.
- API services and transport: `services/api/internal/ticketing/async_export_*` and
  `services/api/internal/httpserver/ticket_export_*`.
- Worker, S3 adapter, and reconciliation: `services/worker/internal/ticketexport`.
- Operator controls: `apps/web/src/ticketing/ticket-export-*`.
- Canonical route shapes: `packages/contracts/openapi/openapi.yaml` plus the generated drift
  gates.

All layers consume the domain/application contracts rather than recreating audience,
visibility, idempotency, or state-machine decisions independently. The remaining release
work is external evidence for the exact candidate digest; see
[`TASKS.md`](../TASKS.md).
