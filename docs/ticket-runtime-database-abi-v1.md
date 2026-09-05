# Ticket bulk and asynchronous export database ABI v1

This document freezes the Go production adapter boundary implemented by the canonical
Drizzle schema and `0194_ticket_bulk_export_runtime.sql`. It is descriptive: schema changes
remain owned by the Drizzle/migration workflow and must not be applied from this document.

## SQL contract

Every operation function below has the exact signature:

```sql
app.<name>_v1(request jsonb)
RETURNS TABLE(response jsonb)
```

Operation functions are `VOLATILE SECURITY DEFINER`, reject every unknown or
missing JSON field, pin a safe `search_path`, and return either exactly one row
or the explicitly documented no-row result. `PUBLIC` has no `EXECUTE`; only
`periapsis_api` receives the API functions and only `periapsis_worker` receives
the worker functions. Neither runtime role receives table privileges.

The readiness functions have exact signatures:

```sql
app.ticket_bulk_runtime_schema_readiness_v1() RETURNS boolean
app.ticket_export_runtime_schema_readiness_v1() RETURNS boolean
```

They are `STABLE SECURITY DEFINER`, fail closed on any missing table, column,
constraint, index, RLS policy, function, owner, ACL, or source-hash invariant,
and are executable by both runtime roles but not `PUBLIC`.

## Runtime configuration and health

The worker composes the runtime only when
`PERIAPSIS_TICKET_RUNTIME_SERVICE_ACCOUNT_ID` (or its `_FILE` form) contains a
canonical UUIDv7. This is an operator-provisioned, least-privileged service
account identity, not an application-generated fallback. If it is absent, the
process may serve liveness and metrics, but ticket runtime readiness and the
overall worker readiness remain false.

Exports reuse the hardened worker S3 configuration (`PERIAPSIS_S3_ENDPOINT`,
`PERIAPSIS_S3_REGION`, `PERIAPSIS_S3_BUCKET`, access-key/secret-key `_FILE`
mounts in production, optional session token/CA/private-egress policy, and
bounded concurrency). `PERIAPSIS_TICKET_EXPORT_SPOOL_DIR` is an absolute,
clean writable path and defaults to the process temporary directory.
`PERIAPSIS_TICKET_EXPORT_EXPECTED_BUCKET_OWNER`, when set, is exactly twelve
decimal digits and is attached to object operations. Before advertising ticket
runtime readiness, each poll performs a bounded `HeadBucket` against that exact
bucket and owner; the storage principal must permit this check.

The API readiness dependency is named `ticket_operations`. The worker exposes
`periapsis_worker_ticket_runtime_ready` and the fixed-label counters
`periapsis_ticket_bulk_worker_runs_total{outcome="worked|empty|failure"}` and
`periapsis_ticket_export_worker_runs_total{outcome="worked|empty|failure"}`.
No metric or runtime log contains tenant, identity, cursor, row, object-key, or
raw error labels. Both readiness paths require both versioned database
readiness functions. A missing function, false/NULL result, cancelled context,
typed-nil dependency, S3/spool failure, or failed queue iteration clears worker
readiness. Shutdown cancellation reaches all in-flight database, spool, and S3
operations; the process waits for bounded background completion and closes
idle S3 transport connections.

All documents use `schemaVersion: 1`. UUIDs are canonical UUIDv7 strings;
digests are 64-character lower-case SHA-256 hex; timestamps are UTC and have
microsecond precision. JSON timestamps with `Z` or an explicit zero offset are
accepted and normalized to UTC; non-zero offsets are rejected. Durations are
integral microseconds. Empty optionals
are encoded as `null` for pointer/object fields and as `""` for scalar string
fields. Responses must not contain additional fields. Request and response
limits are respectively 2 MiB and 32 MiB; a response may contain at most
2,000,000 JSON tokens.

## Shared JSON shapes

The following pseudo-JSON is exact as to field names, nesting, and nullability.

```json
Actor = {
  "userId":"<uuidv7>", "sessionId":"<uuidv7>",
  "activeTenantId":"<uuidv7>", "authenticationMethod":"<closed string>"
}
Audit = {
  "requestId":"<uuid>", "correlationId":"<uuid>",
  "remoteAddress":"<canonical IP>", "userAgent":"<bounded string>"
}
WorkerIdentity = {
  "serviceAccountId":"<uuidv7>", "workerId":"<uuidv7>",
  "purpose":"ticket_runtime|ticket_bulk|ticket_export"
}
SavedView = {
  "id":"<uuidv7>", "ownerId":"<uuidv7>", "revision":1,
  "specSha256":"<sha256>"
}
Query = {
  "source":"inline|saved_view", "specCanonicalBase64":"<raw-base64>",
  "querySha256":"<sha256>", "catalogSha256":"<sha256>",
  "savedView":null
}
Target = {"id":"<uuidv7>", "version":1}
BulkSelection = {
  "source":"explicit|query", "explicitTargets":null,
  "querySha256":"", "targetSetSha256":"<sha256>",
  "targetCount":1, "savedView":null
}
BulkMutation = {
  "action":"transition|assign|transfer|claim|release",
  "transition":"", "to":"", "teamId":"", "assigneeId":""
}
BulkDefinition = {
  "id":"<uuidv7>", "tenantId":"<uuidv7>", "requesterId":"<uuidv7>",
  "ownerMembershipId":"<uuidv7>", "kind":"alert|case",
  "selection":BulkSelection, "mutation":BulkMutation,
  "projectionVersion":1, "maximumAttempts":1
}
BulkProgress = {
  "total":1, "succeeded":0, "noChange":0, "versionConflict":0,
  "notFoundOrHidden":0, "authorizationDenied":0, "rejected":0,
  "cancelled":0, "authorizationRevoked":0, "internalFailure":0
}
BulkJob = {
  "definition":BulkDefinition,
  "state":"pending|running|cancellation_requested|completed|failed|cancelled|authorization_revoked",
  "revision":1, "progress":BulkProgress,
  "requestedAt":"<instant>", "updatedAt":"<instant>",
  "availableAt":"<instant>", "expiresAt":"<instant>",
  "activeBatch":false, "terminalAt":null
}
BulkRecord = {"job":BulkJob, "query":null}
ExportDefinition = {
  "id":"<uuidv7>", "tenantId":"<uuidv7>", "requesterId":"<uuidv7>",
  "ownerMembershipId":"<uuidv7>", "customerContactId":"",
  "kind":"alert|case", "audience":"operator|customer",
  "commentScope":"none|public|public_and_private",
  "querySource":"inline|saved_view", "savedView":null,
  "querySha256":"<sha256>", "catalogSha256":"<sha256>",
  "projectionVersion":1, "format":"csv", "maximumRows":1,
  "maximumBytes":1, "maximumAttempts":1
}
ExportLease = {
  "workerId":"<uuidv7>", "fenceSha256":"<sha256>",
  "claimedAt":"<instant>", "expiresAt":"<instant>"
}
ExportArtifact = {
  "id":"<uuidv7>", "sha256":"<sha256>", "rows":0, "bytes":1,
  "expiresAt":"<instant>"
}
ExportJob = {
  "definition":ExportDefinition,
  "state":"pending|running|cancellation_requested|succeeded|failed|cancelled",
  "revision":1, "attempts":0,
  "failureCode":"none|transient_storage|transient_database|authorization_revoked|snapshot_stale|output_limit|lease_expired|expired|internal",
  "requestedAt":"<instant>", "updatedAt":"<instant>",
  "availableAt":"<instant>", "expiresAt":"<instant>",
  "lease":null, "artifact":null, "terminalAt":null
}
ExportRecord = {"job":ExportJob, "query":Query}
BulkBinding = {
  "tenantId":"<uuidv7>", "jobId":"<uuidv7>", "batchId":"<uuidv7>",
  "kind":"alert|case", "workerId":"<uuidv7>", "revision":1,
  "attempt":1, "fenceSha256":"<sha256>",
  "targetSetSha256":"<sha256>", "projectionVersion":1,
  "claimedAt":"<instant>", "leaseExpiresAt":"<instant>",
  "jobExpiresAt":"<instant>"
}
ExportBinding = {
  "tenantId":"<uuidv7>", "jobId":"<uuidv7>", "kind":"alert|case",
  "audience":"operator|customer", "workerId":"<uuidv7>",
  "revision":1, "attempt":1, "fenceSha256":"<sha256>",
  "querySha256":"<sha256>", "catalogSha256":"<sha256>",
  "projectionVersion":1, "leaseClaimedAt":"<instant>",
  "leaseExpiresAt":"<instant>", "jobExpiresAt":"<instant>"
}
Manifest = {"artifactId":"<uuidv7>", "sha256":"<sha256>", "rows":0, "bytes":1}
```

`Query.savedView` is `null` only for inline sources and is `SavedView` for a
saved-view source. `BulkSelection.explicitTargets` is a non-empty array for an
explicit selection and is `null` for a query selection; a query selection
carries the exact query/catalog pins and its `savedView` follows the same
rule. `BulkRecord.query` is `null` only
for explicit selection and is `Query` for query selection.
`ExportDefinition.savedView` follows its `querySource`. Job `lease`,
`artifact`, and `terminalAt` fields are `null` exactly when the kernel state
does not permit the corresponding value; otherwise they contain the shared
shape above.

An inline query source is exactly
`{"mode":"inline","spec":<saved-view resolve-spec v1 request>}`. A saved-view
source is exactly
`{"mode":"saved_view","id":"<uuidv7>","revision":1,"specSha256":"<sha256>"}`.
The inline resolve-spec request is the existing saved-view ABI v1 shape and
must bind its distinct `actorId` and `ownerMembershipId` fields.

## API role functions

`NO ROW` is allowed only where shown and maps to a non-oracular not-found or
idempotency miss.

| Function                                   | Request `request`                                                                                                                                                                                                 | Response `response`                                                                                                                                                                                                                                                                                                                 |
| ------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `resolve_ticket_bulk_access_v1`            | `{"schemaVersion":1,"actor":Actor,"tenantId":"<uuidv7>","kind":"alert                                                                                                                                             | case","capability":"<closed>","mutationAction":"<closed>"}`                                                                                                                                                                                                                                                                         | `{"schemaVersion":1,"tenantId":"<uuidv7>","actorId":"<uuidv7>","membershipId":"<uuidv7>","kind":"alert                                                | case","capability":"<closed>","principal":"operator                                                          | customer                   | service_account","mutationAction":"<closed>","allowed":true}` |
| `resolve_ticket_bulk_query_v1`             | `{"schemaVersion":1,"actor":Actor,"tenantId":"<uuidv7>","kind":"alert                                                                                                                                             | case","membershipId":"<uuidv7>","source":<inline-or-saved-view>}`                                                                                                                                                                                                                                                                   | `{"schemaVersion":1,"query":Query}`                                                                                                                   |
| `lookup_ticket_bulk_replay_v1`             | `{"schemaVersion":1,"tenantId":"<uuidv7>","actorId":"<uuidv7>","ownerMembershipId":"<uuidv7>","kind":"alert                                                                                                       | case","action":"<closed>","idempotencyKeySha256":"<sha256>"}`                                                                                                                                                                                                                                                                       | no row, or `{"schemaVersion":1,"replayed":true,"requestFingerprintSha256":"<sha256>","record":BulkRecord}`                                            |
| `commit_ticket_bulk_request_v1`            | `{"schemaVersion":1,"actor":Actor,"audit":Audit,"tenantId":"<uuidv7>","ownerMembershipId":"<uuidv7>","kind":"alert                                                                                                | case","requiredCapability":"<closed>","jobId":"<uuidv7>","explicitTargets":null,"query":Query,"mutation":BulkMutation,"requestedAt":"<instant>","expiresAt":"<instant>","action":"<closed>","idempotencyKeySha256":"<sha256>","requestFingerprintSha256":"<sha256>"}`; exactly one of non-empty `explicitTargets`or non-null`query` | `{"schemaVersion":1,"replayed":false,"requestFingerprintSha256":"<sha256>","record":BulkRecord}`                                                      |
| `get_ticket_bulk_v1`                       | `{"schemaVersion":1,"actor":Actor,"tenantId":"<uuidv7>","ownerMembershipId":"<uuidv7>","kind":"alert                                                                                                              | case","capability":"<closed>","jobId":"<uuidv7>"}`                                                                                                                                                                                                                                                                                  | no row, or `{"schemaVersion":1,"record":BulkRecord}`                                                                                                  |
| `commit_ticket_bulk_cancellation_v1`       | `{"schemaVersion":1,"actor":Actor,"audit":Audit,"requiredCapability":"<closed>","expectedRevision":1,"next":BulkJob,"action":"<closed>","idempotencyKeySha256":"<sha256>","requestFingerprintSha256":"<sha256>"}` | bulk commit response                                                                                                                                                                                                                                                                                                                |
| `list_ticket_bulk_results_v1`              | `{"schemaVersion":1,"actor":Actor,"tenantId":"<uuidv7>","ownerMembershipId":"<uuidv7>","kind":"alert                                                                                                              | case","jobId":"<uuidv7>","limit":50,"after":"<opaque>"}`                                                                                                                                                                                                                                                                            | `{"schemaVersion":1,"items":[{"sequence":1,"targetId":"<uuidv7>","targetVersion":1,"result":"<closed>","recordedAt":"<instant>"}],"next":"<opaque>"}` |
| `resolve_ticket_export_access_v1`          | `{"schemaVersion":1,"actor":Actor,"tenantId":"<uuidv7>","kind":"alert                                                                                                                                             | case","audience":"operator                                                                                                                                                                                                                                                                                                          | customer","capability":"<closed>"}`                                                                                                                   | `{"schemaVersion":1,"tenantId":"<uuidv7>","actorId":"<uuidv7>","membershipId":"<uuidv7>","kind":"alert       | case","audience":"operator | customer","capability":"<closed>","principal":"operator       | customer | service_account","customerContactId":"","publicComments":true,"privateComments":false,"allowed":true}` |
| `resolve_ticket_export_query_v1`           | `{"schemaVersion":1,"actor":Actor,"tenantId":"<uuidv7>","ownerMembershipId":"<uuidv7>","kind":"alert                                                                                                              | case","audience":"operator                                                                                                                                                                                                                                                                                                          | customer","source":<inline-or-saved-view>}`                                                                                                           | `{"schemaVersion":1,"query":Query}`                                                                          |
| `lookup_ticket_export_replay_v1`           | `{"schemaVersion":1,"tenantId":"<uuidv7>","actorId":"<uuidv7>","ownerMembershipId":"<uuidv7>","kind":"alert                                                                                                       | case","audience":"operator                                                                                                                                                                                                                                                                                                          | customer","action":"<closed>","idempotencyKeySha256":"<sha256>"}`                                                                                     | no row, or `{"schemaVersion":1,"replayed":true,"requestFingerprintSha256":"<sha256>","record":ExportRecord}` |
| `commit_ticket_export_request_v1`          | export transition request below                                                                                                                                                                                   | export commit response below                                                                                                                                                                                                                                                                                                        |
| `get_ticket_export_v1`                     | `{"schemaVersion":1,"actor":Actor,"tenantId":"<uuidv7>","ownerMembershipId":"<uuidv7>","kind":"alert                                                                                                              | case","audience":"operator                                                                                                                                                                                                                                                                                                          | customer","capability":"<closed>","jobId":"<uuidv7>"}`                                                                                                | no row, or `{"schemaVersion":1,"record":ExportRecord}`                                                       |
| `commit_ticket_export_owner_transition_v1` | export transition request below                                                                                                                                                                                   | export commit response below                                                                                                                                                                                                                                                                                                        |

The export transition request is exactly:

```json
{"schemaVersion":1,"actor":Actor,"audit":Audit,
 "requiredCapability":"<closed>","expectedRevision":0,"next":ExportJob,
 "query":Query,"action":"<closed>","idempotencyKeySha256":"<sha256>",
 "requestFingerprintSha256":"<sha256>"}
```

The export commit response is exactly:

```json
{"schemaVersion":1,"replayed":false,
 "requestFingerprintSha256":"<sha256>","record":ExportRecord}
```

The existing application worker port also requires these separate API-role
functions. They are not the new worker runtime protocol and must not share its
page function:

| Function                                    | Request                                                                                                                          | Response                                                               |
| ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `resolve_ticket_export_worker_access_v1`    | `{"schemaVersion":1,"serviceAccountId":"<uuidv7>","workerId":"<uuidv7>","purpose":"<closed>","tenantId":"<uuidv7>","kind":"alert | case","audience":"operator                                             | customer","capability":"<closed>"}`                                                                                                                                 | same echoed fields plus `"allowed":true`    |
| `select_ticket_export_claim_candidate_v1`   | legacy worker request below (`jobId:""`, revision/fence zero, `now` set)                                                         | no row, or `{"schemaVersion":1,"record":ExportRecord}`                 |
| `get_ticket_export_for_worker_v1`           | legacy worker request below (`jobId` set)                                                                                        | no row, or export get response                                         |
| `get_revoked_ticket_export_for_worker_v1`   | legacy worker request below (`jobId` set)                                                                                        | no row, or `{"schemaVersion":1,"job":ExportJob}`; never return `Query` |
| `commit_ticket_export_worker_transition_v1` | `{"schemaVersion":1,"worker":WorkerIdentity,"tenantId":"<uuidv7>","kind":"alert                                                  | case","audience":"operator                                             | customer","requiredCapability":"<closed>","expectedRevision":1,"next":ExportJob,"query":Query}`                                                                     | `{"schemaVersion":1,"record":ExportRecord}` |
| `commit_ticket_export_revocation_v1`        | same as worker transition without `query`                                                                                        | `{"schemaVersion":1,"job":ExportJob}`                                  |
| `read_ticket_export_application_page_v1`    | `{"schemaVersion":1,"worker":WorkerIdentity,"tenantId":"<uuidv7>","jobId":"<uuidv7>","kind":"alert                               | case","audience":"operator                                             | customer","expectedRevision":1,"fenceSha256":"<sha256>","querySha256":"<sha256>","catalogSha256":"<sha256>","projectionVersion":1,"after":"<opaque>","limit":1000}` | `{"schemaVersion":1,"rows":[{"kind":"ticket | public_comment | private_comment","cells":["<value>"]}],"next":"<opaque>"}` |

The legacy worker request is exactly (claim-candidate sets `now` to an
instant; get/revocation reads set it to `null`):

```json
{"schemaVersion":1,"worker":WorkerIdentity,"tenantId":"<uuidv7>",
 "kind":"alert|case","audience":"operator|customer","capability":"<closed>",
 "jobId":"","expectedRevision":0,"fenceSha256":"","now":null}
```

## Worker role functions

All worker functions re-resolve the service-account purpose and the original
requester's live authorization inside the same tenant transaction. A worker
request with an unknown purpose, tenant, kind, audience, fence, digest,
revision, attempt, or projection version is denied before mutation or source
row disclosure.

| Function                                           | Request                                                                                                                                                         | Response                                                           |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `list_ticket_work_queues_v1`                       | `{"schemaVersion":1,"serviceAccountId":"<uuidv7>","workerId":"<uuidv7>","purpose":"ticket_runtime","limit":256}`                                                | `{"schemaVersion":1,"queues":[{"type":"bulk                        | export","tenantId":"<uuidv7>","kind":"alert                                                                                                                                                | case","audience":""}]}`; export audience is operator/customer                                                           |
| `claim_ticket_bulk_batch_v1`                       | `{"schemaVersion":1,"identity":WorkerIdentity,"tenantId":"<uuidv7>","kind":"alert                                                                               | case","now":"<instant>","leaseMicroseconds":300000000,"limit":50}` | no row, or `{"schemaVersion":1,"definition":BulkDefinition,"binding":BulkBinding,"targets":[{"id":"<uuidv7>","version":1,"sequence":1}],"progress":BulkProgress,"observedAt":"<instant>"}` |
| `apply_ticket_bulk_target_v1`                      | `{"schemaVersion":1,"identity":WorkerIdentity,"binding":BulkBinding,"sequence":1,"targetId":"<uuidv7>","targetVersion":1,"action":"<closed>"}`                  | `{"schemaVersion":1,"disposition":"applied                         | replayed                                                                                                                                                                                   | cancellation_requested                                                                                                  | authorization_revoked                             | fence_lost","sequence":1,"result":"<closed or empty>","controlRevision":0}` |
| `release_ticket_bulk_batch_v1`                     | `{"schemaVersion":1,"identity":WorkerIdentity,"binding":BulkBinding,"processed":1,"receiptSha256":"<sha256>","releasedAt":"<instant>"}`                         | `{"schemaVersion":1,"disposition":"batch_released                  | job_completed                                                                                                                                                                              | cancellation_requested                                                                                                  | authorization_revoked                             | fence_lost                                                                  | job_failed","progress":BulkProgress-or-null,"controlRevision":0}` |
| `report_ticket_bulk_batch_failure_v1`              | `{"schemaVersion":1,"identity":WorkerIdentity,"binding":BulkBinding,"code":"transient_database                                                                  | invalid_projection                                                 | lease_safety                                                                                                                                                                               | interrupted                                                                                                             | internal","failedAt":"<instant>","retryAt":null}` | `{"schemaVersion":1,"disposition":"retry_scheduled                          | replay_retry                                                      | batch_terminalized                                                                        | replay_batch_terminalized | job_failed | replay_job_failed | cancellation_requested | authorization_revoked | fence_lost | batch_released | replay_batch_released | job_completed | replay_job_completed","progress":BulkProgress-or-null,"controlRevision":0,"retryAt":null}` |
| `finalize_ticket_bulk_cancellation_v1`             | bulk control request below                                                                                                                                      | bulk control response below                                        |
| `finalize_ticket_bulk_authorization_revocation_v1` | bulk control request below                                                                                                                                      | bulk control response below                                        |
| `claim_ticket_export_v1`                           | `{"schemaVersion":1,"identity":WorkerIdentity,"tenantId":"<uuidv7>","kind":"alert                                                                               | case","audience":"operator                                         | customer","artifactId":"<uuidv7>","now":"<instant>","leaseMicroseconds":600000000}`                                                                                                        | no row, or `{"schemaVersion":1,"job":ExportJob,"artifactId":"<uuidv7>","header":["<column>"],"observedAt":"<instant>"}` |
| `read_ticket_export_page_v1`                       | `{"schemaVersion":1,"identity":WorkerIdentity,"binding":ExportBinding,"after":"<opaque>","limit":1000}`                                                         | `{"schemaVersion":1,"control":"ready                               | cancellation_requested                                                                                                                                                                     | authorization_revoked                                                                                                   | fence_lost                                        | snapshot_stale","controlRevision":0,"rows":[{"kind":"ticket                 | public_comment                                                    | private_comment","snapshotKeySha256":"<sha256>","cells":["<value>"]}],"next":"<opaque>"}` |
| `record_ticket_export_manifest_v1`                 | `{"schemaVersion":1,"identity":WorkerIdentity,"binding":ExportBinding,"artifactId":"<uuidv7>","sha256":"<sha256>","rows":0,"bytes":1,"recordedAt":"<instant>"}` | export manifest response below                                     |
| `commit_ticket_export_success_v1`                  | manifest request plus `"expiresAt":"<instant>","completedAt":"<instant>"` instead of `recordedAt`                                                               | export commit response below                                       |
| `report_ticket_export_failure_v1`                  | `{"schemaVersion":1,"identity":WorkerIdentity,"binding":ExportBinding,"code":"<closed>","failedAt":"<instant>","retryAt":null}`                                 | `{"schemaVersion":1,"disposition":"retry_scheduled                 | terminal                                                                                                                                                                                   | replay_retry                                                                                                            | replay_terminal                                   | cancellation_requested                                                      | authorization_revoked                                             | fence_lost","currentRevision":0,"code":"<closed or none>","retryAt":null}`                |
| `acknowledge_ticket_export_cancellation_v1`        | export control request below                                                                                                                                    | export control response below                                      |
| `reject_ticket_export_revocation_v1`               | export control request below                                                                                                                                    | export control response below                                      |

```json
BulkControlRequest = {
  "schemaVersion":1, "identity":WorkerIdentity, "binding":BulkBinding,
  "expectedRevision":1, "finalizedAt":"<instant>"
}
BulkControlResponse = {
  "schemaVersion":1, "disposition":"applied|replayed|fence_lost",
  "progress":BulkProgress-or-null, "controlRevision":0
}
ExportManifestResponse = {
  "schemaVersion":1,
  "disposition":"recorded|cancellation_requested|authorization_revoked|fence_lost|snapshot_stale",
  "currentRevision":0, "manifest":Manifest-or-null
}
ExportCommitResponse = {
  "schemaVersion":1,
  "disposition":"applied|replayed|cancellation_requested|authorization_revoked|fence_lost|snapshot_stale",
  "currentRevision":0, "manifest":Manifest-or-null
}
ExportControlRequest = {
  "schemaVersion":1, "identity":WorkerIdentity, "binding":ExportBinding,
  "expectedRevision":1, "transitionedAt":"<instant>"
}
ExportControlResponse = {
  "schemaVersion":1, "disposition":"applied|replayed|fence_lost",
  "currentRevision":0
}
```

## Required persistence invariants

The migration must provide tenant-owned bulk jobs, materialized targets,
claimed batches, per-target terminal results, and idempotency rows; and
tenant-owned export jobs, canonical query snapshots, attempt-manifest ledger,
artifact metadata, and idempotency rows. Every customer-owned row has a
non-null `tenant_id`; all cross-table keys lead with `tenant_id`; all tables
use enabled and forced RLS; queue indexes lead with tenant plus the exact
queue dimensions and eligibility fields.

Bulk claim, target apply, batch release/failure, cancellation/revocation,
progress derivation, audit, and outbox changes are each atomic. Target apply
must reauthorize the original human requester live, compare the exact target
version and fence, and write one immutable result. Retry and replay cannot
double-count progress.

Export claim, page reads, manifest ledger, success/failure, cancellation, and
revocation are fenced and idempotent. Page reads bind job/revision/fence,
query/catalog digests, projection version, cursor, page size, audience, comment
scope, and live requester authority. The revocation path returns no query or
source rows. A recorded manifest is immutable; success can reference only its
exact artifact/digest/row/byte tuple. Audit/outbox writes are transactionally
coupled, append-only, and contain no query text, cell values, cursor, object
key, credential, or customer identifier beyond the approved opaque IDs.
