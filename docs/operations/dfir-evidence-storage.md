# DFIR evidence storage and malware scanning

Evidence and attachment bytes live only in S3-compatible object storage. PostgreSQL is
the authority for the tenant, opaque object key, exact expected size, SHA-256 digest,
scan state, retention/legal-hold state, attachment/evidence link, and append-only custody
history. An object key, object metadata, or presigned URL is never an authorization
capability by itself.

## Upload boundary

The initial ceremony supports one `PutObject` of exactly the browser-reported file size,
with a hard upper bound of `5_000_000_000` bytes. Amazon documents single PUT uploads up
to 5 GB and multipart uploads for larger objects; Periapsis deliberately uses the
conservative decimal bound and requires a separate future multipart protocol for larger
files ([Amazon S3 upload guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html)).

Before issuing a grant, the API authorizes the target Alert or Case, creates the pending
storage/attachment record atomically, and persists the exact size. The presigned request
binds `If-None-Match: *`, `Content-Length`,
`X-Amz-Meta-Periapsis-Expected-Size`, and
`X-Amz-Meta-Periapsis-Declared-Mime`; the precondition makes the opaque key create-only,
so a replay or concurrent second PUT fails at the object-store precondition/conflict
boundary instead of replacing bytes already queued for verification. Expected-size metadata is
defense in depth; persisted database size and actual object length remain authoritative.
The signed declared-MIME metadata is the trusted client declaration used for policy comparison.
`Content-Type` is signed as well, and the worker requires the stored value to equal both the signed
metadata and the declaration persisted in the scan job. On open/scan, the worker also compares the
object store's actual content length with the persisted database value before reading any bytes. A
mismatch is fail-closed, audited without the key or URL, and sent through bounded cleanup.

The browser-facing object-store endpoint may differ from the internal endpoint used by
API and worker. Both are compiled once from deployment configuration. Internal calls use
the reviewed resolver/dial/TLS policy with ambient proxy discovery and redirects disabled.
Production credentials are accepted only from `PERIAPSIS_S3_ACCESS_KEY_FILE` and
`PERIAPSIS_S3_SECRET_KEY_FILE`; a private CA, when required, is mounted through
`PERIAPSIS_S3_CA_BUNDLE_FILE`.

Configure bucket CORS for the one canonical web origin, never `*` and never credentialed
cross-origin requests. Permit only `GET`, `HEAD`, and `PUT`; allow `Content-Length`,
`Content-Type`, `Cache-Control`, `Content-Disposition`, `If-None-Match`, and
`X-Amz-Meta-Periapsis-Declared-Mime` and `X-Amz-Meta-Periapsis-Expected-Size`; expose only
`ETag`. The browser must not synthesize
the forbidden `Content-Length` header: its fetch implementation derives that header from
the exact `File` body, while the signature still binds the resulting wire value.

## Scan, hash, and custody

Every uploaded object remains unavailable for download until a bounded worker operation
has verified exact size, streamed it through clamd, calculated SHA-256, and finalized the
database transition. A clean verdict never overrides a size/hash/state mismatch. An
infected, encrypted, scanner-error, stale-signature, timeout, or truncated stream remains
quarantined. Logs and telemetry contain only safe state/reason codes, never object keys,
filenames, signatures, presigned URLs, customer content, or raw clamd responses.

Upload prepare emits the dedicated `dfir.storage.scan.requested` outbox job in the same
transaction as storage and attachment creation. The worker claims at most sixteen jobs with
`SKIP LOCKED`; each receives an independent UUIDv7 lease token, and all claimed jobs execute
concurrently so every operation retains its configured timeout plus a five-second fencing margin.
Missing bytes before the signed upload expiry reschedule without consuming an attempt. After
expiry the job closes and the orphan cleanup path remains authoritative. Crashes resume from
`uploaded`, `verifying`, `quarantined`, `scanning`, or `scan_failed` without bypassing the
database compare-and-swap fence.

Evidence custody is bounded at 1,000 events. If a scan would append event 1,001,
the worker records the exact leased job as a dead letter with the safe category
`evidence_custody_limit`. It leaves the custody chain, evidence, attachment and object
state unchanged; a clean scanner verdict does not make the object downloadable. The
queue item is not retried automatically. Preserve the object and failure record for
operator investigation; never reset revisions, remove custody events or mark the
object available manually to bypass this limit.

The shared DFIR kernel also defines a pure declared-versus-detected file-type decision.
The worker must apply it before any future `Scanning` to `Available` transition; the
kernel does not make an object available by itself. The input includes between 1 and
8,192 bytes sampled from the same stream that is hashed and scanned. MIME type/subtype
tokens are compared case-insensitively after parsing, while parameters are canonicalized
but do not disguise a differing base type. Recognized magic bytes override a generic or
misleading MIME observation, and embedded conflicting signatures fail closed as a
suspicious polyglot.

| Declared/detected observation                                           | Decision                                       | Safe reason code                                |
| ----------------------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------- |
| Same recognized passive type                                            | Allow scan pipeline to continue                | `consistent_passive`                            |
| Same `application/octet-stream`                                         | Allow generic binary scan pipeline to continue | `consistent_generic_binary`                     |
| HTML, XHTML, SVG, XML, or any `+xml` type                               | Reject and keep unavailable                    | `active_content`                                |
| Known executable or script type                                         | Reject and keep unavailable                    | `executable` / `script`                         |
| Two different recognized base types                                     | Reject as suspicious mismatch/polyglot         | `mime_mismatch`                                 |
| Empty, malformed, oversized, control-bearing, wildcard, or unknown type | Reject                                         | `invalid_mime` / `unknown_mime`                 |
| Empty/oversized prefix or malformed encoded text                        | Reject                                         | `invalid_content_prefix` / `suspicious_content` |
| PE/ELF/shebang or HTML/SVG/XML bytes hidden by a passive MIME           | Reject and keep unavailable                    | `executable` / `script` / `active_content`      |
| MIME contradicts recognized magic, or conflicting magic is embedded     | Reject as suspicious mismatch/polyglot         | `content_mismatch` / `suspicious_polyglot`      |

An allow decision remains subordinate to exact-size/hash checks, a clean malware scan,
and the database state machine. Audit and telemetry should record only verdict, class,
and reason; do not log either MIME observation, a filename, an object key, or content.

ClamAV runs from the pinned Debian base image as its documented unprivileged UID. Its
signature directory is a dedicated writable volume; config and root filesystem remain
read-only. Readiness requires both a successful clamd check and a `daily.cvd`/`daily.cld`
no older than 26 hours, while clamd also rejects databases older than two days. FreshClam
checks twelve times daily. Alert if an update fails or database age approaches the
readiness threshold. Allocate at least the requests/limits in the Kubernetes manifests;
five-billion-byte scans also require adequate temporary storage and operational
concurrency limits.

- Compose isolates MinIO and unencrypted clamd TCP on the internal storage network;
  ClamAV alone receives a separate outbound update network.
- Kubernetes colocates an unprivileged ClamAV sidecar with API and worker. The application
  uses a shared Unix socket, so clamd TCP never crosses a pod boundary.
- Swarm requires an operator-managed TLS clamd gateway and an explicit CA-bundle Secret.
  Never expose native unencrypted clamd TCP on an overlay or public network.

## Orphan cleanup and retention

Cleanup is two-phase and fenced. A worker may claim a pending object only after the
presign/session expiry is certainly past, using `SKIP LOCKED`, a bounded lease, and a new
fence token. Only that worker receives the real object key. It performs an idempotent
object-store delete and then finalizes the matching database fence idempotently, marking
storage and attachment deleted while appending audit/outbox/custody evidence atomically.
Failures remain retryable with bounded backoff; no metadata is removed before confirmed
object deletion, and a stale lease cannot finalize a newer claim. Because the bucket is
versioned, cleanup lists the exact validated tenant/object key, deletes every object version
and delete marker with an explicit `VersionId`, and repeats the bounded listing. Database
finalization is forbidden while any matching version or marker remains. The storage identity
therefore needs `s3:ListBucketVersions` and `s3:DeleteObjectVersion` only for the canonical
UUIDv7 tenant/object key shape in addition to its upload/read permissions.

The production defaults are scan batch `4`, operation timeout `6m`, lease `10m`, upload poll
`5s`, and cleanup batch `16`, delete timeout `30s`, lease `2m`. Both worker paths expose a
separate readiness gauge and fixed-label counters. Readiness verifies PostgreSQL, S3 object
reads, S3 version listing, and clamd; a denied version-list permission keeps the worker unready.

Bucket lifecycle rules must not race the database workflow. Keep versioning enabled and
align version expiry, legal hold, retention, inventory, replication, backup, and restore
with PostgreSQL recovery points. Test cross-tenant denial, oversized upload rejection,
expired grant cleanup, stale-fence rejection, scanner outage, stale signatures, object
length mismatch, hash mismatch, and object-store delete retries before production rollout.

## DFIR mutation receipts and retry retention

Receipt retention is separate from evidence retention, legal hold, object deletion, and
the short-lived upload grant. Case and Alert DFIR commands currently create receipts with
a **24-hour expiry**. The canonical database constraints permit a receipt lifetime from
24 hours through 7 days; that range is a schema safeguard, not a promise that the current
API grants seven days of replay. Expiry is measured from the original command, not from
the most recent retry. Expired receipts become ineligible for replay immediately, even
if asynchronous cleanup has not yet removed their payloads.

Within the receipt lifetime, an exact authorized retry returns the original immutable
mutation result, not the resource's later live revision. The binding includes tenant,
actor user, operation, key digest, root, resource identifiers, result revision, and
canonical request digest. A changed request or membership epoch cannot inherit the old
receipt. Every retry still checks current authorization, including every current linked
root for shared IOC/asset writes; a historical receipt never preserves revoked authority
or a stale related-ticket projection.

Receipt cleanup does **not** release idempotency keys or caller-owned identifiers. The
`dfir_mutation_replay_keys` registry retains the tenant/user/operation/key digest, and
`dfir_mutation_resource_ids` retains each tenant/resource-kind/identifier tombstone.
These registries have no expiry cleanup and are immutable. Reusing an expired key fails
closed both before and after its receipt is pruned; a new key also cannot reuse an old
caller-owned create identifier. Removing and recreating a membership does not reset the
user's consumed keys. Clients should reconcile an uncertain outcome through authorized
reads instead of deleting tombstones or blindly submitting another create command.

The worker's maintenance loop calls `app.prune_expired_dfir_mutation_commands_v1` with a
bounded batch of 1–1,000 candidates per receipt family. It uses `SKIP LOCKED`, removes
result snapshots before their command rows, and matches legacy Alert mirrors and Case
task receipts by their exact coordinates. Cleanup does not delete the resource, its
key/identifier tombstones, audit events, activity, or outbox history. It neither deletes
S3 objects nor overrides their retention or legal hold. Runtime API roles cannot update
receipts or perform this cleanup.

Upload-prepare replay has an additional live-state requirement. Its immutable receipt
contains a redacted storage/attachment projection, not an object key, bucket, presigned
URL, or signed headers. The API may issue another bounded grant only for the exact
original storage/attachment pair while both remain `pending_upload` at revision 1 and
the original upload expiry is still in the future. Once processing changes that state
or revision, or the upload expires, the retry fails closed without minting a new grant,
even if the 24-hour receipt remains retained. A retry does not extend the original upload
expiry, and the signed create-only PUT precondition still prevents overwriting bytes
that already reached S3 before the worker observed them.

Implementation and focused regression references:

- [Canonical receipt and tombstone models](../../packages/db/src/schema/dfir.ts):
  `dfirMutationReplayKeys`, `dfirMutationResourceIds`, `dfirMutationCommands`,
  `alertDfirResourceCommands`, and `dfirTicketCommandRetentions`.
- [Database receipt policy](../../packages/db/migrations/0228_tenant_federation_administration.sql):
  `guard_dfir_mutation_receipt_v1`, `reserve_dfir_mutation_command_v1`, and
  `prune_expired_dfir_mutation_commands_v1`;
  [worker maintenance wiring](../../services/worker/internal/postgres/auth_cleanup.go).
- [Live upload replay checks](../../services/api/internal/postgres/dfir_repository_storage.go):
  `validDFIRPreparedUploadReplay`, shared by the Case and Alert repositories;
  [typed receipt regression tests](../../services/api/internal/postgres/dfir_repository_mutation_receipts_test.go),
  including `TestPreparedUploadReceiptIsRedactedAndReplayRequiresLivePendingPair`.
- [PostgreSQL retention regressions](../../packages/db/tests/security/dfir-mutation-retention-runtime.ts):
  expiry bounds, expired replay before cleanup, role isolation, bounded concurrent
  cleanup, preserved history/tombstones, and caller-owned identifier reuse denial.

## Deployment verification

Before enabling traffic:

1. Run the repository deployment validator and render the selected Compose, Swarm, or
   Kustomize model.
2. Verify the public object-store CORS response from the canonical web origin and confirm
   the returned upload grant signs `content-length` plus the expected-size metadata.
3. Upload a harmless test fixture, confirm the stored length equals the database expected
   size, and verify scan/hash/custody completion without inspecting customer content.
4. Confirm an oversized body, modified signed header, stale ClamAV database, unavailable
   scanner, and cross-tenant object ID all fail closed.
5. Exercise orphan deletion after expiry and prove a stale fence cannot finalize it.

Treat any missing database expected-size authority, unfenced cleanup ABI, object-store
CORS drift, stale signatures, or readiness bypass as a rollout blocker.
