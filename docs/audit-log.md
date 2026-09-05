# Security audit log

Status: tenant/platform reader, verification, export, and retention boundary implemented

## Boundaries

Periapsis keeps two physically independent append-only streams:

- every tenant stream has a non-null `tenant_id`, a per-tenant sequence, forced RLS, and a
  tenant chain head;
- the platform stream has no nullable tenant ownership and has its own global sequence and
  chain head.

An activity feed is domain-facing history. It is not an audit projection and cannot be used
as security evidence. Audit rows contain actor and impersonation attribution,
request/correlation IDs, network/client context, authentication method, outcome, reason,
redacted before/after documents, bounded metadata, and the previous/event hashes.

## Authorization and access evidence

Tenant reads and verification require the exact live human permission `audit.read` at
`tenant` scope. The active session tenant, resolved authority tenant, requested tenant, and
database transaction context must all agree. Customer portal and service-account principals
cannot read the security stream.

Platform reads and verification require the independent `platform.audit.read` permission.
A platform grant never implies tenant audit access, and a tenant grant never implies access
to the platform stream. Cross-tenant inspection enters one explicit tenant context at a time.

The application performs a deny-by-default permission check before persistence. The
database operation repeats the permission and active-membership check and writes an
`audit.accessed` or `audit.chain_verified` event in the same transaction as the successful
read/verification. Request and correlation IDs bind that access evidence to the response.
The client cannot supply the access-event identifier or permission key.

## Query model

Pages are ordered by the immutable positive sequence and use a forward-only
`afterSequence` cursor. The server fetches one sentinel row, returns at most 100 events, and
sets the next cursor to the last returned sequence. Filters are allowlisted and
parameterized:

- half-open occurrence interval (`from <= occurredAt < before`);
- actor type and exact identifiers when represented by that stream (tenant service-account
  identifiers are supported; the platform stream currently exposes service actors by type);
- action namespace prefix, exact resource type and resource identifier;
- request ID, correlation ID, and outcome;
- bounded text search over action, resource type, and redacted reason only.

No filter, sort expression, JSON path, regular expression, or SQL fragment comes from a
caller. A repository result that violates the requested tenant, filter, ordering, size, or
actor consistency is treated as an unavailable/corrupt projection rather than being
silently repaired.

## Operator interface

The authenticated shell exposes two deliberately separate readers:

- `/tenant/audit` is visible only from the live tenant-authority projection with
  `audit.read` at `tenant` scope and requires an explicit active tenant;
- `/platform/audit` is visible only from the current platform session capability
  `platform.audit.read` and never accepts a tenant-service-account filter.

Direct navigation remains fail-closed. The UI waits for live tenant authority before it
issues a request, clears a rejected session on `401`, invalidates stale tenant authority on
`403`, and stops rendering a response whose scope, cursor, event shape, hash link, redaction
contract, or `Cache-Control: no-store` protection is inconsistent. React development
StrictMode is also prevented from duplicating the initial self-audited read. Chain
verification is an explicit CSRF-protected action; it is never run speculatively.

## Redaction and response validation

Writers must redact credentials before insertion. The reader is a second fail-closed
boundary: it rejects malformed or oversized JSON, excessive nesting, and prohibited
credential-bearing keys at any nesting depth. This includes passwords, session/access/
refresh/ID tokens, CSRF material, TOTP secrets, recovery codes, SAML assertions, client
secrets, private keys, cookies, authorization headers, and API keys.
Sensitive-looking compound keys are rejected as a family, not only by exact spelling.
The narrow exceptions for non-secret references, versions, kinds, and configuration flags
have an exact value contract (UUIDv7, non-negative integer, stable kind, or boolean); a
plaintext value cannot be hidden behind a key such as `passwordConfigured`.

The API returns explicit allowlisted fields. It never returns credential tables, encrypted
secret material, raw authentication assertions, notification bodies, or private comments.
Legacy SQL `NULL` and JSON `null` values in the optional before/after snapshots are
projected as canonical empty objects; malformed non-null JSON remains a hard failure.
Returned byte slices and optional values are defensively copied so a caller cannot mutate
repository-owned projections.

## Chain verification

The sealing trigger serializes each stream, assigns the next sequence, binds
`previous_hash`, calculates `event_hash`, and advances the protected chain head. Runtime
application roles cannot update or delete events or write chain heads directly.

Verification recalculates every event hash, checks sequence/previous-hash continuity, and
compares the terminal event with the protected head. Its public result is bounded to event
count, last sequence, first invalid sequence (when present), head validity, overall validity,
and verification time. A contradictory repository result is rejected. Verification is
tamper evidence, not a replacement for protected backups or independently retained exports.

## Export and retention

Large exports are asynchronous jobs, not unbounded HTTP reads. A job pins the requester,
tenant/platform stream, normalized filter, permission epoch, projection version, and output
format. Workers re-authorize before materialization, write only redacted projections to a
tenant-scoped object key, record a checksum and expiry, and never return a raw storage URL
without a fresh download authorization. Export creation and download are audited.

Retention is policy-driven and legal-hold aware. It never exposes update/delete authority to
the API role. Any future pruning protocol must first close and externally preserve a signed
chain segment, advance a separately protected retention anchor, and prove that verification
distinguishes an authorized retained prefix from deletion/tampering.
