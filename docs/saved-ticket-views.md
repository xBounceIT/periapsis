# Saved ticket views and dynamic table contract

This document fixes the first production boundary for private Alert and Case
table views. It complements the ticket-list contract: a saved view stores a
bounded query and layout, but never stores or grants ticket authority.

## Ownership and authorization

- Every view is tenant-owned and belongs to one exact active human tenant
  membership. Views are private in v1; sharing and tenant defaults are not
  implicit future-compatible fields.
- The route intent is operator-only. Customer and service-account principals
  are rejected even if a malformed grant graph claims an equivalent key.
- Reading or mutating an Alert view requires the same live `alert.read`
  capability and scope resolution used by the Alert list. Case views use
  `case.read`. Creating a personal layout does not introduce an administrative
  permission or widen the ticket scope.
- View lookup, replay lookup, mutation, and ticket execution all re-resolve the
  current membership and capability inside their transaction. UI visibility,
  a view identifier, an earlier access proof, or a stored filter is never an
  authorization boundary.

## Canonical state

A view contains:

- UUIDv7 ID, tenant ID, owner membership ID, and closed kind `alert|case`;
- a bounded UTF-8 name;
- active or archived lifecycle plus monotonic resource revision;
- a canonical v1 filter, sort, and ordered column specification;
- exact immutable definition pins for each custom-field or SLA filter, column,
  and sort: definition ID, tenant, ticket kind, stable key, version, and a
  non-zero SHA-256 semantics digest;
- created, updated, and optional archived timestamps.

Filters support bounded core sets, assignment relationships, the caller-relative
queues `all`, `assigned_to_me`, `my_operator_teams`, and `unassigned`, optional
customer visibility, bounded search, and at most eight scalar custom-field
equality filters. Collection and arbitrary JSON filters fail closed until a
separately indexed and versioned query vocabulary exists. The filters also
share an aggregate canonical-value budget, preventing individually valid text
values from expanding beyond the bounded persistence document.

Columns are ordered, unique, and capped at 64. They support core, custom-field,
and SLA sources; visible/hidden state; optional widths from 80 through 1200
pixels; and start/end pinning. At least one visible `ticket` identity column is
mandatory. A dynamic sort is accepted only when the same exact definition pin
is projected as a column. If one custom-field definition is referenced by both
a filter and a column, every occurrence must carry the same complete pin;
mixed historical IDs, versions, keys, or digests fail closed. Duplicate stable
keys within one dynamic source are rejected even when their IDs differ.

## Persistence boundary

Migrations 0136 through 0138 materialize the schema, versioned ABI, grants,
forced RLS, compatibility projection, readiness check, and supporting typed
indexes described below. There is no in-memory or direct-table fallback. API
and worker readiness consume the current sealed manifest and the saved-view/query dependency
probes; the historical v29 handoff is no longer the release root. Canonical digests use
PostgreSQL 18's built-in `pg_catalog.sha256(bytea)`, so runtime correctness does not depend
on an undeclared extension.

The production ticket-query successor binds exact operator-team assignment epochs, live
authority, query/catalog fingerprints, and dynamic definition pins into the same snapshot
and cursor. The API, PostgreSQL adapter, OpenAPI/generated client, and UI compose that
boundary; a remove/recreate or stale-definition ABA fails closed.

## Lossless persistence

The canonical Drizzle model defines `ticket_saved_views` and
`ticket_saved_view_commands`. Both have `tenant_id NOT NULL`, composite tenant
foreign keys, enabled and forced RLS, and a dedicated NOLOGIN owner. Runtime
roles receive no direct write privilege.

`ticket_saved_views` stores the canonical v1 specification as bounded `text`
with C collation, not `jsonb`. The exact bytes are part of the security
boundary: PostgreSQL JSONB key reordering would destroy the reproducible digest.
The row also stores a 32-byte `spec_digest`; the Go adapter restores the typed
kernel value, re-encodes it, requires byte-for-byte equality, recomputes the
digest, and compares both values before returning a record.

The canonical decoder rejects unknown or duplicate fields, extra JSON values,
noncanonical empty sets, whitespace drift, alternate decimal/time/network/URL/
email/UUID spellings, invalid dynamic pins, and collection reinterpretation.
It applies the operation-shaped set/filter/column bounds before allocating the
typed kernel slices. Database size checks remain defense in depth and do not
replace the Go decoder.

HTTP projections encode canonical numeric filter and dynamic-column values as
decimal strings. The pinned live definition remains the type authority when a
string is submitted again. This prevents generated JavaScript clients from
rounding valid PostgreSQL `numeric` values or 64-bit integers before save/update
and keeps the persisted canonical bytes lossless.

`ticket_saved_view_commands` stores only SHA-256 idempotency-key and request
digests. Uniqueness is scoped to tenant, actor user, owner membership, action,
and key digest. Result snapshots use a closed, bounded schema and are immutable.
An exact concurrent create replay may return the winning generated view ID;
replace/archive/restore replays remain bound to the exact view and expected
revision. Raw idempotency keys, search strings, filter values, and view names
must not enter logs, audit metadata, or outbox payloads.

## Database ABI

The application expects these versioned, bounded `SECURITY DEFINER` functions
rather than direct writes:

- `app.resolve_ticket_saved_view_spec_v1`;
- `app.list_ticket_saved_views_v1`;
- `app.get_ticket_saved_view_v1`;
- `app.lookup_ticket_saved_view_replay_v1`;
- `app.commit_ticket_saved_view_v1`.

Saved-view access itself is re-resolved through the existing live tenant
authority boundary inside each repository transaction; it does not have a
parallel saved-view-specific access function.

Access and list/get transactions are read-only repeatable-read. The commit ABI
locks the exact owner membership and current row, repeats live operator ticket
read authorization, validates the compare-and-swap revision, inserts immutable
replay evidence, and appends redacted audit and outbox records atomically.
Create, replace, and restore recheck every dynamic pin; archive intentionally
does not, so an owner can retire a stale view while preserving its forensic
record. Create collision handling is replay-first and never selects a winner
belonging to another actor or membership.

Dynamic definition resolution uses the current custom-field and SLA catalog
rows from the same transaction. Stable keys are convenience labels only. If a
definition is archived, hidden from list/filter, made non-sortable, advances
version, or changes digest, applying or mutating the stale view fails closed.
The owner may still archive the stale record through its identity-bound lifecycle command;
the editor must explicitly replace invalid pins rather than silently rebinding them.

## HTTP boundary

The canonical OpenAPI slice exposes:

| Method | Path                                                       | Purpose                                 |
| ------ | ---------------------------------------------------------- | --------------------------------------- |
| `GET`  | `/api/v1/tenants/{tenantId}/ticket-views?kind=alert\|case` | List the caller's private views         |
| `POST` | `/api/v1/tenants/{tenantId}/ticket-views`                  | Create a private view                   |
| `GET`  | `/api/v1/tenants/{tenantId}/ticket-views/{viewId}`         | Read one owned view                     |
| `PUT`  | `/api/v1/tenants/{tenantId}/ticket-views/{viewId}`         | Replace name and complete specification |
| `POST` | `/api/v1/tenants/{tenantId}/ticket-views/{viewId}/archive` | Archive with compare-and-swap           |
| `POST` | `/api/v1/tenants/{tenantId}/ticket-views/{viewId}/restore` | Restore with compare-and-swap           |

Create and mutations require a bounded `Idempotency-Key`; replace and lifecycle
also require an exact strong `If-Match` ETag and matching body revision. The
terminal supported revision is immutable and rejected before any repository
work, so a committed mutation can never be reported as an invalid projection.
The server returns RFC 9457 errors: malformed input `400`, denied live authority
`403`, missing/foreign/non-owned resource `404`, no-change or stale-definition
conflict `409`, stale ETag `412`, and persistence projection drift `503`.
Responses use `Cache-Control: private, no-store` and `X-Content-Type-Options:
nosniff`.

Ticket list requests may reference one owned `viewId`. The backend loads and
compiles that view in the same repeatable-read transaction as the page query,
rechecks the exact current dynamic definitions, and binds the effective query
fingerprint into the opaque cursor. A caller cannot combine a view ID with
conflicting inline filters or sort parameters. Every page still applies live
ticket scopes and RLS; stored assignment-relative queues are evaluated against
the current actor. Exact team-epoch and roster binding remains the release gate
identified above.

## UI behavior

Alert and Case tables provide a keyboard-accessible view selector, explicit
save/update/save-as controls, column visibility, resize, pinning, and URL state.
The unsaved current layout remains usable without persistence. Archived or
stale views are never selected silently. A `409`/`412` offers reload and review,
not blind overwrite. Bulk selection and export consume the effective backend
query fingerprint and never infer authority from visible client rows.

## Verification

The slice must prove:

- owner, membership, tenant, principal-kind, direct-ID, list, replay, and RLS
  isolation, including conflicting legacy role labels;
- exact create replay, idempotency payload drift, revision races, archive/
  restore races, and commit-time permission or membership revocation;
- custom-field and SLA visibility/filter/sort/version/digest drift;
- lossless canonical decode and digest comparison for every scalar type;
- cursor invalidation when view revision, definition semantics, actor-relative
  queue membership, or authorization scope changes;
- PostgreSQL 18 clean and exact-predecessor rolling migration, direct privilege
  denial, audit/outbox redaction, indexed list/execution plans, Go race tests,
  generated-contract drift, and accessible React interaction tests.
