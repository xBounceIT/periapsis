# ADR-0002: Shared-schema multi-tenancy with application policy and PostgreSQL RLS

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Architecture, Security, and Data
- Applies from: Phase 1 and every later tenant-owned feature

## Context

Periapsis must serve multiple customers for SOC/MSSP/CSIRT operation. An operator may be
authorized for several tenants, a customer user for one or a small set, an operator team
may serve several tenants, and a platform super-admin needs exceptional cross-tenant
capability. A tenant-data disclosure is a critical security failure across direct APIs,
search, joins, bulk actions, exports, object downloads, notifications, webhooks, audit,
and background work.

Application predicates alone are vulnerable to omission. Database isolation alone cannot
express the complete decision, which also involves permission scope, membership, token
scope, team assignment, workflow state, field visibility, and recipient/channel policy.
The product therefore needs defense in depth.

## Decision

Use **one PostgreSQL database and shared schema** for the initial product. Every
tenant-owned table has:

- `tenant_id UUID NOT NULL`;
- `UNIQUE (tenant_id, id)` on identified entities;
- composite `(tenant_id, referenced_id)` foreign keys for tenant-owned relationships;
- tenant-leading indexes for supported query paths;
- enabled and forced PostgreSQL Row-Level Security;
- policies keyed by transaction-local server-established tenant context.

Every tenant action is also authorized in the Go application. RLS is mandatory defense in
depth, not a substitute for membership, RBAC, team, workflow, token-scope, or visibility
checks.

Tenant API paths are explicit:

```text
/api/v1/tenants/{tenantId}/alerts
/api/v1/tenants/{tenantId}/cases
```

The path tenant is matched against server-side identity grants. A customer cannot select
or override tenant context with a header. Multi-tenant operators can switch only among
authorized assignments, and the UI must show the active tenant clearly.

## Tenant context lifecycle

For each database operation the API or worker:

1. authenticates the actor/job identity;
2. validates the requested tenant against membership, platform/team assignment, role,
   token scopes, and action policy;
3. begins a pgx transaction on a least-privileged runtime role;
4. sets tenant, actor, request/correlation, and purpose context using parameterized,
   transaction-local configuration (`SET LOCAL` semantics / `set_config(..., true)`);
5. executes generated/parameterized queries in that transaction;
6. commits or rolls back, automatically discarding local context.

No tenant query is allowed on a pooled connection before this transaction-local context is
installed. `SET SESSION`, mutable global variables, and client-supplied GUC statements are
forbidden because pooled connections could leak context. A missing, empty, malformed, or
unknown tenant setting makes RLS return no tenant rows and reject writes.

Conceptually, policies use the equivalent of:

```sql
USING (
  tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
)
WITH CHECK (
  tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
)
```

The canonical expression is owned by the Drizzle schema/migrations and tested on the
actual PostgreSQL version. The example above is explanatory, not an alternate schema.

## Application authorization layers

RLS only decides tenant row eligibility. Before a use case reaches persistence, backend
policy also verifies:

- authenticated session/service credential and assurance/step-up requirements;
- active TenantMembership or explicit platform access action;
- stable permission key and scope (`own`, `assigned`, `operator_team`, `tenant`, or
  `platform`);
- service-account/API-key tenant and permission scopes;
- operator-team tenant assignment and membership where the command requires it;
- aggregate workflow state and optimistic version;
- public/private comment, customer visibility, field visibility, and classification;
- destination/channel rules for exports, notifications, webhooks, and object access.

Unknown actions, scopes, states, object types, provider claims, and visibility values fail
closed.

## Platform data and exceptional access

Pure platform catalogs/configuration are stored separately from tenant-owned records and
use `/api/v1/platform/...` policies. Where a concept can be platform- or tenant-scoped,
such as authentication providers, persistence is split into platform and tenant tables so
tenant rows never depend on a nullable tenant ID. Tenant-specific roles, mappings,
contacts, workflows, SLA, templates, and notification settings always have non-null tenant
ownership.

`User` is a platform identity; `TenantMembership` and tenant profile data control its
tenant presence. This does not permit tenant endpoints to expose the global user catalog.

A platform super-admin does not receive a normal API connection with blanket
`BYPASSRLS`. Cross-tenant work is an explicit, reason-bearing, step-up-capable action that:

- selects one target tenant at a time;
- verifies the protected platform permission;
- makes the active tenant and impersonation/access mode visible;
- records an audit event for entry, action, and exit;
- installs the same target tenant RLS context as ordinary work.

Purpose-built cross-tenant platform reporting/audit, if introduced, uses a separate
read-only path, database role, field allowlist, query limits, and audited authorization. It
requires its own threat-model review and cannot be reached from normal tenant handlers.

## Database roles

| Role            | Intended access                                                                           | Prohibited in normal operation                                       |
| --------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| migration/owner | Apply reviewed migrations in a one-shot deployment job                                    | Interactive application traffic; embedded credentials in images      |
| API             | Tenant transactions, platform operations explicitly granted, insert audit/outbox          | `BYPASSRLS`; audit update/delete; schema changes                     |
| worker          | Claim authorized tenant jobs and mutate only job/domain tables needed by worker use cases | Unscoped scans; audit update/delete; schema changes                  |
| notifier        | Claim notification jobs, read published template/config projections, record attempts      | Broad Alert/Case/private-comment access; `BYPASSRLS`; schema changes |
| audit/read-only | Purpose-specific reviewed audit/report access                                             | Domain mutation, secret readback, unaudited general application use  |

Runtime roles are not table owners and do not have `BYPASSRLS`. Tenant-owned tables use
`FORCE ROW LEVEL SECURITY` so owner-like behavior cannot accidentally disable policies.

## Background work and integrations

Every tenant outbox/job row has `tenant_id NOT NULL`. A worker claims a row, validates its
purpose/service policy, then installs that tenant context before reading or changing
domain data. Batches do not mix tenant context in one transaction. Platform jobs use a
separate platform queue.

Search documents, materialized SLA values, exports, caches if later introduced,
notification jobs, webhook deliveries, and audit records retain tenant ownership. An
export artifact or pre-signed object URL is authorized like its source resource, not like
an unscoped blob.

S3 object keys are tenant-prefixed as operational defense, and object-storage credentials
are least-privileged, but database metadata plus a fresh application authorization check
is the access decision. A user cannot download an object merely by knowing its key.

## Referential-integrity rules

- Relationships between tenant-owned entities repeat `tenant_id` in both sides of the
  foreign key.
- Link tables, activity, audit, idempotency, custom-field values, and outbox records all
  carry the tenant ID even when it could be inferred.
- A tenant-owned row cannot change tenant. Moving customer data is a privileged export/
  import or lifecycle operation with provenance, not an update.
- Polymorphic references require an enforceable tenant-owned object registry or
  type-specific tables/constraints; an unchecked `(object_type, object_id)` pair is not
  accepted.
- Tenant uniqueness includes `tenant_id`, for example Alert/Case number, workflow key,
  custom-field key, provider subject, and idempotency key.

## Verification requirements

Phase 1 must provide automated tests using real PostgreSQL roles and policies that prove:

- Tenant A cannot select, insert, update, or delete Tenant B rows by direct query or join;
- missing/wrong transaction context returns no rows and rejects writes;
- RLS applies to table owners/runtime roles as intended and runtime roles lack
  `BYPASSRLS`;
- composite foreign keys reject cross-tenant links;
- pooled connections do not retain tenant context after commit/rollback/cancellation;
- API path/header/token mismatches fail before data access.

Later phases add cross-tenant tests for search, filters, bulk commands, claims, comments,
custom fields, exports, notification/email, webhooks, and evidence upload/download. The
matrix covers both customer and operator actors, direct IDs, include/expand, retries, and
background consumers.

## Consequences

### Positive

- Shared-schema operations and migrations are simpler than one database/schema per tenant.
- RLS catches omitted tenant predicates at the database boundary.
- Composite tenant foreign keys prevent a broad class of cross-tenant relationship bugs.
- Platform and multi-tenant operator workflows remain possible without copying data.
- One tenant-context mechanism applies to API, worker, notifier, tests, and administrative
  tooling.

### Costs and constraints

- Every transaction, query, migration, job, and integration must preserve tenant context;
  this requires disciplined APIs and extensive negative tests.
- RLS can obscure query behavior and requires careful EXPLAIN/performance testing with
  realistic roles.
- Shared infrastructure has a performance/noisy-neighbor blast radius, mitigated through
  quotas, fair queues, tenant-leading indexes, resource controls, and observability.
- Backup/restore of a single tenant is more complex and requires controlled export/import
  tooling rather than database-level restore alone.
- Pure platform data must be deliberately separated to avoid weakening non-null tenant
  ownership.

## Alternatives considered

### Application filtering without RLS

Rejected. One missed predicate in a direct query, join, or new channel could cause a
critical disclosure.

### Database per tenant

Deferred. It provides a stronger physical boundary but makes MSSP cross-tenant operations,
schema rollout, connection management, search/reporting, and small-tenant economics more
complex. It may become an enterprise isolation tier later.

### Schema per tenant

Rejected initially. It creates migration/catalog complexity without the operational
isolation of a separate database and makes dynamic SQL/search more hazardous.

### RLS without application authorization

Rejected. Tenant equality cannot decide roles, scopes, team assignment, workflow state,
field visibility, private comments, or recipient policy.

## Staged delivery and migration path

Phase 0 fixes this architecture. Phase 1 must introduce RLS, role separation, composite
tenant integrity, audit/outbox ownership, and negative tests before any meaningful tenant
data slice is considered complete. Every later phase extends the same controls to its new
tables and channels.

If a future regulated deployment requires database-per-tenant isolation, repositories and
tenant context remain the abstraction boundary. A new ADR must define placement,
provisioning, migrations, global operator workflows, encryption/backup keys, and a tested
data-migration plan. The shared-schema tier remains secure and supported rather than
becoming an undocumented fallback.
