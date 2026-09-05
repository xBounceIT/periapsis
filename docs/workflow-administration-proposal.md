# Workflow administration contract and persistence

Status: implemented; the filename is retained for stable documentation links

This document records the boundary used by the workflow-administration use cases. Schema,
migration, OpenAPI, generated artifacts, repository code, and UI are implemented and must
remain reproducible from their canonical sources.

## Publish model and concurrency

Editing is publish-on-save. There is no mutable draft persisted by the first
version of the administration surface. A successful design change appends one
immutable `ticket_workflow_versions` row and advances `current_version` by
exactly one. Metadata, default selection, archive, and restore change the
catalog resource but do not manufacture a workflow version.

Add `revision integer not null default 1` to `ticket_workflows`, constrained to
`1..2147483647`. This is the resource revision used by strong ETags and compare
and swap. It is deliberately independent from `current_version`. All writes
take both `If-Match` and the equivalent body `expectedRevision`; the handler
must reject a mismatch between them before the use case runs.

Make `ticket_workflow_versions` append-only for application roles. Reject
`UPDATE` and `DELETE`, including through privileged application functions. A
publish transaction must lock the catalog row, verify its revision and current
version, append version `current_version + 1`, then update both catalog counters.

Setting a default first takes a transaction-scoped tenant-and-kind lock, then
locks the target plus the exact current default in stable UUID order. It
re-resolves that the current default matches the plan, including the explicit
no-default case, compares both revisions, and updates both rows atomically. A
partial default swap is invalid. An active default cannot be archived.

## Idempotent command ledger

Add a tenant-owned `ticket_workflow_commands` table with:

- `id uuid primary key default uuidv7()`;
- `tenant_id uuid not null`;
- `actor_user_id uuid not null` and `actor_membership_id uuid not null`, with
  tenant-scoped identity foreign keys;
- closed `action` values `create`, `publish`, `update_metadata`, `set_default`,
  `archive`, and `restore`;
- `key_digest bytea not null` and `request_digest bytea not null`,
  both constrained to 32 bytes;
- `result_workflow_id uuid not null`, `result_revision integer not null`, and a
  bounded, schema-versioned `result_snapshot jsonb not null`;
- `created_at timestamptz not null default now()` and a bounded replay
  `expires_at` with an indexed cleanup path.

Uniqueness is `(tenant_id, actor_user_id, action, key_digest)`. Only digests are
stored; raw idempotency keys never enter persistence, audit, outbox, or logs. A
reused key with a different request digest returns conflict. The lookup and
insert are in the same mutation transaction so concurrent identical requests
return one result. An exact replay returns the immutable original result
snapshot and never rereads a later mutable catalog representation. The snapshot
is available only through the live-authorized definer ABI, is capped at 512 KiB,
uses an exact closed field set, and is rejected by the application if its action,
workflow ID, revision, lifecycle, timestamps, or definition drift.

The key digest and canonical request digest use distinct, versioned domain
prefixes. Canonical request JSON contains no maps or raw idempotency key and is
ordered exactly as the validated kernel definition, making the persisted v1
fingerprint reproducible across Go processes and deployments.

## Database ABI and security

Expose versioned, SECURITY DEFINER functions for command replay and atomic
writes:

- `app.lookup_ticket_workflow_admin_replay_v1`;
- `app.commit_ticket_workflow_admin_v1`.

Bounded catalog and publication reads run in read-only transactions after the
backend use case resolves `workflow.read`; the repository repeats that exact
live capability check inside the same transaction and PostgreSQL RLS separately
requires the active actor/tenant context. Runtime roles receive no direct table
write privilege.

Every function receives the tenant and authenticated actor identity explicitly,
sets a bounded statement timeout, checks the active tenant membership and exact
live capability, and fails closed on identity drift. Mutation functions repeat
the `workflow.manage` check inside their transaction; a proof produced by an
earlier read is not write authority. RLS remains enabled and forced on every
tenant table. Revoke direct DML from runtime roles.

Add tenant permissions `workflow.read` and `workflow.manage`. They are human
operator permissions only. Customer, service-account, and platform principals
are rejected by this tenant surface. `workflow.manage` is checked on every
mutation and must not be inferred from UI visibility.

Each mutation atomically appends a redacted audit record and an outbox event
carrying IDs, action, kind, version, revision, and trace context only. It must
not carry workflow descriptions, conditions, authentication material, or
idempotency keys. Ticket activity is not reused for catalog administration
because that table requires an Alert or Case resource.

## HTTP contract proposal

The canonical OpenAPI change should add these operations after the shared
contract window reopens:

| Method and path                                                            | Operation ID                   | Capability        |
| -------------------------------------------------------------------------- | ------------------------------ | ----------------- |
| `GET /api/v1/tenants/{tenantId}/workflows`                                 | `listTenantWorkflows`          | `workflow.read`   |
| `POST /api/v1/tenants/{tenantId}/workflows`                                | `createTenantWorkflow`         | `workflow.manage` |
| `GET /api/v1/tenants/{tenantId}/workflows/{workflowId}`                    | `getTenantWorkflow`            | `workflow.read`   |
| `PATCH /api/v1/tenants/{tenantId}/workflows/{workflowId}`                  | `updateTenantWorkflowMetadata` | `workflow.manage` |
| `GET /api/v1/tenants/{tenantId}/workflows/{workflowId}/versions`           | `listTenantWorkflowVersions`   | `workflow.read`   |
| `POST /api/v1/tenants/{tenantId}/workflows/{workflowId}/versions`          | `publishTenantWorkflowVersion` | `workflow.manage` |
| `GET /api/v1/tenants/{tenantId}/workflows/{workflowId}/versions/{version}` | `getTenantWorkflowVersion`     | `workflow.read`   |
| `POST /api/v1/tenants/{tenantId}/workflows/{workflowId}/simulate`          | `simulateTenantWorkflow`       | `workflow.read`   |
| `POST /api/v1/tenants/{tenantId}/workflows/{workflowId}/default`           | `setDefaultTenantWorkflow`     | `workflow.manage` |
| `POST /api/v1/tenants/{tenantId}/workflows/{workflowId}/archive`           | `archiveTenantWorkflow`        | `workflow.manage` |
| `POST /api/v1/tenants/{tenantId}/workflows/{workflowId}/restore`           | `restoreTenantWorkflow`        | `workflow.manage` |

List filters are closed `kind=alert|case`, `status=active|archived`, `default`,
bounded search, and opaque cursor. Version history is newest first with an
integer version cursor. Create and every mutation require a bounded
`Idempotency-Key`. Mutations require a strong catalog ETag based on workflow ID
and `revision`; workflow `version` is not an ETag substitute.

Alert and Case definitions use the existing closed state, transition,
condition, action, effect, visibility, permission, and requirement schemas.
Request arrays retain the kernel bounds: 2..64 states, 1..256 transitions, and
at most 64 items per role, permission, or custom-field requirement. Conditions
retain the documented depth, node, child, and value bounds.

Simulation accepts a published version (or the current version), a state,
hypothetical roles, permissions, present custom fields, comment presence, and
typed facts. It returns every outgoing transition in deterministic key order,
all individual gates, missing requirements, and the closed side-effect plan.
The response states explicitly that it is explanatory and is never an
authorization decision.

Use RFC 9457 responses consistently: invalid input `400`, denied live
capability `403`, missing tenant-owned resource `404`, idempotency/no-change or
lifecycle conflict `409`, stale ETag/revision `412`, and repository projection
or invariant drift `503`. Do not reveal whether a cross-tenant ID exists.

## UI handoff

Mount a tenant-admin workspace at `/tenant/workflows`, with separate
Alert and Case views, catalog list, current editor, immutable history, and
simulator. Read-only users may inspect and simulate; only `workflow.manage`
users see publish and lifecycle controls. Each edit attempt keeps one stable
idempotency key, sends the last ETag, and offers explicit reload/review after a
`409` or `412`. Backend authorization remains the boundary, including deep
links.

The editor should publish a complete validated definition and show a structural
diff before confirmation. The first release intentionally has no autosaved
server draft, arbitrary expression text, JavaScript/SQL, rollback mutation, or
in-place edit of history. Restoring an old design is a new publication with the
next version.
