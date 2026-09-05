# Authorization and permission model

Status: platform, tenant, customer, service-account, and worker authorization implemented  
Last updated: 2026-09-02

Periapsis authorization is deny-by-default and enforced in backend use cases. Hiding a
button, returning permissions to a browser, knowing a UUID, possessing a stale session, or
setting a tenant header never grants authority. PostgreSQL constraints and RLS provide an
independent containment boundary, but they do not replace the backend decision.

The [current permission catalog](permission-catalog.md) is the reproducible matrix of
all platform and tenant capability keys, tenant scopes, and admitted principal types.
It is not a role-assignment inventory or a runtime authority snapshot. The tables below
record how the authorization kernel was introduced; they are historical, not exhaustive.
The canonical current keys, scopes, and route requirements live in the Drizzle schema,
OpenAPI extensions, and backend policy mapping and are checked for drift.

## Phase 2A platform authority

Platform role bindings are separate from tenant memberships. The protected one-time
bootstrap assigns `platform_super_admin`. The initial Phase 2A projection contained these
permissions:

| Permission                      | Authorized operation                     |
| ------------------------------- | ---------------------------------------- |
| `platform.tenant.read`          | `GET /api/v1/platform/tenants`           |
| `platform.tenant.create`        | `POST /api/v1/platform/tenants`          |
| `platform.operator_team.read`   | Read global operator-team inventory      |
| `platform.operator_team.manage` | Create, update, and archive global teams |

Every protected route names its required permission and calls the central authorizer. An
unknown permission, absent binding, disabled user, expired/revoked session, or failed data
load is a denial. The UI may use the returned permission set to avoid offering impossible
actions, but the server always decides again.

Tenant creation is one transaction: the database rechecks the protected platform grant,
creates the tenant, adds the creator's active `tenant_admin` membership, and appends the
platform audit event. A direct application query cannot create a privileged tenant without
that database-visible actor and grant. Slug conflicts do not partially create membership
or audit state.

## Phase 2B.1 direct-human tenant authority

Tenant authority is distinct from `Session.permissions`, which remains the live platform
permission projection. An active tenant membership permits tenant selection but grants no
business or administrative action by itself. The legacy membership `role` value remains
temporary compatibility/display metadata and is not an authorization input.

The initial tenant administration catalog is:

| Permission                    | Purpose                                                | Allowed scope             |
| ----------------------------- | ------------------------------------------------------ | ------------------------- |
| `permission.read`             | Read the tenant permission catalog                     | `tenant`                  |
| `role.read`                   | Read tenant roles, policies, and direct grant metadata | `tenant`                  |
| `role.manage`                 | Create and change custom tenant roles                  | `tenant`                  |
| `role.grant`                  | Grant or revoke a tenant role                          | `tenant`                  |
| `user.read`                   | Read tenant-safe membership projections                | `tenant`                  |
| `membership.manage`           | Manage membership lifecycle                            | `tenant`                  |
| `group.read`                  | Read tenant security groups and provenance             | `tenant`                  |
| `group.manage`                | Create, update, archive, and bind roles to groups      | `tenant`                  |
| `group.membership.manage`     | Add or revoke direct tenant-group membership edges     | `tenant`                  |
| `operator_team.read`          | Read team assignment epochs and exact-epoch rosters    | `tenant`, `operator_team` |
| `operator_team.manage`        | Start or end a tenant assignment epoch                 | `tenant`                  |
| `operator_team.roster.manage` | Add or revoke exact-epoch roster entries               | `tenant`, `operator_team` |

These permissions are human-only. At this milestone the protected system `tenant_admin` role
had all twelve permission keys across fourteen exact policy/delegation tuples. Later domain
slices extend the same catalog and delegation rules. A custom tenant role cannot contain `platform`
scope, and no tenant grant creates platform authority.

Every tenant use case checks the authenticated live session, requires that the path tenant
equals the session's active tenant, resolves current authority from PostgreSQL, evaluates
the named permission and resource relationship, and performs the operation in the same
tenant context. The database mutation function repeats the authority and delegation check
after locking the tenant authorization revision. The browser's authority projection is
`no-store` advisory state, not a credential.

## Scope semantics

The complete scope vocabulary is `own`, `assigned`, `operator_team`, `tenant`, and
`platform`. Tenant roles may use only catalog-allowed non-platform scopes.

`own`, `assigned`, and `operator_team` are incomparable relationship scopes. They
require, respectively, an explicit owner/creator, direct assignee, or matching resource
team plus live tenant-scoped team assignment and membership. Missing relationship data
never matches. An explicit `tenant` grant covers all resources in the active tenant at
runtime. No tenant rule derives `platform` authority.

Delegation uses exact `(permission, scope)` tuples, not runtime coverage. For example,
holding or delegating `case.read@tenant` does not silently make
`case.read@assigned` delegable. A delegated role's complete policy and its grant lifetime
must fit within the actor's live ceiling; expiry is limited by the earliest authority
horizon used to grant it.

## Grant provenance and recovery

Direct role grants record tenant membership, role, source, grantor, reason, expiry, and
append-only revocation metadata. Phase 2B.2a group membership and role edges are independent
source-owned rows, so authoritative synchronization removes only the authority it owns.

Every initialized tenant retains at least one enabled human with an active membership and
an active, non-expiring, non-revoked direct grant to the protected system
`tenant_admin` role. A compatibility role label, group-derived grant, service account, or
expiring grant does not satisfy recovery. PostgreSQL serializes recovery-affecting
mutations and verifies the final transaction state with deferred constraints.

Tenant creation seeds all built-in roles and creates the creator's direct recovery grant
in the same transaction as tenant, membership, audit head, and audit events. Upgrade
backfill promotes only active legacy `tenant_admin` memberships into equivalent direct
grants. A tenant without one remains uninitialized and fail-closed until a separate
protected platform repair workflow explicitly designates an active member.

## Phase 2B.2 group and team authority

Phase 2B.2a introduces the tenant-owned `TenantSecurityGroup`; the earlier conceptual name
`PlatformGroup` is retired. A group membership binds a tenant membership and becomes
effective only while that membership and user are active. Every group membership or
group-role edge has non-null tenant ownership, tenant-consistent
foreign keys, forced RLS, its own authorization source, lifetime, and revocation history.
Nested tenant groups are not supported in this slice.

Authority path and source origin are independent dimensions. `direct` and
`group` explain how a role reaches a principal. A protected manual,
migration, or exact provider/mapping source identifies who owns an edge and may reconcile
it. Group authority retains the source of both the membership and role-grant edges; a
provider may not update or revoke manual or another provider's rows. Authoritative sync
removes only absent edges it owns, while additive sync does not remove absent authority.

Adding, restoring, extending, or revoking a group membership computes every live role the
group confers. The actor's live exact delegation ceiling and lifetime must cover the
complete policy of every affected role, not merely the permission to manage a group.
Changing or revoking a group-role binding performs the same exact consequence check for
every affected live membership path. The protected database mutation rechecks that
complete result while holding the tenant authorization serialization boundary.

Group-derived `tenant_admin` may authorize ordinary administration,
but it never satisfies recovery. The last recovery administrator remains a non-expiring
direct grant to an enabled human under the Phase 2B.1 rule.

Phase 2B.2b implements `OperatorTeam` as a global platform-owned identity that
grants no tenant authority by itself. The `operator_team` relationship additionally
require an active tenant-owned assignment epoch and a tenant roster entry tied to that
exact epoch and active tenant membership. Ending and restoring an assignment creates a new
epoch so an old roster cannot revive. Global team lifecycle uses platform audit; tenant
assignment and roster changes use tenant audit, and a cross-boundary command records
correlated events in both.

Both Phase 2B.2 authority paths are live: group-derived paths retain both edge sources, and
team-derived relationships retain the exact assignment epoch. Unknown, ended, expired,
revoked, cross-tenant, or source-retired paths deny.

## ADR-0008 service-principal authority

Human administrators use these exact tenant-scoped permissions:

| Permission                          | Purpose                                                  | Allowed scope |
| ----------------------------------- | -------------------------------------------------------- | ------------- |
| `service_account.read`              | Read accounts, role provenance, and redacted credentials | `tenant`      |
| `service_account.manage`            | Manage account lifecycle and machine-role grants         | `tenant`      |
| `service_account.credential.manage` | Issue, rotate, and revoke one-time API credentials       | `tenant`      |
| `alert.create`                      | Create the bounded ADR-0008 Alert projection             | `tenant`      |

The first three permissions are human-only. The protected `tenant_admin` role receives all
four with exact delegation ceilings. The protected machine-role template
`service_account` contains only `alert.create@tenant`, which is the sole catalog tuple in
this slice marked `service_account_allowed`. A machine-role grant can be added or revoked
only when the human actor holds both `service_account.manage@tenant` and
`role.grant@tenant`, and the complete role policy and effective lifetime fit the actor's
current delegation ceiling.

Bearer authority is recomputed for every command and is the intersection of live tenant,
account, source, role, role-policy, grant, credential, expiry, exact credential allowlist,
and optional CIDR state. No broader scope subsumes a credential tuple. A service account
has no User or tenant membership, cannot install a human database context, and cannot use
human-only administration permissions.

## Tenant context

Tenant memberships bind one user to one tenant. They enumerate and validate tenant
selection; effective roles are separate live grants. The selected tenant is stored in the
server-side session only after a current membership and tenant-status check, then installed
as transaction-local database context before tenant-owned queries.

Tenant-security-group, operator-team, service-account, customer portal, ticketing, DFIR,
SLA, notification, audit, export, tenant-settings, and platform-operations authority consume
the same live kernel. No business endpoint interprets a membership role label or infers
authorization from the switcher.

## Enforcement order

For a protected operation, the backend evaluates:

1. an unexpired, unrevoked session for an enabled user;
2. request-integrity controls for mutations;
3. the explicit platform permission or active tenant membership;
4. selected-tenant equality where the operation is tenant-scoped;
5. resource, workflow, scope, team/assignment, and visibility policy for the exact operation;
6. the mutation inside a transaction with transaction-local actor and tenant context;
7. database constraints, forced RLS, and auditable privileged procedures.

Failure at any step stops the operation. Authorization failures do not disclose another
tenant's resource existence. Permission changes and membership suspension take effect on
the next request because authority is not embedded in the cookie.

## Audit boundary

Bootstrap, authentication, session, protected-role, global operator-team lifecycle, and
platform-tenant lifecycle events use the platform audit stream because they can occur
without a tenant. Tenant-owned mutations, including security-group, team-assignment,
and team-roster changes, use the non-null tenant audit stream. An assignment start/end command
records correlated events in both streams. Audit metadata contains identifiers and safe
outcomes, never credentials, raw session material, password values, MFA secrets, or
recovery codes.
