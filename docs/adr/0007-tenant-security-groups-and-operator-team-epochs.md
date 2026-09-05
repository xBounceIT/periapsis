# ADR-0007: Tenant security groups and operator-team assignment epochs

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Architecture, Security, Identity, Authorization, and Data
- Applies from: Phase 2B.2

## Context

ADR-0006 established a direct-human authorization kernel and reserved later slices for
group-derived authority and operator-team resource scopes. Those two concepts cross
different ownership boundaries and must not be represented by one ambiguous `PlatformGroup`
entity.

A tenant administrator needs a tenant-local security group whose membership can be managed
manually or reconciled by a future identity provider. An MSSP also needs a global technical
team that can serve several tenants without a roster or assignment in one tenant granting
access to another. In both cases, the route by which authority reaches a principal is
different from the system that created and owns the contributing row. Conflating those two
dimensions would make reconciliation unsafe and audit explanations incomplete.

Group membership is itself an authority-bearing mutation because one membership edge can
activate several roles. Checking only a generic group-management permission would bypass
the exact delegation ceiling from ADR-0006. Group-derived administration also cannot
replace the deliberately narrow direct-human recovery path.

## Decision

### Use `TenantSecurityGroup`, not `PlatformGroup`

The canonical domain name is `TenantSecurityGroup`. `PlatformGroup` is retired before a
physical group slice ships and is not retained as an API or database alias.

A tenant security group and every membership or role-binding edge attached to it are
tenant-owned. They carry `tenant_id NOT NULL`, use tenant-consistent composite foreign
keys, have tenant-leading indexes, and are protected by enabled and forced RLS. A group
membership binds a `TenantMembership`, not a bare platform `User`, so an edge cannot
manufacture tenant access or connect a user through the wrong tenant. The edge is
effective only while that tenant membership and user are active; it may remain as
revocable history while a membership is invited or suspended.

Phase 2B.2a has no nested tenant security groups. The only membership shape is a direct
`TenantMembership -> TenantSecurityGroup` edge; group-to-group edges, recursive expansion,
and transitive local membership are rejected. A later provider may resolve nested groups
in its external directory, but any accepted result is flattened into explicit tenant-local
membership edges and does not create a nested Periapsis group graph.

### Separate authority path from source origin

Authority path answers _how did this role reach this principal?_ The initial values are
`direct` and `group`. A group-derived authority explanation identifies the
group, its membership edge, its role-binding edge, and the effective lifetime of that
complete path.

Source origin answers _which workflow owns this stored edge and may reconcile it?_ Sources
include protected manual administration, migration/bootstrap, and, in later slices, a
specific tenant identity provider and mapping rule. `group` is never a
source origin, and `provider` is never an authority path. A manually added group member and
a provider-reconciled group member share the same authority path but have different source
owners.

Both the membership edge and the group-role binding retain their own authorization source,
grantor or reconciler attribution, reason, activation/expiry, and append-only revocation
metadata. Effective-authority projections retain both source contributions rather than
collapsing them into an unattributed role. If an implementation materializes the derived
projection, the source edges remain canonical.

### Authorize every consequence of a group mutation

Adding, restoring, or extending a group membership first computes every active role that
the group would confer for the proposed lifetime. The actor must have group/membership
management authority and must be allowed to delegate the complete exact
`(permission, scope)` policy of every resulting role. The membership cannot outlive the
earliest delegation horizon required by any consequence.

Creating, replacing, restoring, or extending a group-role binding applies the same rule to
the role and every live membership path it would affect. A command may not validate one
role or one member and leave stronger consequences unchecked. The protected database
mutation serializes on the tenant authorization state, recomputes the prospective result,
rechecks every consequence, records audit, and advances the authorization revision in one
transaction. Unknown, stale, cross-tenant, or partially explainable paths deny.

Revoking a live group-membership edge requires both membership management and exact
delegation coverage for every still-live group role and effective lifetime. Revoking a
group-role binding likewise requires role-grant authority and exact policy coverage. This
keeps who may add and remove high-impact authority symmetric and prevents a generic group
manager from stripping roles they are not allowed to administer. Concurrent updates use
optimistic versions plus the same tenant serialization boundary as direct grants.

### Preserve the direct-human recovery path

Group-derived authority may include the protected `tenant_admin` role for ordinary runtime
administration only when the complete delegation check succeeds. It never satisfies the
recovery-administrator invariant. Recovery continues to require an enabled human with an
active tenant membership and an active, non-expiring, non-revoked **direct** grant to the
protected system role from a non-retired source.

Deleting a group, revoking a membership, changing a group-role binding, retiring its
source, or losing every group-derived administrator therefore cannot remove the last
recovery path because none of those paths counted as recovery in the first place.

### Reconciliation is source-owned and prospective

Each mutable authorization edge has exactly one source owner. Only that source's protected
workflow may update, expire, or revoke it; no provider may adopt or delete a manual,
migration, or other provider's edge. A source retirement makes its active contributions
ineffective without rewriting another source's history.

Authoritative reconciliation computes the desired set for one tenant, provider, mapping
configuration version, and source epoch, then applies the difference only to edges owned
by that source. Additive reconciliation may add or refresh owned edges but does not remove
an absent edge. Stable source-qualified natural keys and idempotent commands make retries
converge without duplicate authority.

Before applying a reconciliation plan, the service evaluates the full prospective
membership and role consequence set under the mapping's configured delegation boundary.
The dry-run and commit paths must use the same planner. Commit writes the source-owned
changes, safe redacted audit detail, and any required outbox event atomically. Provider
claims are input to that planner, never authority by themselves.

### Model operator teams as global identities with tenant epochs and rosters

Phase 2B.2b introduces `OperatorTeam` as a platform-owned global identity and technical
work-queue label. It is not a tenant security group, tenant role, or platform role, and its
existence or global membership grants no tenant access.

Serving a tenant requires an explicit tenant-owned assignment epoch. Ending and later
restoring an assignment creates a new epoch rather than reactivating an old row. Each epoch
has a tenant-scoped roster whose entries bind active tenant memberships and retain their
own source provenance and lifetime. A global directory/team roster may be an input to
reconciliation, but it cannot directly authorize a tenant resource or silently repopulate
a new epoch from stale entries.

The database treats an epoch's identifier, tenant, team, assigner, reason, and assignment
timestamp as immutable provenance. Its end timestamp, ender, and reason may change only
together, once, from the wholly open state to the wholly closed state; an ended epoch
cannot be reopened or rewritten. Representation `version` and `updated_at` remain mutable
for lifecycle and nested-summary invalidation, and exact no-op updates remain valid.

One membership may have at most 200 potentially live exact `(team, epoch)` relationships.
Duplicate source provenance for the same epoch counts once. The database enforces the cap
atomically for inserts, expiry refreshes, unrevocation, and relationship reassignment while
holding the tenant authorization state. Reversible tenant, user, and membership status
gates are intentionally excluded from the count, so a suspended or inactive principal
cannot accumulate dormant edges that become an oversized live projection on reactivation.
Roster `tenant_id` is immutable. Ending an assignment evaluates every live roster
consequence with a set-based aggregate bounded by the permission catalog, not by roster
cardinality.

The `operator_team` scope matches only when all of the following are live and
tenant-consistent:

- the resource identifies the global operator team;
- that team has an active assignment epoch for the resource tenant;
- the actor's active tenant membership has an active roster entry in that exact epoch;
- the actor separately holds the required permission at `operator_team` scope; and
- workflow, assignment, visibility, and credential restrictions also pass.

Global team lifecycle changes append platform audit. Tenant assignment-epoch and roster
changes append that tenant's audit. A command that crosses both boundaries appends both
events with the same command/correlation identity and commits them with the state change;
fan-out work records one tenant event per affected tenant through an auditable durable
workflow. Neither stream substitutes for the other.

Operator-team lifecycle writers use the canonical lock order: tenant authorization states
in tenant order, global team, exact assignment, then roster rows. Strong HTTP ETags remain
`"vN"`, but the stored versions are representation-bound: assignment start/end advances
the team version because `activeAssignmentCount` changes, while team display-name or
archive-state changes advance every assignment version whose nested team summary changes.
The hardening migration invalidates all pre-existing team and assignment ETags once. A
table trigger also covers crossing old function bodies and future protected writers; a
team-first crossing writer fails retryably rather than waiting into a lock cycle.

Expired platform and tenant authorization idempotency commands are pruned only by the
worker through one security-definer function. Each command class has its own bounded
`FOR UPDATE SKIP LOCKED` batch, so neither class can starve the other and unexpired replay
state is retained.

### Deliver the concepts as two closed vertical slices

Phase 2B.2a is the implemented tenant-security-group slice. It includes canonical
persistence, source-owned membership and role grants, complete consequence checks,
live authority/provenance projection, protected mutations, tenant audit, API/UI, and
isolation/concurrency tests. Group-derived authority is enabled only through those guarded
paths and never satisfies the direct recovery-administrator invariant.

Phase 2B.2b is implemented with global operator-team identities, immutable tenant
assignment epochs, exact-epoch rosters, dual audit, and runtime `operator_team`
relationship evaluation. Provider mapping and reconciliation now consume the implemented
source-owned commands for the current assignment epoch. Identity providers never write
authorization tables directly.

## Consequences

### Positive

- Tenant security groups cannot be mistaken for platform-wide authority or work queues.
- Authorization explanations preserve both the structural path and every source owner.
- Group membership cannot bypass exact delegation by activating several unchecked roles.
- Provider reconciliation cannot delete manual or another provider's authority.
- Assignment epochs prevent a retired tenant/team relationship from reviving stale rosters.
- Cross-boundary team operations leave both platform and tenant audit evidence.

### Costs and constraints

- Effective authority needs path-aware joins and may return several explanations for the
  same permission tuple.
- Group mutations must evaluate a prospective multi-role result and serialize with other
  authorization changes.
- Operator-team administration needs separate global and tenant policies plus correlated
  audit writes.
- Nested local groups are unavailable in Phase 2B.2a; external nesting must be resolved and
  flattened by a later provider adapter.

## Alternatives considered

### Keep the name `PlatformGroup`

Rejected. The entity is tenant-owned, and the name suggests a platform-wide trust boundary
that it does not have.

### Encode `group` as the grant source

Rejected. It loses the manual/provider owner needed for safe reconciliation and cannot
explain which membership and binding edges produced authority.

### Check only `membership.manage` when adding a group member

Rejected. One membership can activate several roles and would become an indirect path
around the exact delegation ceiling.

### Let a group-derived administrator satisfy recovery

Rejected. Group membership, bindings, and provider sources have broader reconciliation and
expiry failure modes than the deliberately direct, non-expiring human recovery grant.

### Use one global operator-team roster for every tenant

Rejected. Membership for one customer would become transitive tenant access, and a tenant
reassignment could revive stale authority.

### Represent assignment as a reusable current-state row

Rejected. Reusing the row makes old roster entries ambiguous after retirement and
reactivation. Immutable epochs make the authorization interval and audit history explicit.

## Staged verification

Phase 2B.2a must prove forced-RLS and composite-FK isolation, direct-only group topology,
source-owner reconciliation, additive versus authoritative behavior, multi-role
consequence and expiry checks, immediate revocation, complete provenance projection,
idempotent retry, concurrent group/binding changes, and exclusion from recovery.

Phase 2B.2b must additionally prove that global team identity alone grants nothing,
tenant-assignment and exact-epoch roster checks, no stale-roster revival, cross-tenant
direct-ID denial, atomic/correlated dual audit, team-scope relationship evaluation, and
concurrent assignment/roster revocation before an Alert or Case claim depends on it. It
also proves the 200/201 potential-relationship boundary (including dormant refresh),
assignment end above 500 provenance rows, bounded command retention, representation-bound
team/assignment versions, raw-writer rejection for epoch identity moves and end-history
rewrites without version or exact-relationship drift, and deterministic end-versus-add,
revoke-versus-policy, and archive-versus-start serialization.
