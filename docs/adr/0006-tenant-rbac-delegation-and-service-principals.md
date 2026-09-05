# ADR-0006: Tenant RBAC uses live grants, exact delegation ceilings, and separate service principals

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Architecture, Security, Identity, and Data
- Applies from: Phase 2B and every later tenant-owned use case

## Context

Periapsis needs customizable tenant roles, identity-provider mappings, operator teams,
service accounts, and resource-sensitive scopes without weakening the platform/tenant
boundary. A role label stored on a membership is not sufficient: it cannot explain grant
provenance or expiry, represent multiple roles, distinguish direct and group authority,
enforce a delegation ceiling, or be safely reconciled by an authoritative identity
provider.

The same user may operate in several tenants, and permissions can change while a session
is active. Authority therefore cannot be embedded in a cookie or trusted from a browser.
PostgreSQL RLS contains tenant rows, but it cannot by itself decide whether an actor owns,
is assigned to, or serves the operator team for a resource.

Tenant administrators must be able to delegate useful authority without creating a role
or grant stronger or longer-lived than the authority they are explicitly allowed to
delegate. Concurrent changes must not remove every recovery administrator from a tenant.
Future API credentials must narrow service-account authority and must never turn into
synthetic human users or platform roles.

## Decision

### Separate platform and tenant authority

Platform permissions, roles, and grants remain physically separate from tenant RBAC.
Tenant roles never contain the `platform` scope and never imply a platform permission.
Cross-tenant work remains an explicit, protected, audited platform operation under
ADR-0002.

The initial implemented tenant permission catalog is:

- `permission.read`;
- `role.read`;
- `role.manage`;
- `role.grant`;
- `user.read`;
- `membership.manage`.

These administrative permissions initially allow only `tenant` scope and human
principals. Later vertical slices add their own stable permission keys and allowed scopes
instead of overloading these administration keys.

### Live authority from explicit grants

An active tenant membership is necessary for a human actor but does not itself grant a
permission. `tenant_memberships.role` is retained temporarily as compatibility and
display metadata; no Phase 2B authorization path reads it.

Effective human authority is resolved live from active, unexpired explicit grants. In the
first Phase 2B slice these are direct membership-role grants. Later slices add the union
of group-derived grants while retaining provenance, source ownership, expiry, and
revocation independently. An authoritative identity-provider source may revoke only rows
it owns; a manual grant survives unrelated synchronization.

Every authorization decision verifies the authenticated session, active path tenant,
live membership, current grants, permission, scope, and required resource relationship.
Unknown permissions, scopes, principal kinds, provenance values, or absent relationship
data deny.

### Runtime scopes are relationship-aware

Supported scope names are `own`, `assigned`, `operator_team`, `tenant`, and `platform`.
For tenant resources:

- `own` requires an explicit owner or creator relationship to the actor;
- `assigned` requires the actor to be the direct assignee;
- `operator_team` requires the resource team plus a live tenant assignment and a live
  tenant-scoped team membership;
- `tenant` covers resources in the active tenant;
- `platform` is never derived from tenant authority.

The three relationship scopes are incomparable. Holding `own` does not satisfy
`assigned`; team membership does not imply either. Missing resource relationships fail
closed. A `tenant` grant covers the tenant resource at runtime, but that coverage does not
implicitly widen delegation.

### Delegation is an exact, lifetime-bounded subset

A role stores exact `(permission, scope)` tuples. Its delegation ceiling stores a subset
of those same tuples, enforced by a composite database foreign key. Delegation checks use
exact tuple membership rather than the runtime coverage relation: holding
`case.read@tenant` does not silently make `case.read@own` delegable.

Creating or replacing a custom role policy, and granting that role, requires every target
tuple to fit within the actor's current live delegation ceiling. A grant cannot outlive
the earliest expiry of the authority needed to delegate the target role. The database
mutation function locks the tenant authorization state, re-resolves the actor's live
authority, rechecks the exact ceiling and lifetime, writes the mutation and tenant audit,
and increments a monotonic authorization revision in one transaction.

System roles are immutable through runtime administration. Each tenant receives exactly:
`tenant_admin`, `soc_manager`, `senior_analyst`, `analyst`, `customer_manager`,
`customer_user`, `read_only`, and `service_account`. Initially only the protected
`tenant_admin` role receives the implemented administration permissions and matching
delegation tuples. Other built-ins remain intentionally inert until their domain slices
ship.

### Preserve a human recovery administrator

Every initialized tenant must retain at least one enabled human user with an active
membership and an active, non-expiring, non-revoked direct grant to the protected system
`tenant_admin` role from a non-retired source. A group-derived, service-account,
expiring, or legacy membership-role value does not satisfy this invariant.

Mutation procedures serialize on one tenant authorization-state row. Immediate triggers
touch that row for changes that can affect recovery, and deferred constraint triggers
validate the final transaction state. This permits an atomic transfer while preventing
write skew when administrators concurrently remove one another. A serialization failure
is preferable to committing a tenant with no recovery path.

Tenant creation atomically creates the tenant, audit head, creator membership,
authorization state and source, built-in roles/policies, the creator's non-expiring direct
administrator grant, and tenant/platform audit events. Upgrade backfill creates grants
only for active legacy `tenant_admin` memberships. A tenant without a safe legacy
administrator remains explicitly uninitialized and all tenant-authority operations deny;
repair requires a separate protected, reason-bearing platform workflow rather than
promoting an arbitrary member.

### Database and API boundaries

Authorization tables are canonical Drizzle tables with non-null tenant ownership,
tenant-consistent composite foreign keys, tenant-leading indexes, enabled and forced RLS,
and no direct runtime-role access. Bounded `SECURITY DEFINER` functions have a fixed
search path, validate transaction-local actor and tenant context, recheck authority, and
couple mutations to append-only tenant audit. Runtime roles receive only explicit execute
privileges on the functions they need.

The HTTP API exposes a live tenant-authority projection for the active member plus
permission, role, user, and direct-grant administration endpoints. The projection is
`Cache-Control: no-store` and is an advisory UI input, never a bearer credential. Mutable
authorization resources use a version and strong ETag; mutation requires one exact
`If-Match`, returning RFC 9457 `428 precondition_required` when absent and
`412 precondition_failed` when stale. Non-secret creation and grant commands use an
idempotency key.

The browser keys authority queries by both session ID and active tenant ID. A late
response from a rotated session or previously selected tenant cannot update navigation or
administration state. The server independently authorizes every request.

### Groups, teams, and service principals are later coherent slices

After the direct-human kernel is proven:

1. tenant-owned security groups add provenance-preserving membership and role grants;
2. global operator-team identities gain explicit tenant assignments and tenant-scoped
   rosters, so a mapping in one tenant cannot confer team authority in another;
3. tenant-owned service accounts gain separate role grants and API credentials.

ADR-0007 fixes the group/team vocabulary, provenance dimensions, consequence checks,
assignment epochs, audit split, and Phase 2B.2a/2B.2b delivery boundary for the first two
slices.

A service account is not a `User` and does not hold a human tenant membership or
delegation ceiling. An API key stores only a keyed digest, is shown once, expires, rotates,
revokes, and may have normalized CIDR restrictions. Its live authority is the intersection
of service-account role authority, the credential's exact permission/scope allowlist, and
current tenant/account/key state. Changing the service-account role immediately narrows
existing credentials. Tenant administrative permissions remain human-only.

## Consequences

### Positive

- Role customization and identity reconciliation have explicit provenance and expiry.
- Permission changes take effect on the next request without rotating a cookie.
- Delegation cannot rely on an ambiguous scope hierarchy or outlive its authority.
- Database procedures close the check/write race and preserve a recovery path.
- Groups, operator teams, and API keys extend one kernel without conflating identities.
- Platform authority remains isolated from tenant mappings and roles.

### Costs and constraints

- Authority resolution and mutation require more joins and locking than a membership role
  label; tenant-leading indexes and the authorization revision support bounded caching
  where a later measured need justifies it.
- Compatibility metadata can temporarily disagree with effective roles and must be
  clearly labeled until it is removed by a later migration.
- Recovery validation touches global users as well as tenant rows, so user disablement
  must participate in deterministic tenant locking.
- Role policy editing needs optimistic-concurrency and conflict UX.
- Service credentials require a separate authentication and audit attribution path.

## Alternatives considered

### Treat `tenant_memberships.role` as authority

Rejected. It cannot represent multiple roles, provenance, exact scope, expiry, group
inheritance, or safe authoritative reconciliation.

### Model scopes as a single ordinal hierarchy

Rejected. `own`, `assigned`, and `operator_team` describe different resource
relationships and are not ordered. Using the runtime `tenant` coverage relation for
delegation would silently widen what an administrator can grant.

### Enforce delegation and recovery only in Go

Rejected. Authority can change between application check and write, and concurrent
transactions could remove the last administrators through write skew. PostgreSQL must
recheck and serialize the protected mutation.

### Represent service accounts as disabled users

Rejected. Synthetic humans obscure audit attribution, invite membership/platform-role
confusion, and make token-only lifecycle policy harder to enforce.

### Put all credential scopes and CIDRs in JSON

Rejected. Relational exact tuples and normalized network rows give enforceable foreign
keys, queryable policy, deterministic comparison, and safer migrations.

## Staged verification

Phase 2B.1 must prove pure scope and delegation matrices, safe legacy backfill, atomic
tenant creation, forced RLS/direct-ID isolation, runtime privilege denial, authority
revocation between application check and write, optimistic-concurrency conflict, and
concurrent last-admin preservation. Later group, team, and service-account slices add
their own provenance, cross-tenant, authority-intersection, expiry, CIDR, rotation, and
audit tests before any provider mapping or business API depends on them.
