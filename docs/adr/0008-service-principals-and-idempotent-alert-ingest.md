# ADR-0008: Service principals and idempotent Alert ingest

- Status: Accepted
- Date: 2026-08-24
- Owners: Security, Identity, Authorization, Alerts, API, Database

## Context

Periapsis needs tenant-owned machine identities before an external collector can create a
real business resource. Issuing an API secret without a usable, independently enforced
business permission would create a credential that can only exercise administrative or
placeholder behavior. Treating the machine identity as a disabled human would also blur
tenant membership, MFA, delegation, and audit attribution.

The first service-principal slice therefore has to close two boundaries together:

1. service-account administration and one-time API credentials; and
2. an idempotent `alert.create` command whose database mutation, activity, audit, and
   outbox records are committed atomically.

The existing Phase 2B authorization ABI is consumed by deployed application versions.
The audit hash chain also hashes a stable row payload, so adding a nullable actor column
must not rewrite the effective payload of historical events.

## Decision

### Principal and administration model

A tenant service account is a first-class machine principal. It is not a `User`, has no
human tenant membership, cannot open a browser session, cannot satisfy MFA, and has no
delegation ceiling. It has tenant-leading identifiers and foreign keys, an immutable
tenant, mutable display metadata under optimistic concurrency, and a permanent archive
lifecycle. Archiving immediately removes all authority and never revives an existing
credential.

Tenant roles carry an enforced principal kind. All existing roles are human roles except
the built-in `service_account` role. Human direct/group resolvers and grant functions
exclude machine-only roles; service-account resolvers and grant functions exclude human-
only roles. The rolling migration changes the resolvers before adding any permission to
the machine role, so a historical human grant naming that previously inert role cannot
gain authority during upgrade. Such inert historical edges remain visible and revocable
but cannot become live authority.

Human administrators use three human-only tenant permissions at `tenant` scope:

- `service_account.read` for account, grant, and redacted credential inventory;
- `service_account.manage` for account lifecycle and service-account role grants; and
- `service_account.credential.manage` for issue, rotate, and revoke operations.

The system `service_account` role remains a role template for machine principals and
initially contains only `alert.create@tenant`, with no delegation ceiling. `alert.create`
is the only catalog entry in this slice with `service_account_allowed = true`. The
protected human `tenant_admin` role receives all three service-account administration
permissions plus `alert.create`, with matching exact delegation ceilings. Other human
business-role policy is deferred until its Alert workflow slice is implemented. Tenant-
administration permissions remain human-only and database constraints/functions reject
attempts to grant them to a service account.

Service-account role grants preserve source, grantor, reason, expiry, revocation, and
version. Creating or revoking one requires both `service_account.manage@tenant` and
`role.grant@tenant`. Both operations require the still-live grant's complete exact role
policy and effective lifetime to fit within the human actor's current delegation ceiling;
the database repeats the consequence and horizon check while holding the authorization
lock. This preserves the add/remove symmetry used for human groups and prevents a generic
account manager from stripping a machine role they cannot administer. The effective
service-account role authority is recomputed from current tenant, account, source, role,
role-policy, grant-expiry, and revocation state on every credential request. A role or
policy change therefore narrows an existing credential immediately.

### Credential representation and authority

Each credential has an internal UUIDv7 entity identifier and a separate globally unique,
canonical random 128-bit locator. The bearer token has a canonical textual envelope that
contains the format version, HMAC key version, random locator, and 32 random secret bytes;
the time-ordered entity identifier is never a lookup credential. PostgreSQL stores the
locator, key version, and only a keyed HMAC-SHA-256 digest. Go authenticates the format
version, key version, locator, and secret together when calculating the digest. The
database authentication function also requires the envelope key version to equal the
credential row's version.

Go derives the HMAC key with HKDF and a domain-separated context from a file-mounted,
versioned credential keyring; neither source nor derived keys are stored in PostgreSQL.
The keyring retains verification keys for every live credential and declares one active
issuance version. Removing an old version is allowed only after the corresponding
credentials are expired or revoked.

Go computes the presented digest without logging it. Each bearer business operation uses
one bounded `SECURITY DEFINER` entry point that receives the locator, envelope key version,
computed digest, canonical client address, and validated command. Its private, ungranted
authentication helper looks up the locator, acquires `FOR KEY SHARE` on the tenant
authorization-state row and then locks account and credential lifecycle in a fixed order,
compares the computed digest to the stored digest, and checks key version, expiry, network,
and live exact authority before the same entry point mutates business state. Authorization
mutations take `FOR UPDATE` on that same tenant state, so set-replacement policy/grant
changes cannot cross the check/write interval.

The runtime role cannot execute the helper and receives no stored digest or secret-bearing
row. A custom GUC, caller-supplied principal/credential identifier, or transaction-local
setting is never treated as proof of bearer authentication because the runtime role could
set it directly. Future bearer business commands repeat this authenticated-entry-point
pattern rather than reusing the human actor context.

Credentials have mandatory expiry no more than 90 days after issuance. Their exact
`(permission, scope)` allowlist and optional normalized PostgreSQL `cidr` rows are
relational, tenant-leading records. Empty network rows mean any source address; otherwise
the trusted client address must fall inside at least one row. Credential authority is the
intersection of:

1. live tenant, service-account, and credential lifecycle;
2. live service-account role authority;
3. `service_account_allowed` permission catalog entries;
4. the credential's exact permission/scope allowlist; and
5. expiry and source-network restrictions.

No wider scope subsumes a credential allowlist tuple. Issue and rotation fail
transactionally unless the requested allowlist intersects the account's live role
authority in at least one currently service-account-allowed tuple. A bearer request may
not fall back to a cookie or a different authentication mechanism. Multiple
`Authorization` values, comma-folded credentials, an unsupported scheme, or simultaneous
bearer and authenticated session state are rejected. A bearer token is bound to its
stored tenant and cannot select or override another path tenant.

The API resolves client addresses only through the configured trusted-proxy chain. Before
CIDR-restricted credentials ship, the web same-origin proxy gains the same explicit
trusted-proxy CIDR configuration and right-to-left chain algorithm: it strips untrusted
forwarding headers and forwards one canonical resolved client address. Arbitrary inbound
`X-Forwarded-For` is never accepted for a CIDR decision.

### One-time issue and rotation

Credential issue requires exactly one `Idempotency-Key`. The first successful response is
`201`, carries `Cache-Control: no-store`, and returns the bearer token exactly once. The
idempotency record stores the request fingerprint and resulting credential identifier, but
never the token or secret bytes.

Every secret-bearing issue or rotation response, and every related Problem Detail that
contains credential metadata, carries `Cache-Control: no-store`.

An exact replay returns `409 one_time_secret_already_issued` with the credential metadata
identifier/Location and no token. A replay with a different payload returns the standard
idempotency-conflict Problem Detail. If a caller loses the initial response, it must revoke
that credential and issue another. Rotation atomically issues a new credential and revokes
the predecessor; a replay never reveals the replacement secret. If the rotation response
is lost, its `409` replay identifies the replacement metadata without its token; the
operator revokes that replacement and issues another. Revocation is permanent.

Issue/rotate idempotency tombstones are retained for the service account's lifetime and
are not removed by ordinary short-lived command-idempotency cleanup. Reuse therefore
cannot expose a second credential after a cleanup window. Tenant retention may remove the
tombstone only together with the service account and all referenced credential metadata.

### Alert create command

`POST /api/v1/tenants/{tenantId}/alerts` requires exactly one `Idempotency-Key` for both
human-cookie and bearer callers. Human callers use the existing session/CSRF path and live
human authorization. Bearer callers use a separate authentication path and a separate
bounded database entry point; they do not populate spoofable user-context settings.

This bounded slice accepts a title, optional description and external identifier, and
severity. Tags, raw source payloads, custom-field definitions/values, list/detail/search,
and their human UI are delivered in the immediately following Alert slice rather than
being represented as ungoverned JSON placeholders. Validation rejects unknown fields,
control characters, excessive size, and noncanonical values before the transaction.

The database serializes an idempotency identity of `(tenant, operation, principal_kind,
principal_id, key_digest)`, rechecks live authority in the same transaction, and writes the
Alert, domain activity, redacted append-only audit event, minimal transactional-outbox
event, and idempotency result atomically. `principal_id` is the tenant membership for a
human and the service-account identifier for a machine; a bearer replay must additionally
reauthenticate its current credential. The same principal, key, and canonical request
fingerprint returns the same Alert without duplicate side effects; a different fingerprint
returns conflict. Another principal may independently use the same external key without
receiving or changing the first principal's result. Replays recheck current authority
before returning the prior result. Alert-command idempotency records live as long as their
Alert so a cleanup job cannot later create a duplicate. The alert creator is an exclusive
human-or-service-account attribution, enforced by tenant-leading composite foreign keys
and a database check.

That identity tuple is conceptual. The physical idempotency row has `principal_kind` plus
nullable `actor_membership_id` and `actor_service_account_id`, an XOR check, and separate
tenant-leading composite foreign keys. Human and machine partial unique indexes cover
`(tenant, operation, respective_actor_id, key_digest)`. PostgreSQL therefore cannot retain
an orphan or cross-tenant principal and does not rely on an unenforceable polymorphic
foreign key.

Credential authentication locks the relevant lifecycle rows against concurrent revoke,
archive, role-grant, and role-policy mutations. Successful use updates redacted `last_used`
metadata without weakening the command's authorization or atomicity. This monotonic
per-authentication telemetry may advance on an authorized idempotent replay; the Alert,
activity, audit, outbox, and command-result side effects are still created exactly once.
The API runtime role has no direct `SELECT`, `INSERT`, `UPDATE`, or `DELETE` privilege on
service-account, grant, credential, allowlist, network, or idempotency tables and no direct
mutation privilege on Alert, activity, audit, or outbox tables. Inventory, authentication,
and mutation use only bounded definers with fixed search paths.

### Audit-chain compatibility and rolling schema ABI

Tenant audit events gain nullable `actor_service_account_id` with tenant-leading
attribution. The validated actor truth table is: a `user` has `actor_user_id`, no service
account, and may have an impersonator; a `service_account` has
`actor_service_account_id`, no user, and no impersonator; a `system` has neither actor and
no impersonator. Because the old schema allowed an unattributed `service_account` enum
value before service accounts existed, the migration preflights that no such historical
row exists and fails closed if one does rather than rewriting an append-only event.

The canonical audit payload removes the new actor key when it is null and includes it only
for new service-account events. Consequently all pre-migration event bytes and hashes
remain verifiable. `ADD COLUMN`, the exclusive actor constraint, and the replacement
payload/hash function are installed in the same migration transaction; there is no
interval in which an event can be hashed with an unstable null field.

The permission/authority SQL ABI advances by one version. The new version exposes the
expanded exact catalog and service-account resolution. The current human runtime consumes
`resolve_current_tenant_human_authority_v2`; rolling safety freezes that predecessor's
signature, row shape, ordering, and pre-slice permission projection, not its vulnerable
function body. In the same migration transaction, v2 is replaced by a compatible wrapper
that explicitly excludes machine roles and every new permission key before any permission
is attached to the machine role. Older compatibility functions apply the same filtering
and fail closed for mutation attempts involving the new tuples. New binaries move to the
next version. A readiness contract records hashes and sentinels for the sealed predecessor
ABI and hardened implementation before the migration is considered deployable.

API startup and readiness call a bounded function that returns only the distinct key
versions referenced by live credentials. Every replica must have all those verification
versions plus the configured active issuance version or remain unready. Key rotation order
is fixed: distribute the new verification key to every replica, prove readiness, switch the
active issuance version, expire or revoke every credential on the old version, prove that
the live-version inventory no longer references it, and only then remove the old key.

### HTTP and UI surface

The canonical OpenAPI contract exposes tenant-scoped account list/create/detail/update/
archive, role-grant list/add/revoke, credential list/issue/detail/revoke/rotate, and Alert
create operations. Secret-bearing response schemas are distinct from redacted metadata
schemas, cannot appear in list/detail operations, and include no examples with usable
credential material.

The tenant administration UI uses live authority keyed by session and tenant, supports
server-side cursor pagination, and stores the one-time token only in local mutation state.
It never writes the token to query caches, browser storage, URLs, telemetry, or toast text.
Navigation and dialogs retract immediately when live capability disappears. Alert
inventory and detail UI follow with `alert.read` and the governed Phase 3 projection; this
slice does not expose an active-membership-only read path.

## Consequences

### Positive

- The first API credential is useful while retaining least privilege.
- Machine and human identity, audit attribution, and lifecycle cannot be confused.
- Role changes, revocation, expiry, tenant state, exact scopes, and CIDRs fail closed on
  the next request and across concurrent changes.
- Idempotency covers every side effect, not only the Alert row.
- Historical audit hashes and rolling application deployments remain verifiable.

### Costs and constraints

- Credential issue cannot recover a lost response; operators must revoke and reissue.
- Safe IP restrictions require a trustworthy proxy topology and explicit deployment
  configuration.
- Separate authentication/database entry points add code, tests, and operational key
  rotation work.
- The first Alert command is intentionally smaller than the complete Phase 3 projection,
  workflow, assignment, search, and custom-field model.

## Alternatives considered

### Issue credentials before a business permission exists

Rejected. A placeholder credential creates operational and attack surface without a useful
least-privilege outcome.

### Store an Argon2 password hash for every high-entropy token

Rejected for this locator-based API credential. A keyed digest provides constant bounded
verification after direct lookup and makes a database-only disclosure insufficient. The
external master key and rotation/versioning are mandatory.

### Return the original token on an idempotent replay

Rejected. Doing so would require retaining recoverable secret material and violate the
one-time-display guarantee.

### Let service accounts use human memberships and grants

Rejected. This would create ambiguous MFA, session, delegation, provider-mapping, and audit
semantics.

### Trust the first forwarded client-address header

Rejected. It would let a caller bypass credential CIDR restrictions unless every upstream
hop were independently trusted and sanitized.

## Verification requirements

The slice is not complete until automated tests prove clean and rolling migration,
readiness/hash compatibility, forced RLS and runtime privilege denial, cross-tenant direct
ID isolation, human-only administration, exact authority intersection, role/policy/source/
account/credential revocation, expiry, CIDR allow/deny including proxy spoof attempts,
keyring-version readiness and rolling key rotation, single-display issuance/replay/rotation
including response loss, concurrent revoke-versus-use, idempotent concurrent Alert create,
cross-principal key isolation, payload-drift conflict, replay after authority loss,
exclusive creator attribution, atomic activity/audit/outbox creation, audit legacy-actor
preflight and redaction/hash continuity, OpenAPI and generated-code drift, Go repository/
transport behavior, and permission-aware accessible UI behavior.
