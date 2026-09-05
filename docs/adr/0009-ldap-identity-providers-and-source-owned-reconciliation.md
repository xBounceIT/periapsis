# ADR-0009: LDAP identities use explicit tenant bindings and source-owned reconciliation

- Status: Accepted
- Date: 2026-08-25
- Decision owners: Architecture, Security, Identity, Authorization, Data, and Reliability
- Applies from: Phase 2C LDAP and every later federated-identity provider

Implementation status (2026-09-02): tenant LDAP and the physically separate platform-global
LDAP family are composed through protected administration, real redacted diagnostics,
mapping dry-run, tenant JIT/pre-link where configured, platform existing-identity-only login,
mandatory platform TOTP, scheduled/manual reconciliation, audit, and session revalidation.
Platform mappings cannot create `platform_super_admin`.

## Context

Periapsis must authenticate people through tenant-owned and platform-managed LDAP
directories without making directory claims an authorization boundary. A directory entry
can identify a person and report attributes or groups, but it does not by itself create a
tenant membership, a role, an operator-team relationship, or a platform grant. Those
effects must pass the same deny-by-default authorization, provenance, delegation, audit,
and concurrency rules established by ADR-0002, ADR-0005, ADR-0006, and ADR-0007.

The first schema modeled `users.email` as a required globally unique login identifier and
stored a single global display profile on `users`. That shape is sufficient for the local
break-glass slice but is not a valid federated-identity model. LDAP may omit email, two
tenants may report the same address for different people, and the same person may have
different tenant profiles. Linking an external login by mutable email, username, or DN
would permit account takeover after a directory rename or attribute reassignment.

LDAP also crosses a hostile network boundary. Administrators configure destinations,
filters, DNs, custom CAs, bind credentials, attribute names, nesting, and reconciliation
behavior. Incorrect handling can create SSRF, LDAP injection, credential disclosure,
unbounded queries, privilege escalation, or destructive deprovisioning after a partial
directory result. A test-connection or dry-run endpoint has the same security boundary as
login and scheduled synchronization.

The product requirement used the earlier term `PlatformGroup` for a directory mapping
target. ADR-0007 retired that ambiguous entity before it was persisted. The implemented
equivalent is a tenant-owned `TenantSecurityGroup`; the separate global `OperatorTeam`
remains non-authorizing until a tenant assignment epoch and exact-epoch roster entry exist.

## Decision

### Provider scope and tenant admission are separate

Tenant-owned and platform-managed providers are persisted in physically separate table
families. A tenant provider and every tenant-owned child row carry `tenant_id NOT NULL`,
tenant-consistent composite foreign keys, tenant-leading indexes, and enabled and forced
RLS. Platform providers have no nullable tenant column and are accessible only to bounded
platform workflows. A polymorphic table with an optional tenant ID is not used.

Authentication into a tenant always traverses a tenant-owned provider binding. A binding
has a tenant-unique login code, lifecycle state, profile precedence, version, and exactly
one origin:

- a provider owned by that same tenant; or
- a platform-managed provider explicitly made available to and bound by that tenant.

The two origins use real foreign keys and an exclusive-or database constraint. A global
provider is therefore not transitively usable by every tenant. Creating or ending a
platform-provider binding is a protected cross-boundary operation, emits correlated
platform and tenant audit, and cannot be achieved by supplying a guessed provider ID.
Tenant-provider administration never grants platform administration.

Provider lifecycle and binding lifecycle are independent. A disabled provider, disabled
binding, suspended tenant, retired provider access source, or stale incompatible
configuration denies new authentication. Existing federated sessions recheck their
provenance and are revoked or rejected when that path ceases to be live.

### Identity, login identifier, profile, and tenant access are distinct

`User` remains a platform identity, but email is no longer its primary key or a mandatory
attribute for federated users. The schema expands before JIT is enabled:

- `user_login_identifiers` stores purpose-qualified local identifiers such as canonical
  break-glass email, with verification and lifecycle metadata;
- tenant profile rows store tenant-specific name, username, and email projections;
- provider profile contributions retain their source, observed value, configuration
  revision, observation time, and lifecycle; and
- an explicit deterministic precedence policy materializes the effective tenant profile.

Existing local users are backfilled with a `local_email` login identifier. Local login is
moved to that identifier before `users.email` becomes nullable. The legacy email column
may remain as rolling-upgrade display compatibility, but no new authorization or linking
decision depends on it. No synthetic or placeholder email is created for an LDAP user.

An external identity is linked only by a provider-qualified immutable subject. Periapsis
does not automatically link by email, username, display name, DN, or a mutable directory
attribute. Deliberate account linking, if later exposed, requires fresh authentication of
both identities, conflict handling, reason-bearing audit, and a protected workflow.

A provider access source owns the tenant membership and effective profile contribution it
creates. Each mapping-rule epoch owns its group membership, group-role, and operator-team
roster consequences separately. Retiring a rule therefore cannot accidentally retire the
provider access path, and disabling a provider cannot adopt or rewrite manual or another
provider's authorization edges.

### Immutable subjects are encrypted and matched through versioned keyed digests

Tenant-provider and platform-provider external identities are physically separate. Each
stores the canonical immutable subject encrypted with authenticated encryption plus its
subject format and key version. Lookup uses a child alias table containing one or more
`(digest_key_version, HMAC-SHA-256(subject))` values unique within the exact provider.
Plaintext subjects and reversible ciphertext are not query keys.

Canonical LDAP subject formats are explicit:

- Active Directory `objectGUID` is the exact 16 directory bytes;
- `entryUUID` is parsed as an RFC 4122 UUID and encoded as its 16 bytes; and
- a custom immutable attribute is exact UTF-8 or Unicode case-folded UTF-8 according to a
  provider setting fixed before identities are admitted.

DN is never the immutable subject. Invalid, missing, duplicate, multi-valued, oversized,
or differently typed subject attributes deny admission and appear only as sanitized error
categories.

The identity keyring is supplied through `PERIAPSIS_IDENTITY_KEYRING_FILE` and is distinct
from bootstrap/TOTP and API-credential keyrings. Each version contains a CSPRNG 32-byte
root. HKDF-SHA-256 derives disjoint keys for LDAP bind-secret encryption, external-subject
encryption, and external-subject digests using fixed Periapsis context strings. AES-256-GCM
ciphertext binds scope, tenant where applicable, provider, row identity, purpose, format,
and key version as associated data.

The active key writes new ciphertext and digest aliases; retained decrypt/digest keys read
old versions. Successful lookup through an old digest adds the active digest alias and may
re-encrypt lazily under a guarded write. An old key cannot be retired until a database
inventory proves that no required ciphertext or sole digest alias depends on it.
Readiness verifies keyring shape, active-version uniqueness, required historical versions,
and a domain-separated database verifier without exposing key material.

Bind secrets are write-only after submission. Read APIs report only whether a usable
secret exists and its rotation timestamp. User LDAP passwords are passed once to the
directory over the bounded authentication operation and are never stored, audited,
queued, logged, traced, or retained in an error.

### LDAP configuration is typed, versioned, and bounded

LDAP configuration is relational and typed rather than an encrypted JSON document. It
includes editable Active Directory, OpenLDAP, and POSIX starting templates and supports:

- ordered `ldap://` or `ldaps://` endpoints, TLS/StartTLS mode, certificate verification,
  bounded custom CA material, connect/operation timeout, and deployment-authorized egress;
- bind DN and encrypted bind secret;
- parsed user/group base DNs, fixed-placeholder search-filter templates, optional user-DN
  template, page size, bounded result size, and attribute allowlists;
- configurable first name, last name, display name, username, alternate username, email,
  immutable subject, and group attributes;
- direct attribute, reverse group search, AD nested membership, or POSIX `memberUid` group
  resolution with bounded depth, nodes, and elapsed time;
- scheduled sync interval, JIT mode, deprovision policy, grace period, no-match policy, and
  disabled-entry policy; and
- immutable revision snapshots used by test, login, dry-run, and synchronization.

Templates create editable validated values; runtime behavior does not branch on a hidden
hardcoded template name. Unknown modes, attributes outside the configured allowlist,
unsupported URL schemes, invalid DNs/filters, zero or excessive bounds, inconsistent TLS
settings, and incomplete immutable-subject configuration fail closed at write and again at
use.

The v1 template grammar is deliberately closed. `userSearchFilter` contains
`{username}` exactly once in a positive equality or substring assertion; negated,
ordering, approximate, and extensible username assertions are rejected. When present,
`userDnTemplate` contains `{username}` exactly
once and permits no other placeholder. `groupSearchFilter` is mode-scoped: Active
Directory and reverse-search modes require `{userDn}` exactly once and may additionally
contain `{username}` once; POSIX `memberUid` mode requires `{username}` exactly once and
may additionally contain `{gidNumber}` once; disabled group resolution does not accept a
group search filter. Unknown, duplicate, unmatched, or mode-inapplicable placeholders are
rejected. Validation substitutes hostile sentinel values with RFC 4515 filter escaping or
RFC 4514 DN-value escaping as appropriate, then compiles or parses the complete rendered
value with the LDAP library. The same typed renderer is used at execution time; raw string
replacement is forbidden.

Synchronization does not accept a second unrestricted user filter. Its population filter is
derived from the compiled `userSearchFilter` by replacing the single typed `{username}` token
with a fixed LDAP presence wildcard and recompiling the result. This keeps login and complete
enumeration inside the same administrator-defined population while preserving exact escaping
for every caller-supplied username. A sync is authoritative only after this derived search has
ended with validated paging termination; a limit or partial page is never a smaller successful
population.

Provider updates use a strong version/ETag and exact `If-Match`. Secret replacement is an
explicit write-only action. A change that would reinterpret an admitted immutable subject
requires a separately protected migration workflow; ordinary update cannot change subject
format, normalization, or attribute once external identities exist.

### Network access is SSRF resistant and cancellation aware

The LDAP adapter pins maintained `github.com/go-ldap/ldap/v3` version 3.4.14 and wraps it
behind the shared identity module. Every operation uses a dedicated connection and a
server-owned deadline. It resolves each configured hostname at connection time, validates
every returned address against the LDAP egress policy, dials an approved address with
`net.Dialer.DialContext`, preserves the original hostname for TLS `ServerName`, constructs
the LDAP connection over that raw socket, and completes StartTLS before any bind.

Loopback, link-local, multicast, unspecified, documentation, reserved, metadata-service,
and private ranges are blocked by default. Private enterprise directories require a
deployment-level CIDR allowlist supplied outside tenant configuration. A tenant cannot
weaken the global egress boundary. URL userinfo, nonempty path/query/fragment, ambiguous
hosts, IP encodings, and unexpected ports are rejected. Certificate verification is on by
default; production cannot disable it. Custom CAs extend an isolated provider trust pool
and do not alter process-wide roots.

LDAP library calls that do not accept a context are made cancellation aware by closing the
dedicated connection when the context ends. Searches use an explicit paging loop with
page, entry, attribute, value, byte, nesting, and total-time ceilings. Filters interpolate
only fixed named placeholders through RFC-compliant escaping. DNs are parsed with the LDAP
library; string concatenation never builds an unescaped DN or filter.

Arbitrary server-supplied referral following is disabled. The configurable v1 referral
mode may follow only endpoints already listed in the provider configuration that share the
same TLS and trust profile, after the complete resolution and egress validation is repeated.
Cross-origin referral URLs are rejected. Endpoint failover is ordered, bounded, and does
not retry invalid credentials across an unbounded server set.

Database-backed admission rate limits are checked before network work. Per-provider and
global semaphores, failure budgets/circuit state, response-size limits, and sanitized
metrics prevent one tenant or directory from exhausting API/worker resources. Public
authentication failures remain generic; administrative diagnostics expose only stable safe
categories and correlation IDs.

### One normalizer and planner serve dry-run, login, and sync

Raw LDAP results are converted to a bounded provider-neutral identity observation. The
normalizer owns subject encoding, DN parsing, string normalization, attribute cardinality,
group identity, and deterministic ordering. Neither an HTTP handler nor a worker has a
second interpretation of LDAP attributes.

Each enabled tenant mapping rule matches an observed external group by exactly one typed
matcher: parsed exact DN, exact CN, or a bounded Go/RE2 regular expression. Case behavior
is explicit. Regex length and input size are capped and expressions compile when the rule
is written. All matching rules contribute; priority provides deterministic evaluation and
presentation order, not first-match short-circuiting.

The canonical local group target is a `TenantSecurityGroup`, never the retired
`PlatformGroup`. A rule may declare one or more tenant roles to be bound to that group and
an optional `OperatorTeam` target only through a currently live assignment epoch. It may
not name a platform role or create a platform grant. In particular,
`platform_super_admin` is never provider-mappable, including from a platform-managed
provider. Platform roles remain protected manual grants.

The pure planner receives the normalized observation, exact provider/binding/config/rule
revisions, current source-owned state, mapping rules, role policies, delegation boundary,
and assignment epochs. It returns the complete prospective profile, membership, group,
role, roster, denial, and revocation plan plus safe explanations. It evaluates every
consequence as required by ADR-0007. Dry-run returns a redacted form of this exact plan;
login and sync are prohibited from using a different evaluator.

Rules and provider access sources have immutable epochs. Authoritative reconciliation may
add, refresh, or revoke only live edges owned by the relevant source epoch. Additive mode
may add or refresh its edges but does not remove an absent observation. Manual,
migration, another rule, and another provider contributions survive. All matching source
contributions remain visible even when they result in the same effective role.

### Authentication separates network proof from transactional application

LDAP login follows this order:

1. resolve the tenant binding and perform the shared database rate-limit decision;
2. read an immutable provider/config/rule snapshot and decrypt only the required bind
   secret;
3. outside a database transaction, connect, service-bind where configured, locate exactly
   one user, authenticate with a separate user-bound connection, fetch bounded attributes,
   resolve groups, normalize, and build the reconciliation plan;
4. open one bounded transaction, acquire locks in the canonical tenant authorization
   order, and recheck tenant, binding, provider, configuration, rule, source, and
   authorization revisions;
5. match or create the external identity/User, apply JIT profile and provider-owned tenant
   membership changes, apply every mapping-source-owned consequence, append redacted
   tenant/platform audit and required outbox facts, and create or rotate the session; and
6. commit once, or reject and retry from a fresh snapshot when a relevant revision changed.

No LDAP call, DNS lookup, TLS handshake, or bind occurs while a database transaction is
open. A successful LDAP bind does not guarantee admission: ambiguous identity, no mapping
under a deny policy, stale configuration, suspended tenant, inactive binding, failed MFA
policy, or unauthorized prospective consequence still denies the session.

JIT mode is explicit (`disabled`, `existing_identity`, or `create`). No-match policy is
explicit (`deny` or `provider_access_only`). Provider access alone may create an active
tenant membership only when JIT and binding policy permit it, but membership alone grants
no permission under ADR-0006. Denied no-match login does not leave a partially provisioned
User or membership.

Federated session provenance records the provider scope and ID, tenant binding, external
identity, configuration/rule revisions, authentication time, and MFA evidence. Physically
separate provenance rows preserve tenant/platform foreign keys rather than storing a
nullable polymorphic provider reference on the session. Session resolution rechecks the
live binding, external identity, provider source, tenant membership, user, and current
authorization. Provider disablement, deprovisioning, or subject retirement takes effect
without trusting cookie state.

LDAP password proof carries no MFA assurance. A tenant policy that requires MFA must obtain
platform-managed second-factor/step-up evidence before admitting the session. That later
MFA slice may not relabel an LDAP password bind as MFA.

### Synchronization stages complete observations before authoritative removal

Scheduled and manual synchronization use durable PostgreSQL jobs and the shared LDAP
adapter/normalizer/planner. Network enumeration occurs outside the apply transaction and
writes bounded tenant-scoped staging observations and a sync-run record. A run pins the
provider, binding, configuration, mapping revisions, cursor, limits, and source epochs.

Authoritative absence is actionable only after a complete, non-truncated enumeration with
validated paging termination. Timeout, cancellation, failover exhaustion, referral
rejection, duplicate subject, limit breach, parse error, stale revision, worker crash, or
partial page marks the run incomplete and performs no absence-based revocation. A later
transaction applies one bounded chunk, rechecks revisions, and uses the same prospective
consequence planner and source ownership rules as login.

Deprovision policies are explicit: deny new login immediately, retain, suspend provider-
owned tenant access after a grace period, or revoke owned mapping consequences according
to the configured authoritative policy. A provider never globally disables a `User` that
has another live provider, tenant, or local recovery path. Mapping changes create a new
source epoch and reconcile from the old epoch through an audited plan; they do not silently
reinterpret historical edges.

Manual sync requires `identity_sync.run`, a reason, rate limit, and audit. Runs expose safe
counts, timestamps, cursor state, and categorized errors but not DNs, subjects, filters,
attributes, bind data, or customer values in logs/metrics. Staging and detailed observations
have bounded retention and tenant RLS.

### Permissions, API, UI, audit, and cache policy remain deny by default

Tenant permissions are separate and human-only:

- `identity_provider.read`, `identity_provider.manage`, and `identity_provider.test`;
- `identity_mapping.read` and `identity_mapping.manage`; and
- `identity_sync.run`.

Parallel platform permissions govern platform provider inventory and cross-boundary
bindings. Tenant roles cannot contain platform permissions. Provider/rule mutation still
checks the actor's exact live delegation ceiling for every prospective local role or roster
consequence; possessing a generic provider-management permission cannot grant stronger
authority indirectly.

Canonical OpenAPI endpoints expose provider inventory/detail, template application,
write-only secret replacement, bounded connection/bind/search/filter tests, mapping CRUD,
mapping dry-run, sync status, and authorized manual sync. Reads and mutations use generated
contracts, bounded pagination, RFC 9457 errors, strong ETags, exact `If-Match`, and
idempotency keys where retry could duplicate a command. Every provider, test, authentication,
dry-run, and sync response sends `Cache-Control: no-store`.

The UI uses the same generated contract and live authority projection. It identifies
unsaved/rotated secrets without ever rendering their value, warns before losing an unsaved
secret, displays sanitized diagnostics, and keeps test, dry-run, and sync actions separately
permission gated. Hiding a control is advisory; the backend and database recheck every
action.

Provider, binding, secret rotation, test, mapping, login, JIT, sync, deprovision, denial,
and session-revocation events are audited. Audit metadata is allowlisted and redacted;
secrets, LDAP passwords, full subjects/DNs, filters with user values, raw attributes,
group lists, custom CA contents, and upstream error strings are excluded. Mutations append
audit and required outbox events in the same transaction. LDAP network work never appears
inside that transaction.

### Delivery used expand, migrate, contract, then enable

During the rollout, federated login remained fail closed until the identity expansion was
complete. Delivery followed these compatibility boundaries:

1. add provider/identifier/profile/external-identity/source tables and security controls;
2. backfill and verify `local_email` identifiers and tenant profile fallbacks while old
   readers continue to use non-null `users.email`;
3. deploy dual-read/dual-write local authentication and profile projections;
4. prove every reader tolerates absent global email, then make `users.email` nullable;
5. enable provider administration and tests without login/JIT;
6. enable the shared planner and dry-run;
7. enable LDAP login/JIT only after the nullable-email and session-provenance readiness
   contract is current on every serving replica; and
8. enable sync/authoritative removal last, after complete-enumeration and recovery tests.

Each database stage has an exact migration-journal/readiness fingerprint and a sealed
predecessor accepted during its intended rolling window. New code tolerates the predecessor
only in explicitly degraded, fail-closed mode; old code never observes new nullable user
rows before it is retired. Generated Drizzle, sqlc, Go, and TypeScript artifacts change only
from their canonical sources.

## Consequences

### Positive

- A mutable email, username, or DN cannot silently take over an existing identity.
- Global providers do not create implicit cross-tenant access.
- Dry-run, JIT, login, and sync calculate the same source-qualified consequences.
- Provider removal and rule changes cannot delete manual or another provider's authority.
- LDAP network behavior is bounded, cancellation aware, and resistant to SSRF and injection.
- Key rotation retains deterministic lookup without exposing immutable subjects.
- Partial synchronization cannot become mass deprovisioning.
- Platform roles, especially `platform_super_admin`, are outside provider mapping entirely.

### Costs and constraints

- Separate tenant/platform table families and versioned subject aliases add schema and
  migration complexity.
- Profile projection and identity linking need more explicit state than one global email
  column.
- LDAP login requires two-phase snapshot/network/apply behavior and may retry after a
  concurrent configuration change.
- Private LDAP destinations require a deployment egress allowlist rather than a tenant UI
  bypass.
- Nested group resolution and authoritative sync require strict limits and may reject a
  directory whose result cannot be completely proven.
- Provider-driven role and roster changes remain constrained by an explicit delegated
  policy; convenience cannot bypass tenant recovery or delegation invariants.

## Alternatives considered

### Use one provider table with nullable `tenant_id`

Rejected. It weakens the non-null tenant invariant, complicates RLS, and makes a mistaken
global/tenant query a cross-tenant authorization defect.

### Let every tenant use every platform provider

Rejected. Provider scope is not tenant admission. An explicit binding and correlated audit
are required before a global authentication system can affect a customer.

### Link users by normalized email, username, or DN

Rejected. All are mutable and can be reassigned. Only a provider-qualified immutable
subject is an automatic identity key.

### Store the subject only as plaintext or only as one hash

Rejected. Plaintext unnecessarily exposes confidential identifiers; one unversioned hash
cannot rotate safely; hash-only storage cannot support protected diagnostics and migration
that require recovery of the canonical subject.

### Store all LDAP settings and mappings in encrypted JSON

Rejected. Typed relational configuration provides enforceable cardinality, foreign keys,
safe partial updates, deterministic comparison, queryable lifecycle, and migration review.
Only secret material is encrypted.

### Follow arbitrary LDAP referrals or trust DNS after initial validation

Rejected. Both enable SSRF, DNS rebinding, and credential forwarding to a foreign trust
domain. Every connection is resolved and validated, and v1 referrals are limited to
preconfigured same-profile endpoints.

### Apply the first matching rule

Rejected. It makes priority an accidental authorization override and loses independent
source provenance. Every match contributes and conflicts are resolved by explicit planner
policy.

### Perform LDAP calls inside the JIT transaction

Rejected. External latency and cancellation would hold authorization locks, and a remote
result cannot be rolled back. Network proof is followed by a short transaction that
rechecks every pinned revision.

### Treat an incomplete sync as authoritative absence

Rejected. Timeout, truncation, paging defects, or directory outage would become a mass
revocation event. Absence is meaningful only after complete enumeration.

## Staged verification

The provider foundation must prove generated-schema drift, forced RLS, runtime privilege
denial, composite-FK/direct-ID tenant isolation, keyring/readiness mismatch, ciphertext
associated-data substitution, write-only secret APIs, exact ETag/idempotency behavior, and
rolling local-identifier/email compatibility before provider login is enabled.

The LDAP adapter must prove URL and IP canonicalization, IPv4/IPv6 special-range denial,
deployment allowlists, DNS rebinding defense, hostname-preserving TLS, custom-CA isolation,
StartTLS-before-bind, cancellation by connection close, endpoint failover, referral limits,
filter/DN escaping, paging termination, size/nesting limits, and sanitized errors against
unit fixtures plus an OpenLDAP/AD-compatible integration matrix.

The mapping/JIT/sync slices must prove dry-run/apply parity, all-match deterministic rules,
immutable-subject collision and key rotation, no email linking, no platform-role mapping,
complete consequence/delegation checks, provider-versus-rule source separation, additive
and authoritative ownership, exact operator-team epochs, no partial-sync removals, grace
and deprovision races, immediate session denial after source retirement, concurrent first
login, and cross-tenant/global-binding isolation under PostgreSQL concurrency tests.
