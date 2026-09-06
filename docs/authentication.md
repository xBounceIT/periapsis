# Authentication and bootstrap operations

Status: local, tenant/platform LDAP, OIDC, SAML, MFA, and step-up paths implemented  
Last updated: 2026-09-02

This document covers one-time bootstrap, local emergency accounts, tenant and platform
LDAP, OIDC and SAML, MFA policy, step-up, server-side sessions, and service-account bearer
credentials. Provider catalogs and tenant bindings are protected administration surfaces;
interactive execution uses one-time protocol transactions, pinned provider material,
JIT or pre-linked admission according to policy, exact assurance evidence, session
provenance, and live revalidation. WebAuthn/passkey, TOTP, recovery-code, device, and
session-bound step-up flows are composed for local and federated authorities. Fresh
installations intentionally seed no permissive MFA trust: an administrator must publish the
required platform/tenant/role/group/action policy before activating a path that depends on
it. The local account remains an emergency recovery path, not the primary identity provider.

The canonical request and response shapes are in
[`packages/contracts/openapi/openapi.yaml`](../packages/contracts/openapi/openapi.yaml).
Swagger UI is available at `/docs` only when explicitly enabled.

## Required deployment secrets

The authentication surface uses independent secret classes:

- `PERIAPSIS_BOOTSTRAP_TOKEN_FILE` points to a high-entropy, one-time deployment token;
- `PERIAPSIS_MASTER_KEY_FILE` points to standard padded Base64 encoding of exactly 32
  random bytes used to encrypt TOTP material;
- `PERIAPSIS_API_CREDENTIAL_KEYRING_FILE` points to the versioned, independently generated
  32-byte keys used to authenticate API credentials;
- `PERIAPSIS_IDENTITY_KEYRING_FILE` points to the versioned 32-byte roots used for
  provider/client material and one-time identity ceremonies.

The master key, bootstrap-token digest, and API credential keyring are required for the
authenticated application surface. If any is unavailable, the affected access boundary
returns a fail-closed service error rather than guessing that bootstrap is complete. After
bootstrap, keep the token file mounted for the API but remove human access to its plaintext;
the database still permanently rejects another bootstrap. Production accepts these values
only from files. Docker Compose maps the local `.env` values
`PERIAPSIS_BOOTSTRAP_TOKEN`, `PERIAPSIS_MASTER_KEY`, and
`PERIAPSIS_API_CREDENTIAL_KEYRING` into read-only secret files; do not commit the resulting
`.env`. Example generation commands are:

```bash
openssl rand -hex 32
openssl rand -base64 32
```

Store the master key in the deployment secret manager and backup process. Losing it makes
encrypted MFA credentials unusable. Anyone who obtains either secret should be treated as
having sensitive security material. This slice records a key version but does not yet ship
master-key re-encryption tooling, so do not retire the original key until that migration is
implemented and verified.

Before the first enrollment, one PostgreSQL operation locks the bootstrap singleton and
atomically binds both the bootstrap-authority digest and a domain-separated, one-way
verifier derived from the master key. A failed or rolled-back call binds neither value.
Readiness compares both values on every API replica, so a length-valid but different secret
cannot receive traffic or partially claim a fresh deployment. The raw key never crosses the
application boundary and the API runtime role cannot read either stored binding directly.

Each API process starts with the protected authentication boundary blocked. Before the HTTP
listener starts, it runs one bounded, server-owned readiness preflight that verifies the full
ordered migration fingerprint and then atomically verifies or binds both protected values.
An unhealthy preflight does not terminate process liveness, but bootstrap, login, session,
membership, and platform requests remain fail-closed with `503` until a later complete
readiness check succeeds. Request cancellation cannot cancel or publish the shared check.
Concurrent probes share a short-lived immutable readiness result, and public system status
reports only the last completed snapshot rather than initiating database work.
The public bootstrap-status endpoint likewise reads only the last verified availability;
it never runs the locked verification or pauses authenticated traffic. Successful readiness
checks refresh that value, and successful bootstrap confirmation marks it unavailable
immediately on the completing replica.

`PERIAPSIS_PUBLIC_URL` is the exact browser-facing origin. Production requires HTTPS. It
must match the request `Origin` (or accepted same-origin `Referer`) on cookie-authenticated
mutations. Default local Compose also uses HTTPS: its external Caddy edge sets the origin to
`https://localhost:PERIAPSIS_WEB_PORT`; the API and web upstream have no direct host HTTP
binding.

`PERIAPSIS_TRUSTED_PROXY_CIDRS` is empty by default. When a same-origin web proxy or ingress
is present, list only its immediate peer networks. The API ignores forwarded client
addresses from any other peer. Compose assigns its web service one fixed address and trusts
only that `/32`; a direct API client therefore cannot choose its authentication-throttle
network identity.

`PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS` independently controls which ingress peers the web
server trusts. The web server walks one bounded `X-Forwarded-For` chain from right to left,
stops at the first untrusted hop, strips all inbound forwarding headers, and sends only that
canonical address to the API. Local Compose trusts only the fixed Caddy edge `/32`; direct
local-process development leaves the value empty. Production ingress networks must be
listed explicitly on both boundaries; malformed or duplicate chains fail closed.

For HTTP origins behind a remote TLS-terminating proxy, enable
`PERIAPSIS_WEB_PROXY_ONLY=true` using the dedicated Compose or Swarm variant. Web
requires a nonempty restricted `PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS` and canonical
`PERIAPSIS_PUBLIC_URL` HTTPS origin (lowercase hostname, no trailing slash or redundant
`:443`). It rejects untrusted socket peers before static/API routing and requires exactly
one public `Host`, one valid bounded `X-Forwarded-For`, and one `X-Forwarded-Proto: https`.
Alternate forwarding headers are removed before calling the API. Only exact GET/HEAD
`/health/live` is available directly; exact GET `/health/ready` additionally bypasses the
gate only from loopback and still reflects API readiness. Neither exception exposes
application routes. Secure cookies and origin/CSRF checks derive from the public HTTPS
origin, not from the unencrypted backend socket. Keep the cross-machine hop on a private,
firewall-restricted network or encrypted tunnel. See the
[deployment setup](operations/deployment.md#remote-reverse-proxy-with-an-http-origin).

The Compose edge serves the Keycloak test realm at
`https://idp.localhost:PERIAPSIS_IDP_PORT`. The API receives the external development CA
as `PERIAPSIS_FEDERATED_CA_BUNDLE_FILE` and explicitly allowlists port `18090`; it does not
disable certificate verification. The imported realm resolves its OIDC/SAML callback
placeholders to the same HTTPS web origin. Generate the certificate with SANs for
`localhost`, `idp.localhost`, `storage.localhost`, `127.0.0.1`, and `::1` as documented in the
[Compose runbook](../deploy/compose/README.md#create-the-local-tls-material).

`PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW` applies the same OIDC timestamp tolerance to tenant
and platform providers. It defaults to `1m`, accepts only microsecond-aligned durations from
`0s` through `5m`, and never extends the configured token-age or token-lifetime ceilings.

API credentials use the file-mounted `PERIAPSIS_API_CREDENTIAL_KEYRING_FILE`. Its strict
one-line JSON shape is `{"activeVersion":N,"keys":[{"version":N,"key":"..."}]}`; each
key is an independent 32-byte random value encoded with standard padded Base64. The API
derives domain-separated HMAC keys with HKDF and never stores source or derived keys in
PostgreSQL. Distribute a new verification version to every replica before making it active,
and remove an old version only after readiness reports that no live credential references
it. Production rejects the environment form; local Compose converts it into a secret file.

An API credential is not a browser session. The Alert-create endpoint accepts exactly one
authentication mode: either the normal session cookie plus CSRF protection or one bounded
`Authorization: Bearer` value. Multiple or comma-folded authorization values, mixed
cookie/bearer state, malformed envelopes, unknown key versions, and failed digests all use
the same non-oracular authentication failure. Bearer responses are `no-store`; a token is
shown only after a successful issue or rotation and is never returned by inventory,
replay, logs, URLs, or persistent browser storage. Current account, role, credential,
expiry, exact permission/scope, and optional CIDR authority is re-evaluated inside the
single database mutation transaction on every bearer command.

## One-time bootstrap

1. Start the database and apply all migrations.
2. Open the web application. It checks only whether bootstrap is still available; it does
   not expose secret or identity details.
3. Enter the deployment bootstrap token and the administrator email. The server reserves
   a bounded enrollment, generates the TOTP secret, encrypts it for storage, and returns
   the secret and `otpauth` URI once. The normalized email is bound to that reservation.
4. Add the TOTP credential to an authenticator and keep its clock synchronized.
5. Enter the display name, a 15-128 character password, and a current six-digit TOTP.
   Confirmation atomically creates the user, Argon2id password credential, confirmed TOTP,
   protected `platform_super_admin` binding, recovery-code hashes, initial session, and
   platform audit event.
6. Save all ten recovery codes in an offline password vault. They are displayed once and
   cannot be reconstructed from the database.
7. Remove bootstrap-token access from routine operators. The database permanently rejects
   a second completed bootstrap even if an old API replica or leaked token tries again.

An abandoned enrollment expires. Starting again replaces only an expired reservation; it
never creates a user. Confirmation needs both the deployment token and the opaque
enrollment token, and the email must match the one bound at enrollment.

## Login and MFA

Password login is deliberately two-step. A correct password creates a short-lived MFA
challenge but no authenticated session. Complete that challenge with either:

- `totp` and the current six-digit code; or
- `recovery_code` and one unused recovery code.

Each recovery code can transition from unused to used only once. A TOTP time-step can be
accepted only once for the credential, including across concurrent challenges. Invalid and
unknown-user password responses are intentionally indistinguishable, and the unknown-user
path still performs bounded Argon2id work. PostgreSQL-backed account and network limits are
shared by all API replicas; clients must honor `429 Too Many Requests` and `Retry-After`.

Passwords are never trimmed or silently truncated. The API bounds their character and byte
length before hashing. Passwords, deployment and challenge tokens, TOTP material, recovery
codes, session credentials, and CSRF tokens must never appear in logs or audit details.
Each API replica also admits only a bounded number of concurrent Argon2 operations;
`PERIAPSIS_AUTH_KDF_CONCURRENCY` defaults to `2` and accepts `1` through `16`. The general
request context defaults to `15s` and can be set from `1s` through `25s` with
`PERIAPSIS_REQUEST_TIMEOUT`; PostgreSQL statements inherit the same upper bound. Size the
KDF concurrency explicitly against the memory limit of each API replica.

## Shared API admission limits

The API applies a database-authoritative one-second budget before every non-exempt request,
including unknown API routes and unsupported methods. Liveness, readiness, `/metrics`,
`/docs` and its static assets, and `/openapi.json` are deliberately exempt so orchestration,
monitoring, and local contract inspection remain available during an admission-store
incident. A PostgreSQL error or malformed database decision fails closed with an RFC 9457
`503` response and integer `Retry-After: 1`; an exhausted budget returns an RFC 9457 `429`
with the positive integer delay computed from the database clock.

Every request consumes a client-network meter. IPv4 clients use an exact `/32`; IPv6
clients use a `/64` to resist privacy-address rotation. The address comes only from the
existing immediate-peer/trusted-proxy resolution rules, so operators must keep
`PERIAPSIS_TRUSTED_PROXY_CIDRS` narrowly pinned. A syntactically valid session cookie or
Bearer credential adds a stable credential meter. Tenant routes add a bounded subject
tuple: `(tenant, credential)` for credentialed traffic or `(tenant, network)` for
anonymous traffic. There is no tenant-global counter through which one noisy client can
consume every user's budget.

Only purpose-separated HMAC-SHA-256 digests reach PostgreSQL; credentials, tenant tuple
material, and network strings are not stored or logged by the limiter. All replicas derive
the same limiter namespace from the externally mounted master key and serialize the
aggregate decision through `app.admit_auth_attempts`; there is no in-memory admission
fallback. Configure the three non-secret budgets with
`PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS` (default `100`),
`PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS` (default `60`), and
`PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS` (default `40`). Each accepts `1` through
`100`. Authentication, MFA, recovery, LDAP, and federation retain their independent,
stricter long-window throttles in addition to these general budgets.

## Browser session contract

The browser receives an opaque random cookie; only its SHA-256 digest is stored. Production
uses the host-only `__Host-periapsis_session` cookie with `Secure`, `HttpOnly`,
`SameSite=Strict`, and `Path=/`. The HTTPS Compose profile exercises that secure-cookie
contract even though the application environment remains `development`. Direct local HTTP
processes use a deliberately different, non-`__Host-` cookie name so an invalid prefixed
cookie is never emitted; federated browser login and platform identity-provider
administration stay unavailable on that HTTP-only origin instead of preventing the rest of
the local API from starting.

Session responses include a per-session CSRF token. The web client keeps it in memory and
sends it as `X-CSRF-Token` on every cookie-authenticated mutation. The API also validates
the exact browser origin. A cookie or a UI-visible permission list is not authorization:
each request reloads current session state, live platform grants, and any selected tenant
membership.

Sessions expire at both an idle deadline and a non-extendable absolute deadline. The API
rotates the opaque credential on authentication and security-boundary changes. Logout
revokes the server-side row before clearing the browser cookie. Users can list their own
session metadata and revoke another session; session tokens and digests are never listed.
The bounded listing uses an immutable keyset cursor and returns at most 100 rows per page.
The first page always starts with the live current session; later pages make every retained
historical or still-live session reachable exactly once. The web UI loads one page at a time
and exposes an explicit **Load more sessions** action rather than issuing an unbounded read.
Invalid or retention-expired cursors return a generic bad request and never invalidate an
otherwise live current session.

The worker performs bounded retention passes for expired rate-limit meters, consumed or
expired challenges, and fully dead session families. Its per-class batch cap prevents a
backlog in one class from starving cleanup of the others; the worker login is the only
runtime role allowed to invoke this maintenance function. Challenges are retained for an
audit/debugging buffer after consumption or expiry, and dead session families remain for
30 days before deletion. Platform audit events remain the canonical append-only history.

## Tenant selection

The tenant switcher is populated only from active memberships returned by the server. For
legacy local/recovery sessions, a requested tenant ID is accepted only while that same user
has an active membership in an active tenant. Selecting a tenant changes session context;
it does not grant membership or platform permissions. Removal or suspension therefore takes
effect on the next backend authorization decision without trusting cached browser state.

Typed passkey and federated sessions do not use the legacy row-only tenant rotation ABI.
Until a provenance-aware switch has atomically copied or replaced their MFA/provenance,
cross-tenant switches fail before rotation and leave the current session intact. In
particular, a tenant-owned provider session cannot switch tenants, and a platform-provider
session will later require the exact live target binding, external identity, admission grant,
and acceptable fresh evidence rather than membership alone.

Memberships are also keyset-paginated at 100 rows per page. The switcher offers an explicit
**Load more tenants** action; if the active tenant is on a later page, it reports that fact
without inventing a name or treating browser state as authorization. Tenant changes rotate
the session identity, and the client ignores late responses that belong to the superseded
identity.

## Tenant and platform LDAP

Tenant LDAP and platform-global LDAP are physically separate provider and provenance
families. Both support deployment-bounded TLS/StartTLS destinations, write-only encrypted
bind secrets, AD/OpenLDAP/POSIX attribute templates, connection/bind/search diagnostics,
mapping dry-run, and shared source-owned reconciliation. Tenant login may JIT or admit an
existing identity according to policy. Platform-global login is fixed to existing identities
and cannot create platform users or grant `platform_super_admin`; its mapping output is
limited to already authorized platform groups/roles. Passwords are verified only by the
directory and are never persisted. A required second factor is completed by the platform.

Disabling a provider/mapping or observing a denied mapping result closes only that exact
source-owned access. Scheduled and manual reconciliation revoke removed group/role/team
effects transactionally, append audit, and invalidate affected sessions without deleting
unrelated manual authority.

## Platform-provider tenant bindings and federated admission

Platform administrators with `platform.identity_binding.read` can list and inspect explicit
tenant admissions for a known platform OIDC/SAML provider. Mutations additionally require
`platform.identity_binding.manage`, a live human session, same-origin CSRF, and an audit
reason. Create is payload-bound and idempotent; update and archive require the exact strong
`If-Match` validator composed from both the binding version and the live tenant-summary
version. Lifecycle commands use that same composite validator and open or close one immutable
access epoch. The create replay ledger retains the current-projection guarantee for 24 hours;
after that bounded window the permanent tenant/provider uniqueness constraint still
prevents a duplicate and the request returns a conflict. Every accepted mutation appends
correlated tenant and platform audit in the same database transaction.

Tenant execution is deliberately independent from direct platform login. A provider
must be active for tenant execution and an exact tenant binding must own a current live
access epoch before its tenant-unique login key resolves. Deactivation closes the epoch,
ends provider-owned admissions, resets the binding to disabled/deny admission policy, and
makes new starts plus live-session revalidation fail closed. Direct platform OIDC uses a
separate reason-bearing activation/deactivation command and can be activated only when the
provider projection reports every runtime prerequisite live. Its v1 account mode is fixed
to `existing_identity`: an exact provider-qualified subject must already be prelinked, and
provider claims never create platform users or platform authority.

The tenant OIDC flow uses Authorization Code + PKCE, a dedicated one-time HttpOnly/Secure
`SameSite=Lax` transaction cookie, exact state/browser/nonce correlation, pinned discovery/JWKS/secret and
policy revisions, and the shared tenant callback. The encrypted PKCE verifier is bound to
the transaction, platform provider, tenant, and exact admission binding. A provider subject
is unique only inside that platform provider. The resulting external identity is therefore
provider-global, while membership, access grant, profile contribution, MFA evidence, and
session provenance stay tenant-local and reference the exact binding, access epoch, source,
and external identity.

JIT can be disabled or create the provider-global identity and tenant membership. A
`provider_access_only` no-match policy may repair a missing admission grant for an existing
eligible identity; `deny` cannot. A repeat `no_change` plan succeeds only when the exact live
grant, membership, identity, binding, epoch, and source still agree. Rejected, stale, or
colliding applies roll back every identity, alias, membership, MFA, grant, profile, session,
application, and audit mutation as one database subtransaction. Provider claims never
produce platform roles or provider-derived tenant roles, groups, or operator teams.

The SAML path has separate tenant and direct-platform start/ACS routes. It pins the exact
metadata and SP-key revisions, rejects unsafe XML and unbounded encodings, validates the
selected signature object, issuer, audience, recipient, correlation, timestamps, and replay
identity, and supports certificate/key overlap for rotation. Its admission, MFA continuation,
session provenance, and revalidation converge with the same deny-by-default planner used by
OIDC without treating an assertion as authority.

## Direct platform OIDC login

`POST /api/v1/auth/platform/oidc/{providerKey}/start` begins an anonymous, same-origin,
metered Authorization Code + S256 PKCE ceremony and replaces any prior direct-platform OIDC
browser transaction. `GET /api/v1/auth/platform/oidc/callback` is the only cross-site
callback boundary. It requires the exact host-only `Secure`, `HttpOnly`, `SameSite=Lax`
transaction capability and clears it on every outcome. Both endpoints reject bearer,
existing-session, and unrelated continuation authority and return generic, no-store public
failures.

Completion admits exactly one live prelinked identity for the provider-qualified
`(issuer, subject)` tuple. It either creates a tenantless direct `oidc` session or the common
one-use MFA continuation selected by the live platform floor. The session records direct
provider provenance and is revalidated before authority or idle-time mutation. Selecting a
tenant is a separate authenticated command: the target must have a live binding, access
epoch, membership, provider-global identity, and tenant-local grant for that exact provider.
Success rotates the session credential and replaces direct provenance with exact-binding
provenance. An in-process bounded lookup can recover a proven ambiguous database commit; it
does not claim crash-safe or later HTTP-retry idempotency.

The runtime never invents or seeds the platform MFA floor it pins. The protected policy
administration surface publishes immutable, simulated platform/tenant/role/group/action
revisions. Provider activation remains fail closed until a current explicit policy satisfies
its prerequisites; an operator cannot bypass that dependency with a request flag.

Deployed API and worker processes must read the same closed identity-keyring document only
through `PERIAPSIS_IDENTITY_KEYRING_FILE`. Each retained root is exactly 32 random bytes in
standard padded Base64, versions are unique and positive, and `activeVersion` identifies the
write key. Add a new version before rotating writers and retain old roots until every stored
subject, alias dependency, PKCE verifier, and other identity envelope has been re-encrypted
or expired. Never reuse one root across the bootstrap, master, API-credential, notification,
or identity secret classes.

Operators who have binding permission without provider-catalog read permission use the
provider-ID-scoped UI; that UI reveals no provider configuration, and every request is still
authorized independently by the backend and PostgreSQL ABI.

The safe tenant summary exposes its positive version alongside ID, slug, name, and status.
Any change to those projected fields must advance the tenant version. PostgreSQL checks the
tenant and binding revisions together, after taking the canonical authorization-state,
tenant, and binding locks, so a tenant suspension cannot leave an old representation tag
valid or race a metadata mutation.

API and worker availability checks require the current sealed journal root plus every
trusted identity/MFA/protocol dependency probe named by the binary. Those probes attest the
exact owner-only helpers, source hashes, catalog shape, ACLs, transaction/apply, provenance,
assurance, replay-recovery, administration, and revalidation surfaces before delegating.
Superseded roots are immutable evidence and have no application runtime `EXECUTE` grant
unless the migration explicitly advertises one immediate predecessor. The migration-to-seal
interval is deliberately unready and is not a zero-downtime guarantee; follow the
[upgrade runbook](operations/migration-bootstrap-upgrade.md#current-compatibility-handoff).

## Phase 2A endpoint inventory

| Operation                    | Endpoint                                            | Anonymous | Additional request integrity           |
| ---------------------------- | --------------------------------------------------- | --------- | -------------------------------------- |
| Check bootstrap availability | `GET /api/v1/bootstrap/status`                      | Yes       | None                                   |
| Reserve TOTP enrollment      | `POST /api/v1/bootstrap/enroll`                     | Yes       | Bootstrap header                       |
| Confirm one-time bootstrap   | `POST /api/v1/bootstrap/confirm`                    | Yes       | Bootstrap header and enrollment token  |
| Start password login         | `POST /api/v1/auth/login`                           | Yes       | Shared throttle                        |
| Complete MFA                 | `POST /api/v1/auth/mfa`                             | Yes       | Challenge token and shared throttle    |
| Resolve current session      | `GET /api/v1/auth/session`                          | No        | Live session lookup                    |
| Logout current session       | `DELETE /api/v1/auth/session`                       | No        | CSRF and exact origin                  |
| List own sessions            | `GET /api/v1/auth/sessions?after=&limit=`           | No        | Live session lookup                    |
| Revoke own session           | `DELETE /api/v1/auth/sessions/{sessionId}`          | No        | CSRF and exact origin                  |
| List selectable memberships  | `GET /api/v1/auth/tenant-memberships?after=&limit=` | No        | Live membership lookup                 |
| Switch selected tenant       | `PUT /api/v1/auth/session/tenant`                   | No        | CSRF, exact origin, live membership    |
| List platform tenants        | `GET /api/v1/platform/tenants`                      | No        | `platform.tenant.read`                 |
| Create a platform tenant     | `POST /api/v1/platform/tenants`                     | No        | CSRF, origin, `platform.tenant.create` |

API errors use `application/problem+json` with a stable machine code and request ID. Public
authentication errors do not reveal whether an email, challenge, recovery code, or session
exists.
