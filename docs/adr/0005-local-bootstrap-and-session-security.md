# ADR-0005: Local bootstrap and server-side session security

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Security, Identity, API, Data, and Web
- Applies from: Phase 2A

## Context

Periapsis needs a first administrative identity before LDAP, OIDC, or SAML can be
configured. That path is also the emergency break-glass mechanism, so it cannot be a demo
credential, a permanently open registration endpoint, or a password-only account. Browser
sessions carry platform and tenant authority and therefore need revocation, rotation,
bounded lifetime, CSRF protection, and a server-side authorization decision on every use.

The bootstrap path precedes the first tenant. Tenant-scoped audit records cannot represent
it without inventing a tenant or weakening the non-null tenant invariant. Platform identity
and lifecycle events consequently require a physically separate platform audit stream.

## Decision

### One-time bootstrap

Bootstrap requires a high-entropy token supplied through a file-backed deployment secret.
Only a digest/constant-time comparison is used in process, and the token is never stored in
the database, returned to a client, logged, or included in an audit diff. Production refuses
an environment-only bootstrap token.

Startup/readiness passes the bootstrap-authority digest and a domain-separated, one-way
master-key verifier to one locked database operation. A fresh deployment binds both or
neither in that transaction; later replicas must match both. Separate autocommit calls are
not permitted because a crash between them could leave a foreign authority bound without
proving the encryption key.

The authentication service begins in a readiness-blocked state. Before accepting HTTP
traffic, the API performs one bounded full readiness preflight: exact ordered migration
fingerprint first, then the atomic protected-configuration verification. Failure is
nonfatal for liveness but keeps every authentication and authenticated application path
fail-closed until a later full readiness check succeeds. Shared checks use a server-owned
deadline, coalesce concurrent callers, and publish one immutable short-lived result; a
disconnected public requester cannot cancel the shared operation or overwrite a newer
snapshot. Public system status reads the last completed snapshot and never initiates the
locked database verification.
Bootstrap status is also a cached read: anonymous status traffic cannot elect the locked
verification or move a verified replica back into a globally blocking state. Full
readiness checks refresh availability, while successful confirmation marks the local
snapshot complete immediately.

The database owns the one-time invariant. A transaction can create the first local user,
credential, confirmed MFA credential, recovery-code hashes, and protected platform role
binding only while the singleton bootstrap state is incomplete and no protected platform
binding exists. The same transaction marks bootstrap complete and appends the platform
audit event. A read-then-insert sequence in application code is not sufficient.

Bootstrap is a server-generated, two-step enrollment. A start request guarded by the
external bootstrap token reserves the singleton bootstrap state for a short bounded period,
generates the TOTP secret with the operating-system CSPRNG, and returns that secret,
`otpauth` URI, and a separate opaque enrollment token once. A confirmation request requires
both authorities plus the password/profile and TOTP proof. Only confirmation creates the
identity. An abandoned reservation expires and can be replaced; concurrent starts cannot
create independent candidates. Failed proof creates no user or protected role. The initial
local identity receives only the protected `platform_super_admin` role; later local
identities require an already-authorized administration flow. Local authentication is
disableable, but deleting the last recovery path is a separately protected future
operation.

### Passwords and MFA

Passwords are stored only in PHC-formatted Argon2id hashes with a unique CSPRNG salt. The
initial server profile is 64 MiB memory, three iterations, one lane, a 16-byte salt, and a
32-byte key. Parameters are encoded in the hash so a later calibrated upgrade can rehash on
successful authentication. Unknown users run the same bounded Argon2id verification path,
and public failures do not reveal whether an identity exists.

TOTP generation and validation use a maintained RFC 6238 library, not a local protocol
implementation. The profile is six digits, a 30-second period, SHA-1 for authenticator
interoperability, and at most one adjacent time-step of clock skew. The accepted time-step
is advanced atomically so the same TOTP cannot satisfy two challenges. TOTP secrets are
encrypted with AES-256-GCM under a 32-byte file-backed master key. The ciphertext binds its
credential/user identity and key version as associated data; plaintext secrets are never
logged or returned after bootstrap.

Recovery codes are independent high-entropy random values displayed once. Only digests are
stored, and consumption is an atomic unused-to-used transition. Passwords, bootstrap
tokens, TOTP secrets, MFA codes, recovery codes, challenge tokens, session tokens, and CSRF
tokens are redacted from logs and audit metadata.

### Login challenges and sessions

Correct password verification creates only a short-lived, hashed MFA challenge with a
strict attempt limit. It does not create an authenticated browser session. Successful TOTP
or recovery proof consumes the challenge and creates a fresh opaque session identifier with
at least 256 bits from the operating-system CSPRNG. Only its SHA-256 digest is stored; the
identifier contains no user, role, tenant, or expiry data.

Sessions have inactivity and absolute expiries, last-seen metadata, authentication method,
MFA assurance, a rotation family, and explicit revocation. Authentication, privilege
changes, and step-up rotate the identifier. Logout/revocation invalidates the server-side
record rather than merely deleting a cookie. Cookie-authenticated requests always reload
the current user, session state, grants, and relevant tenant membership; a stale role cached
in a client or cookie has no authority.

The production session cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, host-only, and
uses `Path=/`. Local HTTP development is an explicit non-production concession; production
configuration cannot disable `Secure`. Mutating cookie-authenticated requests require a
per-session CSRF secret presented in a custom header and verified against its server-side
digest, plus an exact trusted `Origin` (or a same-origin `Referer` fallback where defined).
SameSite is defense in depth, not the only CSRF control.

### Throttling and authorization

Password and MFA attempts are throttled in PostgreSQL so multiple API replicas share the
same decision. Keys are purpose-separated, privacy-preserving digests of normalized account
and network inputs. Limits are bounded, expire, and cannot be bypassed by restarting a
replica. A successful login clears only the appropriate counters; security audit remains.

Authorization is a central, deny-by-default backend decision. Phase 2A introduces only the
explicit platform permissions needed to read and create tenants. A protected platform role
binding is distinct from tenant roles. Tenant selection is derived from active memberships
returned by the server; a client-supplied tenant ID never creates access. The database
re-checks one-time bootstrap and privileged tenant creation invariants in addition to the
Go policy decision.

### Audit separation

Platform bootstrap, authentication, session, protected-role, and tenant-lifecycle events
append to a dedicated platform audit chain. Tenant mutations continue to use the existing
non-null tenant audit chain. Both streams are append-only and tamper-evident; neither is a
substitute for protected backup/export.

## Consequences

### Positive

- There is no committed, default, or password-only administrator credential.
- Database transactions close bootstrap races and recovery-code/session replay races.
- Stolen database rows do not directly reveal passwords, MFA secrets, or live session
  tokens.
- Session revocation and permission changes take effect without trusting browser state.
- Platform audit does not weaken tenant ownership merely to record pre-tenant events.

### Costs and constraints

- Operators must provide independent bootstrap and encryption secrets before first use.
- Argon2id consumes deliberate CPU and memory, so shared throttling and capacity testing are
  required.
- Exact origin configuration is part of production deployment correctness.
- Key rotation needs versioned decrypt support before an old master key can be retired.
- This decision intentionally left WebAuthn/passkeys, federated identity, device lifecycle,
  and tenant MFA policy to later slices. Those slices are now implemented; break-glass TOTP
  and the Phase 2A session list remain distinct recovery controls, not substitutes.

## Alternatives considered

### Seed a default administrator

Rejected. It creates a known credential lifecycle, encourages deployment without rotation,
and cannot prove who completed bootstrap.

### Password-only bootstrap followed by optional MFA enrollment

Rejected. The interval before enrollment is exactly when the most powerful identity is
most exposed, and it violates the mandatory break-glass MFA invariant.

### Stateless signed browser tokens

Rejected for interactive administration. Immediate revocation, inactivity expiry,
privilege-change rotation, device/session listing, and server-side tenant grants are core
requirements; embedding authority in a long-lived client token makes those properties
harder and more failure-prone.

### Store TOTP secrets in plaintext or password hashes with SHA-256

Rejected. TOTP secrets must be recoverable only for validation and therefore require
authenticated encryption; human passwords require a salted memory-hard password hashing
function.

### Rely only on SameSite for CSRF

Rejected. Browser behavior, sibling-domain attacks, deployment mistakes, and future flows
make SameSite a useful secondary control rather than proof of request intent.
