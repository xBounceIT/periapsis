# ADR-0010: Federated SSO and MFA use one-time ceremonies and revalidated assurance

- Status: Accepted
- Date: 2026-08-25
- Decision owners: Architecture, Security, Identity, Authentication, Authorization,
  Data, Web, and Reliability
- Applies from: Phase 2D OIDC/SAML/MFA and every later interactive authentication flow

## Context

ADR-0005 established local break-glass authentication, mandatory TOTP, opaque server-side
sessions, CSRF protection, and live authorization. ADR-0009 established the identity model
that LDAP and every later federated provider must share: tenant admission is distinct from
provider scope, external subjects are immutable provider-qualified identifiers, mappings
are source-owned, and tenant and platform provider families remain physically separate.

Periapsis must now admit OIDC Authorization Code, SAML 2.0, and WebAuthn/passkey proofs
without turning protocol claims into authority or weakening the existing session boundary.
These protocols have different browser return paths and replay properties:

- OIDC returns a short-lived code on a cross-site top-level GET and requires exact state,
  nonce, issuer, audience, redirect URI, and PKCE validation;
- SAML returns attacker-controlled XML in a cross-site POST and requires exact request
  correlation, signature, issuer, audience, recipient, time, and replay validation; and
- WebAuthn verifies an origin- and relying-party-bound public-key ceremony but still needs
  one-time challenges, user-verification policy, credential lifecycle, and clone-risk
  handling.

The current Phase 2A model cannot merely be widened in place. `auth_challenges` assumes a
known local User and a TOTP credential, while an OIDC or SAML transaction begins before JIT
can identify or create a User. `auth_sessions.authentication_method` accepts only the three
local outcomes. The HTTP `AuthenticatedUser` projection still requires email even though
the canonical User model now permits federated identities without email. Finally, the
production session cookie is `SameSite=Strict` and ordinary mutations require an exact
same-origin CSRF proof; neither mechanism is available on an IdP callback and neither may
be weakened globally to make SSO work.

Federated MFA assertions also need an explicit trust decision. An `amr`, `acr`, or SAML
`AuthnContextClassRef` value is evidence asserted by one configured provider, not a
universal statement that satisfies every tenant, role, group, or privileged action.
Provider disablement, binding retirement, mapping changes, MFA-policy changes, factor
revocation, and local-account disablement must affect existing sessions without trusting
stale cookie state.

## Implementation status

As of 2026-09-02, tenant and platform OIDC/SAML execution, provider/binding administration,
provider-global external identities, tenant-local JIT/access grants, direct pre-linked
platform admission, transaction/replay/key rotation, assurance continuation, session
provenance/revalidation, and exact-binding tenant switch are implemented. Protected MFA
policy administration publishes simulated immutable platform/tenant/role/group/action
revisions; no permissive policy is implicitly seeded. TOTP, WebAuthn/passkey, recovery-code,
device, and session-bound step-up flows consume the same effective-policy boundary. Provider
claims cannot create platform roles or provider-derived tenant roles, groups, or teams.
Current compatibility is determined by the sealed root and dependency probes named by the
candidate API/worker binaries, not the older rollout snapshot previously recorded here. An
incompatible migration-to-seal interval remains intentionally fail closed and is not a
zero-downtime guarantee.

## Decision

### Provider scope, tenant admission, and platform authority remain separate

The provider boundary from ADR-0009 applies unchanged to LDAP, OIDC, and SAML:

- tenant-owned provider, subtype configuration, secret, external identity, mapping,
  transaction, diagnostic, and profile rows carry `tenant_id NOT NULL`, tenant-consistent
  composite foreign keys, tenant-leading indexes, and enabled and forced RLS;
- platform-managed providers use physically separate platform tables and platform
  permissions, never a nullable tenant discriminator; and
- tenant login through either origin requires one live tenant-owned provider binding.
  A platform provider is not implicitly available to any tenant.

The existing `tenant_auth_providers` catalog may be expanded from LDAP to the closed set
`ldap`, `oidc`, and `saml`, but an enabled base row must have exactly one matching subtype
row. Protected database writers enforce the base/subtype invariant and never permit a
kind change. Platform providers have a parallel base catalog rather than sharing this
table. A tenant binding retains its tenant-unique login code, lifecycle, version, and the
exclusive origin foreign keys fixed by ADR-0009.

A tenant provider can authenticate only into its owning tenant. A platform provider can
authenticate a platform identity through a separately enabled platform-login policy, or
authenticate into a tenant through that tenant's explicit binding. A platform provider
mapping never creates a platform role or platform permission. Platform authority remains
an existing, protected manual grant that is re-evaluated after authentication; in
particular no OIDC/SAML claim can create `platform_super_admin`.

Provider administration, tenant binding, authentication, mapping, and assurance are
different permissions. Tenant permissions are:

- `identity_provider.read`, `identity_provider.manage`, and `identity_provider.test`;
- `identity_mapping.read` and `identity_mapping.manage`;
- `identity_policy.read` and `identity_policy.manage`; and
- `identity_session.manage` only when tenant-wide session revocation is later exposed.

Parallel `platform.identity_provider.*`, `platform.identity_binding.*`,
`platform.identity_policy.*`, and `platform.identity_account.*` permissions protect the
platform tables. Tenant roles cannot contain them. Self-service session and factor
lifecycle endpoints still authenticate the owning human and require fresh assurance; they
do not use a broad tenant administration permission.

### Use maintained protocol libraries behind a narrow adapter

Periapsis does not implement JOSE, XML Signature, XML Encryption, or WebAuthn verification
primitives. The implementation admission gate evaluates and pins maintained releases
compatible with Go 1.26. The intended adapters are:

- `github.com/coreos/go-oidc/v3/oidc` with `golang.org/x/oauth2` for OIDC;
- `github.com/crewjam/saml` for the SAML service-provider profile; and
- `github.com/go-webauthn/webauthn` for WebAuthn.

The library is a parser and cryptographic verifier, not the whole security policy.
Periapsis still performs the exact issuer, audience, redirect, transaction, revision,
claim-cardinality, mapping, authorization, and session checks in this ADR. The SAML
adapter consumes only the exact signed object proved by the library and is admitted only
after the wrapping/duplicate-ID/encryption corpus is green. If a candidate cannot enforce
these invariants, it is rejected rather than patched with custom cryptography.

### Federated browser transactions are not authentication sessions

OIDC and SAML starts create a short-lived, server-side federated authentication
transaction before redirecting. Tenant and platform transaction tables remain separate.
Each transaction records only bounded state:

- CSPRNG transaction ID and a unique SHA-256 digest of the opaque browser handle;
- exact provider, tenant binding where applicable, provider/configuration/security
  revision, and protocol;
- exact expected callback, same-origin normalized relative return path, creation and
  expiry times, attempt state, and one-way network/account throttle keys;
- OIDC nonce digest, encrypted PKCE verifier, and exact discovery/JWKS snapshot;
- SAML AuthnRequest ID digest, RelayState digest, exact metadata revision, and service-
  provider key revision; and
- one lifecycle state: `pending`, `claimed`, `completed`, `failed`, or `expired`.

Raw authorization codes, ID/access tokens, SAML responses/assertions, passwords, and
WebAuthn responses are never stored. State, RelayState, nonce, transaction cookies, and
continuation credentials contain at least 256 random bits, use canonical unpadded base64url,
are length bounded, are stored only as digests unless recovery is required for the
protocol, and are consumed once.

OIDC uses a dedicated host-only `Secure`, `HttpOnly`, `SameSite=Lax` transaction cookie
scoped to the callback plus the independent `state` value. The callback requires both
digests. Starting a newer OIDC transaction invalidates the earlier cookie-bound transaction;
v1 deliberately supports one active OIDC start per browser rather than weakening browser
binding for multi-tab convenience.

SAML HTTP POST cannot use the Strict session cookie. It uses an independent host-only,
`Secure`, `HttpOnly`, `SameSite=None` transaction cookie plus an independent opaque
RelayState of at most 80 bytes and exact `InResponseTo`. A browser or deployment that
suppresses that cookie fails closed and restarts; IdP-initiated SSO is not accepted as a
fallback. The final session cookie remains `SameSite=Strict`.

The start operation rejects a live session cookie. Anonymous start and option requests are
same-origin POSTs, require the exact configured public Origin, are unavailable through
CORS, and apply shared network/provider throttles. Reauthentication, account linking, and
step-up are explicit flows with their own session-bound transactions; a generic login
start cannot silently replace an authenticated account. Callback endpoints are the only
exception to ordinary same-origin CSRF because they require the independent one-time
protocol and browser artifacts. They reject normal CSRF headers as a substitute, never
reuse a pre-authentication session ID, clear transaction cookies, emit `Cache-Control:
no-store` and `Referrer-Policy: no-referrer`, and redirect only to the stored same-origin
relative path.

An OIDC callback atomically changes `pending` to `claimed` before exchanging the code.
This prevents concurrent exchange; any exchange or validation failure is terminal and the
user starts again. A SAML callback can validate the bounded signed document outside a
database transaction, then atomically consume the pending transaction and insert the
response/assertion replay keys with the JIT/session result. Unique constraints select one
winner when callbacks race.

### Secrets use purpose-separated, rotation-aware protection

`PERIAPSIS_IDENTITY_KEYRING_FILE` remains the external root for federated identity data.
HKDF-SHA-256 derives disjoint keys for OIDC client secrets, OIDC transaction PKCE
verifiers, optional session token material, SAML service-provider private keys, protected
SAML session identifiers, and external subjects. AES-256-GCM associated data includes the
provider scope, tenant where applicable, provider/binding, row identity, purpose,
algorithm, and key version. A ciphertext is never portable to a different row or purpose.

OIDC client secrets are accepted only by explicit write-only replacement/clear actions.
Reads reveal only presence, version, and rotation time. Secrets are copied into bounded
byte buffers, used for the token request, zeroed where Go permits, and excluded from
errors, audit, metrics, traces, generated examples, and the browser after submission.
`client_secret_basic` and `client_secret_post` are the only v1 client-authentication modes;
the configured mode must be advertised by discovery and `none` is rejected for this
server-side client profile.

SAML service-provider signing/decryption keys are server-generated per provider with the
operating-system CSPRNG, encrypted under the identity keyring, and never accepted from or
returned to the ordinary UI in v1. Rotation is staged:

1. generate a successor key and certificate;
2. publish current and successor public certificates in SP metadata;
3. allow the IdP rollout interval;
4. make the successor active for signing and encryption metadata; and
5. retain the predecessor only for the bounded decryption/request overlap before retiring
   it.

Private-key retirement is blocked while an unexpired transaction or accepted encrypted
message can require that version. Symmetric identity-key retirement is blocked while any
live ciphertext or sole subject digest alias depends on it. Readiness inventories every
required version and fails the affected provider boundary closed without exposing key
material.

OIDC access tokens are used only for the immediate bounded UserInfo call and are not
persisted. The default login does not request `offline_access`. If a provider's documented
logout or revalidation policy genuinely requires an ID or refresh token, that policy is
explicit, the minimum token bundle is encrypted per session under its own purpose key,
and its expiry/key version is inventoried. Refresh never extends the local absolute
session lifetime. Rotation replaces the encrypted token atomically; refresh failure,
reuse indication, or decryption failure revokes the local session. No token enters an
outbox payload.

WebAuthn stores only credential public material and required credential-record metadata;
the authenticator retains the private key. Recovery codes remain one-use high-entropy
values stored only as digests. TOTP encryption continues to use the existing dedicated
authentication master-key boundary rather than silently moving old credentials to the
identity keyring.

### Discovery, JWKS, and metadata retrieval share an SSRF-safe HTTP boundary

OIDC issuer discovery/JWKS, every server-side OIDC endpoint learned from discovery, and
SAML metadata URLs use one hardened federated HTTP adapter. Tenant configuration cannot
supply a custom transport, proxy, DNS server, or egress exception. The adapter:

- accepts HTTPS only, canonical hostnames, deployment-authorized ports, no URL userinfo or
  fragment, and no ambiguous IP notation; an OIDC issuer may have a canonical path but no
  query, while a metadata URL has a bounded path and no secret-bearing query;
- disables environment-derived proxies unless a deployment-controlled proxy is explicitly
  configured and covered by the same trust boundary;
- resolves at connection time, validates every returned address, dials one approved
  address with `DialContext`, and preserves the original hostname for TLS SNI and
  certificate validation;
- blocks loopback, link-local, multicast, unspecified, documentation, reserved, metadata-
  service, and private ranges by default;
- permits private enterprise IdPs only through a deployment-level CIDR allowlist that a
  tenant cannot widen;
- repeats complete URL, DNS, address, TLS, and credential-forwarding validation for every
  permitted document redirect, with a maximum of three redirects; token, UserInfo,
  revocation, and logout requests carrying credentials never follow redirects;
- applies connect, TLS, response-header, total-operation, byte, decompression, JSON/XML
  depth, key/certificate, and cache-age limits; and
- never performs metadata/JWKS network I/O while a database transaction is open.

Discovery starts from the exact configured OIDC issuer; tenants do not edit discovered
authorization, token, JWKS, UserInfo, revocation, or end-session endpoints independently.
The returned `issuer` must exactly equal the configured canonical issuer string. SAML
metadata must contain exactly the configured IdP entity ID and an allowed SSO binding.
Uploaded SAML metadata is an alternative to URL retrieval and passes the same bounded XML,
entity, endpoint, certificate, and algorithm validation without network access.

Successful documents become immutable revision snapshots with content digest, retrieval
time, protocol expiry/cache metadata, extracted endpoints, and safe certificate/key
summaries. Runtime pins one snapshot for the entire ceremony. A background refresh stages
a candidate and rechecks the provider version before activation. Last-known-good material
may be used only until its explicit capped expiry; failure never extends trust indefinitely.

A SAML URL refresh may activate automatically only when the entity ID is exact, no policy
weakens, endpoints remain allowed, and the new signing set overlaps the currently trusted
set. A non-overlapping signing-key change requires explicit protected approval unless a
separately pinned metadata-signing trust anchor validates it. Removed IdP certificates may
remain accepted only for an explicit bounded rollover window; every accepted certificate
fingerprint belongs to a named metadata revision.

### OIDC v1 is Authorization Code with mandatory S256 PKCE

OIDC v1 supports only the Authorization Code flow. Implicit, hybrid, device, password,
client-credentials, token-in-URL, and unsigned-ID-token flows are rejected. Every request
uses:

- `response_type=code` and query response mode;
- `scope=openid` plus a configured bounded allowlist;
- a CSPRNG `state` and nonce;
- a 43-128 character CSPRNG PKCE verifier with `code_challenge_method=S256`; and
- the exact server-derived callback URI
  `${PERIAPSIS_PUBLIC_URL}/api/v1/auth/federated/oidc/callback`.

The callback URI is not tenant-editable and the identical byte string is used for the
authorization request and code exchange. `PERIAPSIS_PUBLIC_URL` supplies one production
HTTPS origin; arbitrary forwarded hosts never influence it. Query parameters must be
single-valued and bounded. A callback containing both an error and a code, duplicate code
or state parameters, a missing browser binding, or a response issuer that is present but
not exact is rejected generically.

Code exchange uses the transaction's pinned token endpoint, client ID, client-auth mode,
redirect URI, and decrypted verifier. The ID token must pass the library signature and
time validation. Before claim mapping, the compact token and decoded header/payload have
strict segment/byte/depth limits and duplicate JSON member names are rejected. It then
passes all of these local checks:

- `iss` is byte-for-byte the pinned discovery issuer;
- `aud` contains the exact client ID; multiple audiences require `azp`, and any present
  `azp` equals the client ID;
- `nonce` hashes to the transaction's exact one-time nonce digest;
- `sub` is one nonempty bounded UTF-8 string and is never case-folded;
- `exp`, `iat`, optional `nbf`, and required `auth_time` under a configured freshness
  policy fit the bounded clock-skew and transaction window; and
- the JWS algorithm is in the deployment/provider allowlist and is never `none`.

If an `at_hash` claim is present and the access token is used, it must validate against
that exact access token before UserInfo is called.

Clock skew defaults to 60 seconds and is configurable only between zero and five minutes.
Token maximum age is independent of clock skew. JWKS key selection is pinned to the
transaction snapshot; an unknown `kid` may trigger one bounded SSRF-safe refresh, but the
transaction must then restart against the new immutable revision rather than mixing
snapshots.

OIDC immutable identity is always `(exact provider, exact iss, exact sub)`. It is not a
configurable email claim. Profile attributes map from exact top-level claim names with
closed expected types and cardinality. The v1 group claim is an array of bounded strings;
numbers, objects, delimiter coercion, duplicate JSON keys, and mixed arrays fail closed.
UserInfo is optional and explicitly configured. Its `sub` must exactly match the ID-token
subject, and it cannot override issuer, audience, nonce, authentication time, or MFA
evidence.

Local logout always revokes the Periapsis session before any upstream action. A discovered
RP-initiated logout or token revocation is best effort after local revocation, uses only an
exact allowlisted endpoint and session-scoped encrypted material, and cannot restore or
extend the local session when it fails. Front-channel and back-channel logout callbacks
are separate later slices with issuer, `sid`/subject, signature, audience, and replay
validation; their absence is visible operationally rather than misrepresented as upstream
revocation.

### SAML v1 is SP-initiated Web SSO with signed consumed assertions

SAML v1 supports SP-initiated Web Browser SSO. Periapsis sends an AuthnRequest through the
HTTP Redirect binding and accepts a response only through a bounded HTTP POST ACS at
`${PERIAPSIS_PUBLIC_URL}/api/v1/auth/federated/saml/acs`. IdP-initiated SSO, unsolicited
responses, artifact binding, unsigned logout messages, and a generic SAML middleware
session are rejected.

The service-provider entity ID and ACS URL are stable server-derived values, not callback
input. Provider-specific SP metadata publishes those exact values and the staged public
certificates. AuthnRequests have CSPRNG IDs, are signed when the provider policy requires
it, and pin the provider/binding, metadata, SP key, requested AuthnContext, and transaction
revision.

Before signature processing, the ACS enforces media type and encoded/decoded byte limits.
XML parsing forbids DTDs, external entities, XInclude, external retrieval, duplicate ID
attributes, excessive depth/nodes/attributes/certificates, and ambiguous namespace or
schema shapes. Periapsis never selects an assertion by an unsigned XPath after validating
a different object.

Every accepted response satisfies all of the following:

- RelayState, browser transaction cookie, Response `InResponseTo`, and each consumed
  SubjectConfirmationData `InResponseTo` match the one pending AuthnRequest;
- Response `Destination` and SubjectConfirmationData `Recipient` exactly equal the ACS;
- Response and Assertion issuers exactly equal the configured IdP entity ID;
- every applicable AudienceRestriction admits the exact SP entity ID;
- Conditions, SubjectConfirmationData, and AuthnStatement times are valid under the
  configured zero-to-five-minute skew and maximum-authentication-age policy;
- the consumed assertion has one allowed bearer subject confirmation and one bounded
  AuthnStatement; and
- both the Response ID and consumed Assertion ID are nonempty, bounded, and newly inserted
  into the exact provider/binding replay namespace.

Signature policy is an explicit enum: `signed_assertion` (default), `signed_response`, or
`both`. No policy accepts an unsigned response and unsigned consumed assertion. The exact
configured signed object is verified with a currently accepted certificate from the pinned
metadata revision. XML Signature algorithms are allowlisted to modern SHA-256-or-stronger
RSA/ECDSA profiles supported by the admitted library; SHA-1, DSA, unknown transforms,
external references, and algorithm downgrade are rejected.

Encrypted assertions are `disabled`, `optional`, or `required`. Decryption uses only the
pinned provider's active/overlap SP private-key versions. V1 admits AES-GCM content
encryption and RSA-OAEP key transport profiles that the selected library proves against
the interoperability corpus; RSA1_5, CBC-only profiles, unknown algorithms, and key-name
fallback across providers are rejected. Decryption never substitutes for signature
validation: the exact decrypted assertion still satisfies the configured signature
policy. Unsupported encryption fails generically and exposes only a safe administrative
category.

SAML immutable identity is either a persistent NameID with its exact Format or one
configured immutable attribute with exact Name/NameFormat and exactly one bounded string
value. Transient/unspecified NameID is never silently promoted to a stable subject.
Changing subject source or normalization after admission requires the protected identity-
migration workflow from ADR-0009. Attribute and group mappings use exact names, expected
types/cardinality, byte/value caps, and the shared identity planner.

IdP signing certificate rotation follows immutable metadata revisions. Multiple
certificates are valid only when each is explicitly present in an accepted active/overlap
revision. A removed or expired certificate does not remain trusted because it once
validated a message.

SAML Single Logout is optional and ships only after login is green. SP-initiated logout
first revokes the local session, then sends a signed bounded LogoutRequest to the exact
metadata endpoint when the session retained protected NameID/SessionIndex material.
Inbound LogoutRequest/Response messages require exact issuer, destination, signature,
request correlation, time, and replay validation before they can revoke a matching local
session family. SLO failure never undoes local logout.

### JIT linking is only by immutable provider-qualified subject

OIDC/SAML observations enter the provider-neutral normalizer and the exact planner from
ADR-0009. Claims and assertions are identity/mapping inputs, never permissions. The
transactional apply step rechecks tenant, binding, provider, security/configuration,
metadata/discovery, mapping, authorization-source, and MFA-policy revisions before it
changes identity state or creates a session.

Automatic linking uses only the external-subject digest namespace:

- tenant-provider subjects are unique inside that exact tenant/provider;
- platform-provider subjects are unique inside that exact platform provider; and
- issuer/entity ID and subject format are part of canonical subject context.

Email, username, NameID display value, group, tenant profile, and an equal subject from a
different provider never link Users. If no external identity exists, `disabled` JIT denies,
`existing_identity` requires a deliberately pre-linked identity for that exact provider
subject, and `create` may create a new User and provider-owned tenant membership. An equal
email on another User remains two identities; no synthetic email, suffix, merge, or
account takeover occurs. Tenant profile username/email are non-authorizing projections and
need not be unique.

If the subject already belongs to a different, retired, disabled, or inconsistent User,
automatic reassignment is denied with a sanitized `identity_collision` category. Restoring
or linking requires a separate reason-bearing workflow with fresh proof of both identities.
Two concurrent first logins for the same subject converge through the unique digest alias:
one creates the identity and the other retries a fresh snapshot and may use that same
result only if every pinned provider/source revision still matches. Two distinct subjects
never converge because another mutable attribute happens to match.

The planner evaluates all matching group rules and every role/team consequence, including
the exact delegation boundary and operator-team assignment epoch. It cannot map platform
roles. JIT identity/profile, provider-owned membership, mapping-source edges, redacted
audit/outbox facts, MFA continuation or session, and replay consumption commit once. A
failure or insufficient policy cannot leave an authenticated session; an abandoned JIT
User has no authority without live source-owned access and a valid session.

### Federated MFA evidence is trusted only by an explicit policy

Periapsis stores normalized assurance, not a boolean copied from a provider. Assurance
levels are ordered `primary`, `mfa`, and `phishing_resistant`. Evidence also records a
source constraint (`local` or one exact provider/binding), authentication time, factor or
trust-rule revision, and expiry. A recovery code is recorded separately as recovery
evidence and never becomes phishing-resistant.

OIDC trust rules match an exact configured `acr` value and/or an exact required set of
case-sensitive `amr` strings, plus a maximum `auth_time` age. SAML trust rules match exact
case-sensitive AuthnContextClassRef values plus AuthnInstant age. There is no substring,
regex, case-folding, default `mfa` interpretation, or trust inherited from another
provider. Missing, wrong-type, duplicated, stale, or unmapped evidence yields only
`primary`. Provider evidence can raise assurance only after the entire OIDC/SAML proof is
valid.

Platform, tenant baseline, every effective tenant role, every effective tenant security
group, and the protected action can each impose an MFA policy. The effective requirement
is deterministic and monotonic:

- the strongest assurance level wins;
- any `local_required` source constraint wins;
- the shortest nonzero freshness interval wins; and
- the earliest enrollment deadline wins.

A lower-scope policy cannot weaken the platform administrator floor or a stronger policy.
The policy is computed from the prospective post-mapping roles/groups during JIT and from
live roles/groups on every later authorization. Unknown targets, assurance values,
provider evidence, or conflict states deny.

If fresh primary authentication succeeds but effective assurance is insufficient, the
system creates a short-lived, one-use post-primary continuation instead of an authenticated
session. The continuation is bound to the User, provider provenance, tenant intent,
prospective policy revision, allowed factor operations, expiry, and attempt budget. The
browser receives only an HttpOnly same-origin continuation cookie and may call only status,
MFA completion/enrollment, restart, and cancellation endpoints. Completing it creates a
fresh session ID; it never upgrades a pre-authentication cookie.

Enrollment grace is not ordinary access. A user inside the configured grace window may
use the continuation solely to enroll an allowed factor. Once grace expires, login denies
until a protected administrator recovery flow changes the policy or factor state. A policy
cannot be activated if simulation proves that every direct recovery administrator would
be unable to satisfy it.

Step-up for an existing session uses a distinct challenge bound to that exact rotation
family, User, active tenant, requested action/audience, current policy revision, and
required assurance. Completion rotates the session credential and records a new assurance
event. A step-up for one tenant/action does not silently satisfy another tenant or a
stronger action, and its bounded freshness never extends the session's absolute lifetime.

### WebAuthn credentials are origin-bound factors and optional passkey primaries

Production WebAuthn RP ID and allowed origins are derived from the validated
`PERIAPSIS_PUBLIC_URL` deployment configuration. Tenants cannot supply RP IDs or origins.
Changing the RP ID is a protected migration that can invalidate credentials; forwarded
Host and Origin values never define it.

Every registration or assertion uses a server-side one-time ceremony containing a CSPRNG
challenge digest, exact RP/origin configuration revision, User where known, session family
or post-primary continuation, tenant/policy/action binding, allowed credential IDs,
expiry, and attempt state. Options and responses are size/count bounded. The admitted
library validates exact challenge, origin, RP ID hash, ceremony type, signature, user
presence, and required user verification. Cross-origin/iframe ceremonies are rejected in
v1.

Registration requires fresh acceptable assurance or a bounded enrollment continuation.
User verification is required. Resident/discoverable credentials are preferred for
passkeys and required for usernameless login. The WebAuthn user handle is an opaque stable
random value, not an email, username, tenant ID, or database UUID exposed verbatim.
Attestation defaults to `none`; direct/enterprise attestation requires a separate explicit
platform policy, metadata trust source, privacy review, and test corpus.

Credential storage retains the exact credential ID and public key, user-handle binding,
sign counter, transports, AAGUID, attestation format/type, user-verification and backup
eligibility/state flags, friendly name, creation/last-use time, version, and revocation
metadata required to reconstruct the library credential record. Credential ID is globally
unique and bounded. A credential can belong to only one User and is never reassigned.

An authenticator whose counter is unsupported/always zero remains usable with a visible
risk category. For a previously nonzero counter, a non-increasing assertion is denied and
atomically marks the credential clone-suspected/revoked before any session is created or
upgraded. Concurrent use compares and advances the stored counter so the same assertion
has one winner. Backup-state changes are recorded and audited but do not by themselves
become a hardware-bound assurance claim.

A discoverable, user-verified passkey may be enabled as a primary platform-managed login.
It resolves the User from the opaque user handle and credential ID, then performs the same
live User, tenant admission, MFA policy, session provenance, and authorization checks as
other methods. A non-discoverable credential is an MFA/step-up factor only. WebAuthn does
not create tenant membership or platform authority.

Users can list safe device summaries, rename, and revoke their own credentials after fresh
assurance. Administrators see only policy-safe metadata. Revoking a credential immediately
invalidates challenges and assurance derived from it; it never exposes public key bytes,
attestation statements, or raw client data in routine UI/audit.

### Local credentials remain protected recovery paths

`User` lifecycle, local login-identifier lifecycle, local password-credential lifecycle,
and MFA-factor lifecycle are distinct. Tenant policy may hide or deny ordinary local login,
but a tenant cannot disable the protected platform break-glass route. There is no public
local registration or email-reset flow.

Creating another local identity, disabling/enabling a local credential, rotating a
password, regenerating recovery codes, or changing the protected break-glass policy is a
reason-bearing platform workflow with fresh local MFA/step-up. The database serializes and
rechecks that at least one enabled human recovery principal retains an active local
credential, verified login identifier, confirmed acceptable factor, and protected manual
platform role. A protected configuration change cannot deliberately remove the last
configured recovery mechanism; ordinary one-use code consumption may exhaust a set and
raises a recovery-health signal rather than making the last code unusable. Tenant
group/provider authority never satisfies this invariant.

Local credential disablement immediately denies and revokes sessions whose primary
provenance depends on it. It does not globally disable a User that has another provider or
passkey path. User disablement denies every method. Password replacement advances the
credential version, rotates the completing session, revokes other local password session
families according to policy, and never reuses a password hash or challenge.

Recovery-code regeneration requires fresh assurance, atomically retires every prior
unused code set, writes only new digests, and returns the new values once with `no-store`.
The schema migrates recovery sets away from an implicit one-TOTP ownership assumption so
WebAuthn and federated recovery can share the lifecycle without treating a code as a normal
provider claim. A recovery-code login is marked `recovery`, never
`phishing_resistant`, and may access only the policy's bounded recovery/repair path until
an accepted factor re-establishes full assurance.

### Session provenance and assurance are revalidated before authority

`auth_sessions` remains the opaque token, CSRF, expiry, rotation-family, and revocation
record. Primary authentication provenance and assurance are normalized outside its flat
`authentication_method` string. Physically separate rows preserve exact foreign keys:

- local credential and passkey primary provenance;
- tenant-owned-provider session provenance;
- tenant-to-platform-provider-binding session provenance; and
- direct platform-provider session provenance.

Exactly one primary provenance row exists before a session becomes usable. Federated rows
record provider/binding/external identity, security and mapping revisions, subject alias
version, authentication instant, versioned keyed digest of a protocol session identifier
where applicable, and safe assurance-rule references. Separate append-only
session-assurance events record local factor or explicitly trusted provider evidence. Raw
claims, tokens, assertions, NameIDs, subjects, and group lists are not session metadata.

Every authenticated request rechecks, before touching idle expiry or evaluating RBAC:

- User, session, rotation family, credential/factor, and absolute/idle lifecycle;
- exact primary provenance and external identity;
- provider, tenant binding, tenant, provider-access source, and tenant membership when
  tenant-scoped;
- the provider's session-invalidation epoch and every referenced credential/trust
  lifecycle;
- live authorization and mapping-source consequences; and
- effective MFA policy, evidence source, freshness, and target tenant/action.

Provider disablement, binding retirement, external-identity retirement, local credential
disablement, factor revocation, subject-security change, or User suspension denies
immediately and records/reconciles session revocation. A policy change that merely raises
assurance produces `step_up_required` and a restricted challenge; it never permits the
stale assurance. Claim/profile mapping changes use source reconciliation and live RBAC
rather than preserving a stale embedded permission.

Ceremony, session-invalidation, and presentation/mapping revisions are distinct. A callback
must finish against the exact immutable ceremony revision it started with. Issuer/entity
ID, client identity/authentication, redirect/ACS, subject source, metadata trust policy, or
MFA trust semantics advance the session-invalidation epoch and require fresh
authentication. Normal additive/removal key rotation affects new ceremonies but does not
retroactively invalidate a proof that was valid when accepted; an explicit key-compromise
action advances the invalidation epoch and revokes affected sessions. Display names and
profile mappings do not pretend to be authentication proof, though their source-owned
projections reconcile under their own revision.

A tenant-owned provider session cannot switch into another tenant. A platform-provider
session may switch only when the target tenant has a live binding to that exact provider
and external identity and its current policy accepts the same fresh evidence; the switch
rotates the session and changes binding provenance. Otherwise the user performs a fresh
target-tenant authentication. Local/passkey sessions continue to use live membership and
policy checks. A tenant switch never broadens provider trust.

Upstream continuous revocation cannot be inferred where a protocol supplies no signal.
Periapsis guarantees immediate local revocation and local provenance revalidation, then
uses bounded maximum authentication age, explicit reauthentication, optional protected
OIDC token/back-channel support, and signed SAML SLO where configured. Operations and UI
must not claim that an upstream IdP session was revoked when only the local session ended.

### Database, transaction, audit, and redaction boundaries are explicit

Anonymous start/callback handlers do not receive general table privileges. Narrow,
security-definer database functions with fixed search paths perform digest lookup,
transaction claim/consume, replay insertion, JIT apply, continuation/session creation,
and audit under server-established context. Tenant functions install and verify the exact
tenant/binding context and RLS; platform functions use physically separate platform rows.
Direct IDs from another tenant return the same generic outcome as an absent transaction.

No DNS, HTTP, token exchange, metadata/JWKS retrieval, XML processing, or IdP logout call
occurs in a database transaction. Protocol proof is followed by one short apply transaction
that locks in canonical identity/authorization order and rechecks every pinned revision.
SAML replay IDs are inserted in that same transaction. OIDC state is claimed before its
one external code exchange, and final apply rejects a changed revision. A rollback creates
no session, partial mapping, or success audit.

Tenant provider/binding/config/secret/trust/mapping, authentication result, JIT, factor,
policy, session, and revocation events append to tenant audit where they are tenant-owned.
Platform provider, platform login, local account, platform MFA policy, and protected-role
events append to platform audit. Cross-boundary binding actions append correlated events
to both streams. Audit and structured telemetry use allowlisted categories and identifiers;
they exclude raw state/nonce/verifier/code/token/assertion/XML, NameID/subject, claims,
attributes/groups, private/public keys, client secrets, recovery codes, WebAuthn client
data, and upstream error bodies.

Public failures remain non-oracular. Administrative diagnostics can expose stable safe
categories such as `discovery_unreachable`, `issuer_mismatch`, `jwks_invalid`,
`metadata_invalid`, `certificate_expired`, `signature_rejected`, `replay_rejected`,
`identity_collision`, `assurance_insufficient`, and `stale_configuration`, plus a
correlation ID. They never return the rejected value.

### Canonical API and UI expose capabilities without secrets

OpenAPI remains canonical. Provider administration evolves the current LDAP-only
`/api/v1/tenants/{tenantId}/auth-providers` contract into a discriminated provider union
only in an expand/deploy/enable sequence. LDAP wire representations remain one union arm;
new OIDC/SAML rows are not enabled until every serving API and web client understands the
union. Provider reads and every authentication response are `Cache-Control: no-store`.

The initial anonymous/session API surface is:

- a sanitized provider-choice read by tenant login code;
- OIDC start and callback;
- SAML start, ACS, and public provider-specific SP metadata;
- passkey login option and verification endpoints;
- post-primary continuation status/completion/cancellation;
- session-bound step-up start and factor completion;
- self-service MFA device inventory, WebAuthn registration, revoke/rename;
- TOTP replacement and recovery-code regeneration; and
- local session logout/list/revoke with safe provenance/assurance summaries.

Starts, options, completions, and destructive self-service commands are POST/PUT/DELETE,
never state-changing GETs. Ordinary cookie mutations retain exact Origin/CSRF checks.
Protocol callback bodies/queries have endpoint-specific limits and never accept a caller-
supplied redirect URL. Every retry-sensitive creation uses an explicit idempotency key or
one-time ceremony, and mutable administration uses strong ETags with exact `If-Match`.

Tenant administration adds typed OIDC discovery/client/claim/trust configuration; typed
SAML metadata/signature/encryption/attribute/trust configuration; safe discovery/metadata
tests; secret replacement; certificate/SP-key rotation; mapping dry-run; and versioned MFA
policy simulation/publish. Platform administration has a parallel surface plus explicit
tenant-binding operations. A secret is never included in a general provider create/update
body or response.

The login UI requires explicit tenant and provider choice, preserves only a server-
validated relative return path, and presents generic public errors. Administration shows
issuer/entity ID, exact redirect/ACS/entity values to register upstream, safe endpoint and
certificate summaries, expiry/rotation state, and whether a secret exists. It never shows
saved secrets, raw metadata/assertions/tokens/claims, or a generated SAML private key.

Users receive accessible MFA enrollment/challenge/device/session views, one-time recovery
codes with an explicit saved acknowledgement, assurance/source/age summaries, and a clear
warning when upstream logout is not confirmed. Policy UI explains the monotonic effective
result and simulates baseline/role/group combinations before publish. Hiding controls is
advisory; backend use cases and protected database writers recheck every action.

### Workers refresh trust and prune state in bounded classes

The worker owns bounded, fair `FOR UPDATE SKIP LOCKED` classes for:

- OIDC discovery/JWKS and SAML metadata candidate refresh;
- expired/terminal federated transactions, continuations, WebAuthn ceremonies, and MFA
  challenges after their audit/debug retention;
- expired SAML Response/Assertion replay digests only after the maximum accepted validity,
  skew, and safety retention have elapsed;
- superseded metadata/JWKS/SP-key/identity-key revisions only after no live transaction,
  session, ciphertext, or subject alias references them;
- provider/binding/factor/policy changes that proactively revoke affected session families;
  request-time revalidation remains the immediate fail-closed boundary; and
- optional upstream token revocation/logout retries containing only encrypted references,
  bounded attempts, sanitized outcomes, and terminal dead-letter state.

Network fetch and protocol parsing occur outside apply transactions. A worker claims a
job, reads an immutable revision, releases database locks, performs bounded network work,
then applies a candidate only if the provider revision is still exact. An incomplete,
cancelled, truncated, expired, or stale refresh never removes a last-known-good revision or
extends it beyond policy. Tenant jobs never mix tenants in one transaction. Runtime API
roles cannot invoke cleanup or delete replay evidence directly.

### Delivery is expand, verify, and enable one protocol at a time

Federated login and new MFA policy remain feature-disabled until their prerequisites are
current on every serving replica. The exact delivery slices are:

1. **Session/identity compatibility expansion.** Make authenticated email optional in
   Go/OpenAPI/UI; migrate current local session methods into separate primary provenance
   and assurance without changing behavior; generalize recovery sets; add exact security
   revisions and fail-closed readiness.
2. **Federation kernel.** Add separate platform providers, tenant bindings, separate
   external-identity/provenance families, one-time transaction/continuation/replay tables,
   protected writers, RLS/privilege tests, and generic provider union contracts. No SSO
   login is enabled.
3. **MFA policy and step-up kernel.** Add immutable platform/tenant/role/group policy
   versions, exact IdP trust rules, policy simulation, post-primary continuations,
   generalized TOTP/recovery lifecycle, and session-bound step-up. Existing break-glass
   remains usable throughout.
4. **Tenant OIDC administration.** Add typed config/secret actions, safe discovery/JWKS
   snapshots and diagnostics, claim/mapping dry-run, admin UI, SSRF/redaction tests, and
   keyring readiness. Login remains disabled.
5. **Tenant OIDC login.** Enable start/callback, mandatory S256 PKCE, exact token validation,
   JIT/planner apply, MFA trust/continuation, session provenance/revalidation, local logout,
   generated client, and end-to-end replay/collision/isolation tests.
6. **WebAuthn/passkeys.** Add registration, step-up assertion, device lifecycle, counter
   concurrency, recovery repair, and then discoverable passkey primary login after the
   factor/session matrix is green.
7. **Tenant SAML administration.** Add bounded metadata upload/fetch, immutable revisions,
   certificate summaries, SP metadata/key staging, signature/encryption policy, admin UI,
   and adversarial XML/SSRF tests. Login remains disabled.
8. **Tenant SAML login.** Enable signed AuthnRequest/start/ACS, exact consumed-object
   validation, encrypted assertion support, replay/JIT/MFA/session paths, and end-to-end
   corpus. Signed SLO is a following closed sub-slice.
9. **Platform federation and tenant bindings.** Enable platform OIDC/SAML login without
   provider-created platform roles, explicit tenant binding workflows, correlated audit,
   tenant-switch provenance rules, and cross-boundary security tests.
10. **Lifecycle and operations closeout.** Complete local-account disable/enable/password
    rotation, policy-safe recovery administration, optional OIDC token/logout and SAML SLO
    integrations, refresh/cleanup workers, documentation, Compose test IdP, metrics, and
    full acceptance/security matrices.

Each slice updates canonical Drizzle/OpenAPI sources, regenerates artifacts, seals the
exact migration predecessor/current journal, and proves direct Windows gates plus live
PostgreSQL 18 integration. A protocol remains disabled when its subtype, keyring,
metadata/discovery, policy, or session-provenance readiness is incomplete. Old code never
observes a new session/provider kind it cannot parse.

## Compatibility obligations for the current authentication slice

The enabled slices resolve the original compatibility conflicts as follows:

- Go `authentication.User.Email` and OpenAPI `AuthenticatedUser.email` are optional and use
  tenant-effective profile data without inventing an address.
- `auth_sessions.authentication_method` and SessionSummary admit the implemented primary
  methods only after lossless primary-provenance and assurance records exist.
- Pre-JIT federation transactions, post-primary continuations, WebAuthn ceremonies, and
  session-bound step-up use separate typed tables. The legacy non-null TOTP challenge table
  was not widened into a nullable polymorphic family.
- the Strict session cookie and exact Origin/CSRF boundary remain unchanged. OIDC/SAML
  callbacks use their dedicated one-time transaction cookies and protocol correlation;
  no global `SameSite=Lax/None` or callback Origin bypass is introduced.
- `tenant_auth_providers` remains the tenant-owned provider family. Platform providers,
  their tenant admissions, provider-global external identities, tenant-local grants, and
  exact-binding provenance are separate tables and ABIs; a nullable `tenant_id` shortcut
  remains incompatible with this decision.
- platform OIDC/SAML through an explicit tenant binding and direct platform OIDC/SAML are
  executable through physically separate transaction, assurance/provenance, lifecycle,
  replay, key-material, and readiness families.
- platform-provider and binding administration permissions are human-only and explicit.
  Provider claims remain data for admission/profile/assurance evaluation and never become
  a source of platform-role authority or implicit tenant authorization.

## Consequences

### Positive

- OIDC code, SAML response/assertion, WebAuthn assertion, and MFA challenge replays have
  durable one-time boundaries across replicas.
- Cross-site callbacks do not weaken the final Strict cookie or ordinary CSRF policy.
- Exact provider/binding subjects prevent email or username account takeover.
- IdP MFA evidence satisfies policy only when an explicit exact trust rule says so.
- Provider, factor, binding, and policy changes affect live sessions without embedding
  stale authority in cookies.
- SAML signing/encryption and WebAuthn verification use maintained implementations while
  local policy closes mix-up, wrapping, collision, and lifecycle gaps.
- Platform providers remain explicit infrastructure, not implicit tenant or platform
  authority.

### Costs and constraints

- Separate platform/tenant tables, subtype rows, provenance rows, transactions, replay
  caches, policy versions, and key inventories add deliberate schema complexity.
- SameSite-bound one-flow transaction cookies trade multi-tab convenience for login-CSRF
  protection; a new start invalidates the prior browser flow.
- Private IdPs need a deployment egress allowlist, not a tenant bypass.
- SAML metadata/certificate and SP-key rotation require an operational overlap procedure.
- Some legacy IdPs using SHA-1, RSA1_5, CBC-only encryption, unsigned assertions, implicit
  OIDC, or IdP-initiated SSO are intentionally incompatible.
- Continuous upstream revocation is not available for every provider; bounded reauth and
  truthful local-session status remain necessary.

## Alternatives considered

### Reuse the current MFA challenge for every protocol

Rejected. It requires a known User/TOTP before JIT, cannot bind discovery/SAML revisions or
browser returns, and would become a nullable polymorphic state table with weak invariants.

### Link federated logins by verified email

Rejected. Verification establishes control at one issuer, not ownership of an existing
Periapsis User. Email is mutable and provider-local. Deliberate account linking requires
fresh proof of both identities.

### Trust any `amr=mfa` or AuthnContext that sounds strong

Rejected. Providers use different vocabularies and assurance processes. Only an exact
provider/binding rule may translate evidence, and a tenant/action may still require local
step-up.

### Put provider scope, subtype, provenance, and transaction data in JSON

Rejected. Typed separate rows provide RLS, real foreign keys, uniqueness, replay keys,
revision pinning, inventory, and reviewable migration behavior. JSON is limited to bounded
protocol payload parsing before normalization and is never the authority store.

### Rely on the Strict session cookie as OIDC/SAML state

Rejected. It is intentionally absent on cross-site flows, and loosening it would weaken
every application request. Dedicated short-lived transaction cookies and one-time state
preserve both boundaries.

### Accept either a signed SAML Response or Assertion without fixing which object is used

Rejected. Ambiguous signature coverage enables wrapping/substitution errors. The provider
chooses one explicit signature policy, and the adapter consumes exactly the verified
object.

### Store a SAML private key in a deployment-wide unversioned PEM

Rejected. It obscures tenant/provider blast radius, rollout state, readiness, and overlap.
Per-provider server-generated versioned keys are encrypted under the existing external
identity keyring and publish only their certificates.

### Treat WebAuthn as authority or tenant membership

Rejected. It proves control of a credential for an RP/User. Tenant admission, roles,
groups, teams, workflow, and permissions remain independent live backend decisions.

### Call the IdP on every request

Rejected. It makes application availability and latency depend on upstream network I/O,
creates token-handling risk, and still does not provide universal revocation semantics.
Periapsis revalidates local provenance every request and uses explicit bounded upstream
signals where supported.

## Staged verification

The federation kernel must prove forced RLS, runtime privilege denial, platform/tenant
direct-ID isolation, exact subtype/base and provenance cardinality, transaction-cookie and
state/RelayState one-use behavior, revision races, keyring mismatch/readiness, ciphertext
AAD substitution, secret no-readback/redaction, optional-email compatibility, and safe
rolling upgrade before any protocol login is enabled.

OIDC tests cover exact discovery issuer, redirect URI, state/browser binding, nonce, S256
PKCE, single-valued callback parameters, code replay, issuer mix-up, audience/azp, subject
type/cardinality, signature algorithms, JWKS unknown-key refresh/revision restart,
UserInfo-subject equality, clock boundaries, claim bounds, SSRF/DNS rebinding/redirects,
client-secret redaction, concurrent first JIT, no email linking, trust-rule matrices,
provider disablement, and local/upstream logout truthfulness.

SAML tests use an adversarial corpus for DTD/entity/XInclude, decompression/size/depth,
duplicate IDs, signature wrapping, signed-object substitution, unsigned response/assertion
combinations, issuer/audience/destination/recipient/InResponseTo, time/skew, Response and
Assertion replay races, metadata entity/endpoint/certificate rotation, expired/no-overlap
keys, algorithm downgrade, encryption key confusion, unsupported encryption, transient
NameID, attribute cardinality, SLO signature/replay, and cross-tenant binding isolation.

MFA/WebAuthn tests cover exact effective-policy combination across platform/tenant/role/
group/action, IdP trust evidence and age, local-required override, enrollment-grace
restriction, continuation and step-up audience/replay, session rotation, RP ID/origin/
challenge/UV/cross-origin checks, credential/user-handle collision, concurrent counters,
zero-counter behavior, clone suspicion, backup-state changes, device revoke, recovery-code
regeneration/one-use races, and last break-glass recovery preservation.

Session tests prove that no idle touch or authorization occurs before provenance/policy
revalidation; provider/binding/external identity/local credential/factor disablement denies
immediately; tenant-owned federation cannot switch tenants; platform-provider switching
requires an exact target binding; policy increases require step-up; mapping changes do not
leave embedded roles; old session tokens fail after every authentication/step-up/tenant
rotation; and all public errors/caches/logs/audit remain non-oracular and secret-free.
