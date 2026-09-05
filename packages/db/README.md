# `@periapsis/db`

This package is the canonical PostgreSQL 18 schema for Periapsis. Drizzle owns the table,
constraint, index, relation, role, and RLS definitions. Go/sqlc and every runtime service
consume the committed SQL under `migrations`; they must not maintain a second schema.

## Commands

From the repository root:

```text
pnpm --filter @periapsis/db typecheck
pnpm --filter @periapsis/db test
pnpm --filter @periapsis/db verify:generated
pnpm --filter @periapsis/db db:migrate
pnpm --filter @periapsis/db db:provision
pnpm --filter @periapsis/db db:seed
```

`DATABASE_URL` (or `DATABASE_URL_FILE`) is the bootstrap connection used by migration,
provisioning, and seed commands. The initial migration creates NOLOGIN group roles,
transfers object ownership, and assigns `BYPASSRLS` to `periapsis_migrator`. PostgreSQL
allows only a superuser to assign `BYPASSRLS`; a bootstrap role with only `CREATEROLE` is
not sufficient. On a managed service, have its privileged control-plane role pre-provision
that attribute or run the migration through the provider's superuser-equivalent account.

Keeping `BYPASSRLS` on the NOLOGIN migrator is deliberate: every table uses `FORCE ROW
LEVEL SECURITY`, so table ownership alone cannot perform cross-tenant migrations or the
idempotent seed. Never grant `periapsis_migrator` to a runtime login. The migration command
pins its session `search_path` to `public`, preventing a bootstrap login's personal schema
from receiving unqualified generated DDL.

`db:migrate` is the only supported migration runner. It reserves one database connection
and holds a session advisory lock on that connection until the complete protocol finishes.
Under the lock it first compares every packaged migration filename, journal timestamp, and
SQL hash with the generated external manifest at
`src/admin/schema-compatibility-manifest.gen.ts`. It then reads the existing Drizzle journal
in `(created_at, id)` order and requires every applied timestamp and hash to be the exact
corresponding manifest prefix. A stale bundle or a newer, reordered, or divergent database
journal aborts before Drizzle executes any migration SQL.

After Drizzle applies the remaining migrations, the runner calls the migrator-only
`app.seal_schema_compatibility_manifest(...)` function with the trusted manifest's full
count, latest entry, and ordered fingerprint. That operation validates the completed
journal and, for an explicitly supported immediate-predecessor edge, replaces that
projection's `app.schema_compatibility_fingerprint = 'UNSEALED'` function setting with the
full trusted fingerprint. Migration 0025 seals the v1 predecessor projection, migration
0026 rotates current readiness to v3 and seals v2, and migration 0029 rotates current
readiness to v4, seals the exact v3 predecessor, and retires v2. Migration 0032 rotates
current readiness to v5, seals the exact v4 predecessor, and retires v3. Calling Drizzle's
raw migrator directly bypasses the lock,
preflights, and seal and is unsupported outside explicit staged or negative migration
tests. The command preserves migration and resource-cleanup failures together in chronological
order, and the upgrade gate applies the same rule while restoring deliberately tampered journal
rows and removing staged migration directories.

`db:provision` idempotently creates or rotates the fixed runtime LOGIN roles and grants
each exactly one direct group membership. Provisioning preflights every secret, then uses a
single transaction to revoke every direct membership reported by `pg_auth_members` before
granting the intended NOLOGIN group; stale or future privileged memberships cannot survive a
rotation. Supply passwords through
`PERIAPSIS_{API,WORKER,NOTIFIER,AUDITOR}_DATABASE_PASSWORD_FILE` (preferred) or the
corresponding password variable. Passwords are neither logged nor written to SQL files.
Runtime connection URLs must use `periapsis_api_login`, `periapsis_worker_login`,
`periapsis_notifier_login`, or `periapsis_auditor_login`; a URL naming a NOLOGIN
`periapsis_*` group cannot authenticate.

For local webhook delivery over plain HTTP, provisioning also owns the durable database-side
opt-in for the exact API and notifier login roles. It is disabled by default and in every
production environment. A development database must be provisioned with both
`PERIAPSIS_ENV=development` and `PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL=true`; the API and notifier
must receive the same values. The runtime still supplies a transaction-local intent flag for
each configuration write or claim, so neither the durable opt-in nor a forged session setting
is sufficient by itself. Only `localhost`, `127.0.0.1`, and `::1` are eligible.

The demo seed is idempotent and contains only `.invalid` identities. It creates Acme and
Globex, SOC L1/L2, example tenant roles and contacts, a disabled LDAP provider and mapping,
and an Acme incident slice spanning custom fields, workflows, SLA, notifications, Alert,
Case, IOC, Asset, Evidence metadata, and public/private comments. It creates no
authentication or LDAP bind credential. Authorization initialization is recorded as one
redacted `tenant.authorization.initialized` system event per tenant with `database_seed`
provenance; rerunning the seed does not duplicate demo resources or their audit events.

## Tenant context

Every API transaction must install both settings with `set_config(..., true)` before a
tenant query:

```sql
BEGIN;
SELECT set_config('app.tenant_id', '<authorized-tenant-uuid>', true);
SELECT set_config('app.user_id', '<authenticated-user-uuid>', true);
-- application queries
COMMIT;
```

Missing settings deny access. A tenant ID paired with an actor who has no active
membership also denies access. Connection-pool session settings must never be used;
transaction-local context prevents tenant state from leaking between requests.

## Migrations and tests

- `0000_little_red_shift.sql` is generated from `src/schema` by Drizzle Kit.
- `0001_security_controls.sql` is a Drizzle custom migration for `FORCE ROW LEVEL
SECURITY`, least-privilege grants, ownership, and append-only audit sealing.
- `0002_*` is the generated migration that makes background queue/audit access require
  explicit tenant context and replaces the global audit identity with trigger-assigned
  per-tenant sequence numbers.
- `0003_audit_chain_concurrency.sql` serializes per-tenant sequence assignment and makes
  verification compare the event tail against the protected chain head.
- `0004_uuidv7_fail_closed.sql` replaces every UUIDv7 constraint so a non-RFC UUID whose
  extracted version is `NULL` is rejected and narrows notifier reads to notification events.
- `0005_audit_tail_verification.sql` makes a missing event tail or missing chain head an
  explicit verification failure.
- `0006_audit_attribution.sql` binds API user events to `app.user_id`, requires explicit
  impersonation to name that context user, and prevents background roles from emitting
  user-attributed events.
- `0007_schema_compatibility.sql` exposes the applied migration count, latest
  timestamp/hash, and the colon-joined lowercase migration hashes in exact
  `(created_at, id)` order to API and worker readiness checks through a SECURITY DEFINER
  function; runtime roles cannot read the Drizzle journal directly.
- `0008_phase_2a_auth.sql` is generated from the canonical Drizzle model and adds local
  Argon2id PHC credentials, encrypted TOTP metadata, HMAC-digested recovery codes,
  challenges, opaque-digest sessions, rate-limit state, platform roles, the two-step
  bootstrap reservation, and a tenant-independent platform audit stream.
- `0009_phase_2a_security.sql` forces RLS on those authority tables and exposes only
  bounded SECURITY DEFINER operations. Runtime roles have no direct credential, recovery,
  challenge, session, bootstrap, permission-grant, or audit-chain-head table privileges.
- `0025_authorization_compatibility_and_ownership.sql` restores the Phase 2B.1
  function ABI for rolling replicas, moves the provenance-rich direct-grant inventory to
  explicit v2 functions, binds direct mutation ownership to the canonical manual source,
  and seals the missing existing-tenant RBAC migration audits. It also keeps only the
  exact 25-to-26 migration edge ready for old replicas. The legacy
  `app.schema_compatibility()` projection exposes the verified 0000-0024 prefix only when
  its post-migration seal matches the full trusted 0000-0025 fingerprint. An intact but
  `UNSEALED` 26-row journal, including a runner crash before sealing, leaves legacy replicas
  unready. Current replicas validate the full real journal through
  `app.schema_compatibility_v2()`; v2 readiness is not seal-gated, but deployment must still
  wait for the official migration job to succeed. The forward retirement below closes the
  historical fallback's ability to expose a truncated real journal.
- `0026_schema_compatibility_fail_closed.sql` retires the v1 projection with a constant
  impossible sentinel, rotates current replicas to the full-journal
  `app.schema_compatibility_v3()` projection, and turns v2 into the single sealed 26-to-27
  predecessor edge. V3 binds every ordered journal entry as
  `<created_at>@<lowercase SQL SHA-256>`; changing an interior timestamp therefore changes
  current readiness even when count, order, latest timestamp, and every SQL hash remain the
  same. V2 still returns the exact hash-only 0000-0025 fingerprint required by 0025 binaries,
  but only while the real journal is the complete 27-row timestamp-bound manifest and its
  fingerprint matches the trusted runner seal. An unsealed, truncated, timestamp-drifted,
  hash-drifted, or additional journal returns the impossible sentinel. In particular,
  deleting only 0026 makes v3 expose an incomplete 26-row state that current replicas reject
  while sealed v2 also fails closed instead of reproducing a released ready state.
- `0029_operator_team_readiness_v4.sql` rotates current replicas to the complete 30-row
  `app.schema_compatibility_v4()` projection. V3 exposes the exact timestamp-bound 27-row
  predecessor only while the complete 30-row journal matches the canonical runner seal.
  V2 is explicitly replaced with an impossible sentinel, so only one predecessor release
  remains supported. Raw migration, truncation, interior drift, and extra rows fail closed.
- `0030_operator_team_hardening.sql` is generated from the canonical Drizzle schema and
  adds the tenant-assignment lookup index used by global team lifecycle serialization.
- `0031_operator_team_hardening_security.sql` enforces a duplicate-provenance-safe maximum
  of 200 potentially live exact team epochs per membership across insert and refresh paths,
  makes large assignment-end consequence checks set-based, and binds team/assignment row
  versions to their complete joined HTTP representations. It invalidates pre-hardening
  ETags once, enforces the state-to-team lock order, and exposes only the worker-only
  `app.prune_expired_authorization_commands(integer)` function for independently bounded
  platform and tenant replay-state cleanup.
- `0032_operator_team_readiness_v5.sql` rotates current replicas to the complete 33-row
  `app.schema_compatibility_v5()` projection. V4 exposes the exact timestamp-bound 30-row
  predecessor only while the complete 33-row journal matches the canonical runner seal;
  v3 is an impossible sentinel.
- `0038_service_principal_readiness_v6.sql` introduces the service-principal readiness
  projection, and `0039_service_principal_audit_readiness.sql` advances it to the complete
  40-row journal after a forward-only audit repair. Current API and worker replicas query
  `app.schema_compatibility_v6()`; v5 exposes only the sealed 33-row predecessor. The repair
  records every expired machine-role grant superseded by create, including its identifier
  and prior/result versions.
- `0155_jazzy_felicia_hardy.sql` and `0156_panoramic_blackheart.sql` are generated from
  the canonical Drizzle model and introduce the physically separate platform OIDC/SAML
  provider catalog, subtype, policy, secret, trust, diagnostic, and idempotency rows. The
  administration slice is structurally disabled: provider execution, account mode, and
  platform login cannot be enabled by these migrations.
- `0157_platform_identity_provider_security.sql` exposes the bounded platform-provider
  administration ABI. Runtime roles retain no direct table access; every operation
  rechecks the exact live session permission, validates canonical typed input, couples
  audit to mutation, and returns only a sanitized projection. Create idempotency keeps its
  version-1 receipt while a replay returns the current live projection; HTTP ETags must use
  the projection version. Expired command reuse and opportunistic cleanup are bounded.
- `0158_platform_identity_provider_compatibility.sql` advances current readiness to the
  complete 159-row `app.schema_compatibility_v33()` journal, retains only the exact sealed
  v32 predecessor, and retires v31. Readiness additionally proves the platform provider
  table/helper/function ACL surface and the disabled-only policy state.
- `0159_material_talkback.sql` through
  `0162_tenant_platform_identity_binding_compatibility.sql` introduce the shared
  tenant-login-key reservation plus physically separate platform-provider tenant bindings,
  immutable access epochs, bounded replay, protected lifecycle administration, and the
  historical disabled-only v34 compatibility boundary.
- `0163_workable_hannibal_king.sql` through
  `0165_platform_oidc_binding_runtime.sql` add platform-provider-global external identities
  and subject aliases together with tenant-local access grants, profile contributions,
  OIDC transactions/applications, exact-binding session provenance, assurance evidence,
  and revalidation commands. Lifecycle activation opens one access epoch; deactivation
  closes it and ends provider-owned admission. The runtime ABI applies identity, membership,
  MFA, access, profile, application, session, and audit changes atomically and rolls back the
  entire database subtransaction on denied, stale, or collision outcomes.
- `0166_platform_oidc_binding_readiness.sql` advances current readiness to sealed
  `app.schema_compatibility_v35()` and the trusted public
  `app.tenant_platform_oidc_runtime_schema_readiness_v1()` probe. V34 is retired and has no
  runtime `EXECUTE` grant because the new ABI has no compatible rolling predecessor; the
  migration-to-seal interval is intentionally fail-closed.
- `0167_platform_identity_account_foundation.sql` through
  `0169_platform_identity_account_compatibility.sql` add the private prelink replay ledger,
  provider-global identity-account read/prelink/retire ABI, provider-kind-specific OIDC/SAML
  create boundaries, and sealed `app.schema_compatibility_v36()` plus the exact
  `app.platform_identity_runtime_schema_readiness_v2()` probe. V35 and its runtime probe are
  retired because they do not describe the account-administration surface.
- IDs may be supplied by an application as UUIDv7. Omitted IDs use PostgreSQL 18's core
  `uuidv7()` and are constrained to UUID version 7.
- `tests/security/rls.sql` is the PostgreSQL integration gate. Run it with `psql -X -v
ON_ERROR_STOP=1 -f tests/security/rls.sql` after applying migrations.
- `pnpm --filter @periapsis/db test:security:authorization-upgrade` exercises the
  real 0010 -> 0011 -> 0024 -> 0025 -> 0026 -> 0029 -> 0032 -> 0038 -> 0039 upgrade
  path, retired projections, the sealed v4/v5 predecessors, and the current v6
  compatibility projection. It covers interior timestamp/hash drift, middle and tail
  journal-deletion failure, restore/reseal recovery, pre-hardening ETag invalidation, and
  the sealed legacy audit backfill. Point
  `PERIAPSIS_AUTHORIZATION_UPGRADE_TEST_DATABASE_URL` at an isolated empty PostgreSQL
  18 database in a cluster with no pre-existing `periapsis_*` roles; the test applies
  the complete migration chain and intentionally leaves that database at the current
  schema version for subsequent integration checks.
- `pnpm --filter @periapsis/db test:security:seed-audit` verifies that a freshly migrated
  database seeded twice contains exactly one redacted authorization-initialization event
  for each demo tenant and that both tenant audit chains remain valid. CI runs the required
  migrate -> seed -> seed sequence before invoking the assertion.
- `pnpm --filter @periapsis/db test:security:api-rate-limit` targets a fresh PostgreSQL 18
  database through `PERIAPSIS_API_RATE_LIMIT_TEST_DATABASE_URL`. It proves function-only
  API access, forced RLS/no direct runtime table privileges, exact cross-pool concurrency,
  database-clock retry guidance, aggregate denied-row cleanup, and bounded opportunistic
  retirement of stale high-churn meters for the three API scopes.

The audit trigger serializes each tenant's sequence and chain through an internal head row,
computes a core SHA-256 hash in the database, and blocks update/delete even for the schema
owner. For a `user` event, an API caller must either use its `app.user_id` as
`actor_user_id`, or place that context user in `impersonated_by_user_id` when recording an
effective actor. Worker and notifier roles cannot emit user-attributed events, even if they
set a custom user GUC; non-user events cannot carry either user field. The trigger resolves
an explicit, permission-checked `SET ROLE` before falling back to the fixed session login.
Only `SET ROLE periapsis_migrator` bypasses the API user-context binding, which is why the
trusted seed sets that role before inserting its synthetic audit events.

`app.verify_audit_chain(tenant_id)` validates the stored chain. Tamper evidence does not
replace protected backups or external audit export.

## Local authentication and bootstrap

The local credential table stores only a versioned Argon2id PHC string. TOTP secrets are
encrypted outside PostgreSQL; the database stores ciphertext, nonce, key version, and AAD.
Bootstrap enrollment AAD is the UTF-8 string
`bootstrap_enrollment:<enrollment-id>:email:<canonical-email>`. Confirmation requires the
server to decrypt and validate the reserved secret, then re-encrypt it with final AAD
`totp_credential:<credential-id>:user:<user-id>`. Recovery values and all browser tokens
are stored only as 32-byte keyed-HMAC/SHA-256 digests. Secret keys and raw tokens remain in
the application secret store.

The deployment supplies a 256-bit bootstrap authority token. The API hashes it, derives a
domain-separated 32-byte HKDF verifier from the master key, and passes both values to
`app.verify_protected_configuration(bytea, bytea)`. The first call locks the singleton and
installs both bindings in one transaction; a failure or rollback leaves neither binding.
Later replicas must match both values, and the function returns only whether bootstrap is
still available. The raw key never enters PostgreSQL, no API-callable single-binding
operation exists, and a completed bootstrap row cannot exist without the bound verifier.
A live reservation does not make bootstrap unavailable. Reservation, proof-attempt
exhaustion, canonical email binding,
exactly ten recovery digests, user creation, the sole initial `platform_super_admin`
grant, initial `bootstrap_totp` session, and platform audit event are database-enforced.

Normal MFA completion uses `app.complete_mfa_login(...)`, which consumes the challenge,
advances a TOTP counter or consumes one recovery digest, creates the `totp` or
`recovery_code` session, clears only the challenge-, MFA-user-, and login-account meters
persistently bound to that challenge, and appends its platform audit event in one
statement. Shared network meters are never cleared by one principal. Account and network
rate keys are privacy-preserving digests supplied by the API. Pre-KDF admission meters up
to eight distinct-policy keys atomically; denied aggregate admission removes only sibling
rows introduced by that call. Bootstrap and MFA failure functions update proof-attempt and
database rate-limit state atomically with one redacted audit event. The worker-only
`app.prune_expired_auth_state(integer)` applies a separate bounded batch to expired rate
rows, consumed/expired challenges retained for 24 hours, and wholly dead session families
retained for 30 days. Session idle expiry never exceeds absolute expiry, rotation cannot
extend the original absolute deadline, and selecting an active tenant requires an active
membership.

The generic HTTP limiter deliberately reuses this same sorted, aggregate
`app.admit_auth_attempts(...)` ABI with the purpose-separated `api_network`,
`api_credential`, and `api_tenant_subject` enum scopes. It supplies one-second policy
arrays, so all API replicas serialize against the same PostgreSQL rows and the existing
worker cleanup bounds retention. The API role retains function-only access: no runtime
role receives direct privileges on `auth_rate_limits`. Only 32-byte HMAC digests are
persisted; a tenant meter is keyed by tenant plus credential digest, or tenant plus network
for anonymous requests, never by a tenant-global key.

The platform permission seed is intentionally limited to `platform.tenant.read` and
`platform.tenant.create`; the one bootstrap super-admin role receives both. Platform
tenant listing uses UUIDv7 keyset pagination (`after_id`, bounded `limit + 1`), and tenant
creation rechecks permission and creates the caller's active `tenant_admin` membership in
the same transaction. Active tenant memberships use ascending membership UUIDv7 keysets;
session history keeps the current session first on page one and then uses descending
`(created_at, id)` keysets. Both functions accept at most 101 rows so a repository can
request a 100-row page plus one sentinel without stranding older live sessions or later
memberships.

Platform events never weaken tenant audit rows with a nullable tenant. They use their own
append-only SHA-256 chain and protected head. Pre-authentication failures may have no user
actor; authenticated platform operations carry their user actor. Authentication failure
insertion is coupled to database rate limits, which bound per-key/window contention on the
single Phase 2A platform head. The auditor database role can verify the stream; the API has
no general platform-audit read or write grant.
