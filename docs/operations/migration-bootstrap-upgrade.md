# Migration, bootstrap, and upgrade runbook

## Preconditions

- Change approval identifies the exact release and immutable image digests.
- Schema/generated drift gates and the previous-release upgrade fixture are green.
- A fresh restore drill has proved the backup that will guard this change.
- Database and object-storage capacity, replication lag, and error budgets are healthy.
- Runtime, migration, and rollback operators have distinct least-privileged access.
- The database is PostgreSQL 18.x, UTF8, with both `LC_COLLATE` and `LC_CTYPE`
  set to `C`. The migration runner rejects any other database before reading or
  applying a migration because compatibility source attestations deliberately bind
  this locale-sensitive catalog surface.
- The API/notifier notification keyring contains every retained ciphertext version and
  both readiness checks can decrypt a controlled canary without exposing plaintext.
- Notification/webhook side effects can be paused without losing the PostgreSQL outbox.

## One-shot migration

Stop rollout if the migration task is not the only schema writer. Capture its task/pod ID,
release, start/end time, and redacted result. The task must finish before new application
replicas receive traffic. Never place migration logic in init containers or application
startup.

Compose waits on its one-shot `migration` service. Swarm starts with zero runtime replicas,
scales `periapsis_migration` to one, and checks the completed task. Kubernetes renders once,
applies foundation plus NetworkPolicies, runs the Job, waits for `Complete`, then applies
runtime resources as documented in `deploy/k8s/README.md`.

The migration runner reads a complete administrator URL from
`PERIAPSIS_DATABASE_ADMIN_URL_FILE`; production startup rejects any URL whose single
`sslmode` is not `verify-full`. The hostname must be covered by the database certificate.
Keep this privileged URL separate from all runtime credentials.

Verify the immutable database locale before a first bootstrap or restore:

```sql
SELECT pg_catalog.pg_encoding_to_char(encoding) AS encoding,
       datcollate, datctype,
       pg_catalog.current_setting('server_version_num')::integer
         AS server_version_num,
       (SELECT role.rolsuper
        FROM pg_catalog.pg_roles AS role
        WHERE role.rolname=CURRENT_USER) AS migration_role_superuser
FROM pg_catalog.pg_database
WHERE datname = pg_catalog.current_database();
```

The only supported result is `UTF8`, `C`, `C`, with `server_version_num` in
`[180000,190000)`. The administrator URL must also authenticate as a
superuser: the V49 sealer owns a private, zero-argument credential-state probe
that reads `pg_authid` and exposes only `absent`, `scram`, or `other` for the
four fixed runtime login roles. It never returns a verifier or password hash.
Create a replacement PostgreSQL 18 cluster with
`initdb --encoding=UTF8 --locale=C` when it differs; PostgreSQL cannot safely change
these database properties in place. Do not bypass the runner's
`MIGRATION_DATABASE_VERSION_UNSUPPORTED` or
`MIGRATION_DATABASE_LOCALE_UNSUPPORTED` failure, or its
`MIGRATION_DATABASE_ADMIN_UNSUPPORTED` sealer check, and do not weaken
historical source hashes.

After migration, verify schema journal/checksums, runtime-role membership, RLS/append-only
audit protections, readiness, and a tenant-isolation smoke test before scaling out.
The one-shot task provisions `periapsis_notifier_login` from its independent password;
the notifier URL must use that exact login. Provision `periapsis_auditor_login` separately
under an approved operational access request; audit export/verification uses its dedicated
bounded operations path and normal application processes must not inherit it.

## First bootstrap

Bootstrap is a single controlled ceremony:

1. Generate the bootstrap token in the secret manager and expose it only to the API file
   mount and the named operator.
2. Bring up one API and one web replica through the canonical HTTPS origin.
3. Enroll the first platform administrator and mandatory TOTP; verify recovery codes are
   stored in the approved offline location.
4. Test login, step-up, session listing/revocation, tenant creation, and audit events.
5. Mark bootstrap complete, rotate the mounted token to a fresh inaccessible tombstone
   value, and roll the API. Production startup requires the file path even after the
   ceremony, so keep the mount but deny operator read access and confirm bootstrap can no
   longer be used.
6. Create a separate recovery administrator before enabling tenant/customer traffic.

Never bootstrap from an ingress bypass, log the token, or keep an emergency account
without MFA.

## Current compatibility handoff

Resolve the current compatibility root from the exact candidate API/worker health source and
the generated migration manifest. Do not copy a version from an older release note: the root
advances whenever a new runtime ABI is sealed. The candidate must name the same root in both
processes, pin every independently owned dependency probe it calls, and match the complete
ordered journal. Older functions may remain as catalog-attested historical evidence, but
application roles must not call them unless the migration explicitly publishes one sealed
immediate-predecessor edge.

Treat an unadvertised or incompatible handoff as a quiesced cutover, not a rolling migration.
The V51 candidate is such a cutover: migrations `0232`/`0233` preserve the published
0000–0231 bytes, repair SAML admission and typed tenant-platform provenance, and seal
the complete 234-entry journal. V50 public runtime roots become retired evidence;
do not pair V50 application images with the V51 database. The repair preserves the
historical variable-conflict, identity-observation, and logout-snapshot amendments,
and rejects a drifted source, owner, signature, search path or execute ACL before
replacing a function. A successful install is not a substitute for the release
acceptance, cross-tenant security and backup/restore gates.

Before starting the migration task, remove traffic, scale web/API/worker/notifier to zero,
and wait for graceful shutdown. Using the administrator connection, close the supported
runtime login gate before checking for residual sessions:

```sql
ALTER ROLE periapsis_api_login NOLOGIN;
ALTER ROLE periapsis_worker_login NOLOGIN;
ALTER ROLE periapsis_notifier_login NOLOGIN;

SELECT pid, usename, state, xact_start
FROM pg_catalog.pg_stat_activity
WHERE usename IN (
  'periapsis_api_login',
  'periapsis_worker_login',
  'periapsis_notifier_login'
)
ORDER BY pid;
```

The query must return no rows. Investigate any residual transaction; after the approved
grace period, terminate only those exact runtime-login backends and repeat the query. Do
not rely on readiness or table locks alone: a predecessor function that entered before its
first table access could otherwise resume its old body after the cutover scan. Keep the
three runtime logins, and any unexpected transitive member of an application writer group,
closed until migration, verification, and sealing all succeed.

The database task restores the API/worker/notifier logins and their reviewed passwords
only after migration and schema sealing both succeed. A failed task deliberately leaves
the roles `NOLOGIN`; do not reopen them or restart an old image unless the approved
restore/forward-fix decision proves that image compatible with the actual database state.

API and worker readiness also require all trusted public subsystem probes named by the
candidate. They attest their exact owner-only private dependencies and the complete tenant,
identity, ticket, SLA, notification, export, audit, and operations surfaces consumed by that
binary. Compare function identity, owner, volatility/security mode, configuration, ACL,
source hash, and dependency catalog shape; a boolean result from an untrusted lookalike is
not readiness.

The migration transaction commits before the runner invokes the separate seal operation.
In that interval the new root still carries `UNSEALED`; current application replicas report
unready, while unsupported older replicas have no runtime projection. This fail-closed
interval is expected and does not guarantee zero downtime. Do not start the application
rollout until the migration job reports successful sealing. If readiness does not recover,
abort and investigate or forward-fix under the approved upgrade procedure rather than
bypassing probes or granting an old function.

## Rolling upgrade

1. Read release/ADR notes and confirm backward compatibility across the entire rolling
   window. Prefer expand/migrate/backfill/contract over destructive schema changes.
2. Backup and record the restore point. Pause release if PITR/archive lag is outside SLO.
3. Run the migration and verification above.
4. Roll API one replica at a time; verify readiness, error rate, latency, authentication,
   and tenant isolation.
5. Roll web, then worker/notifier with one consumer unavailable at a time. Watch outbox
   age, retries, dead letters, LDAP sync leases, and notification delivery.
6. Run acceptance smoke tests and keep the prior images/secrets available until the
   observation window ends.

Rollback application images only when the old release understands the migrated schema.
Do not run an improvised down migration after new writes. If schema compatibility is lost,
stop mutations and execute the approved restore/forward-fix decision with the incident
commander and data owner.
