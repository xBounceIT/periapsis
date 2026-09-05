# Backup and restore runbook

Status: bounded evidence/sealing tooling implemented; approved production-boundary drill pending

This runbook restores the complete platform. A shared-schema database, cross-object links,
append-only audit chains, outbox events, and S3 evidence metadata make an ad-hoc single-
tenant SQL restore unsafe. Tenant export/import requires a dedicated authorized product
workflow with provenance; it is not a database operator shortcut.

## Protection set

- PostgreSQL base backups/snapshots plus continuous WAL for point-in-time recovery.
- Database globals needed to recreate reviewed roles and grants, stored encrypted and
  access-controlled separately from application data.
- S3 bucket versioning/inventory and provider backup/replication for attachments/evidence.
- Immutable image digests, migrations, release manifest, and rendered deployment config.
- Secret-manager versions for master/API-credential/identity/notification keyrings and
  dependency credentials. Back them up under a different administrative boundary from
  data.
- Ingress/LDAP trust roots and external IdP configuration metadata, without exporting
  reusable assertions or user passwords.

Set approved RPO/RTO values per environment. A reasonable starting exercise target is a
15-minute RPO and four-hour RTO, but it is not an SLO until capacity tests and owners sign
it. Encrypt backups in transit and at rest, make deletion multi-party, and test retention
and legal-hold behavior.

## Backup verification

Daily automation must verify completion, size/change-rate bounds, encryption/key access,
WAL archive continuity, object inventory, and restore-point age. At least quarterly, restore
into an isolated account/network using credentials that cannot reach production SMTP,
webhooks, LDAP, IdP, or customer object stores.

The drill is successful only when it proves:

- PostgreSQL starts on the supported version and reaches the chosen recovery point;
- schema journal/checksums and generated compatibility gates pass;
- runtime roles lack `BYPASSRLS`, RLS is forced, and audit rows remain update/delete
  protected;
- tenant row counts/foreign keys and sampled object SHA-256 metadata match;
- the audit hash chain verifies from its trusted checkpoint;
- application readiness and a cross-tenant negative test pass;
- outbox/notifier remain paused until the deliberate cutover step.

Record duration, bottlenecks, evidence, and follow-up owners without copying customer data
into the drill report.

### Signed drill evidence

Produce bounded check outputs for schema compatibility, RLS/runtime roles, audit-chain
verification, object inventory, cross-tenant denial, and readiness. Do not export customer
rows, object names, recipients, assertions, credentials, or application payloads as drill
evidence. Use `scripts/operations/recovery-evidence.mjs` to calculate their SHA-256 digests,
enforce the positive acceptance matrix and RPO/RTO, and sign the canonical manifest with a
recovery-only Ed25519 key mounted from the environment's secret system. Verify the pair in
a separate trust domain and retain the manifest, signature, public-key fingerprint, release
manifest, and approval record immutably.

The sealer creates outputs exclusively and will not replace an earlier attestation. A valid
signature protects the report after sealing but does not replace two-person review of the
source evidence or an actual isolated restore. The exact CLI and input contract are in
`scripts/operations/README.md`.

## Restore procedure

1. Declare the incident, freeze writes, pause worker/notifier, and record the last trusted
   database/object/audit timestamps.
2. Select a PostgreSQL recovery point and the corresponding S3 version/inventory. Restoring
   only one side can create dangling or incorrect evidence provenance.
3. Provision a new isolated PostgreSQL 18 target; never restore over the only source copy.
4. Restore base backup/snapshot and replay WAL to the approved point. Restore roles/grants
   through reviewed automation, not a blanket superuser dump.
5. Restore or expose the matching S3 object versions under quarantine. Keep downloads and
   external delivery disabled.
6. Deploy the exact application release compatible with that schema and mount the retained
   keyring versions. Do not migrate until integrity checks complete.
7. Run the verification matrix above. Investigate any audit-chain, RLS, tenant-count, or
   object-hash mismatch before continuing.
8. If approved, apply forward migrations, rotate every credential exposed to the recovery
   team, and enable one API/web replica for an internal smoke test.
9. Cut traffic through DNS/load balancer, then resume worker and notifier while watching
   duplicate/replay-safe outbox behavior.
10. Keep the former environment isolated and immutable until post-incident approval permits
    disposal.

Destructive restore options such as `pg_restore --clean` are allowed only against the
explicitly named isolated target after two-person verification. Use a service file or
password file with restrictive permissions; never put database passwords in command
arguments, URLs saved to history, or logs.

## Failure and compromise cases

If backup encryption or keyring material is unavailable, stop: encrypted provider data may
be unrecoverable and inventing replacement keys will corrupt provenance. If credentials or
the backup system may be compromised, restore into a clean administrative plane, rotate
trust roots before cutover, and treat old artifacts as evidence. If the audit chain fails,
preserve all versions and escalate to security; do not rewrite audit rows to make checks
pass.
