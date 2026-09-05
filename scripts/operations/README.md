# Recovery evidence tooling

`recovery-evidence.mjs` seals the bounded results of an isolated restore drill with an
Ed25519 key and verifies the resulting manifest offline. It never embeds the evidence
files or their local paths: the signed manifest contains only allowlisted drill facts,
file labels, byte counts, and SHA-256 digests.

The tool is deliberately fail-closed. It refuses a manifest unless PostgreSQL 18, schema
compatibility, forced RLS, runtime-role restrictions, foreign keys, tenant and platform
audit chains, object inventory, readiness, cross-tenant denial, and paused asynchronous
delivery are all positively attested. It also calculates the observed RPO/RTO and rejects
an exceeded objective. Required evidence labels are:

- `schema-compatibility`
- `rls-roles`
- `audit-chain`
- `object-inventory`
- `cross-tenant`
- `readiness`

Prepare canonical JSON (object keys sorted, one trailing newline, no duplicate fields) with
the strict shape exercised in `recovery-evidence.test.mjs`. Every `evidenceFiles[].path`
is absolute and points to a bounded, non-empty file created by the corresponding drill
check; paths are omitted from the output. The file is hashed through one stable open handle
and rejected if it changes during the read. Then seal it using a private key supplied
through the recovery environment's secret mount:

```text
node scripts/operations/recovery-evidence.mjs seal \
  --input C:/recovery/drill-input.json \
  --private-key C:/run/secrets/recovery-evidence-ed25519.pem \
  --manifest C:/recovery/drill-manifest.json \
  --signature C:/recovery/drill-manifest.sig.json
```

Outputs are created with exclusive semantics and are never overwritten. Verify them in a
separate trust domain with only the public key:

```text
node scripts/operations/recovery-evidence.mjs verify \
  --manifest C:/recovery/drill-manifest.json \
  --signature C:/recovery/drill-manifest.sig.json \
  --public-key C:/recovery/recovery-evidence-ed25519.pub.pem
```

Store the public-key fingerprint and signed manifest in the approved immutable retention
system. A valid signature proves manifest integrity and signer identity; it does not make
untrusted source evidence truthful. Generate evidence in an isolated network, review it
under two-person control, keep signing keys outside the repository, and never include
customer payloads, credentials, assertions, email content, or evidence metadata in the
input or attached reports.

Run the dependency-free test with:

```text
node --test scripts/operations/recovery-evidence.test.mjs
```
