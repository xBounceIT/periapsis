import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import {
  buildRecoveryManifest,
  canonicalJson,
  main,
  sealRecoveryManifest,
  verifyRecoveryEnvelope,
} from "./recovery-evidence.mjs";

const temporaryDirectories = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

test("builds, signs, and verifies a bounded recovery evidence manifest", async () => {
  const fixture = await createFixture();
  const manifest = await buildRecoveryManifest(fixture.input);

  assert.deepEqual(
    manifest.evidence.map(({ label }) => label),
    [
      "audit-chain",
      "cross-tenant",
      "object-inventory",
      "readiness",
      "rls-roles",
      "schema-compatibility",
    ],
  );
  assert.equal(manifest.window.observedRpoSeconds, 300);
  assert.equal(manifest.window.observedRtoSeconds, 1800);
  assert.ok(
    manifest.evidence.every(({ sha256 }) => /^[0-9a-f]{64}$/u.test(sha256)),
  );

  const sealed = sealRecoveryManifest(manifest, fixture.privateKey);
  const verified = verifyRecoveryEnvelope(
    sealed.manifestBytes,
    sealed.envelope,
    fixture.publicKey,
  );
  assert.deepEqual(verified, manifest);
  assert.match(sealed.envelope.keyId, /^sha256:[0-9a-f]{64}$/u);
});

test("fails closed when recovery objectives or required evidence are not proved", async () => {
  const fixture = await createFixture();
  fixture.input.window.maxRpoSeconds = 299;
  await assert.rejects(
    buildRecoveryManifest(fixture.input),
    /exceeds the approved RPO/u,
  );

  const secondFixture = await createFixture();
  secondFixture.input.evidenceFiles = secondFixture.input.evidenceFiles.filter(
    ({ label }) => label !== "cross-tenant",
  );
  await assert.rejects(
    buildRecoveryManifest(secondFixture.input),
    /between 6 and 64 files|required evidence label is missing/u,
  );

  const thirdFixture = await createFixture();
  thirdFixture.input.evidenceFiles[0].path = "relative-evidence.txt";
  await assert.rejects(
    buildRecoveryManifest(thirdFixture.input),
    /path must be absolute/u,
  );
});

test("rejects canonical manifest, signature, and verification-key tampering", async () => {
  const fixture = await createFixture();
  const manifest = await buildRecoveryManifest(fixture.input);
  const sealed = sealRecoveryManifest(manifest, fixture.privateKey);

  const emptyEvidence = structuredClone(manifest);
  emptyEvidence.evidence[0].bytes = 0;
  assert.throws(
    () => sealRecoveryManifest(emptyEvidence, fixture.privateKey),
    /integer range/u,
  );

  const tamperedManifest = structuredClone(manifest);
  tamperedManifest.release.version = "1.0.1";
  assert.throws(
    () =>
      verifyRecoveryEnvelope(
        Buffer.from(canonicalJson(tamperedManifest), "utf8"),
        sealed.envelope,
        fixture.publicKey,
      ),
    /digest mismatch/u,
  );

  const replacement = sealed.envelope.signature.endsWith("A") ? "B" : "A";
  const tamperedEnvelope = {
    ...sealed.envelope,
    signature: `${sealed.envelope.signature.slice(0, -1)}${replacement}`,
  };
  assert.throws(
    () =>
      verifyRecoveryEnvelope(
        sealed.manifestBytes,
        tamperedEnvelope,
        fixture.publicKey,
      ),
    /signature is invalid/u,
  );

  const unrelated = generateKeyPairSync("ed25519").publicKey.export({
    type: "spki",
    format: "pem",
  });
  assert.throws(
    () =>
      verifyRecoveryEnvelope(sealed.manifestBytes, sealed.envelope, unrelated),
    /does not match keyId/u,
  );
});

test("CLI writes a non-overwriting pair and verifies it", async () => {
  const fixture = await createFixture();
  const inputPath = join(fixture.directory, "input.json");
  const privateKeyPath = join(fixture.directory, "private.pem");
  const publicKeyPath = join(fixture.directory, "public.pem");
  const manifestPath = join(fixture.directory, "manifest.json");
  const signaturePath = join(fixture.directory, "manifest.sig.json");
  await writeFile(inputPath, canonicalJson(fixture.input));
  await writeFile(privateKeyPath, fixture.privateKey, { mode: 0o600 });
  await writeFile(publicKeyPath, fixture.publicKey);

  await main([
    "seal",
    "--input",
    inputPath,
    "--private-key",
    privateKeyPath,
    "--manifest",
    manifestPath,
    "--signature",
    signaturePath,
  ]);
  await main([
    "verify",
    "--manifest",
    manifestPath,
    "--signature",
    signaturePath,
    "--public-key",
    publicKeyPath,
  ]);
  assert.equal((await readFile(manifestPath, "utf8")).endsWith("\n"), true);
  await assert.rejects(
    main([
      "seal",
      "--input",
      inputPath,
      "--private-key",
      privateKeyPath,
      "--manifest",
      manifestPath,
      "--signature",
      signaturePath,
    ]),
    /EEXIST/u,
  );
});

test("CLI rejects non-canonical JSON before duplicate keys can be ambiguous", async () => {
  const fixture = await createFixture();
  const inputPath = join(fixture.directory, "ambiguous.json");
  const privateKeyPath = join(fixture.directory, "private.pem");
  const manifestPath = join(fixture.directory, "manifest.json");
  const signaturePath = join(fixture.directory, "manifest.sig.json");
  const ambiguous = `${JSON.stringify(fixture.input).slice(0, -1)},"environment":"shadow"}`;
  await writeFile(inputPath, ambiguous);
  await writeFile(privateKeyPath, fixture.privateKey);

  await assert.rejects(
    main([
      "seal",
      "--input",
      inputPath,
      "--private-key",
      privateKeyPath,
      "--manifest",
      manifestPath,
      "--signature",
      signaturePath,
    ]),
    /canonical JSON/u,
  );
});

async function createFixture() {
  const directory = await mkdtemp(
    join(tmpdir(), "periapsis-recovery-evidence-"),
  );
  temporaryDirectories.push(directory);
  const labels = [
    "schema-compatibility",
    "rls-roles",
    "audit-chain",
    "object-inventory",
    "cross-tenant",
    "readiness",
  ];
  const evidenceFiles = [];
  for (const label of labels) {
    const path = join(directory, `${label}.txt`);
    await writeFile(path, `bounded ${label} evidence\n`);
    evidenceFiles.push({ label, path });
  }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const digest = "a".repeat(64);
  return {
    directory,
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }),
    publicKey: publicKey.export({ type: "spki", format: "pem" }),
    input: {
      drillId: "0198d7f0-37a2-7000-8000-000000000001",
      environment: "recovery-isolated",
      release: {
        version: "1.0.0-rc.1",
        releaseManifestSha256: digest,
        schemaJournalCount: 126,
        latestMigrationSha256: "b".repeat(64),
      },
      window: {
        startedAt: "2026-08-26T08:00:00Z",
        completedAt: "2026-08-26T08:30:00Z",
        incidentCutoffAt: "2026-08-26T07:55:00Z",
        recoveryPointAt: "2026-08-26T07:50:00Z",
        maxRpoSeconds: 900,
        maxRtoSeconds: 14_400,
      },
      database: {
        postgresVersion: "18.6",
        schemaCompatible: true,
        forcedRls: true,
        runtimeRolesBypassRls: false,
        foreignKeysValid: true,
      },
      audit: {
        tenantChainsChecked: 2,
        tenantChainsValid: true,
        platformChainValid: true,
        trustedCheckpointSha256: "c".repeat(64),
      },
      storage: {
        inventorySha256: "d".repeat(64),
        objectCount: 42,
        missingObjects: 0,
        sampledObjectHashesValid: true,
      },
      acceptance: {
        readinessPassed: true,
        crossTenantDenied: true,
        outboxPaused: true,
        workerPaused: true,
        notifierPaused: true,
      },
      evidenceFiles,
    },
  };
}
