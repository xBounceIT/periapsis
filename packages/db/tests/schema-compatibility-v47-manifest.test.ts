import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import * as manifest from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const generatedGoManifests = [
  "services/api/internal/postgres/schema_compatibility.gen.go",
  "services/worker/internal/postgres/schema_compatibility.gen.go",
].map((fileName) => readFileSync(resolve(repositoryRoot, fileName), "utf8"));

const v48SealMigrationCount = 219;
const v48SealCreatedAt = 1_788_276_517_454;
const v48SealHash =
  "d6a20868f2707d3ff199cccbb2f6c1afc66d068f8f9bc41660482c010317a50a";

const expectedV47SourceHashes = {
  expectedSchemaCompatibilityV47SourceHash:
    "35c5dff8868de5bb4b8c3a3575c06affd3fd324e24945d918e9d9972d7ee331c",
  expectedRetiredSchemaCompatibilityV46SourceHash:
    "28dc94abe60616891370da8e3a446625b772d3f67e599df5eb35cb63013f566b",
  expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash:
    "2d4deb80aead72791a25321f048fdebb4d13e5fea2c621df0cf42b9ebf5de4c9",
  expectedPrivateSchemaCompatibilityJournalV47SourceHash:
    "2e791f4971aee4243998a655be19e84be3c522ce959a0048f8e7eee71057d580",
  expectedPrivatePlatformIdentityDependencySurfaceHashV13SourceHash:
    "a90fe9d78c3bce7bffc47a71cb01ec3b83161dedc4adf3fee6839fa63c9a2394",
  expectedPrivatePlatformIdentityRuntimeReadinessV13SourceHash:
    "dee7c12d79449547e3f455af1386024d6e0edc9e0b048475fa6f465295e01291",
  expectedPlatformIdentityRuntimeReadinessV13SourceHash:
    "9ff76e5357336d099891a241d34c1d2a15cd5b6e79ecaf53a10697d50c843561",
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV9SourceHash:
    "c3114e78f9d6fc728f0884187aaeedfc48dbbf78ec83bd36746a8c9b74b52d0f",
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV9SourceHash:
    "187714eab6ee82e106bdebf7403f47f333795fc2788605c1fcca8ca06dca2806",
  expectedPlatformOIDCDirectRuntimeReadinessV9SourceHash:
    "d9c2298a517a341cbc6aefa49b8a3b080e8cf92154da1fb6ecad5b73b73edfcb",
  expectedPrivatePlatformSAMLDirectDependencySurfaceHashV6SourceHash:
    "c3114e78f9d6fc728f0884187aaeedfc48dbbf78ec83bd36746a8c9b74b52d0f",
  expectedPrivatePlatformSAMLDirectRuntimeReadinessV6SourceHash:
    "fa4bfa984cf400786f783b4730035e2b59130ad843f47b7e70e64c9ba6315bcf",
  expectedPlatformSAMLDirectRuntimeReadinessV6SourceHash:
    "945a1fc803e1c855a6863192a50ef6a4edecdcdd86ed70b7da54d0e8f27d6537",
  expectedPrivateMFAPolicyAdministrationDependencySurfaceHashV7SourceHash:
    "c3114e78f9d6fc728f0884187aaeedfc48dbbf78ec83bd36746a8c9b74b52d0f",
  expectedPrivateMFAPolicyAdministrationReadinessV7SourceHash:
    "f2dc80445f4eca3f13bdc63e8c314cf242046fd3424637687bd48b8cfb49eb79",
  expectedMFAPolicyAdministrationReadinessV7SourceHash:
    "8c1b31d6a19ca0b41b8b449171dffa2e36757f52be2403a24bfa49f41a2d1a16",
  expectedTicketMutationRuntimeReadinessV2SourceHash:
    "d0612cd5e47bb4c7a8d67b661ad1866cf870a8038287783e81e61eb5d6789f4b",
  expectedTicketWatcherRuntimeReadinessV2SourceHash:
    "9258a917d7e445410b0ea9c38e8dc7d4ca0bdc0918fd31b3de1df596041c100f",
  expectedTicketBulkRuntimeReadinessV2SourceHash:
    "0d7e684287d8bfd452e824b2cf4543861b291dc09a272db57d5eb905d03515b4",
  expectedTicketExportRuntimeReadinessV2SourceHash:
    "713f1f638f1cc0d164b340dca8b8db7456e67c89f855152d1d315a5fdc05b356",
  expectedContactsPortalSchemaReadinessV2SourceHash:
    "b6e1888dd265344bd018ecbba74e551b4d1928165fa996de44d0cca1e415414d",
  expectedSLAObjectEventIngressSchemaReadinessV1SourceHash:
    "7bfb6de934804e1c688a3a44094abbcff0a84580987309fbdeff17f0b45e8d9e",
  expectedNotificationSchemaReadinessV4SourceHash:
    "efaddc8a37603a1794e4567301c101d54e9b9854f143675495a4474f9640b8ea",
  expectedTenantLDAPInteractiveAuthSchemaReadinessV1SourceHash:
    "a69c71e1eaf4522420d43c119df48a708f7bf4ca5302b8d12981be31c8628c5b",
} satisfies Partial<Record<keyof typeof manifest, string>>;

const actualV47SourceHashes = {
  expectedSchemaCompatibilityV47SourceHash:
    manifest.expectedSchemaCompatibilityV47SourceHash,
  expectedRetiredSchemaCompatibilityV46SourceHash:
    manifest.expectedRetiredSchemaCompatibilityV46SourceHash,
  expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash:
    manifest.expectedPrivateV47MigrationConvergenceSchemaReadinessV1SourceHash,
  expectedPrivateSchemaCompatibilityJournalV47SourceHash:
    manifest.expectedPrivateSchemaCompatibilityJournalV47SourceHash,
  expectedPrivatePlatformIdentityDependencySurfaceHashV13SourceHash:
    manifest.expectedPrivatePlatformIdentityDependencySurfaceHashV13SourceHash,
  expectedPrivatePlatformIdentityRuntimeReadinessV13SourceHash:
    manifest.expectedPrivatePlatformIdentityRuntimeReadinessV13SourceHash,
  expectedPlatformIdentityRuntimeReadinessV13SourceHash:
    manifest.expectedPlatformIdentityRuntimeReadinessV13SourceHash,
  expectedPrivatePlatformOIDCDirectDependencySurfaceHashV9SourceHash:
    manifest.expectedPrivatePlatformOIDCDirectDependencySurfaceHashV9SourceHash,
  expectedPrivatePlatformOIDCDirectRuntimeReadinessV9SourceHash:
    manifest.expectedPrivatePlatformOIDCDirectRuntimeReadinessV9SourceHash,
  expectedPlatformOIDCDirectRuntimeReadinessV9SourceHash:
    manifest.expectedPlatformOIDCDirectRuntimeReadinessV9SourceHash,
  expectedPrivatePlatformSAMLDirectDependencySurfaceHashV6SourceHash:
    manifest.expectedPrivatePlatformSAMLDirectDependencySurfaceHashV6SourceHash,
  expectedPrivatePlatformSAMLDirectRuntimeReadinessV6SourceHash:
    manifest.expectedPrivatePlatformSAMLDirectRuntimeReadinessV6SourceHash,
  expectedPlatformSAMLDirectRuntimeReadinessV6SourceHash:
    manifest.expectedPlatformSAMLDirectRuntimeReadinessV6SourceHash,
  expectedPrivateMFAPolicyAdministrationDependencySurfaceHashV7SourceHash:
    manifest.expectedPrivateMFAPolicyAdministrationDependencySurfaceHashV7SourceHash,
  expectedPrivateMFAPolicyAdministrationReadinessV7SourceHash:
    manifest.expectedPrivateMFAPolicyAdministrationReadinessV7SourceHash,
  expectedMFAPolicyAdministrationReadinessV7SourceHash:
    manifest.expectedMFAPolicyAdministrationReadinessV7SourceHash,
  expectedTicketMutationRuntimeReadinessV2SourceHash:
    manifest.expectedTicketMutationRuntimeReadinessV2SourceHash,
  expectedTicketWatcherRuntimeReadinessV2SourceHash:
    manifest.expectedTicketWatcherRuntimeReadinessV2SourceHash,
  expectedTicketBulkRuntimeReadinessV2SourceHash:
    manifest.expectedTicketBulkRuntimeReadinessV2SourceHash,
  expectedTicketExportRuntimeReadinessV2SourceHash:
    manifest.expectedTicketExportRuntimeReadinessV2SourceHash,
  expectedContactsPortalSchemaReadinessV2SourceHash:
    manifest.expectedContactsPortalSchemaReadinessV2SourceHash,
  expectedSLAObjectEventIngressSchemaReadinessV1SourceHash:
    manifest.expectedSLAObjectEventIngressSchemaReadinessV1SourceHash,
  expectedNotificationSchemaReadinessV4SourceHash:
    manifest.expectedNotificationSchemaReadinessV4SourceHash,
  expectedTenantLDAPInteractiveAuthSchemaReadinessV1SourceHash:
    manifest.expectedTenantLDAPInteractiveAuthSchemaReadinessV1SourceHash,
} satisfies Record<keyof typeof expectedV47SourceHashes, string>;

describe("schema compatibility V47 manifest", () => {
  it("preserves V47 inside the immutable V48 seal prefix", () => {
    const v48Prefix = manifest.expectedMigrations.slice(
      0,
      v48SealMigrationCount,
    );

    expect(manifest.expectedMigrations.length).toBeGreaterThanOrEqual(
      v48SealMigrationCount,
    );
    expect(v48Prefix).toHaveLength(v48SealMigrationCount);
    expect(manifest.expectedMigrations[208]).toMatchObject({
      tag: "0208_v47_compatibility",
      createdAt: 1788275200000,
    });
    expect(manifest.expectedMigrations[208]?.hash).toMatch(/^[0-9a-f]{64}$/u);
    expect(v48Prefix.at(-1)).toEqual({
      tag: "0218_v48_compatibility",
      createdAt: v48SealCreatedAt,
      hash: v48SealHash,
    });
  });

  it("matches every V47 runtime root and both Go manifests", () => {
    expect(actualV47SourceHashes).toEqual(expectedV47SourceHashes);
    for (const [constant, expectedHash] of Object.entries(
      expectedV47SourceHashes,
    )) {
      for (const generatedGoManifest of generatedGoManifests) {
        expect(generatedGoManifest).toContain(
          `const ${constant} = ${JSON.stringify(expectedHash)}`,
        );
      }
    }
  });

  it("preserves the exact V46 predecessor pins used by the V47 derivations", () => {
    expect(
      manifest.expectedPrivatePlatformIdentityRuntimeReadinessV12SourceHash,
    ).toBe("f144de3c10a170e3bedf6c40a428ede8813322366fc944e32b84a44e0becf9a3");
    expect(
      manifest.expectedPrivatePlatformOIDCDirectRuntimeReadinessV8SourceHash,
    ).toBe("1c8e651bd145350b4788c9f74e12651aa729e112975f1bb1721f7d5fa8763764");
    expect(
      manifest.expectedPrivatePlatformSAMLDirectRuntimeReadinessV5SourceHash,
    ).toBe("6c48a1da606dcfd1d06fa351ec505ee4de5f71c9e86b06cc7c47e66b184d25f0");
    expect(
      manifest.expectedPrivateMFAPolicyAdministrationReadinessV6SourceHash,
    ).toBe("e2e054209aed0eeb65634f78465955efef0631e34615212738b3d7b9d121b8c9");
  });
});
