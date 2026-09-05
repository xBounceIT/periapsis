import { sql } from "drizzle-orm";
import {
  check,
  pgSchema,
  smallint,
  text,
  timestamp,
  unique,
  uuid,
} from "drizzle-orm/pg-core";

const drizzleInternal = pgSchema("drizzle");

/**
 * Append-only evidence that an exact, supported predecessor journal and its
 * repaired catalog converged to the canonical compatibility surface. The raw
 * predecessor hashes are retained so normalization never erases migration
 * history.
 */
export const migrationConvergenceAttestations = drizzleInternal.table(
  "__periapsis_migration_convergence_attestations",
  {
    attestationId: uuid("attestation_id")
      .primaryKey()
      .default(sql`uuidv7()`),
    convergenceVersion: smallint("convergence_version").notNull(),
    sourceVariant: text("source_variant").notNull(),
    metadataOriginalHash: text("metadata_original_hash").notNull(),
    compatibilityOriginalHash: text("compatibility_original_hash").notNull(),
    rawV45Fingerprint: text("raw_v45_fingerprint").notNull(),
    normalizedV45Fingerprint: text("normalized_v45_fingerprint").notNull(),
    canonicalCatalogDigest: text("canonical_catalog_digest").notNull(),
    attestedAt: timestamp("attested_at", {
      withTimezone: true,
      mode: "date",
    }).notNull(),
  },
  (table) => [
    unique("migration_convergence_version_key").on(table.convergenceVersion),
    check(
      "migration_convergence_version_check",
      sql`${table.convergenceVersion} = 46`,
    ),
    check(
      "migration_convergence_source_variant_check",
      sql`${table.sourceVariant} in ('legacy-v45', 'canonical-v45')`,
    ),
    check(
      "migration_convergence_uuidv7_check",
      sql`(uuid_extract_version(${table.attestationId}) = 7) is true`,
    ),
    check(
      "migration_convergence_hashes_check",
      sql`${table.metadataOriginalHash} ~ '^[0-9a-f]{64}$'
        and ${table.compatibilityOriginalHash} ~ '^[0-9a-f]{64}$'
        and ${table.canonicalCatalogDigest} ~ '^[0-9a-f]{64}$'`,
    ),
    check(
      "migration_convergence_fingerprints_check",
      sql`${table.rawV45Fingerprint} ~ '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){198}$'
        and ${table.normalizedV45Fingerprint} ~ '^[0-9]+@[0-9a-f]{64}(:[0-9]+@[0-9a-f]{64}){198}$'`,
    ),
  ],
);
