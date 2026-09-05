import { execFileSync } from "node:child_process";
import {
  cp,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

const repositoryRoot = resolve(import.meta.dirname, "..");
const apiRoot = resolve(repositoryRoot, "services/api");
const canonicalMigrations = resolve(repositoryRoot, "packages/db/migrations");
const canonicalConfig = resolve(apiRoot, "sqlc.yaml");
const canonicalQueries = resolve(apiRoot, "internal/postgres/queries");
const generatedOutput = resolve(apiRoot, "internal/postgres/dbsql");
const scratchRoot = await mkdtemp(resolve(tmpdir(), "periapsis-sqlc-"));
const scratchMigrations = resolve(scratchRoot, "migrations");
const scratchQueries = resolve(scratchRoot, "queries");
const scratchOutput = resolve(scratchRoot, "dbsql");
const scratchConfig = resolve(scratchRoot, "sqlc.yaml");

// sqlc v1.31 does not update its function catalog for ALTER FUNCTION ...
// RENAME. Migration 0103 predates the repository convention that follows a
// runtime rename with a parser-only DROP, so sqlc otherwise sees the successor
// CREATE as a duplicate. Patch only a disposable schema copy: the canonical
// migration remains byte-for-byte identical and PostgreSQL never executes this
// compatibility statement.
const auditCompatibilityMigration = "0103_crazy_scarlet_witch.sql";
const renameAnchor = `ALTER FUNCTION app.seed_tenant_authorization(uuid, uuid)
  RENAME TO seed_tenant_authorization_audit_compatibility_impl;
--> statement-breakpoint`;
const parserCompatibilityDrop = `DROP FUNCTION IF EXISTS app.seed_tenant_authorization(uuid, uuid);
--> statement-breakpoint`;

function replaceExactlyOnce(source, needle, replacement, label) {
  const first = source.indexOf(needle);
  if (first < 0 || source.indexOf(needle, first + needle.length) >= 0) {
    throw new Error(`Expected exactly one ${label}`);
  }
  return `${source.slice(0, first)}${replacement}${source.slice(first + needle.length)}`;
}

// sqlc also misses later ALTER FUNCTION ... RENAME transitions. PostgreSQL
// removes the old signature from the catalog during the rename, whereas sqlc
// incorrectly keeps it and rejects the successor CREATE. Add parser-only
// drops to every disposable migration copy so new compatibility wrappers do
// not require one-off generator patches.
function addParserDropsAfterFunctionRenames(source) {
  const renamePattern =
    /ALTER FUNCTION\s+([A-Za-z0-9_".]+\s*\([^;]*?\))\s+RENAME TO\s+[A-Za-z0-9_"]+\s*;/g;
  return source.replace(
    renamePattern,
    (statement, originalSignature) =>
      `${statement}\nDROP FUNCTION IF EXISTS ${originalSignature};`,
  );
}

try {
  await Promise.all([
    cp(canonicalMigrations, scratchMigrations, { recursive: true }),
    cp(canonicalQueries, scratchQueries, { recursive: true }),
  ]);

  const compatibilityPath = resolve(
    scratchMigrations,
    auditCompatibilityMigration,
  );
  const compatibilitySource = await readFile(compatibilityPath, "utf8");
  const patchedCompatibilitySource = replaceExactlyOnce(
    compatibilitySource,
    renameAnchor,
    `${renameAnchor}\n${parserCompatibilityDrop}`,
    `${auditCompatibilityMigration} sqlc rename anchor`,
  );
  await writeFile(compatibilityPath, patchedCompatibilitySource, "utf8");

  const scratchMigrationNames = await readdir(scratchMigrations);
  await Promise.all(
    scratchMigrationNames
      .filter((name) => name.endsWith(".sql"))
      .map(async (name) => {
        const path = resolve(scratchMigrations, name);
        const source = await readFile(path, "utf8");
        const patched = addParserDropsAfterFunctionRenames(source);
        if (patched !== source) {
          await writeFile(path, patched, "utf8");
        }
      }),
  );

  let configSource = await readFile(canonicalConfig, "utf8");
  configSource = replaceExactlyOnce(
    configSource,
    "      - ../../packages/db/migrations",
    "      - migrations",
    "sqlc schema path",
  );
  configSource = replaceExactlyOnce(
    configSource,
    "      - internal/postgres/queries",
    "      - queries",
    "sqlc query path",
  );
  configSource = replaceExactlyOnce(
    configSource,
    "        out: internal/postgres/dbsql",
    "        out: dbsql",
    "sqlc output path",
  );
  await writeFile(scratchConfig, configSource, "utf8");

  execFileSync(
    "go",
    [
      "run",
      "github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1",
      "generate",
      "-f",
      scratchConfig,
    ],
    { cwd: apiRoot, stdio: "inherit" },
  );

  const generatedFiles = await readdir(scratchOutput);
  if (
    !generatedFiles.includes("db.go") ||
    !generatedFiles.includes("models.go") ||
    generatedFiles.some((name) => !name.endsWith(".go"))
  ) {
    throw new Error(
      "sqlc produced an incomplete or unexpected output inventory",
    );
  }

  await rm(generatedOutput, { force: true, recursive: true });
  await cp(scratchOutput, generatedOutput, { recursive: true });
} finally {
  await rm(scratchRoot, { force: true, recursive: true });
}
