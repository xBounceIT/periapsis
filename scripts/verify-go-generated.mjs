import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import { changedFiles, inventory } from "./generated-inventory.mjs";

const repositoryRoot = resolve(import.meta.dirname, "..");
const targets = [
  "packages/db/src/admin/schema-compatibility-manifest.gen.ts",
  "services/api/internal/contract/api.gen.go",
  "services/api/internal/postgres/dbsql",
  "services/api/internal/postgres/schema_compatibility.gen.go",
  "services/notifier/src/schema-compatibility.gen.ts",
  "services/worker/internal/postgres/schema_compatibility.gen.go",
];
const before = inventory(repositoryRoot, targets);

execFileSync(process.execPath, ["scripts/generate-schema-compatibility.mjs"], {
  cwd: repositoryRoot,
  stdio: "inherit",
});

execFileSync("go", ["generate", "./services/api/..."], {
  cwd: repositoryRoot,
  stdio: "inherit",
});

const changed = changedFiles(before, inventory(repositoryRoot, targets));
if (changed.length > 0) {
  process.stderr.write(
    `Generated application artifacts were stale:\n${changed.map((path) => `- ${path}`).join("\n")}\n`,
  );
  process.exitCode = 1;
}
