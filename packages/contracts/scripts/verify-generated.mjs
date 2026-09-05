import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import {
  changedFiles,
  inventory,
} from "../../../scripts/generated-inventory.mjs";

const packageRoot = resolve(import.meta.dirname, "..");
const repositoryRoot = resolve(packageRoot, "../..");
const targets = [
  "packages/contracts/generated/typescript",
  "services/api/internal/contract/openapi.json",
  "services/api/internal/httpserver/swagger-ui",
];
const before = inventory(repositoryRoot, targets);
const pnpmEntrypoint = process.env["npm_execpath"];

if (pnpmEntrypoint === undefined || pnpmEntrypoint === "") {
  throw new Error("verify-generated must run through pnpm");
}
execFileSync(process.execPath, [pnpmEntrypoint, "run", "generate"], {
  cwd: packageRoot,
  stdio: "inherit",
});

const changed = changedFiles(before, inventory(repositoryRoot, targets));
if (changed.length > 0) {
  process.stderr.write(
    `Contract generated artifacts were stale:\n${changed.map((path) => `- ${path}`).join("\n")}\n`,
  );
  process.exitCode = 1;
}
