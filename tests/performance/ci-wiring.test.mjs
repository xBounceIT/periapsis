import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(
  fileURLToPath(new URL("../../", import.meta.url)),
);

async function readRepositoryFile(path) {
  return readFile(resolve(repositoryRoot, path), "utf8");
}

test("performance workflow runs the real gate and always retains evidence", async () => {
  const workflow = await readRepositoryFile(
    ".github/workflows/ticketing-performance.yml",
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /schedule:/);
  assert.match(workflow, /runs-on: ubuntu-24\.04/);
  assert.match(
    workflow,
    /docker build[\s\S]*--file deploy\/performance\/Dockerfile/,
  );
  assert.match(workflow, /docker run --rm --init --stop-timeout 120/);
  assert.match(
    workflow,
    /PERIAPSIS_PERFORMANCE_CI_ACKNOWLEDGEMENT=disposable-container-postgres-18\.6/,
  );
  assert.match(
    workflow,
    /--volume "\$\{GITHUB_WORKSPACE\}\/tmp\/performance:\/workspace\/tmp\/performance"/,
  );
  assert.match(
    workflow,
    /if: \$\{\{ always\(\) \}\}[\s\S]*actions\/upload-artifact@[0-9a-f]{40}/,
  );
  assert.match(workflow, /if-no-files-found: error/);
});

test("performance image pins the exact Node and PostgreSQL runtimes", async () => {
  const dockerfile = await readRepositoryFile("deploy/performance/Dockerfile");
  for (const image of [
    /node:24\.19\.0-alpine3\.23@sha256:[0-9a-f]{64}/,
    /postgres:18\.6-alpine3\.23@sha256:[0-9a-f]{64}/,
    /golang:1\.26\.7-alpine3\.23@sha256:[0-9a-f]{64}/,
  ]) {
    assert.match(dockerfile, image);
  }
  assert.match(
    dockerfile,
    /COPY --from=node-runtime \/usr\/local\/ \/usr\/local\//,
  );
  assert.match(dockerfile, /corepack pnpm install --frozen-lockfile/);
  assert.match(
    dockerfile,
    /go build[\s\S]*-o \/out\/performance-sla \.\/cmd\/performance-sla/u,
  );
  assert.match(
    dockerfile,
    /COPY --from=sla-worker-build \/out\/performance-sla \/usr\/local\/bin\/performance-sla/u,
  );
  assert.match(
    dockerfile,
    /PERIAPSIS_PERFORMANCE_SLA_WORKER=\/usr\/local\/bin\/performance-sla/u,
  );
  assert.match(dockerfile, /node --test tests\/performance\/\*\.test\.mjs/);
  assert.match(
    dockerfile,
    /ENTRYPOINT \["\/workspace\/scripts\/performance\/run-ci-ticketing-hot-paths\.sh"\]/,
  );
});

test("performance entrypoint owns a fresh exact cluster and direct psql", async () => {
  const entrypoint = await readRepositoryFile(
    "scripts/performance/run-ci-ticketing-hot-paths.sh",
  );
  assert.match(
    entrypoint,
    /mktemp -d \/tmp\/periapsis-performance-pg-XXXXXXXXXX/,
  );
  assert.match(entrypoint, /postgres \(PostgreSQL\) 18\.6/);
  assert.match(entrypoint, /su-exec postgres initdb/);
  assert.match(entrypoint, /-A trust/);
  assert.match(entrypoint, /listen_addresses=127\.0\.0\.1/);
  assert.match(entrypoint, /-c timezone=UTC/);
  assert.match(
    entrypoint,
    /PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY="\$data_directory"/,
  );
  assert.match(
    entrypoint,
    /PERIAPSIS_PERFORMANCE_PSQL=\/usr\/local\/bin\/psql/,
  );
  assert.match(
    entrypoint,
    /node scripts\/performance\/run-ticketing-hot-paths\.mjs &/,
  );
  assert.match(entrypoint, /trap 'terminate_gate TERM' TERM/);
  assert.match(entrypoint, /pg_ctl -D "\$data_directory" -m fast -w stop/);
  assert.doesNotMatch(entrypoint, /rm\s+-rf|DROP DATABASE|docker exec/);
});

test("Docker context includes the required performance workflow and excludes local diagnostics", async () => {
  const ignore = (await readRepositoryFile(".dockerignore")).split(/\r?\n/u);
  assert.ok(!ignore.includes(".github"));
  assert.deepEqual(
    ignore.filter((line) => line.includes(".github")),
    [
      ".github/*",
      "!.github/workflows",
      ".github/workflows/*",
      "!.github/workflows/ticketing-performance.yml",
    ],
  );
  for (const excluded of [
    ".tmp",
    ".env",
    ".env.*",
    "**/node_modules",
    "**/tmp",
  ]) {
    assert.ok(ignore.includes(excluded));
  }
});
