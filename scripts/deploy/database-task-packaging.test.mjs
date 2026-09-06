import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  cp,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { validateDatabaseTaskPackaging } from "./validate-manifests.mjs";

const repository = fileURLToPath(new URL("../../", import.meta.url));
const databaseSource = join(repository, "packages/db");
let isolatedRoot;
let databaseRuntime;

before(async () => {
  isolatedRoot = await mkdtemp(join(tmpdir(), "periapsis-db-runtime-test-"));
  databaseRuntime = join(isolatedRoot, "packages/db");
  await mkdir(databaseRuntime, { recursive: true });
  const compilation = runNode(
    [
      join(databaseSource, "node_modules/typescript/bin/tsc"),
      "-p",
      join(databaseSource, "tsconfig.runtime.json"),
      "--outDir",
      databaseRuntime,
    ],
    repository,
  );
  assert.equal(compilation.status, 0, compilation.stderr + compilation.stdout);

  // Reproduce the final Docker COPY layout, without any workspace dependency links.
  await Promise.all(
    ["package.json", "migrations", "seeds/sla-fixture.generated.json"].map(
      (path) =>
        cp(join(databaseSource, path), join(databaseRuntime, path), {
          recursive: true,
        }),
    ),
  );
  await Promise.all(
    ["postgres", "drizzle-orm"].map(async (dependency) =>
      cp(
        await realpath(join(databaseSource, "node_modules", dependency)),
        join(databaseRuntime, "node_modules", dependency),
        { recursive: true, dereference: true },
      ),
    ),
  );
  await Promise.all(
    ["database-task.mjs", "database-task-config.mjs"].map((script) =>
      cp(
        join(repository, "deploy/compose", script),
        join(isolatedRoot, "deploy/compose", script),
      ),
    ),
  );
});

after(async () => {
  if (isolatedRoot !== undefined) {
    await rm(isolatedRoot, { recursive: true, force: true });
  }
});

test("database image keeps production dependencies and exact runtime assets only", async () => {
  const source = await readFile(
    join(repository, "deploy/compose/Dockerfile.database"),
    "utf8",
  );
  assert.deepEqual(validateDatabaseTaskPackaging(source, "database"), []);
  for (const mutated of [
    source.replace("--legacy --prod", "--legacy"),
    source.replace("--config.hoist-workspace-packages=false", ""),
    source.replace("build:runtime", "build"),
    source.replace(
      "/workspace/packages/db/dist/",
      "/workspace/packages/db/src/",
    ),
    source.replace("/workspace/packages/db/migrations/", "/missing/"),
    source.replace(
      "/workspace/packages/db/seeds/sla-fixture.generated.json",
      "/missing/",
    ),
    `${source}\nCOPY --from=build /workspace /workspace\n`,
    `${source}\nCOPY --from=build /out/ /workspace/packages/db/\n`,
  ]) {
    assert.notDeepEqual(validateDatabaseTaskPackaging(mutated, "database"), []);
  }
});

test("compiled entrypoint graph has no TypeScript, test suites, or runtime compiler", async () => {
  const files = [
    ...(await readdir(join(databaseRuntime, "src"), { recursive: true })),
    ...(await readdir(join(databaseRuntime, "seeds"), { recursive: true })),
  ];
  assert.ok(
    files.some((file) => file.replaceAll("\\", "/") === "admin/migrate.js"),
  );
  assert.ok(files.includes("seed.js"));
  assert.ok(
    files.every((file) => !/\.(?:ts|tsx|test\.js|spec\.js)$/u.test(file)),
  );
  assert.deepEqual(
    (await readdir(join(databaseRuntime, "node_modules"))).toSorted(),
    ["drizzle-orm", "postgres"],
  );
  const resolution = runNode([
    "--input-type=module",
    "-e",
    `import assert from 'node:assert/strict';
     import { createRequire } from 'node:module';
     const require = createRequire(new URL('./packages/db/package.json', import.meta.url));
     for (const name of ['tsx/cli', 'typescript', 'esbuild', 'drizzle-kit', 'oxlint', 'vitest']) {
       assert.throws(() => require.resolve(name), { code: 'MODULE_NOT_FOUND' });
     }
     require('postgres');
     await import('./packages/db/src/schema/index.js');`,
  ]);
  assert.equal(resolution.status, 0, resolution.stderr);
});

test("packaged migration journal and every SQL file preserve canonical bytes", async () => {
  const journal = JSON.parse(
    await readFile(
      join(databaseSource, "migrations/meta/_journal.json"),
      "utf8",
    ),
  );
  await Promise.all(
    [
      "meta/_journal.json",
      ...journal.entries.map(({ tag }) => `${tag}.sql`),
    ].map(async (path) => {
      const [packaged, canonical] = await Promise.all([
        readFile(join(databaseRuntime, "migrations", path)),
        readFile(join(databaseSource, "migrations", path)),
      ]);
      assert.deepEqual(packaged, canonical, path);
    }),
  );
  const result = runNode([
    "--input-type=module",
    "-e",
    `import assert from 'node:assert/strict';
     import { createRequire } from 'node:module';
     const require = createRequire(new URL('./packages/db/package.json', import.meta.url));
     const { readMigrationFiles } = require('drizzle-orm/migrator');
     const manifest = await import('./packages/db/src/admin/schema-compatibility-manifest.gen.js');
     const migrations = readMigrationFiles({ migrationsFolder: './packages/db/migrations' });
     assert.equal(migrations.length, manifest.expectedMigrationCount);
     migrations.forEach((migration, index) => assert.equal(migration.hash, manifest.expectedMigrations[index].hash));
     await import('./packages/db/src/admin/schema-migration.js');`,
  ]);
  assert.equal(result.status, 0, result.stderr);
});

test("compiled seed loads its real generated SLA fixture from the adjacent JSON", async () => {
  const result = runNode([
    "--input-type=module",
    "-e",
    `import assert from 'node:assert/strict';
     import { readFileSync } from 'node:fs';
     const fixture = await import('./packages/db/seeds/sla-fixture.js');
     assert.ok(fixture.demoSlaCalendarDocument);
     assert.ok(fixture.demoSlaPolicyDocument);
     assert.ok(JSON.parse(readFileSync('./packages/db/seeds/sla-fixture.generated.json', 'utf8')));`,
  ]);
  assert.equal(result.status, 0, result.stderr);
});

test("Node-only deployment driver retains fail-closed production configuration", async () => {
  const driver = await readFile(
    join(isolatedRoot, "deploy/compose/database-task.mjs"),
    "utf8",
  );
  assert.match(driver, /runDatabaseScript\("src\/admin\/migrate\.js"/u);
  assert.match(driver, /runDatabaseScript\("seeds\/seed\.js"/u);
  assert.doesNotMatch(driver, /tsx|\.ts"/u);
  const result = runNode(["deploy/compose/database-task.mjs"], isolatedRoot, {
    PERIAPSIS_ENV: "production",
  });
  assert.equal(result.status, 1);
  assert.equal(JSON.parse(result.stderr).code, "DATABASE_URL_FILE_REQUIRED");
  assert.equal(result.stdout, "");
});

function runNode(arguments_, cwd = isolatedRoot, overrides = {}) {
  const environment = { ...process.env };
  for (const key of Object.keys(environment)) {
    if (
      /^(?:NODE_PATH|NODE_OPTIONS|DATABASE_URL(?:_FILE)?|PERIAPSIS_.*)$/iu.test(
        key,
      )
    ) {
      delete environment[key];
    }
  }
  return spawnSync(process.execPath, arguments_, {
    cwd: resolve(cwd),
    env: { ...environment, ...overrides },
    encoding: "utf8",
    timeout: 30_000,
    killSignal: "SIGKILL",
    windowsHide: true,
  });
}
