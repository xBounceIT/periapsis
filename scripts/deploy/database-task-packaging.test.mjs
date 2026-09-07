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
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";

import { validateDatabaseTaskPackaging } from "./validate-manifests.mjs";
import {
  verifyPortableDatabaseArtifact,
  verifyPortableJavaScriptArtifact,
} from "../../deploy/compose/portable-database-artifact.mjs";

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

async function portableFixture(t) {
  const root = await mkdtemp(join(tmpdir(), "periapsis-db-portability-test-"));
  t.after(async () => {
    const owned = relative(resolve(tmpdir()), root);
    assert.ok(
      owned.startsWith("periapsis-db-portability-test-") &&
        !isAbsolute(owned) &&
        !owned.includes(".."),
    );
    await rm(root, { recursive: true, force: true });
  });
  const modules = join(root, "node_modules");
  const compiled = join(root, "dist");
  await mkdir(compiled);
  await writeFile(
    join(compiled, "migrate.js"),
    "export const compiled = true;\n",
  );
  await Promise.all(
    [
      ["@opentelemetry/api", "1.9.1"],
      ["drizzle-orm", "0.45.2"],
      ["postgres", "3.4.9"],
    ].map(async ([name, version]) => {
      const directory = join(modules, name);
      await mkdir(directory, { recursive: true });
      await writeFile(
        join(directory, "package.json"),
        JSON.stringify({ name, version }),
      );
      await writeFile(
        join(directory, "index.js"),
        "export const portable = true;\n",
      );
    }),
  );
  return { root, modules, compiled };
}

test("portability gate accepts exactly the reviewed JavaScript packages and confined relative links", async (t) => {
  const fixture = await portableFixture(t);
  await symlink("postgres", join(fixture.modules, "alias"), "dir");
  assert.deepEqual(
    verifyPortableDatabaseArtifact(fixture.modules, fixture.compiled),
    {
      dependencies: { files: 6, links: 1 },
      compiled: { files: 1, links: 0 },
    },
  );
});

for (const [label, filename, content] of [
  ["renamed ELF", "payload.js", Buffer.from("7f454c4602010100", "hex")],
  ["renamed PE", "payload.json", Buffer.from("4d5a900003000000", "hex")],
  ["renamed Mach-O", "payload.js", Buffer.from("cffaedfe01000000", "hex")],
  ["universal Mach-O", "payload", Buffer.from("cafebabe00000001", "hex")],
  ["WebAssembly", "payload.js", Buffer.from("0061736d01000000", "hex")],
  ["native archive", "payload.js", Buffer.from("!<arch>\n")],
  ["LLVM bitcode", "payload.js", Buffer.from("4243c0de00000000", "hex")],
  ["renamed ZIP", "payload.js", Buffer.from("504b030400000000", "hex")],
  ["renamed gzip", "payload.js", Buffer.from("1f8b080000000000", "hex")],
  ["renamed bzip2", "payload.js", Buffer.from("425a683900000000", "hex")],
  ["renamed XZ", "payload.js", Buffer.from("fd377a585a000000", "hex")],
  ["renamed Zstandard", "payload.js", Buffer.from("28b52ffd00000000", "hex")],
  ["Node addon", "payload.node", "export {};"],
  ["versioned shared library", "payload.so.1", "export {};"],
  ["uppercase DLL", "payload.DLL", "export {};"],
  ["opaque archive", "payload.zip", "opaque"],
]) {
  test(`portability gate rejects ${label} in dependencies and compiled output`, async (t) => {
    await Promise.all(
      ["dependencies", "compiled"].map(async (location) => {
        const fixture = await portableFixture(t);
        const directory =
          location === "dependencies"
            ? join(fixture.modules, "postgres")
            : fixture.compiled;
        await writeFile(join(directory, filename), content);
        assert.throws(
          () =>
            verifyPortableDatabaseArtifact(fixture.modules, fixture.compiled),
          /Native or opaque binary payload|Native artifact extension/u,
        );
        assert.throws(
          () => verifyPortableJavaScriptArtifact(fixture.root),
          /Native or opaque binary payload|Native artifact extension/u,
        );
      }),
    );
  });
}

test("JavaScript artifact gate permits portable scripts and rejects platform restrictions", async (t) => {
  const fixture = await portableFixture(t);
  const manifestPath = join(fixture.modules, "postgres/package.json");
  await writeFile(
    manifestPath,
    JSON.stringify({ name: "portable-cli", version: "1.0.0", bin: "index.js" }),
  );
  assert.ok(verifyPortableJavaScriptArtifact(fixture.root).files > 0);
  for (const key of ["os", "cpu", "libc", "gypfile"]) {
    await writeFile(
      manifestPath,
      JSON.stringify({
        name: "portable-cli",
        version: "1.0.0",
        [key]: "restricted",
      }),
    );
    assert.throws(
      () => verifyPortableJavaScriptArtifact(fixture.root),
      /Platform-specific production package metadata/u,
    );
  }
});

test("portability gate rejects unreviewed versions, packages and platform restrictions", async (t) => {
  await Promise.all(
    [
      { name: "postgres", version: "3.4.10" },
      { name: "unreviewed", version: "3.4.9" },
      ...["os", "cpu", "libc", "gypfile", "bin"].map((key) => ({
        name: "postgres",
        version: "3.4.9",
        [key]: "restricted",
      })),
    ].map(async (manifest) => {
      const fixture = await portableFixture(t);
      await writeFile(
        join(fixture.modules, "postgres/package.json"),
        JSON.stringify(manifest),
      );
      assert.throws(
        () => verifyPortableDatabaseArtifact(fixture.modules, fixture.compiled),
        /Unreviewed production dependency|Platform-specific production package metadata/u,
      );
    }),
  );
});

test("portability gate rejects missing dependencies and files outside reviewed packages", async (t) => {
  const fixture = await portableFixture(t);
  await writeFile(
    join(fixture.modules, "postgres/package.json"),
    JSON.stringify({ type: "module" }),
  );
  assert.throws(
    () => verifyPortableDatabaseArtifact(fixture.modules, fixture.compiled),
    /Expected exactly the three reviewed production packages/u,
  );
  await writeFile(
    join(fixture.modules, "postgres/package.json"),
    JSON.stringify({ name: "postgres", version: "3.4.9" }),
  );
  await writeFile(join(fixture.modules, "unexpected.js"), "export {};");
  assert.throws(
    () => verifyPortableDatabaseArtifact(fixture.modules, fixture.compiled),
    /Unowned production dependency file/u,
  );
});

test("portability gate rejects absolute, escaping, dangling and cyclic artifact links", async (t) => {
  await Promise.all(
    ["absolute", "escaping", "dangling", "cyclic"].map(async (kind) => {
      const fixture = await portableFixture(t);
      const path = join(fixture.modules, "alias");
      const target =
        kind === "absolute"
          ? join(fixture.modules, "postgres")
          : kind === "escaping"
            ? "../dist"
            : kind === "dangling"
              ? "missing"
              : "alias";
      await symlink(target, path, "dir");
      assert.throws(() =>
        verifyPortableDatabaseArtifact(fixture.modules, fixture.compiled),
      );
    }),
  );
});

test("portability gate rejects native artifact names on confined symlinks", async (t) => {
  const fixture = await portableFixture(t);
  await symlink("migrate.js", join(fixture.compiled, "alias.node"), "file");
  assert.throws(
    () => verifyPortableDatabaseArtifact(fixture.modules, fixture.compiled),
    /Native artifact extension/u,
  );
});

test("portability CLI fails closed without printing artifact content", async (t) => {
  const fixture = await portableFixture(t);
  const path = join(fixture.compiled, "bad.node");
  await writeFile(path, "private-canary-never-log");
  const result = runNode(
    [
      join(repository, "deploy/compose/portable-database-artifact.mjs"),
      fixture.modules,
      fixture.compiled,
    ],
    dirname(fixture.root),
  );
  assert.equal(result.status, 1);
  assert.equal(result.stdout, "");
  assert.equal(
    result.stderr,
    "Database artifact portability verification failed.\n",
  );
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
  const envelope = JSON.parse(result.stderr);
  assert.equal(envelope.code, "DATABASE_URL_FILE_REQUIRED");
  assert.equal(envelope.mode, "migrate");
  assert.equal(envelope.phase, "configuration");
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
