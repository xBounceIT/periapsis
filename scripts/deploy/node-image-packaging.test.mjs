import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";

const repositoryRoot = new URL("../../", import.meta.url);
// Verified official multiarchitecture index, including AMD64 and ARM64/v8.
const nodeImage =
  "node:24.20.0-alpine3.23@sha256:0388af2af070cd4736a1567cfed02469ba117848845b4165d87a333edb53d2ca";
const opensslUpgrade =
  "apk add --no-cache --upgrade libcrypto3=3.5.8-r0 libssl3=3.5.8-r0";

async function readSource(path) {
  return readFile(new URL(path, repositoryRoot), "utf8");
}

function stages(source) {
  const result = [];
  for (const instruction of source
    .replace(/\\\r?\n/gu, " ")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))) {
    if (instruction.startsWith("FROM ")) {
      result.push({ from: instruction, instructions: [] });
    } else {
      result.at(-1)?.instructions.push(instruction);
    }
  }
  return result;
}

function assertPatchedNodeStage(stage) {
  const upgradeIndex = stage.instructions.findIndex((instruction) =>
    instruction.startsWith(`RUN ${opensslUpgrade}`),
  );
  assert.ok(upgradeIndex >= 0, `missing exact OpenSSL update: ${stage.from}`);
  const installIndex = stage.instructions.findIndex((instruction) =>
    instruction.includes("pnpm install"),
  );
  if (installIndex >= 0) {
    assert.ok(upgradeIndex < installIndex, "patch before package installation");
  }
  const removalIndex = stage.instructions.findIndex((instruction) =>
    /\brm\b.*\/sbin\/apk/u.test(instruction),
  );
  if (removalIndex >= 0) {
    assert.ok(upgradeIndex < removalIndex, "patch before removing apk");
  }
}

for (const path of [
  "apps/web/Dockerfile",
  "deploy/compose/Dockerfile.database",
  "deploy/images/Dockerfile.notifier",
  "deploy/compose/Dockerfile.minio-provision",
  "deploy/performance/Dockerfile",
]) {
  test(`${path}: Node LTS base has the verified immutable index`, async () => {
    const source = await readSource(path);
    const references = source.match(/node:\S+/gu);
    assert.ok(references?.length > 0);
    for (const reference of references) assert.equal(reference, nodeImage);
  });
}

for (const path of [
  "apps/web/Dockerfile",
  "deploy/compose/Dockerfile.database",
  "deploy/images/Dockerfile.notifier",
  "deploy/compose/Dockerfile.minio-provision",
]) {
  test(`${path}: patch every Node stage before dependency use or apk removal`, async () => {
    const source = await readSource(path);
    const nodeStages = stages(source).filter((stage) =>
      /(?:node:|\$\{NODE_IMAGE\})/u.test(stage.from),
    );
    assert.ok(nodeStages.length > 0);
    for (const stage of nodeStages) {
      assertPatchedNodeStage(stage);
      assert.throws(() =>
        assertPatchedNodeStage({
          ...stage,
          instructions: stage.instructions.map((instruction) =>
            instruction.replace(opensslUpgrade, "apk add --no-cache libssl3"),
          ),
        }),
      );
    }
    assert.ok(stages(source).at(-1).instructions.includes("USER 10001:10001"));
  });
}

test("web builds natively but keeps the runtime target platform and artifact-only copies", async () => {
  const webStages = stages(await readSource("apps/web/Dockerfile"));
  assert.equal(webStages.length, 2);
  assert.equal(
    webStages[0].from,
    `FROM --platform=$BUILDPLATFORM ${nodeImage} AS build`,
  );
  assert.equal(webStages[1].from, `FROM ${nodeImage}`);
  const copies = webStages[1].instructions.filter((instruction) =>
    instruction.startsWith("COPY "),
  );
  assert.deepEqual(copies, [
    "COPY --from=build --chown=10001:10001 /workspace/apps/web/dist ./dist",
    "COPY --from=build --chown=10001:10001 /workspace/apps/web/dist-server ./dist-server",
  ]);
  assert.ok(
    webStages[1].instructions.includes(
      'ENTRYPOINT ["node", "dist-server/index.js"]',
    ),
  );
});

function assertPortableDatabaseStages(databaseStages) {
  assert.equal(databaseStages.length, 2);
  const [builder, runtime] = databaseStages;
  assert.equal(
    builder.from,
    "FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS build",
  );
  assert.equal(runtime.from, "FROM ${NODE_IMAGE}");
  const validator = "deploy/compose/portable-database-artifact.mjs";
  assert.ok(builder.instructions.includes(`COPY ${validator} ${validator}`));
  const build = builder.instructions.find((instruction) =>
    instruction.includes("build:runtime"),
  );
  const exportCommand =
    "corepack pnpm --filter @periapsis/db deploy --legacy --prod --config.hoist-workspace-packages=false /out";
  const validation = `node ${validator} /out/node_modules packages/db/dist`;
  const buildCommands = build.split(/\s*&&\s*/u);
  assert.ok(buildCommands.includes(exportCommand));
  assert.ok(buildCommands.includes(validation));
  assert.equal(
    buildCommands.indexOf(exportCommand) + 1,
    buildCommands.indexOf(validation),
  );
  assert.ok(
    !runtime.instructions.some((instruction) =>
      instruction.includes(validator),
    ),
  );
  assert.deepEqual(
    runtime.instructions.filter((instruction) =>
      instruction.startsWith("COPY "),
    ),
    [
      "COPY --from=build --chown=10001:10001 /out/package.json /workspace/packages/db/package.json",
      "COPY --from=build --chown=10001:10001 /out/node_modules /workspace/packages/db/node_modules",
      "COPY --from=build --chown=10001:10001 /workspace/packages/db/dist/ /workspace/packages/db/",
      "COPY --from=build --chown=10001:10001 /workspace/packages/db/migrations/ /workspace/packages/db/migrations/",
      "COPY --from=build --chown=10001:10001 /workspace/packages/db/seeds/sla-fixture.generated.json /workspace/packages/db/seeds/sla-fixture.generated.json",
      "COPY --from=build --chown=10001:10001 /workspace/deploy/compose/database-task-config.mjs /workspace/deploy/compose/database-task-config.mjs",
      "COPY --from=build --chown=10001:10001 /workspace/deploy/compose/database-task.mjs /workspace/deploy/compose/database-task.mjs",
    ],
  );
}

test("database builds natively only behind a production-artifact portability gate", async () => {
  const source = await readSource("deploy/compose/Dockerfile.database");
  assertPortableDatabaseStages(stages(source));
  for (const mutated of [
    source.replace("--platform=$BUILDPLATFORM ", ""),
    source.replace(
      "\nFROM ${NODE_IMAGE}\n",
      "\nFROM --platform=$BUILDPLATFORM ${NODE_IMAGE}\n",
    ),
    source.replace(
      "&& node deploy/compose/portable-database-artifact.mjs",
      "&& echo deploy/compose/portable-database-artifact.mjs",
    ),
    source.replace("--config.hoist-workspace-packages=false", ""),
    source.replace(
      "/out/node_modules packages/db/dist",
      "/out/node_modules packages/db/dist || true",
    ),
    `${source}\nCOPY --from=build /workspace/deploy/compose/portable-database-artifact.mjs /workspace/validator.mjs\n`,
  ])
    assert.throws(() => assertPortableDatabaseStages(stages(mutated)));
});

test("performance patches its actual PostgreSQL final stage, not the copied Node stage", async () => {
  const performanceStages = stages(
    await readSource("deploy/performance/Dockerfile"),
  );
  const runtime = performanceStages.at(-1);
  assert.equal(runtime.from, "FROM ${POSTGRES_IMAGE}");
  assertPatchedNodeStage(runtime);
  assert.ok(
    runtime.instructions.includes(
      "COPY --from=node-runtime /usr/local/ /usr/local/",
    ),
  );
  assert.ok(runtime.instructions.includes("USER 10001:10001"));
});

test("web server source has no external runtime package imports", async () => {
  const server = new URL("apps/web/server/", repositoryRoot);
  const files = await readdir(server, { recursive: true });
  const sources = files.filter(
    (file) => file.endsWith(".ts") && !file.endsWith(".test.ts"),
  );
  assert.ok(sources.length > 0);
  await Promise.all(
    sources.map(async (file) => {
      const source = await readFile(
        new URL(file.replaceAll("\\", "/"), server),
        "utf8",
      );
      assert.doesNotMatch(
        source,
        /\brequire\s*\(/u,
        `${file}: CommonJS dependency`,
      );
      for (const match of source.matchAll(
        /\b(?:from\s*|import\s*\(\s*|import\s*)["']([^"']+)["']/gu,
      )) {
        assert.ok(
          match[1].startsWith("node:") ||
            match[1].startsWith("./") ||
            match[1].startsWith("../"),
          `${file}: external runtime dependency ${match[1]}`,
        );
      }
    }),
  );
});

test("notifier builds portable production artifacts natively and retains the target runtime", async () => {
  const source = await readSource("deploy/images/Dockerfile.notifier");
  const notifierStages = stages(source);
  assert.equal(
    notifierStages[0].from,
    "FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS build",
  );
  assert.equal(notifierStages[1].from, "FROM ${NODE_IMAGE}");
  const build = notifierStages[0].instructions.find((instruction) =>
    instruction.includes("notifier build"),
  );
  const commands = build.split(/\s*&&\s*/u);
  assert.equal(
    commands[
      commands.indexOf(
        "corepack pnpm --filter @periapsis/notifier deploy --legacy --prod --config.hoist-workspace-packages=false /out",
      ) + 1
    ],
    "node deploy/compose/portable-notifier-artifact.mjs /out",
  );
  assert.ok(
    notifierStages[0].instructions.some((instruction) =>
      instruction.includes(
        "corepack pnpm --filter @periapsis/notifier deploy --legacy --prod --config.hoist-workspace-packages=false /out",
      ),
    ),
  );
  assert.deepEqual(
    notifierStages[1].instructions.filter((instruction) =>
      instruction.startsWith("COPY "),
    ),
    [
      "COPY --from=build --chown=10001:10001 /out/package.json ./package.json",
      "COPY --from=build --chown=10001:10001 /out/node_modules ./node_modules",
      "COPY --from=build --chown=10001:10001 /out/dist ./dist",
    ],
  );
});

test("MinIO provisioner preserves the immutable client and entrypoint", async () => {
  const source = await readSource("deploy/compose/Dockerfile.minio-provision");
  assert.ok(
    source.includes(
      "ARG MC_IMAGE=minio/mc:RELEASE.2025-08-13T08-35-41Z@sha256:a7fe349ef4bd8521fb8497f55c6042871b2ae640607cf99d9bede5e9bdf11727",
    ),
  );
  const runtime = stages(source).at(-1);
  assert.ok(
    runtime.instructions.includes(
      "COPY --from=minio-client --chmod=0555 /usr/bin/mc /usr/local/bin/mc",
    ),
  );
  assert.ok(
    runtime.instructions.includes(
      'ENTRYPOINT ["/usr/local/bin/provision-minio"]',
    ),
  );
});
