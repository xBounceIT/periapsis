import { execFileSync } from "node:child_process";
import { resolve } from "node:path";

import { expect, it } from "vitest";

it("Drizzle's legacy loader uses patched esbuild for sync and async TypeScript", () => {
  // Use the actual pnpm dependency graph in an isolated process. Disabling the
  // legacy adapter cache ensures both calls exercise esbuild without file writes.
  const output = execFileSync(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
        import assert from "node:assert/strict";
        import { createRequire } from "node:module";
        import { resolve } from "node:path";
        import { runInNewContext } from "node:vm";
        const fromDatabase = createRequire(resolve("package.json"));
        const fromDrizzle = createRequire(fromDatabase.resolve("drizzle-kit"));
        const fromLoader = createRequire(fromDrizzle.resolve("@esbuild-kit/esm-loader"));
        const corePath = fromLoader.resolve("@esbuild-kit/core-utils");
        const fromCore = createRequire(corePath);
        const esbuild = fromCore("esbuild");
        const core = fromLoader("@esbuild-kit/core-utils");
        try {
          assert.equal(esbuild.version, "0.25.12");
          const sync = core.transformSync(
            "const answer: number = 42; module.exports = answer;",
            resolve("compat-control.cts"),
          );
          const context = { module: { exports: null } };
          runInNewContext(sync.code, context, { timeout: 1000 });
          assert.equal(context.module.exports, 42);
          assert.ok(JSON.parse(sync.map).sources.length > 0);
          const asynchronous = await core.transform(
            "export const answer: number = 42;",
            resolve("compat-control.mts"),
          );
          const compiledModule = await import(
            "data:text/javascript;base64," + Buffer.from(asynchronous.code).toString("base64")
          );
          assert.equal(compiledModule.answer, 42);
          assert.ok(JSON.parse(asynchronous.map).sources.length > 0);
          process.stdout.write(JSON.stringify({ version: esbuild.version, sync: context.module.exports, async: compiledModule.answer }));
        } finally {
          esbuild.stop();
        }
      `,
    ],
    {
      cwd: resolve(import.meta.dirname, ".."),
      encoding: "utf8",
      env: { ...process.env, ESBK_DISABLE_CACHE: "1" },
      maxBuffer: 64 * 1024,
      timeout: 10_000,
    },
  );
  expect(JSON.parse(output)).toEqual({
    version: "0.25.12",
    sync: 42,
    async: 42,
  });
});
