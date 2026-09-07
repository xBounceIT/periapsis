import { readFile, readdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

type PackageManifest = {
  scripts: Record<string, string>;
};

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function isUnknownRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function loadManifest(): Promise<PackageManifest> {
  const parsed: unknown = JSON.parse(
    await readFile(resolve(packageRoot, "package.json"), "utf8"),
  );
  if (!isUnknownRecord(parsed)) {
    throw new TypeError("package manifest must be an object");
  }
  const rawScripts = parsed.scripts;
  if (!isUnknownRecord(rawScripts)) {
    throw new TypeError("package manifest scripts must be an object");
  }
  const scripts: Record<string, string> = {};
  for (const [name, command] of Object.entries(rawScripts)) {
    if (typeof command !== "string") {
      throw new TypeError(`package script ${name} must be a string`);
    }
    scripts[name] = command;
  }
  return { scripts };
}

describe("database security script aggregation", () => {
  it("maps every suite exactly once and aggregates only fresh runtime suites", async () => {
    const manifest = await loadManifest();
    const securityFiles = (
      await readdir(resolve(packageRoot, "tests/security"))
    )
      .filter((name) => name.endsWith(".ts"))
      .toSorted();
    const scriptToFile = new Map<string, string>();
    for (const [name, command] of Object.entries(manifest.scripts)) {
      if (!name.startsWith("test:security:") || name === "test:security") {
        continue;
      }
      const match = /^tsx tests\/security\/([^\s]+\.ts)$/u.exec(command);
      expect(
        match,
        `${name} must execute exactly one security suite`,
      ).not.toBeNull();
      scriptToFile.set(name, match?.[1] ?? "");
    }

    for (const file of securityFiles) {
      const mappings = [...scriptToFile].filter(
        ([, mapped]) => mapped === file,
      );
      expect(
        mappings,
        `${file} must have exactly one package script`,
      ).toHaveLength(1);
    }
    expect(
      [...scriptToFile.values()].filter(
        (file) => !securityFiles.includes(file),
      ),
      "security scripts must not point outside the suite inventory",
    ).toEqual([]);

    const aggregate = manifest.scripts["test:security"] ?? "";
    const aggregateScripts = [
      ...aggregate.matchAll(/corepack pnpm run (test:security:[a-z0-9-]+)/gu),
    ].map((match) => match[1] ?? "");
    expect(new Set(aggregateScripts).size).toBe(aggregateScripts.length);
    expect(
      aggregateScripts.filter((script) => !scriptToFile.has(script)),
      "the fresh aggregate must not reference an unmapped security script",
    ).toEqual([]);

    for (const [script, file] of scriptToFile) {
      const occurrences = aggregateScripts.filter(
        (entry) => entry === script,
      ).length;
      if (
        file === "seed-audit.ts" ||
        file === "schema-compatibility-v49-runtime.ts" ||
        file === "schema-compatibility-v50-runtime.ts" ||
        file === "schema-compatibility-v51-runtime.ts" ||
        file === "schema-compatibility-v52-runtime.ts" ||
        file === "schema-compatibility-v53-runtime.ts" ||
        file === "schema-compatibility-v54-runtime.ts" ||
        file === "schema-compatibility-v55-runtime.ts" ||
        file.endsWith("-upgrade.ts")
      ) {
        expect(
          occurrences,
          `${script} must remain outside the fresh runtime aggregate`,
        ).toBe(0);
      } else {
        expect(
          occurrences,
          `${script} must appear exactly once in the fresh runtime aggregate`,
        ).toBe(1);
      }
    }
  });

  it("retains V49/V50/V51 predecessor coverage and runs V56 on its dedicated fresh database", async () => {
    const manifest = await loadManifest();
    const workflow = await readFile(
      resolve(packageRoot, "../../.github/workflows/ci.yml"),
      "utf8",
    );
    const runtime = await readFile(
      resolve(
        packageRoot,
        "tests/security/schema-compatibility-v56-runtime.ts",
      ),
      "utf8",
    );
    expect(manifest.scripts["test:security:schema-compatibility-v49"]).toBe(
      "tsx tests/security/schema-compatibility-v49-runtime.ts",
    );
    expect(
      manifest.scripts["test:security:schema-compatibility-v49-upgrade"],
    ).toBe("tsx tests/security/schema-compatibility-v49-upgrade.ts");
    expect(manifest.scripts["test:security:schema-compatibility-v50"]).toBe(
      "tsx tests/security/schema-compatibility-v50-runtime.ts",
    );
    expect(manifest.scripts["test:security:schema-compatibility-v51"]).toBe(
      "tsx tests/security/schema-compatibility-v51-runtime.ts",
    );
    expect(manifest.scripts["test:security:schema-compatibility-v56"]).toBe(
      "tsx tests/security/schema-compatibility-v56-runtime.ts",
    );
    for (const version of [50, 51, 52, 53]) {
      expect(
        manifest.scripts[
          `test:security:schema-compatibility-v${version}-upgrade`
        ],
      ).toBe(`tsx tests/security/schema-compatibility-v${version}-upgrade.ts`);
      expect(workflow).toContain(
        `script: test:security:schema-compatibility-v${version}-upgrade`,
      );
    }
    expect(workflow).toMatch(
      /script: test:security:schema-compatibility-v49-upgrade\s+database_env: PERIAPSIS_SCHEMA_COMPATIBILITY_V49_UPGRADE_TEST_DATABASE_URL/u,
    );
    expect(runtime).toContain(
      "process.env.PERIAPSIS_SCHEMA_COMPATIBILITY_V56_SECURITY_TEST_DATABASE_URL",
    );
    expect(workflow).toMatch(
      /^\s+PERIAPSIS_SCHEMA_COMPATIBILITY_V56_SECURITY_TEST_DATABASE_URL: postgresql:\/\/[^\r\n]+@127\.0\.0\.1:5432\/periapsis_schema_compatibility_v56\?sslmode=disable$/mu,
    );
    expect(workflow).toMatch(/^\s+periapsis_schema_compatibility_v56 \\$/mu);
  });
});
