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
      if (file === "seed-audit.ts" || file.endsWith("-upgrade.ts")) {
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
});
