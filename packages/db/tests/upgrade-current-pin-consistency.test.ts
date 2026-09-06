import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import * as manifest from "../src/admin/schema-compatibility-manifest.gen.js";

const packageRoot = resolve(import.meta.dirname, "..");

function literalCurrentPinMismatches(source: string): string[] {
  const expected = new Map<string, number>([
    ["expectedMigrationCount", manifest.expectedMigrationCount],
    ["expectedMigrations.length", manifest.expectedMigrationCount],
    ["journal.entries.length", manifest.expectedMigrationCount],
    ["expectedMigrationCreatedAt", manifest.expectedMigrationCreatedAt],
    ["appendedCreatedAt.at(-1)", manifest.expectedMigrationCreatedAt],
  ]);
  const predecessor = /const predecessorIndex\s*=\s*([\d_]+)\s*;/u.exec(source);
  const predecessorIndex = predecessor?.[1];
  if (predecessorIndex !== undefined) {
    expected.set(
      "appendedCreatedAt.length",
      manifest.expectedMigrationCount -
        Number(predecessorIndex.replaceAll("_", "")) -
        1,
    );
  }
  // Only full/current-manifest assertions are selected. Prefix/sliced manifests,
  // historical tags, source hashes, counts and fingerprints remain untouched.
  return [
    ...source.matchAll(
      /assert\.equal\(\s*(expectedMigrationCount|expectedMigrations\.length|journal\.entries\.length|expectedMigrationCreatedAt|appendedCreatedAt\.at\(-1\)|appendedCreatedAt\.length)\s*,\s*([\d_]+)\s*,?\s*\)/gu,
    ),
  ].flatMap((match) => {
    const expression = match[1];
    const literal = match[2];
    assert(expression !== undefined && literal !== undefined);
    const wanted = expected.get(expression);
    assert(wanted !== undefined, `cannot derive current pin ${expression}`);
    const actual = Number(literal.replaceAll("_", ""));
    return actual === wanted ? [] : [`${expression}: ${actual} != ${wanted}`];
  });
}

function upgradeSources(): [string, string][] {
  const value: unknown = JSON.parse(
    readFileSync(resolve(packageRoot, "package.json"), "utf8"),
  );
  assert(value !== null && typeof value === "object" && "scripts" in value);
  const scripts = value.scripts;
  assert(scripts !== null && typeof scripts === "object");
  return Object.entries(scripts)
    .filter(
      ([name]) =>
        name.startsWith("test:security:") && name.endsWith("-upgrade"),
    )
    .map(([name, command]) => {
      assert.equal(typeof command, "string");
      const match = /^tsx (tests\/security\/[a-z0-9-]+-upgrade\.ts)$/u.exec(
        String(command),
      );
      const file = match?.[1];
      assert(
        file !== undefined,
        `upgrade command is not one exact suite: ${name}`,
      );
      return [name, readFileSync(resolve(packageRoot, file), "utf8")];
    });
}

describe("upgrade current-manifest pin consistency", () => {
  it("recomputes the generated current manifest from every canonical migration byte", () => {
    const value: unknown = JSON.parse(
      readFileSync(
        resolve(packageRoot, "migrations/meta/_journal.json"),
        "utf8",
      ),
    );
    assert(
      value !== null &&
        typeof value === "object" &&
        "entries" in value &&
        Array.isArray(value.entries),
    );
    const canonical = value.entries.map((entry: unknown, index: number) => {
      assert(
        entry !== null &&
          typeof entry === "object" &&
          "idx" in entry &&
          "when" in entry &&
          "tag" in entry,
      );
      assert.equal(entry.idx, index);
      assert.equal(typeof entry.when, "number");
      assert.equal(typeof entry.tag, "string");
      const tag = String(entry.tag);
      assert.match(tag, /^\d{4}_[a-z0-9_]+$/u);
      return {
        createdAt: Number(entry.when),
        tag,
        hash: createHash("sha256")
          .update(readFileSync(resolve(packageRoot, `migrations/${tag}.sql`)))
          .digest("hex"),
      };
    });
    expect(canonical).toEqual(manifest.expectedMigrations);
    expect(canonical).toHaveLength(manifest.expectedMigrationCount);
    expect(canonical.at(-1)?.createdAt).toBe(
      manifest.expectedMigrationCreatedAt,
    );
    expect(canonical.at(-1)?.hash).toBe(manifest.expectedMigrationHash);
    expect(
      canonical.map((entry) => `${entry.createdAt}@${entry.hash}`).join(":"),
    ).toBe(manifest.expectedMigrationFingerprint);
  });

  it("keeps all 21 upgrade suites aligned with generated current pins", () => {
    const sources = upgradeSources();
    expect(sources).toHaveLength(21);
    const workflow = readFileSync(
      resolve(packageRoot, "../../.github/workflows/ci.yml"),
      "utf8",
    );
    const problems = sources.flatMap(([name, source]) => {
      expect(workflow).toContain(`script: ${name}`);
      return literalCurrentPinMismatches(source).map(
        (failure) => `${name}: ${failure}`,
      );
    });
    expect(problems).toEqual([]);
  });

  it("distinguishes current drift from intentional immutable historical prefixes", () => {
    expect(
      literalCurrentPinMismatches(`
      const v48MigrationCount = 219;
      const v49MigrationCount = 230;
      const v50Count = 232;
      assert.equal(v49Entries.length, 230);
      assert.equal(predecessor.createdAt, 1788650095675);
      assert.equal(targetEntries.length, 163);
    `),
    ).toEqual([]);
    expect(
      literalCurrentPinMismatches(
        `assert.equal(journal.entries.length, ${manifest.expectedMigrationCount - 2});`,
      ),
    ).toHaveLength(1);
    expect(
      literalCurrentPinMismatches(
        `assert.equal(expectedMigrationCreatedAt, ${manifest.expectedMigrationCreatedAt - 1});`,
      ),
    ).toHaveLength(1);
    expect(
      literalCurrentPinMismatches(`const predecessorIndex = 149;
      assert.equal(appendedCreatedAt.length, ${manifest.expectedMigrationCount - 152});
      assert.equal(appendedCreatedAt.at(-1), ${manifest.expectedMigrationCreatedAt - 1});`),
    ).toHaveLength(2);
  });
});
