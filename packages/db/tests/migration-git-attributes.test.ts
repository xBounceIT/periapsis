import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { expectedMigrations } from "../src/admin/schema-compatibility-manifest.gen.js";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const legacyTag = "0198_v45_compatibility";
const legacyPath = `packages/db/migrations/${legacyTag}.sql`;
const legacyHash =
  "fffd40eb9eb5800fbe63f9e62fa85f960190e2a149e2313ccb66a1d6c78293ea";
const controlPath = "packages/db/migrations/0198_v45_compatibility_control.sql";
const temporaryPrefix = "periapsis-migration-attributes-";
const gitTimeoutMilliseconds = 5_000;

function sha256(value: Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}

function isolatedGitEnvironment(directory: string): NodeJS.ProcessEnv {
  const environment: NodeJS.ProcessEnv = {};
  for (const [name, value] of Object.entries(process.env)) {
    // Inherited GIT_DIR, worktree, index, config, and object-store overrides
    // must never redirect these commands into the caller's repository.
    if (!name.toUpperCase().startsWith("GIT_")) environment[name] = value;
  }
  return {
    ...environment,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: join(directory, "empty-global.gitconfig"),
    GIT_ATTR_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
}

function git(directory: string, args: string[], input?: Buffer): Buffer {
  try {
    return execFileSync("git", args, {
      cwd: directory,
      env: isolatedGitEnvironment(directory),
      encoding: "buffer",
      input,
      timeout: gitTimeoutMilliseconds,
      maxBuffer: 1_048_576,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
    });
  } catch {
    // Git is a required CI prerequisite. Do not skip a missing executable or
    // echo subprocess output, the canonical SQL bytes, or inherited config.
    throw new Error(
      `Isolated git ${args[0]} failed or exceeded ${gitTimeoutMilliseconds}ms`,
    );
  }
}

async function removeOwnedRepository(
  directory: string,
  parent: string,
): Promise<void> {
  const resolved = await realpath(directory);
  const state = await lstat(directory);
  if (
    resolved !== directory ||
    dirname(resolved) !== parent ||
    !basename(resolved).startsWith(temporaryPrefix) ||
    !state.isDirectory() ||
    state.isSymbolicLink()
  ) {
    throw new Error(
      "Refusing cleanup outside the exact owned temporary Git repository",
    );
  }
  await rm(resolved, {
    recursive: true,
    force: false,
    maxRetries: 3,
    retryDelay: 100,
  });
}

function cachedAttributes(
  directory: string,
  paths: string[],
): Map<string, Map<string, string>> {
  const output = git(
    directory,
    ["check-attr", "--cached", "-z", "--stdin", "text", "eol"],
    Buffer.from(`${paths.join("\0")}\0`),
  );
  const fields = output.toString("utf8").split("\0");
  expect(fields.pop()).toBe("");
  expect(fields.length).toBe(paths.length * 6);
  const result = new Map<string, Map<string, string>>();
  for (let index = 0; index < fields.length; index += 3) {
    const path = fields[index]!;
    const attributes = result.get(path) ?? new Map<string, string>();
    expect(attributes.has(fields[index + 1]!)).toBe(false);
    attributes.set(fields[index + 1]!, fields[index + 2]!);
    result.set(path, attributes);
  }
  return result;
}

describe("immutable migration Git attributes", () => {
  it.each(["false", "true", "input"] as const)(
    "preserves only 0198's deployed bytes through index and checkout with core.autocrlf=%s",
    async (autocrlf) => {
      const parent = await realpath(tmpdir());
      const directory = await mkdtemp(join(parent, temporaryPrefix));
      let operationError: unknown;
      let operationFailed = false;
      try {
        const canonical = await readFile(resolve(repositoryRoot, legacyPath));
        const entry = expectedMigrations.find(
          (candidate) => candidate.tag === legacyTag,
        );
        expect(entry?.hash).toBe(legacyHash);
        expect(sha256(canonical)).toBe(legacyHash);
        expect(canonical.toString("utf8").match(/\r\n/gu)).toHaveLength(1);

        await mkdir(join(directory, "packages/db/migrations"), {
          recursive: true,
        });
        await copyFile(
          resolve(repositoryRoot, ".gitattributes"),
          join(directory, ".gitattributes"),
        );
        await copyFile(
          resolve(repositoryRoot, legacyPath),
          join(directory, legacyPath),
        );
        await writeFile(join(directory, "empty-global.gitconfig"), "");
        const controlCRLF = Buffer.from(
          "-- Synthetic newline control\r\nSELECT 1;\r\n",
        );
        const controlLF = Buffer.from(
          "-- Synthetic newline control\nSELECT 1;\n",
        );
        await writeFile(join(directory, controlPath), controlCRLF);

        git(directory, ["init", "--quiet", "--template=", "."]);
        git(directory, ["config", "--local", "core.autocrlf", autocrlf]);
        git(directory, ["config", "--local", "core.safecrlf", "false"]);
        git(directory, [
          "add",
          "--",
          ".gitattributes",
          legacyPath,
          controlPath,
        ]);

        const indexedLegacy = git(directory, ["show", `:${legacyPath}`]);
        expect(sha256(indexedLegacy)).toBe(entry?.hash);
        expect(
          indexedLegacy.equals(canonical),
          "Git index must preserve every historical byte",
        ).toBe(true);
        expect(
          git(directory, ["show", `:${controlPath}`]).equals(controlLF),
          "ordinary SQL must still normalize to LF",
        ).toBe(true);

        const canonicalPaths = expectedMigrations.map(
          (candidate) => `packages/db/migrations/${candidate.tag}.sql`,
        );
        const sameNameElsewhere = `elsewhere/${legacyTag}.sql`;
        const attributes = cachedAttributes(directory, [
          ...canonicalPaths,
          controlPath,
          sameNameElsewhere,
        ]);
        for (const path of [...canonicalPaths, controlPath]) {
          expect(attributes.get(path), path).toEqual(
            new Map([
              ["text", path === legacyPath ? "unset" : "set"],
              ["eol", "lf"],
            ]),
          );
        }
        expect(attributes.get(sameNameElsewhere)).toEqual(
          new Map([
            ["text", "unspecified"],
            ["eol", "unspecified"],
          ]),
        );

        // Exercise checkout conversion too: this is where a clean CI checkout
        // must reproduce the immutable manifest, independently of autocrlf.
        git(directory, ["checkout-index", "--all", "--prefix=checkout/"]);
        const checkedOutLegacy = await readFile(
          join(directory, "checkout", legacyPath),
        );
        expect(sha256(checkedOutLegacy)).toBe(entry?.hash);
        expect(checkedOutLegacy.equals(canonical)).toBe(true);
        expect(
          (await readFile(join(directory, "checkout", controlPath))).equals(
            controlLF,
          ),
        ).toBe(true);
      } catch (error) {
        operationFailed = true;
        operationError = error;
      }
      try {
        await removeOwnedRepository(directory, parent);
      } catch (cleanupError) {
        if (operationFailed) {
          throw new AggregateError(
            [operationError, cleanupError],
            "Git attribute regression and owned cleanup failed",
            { cause: cleanupError },
          );
        }
        throw cleanupError;
      }
      if (operationFailed) throw operationError;
    },
    30_000,
  );
});
