import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { NotificationValidationError } from "./errors.js";
import { FileSecretResolver } from "./secrets.js";

describe("file secret resolver", () => {
  const roots: string[] = [];

  afterEach(async () => {
    await Promise.all(
      roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
    );
  });

  it("reads a bounded regular file and strips one mount newline", async () => {
    const root = await temporaryRoot();
    await writeFile(join(root, "smtp.password"), "secret-value\n", {
      encoding: "utf8",
    });
    const resolver = await FileSecretResolver.create(root);
    const first = await resolver.read(
      "smtp.password",
      new AbortController().signal,
    );
    expect(new TextDecoder().decode(first)).toBe("secret-value");
    first.fill(0);
    const second = await resolver.read(
      "smtp.password",
      new AbortController().signal,
    );
    expect(new TextDecoder().decode(second)).toBe("secret-value");
  });

  it("rejects traversal, empty files, and embedded NUL bytes", async () => {
    const root = await temporaryRoot();
    const resolver = await FileSecretResolver.create(root);
    await writeFile(join(root, "empty"), "");
    await writeFile(join(root, "nul"), Buffer.from([0x61, 0, 0x62]));
    await expect(
      resolver.read("../escape", new AbortController().signal),
    ).rejects.toThrow(NotificationValidationError);
    await expect(
      resolver.read("empty", new AbortController().signal),
    ).rejects.toThrow(NotificationValidationError);
    await expect(
      resolver.read("nul", new AbortController().signal),
    ).rejects.toThrow(NotificationValidationError);
  });

  async function temporaryRoot(): Promise<string> {
    const root = await mkdtemp(join(tmpdir(), "periapsis-notifier-secret-"));
    roots.push(root);
    return root;
  }
});
