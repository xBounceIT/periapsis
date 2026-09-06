import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

// Official release assets, content-pinned by SHA-256 values published by GitHub's
// release API: https://api.github.com/repos/caddyserver/caddy/releases/tags/v2.11.4
// This installs only a test executable into a newly owned temporary directory.
const assets = {
  "linux-x64": {
    name: "caddy_2.11.4_linux_amd64.tar.gz",
    sha256: "527fbf917c39189a1e3b31d34fa955601680b2d5c8055d2a87b8b9588dec7bb9",
    executable: "caddy",
  },
  "win32-x64": {
    name: "caddy_2.11.4_windows_amd64.zip",
    sha256: "1708333f79e274c7697285afe6d592ab39314e0b131e9ec6bea08ad27df62ebf",
    executable: "caddy.exe",
  },
};
const asset = assets[`${process.platform}-${process.arch}`];
assert.ok(asset, "Caddy test installer supports only Linux/Windows AMD64");
const directory = await mkdtemp(
  path.join(tmpdir(), "periapsis-caddy-test-binary-"),
);
try {
  const response = await fetch(
    `https://github.com/caddyserver/caddy/releases/download/v2.11.4/${asset.name}`,
    { signal: AbortSignal.timeout(60_000) },
  );
  assert.equal(response.status, 200, "official Caddy archive download failed");
  const chunks = [];
  let size = 0;
  for await (const chunk of response.body) {
    size += chunk.length;
    assert.ok(
      size <= 128 * 1024 * 1024,
      "Caddy archive exceeds download bound",
    );
    chunks.push(chunk);
  }
  const archive = Buffer.concat(chunks);
  assert.equal(
    createHash("sha256").update(archive).digest("hex"),
    asset.sha256,
    "Caddy release archive checksum mismatch; refusing extraction/execution",
  );
  const archivePath = path.join(directory, asset.name);
  await writeFile(archivePath, archive, { flag: "wx", mode: 0o600 });
  // Extract only the named executable, never arbitrary archive paths or links.
  execFileSync("tar", ["-xf", archivePath, "-C", directory, asset.executable], {
    timeout: 30_000,
    windowsHide: true,
    stdio: "ignore",
  });
  const executablePath = path.join(directory, asset.executable);
  const executable = await lstat(executablePath);
  assert.ok(executable.isFile() && !executable.isSymbolicLink());
  await chmod(executablePath, 0o700);
  await rm(archivePath);
  // Kept for caller-controlled reuse; no PATH, registry, or global install write.
  process.stdout.write(`${executablePath}\n`);
} catch {
  await rm(directory, { recursive: true, force: true });
  throw new Error("Pinned Caddy test installation failed; owned files removed");
}
