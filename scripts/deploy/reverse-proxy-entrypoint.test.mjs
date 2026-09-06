import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const entrypoint = fileURLToPath(
  new URL(
    "../../deploy/compose/edge/reverse-proxy-entrypoint.sh",
    import.meta.url,
  ),
);
const shell =
  process.platform === "win32"
    ? join(process.env.ProgramFiles ?? "C:/Program Files", "Git/usr/bin/sh.exe")
    : "/bin/sh";
const shellPath = (value) =>
  process.platform === "win32"
    ? value
        .replaceAll("\\", "/")
        .replace(/^([A-Za-z]):/u, (_, drive) => `/${drive.toLowerCase()}`)
    : value;

test(
  "the actual reverse-proxy entrypoint converts explicit peers and rejects unsafe lists before Caddy",
  { timeout: 30_000 },
  async (t) => {
    const source = await readFile(entrypoint);
    const directory = await mkdtemp(
      join(tmpdir(), "periapsis-proxy-entrypoint-"),
    );
    t.after(async () => {
      assert.equal(dirname(directory), resolve(tmpdir()));
      assert.ok(basename(directory).startsWith("periapsis-proxy-entrypoint-"));
      await rm(directory, {
        recursive: true,
        force: true,
        maxRetries: 2,
        retryDelay: 100,
      });
    });
    const bin = join(directory, "bin");
    await mkdir(bin, { mode: 0o700 });
    // Run the real /bin/sh (Git sh on Windows), entrypoint and tr. Only the final
    // Caddy executable is a recorder. Real IP parsing/Caddy policy is covered by
    // storage-cors-runtime.test.mjs, not simulated by this converter contract.
    await writeFile(
      join(bin, "caddy"),
      `#!/bin/sh
set -eu
printf '%s\\000' "$PERIAPSIS_CADDY_TRUSTED_PROXY_CIDRS" "$PERIAPSIS_PUBLIC_URL" "$@" > "$PERIAPSIS_ENTRYPOINT_CAPTURE"
`,
      { flag: "wx", mode: 0o700 },
    );
    const publicOrigin = "https://incidents.example.test:9443";
    const inheritedPlatform = Object.fromEntries(
      ["SystemRoot", "WINDIR", "TEMP", "TMP"]
        .filter((key) => process.env[key] !== undefined)
        .map((key) => [key, process.env[key]]),
    );
    const cases = [
      {
        name: "IPv4 host prefix",
        value: "192.0.2.10/32",
        converted: "192.0.2.10/32",
      },
      {
        name: "IPv6 host prefix",
        value: "2001:db8::10/128",
        converted: "2001:db8::10/128",
      },
      {
        name: "mixed comma-separated peers",
        value: "192.0.2.10/32,2001:db8::10/128,198.51.100.0/24",
        converted: "192.0.2.10/32 2001:db8::10/128 198.51.100.0/24",
      },
      { name: "unset" },
      { name: "empty", value: "" },
      { name: "IPv4 universal", value: "0.0.0.0/0" },
      { name: "IPv6 universal", value: "::/0" },
      { name: "padded universal", value: "0.0.0.0/00" },
      { name: "padded nonzero prefix", value: "192.0.2.10/0001" },
      { name: "padded host prefix", value: "192.0.2.10/032" },
      { name: "mixed universal", value: "192.0.2.10/32,::/0" },
      { name: "leading empty peer", value: ",192.0.2.10/32" },
      { name: "trailing empty peer", value: "192.0.2.10/32," },
      { name: "interior empty peer", value: "192.0.2.10/32,,2001:db8::10/128" },
      { name: "space separated", value: "192.0.2.10/32 2001:db8::10/128" },
      { name: "leading whitespace", value: " 192.0.2.10/32" },
      { name: "trailing whitespace", value: "192.0.2.10/32 " },
      { name: "tab", value: "192.0.2.10/32\t" },
      { name: "newline", value: "192.0.2.10/32\n" },
      { name: "command substitution", value: "$(printf evaluated)" },
      { name: "backticks", value: "`printf evaluated`" },
      { name: "command separator", value: "192.0.2.10/32;printf evaluated" },
      { name: "pipeline", value: "192.0.2.10/32|printf evaluated" },
      { name: "wildcard", value: "*" },
    ];
    const deadline = Date.now() + 25_000;
    const expectedCaptures = new Map();
    for (const [index, input] of cases.entries()) {
      const remaining = deadline - Date.now();
      assert.ok(
        remaining > 0,
        "entrypoint cases exceeded their shared deadline",
      );
      const captureName = `capture-${index}`;
      const env = {
        ...inheritedPlatform,
        PATH: `${shellPath(bin)}:/usr/bin:/bin`,
        BASH_ENV: "",
        ENV: "",
        LC_ALL: "C",
        MSYS2_ARG_CONV_EXCL: "*",
        PERIAPSIS_PUBLIC_URL: publicOrigin,
        PERIAPSIS_ENTRYPOINT_CAPTURE: shellPath(join(directory, captureName)),
        // The converter must replace an inherited Caddy-specific value, not trust it.
        PERIAPSIS_CADDY_TRUSTED_PROXY_CIDRS: "0.0.0.0/0",
        ...(input.value === undefined
          ? {}
          : { PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS: input.value }),
      };
      const result = spawnSync(shell, [shellPath(entrypoint)], {
        cwd: directory,
        env,
        encoding: "utf8",
        timeout: Math.min(5_000, remaining),
        killSignal: "SIGKILL",
        windowsHide: true,
        maxBuffer: 16_384,
      });
      assert.equal(
        result.error,
        undefined,
        `${input.name}: real sh must exist and finish; this gate cannot skip`,
      );
      assert.equal(
        result.signal,
        null,
        `${input.name}: shell terminated unexpectedly`,
      );
      assert.equal(
        result.stdout,
        "",
        `${input.name}: entrypoint must not echo inputs`,
      );
      if (input.converted !== undefined) {
        assert.equal(
          result.status,
          0,
          `${input.name}: canonical peers rejected`,
        );
        assert.equal(result.stderr, "");
        expectedCaptures.set(captureName, [
          input.converted,
          publicOrigin,
          "run",
          "--config",
          "/etc/caddy/Caddyfile",
          "--adapter",
          "caddyfile",
          "",
        ]);
      } else {
        assert.equal(result.status, 1, `${input.name}: unsafe peers admitted`);
        assert.ok(
          [
            "Configure explicit external proxy IP/CIDR peers.\n",
            "Universal external proxy CIDRs are forbidden.\n",
          ].includes(result.stderr),
          `${input.name}: non-fixed diagnostic escaped`,
        );
      }
    }
    assert.deepEqual(
      (await readdir(directory)).toSorted(),
      ["bin", ...expectedCaptures.keys()].toSorted(),
      "only admitted inputs may execute Caddy and create a capture",
    );
    await Promise.all(
      [...expectedCaptures].map(async ([name, expected]) => {
        const captured = (await readFile(join(directory, name), "utf8")).split(
          "\0",
        );
        assert.deepEqual(
          captured,
          expected,
          "converted environment or fixed Caddy arguments changed",
        );
      }),
    );
    assert.deepEqual(
      await readFile(entrypoint),
      source,
      "deployed entrypoint changed during its test",
    );
  },
);
