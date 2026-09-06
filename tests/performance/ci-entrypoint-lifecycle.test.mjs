import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

const entrypoint = readFileSync(
  new URL(
    "../../scripts/performance/run-ci-ticketing-hot-paths.sh",
    import.meta.url,
  ),
  "utf8",
).replaceAll("\r\n", "\n");
const shell =
  process.platform === "win32"
    ? // bin/sh.exe is a launcher: killing it can leave the real shell holding
      // Node's pipes open indefinitely. Execute the MSYS shell itself.
      ["C:/Program Files/Git/usr/bin/sh.exe"].find(existsSync)
    : "/bin/sh";

function shellPath(path) {
  return path.replaceAll("\\", "/").replace(/^([A-Za-z]):/u, "/$1");
}

function quote(value) {
  return `'${value.replaceAll("'", "'\\''")}'`;
}

function executeShell(input, timeout = 10_000) {
  assert.ok(shell, "a POSIX shell is required for entrypoint lifecycle tests");
  return spawnSync(shell, ["-s"], {
    input:
      process.platform === "win32"
        ? `PATH=${quote(shellPath(dirname(shell)))}:"$PATH"\nexport PATH\n${input}`
        : input,
    encoding: "utf8",
    timeout,
    // A timed-out fixture must not ignore termination via its signal traps.
    killSignal: "SIGKILL",
    windowsHide: true,
  });
}

// Execute the whole wrapper, substituting only its fixed filesystem paths and
// external commands. These are shell lifecycle tests, not a PostgreSQL benchmark
// or proof of the image's UID/mount permissions. There is no production override.
function runFixture(t, options = {}) {
  assert.ok(shell, "a POSIX shell is required for entrypoint lifecycle tests");
  const directory = mkdtempSync(join(tmpdir(), "periapsis-entrypoint-test-"));
  t.after(() => rmSync(directory, { recursive: true }));
  const evidence = join(directory, "evidence");
  if (!options.missingEvidence) mkdirSync(evidence);
  const events = join(directory, "events");
  const fixture = entrypoint
    .replaceAll("/usr/local/bin/node", quote(shellPath(process.execPath)))
    .replaceAll("/usr/local/bin/psql", quote(shellPath(process.execPath)))
    .replace('"/workspace/tmp/performance"', quote(shellPath(evidence)))
    .replace(
      "/tmp/periapsis-performance-pg-XXXXXXXXXX",
      quote(`${shellPath(directory)}/pg-XXXXXXXXXX`),
    );
  const input = `
events=${quote(shellPath(events))}
server_running=false
record() { printf '%s\\n' "$*" >> "$events"; }
id() {
  if [ "$1" = -u ]; then printf '%s\\n' ${options.uid ?? 10001};
  else printf '%s\\n' ${options.gid ?? 10001}; fi
}
postgres() { printf '%s\\n' ${quote(options.version ?? "postgres (PostgreSQL) 18.6")}; }
initdb() { record "initdb $*"; return ${options.initStatus ?? 0}; }
pg_ctl() {
  record "pg_ctl $*"
  case "$*" in
    *' start')
      server_running=${options.startWithoutServer ? "false" : "true"}
      ${options.signal ? `kill -${options.signal} "$$"` : ":"}
      return ${options.startStatus ?? 0} ;;
    *' status')
      if [ "$server_running" = true ]; then return ${options.probeStatus ?? 0}; fi
      return 3 ;;
    *' stop') server_running=false; return ${options.stopStatus ?? 0} ;;
    *) return 98 ;;
  esac
}
env() { record "gate $*"; return ${options.gateStatus ?? 0}; }
${fixture}`;
  const acknowledgement = options.missingAcknowledgement
    ? ""
    : "disposable-container-postgres-18.6";
  const result = executeShell(
    `PERIAPSIS_PERFORMANCE_CI_ACKNOWLEDGEMENT=${quote(acknowledgement)}\nexport PERIAPSIS_PERFORMANCE_CI_ACKNOWLEDGEMENT\n${input}`,
  );
  assert.ifError(result.error);
  assert.equal(result.signal, null, result.stderr);
  return {
    status: result.status,
    stderr: result.stderr,
    events: existsSync(events)
      ? readFileSync(events, "utf8").trim().split("\n")
      : [],
  };
}

test("a timed-out shell fixture cannot keep Node's pipes open by ignoring TERM", () => {
  const startedAt = performance.now();
  const result = executeShell("trap '' TERM\nwhile :; do :; done\n", 250);
  assert.equal(result.error?.code, "ETIMEDOUT");
  assert.ok(
    performance.now() - startedAt < 5_000,
    "the direct shell must terminate within the bounded failure test",
  );
});

for (const [name, options, expected] of [
  ["missing acknowledgement", { missingAcknowledgement: true }, 64],
  ["root UID", { uid: 0 }, 69],
  ["other non-root UID", { uid: 1000 }, 69],
  ["malformed UID", { uid: "invalid" }, 69],
  ["wrong GID", { gid: 0 }, 69],
  ["wrong PostgreSQL version", { version: "postgres (PostgreSQL) 18.5" }, 69],
  ["missing evidence mount", { missingEvidence: true }, 69],
]) {
  test(`entrypoint rejects ${name} before creating or starting PostgreSQL`, (t) => {
    const result = runFixture(t, options);
    assert.equal(result.status, expected, result.stderr);
    assert.deepEqual(result.events, []);
  });
}

test("entrypoint preserves the bootstrap, private socket and exact runner pins", (t) => {
  const result = runFixture(t);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.events.length, 5);
  const [init, start, gate, probe, stop] = result.events;
  const dataDirectory = /initdb -D (.+) -U postgres/u.exec(init)?.[1];
  assert.ok(dataDirectory?.includes("/pg-"));
  assert.match(init, /-U postgres -A trust --no-locale --encoding=UTF8$/u);
  assert.ok(
    start.includes(`-D ${dataDirectory} -l ${dataDirectory}/postgres.log`),
  );
  assert.ok(
    start.endsWith(`-c unix_socket_directories=${dataDirectory} -w start`),
  );
  assert.ok(
    start.includes("-p 55432 -c listen_addresses=127.0.0.1 -c timezone=UTC"),
  );
  assert.ok(
    gate.includes(
      `PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY=${dataDirectory}`,
    ),
  );
  assert.ok(
    gate.includes(
      "postgresql://postgres@127.0.0.1:55432/postgres?sslmode=disable",
    ),
  );
  assert.ok(
    gate.endsWith("node scripts/performance/run-ticketing-hot-paths.mjs"),
  );
  assert.equal(probe, `pg_ctl -D ${dataDirectory} status`);
  assert.equal(stop, `pg_ctl -D ${dataDirectory} -m fast -w stop`);
});

for (const [name, options, expected, shouldStop, shouldRunGate] of [
  ["gate failure", { gateStatus: 42 }, 42, true, true],
  ["cleanup failure", { stopStatus: 61 }, 61, true, true],
  [
    "gate failure before cleanup failure",
    { gateStatus: 42, stopStatus: 61 },
    42,
    true,
    true,
  ],
  ["unprovable server status", { probeStatus: 4 }, 4, false, true],
  ["initdb failure", { initStatus: 41 }, 41, false, false],
  [
    "failed startup that left a live server",
    { startStatus: 43 },
    43,
    true,
    false,
  ],
  [
    "failed startup without a live server",
    { startStatus: 43, startWithoutServer: true },
    43,
    false,
    false,
  ],
  ["TERM during startup", { signal: "TERM" }, 143, true, false],
  ["INT during startup", { signal: "INT" }, 130, true, false],
]) {
  test(`entrypoint handles ${name} without losing the gate result or its cleanup boundary`, (t) => {
    const result = runFixture(t, options);
    assert.equal(result.status, expected, result.stderr);
    assert.equal(
      result.events.some((line) => line.endsWith(" -m fast -w stop")),
      shouldStop,
    );
    assert.equal(
      result.events.some((line) => line.startsWith("gate ")),
      shouldRunGate,
    );
    assert.ok(
      result.events.filter((line) => line.endsWith(" -m fast -w stop"))
        .length <= 1,
    );
  });
}
