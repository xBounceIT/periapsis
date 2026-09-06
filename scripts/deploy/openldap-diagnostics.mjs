import { spawnSync } from "node:child_process";

const compose = [
  "compose",
  "--file",
  "deploy/compose/compose.yaml",
  "--profile",
  "auth-test",
];
const stateFormat =
  '{"status":{{json .State.Status}},"exitCode":{{json .State.ExitCode}},"oomKilled":{{json .State.OOMKilled}},"errorPresent":{{if .State.Error}}true{{else}}false{{end}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}';
const states = new Set([
  "created",
  "running",
  "paused",
  "restarting",
  "removing",
  "exited",
  "dead",
]);
const healthStates = new Set([null, "starting", "healthy", "unhealthy"]);
const reasons = [
  "Read-only file system",
  "Operation not permitted",
  "Permission denied",
  "No such file or directory",
  "File exists",
];

// Startup logs can contain credentials, DNs, assertions or private-key material.
// Reconstruct only fixed filesystem error categories; never print free-form text,
// paths, Docker error strings, health-check output or configuration/environment.
export function redactStartupLogs(source) {
  const lines = source.slice(-65_536).trimEnd().split(/\r?\n/u).slice(-100);
  const errors = [];
  const bootstrapErrors = [];
  let redactedLines = 0;
  for (const [index, line] of lines.entries()) {
    if (!line) continue;
    const bootstrapStage =
      /^PERIAPSIS_OPENLDAP_ERROR stage=(identity|storage|password_file|tls|existing_state|password_hash|config_import|tree_import|config_validation|settings)$/u.exec(
        line,
      )?.[1];
    if (bootstrapStage) {
      bootstrapErrors.push({ tailLine: index + 1, stage: bootstrapStage });
      continue;
    }
    const operation = /\b(chown|chmod|mkdir|touch|cp|mv|rm):/u.exec(line)?.[1];
    const reason = reasons.find((candidate) => line.includes(candidate));
    if (!operation || !reason) {
      redactedLines += 1;
      continue;
    }
    const pathRoot =
      /\/(etc\/ldap|var\/lib\/ldap|run\/slapd|tmp)(?=[/'":\s])/u.exec(
        line,
      )?.[1];
    errors.push({
      tailLine: index + 1,
      operation,
      pathRoot: pathRoot ? `/${pathRoot}` : null,
      reason,
    });
  }
  return { filesystemErrors: errors, bootstrapErrors, redactedLines };
}

function docker(args, execute) {
  const result = execute("docker", args, {
    encoding: "utf8",
    timeout: 10_000,
    killSignal: "SIGKILL",
    maxBuffer: 65_536,
    windowsHide: true,
  });
  return !result.error && result.signal === null && result.status === 0
    ? result
    : null;
}

export function collectOpenLdapDiagnostics(execute = spawnSync) {
  const lookup = docker(
    [...compose, "ps", "--all", "--quiet", "openldap"],
    execute,
  );
  const container = lookup?.stdout.trim();
  if (!container || !/^[a-f0-9]{64}$/u.test(container)) {
    return { service: "openldap", state: "unavailable", logs: "unavailable" };
  }
  const result = {
    service: "openldap",
    state: "unavailable",
    logs: "unavailable",
  };
  const inspected = docker(
    ["inspect", "--format", stateFormat, container],
    execute,
  );
  if (inspected) {
    try {
      const state = JSON.parse(inspected.stdout);
      if (
        states.has(state.status) &&
        Number.isInteger(state.exitCode) &&
        state.exitCode >= 0 &&
        state.exitCode <= 255 &&
        typeof state.oomKilled === "boolean" &&
        typeof state.errorPresent === "boolean" &&
        healthStates.has(state.health)
      ) {
        result.state = {
          status: state.status,
          exitCode: state.exitCode,
          oomKilled: state.oomKilled,
          errorPresent: state.errorPresent,
          health: state.health,
        };
      }
    } catch {
      // Malformed output is unavailable, never copied into the CI report.
    }
  }
  const logs = docker(["logs", "--tail", "100", container], execute);
  if (logs) result.logs = redactStartupLogs(`${logs.stdout}\n${logs.stderr}`);
  return result;
}

if (import.meta.main) {
  try {
    process.stdout.write(`${JSON.stringify(collectOpenLdapDiagnostics())}\n`);
  } catch {
    process.stderr.write(
      "OpenLDAP diagnostics unavailable; raw output withheld.\n",
    );
    process.exitCode = 1;
  }
}
