import { spawnSync } from "node:child_process";
import { stripVTControlCharacters } from "node:util";

const profiles = new Set(["auth-test", "full"]);
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
const stateFormat =
  '{"status":{{json .State.Status}},"exitCode":{{json .State.ExitCode}},"oomKilled":{{json .State.OOMKilled}},"errorPresent":{{if .State.Error}}true{{else}}false{{end}},"health":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}}}';

// Fixed observed markers only, never free-form exception text or inferred causes.
// The import/configuration markers are from Keycloak 26.7.2:
// model/storage-services/.../exportimport/dir/DirImportProvider.java
// services/.../exportimport/ExportImportManager.java
// services/.../url/HostnameV2ProviderFactory.java
// quarkus/runtime/.../Messages.java and cli/ExecutionExceptionHandler.java
const markers = [
  ["File name / realm name mismatch.", "realm_filename_mismatch"],
  ["Failed to run import", "startup_import_failed"],
  ["Key material not provided to setup HTTPS.", "https_key_material_missing"],
  ["hostname is not configured;", "hostname_missing"],
  [
    "Provided hostname is neither a plain hostname nor a valid URL",
    "hostname_invalid",
  ],
  ["flag was used for first ever server start.", "optimized_build_missing"],
  ["Read-only file system", "read_only_filesystem"],
  ["Permission denied", "permission_denied"],
  ["AccessDeniedException", "permission_denied"],
  ["Operation not permitted", "operation_not_permitted"],
  ["No such file or directory", "file_missing"],
  ["NoSuchFileException", "file_missing"],
  ["Failed to obtain JDBC connection", "database_connection_failed"],
  ["Address already in use", "address_in_use"],
  ["OutOfMemoryError", "out_of_memory"],
  ["Unknown option:", "unknown_option"],
  ["Failed to start server in", "startup_failed"],
  ["Failed to run 'start' command.", "startup_failed"],
];

export function redactIdentityProviderLogs(source) {
  const lines = source.slice(-65_536).trimEnd().split(/\r?\n/u).slice(-100);
  const events = [];
  let redactedLines = 0;
  for (const [index, raw] of lines.entries()) {
    if (!raw) continue;
    const line = stripVTControlCharacters(raw);
    const errorEnvelope =
      /^(?:ERROR:|Caused by:|(?:\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?\s+)?(?:ERROR|WARN)\s+\[)/u.test(
        line,
      );
    const category = errorEnvelope
      ? markers.find(([marker]) => line.includes(marker))?.[1]
      : undefined;
    if (category) events.push({ tailLine: index + 1, category });
    else redactedLines += 1;
  }
  return { events, redactedLines };
}

function docker(args, execute) {
  try {
    const result = execute("docker", args, {
      encoding: "utf8",
      timeout: 5_000,
      killSignal: "SIGKILL",
      maxBuffer: 65_536,
      windowsHide: true,
    });
    return !result.error &&
      result.signal === null &&
      result.status === 0 &&
      typeof result.stdout === "string" &&
      typeof result.stderr === "string"
      ? result
      : null;
  } catch {
    return null;
  }
}

function safeState(source) {
  try {
    const state = JSON.parse(source);
    if (
      states.has(state?.status) &&
      Number.isInteger(state.exitCode) &&
      state.exitCode >= 0 &&
      state.exitCode <= 255 &&
      typeof state.oomKilled === "boolean" &&
      typeof state.errorPresent === "boolean" &&
      healthStates.has(state.health)
    ) {
      return {
        status: state.status,
        exitCode: state.exitCode,
        oomKilled: state.oomKilled,
        errorPresent: state.errorPresent,
        health: state.health,
      };
    }
  } catch {
    // Docker details, environment, health-check output and errors are withheld.
  }
  return "unavailable";
}

export function collectIdentityProviderDiagnostics(
  profile = "auth-test",
  execute = spawnSync,
) {
  if (!profiles.has(profile))
    throw new Error("unsupported identity provider profile");
  const result = {
    service: "identity-provider",
    state: "unavailable",
    logs: "unavailable",
  };
  const lookup = docker(
    [
      "compose",
      "--file",
      "deploy/compose/compose.yaml",
      "--profile",
      profile,
      "ps",
      "--all",
      "--quiet",
      "identity-provider",
    ],
    execute,
  );
  const container = lookup?.stdout.trim();
  if (!container || !/^[a-f0-9]{64}$/u.test(container)) return result;
  const inspected = docker(
    ["inspect", "--format", stateFormat, container],
    execute,
  );
  if (inspected) result.state = safeState(inspected.stdout);
  const logs = docker(["logs", "--tail", "100", container], execute);
  if (logs)
    result.logs = redactIdentityProviderLogs(`${logs.stdout}\n${logs.stderr}`);
  return result;
}

if (import.meta.main) {
  try {
    if (process.argv.length > 3)
      throw new Error("unexpected diagnostic arguments");
    process.stdout.write(
      `${JSON.stringify(collectIdentityProviderDiagnostics(process.argv[2]))}\n`,
    );
  } catch {
    process.stderr.write(
      "Identity-provider diagnostics unavailable; raw output withheld.\n",
    );
    process.exitCode = 1;
  }
}
