import { spawnSync } from "node:child_process";
import { stripVTControlCharacters } from "node:util";
import apiStartupErrors from "./api-startup-errors.json" with { type: "json" };

const services = [
  "minio-provision",
  "migration",
  "minio",
  "postgres",
  "api",
  "worker",
];
const loggedServices = new Set([
  "minio-provision",
  "migration",
  "api",
  "worker",
]);
const runtimeErrors = new Set([
  ...apiStartupErrors,
  "validate worker database role",
  "database connection is not a least-privileged worker role",
]);
const runtimeDependencies = new Set([
  "postgresql",
  "protected_authentication_configuration",
  "api_credential_keyring",
  "identity_keyring",
  "notification_keyring",
  "dfir_object_storage",
  "dfir_malware_scanner",
  "ticket_operations",
  "platform_local_accounts",
  "federated_authentication",
]);
const readinessFailures = new Set([
  "deadline_exceeded",
  "query_unavailable",
  "trusted_functions_changed",
  "runtime_schema_unavailable",
  "migration_state_changed",
]);
const workerFailures = new Set([
  "audit operations worker is not configured",
  "ticket runtime is not configured",
  "DFIR scan cycle failed",
  "DFIR orphan cleanup cycle failed",
  "custom-field import cycle failed",
  "custom-field import readiness failed",
  "audit operations cycle failed",
  "audit operations readiness failed",
  "ticket runtime readiness failed",
  "ticket export storage readiness failed",
  "ticket export spool reconciliation failed",
  "ticket work queue discovery failed",
  "SLA trigger action execution failed",
  "SLA event ingress failed",
  "SLA evaluation failed",
]);
const workerFailureCodes = new Set([
  "retention_signing_key_missing",
  "service_identity_missing",
  "dependency_unavailable",
  "database_abi_unavailable",
  "storage_unavailable",
  "canceled",
  "deadline_exceeded",
  "fence_lost",
  "invalid_projection",
  "invalid_input",
  "unavailable",
  "internal",
]);
const compose = [
  "compose",
  "--file",
  "deploy/compose/compose.yaml",
  "--profile",
  "minimal",
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
const databasePhases = new Set([
  "configuration",
  "migration",
  "runtime_credentials",
  "runtime_provision",
  "seed",
]);
const databaseModes = new Set([
  "migrate",
  "provision-notifier",
  "seed",
  "unsupported",
]);
const databaseCodes = new Set([
  "DATABASE_TASK_FAILED",
  "UNSUPPORTED_TASK",
  "INVALID_SECRET",
  "INVALID_DATABASE_URL_FILE",
  "DATABASE_URL_FILE_REQUIRED",
  "INVALID_ENVIRONMENT",
  "INVALID_DATABASE_URL",
  "DATABASE_TLS_REQUIRED",
  "ROLE_STATEMENT_FAILED",
  "INVALID_WEBHOOK_PLAIN_LOCAL_OPT_IN",
  "WEBHOOK_PLAIN_LOCAL_PRODUCTION_FORBIDDEN",
  "MIGRATION_DATABASE_VERSION_UNSUPPORTED",
  "MIGRATION_DATABASE_ADMIN_UNSUPPORTED",
  "MIGRATION_DATABASE_LOCALE_UNSUPPORTED",
  "MIGRATION_CLIENT_INCOMPATIBLE",
  "MIGRATION_BUNDLE_DIVERGED",
  "MIGRATION_JOURNAL_DIVERGED",
  "MIGRATION_JOURNAL_UNAVAILABLE",
  "MIGRATION_SEALER_DIVERGED",
  "MIGRATION_LOCK_UNAVAILABLE",
  "MIGRATION_LOCK_LOST",
  "ENOENT",
  "EACCES",
  "EPERM",
  "EROFS",
  "ECONNREFUSED",
  "ENOTFOUND",
  "ETIMEDOUT",
  "08001",
  "08006",
  "28P01",
  "42501",
  "42702",
  "42P18",
  "42P01",
  "57014",
  "55P03",
  "23505",
  "3D000",
  "SIGNAL_SIGTERM",
  "SIGNAL_SIGKILL",
  "SIGNAL_SIGILL",
  "SIGNAL_SIGABRT",
]);
// Error prefixes verified against the pinned mc RELEASE.2025-08-13T08-35-41Z
// sources. Values, paths, credentials, remote messages and stack traces are omitted.
const minioOperations = [
  [
    "Unable to initialize new alias from the provided credentials.",
    "alias_set",
  ],
  ["Invalid access key", "alias_access_key_validation"],
  ["Invalid secret key", "alias_secret_key_validation"],
  ["Unable to load config", "config_load"],
  ["Unable to update hosts in config version", "config_write"],
  ["Unable to make bucket", "bucket_create"],
  ["Unable to enable versioning", "version_enable"],
  ["Unable to get policy", "policy_read"],
  ["Unable to create new policy", "policy_create"],
  ["Unable to add new user", "user_add"],
  ["Unable to make user/group policy association", "policy_attach"],
  ["Unable to initialize admin connection.", "admin_connect"],
  ["Unable to open bucket CORS configuration file.", "cors_file_open"],
  ["Unable to read bucket CORS configuration file.", "cors_file_read"],
  ["Unable to set bucket CORS configuration for", "cors_set"],
];
const reasons = [
  ["read-only file system", "read_only_filesystem"],
  ["operation not permitted", "operation_not_permitted"],
  ["permission denied", "permission_denied"],
  ["no such file or directory", "file_missing"],
  ["access denied", "access_denied"],
  ["connection refused", "connection_refused"],
  ["no such host", "dns_lookup_failed"],
  ["i/o timeout", "io_timeout"],
  ["not implemented", "not_implemented"],
];

function knownDatabaseCode(candidate) {
  if (typeof candidate !== "string") return null;
  if (databaseCodes.has(candidate)) return candidate;
  const exit = /^EXIT_([1-9][0-9]{0,2})$/u.exec(candidate ?? "");
  return exit && Number(exit[1]) <= 255 ? candidate : null;
}

function databaseEvent(line) {
  try {
    const entry = JSON.parse(line);
    if (
      entry?.service === "database-task" &&
      entry.event === "database_task_failed"
    ) {
      return {
        kind: "database_driver",
        code: knownDatabaseCode(entry.code) ?? "UNCLASSIFIED",
        mode: databaseModes.has(entry.mode) ? entry.mode : "unknown",
        phase: databasePhases.has(entry.phase) ? entry.phase : "unknown",
      };
    }
  } catch {
    // Native Node error properties are considered separately; never print the error.
  }
  const property = /^\s*code:\s*['"]([A-Z0-9_]{1,64})['"],?\s*$/u.exec(line);
  const code = knownDatabaseCode(property?.[1]);
  return code ? { kind: "database_error_property", code } : null;
}

function minioEvent(line) {
  const message = /^mc: <ERROR>\s+(.*)$/u.exec(line)?.[1];
  const operation = message
    ? (minioOperations.find(([prefix]) => message.startsWith(prefix))?.[1] ??
      "unclassified")
    : /^(?:mkdir|tr):/u.test(line)
      ? line.slice(0, line.indexOf(":"))
      : line.startsWith("/usr/local/bin/provision-minio:")
        ? "shell"
        : null;
  if (!operation) return null;
  const reason =
    reasons.find(([phrase]) => line.toLowerCase().includes(phrase))?.[1] ??
    null;
  return { kind: "minio_startup", operation, observedReason: reason };
}

function runtimeEvent(service, line) {
  try {
    const entry = JSON.parse(line);
    if (entry?.level === "WARN") {
      if (
        service === "api" &&
        entry.msg === "readiness dependency unavailable"
      ) {
        return {
          kind: "runtime_readiness",
          dependency: runtimeDependencies.has(entry.dependency)
            ? entry.dependency
            : "UNCLASSIFIED",
          failure: readinessFailures.has(entry.failure)
            ? entry.failure
            : "UNCLASSIFIED",
          latencyMs:
            Number.isSafeInteger(entry.latency_ms) &&
            entry.latency_ms >= 0 &&
            entry.latency_ms <= 30000
              ? entry.latency_ms
              : null,
        };
      }
      if (service === "worker" && workerFailures.has(entry.msg)) {
        return {
          kind: "worker_readiness",
          operation: entry.msg,
          failure: workerFailureCodes.has(entry.failure)
            ? entry.failure
            : "UNCLASSIFIED",
        };
      }
    }
    if (entry?.level !== "ERROR" || entry.msg !== `${service} stopped`)
      return null;
    return {
      kind: "runtime_startup",
      // Go errors.Join can append an independent telemetry shutdown error.
      // Reconstruct only exact reviewed literals, never arbitrary error text.
      error: (typeof entry.error === "string"
        ? entry.error.split("\n", 4)
        : [null]
      )
        .map((error) => (runtimeErrors.has(error) ? error : "UNCLASSIFIED"))
        .join("; "),
    };
  } catch {
    return null;
  }
}

// These are observed, allowlisted log markers, not a claim to infer every root
// cause. The provisioning shell has silent exit-1 branches that remain unknown.
export function redactComposeStartupLogs(service, source) {
  const lines = source.slice(-65_536).trimEnd().split(/\r?\n/u).slice(-100);
  const events = [];
  let redactedLines = 0;
  for (const raw of lines) {
    if (!raw) continue;
    const line = stripVTControlCharacters(raw);
    const event =
      service === "migration"
        ? databaseEvent(line)
        : service === "minio-provision"
          ? minioEvent(line)
          : service === "api" || service === "worker"
            ? runtimeEvent(service, line)
            : null;
    if (event) events.push(event);
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
    return !result.error && result.signal === null && result.status === 0
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
    // No raw Docker error, health output, environment or configuration is returned.
  }
  return "unavailable";
}

export function collectComposeStartupDiagnostics(execute = spawnSync) {
  return {
    profile: "minimal",
    services: services.map((service) => {
      const result = {
        service,
        state: "unavailable",
        logs: loggedServices.has(service) ? "unavailable" : "not-collected",
      };
      const lookup = docker(
        [...compose, "ps", "--all", "--quiet", service],
        execute,
      );
      const container = lookup?.stdout.trim();
      if (!container || !/^[a-f0-9]{64}$/u.test(container)) return result;
      const inspected = docker(
        ["inspect", "--format", stateFormat, container],
        execute,
      );
      if (inspected) result.state = safeState(inspected.stdout);
      if (loggedServices.has(service)) {
        const logs = docker(["logs", "--tail", "100", container], execute);
        if (logs)
          result.logs = redactComposeStartupLogs(
            service,
            `${logs.stdout}\n${logs.stderr}`,
          );
      }
      return result;
    }),
  };
}

if (import.meta.main) {
  try {
    process.stdout.write(
      `${JSON.stringify(collectComposeStartupDiagnostics())}\n`,
    );
  } catch {
    process.stderr.write(
      "Compose startup diagnostics unavailable; raw output withheld.\n",
    );
    process.exitCode = 1;
  }
}
