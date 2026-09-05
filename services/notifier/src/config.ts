import type { NotificationRuntimeOptions } from "./runtime.js";
import type { NotificationFanoutOptions } from "./fanout.js";
import { notificationDispatchLimits } from "./dispatch-limits.js";
import { readBoundedSecretFile } from "./secrets.js";
import { canonicalSmtpHost } from "./smtp.js";
import type { DeliveryWorkerOptions } from "./delivery.js";
import { requireInteger, requireText } from "./validation.js";
import { NotificationValidationError } from "./errors.js";
import { NotificationSecretKeyring } from "./keyring.js";
import {
  loadNotifierTelemetryConfiguration,
  type NotifierTelemetryConfiguration,
} from "./telemetry.js";

export interface NotifierConfiguration {
  readonly environment: "development" | "test" | "production";
  readonly release: string;
  readonly listen: Readonly<{ host: string; port: number }>;
  readonly databaseUrl: string;
  readonly previewToken: Uint8Array;
  readonly notificationKeyring: NotificationSecretKeyring;
  readonly smtpAllowedPorts: readonly number[];
  readonly smtpAllowedPrivateHosts: readonly string[];
  readonly allowPlainLocalSmtp: boolean;
  readonly webhookAllowedPorts: readonly number[];
  readonly webhookAllowedPrivateHosts: readonly string[];
  readonly allowPlainLocalWebhook: boolean;
  readonly logLevel: "info" | "error";
  readonly telemetry: NotifierTelemetryConfiguration;
  readonly worker: Readonly<DeliveryWorkerOptions>;
  readonly fanout: Readonly<NotificationFanoutOptions>;
  readonly runtime: Readonly<NotificationRuntimeOptions>;
}

export interface NotifierConfigurationLoaderOptions {
  env?: Readonly<Record<string, string | undefined>>;
  signal?: AbortSignal;
  readSecretFile?: (
    path: string,
    signal: AbortSignal,
    maximumBytes: number,
  ) => Promise<Uint8Array>;
}

export async function loadNotifierConfiguration(
  options: NotifierConfigurationLoaderOptions = {},
): Promise<NotifierConfiguration> {
  const env = options.env ?? process.env;
  const signal = options.signal ?? new AbortController().signal;
  const readSecret = options.readSecretFile ?? readBoundedSecretFile;
  let databaseBytes: Uint8Array | undefined;
  let previewToken: Uint8Array | undefined;
  let notificationKeyring: NotificationSecretKeyring | undefined;
  let retainRuntimeSecrets = false;
  try {
    const environment = parseEnvironment(env["PERIAPSIS_ENV"] ?? "production");
    const release = requireText(
      env["PERIAPSIS_RELEASE"] ?? "development",
      "release",
      128,
    );
    const telemetry = loadNotifierTelemetryConfiguration(
      environment,
      release,
      env,
    );
    const listen = parseListenAddress(
      env["PERIAPSIS_NOTIFIER_ADDR"] ?? "0.0.0.0:8083",
    );
    databaseBytes = await loadSecret(
      env,
      "PERIAPSIS_DATABASE_URL",
      environment,
      signal,
      readSecret,
      4_096,
    );
    previewToken = await loadSecret(
      env,
      "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN",
      environment,
      signal,
      readSecret,
      512,
    );
    let databaseUrl: string;
    try {
      databaseUrl = canonicalDatabaseUrl(
        new TextDecoder("utf-8", { fatal: true }).decode(databaseBytes),
      );
    } finally {
      databaseBytes.fill(0);
    }
    if (
      previewToken.byteLength < 32 ||
      previewToken.byteLength > 512 ||
      !/^[A-Za-z0-9._~+/=-]+$/u.test(new TextDecoder().decode(previewToken))
    ) {
      previewToken.fill(0);
      throw new NotificationValidationError(
        "notifier preview token is not a strong bearer token",
      );
    }
    const allowPlainLocalSmtp = parseBoolean(
      env["PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL"] ?? "false",
      "PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL",
    );
    if (allowPlainLocalSmtp && environment === "production") {
      previewToken.fill(0);
      throw new NotificationValidationError(
        "plaintext SMTP cannot be enabled in production",
      );
    }
    const smtpAllowedPorts = parseIntegerList(
      env["PERIAPSIS_SMTP_ALLOWED_PORTS"] ?? "465,587",
      "PERIAPSIS_SMTP_ALLOWED_PORTS",
      32,
    );
    const smtpAllowedPrivateHosts = parseHostList(
      env["PERIAPSIS_SMTP_ALLOWED_PRIVATE_HOSTS"] ?? "",
      "PERIAPSIS_SMTP_ALLOWED_PRIVATE_HOSTS",
    );
    const allowPlainLocalWebhook = parseBoolean(
      env["PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL"] ?? "false",
      "PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL",
    );
    if (allowPlainLocalWebhook && environment === "production") {
      previewToken.fill(0);
      throw new NotificationValidationError(
        "plaintext webhooks cannot be enabled in production",
      );
    }
    const webhookAllowedPorts = parseIntegerList(
      env["PERIAPSIS_WEBHOOK_ALLOWED_PORTS"] ?? "443",
      "PERIAPSIS_WEBHOOK_ALLOWED_PORTS",
      32,
    );
    const webhookAllowedPrivateHosts = parseHostList(
      env["PERIAPSIS_WEBHOOK_ALLOWED_PRIVATE_HOSTS"] ?? "",
      "PERIAPSIS_WEBHOOK_ALLOWED_PRIVATE_HOSTS",
    );
    const logLevel = parseLogLevel(env["PERIAPSIS_LOG_LEVEL"] ?? "info");
    const worker = Object.freeze({
      workerId: requireText(
        env["PERIAPSIS_NOTIFIER_WORKER_ID"] ?? "notifier-local",
        "notifier worker id",
        128,
      ),
      batchSize: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_BATCH_SIZE",
        50,
        1,
        notificationDispatchLimits.maximumBatchSize,
      ),
      maximumConcurrency: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_CONCURRENCY",
        8,
        1,
        64,
      ),
      leaseDurationMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_LEASE_MS",
        60_000,
        5_000,
        notificationDispatchLimits.maximumLeaseDurationMs,
      ),
      heartbeatIntervalMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_HEARTBEAT_MS",
        15_000,
        1_000,
        10 * 60_000,
      ),
      deliveryTimeoutMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_DELIVERY_TIMEOUT_MS",
        30_000,
        1_000,
        notificationDispatchLimits.maximumLeaseDurationMs - 1,
      ),
      renderTimeoutMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_RENDER_TIMEOUT_MS",
        100,
        1,
        5_000,
      ),
      maximumOutputBytes: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_MAX_OUTPUT_BYTES",
        256 * 1_024,
        1_024,
        1024 * 1_024,
      ),
    });
    if (
      worker.heartbeatIntervalMs * 3 >= worker.leaseDurationMs ||
      worker.deliveryTimeoutMs >= worker.leaseDurationMs
    ) {
      previewToken.fill(0);
      throw new NotificationValidationError(
        "notifier lease, heartbeat, and delivery timeouts are inconsistent",
      );
    }
    const fanout = Object.freeze({
      workerId: requireText(
        env["PERIAPSIS_NOTIFIER_FANOUT_WORKER_ID"] ?? "notifier-fanout-local",
        "fanout worker id",
        128,
      ),
      batchSize: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FANOUT_BATCH_SIZE",
        50,
        1,
        notificationDispatchLimits.maximumBatchSize,
      ),
      maximumConcurrency: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FANOUT_CONCURRENCY",
        8,
        1,
        64,
      ),
      leaseDurationMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FANOUT_LEASE_MS",
        60_000,
        5_000,
        notificationDispatchLimits.maximumLeaseDurationMs,
      ),
      heartbeatIntervalMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FANOUT_HEARTBEAT_MS",
        15_000,
        1_000,
        10 * 60_000,
      ),
      processingTimeoutMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FANOUT_TIMEOUT_MS",
        30_000,
        1_000,
        notificationDispatchLimits.maximumLeaseDurationMs - 1,
      ),
      initialRetryDelayMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FANOUT_INITIAL_RETRY_MS",
        1_000,
        1_000,
        24 * 60 * 60_000,
      ),
      maximumRetryDelayMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FANOUT_MAX_RETRY_MS",
        60_000,
        1_000,
        7 * 24 * 60 * 60_000,
      ),
    });
    if (
      fanout.heartbeatIntervalMs * 3 >= fanout.leaseDurationMs ||
      fanout.processingTimeoutMs >= fanout.leaseDurationMs ||
      fanout.maximumRetryDelayMs < fanout.initialRetryDelayMs
    ) {
      previewToken.fill(0);
      throw new NotificationValidationError(
        "fanout lease, heartbeat, processing, and retry settings are inconsistent",
      );
    }
    const runtime = Object.freeze({
      idlePollIntervalMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_IDLE_POLL_MS",
        1_000,
        100,
        60_000,
      ),
      busyPollIntervalMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_BUSY_POLL_MS",
        25,
        10,
        10_000,
      ),
      failurePollIntervalMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_FAILURE_POLL_MS",
        5_000,
        100,
        5 * 60_000,
      ),
      readinessTimeoutMs: integerEnv(
        env,
        "PERIAPSIS_NOTIFIER_READINESS_TIMEOUT_MS",
        2_000,
        100,
        30_000,
      ),
    });
    notificationKeyring = await loadNotificationKeyring(
      env,
      signal,
      readSecret,
    );
    const configuration = Object.freeze({
      environment,
      release,
      listen,
      databaseUrl,
      previewToken,
      notificationKeyring,
      smtpAllowedPorts,
      smtpAllowedPrivateHosts,
      allowPlainLocalSmtp,
      webhookAllowedPorts,
      webhookAllowedPrivateHosts,
      allowPlainLocalWebhook,
      logLevel,
      telemetry,
      worker,
      fanout,
      runtime,
    });
    retainRuntimeSecrets = true;
    return configuration;
  } finally {
    databaseBytes?.fill(0);
    if (!retainRuntimeSecrets) {
      previewToken?.fill(0);
      notificationKeyring?.close();
    }
  }
}

async function loadNotificationKeyring(
  env: Readonly<Record<string, string | undefined>>,
  signal: AbortSignal,
  readSecret: NonNullable<NotifierConfigurationLoaderOptions["readSecretFile"]>,
): Promise<NotificationSecretKeyring> {
  if (env["NOTIFICATION_KEYRING"] !== undefined) {
    throw new NotificationValidationError(
      "NOTIFICATION_KEYRING must not be set; use NOTIFICATION_KEYRING_FILE",
    );
  }
  const path = env["NOTIFICATION_KEYRING_FILE"];
  if (path === undefined || path.length < 1 || path.trim() !== path) {
    throw new NotificationValidationError(
      "NOTIFICATION_KEYRING_FILE is required",
    );
  }
  const document = await readSecret(path, signal, 64 * 1_024);
  try {
    return NotificationSecretKeyring.parse(document);
  } finally {
    document.fill(0);
  }
}

async function loadSecret(
  env: Readonly<Record<string, string | undefined>>,
  name: string,
  environment: NotifierConfiguration["environment"],
  signal: AbortSignal,
  readSecret: NonNullable<NotifierConfigurationLoaderOptions["readSecretFile"]>,
  maximumBytes: number,
): Promise<Uint8Array> {
  const direct = env[name];
  const file = env[`${name}_FILE`];
  if (
    (direct !== undefined && file !== undefined) ||
    (direct === undefined && file === undefined) ||
    (environment === "production" && direct !== undefined)
  ) {
    throw new NotificationValidationError(
      `${name} must use exactly one permitted secret source`,
    );
  }
  if (file !== undefined) return readSecret(file, signal, maximumBytes);
  if (direct === undefined) {
    throw new NotificationValidationError(`${name} secret source is missing`);
  }
  const bytes = new TextEncoder().encode(direct);
  if (bytes.byteLength < 1 || bytes.byteLength > maximumBytes) {
    bytes.fill(0);
    throw new NotificationValidationError(`${name} has an invalid size`);
  }
  return bytes;
}

function canonicalDatabaseUrl(input: string): string {
  let value: URL;
  try {
    value = new URL(input);
  } catch {
    throw new NotificationValidationError("database URL is invalid");
  }
  if (
    (value.protocol !== "postgres:" && value.protocol !== "postgresql:") ||
    value.hostname === "" ||
    value.username === "" ||
    value.pathname.length < 2 ||
    value.hash !== ""
  ) {
    throw new NotificationValidationError("database URL is invalid");
  }
  return input;
}

function parseEnvironment(value: string): NotifierConfiguration["environment"] {
  if (value === "development" || value === "test" || value === "production")
    return value;
  throw new NotificationValidationError("PERIAPSIS_ENV is invalid");
}

function parseLogLevel(value: string): "info" | "error" {
  if (value === "info" || value === "error") return value;
  throw new NotificationValidationError("PERIAPSIS_LOG_LEVEL is invalid");
}

function parseBoolean(value: string, name: string): boolean {
  if (value === "true") return true;
  if (value === "false") return false;
  throw new NotificationValidationError(`${name} must be true or false`);
}

function integerEnv(
  env: Readonly<Record<string, string | undefined>>,
  name: string,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  const source = env[name];
  if (source === undefined) return fallback;
  if (!/^(?:0|[1-9][0-9]*)$/u.test(source)) {
    throw new NotificationValidationError(`${name} must be an integer`);
  }
  return requireInteger(Number(source), name, minimum, maximum);
}

function parseIntegerList(
  value: string,
  name: string,
  maximumItems: number,
): readonly number[] {
  const entries = value.split(",");
  if (
    entries.length === 0 ||
    entries.length > maximumItems ||
    entries.some((entry) => !/^[1-9][0-9]*$/u.test(entry))
  ) {
    throw new NotificationValidationError(`${name} is invalid`);
  }
  const result = entries.map((entry) =>
    requireInteger(Number(entry), name, 1, 65_535),
  );
  if (new Set(result).size !== result.length) {
    throw new NotificationValidationError(`${name} contains duplicates`);
  }
  return Object.freeze(result);
}

function parseHostList(value: string, name: string): readonly string[] {
  if (value === "") return Object.freeze([]);
  const result = value.split(",").map(canonicalSmtpHost);
  if (result.length > 64 || new Set(result).size !== result.length) {
    throw new NotificationValidationError(`${name} is invalid`);
  }
  return Object.freeze(result);
}

function parseListenAddress(
  value: string,
): Readonly<{ host: string; port: number }> {
  const match = /^(?:\[([^\]]+)\]|([^:]*)):(\d+)$/u.exec(value);
  if (match === null) {
    throw new NotificationValidationError("PERIAPSIS_NOTIFIER_ADDR is invalid");
  }
  const hostInput = match[1] ?? match[2] ?? "";
  const host =
    hostInput === "" ? "0.0.0.0" : requireText(hostInput, "notifier host", 253);
  const port = requireInteger(Number(match[3]), "notifier port", 1_024, 65_535);
  return Object.freeze({ host, port });
}
