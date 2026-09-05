import { pathToFileURL } from "node:url";
import type { Server } from "node:http";

import { loadNotifierConfiguration } from "./config.js";
import { NotificationDeliveryWorker } from "./delivery.js";
import { NotificationFanoutWorker } from "./fanout.js";
import {
  createNotifierHttpServer,
  InternalTokenAuthenticator,
  SafeNotificationPreviewer,
} from "./http.js";
import { NotifierMetrics, StructuredNotifierLogger } from "./observability.js";
import { createPostgresNotificationRepository } from "./postgres-repository.js";
import {
  CompositeNotificationBatchRunner,
  NotificationRuntime,
} from "./runtime.js";
import {
  PolicySmtpSocketConnector,
  PolicyTcpSocketConnector,
} from "./smtp-egress.js";
import { ExactPinnedSmtpHealthProbe } from "./smtp-health.js";
import { CachedSmtpProviderResolver } from "./smtp-resolver.js";
import {
  startNotifierTelemetry,
  type NotifierTelemetryRuntime,
} from "./telemetry.js";
import { PinnedWebhookTransport } from "./webhook.js";
import { LiveWebhookUrlPolicyGate } from "./webhook-url-policy.js";
import { NotificationWebhookDeliveryWorker } from "./webhook-worker.js";

const shutdownTimeoutMs = 8_000;
const httpDrainTimeoutMs = 4_000;

export async function runNotifier(signal: AbortSignal): Promise<void> {
  const configuration = await loadNotifierConfiguration({ signal });
  let telemetry: NotifierTelemetryRuntime | undefined;
  let repository:
    ReturnType<typeof createPostgresNotificationRepository> | undefined;
  let smtpProviders: CachedSmtpProviderResolver | undefined;
  let runtime: NotificationRuntime | undefined;
  let authenticator: InternalTokenAuthenticator | undefined;
  let runFailure: unknown;
  try {
    const logger = new StructuredNotifierLogger({
      release: configuration.release,
      minimumLevel: configuration.logLevel,
    });
    telemetry = startNotifierTelemetry(configuration.telemetry, logger);
    const metrics = new NotifierMetrics();
    repository = createPostgresNotificationRepository({
      databaseUrl: configuration.databaseUrl,
      allowPlainLocalSmtp: configuration.allowPlainLocalSmtp,
      allowPlainLocalWebhooks: configuration.allowPlainLocalWebhook,
    });
    const smtpConnector = new PolicySmtpSocketConnector({
      policy: {
        allowedPorts: configuration.smtpAllowedPorts,
        allowedPrivateHosts: configuration.smtpAllowedPrivateHosts,
      },
    });
    smtpProviders = new CachedSmtpProviderResolver({
      repository,
      secrets: configuration.notificationKeyring,
      connector: smtpConnector,
    });
    const smtpHealth = new ExactPinnedSmtpHealthProbe({
      repository,
      secrets: configuration.notificationKeyring,
      connector: smtpConnector,
    });
    const localWebhookHosts = configuration.allowPlainLocalWebhook
      ? (["localhost", "127.0.0.1", "::1"] as const)
      : [];
    const webhookConnector = new PolicyTcpSocketConnector({
      policy: {
        allowedPorts: configuration.webhookAllowedPorts,
        allowedPrivateHosts: [
          ...new Set([
            ...configuration.webhookAllowedPrivateHosts,
            ...localWebhookHosts,
          ]),
        ],
      },
    });
    const webhookUrlPolicyGate = new LiveWebhookUrlPolicyGate(
      repository,
      webhookConnector,
      { allowPlainLocal: configuration.allowPlainLocalWebhook },
    );
    const webhookTransport = new PinnedWebhookTransport(
      webhookConnector,
      webhookUrlPolicyGate,
    );
    const fanout = new NotificationFanoutWorker({
      repository,
      logger,
      tracing: telemetry,
      options: configuration.fanout,
    });
    const email = new NotificationDeliveryWorker({
      repository,
      providers: smtpProviders,
      telemetry: metrics,
      logger,
      tracing: telemetry,
      options: configuration.worker,
    });
    const webhook = new NotificationWebhookDeliveryWorker({
      repository,
      secrets: configuration.notificationKeyring,
      transport: webhookTransport,
      urlPolicyGate: webhookUrlPolicyGate,
      telemetry: metrics,
      logger,
      tracing: telemetry,
      options: {
        workerId: configuration.worker.workerId,
        batchSize: configuration.worker.batchSize,
        maximumConcurrency: configuration.worker.maximumConcurrency,
        leaseDurationMs: configuration.worker.leaseDurationMs,
        heartbeatIntervalMs: configuration.worker.heartbeatIntervalMs,
        deliveryTimeoutMs: configuration.worker.deliveryTimeoutMs,
      },
    });
    runtime = new NotificationRuntime({
      worker: new CompositeNotificationBatchRunner({
        fanout,
        delivery: email,
        webhook,
        metrics,
      }),
      repository,
      metrics,
      logger,
      tracing: telemetry,
      options: configuration.runtime,
    });
    try {
      authenticator = new InternalTokenAuthenticator(
        configuration.previewToken,
      );
    } finally {
      configuration.previewToken.fill(0);
    }
    const server = createNotifierHttpServer({
      runtime,
      metrics,
      previewer: new SafeNotificationPreviewer(),
      smtpHealth,
      authenticator,
      logger,
      tracing: telemetry,
      release: configuration.release,
    });
    await superviseNotifier({
      server,
      runtime,
      signal,
      host: configuration.listen.host,
      port: configuration.listen.port,
    });
  } catch (error) {
    runFailure = error;
  } finally {
    configuration.previewToken.fill(0);
  }

  const cleanupFailures: unknown[] = [];
  authenticator?.close();
  smtpProviders?.close();
  configuration.notificationKeyring.close();
  const shutdownSignal = AbortSignal.timeout(shutdownTimeoutMs);
  const cleanup: Promise<void>[] = [];
  if (runtime !== undefined) {
    cleanup.push(collectFailure(() => runtime.close(), cleanupFailures));
  } else if (repository !== undefined) {
    cleanup.push(collectFailure(() => repository.close(), cleanupFailures));
  }
  if (telemetry !== undefined) {
    cleanup.push(shutdownTelemetry(telemetry, shutdownSignal, cleanupFailures));
  }
  await Promise.all(cleanup);

  if (runFailure !== undefined && cleanupFailures.length > 0) {
    throw new AggregateError(
      [runFailure, ...cleanupFailures],
      "notifier runtime and shutdown failed",
      { cause: runFailure },
    );
  }
  if (runFailure !== undefined) throw runFailure;
  if (cleanupFailures.length === 1) throw cleanupFailures[0];
  if (cleanupFailures.length > 1) {
    throw new AggregateError(cleanupFailures, "notifier shutdown failed", {
      cause: cleanupFailures.at(-1),
    });
  }
}

export async function superviseNotifier(input: {
  server: Server;
  runtime: Readonly<{ run(signal: AbortSignal): Promise<void> }>;
  signal: AbortSignal;
  host: string;
  port: number;
}): Promise<void> {
  if (input.signal.aborted) throw input.signal.reason;
  const lifecycle = new AbortController();
  const forwardAbort = (): void => lifecycle.abort(input.signal.reason);
  input.signal.addEventListener("abort", forwardAbort, { once: true });
  let runtimeTask: Promise<void> | undefined;
  try {
    await listen(input.server, input.host, input.port);
    const serverFailure = new Promise<never>((_resolve, reject) => {
      input.server.once("error", reject);
    });
    const aborted = new Promise<void>((resolve) => {
      if (lifecycle.signal.aborted) resolve();
      else
        lifecycle.signal.addEventListener("abort", () => resolve(), {
          once: true,
        });
    });
    runtimeTask = input.runtime.run(lifecycle.signal);
    const outcome = await Promise.race([
      runtimeTask.then(() => "runtime_stopped" as const),
      serverFailure,
      aborted.then(() => "aborted" as const),
    ]);
    if (outcome === "runtime_stopped" && !lifecycle.signal.aborted) {
      throw new Error("notification runtime stopped unexpectedly");
    }
  } finally {
    input.signal.removeEventListener("abort", forwardAbort);
    if (!lifecycle.signal.aborted) {
      lifecycle.abort(new DOMException("Shutdown requested", "AbortError"));
    }
    await closeServer(input.server, httpDrainTimeoutMs);
    if (runtimeTask !== undefined) await runtimeTask;
  }
}

function listen(server: Server, host: string, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const failed = (error: Error): void => reject(error);
    server.once("error", failed);
    server.listen(port, host, () => {
      server.removeListener("error", failed);
      resolve();
    });
  });
}

async function closeServer(server: Server, timeoutMs: number): Promise<void> {
  if (!server.listening) return;
  let timeout: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<"timeout">((resolve) => {
    timeout = setTimeout(() => resolve("timeout"), timeoutMs);
    timeout.unref();
  });
  const closed = new Promise<"closed">((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) resolve("closed");
      else reject(error);
    });
  });
  try {
    if ((await Promise.race([closed, deadline])) === "timeout") {
      server.closeAllConnections();
      await closed;
    }
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

async function shutdownTelemetry(
  telemetry: NotifierTelemetryRuntime,
  signal: AbortSignal,
  failures: unknown[],
): Promise<void> {
  await collectFailure(() => telemetry.forceFlush(signal), failures);
  await collectFailure(() => telemetry.shutdown(signal), failures);
}

async function collectFailure(
  operation: () => Promise<void>,
  failures: unknown[],
): Promise<void> {
  try {
    await operation();
  } catch (error) {
    failures.push(error);
  }
}

function processSignals(): Readonly<{
  signal: AbortSignal;
  close(): void;
}> {
  const controller = new AbortController();
  const terminate = (): void => {
    controller.abort(new DOMException("Termination requested", "AbortError"));
  };
  process.once("SIGINT", terminate);
  process.once("SIGTERM", terminate);
  return Object.freeze({
    signal: controller.signal,
    close(): void {
      process.removeListener("SIGINT", terminate);
      process.removeListener("SIGTERM", terminate);
    },
  });
}

function safeErrorClass(error: unknown): string {
  if (
    error instanceof Error &&
    /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(error.name)
  ) {
    return error.name;
  }
  return "UnknownError";
}

async function main(): Promise<void> {
  const signals = processSignals();
  try {
    await runNotifier(signals.signal);
  } finally {
    signals.close();
  }
}

const executable = process.argv[1];
if (
  executable !== undefined &&
  import.meta.url === pathToFileURL(executable).href
) {
  void main().catch((error: unknown) => {
    process.stderr.write(
      `${JSON.stringify({
        timestamp: new Date().toISOString(),
        level: "error",
        service: "notifier",
        event: "notifier_stopped",
        errorClass: safeErrorClass(error),
      })}\n`,
    );
    process.exitCode = 1;
  });
}
