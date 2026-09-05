import {
  ROOT_CONTEXT,
  SpanKind,
  SpanStatusCode,
  TraceFlags,
  context,
  trace,
  type Span,
  type SpanContext,
  type Tracer,
} from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import {
  TraceState,
  W3CTraceContextPropagator,
  setGlobalErrorHandler,
} from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-proto";
import { resourceFromAttributes } from "@opentelemetry/resources";
import {
  BatchSpanProcessor,
  NodeTracerProvider,
  ParentBasedSampler,
  TraceIdRatioBasedSampler,
} from "@opentelemetry/sdk-trace-node";

import {
  NotificationConfigurationError,
  NotificationValidationError,
} from "./errors.js";

const instrumentationName = "@periapsis/notifier/telemetry";
const expectedServiceName = "periapsis-notifier";
const defaultExportTimeoutMs = 5_000;
const defaultSampleRatio = 0.1;
const maximumEndpointBytes = 2_048;
const maximumTraceStateBytes = 512;
const traceParentPattern = /^00-([0-9a-f]{32})-([0-9a-f]{16})-(00|01)$/u;
const allZeroTraceId = "0".repeat(32);
const allZeroSpanId = "0".repeat(16);
const safeErrorClassPattern = /^[A-Za-z][A-Za-z0-9]{0,63}$/u;
const supportedHttpRoutes = new Set<NotifierHttpRoute>([
  "/health/live",
  "/health/ready",
  "/internal/v1/notification-preview",
  "/internal/v1/smtp-health",
  "/metrics",
  "/invalid",
  "/unknown",
]);
const supportedDatabaseOperations = new Set<NotifierDatabaseOperation>([
  "claim_delivery",
  "claim_fanout",
  "commit_fanout",
  "complete_delivery",
  "complete_replay",
  "dead_letter_delivery",
  "dead_letter_fanout",
  "heartbeat_delivery",
  "heartbeat_fanout",
  "load_fanout",
  "readiness",
  "reserve_delivery",
  "retry_delivery",
  "retry_fanout",
]);
const consumerChannels = new Map<NotifierConsumerOperation, string>([
  ["email_delivery", "email"],
  ["fanout", "fanout"],
  ["webhook_delivery", "webhook"],
]);
const consumerOutcomes = new Set<NotifierConsumerOutcome>([
  "committed",
  "dead_lettered",
  "delivered",
  "fenced",
  "replayed",
  "retried",
  "uncertain",
]);
const authenticConfigurations = new WeakSet<object>();

export type NotifierEnvironment = "development" | "test" | "production";

export interface NotifierTelemetryConfiguration {
  readonly enabled: boolean;
  readonly endpoint?: string;
  readonly environment: NotifierEnvironment;
  readonly exportTimeoutMs: number;
  readonly sampleRatio: number;
  readonly serviceName: typeof expectedServiceName;
  readonly serviceVersion: string;
}

export interface PersistedTraceContext {
  readonly traceParent: string;
  readonly traceState?: string;
}

export type NotifierConsumerOperation =
  "email_delivery" | "fanout" | "webhook_delivery";

export type NotifierConsumerOutcome =
  | "committed"
  | "dead_lettered"
  | "delivered"
  | "fenced"
  | "replayed"
  | "retried"
  | "uncertain";

export type NotifierDatabaseOperation =
  | "claim_delivery"
  | "claim_fanout"
  | "commit_fanout"
  | "complete_delivery"
  | "complete_replay"
  | "dead_letter_delivery"
  | "dead_letter_fanout"
  | "heartbeat_delivery"
  | "heartbeat_fanout"
  | "load_fanout"
  | "readiness"
  | "reserve_delivery"
  | "retry_delivery"
  | "retry_fanout";

export type NotifierHttpRoute =
  | "/health/live"
  | "/health/ready"
  | "/internal/v1/notification-preview"
  | "/internal/v1/smtp-health"
  | "/metrics"
  | "/invalid"
  | "/unknown";

export interface NotifierHttpTraceInput {
  readonly method: string | undefined;
  readonly rawHeaders: readonly string[];
  readonly route: NotifierHttpRoute;
  readonly statusCode: () => number;
}

export interface TraceCorrelation {
  readonly spanId: string;
  readonly traceId: string;
  readonly traceSampled: boolean;
}

export interface NotificationTracing {
  runConsumerSpan<T>(
    operation: NotifierConsumerOperation,
    producer: PersistedTraceContext | undefined,
    work: () => Promise<T>,
    outcome: (value: T) => NotifierConsumerOutcome,
  ): Promise<T>;
  runDatabaseSpan<T>(
    operation: NotifierDatabaseOperation,
    work: () => Promise<T>,
  ): Promise<T>;
  runHttpServerSpan<T>(
    input: NotifierHttpTraceInput,
    work: () => Promise<T>,
  ): Promise<T>;
}

export interface NotifierTelemetryRuntime extends NotificationTracing {
  readonly enabled: boolean;
  forceFlush(signal: AbortSignal): Promise<void>;
  shutdown(signal: AbortSignal): Promise<void>;
}

export interface TelemetryDiagnosticLogger {
  error(
    event: string,
    attributes: Readonly<Record<string, string | number | boolean>>,
  ): void;
}

export function loadNotifierTelemetryConfiguration(
  environment: NotifierEnvironment,
  serviceVersionInput: string,
  env: Readonly<Record<string, string | undefined>>,
): NotifierTelemetryConfiguration {
  if (
    environment !== "development" &&
    environment !== "test" &&
    environment !== "production"
  ) {
    throw new NotificationValidationError(
      "OpenTelemetry environment is unsupported",
    );
  }
  const serviceVersion = boundedPrintable(
    serviceVersionInput,
    1,
    128,
    "OpenTelemetry service version",
  );
  const disabled = env["OTEL_SDK_DISABLED"];
  if (disabled !== "true" && disabled !== "false") {
    throw new NotificationValidationError(
      "OTEL_SDK_DISABLED must be explicitly true or false",
    );
  }
  const configuredServiceName = env["OTEL_SERVICE_NAME"];
  if (
    configuredServiceName !== undefined &&
    configuredServiceName !== expectedServiceName
  ) {
    throw new NotificationValidationError(
      "OTEL_SERVICE_NAME does not match the notifier process",
    );
  }
  if (disabled === "true") {
    return authenticateConfiguration({
      enabled: false,
      environment,
      exportTimeoutMs: defaultExportTimeoutMs,
      sampleRatio: defaultSampleRatio,
      serviceName: expectedServiceName,
      serviceVersion,
    });
  }
  if (configuredServiceName === undefined) {
    throw new NotificationValidationError(
      "OTEL_SERVICE_NAME is required when tracing is enabled",
    );
  }
  if (env["OTEL_EXPORTER_OTLP_PROTOCOL"] !== "http/protobuf") {
    throw new NotificationValidationError(
      "OTEL_EXPORTER_OTLP_PROTOCOL must be http/protobuf",
    );
  }
  const endpointInput = env["OTEL_EXPORTER_OTLP_ENDPOINT"];
  if (endpointInput === undefined) {
    throw new NotificationValidationError(
      "OTEL_EXPORTER_OTLP_ENDPOINT is required",
    );
  }
  const endpoint = canonicalEndpoint(endpointInput);
  if (
    env["OTEL_PROPAGATORS"] !== undefined &&
    env["OTEL_PROPAGATORS"] !== "tracecontext"
  ) {
    throw new NotificationValidationError(
      "OTEL_PROPAGATORS must be tracecontext",
    );
  }
  if (
    env["OTEL_TRACES_SAMPLER"] !== undefined &&
    env["OTEL_TRACES_SAMPLER"] !== "parentbased_traceidratio"
  ) {
    throw new NotificationValidationError(
      "OTEL_TRACES_SAMPLER must be parentbased_traceidratio",
    );
  }
  const sampleRatioInput = env["OTEL_TRACES_SAMPLER_ARG"];
  const sampleRatio =
    sampleRatioInput === undefined
      ? defaultSampleRatio
      : parseCanonicalRatio(sampleRatioInput);
  const timeoutInput = env["PERIAPSIS_OTEL_EXPORT_TIMEOUT_MS"];
  const exportTimeoutMs =
    timeoutInput === undefined
      ? defaultExportTimeoutMs
      : parseBoundedInteger(timeoutInput, 100, 30_000, "OTel export timeout");

  const supported = new Set([
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_PROTOCOL",
    "OTEL_PROPAGATORS",
    "OTEL_SDK_DISABLED",
    "OTEL_SERVICE_NAME",
    "OTEL_TRACES_SAMPLER",
    "OTEL_TRACES_SAMPLER_ARG",
  ]);
  const unsupported = Object.keys(env)
    .filter((key) => key.startsWith("OTEL_") && !supported.has(key))
    .toSorted();
  if (unsupported.length > 0) {
    throw new NotificationValidationError(
      `${unsupported[0]} is not supported by the notifier telemetry boundary`,
    );
  }
  return authenticateConfiguration({
    enabled: true,
    endpoint,
    environment,
    exportTimeoutMs,
    sampleRatio,
    serviceName: expectedServiceName,
    serviceVersion,
  });
}

export function startNotifierTelemetry(
  configuration: NotifierTelemetryConfiguration,
  logger: TelemetryDiagnosticLogger,
): NotifierTelemetryRuntime {
  if (!authenticConfigurations.has(configuration)) {
    throw new NotificationConfigurationError(
      "OpenTelemetry configuration was not created by its loader",
    );
  }
  if (!configuration.enabled) {
    return new TelemetryRuntime(false);
  }
  if (
    logger === null ||
    typeof logger !== "object" ||
    typeof logger.error !== "function"
  ) {
    throw new NotificationConfigurationError(
      "OpenTelemetry diagnostic logger is unavailable",
    );
  }
  const endpoint = configuration.endpoint;
  if (endpoint === undefined) {
    throw new NotificationConfigurationError(
      "OpenTelemetry configuration is unavailable",
    );
  }
  try {
    setGlobalErrorHandler((error) => {
      try {
        logger.error("otel_export_failed", {
          errorClass: safeErrorClass(error),
        });
      } catch {
        // Export diagnostics are best effort and may never break the workload.
      }
    });
    const exporter = new OTLPTraceExporter({
      concurrencyLimit: 2,
      keepAlive: true,
      timeoutMillis: configuration.exportTimeoutMs,
      url: `${endpoint}/v1/traces`,
    });
    const rootSampler = new TraceIdRatioBasedSampler(configuration.sampleRatio);
    const provider = new NodeTracerProvider({
      forceFlushTimeoutMillis: configuration.exportTimeoutMs,
      generalLimits: {
        attributeCountLimit: 32,
        attributeValueLengthLimit: 256,
      },
      resource: resourceFromAttributes({
        "deployment.environment.name": configuration.environment,
        "service.name": configuration.serviceName,
        "service.version": configuration.serviceVersion,
      }),
      sampler: new ParentBasedSampler({
        remoteParentNotSampled: rootSampler,
        remoteParentSampled: rootSampler,
        root: rootSampler,
      }),
      spanLimits: {
        attributeCountLimit: 32,
        attributePerEventCountLimit: 0,
        attributePerLinkCountLimit: 8,
        attributeValueLengthLimit: 256,
        eventCountLimit: 0,
        linkCountLimit: 4,
      },
      spanProcessors: [
        new BatchSpanProcessor(exporter, {
          exportTimeoutMillis: configuration.exportTimeoutMs,
          maxExportBatchSize: 256,
          maxQueueSize: 2_048,
          scheduledDelayMillis: 2_000,
        }),
      ],
    });
    provider.register({
      contextManager: new AsyncLocalStorageContextManager(),
      propagator: new W3CTraceContextPropagator(),
    });
    return new TelemetryRuntime(true, provider);
  } catch {
    throw new NotificationConfigurationError(
      "OpenTelemetry runtime initialization failed",
    );
  }
}

export function canonicalPersistedTraceContext(
  input: unknown,
): PersistedTraceContext {
  if (!isPlainRecord(input)) {
    throw invalidPersistedTraceContext();
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const keys = Object.keys(descriptors).toSorted();
  if (
    (keys.length !== 1 && keys.length !== 2) ||
    keys[0] !== "traceParent" ||
    (keys.length === 2 && keys[1] !== "traceState")
  ) {
    throw invalidPersistedTraceContext();
  }
  const traceParentDescriptor = descriptors["traceParent"];
  const traceStateDescriptor = descriptors["traceState"];
  if (
    traceParentDescriptor === undefined ||
    !("value" in traceParentDescriptor) ||
    (traceStateDescriptor !== undefined && !("value" in traceStateDescriptor))
  ) {
    throw invalidPersistedTraceContext();
  }
  const parsed = parseTraceParent(traceParentDescriptor.value);
  const traceState = parseTraceState(traceStateDescriptor?.value);
  return Object.freeze({
    traceParent: formatTraceParent(parsed),
    ...(traceState === undefined ? {} : { traceState }),
  });
}

export function persistedTraceContextFromActive():
  PersistedTraceContext | undefined {
  const spanContext = trace.getSpanContext(context.active());
  if (
    spanContext === undefined ||
    spanContext.isRemote === true ||
    !isCanonicalSpanContext(spanContext)
  ) {
    return undefined;
  }
  const traceState = spanContext.traceState?.serialize();
  return Object.freeze({
    traceParent: formatTraceParent(spanContext),
    ...(traceState === undefined || traceState === "" ? {} : { traceState }),
  });
}

export function activeTraceCorrelation(): TraceCorrelation | undefined {
  const spanContext = trace.getSpanContext(context.active());
  if (spanContext === undefined || !isCanonicalSpanContext(spanContext)) {
    return undefined;
  }
  return Object.freeze({
    spanId: spanContext.spanId,
    traceId: spanContext.traceId,
    traceSampled: (spanContext.traceFlags & TraceFlags.SAMPLED) !== 0,
  });
}

class TelemetryRuntime implements NotifierTelemetryRuntime {
  readonly enabled: boolean;
  readonly #provider: NodeTracerProvider | undefined;
  readonly #tracer: Tracer | undefined;
  #shutdownPromise: Promise<void> | undefined;

  constructor(enabled: boolean, provider?: NodeTracerProvider) {
    if (enabled !== (provider !== undefined)) {
      throw new NotificationConfigurationError(
        "OpenTelemetry runtime construction failed",
      );
    }
    this.enabled = enabled;
    this.#provider = provider;
    this.#tracer = provider?.getTracer(instrumentationName);
  }

  async runConsumerSpan<T>(
    operation: NotifierConsumerOperation,
    producerInput: PersistedTraceContext | undefined,
    work: () => Promise<T>,
    outcome: (value: T) => NotifierConsumerOutcome,
  ): Promise<T> {
    const channel = consumerChannels.get(operation);
    if (channel === undefined || typeof outcome !== "function") {
      throw new NotificationValidationError(
        "notification consumer operation is unsupported",
      );
    }
    if (!this.enabled || this.#tracer === undefined) {
      const value = await work();
      requireConsumerOutcome(outcome(value));
      return value;
    }
    const producer =
      producerInput === undefined
        ? undefined
        : parsePersistedSpanContext(producerInput);
    return this.#tracer.startActiveSpan(
      `notification ${operation}`,
      {
        attributes: {
          "messaging.operation.name": operation,
          "messaging.operation.type": "process",
          "messaging.system": "periapsis.outbox",
          "periapsis.notification.channel": channel,
        },
        kind: SpanKind.CONSUMER,
        ...(producer === undefined ? {} : { links: [{ context: producer }] }),
      },
      ROOT_CONTEXT,
      async (span) =>
        runSpan(span, async () => {
          const value = await work();
          span.setAttribute(
            "periapsis.notification.outcome",
            requireConsumerOutcome(outcome(value)),
          );
          return value;
        }),
    );
  }

  async runDatabaseSpan<T>(
    operation: NotifierDatabaseOperation,
    work: () => Promise<T>,
  ): Promise<T> {
    if (!supportedDatabaseOperations.has(operation)) {
      throw new NotificationValidationError(
        "notification database operation is unsupported",
      );
    }
    if (!this.enabled || this.#tracer === undefined) return work();
    return this.#tracer.startActiveSpan(
      `DB ${operation}`,
      {
        attributes: {
          "db.operation.name": operation,
          "db.system.name": "postgresql",
        },
        kind: SpanKind.CLIENT,
      },
      async (span) => runSpan(span, work),
    );
  }

  async runHttpServerSpan<T>(
    input: NotifierHttpTraceInput,
    work: () => Promise<T>,
  ): Promise<T> {
    if (!supportedHttpRoutes.has(input.route)) {
      throw new NotificationValidationError(
        "notifier HTTP trace route is unsupported",
      );
    }
    if (!this.enabled || this.#tracer === undefined) return work();
    const method = canonicalHttpMethod(input.method);
    const remote = extractHttpSpanContext(input.rawHeaders);
    const parent =
      remote === undefined
        ? ROOT_CONTEXT
        : trace.setSpanContext(ROOT_CONTEXT, remote);
    return this.#tracer.startActiveSpan(
      `${method} ${input.route}`,
      {
        attributes: {
          "http.request.method": method,
          "http.route": input.route,
        },
        kind: SpanKind.SERVER,
      },
      parent,
      async (span) => {
        try {
          return await runSpan(span, work, false);
        } finally {
          setHttpStatus(span, input.statusCode);
          span.end();
        }
      },
    );
  }

  async forceFlush(signal: AbortSignal): Promise<void> {
    if (!this.enabled || this.#provider === undefined) return;
    await boundedOperation(() => this.#provider!.forceFlush(), signal, "flush");
  }

  async shutdown(signal: AbortSignal): Promise<void> {
    if (!this.enabled || this.#provider === undefined) return;
    await boundedOperation(
      () => {
        this.#shutdownPromise ??= this.#provider!.shutdown();
        return this.#shutdownPromise;
      },
      signal,
      "shutdown",
    );
  }
}

async function runSpan<T>(
  span: Span,
  work: () => Promise<T>,
  end = true,
): Promise<T> {
  try {
    return await work();
  } catch (error) {
    span.setAttribute("error.type", safeErrorClass(error));
    span.setStatus({ code: SpanStatusCode.ERROR });
    throw error;
  } finally {
    if (end) span.end();
  }
}

function setHttpStatus(span: Span, statusCode: () => number): void {
  let status: number;
  try {
    status = statusCode();
  } catch {
    return;
  }
  if (!Number.isSafeInteger(status) || status < 100 || status > 599) return;
  span.setAttribute("http.response.status_code", status);
  if (status >= 500) span.setStatus({ code: SpanStatusCode.ERROR });
}

function parsePersistedSpanContext(input: PersistedTraceContext): SpanContext {
  const canonical = canonicalPersistedTraceContext(input);
  const parsed = parseTraceParent(canonical.traceParent);
  return {
    ...parsed,
    isRemote: true,
    ...(canonical.traceState === undefined
      ? {}
      : { traceState: new TraceState(canonical.traceState) }),
  };
}

function parseTraceParent(value: unknown): SpanContext {
  if (typeof value !== "string") throw invalidPersistedTraceContext();
  const match = traceParentPattern.exec(value);
  const traceId = match?.[1];
  const spanId = match?.[2];
  const flags = match?.[3];
  if (
    traceId === undefined ||
    spanId === undefined ||
    flags === undefined ||
    traceId === allZeroTraceId ||
    spanId === allZeroSpanId
  ) {
    throw invalidPersistedTraceContext();
  }
  return {
    spanId,
    traceFlags: flags === "01" ? TraceFlags.SAMPLED : TraceFlags.NONE,
    traceId,
  };
}

function parseTraceState(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    Buffer.byteLength(value, "utf8") > maximumTraceStateBytes ||
    containsControl(value)
  ) {
    throw invalidPersistedTraceContext();
  }
  const traceState = new TraceState(value);
  if (traceState.serialize() !== value) throw invalidPersistedTraceContext();
  return value;
}

function formatTraceParent(spanContext: SpanContext): string {
  return `00-${spanContext.traceId}-${spanContext.spanId}-${
    (spanContext.traceFlags & TraceFlags.SAMPLED) === 0 ? "00" : "01"
  }`;
}

function extractHttpSpanContext(
  rawHeaders: readonly string[],
): SpanContext | undefined {
  if (rawHeaders.length % 2 !== 0 || rawHeaders.length > 128) return undefined;
  let traceParent: string | undefined;
  let traceState: string | undefined;
  for (let index = 0; index < rawHeaders.length; index += 2) {
    const name = rawHeaders[index]?.toLowerCase();
    if (name !== "traceparent" && name !== "tracestate") continue;
    const value = rawHeaders[index + 1];
    if (value === undefined || containsControl(value)) return undefined;
    if (name === "traceparent") {
      if (traceParent !== undefined) return undefined;
      traceParent = value;
    } else {
      if (traceState !== undefined) return undefined;
      traceState = value;
    }
  }
  if (traceParent === undefined) return undefined;
  try {
    return parsePersistedSpanContext({
      traceParent,
      ...(traceState === undefined ? {} : { traceState }),
    });
  } catch {
    return undefined;
  }
}

function canonicalHttpMethod(value: string | undefined): string {
  if (value === undefined || value.length < 1 || value.length > 16) {
    return "OTHER";
  }
  const method = value.toUpperCase();
  return method !== undefined &&
    ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"].includes(
      method,
    )
    ? method
    : "OTHER";
}

function canonicalEndpoint(input: string): string {
  boundedPrintable(input, 1, maximumEndpointBytes, "OTLP endpoint");
  if (input.trim() !== input) throw invalidEndpoint();
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    throw invalidEndpoint();
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.hostname === "" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.pathname !== "/"
  ) {
    throw invalidEndpoint();
  }
  const canonical = `${parsed.protocol}//${parsed.host}`;
  if (input !== canonical && input !== `${canonical}/`) throw invalidEndpoint();
  return canonical;
}

function parseCanonicalRatio(value: string): number {
  if (value !== "0" && value !== "1" && !/^0\.[0-9]{0,9}[1-9]$/u.test(value)) {
    throw new NotificationValidationError(
      "OTEL_TRACES_SAMPLER_ARG must be a canonical ratio from 0 to 1",
    );
  }
  const result = Number(value);
  if (!Number.isFinite(result) || result < 0 || result > 1) {
    throw new NotificationValidationError(
      "OTEL_TRACES_SAMPLER_ARG must be a canonical ratio from 0 to 1",
    );
  }
  return result;
}

function parseBoundedInteger(
  value: string,
  minimum: number,
  maximum: number,
  field: string,
): number {
  if (!/^(?:0|[1-9][0-9]*)$/u.test(value)) {
    throw new NotificationValidationError(`${field} is invalid`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new NotificationValidationError(`${field} is invalid`);
  }
  return parsed;
}

function authenticateConfiguration(
  input: NotifierTelemetryConfiguration,
): NotifierTelemetryConfiguration {
  const configuration = Object.freeze({ ...input });
  authenticConfigurations.add(configuration);
  return configuration;
}

function boundedPrintable(
  value: string,
  minimum: number,
  maximum: number,
  field: string,
): string {
  if (
    value.length < minimum ||
    Buffer.byteLength(value, "utf8") > maximum ||
    containsControl(value)
  ) {
    throw new NotificationValidationError(`${field} is invalid`);
  }
  return value;
}

function containsControl(value: string): boolean {
  for (const character of value) {
    const code = character.codePointAt(0) ?? 0;
    if (code < 0x20 || code > 0x7e) return true;
  }
  return false;
}

function isPlainRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  try {
    const prototype = Object.getPrototypeOf(value) as unknown;
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function isCanonicalSpanContext(value: SpanContext): boolean {
  return (
    /^[0-9a-f]{32}$/u.test(value.traceId) &&
    value.traceId !== allZeroTraceId &&
    /^[0-9a-f]{16}$/u.test(value.spanId) &&
    value.spanId !== allZeroSpanId
  );
}

async function boundedOperation(
  start: () => Promise<void>,
  signal: AbortSignal,
  name: "flush" | "shutdown",
): Promise<void> {
  if (signal.aborted) {
    throw new NotificationConfigurationError(
      `OpenTelemetry ${name} deadline expired`,
    );
  }
  let operation: Promise<void>;
  try {
    operation = start();
  } catch {
    throw new NotificationConfigurationError(`OpenTelemetry ${name} failed`);
  }
  const result = operation.then(
    () => ({ kind: "completed" as const }),
    () => ({ kind: "failed" as const }),
  );
  let onAbort: (() => void) | undefined;
  const aborted = new Promise<{ readonly kind: "aborted" }>((resolve) => {
    onAbort = () => resolve({ kind: "aborted" });
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try {
    const outcome = await Promise.race([result, aborted]);
    if (outcome.kind !== "completed") {
      throw new NotificationConfigurationError(`OpenTelemetry ${name} failed`);
    }
  } finally {
    if (onAbort !== undefined) signal.removeEventListener("abort", onAbort);
  }
}

function safeErrorClass(error: unknown): string {
  try {
    if (
      error instanceof Error &&
      safeErrorClassPattern.test(error.constructor.name)
    ) {
      return error.constructor.name;
    }
  } catch {
    return "UnknownError";
  }
  return "UnknownError";
}

function requireConsumerOutcome(
  value: NotifierConsumerOutcome,
): NotifierConsumerOutcome {
  if (!consumerOutcomes.has(value)) {
    throw new NotificationValidationError(
      "notification consumer outcome is unsupported",
    );
  }
  return value;
}

function invalidPersistedTraceContext(): NotificationValidationError {
  return new NotificationValidationError(
    "persisted OpenTelemetry span context is invalid",
  );
}

function invalidEndpoint(): NotificationValidationError {
  return new NotificationValidationError(
    "OTEL_EXPORTER_OTLP_ENDPOINT is invalid",
  );
}
