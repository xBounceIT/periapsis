import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";

import type { DeliveryLogger } from "./delivery.js";
import {
  NotificationRenderError,
  NotificationValidationError,
} from "./errors.js";
import { canonicalizeNotificationContext } from "./event.js";
import type { NotifierMetrics } from "./observability.js";
import type { SmtpHealthProber } from "./smtp-health.js";
import {
  createNotificationTemplate,
  renderNotificationTemplate,
  type NotificationTemplateInput,
  type RenderedNotification,
} from "./template.js";
import type { NotificationTracing, NotifierHttpRoute } from "./telemetry.js";
import { parseStrictJson } from "./validation.js";

const maximumPreviewBodyBytes = 512 * 1_024;
const maximumSmtpHealthBodyBytes = 4 * 1_024;
const smtpHealthTimeoutMs = 30_000;
const bearerPattern = /^[A-Za-z0-9._~+/=-]{32,512}$/u;

export interface NotificationPreviewer {
  preview(input: unknown): RenderedNotification;
}

export interface NotifierHealthReader {
  readiness(signal: AbortSignal): Promise<{
    ready: boolean;
    queueDepth: number;
  }>;
}

export class SafeNotificationPreviewer implements NotificationPreviewer {
  preview(input: unknown): RenderedNotification {
    const root = requireRecord(input, "preview request");
    rejectUnknownKeys(root, ["audience", "context", "template"]);
    const audience = requireString(root, "audience");
    if (audience !== "operator" && audience !== "customer") {
      throw new NotificationValidationError("preview audience is unsupported");
    }
    const template = parseTemplate(root["template"]);
    const context = canonicalizeNotificationContext(root["context"]);
    return renderNotificationTemplate(template, context, {
      audience,
      timeoutMs: 100,
      maximumOutputBytes: 256 * 1_024,
    });
  }
}

export class InternalTokenAuthenticator {
  readonly #digest: Buffer;
  #closed = false;

  constructor(secret: Uint8Array) {
    let token: string;
    try {
      token = new TextDecoder("utf-8", { fatal: true }).decode(secret);
    } catch {
      token = "";
    }
    if (
      secret.byteLength < 32 ||
      secret.byteLength > 512 ||
      !bearerPattern.test(token)
    ) {
      throw new NotificationValidationError(
        "internal preview token is not a strong ASCII bearer token",
      );
    }
    this.#digest = createHash("sha256").update(secret).digest();
  }

  authenticate(header: string | undefined): boolean {
    const match = /^Bearer ([^\s]+)$/u.exec(header ?? "");
    const token = match?.[1] ?? "";
    const candidate = createHash("sha256").update(token, "utf8").digest();
    return (
      !this.#closed &&
      bearerPattern.test(token) &&
      timingSafeEqual(candidate, this.#digest)
    );
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#digest.fill(0);
  }
}

export function createNotifierHttpServer(dependencies: {
  runtime: NotifierHealthReader;
  metrics: NotifierMetrics;
  previewer: NotificationPreviewer;
  smtpHealth: SmtpHealthProber;
  authenticator: InternalTokenAuthenticator;
  logger: DeliveryLogger;
  tracing: NotificationTracing;
  release: string;
  maximumConcurrentPreviews?: number;
  maximumConcurrentSmtpHealth?: number;
}): Server {
  const maximumConcurrentPreviews = dependencies.maximumConcurrentPreviews ?? 4;
  const maximumConcurrentSmtpHealth =
    dependencies.maximumConcurrentSmtpHealth ?? 4;
  if (
    !Number.isSafeInteger(maximumConcurrentPreviews) ||
    maximumConcurrentPreviews < 1 ||
    maximumConcurrentPreviews > 32
  ) {
    throw new NotificationValidationError(
      "maximum concurrent previews is outside its supported range",
    );
  }
  if (
    !Number.isSafeInteger(maximumConcurrentSmtpHealth) ||
    maximumConcurrentSmtpHealth < 1 ||
    maximumConcurrentSmtpHealth > 32
  ) {
    throw new NotificationValidationError(
      "maximum concurrent SMTP health probes is outside its supported range",
    );
  }
  let activePreviews = 0;
  let activeSmtpHealth = 0;
  const server = createServer(
    { joinDuplicateHeaders: true },
    (request, response) => {
      const startedAt = performance.now();
      const requestId = randomUUID();
      void dependencies.tracing
        .runHttpServerSpan(
          {
            method: request.method,
            rawHeaders: request.rawHeaders,
            route: safePath(request.url),
            statusCode: () => response.statusCode,
          },
          async () => {
            setSecurityHeaders(response, requestId);
            response.once("finish", () => {
              dependencies.logger.info("notifier_http_request", {
                requestId,
                method: request.method ?? "UNKNOWN",
                path: safePath(request.url),
                status: response.statusCode,
                durationMs:
                  Math.round((performance.now() - startedAt) * 100) / 100,
              });
            });
            try {
              await route(request, response);
            } catch (error) {
              dependencies.logger.error("notifier_http_failure", {
                requestId,
                errorClass: safeErrorClass(error),
              });
              if (response.headersSent) {
                response.destroy(error instanceof Error ? error : undefined);
                return;
              }
              sendProblem(response, 500, "Internal server error", requestId);
            }
          },
        )
        .catch(() => {
          dependencies.logger.error("notifier_http_failure", {
            requestId,
            errorClass: "TelemetryFailure",
          });
          if (response.headersSent) {
            response.destroy();
            return;
          }
          setSecurityHeaders(response, requestId);
          sendProblem(response, 500, "Internal server error", requestId);
        });

      async function route(
        incoming: IncomingMessage,
        outgoing: ServerResponse,
      ): Promise<void> {
        const method = incoming.method ?? "GET";
        let target: URL;
        try {
          target = new URL(incoming.url ?? "/", "http://notifier.internal");
        } catch {
          sendProblem(outgoing, 400, "Malformed request target", requestId);
          return;
        }
        if (target.search !== "") {
          sendProblem(
            outgoing,
            400,
            "Query parameters are not supported",
            requestId,
          );
          return;
        }
        if (method === "GET" && target.pathname === "/health/live") {
          sendJson(outgoing, 200, {
            status: "alive",
            service: "notifier",
            version: dependencies.release,
          });
          return;
        }
        if (method === "GET" && target.pathname === "/health/ready") {
          const readiness = await dependencies.runtime.readiness(
            new AbortController().signal,
          );
          sendJson(outgoing, readiness.ready ? 200 : 503, {
            status: readiness.ready ? "ready" : "unavailable",
            service: "notifier",
            version: dependencies.release,
          });
          return;
        }
        if (method === "GET" && target.pathname === "/metrics") {
          const payload = dependencies.metrics.renderPrometheus();
          outgoing.statusCode = 200;
          outgoing.setHeader(
            "Content-Type",
            "text/plain; version=0.0.4; charset=utf-8",
          );
          outgoing.setHeader("Cache-Control", "no-store");
          outgoing.setHeader("Content-Length", Buffer.byteLength(payload));
          outgoing.end(payload);
          return;
        }
        if (
          method === "POST" &&
          target.pathname === "/internal/v1/notification-preview"
        ) {
          if (
            !dependencies.authenticator.authenticate(
              singleHeader(incoming.headers.authorization),
            )
          ) {
            outgoing.setHeader("WWW-Authenticate", "Bearer");
            sendProblem(outgoing, 401, "Unauthorized", requestId);
            return;
          }
          if (
            !isJsonMediaType(singleHeader(incoming.headers["content-type"]))
          ) {
            sendProblem(outgoing, 415, "JSON content type required", requestId);
            return;
          }
          if (activePreviews >= maximumConcurrentPreviews) {
            outgoing.setHeader("Retry-After", "1");
            sendProblem(outgoing, 429, "Preview capacity exceeded", requestId);
            return;
          }
          activePreviews += 1;
          try {
            const payload = await readJson(incoming, maximumPreviewBodyBytes);
            const rendered = dependencies.previewer.preview(payload);
            outgoing.setHeader("Cache-Control", "no-store");
            sendJson(outgoing, 200, rendered);
          } catch (error) {
            if (
              error instanceof NotificationValidationError ||
              error instanceof NotificationRenderError ||
              error instanceof SyntaxError
            ) {
              sendProblem(outgoing, 400, "Invalid preview request", requestId);
              return;
            }
            if (error instanceof PayloadTooLargeError) {
              sendProblem(outgoing, 413, "Request body too large", requestId);
              return;
            }
            throw error;
          } finally {
            activePreviews -= 1;
          }
          return;
        }
        if (
          method === "POST" &&
          target.pathname === "/internal/v1/smtp-health"
        ) {
          if (
            !dependencies.authenticator.authenticate(
              singleHeader(incoming.headers.authorization),
            )
          ) {
            outgoing.setHeader("WWW-Authenticate", "Bearer");
            sendProblem(outgoing, 401, "Unauthorized", requestId);
            return;
          }
          if (
            !isJsonMediaType(singleHeader(incoming.headers["content-type"]))
          ) {
            sendProblem(outgoing, 415, "JSON content type required", requestId);
            return;
          }
          if (activeSmtpHealth >= maximumConcurrentSmtpHealth) {
            outgoing.setHeader("Retry-After", "1");
            sendProblem(
              outgoing,
              429,
              "SMTP health capacity exceeded",
              requestId,
            );
            return;
          }
          activeSmtpHealth += 1;
          const lifecycle = new AbortController();
          const timeout = setTimeout(() => {
            lifecycle.abort(
              new DOMException("SMTP health timed out", "TimeoutError"),
            );
          }, smtpHealthTimeoutMs);
          timeout.unref();
          const abort = (): void => {
            lifecycle.abort(new DOMException("Request closed", "AbortError"));
          };
          incoming.once("aborted", abort);
          outgoing.once("close", abort);
          try {
            const payload = await readJson(
              incoming,
              maximumSmtpHealthBodyBytes,
            );
            const result = await dependencies.smtpHealth.probe(
              payload,
              lifecycle.signal,
            );
            if (lifecycle.signal.aborted) return;
            outgoing.setHeader("Cache-Control", "no-store");
            sendJson(outgoing, 200, result);
          } catch (error) {
            if (lifecycle.signal.aborted) {
              if (!outgoing.headersSent && !outgoing.destroyed) {
                sendProblem(
                  outgoing,
                  503,
                  "SMTP health unavailable",
                  requestId,
                );
              }
              return;
            }
            if (
              error instanceof NotificationValidationError ||
              error instanceof SyntaxError
            ) {
              sendProblem(
                outgoing,
                400,
                "Invalid SMTP health request",
                requestId,
              );
              return;
            }
            if (error instanceof PayloadTooLargeError) {
              sendProblem(outgoing, 413, "Request body too large", requestId);
              return;
            }
            throw error;
          } finally {
            clearTimeout(timeout);
            incoming.removeListener("aborted", abort);
            outgoing.removeListener("close", abort);
            activeSmtpHealth -= 1;
          }
          return;
        }
        if (
          target.pathname === "/internal/v1/notification-preview" ||
          target.pathname === "/internal/v1/smtp-health" ||
          target.pathname.startsWith("/health/") ||
          target.pathname === "/metrics"
        ) {
          sendProblem(outgoing, 405, "Method not allowed", requestId);
          return;
        }
        sendProblem(outgoing, 404, "Resource not found", requestId);
      }
    },
  );
  server.requestTimeout = 10_000;
  server.headersTimeout = 5_000;
  server.keepAliveTimeout = 5_000;
  server.timeout = smtpHealthTimeoutMs + 5_000;
  server.maxHeadersCount = 64;
  server.maxRequestsPerSocket = 100;
  return server;
}

function parseTemplate(value: unknown) {
  const input = requireRecord(value, "preview template");
  rejectUnknownKeys(input, [
    "css",
    "html",
    "id",
    "key",
    "language",
    "name",
    "plainText",
    "subject",
    "tenantId",
    "version",
  ]);
  const plainText = optionalString(input, "plainText");
  const css = optionalString(input, "css");
  const template: NotificationTemplateInput = {
    id: requireString(input, "id"),
    tenantId: requireString(input, "tenantId"),
    key: requireString(input, "key"),
    name: requireString(input, "name"),
    language: requireString(input, "language"),
    version: requireNumber(input, "version"),
    subject: requireString(input, "subject"),
    html: requireString(input, "html"),
    ...(plainText === undefined ? {} : { plainText }),
    ...(css === undefined ? {} : { css }),
  };
  return createNotificationTemplate(template);
}

async function readJson(
  request: IncomingMessage,
  maximumBytes: number,
): Promise<unknown> {
  const contentLength = singleHeader(request.headers["content-length"]);
  if (
    contentLength !== undefined &&
    (!/^\d+$/u.test(contentLength) || Number(contentLength) > maximumBytes)
  ) {
    throw new PayloadTooLargeError();
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunkInput of request) {
    const chunk = Buffer.isBuffer(chunkInput)
      ? chunkInput
      : Buffer.from(String(chunkInput));
    size += chunk.byteLength;
    if (size > maximumBytes) throw new PayloadTooLargeError();
    chunks.push(chunk);
  }
  const body = Buffer.concat(chunks);
  try {
    if (body.byteLength === 0) throw new SyntaxError("empty JSON body");
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(body);
    } catch {
      throw new SyntaxError("request body is not valid UTF-8");
    }
    return parseStrictJson(text);
  } finally {
    body.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

function requireRecord(
  value: unknown,
  field: string,
): Readonly<Record<string, unknown>> {
  if (!isPlainRecord(value)) {
    throw new NotificationValidationError(`${field} must be an object`);
  }
  return value;
}

function isPlainRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}

function rejectUnknownKeys(
  value: Readonly<Record<string, unknown>>,
  allowed: readonly string[],
): void {
  const allowlist = new Set(allowed);
  if (Object.keys(value).some((key) => !allowlist.has(key))) {
    throw new NotificationValidationError("request contains unknown fields");
  }
}

function requireString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string {
  const item = value[key];
  if (typeof item !== "string")
    throw new NotificationValidationError(`${key} must be a string`);
  return item;
}

function optionalString(
  value: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const item = value[key];
  if (item !== undefined && typeof item !== "string")
    throw new NotificationValidationError(`${key} must be a string`);
  return item;
}

function requireNumber(
  value: Readonly<Record<string, unknown>>,
  key: string,
): number {
  const item = value[key];
  if (typeof item !== "number")
    throw new NotificationValidationError(`${key} must be a number`);
  return item;
}

function singleHeader(
  value: string | readonly string[] | undefined,
): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isJsonMediaType(value: string | undefined): boolean {
  return /^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(value ?? "");
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: unknown,
  mediaType = "application/json; charset=utf-8",
): void {
  const payload = JSON.stringify(body);
  response.statusCode = status;
  response.setHeader("Content-Type", mediaType);
  response.setHeader("Content-Length", Buffer.byteLength(payload));
  response.end(payload);
}

function sendProblem(
  response: ServerResponse,
  status: number,
  title: string,
  requestId: string,
): void {
  sendJson(
    response,
    status,
    { type: "about:blank", title, status, requestId },
    "application/problem+json; charset=utf-8",
  );
}

function setSecurityHeaders(response: ServerResponse, requestId: string): void {
  response.setHeader("Cache-Control", "no-store");
  response.setHeader("Content-Security-Policy", "default-src 'none'");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("X-Request-ID", requestId);
}

function safePath(value: string | undefined): NotifierHttpRoute {
  try {
    const pathname = new URL(value ?? "/", "http://notifier.internal").pathname;
    switch (pathname) {
      case "/health/live":
      case "/health/ready":
      case "/internal/v1/notification-preview":
      case "/internal/v1/smtp-health":
      case "/metrics":
        return pathname;
      default:
        return "/unknown";
    }
  } catch {
    return "/invalid";
  }
}

function safeErrorClass(error: unknown): string {
  if (error instanceof Error && /^[A-Za-z][A-Za-z0-9]{0,63}$/u.test(error.name))
    return error.name;
  return "UnknownError";
}

class PayloadTooLargeError extends Error {}
