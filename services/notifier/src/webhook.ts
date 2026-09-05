import { createHash, createHmac } from "node:crypto";
import { request as httpRequest } from "node:http";
import { isIP, type Socket } from "node:net";
import {
  checkServerIdentity,
  connect as tlsConnect,
  type TLSSocket,
} from "node:tls";

import {
  DeliveryProviderError,
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import {
  canonicalizeNotificationContext,
  eventTypeSupportsObject,
  isAuthenticNotificationEvent,
  isNotificationEventType,
  notificationEventTypes,
  projectEventContext,
  type ContextValue,
  type NotificationAudience,
  type NotificationEvent,
  type NotificationEventType,
  type NotificationObjectType,
} from "./event.js";
import {
  isAuthenticNotificationProtectedSecret,
  type NotificationProtectedSecret,
} from "./keyring.js";
import type { SecretResolver } from "./smtp.js";
import type { PolicyTcpSocketConnector } from "./smtp-egress.js";
import {
  requireInstant,
  requireInteger,
  requireText,
  requireUuidV7,
} from "./validation.js";
import type {
  LiveWebhookUrlPolicyGate,
  WebhookUrlPolicyAttemptPermit,
} from "./webhook-url-policy.js";

export interface WebhookConfigurationInput {
  id: string;
  tenantId: string;
  name: string;
  endpointUrl: string;
  eventTypes: readonly NotificationEventType[];
  audience: NotificationAudience;
  signingKey: NotificationProtectedSecret;
  timeoutMs: number;
  enabled: boolean;
  version: number;
}

export interface WebhookConfiguration {
  readonly id: string;
  readonly tenantId: string;
  readonly name: string;
  readonly endpointUrl: string;
  readonly eventTypes: readonly NotificationEventType[];
  readonly audience: NotificationAudience;
  readonly signingKey: NotificationProtectedSecret;
  readonly timeoutMs: number;
  readonly enabled: boolean;
  readonly version: number;
}

export interface WebhookDelivery {
  readonly id: string;
  readonly tenantId: string;
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly endpointUrl: string;
  readonly signingKey: NotificationProtectedSecret;
  readonly timeoutMs: number;
  readonly timestamp: number;
  readonly body: string;
}

export interface WebhookPayloadSnapshotInput {
  readonly schemaVersion: 1;
  readonly event: Readonly<{
    id: string;
    type: NotificationEventType;
    objectType: NotificationObjectType;
    objectId: string;
    objectVersion: number;
    occurredAt: Date;
    actorId?: string;
  }>;
  readonly context: Readonly<Record<string, ContextValue>>;
}

export interface WebhookDeliverySnapshotInput {
  readonly id: string;
  readonly tenantId: string;
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly endpointUrl: string;
  readonly signingKey: NotificationProtectedSecret;
  readonly timeoutMs: number;
  readonly createdAt: Date;
  readonly attemptAt: Date;
  readonly payload: WebhookPayloadSnapshotInput;
}

export interface SignedWebhookRequest {
  readonly deliveryId: string;
  readonly tenantId: string;
  readonly endpointUrl: string;
  readonly timeoutMs: number;
  readonly body: string;
  readonly headers: Readonly<Record<string, string>>;
}

export interface SanitizedWebhookResponse {
  readonly provider: "webhook";
  readonly statusCode: number;
  readonly receiptDigest: string;
}

const webhookObjectTypeSet = new Set<string>([
  "alert",
  "case",
  "task",
  "evidence",
  "contact",
]);
const authenticWebhookConfigurations = new WeakSet<WebhookConfiguration>();
const authenticWebhookDeliveries = new WeakSet<WebhookDelivery>();
const authenticSignedRequests = new WeakSet<SignedWebhookRequest>();

export function createWebhookConfiguration(
  input: WebhookConfigurationInput,
  options: { allowPlainLocal?: boolean } = {},
): WebhookConfiguration {
  requireUuidV7(input.id, "webhook.id");
  requireUuidV7(input.tenantId, "webhook.tenantId");
  const name = requireText(input.name, "webhook.name", 160);
  const endpointUrl = canonicalWebhookUrl(
    input.endpointUrl,
    options.allowPlainLocal === true,
  );
  if (
    input.eventTypes.length === 0 ||
    input.eventTypes.length > notificationEventTypes.length ||
    input.eventTypes.some((value) => !isNotificationEventType(value)) ||
    new Set(input.eventTypes).size !== input.eventTypes.length
  ) {
    throw new NotificationValidationError("webhook event types are invalid");
  }
  if (input.audience !== "operator" && input.audience !== "customer") {
    throw new NotificationValidationError("webhook audience is unsupported");
  }
  if (
    !isAuthenticNotificationProtectedSecret(input.signingKey) ||
    input.signingKey.tenantId !== input.tenantId ||
    input.signingKey.kind !== "webhook_signing_key"
  ) {
    throw new NotificationValidationError(
      "webhook signing key has an invalid scope or kind",
    );
  }
  requireInteger(input.timeoutMs, "webhook.timeoutMs", 1_000, 120_000);
  requireInteger(input.version, "webhook.version", 1, 2_147_483_647);
  const configuration = Object.freeze({
    id: input.id,
    tenantId: input.tenantId,
    name,
    endpointUrl,
    eventTypes: Object.freeze([...input.eventTypes].toSorted()),
    audience: input.audience,
    signingKey: input.signingKey,
    timeoutMs: input.timeoutMs,
    enabled: input.enabled,
    version: input.version,
  });
  authenticWebhookConfigurations.add(configuration);
  return configuration;
}

export function prepareWebhookDelivery(
  configuration: WebhookConfiguration,
  event: NotificationEvent,
  deliveryId: string,
  createdAtInput: Date,
): WebhookDelivery | null {
  if (
    !authenticWebhookConfigurations.has(configuration) ||
    !isAuthenticNotificationEvent(event)
  ) {
    throw new NotificationValidationError(
      "webhook configuration or event is not authentic",
    );
  }
  if (configuration.tenantId !== event.tenantId) {
    throw new NotificationTenantBoundaryError();
  }
  if (!configuration.enabled || !configuration.eventTypes.includes(event.type))
    return null;
  requireUuidV7(deliveryId, "webhook delivery id");
  const createdAt = requireInstant(createdAtInput, "webhook createdAt");
  if (createdAt < event.occurredAt) {
    throw new NotificationValidationError(
      "webhook delivery cannot predate its event",
    );
  }
  return createWebhookDeliveryFromSnapshot(
    {
      id: deliveryId,
      tenantId: configuration.tenantId,
      configurationId: configuration.id,
      configurationVersion: configuration.version,
      endpointUrl: configuration.endpointUrl,
      signingKey: configuration.signingKey,
      timeoutMs: configuration.timeoutMs,
      createdAt,
      attemptAt: createdAt,
      payload: {
        schemaVersion: 1,
        event: {
          id: event.id,
          type: event.type,
          objectType: event.objectType,
          objectId: event.objectId,
          objectVersion: event.objectVersion,
          occurredAt: event.occurredAt,
          ...(event.actorId === undefined ? {} : { actorId: event.actorId }),
        },
        context: projectEventContext(event, configuration.audience),
      },
    },
    { allowPlainLocal: configuration.endpointUrl.startsWith("http://") },
  );
}

export function createWebhookDeliveryFromSnapshot(
  input: WebhookDeliverySnapshotInput,
  options: { allowPlainLocal?: boolean } = {},
): WebhookDelivery {
  requireUuidV7(input.id, "webhook delivery id");
  requireUuidV7(input.tenantId, "webhook delivery tenant id");
  requireUuidV7(input.configurationId, "webhook configuration id");
  requireInteger(
    input.configurationVersion,
    "webhook configuration version",
    1,
    2_147_483_647,
  );
  const endpointUrl = canonicalWebhookUrl(
    input.endpointUrl,
    options.allowPlainLocal === true,
  );
  if (
    !isAuthenticNotificationProtectedSecret(input.signingKey) ||
    input.signingKey.tenantId !== input.tenantId ||
    input.signingKey.kind !== "webhook_signing_key"
  ) {
    throw new NotificationValidationError(
      "webhook delivery signing key has an invalid scope or kind",
    );
  }
  requireInteger(input.timeoutMs, "webhook delivery timeout", 1_000, 120_000);
  const createdAt = requireInstant(
    input.createdAt,
    "webhook delivery createdAt",
  );
  const attemptAt = requireInstant(
    input.attemptAt,
    "webhook delivery attemptAt",
  );
  if (attemptAt < createdAt) {
    throw new NotificationValidationError(
      "webhook delivery attempt cannot predate its creation",
    );
  }
  const payload = canonicalWebhookPayloadSnapshot(input.payload, createdAt);
  const body = JSON.stringify({
    schema: "periapsis.webhook.v1",
    deliveryId: input.id,
    tenantId: input.tenantId,
    emittedAt: createdAt.toISOString(),
    event: {
      id: payload.event.id,
      type: payload.event.type,
      objectType: payload.event.objectType,
      objectId: payload.event.objectId,
      objectVersion: payload.event.objectVersion,
      occurredAt: payload.event.occurredAt.toISOString(),
      ...(payload.event.actorId === undefined
        ? {}
        : { actorId: payload.event.actorId }),
      context: payload.context,
    },
  });
  if (Buffer.byteLength(body) > 512 * 1_024) {
    throw new NotificationValidationError("webhook payload is too large");
  }
  const delivery = Object.freeze({
    id: input.id,
    tenantId: input.tenantId,
    configurationId: input.configurationId,
    configurationVersion: input.configurationVersion,
    endpointUrl,
    signingKey: input.signingKey,
    timeoutMs: input.timeoutMs,
    timestamp: Math.floor(attemptAt.getTime() / 1_000),
    body,
  });
  authenticWebhookDeliveries.add(delivery);
  return delivery;
}

function canonicalWebhookPayloadSnapshot(
  input: WebhookPayloadSnapshotInput,
  createdAt: Date,
): WebhookPayloadSnapshotInput {
  const root = requireDataObject(
    input,
    "webhook payload snapshot",
    ["schemaVersion", "event", "context"],
    ["schemaVersion", "event", "context"],
  );
  if (root["schemaVersion"] !== 1) {
    throw new NotificationValidationError(
      "webhook payload schema version is unsupported",
    );
  }
  const event = requireDataObject(
    root["event"],
    "webhook payload event",
    [
      "id",
      "type",
      "objectType",
      "objectId",
      "objectVersion",
      "occurredAt",
      "actorId",
    ],
    ["id", "type", "objectType", "objectId", "objectVersion", "occurredAt"],
  );
  const id = requireRuntimeString(event["id"], "webhook event id");
  const type = requireRuntimeString(event["type"], "webhook event type");
  const objectType = requireRuntimeString(
    event["objectType"],
    "webhook event object type",
  );
  const objectId = requireRuntimeString(
    event["objectId"],
    "webhook event object id",
  );
  requireUuidV7(id, "webhook event id");
  requireUuidV7(objectId, "webhook event object id");
  if (
    !isNotificationEventType(type) ||
    !isWebhookObjectType(objectType) ||
    !eventTypeSupportsObject(type, objectType)
  ) {
    throw new NotificationValidationError(
      "webhook event type or object type is unsupported",
    );
  }
  const objectVersion = requireRuntimeInteger(
    event["objectVersion"],
    "webhook event object version",
    1,
    2_147_483_647,
  );
  const occurredAt = requireRuntimeInstant(
    event["occurredAt"],
    "webhook event occurredAt",
  );
  if (occurredAt > createdAt) {
    throw new NotificationValidationError(
      "webhook event cannot postdate its delivery",
    );
  }
  const actorValue = event["actorId"];
  const actorId =
    actorValue === undefined
      ? undefined
      : requireRuntimeString(actorValue, "webhook event actor id");
  if (actorId !== undefined) requireUuidV7(actorId, "webhook event actor id");
  const context = canonicalizeNotificationContext(root["context"]);
  return Object.freeze({
    schemaVersion: 1,
    event: Object.freeze({
      id,
      type,
      objectType,
      objectId,
      objectVersion,
      occurredAt,
      ...(actorId === undefined ? {} : { actorId }),
    }),
    context,
  });
}

export async function signWebhookDelivery(
  delivery: WebhookDelivery,
  secrets: SecretResolver,
  signal: AbortSignal,
): Promise<SignedWebhookRequest> {
  if (!authenticWebhookDeliveries.has(delivery)) {
    throw new NotificationValidationError("webhook delivery is not authentic");
  }
  if (signal.aborted) throw signal.reason;
  const key = await secrets.read(delivery.signingKey, signal);
  try {
    if (key.byteLength < 32 || key.byteLength > 4_096) {
      throw new NotificationValidationError(
        "webhook signing key is outside its supported size",
      );
    }
    const bodyDigest = createHash("sha256").update(delivery.body).digest("hex");
    const signingInput = [
      "periapsis.webhook.v1",
      String(delivery.timestamp),
      delivery.id,
      bodyDigest,
    ].join("\n");
    const signature = createHmac("sha256", key)
      .update(signingInput)
      .digest("hex");
    const request = Object.freeze({
      deliveryId: delivery.id,
      tenantId: delivery.tenantId,
      endpointUrl: delivery.endpointUrl,
      timeoutMs: delivery.timeoutMs,
      body: delivery.body,
      headers: Object.freeze({
        "content-type": "application/json",
        "user-agent": "Periapsis-Notifier/1",
        "x-periapsis-delivery-id": delivery.id,
        "x-periapsis-key-version": String(delivery.signingKey.secretVersion),
        "x-periapsis-signature": `v1=${signature}`,
        "x-periapsis-timestamp": String(delivery.timestamp),
      }),
    });
    authenticSignedRequests.add(request);
    return request;
  } finally {
    key.fill(0);
  }
}

export class PinnedWebhookTransport {
  readonly #connector: PolicyTcpSocketConnector;
  readonly #policyGate: LiveWebhookUrlPolicyGate | undefined;

  constructor(
    connector: PolicyTcpSocketConnector,
    policyGate?: LiveWebhookUrlPolicyGate,
  ) {
    this.#connector = connector;
    this.#policyGate = policyGate;
  }

  async send(
    input: SignedWebhookRequest,
    signal: AbortSignal,
    permit?: WebhookUrlPolicyAttemptPermit,
  ): Promise<SanitizedWebhookResponse> {
    if (!authenticSignedRequests.has(input)) {
      throw new NotificationValidationError(
        "webhook transport received a forged request",
      );
    }
    if (signal.aborted) throw signal.reason;
    const endpoint = new URL(input.endpointUrl);
    const port =
      endpoint.port === ""
        ? endpoint.protocol === "https:"
          ? 443
          : 80
        : Number(endpoint.port);
    const host = urlHostname(endpoint);
    const deadline = AbortSignal.any([
      signal,
      AbortSignal.timeout(input.timeoutMs),
    ]);
    let rawSocket: Socket | undefined;
    let transportSocket: Socket | TLSSocket | undefined;
    let submitted = false;
    try {
      if (this.#policyGate === undefined) {
        if (permit !== undefined) {
          throw new NotificationValidationError(
            "webhook policy permit has no enforcement gate",
          );
        }
        rawSocket = await this.#connector.connect({
          host,
          port,
          timeoutMs: input.timeoutMs,
          signal: deadline,
        });
      } else {
        if (permit === undefined) {
          throw new NotificationValidationError(
            "webhook policy permit is required",
          );
        }
        rawSocket = (
          await this.#policyGate.connect(permit, {
            host,
            port,
            timeoutMs: input.timeoutMs,
            signal: deadline,
          })
        ).socket;
      }
      transportSocket =
        endpoint.protocol === "https:"
          ? await secureSocket(rawSocket, host, deadline)
          : rawSocket;
      const response = await new Promise<{
        statusCode: number;
        receiptSource: string;
      }>((resolve, reject) => {
        const request = httpRequest(
          {
            method: "POST",
            host,
            port,
            path: `${endpoint.pathname}${endpoint.search}`,
            agent: false,
            createConnection: () => transportSocket!,
            headers: {
              ...input.headers,
              host: endpoint.host,
              "content-length": Buffer.byteLength(input.body),
            },
            signal: deadline,
          },
          (incoming) => {
            const chunks: Buffer[] = [];
            let size = 0;
            const clearChunks = (): void => {
              for (const chunk of chunks) chunk.fill(0);
              chunks.length = 0;
            };
            incoming.on("data", (chunkInput: Buffer | string) => {
              const chunk = Buffer.isBuffer(chunkInput)
                ? chunkInput
                : Buffer.from(chunkInput);
              size += chunk.byteLength;
              if (size > 8_192) {
                chunk.fill(0);
                clearChunks();
                reject(new DeliveryProviderError("security", "terminal"));
                incoming.destroy();
                return;
              }
              chunks.push(chunk);
            });
            incoming.once("error", (error: Error) => {
              clearChunks();
              reject(error);
            });
            incoming.once("aborted", () => {
              clearChunks();
              reject(new Error("webhook response was incomplete"));
            });
            incoming.once("end", () => {
              const statusCode = incoming.statusCode ?? 0;
              const requestId = incoming.headers["x-request-id"];
              const safeRequestId =
                typeof requestId === "string" ? requestId.slice(0, 256) : "";
              clearChunks();
              resolve({
                statusCode,
                receiptSource: `${statusCode}\0${safeRequestId}\0${size}`,
              });
            });
          },
        );
        request.once("error", reject);
        // From the instant end() may hand bytes to the socket, the remote side
        // can have processed the request even if no response ever arrives.
        submitted = true;
        request.end(input.body);
      });
      if (response.statusCode < 200 || response.statusCode >= 300) {
        const retryable = [408, 425, 429, 500, 502, 503, 504].includes(
          response.statusCode,
        );
        throw new DeliveryProviderError(
          response.statusCode === 429 ? "rate_limited" : "unknown",
          retryable ? "safe" : "terminal",
        );
      }
      return Object.freeze({
        provider: "webhook",
        statusCode: response.statusCode,
        receiptDigest: createHash("sha256")
          .update(response.receiptSource)
          .digest("hex"),
      });
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      if (error instanceof DeliveryProviderError) throw error;
      const code = errorCode(error);
      if (
        code.startsWith("ERR_TLS") ||
        code.startsWith("ERR_SSL") ||
        code.includes("CERT")
      ) {
        throw new DeliveryProviderError("tls", "safe");
      }
      throw new DeliveryProviderError(
        deadline.aborted ? "timeout" : "connectivity",
        submitted ? "uncertain" : "safe",
      );
    } finally {
      transportSocket?.destroy();
      if (transportSocket !== rawSocket) rawSocket?.destroy();
    }
  }
}

function errorCode(error: unknown): string {
  if (error === null || typeof error !== "object") return "";
  const value = Reflect.get(error, "code");
  return typeof value === "string" ? value : "";
}

function canonicalWebhookUrl(input: string, allowPlainLocal: boolean): string {
  requireText(input, "webhook.endpointUrl", 2_048);
  let endpoint: URL;
  try {
    endpoint = new URL(input);
  } catch {
    throw new NotificationValidationError("webhook endpoint URL is invalid");
  }
  const host = urlHostname(endpoint);
  const isPlainLocal =
    endpoint.protocol === "http:" &&
    allowPlainLocal &&
    ["localhost", "127.0.0.1", "::1"].includes(host);
  if (
    (endpoint.protocol !== "https:" && !isPlainLocal) ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.hash !== "" ||
    endpoint.hostname === "" ||
    endpoint.pathname.length > 1_024 ||
    endpoint.search.length > 1_024
  ) {
    throw new NotificationValidationError("webhook endpoint URL is invalid");
  }
  return endpoint.toString();
}

function urlHostname(endpoint: URL): string {
  const value = endpoint.hostname;
  return value.startsWith("[") && value.endsWith("]")
    ? value.slice(1, -1)
    : value;
}

function requireDataObject(
  value: unknown,
  field: string,
  allowedKeys: readonly string[],
  requiredKeys: readonly string[],
): Readonly<Record<string, unknown>> {
  if (!isPlainDataRecord(value)) {
    throw new NotificationValidationError(`${field} must be a plain object`);
  }
  const allowed = new Set(allowedKeys);
  const keys = Reflect.ownKeys(value);
  if (
    keys.some((key) => typeof key !== "string" || !allowed.has(key)) ||
    requiredKeys.some((key) => !Object.hasOwn(value, key))
  ) {
    throw new NotificationValidationError(`${field} has invalid fields`);
  }
  for (const key of keys) {
    if (typeof key !== "string") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      descriptor === undefined ||
      !descriptor.enumerable ||
      !("value" in descriptor)
    ) {
      throw new NotificationValidationError(
        `${field} contains an accessor or hidden field`,
      );
    }
  }
  return value;
}

function requireRuntimeString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new NotificationValidationError(`${field} must be a string`);
  }
  return value;
}

function requireRuntimeInteger(
  value: unknown,
  field: string,
  minimum: number,
  maximum: number,
): number {
  if (typeof value !== "number") {
    throw new NotificationValidationError(`${field} must be a number`);
  }
  return requireInteger(value, field, minimum, maximum);
}

function requireRuntimeInstant(value: unknown, field: string): Date {
  if (!(value instanceof Date)) {
    throw new NotificationValidationError(`${field} must be a Date`);
  }
  return requireInstant(value, field);
}

function isPlainDataRecord(
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

function isWebhookObjectType(value: string): value is NotificationObjectType {
  return webhookObjectTypeSet.has(value);
}

function secureSocket(
  socket: Socket,
  host: string,
  signal: AbortSignal,
): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      socket.destroy();
      reject(signal.reason);
      return;
    }
    const secured = tlsConnect({
      socket,
      servername: isIP(host) === 0 ? host : undefined,
      minVersion: "TLSv1.2",
      rejectUnauthorized: true,
      checkServerIdentity: (_servername, certificate) =>
        checkServerIdentity(host, certificate),
    });
    const cleanup = (): void => {
      secured.off("secureConnect", onSecure);
      secured.off("error", onError);
      signal.removeEventListener("abort", onAbort);
    };
    const onSecure = (): void => {
      cleanup();
      resolve(secured);
    };
    const onError = (error: Error): void => {
      cleanup();
      secured.destroy();
      reject(error);
    };
    const onAbort = (): void => {
      cleanup();
      secured.destroy();
      reject(signal.reason);
    };
    secured.once("secureConnect", onSecure);
    secured.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}
