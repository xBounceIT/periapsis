import { createHmac } from "node:crypto";
import { createServer, type Server } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  DeliveryProviderError,
  NotificationTenantBoundaryError,
  NotificationValidationError,
} from "./errors.js";
import { createNotificationEvent } from "./event.js";
import { PolicyTcpSocketConnector } from "./smtp-egress.js";
import { id, protectedSecret } from "./test/fixtures.js";
import {
  createWebhookConfiguration,
  createWebhookDeliveryFromSnapshot,
  PinnedWebhookTransport,
  prepareWebhookDelivery,
  signWebhookDelivery,
} from "./webhook.js";

describe("webhook delivery", () => {
  const servers: Server[] = [];

  afterEach(async () => {
    await Promise.all(servers.splice(0).map(closeServer));
  });

  it("signs a versioned customer-safe payload and sends it through pinned egress", async () => {
    const received: Array<{ body: string; headers: Record<string, unknown> }> =
      [];
    const fixture = await startFixture(204, received);
    const configuration = webhookConfiguration(fixture.endpoint);
    const event = publicEvent();
    const delivery = prepareWebhookDelivery(
      configuration,
      event,
      id(93),
      new Date("2026-08-25T10:01:00.000Z"),
    );
    expect(delivery).not.toBeNull();
    if (delivery === null) throw new Error("delivery was not planned");
    let exposedKey: Uint8Array | undefined;
    const signed = await signWebhookDelivery(
      delivery,
      {
        async read() {
          exposedKey = new TextEncoder().encode(signingKey);
          return exposedKey;
        },
      },
      new AbortController().signal,
    );
    expect([...exposedKey!]).toEqual(
      Array.from({ length: signingKey.length }, () => 0),
    );

    const signatureInput = [
      "periapsis.webhook.v1",
      String(delivery.timestamp),
      delivery.id,
      await sha256(delivery.body),
    ].join("\n");
    expect(signed.headers["x-periapsis-signature"]).toBe(
      `v1=${createHmac("sha256", signingKey).update(signatureInput).digest("hex")}`,
    );
    const connector = new PolicyTcpSocketConnector({
      policy: {
        allowedPorts: [fixture.port],
        allowedPrivateHosts: ["127.0.0.1"],
      },
    });
    const response = await new PinnedWebhookTransport(connector).send(
      signed,
      new AbortController().signal,
    );
    expect(response).toMatchObject({ provider: "webhook", statusCode: 204 });
    expect(received).toHaveLength(1);
    const payload: unknown = JSON.parse(received[0]!.body);
    const payloadEvent =
      payload !== null && typeof payload === "object"
        ? Reflect.get(payload, "event")
        : undefined;
    const context =
      payloadEvent !== null && typeof payloadEvent === "object"
        ? Reflect.get(payloadEvent, "context")
        : undefined;
    expect(context).toEqual({ alert: { severity: "critical" } });
    expect(JSON.stringify(payload)).not.toContain("operator-only");
  });

  it("fails closed for private customer events, cross-tenant data, and forged transport requests", async () => {
    const configuration = createWebhookConfiguration({
      ...webhookInput("https://hooks.example/hook"),
      eventTypes: ["comment.private_added"],
    });
    const privateEvent = createNotificationEvent({
      id: id(94),
      tenantId: id(2),
      type: "comment.private_added",
      objectType: "case",
      objectId: id(95),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
      actorKind: "system",
      source: "api",
      context: {
        comment: { body: "operator-only" },
      },
      maximumAudience: "operator",
    });
    expect(() =>
      prepareWebhookDelivery(
        configuration,
        privateEvent,
        id(96),
        privateEvent.occurredAt,
      ),
    ).toThrow(NotificationValidationError);

    const foreignInput = webhookInput("https://hooks.example/hook");
    foreignInput.tenantId = id(99);
    foreignInput.signingKey = protectedSecret("webhook_signing_key", id(99), 3);
    expect(() =>
      prepareWebhookDelivery(
        createWebhookConfiguration(foreignInput),
        publicEvent(),
        id(97),
        new Date("2026-08-25T10:01:00.000Z"),
      ),
    ).toThrow(NotificationTenantBoundaryError);

    const connector = new PolicyTcpSocketConnector({
      policy: { allowedPorts: [443] },
    });
    await expect(
      new PinnedWebhookTransport(connector).send(
        {
          deliveryId: id(98),
          tenantId: id(2),
          endpointUrl: "https://hooks.example/hook",
          timeoutMs: 5_000,
          body: "{}",
          headers: {},
        },
        new AbortController().signal,
      ),
    ).rejects.toThrow(NotificationValidationError);
  });

  it.each([
    "alert.watcher_added",
    "alert.watcher_removed",
    "case.watcher_added",
    "case.watcher_removed",
  ] as const)(
    "fails closed when a %s webhook targets customers",
    (eventType) => {
      const configuration = createWebhookConfiguration({
        ...webhookInput("https://hooks.example/hook"),
        eventTypes: [eventType],
      });
      const objectType = eventType.startsWith("alert.") ? "alert" : "case";
      const event = createNotificationEvent({
        id: id(120),
        tenantId: id(2),
        type: eventType,
        objectType,
        objectId: id(121),
        objectVersion: 2,
        occurredAt: new Date("2026-09-01T08:00:00.000Z"),
        actorKind: "system",
        source: "ticketing",
        context: { [objectType]: { id: id(121), version: 2 } },
        maximumAudience: "operator",
      });
      expect(() =>
        prepareWebhookDelivery(configuration, event, id(122), event.occurredAt),
      ).toThrow(NotificationValidationError);
    },
  );

  it("classifies explicit retryable and terminal HTTP failures", async () => {
    await Promise.all(
      (
        [
          [503, "safe"],
          [400, "terminal"],
        ] as const
      ).map(async ([status, retrySafety]) => {
        const fixture = await startFixture(status, []);
        const delivery = prepareWebhookDelivery(
          webhookConfiguration(fixture.endpoint),
          publicEvent(),
          id(status),
          new Date("2026-08-25T10:01:00.000Z"),
        );
        if (delivery === null) throw new Error("delivery was not planned");
        const signed = await signWebhookDelivery(
          delivery,
          {
            async read() {
              return new TextEncoder().encode(signingKey);
            },
          },
          new AbortController().signal,
        );
        const connector = new PolicyTcpSocketConnector({
          policy: {
            allowedPorts: [fixture.port],
            allowedPrivateHosts: ["127.0.0.1"],
          },
        });
        const failure = await new PinnedWebhookTransport(connector)
          .send(signed, new AbortController().signal)
          .catch((error: unknown) => error);
        expect(failure).toBeInstanceOf(DeliveryProviderError);
        expect(failure).toMatchObject({ retrySafety });
      }),
    );
  });

  it("terminates oversized webhook responses instead of draining them", async () => {
    const fixture = await startFixture(200, [], "x".repeat(8_193));
    const delivery = prepareWebhookDelivery(
      webhookConfiguration(fixture.endpoint),
      publicEvent(),
      id(101),
      new Date("2026-08-25T10:01:00.000Z"),
    );
    if (delivery === null) throw new Error("delivery was not planned");
    const signed = await signWebhookDelivery(
      delivery,
      {
        async read() {
          return new TextEncoder().encode(signingKey);
        },
      },
      new AbortController().signal,
    );
    const connector = new PolicyTcpSocketConnector({
      policy: {
        allowedPorts: [fixture.port],
        allowedPrivateHosts: ["127.0.0.1"],
      },
    });

    const failure = await new PinnedWebhookTransport(connector)
      .send(signed, new AbortController().signal)
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(DeliveryProviderError);
    expect(failure).toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
    });
  });

  it("treats a connection loss after request submission as ambiguous", async () => {
    const fixture = await startDroppedResponseFixture();
    const delivery = prepareWebhookDelivery(
      webhookConfiguration(fixture.endpoint),
      publicEvent(),
      id(102),
      new Date("2026-08-25T10:01:00.000Z"),
    );
    if (delivery === null) throw new Error("delivery was not planned");
    const signed = await signWebhookDelivery(
      delivery,
      {
        async read() {
          return new TextEncoder().encode(signingKey);
        },
      },
      new AbortController().signal,
    );
    const connector = new PolicyTcpSocketConnector({
      policy: {
        allowedPorts: [fixture.port],
        allowedPrivateHosts: ["127.0.0.1"],
      },
    });

    await expect(
      new PinnedWebhookTransport(connector).send(
        signed,
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({
      failureClass: "connectivity",
      retrySafety: "uncertain",
    });
  });

  it("allows plaintext webhook endpoints only for explicit loopback tests", () => {
    const input = webhookInput("http://127.0.0.1:8080/hook");
    expect(() => createWebhookConfiguration(input)).toThrow(
      NotificationValidationError,
    );
    expect(
      createWebhookConfiguration(input, { allowPlainLocal: true }).endpointUrl,
    ).toBe("http://127.0.0.1:8080/hook");
    input.endpointUrl = "http://10.0.0.1/hook";
    expect(() =>
      createWebhookConfiguration(input, { allowPlainLocal: true }),
    ).toThrow(NotificationValidationError);
  });

  it("keeps the payload immutable while refreshing the HMAC timestamp for a retry", () => {
    const createdAt = new Date("2026-08-25T10:01:00.000Z");
    const attemptAt = new Date("2026-08-25T10:06:00.000Z");
    const delivery = createWebhookDeliveryFromSnapshot({
      id: id(103),
      tenantId: id(2),
      configurationId: id(90),
      configurationVersion: 7,
      endpointUrl: "https://hooks.example/hook",
      signingKey: protectedSecret("webhook_signing_key", id(2), 3),
      timeoutMs: 5_000,
      createdAt,
      attemptAt,
      payload: webhookPayloadSnapshot(),
    });

    expect(delivery.timestamp).toBe(Math.floor(attemptAt.getTime() / 1_000));
    expect(JSON.parse(delivery.body)).toEqual({
      schema: "periapsis.webhook.v1",
      deliveryId: id(103),
      tenantId: id(2),
      emittedAt: createdAt.toISOString(),
      event: {
        id: id(91),
        type: "alert.created",
        objectType: "alert",
        objectId: id(92),
        objectVersion: 1,
        occurredAt: "2026-08-25T10:00:00.000Z",
        context: { alert: { severity: "critical" } },
      },
    });
  });

  it("rejects webhook snapshots with extra fields before signing", () => {
    const payload = webhookPayloadSnapshot();
    Object.defineProperty(payload, "destination", {
      value: "https://attacker.example",
      enumerable: true,
    });

    expect(() =>
      createWebhookDeliveryFromSnapshot({
        id: id(104),
        tenantId: id(2),
        configurationId: id(90),
        configurationVersion: 7,
        endpointUrl: "https://hooks.example/hook",
        signingKey: protectedSecret("webhook_signing_key", id(2), 3),
        timeoutMs: 5_000,
        createdAt: new Date("2026-08-25T10:01:00.000Z"),
        attemptAt: new Date("2026-08-25T10:02:00.000Z"),
        payload,
      }),
    ).toThrow(NotificationValidationError);
  });

  async function startFixture(
    status: number,
    received: Array<{ body: string; headers: Record<string, unknown> }>,
    responseBody = "",
  ): Promise<{ endpoint: string; port: number }> {
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on("data", (chunk: Buffer) => chunks.push(chunk));
      request.on("end", () => {
        received.push({
          body: Buffer.concat(chunks).toString("utf8"),
          headers: { ...request.headers },
        });
        response.statusCode = status;
        response.setHeader("x-request-id", "fixture-request");
        response.end(responseBody);
      });
    });
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error("webhook fixture did not bind");
    return {
      endpoint: `http://127.0.0.1:${address.port}/hook?source=test`,
      port: address.port,
    };
  }

  async function startDroppedResponseFixture(): Promise<{
    endpoint: string;
    port: number;
  }> {
    const server = createServer((request) => {
      request.resume();
      request.once("end", () => request.socket.destroy());
    });
    servers.push(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => {
        server.off("error", reject);
        resolve();
      });
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("webhook fixture did not bind");
    }
    return {
      endpoint: `http://127.0.0.1:${address.port}/hook`,
      port: address.port,
    };
  }
});

const signingKey = "0123456789abcdef0123456789abcdef";

function webhookInput(endpointUrl: string) {
  return {
    id: id(90),
    tenantId: id(2),
    name: "Customer webhook",
    endpointUrl,
    eventTypes: ["alert.created" as const],
    audience: "customer" as const,
    signingKey: protectedSecret("webhook_signing_key", id(2), 3),
    timeoutMs: 5_000,
    enabled: true,
    version: 7,
  };
}

function webhookConfiguration(endpointUrl: string) {
  return createWebhookConfiguration(webhookInput(endpointUrl), {
    allowPlainLocal: endpointUrl.startsWith("http://127.0.0.1:"),
  });
}

function publicEvent() {
  return createNotificationEvent({
    id: id(91),
    tenantId: id(2),
    type: "alert.created",
    objectType: "alert",
    objectId: id(92),
    objectVersion: 1,
    occurredAt: new Date("2026-08-25T10:00:00.000Z"),
    actorKind: "system",
    source: "api",
    context: {
      alert: { severity: "critical", note: "operator-only" },
      customer: { alert: { severity: "critical" } },
    },
    maximumAudience: "customer",
  });
}

function webhookPayloadSnapshot() {
  return {
    schemaVersion: 1 as const,
    event: {
      id: id(91),
      type: "alert.created" as const,
      objectType: "alert" as const,
      objectId: id(92),
      objectVersion: 1,
      occurredAt: new Date("2026-08-25T10:00:00.000Z"),
    },
    context: { alert: { severity: "critical" } },
  };
}

async function sha256(value: string): Promise<string> {
  const { createHash } = await import("node:crypto");
  return createHash("sha256").update(value).digest("hex");
}

async function closeServer(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}
