import type { Server } from "node:http";

import { afterEach, describe, expect, it } from "vitest";

import {
  createNotifierHttpServer,
  InternalTokenAuthenticator,
  SafeNotificationPreviewer,
} from "./http.js";
import { NotifierMetrics } from "./observability.js";
import { disabledTestTracing } from "./test/telemetry.js";
import { id } from "./test/fixtures.js";
import type { SmtpHealthProber } from "./smtp-health.js";

describe("notifier internal HTTP server", () => {
  const servers: Server[] = [];

  afterEach(async () => {
    await Promise.all(servers.splice(0).map(closeServer));
  });

  it("bounds slow clients and connection reuse", async () => {
    const value = server(new NotifierMetrics());
    await startServer(value);

    expect(value.requestTimeout).toBe(10_000);
    expect(value.headersTimeout).toBe(5_000);
    expect(value.keepAliveTimeout).toBe(5_000);
    expect(value.timeout).toBe(35_000);
    expect(value.maxHeadersCount).toBe(64);
    expect(value.maxRequestsPerSocket).toBe(100);
  });

  it("destroys the retained preview credential on shutdown", () => {
    const authenticator = new InternalTokenAuthenticator(
      Buffer.from(internalToken),
    );
    expect(authenticator.authenticate(`Bearer ${internalToken}`)).toBe(true);

    authenticator.close();
    authenticator.close();

    expect(authenticator.authenticate(`Bearer ${internalToken}`)).toBe(false);
  });

  it("serves health and metrics without exposing tenant labels", async () => {
    const metrics = new NotifierMetrics();
    metrics.record("delivered", { tenantId: id(2) });
    const origin = await startServer(server(metrics));

    const live = await fetch(`${origin}/health/live`);
    expect(live.status).toBe(200);
    expect(await live.json()).toMatchObject({
      status: "alive",
      service: "notifier",
    });
    const ready = await fetch(`${origin}/health/ready`);
    expect(ready.status).toBe(200);
    const metricResponse = await fetch(`${origin}/metrics`);
    const body = await metricResponse.text();
    expect(body).toContain("periapsis_notification_deliveries_total");
    expect(body).not.toContain(id(2));
  });

  it("requires the internal bearer token and returns only sanitized preview output", async () => {
    const origin = await startServer(server(new NotifierMetrics()));
    const endpoint = `${origin}/internal/v1/notification-preview`;
    const request = {
      audience: "operator",
      template: {
        id: id(80),
        tenantId: id(2),
        key: "alert.created",
        name: "Alert created",
        language: "en",
        version: 1,
        subject: "Alert {{alert.title}}",
        html: "<p>{{alert.title}}</p><script>alert(1)</script>",
      },
      context: { alert: { title: "<img src=x onerror=alert(2)>" } },
    };

    const unauthorized = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    expect(unauthorized.status).toBe(401);

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${internalToken}`,
        "content-type": "application/json; charset=utf-8",
      },
      body: JSON.stringify(request),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const rendered = await response.json();
    expect(rendered).toMatchObject({
      subject: "Alert <img src=x onerror=alert(2)>",
      plainText: "<img src=x onerror=alert(2)>",
    });
    const html =
      rendered !== null && typeof rendered === "object"
        ? Reflect.get(rendered, "html")
        : undefined;
    expect(html).toBeTypeOf("string");
    expect(html).toContain("&lt;img src=x onerror=alert(2)&gt;");
    expect(html).not.toContain("<script");
  });

  it("rejects unsupported media types, query parameters, and oversized bodies", async () => {
    const origin = await startServer(server(new NotifierMetrics()));
    const endpoint = `${origin}/internal/v1/notification-preview`;
    const authorization = `Bearer ${internalToken}`;
    expect(
      (
        await fetch(endpoint, {
          method: "POST",
          headers: { authorization, "content-type": "text/plain" },
          body: "{}",
        })
      ).status,
    ).toBe(415);
    expect((await fetch(`${origin}/health/live?secret=x`)).status).toBe(400);
    expect(
      (
        await fetch(endpoint, {
          method: "POST",
          headers: { authorization, "content-type": "application/json" },
          body: JSON.stringify({ padding: "x".repeat(512 * 1_024) }),
        })
      ).status,
    ).toBe(413);
  });

  it("rejects duplicate JSON names and malformed UTF-8", async () => {
    const origin = await startServer(server(new NotifierMetrics()));
    const endpoint = `${origin}/internal/v1/notification-preview`;
    const headers = {
      authorization: `Bearer ${internalToken}`,
      "content-type": "application/json",
    };
    const template = JSON.stringify({
      id: id(80),
      tenantId: id(2),
      key: "alert.created",
      name: "Alert created",
      language: "en",
      version: 1,
      subject: "Alert",
      html: "<p>Alert</p>",
    });
    const duplicate = await fetch(endpoint, {
      method: "POST",
      headers,
      body: `{"audience":"operator","aud\\u0069ence":"customer","template":${template},"context":{}}`,
    });
    expect(duplicate.status).toBe(400);

    const malformed = await fetch(endpoint, {
      method: "POST",
      headers,
      body: Uint8Array.of(0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d),
    });
    expect(malformed.status).toBe(400);
  });

  it("authenticates SMTP health requests and returns only the fenced result", async () => {
    const request = {
      probeId: id(70),
      fenceToken: id(71),
      tenantId: id(2),
      configurationScope: "tenant" as const,
      configurationId: id(72),
      configurationVersion: 3,
    };
    const smtpHealth: SmtpHealthProber = {
      async probe(input) {
        expect(input).toEqual(request);
        return {
          ...request,
          healthy: true,
          checkedAt: new Date("2026-09-01T12:00:00.000Z"),
          checks: [
            { kind: "dns", outcome: "passed" },
            { kind: "connect", outcome: "passed" },
            { kind: "tls", outcome: "passed" },
          ],
        };
      },
    };
    const origin = await startServer(server(new NotifierMetrics(), smtpHealth));
    const endpoint = `${origin}/internal/v1/smtp-health`;

    const unauthorized = await fetch(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    expect(unauthorized.status).toBe(401);

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        authorization: `Bearer ${internalToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(request),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({
      ...request,
      healthy: true,
      checkedAt: "2026-09-01T12:00:00.000Z",
      checks: [
        { kind: "dns", outcome: "passed" },
        { kind: "connect", outcome: "passed" },
        { kind: "tls", outcome: "passed" },
      ],
    });
  });

  function server(
    metrics: NotifierMetrics,
    smtpHealth: SmtpHealthProber = {
      async probe() {
        throw new Error("unexpected SMTP health probe");
      },
    },
  ): Server {
    const value = createNotifierHttpServer({
      runtime: {
        async readiness() {
          return { ready: true, queueDepth: 0 };
        },
      },
      metrics,
      previewer: new SafeNotificationPreviewer(),
      smtpHealth,
      authenticator: new InternalTokenAuthenticator(Buffer.from(internalToken)),
      logger: { info() {}, error() {} },
      tracing: disabledTestTracing,
      release: "test",
    });
    servers.push(value);
    return value;
  }
});

const internalToken = "0123456789abcdef0123456789abcdef";

async function startServer(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("HTTP fixture did not bind");
  return `http://127.0.0.1:${address.port}`;
}

async function closeServer(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}
