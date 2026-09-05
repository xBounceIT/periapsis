import { createServer, type Server } from "node:http";

import { describe, expect, it } from "vitest";

import {
  NotificationConfigurationError,
  NotificationValidationError,
} from "./errors.js";
import { StructuredNotifierLogger, type LogSink } from "./observability.js";
import {
  activeTraceCorrelation,
  canonicalPersistedTraceContext,
  loadNotifierTelemetryConfiguration,
  persistedTraceContextFromActive,
  startNotifierTelemetry,
  type PersistedTraceContext,
} from "./telemetry.js";

const producerTrace: PersistedTraceContext = Object.freeze({
  traceParent: "00-11111111111111111111111111111111-2222222222222222-01",
  traceState: "vendor=value",
});
const remoteHttpTrace =
  "00-33333333333333333333333333333333-4444444444444444-01";

describe("notifier OpenTelemetry boundary", () => {
  it("loads only explicit, closed OTLP/HTTP configuration", () => {
    expect(
      loadNotifierTelemetryConfiguration("production", "2026.08.25", {
        OTEL_SDK_DISABLED: "true",
      }),
    ).toMatchObject({
      enabled: false,
      serviceName: "periapsis-notifier",
    });

    const configured = loadNotifierTelemetryConfiguration(
      "production",
      "2026.08.25",
      enabledEnvironment("https://collector.example.test"),
    );
    expect(configured).toMatchObject({
      enabled: true,
      endpoint: "https://collector.example.test",
      exportTimeoutMs: 5_000,
      sampleRatio: 1,
    });

    const hostile: ReadonlyArray<Readonly<Record<string, string | undefined>>> =
      [
        {},
        { OTEL_SDK_DISABLED: "false" },
        {
          ...enabledEnvironment("https://user:secret@collector.example.test"),
        },
        { ...enabledEnvironment("https://collector.example.test/path") },
        {
          ...enabledEnvironment("https://collector.example.test?token=secret"),
        },
        {
          ...enabledEnvironment("https://collector.example.test"),
          OTEL_PROPAGATORS: "tracecontext,baggage",
        },
        {
          ...enabledEnvironment("https://collector.example.test"),
          OTEL_TRACES_SAMPLER_ARG: "0.0",
        },
        {
          ...enabledEnvironment("https://collector.example.test"),
          OTEL_EXPORTER_OTLP_HEADERS: "authorization=super-secret",
        },
        {
          ...enabledEnvironment("https://collector.example.test"),
          PERIAPSIS_OTEL_EXPORT_TIMEOUT_MS: "99",
        },
      ];
    for (const env of hostile) {
      let message = "";
      try {
        loadNotifierTelemetryConfiguration("production", "2026.08.25", env);
      } catch (error) {
        message = error instanceof Error ? error.message : String(error);
      }
      expect(message).not.toBe("");
      expect(message).not.toContain("super-secret");
      expect(message).not.toContain("user:secret");
      expect(message).not.toContain("token=secret");
    }
  });

  it("accepts only canonical bounded persisted W3C context", () => {
    expect(canonicalPersistedTraceContext(producerTrace)).toEqual(
      producerTrace,
    );
    expect(
      canonicalPersistedTraceContext({
        traceParent: "00-11111111111111111111111111111111-2222222222222222-00",
      }),
    ).toEqual({
      traceParent: "00-11111111111111111111111111111111-2222222222222222-00",
    });

    const hostile: unknown[] = [
      null,
      {},
      { ...producerTrace, extra: "field" },
      {
        ...producerTrace,
        traceParent: "00-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA-BBBBBBBBBBBBBBBB-01",
      },
      { ...producerTrace, traceParent: producerTrace.traceParent.slice(1) },
      {
        ...producerTrace,
        traceParent: "00-00000000000000000000000000000000-2222222222222222-01",
      },
      {
        ...producerTrace,
        traceParent: "00-11111111111111111111111111111111-0000000000000000-01",
      },
      {
        ...producerTrace,
        traceParent: `${producerTrace.traceParent.slice(0, -2)}02`,
      },
      { ...producerTrace, traceState: "" },
      { ...producerTrace, traceState: "vendor=value,vendor=duplicate" },
      { ...producerTrace, traceState: "vendor=value\r\nsecret=leak" },
      { ...producerTrace, traceState: `vendor=${"a".repeat(513)}` },
    ];
    for (const input of hostile) {
      expect(() => canonicalPersistedTraceContext(input)).toThrow(
        "persisted OpenTelemetry span context is invalid",
      );
    }
  });

  it("exports linked consumer, HTTP, and DB spans without sensitive values", async () => {
    const requests: Array<{
      readonly body: Buffer;
      readonly contentType: string | undefined;
      readonly path: string | undefined;
    }> = [];
    const collector = createServer(async (request, response) => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      requests.push({
        body: Buffer.concat(chunks),
        contentType: request.headers["content-type"],
        path: request.url,
      });
      response.writeHead(200);
      response.end();
    });
    const endpoint = await listen(collector);
    const diagnosticEvents: unknown[] = [];
    const runtime = startNotifierTelemetry(
      loadNotifierTelemetryConfiguration(
        "test",
        "2026.08.25-test",
        enabledEnvironment(endpoint),
      ),
      {
        error(event, attributes) {
          diagnosticEvents.push({ event, attributes });
        },
      },
    );
    const logLines: string[] = [];
    const sink: LogSink = { write: (value) => logLines.push(value) };
    const logger = new StructuredNotifierLogger({
      errors: sink,
      output: sink,
      release: "test",
    });
    try {
      let consumerTraceId = "";
      await runtime.runConsumerSpan(
        "fanout",
        producerTrace,
        async () => {
          const correlation = activeTraceCorrelation();
          expect(correlation).toBeDefined();
          consumerTraceId = correlation?.traceId ?? "";
          expect(consumerTraceId).not.toBe("1".repeat(32));
          expect(persistedTraceContextFromActive()?.traceParent).toMatch(
            new RegExp(`^00-${consumerTraceId}-[0-9a-f]{16}-01$`, "u"),
          );
          logger.info("notification_fanout_finished", {
            deliveries: 1,
            eventId: "019d0000-0000-7000-8000-000000000001",
            outcome: "committed",
            tenantId: "019d0000-0000-7000-8000-000000000002",
          });
          await runtime.runDatabaseSpan("load_fanout", async () => {
            const database = activeTraceCorrelation();
            expect(database?.traceId).toBe(consumerTraceId);
            expect(database?.spanId).not.toBe(correlation?.spanId);
          });
          return "committed" as const;
        },
        (outcome) => outcome,
      );

      let httpTraceId = "";
      await runtime.runHttpServerSpan(
        {
          method: "get",
          rawHeaders: ["traceparent", remoteHttpTrace],
          route: "/health/ready",
          statusCode: () => 503,
        },
        async () => {
          httpTraceId = activeTraceCorrelation()?.traceId ?? "";
        },
      );
      expect(httpTraceId).toBe("3".repeat(32));

      let duplicateHeaderTraceId = "";
      await runtime.runHttpServerSpan(
        {
          method: "GET",
          rawHeaders: [
            "traceparent",
            remoteHttpTrace,
            "TraceParent",
            remoteHttpTrace,
          ],
          route: "/health/live",
          statusCode: () => 200,
        },
        async () => {
          duplicateHeaderTraceId = activeTraceCorrelation()?.traceId ?? "";
        },
      );
      expect(duplicateHeaderTraceId).not.toBe("3".repeat(32));

      await expect(
        runtime.runConsumerSpan(
          "email_delivery",
          producerTrace,
          async () => {
            throw new Error(
              "recipient@example.test bearer-super-secret must not be exported",
            );
          },
          (outcome) => outcome,
        ),
      ).rejects.toThrow("recipient@example.test");

      await runtime.forceFlush(AbortSignal.timeout(2_000));
      expect(requests.length).toBeGreaterThan(0);
      expect(requests.every((request) => request.path === "/v1/traces")).toBe(
        true,
      );
      expect(
        requests.every(
          (request) => request.contentType === "application/x-protobuf",
        ),
      ).toBe(true);
      const exported = Buffer.concat(requests.map((request) => request.body));
      expect(exported.includes(Buffer.from("1".repeat(32), "hex"))).toBe(true);
      expect(exported.includes(Buffer.from("3".repeat(32), "hex"))).toBe(true);
      expect(exported.includes(Buffer.from(consumerTraceId, "hex"))).toBe(true);
      expect(exported.toString("utf8")).not.toContain("recipient@example.test");
      expect(exported.toString("utf8")).not.toContain("bearer-super-secret");
      expect(exported.toString("utf8")).toContain(
        "periapsis.notification.channel",
      );
      expect(exported.toString("utf8")).toContain(
        "periapsis.notification.outcome",
      );
      expect(exported.toString("utf8")).toContain("committed");
      expect(JSON.parse(logLines[0] ?? "{}")).toMatchObject({
        traceId: consumerTraceId,
        traceSampled: true,
      });
      expect(diagnosticEvents).toEqual([]);

      await expect(runtime.shutdown(AbortSignal.abort())).rejects.toThrow(
        NotificationConfigurationError,
      );
      await runtime.shutdown(AbortSignal.timeout(2_000));
      await runtime.shutdown(AbortSignal.timeout(2_000));
    } finally {
      await close(collector);
    }
  });

  it("permits no-op behavior only through an authenticated disabled config", async () => {
    const configuration = loadNotifierTelemetryConfiguration("test", "test", {
      OTEL_SDK_DISABLED: "true",
    });
    expect(() =>
      startNotifierTelemetry({ ...configuration }, { error() {} }),
    ).toThrow(NotificationConfigurationError);

    const runtime = startNotifierTelemetry(configuration, { error() {} });
    let called = false;
    await runtime.runConsumerSpan(
      "webhook_delivery",
      undefined,
      async () => {
        called = true;
        expect(activeTraceCorrelation()).toBeUndefined();
        return "delivered" as const;
      },
      (outcome) => outcome,
    );
    expect(called).toBe(true);
    const invokeConsumerSpan = runtime.runConsumerSpan.bind(runtime);
    await expect(
      Promise.resolve().then(() =>
        Reflect.apply(invokeConsumerSpan, undefined, [
          "unknown",
          undefined,
          async () => "delivered",
          (outcome: string) => outcome,
        ]),
      ),
    ).rejects.toThrow(NotificationValidationError);
    await expect(
      Promise.resolve().then(() =>
        Reflect.apply(invokeConsumerSpan, undefined, [
          "email_delivery",
          undefined,
          async () => "delivered",
          () => "recipient@example.invalid",
        ]),
      ),
    ).rejects.toThrow(NotificationValidationError);
    await runtime.shutdown(AbortSignal.abort());
  });
});

function enabledEnvironment(
  endpoint: string,
): Readonly<Record<string, string | undefined>> {
  return {
    OTEL_EXPORTER_OTLP_ENDPOINT: endpoint,
    OTEL_EXPORTER_OTLP_PROTOCOL: "http/protobuf",
    OTEL_SDK_DISABLED: "false",
    OTEL_SERVICE_NAME: "periapsis-notifier",
    OTEL_TRACES_SAMPLER: "parentbased_traceidratio",
    OTEL_TRACES_SAMPLER_ARG: "1",
  };
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string") {
    throw new Error("collector fixture did not bind");
  }
  return `http://127.0.0.1:${address.port}`;
}

async function close(server: Server): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}
