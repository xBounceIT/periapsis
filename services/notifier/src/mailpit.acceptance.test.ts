import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { createNotificationEvent, projectEventContext } from "./event.js";
import { PolicySmtpSocketConnector } from "./smtp-egress.js";
import { ExactPinnedSmtpHealthProbe } from "./smtp-health.js";
import { createSmtpConfiguration, NodemailerSmtpProvider } from "./smtp.js";
import {
  createNotificationTemplate,
  renderNotificationTemplate,
} from "./template.js";
import { id } from "./test/fixtures.js";

const enabled = process.env.PERIAPSIS_MAILPIT_ACCEPTANCE === "1";

describe.skipIf(!enabled)("Mailpit SMTP acceptance", () => {
  it("probes and delivers a customer-safe rendered message through the full-profile fixture", async () => {
    const host = process.env.PERIAPSIS_MAILPIT_SMTP_HOST ?? "127.0.0.1";
    const smtpPort = environmentPort(
      process.env.PERIAPSIS_MAILPIT_SMTP_PORT,
      11_025,
    );
    const apiOrigin =
      process.env.PERIAPSIS_MAILPIT_API_ORIGIN ?? "http://127.0.0.1:18025";
    const configuration = createSmtpConfiguration(
      {
        id: id(910),
        tenantId: id(2),
        name: "Mailpit acceptance",
        host,
        port: smtpPort,
        security: "plain_local",
        fromName: "Periapsis acceptance",
        fromEmail: "notifications@example.invalid",
        timeoutMs: 5_000,
        maximumConnections: 1,
        maximumMessagesPerConnection: 2,
        rateLimitPerSecond: 2,
        enabled: true,
        version: 17,
      },
      { allowPlainLocal: true },
    );
    const secrets = {
      async read(): Promise<never> {
        throw new Error("Mailpit acceptance must not resolve a secret");
      },
    };
    const connector = new PolicySmtpSocketConnector({
      policy: {
        allowedPorts: [smtpPort],
        allowedPrivateHosts: [host],
      },
    });
    const probe = new ExactPinnedSmtpHealthProbe({
      repository: {
        async loadPinnedForProbe(_tenantId, pin) {
          return pin.scope === "tenant" &&
            pin.id === configuration.id &&
            pin.version === configuration.version
            ? configuration
            : null;
        },
      },
      secrets,
      connector,
    });

    const health = await probe.probe(
      {
        probeId: id(911),
        fenceToken: id(912),
        tenantId: id(2),
        configurationScope: "tenant",
        configurationId: configuration.id,
        configurationVersion: configuration.version,
      },
      AbortSignal.timeout(10_000),
    );
    expect(health).toMatchObject({
      healthy: true,
      checks: [
        { kind: "dns", outcome: "passed" },
        { kind: "connect", outcome: "passed" },
      ],
    });

    const operatorOnlyMarker = "operator-private-marker-never-send";
    const hostileCustomerText = '<img src=x onerror="alert(1)">';
    const event = createNotificationEvent({
      id: id(913),
      tenantId: id(2),
      type: "comment.public_added",
      objectType: "case",
      objectId: id(914),
      objectVersion: 1,
      occurredAt: new Date("2026-09-01T00:00:00.000Z"),
      actorKind: "system",
      source: "mailpit_acceptance",
      maximumAudience: "customer",
      context: {
        comment: { body: operatorOnlyMarker },
        customer: { comment: { body: hostileCustomerText } },
      },
    });
    const template = createNotificationTemplate({
      id: id(915),
      tenantId: id(2),
      key: "mailpit_acceptance",
      name: "Mailpit acceptance",
      language: "en",
      version: 1,
      subject: "Comment {{comment.body}}",
      html: "<p>{{comment.body}}</p>",
      plainText: "{{comment.body}}",
    });
    const rendered = renderNotificationTemplate(
      template,
      projectEventContext(event, "customer"),
      { audience: "customer" },
    );
    expect(rendered.html).toContain('&lt;img src=x onerror="alert(1)"&gt;');
    expect(JSON.stringify(rendered)).not.toContain(operatorOnlyMarker);

    const deliveryId = id(916);
    const messageDigest = createHash("sha256")
      .update(`${deliveryId}:mailpit-acceptance`)
      .digest("hex");
    const messageId = `<${messageDigest}@notifications.periapsis.invalid>`;
    const recipient = `smtp-acceptance+${deliveryId}@example.invalid`;
    const provider = await NodemailerSmtpProvider.create(
      configuration,
      secrets,
      connector,
      AbortSignal.timeout(10_000),
    );
    try {
      const result = await provider.send(
        {
          tenantId: id(2),
          recipient,
          subject: rendered.subject,
          html: rendered.html,
          plainText: rendered.plainText,
          headers: {
            "message-id": messageId,
            "x-periapsis-delivery-id": deliveryId,
          },
        },
        AbortSignal.timeout(10_000),
      );
      expect(result).toEqual({
        provider: "smtp",
        receiptDigest: expect.stringMatching(/^[0-9a-f]{64}$/u),
        acceptedCount: 1,
        rejectedCount: 0,
        responseClass: 2,
      });
      expect(JSON.stringify(result)).not.toMatch(
        /recipient|subject|body|secret|password|banner/iu,
      );
    } finally {
      provider.close();
    }

    const captured = await waitForMessage(apiOrigin, messageId);
    expect(captured.messageId).toBe(normalizeMessageId(messageId));
    expect(captured.html).toContain('&lt;img src=x onerror="alert(1)"&gt;');
    expect(captured.html).not.toMatch(/<\s*(?:img|script)\b/iu);
    expect(captured.html).not.toMatch(/href\s*=\s*["']javascript:/iu);
    expect(captured.text).toContain(hostileCustomerText);
    expect(JSON.stringify(captured)).not.toContain(operatorOnlyMarker);
  }, 60_000);
});

function environmentPort(input: string | undefined, fallback: number): number {
  const value = input === undefined ? fallback : Number(input);
  if (!Number.isInteger(value) || value < 1 || value > 65_535) {
    throw new Error("Mailpit acceptance port is invalid");
  }
  return value;
}

async function waitForMessage(
  apiOrigin: string,
  expectedMessageId: string,
): Promise<{
  readonly messageId: string;
  readonly html: string;
  readonly text: string;
}> {
  return pollForMessage(apiOrigin, expectedMessageId, Date.now() + 30_000);
}

async function pollForMessage(
  apiOrigin: string,
  expectedMessageId: string,
  deadline: number,
): Promise<{
  readonly messageId: string;
  readonly html: string;
  readonly text: string;
}> {
  const response = await fetch(
    `${apiOrigin}/api/v1/messages?start=0&limit=50`,
    { signal: AbortSignal.timeout(5_000) },
  );
  if (!response.ok) throw new Error("Mailpit list request failed");
  const payload: unknown = await response.json();
  const messages = mailpitMessages(payload);
  const match = messages.find(
    (message) =>
      normalizeMessageId(message.MessageID) ===
      normalizeMessageId(expectedMessageId),
  );
  if (match !== undefined) {
    const detailResponse = await fetch(
      `${apiOrigin}/api/v1/message/${encodeURIComponent(match.ID)}`,
      { signal: AbortSignal.timeout(5_000) },
    );
    if (!detailResponse.ok) throw new Error("Mailpit detail request failed");
    return mailpitMessage(await detailResponse.json());
  }
  if (Date.now() >= deadline) {
    throw new Error("Mailpit did not capture the expected message");
  }
  await new Promise((resolve) => setTimeout(resolve, 250));
  return pollForMessage(apiOrigin, expectedMessageId, deadline);
}

function mailpitMessages(
  input: unknown,
): readonly { readonly ID: string; readonly MessageID: string }[] {
  if (!plainRecord(input) || !Array.isArray(input.messages)) {
    throw new Error("Mailpit list response is invalid");
  }
  return input.messages.map((entry) => {
    if (
      !plainRecord(entry) ||
      typeof entry.ID !== "string" ||
      entry.ID.length === 0 ||
      typeof entry.MessageID !== "string"
    ) {
      throw new Error("Mailpit message summary is invalid");
    }
    return { ID: entry.ID, MessageID: entry.MessageID };
  });
}

function mailpitMessage(input: unknown): {
  readonly messageId: string;
  readonly html: string;
  readonly text: string;
} {
  if (
    !plainRecord(input) ||
    typeof input.MessageID !== "string" ||
    typeof input.HTML !== "string" ||
    typeof input.Text !== "string"
  ) {
    throw new Error("Mailpit message response is invalid");
  }
  return Object.freeze({
    messageId: normalizeMessageId(input.MessageID),
    html: input.HTML,
    text: input.Text,
  });
}

function normalizeMessageId(value: string): string {
  return value.trim().replace(/^<|>$/gu, "").toLowerCase();
}

function plainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
