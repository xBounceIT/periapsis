import { createServer, type Server, type Socket } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import { NotificationValidationError } from "./errors.js";
import { PolicySmtpSocketConnector } from "./smtp-egress.js";
import {
  createSmtpConfiguration,
  NodemailerSmtpProvider,
  selectSmtpConfiguration,
  type SmtpConfigurationInput,
} from "./smtp.js";
import { id, protectedSecret } from "./test/fixtures.js";

describe("SMTP configuration and provider", () => {
  const closeables: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    await Promise.all(
      closeables
        .splice(0)
        .toReversed()
        .map((close) => Promise.resolve(close())),
    );
  });

  it("prefers an exact tenant override and rejects ambiguous inventory", () => {
    const global = createSmtpConfiguration(smtpInput(), {
      allowPlainLocal: true,
    });
    const tenantInput = smtpInput();
    tenantInput.id = id(61);
    tenantInput.tenantId = id(2);
    tenantInput.name = "Tenant SMTP";
    const tenant = createSmtpConfiguration(tenantInput, {
      allowPlainLocal: true,
    });
    expect(selectSmtpConfiguration(id(2), global, [tenant])).toBe(tenant);
    expect(selectSmtpConfiguration(id(3), global, [tenant])).toBe(global);
    expect(() =>
      selectSmtpConfiguration(id(2), global, [tenant, tenant]),
    ).toThrow(NotificationValidationError);
    expect(() =>
      selectSmtpConfiguration(id(2), { ...global }, [tenant]),
    ).toThrow(NotificationValidationError);
  });

  it("allows plaintext only for an explicitly enabled loopback development endpoint", () => {
    const input = smtpInput();
    expect(() => createSmtpConfiguration(input)).toThrow(
      NotificationValidationError,
    );
    expect(
      createSmtpConfiguration(input, { allowPlainLocal: true }).security,
    ).toBe("plain_local");
    input.host = "mail.example.com";
    expect(createSmtpConfiguration(input, { allowPlainLocal: true }).host).toBe(
      "mail.example.com",
    );
    input.host = "127.0.0.1";
    input.username = "mailer";
    expect(() =>
      createSmtpConfiguration(input, { allowPlainLocal: true }),
    ).toThrow(NotificationValidationError);

    input.passwordSecret = protectedSecret("smtp_password", id(2));
    expect(() =>
      createSmtpConfiguration(input, { allowPlainLocal: true }),
    ).toThrow(NotificationValidationError);
    input.tenantId = id(2);
    expect(
      createSmtpConfiguration(input, { allowPlainLocal: true }).passwordSecret,
    ).toBe(input.passwordSecret);
    input.passwordSecret = protectedSecret("webhook_signing_key", id(2));
    expect(() =>
      createSmtpConfiguration(input, { allowPlainLocal: true }),
    ).toThrow(NotificationValidationError);
  });

  it("delivers through the real pooled Nodemailer SMTP adapter and returns only sanitized response data", async () => {
    const fixture = await startSmtpFixture();
    closeables.push(fixture.close);
    const input = smtpInput();
    input.port = fixture.port;
    const configuration = createSmtpConfiguration(input, {
      allowPlainLocal: true,
    });
    const provider = await NodemailerSmtpProvider.create(
      configuration,
      {
        async read() {
          throw new Error("no secret expected");
        },
      },
      localConnector(fixture.port),
      new AbortController().signal,
    );
    closeables.push(() => provider.close());

    const health = await provider.health(new AbortController().signal);
    expect(health.healthy).toBe(true);
    const result = await provider.send(
      {
        tenantId: id(2),
        recipient: "analyst@example.com",
        subject: "Critical alert",
        html: "<p>Safe</p>",
        plainText: "Safe",
        headers: {
          "message-id": `<${"a".repeat(64)}@notifications.periapsis.invalid>`,
          "x-periapsis-delivery-id": id(62),
        },
      },
      new AbortController().signal,
    );
    expect(result).toEqual({
      provider: "smtp",
      receiptDigest: expect.stringMatching(/^[0-9a-f]{64}$/u),
      acceptedCount: 1,
      rejectedCount: 0,
      responseClass: 2,
    });
    expect(JSON.stringify(result)).not.toContain("analyst@example.com");
    expect(fixture.messages[0]).toContain("Message-ID:");
    expect(fixture.messages[0]).not.toContain("Bcc:");
  });

  it("rejects arbitrary mail headers", async () => {
    const fixture = await startSmtpFixture();
    closeables.push(fixture.close);
    const input = smtpInput();
    input.port = fixture.port;
    const configuration = createSmtpConfiguration(input, {
      allowPlainLocal: true,
    });
    const provider = await NodemailerSmtpProvider.create(
      configuration,
      {
        async read() {
          throw new Error("no secret expected");
        },
      },
      localConnector(fixture.port),
      new AbortController().signal,
    );
    closeables.push(() => provider.close());
    await expect(
      provider.send(
        {
          tenantId: id(2),
          recipient: "analyst@example.com",
          subject: "Safe",
          html: "<p>Safe</p>",
          plainText: "Safe",
          headers: { "return-path": "attacker@example.com" },
        },
        new AbortController().signal,
      ),
    ).rejects.toThrow(NotificationValidationError);

    await expect(
      provider.send(
        {
          tenantId: id(2),
          recipient: "analyst@example.com",
          subject: "Safe",
          html: "<p>Safe</p>",
          plainText: "Safe",
          headers: { "message-id": "attacker-controlled" },
        },
        new AbortController().signal,
      ),
    ).rejects.toThrow(NotificationValidationError);
  });

  it("honors cancellation while an SMTP handshake is stalled", async () => {
    const fixture = await startStalledTcpFixture();
    closeables.push(fixture.close);
    const input = smtpInput();
    input.port = fixture.port;
    const provider = await NodemailerSmtpProvider.create(
      createSmtpConfiguration(input, { allowPlainLocal: true }),
      {
        async read() {
          throw new Error("no secret expected");
        },
      },
      localConnector(fixture.port),
      new AbortController().signal,
    );
    closeables.push(() => provider.close());

    const cancellation = new AbortController();
    const pending = provider.health(cancellation.signal);
    cancellation.abort(new Error("operation cancelled"));
    await expect(pending).rejects.toThrow("operation cancelled");
  });
});

function localConnector(port: number): PolicySmtpSocketConnector {
  return new PolicySmtpSocketConnector({
    policy: {
      allowedPorts: [port],
      allowedPrivateHosts: ["127.0.0.1"],
    },
  });
}

function smtpInput(): SmtpConfigurationInput {
  return {
    id: id(60),
    name: "Global SMTP",
    host: "127.0.0.1",
    port: 2525,
    security: "plain_local",
    fromName: "Periapsis",
    fromEmail: "notifications@example.com",
    timeoutMs: 5_000,
    maximumConnections: 2,
    maximumMessagesPerConnection: 10,
    rateLimitPerSecond: 50,
    enabled: true,
    version: 1,
  };
}

async function startSmtpFixture(): Promise<{
  server: Server;
  port: number;
  messages: string[];
  close: () => Promise<void>;
}> {
  const messages: string[] = [];
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.setEncoding("utf8");
    socket.write("220 localhost ESMTP test\r\n");
    let buffer = "";
    let dataMode = false;
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      while (true) {
        if (dataMode) {
          const boundary = buffer.indexOf("\r\n.\r\n");
          if (boundary < 0) return;
          messages.push(buffer.slice(0, boundary));
          buffer = buffer.slice(boundary + 5);
          dataMode = false;
          socket.write("250 2.0.0 queued\r\n");
          continue;
        }
        const boundary = buffer.indexOf("\r\n");
        if (boundary < 0) return;
        const line = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const command = line.split(" ", 1)[0]?.toUpperCase();
        if (command === "EHLO" || command === "HELO") {
          socket.write("250-localhost\r\n250 PIPELINING\r\n");
        } else if (
          command === "MAIL" ||
          command === "RCPT" ||
          command === "RSET" ||
          command === "NOOP"
        ) {
          socket.write("250 2.0.0 ok\r\n");
        } else if (command === "DATA") {
          dataMode = true;
          socket.write("354 end with dot\r\n");
        } else if (command === "QUIT") {
          socket.end("221 2.0.0 bye\r\n");
        } else {
          socket.write("500 5.5.1 unsupported\r\n");
        }
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("fixture did not bind TCP");
  return {
    server,
    port: address.port,
    messages,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => {
        server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      });
    },
  };
}

async function startStalledTcpFixture(): Promise<{
  port: number;
  close: () => Promise<void>;
}> {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("stalled fixture did not bind TCP");
  return {
    port: address.port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve, reject) => {
        server.close((error) =>
          error === undefined ? resolve() : reject(error),
        );
      });
    },
  };
}
