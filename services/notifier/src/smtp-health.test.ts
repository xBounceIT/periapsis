import { createServer, type Server, type Socket } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import { NotificationValidationError } from "./errors.js";
import { PolicySmtpSocketConnector } from "./smtp-egress.js";
import { ExactPinnedSmtpHealthProbe } from "./smtp-health.js";
import { createSmtpConfiguration } from "./smtp.js";
import { id, protectedSecret } from "./test/fixtures.js";

describe("exact pinned SMTP health probe", () => {
  const closeables: Array<() => Promise<void> | void> = [];

  afterEach(async () => {
    await Promise.all(
      closeables
        .splice(0)
        .toReversed()
        .map((close) => Promise.resolve(close())),
    );
  });

  it("loads and verifies exactly the requested tenant configuration with an ephemeral provider", async () => {
    const fixture = await startSmtpFixture();
    closeables.push(fixture.close);
    const passwordSecret = protectedSecret("smtp_password", id(2), 9);
    const configuration = createSmtpConfiguration(
      {
        id: id(82),
        tenantId: id(2),
        name: "Health probe",
        host: "127.0.0.1",
        port: fixture.port,
        security: "plain_local",
        username: "health-probe",
        passwordSecret,
        fromName: "Periapsis",
        fromEmail: "notifications@example.invalid",
        timeoutMs: 5_000,
        maximumConnections: 1,
        maximumMessagesPerConnection: 1,
        rateLimitPerSecond: 1,
        enabled: true,
        version: 7,
      },
      { allowPlainLocal: true },
    );
    const loadPinnedForProbe = vi.fn(async () => configuration);
    const plaintext = new Uint8Array([0x70, 0x72, 0x6f, 0x62, 0x65]);
    const read = vi.fn(async (secret) => {
      expect(secret).toBe(passwordSecret);
      return plaintext;
    });
    const probe = new ExactPinnedSmtpHealthProbe({
      repository: { loadPinnedForProbe },
      secrets: { read },
      connector: new PolicySmtpSocketConnector({
        policy: {
          allowedPorts: [fixture.port],
          allowedPrivateHosts: ["127.0.0.1"],
        },
      }),
    });
    const request = {
      probeId: id(80),
      fenceToken: id(81),
      tenantId: id(2),
      configurationScope: "tenant",
      configurationId: id(82),
      configurationVersion: 7,
    } as const;

    const result = await probe.probe(request, new AbortController().signal);

    expect(loadPinnedForProbe).toHaveBeenCalledWith(
      id(2),
      { scope: "tenant", id: id(82), version: 7 },
      expect.any(AbortSignal),
    );
    expect(result).toMatchObject({
      ...request,
      healthy: true,
      checks: [
        { kind: "dns", outcome: "passed" },
        { kind: "connect", outcome: "passed" },
        { kind: "authentication", outcome: "passed" },
      ],
    });
    expect(read).toHaveBeenCalledOnce();
    expect(plaintext.every((value) => value === 0)).toBe(true);
    expect(result.checkedAt).toBeInstanceOf(Date);
    expect(JSON.stringify(result)).not.toMatch(
      /recipient|password|secret|banner/iu,
    );
  });

  it("fails closed for a missing or mismatched pin and rejects protocol drift", async () => {
    const loadPinnedForProbe = vi.fn(async () => null);
    const connector = { connect: vi.fn() };
    const probe = new ExactPinnedSmtpHealthProbe({
      repository: { loadPinnedForProbe },
      secrets: { read: vi.fn() },
      connector,
    });
    const request = {
      probeId: id(83),
      fenceToken: id(84),
      configurationScope: "platform",
      configurationId: id(85),
      configurationVersion: 1,
    } as const;
    const result = await probe.probe(request, new AbortController().signal);
    expect(result).toMatchObject({
      ...request,
      healthy: false,
      checks: [{ kind: "dns", outcome: "failed", errorClass: "security" }],
    });
    expect(connector.connect).not.toHaveBeenCalled();

    await expect(
      probe.probe(
        { ...request, unexpected: "drift" },
        new AbortController().signal,
      ),
    ).rejects.toThrow(NotificationValidationError);
    await expect(
      probe.probe(
        { ...request, configurationScope: "tenant" },
        new AbortController().signal,
      ),
    ).rejects.toThrow(NotificationValidationError);
  });
});

async function startSmtpFixture(): Promise<{
  server: Server;
  port: number;
  close: () => Promise<void>;
}> {
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.setEncoding("utf8");
    socket.write("220 localhost ESMTP health-test\r\n");
    let buffer = "";
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      while (true) {
        const boundary = buffer.indexOf("\r\n");
        if (boundary < 0) return;
        const line = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + 2);
        const command = line.split(" ", 1)[0]?.toUpperCase();
        if (command === "EHLO" || command === "HELO") {
          socket.write("250-localhost\r\n250-AUTH PLAIN\r\n250 PIPELINING\r\n");
        } else if (command === "AUTH") {
          socket.write("235 2.7.0 authentication successful\r\n");
        } else if (command === "QUIT") {
          socket.end("221 2.0.0 bye\r\n");
        } else {
          socket.write("250 2.0.0 ok\r\n");
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
  if (address === null || typeof address === "string") {
    throw new Error("SMTP health fixture did not bind");
  }
  return {
    server,
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
