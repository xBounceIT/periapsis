import { Socket } from "node:net";

import { describe, expect, it, vi } from "vitest";

import type { DeliveryProviderError } from "./errors.js";
import {
  PolicySmtpSocketConnector,
  PolicyTcpSocketConnector,
  type SmtpDnsResolver,
  type SmtpTcpDialer,
} from "./smtp-egress.js";
import { createSmtpConfiguration } from "./smtp.js";
import { id } from "./test/fixtures.js";

describe("SMTP egress connector", () => {
  it("rejects a mixed public/private DNS answer before dialing", async () => {
    const dial = vi.fn<SmtpTcpDialer["connect"]>();
    const connector = connectorWith(
      [
        { address: "203.0.114.10", family: 4 },
        { address: "10.0.0.8", family: 4 },
      ],
      dial,
    );

    await expect(connector.connect(configuration())).rejects.toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
    } satisfies Partial<DeliveryProviderError>);
    expect(dial).not.toHaveBeenCalled();
  });

  it("pins an explicitly allowed private target to its resolved literal IP", async () => {
    const socket = new Socket();
    const dial = vi.fn<SmtpTcpDialer["connect"]>().mockResolvedValue(socket);
    const connector = connectorWith(
      [{ address: "10.20.30.40", family: 4 }],
      dial,
      { allowedPrivateHosts: ["mail.internal.example"] },
    );

    await expect(connector.connect(configuration())).resolves.toBe(socket);
    expect(dial).toHaveBeenCalledWith(
      expect.objectContaining({
        address: "10.20.30.40",
        family: 4,
        port: 587,
      }),
    );
  });

  it("never permits link-local metadata or a deployment-unapproved port", async () => {
    const dial = vi.fn<SmtpTcpDialer["connect"]>();
    const metadataConnector = connectorWith(
      [{ address: "169.254.169.254", family: 4 }],
      dial,
      { allowedPrivateHosts: ["mail.internal.example"] },
    );
    await expect(
      metadataConnector.connect(configuration()),
    ).rejects.toMatchObject({ failureClass: "security" });

    const portConnector = connectorWith(
      [{ address: "203.0.114.10", family: 4 }],
      dial,
      { allowedPorts: [465] },
    );
    await expect(portConnector.connect(configuration())).rejects.toMatchObject({
      failureClass: "security",
    });
    expect(dial).not.toHaveBeenCalled();
  });

  it("keeps plaintext development SMTP on an explicitly allowed private target", async () => {
    const publicDial = vi.fn<SmtpTcpDialer["connect"]>();
    const publicConnector = connectorWith(
      [{ address: "203.0.114.10", family: 4 }],
      publicDial,
      { allowedPrivateHosts: ["mail.internal.example"] },
    );

    await expect(
      publicConnector.connect(plainLocalConfiguration()),
    ).rejects.toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
    } satisfies Partial<DeliveryProviderError>);
    expect(publicDial).not.toHaveBeenCalled();

    const privateSocket = new Socket();
    const privateDial = vi
      .fn<SmtpTcpDialer["connect"]>()
      .mockResolvedValue(privateSocket);
    const privateConnector = connectorWith(
      [{ address: "10.20.30.40", family: 4 }],
      privateDial,
      { allowedPrivateHosts: ["mail.internal.example"] },
    );

    await expect(
      privateConnector.connect(plainLocalConfiguration()),
    ).resolves.toBe(privateSocket);
  });

  it("cancels DNS resolution when its caller shuts down", async () => {
    const controller = new AbortController();
    const reason = new Error("shutdown");
    const dial = vi.fn<SmtpTcpDialer["connect"]>();
    const connector = new PolicyTcpSocketConnector({
      resolver: {
        resolve(_hostname, signal) {
          return new Promise((_, reject) => {
            signal.addEventListener("abort", () => reject(signal.reason), {
              once: true,
            });
          });
        },
      },
      dialer: { connect: dial },
      policy: { allowedPorts: [443] },
    });

    const operation = connector.connect({
      host: "hooks.example.com",
      port: 443,
      timeoutMs: 5_000,
      signal: controller.signal,
    });
    controller.abort(reason);

    await expect(operation).rejects.toBe(reason);
    expect(dial).not.toHaveBeenCalled();
  });
});

function configuration() {
  return createSmtpConfiguration({
    id: id(70),
    name: "Tenant SMTP",
    host: "mail.internal.example",
    port: 587,
    security: "starttls",
    fromName: "Periapsis",
    fromEmail: "notifications@example.com",
    timeoutMs: 5_000,
    maximumConnections: 2,
    maximumMessagesPerConnection: 10,
    rateLimitPerSecond: 20,
    enabled: true,
    version: 1,
  });
}

function plainLocalConfiguration() {
  return createSmtpConfiguration(
    {
      id: id(71),
      name: "Local SMTP",
      host: "mail.internal.example",
      port: 587,
      security: "plain_local",
      fromName: "Periapsis",
      fromEmail: "notifications@example.com",
      timeoutMs: 5_000,
      maximumConnections: 2,
      maximumMessagesPerConnection: 10,
      rateLimitPerSecond: 20,
      enabled: true,
      version: 1,
    },
    { allowPlainLocal: true },
  );
}

function connectorWith(
  addresses: readonly { address: string; family: 4 | 6 }[],
  connect: SmtpTcpDialer["connect"],
  policy: {
    allowedPorts?: readonly number[];
    allowedPrivateHosts?: readonly string[];
  } = {},
): PolicySmtpSocketConnector {
  const resolver: SmtpDnsResolver = {
    async resolve() {
      return addresses;
    },
  };
  return new PolicySmtpSocketConnector({
    resolver,
    dialer: { connect },
    policy,
  });
}
