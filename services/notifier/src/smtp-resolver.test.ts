import type { Socket } from "node:net";

import { describe, expect, it, vi } from "vitest";

import { DeliveryProviderError } from "./errors.js";
import {
  CachedSmtpProviderResolver,
  type SmtpConfigurationRepository,
} from "./smtp-resolver.js";
import {
  createSmtpConfiguration,
  type SecretResolver,
  type SmtpConfiguration,
  type SmtpConfigurationInput,
} from "./smtp.js";
import { id, protectedSecret } from "./test/fixtures.js";

describe("cached SMTP provider resolution", () => {
  it("loads the exact immutable pin and coalesces provider creation", async () => {
    const configuration = smtpConfiguration();
    const loadPinnedForTenant = vi.fn(
      async (
        tenantId: string,
        pin: Readonly<{
          scope: "tenant" | "platform";
          id: string;
          version: number;
        }>,
      ) => {
        expect(tenantId).toBe(id(2));
        expect(pin).toEqual({
          scope: "platform",
          id: configuration.id,
          version: 1,
        });
        return configuration;
      },
    );
    let secretReads = 0;
    const resolver = resolverFor(
      { loadPinnedForTenant },
      {
        async read() {
          secretReads += 1;
          await Promise.resolve();
          return new TextEncoder().encode("correct horse battery staple");
        },
      },
    );

    const pin = {
      scope: "platform" as const,
      id: configuration.id,
      version: configuration.version,
    };
    const [first, second] = await Promise.all([
      resolver.resolve(id(2), pin, new AbortController().signal),
      resolver.resolve(id(2), pin, new AbortController().signal),
    ]);

    expect(first).toBe(second);
    expect(secretReads).toBe(1);
    expect(loadPinnedForTenant).toHaveBeenCalledTimes(2);
    resolver.close();
  });

  it("fails terminally when a repository substitutes a version or tenant", async () => {
    const pinned = smtpConfiguration();
    const substitutedInput = smtpInput();
    substitutedInput.version = 2;
    const substituted = createSmtpConfiguration(substitutedInput);
    const wrongTenantInput = smtpInput();
    wrongTenantInput.tenantId = id(3);
    wrongTenantInput.passwordSecret = protectedSecret("smtp_password", id(3));
    const wrongTenant = createSmtpConfiguration(wrongTenantInput);

    await Promise.all(
      [substituted, wrongTenant, { ...pinned }].map(async (returned) => {
        const resolver = resolverFor({
          async loadPinnedForTenant() {
            return returned;
          },
        });
        const error = await resolver
          .resolve(
            id(2),
            { scope: "platform", id: pinned.id, version: pinned.version },
            new AbortController().signal,
          )
          .catch((reason: unknown) => reason);
        expect(error).toBeInstanceOf(DeliveryProviderError);
        expect(error).toMatchObject({
          failureClass: "security",
          retrySafety: "terminal",
        });
        resolver.close();
      }),
    );
  });

  it("never shares a same-id provider cache entry across tenants", async () => {
    const firstInput = smtpInput();
    firstInput.tenantId = id(2);
    firstInput.passwordSecret = protectedSecret("smtp_password", id(2));
    const secondInput = smtpInput();
    secondInput.tenantId = id(3);
    secondInput.passwordSecret = protectedSecret("smtp_password", id(3));
    const configurations = new Map([
      [id(2), createSmtpConfiguration(firstInput)],
      [id(3), createSmtpConfiguration(secondInput)],
    ]);
    let secretReads = 0;
    const resolver = resolverFor(
      {
        async loadPinnedForTenant(tenantId) {
          return configurations.get(tenantId) ?? null;
        },
      },
      {
        async read() {
          secretReads += 1;
          return new TextEncoder().encode("correct horse battery staple");
        },
      },
    );
    const pin = {
      scope: "tenant" as const,
      id: firstInput.id,
      version: firstInput.version,
    };
    const first = await resolver.resolve(
      id(2),
      pin,
      new AbortController().signal,
    );
    const second = await resolver.resolve(
      id(3),
      pin,
      new AbortController().signal,
    );
    expect(first).not.toBe(second);
    expect(secretReads).toBe(2);
    resolver.close();
  });

  it("never substitutes a platform configuration for an exact tenant-scoped pin", async () => {
    const platformConfiguration = smtpConfiguration();
    const resolver = resolverFor({
      async loadPinnedForTenant(tenantId, pin) {
        expect(tenantId).toBe(id(2));
        expect(pin).toEqual({
          scope: "tenant",
          id: platformConfiguration.id,
          version: platformConfiguration.version,
        });
        return platformConfiguration;
      },
    });

    await expect(
      resolver.resolve(
        id(2),
        {
          scope: "tenant",
          id: platformConfiguration.id,
          version: platformConfiguration.version,
        },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
    });
    resolver.close();
  });

  it("treats missing, disabled, or revoked pins as terminal authentication failures", async () => {
    const pinned = smtpConfiguration();
    const disabledInput = smtpInput();
    disabledInput.enabled = false;
    const disabled = createSmtpConfiguration(disabledInput);

    await Promise.all(
      [null, disabled].map(async (returned) => {
        const resolver = resolverFor({
          async loadPinnedForTenant() {
            return returned;
          },
        });
        const error = await resolver
          .resolve(
            id(2),
            { scope: "platform", id: pinned.id, version: pinned.version },
            new AbortController().signal,
          )
          .catch((reason: unknown) => reason);
        expect(error).toMatchObject({
          failureClass: "authentication",
          retrySafety: "terminal",
        });
        resolver.close();
      }),
    );
  });

  it("bounds the cache and closes evicted and shutdown providers", async () => {
    const firstConfiguration = smtpConfiguration();
    const secondInput = smtpInput();
    secondInput.id = id(61);
    const secondConfiguration = createSmtpConfiguration(secondInput);
    const configurations = new Map([
      [firstConfiguration.id, firstConfiguration],
      [secondConfiguration.id, secondConfiguration],
    ]);
    const resolver = resolverFor(
      {
        async loadPinnedForTenant(_tenantId, pin) {
          return configurations.get(pin.id) ?? null;
        },
      },
      undefined,
      1,
    );
    const first = await resolver.resolve(
      id(2),
      { scope: "platform", id: firstConfiguration.id, version: 1 },
      new AbortController().signal,
    );
    const second = await resolver.resolve(
      id(2),
      { scope: "platform", id: secondConfiguration.id, version: 1 },
      new AbortController().signal,
    );

    await expect(
      first.send(deliveryInput(), new AbortController().signal),
    ).rejects.toMatchObject({
      failureClass: "connectivity",
      retrySafety: "safe",
    });
    resolver.close();
    await expect(
      second.send(deliveryInput(), new AbortController().signal),
    ).rejects.toMatchObject({
      failureClass: "connectivity",
      retrySafety: "safe",
    });
  });
});

function resolverFor(
  repository: SmtpConfigurationRepository,
  secrets: SecretResolver = {
    async read() {
      return new TextEncoder().encode("correct horse battery staple");
    },
  },
  maximumProviders = 64,
): CachedSmtpProviderResolver {
  return new CachedSmtpProviderResolver({
    repository,
    secrets,
    connector: {
      async connect(): Promise<Socket> {
        throw new Error("network is not expected in this test");
      },
    },
    maximumProviders,
  });
}

function smtpConfiguration(): SmtpConfiguration {
  return createSmtpConfiguration(smtpInput());
}

function smtpInput(): SmtpConfigurationInput {
  return {
    id: id(60),
    name: "Global SMTP",
    host: "mail.example.test",
    port: 587,
    security: "starttls",
    username: "mailer",
    passwordSecret: protectedSecret("smtp_password"),
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

function deliveryInput() {
  return {
    tenantId: id(2),
    recipient: "analyst@example.com",
    subject: "Critical alert",
    html: "<p>Safe</p>",
    plainText: "Safe",
  };
}
