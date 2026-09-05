import { describe, expect, it, vi } from "vitest";

import { loadNotifierConfiguration } from "./config.js";
import { NotificationValidationError } from "./errors.js";

describe("notifier configuration", () => {
  it("requires production secrets through files and parses bounded runtime settings", async () => {
    const readSecretFile = vi.fn(async (path: string): Promise<Uint8Array> =>
      new TextEncoder().encode(
        path === "/run/secrets/database"
          ? "postgresql://notifier:secret@postgres/periapsis?sslmode=require"
          : path === "/run/secrets/preview"
            ? previewToken
            : keyringDocument,
      ),
    );
    const config = await loadNotifierConfiguration({
      env: {
        PERIAPSIS_ENV: "production",
        OTEL_SDK_DISABLED: "true",
        PERIAPSIS_DATABASE_URL_FILE: "/run/secrets/database",
        PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE: "/run/secrets/preview",
        NOTIFICATION_KEYRING_FILE: "/run/secrets/notification-keyring",
        PERIAPSIS_NOTIFIER_ADDR: "[::]:9082",
        PERIAPSIS_SMTP_ALLOWED_PORTS: "465,587,2525",
        PERIAPSIS_SMTP_ALLOWED_PRIVATE_HOSTS: "mail.internal.example",
        PERIAPSIS_NOTIFIER_CONCURRENCY: "12",
        PERIAPSIS_LOG_LEVEL: "error",
      },
      readSecretFile,
    });

    expect(config.listen).toEqual({ host: "::", port: 9082 });
    expect(config.worker.maximumConcurrency).toBe(12);
    expect(config.fanout).toMatchObject({
      maximumConcurrency: 8,
      processingTimeoutMs: 30_000,
    });
    expect(config.smtpAllowedPorts).toEqual([465, 587, 2525]);
    expect(config.smtpAllowedPrivateHosts).toEqual(["mail.internal.example"]);
    expect(config.allowPlainLocalWebhook).toBe(false);
    expect(config.webhookAllowedPorts).toEqual([443]);
    expect(config.webhookAllowedPrivateHosts).toEqual([]);
    expect(config.logLevel).toBe("error");
    expect(config.notificationKeyring.activeVersion).toBe(1);
    expect(readSecretFile).toHaveBeenCalledTimes(3);
    config.previewToken.fill(0);
    config.notificationKeyring.close();
  });

  it("allows direct secrets only outside production and keeps plaintext SMTP explicit", async () => {
    const config = await loadNotifierConfiguration({
      env: {
        PERIAPSIS_ENV: "development",
        OTEL_SDK_DISABLED: "true",
        PERIAPSIS_DATABASE_URL:
          "postgresql://notifier:local@127.0.0.1/periapsis",
        PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
        NOTIFICATION_KEYRING_FILE: "/run/secrets/notification-keyring",
        PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL: "true",
        PERIAPSIS_SMTP_ALLOWED_PORTS: "1025",
        PERIAPSIS_SMTP_ALLOWED_PRIVATE_HOSTS: "127.0.0.1",
        PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL: "true",
        PERIAPSIS_WEBHOOK_ALLOWED_PORTS: "8080",
        PERIAPSIS_WEBHOOK_ALLOWED_PRIVATE_HOSTS: "127.0.0.1",
      },
      readSecretFile: async () => new TextEncoder().encode(keyringDocument),
    });
    expect(config.allowPlainLocalSmtp).toBe(true);
    expect(config.allowPlainLocalWebhook).toBe(true);
    expect(config.webhookAllowedPorts).toEqual([8080]);
    expect(config.webhookAllowedPrivateHosts).toEqual(["127.0.0.1"]);
    expect(config.listen).toEqual({ host: "0.0.0.0", port: 8083 });
    config.previewToken.fill(0);
    config.notificationKeyring.close();

    await expect(
      loadNotifierConfiguration({
        env: {
          PERIAPSIS_ENV: "production",
          OTEL_SDK_DISABLED: "true",
          PERIAPSIS_DATABASE_URL:
            "postgresql://notifier:secret@postgres/periapsis",
          PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
        },
      }),
    ).rejects.toThrow(NotificationValidationError);
    await expect(
      loadNotifierConfiguration({
        env: {
          PERIAPSIS_ENV: "test",
          OTEL_SDK_DISABLED: "true",
          PERIAPSIS_DATABASE_URL:
            "postgresql://notifier:test@127.0.0.1/periapsis",
          PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
          PERIAPSIS_NOTIFIER_FANOUT_LEASE_MS: "5000",
          PERIAPSIS_NOTIFIER_FANOUT_TIMEOUT_MS: "5000",
        },
      }),
    ).rejects.toThrow(NotificationValidationError);
  });

  it("rejects the development-only webhook transport mode in production", async () => {
    await expect(
      loadNotifierConfiguration({
        env: {
          PERIAPSIS_ENV: "production",
          OTEL_SDK_DISABLED: "true",
          PERIAPSIS_DATABASE_URL_FILE: "/run/secrets/database",
          PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE: "/run/secrets/preview",
          NOTIFICATION_KEYRING_FILE: "/run/secrets/keyring",
          PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL: "true",
        },
        readSecretFile: async (path) =>
          new TextEncoder().encode(
            path.endsWith("database")
              ? "postgresql://notifier:secret@postgres/periapsis"
              : path.endsWith("preview")
                ? previewToken
                : keyringDocument,
          ),
      }),
    ).rejects.toThrow(NotificationValidationError);
  });

  it("rejects ambiguous secret sources and inconsistent lease timing", async () => {
    await expect(
      loadNotifierConfiguration({
        env: {
          PERIAPSIS_ENV: "test",
          OTEL_SDK_DISABLED: "true",
          PERIAPSIS_DATABASE_URL:
            "postgresql://notifier:test@127.0.0.1/periapsis",
          PERIAPSIS_DATABASE_URL_FILE: "database",
          PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
        },
      }),
    ).rejects.toThrow(NotificationValidationError);
    await expect(
      loadNotifierConfiguration({
        env: {
          PERIAPSIS_ENV: "test",
          OTEL_SDK_DISABLED: "true",
          PERIAPSIS_DATABASE_URL:
            "postgresql://notifier:test@127.0.0.1/periapsis",
          PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
          PERIAPSIS_NOTIFIER_LEASE_MS: "5000",
          PERIAPSIS_NOTIFIER_HEARTBEAT_MS: "2000",
        },
      }),
    ).rejects.toThrow(NotificationValidationError);
  });

  it("keeps dispatch batches and leases within the database ABI bounds", async () => {
    await Promise.all(
      [
        { PERIAPSIS_NOTIFIER_BATCH_SIZE: "101" },
        { PERIAPSIS_NOTIFIER_FANOUT_BATCH_SIZE: "101" },
        { PERIAPSIS_NOTIFIER_LEASE_MS: "300001" },
        { PERIAPSIS_NOTIFIER_FANOUT_LEASE_MS: "300001" },
      ].map((override) =>
        expect(
          loadNotifierConfiguration({
            env: {
              PERIAPSIS_ENV: "test",
              OTEL_SDK_DISABLED: "true",
              PERIAPSIS_DATABASE_URL:
                "postgresql://notifier:test@127.0.0.1/periapsis",
              PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
              NOTIFICATION_KEYRING_FILE: "/run/secrets/keyring",
              ...override,
            },
            readSecretFile: async () =>
              new TextEncoder().encode(keyringDocument),
          }),
        ).rejects.toThrow(NotificationValidationError),
      ),
    );
  });

  it("requires the exact file-backed notification keyring source", async () => {
    await expect(
      loadNotifierConfiguration({
        env: {
          PERIAPSIS_ENV: "test",
          OTEL_SDK_DISABLED: "true",
          PERIAPSIS_DATABASE_URL:
            "postgresql://notifier:test@127.0.0.1/periapsis",
          PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
          NOTIFICATION_KEYRING: keyringDocument,
        },
      }),
    ).rejects.toThrow(NotificationValidationError);

    const document = new TextEncoder().encode(keyringDocument);
    const config = await loadNotifierConfiguration({
      env: {
        PERIAPSIS_ENV: "test",
        OTEL_SDK_DISABLED: "true",
        PERIAPSIS_DATABASE_URL:
          "postgresql://notifier:test@127.0.0.1/periapsis",
        PERIAPSIS_NOTIFIER_PREVIEW_TOKEN: previewToken,
        NOTIFICATION_KEYRING_FILE: "/run/secrets/keyring",
      },
      readSecretFile: async () => document,
    });
    expect([...document]).toEqual(
      Array.from({ length: document.byteLength }, () => 0),
    );
    config.previewToken.fill(0);
    config.notificationKeyring.close();
  });

  it("clears already-loaded secret buffers when later validation fails", async () => {
    const database = new TextEncoder().encode(
      "postgresql://notifier:secret@postgres/periapsis",
    );
    const token = new TextEncoder().encode(previewToken);
    await expect(
      loadNotifierConfiguration({
        env: {
          PERIAPSIS_ENV: "production",
          OTEL_SDK_DISABLED: "true",
          PERIAPSIS_DATABASE_URL_FILE: "/run/secrets/database",
          PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE: "/run/secrets/preview",
          PERIAPSIS_NOTIFIER_LEASE_MS: "5000",
          PERIAPSIS_NOTIFIER_HEARTBEAT_MS: "2000",
          NOTIFICATION_KEYRING_FILE: "/run/secrets/keyring",
        },
        readSecretFile: async (path) =>
          path.endsWith("database") ? database : token,
      }),
    ).rejects.toThrow(NotificationValidationError);
    expect([...database]).toEqual(
      Array.from({ length: database.byteLength }, () => 0),
    );
    expect([...token]).toEqual(
      Array.from({ length: token.byteLength }, () => 0),
    );
  });
});

const previewToken = "0123456789abcdef0123456789abcdef";
const keyringDocument =
  '{"activeVersion":1,"keys":[{"version":1,"key":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY"}]}';
