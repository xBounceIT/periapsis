import { beforeEach, describe, expect, it, vi } from "vitest";

import { createDeliveryClaim, type DeliveryClaim } from "./delivery.js";
import { PostgresNotificationRepository } from "./postgres-repository.js";
import { createFanoutClaim } from "./fanout.js";
import { createNotificationRule } from "./rule.js";
import {
  expectedMigrationFingerprint,
  expectedNotificationDispatchReadinessV62SourceHash,
  expectedPrivateReleaseRuntimeDependencySurfaceHashV62SourceHash,
  expectedPrivateReleaseRuntimeReadinessV62SourceHash,
  expectedReleaseRuntimeReadinessV62SourceHash,
  expectedSchemaCompatibilityV62SourceHash,
} from "./schema-compatibility.gen.js";
import { baseRule, id } from "./test/fixtures.js";

type QueryOutcome =
  | { readonly rows: readonly Record<string, unknown>[] }
  | { readonly code: string }
  | { readonly pending: true };

const database = vi.hoisted(() => ({
  cancellations: 0,
  outcomes: [] as QueryOutcome[],
  parameters: [] as (readonly unknown[])[],
  statements: [] as string[],
}));

vi.mock("postgres", () => ({
  default: vi.fn(() => {
    const unsafe = (statement: string, parameters: readonly unknown[]) => {
      database.statements.push(statement.replaceAll(/\s+/gu, " "));
      database.parameters.push(parameters);
      const outcome = database.outcomes.shift();
      if (outcome === undefined) throw new Error("unexpected database query");
      if ("pending" in outcome) {
        let rejectQuery: ((reason: unknown) => void) | undefined;
        const operation = new Promise<never>((_resolve, reject) => {
          rejectQuery = reject;
        });
        return Object.assign(operation, {
          cancel: vi.fn(() => {
            database.cancellations += 1;
            rejectQuery?.(new Error("database query cancelled"));
          }),
        });
      }
      const operation =
        "code" in outcome
          ? Promise.reject(
              Object.assign(new Error("database detail is redacted"), {
                code: outcome.code,
              }),
            )
          : Promise.resolve(outcome.rows);
      return Object.assign(operation, { cancel: vi.fn() });
    };
    const client = vi.fn();
    return Object.assign(client, {
      end: vi.fn(async () => undefined),
      options: { parsers: {}, serializers: {} },
      unsafe,
    });
  }),
}));

describe("PostgreSQL notification rolling compatibility", () => {
  beforeEach(() => {
    database.cancellations = 0;
    database.outcomes.length = 0;
    database.parameters.length = 0;
    database.statements.length = 0;
  });

  it.each([
    [{ mode: "none", windowMs: 0, maximumItems: 1 }, true],
    [{ mode: "none" }, true],
    [{ mode: "none", windowMs: 1000, maximumItems: 1 }, false],
    [{ mode: "none", windowMs: 0, maximumItems: 2 }, false],
  ])(
    "decodes persisted ungrouped policies without permitting a window: %j",
    async (grouping, valid) => {
      const repository = createRepository();
      const claim = createFanoutClaim({
        id: id(1),
        tenantId: id(2),
        attempt: 1,
        maximumAttempts: 3,
        fenceToken: id(3),
        leaseUntil: new Date("2026-09-08T00:01:00Z"),
        event: {
          id: id(1),
          tenantId: id(2),
          type: "sla.warning",
          objectType: "alert",
          objectId: id(4),
          objectVersion: 1,
          occurredAt: new Date("2026-09-08T00:00:00Z"),
          actorKind: "system",
          source: "sla-action",
          maximumAudience: "operator",
          context: {},
        },
      });
      database.outcomes.push({
        rows: [
          {
            value: {
              rules: [JSON.parse(JSON.stringify({ ...baseRule(), grouping }))],
              candidates: [],
              templates: [],
              smtpConfiguration: null,
            },
          },
        ],
      });
      try {
        const result = repository.loadFanoutInputs(
          claim,
          new AbortController().signal,
        );
        if (valid) {
          const inputs = await result;
          expect(createNotificationRule(inputs.rules[0]!).grouping).toEqual({
            mode: "none",
            windowMs: 0,
            maximumItems: 1,
          });
        } else {
          await expect(result).rejects.toThrow("invalid ungrouped policy");
        }
      } finally {
        await repository.close();
      }
    },
  );

  it("encodes claim timestamps for Drizzle's pass-through postgres-js serializers", async () => {
    const repository = createRepository();
    const now = new Date("2026-09-07T12:34:56.789Z");
    const input = {
      workerId: id(1),
      limit: 4,
      leaseDurationMs: 30_000,
      now,
      signal: new AbortController().signal,
    };
    database.outcomes.push({ rows: [] }, { rows: [] }, { rows: [] });
    await repository.claimFanoutBatch(input);
    await repository.claimBatch(input);
    await repository.claimWebhookBatch(input);
    expect(database.parameters).toHaveLength(3);
    for (const parameters of database.parameters) {
      expect(parameters.at(-1)).toBe("2026-09-07T12:34:56.789Z");
      expect(parameters.some((value) => value instanceof Date)).toBe(false);
    }
    await expect(
      repository.claimBatch({ ...input, now: new Date(Number.NaN) }),
    ).rejects.toMatchObject({ code: "notification_validation_failed" });
    expect(database.parameters).toHaveLength(3);
    await repository.close();
  });

  it("falls back from the SMTP pin, readiness, and completion successors only on undefined_function", async () => {
    const repository = createRepository();
    database.outcomes.push(
      { code: "42883" },
      { rows: [smtpConfigurationRow()] },
      { rows: [{ available: false }] },
      {
        rows: [
          {
            queue_depth: 3,
            role_safe: true,
            schema_safe: true,
            source_safe: true,
            oldest_pending_seconds: 4,
          },
        ],
      },
      { code: "42883" },
      { rows: [] },
    );
    const signal = new AbortController().signal;

    await expect(
      repository.loadPinnedForProbe(
        id(2),
        { scope: "tenant", id: id(930), version: 5 },
        signal,
      ),
    ).resolves.toMatchObject({
      id: id(930),
      tenantId: id(2),
      version: 5,
      enabled: true,
    });
    await expect(repository.readiness(signal)).resolves.toEqual({
      queueDepth: 3,
      oldestPendingSeconds: 4,
    });
    await expect(
      repository.complete(
        deliveryClaim(),
        {
          provider: "smtp",
          receiptDigest: "a".repeat(64),
          acceptedCount: 1,
          rejectedCount: 0,
          responseClass: 2,
        },
        new Date("2026-09-01T00:00:00.000Z"),
        signal,
      ),
    ).resolves.toBeUndefined();

    expect(database.statements).toHaveLength(6);
    expect(database.statements[0]).toContain(
      "app.load_pinned_smtp_configuration_v2",
    );
    expect(database.statements[1]).toContain(
      "app.load_pinned_smtp_configuration_v1",
    );
    expect(database.statements[2]).toContain("pg_catalog.to_regprocedure");
    expect(database.statements[3]).toContain(
      "app.notification_dispatch_readiness_v4",
    );
    expect(database.statements[4]).toContain(
      "app.complete_notification_delivery_v3",
    );
    expect(database.statements[5]).toContain(
      "app.complete_notification_delivery_v2",
    );
    expect(database.parameters[0]).toEqual([id(2), "tenant", id(930), 5]);
  });

  it("keeps the platform-admin probe closed while only the tenant-taking V1 loader exists", async () => {
    const repository = createRepository();
    database.outcomes.push({ code: "42883" });

    await expect(
      repository.loadPinnedForProbe(
        undefined,
        { scope: "platform", id: id(930), version: 5 },
        new AbortController().signal,
      ),
    ).rejects.toMatchObject({ code: "42883" });
    expect(database.statements).toHaveLength(1);
    expect(database.statements[0]).toContain(
      "app.load_pinned_smtp_configuration_v2",
    );
  });

  it("does not downgrade on authorization or data failures", async () => {
    const repository = createRepository();
    database.outcomes.push({ code: "42501" });

    await expect(
      repository.loadPinnedForProbe(
        id(2),
        { scope: "tenant", id: id(930), version: 5 },
        new AbortController().signal,
      ),
    ).rejects.toThrow();
    expect(database.statements).toHaveLength(1);
  });

  it("binds current V62 readiness to all five generated source pins and the exact journal", async () => {
    const repository = createRepository();
    database.outcomes.push(
      { rows: [{ available: true }] },
      {
        rows: [
          {
            queue_depth: 3,
            role_safe: true,
            schema_safe: true,
            source_safe: true,
            oldest_pending_seconds: 4,
          },
        ],
      },
    );

    await expect(
      repository.readiness(new AbortController().signal),
    ).resolves.toEqual({ queueDepth: 3, oldestPendingSeconds: 4 });

    expect(database.statements).toHaveLength(2);
    expect(database.statements[0]).toContain(
      "'app.notification_dispatch_readiness_v62()'",
    );
    expect(database.statements[1]).toContain(
      "FROM app.notification_dispatch_readiness_v62()",
    );
    expect(database.statements[1]).toContain("count(function_oid)=5");
    expect(database.statements[1]).not.toContain("_v49()");
    expect(database.statements[1]).not.toContain("_v50()");
    expect(database.statements[1]).not.toContain("_v51()");
    expect(database.statements[1]).not.toContain(
      "FROM app.notification_dispatch_readiness_v4()",
    );
    expect(database.parameters[1]).toEqual([
      expectedSchemaCompatibilityV62SourceHash,
      `app.schema_compatibility_fingerprint=${expectedMigrationFingerprint}`,
      expectedPrivateReleaseRuntimeDependencySurfaceHashV62SourceHash,
      expectedPrivateReleaseRuntimeReadinessV62SourceHash,
      expectedReleaseRuntimeReadinessV62SourceHash,
      expectedNotificationDispatchReadinessV62SourceHash,
    ]);
  });

  it("does not downgrade V62 readiness on authorization failures", async () => {
    const repository = createRepository();
    database.outcomes.push({ rows: [{ available: true }] }, { code: "42501" });

    await expect(
      repository.readiness(new AbortController().signal),
    ).rejects.toMatchObject({ code: "notification_configuration_failed" });
    expect(database.statements).toHaveLength(2);
    expect(database.statements[1]).toContain(
      "app.notification_dispatch_readiness_v62",
    );
  });

  it("does not downgrade when a present V62 root raises undefined_function", async () => {
    const repository = createRepository();
    database.outcomes.push({ rows: [{ available: true }] }, { code: "42883" });

    await expect(
      repository.readiness(new AbortController().signal),
    ).rejects.toMatchObject({ code: "notification_configuration_failed" });
    expect(database.statements).toHaveLength(2);
    expect(database.statements[0]).toContain("pg_catalog.to_regprocedure");
    expect(database.statements[1]).toContain(
      "app.notification_dispatch_readiness_v62",
    );
    expect(database.statements[1]).not.toContain(
      "FROM app.notification_dispatch_readiness_v4()",
    );
  });

  it("fails closed without a V4 downgrade when the V62 source chain drifts", async () => {
    const repository = createRepository();
    database.outcomes.push({
      rows: [{ available: true }],
    });
    database.outcomes.push({
      rows: [
        {
          queue_depth: 0,
          role_safe: true,
          schema_safe: true,
          source_safe: false,
          oldest_pending_seconds: 0,
        },
      ],
    });

    await expect(
      repository.readiness(new AbortController().signal),
    ).rejects.toMatchObject({ code: "notification_configuration_failed" });
    expect(database.statements).toHaveLength(2);
    expect(database.statements[1]).toContain(
      "app.notification_dispatch_readiness_v62",
    );
    expect(database.statements[1]).toContain("pg_catalog.to_regprocedure");
    expect(database.statements[1]).toContain("function_row.prosrc");
  });

  it("retains protocol-level cancellation around Drizzle-compiled queries", async () => {
    const repository = createRepository();
    const controller = new AbortController();
    const reason = new Error("test cancellation");
    database.outcomes.push({ rows: [{ available: true }] }, { pending: true });

    const readiness = repository.readiness(controller.signal);
    await vi.waitFor(() => expect(database.statements).toHaveLength(2));
    controller.abort(reason);

    await expect(readiness).rejects.toBe(reason);
    expect(database.cancellations).toBe(1);
    expect(database.statements[1]).toContain(
      "app.notification_dispatch_readiness_v62",
    );
  });

  it("rejects a nullable secret projection with residual envelope material", async () => {
    const repository = createRepository();
    database.outcomes.push({
      rows: [
        { ...smtpConfigurationRow(), password_ciphertext: new Uint8Array(17) },
      ],
    });

    await expect(
      repository.loadPinnedForProbe(
        id(2),
        { scope: "tenant", id: id(930), version: 5 },
        new AbortController().signal,
      ),
    ).rejects.toThrow();
  });
});

function createRepository(): PostgresNotificationRepository {
  return new PostgresNotificationRepository({
    databaseUrl: "postgresql://notifier:unused@database.invalid/periapsis",
    allowPlainLocalSmtp: true,
  });
}

function smtpConfigurationRow(): Record<string, unknown> {
  return {
    configuration_scope: "tenant",
    tenant_id: id(2),
    configuration_id: id(930),
    configuration_version: 5,
    name: "Rolling SMTP",
    host: "127.0.0.1",
    port: 1025,
    security: "plain_local",
    username: null,
    from_name: "Periapsis",
    from_email: "notifications@example.invalid",
    reply_to_email: null,
    timeout_ms: 5_000,
    maximum_connections: 1,
    maximum_messages_per_connection: 10,
    rate_limit_per_second: 2,
    enabled: true,
    password_secret_id: null,
    password_secret_version: null,
    password_secret_kind: null,
    password_key_version: null,
    password_nonce: null,
    password_ciphertext: null,
    dkim_domain_name: null,
    dkim_selector: null,
    dkim_secret_id: null,
    dkim_secret_version: null,
    dkim_secret_kind: null,
    dkim_key_version: null,
    dkim_nonce: null,
    dkim_ciphertext: null,
  };
}

function deliveryClaim(): DeliveryClaim {
  return createDeliveryClaim({
    id: id(931),
    tenantId: id(2),
    eventId: id(933),
    ruleId: id(934),
    ruleVersion: 1,
    smtpConfigurationScope: "tenant",
    smtpConfigurationId: id(930),
    smtpConfigurationVersion: 5,
    deduplicationKey: "b".repeat(64),
    recipient: "recipient@example.invalid",
    audience: "operator",
    context: {},
    template: {
      id: id(935),
      tenantId: id(2),
      key: "rolling_test",
      name: "Rolling test",
      language: "en",
      version: 1,
      subject: "Rolling test",
      html: "<p>Rolling test</p>",
      plainText: "Rolling test",
    },
    retry: {
      maximumAttempts: 3,
      initialDelayMs: 1_000,
      maximumDelayMs: 30_000,
      multiplier: 2,
      jitterPercent: 10,
    },
    attempt: 1,
    fenceToken: id(932),
    leaseUntil: new Date("2026-09-01T00:01:00.000Z"),
  });
}
