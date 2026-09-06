import { describe, expect, it, vi } from "vitest";

import {
  bindMutationAttempt,
  bindOpaqueMutationAttempt,
  forgetWriteOnlySmtp,
  forgetWriteOnlyWebhook,
  parseRecipients,
  parseSampleData,
  resetOpaqueMutationAttempt,
  type MutationAttemptReference,
  type OpaqueMutationAttemptReference,
} from "./model";
import { assertStructurallyRedacted } from "./notification-api";
import { isolateTemplatePreview } from "./templates-panel-model";

describe("notification administration model", () => {
  it("binds retry keys to ordinary payloads and keeps opaque secret retries stable", () => {
    vi.spyOn(globalThis.crypto, "randomUUID")
      .mockReturnValueOnce("00000000-0000-4000-8000-000000000001")
      .mockReturnValueOnce("00000000-0000-4000-8000-000000000002")
      .mockReturnValueOnce("00000000-0000-4000-8000-000000000003");
    const ordinary: MutationAttemptReference = { current: null };
    const opaque: OpaqueMutationAttemptReference = { current: null };
    expect(
      bindMutationAttempt(ordinary, "rule.create", "tenant-1", { name: "A" }),
    ).toBe(
      bindMutationAttempt(ordinary, "rule.create", "tenant-1", { name: "A" }),
    );
    const firstOpaque = bindOpaqueMutationAttempt(opaque);
    expect(bindOpaqueMutationAttempt(opaque)).toBe(firstOpaque);
    expect(JSON.stringify(opaque)).not.toContain("secret material");
    resetOpaqueMutationAttempt(opaque);
    expect(bindOpaqueMutationAttempt(opaque)).not.toBe(firstOpaque);
  });

  it("forgets write-only SMTP and webhook material without dropping public settings", () => {
    const smtp = forgetWriteOnlySmtp({
      name: "Relay",
      host: "smtp.example.test",
      port: 587,
      security: "starttls",
      username: "mailer",
      password: "smtp-secret",
      clearPassword: false,
      fromName: "SOC",
      fromEmail: "soc@example.test",
      replyToEmail: null,
      timeoutMs: 1_000,
      maximumConnections: 1,
      maximumMessagesPerConnection: 10,
      rateLimitPerSecond: 1,
      dkim: {
        domainName: "example.test",
        selector: "mail",
        privateKey: "private-key",
      },
      clearDkim: false,
      enabled: true,
    });
    expect(smtp).not.toHaveProperty("password");
    expect(smtp.dkim).not.toHaveProperty("privateKey");
    expect(smtp.host).toBe("smtp.example.test");
    expect(
      forgetWriteOnlyWebhook({
        name: "Hook",
        endpointUrl: "https://example.test/hook",
        eventTypes: ["alert.created"],
        audience: "operator",
        signingKey: "signing-secret",
        timeoutMs: 1_000,
        enabled: true,
      }),
    ).not.toHaveProperty("signingKey");
  });

  it("rejects unsafe or unbounded sample JSON and secret-bearing response shapes", () => {
    expect(() => parseSampleData('{"__proto__":{"polluted":true}}')).toThrow(
      /unsafe key/u,
    );
    expect(() =>
      parseSampleData(
        `{"items":[${Array.from({ length: 101 }, () => "1").join(",")}]}`,
      ),
    ).toThrow(/too large/u);
    expect(() =>
      assertStructurallyRedacted({ id: "delivery-1", password: "leaked" }),
    ).toThrow(/safe to display/u);
    expect(() =>
      assertStructurallyRedacted({
        attempts: [{ providerReceipt: { receiptDigest: "safe" } }],
      }),
    ).not.toThrow();
  });

  it("isolates HTML previews with a network-denying CSP", () => {
    const isolated = isolateTemplatePreview(
      '<html><head><title>Preview</title></head><body><img src="https://tracker.test/pixel"></body></html>',
    );
    expect(isolated).toContain("default-src 'none'");
    expect(isolated.indexOf("Content-Security-Policy")).toBeLessThan(
      isolated.indexOf("<title>"),
    );
  });

  it("keeps recipient selector audiences and value controls closed by kind", () => {
    expect(
      parseRecipients(
        JSON.stringify([
          { kind: "mentioned", audience: "operator" },
          { kind: "operator_team", audience: "operator", value: "team-id" },
          { kind: "contact_tag", audience: "customer", value: "on-call" },
          { kind: "actor", audience: "customer" },
          {
            kind: "explicit_email",
            audience: "operator",
            value: "soc@example.test",
            authorized: true,
          },
        ]),
      ),
    ).toHaveLength(5);

    for (const invalid of [
      { kind: "mentioned", audience: "customer" },
      { kind: "watcher", audience: "operator", value: "unexpected" },
      { kind: "operator_team", audience: "customer", value: "team-id" },
      { kind: "contact_group", audience: "customer" },
      { kind: "customer_contacts", audience: "customer", authorized: false },
      {
        kind: "explicit_email",
        audience: "operator",
        value: "soc@example.test",
      },
      {
        kind: "explicit_email",
        audience: "operator",
        value: "not-an-email",
        authorized: true,
      },
      {
        kind: "custom_email_field",
        audience: "customer",
        value: "contact.email",
        authorized: true,
      },
    ]) {
      expect(() => parseRecipients(JSON.stringify([invalid]))).toThrow(
        /invalid/u,
      );
    }
  });
});
