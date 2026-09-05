import { describe, expect, it } from "vitest";

import {
  prepareWebhookUrlPolicyRules,
  previewWebhookUrlPolicy,
  webhookUrlPolicyDraft,
  type WebhookUrlPolicyRuleDraft,
} from "./webhook-url-policy-model";

const rules: WebhookUrlPolicyRuleDraft[] = [
  {
    effect: "allow",
    match: "subdomains",
    hostname: "example.test",
    port: "443",
  },
  {
    effect: "deny",
    match: "exact",
    hostname: "blocked.example.test",
    port: "443",
  },
  {
    effect: "allow",
    match: "exact",
    hostname: "hooks.example.test",
    port: "8443",
  },
];

describe("webhook URL policy model", () => {
  it("previews deny precedence, strict subdomains, ports, and default deny", () => {
    expect(
      previewWebhookUrlPolicy(rules, "https://blocked.example.test/"),
    ).toMatchObject({ allowed: false, reason: "denied_by_rule", ruleIndex: 1 });
    expect(
      previewWebhookUrlPolicy(rules, "https://child.example.test/path?a=b"),
    ).toMatchObject({ allowed: true, reason: "allowed_by_rule", ruleIndex: 0 });
    expect(
      previewWebhookUrlPolicy(rules, "https://example.test/"),
    ).toMatchObject({ allowed: false, reason: "default_deny" });
    expect(
      previewWebhookUrlPolicy(rules, "https://hooks.example.test:8443/"),
    ).toMatchObject({ allowed: true, reason: "allowed_by_rule", ruleIndex: 2 });
    expect(
      previewWebhookUrlPolicy(rules, "https://unknown.invalid/"),
    ).toMatchObject({ allowed: false, reason: "default_deny" });
  });

  it("fails closed for local, IP, encoded, malformed, and incomplete inputs", () => {
    for (const endpoint of [
      "http://localhost:8080/",
      "https://127.0.0.1/",
      "https://hooks.example.test/%2e%2e/secret",
      "https://hooks.example.test/./secret",
      "https://hooks.example.test/a/../secret",
      " https://hooks.example.test/",
      "https://hooks.example.test/#fragment",
      "https://user@hooks.example.test/",
    ]) {
      expect(previewWebhookUrlPolicy(rules, endpoint)).toEqual({
        allowed: false,
        reason: "invalid",
      });
    }
    expect(
      previewWebhookUrlPolicy(
        [{ ...rules[0]!, hostname: "", port: "443" }],
        "https://child.example.test/",
      ),
    ).toEqual({ allowed: false, reason: "invalid" });
  });

  it("preserves edit projections and rejects duplicate or out-of-range rule drafts", () => {
    expect(
      webhookUrlPolicyDraft({
        id: "01991c20-7d5f-7000-8000-000000000060",
        versionId: "01991c20-7d5f-7000-8000-000000000061",
        tenantId: "01991c20-7d5f-7000-8000-000000000001",
        version: 1,
        scheme: "https",
        defaultAction: "deny",
        rules: [
          {
            effect: "allow",
            match: "exact",
            hostname: "hooks.example.test",
            port: 443,
          },
        ],
        publishedByMembershipId: "01991c20-7d5f-7000-8000-000000000062",
        publishedAt: "2026-09-03T10:00:00.000Z",
      }),
    ).toEqual([
      {
        effect: "allow",
        match: "exact",
        hostname: "hooks.example.test",
        port: "443",
      },
    ]);
    expect(() => prepareWebhookUrlPolicyRules([rules[0]!, rules[0]!])).toThrow(
      "unique",
    );
    expect(() =>
      prepareWebhookUrlPolicyRules([{ ...rules[0]!, port: "65536" }]),
    ).toThrow("complete");
  });
});
