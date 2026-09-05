import { Socket } from "node:net";

import { describe, expect, it, vi } from "vitest";

import {
  DeliveryProviderError,
  NotificationValidationError,
} from "./errors.js";
import { PolicyTcpSocketConnector } from "./smtp-egress.js";
import { id } from "./test/fixtures.js";
import {
  canonicalWebhookEndpoint,
  createWebhookConfigurationPolicyPin,
  createWebhookDeliveryPolicyPin,
  createWebhookLocalDevelopmentPin,
  createWebhookUrlPolicyVersion,
  evaluateWebhookUrlPolicy,
  LiveWebhookUrlPolicyGate,
  planWebhookUrlPolicyCreation,
  planWebhookUrlPolicyReplacement,
  WebhookUrlPolicyEnforcementError,
  type LiveWebhookUrlPolicySource,
  type WebhookPolicyTcpConnector,
  type WebhookUrlPolicyRuleInput,
  type WebhookUrlPolicyVersion,
} from "./webhook-url-policy.js";

const publishedAt = new Date("2026-09-03T10:00:00.000Z");

describe("webhook URL policy", () => {
  it("publishes cross-runtime golden digests for the v1 canonical ABI", () => {
    const golden = createWebhookUrlPolicyVersion({
      id: id(101),
      versionId: id(102),
      tenantId: id(103),
      version: 7,
      rules: [
        {
          effect: "deny",
          match: "subdomains",
          hostname: "EXAMPLE.com",
          port: 8443,
        },
        {
          effect: "allow",
          match: "exact",
          hostname: "BÜCHER.Example",
        },
      ],
      publishedByMembershipId: id(104),
      publishedAt,
    });

    expect({
      semanticDigest: golden.semanticDigest,
      versionDigest: golden.digest,
      ruleDigests: golden.rules.map((rule) => rule.digest),
      defaultPortEndpointDigest: canonicalWebhookEndpoint(
        "HTTPS://BÜCHER.Example:443/hook?mode=alert",
      ).digest,
      nonDefaultPortEndpointDigest: canonicalWebhookEndpoint(
        "https://BÜCHER.Example:8443/hook?mode=alert",
      ).digest,
    }).toEqual({
      semanticDigest:
        "631a59fd46573840e7983d766c47f351e0de5cc9adc10000051a9cf929d5c0c7",
      versionDigest:
        "528df0fcdf6344273fec78a1d8462d5df471cad0bc7520a5e07f4d9181da9d5c",
      ruleDigests: [
        "73bb7cccfe289491dd46280f555ab2d141604a43c7ad6fc69d2239a12d47e3df",
        "7fc135421d7cae719a12ba544ded088eb2635213ebc5372eb27c8a58be8bd5bb",
      ],
      defaultPortEndpointDigest:
        "2196681bacef4a3a792566dd0213a7337dd63cd93e7c4031d1b954d45bbb3b7c",
      nonDefaultPortEndpointDigest:
        "81c3853826acdde5d51307e419018ecdd2b84c0f1977335d4e40ce198a120117",
    });
  });

  it("builds canonical immutable versions and deterministic digests", () => {
    const rules: readonly WebhookUrlPolicyRuleInput[] = [
      {
        effect: "allow",
        match: "subdomains",
        hostname: "Example.COM",
      },
      {
        effect: "deny",
        match: "exact",
        hostname: "Admin.Example.com",
      },
      {
        effect: "allow",
        match: "exact",
        hostname: "BÜCHER.Example",
        port: 8443,
      },
    ];
    const first = policy({ rules });
    const same = policy({ rules: rules.toReversed() });

    expect(first).toMatchObject({
      scheme: "https",
      defaultAction: "deny",
      version: 1,
    });
    expect(first.rules.map((rule) => rule.hostname)).toContain(
      "xn--bcher-kva.example",
    );
    expect(first.semanticDigest).toBe(same.semanticDigest);
    expect(first.digest).toBe(same.digest);
    expect(first.digest).toMatch(/^[0-9a-f]{64}$/u);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(first.rules)).toBe(true);
    expect(first.rules.every(Object.isFrozen)).toBe(true);
    expect(Reflect.set(first.rules[0]!, "hostname", "attacker.example")).toBe(
      false,
    );
    expect(first.rules[0]!.hostname).not.toBe("attacker.example");
  });

  it("plans append-only replacements with CAS and semantic no-change checks", () => {
    const creation = planWebhookUrlPolicyCreation({
      id: id(1),
      versionId: id(2),
      tenantId: id(3),
      rules: [{ effect: "allow", match: "exact", hostname: "hooks.example" }],
      publishedByMembershipId: id(4),
      publishedAt,
    });
    expect(creation.expectedVersion).toBe(0);
    expect(creation.next.version).toBe(1);

    const replacement = planWebhookUrlPolicyReplacement(creation.next, {
      expectedVersion: 1,
      versionId: id(5),
      rules: [
        { effect: "allow", match: "subdomains", hostname: "hooks.example" },
      ],
      publishedByMembershipId: id(4),
      publishedAt: new Date(publishedAt.getTime() + 1),
    });
    expect(replacement).toMatchObject({ expectedVersion: 1 });
    expect(replacement.next).toMatchObject({
      id: creation.next.id,
      tenantId: creation.next.tenantId,
      version: 2,
    });
    expect(replacement.next.versionId).not.toBe(creation.next.versionId);

    expect(() =>
      planWebhookUrlPolicyReplacement(creation.next, {
        expectedVersion: 2,
        versionId: id(6),
        rules: replacement.next.rules,
        publishedByMembershipId: id(4),
        publishedAt,
      }),
    ).toThrow(/revision conflict/u);
    expect(() =>
      planWebhookUrlPolicyReplacement(creation.next, {
        expectedVersion: 1,
        versionId: id(6),
        rules: [{ effect: "allow", match: "exact", hostname: "HOOKS.EXAMPLE" }],
        publishedByMembershipId: id(4),
        publishedAt,
      }),
    ).toThrow(/no change/u);
    expect(() =>
      planWebhookUrlPolicyReplacement(creation.next, {
        expectedVersion: 1,
        versionId: id(6),
        rules: replacement.next.rules,
        publishedByMembershipId: id(4),
        publishedAt: new Date(publishedAt.getTime() - 1),
      }),
    ).toThrow(NotificationValidationError);
  });

  it("rejects malformed, duplicate, local, IP, CIDR, and oversized rule sets", () => {
    const invalidRules: readonly WebhookUrlPolicyRuleInput[][] = [
      [{ effect: "allow", match: "exact", hostname: "127.0.0.1" }],
      [{ effect: "allow", match: "exact", hostname: "[2001:db8::1]" }],
      [{ effect: "allow", match: "exact", hostname: "10.0.0.0/8" }],
      [{ effect: "allow", match: "exact", hostname: "tenant.localhost" }],
      [{ effect: "allow", match: "exact", hostname: "hooks.example." }],
      [{ effect: "allow", match: "exact", hostname: "hooks%2eexample" }],
      [{ effect: "allow", match: "exact", hostname: "*.example.com" }],
      [{ effect: "allow", match: "exact", hostname: "singlelabel" }],
      [{ effect: "allow", match: "exact", hostname: "hooks.example", port: 0 }],
      [
        {
          effect: "allow",
          match: "exact",
          hostname: "hooks.example",
          port: 65_536,
        },
      ],
      [
        { effect: "allow", match: "exact", hostname: "hooks.example" },
        {
          effect: "allow",
          match: "exact",
          hostname: "HOOKS.EXAMPLE",
          port: 443,
        },
      ],
    ];
    for (const rules of invalidRules) {
      expect(() => policy({ rules })).toThrow(NotificationValidationError);
    }
    expect(() =>
      policy({
        rules: Array.from({ length: 257 }, (_, index) => ({
          effect: "allow" as const,
          match: "exact" as const,
          hostname: `hooks-${index}.example`,
        })),
      }),
    ).toThrow(NotificationValidationError);
    expect(() =>
      createWebhookUrlPolicyVersion({
        ...policyInput(),
        publishedAt: new Date("1999-12-31T23:59:59.999Z"),
      }),
    ).toThrow(NotificationValidationError);
  });

  it("canonicalizes safe HTTPS DNS endpoints and IDNA without leaking aliases", () => {
    expect(canonicalWebhookEndpoint("https://Hooks.Example")).toMatchObject({
      url: "https://hooks.example/",
      hostname: "hooks.example",
      port: 443,
    });
    expect(
      canonicalWebhookEndpoint(
        "HTTPS://BÜCHER.Example:8443/hooks/v1?event=alert",
      ),
    ).toMatchObject({
      url: "https://xn--bcher-kva.example:8443/hooks/v1?event=alert",
      hostname: "xn--bcher-kva.example",
      port: 8443,
    });
  });

  it.each([
    "http://hooks.example/",
    "https://hooks.example./",
    "https://hooks.example.:443/",
    "https://@hooks.example/",
    "https://user:password@hooks.example/",
    "https://127.0.0.1/",
    "https://127.1/",
    "https://0x7f000001/",
    "https://2130706433/",
    "https://[2001:db8::1]/",
    "https://hooks%2eexample/",
    "https://hooks.example/%2e%2e/admin",
    "https://hooks.example/a/../admin",
    "https://hooks.example\\@attacker.example/",
    "https://hooks.example/#fragment",
    "https://hooks.example:0443/",
    "https://hooks.example:/",
    "https://localhost/",
    "https://tenant.localhost/",
    " https://hooks.example/",
    "https://hooks.example/\nattacker",
    "https://hooks.\u202eexample/",
    "https://hooks.example/秘密",
  ])("rejects ambiguous or unsafe endpoint %s", (candidate) => {
    expect(() => canonicalWebhookEndpoint(candidate)).toThrow(
      NotificationValidationError,
    );
  });

  it("applies deny precedence, exact/subdomain boundaries, ports, and default deny", () => {
    const current = policy({
      rules: [
        { effect: "allow", match: "exact", hostname: "example.com" },
        { effect: "allow", match: "subdomains", hostname: "example.com" },
        {
          effect: "allow",
          match: "exact",
          hostname: "port.example.com",
          port: 8443,
        },
        { effect: "deny", match: "exact", hostname: "blocked.example.com" },
        {
          effect: "deny",
          match: "subdomains",
          hostname: "private.example.com",
        },
      ],
    });

    expect(
      evaluateWebhookUrlPolicy(current, "https://example.com/"),
    ).toMatchObject({
      allowed: true,
      reason: "allowed_by_rule",
    });
    expect(
      evaluateWebhookUrlPolicy(current, "https://child.example.com/"),
    ).toMatchObject({ allowed: true, reason: "allowed_by_rule" });
    expect(
      evaluateWebhookUrlPolicy(current, "https://blocked.example.com/"),
    ).toMatchObject({ allowed: false, reason: "denied_by_rule" });
    expect(
      evaluateWebhookUrlPolicy(current, "https://x.private.example.com/"),
    ).toMatchObject({ allowed: false, reason: "denied_by_rule" });
    expect(
      evaluateWebhookUrlPolicy(current, "https://private.example.com/"),
    ).toMatchObject({ allowed: true, reason: "allowed_by_rule" });
    expect(
      evaluateWebhookUrlPolicy(current, "https://port.example.com:8443/"),
    ).toMatchObject({ allowed: true, reason: "allowed_by_rule" });
    expect(
      evaluateWebhookUrlPolicy(current, "https://port.example.com/"),
    ).toMatchObject({ allowed: true, reason: "allowed_by_rule" });
    expect(
      evaluateWebhookUrlPolicy(current, "https://unrelated.example.net/"),
    ).toMatchObject({ allowed: false, reason: "default_deny" });

    const subdomainOnly = policy({
      rules: [
        { effect: "allow", match: "subdomains", hostname: "vendor.example" },
      ],
    });
    expect(
      evaluateWebhookUrlPolicy(subdomainOnly, "https://vendor.example/"),
    ).toMatchObject({ allowed: false, reason: "default_deny" });
    expect(
      evaluateWebhookUrlPolicy(subdomainOnly, "https://x.vendor.example/"),
    ).toMatchObject({ allowed: true });
  });

  it("produces digest-only decision evidence", () => {
    const secretEndpoint =
      "https://sensitive.example/hook?token=not-a-secret-log";
    const decision = evaluateWebhookUrlPolicy(
      policy({
        rules: [
          { effect: "allow", match: "exact", hostname: "sensitive.example" },
        ],
      }),
      secretEndpoint,
    );
    const serialized = JSON.stringify(decision);

    expect(decision).toMatchObject({
      allowed: true,
      reason: "allowed_by_rule",
    });
    expect(serialized).not.toContain("sensitive.example");
    expect(serialized).not.toContain("not-a-secret-log");
    expect(serialized).not.toContain("https://");
    expect(decision.endpointDigest).toMatch(/^[0-9a-f]{64}$/u);
    expect(decision.matchedRuleDigest).toMatch(/^[0-9a-f]{64}$/u);
  });

  it("pins the exact policy into configuration and delivery coordinates", () => {
    const current = policy();
    const configuration = configurationPin(current);
    const delivery = deliveryPin(configuration);

    expect(configuration).toMatchObject({
      policyId: current.id,
      policyVersionId: current.versionId,
      policyVersion: current.version,
      policyDigest: current.digest,
      endpointUrl: "https://hooks.example/path?tenant=opaque",
    });
    expect(delivery).toMatchObject({
      policyDigest: configuration.policyDigest,
      endpointDigest: configuration.endpointDigest,
      tenantId: configuration.tenantId,
    });
    expect(Object.isFrozen(configuration)).toBe(true);
    expect(Object.isFrozen(delivery)).toBe(true);

    expect(() =>
      createWebhookConfigurationPolicyPin(current, {
        configurationId: id(20),
        configurationVersion: 1,
        tenantId: id(999),
        endpointUrl: "https://hooks.example/",
      }),
    ).toThrow(/tenant boundary/u);
    expect(() =>
      createWebhookDeliveryPolicyPin(configuration, {
        deliveryId: id(21),
        configurationId: configuration.configurationId,
        configurationVersion: configuration.configurationVersion,
        tenantId: configuration.tenantId,
        endpointUrl: "https://attacker.example/",
      }),
    ).toThrow(/pin is invalid/u);
    expect(() =>
      createWebhookDeliveryPolicyPin(
        { ...configuration },
        {
          deliveryId: id(21),
          configurationId: configuration.configurationId,
          configurationVersion: configuration.configurationVersion,
          tenantId: configuration.tenantId,
          endpointUrl: configuration.endpointUrl,
        },
      ),
    ).toThrow(/pin is invalid/u);
  });

  it("revalidates the exact current policy at attempt and immediately before connect", async () => {
    const current = policy();
    const pin = deliveryPin(configurationPin(current));
    const phases: string[] = [];
    const source: LiveWebhookUrlPolicySource = {
      async loadCurrent(input) {
        phases.push(input.phase);
        expect(input).toMatchObject({
          tenantId: current.tenantId,
          policyId: current.id,
        });
        return current;
      },
    };
    const socket = new Socket();
    const connect = vi
      .fn<WebhookPolicyTcpConnector["connect"]>()
      .mockResolvedValue(socket);
    const gate = new LiveWebhookUrlPolicyGate(source, { connect });

    const permit = await gate.beginAttempt(pin, new AbortController().signal);
    const result = await gate.connect(permit, {
      host: "HOOKS.EXAMPLE",
      port: 443,
      timeoutMs: 5_000,
    });

    expect(phases).toEqual(["attempt", "connect"]);
    expect(permit.attemptEvidence.allowed).toBe(true);
    expect(result).toEqual({
      socket,
      connectEvidence: expect.objectContaining({ allowed: true }),
    });
    expect(connect).toHaveBeenCalledWith({
      host: "hooks.example",
      port: 443,
      timeoutMs: 5_000,
      signal: expect.any(AbortSignal),
    });
  });

  it("blocks policy drift between attempt and connect without touching the network", async () => {
    const current = policy();
    const replacement = createWebhookUrlPolicyVersion({
      ...policyInput(),
      versionId: id(31),
      version: 2,
      rules: [],
      publishedAt: new Date(publishedAt.getTime() + 1),
    });
    const pin = deliveryPin(configurationPin(current));
    let loads = 0;
    const source: LiveWebhookUrlPolicySource = {
      async loadCurrent() {
        loads += 1;
        return loads === 1 ? current : replacement;
      },
    };
    const connect = vi.fn<WebhookPolicyTcpConnector["connect"]>();
    const gate = new LiveWebhookUrlPolicyGate(source, { connect });
    const permit = await gate.beginAttempt(pin, new AbortController().signal);

    const failure = await gate
      .connect(permit, { host: "hooks.example", port: 443, timeoutMs: 5_000 })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(WebhookUrlPolicyEnforcementError);
    expect(failure).toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
      evidence: { allowed: false, reason: "policy_pin_mismatch" },
    });
    expect(connect).not.toHaveBeenCalled();
  });

  it("treats a removed current policy as a terminal pin mismatch", async () => {
    const current = policy();
    const pin = deliveryPin(configurationPin(current));
    let loads = 0;
    const connect = vi.fn<WebhookPolicyTcpConnector["connect"]>();
    const gate = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          loads += 1;
          return loads === 1 ? current : null;
        },
      },
      { connect },
    );
    const permit = await gate.beginAttempt(pin, new AbortController().signal);

    await expect(
      gate.connect(permit, {
        host: "hooks.example",
        port: 443,
        timeoutMs: 5_000,
      }),
    ).rejects.toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
      evidence: { reason: "policy_pin_mismatch" },
    });
    expect(connect).not.toHaveBeenCalled();
  });

  it("consumes permits before awaiting, preventing concurrent double-connect", async () => {
    const current = policy();
    const pin = deliveryPin(configurationPin(current));
    const source: LiveWebhookUrlPolicySource = {
      async loadCurrent() {
        return current;
      },
    };
    const connect = vi
      .fn<WebhookPolicyTcpConnector["connect"]>()
      .mockResolvedValue(new Socket());
    const gate = new LiveWebhookUrlPolicyGate(source, { connect });
    const permit = await gate.beginAttempt(pin, new AbortController().signal);

    const results = await Promise.allSettled([
      gate.connect(permit, {
        host: "hooks.example",
        port: 443,
        timeoutMs: 5_000,
      }),
      gate.connect(permit, {
        host: "hooks.example",
        port: 443,
        timeoutMs: 5_000,
      }),
    ]);

    expect(results.filter(({ status }) => status === "fulfilled")).toHaveLength(
      1,
    );
    expect(results.filter(({ status }) => status === "rejected")).toHaveLength(
      1,
    );
    expect(connect).toHaveBeenCalledTimes(1);
  });

  it("rejects target substitution and foreign or unavailable live policies with redacted errors", async () => {
    const current = policy();
    const pin = deliveryPin(configurationPin(current));
    const source = {
      loadCurrent: vi
        .fn<LiveWebhookUrlPolicySource["loadCurrent"]>()
        .mockResolvedValue(current),
    };
    const connect = vi.fn<WebhookPolicyTcpConnector["connect"]>();
    const gate = new LiveWebhookUrlPolicyGate(source, { connect });
    const targetPermit = await gate.beginAttempt(
      pin,
      new AbortController().signal,
    );
    await expect(
      gate.connect(targetPermit, {
        host: "attacker.example",
        port: 443,
        timeoutMs: 5_000,
      }),
    ).rejects.toMatchObject({
      evidence: { reason: "target_mismatch" },
    });
    expect(source.loadCurrent).toHaveBeenCalledTimes(1);
    expect(connect).not.toHaveBeenCalled();

    const rawSecret = "https://sensitive.example/?token=raw-secret";
    const unavailable = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          throw new Error(rawSecret);
        },
      },
      { connect },
    );
    const failure = await unavailable
      .beginAttempt(pin, new AbortController().signal)
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(WebhookUrlPolicyEnforcementError);
    expect(failure).toMatchObject({
      failureClass: "connectivity",
      retrySafety: "safe",
      evidence: { reason: "policy_unavailable" },
    });
    expect(String(failure)).not.toContain(rawSecret);
    if (!(failure instanceof WebhookUrlPolicyEnforcementError)) {
      throw new Error("expected a policy enforcement error");
    }
    expect(JSON.stringify(failure.evidence)).not.toContain(rawSecret);

    const foreign = policy({ tenantId: id(777) });
    const foreignGate = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          return foreign;
        },
      },
      { connect },
    );
    await expect(
      foreignGate.beginAttempt(pin, new AbortController().signal),
    ).rejects.toMatchObject({
      evidence: { reason: "policy_pin_mismatch" },
    });
  });

  it("sanitizes unexpected connector failures after successful revalidation", async () => {
    const current = policy();
    const pin = deliveryPin(configurationPin(current));
    const rawSecret = "https://sensitive.example/?token=connector-secret";
    const gate = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          return current;
        },
      },
      {
        async connect() {
          throw new Error(rawSecret);
        },
      },
    );
    const permit = await gate.beginAttempt(pin, new AbortController().signal);
    const failure = await gate
      .connect(permit, {
        host: "hooks.example",
        port: 443,
        timeoutMs: 5_000,
      })
      .catch((error: unknown) => error);

    expect(failure).toBeInstanceOf(DeliveryProviderError);
    expect(failure).toMatchObject({
      failureClass: "connectivity",
      retrySafety: "safe",
    });
    expect(String(failure)).not.toContain(rawSecret);
  });

  it("retains DNS/IP pinning and private-address rejection beneath live policy", async () => {
    const current = policy();
    const pin = deliveryPin(configurationPin(current));
    const dial = vi.fn();
    const connector = new PolicyTcpSocketConnector({
      resolver: {
        async resolve() {
          return [{ address: "169.254.169.254", family: 4 }];
        },
      },
      dialer: { connect: dial },
      policy: { allowedPorts: [443] },
    });
    const gate = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          return current;
        },
      },
      connector,
    );
    const permit = await gate.beginAttempt(pin, new AbortController().signal);

    await expect(
      gate.connect(permit, {
        host: "hooks.example",
        port: 443,
        timeoutMs: 5_000,
      }),
    ).rejects.toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
    } satisfies Partial<DeliveryProviderError>);
    expect(dial).not.toHaveBeenCalled();
  });

  it("requires a fresh pair of policy reads for every delivery attempt", async () => {
    const current = policy();
    const pin = deliveryPin(configurationPin(current));
    const loadCurrent = vi
      .fn<LiveWebhookUrlPolicySource["loadCurrent"]>()
      .mockResolvedValue(current);
    const connect = vi
      .fn<WebhookPolicyTcpConnector["connect"]>()
      .mockImplementation(async () => new Socket());
    const gate = new LiveWebhookUrlPolicyGate({ loadCurrent }, { connect });

    const runAttempt = async (): Promise<void> => {
      const permit = await gate.beginAttempt(pin, new AbortController().signal);
      await gate.connect(permit, {
        host: "hooks.example",
        port: 443,
        timeoutMs: 5_000,
      });
    };
    await runAttempt();
    await runAttempt();

    expect(loadCurrent.mock.calls.map(([input]) => input.phase)).toEqual([
      "attempt",
      "connect",
      "attempt",
      "connect",
    ]);
    expect(connect).toHaveBeenCalledTimes(2);
  });

  it("keeps the plaintext loopback exemption explicit and development-only", async () => {
    const localChecks: Array<{ tenantId: string; phase: string }> = [];
    const source = {
      loadCurrent: vi.fn<LiveWebhookUrlPolicySource["loadCurrent"]>(),
      async loadLocalDevelopmentAuthorization(input: {
        tenantId: string;
        phase: "attempt" | "connect";
      }) {
        localChecks.push({ tenantId: input.tenantId, phase: input.phase });
        return true;
      },
    };
    const socket = new Socket();
    const connect = vi
      .fn<WebhookPolicyTcpConnector["connect"]>()
      .mockResolvedValue(socket);
    const pin = createWebhookLocalDevelopmentPin(
      {
        deliveryId: id(40),
        configurationId: id(41),
        configurationVersion: 2,
        tenantId: id(42),
        endpointUrl: "http://[::1]:8080/hook",
      },
      { allowPlainLocal: true },
    );

    const productionGate = new LiveWebhookUrlPolicyGate(source, { connect });
    await expect(
      productionGate.beginAttempt(pin, new AbortController().signal),
    ).rejects.toThrow(/pin is invalid/u);
    expect(source.loadCurrent).not.toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();

    const developmentGate = new LiveWebhookUrlPolicyGate(
      source,
      { connect },
      { allowPlainLocal: true },
    );
    const permit = await developmentGate.beginAttempt(
      pin,
      new AbortController().signal,
    );
    await expect(
      developmentGate.connect(permit, {
        host: "::1",
        port: 8080,
        timeoutMs: 5_000,
      }),
    ).resolves.toEqual({
      socket,
      connectEvidence: {
        allowed: true,
        reason: "local_development_exemption",
        endpointDigest: pin.endpointDigest,
      },
    });
    expect(source.loadCurrent).not.toHaveBeenCalled();
    expect(localChecks).toEqual([
      { tenantId: id(42), phase: "attempt" },
      { tenantId: id(42), phase: "connect" },
    ]);
    expect(connect).toHaveBeenCalledWith({
      host: "::1",
      port: 8080,
      timeoutMs: 5_000,
      requireLoopbackTarget: true,
      signal: expect.any(AbortSignal),
    });
  });

  it("rejects a hostile non-loopback DNS answer for localhost", async () => {
    const dial = vi.fn();
    const connector = new PolicyTcpSocketConnector({
      resolver: {
        async resolve() {
          return [{ address: "93.184.216.34", family: 4 }];
        },
      },
      dialer: { connect: dial },
      policy: {
        allowedPorts: [8080],
        allowedPrivateHosts: ["localhost"],
      },
    });
    const pin = createWebhookLocalDevelopmentPin(
      {
        deliveryId: id(49),
        configurationId: id(50),
        configurationVersion: 1,
        tenantId: id(51),
        endpointUrl: "http://localhost:8080/hook",
      },
      { allowPlainLocal: true },
    );
    const gate = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          return null;
        },
        async loadLocalDevelopmentAuthorization() {
          return true;
        },
      },
      connector,
      { allowPlainLocal: true },
    );
    const permit = await gate.beginAttempt(pin, new AbortController().signal);

    await expect(
      gate.connect(permit, {
        host: "localhost",
        port: 8080,
        timeoutMs: 5_000,
      }),
    ).rejects.toMatchObject({
      failureClass: "security",
      retrySafety: "terminal",
    } satisfies Partial<DeliveryProviderError>);
    expect(dial).not.toHaveBeenCalled();
  });

  it("revalidates the durable localhost opt-in and sanitizes dependency failures", async () => {
    const pin = createWebhookLocalDevelopmentPin(
      {
        deliveryId: id(46),
        configurationId: id(47),
        configurationVersion: 1,
        tenantId: id(48),
        endpointUrl: "http://localhost:8080/",
      },
      { allowPlainLocal: true },
    );
    const connect = vi.fn<WebhookPolicyTcpConnector["connect"]>();
    const disabled = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          return null;
        },
        async loadLocalDevelopmentAuthorization() {
          return false;
        },
      },
      { connect },
      { allowPlainLocal: true },
    );
    await expect(
      disabled.beginAttempt(pin, new AbortController().signal),
    ).rejects.toThrow(/pin is invalid/u);

    const unavailable = new LiveWebhookUrlPolicyGate(
      {
        async loadCurrent() {
          return null;
        },
        async loadLocalDevelopmentAuthorization() {
          throw new Error("sensitive database detail");
        },
      },
      { connect },
      { allowPlainLocal: true },
    );
    const failure = await unavailable
      .beginAttempt(pin, new AbortController().signal)
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(DeliveryProviderError);
    expect(failure).toMatchObject({
      failureClass: "connectivity",
      retrySafety: "safe",
    });
    expect(String(failure)).not.toContain("sensitive database detail");
    expect(connect).not.toHaveBeenCalled();
  });

  it("rejects forged or non-loopback plaintext exemptions", () => {
    expect(() =>
      createWebhookLocalDevelopmentPin(
        {
          deliveryId: id(43),
          configurationId: id(44),
          configurationVersion: 1,
          tenantId: id(45),
          endpointUrl: "http://localhost:8080/",
        },
        { allowPlainLocal: false },
      ),
    ).toThrow(/pin is invalid/u);
    expect(() =>
      createWebhookLocalDevelopmentPin(
        {
          deliveryId: id(43),
          configurationId: id(44),
          configurationVersion: 1,
          tenantId: id(45),
          endpointUrl: "http://internal.example:8080/",
        },
        { allowPlainLocal: true },
      ),
    ).toThrow(/endpoint URL is invalid/u);
  });
});

function policy(
  overrides: Partial<{
    tenantId: string;
    rules: readonly WebhookUrlPolicyRuleInput[];
  }> = {},
): WebhookUrlPolicyVersion {
  return createWebhookUrlPolicyVersion({
    ...policyInput(),
    ...overrides,
  });
}

function policyInput() {
  return {
    id: id(10),
    versionId: id(11),
    tenantId: id(12),
    version: 1,
    rules: [
      { effect: "allow", match: "exact", hostname: "hooks.example" },
    ] satisfies readonly WebhookUrlPolicyRuleInput[],
    publishedByMembershipId: id(13),
    publishedAt,
  };
}

function configurationPin(current: WebhookUrlPolicyVersion) {
  return createWebhookConfigurationPolicyPin(current, {
    configurationId: id(20),
    configurationVersion: 4,
    tenantId: current.tenantId,
    endpointUrl: "https://hooks.example/path?tenant=opaque",
  });
}

function deliveryPin(configuration: ReturnType<typeof configurationPin>) {
  return createWebhookDeliveryPolicyPin(configuration, {
    deliveryId: id(21),
    configurationId: configuration.configurationId,
    configurationVersion: configuration.configurationVersion,
    tenantId: configuration.tenantId,
    endpointUrl: configuration.endpointUrl,
  });
}
