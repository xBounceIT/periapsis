import { afterEach, describe, expect, it, vi } from "vitest";

import { mfaPolicyApi } from "./mfa-policy-api";

const tenantId = "019b0000-0000-7000-8000-000000000001";
const policyId = "019b0000-0000-7000-8000-000000000002";
const commandId = "019b0000-0000-7000-8000-000000000003";
const context = { action: "case.export", roleIds: [], securityGroupIds: [] };
const requirement = {
  enrollmentDeadline: null,
  freshnessSeconds: 300,
  level: "mfa" as const,
  localRequired: true,
};

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("mfaPolicyApi", () => {
  it("uses no-store and rejects list projections with missing strict fields", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({ items: [platformDocument()], nextCursor: null }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [{ ...platformDocument(), retiredAt: undefined }],
            nextCursor: null,
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              { ...platformDocument(), createdAt: "2027-02-31T12:00:00.000Z" },
            ],
            nextCursor: null,
          }),
        ),
    );

    await expect(
      mfaPolicyApi.list({ kind: "platform" }),
    ).resolves.toMatchObject({
      items: [{ id: policyId, revision: 1 }],
      nextCursor: null,
    });
    await expect(mfaPolicyApi.list({ kind: "platform" })).rejects.toMatchObject(
      {
        code: "projection_mismatch",
      },
    );
    await expect(mfaPolicyApi.list({ kind: "platform" })).rejects.toMatchObject(
      {
        code: "projection_mismatch",
      },
    );
  });

  it.each([
    {
      recovery: {
        eligibleDirectAdministrators: 2,
        readyDirectAdministrators: 1,
        reasonCodes: [],
        safe: true,
      },
      safe: true,
    },
    {
      recovery: {
        eligibleDirectAdministrators: 2,
        readyDirectAdministrators: 0,
        reasonCodes: ["no_ready_local_mfa", "no_ready_local_primary"],
        safe: false,
      },
      safe: false,
    },
  ])(
    "accepts exact DB-authoritative recovery result safe=$safe",
    async ({ recovery, safe }) => {
      const requests: Request[] = [];
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL) => {
          if (input instanceof Request) requests.push(input);
          return jsonResponse(tenantSimulation(recovery));
        }),
      );

      const result = await mfaPolicyApi.simulate(
        { kind: "tenant", tenantId },
        "csrf-memory-only-value",
        {
          context,
          expectedRevision: 0,
          operation: "publish",
          requirement,
          target: { scope: "tenant_baseline" },
        },
      );

      expect(result.recovery.safe).toBe(safe);
      const requestBody: unknown = await requests[0]?.json();
      expect(requestBody).toEqual(
        expect.objectContaining({ target: { scope: "tenant_baseline" } }),
      );
      expect(JSON.stringify(requestBody)).not.toContain("tenantId");
      expect(requests[0]?.cache).toBe("no-store");
      expect(requests[0]?.headers.get("X-CSRF-Token")).toBe(
        "csrf-memory-only-value",
      );
    },
  );

  it("rejects poisoned recovery and missing source requirements", async () => {
    const poisonedRecovery = tenantSimulation({
      eligibleDirectAdministrators: 2,
      readyDirectAdministrators: 1,
      reasonCodes: ["no_ready_local_mfa"],
      safe: false,
    });
    const missingRequirement = tenantSimulation({
      eligibleDirectAdministrators: 2,
      readyDirectAdministrators: 1,
      reasonCodes: [],
      safe: true,
    });
    const poisonedSource = missingRequirement.effective.sources[0];
    if (!poisonedSource) throw new Error("simulation fixture lost its source");
    Reflect.deleteProperty(poisonedSource, "requirement");
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(jsonResponse(poisonedRecovery))
        .mockResolvedValueOnce(jsonResponse(missingRequirement)),
    );
    const input = {
      context,
      expectedRevision: 0,
      operation: "publish" as const,
      requirement,
      target: { scope: "tenant_baseline" as const },
    };
    await expect(
      mfaPolicyApi.simulate(
        { kind: "tenant", tenantId },
        "csrf-memory-only-value",
        input,
      ),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      mfaPolicyApi.simulate(
        { kind: "tenant", tenantId },
        "csrf-memory-only-value",
        input,
      ),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a target outside the exact simulation context before fetch", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);
    await expect(
      mfaPolicyApi.simulate(
        { kind: "tenant", tenantId },
        "csrf-memory-only-value",
        {
          context,
          expectedRevision: 0,
          operation: "publish",
          requirement,
          target: {
            roleId: "019b0000-0000-7000-8000-000000000004",
            scope: "role",
          },
        },
      ),
    ).rejects.toThrow("must be present");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("binds create receipt, UUIDv7 command, ETag, and Location exactly", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse(
          { policy: platformDocument(), replayed: false },
          201,
          {
            ETag: '"v1"',
            Location: `/api/v1/platform/mfa-policies/${policyId}/revisions/1`,
          },
        );
      }),
    );

    await expect(
      mfaPolicyApi.publish(
        { kind: "platform" },
        "csrf-memory-only-value",
        commandId,
        "Publish explicit floor",
        {
          expectedRevision: 0,
          requirement,
          target: { scope: "platform_floor" },
        },
      ),
    ).resolves.toMatchObject({ etag: '"v1"', value: { replayed: false } });
    expect(requests[0]?.headers.get("Idempotency-Key")).toBe(commandId);
    expect(requests[0]?.headers.get("X-Audit-Reason")).toBe(
      "Publish explicit floor",
    );
  });

  it("does not reflect untrusted recovery-conflict detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            code: "mfa_policy_recovery_unsafe",
            detail: "token=must-not-render",
            status: 409,
            title: "Conflict",
            type: "about:blank",
          },
          409,
        ),
      ),
    );
    await expect(
      mfaPolicyApi.publish(
        { kind: "platform" },
        "csrf-memory-only-value",
        commandId,
        "Publish explicit floor",
        {
          expectedRevision: 0,
          requirement,
          target: { scope: "platform_floor" },
        },
      ),
    ).rejects.toMatchObject({
      code: "mfa_policy_recovery_unsafe",
      message:
        "Publishing this policy would leave no ready direct administrator.",
    });
  });
});

function platformDocument() {
  return {
    createdAt: "2026-08-30T12:00:00.000Z",
    id: policyId,
    requirement,
    retiredAt: null,
    revision: 1,
    status: "live",
    target: { scope: "platform_floor" },
  } as const;
}

function tenantSimulation(recovery: {
  eligibleDirectAdministrators: number;
  readyDirectAdministrators: number;
  reasonCodes: string[];
  safe: boolean;
}) {
  const target = { scope: "tenant_baseline", tenantId } as const;
  return {
    candidate: { requirement, target },
    context,
    current: null,
    effective: {
      requirement,
      sources: [{ requirement, source: "candidate", target }],
    },
    operation: "publish",
    recovery,
    target,
  };
}

function jsonResponse(
  value: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      ...extraHeaders,
    },
    status,
  });
}
