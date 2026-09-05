import { afterEach, describe, expect, it, vi } from "vitest";

import { phaseTwoApi } from "./phase-two-api";
import type {
  OperatorTeamAssignmentEpochView,
  OperatorTeamRosterEntryView,
  OperatorTeamView,
} from "./phase-two-types";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const teamId = "0198c97d-cf4f-7000-8000-000000000401";
const epochId = "0198c97d-cf4f-7000-8000-000000000402";
const rosterEntryId = "0198c97d-cf4f-7000-8000-000000000403";
const membershipId = "0198c97d-cf4f-7000-8000-000000000404";
const edgeEtag = '"v3-n4bQgYhMfWWaL-qgxVrQFaO_T_ZiMsT94ORZLlH_wZA"';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("phaseTwoApi operator-team contracts", () => {
  it("carries payload idempotency and strong ETags through every platform mutation", async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const request = asRequest(input);
      requests.push(request);
      if (request.method === "POST")
        return jsonResponse(teamFixture(), '"v2"', 201);
      if (request.method === "PATCH") {
        return jsonResponse(
          { ...teamFixture(), name: "SOC L2", version: 3 },
          '"v3"',
        );
      }
      if (request.method === "DELETE")
        return new Response(null, { status: 204 });
      if (request.url.endsWith(`/${teamId}`))
        return jsonResponse(teamFixture(), '"v2"');
      return jsonResponse({ items: [teamFixture()] });
    });
    vi.stubGlobal("fetch", fetchMock);

    await phaseTwoApi.listPlatformOperatorTeams({ includeArchived: true });
    await phaseTwoApi.getPlatformOperatorTeam(teamId);
    await phaseTwoApi.createPlatformOperatorTeam("csrf-value", "create-key", {
      key: "soc_l1",
      name: "SOC L1",
    });
    await phaseTwoApi.updatePlatformOperatorTeam("csrf-value", teamId, '"v2"', {
      name: "SOC L2",
    });
    await phaseTwoApi.archivePlatformOperatorTeam(
      "csrf-value",
      teamId,
      '"v3"',
      {
        reason: "Queue retired",
      },
    );

    expect(requests).toHaveLength(5);
    expect(requests[0]?.url).toContain("includeArchived=true");
    expect(requests[2]?.headers.get("Idempotency-Key")).toBe("create-key");
    expect(requests[2]?.headers.get("X-CSRF-Token")).toBe("csrf-value");
    expect(requests[3]?.headers.get("If-Match")).toBe('"v2"');
    expect(requests[4]?.headers.get("If-Match")).toBe('"v3"');
  });

  it("binds assignment and roster requests to one exact epoch", async () => {
    const requests: Request[] = [];
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const request = asRequest(input);
      requests.push(request);
      const url = new URL(request.url);
      if (url.pathname.endsWith("/end") || url.pathname.endsWith("/revoke")) {
        return new Response(null, { status: 204 });
      }
      if (url.pathname.endsWith("/roster") && request.method === "POST") {
        return jsonResponse(rosterFixture(), edgeEtag, 201);
      }
      if (url.pathname.endsWith("/roster")) {
        return jsonResponse({ items: [rosterFixture()] });
      }
      if (
        url.pathname.endsWith("/assignment-epochs") &&
        request.method === "POST"
      ) {
        return jsonResponse(epochFixture(), '"v2"', 201);
      }
      if (url.pathname.includes("/assignment-epochs/")) {
        return jsonResponse(epochFixture(), '"v2"');
      }
      return jsonResponse({ items: [epochFixture()] });
    });
    vi.stubGlobal("fetch", fetchMock);

    await phaseTwoApi.listTenantOperatorTeamAssignmentEpochs(tenantId, {
      includeEnded: true,
    });
    await phaseTwoApi.startOperatorTeamAssignmentEpoch(
      "csrf-value",
      tenantId,
      teamId,
      "epoch-key",
      { reason: "Tenant onboarding" },
    );
    await phaseTwoApi.getOperatorTeamAssignmentEpoch(tenantId, teamId, epochId);
    await phaseTwoApi.endOperatorTeamAssignmentEpoch(
      "csrf-value",
      tenantId,
      teamId,
      epochId,
      '"v2"',
      { reason: "Coverage handoff" },
    );
    await phaseTwoApi.listOperatorTeamRosterEntries(tenantId, teamId, epochId, {
      includeRevoked: true,
    });
    await phaseTwoApi.addOperatorTeamRosterEntry(
      "csrf-value",
      tenantId,
      teamId,
      epochId,
      "roster-key",
      { membershipId, reason: "On-call rotation" },
    );
    await phaseTwoApi.revokeOperatorTeamRosterEntry(
      "csrf-value",
      tenantId,
      teamId,
      epochId,
      rosterEntryId,
      edgeEtag,
      { reason: "Rotation ended" },
    );

    expect(requests).toHaveLength(7);
    for (const request of requests.slice(2)) {
      expect(request.url).toContain(
        `/operator-teams/${teamId}/assignment-epochs/${epochId}`,
      );
    }
    expect(requests[1]?.headers.get("Idempotency-Key")).toBe("epoch-key");
    expect(requests[3]?.headers.get("If-Match")).toBe('"v2"');
    expect(requests[5]?.headers.get("Idempotency-Key")).toBe("roster-key");
    expect(requests[6]?.headers.get("If-Match")).toBe(edgeEtag);
  });

  it("rejects a stale roster projection from a different assignment epoch", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...rosterFixture(),
              assignmentEpochId: "0198c97d-cf4f-7000-8000-000000000499",
            },
          ],
        }),
      ),
    );

    await expect(
      phaseTwoApi.listOperatorTeamRosterEntries(tenantId, teamId, epochId),
    ).rejects.toMatchObject({
      message:
        "The API response did not match the requested tenant projection.",
    });
  });
});

function teamFixture(): OperatorTeamView {
  return {
    activeAssignmentCount: 0,
    createdAt: "2026-08-24T08:00:00Z",
    description: "Primary triage queue",
    id: teamId,
    key: "soc_l1",
    name: "SOC L1",
    state: "active",
    updatedAt: "2026-08-24T08:00:00Z",
    version: 2,
  };
}

function epochFixture(): OperatorTeamAssignmentEpochView {
  return {
    epochId,
    operatorTeam: {
      id: teamId,
      key: "soc_l1",
      name: "SOC L1",
      state: "active",
    },
    startReason: "Tenant onboarding",
    startedAt: "2026-08-24T08:00:00Z",
    startedByUserId: "0198c97d-cf4f-7000-8000-000000000001",
    state: "active",
    tenantId,
    updatedAt: "2026-08-24T08:00:00Z",
    version: 2,
  };
}

function rosterFixture(): OperatorTeamRosterEntryView {
  return {
    assignmentEpochId: epochId,
    etag: edgeEtag,
    id: rosterEntryId,
    managedByOperatorTeamApi: true,
    member: {
      displayName: "Mira Responder",
      membershipId,
      membershipStatus: "active",
      userId: "0198c97d-cf4f-7000-8000-000000000405",
    },
    operatorTeamId: teamId,
    provenance: {
      authoritative: false,
      grantedAt: "2026-08-24T08:30:00Z",
      grantedByUserId: "0198c97d-cf4f-7000-8000-000000000001",
      reason: "On-call rotation",
      sourceId: "0198c97d-cf4f-7000-8000-000000000406",
      sourceKind: "manual",
    },
    state: "active",
    tenantId,
    updatedAt: "2026-08-24T08:30:00Z",
    version: 3,
  };
}

function jsonResponse(body: unknown, etag?: string, status = 200): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "Content-Type": "application/json",
      ...(etag ? { ETag: etag } : {}),
    },
    status,
  });
}

function asRequest(input: RequestInfo | URL): Request {
  if (!(input instanceof Request)) {
    throw new Error("The generated client did not issue a Request.");
  }
  return input;
}
