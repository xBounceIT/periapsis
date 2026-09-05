import { expect, test, type Page, type Route } from "@playwright/test";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const alertId = "0198c97d-cf4f-7000-8000-000000000011";
const caseId = "0198c97d-cf4f-7000-8000-000000000012";
const teamId = "0198c97d-cf4f-7000-8000-000000000013";
const userId = "0198c97d-cf4f-7000-8000-000000000014";
const membershipId = "0198c97d-cf4f-7000-8000-000000000015";
const workflowId = "0198c97d-cf4f-7000-8000-000000000016";

test("Alert to claim to idempotent escalation to a separate Case", async ({
  page,
}) => {
  let alert = alertProjection(1, null);
  let escalationAttempts = 0;
  const escalationKeys: string[] = [];
  const escalationPayloads: string[] = [];
  const inventoryRequests = { comments: 0, contacts: 0, dfir: 0 };

  await mockPhaseThreeApi(
    page,
    async (route, pathname) => {
      const request = route.request();
      if (
        pathname === `/api/v1/tenants/${tenantId}/alerts/${alertId}/dfir` &&
        request.method() === "GET"
      ) {
        expect([...new URL(request.url()).searchParams.entries()]).toEqual([]);
        inventoryRequests.dfir += 1;
        await noStoreJson(route, {
          alertId,
          assets: [],
          attachments: [],
          evidence: [],
          indicators: [],
          relationships: [],
          tasks: [],
          tenantId,
          timeline: [],
        });
        return true;
      }
      if (
        pathname === `/api/v1/tenants/${tenantId}/alerts/${alertId}/contacts` &&
        request.method() === "GET"
      ) {
        expect([...new URL(request.url()).searchParams.entries()]).toEqual([
          ["limit", "100"],
        ]);
        inventoryRequests.contacts += 1;
        await json(route, { items: [] });
        return true;
      }
      if (
        pathname === `/api/v1/tenants/${tenantId}/alerts/${alertId}/comments` &&
        request.method() === "GET"
      ) {
        expect([...new URL(request.url()).searchParams.entries()]).toEqual([
          ["limit", "50"],
        ]);
        inventoryRequests.comments += 1;
        await noStoreJson(route, { items: [] });
        return true;
      }
      if (
        pathname === `/api/v1/tenants/${tenantId}/alerts/${alertId}/claim` &&
        request.method() === "POST"
      ) {
        expect(request.headers()["if-match"]).toBe('"v1"');
        expect(request.headers()["x-csrf-token"]).toBe("csrf-e2e-memory-only");
        expect(await request.postDataJSON()).toEqual({
          expectedVersion: 1,
          operatorTeamId: teamId,
        });
        alert = alertProjection(2, userId);
        await json(
          route,
          {
            alert,
            sideEffects: ["activity", "audit", "sla"],
            winner: {
              claimedAt: alert.assignment.claimedAt,
              claimedBy: userId,
              version: 2,
            },
          },
          '"v2"',
        );
        return true;
      }
      if (
        pathname === `/api/v1/tenants/${tenantId}/alerts/${alertId}/escalate` &&
        request.method() === "POST"
      ) {
        escalationAttempts += 1;
        escalationKeys.push(request.headers()["idempotency-key"] ?? "");
        expect(request.headers()["content-type"]).toBe("application/json");
        expect(request.headers()["if-match"]).toBe('"v2"');
        expect(request.headers()["x-csrf-token"]).toBe("csrf-e2e-memory-only");
        escalationPayloads.push(request.postData() ?? "");
        const body: unknown = await request.postDataJSON();
        expect(body).toEqual({
          expectedVersion: 2,
          relationType: "escalation",
          reason: "Correlate endpoint execution with identity telemetry.",
          sources: [
            {
              alertId,
              copySelection: {
                customFieldKeys: ["host"],
                fields: [
                  "category",
                  "description",
                  "priority",
                  "severity",
                  "tags",
                  "title",
                ],
              },
              expectedVersion: 2,
            },
          ],
          target: {
            case: {
              category: "endpoint",
              customerVisible: true,
              description:
                "Observed encoded command execution on the finance endpoint.",
              priority: "urgent",
              severity: "high",
              summary: "Escalated from ALT-2026-0042",
              title: "Suspicious PowerShell chain",
            },
            mode: "create_case",
          },
        });
        if (escalationAttempts === 1) {
          await route.fulfill({
            body: JSON.stringify({
              code: "precondition_failed",
              detail: "The Alert changed on the server. Review version 2.",
              requestId: "req-e2e-conflict",
              status: 412,
              title: "Precondition failed",
              type: "about:blank",
            }),
            contentType: "application/problem+json",
            status: 412,
          });
          return true;
        }
        await json(
          route,
          {
            alert,
            case: caseProjection(),
            links: [
              {
                projection: "operator",
                id: "0198c97d-cf4f-7000-8000-000000000019",
                tenantId,
                alertId,
                caseId,
                copySelection: {
                  customFieldKeys: ["host"],
                  fields: [
                    "category",
                    "description",
                    "priority",
                    "severity",
                    "tags",
                    "title",
                  ],
                },
                copiedFieldSnapshot: {
                  customFields: { host: "fin-ws-04" },
                  fields: { title: "Suspicious PowerShell chain" },
                },
                escalationReason:
                  "Correlate endpoint execution with identity telemetry.",
                linkedAt: "2026-08-25T08:15:00Z",
                linkedBy: membershipId,
                relationType: "escalation",
                sourceAlertVersion: 2,
              },
            ],
            sideEffects: ["activity", "audit", "sla", "notification"],
          },
          '"v2"',
        );
        return true;
      }
      return false;
    },
    () => alert,
  );

  await page.goto("/alerts");
  await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
  await page.getByRole("link", { name: /ALT-2026-0042/u }).click();
  await expect(
    page.getByRole("heading", { name: "Suspicious PowerShell chain" }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Claim" }).click();
  await page.getByRole("button", { name: "Apply action" }).click();
  await expect(page.getByRole("button", { name: "Release" })).toBeVisible();
  await expect(
    page
      .getByRole("region", { name: "Core details" })
      .getByText("v2", { exact: true }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Escalate" }).click();
  await page.getByRole("checkbox", { name: "Host" }).click();
  await page
    .getByLabel("Reason")
    .fill("Correlate endpoint execution with identity telemetry.");
  await page.getByRole("button", { name: "Apply action" }).click();
  await expect(
    page.getByText("The Alert changed on the server. Review version 2."),
  ).toBeVisible();
  await page.getByRole("button", { name: "Apply action" }).click();

  await expect(page).toHaveURL(new RegExp(`/cases/${caseId}$`, "u"));
  await expect(
    page.getByRole("heading", { name: "Finance endpoint investigation" }),
  ).toBeVisible();
  expect(escalationAttempts).toBe(2);
  expect(escalationPayloads).toHaveLength(2);
  expect(escalationPayloads[1]).toBe(escalationPayloads[0]);
  expect(escalationKeys[0]).toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  expect(escalationKeys[1]).toBe(escalationKeys[0]);
  expect(inventoryRequests).toEqual({ comments: 1, contacts: 1, dfir: 1 });
});

async function mockPhaseThreeApi(
  page: Page,
  extension: (route: Route, pathname: string) => Promise<boolean>,
  currentAlert: () => ReturnType<typeof alertProjection>,
): Promise<void> {
  await page.route("**/api/v1/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (await extension(route, pathname)) return;
    if (pathname === "/api/v1/bootstrap/status") {
      await json(route, { available: false });
      return;
    }
    if (pathname === "/api/v1/auth/session") {
      await json(route, sessionProjection());
      return;
    }
    if (pathname === "/api/v1/auth/tenant-memberships") {
      await json(route, {
        items: [
          {
            membershipId,
            role: "analyst",
            tenant: {
              id: tenantId,
              slug: "acme",
              name: "Acme Corporation",
              status: "active",
              timezone: "Europe/Rome",
              locale: "en",
              createdAt: "2026-08-01T08:00:00Z",
              updatedAt: "2026-08-01T08:00:00Z",
            },
          },
        ],
      });
      return;
    }
    if (pathname === `/api/v1/tenants/${tenantId}/me/authority`) {
      await json(route, authorityProjection());
      return;
    }
    if (
      pathname === `/api/v1/tenants/${tenantId}/alerts` &&
      request.method() === "GET"
    ) {
      await json(route, { items: [currentAlert()] });
      return;
    }
    if (
      pathname === `/api/v1/tenants/${tenantId}/alerts/${alertId}` &&
      request.method() === "GET"
    ) {
      const value = currentAlert();
      await json(route, value, `"v${value.version}"`);
      return;
    }
    if (
      pathname === `/api/v1/tenants/${tenantId}/cases/${caseId}` &&
      request.method() === "GET"
    ) {
      await json(route, caseProjection(), '"v1"');
      return;
    }
    await route.fulfill({
      body: JSON.stringify({
        detail: `Unmocked request: ${request.method()} ${pathname}`,
      }),
      contentType: "application/problem+json",
      status: 500,
    });
  });
}

async function json(route: Route, body: unknown, etag?: string): Promise<void> {
  await route.fulfill({
    body: JSON.stringify(body),
    contentType: "application/json",
    headers: etag ? { ETag: etag } : {},
    status: 200,
  });
}

async function noStoreJson(route: Route, body: unknown): Promise<void> {
  await route.fulfill({
    body: JSON.stringify(body),
    contentType: "application/json",
    headers: { "Cache-Control": "no-store" },
    status: 200,
  });
}

function sessionProjection() {
  return {
    id: "0198c97d-cf4f-7000-8000-000000000020",
    user: {
      id: userId,
      displayName: "Ada Analyst",
      email: "ada@example.invalid",
    },
    csrfToken: "csrf-e2e-memory-only",
    permissions: [],
    activeTenantId: tenantId,
    createdAt: "2026-08-25T08:00:00Z",
    lastSeenAt: "2026-08-25T08:10:00Z",
    idleExpiresAt: "2099-08-25T12:00:00Z",
    absoluteExpiresAt: "2099-08-26T12:00:00Z",
  };
}

function authorityProjection() {
  const permissions = [
    "alert.create",
    "alert.read",
    "alert.update",
    "alert.assign",
    "alert.claim",
    "alert.escalate",
    "alert.comment.public",
    "alert.comment.private",
    "case.create",
    "case.read",
    "case.update",
    "case.claim",
    "case.transfer",
    "case.transition",
    "case.comment.public",
    "case.comment.private",
  ];
  return {
    tenantId,
    userId,
    membershipId,
    membershipStatus: "active",
    legacyMembershipRole: "analyst",
    roleGrants: [],
    permissions: permissions.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    delegationCeiling: [],
    operatorTeamRelationships: [
      {
        operatorTeamId: teamId,
        assignmentEpochId: "0198c97d-cf4f-7000-8000-000000000018",
      },
    ],
    evaluatedAt: "2026-08-25T08:10:00Z",
  };
}

function alertProjection(version: number, claimedBy: string | null) {
  return {
    projection: "operator" as const,
    id: alertId,
    tenantId,
    alertNumber: "ALT-2026-0042",
    source: "sentinel",
    sourceType: "siem",
    title: "Suspicious PowerShell chain",
    description: "Observed encoded command execution on the finance endpoint.",
    workflow: {
      workflowId,
      kind: "alert",
      version: 3,
      stateKey: version === 1 ? "new" : "investigating",
      initial: version === 1,
      terminal: false,
      customerVisible: true,
    },
    severity: "high",
    priority: "urgent",
    category: "endpoint",
    detectedAt: "2026-08-25T08:10:00Z",
    receivedAt: "2026-08-25T08:11:00Z",
    assignment: {
      assignedTeamId: teamId,
      assigneeUserId: null,
      claimedAt: claimedBy ? "2026-08-25T08:13:00Z" : null,
      claimedBy,
    },
    visibility: "customer",
    customerVisible: true,
    tags: ["powershell", "windows"],
    customFields: { host: "fin-ws-04" },
    creator: { principalType: "human", membershipId },
    availableTransitions: [],
    version,
    createdAt: "2026-08-25T08:11:00Z",
    updatedAt: version === 1 ? "2026-08-25T08:11:00Z" : "2026-08-25T08:13:00Z",
  };
}

function caseProjection() {
  return {
    projection: "operator" as const,
    id: caseId,
    tenantId,
    caseNumber: "CASE-2026-0007",
    title: "Finance endpoint investigation",
    summary: "Escalated endpoint signal",
    description: "Investigate the encoded command chain.",
    workflow: {
      workflowId,
      kind: "case",
      version: 2,
      stateKey: "open",
      initial: true,
      terminal: false,
      customerVisible: true,
    },
    severity: "high",
    priority: "urgent",
    category: "endpoint",
    detectionTime: "2026-08-25T08:10:00Z",
    openedAt: "2026-08-25T08:15:00Z",
    assignment: {
      assignedTeamId: teamId,
      assigneeUserId: null,
      claimedAt: null,
      claimedBy: null,
    },
    visibility: "customer",
    customerVisible: true,
    tags: ["powershell", "windows"],
    customFields: {},
    creator: { principalType: "human", membershipId },
    availableTransitions: [],
    version: 1,
    createdAt: "2026-08-25T08:15:00Z",
    updatedAt: "2026-08-25T08:15:00Z",
  };
}
