import {
  expect,
  test,
  type Browser,
  type BrowserContext,
  type Page,
  type Request,
} from "@playwright/test";
import { createHash, createHmac, randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";

interface LiveAcceptanceState {
  baseUrl: string;
  cookieName: string;
  cookieValue: string;
  csrfToken: string;
  tenantId: string;
  operatorUserId: string;
  alertId: string;
  alertTitle: string;
  alertVersion: number;
  caseTitle: string;
  indicatorId: string;
  assetId: string;
  customerCookieValue: string;
  customerCSRFToken: string;
  customerUserId: string;
  customerPublicComment: string;
  operatorPrivateComment: string;
  operatorPublicComment: string;
  globexCookieValue: string;
  globexCSRFToken: string;
  globexTenantId: string;
  notificationOperatorSubject: string;
  notificationPrivateSubject: string;
  notificationPublicSubject: string;
  slaPolicyId: string;
  oidcMappedRoleId: string;
  oidcSecurityGroupId: string;
}

interface OIDCAcceptanceEnvironment {
  clientId: string;
  fallbackPassword: string;
  fallbackUsername: string;
  issuer: string;
  loginKey: string;
  tenantSlug: string;
  trustedPassword: string;
  trustedUsername: string;
}

test.describe.configure({ mode: "serial" });

test("served Swagger contract and live tenant boundaries agree", async ({
  browser,
  context,
  page,
}) => {
  test.setTimeout(180_000);
  const state = loadState();
  await installSession(context, state, state.cookieValue);

  await page.goto(`/alerts/${state.alertId}`);
  await expect(
    page.getByRole("heading", { name: state.alertTitle }),
  ).toBeVisible();

  const direct = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}`,
  );
  expect(direct.status).toBe(200);
  expect(direct.body).toMatchObject({
    id: state.alertId,
    projection: "operator",
    tenantId: state.tenantId,
    title: state.alertTitle,
    creator: { principalType: "service_account" },
    customFields: { host: "live-e2e-host" },
    rawPayload: { producer: "live-acceptance" },
  });
  const alertNumber = objectValue(direct.body, "alertNumber");

  const search = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/alerts?search=${encodeURIComponent(
      state.alertTitle,
    )}&customFieldKey=host&customFieldValue=live-e2e-host`,
  );
  expect(search.status).toBe(200);
  expect(itemIds(search.body)).toEqual([state.alertId]);

  const sla = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}/sla`,
  );
  expect(sla.status).toBe(200);
  expect(sla.body).toMatchObject({
    audience: "operator",
    objectId: state.alertId,
    objectType: "alert",
    policyId: state.slaPolicyId,
  });
  expect(
    arrayProperty(sla.body, "metrics").map((metric) =>
      objectValue(metric, "key"),
    ),
  ).toEqual(expect.arrayContaining(["first_response", "resolution"]));
  expect(
    arrayProperty(sla.body, "columns").map((column) =>
      objectValue(column, "key"),
    ),
  ).toEqual(
    expect.arrayContaining(["first_response_due", "resolution_remaining"]),
  );
  await expect(page.getByText("First response due")).toBeVisible();
  await expect(page.getByText("Resolution remaining")).toBeVisible();

  const exportRequest = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/ticket-exports`,
    {
      method: "POST",
      csrfToken: state.csrfToken,
      idempotencyKey: randomUUID(),
      json: ticketExportBody(state.alertTitle),
    },
  );
  expect(exportRequest.status).toBe(202);
  expect(exportRequest.body).toMatchObject({
    job: { kind: "alert", tenantId: state.tenantId },
  });
  const exportJobId = objectIdentifier(exportRequest.body, "job", "id");
  const completedExport = await waitForTicketExport(
    page,
    state.tenantId,
    exportJobId,
  );
  const artifact = objectRecord(completedExport, "artifact");
  expect(numberValue(artifact, "rows")).toBe(1);
  const artifactBytes = numberValue(artifact, "bytes");
  const artifactSha256 = objectValue(artifact, "sha256");
  expect(artifactSha256).toMatch(/^[0-9a-f]{64}$/u);
  const preparedDownload = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/ticket-exports/${exportJobId}/prepare-download?kind=alert`,
    { method: "POST", csrfToken: state.csrfToken },
  );
  expect(preparedDownload.status).toBe(200);
  expect(objectRecord(preparedDownload.body, "artifact")).toEqual(artifact);
  const downloadUrl = objectValue(preparedDownload.body, "downloadUrl");
  const parsedDownload = new URL(downloadUrl);
  expect(parsedDownload.protocol).toBe("https:");
  expect(parsedDownload.hostname).toBe("storage.localhost");
  const downloadedExport = await page.evaluate(async (url) => {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "omit",
    });
    return {
      contentType: response.headers.get("content-type"),
      status: response.status,
      text: await response.text(),
    };
  }, downloadUrl);
  expect(downloadedExport.status).toBe(200);
  expect(downloadedExport.contentType).toContain("text/csv");
  expect(Buffer.byteLength(downloadedExport.text, "utf8")).toBe(artifactBytes);
  expect(createHash("sha256").update(downloadedExport.text).digest("hex")).toBe(
    artifactSha256,
  );
  expect(downloadedExport.text).toBe(`ticket\r\n${alertNumber}\r\n`);

  await page.goto("/docs/");
  await expect(page.locator("#swagger-ui")).toBeVisible();
  await expect(
    page.getByText("Periapsis Incident Management API"),
  ).toBeVisible();
  const contract = await browserRequest(page, "/openapi.json");
  expect(contract.status).toBe(200);
  expect(contract.headers["content-type"]).toContain("application/json");
  expect(contract.body).toMatchObject({
    openapi: "3.1.0",
    info: { title: "Periapsis Incident Management API" },
  });
  const paths = objectRecord(contract.body, "paths");
  expect(paths).toHaveProperty("/api/v1/tenants/{tenantId}/alerts");
  expect(paths).toHaveProperty(
    "/api/v1/tenants/{tenantId}/portal/alerts/{alertId}/export",
  );

  const globexContext = await browser.newContext({
    baseURL: state.baseUrl,
    ignoreHTTPSErrors: true,
  });
  try {
    await installSession(globexContext, state, state.globexCookieValue);
    const globexPage = await globexContext.newPage();
    await globexPage.goto("/");

    const foreignDirect = await browserRequest(
      globexPage,
      `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}`,
    );
    expect([403, 404]).toContain(foreignDirect.status);

    const foreignSearch = await browserRequest(
      globexPage,
      `/api/v1/tenants/${state.globexTenantId}/alerts?search=${encodeURIComponent(
        state.alertTitle,
      )}`,
    );
    expect(foreignSearch.status).toBe(200);
    expect(itemIds(foreignSearch.body)).not.toContain(state.alertId);

    const foreignExport = await browserRequest(
      globexPage,
      `/api/v1/tenants/${state.tenantId}/ticket-exports`,
      {
        method: "POST",
        csrfToken: state.globexCSRFToken,
        idempotencyKey: randomUUID(),
        json: ticketExportBody(state.alertTitle),
      },
    );
    expect([403, 404]).toContain(foreignExport.status);

    const foreignJob = await browserRequest(
      globexPage,
      `/api/v1/tenants/${state.globexTenantId}/ticket-exports/${exportJobId}?kind=alert`,
    );
    expect(foreignJob.status).toBe(404);
    const foreignDownload = await browserRequest(
      globexPage,
      `/api/v1/tenants/${state.globexTenantId}/ticket-exports/${exportJobId}/prepare-download?kind=alert`,
      { method: "POST", csrfToken: state.globexCSRFToken },
    );
    expect(foreignDownload.status).toBe(404);

    await globexPage.goto(`/alerts/${state.alertId}`);
    await expect(
      globexPage
        .getByRole("heading", { name: "Access was denied by the server." })
        .or(
          globexPage
            .getByRole("alert")
            .getByText("Alert unavailable", { exact: true }),
        ),
    ).toBeVisible();
    await expect(
      globexPage.getByRole("heading", { name: state.alertTitle }),
    ).not.toBeVisible();
  } finally {
    await globexContext.close();
  }
});

test("operator and customer comments stay private across API, UI, and export", async ({
  browser,
  context,
  page,
}) => {
  const state = loadState();
  await installSession(context, state, state.cookieValue);
  await page.goto(`/alerts/${state.alertId}`);

  const commentsPath = `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}/comments`;
  const publicKey = randomUUID();
  const operatorPublic = await browserRequest(page, commentsPath, {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: publicKey,
    json: {
      bodyMarkdown: state.operatorPublicComment,
      visibility: "public",
    },
  });
  expect(operatorPublic.status).toBe(201);
  expect(operatorPublic.body).toMatchObject({
    bodyMarkdown: state.operatorPublicComment,
    origin: "api",
    visibility: "public",
  });
  const publicReplay = await browserRequest(page, commentsPath, {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: publicKey,
    json: {
      bodyMarkdown: state.operatorPublicComment,
      visibility: "public",
    },
  });
  expect(publicReplay.status).toBe(201);
  expect(publicReplay.body).toEqual(operatorPublic.body);
  expect(publicReplay.headers["x-idempotent-replay"]).toBe("true");

  const operatorPrivate = await browserRequest(page, commentsPath, {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: randomUUID(),
    json: {
      bodyMarkdown: state.operatorPrivateComment,
      visibility: "private",
    },
  });
  expect(operatorPrivate.status).toBe(201);
  expect(operatorPrivate.body).toMatchObject({
    bodyMarkdown: state.operatorPrivateComment,
    origin: "api",
    visibility: "private",
  });

  const operatorList = await browserRequest(page, `${commentsPath}?limit=100`);
  expect(operatorList.status).toBe(200);
  expect(commentBodies(operatorList.body)).toEqual(
    expect.arrayContaining([
      state.operatorPublicComment,
      state.operatorPrivateComment,
    ]),
  );

  const customerContext = await browser.newContext({
    baseURL: state.baseUrl,
    ignoreHTTPSErrors: true,
  });
  try {
    await installSession(customerContext, state, state.customerCookieValue);
    const customerPage = await customerContext.newPage();
    await customerPage.goto(`/portal?kind=alert&ticket=${state.alertId}`);
    await expect(
      customerPage.getByRole("heading", { name: "Your incident workspace" }),
    ).toBeVisible();
    await expect(
      customerPage.getByText(state.operatorPublicComment),
    ).toBeVisible();
    await expect(
      customerPage.getByText(state.operatorPrivateComment),
    ).not.toBeVisible();

    const customerPath = `/api/v1/tenants/${state.tenantId}/portal/alerts/${state.alertId}/comments`;
    const customerReply = await browserRequest(customerPage, customerPath, {
      method: "POST",
      csrfToken: state.customerCSRFToken,
      idempotencyKey: randomUUID(),
      json: { bodyMarkdown: state.customerPublicComment },
    });
    expect(customerReply.status).toBe(201);
    expect(customerReply.body).toMatchObject({
      author: { audience: "customer" },
      bodyMarkdown: state.customerPublicComment,
      origin: "customer_portal",
      visibility: "public",
    });

    const customerList = await browserRequest(
      customerPage,
      `${customerPath}?limit=100`,
    );
    expect(customerList.status).toBe(200);
    const customerBodies = commentBodies(customerList.body);
    expect(customerBodies).toEqual(
      expect.arrayContaining([
        state.operatorPublicComment,
        state.customerPublicComment,
      ]),
    );
    expect(customerBodies).not.toContain(state.operatorPrivateComment);
    expect(JSON.stringify(customerList.body)).not.toContain(
      state.operatorPrivateComment,
    );

    const operatorOnlyRoute = await browserRequest(customerPage, commentsPath);
    expect(operatorOnlyRoute.status).toBe(403);

    const customerExport = await browserRequest(
      customerPage,
      `/api/v1/tenants/${state.tenantId}/portal/alerts/${state.alertId}/export`,
    );
    expect(customerExport.status).toBe(200);
    expect(customerExport.headers["content-type"]).toContain("text/csv");
    expect(customerExport.headers["content-disposition"]).toBe(
      'attachment; filename="periapsis-customer-alert.csv"',
    );
    expect(customerExport.text).toContain(state.operatorPublicComment);
    expect(customerExport.text).toContain(state.customerPublicComment);
    expect(customerExport.text).not.toContain(state.operatorPrivateComment);
    expect(customerExport.text).not.toContain("live-acceptance");

    await customerPage.reload();
    await expect(
      customerPage.getByText(state.customerPublicComment),
    ).toBeVisible();
    await expect(
      customerPage.getByText(state.operatorPrivateComment),
    ).not.toBeVisible();
  } finally {
    await customerContext.close();
  }
});

test("real object storage, scanner, evidence custody, timeline, task, and relationship work", async ({
  context,
  page,
}) => {
  const state = loadState();
  await installSession(context, state, state.cookieValue);
  await page.goto(`/alerts/${state.alertId}`);
  const bundle = await createDfirBundle(page, state, {
    assetId: state.assetId,
    indicatorId: state.indicatorId,
    label: "Alert",
    root: `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}/dfir`,
    subject: { id: state.alertId, kind: "alert" },
  });

  await assertDfirActivity(page, state.tenantId, "alert", state.alertId, [
    "alert.evidence.added",
    "alert.evidence.custody_appended",
    "alert.task.created",
    "alert.relationship.created",
  ]);

  await page.reload();
  await page.getByRole("tab", { name: "DFIR" }).click();
  await expect(
    page.getByRole("heading", { name: "Alert investigation room" }),
  ).toBeVisible();
  await page.getByRole("tab", { name: /Evidence/u }).click();
  await expect(page.getByText(bundle.evidenceTitle)).toBeVisible();
  await page.getByRole("tab", { name: /Tasks/u }).click();
  await expect(page.getByText(bundle.taskTitle)).toBeVisible();
});

test("real LDAP operator claims and idempotently escalates an Alert", async ({
  context,
  page,
}) => {
  const state = loadState();
  await installSession(context, state, state.cookieValue);

  await page.goto(`/alerts/${state.alertId}`);
  await expect(
    page.getByRole("heading", { name: state.alertTitle }),
  ).toBeVisible();

  await page.getByRole("button", { name: "Claim" }).click();
  const claimPath = `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}/claim`;
  const claimResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === claimPath,
  );
  await page.getByRole("button", { name: "Apply action" }).click();
  const claimResponse = await claimResponsePromise;
  expect(claimResponse.status()).toBe(200);
  expect(await claimResponse.json()).toMatchObject({
    alert: {
      id: state.alertId,
      assignment: { claimedBy: state.operatorUserId },
    },
    winner: {
      claimedBy: state.operatorUserId,
      version: state.alertVersion + 1,
    },
  });
  await expect(page.getByRole("button", { name: "Release" })).toBeVisible();

  await page.getByRole("button", { name: "Escalate" }).click();
  const escalationDialog = page.getByRole("dialog");
  await expect(
    escalationDialog.getByText("Select exact records to copy.", {
      exact: false,
    }),
  ).toBeVisible();
  await escalationDialog.getByLabel("New Case title").fill(state.caseTitle);
  const escalationReason =
    "Live browser acceptance of the separate Case escalation boundary.";
  await escalationDialog.getByLabel("Reason").fill(escalationReason);
  await escalationDialog
    .getByRole("checkbox", { name: "Title", exact: true })
    .click();
  await escalationDialog
    .getByRole("checkbox", { name: "Host", exact: true })
    .click();
  await escalationDialog
    .getByRole("checkbox", { name: /IOCs: ipv4: 198\.51\.100\.42/u })
    .click();
  await escalationDialog
    .getByRole("checkbox", { name: /Assets: live-e2e-host/u })
    .click();

  const escalationPath = `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}/escalate`;
  const requestPromise = page.waitForRequest(
    (request) =>
      request.method() === "POST" &&
      new URL(request.url()).pathname === escalationPath,
  );
  const responsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === escalationPath,
  );
  await escalationDialog.getByRole("button", { name: "Apply action" }).click();
  const [escalationRequest, escalationResponse] = await Promise.all([
    requestPromise,
    responsePromise,
  ]);
  expect(escalationResponse.status()).toBe(201);
  const escalationBody = await escalationResponse.json();

  await expect(page).toHaveURL(/\/cases\/[0-9a-f-]{36}$/u);
  const caseId = requiredUuidV7(
    new URL(page.url()).pathname.split("/").at(-1),
    "escalated Case ID",
  );
  await expect(
    page.getByRole("heading", { name: state.caseTitle }),
  ).toBeVisible();

  const copied = await page.evaluate(
    async ({ tenantId, caseId: exactCaseId }) => {
      const [caseResponse, workspaceResponse] = await Promise.all([
        fetch(`/api/v1/tenants/${tenantId}/cases/${exactCaseId}`, {
          cache: "no-store",
          credentials: "same-origin",
        }),
        fetch(`/api/v1/tenants/${tenantId}/cases/${exactCaseId}/dfir`, {
          cache: "no-store",
          credentials: "same-origin",
        }),
      ]);
      return {
        caseStatus: caseResponse.status,
        caseBody: await caseResponse.json(),
        workspaceStatus: workspaceResponse.status,
        workspaceBody: await workspaceResponse.json(),
      };
    },
    { tenantId: state.tenantId, caseId },
  );
  expect(copied.caseStatus).toBe(200);
  expect(copied.workspaceStatus).toBe(200);
  expect(copied.caseBody).toMatchObject({
    category: "endpoint",
    description:
      "Real bearer API, browser, isolation, comment, escalation, and DFIR acceptance.",
    id: caseId,
    priority: "urgent",
    severity: "high",
    title: state.caseTitle,
  });
  expect(copied.caseBody.customFields).toEqual({ host: "live-e2e-host" });
  expect(copied.caseBody.tags).toEqual(["api", "live-e2e"]);
  expect(copied.workspaceBody.indicators).toHaveLength(1);
  expect(copied.workspaceBody.indicators[0]).toMatchObject({
    id: state.indicatorId,
  });
  expect(copied.workspaceBody.assets).toHaveLength(1);
  expect(copied.workspaceBody.assets[0]).toMatchObject({ id: state.assetId });
  for (const resource of [
    { kind: "ioc", id: state.indicatorId },
    { kind: "asset", id: state.assetId },
  ]) {
    const links = arrayProperty(copied.workspaceBody, "sharedResources").filter(
      (item) =>
        objectValue(item, "resourceKind") === resource.kind &&
        objectValue(item, "resourceId") === resource.id,
    );
    expect(links).toHaveLength(1);
    expect(links[0]).toMatchObject({
      roots: expect.arrayContaining([
        { kind: "alert", id: state.alertId },
        { kind: "case", id: caseId },
      ]),
    });
  }
  for (const unselectedCollection of [
    "attachments",
    "evidence",
    "relationships",
    "tasks",
    "timeline",
  ]) {
    expect(arrayProperty(copied.workspaceBody, unselectedCollection)).toEqual(
      [],
    );
  }

  const copiedContacts = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/cases/${caseId}/contacts?limit=100`,
  );
  expect(copiedContacts.status).toBe(200);
  expect(arrayProperty(copiedContacts.body, "items")).toEqual([]);

  const linkId = objectIdentifier(escalationBody, "links", "id");
  const [alertLinks, caseLinks] = await Promise.all([
    browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}/linked-cases?limit=100`,
    ),
    browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/cases/${caseId}/linked-alerts?limit=100`,
    ),
  ]);
  expect(alertLinks.status).toBe(200);
  expect(caseLinks.status).toBe(200);
  for (const projection of [alertLinks.body, caseLinks.body]) {
    const matchingLinks = arrayProperty(projection, "items").filter(
      (link) => objectValue(link, "id") === linkId,
    );
    expect(matchingLinks).toHaveLength(1);
    expect(matchingLinks[0]).toMatchObject({
      alertId: state.alertId,
      caseId,
      relationType: "escalation",
      sourceAlertVersion: state.alertVersion + 1,
    });
  }

  const originalBody = escalationRequest.postData();
  expect(originalBody).not.toBeNull();
  const originalPayload = JSON.parse(originalBody!) as {
    expectedVersion?: number;
    reason?: string;
    relationType?: string;
    sources?: Array<{
      alertId?: string;
      copySelection?: unknown;
      expectedVersion?: number;
    }>;
    target?: { case?: { title?: string }; mode?: string };
  };
  expect(originalPayload).toMatchObject({
    expectedVersion: state.alertVersion + 1,
    reason: escalationReason,
    relationType: "escalation",
    sources: [
      {
        alertId: state.alertId,
        expectedVersion: state.alertVersion + 1,
      },
    ],
    target: { case: { title: state.caseTitle }, mode: "create_case" },
  });
  expect(originalPayload.sources?.[0]?.copySelection).toEqual({
    assetIds: [state.assetId],
    customFieldKeys: ["host"],
    fields: ["category", "description", "priority", "severity", "tags"],
    iocIds: [state.indicatorId],
  });

  const replayHeaders = {
    "Content-Type": await requiredRequestHeader(
      escalationRequest,
      "content-type",
    ),
    "Idempotency-Key": await requiredRequestHeader(
      escalationRequest,
      "idempotency-key",
    ),
    "If-Match": await requiredRequestHeader(escalationRequest, "if-match"),
    "X-CSRF-Token": await requiredRequestHeader(
      escalationRequest,
      "x-csrf-token",
    ),
  };
  expect(replayHeaders["Content-Type"]).toBe("application/json");
  expect(replayHeaders["Idempotency-Key"]).toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  expect(replayHeaders["If-Match"]).toBe(`"v${state.alertVersion + 1}"`);
  expect(/^[A-Za-z0-9_-]{43}$/u.test(replayHeaders["X-CSRF-Token"])).toBe(true);
  const originalResponseHeaders = escalationResponse.headers();
  const replay = await page.evaluate(
    async ({ body, headers, url }) => {
      const response = await fetch(url, {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        headers,
        body,
      });
      return {
        status: response.status,
        body: await response.json(),
        etag: response.headers.get("etag"),
        location: response.headers.get("location"),
      };
    },
    {
      body: originalBody,
      headers: replayHeaders,
      url: escalationRequest.url(),
    },
  );
  expect(replay.status).toBe(201);
  expect(replay.body).toEqual(escalationBody);
  expect(replay.etag).toBe(originalResponseHeaders["etag"]);
  expect(replay.location).toBe(originalResponseHeaders["location"]);

  const [
    caseSearch,
    alertActivity,
    caseActivity,
    alertEscalationAudit,
    caseCreationAudit,
  ] = await Promise.all([
    browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/cases?search=${encodeURIComponent(state.caseTitle)}`,
    ),
    browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/alerts/${state.alertId}/activities?limit=100`,
    ),
    browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/cases/${caseId}/activities?limit=100`,
    ),
    browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/audit-events?actionPrefix=tenant.alert.escalated&limit=100`,
    ),
    browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/audit-events?actionPrefix=tenant.case.created&limit=100`,
    ),
  ]);
  for (const response of [
    caseSearch,
    alertActivity,
    caseActivity,
    alertEscalationAudit,
    caseCreationAudit,
  ]) {
    expect(response.status).toBe(200);
  }
  expect(itemIds(caseSearch.body)).toEqual([caseId]);
  expect(
    arrayProperty(alertActivity.body, "items").filter(
      (item) => objectValue(item, "kind") === "escalated",
    ),
  ).toHaveLength(1);
  expect(
    arrayProperty(caseActivity.body, "items").filter(
      (item) => objectValue(item, "kind") === "created",
    ),
  ).toHaveLength(1);
  expect(
    arrayProperty(alertEscalationAudit.body, "items").some(
      (item) =>
        objectValue(item, "action") === "tenant.alert.escalated" &&
        JSON.stringify(item).includes(state.alertId) &&
        JSON.stringify(item).includes(caseId),
    ),
  ).toBe(true);
  expect(
    arrayProperty(caseCreationAudit.body, "items").some(
      (item) =>
        objectValue(item, "action") === "tenant.case.created" &&
        JSON.stringify(item).includes(caseId),
    ),
  ).toBe(true);

  const caseBundle = await createDfirBundle(page, state, {
    assetId: state.assetId,
    indicatorId: state.indicatorId,
    label: "Case",
    root: `/api/v1/tenants/${state.tenantId}/cases/${caseId}/dfir`,
    subject: { id: caseId, kind: "case" },
  });
  await assertDfirActivity(page, state.tenantId, "case", caseId, [
    "dfir.evidence.collected",
    "dfir.evidence.custody_appended",
    "dfir.timeline.created",
    "dfir.task.created",
    "dfir.relationship.created",
  ]);

  const audit = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/audit-events?actionPrefix=dfir.&limit=100`,
  );
  expect(audit.status).toBe(200);
  const auditItems = arrayProperty(audit.body, "items");
  const serializedAudit = JSON.stringify(auditItems);
  for (const resourceId of [
    caseBundle.evidenceId,
    caseBundle.relationshipId,
    caseBundle.taskId,
    caseBundle.timelineId,
  ]) {
    expect(serializedAudit).toContain(resourceId);
  }
  for (const action of [
    "dfir.evidence.collected",
    "dfir.evidence.custody_appended",
    "dfir.timeline.created",
    "dfir.task.created",
    "dfir.relationship.created",
  ]) {
    expect(
      auditItems.some((item) => objectValue(item, "action") === action),
    ).toBe(true);
  }

  await page.reload();
  await page.getByRole("tab", { name: "DFIR" }).click();
  await expect(
    page.getByRole("heading", { name: "Case evidence room" }),
  ).toBeVisible();
  await page.getByRole("tab", { name: /IOC/u }).click();
  await expect(page.getByText("198.51.100.42")).toBeVisible();
  const relatedTickets = page.locator(".dfir-related-tickets").first();
  await relatedTickets.locator("summary").click();
  await expect(
    relatedTickets.getByRole("link", {
      name: `Alert ${state.alertId}`,
      exact: true,
    }),
  ).toHaveAttribute("href", `/alerts/${state.alertId}`);
  await page.getByRole("tab", { name: /Assets/u }).click();
  await expect(page.getByText("live-e2e-host", { exact: true })).toBeVisible();
  await page.getByRole("tab", { name: /Evidence/u }).click();
  await expect(page.getByText(caseBundle.evidenceTitle)).toBeVisible();
  await page.getByRole("tab", { name: /Timeline/u }).click();
  await expect(page.getByText(caseBundle.timelineTitle)).toBeVisible();
  await page.getByRole("tab", { name: /Tasks/u }).click();
  await expect(page.getByText(caseBundle.taskTitle)).toBeVisible();
  await page.getByRole("tab", { name: /Links/u }).click();
  await expect(page.getByText("observed indicator")).toBeVisible();
});

test("real Keycloak OIDC JIT trusts completed password/OTP AMR and completes local TOTP fallback", async ({
  browser,
}) => {
  test.setTimeout(180_000);
  const state = loadState();
  const oidc = loadOIDCAcceptanceEnvironment();
  const trustedTOTPSecret = await enrollKeycloakTOTP(browser, state, oidc);

  const trustedContext = await browser.newContext({
    baseURL: state.baseUrl,
    ignoreHTTPSErrors: true,
  });
  try {
    const page = await trustedContext.newPage();
    await signInWithKeycloak(
      page,
      state,
      oidc,
      {
        password: oidc.trustedPassword,
        username: oidc.trustedUsername,
      },
      trustedTOTPSecret,
    );
    await expect(page).toHaveURL(`${state.baseUrl}/`);
    await assertOIDCSessionAndAuthority(page, state, oidc.trustedUsername);
    await page.goto(`/alerts/${state.alertId}`);
    await expect(
      page.getByRole("heading", { name: state.alertTitle }),
    ).toBeVisible();
  } finally {
    await trustedContext.close();
  }

  const fallbackContext = await browser.newContext({
    baseURL: state.baseUrl,
    ignoreHTTPSErrors: true,
  });
  try {
    const page = await fallbackContext.newPage();
    await signInWithKeycloak(page, state, oidc, {
      password: oidc.fallbackPassword,
      username: oidc.fallbackUsername,
    });
    await expect(page).toHaveURL(`${state.baseUrl}/?auth=federated-mfa`);
    await expect(
      page.getByRole("heading", { name: "Complete local MFA." }),
    ).toBeVisible();

    const beforeEnrollment = await browserRequest(page, "/api/v1/auth/session");
    expect(beforeEnrollment.status).toBe(401);

    const enrollmentStarted = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        new URL(response.url()).pathname ===
          "/api/v1/auth/federated/mfa/totp/enrollments",
    );
    await page.getByRole("button", { name: "Set up an authenticator" }).click();
    expect((await enrollmentStarted).status()).toBe(201);
    const secret = requireBrowserTotpSecret(
      await page
        .locator(".secret-value")
        .filter({ hasText: "Manual secret" })
        .locator("code")
        .textContent(),
    );
    await avoidBrowserTotpBoundary(page);
    const enrollmentCode = browserTotp(secret);
    const enrollmentCompleted = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        /^\/api\/v1\/auth\/federated\/mfa\/totp\/enrollments\/[0-9a-f-]{36}$/u.test(
          new URL(response.url()).pathname,
        ),
    );
    await page.getByLabel("Current six-digit code").fill(enrollmentCode);
    await page.getByRole("button", { name: "Confirm authenticator" }).click();
    const enrollmentResponse = await enrollmentCompleted;
    expect(enrollmentResponse.status()).toBe(200);
    expect(await enrollmentResponse.json()).toMatchObject({ next: "step_up" });
    await expect(page.getByText("Authenticator ready")).toBeVisible();

    const afterEnrollment = await browserRequest(page, "/api/v1/auth/session");
    expect(afterEnrollment.status).toBe(401);
    await waitForFreshBrowserTotp(page, secret, enrollmentCode);

    const challengeStarted = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        new URL(response.url()).pathname ===
          "/api/v1/auth/federated/mfa/step-up",
    );
    await page.getByRole("button", { name: "Use local verification" }).click();
    expect((await challengeStarted).status()).toBe(200);
    const completed = page.waitForResponse(
      (response) =>
        response.request().method() === "POST" &&
        /^\/api\/v1\/auth\/federated\/mfa\/step-up\/[A-Za-z0-9_-]{43}\/totp$/u.test(
          new URL(response.url()).pathname,
        ),
    );
    await page.getByLabel("Authenticator code").fill(browserTotp(secret));
    await page
      .getByRole("button", { name: "Verify and create session" })
      .click();
    const completedResponse = await completed;
    expect(completedResponse.status()).toBe(200);
    expect(await completedResponse.json()).toMatchObject({
      activeTenantId: state.tenantId,
      authenticationMethod: "oidc",
    });
    await expect(page).toHaveURL(`${state.baseUrl}/`);
    await assertOIDCSessionAndAuthority(page, state, oidc.fallbackUsername);
    await page.goto(`/alerts/${state.alertId}`);
    await expect(
      page.getByRole("heading", { name: state.alertTitle }),
    ).toBeVisible();
  } finally {
    await fallbackContext.close();
  }
});

async function enrollKeycloakTOTP(
  browser: Browser,
  state: LiveAcceptanceState,
  oidc: OIDCAcceptanceEnvironment,
): Promise<string> {
  const context = await browser.newContext({
    baseURL: state.baseUrl,
    ignoreHTTPSErrors: true,
  });
  try {
    const page = await context.newPage();
    await signInWithKeycloak(page, state, oidc, {
      password: oidc.trustedPassword,
      username: oidc.trustedUsername,
    });
    await expect(page.locator("#kc-totp-settings-form")).toBeVisible();
    await page.locator("#mode-manual").click();
    const secret = requireBrowserTotpSecret(
      await page.locator("#kc-totp-secret-key").textContent(),
    );
    await avoidBrowserTotpBoundary(page);
    await page.locator("#totp").fill(browserTotp(secret));
    await page.locator("#userLabel").fill("Periapsis live acceptance");
    await Promise.all([
      page.waitForURL((url) => url.origin === new URL(state.baseUrl).origin, {
        timeout: 30_000,
      }),
      page.locator("#saveTOTPBtn").click(),
    ]);
    const afterEnrollment = await browserRequest(page, "/api/v1/auth/session");
    expect(afterEnrollment.status).toBe(401);
    const abandoned = await browserRequest(
      page,
      "/api/v1/auth/federated/mfa/continuation",
      { method: "DELETE" },
    );
    expect(abandoned.status).toBe(204);
    return secret;
  } finally {
    await context.close();
  }
}

async function signInWithKeycloak(
  page: Page,
  state: LiveAcceptanceState,
  oidc: OIDCAcceptanceEnvironment,
  credentials: { password: string; username: string },
  otpSecret?: string,
): Promise<void> {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Identify the operator." }),
  ).toBeVisible();
  const form = page.locator("form").filter({
    has: page.getByRole("button", { name: "Continue with OIDC" }),
  });
  await form.getByLabel("Tenant slug").fill(oidc.tenantSlug);
  await form.getByLabel("Provider login key").fill(oidc.loginKey);
  await form.getByRole("button", { name: "Continue with OIDC" }).click();
  await expect(page.locator("#kc-form-login")).toBeVisible();
  assertKeycloakAuthorizationRequest(page, state, oidc);
  await page.locator("#username").fill(credentials.username);
  await page.locator("#password").fill(credentials.password);
  await page.locator("#kc-login").click();
  if (otpSecret !== undefined) {
    await expect(page.locator("#kc-otp-login-form")).toBeVisible();
    await avoidBrowserTotpBoundary(page);
    await page.locator("#otp").fill(browserTotp(otpSecret));
    await page.locator("#kc-login").click();
  }
}

function assertKeycloakAuthorizationRequest(
  page: Page,
  state: LiveAcceptanceState,
  oidc: OIDCAcceptanceEnvironment,
): void {
  const authorization = new URL(page.url());
  const expectedEndpoint = `${oidc.issuer}/protocol/openid-connect/auth`;
  const expectedRedirect = `${state.baseUrl}/api/v1/auth/federated/oidc/callback`;
  if (`${authorization.origin}${authorization.pathname}` !== expectedEndpoint) {
    throw new Error(
      "OIDC authorization endpoint is not the configured Keycloak issuer",
    );
  }
  const exactParameters = {
    client_id: oidc.clientId,
    code_challenge_method: "S256",
    redirect_uri: expectedRedirect,
    response_mode: "query",
    response_type: "code",
  };
  for (const [name, expected] of Object.entries(exactParameters)) {
    const values = authorization.searchParams.getAll(name);
    if (values.length !== 1 || values[0] !== expected) {
      throw new Error(`OIDC authorization parameter ${name} is malformed`);
    }
  }
  for (const name of ["code_challenge", "nonce", "state"]) {
    requireOpaqueOIDCParameter(authorization, name);
  }
  const scopes = authorization.searchParams.getAll("scope");
  if (scopes.length !== 1 || !scopes[0]?.split(" ").includes("openid")) {
    throw new Error(
      "OIDC authorization scope must contain openid exactly once",
    );
  }
  if (authorization.searchParams.has("code_verifier")) {
    throw new Error(
      "OIDC authorization request must not disclose the PKCE verifier",
    );
  }
}

function requireOpaqueOIDCParameter(url: URL, name: string): void {
  const values = url.searchParams.getAll(name);
  if (
    values.length !== 1 ||
    !/^[A-Za-z0-9_-]{32,256}$/u.test(values[0] ?? "")
  ) {
    throw new Error(`OIDC authorization parameter ${name} is malformed`);
  }
}

async function assertOIDCSessionAndAuthority(
  page: Page,
  state: LiveAcceptanceState,
  username: string,
): Promise<void> {
  const session = await browserRequest(page, "/api/v1/auth/session");
  expect(session.status).toBe(200);
  expect(session.body).toMatchObject({
    activeTenantId: state.tenantId,
    authenticationMethod: "oidc",
    user: { email: `${username}@periapsis.test` },
  });
  const authority = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/me/authority`,
  );
  expect(authority.status).toBe(200);
  const roleGrant = arrayProperty(authority.body, "roleGrants").find(
    (grant) => objectValue(grant, "roleId") === state.oidcMappedRoleId,
  );
  expect(roleGrant).toBeDefined();
  expect(roleGrant).toMatchObject({
    path: {
      pathType: "group",
      group: { group: { id: state.oidcSecurityGroupId } },
    },
  });
  expect(
    arrayProperty(authority.body, "permissions").some(
      (permission) =>
        objectValue(permission, "permissionKey") === "alert.read" &&
        objectValue(permission, "scope") === "tenant",
    ),
  ).toBe(true);
}

async function avoidBrowserTotpBoundary(page: Page): Promise<void> {
  const remaining = 30_000 - (Date.now() % 30_000);
  if (remaining < 8_000) await page.waitForTimeout(remaining + 250);
}

async function waitForFreshBrowserTotp(
  page: Page,
  secret: string,
  previous: string,
): Promise<void> {
  const remaining = 30_000 - (Date.now() % 30_000);
  await page.waitForTimeout(remaining + 250);
  if (browserTotp(secret) === previous) {
    throw new Error("TOTP counter did not advance within one period");
  }
  await avoidBrowserTotpBoundary(page);
}

function browserTotp(secret: string, at = Date.now()): string {
  const key = decodeBase32(secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30_000)));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest[digest.length - 1]! & 0x0f;
  const binary =
    (((digest[offset]! & 0x7f) << 24) |
      (digest[offset + 1]! << 16) |
      (digest[offset + 2]! << 8) |
      digest[offset + 3]!) >>>
    0;
  return String(binary % 1_000_000).padStart(6, "0");
}

function requireBrowserTotpSecret(value: string | null): string {
  const secret = value?.replace(/\s/gu, "") ?? "";
  if (!/^[A-Z2-7]{16,256}$/u.test(secret)) {
    throw new Error(
      "browser TOTP enrollment returned an invalid secret format",
    );
  }
  return secret;
}

function decodeBase32(value: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const character of value.replace(/=+$/u, "").toUpperCase()) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("invalid base32 TOTP secret");
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

interface DfirBundleOptions {
  assetId: string;
  indicatorId: string;
  label: "Alert" | "Case";
  root: string;
  subject: { id: string; kind: "alert" | "case" };
}

interface DfirBundle {
  evidenceId: string;
  evidenceTitle: string;
  relationshipId: string;
  taskId: string;
  taskTitle: string;
  timelineId: string;
  timelineTitle: string;
}

async function createDfirBundle(
  page: Page,
  state: LiveAcceptanceState,
  options: DfirBundleOptions,
): Promise<DfirBundle> {
  const bytes = Buffer.from(
    `Periapsis live ${options.label} DFIR acceptance ${options.subject.id}\n`,
    "utf8",
  );
  const attachmentId = uuidv7();
  const storageObjectId = uuidv7();
  const uploadRequest: BrowserRequestOptions = {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: randomUUID(),
    json: {
      attachmentId,
      storageObjectId,
      subject: options.subject,
      originalFilename: `${options.label.toLowerCase()}-live-evidence.txt`,
      classification: "internal",
      requestedVisibility: "private",
      sizeBytes: bytes.length,
      contentType: "text/plain",
    },
  };
  const prepared = await browserRequest(
    page,
    `${options.root}/attachments/prepare-upload`,
    uploadRequest,
  );
  expect(prepared.status).toBe(201);
  expect(prepared.body).toMatchObject({
    attachment: {
      id: attachmentId,
      scanState: "pending_upload",
      storageObjectId,
    },
    method: "PUT",
  });
  const upload = uploadCapability(prepared.body, bytes.length);
  const uploaded = await page.evaluate(
    async ({ bytes: bodyBytes, headers, url }) => {
      const response = await fetch(url, {
        body: new Uint8Array(bodyBytes),
        headers,
        method: "PUT",
      });
      return { status: response.status, text: await response.text() };
    },
    { bytes: [...bytes], headers: upload.headers, url: upload.url },
  );
  expect(uploaded.status, uploaded.text).toBe(200);

  const scanned = await pollWorkspace(page, options.root, (workspace) =>
    arrayProperty(workspace, "attachments").some(
      (attachment) =>
        objectValue(attachment, "id") === attachmentId &&
        objectValue(attachment, "scanState") === "available",
    ),
  );
  expect(scanned.status).toBe(200);
  const consumedUploadReplay = await browserRequest(
    page,
    `${options.root}/attachments/prepare-upload`,
    uploadRequest,
  );
  expect(consumedUploadReplay.status).toBe(409);
  expect(consumedUploadReplay.text).not.toContain("uploadUrl");

  const evidenceId = uuidv7();
  const evidenceTitle = `${options.label} live evidence artifact`;
  const evidenceRequest: BrowserRequestOptions = {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: randomUUID(),
    json: {
      evidenceId,
      storageObjectId,
      initialCustodyEventId: uuidv7(),
      title: evidenceTitle,
      description:
        "Uploaded to Compose object storage and scanned by the worker.",
      evidenceType: "host_artifact",
      classification: "internal",
      collectedAt: new Date().toISOString(),
      source: "live-browser-acceptance",
      legalHold: false,
    },
  };
  const evidence = await browserRequest(
    page,
    `${options.root}/evidence`,
    evidenceRequest,
  );
  expect(evidence.status).toBe(201);
  expect(evidence.body).toMatchObject({
    [`${options.subject.kind}Id`]: options.subject.id,
    contentSha256: createHash("sha256").update(bytes).digest("hex"),
    id: evidenceId,
    scanState: "available",
    sizeBytes: bytes.length,
    storageObjectId,
    version: 1,
  });
  expect(arrayProperty(evidence.body, "custody")).toHaveLength(1);

  const custody = await browserRequest(
    page,
    `${options.root}/evidence/${evidenceId}/custody`,
    {
      method: "POST",
      csrfToken: state.csrfToken,
      idempotencyKey: randomUUID(),
      ifMatch: '"v1"',
      json: {
        expectedVersion: 1,
        custodyEventId: uuidv7(),
        action: "accessed",
        reason: `Verify live ${options.label} browser custody chain`,
      },
    },
  );
  expect(custody.status).toBe(200);
  expect(custody.body).toMatchObject({ id: evidenceId, version: 2 });
  const custodyEvents = arrayProperty(custody.body, "custody");
  expect(custodyEvents).toHaveLength(2);
  expect(objectValue(custodyEvents[1], "previousHash")).toBe(
    objectValue(custodyEvents[0], "eventHash"),
  );
  const historicalEvidenceReplay = await browserRequest(
    page,
    `${options.root}/evidence`,
    evidenceRequest,
  );
  expect(historicalEvidenceReplay.status).toBe(201);
  expect(historicalEvidenceReplay.body).toEqual(evidence.body);
  expect(historicalEvidenceReplay.headers.etag).toBe(evidence.headers.etag);

  const timelineId = uuidv7();
  const timelineTitle = `${options.label} live evidence analyzed`;
  const timeline = await browserRequest(
    page,
    `${options.root}/timeline-events`,
    {
      method: "POST",
      csrfToken: state.csrfToken,
      idempotencyKey: randomUUID(),
      json: {
        timelineEventId: timelineId,
        event: {
          eventTime: new Date().toISOString(),
          originalTimezone: "Europe/Rome",
          precision: "second",
          source: "live-browser-acceptance",
          category: "execution",
          title: timelineTitle,
          description: "Correlated the uploaded artifact to the IOC and asset.",
          iocIds: [options.indicatorId],
          assetIds: [options.assetId],
          evidenceIds: [evidenceId],
          tags: ["live-e2e"],
        },
      },
    },
  );
  expect(timeline.status).toBe(201);
  expect(timeline.body).toMatchObject({
    [`${options.subject.kind}Id`]: options.subject.id,
    id: timelineId,
  });

  const taskId = uuidv7();
  const taskTitle = `Triage ${options.label} live evidence`;
  const task = await browserRequest(page, `${options.root}/tasks`, {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: randomUUID(),
    json: {
      taskId,
      task: {
        title: taskTitle,
        description: "Complete live DFIR verification.",
        priority: "high",
        checklist: [
          {
            id: uuidv7(),
            title: "Verify object hash",
            completed: false,
          },
        ],
      },
    },
  });
  expect(task.status).toBe(201);
  expect(task.body).toMatchObject({
    [`${options.subject.kind}Id`]: options.subject.id,
    id: taskId,
    status: "todo",
    version: 1,
  });
  const completedTask = await exerciseDfirTaskUpdates(
    page,
    state,
    options,
    task.body,
  );

  const relationshipId = uuidv7();
  const relationship = await browserRequest(
    page,
    `${options.root}/relationships`,
    {
      method: "POST",
      csrfToken: state.csrfToken,
      idempotencyKey: randomUUID(),
      json: {
        relationshipId,
        source: options.subject,
        target: { kind: "ioc", id: options.indicatorId },
        relationshipType: "observed_indicator",
        metadata: { source: "live-e2e" },
      },
    },
  );
  expect(relationship.status).toBe(201);
  expect(relationship.body).toMatchObject({
    tenantId: state.tenantId,
    source: options.subject,
    target: { kind: "ioc", id: options.indicatorId },
    active: true,
    id: relationshipId,
    version: 1,
    retractions: [],
  });
  if (options.subject.kind === "alert") {
    expect(relationship.body).toMatchObject({ alertId: options.subject.id });
  }
  await exerciseDfirChildRelationship(page, state, options);

  const workspace = await browserRequest(page, options.root);
  expect(workspace.status).toBe(200);
  expect(itemIdentifiers(workspace.body, "evidence")).toContain(evidenceId);
  expect(itemIdentifiers(workspace.body, "timeline")).toContain(timelineId);
  expect(itemIdentifiers(workspace.body, "tasks")).toContain(taskId);
  expect(itemIdentifiers(workspace.body, "relationships")).toContain(
    relationshipId,
  );
  return {
    evidenceId,
    evidenceTitle,
    relationshipId,
    taskId,
    taskTitle: objectValue(completedTask, "title"),
    timelineId,
    timelineTitle,
  };
}

async function exerciseDfirTaskUpdates(
  page: Page,
  state: LiveAcceptanceState,
  options: DfirBundleOptions,
  created: unknown,
): Promise<unknown> {
  const ticketPath = `/api/v1/tenants/${state.tenantId}/${options.subject.kind}s/${options.subject.id}`;
  const taskId = requiredUuidV7(objectValue(created, "id"), "live task ID");
  const taskPath = `${options.root}/tasks/${taskId}`;
  const authority = await browserRequest(
    page,
    `/api/v1/tenants/${state.tenantId}/me/authority`,
  );
  expect(authority.status).toBe(200);
  const teams = arrayProperty(authority.body, "operatorTeamRelationships");
  expect(teams).toHaveLength(1);
  const operatorTeamId = requiredUuidV7(
    objectValue(teams[0], "operatorTeamId"),
    "live operator team",
  );
  const comment = await browserRequest(page, `${ticketPath}/comments`, {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: randomUUID(),
    json: {
      bodyMarkdown: `${options.label} task verification completed by the live operator.`,
      visibility: "private",
    },
  });
  expect(comment.status).toBe(201);
  const commentId = requiredUuidV7(
    objectValue(comment.body, "id"),
    "task comment",
  );
  let slaInstanceId: string | undefined;
  // The existing acceptance policy applies only to Alerts. Do not invent a
  // Case SLA or weaken its exact-root association requirement for this journey.
  if (options.subject.kind === "alert") {
    const sla = await browserRequest(page, `${ticketPath}/sla`);
    expect(sla.status).toBe(200);
    expect(sla.body).toMatchObject({
      objectId: options.subject.id,
      objectType: "alert",
      policyId: state.slaPolicyId,
    });
    slaInstanceId = requiredUuidV7(
      objectValue(sla.body, "slaInstanceId"),
      "task SLA",
    );
  }
  let current = created;
  const update = async (
    action:
      | "details"
      | "assignment"
      | "due-date"
      | "checklist"
      | "comments"
      | "transition",
    payload: Record<string, unknown>,
    expected: Record<string, unknown>,
  ) => {
    const version = numberValue(current, "version");
    const request: BrowserRequestOptions = {
      method: action === "transition" ? "POST" : "PUT",
      csrfToken: state.csrfToken,
      idempotencyKey: randomUUID(),
      ifMatch: `"v${version}"`,
      json: { ...payload, expectedVersion: version },
    };
    const response = await browserRequest(
      page,
      `${taskPath}/${action}`,
      request,
    );
    expect(response.status).toBe(200);
    expect(response.headers.etag).toBe(`"v${version + 1}"`);
    expect(response.body).toMatchObject({
      ...expected,
      id: taskId,
      tenantId: state.tenantId,
      [`${options.subject.kind}Id`]: options.subject.id,
      version: version + 1,
    });
    current = response.body;
    return { request, response };
  };
  const details = {
    title: `Verified ${options.label} live task`,
    description: "Revised instructions verified through the composed HTTP API.",
    priority: "urgent",
    ...(slaInstanceId === undefined ? {} : { slaInstanceId }),
  };
  const firstDetails = await update("details", details, details);
  if (slaInstanceId !== undefined) {
    const { slaInstanceId: _removed, ...withoutSla } = details;
    await update("details", withoutSla, withoutSla);
    expect(current).not.toHaveProperty("slaInstanceId");
  }
  const assignment = { operatorTeamId, assigneeId: state.operatorUserId };
  await update("assignment", assignment, assignment);
  const dueAt = new Date(Date.now() + 60 * 60_000).toISOString();
  await update("due-date", { dueAt }, {});
  expect(Date.parse(objectValue(current, "dueAt"))).toBe(Date.parse(dueAt));
  const checklist = arrayProperty(created, "checklist").map((item) => ({
    id: requiredUuidV7(objectValue(item, "id"), "checklist item"),
    title: objectValue(item, "title"),
    completed: true,
  }));
  expect(checklist).toHaveLength(1);
  await update("checklist", { checklist }, { checklist });
  const completedItem = arrayProperty(current, "checklist")[0];
  expect(objectValue(completedItem, "completedBy")).toBe(state.operatorUserId);
  expect(
    Number.isFinite(Date.parse(objectValue(completedItem, "completedAt"))),
  ).toBe(true);
  await update(
    "comments",
    { commentIds: [commentId] },
    { commentIds: [commentId] },
  );
  await update(
    "transition",
    { target: "in_progress", reason: "Begin live verification" },
    { status: "in_progress" },
  );
  const completionData = { verified: true, source: "live-browser-acceptance" };
  const completed = await update(
    "transition",
    {
      target: "done",
      reason: "All evidence verification steps completed",
      completionData,
    },
    { status: "done", completionData, completedBy: state.operatorUserId },
  );
  expect(Number.isFinite(Date.parse(objectValue(current, "completedAt")))).toBe(
    true,
  );

  const replay = await browserRequest(
    page,
    `${taskPath}/transition`,
    completed.request,
  );
  expect(replay.status).toBe(200);
  expect(replay.body).toEqual(completed.response.body);
  expect(replay.headers["x-idempotent-replay"]).toBe("true");
  const historical = await browserRequest(
    page,
    `${taskPath}/details`,
    firstDetails.request,
  );
  expect(historical.status).toBe(200);
  expect(historical.body).toEqual(firstDetails.response.body);
  expect(historical.headers.etag).toBe(firstDetails.response.headers.etag);
  expect(historical.headers["x-idempotent-replay"]).toBe("true");
  const stale = await browserRequest(page, `${taskPath}/details`, {
    ...firstDetails.request,
    idempotencyKey: randomUUID(),
  });
  expect(stale.status).toBe(412);
  const workspace = await browserRequest(page, options.root);
  expect(workspace.status).toBe(200);
  expect(
    arrayProperty(workspace.body, "tasks").filter(
      (item) => objectValue(item, "id") === taskId,
    ),
  ).toEqual([current]);
  await assertDfirActivity(
    page,
    state.tenantId,
    options.subject.kind,
    options.subject.id,
    [
      "details_replaced",
      "assigned",
      "rescheduled",
      "checklist_replaced",
      "comments_replaced",
      "transitioned",
    ].map(
      (action) =>
        `${options.subject.kind === "case" ? "dfir" : "alert"}.task.${action}`,
    ),
  );
  return current;
}

async function exerciseDfirChildRelationship(
  page: Page,
  state: LiveAcceptanceState,
  options: DfirBundleOptions,
): Promise<void> {
  const relationshipId = uuidv7();
  const source = { kind: "ioc", id: options.indicatorId };
  const target = { kind: "asset", id: options.assetId };
  const createRequest: BrowserRequestOptions = {
    method: "POST",
    csrfToken: state.csrfToken,
    idempotencyKey: randomUUID(),
    json: {
      relationshipId,
      source,
      target,
      relationshipType: "observed_on",
      metadata: { source: "live-e2e" },
    },
  };
  const created = await browserRequest(
    page,
    `${options.root}/relationships`,
    createRequest,
  );
  expect(created.status).toBe(201);
  expect(created.body).toMatchObject({
    id: relationshipId,
    tenantId: state.tenantId,
    source,
    target,
    active: true,
    version: 1,
    retractions: [],
  });
  const replay = await browserRequest(
    page,
    `${options.root}/relationships`,
    createRequest,
  );
  expect(replay.status).toBe(201);
  expect(replay.body).toEqual(created.body);
  expect(replay.headers["x-idempotent-replay"]).toBe("true");
  let current = created.body;
  if (options.subject.kind === "case") {
    const path = `${options.root}/relationships/${relationshipId}/retract`;
    const retractionId = uuidv7();
    const reason = "Disproved the live IOC-to-asset association";
    const retractRequest: BrowserRequestOptions = {
      method: "POST",
      csrfToken: state.csrfToken,
      idempotencyKey: randomUUID(),
      ifMatch: '"v1"',
      json: { expectedVersion: 1, retractionId, reason },
    };
    const retracted = await browserRequest(page, path, retractRequest);
    expect(retracted.status).toBe(200);
    expect(retracted.headers.etag).toBe('"v2"');
    expect(retracted.body).toMatchObject({
      id: relationshipId,
      source,
      target,
      active: false,
      version: 2,
      retractions: [{ id: retractionId, reason, sequence: 1 }],
    });
    expect(arrayProperty(retracted.body, "retractions")).toHaveLength(1);
    const retractReplay = await browserRequest(page, path, retractRequest);
    expect(retractReplay.status).toBe(200);
    expect(retractReplay.body).toEqual(retracted.body);
    expect(retractReplay.headers["x-idempotent-replay"]).toBe("true");
    const historicalCreate = await browserRequest(
      page,
      `${options.root}/relationships`,
      createRequest,
    );
    expect(historicalCreate.status).toBe(201);
    expect(historicalCreate.body).toEqual(created.body);
    const stale = await browserRequest(page, path, {
      ...retractRequest,
      idempotencyKey: randomUUID(),
      json: { expectedVersion: 1, retractionId: uuidv7(), reason },
    });
    expect(stale.status).toBe(412);
    current = retracted.body;
    await assertDfirActivity(page, state.tenantId, "case", options.subject.id, [
      "dfir.relationship.retracted",
    ]);
    const audit = await browserRequest(
      page,
      `/api/v1/tenants/${state.tenantId}/audit-events?actionPrefix=dfir.relationship.retracted&limit=100`,
    );
    expect(audit.status).toBe(200);
    expect(
      arrayProperty(audit.body, "items").filter(
        (item) => objectValue(item, "resourceId") === relationshipId,
      ),
    ).toHaveLength(1);
  }
  const workspace = await browserRequest(page, options.root);
  expect(workspace.status).toBe(200);
  expect(workspace.body).toMatchObject({
    tenantId: state.tenantId,
    [`${options.subject.kind}Id`]: options.subject.id,
  });
  expect(
    arrayProperty(workspace.body, "relationships").filter(
      (item) => objectValue(item, "id") === relationshipId,
    ),
  ).toEqual([current]);
}

async function assertDfirActivity(
  page: Page,
  tenantId: string,
  rootKind: "alert" | "case",
  rootId: string,
  expectedKinds: readonly string[],
): Promise<void> {
  const activity = await browserRequest(
    page,
    `/api/v1/tenants/${tenantId}/${rootKind}s/${rootId}/activities?limit=100`,
  );
  expect(activity.status).toBe(200);
  const activityKinds = arrayProperty(activity.body, "items").map((item) =>
    objectValue(item, "kind"),
  );
  expect(activityKinds).toEqual(expect.arrayContaining([...expectedKinds]));
}

interface BrowserRequestOptions {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  csrfToken?: string;
  idempotencyKey?: string;
  ifMatch?: string;
  json?: unknown;
}

interface BrowserResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
  text: string;
}

async function browserRequest(
  page: Page,
  path: string,
  options: BrowserRequestOptions = {},
): Promise<BrowserResponse> {
  return page.evaluate(
    async ({ options: input, path: requestPath }) => {
      const headers = new Headers({ Accept: "application/json" });
      if (input.json !== undefined) {
        headers.set("Content-Type", "application/json");
      }
      if (input.csrfToken) headers.set("X-CSRF-Token", input.csrfToken);
      if (input.idempotencyKey) {
        headers.set("Idempotency-Key", input.idempotencyKey);
      }
      if (input.ifMatch) headers.set("If-Match", input.ifMatch);
      const response = await fetch(requestPath, {
        method: input.method ?? "GET",
        cache: "no-store",
        credentials: "same-origin",
        headers,
        ...(input.json === undefined
          ? {}
          : { body: JSON.stringify(input.json) }),
      });
      const text = await response.text();
      let body: unknown;
      try {
        body = text === "" ? undefined : JSON.parse(text);
      } catch {
        body = undefined;
      }
      return {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body,
        text,
      };
    },
    { options, path },
  );
}

async function installSession(
  context: BrowserContext,
  state: LiveAcceptanceState,
  value: string,
): Promise<void> {
  await context.addCookies([
    {
      name: state.cookieName,
      value,
      url: state.baseUrl,
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
    },
  ]);
}

function ticketExportBody(search: string): unknown {
  return {
    kind: "alert",
    comments: "none",
    source: {
      source: "inline",
      spec: {
        filters: {
          states: [],
          severities: [],
          priorities: [],
          queue: "all",
          search,
          custom: [],
        },
        sort: {
          source: "core",
          coreKey: "updated_at",
          direction: "desc",
          nulls: "last",
        },
        columns: [
          { source: "core", coreKey: "ticket", visible: true, pin: "start" },
        ],
      },
    },
    maximumRows: 10,
    maximumBytes: 1_048_576,
    retentionSeconds: 900,
  };
}

function itemIds(value: unknown): string[] {
  return arrayProperty(value, "items").map((item) => objectValue(item, "id"));
}

function commentBodies(value: unknown): string[] {
  return arrayProperty(value, "items").map((item) =>
    objectValue(item, "bodyMarkdown"),
  );
}

function itemIdentifiers(value: unknown, key: string): string[] {
  return arrayProperty(value, key).map((item) => objectValue(item, "id"));
}

function objectRecord(value: unknown, key: string): Record<string, unknown> {
  if (!isRecord(value) || !isRecord(value[key])) {
    throw new Error(`live response is missing object ${key}`);
  }
  return value[key];
}

function objectIdentifier(
  value: unknown,
  objectKey: string,
  idKey: string,
): string {
  const nested = isRecord(value) ? value[objectKey] : undefined;
  const target = Array.isArray(nested) ? nested[0] : nested;
  const identifier = objectValue(target, idKey);
  if (!uuidV7Pattern.test(identifier)) {
    throw new Error(`live response ${objectKey}.${idKey} is not UUIDv7`);
  }
  return identifier;
}

function objectValue(value: unknown, key: string): string {
  if (!isRecord(value) || typeof value[key] !== "string") {
    throw new Error(`live response is missing string ${key}`);
  }
  return value[key];
}

function numberValue(value: unknown, key: string): number {
  if (
    !isRecord(value) ||
    !Number.isSafeInteger(value[key]) ||
    (value[key] as number) < 0
  ) {
    throw new Error(`live response is missing non-negative integer ${key}`);
  }
  return value[key] as number;
}

function requiredUuidV7(value: unknown, label: string): string {
  if (typeof value !== "string" || !uuidV7Pattern.test(value)) {
    throw new Error(`${label} is not UUIDv7`);
  }
  return value;
}

function arrayProperty(value: unknown, key: string): unknown[] {
  if (!isRecord(value) || !Array.isArray(value[key])) {
    throw new Error(`live response is missing array ${key}`);
  }
  return value[key];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function uploadCapability(
  value: unknown,
  expectedSize: number,
): { headers: Record<string, string>; url: string } {
  const url = objectValue(value, "uploadUrl");
  const parsed = new URL(url);
  if (parsed.protocol !== "https:" || parsed.hostname !== "storage.localhost") {
    throw new Error("live upload capability did not target Compose storage");
  }
  const headers: Record<string, string> = {};
  const seen = new Set<string>();
  let contentLengthBound = false;
  let metadataBound = false;
  for (const item of arrayProperty(value, "headers")) {
    const name = objectValue(item, "name");
    const headerValue = objectValue(item, "value");
    const normalized = name.toLowerCase();
    if (seen.has(normalized)) {
      throw new Error("live upload capability contains duplicate headers");
    }
    seen.add(normalized);
    if (normalized === "content-length") {
      contentLengthBound = headerValue === String(expectedSize);
      continue;
    }
    if (normalized === "x-amz-meta-periapsis-expected-size") {
      metadataBound = headerValue === String(expectedSize);
    }
    headers[name] = headerValue;
  }
  if (!contentLengthBound || !metadataBound) {
    throw new Error(
      "live upload capability did not bind the exact object size",
    );
  }
  return { headers, url };
}

async function waitForTicketExport(
  page: Page,
  tenantId: string,
  jobId: string,
): Promise<unknown> {
  const deadline = Date.now() + 60_000;
  return poll();

  async function poll(): Promise<unknown> {
    const response = await browserRequest(
      page,
      `/api/v1/tenants/${tenantId}/ticket-exports/${jobId}?kind=alert`,
    );
    expect(response.status).toBe(200);
    const state = objectValue(response.body, "state");
    if (state === "succeeded") return response.body;
    if (state !== "pending" && state !== "running") {
      throw new Error(`live ticket export terminated as ${state}`);
    }
    if (Date.now() >= deadline) {
      throw new Error("live ticket export did not complete in time");
    }
    await page.waitForTimeout(500);
    return poll();
  }
}

async function pollWorkspace(
  page: Page,
  path: string,
  predicate: (workspace: unknown) => boolean,
): Promise<BrowserResponse> {
  const deadline = Date.now() + 60_000;
  return poll();

  async function poll(): Promise<BrowserResponse> {
    const response = await browserRequest(page, path);
    expect(response.status).toBe(200);
    if (predicate(response.body)) return response;
    if (Date.now() >= deadline) {
      throw new Error(
        "DFIR scanner did not publish the uploaded object in time",
      );
    }
    await page.waitForTimeout(500);
    return poll();
  }
}

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function uuidv7(): string {
  const bytes = randomBytes(16);
  let timestamp = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(timestamp & 0xffn);
    timestamp >>= 8n;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function loadOIDCAcceptanceEnvironment(): OIDCAcceptanceEnvironment {
  const value = {
    clientId: requiredLiveEnvironment("PERIAPSIS_LIVE_E2E_OIDC_CLIENT_ID"),
    fallbackPassword: requiredLiveEnvironment(
      "PERIAPSIS_LIVE_E2E_OIDC_FALLBACK_PASSWORD",
    ),
    fallbackUsername: requiredLiveEnvironment(
      "PERIAPSIS_LIVE_E2E_OIDC_FALLBACK_USERNAME",
    ),
    loginKey: requiredLiveEnvironment("PERIAPSIS_LIVE_E2E_OIDC_LOGIN_KEY"),
    issuer: requiredLiveEnvironment("PERIAPSIS_LIVE_E2E_OIDC_ISSUER"),
    tenantSlug: requiredLiveEnvironment("PERIAPSIS_LIVE_E2E_OIDC_TENANT_SLUG"),
    trustedPassword: requiredLiveEnvironment(
      "PERIAPSIS_LIVE_E2E_OIDC_TRUSTED_PASSWORD",
    ),
    trustedUsername: requiredLiveEnvironment(
      "PERIAPSIS_LIVE_E2E_OIDC_TRUSTED_USERNAME",
    ),
  };
  if (
    !validOIDCUsername(value.fallbackUsername) ||
    !validOIDCUsername(value.trustedUsername) ||
    value.fallbackUsername === value.trustedUsername ||
    !validOIDCPassword(value.fallbackPassword) ||
    !validOIDCPassword(value.trustedPassword) ||
    !/^periapsis-live-[a-z0-9]{8}$/u.test(value.clientId) ||
    !validOIDCIssuer(value.issuer) ||
    !/^[a-z][a-z0-9_-]{2,63}$/u.test(value.loginKey) ||
    !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(value.tenantSlug)
  ) {
    throw new Error("live OIDC acceptance environment is malformed");
  }
  return value;
}

function validOIDCIssuer(value: string): boolean {
  try {
    const issuer = new URL(value);
    return (
      issuer.protocol === "https:" &&
      issuer.username === "" &&
      issuer.password === "" &&
      issuer.search === "" &&
      issuer.hash === "" &&
      /^\/realms\/[a-z][a-z0-9-]{2,63}$/u.test(issuer.pathname) &&
      issuer.href === value
    );
  } catch {
    return false;
  }
}

function validOIDCUsername(value: string): boolean {
  return /^[a-z][a-z0-9-]{2,63}$/u.test(value);
}

function validOIDCPassword(value: string): boolean {
  return (
    value.length >= 16 && value.length <= 256 && !/[\p{Cc}\p{Cf}]/u.test(value)
  );
}

function requiredLiveEnvironment(name: string): string {
  const value = process.env[name];
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`${name} is required`);
  }
  return value;
}

function loadState(): LiveAcceptanceState {
  const stateFile = process.env["PERIAPSIS_LIVE_E2E_STATE_FILE"];
  if (!stateFile) {
    throw new Error("PERIAPSIS_LIVE_E2E_STATE_FILE is required");
  }
  const value = JSON.parse(
    readFileSync(stateFile, "utf8"),
  ) as Partial<LiveAcceptanceState>;
  const configuredBaseUrl = process.env["PERIAPSIS_LIVE_E2E_BASE_URL"];
  const stateOrigin = canonicalHTTPSOrigin(value.baseUrl);
  const configuredOrigin = canonicalHTTPSOrigin(configuredBaseUrl);
  const identifiers = [
    value.tenantId,
    value.operatorUserId,
    value.alertId,
    value.indicatorId,
    value.assetId,
    value.customerUserId,
    value.globexTenantId,
    value.slaPolicyId,
    value.oidcMappedRoleId,
    value.oidcSecurityGroupId,
  ];
  const opaqueTokens = [
    value.cookieValue,
    value.customerCookieValue,
    value.globexCookieValue,
    value.csrfToken,
    value.customerCSRFToken,
    value.globexCSRFToken,
  ];
  const boundedStateText = [
    value.alertTitle,
    value.caseTitle,
    value.customerPublicComment,
    value.operatorPrivateComment,
    value.operatorPublicComment,
    value.notificationOperatorSubject,
    value.notificationPrivateSubject,
    value.notificationPublicSubject,
  ];
  if (
    stateOrigin === null ||
    configuredOrigin === null ||
    stateOrigin !== configuredOrigin ||
    value.baseUrl !== stateOrigin ||
    value.cookieName !== "__Host-periapsis_session" ||
    !Number.isSafeInteger(value.alertVersion) ||
    (value.alertVersion ?? 0) < 1 ||
    opaqueTokens.some((token) => !opaqueToken(token)) ||
    boundedStateText.some((item) => !boundedTitle(item)) ||
    identifiers.some((identifier) => !uuidV7Pattern.test(identifier ?? ""))
  ) {
    throw new Error("live acceptance state is malformed");
  }
  return value as LiveAcceptanceState;
}

function opaqueToken(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{43}$/u.test(value);
}

async function requiredRequestHeader(
  request: Request,
  name: string,
): Promise<string> {
  const value = await request.headerValue(name);
  if (!value) throw new Error(`live escalation request is missing ${name}`);
  return value;
}

function canonicalHTTPSOrigin(value: unknown): string | null {
  if (typeof value !== "string") return null;
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      parsed.pathname === "/" &&
      parsed.search === "" &&
      parsed.hash === ""
      ? parsed.origin
      : null;
  } catch {
    return null;
  }
}

function boundedTitle(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    [...value].length <= 240 &&
    value.trim() === value &&
    !/[\p{Cc}\p{Cf}]/u.test(value)
  );
}
