import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  NotificationApiError,
  type NotificationAdminApi,
} from "./notification-api";
import {
  createNotificationApiMock,
  deliveryFixture,
  fixtureTenantId,
  notificationRuleFixture,
  notificationTemplateFixture,
  smtpFixture,
  webhookFixture,
  webhookUrlPolicyFixture,
} from "./notification-test-fixtures";
import { TenantNotificationWorkspace } from "./notification-workspace";
import { PlatformSmtpWorkspace } from "./smtp-panel";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("TenantNotificationWorkspace", () => {
  it("preserves the focused webhook rule when an earlier rule is removed", async () => {
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock()}
        canManage
        csrfToken="csrf"
        initialPanel="egress-policy"
        tenantId={fixtureTenantId}
      />,
    );
    await screen.findByRole("heading", { name: "Publish version 2" });
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));
    const hostname = screen.getAllByLabelText("DNS hostname")[1]!;
    fireEvent.change(hostname, { target: { value: "retained.example.test" } });
    hostname.focus();
    fireEvent.click(screen.getByRole("button", { name: "Remove rule 1" }));
    expect(screen.getByLabelText("DNS hostname")).toBe(hostname);
    expect(hostname).toHaveFocus();
    expect(hostname).toHaveValue("retained.example.test");
  });

  it("denies by default without treating UI visibility as server authority", () => {
    const listRules = vi.fn<NotificationAdminApi["listRules"]>();
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({ listRules })}
        canManage={false}
        csrfToken="csrf"
        tenantId={fixtureTenantId}
      />,
    );
    expect(
      screen.getByText("Notification authority required"),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/revalidated by the tenant API/u),
    ).toBeInTheDocument();
    expect(listRules).not.toHaveBeenCalled();
  });

  it("creates and versions rules with payload-stable retry identity and strong ETags", async () => {
    const createRule = vi.fn<NotificationAdminApi["createRule"]>(async () => ({
      etag: '"v1"',
      value: notificationRuleFixture,
    }));
    const versionRule = vi.fn<NotificationAdminApi["versionRule"]>(
      async () => ({
        etag: '"v2"',
        value: { ...notificationRuleFixture, name: "Version two", version: 2 },
      }),
    );
    const api = createNotificationApiMock({
      createRule,
      listRules: async () => ({ items: [] }),
      versionRule,
    });
    const view = render(
      <TenantNotificationWorkspace
        api={api}
        canManage
        csrfToken="csrf"
        tenantId={fixtureTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Create rule" }));
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Critical dispatch" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "Route critical alerts" },
    });
    fireEvent.change(screen.getByLabelText("Template ID"), {
      target: { value: notificationRuleFixture.templateId },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Create rule" }).at(-1)!,
    );
    await waitFor(() => expect(createRule).toHaveBeenCalledTimes(1));
    expect(createRule.mock.calls[0]?.[0].idempotencyKey).toMatch(
      /^[0-9a-f-]{36}$/u,
    );

    view.unmount();
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({ versionRule })}
        canManage
        csrfToken="csrf"
        tenantId={fixtureTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Version" }));
    await screen.findByRole("heading", { name: "Append version 2" });
    fireEvent.change(screen.getByLabelText("Name"), {
      target: { value: "Version two" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Append version" }));
    await waitFor(() => expect(versionRule).toHaveBeenCalledTimes(1));
    expect(versionRule.mock.calls[0]?.[0]).toMatchObject({
      etag: '"v1"',
      id: notificationRuleFixture.id,
    });
  });

  it("requires explicit acknowledgement before retrying an uncertain submission", async () => {
    const retryDelivery = vi.fn<NotificationAdminApi["retryDelivery"]>(
      async () => ({
        ...deliveryFixture,
        id: `${deliveryFixture.id}-retry`,
        parentDeliveryId: deliveryFixture.id,
        status: "queued",
        attemptCount: 0,
      }),
    );
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({ retryDelivery })}
        canManage
        csrfToken="csrf"
        initialPanel="deliveries"
        tenantId={fixtureTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Inspect" }));
    const retry = await screen.findByRole("button", { name: "Create retry" });
    fireEvent.change(screen.getByLabelText("Audited reason"), {
      target: { value: "Operator reviewed provider logs" },
    });
    expect(retry).toBeDisabled();
    fireEvent.click(
      screen.getByRole("checkbox", {
        name: /provider may already have accepted/u,
      }),
    );
    expect(retry).toBeEnabled();
    fireEvent.click(retry);
    await waitFor(() => expect(retryDelivery).toHaveBeenCalledTimes(1));
    expect(retryDelivery.mock.calls[0]?.[0].body).toEqual({
      acknowledgeUncertainSubmission: true,
      expectedAttempt: 2,
      reason: "Operator reviewed provider logs",
    });
  });

  it("wires template preview, duplicate, rollback, and test-send to the current version", async () => {
    const previewTemplate = vi.fn<NotificationAdminApi["previewTemplate"]>(
      async () => ({
        subject: "Sandbox preview",
        html: "<p>Preview</p>",
        plainText: "Preview",
      }),
    );
    const duplicateTemplate = vi.fn<NotificationAdminApi["duplicateTemplate"]>(
      async () => ({
        etag: '"v1"',
        value: {
          ...notificationTemplateFixture,
          id: `${notificationTemplateFixture.id}-copy`,
          key: "critical-alert-copy",
          name: "Critical alert copy",
        },
      }),
    );
    const rollbackTemplate = vi.fn<NotificationAdminApi["rollbackTemplate"]>(
      async () => ({
        etag: '"v2"',
        value: { ...notificationTemplateFixture, version: 2 },
      }),
    );
    const testTemplate = vi.fn<NotificationAdminApi["testTemplate"]>(
      async () => deliveryFixture,
    );
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({
          duplicateTemplate,
          previewTemplate,
          rollbackTemplate,
          testTemplate,
        })}
        canManage
        csrfToken="csrf"
        initialPanel="templates"
        tenantId={fixtureTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Open" }));
    await screen.findByRole("heading", { name: "Edit version 1" });
    fireEvent.click(screen.getByRole("button", { name: "Preview draft" }));
    expect(
      await screen.findByTitle("Isolated template preview"),
    ).toHaveAttribute("sandbox", "");
    expect(previewTemplate).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("button", { name: "Duplicate" }));
    await waitFor(() => expect(duplicateTemplate).toHaveBeenCalledTimes(1));
    expect(duplicateTemplate.mock.calls[0]?.[0].body.sourceVersion).toBe(1);

    fireEvent.change(screen.getByLabelText("Audited reason"), {
      target: { value: "Restore approved wording" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Roll back" }));
    await waitFor(() => expect(rollbackTemplate).toHaveBeenCalledTimes(1));
    expect(rollbackTemplate.mock.calls[0]?.[0].etag).toBe('"v1"');

    fireEvent.change(screen.getByLabelText("Test recipient"), {
      target: { value: "operator@example.test" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send test" }));
    await waitFor(() => expect(testTemplate).toHaveBeenCalledTimes(1));
    expect(testTemplate.mock.calls[0]?.[0].body).toMatchObject({
      recipient: "operator@example.test",
      version: 2,
    });
  });

  it("creates a tenant SMTP override without reusing the platform fallback ETag and clears the password", async () => {
    const inherited = {
      ...smtpFixture,
      tenantId: null,
      inheritedFromGlobal: true,
    };
    const putTenantSmtp = vi.fn<NotificationAdminApi["putTenantSmtp"]>(
      async () => ({
        etag: '"v1"',
        value: smtpFixture,
      }),
    );
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({
          getTenantSmtp: async () => ({
            etag: '"v4"',
            value: { ...inherited, version: 4 },
          }),
          putTenantSmtp,
        })}
        canManage
        csrfToken="csrf"
        initialPanel="smtp"
        tenantId={fixtureTenantId}
      />,
    );
    expect(await screen.findByText("Platform fallback")).toBeInTheDocument();
    const password = screen.getByLabelText("New password");
    fireEvent.change(password, { target: { value: "write-only-password" } });
    fireEvent.click(screen.getByRole("button", { name: "Create override" }));
    await waitFor(() => expect(putTenantSmtp).toHaveBeenCalledTimes(1));
    expect(putTenantSmtp.mock.calls[0]?.[0]).not.toHaveProperty("etag");
    expect(putTenantSmtp.mock.calls[0]?.[0].body.password).toBe(
      "write-only-password",
    );
    await waitFor(() => expect(password).toHaveValue(""));
  });

  it("rotates a webhook signing key through a write-only field", async () => {
    const versionWebhook = vi.fn<NotificationAdminApi["versionWebhook"]>(
      async () => ({
        etag: '"v2"',
        value: { ...webhookFixture, signingKeyVersion: 2, version: 2 },
      }),
    );
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({ versionWebhook })}
        canManage
        csrfToken="csrf"
        initialPanel="webhooks"
        tenantId={fixtureTenantId}
      />,
    );
    fireEvent.click(await screen.findByRole("button", { name: "Version" }));
    await screen.findByRole("heading", { name: "Append version 2" });
    const key = screen.getByLabelText("New signing key");
    fireEvent.change(key, { target: { value: "write-only-signing-key" } });
    fireEvent.click(screen.getByRole("button", { name: "Append version" }));
    await waitFor(() => expect(versionWebhook).toHaveBeenCalledTimes(1));
    expect(versionWebhook.mock.calls[0]?.[0].body.signingKey).toBe(
      "write-only-signing-key",
    );
    await waitFor(() => expect(key).toHaveValue(""));
  });

  it("previews and publishes an immutable webhook egress policy under the current strong fence", async () => {
    const publishWebhookUrlPolicy = vi.fn<
      NotificationAdminApi["publishWebhookUrlPolicy"]
    >(async () => ({
      etag: '"v2"',
      value: {
        ...webhookUrlPolicyFixture,
        version: 2,
        versionId: "01991c20-7d5f-7000-8000-000000000063",
        rules: [
          ...webhookUrlPolicyFixture.rules,
          {
            effect: "deny" as const,
            match: "exact" as const,
            hostname: "blocked.example.test",
            port: 443,
          },
        ].toSorted((left, right) =>
          `${left.effect}\0${left.match}\0${left.hostname}\0${left.port}`.localeCompare(
            `${right.effect}\0${right.match}\0${right.hostname}\0${right.port}`,
          ),
        ),
      },
      replayed: false,
    }));
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({ publishWebhookUrlPolicy })}
        canManage
        csrfToken="csrf"
        initialPanel="egress-policy"
        tenantId={fixtureTenantId}
      />,
    );

    await screen.findByRole("heading", { name: "Publish version 2" });
    fireEvent.click(screen.getByRole("button", { name: "Add rule" }));
    const effects = screen.getAllByLabelText("Effect");
    const hostnames = screen.getAllByLabelText("DNS hostname");
    fireEvent.change(effects[1]!, { target: { value: "deny" } });
    fireEvent.change(hostnames[1]!, {
      target: { value: "blocked.example.test" },
    });
    fireEvent.change(screen.getByLabelText("HTTPS endpoint"), {
      target: { value: "https://blocked.example.test/" },
    });
    expect(await screen.findByText("Deny rule 2 matched.")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Audited reason"), {
      target: { value: "Block retired webhook destination" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Publish next version" }),
    );

    await waitFor(() =>
      expect(publishWebhookUrlPolicy).toHaveBeenCalledTimes(1),
    );
    expect(publishWebhookUrlPolicy.mock.calls[0]?.[0]).toMatchObject({
      auditReason: "Block retired webhook destination",
      body: { expectedVersion: 1 },
      csrfToken: "csrf",
      etag: '"v1"',
      tenantId: fixtureTenantId,
    });
    expect(publishWebhookUrlPolicy.mock.calls[0]?.[0].idempotencyKey).toMatch(
      /^[0-9a-f-]{36}$/u,
    );
    expect(
      await screen.findByText(
        /Existing webhook configurations must be versioned/u,
      ),
    ).toBeInTheDocument();
  });

  it("reloads live policy state instead of treating an older immutable replay as current", async () => {
    const current = {
      etag: '"v3"',
      value: {
        ...webhookUrlPolicyFixture,
        version: 3,
        versionId: "01991c20-7d5f-7000-8000-000000000064",
      },
    };
    const getWebhookUrlPolicy = vi
      .fn<NotificationAdminApi["getWebhookUrlPolicy"]>()
      .mockResolvedValueOnce({
        etag: '"v1"',
        value: webhookUrlPolicyFixture,
      })
      .mockResolvedValue(current);
    const publishWebhookUrlPolicy = vi.fn<
      NotificationAdminApi["publishWebhookUrlPolicy"]
    >(async () => ({
      etag: '"v2"',
      value: {
        ...webhookUrlPolicyFixture,
        version: 2,
        versionId: "01991c20-7d5f-7000-8000-000000000063",
      },
      replayed: true,
    }));
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({
          getWebhookUrlPolicy,
          publishWebhookUrlPolicy,
        })}
        canManage
        csrfToken="csrf"
        initialPanel="egress-policy"
        tenantId={fixtureTenantId}
      />,
    );
    await screen.findByRole("heading", { name: "Publish version 2" });
    fireEvent.change(screen.getByLabelText("Audited reason"), {
      target: { value: "Retry reviewed publication" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Publish next version" }),
    );

    expect(
      await screen.findByText(/current version 3 was reloaded/u),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { name: "Publish version 4" }),
    ).toBeInTheDocument();
    expect(getWebhookUrlPolicy).toHaveBeenCalledTimes(2);
  });

  it("keeps policy publication disabled when live policy state cannot be loaded", async () => {
    const publishWebhookUrlPolicy =
      vi.fn<NotificationAdminApi["publishWebhookUrlPolicy"]>();
    render(
      <TenantNotificationWorkspace
        api={createNotificationApiMock({
          getWebhookUrlPolicy: async () => {
            throw new NotificationApiError("Policy source unavailable", 503);
          },
          publishWebhookUrlPolicy,
        })}
        canManage
        csrfToken="csrf"
        initialPanel="egress-policy"
        tenantId={fixtureTenantId}
      />,
    );
    expect(
      await screen.findByText("Policy source unavailable"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Publish initial policy" }),
    ).toBeDisabled();
    expect(publishWebhookUrlPolicy).not.toHaveBeenCalled();
  });
});

describe("PlatformSmtpWorkspace", () => {
  it("exposes health-only testing with no recipient field", async () => {
    const testPlatformSmtp = vi.fn<NotificationAdminApi["testPlatformSmtp"]>(
      async () => ({
        configurationId: smtpFixture.id,
        configurationVersion: 1,
        healthy: true,
        checkedAt: "2026-08-25T10:00:00Z",
        checks: [{ kind: "connect", outcome: "passed" }],
      }),
    );
    render(
      <PlatformSmtpWorkspace
        api={createNotificationApiMock({ testPlatformSmtp })}
        canManage
        csrfToken="csrf"
      />,
    );
    await screen.findByRole("heading", { name: "SMTP settings" });
    expect(
      screen.queryByLabelText("Optional test recipient"),
    ).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Audited reason"), {
      target: { value: "Release readiness" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run health check" }));
    await waitFor(() => expect(testPlatformSmtp).toHaveBeenCalledTimes(1));
    expect(testPlatformSmtp.mock.calls[0]?.[0].body).toEqual({
      configurationVersion: 1,
      reason: "Release readiness",
    });
    expect(testPlatformSmtp.mock.calls[0]?.[0].body).not.toHaveProperty(
      "recipient",
    );
  });
});
