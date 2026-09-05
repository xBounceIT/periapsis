import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import type {
  SessionView,
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import {
  ContactApiError,
  type ContactPortalApi,
} from "../contacts/contact-api";
import {
  contactTenantId,
  createContactPortalApi,
  portalAttachmentFixture,
  portalAttachmentId,
  portalAlertId,
  portalContactFixture,
  portalSafeCommentFixture,
} from "../contacts/contact-test-fixtures";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import {
  CustomerPortalPage,
  CustomerPortalWorkspace,
  formatNotificationWindows,
  parseNotificationWindows,
} from "./customer-portal-page";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("CustomerPortalWorkspace", () => {
  it("lists customer-visible attachments and prepares an expiring download", async () => {
    const preparePortalAttachmentDownload = vi.fn(async () => ({
      attachment: portalAttachmentFixture,
      downloadUrl:
        "https://downloads.example.invalid/customer-file?grant=opaque",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    }));
    renderWorkspace(
      createContactPortalApi({ preparePortalAttachmentDownload }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      false,
      false,
      true,
    );

    expect(
      await screen.findByRole("heading", { name: "Shared attachments" }),
    ).toBeVisible();
    expect(
      await screen.findByText("customer-incident-summary.pdf"),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Prepare download for customer-incident-summary.pdf",
      }),
    );

    await waitFor(() =>
      expect(preparePortalAttachmentDownload).toHaveBeenCalledTimes(1),
    );
    expect(preparePortalAttachmentDownload).toHaveBeenCalledWith({
      attachmentId: portalAttachmentId,
      csrfToken: "csrf-memory-only",
      kind: "alert",
      resourceId: portalAlertId,
      signal: expect.any(AbortSignal),
      tenantId: contactTenantId,
    });
    const download = await screen.findByRole("link", {
      name: "Download customer-incident-summary.pdf",
    });
    expect(download).toHaveAttribute(
      "href",
      "https://downloads.example.invalid/customer-file?grant=opaque",
    );
    expect(download).toHaveAttribute("referrerpolicy", "no-referrer");
    expect(download).toHaveAttribute("rel", "noreferrer noopener");
  });

  it("does not fetch attachments without the live attachment capability", async () => {
    const listPortalAttachments = vi.fn();
    renderWorkspace(
      createContactPortalApi({ listPortalAttachments }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
    );

    expect(await screen.findByText("Endpoint signal")).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Shared attachments" }),
    ).toBeNull();
    expect(listPortalAttachments).not.toHaveBeenCalled();
  });

  it("stops attachment pagination when a cursor cycle is returned", async () => {
    const listPortalAttachments = vi.fn(
      async ({ after }: { after?: string }) => {
        if (after === undefined) {
          return {
            items: [portalAttachmentFixture],
            nextCursor: "opaque_cursor_0001",
          };
        }
        if (after === "opaque_cursor_0001") {
          return {
            items: [
              {
                ...portalAttachmentFixture,
                id: "01991c20-7d5f-7000-8000-000000000009",
                originalFilename: "customer-timeline.pdf",
              },
            ],
            nextCursor: "opaque_cursor_0002",
          };
        }
        return {
          items: [
            {
              ...portalAttachmentFixture,
              id: "01991c20-7d5f-7000-8000-00000000000a",
              originalFilename: "customer-iocs.csv",
            },
          ],
          nextCursor: "opaque_cursor_0001",
        };
      },
    );
    renderWorkspace(
      createContactPortalApi({ listPortalAttachments }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      false,
      false,
      true,
    );

    await screen.findByText("customer-incident-summary.pdf");
    fireEvent.click(
      screen.getByRole("button", { name: "Load more attachments" }),
    );
    await screen.findByText("customer-timeline.pdf");
    fireEvent.click(
      screen.getByRole("button", { name: "Load more attachments" }),
    );
    await screen.findByText("customer-iocs.csv");

    expect(
      screen.queryByRole("button", { name: "Load more attachments" }),
    ).toBeNull();
    expect(listPortalAttachments).toHaveBeenCalledTimes(3);
  });

  it("hides cached attachment names while a live list reauthorization fails", async () => {
    const listPortalAttachments = vi
      .fn()
      .mockResolvedValueOnce({ items: [portalAttachmentFixture] })
      .mockRejectedValueOnce(new ContactApiError("Attachment access changed."));
    const queryClient = renderWorkspace(
      createContactPortalApi({ listPortalAttachments }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      false,
      false,
      true,
    );

    expect(
      await screen.findByText("customer-incident-summary.pdf"),
    ).toBeVisible();
    await queryClient.refetchQueries({
      queryKey: [
        "customer-portal-attachments",
        contactTenantId,
        "alert",
        portalAlertId,
      ],
    });

    expect(await screen.findByText("Attachments unavailable")).toBeVisible();
    expect(screen.queryByText("customer-incident-summary.pdf")).toBeNull();
  });

  it("downloads the exact customer-safe CSV returned by the portal API", async () => {
    const downloadPortalTicket = vi.fn(async () => ({
      blob: new Blob(["record_type,reference\r\nticket,ALT-42\r\n"], {
        type: "text/csv; charset=utf-8",
      }),
      filename: "periapsis-customer-alert.csv" as const,
    }));
    const createObjectURL = vi.fn(() => "blob:customer-portal-export");
    const revokeObjectURL = vi.fn();
    const NativeURL = globalThis.URL;
    class PortalExportURL extends NativeURL {
      static override createObjectURL = createObjectURL;
      static override revokeObjectURL = revokeObjectURL;
    }
    vi.stubGlobal("URL", PortalExportURL);
    let clickedDownload: string | undefined;
    let clickedHref: string | undefined;
    const click = vi
      .spyOn(HTMLAnchorElement.prototype, "click")
      .mockImplementation(() => {
        const anchor = document.body.querySelector("a[download]");
        if (anchor instanceof HTMLAnchorElement) {
          clickedDownload = anchor.download;
          clickedHref = anchor.href;
        }
      });
    renderWorkspace(
      createContactPortalApi({ downloadPortalTicket }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      true,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Download CSV" }),
    );

    await waitFor(() => expect(downloadPortalTicket).toHaveBeenCalledTimes(1));
    expect(downloadPortalTicket).toHaveBeenCalledWith({
      kind: "alert",
      resourceId: portalAlertId,
      tenantId: contactTenantId,
    });
    expect(createObjectURL).toHaveBeenCalledTimes(1);
    expect(click).toHaveBeenCalledTimes(1);
    expect(clickedDownload).toBe("periapsis-customer-alert.csv");
    expect(clickedHref).toBe("blob:customer-portal-export");
    await waitFor(() =>
      expect(revokeObjectURL).toHaveBeenCalledWith(
        "blob:customer-portal-export",
      ),
    );
  });

  it("does not offer an export without the live public-comment capability", async () => {
    const downloadPortalTicket = vi.fn();
    renderWorkspace(
      createContactPortalApi({ downloadPortalTicket }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
    );

    expect(await screen.findByText("Endpoint signal")).toBeVisible();
    expect(screen.queryByRole("button", { name: "Download CSV" })).toBeNull();
    expect(screen.queryByText("Public update")).toBeNull();
    expect(downloadPortalTicket).not.toHaveBeenCalled();
  });

  it("renders only Markdown from a public comment and ignores transport HTML", async () => {
    renderWorkspace(
      createContactPortalApi(),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      true,
    );

    expect(await screen.findByText("Public update")).toBeVisible();
    expect(screen.queryByText("unsafe transport field")).toBeNull();
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("Investigation started")).toBeVisible();
  });

  it("reuses the public-comment retry key after an ambiguous failure", async () => {
    const createPortalComment = vi
      .fn(
        async (
          input: Parameters<ContactPortalApi["createPortalComment"]>[0],
        ) => ({
          ...portalSafeCommentFixture,
          author: {
            audience: "customer" as const,
            displayName: "Ari Customer",
          },
          bodyMarkdown: input.bodyMarkdown,
          createdAt: "2026-08-25T10:00:00Z",
          id: "01991c20-7d5f-7000-8000-000000000009",
          origin: "customer_portal" as const,
          revision: 1,
          updatedAt: "2026-08-25T10:00:00Z",
        }),
      )
      .mockRejectedValueOnce(new TypeError("network response was lost"));
    renderWorkspace(
      createContactPortalApi({ createPortalComment }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      true,
    );

    fireEvent.change(await screen.findByLabelText("Add a public comment"), {
      target: { value: "Customer-visible update" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Send public comment" }),
    );

    await waitFor(() => expect(createPortalComment).toHaveBeenCalledTimes(1));
    fireEvent.click(
      screen.getByRole("button", { name: "Send public comment" }),
    );
    await waitFor(() => expect(createPortalComment).toHaveBeenCalledTimes(2));

    expect(createPortalComment).toHaveBeenLastCalledWith(
      expect.objectContaining({
        bodyMarkdown: "Customer-visible update",
        idempotencyKey: expect.stringMatching(/^[0-9a-f-]{36}$/u),
        kind: "alert",
        resourceId: portalAlertId,
      }),
    );
    expect(createPortalComment.mock.calls[0]?.[0].idempotencyKey).toBe(
      createPortalComment.mock.calls[1]?.[0].idempotencyKey,
    );
  });

  it("previews code-like HTML inertly and reports a server raw-HTML rejection", async () => {
    const previewPortalComment = vi
      .fn()
      .mockResolvedValueOnce({
        attachments: [],
        bodyMarkdown: "`<script>` is quoted evidence",
        visibility: "public" as const,
      })
      .mockRejectedValueOnce(
        new ContactApiError(
          "Raw HTML is not accepted in comments.",
          422,
          "validation_failed",
        ),
      );
    renderWorkspace(
      createContactPortalApi({ previewPortalComment }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      true,
    );

    const editor = await screen.findByLabelText("Add a public comment");
    fireEvent.change(editor, {
      target: { value: "`<script>` is quoted evidence" },
    });
    fireEvent.click(screen.getByRole("tab", { name: "Preview" }));
    expect(await screen.findByText("<script>")).toBeVisible();
    expect(document.querySelector("script, img, iframe, object")).toBeNull();

    fireEvent.click(screen.getByRole("tab", { name: "Write" }));
    fireEvent.change(screen.getByLabelText("Add a public comment"), {
      target: { value: "\u00a0leading whitespace" },
    });
    fireEvent.click(screen.getByRole("tab", { name: "Preview" }));
    expect(
      await screen.findByText(
        "Comments must contain at most 20000 valid Unicode characters.",
      ),
    ).toBeVisible();
    expect(previewPortalComment).toHaveBeenCalledTimes(1);

    fireEvent.click(screen.getByRole("tab", { name: "Write" }));
    fireEvent.change(screen.getByLabelText("Add a public comment"), {
      target: { value: "<script>alert(1)</script>" },
    });
    fireEvent.click(screen.getByRole("tab", { name: "Preview" }));
    expect(
      await screen.findByText("Raw HTML is not accepted in comments."),
    ).toBeVisible();
    expect(previewPortalComment).toHaveBeenLastCalledWith(
      expect.objectContaining({ bodyMarkdown: "<script>alert(1)</script>" }),
    );
    expect(document.querySelector("script, img, iframe, object")).toBeNull();
  });

  it("recovers a stale portal edit by refetching the comment and history", async () => {
    const editable = {
      ...portalSafeCommentFixture,
      author: { audience: "customer" as const, displayName: "Ari Customer" },
      canEdit: true,
      editableUntil: "2099-08-25T09:35:00Z",
      origin: "customer_portal" as const,
    };
    const fresh = {
      ...editable,
      bodyMarkdown: "Fresh server correction",
      revision: 2,
      updatedAt: "2026-08-25T09:25:00Z",
    };
    const listPortalComments = vi
      .fn()
      .mockResolvedValueOnce({ items: [editable] })
      .mockResolvedValue({ items: [fresh] });
    const listPortalCommentRevisions = vi.fn(async () => ({ items: [] }));
    const editPortalComment = vi.fn(async () => {
      throw new ContactApiError(
        "The comment changed.",
        412,
        "precondition_failed",
      );
    });
    renderWorkspace(
      createContactPortalApi({
        editPortalComment,
        listPortalCommentRevisions,
        listPortalComments,
      }),
      `/portal?kind=alert&ticket=${portalAlertId}`,
      true,
    );

    expect(await screen.findByText("Public update")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const editor = await screen.findByLabelText("Comment");
    fireEvent.change(editor, { target: { value: "Local correction" } });
    fireEvent.click(screen.getByRole("button", { name: "Save correction" }));

    await waitFor(() => expect(editPortalComment).toHaveBeenCalledTimes(1));
    expect(editPortalComment).toHaveBeenCalledWith(
      expect.objectContaining({
        bodyMarkdown: "Local correction",
        commentId: editable.id,
        etag: '"comment-r1"',
        idempotencyKey: expect.any(String),
      }),
    );
    expect(
      await screen.findByText(
        "This comment changed on the server. Review the latest revision before retrying.",
      ),
    ).toBeVisible();
    expect(screen.getByLabelText("Comment")).toHaveValue(
      "Fresh server correction",
    );
    expect(listPortalComments).toHaveBeenCalledTimes(2);
    expect(listPortalCommentRevisions).toHaveBeenCalledTimes(2);
  });

  it("reuses the preference retry key while the body and ETag are unchanged", async () => {
    const replacePortalPreferences = vi
      .fn(async (_input: { idempotencyKey: string }) => ({
        etag: '"v2"',
        value: { ...portalContactFixture, version: 2 },
      }))
      .mockRejectedValueOnce(new TypeError("network response was lost"));
    renderWorkspace(
      createContactPortalApi({ replacePortalPreferences }),
      "/portal",
      false,
      true,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Contact preferences" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Save preferences" }),
    );
    await waitFor(() =>
      expect(replacePortalPreferences).toHaveBeenCalledTimes(1),
    );
    fireEvent.click(screen.getByRole("button", { name: "Save preferences" }));
    await waitFor(() =>
      expect(replacePortalPreferences).toHaveBeenCalledTimes(2),
    );

    expect(replacePortalPreferences.mock.calls[0]?.[0].idempotencyKey).toBe(
      replacePortalPreferences.mock.calls[1]?.[0].idempotencyKey,
    );
  });
});

describe("notification window parsing", () => {
  it("canonicalizes ISO weekday windows and round-trips their local wall time", () => {
    const parsed = parseNotificationWindows("2 13:30-17:00\n1 09:00-12:00");
    expect(parsed).toEqual([
      { endMinute: 720, isoWeekday: 1, startMinute: 540 },
      { endMinute: 1020, isoWeekday: 2, startMinute: 810 },
    ]);
    expect(formatNotificationWindows(parsed)).toBe(
      "1 09:00-12:00\n2 13:30-17:00",
    );
  });

  it.each([
    ["1 17:00-09:00", /end after it starts/u],
    ["1 09:00-12:00\n1 11:59-13:00", /overlap/u],
    ["0 09:00-12:00", /weekday HH:MM/u],
    ["1 24:00-25:00", /valid local wall-clock/u],
  ])("rejects unsafe window input %s", (value, message) => {
    expect(() => parseNotificationWindows(value)).toThrow(message);
  });
});

describe("CustomerPortalPage authorization", () => {
  it("denies a deep link when only the session claim contains a portal permission", async () => {
    const listPortalTickets = vi.fn();
    renderPortalPage(
      createContactPortalApi({ listPortalTickets }),
      [],
      ["portal.alert.read"],
    );

    expect(
      await screen.findByRole("heading", {
        name: "Customer portal unavailable.",
      }),
    ).toBeVisible();
    expect(listPortalTickets).not.toHaveBeenCalled();
  });

  it("uses the exact live attachment permission instead of session claims", async () => {
    const listPortalAttachments = vi.fn(async () => ({
      items: [portalAttachmentFixture],
    }));
    renderPortalPage(
      createContactPortalApi({ listPortalAttachments }),
      ["portal.alert.read", "portal.attachment.read"],
      [],
    );

    expect(
      await screen.findByText("customer-incident-summary.pdf"),
    ).toBeVisible();
    expect(listPortalAttachments).toHaveBeenCalledTimes(1);
  });

  it("does not treat a stale session attachment claim as live authority", async () => {
    const listPortalAttachments = vi.fn();
    renderPortalPage(
      createContactPortalApi({ listPortalAttachments }),
      ["portal.alert.read"],
      ["portal.attachment.read"],
    );

    expect(await screen.findByText("Endpoint signal")).toBeVisible();
    expect(
      screen.queryByRole("heading", { name: "Shared attachments" }),
    ).toBeNull();
    expect(listPortalAttachments).not.toHaveBeenCalled();
  });
});

function renderPortalPage(
  api: ReturnType<typeof createContactPortalApi>,
  livePermissions: readonly TenantPermissionKeyView[],
  sessionPermissions: readonly TenantPermissionKeyView[],
): void {
  const phaseTwoApi = createPhaseTwoApi({
    getTenantAuthority: async () => authorityFixture(livePermissions),
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const session: SessionView = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-25T12:00:00Z",
    activeTenantId: contactTenantId,
    idleExpiresAt: "2099-08-25T11:00:00Z",
    permissions: [...sessionPermissions],
  };

  render(
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api: phaseTwoApi,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: vi.fn(),
        }}
      >
        <TenantAuthorityProvider>
          <MemoryRouter
            initialEntries={[`/portal?kind=alert&ticket=${portalAlertId}`]}
          >
            <CustomerPortalPage api={api} />
          </MemoryRouter>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
}

function renderWorkspace(
  api: ReturnType<typeof createContactPortalApi>,
  route: string,
  canComment = false,
  canManagePreferences = false,
  canReadAttachments = false,
): QueryClient {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const livePermissions: TenantPermissionKeyView[] = ["portal.alert.read"];
  if (canComment) livePermissions.push("portal.comment.public");
  if (canManagePreferences)
    livePermissions.push("portal.contact.preference.manage");
  if (canReadAttachments) livePermissions.push("portal.attachment.read");
  const phaseTwoApi = createPhaseTwoApi({
    getTenantAuthority: async () => authorityFixture(livePermissions),
  });
  const session: SessionView = {
    ...sessionFixture,
    absoluteExpiresAt: "2099-08-25T12:00:00Z",
    activeTenantId: contactTenantId,
    idleExpiresAt: "2099-08-25T11:00:00Z",
  };
  render(
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api: phaseTwoApi,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session,
          updateSession: vi.fn(),
        }}
      >
        <TenantAuthorityProvider>
          <MemoryRouter initialEntries={[route]}>
            <CustomerPortalWorkspace
              api={api}
              canComment={canComment}
              canManagePreferences={canManagePreferences}
              canReadAttachments={canReadAttachments}
              canReadAlerts
              canReadCases={false}
              csrfToken="csrf-memory-only"
              tenantId={contactTenantId}
            />
          </MemoryRouter>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
  return queryClient;
}

function authorityFixture(
  permissionKeys: readonly TenantPermissionKeyView[],
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-25T10:00:00Z",
    legacyMembershipRole: "customer_user",
    membershipId: "01991c20-7d5f-7000-8000-000000000010",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissionKeys.map((permissionKey) => ({
      permissionKey,
      scope: "own",
    })),
    roleGrants: [],
    tenantId: contactTenantId,
    userId: sessionFixture.user.id,
  };
}
