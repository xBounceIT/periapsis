import { afterEach, describe, expect, it, vi } from "vitest";

import { ContactApiError, contactPortalApi } from "./contact-api";
import {
  contactTenantId,
  portalAttachmentFixture,
  portalAttachmentId,
  portalAlertFixture,
  portalAlertId,
  portalCommentFixture,
  portalContactFixture,
} from "./contact-test-fixtures";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("contactPortalApi", () => {
  it.each([
    ["alert", "alerts"],
    ["case", "cases"],
  ] as const)(
    "lists a bounded no-store %s attachment page through the generated route",
    async (kind, pathKind) => {
      const requests: Request[] = [];
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL) => {
          if (input instanceof Request) requests.push(input);
          return attachmentJsonResponse({
            items: [
              {
                ...portalAttachmentFixture,
                resourceKind: kind,
              },
            ],
            nextCursor: "opaque_cursor_0001",
          });
        }),
      );

      const page = await contactPortalApi.listPortalAttachments({
        after: "opaque_cursor_0000",
        kind,
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      });

      expect(page.items).toHaveLength(1);
      expect(page.nextCursor).toBe("opaque_cursor_0001");
      expect(requests).toHaveLength(1);
      expect(requests[0]?.method).toBe("GET");
      expect(requests[0]?.cache).toBe("no-store");
      const url = new URL(requests[0]!.url);
      expect(url.pathname).toBe(
        `/api/v1/tenants/${contactTenantId}/portal/${pathKind}/${portalAlertId}/dfir/attachments`,
      );
      expect(url.searchParams.get("after")).toBe("opaque_cursor_0000");
      expect(url.searchParams.get("limit")).toBe("50");
    },
  );

  it("prepares a path-bound attachment download without sending a subject or storage ID", async () => {
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return attachmentJsonResponse(
          {
            attachment: portalAttachmentFixture,
            downloadUrl:
              "https://downloads.example.invalid/customer-file?grant=opaque",
            expiresAt,
          },
          true,
        );
      }),
    );

    const prepared = await contactPortalApi.preparePortalAttachmentDownload({
      attachmentId: portalAttachmentId,
      csrfToken: "csrf-memory-only",
      kind: "alert",
      resourceId: portalAlertId,
      tenantId: contactTenantId,
    });

    expect(prepared.attachment.id).toBe(portalAttachmentId);
    expect(requests).toHaveLength(1);
    expect(requests[0]?.method).toBe("POST");
    expect(requests[0]?.cache).toBe("no-store");
    expect(requests[0]?.redirect).toBe("error");
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(await requests[0]!.text()).toBe("");
    expect(new URL(requests[0]!.url).pathname).toBe(
      `/api/v1/tenants/${contactTenantId}/portal/alerts/${portalAlertId}/dfir/attachments/${portalAttachmentId}/prepare-download`,
    );
  });

  it("rejects operator attachment fields before they can reach the portal UI", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        attachmentJsonResponse({
          items: [
            {
              ...portalAttachmentFixture,
              storageObjectId: "01991c20-7d5f-7000-8000-000000000099",
            },
          ],
        }),
      ),
    );

    await expect(
      contactPortalApi.listPortalAttachments({
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it.each([
    [
      "top-level metadata",
      {
        items: [portalAttachmentFixture],
        storageObjectId: "01991c20-7d5f-7000-8000-000000000099",
      },
    ],
    [
      "a repeated cursor",
      {
        items: [portalAttachmentFixture],
        nextCursor: "opaque_cursor_0000",
      },
    ],
    [
      "a cursor on an empty page",
      { items: [], nextCursor: "opaque_cursor_0001" },
    ],
    [
      "duplicate attachment identities",
      { items: [portalAttachmentFixture, portalAttachmentFixture] },
    ],
  ])("rejects attachment pages containing %s", async (_label, page) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(attachmentJsonResponse(page)),
    );

    await expect(
      contactPortalApi.listPortalAttachments({
        after: "opaque_cursor_0000",
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a non-canonical attachment cursor before issuing a request", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      contactPortalApi.listPortalAttachments({
        after: "not a cursor",
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toBeInstanceOf(ContactApiError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects a prepared capability without the no-referrer response boundary", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        attachmentJsonResponse({
          attachment: portalAttachmentFixture,
          downloadUrl:
            "https://downloads.example.invalid/customer-file?grant=opaque",
          expiresAt: new Date(Date.now() + 60_000).toISOString(),
        }),
      ),
    );

    await expect(
      contactPortalApi.preparePortalAttachmentDownload({
        attachmentId: portalAttachmentId,
        csrfToken: "csrf-memory-only",
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it.each([
    ["a script URL", "javascript:alert(1)", 60_000],
    [
      "embedded credentials",
      "https://user:secret@downloads.example.invalid/customer-file",
      60_000,
    ],
    [
      "a fragment",
      "https://downloads.example.invalid/customer-file#grant",
      60_000,
    ],
    [
      "an overlong lifetime",
      "https://downloads.example.invalid/customer-file?grant=opaque",
      7 * 60_000,
    ],
  ])("rejects a prepared capability with %s", async (_label, url, lifetime) => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        attachmentJsonResponse(
          {
            attachment: portalAttachmentFixture,
            downloadUrl: url,
            expiresAt: new Date(Date.now() + lifetime).toISOString(),
          },
          true,
        ),
      ),
    );

    await expect(
      contactPortalApi.preparePortalAttachmentDownload({
        attachmentId: portalAttachmentId,
        csrfToken: "csrf-memory-only",
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it.each([
    ["alert", "alerts", "periapsis-customer-alert.csv"],
    ["case", "cases", "periapsis-customer-case.csv"],
  ] as const)(
    "downloads a bounded %s CSV through the generated customer route",
    async (kind, pathKind, filename) => {
      const requests: Request[] = [];
      vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL) => {
          if (input instanceof Request) requests.push(input);
          return csvResponse(
            "record_type,reference\r\nticket,ALT-42\r\n",
            filename,
            kind === "case" ? "private, no-store" : "no-store",
          );
        }),
      );

      const file = await contactPortalApi.downloadPortalTicket({
        kind,
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      });

      expect(file.filename).toBe(filename);
      expect(await file.blob.text()).toContain("ticket,ALT-42");
      expect(requests).toHaveLength(1);
      expect(requests[0]?.method).toBe("GET");
      expect(requests[0]?.cache).toBe("no-store");
      expect(new URL(requests[0]!.url).pathname).toBe(
        `/api/v1/tenants/${contactTenantId}/portal/${pathKind}/${portalAlertId}/export`,
      );
    },
  );

  it("rejects an export whose download headers drift from the closed contract", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          csvResponse(
            "record_type,reference\r\nticket,ALT-42\r\n",
            "private-operator-notes.csv",
          ),
        ),
    );

    await expect(
      contactPortalApi.downloadPortalTicket({
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("maps the bounded synchronous export limit without reflecting problem detail", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            code: "export_too_large",
            detail: "private comment body must not be reflected",
            requestId: "request-1",
            status: 413,
            title: "Export too large",
            type: "about:blank",
          },
          undefined,
          413,
        ),
      ),
    );

    await expect(
      contactPortalApi.downloadPortalTicket({
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({
      message:
        "This incident has too many public updates for a synchronous download.",
      status: 413,
    });
  });

  it("rejects an operator-only field in a customer ticket projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            {
              ...portalAlertFixture,
              assignment: { assigneeUserId: "private-user" },
            },
          ],
        }),
      ),
    );

    await expect(
      contactPortalApi.listPortalTickets({
        kind: "alert",
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("rejects a private comment before it can reach the customer UI", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [{ ...portalCommentFixture, visibility: "private" }],
        }),
      ),
    );

    await expect(
      contactPortalApi.listPortalComments({
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("keeps portal comment lists no-store and rejects duplicate page items", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        if (requests.length === 1) {
          return jsonResponse({ items: [portalCommentFixture] });
        }
        if (requests.length === 2) {
          return jsonResponse({
            items: [portalCommentFixture, portalCommentFixture],
          });
        }
        return jsonResponse({
          items: [portalCommentFixture],
          nextCursor: "not-a-cursor",
        });
      }),
    );

    const input = {
      kind: "alert" as const,
      resourceId: portalAlertId,
      tenantId: contactTenantId,
    };
    await expect(
      contactPortalApi.listPortalComments(input),
    ).resolves.toMatchObject({
      items: [{ id: portalCommentFixture.id }],
    });
    await expect(
      contactPortalApi.listPortalComments(input),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      contactPortalApi.listPortalComments(input),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
    await expect(
      contactPortalApi.listPortalComments({ ...input, after: "not-a-cursor" }),
    ).rejects.toBeInstanceOf(ContactApiError);

    expect(requests).toHaveLength(3);
    expect(requests[0]?.cache).toBe("no-store");
  });

  it("rejects incoherent portal comment authors and timestamps", async () => {
    const editable = {
      ...portalCommentFixture,
      author: { audience: "customer", displayName: "Ari Customer" },
      canEdit: true,
      origin: "customer_portal",
    } as const;
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({ items: [{ ...editable, origin: "api" }] }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...editable,
                author: {
                  audience: "operator",
                  displayName: "Incident team",
                },
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...portalCommentFixture,
                author: {
                  audience: "operator",
                  displayName: "Incident team",
                },
                origin: "customer_portal",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...portalCommentFixture,
                updatedAt: "2026-08-25T09:19:59Z",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...portalCommentFixture,
                updatedAt: "2026-08-25T09:35:01Z",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...portalCommentFixture,
                createdAt: "2026-08-25T09:20:00.000000001Z",
                editableUntil: "2026-08-25T09:35:00.000000001Z",
                updatedAt: "2026-08-25T09:35:00.000000002Z",
              },
            ],
          }),
        ),
    );

    await Promise.all(
      Array.from({ length: 6 }, () =>
        expect(
          contactPortalApi.listPortalComments({
            kind: "alert",
            resourceId: portalAlertId,
            tenantId: contactTenantId,
          }),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
  });

  it("accepts Markdown code containing HTML syntax and enforces scalar limits", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const bodyMarkdown = await portalPreviewRequestBody(input);
      if (bodyMarkdown === "<script>alert(1)</script>") {
        return jsonResponse(
          {
            code: "validation_failed",
            status: 422,
            title: "Validation failed",
            type: "about:blank",
          },
          undefined,
          422,
        );
      }
      return jsonResponse({
        attachments: [],
        bodyHtml: "<p>server-only</p>",
        bodyMarkdown,
        visibility: "public",
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    await Promise.all(
      [
        "`<script>` is quoted evidence",
        "```html\n<script>\n```",
        "😀".repeat(20_000),
        "\uFEFF",
      ].map((bodyMarkdown) =>
        expect(
          contactPortalApi.previewPortalComment({
            bodyMarkdown,
            csrfToken: "csrf-memory-only",
            kind: "alert",
            resourceId: portalAlertId,
            tenantId: contactTenantId,
          }),
        ).resolves.toMatchObject({ bodyMarkdown }),
      ),
    );
    await expect(
      contactPortalApi.previewPortalComment({
        bodyMarkdown: "<script>alert(1)</script>",
        csrfToken: "csrf-memory-only",
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({ status: 422 });
    await expect(
      contactPortalApi.previewPortalComment({
        bodyMarkdown: "😀".repeat(20_001),
        csrfToken: "csrf-memory-only",
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toThrow("A canonical bounded Markdown comment is required.");
    expect(fetchMock).toHaveBeenCalledTimes(5);
  });

  it("rejects non-canonical edge whitespace, CR, and bidi controls in portal comments", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(
      contactPortalApi.previewPortalComment({
        bodyMarkdown: "first\rsecond",
        csrfToken: "csrf-memory-only",
        kind: "alert",
        resourceId: portalAlertId,
        tenantId: contactTenantId,
      }),
    ).rejects.toThrow("A canonical bounded Markdown comment is required.");
    await Promise.all(
      [" leading", "trailing\u3000", String.fromCharCode(0xd800)].map(
        (bodyMarkdown) =>
          expect(
            contactPortalApi.previewPortalComment({
              bodyMarkdown,
              csrfToken: "csrf-memory-only",
              kind: "alert",
              resourceId: portalAlertId,
              tenantId: contactTenantId,
            }),
          ).rejects.toThrow(
            "A canonical bounded Markdown comment is required.",
          ),
      ),
    );
    expect(fetchMock).not.toHaveBeenCalled();

    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...portalCommentFixture,
                bodyMarkdown: "Hidden\u202e direction",
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...portalCommentFixture,
                attachments: [
                  {
                    id: portalAttachmentId,
                    originalFilename: "evidence\u2066.txt",
                    projection: "customer",
                  },
                ],
              },
            ],
          }),
        )
        .mockResolvedValueOnce(
          jsonResponse({
            items: [
              {
                ...portalCommentFixture,
                attachments: [
                  {
                    id: portalAttachmentId,
                    originalFilename: " evidence.txt",
                    projection: "customer",
                  },
                ],
              },
            ],
          }),
        ),
    );
    await Promise.all(
      Array.from({ length: 3 }, () =>
        expect(
          contactPortalApi.listPortalComments({
            kind: "alert",
            resourceId: portalAlertId,
            tenantId: contactTenantId,
          }),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );
  });

  it("binds portal author corrections to exact CAS and replay receipts", async () => {
    const requests: Request[] = [];
    const corrected = {
      ...portalCommentFixture,
      author: { audience: "customer" as const, displayName: "Ari Customer" },
      bodyMarkdown: "Corrected customer update",
      canEdit: false,
      origin: "customer_portal" as const,
      revision: 2,
      updatedAt: "2026-08-25T09:25:00Z",
    };
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request)) {
          throw new TypeError("Expected a generated Request.");
        }
        const request = input;
        requests.push(request);
        return jsonResponse(corrected, '"comment-r2"', 200, {
          "X-Idempotent-Replay": "true",
        });
      }),
    );

    const result = await contactPortalApi.editPortalComment({
      bodyMarkdown: "Corrected customer update",
      commentId: corrected.id,
      csrfToken: "csrf-memory-only",
      etag: '"comment-r1"',
      idempotencyKey: "01991c20-7d5f-7000-8000-000000000099",
      kind: "alert",
      resourceId: portalAlertId,
      tenantId: contactTenantId,
    });

    expect(result).toMatchObject({
      etag: '"comment-r2"',
      replayed: true,
      value: { bodyMarkdown: "Corrected customer update", revision: 2 },
    });
    expect(requests[0]?.headers.get("If-Match")).toBe('"comment-r1"');
    expect(requests[0]?.headers.get("Idempotency-Key")).toBe(
      "01991c20-7d5f-7000-8000-000000000099",
    );
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
  });

  it("binds preference replacement to strong version, CSRF and retry identity", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (input instanceof Request) requests.push(input);
        return jsonResponse({ ...portalContactFixture, version: 2 }, '"v2"');
      }),
    );

    await contactPortalApi.replacePortalPreferences({
      body: {
        emailAllowed: false,
        notificationCategories: ["incident"],
        notificationWindows: [],
      },
      csrfToken: "csrf-memory-only",
      etag: '"v1"',
      idempotencyKey: "portal-preferences-01991c20-7d5f-7000-8000-000000000099",
      tenantId: contactTenantId,
    });

    const request = requests[0];
    expect(request).toBeDefined();
    expect(request!.headers.get("If-Match")).toBe('"v1"');
    expect(request!.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    expect(request!.headers.get("Idempotency-Key")).toBe(
      "portal-preferences-01991c20-7d5f-7000-8000-000000000099",
    );
  });

  it("rejects missing or stale entity tags in a versioned projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(jsonResponse(portalContactFixture, '"v2"')),
    );

    await expect(
      contactPortalApi.getPortalContact({ tenantId: contactTenantId }),
    ).rejects.toMatchObject({ code: "projection_mismatch" });
  });

  it("does not reflect untrusted RFC 9457 detail text", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            code: "forbidden",
            detail: "private comment body and secret destination",
            requestId: "request-1",
            status: 403,
            title: "Forbidden",
            type: "about:blank",
          },
          undefined,
          403,
        ),
      ),
    );

    await expect(
      contactPortalApi.listPortalTickets({
        kind: "alert",
        tenantId: contactTenantId,
      }),
    ).rejects.toMatchObject({
      message: "The server denied this contact operation.",
      status: 403,
    });
  });
});

function jsonResponse(
  value: unknown,
  etag?: string,
  status = 200,
  extraHeaders: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Content-Type": "application/json",
      ...(etag ? { ETag: etag } : {}),
      ...extraHeaders,
    },
    status,
  });
}

async function portalPreviewRequestBody(
  input: RequestInfo | URL,
): Promise<string> {
  if (!(input instanceof Request)) {
    throw new TypeError("Expected a generated Request.");
  }
  const body: unknown = await input.clone().json();
  if (
    typeof body !== "object" ||
    body === null ||
    !("bodyMarkdown" in body) ||
    typeof body.bodyMarkdown !== "string"
  ) {
    throw new TypeError("Expected a portal preview body.");
  }
  return body.bodyMarkdown;
}

function attachmentJsonResponse(value: unknown, noReferrer = false): Response {
  return new Response(JSON.stringify(value), {
    headers: {
      "Cache-Control": "private, no-store",
      "Content-Type": "application/json",
      ...(noReferrer ? { "Referrer-Policy": "no-referrer" } : {}),
    },
    status: 200,
  });
}

function csvResponse(
  value: string,
  filename: string,
  cacheControl = "no-store",
): Response {
  return new Response(value, {
    headers: {
      "Cache-Control": cacheControl,
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Type": "text/csv; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
    status: 200,
  });
}
