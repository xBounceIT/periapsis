import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CaseContactApiError,
  caseContactApi,
  type CaseContactArchiveInput,
  type CaseContactLink,
} from "./case-contact-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const caseId = "0198c97d-cf4f-7000-8000-000000000012";
const contactId = "0198c97d-cf4f-7000-8000-000000000020";
const secondContactId = "0198c97d-cf4f-7000-8000-000000000021";
const linkId = "0198c97d-cf4f-7000-8000-000000000030";
const cursor = "bGlua19jdXJzb3JfMg";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("caseContactApi", () => {
  it("reaches second link and active-contact pages through canonical generated query parameters", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        const url = new URL(input.url);
        if (
          url.pathname.endsWith("/contacts") &&
          url.searchParams.has("active")
        ) {
          return jsonResponse({ items: [contact(secondContactId)] });
        }
        return jsonResponse({ items: [link()], nextCursor: "next_link_page" });
      }),
    );

    await expect(
      caseContactApi.listLinks({
        after: cursor,
        caseId,
        limit: 25,
        tenantId,
      }),
    ).resolves.toMatchObject({ nextCursor: "next_link_page" });
    await expect(
      caseContactApi.listActiveContacts({
        after: cursor,
        caseId,
        limit: 25,
        tenantId,
      }),
    ).resolves.toMatchObject({
      items: [{ active: true, id: secondContactId }],
    });

    expect(requests.map((request) => request.method)).toEqual(["GET", "GET"]);
    expect(new URL(requests[0]!.url).pathname).toBe(
      `/api/v1/tenants/${tenantId}/cases/${caseId}/contacts`,
    );
    expect(new URL(requests[0]!.url).searchParams.get("after")).toBe(cursor);
    expect(new URL(requests[0]!.url).searchParams.get("limit")).toBe("25");
    const contactUrl = new URL(requests[1]!.url);
    expect(contactUrl.pathname).toBe(`/api/v1/tenants/${tenantId}/contacts`);
    expect(contactUrl.searchParams.get("after")).toBe(cursor);
    expect(contactUrl.searchParams.get("limit")).toBe("25");
    expect(contactUrl.searchParams.get("active")).toBe("true");
    expect(contactUrl.searchParams.get("includeArchived")).toBe("false");
    expect(requests.every((request) => request.cache === "no-store")).toBe(
      true,
    );
  });

  it("binds link and archive to exact Case/link CAS and opaque retry keys", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        if (input.method === "POST") {
          return jsonResponse(link(), 201, {
            ETag: '"v1"',
            Location: `/api/v1/tenants/${tenantId}/cases/${caseId}/contacts/${linkId}`,
          });
        }
        return jsonResponse(
          {
            ...link(),
            archivedAt: "2026-09-02T08:05:00Z",
            version: 2,
          },
          200,
          { ETag: '"v2"' },
        );
      }),
    );

    const linked = await caseContactApi.link({
      caseEtag: '"v4"',
      caseId,
      contactId,
      csrfToken: "csrf-memory-only",
      expectedCaseVersion: 4,
      idempotencyKey: "case-contact-link-0001",
      role: "primary",
      tenantId,
    });
    await expect(
      caseContactApi.archive(archiveInput(linked)),
    ).resolves.toMatchObject({
      archivedAt: "2026-09-02T08:05:00Z",
      version: 2,
    });

    expect(requests.map((request) => request.method)).toEqual([
      "POST",
      "DELETE",
    ]);
    expect(requests[0]?.headers.get("If-Match")).toBe('"v4"');
    expect(requests[1]?.headers.get("If-Match")).toBe('"v1"');
    expect(requests[0]?.headers.get("Idempotency-Key")).toBe(
      "case-contact-link-0001",
    );
    expect(requests[1]?.headers.get("Idempotency-Key")).toBe(
      "case-contact-archive-01",
    );
    expect(requests[0]?.headers.get("X-CSRF-Token")).toBe("csrf-memory-only");
    await expect(requests[0]!.clone().json()).resolves.toEqual({
      contactId,
      role: "primary",
    });
    await expect(requests[1]!.clone().json()).resolves.toEqual({
      expectedTicketVersion: 4,
      reason: "No longer an active incident contact",
    });
    expect(new URL(requests[1]!.url).pathname).toBe(
      `/api/v1/tenants/${tenantId}/cases/${caseId}/contacts/${linkId}`,
    );
  });

  it("fails closed on tenant, Case, PII-bearing link, active-contact, order, and cursor drift", async () => {
    const wrongTenant = "0198c97d-cf4f-7000-8000-000000000099";
    const wrongCase = "0198c97d-cf4f-7000-8000-000000000098";
    const variants: unknown[] = [
      { items: [{ ...link(), tenantId: wrongTenant }] },
      { items: [{ ...link(), resourceId: wrongCase }] },
      { items: [{ ...link(), email: "pii@example.test" }] },
      { items: [{ ...link(), archivedAt: "2026-09-02T08:05:00Z" }] },
      {
        items: [
          { ...link(), id: "0198c97d-cf4f-7000-8000-000000000031" },
          link(),
        ],
      },
      {
        items: [
          link(),
          { ...link(), id: "0198c97d-cf4f-7000-8000-000000000031" },
        ],
      },
      { items: [], nextCursor: cursor },
      { items: [link()], nextCursor: cursor },
    ];
    const fetch = vi.fn();
    for (const variant of variants)
      fetch.mockResolvedValueOnce(jsonResponse(variant));
    vi.stubGlobal("fetch", fetch);

    await Promise.all(
      variants.map(() =>
        expect(
          caseContactApi.listLinks({ after: cursor, caseId, tenantId }),
        ).rejects.toMatchObject({ code: "projection_mismatch" }),
      ),
    );

    const invalidContacts = [
      { items: [{ ...contact(), tenantId: wrongTenant }] },
      { items: [{ ...contact(), active: false }] },
      { items: [{ ...contact(), archivedAt: "2026-09-02T08:05:00Z" }] },
      { items: [{ ...contact(), secret: "do-not-display" }] },
      { items: [{ ...contact(), email: "Mixed@Example.test" }] },
      { items: [{ ...contact(), notificationCategories: ["z", "a"] }] },
      { items: [{ ...contact(), timezone: "Mars/Olympus" }] },
      {
        items: [
          {
            ...contact(),
            createdAt: "2026-09-02T08:00:00.001Z",
            updatedAt: "2026-09-02T08:00:00Z",
          },
        ],
      },
    ];
    for (const variant of invalidContacts)
      fetch.mockResolvedValueOnce(jsonResponse(variant));
    await Promise.all(
      invalidContacts.map(() =>
        expect(
          caseContactApi.listActiveContacts({ caseId, tenantId }),
        ).rejects.toBeInstanceOf(CaseContactApiError),
      ),
    );
  });

  it("compares canonical fractional instants chronologically", async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(
        jsonResponse({
          items: [
            {
              ...contact(),
              createdAt: "2026-09-02T08:00:00Z",
              timezone: "UTC",
              updatedAt: "2026-09-02T08:00:00.001Z",
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse(
          {
            ...link(),
            archivedAt: "2026-09-02T08:00:00.001Z",
            version: 2,
          },
          200,
          { ETag: '"v2"' },
        ),
      );
    vi.stubGlobal("fetch", fetch);

    await expect(
      caseContactApi.listActiveContacts({ caseId, tenantId }),
    ).resolves.toMatchObject({
      items: [{ timezone: "UTC", updatedAt: "2026-09-02T08:00:00.001Z" }],
    });
    await expect(
      caseContactApi.archive(archiveInput(link())),
    ).resolves.toMatchObject({ archivedAt: "2026-09-02T08:00:00.001Z" });
  });

  it("rejects malformed coordinates and mutation credentials before transport", async () => {
    const fetch = vi.fn();
    vi.stubGlobal("fetch", fetch);

    await expect(
      caseContactApi.listLinks({
        caseId: "0198c97d-cf4f-4000-8000-000000000012",
        tenantId,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      caseContactApi.link({
        caseEtag: '"v5"',
        caseId,
        contactId,
        csrfToken: "csrf-memory-only",
        expectedCaseVersion: 4,
        idempotencyKey: "case-contact-link-0002",
        role: "primary",
        tenantId,
      }),
    ).rejects.toBeInstanceOf(TypeError);
    await expect(
      caseContactApi.archive({
        ...archiveInput(link()),
        reason: " ",
      }),
    ).rejects.toBeInstanceOf(TypeError);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("sanitizes stale response errors without reflecting server details", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({ detail: "private database coordinates" }, 412),
      ),
    );

    await expect(
      caseContactApi.link({
        caseEtag: '"v4"',
        caseId,
        contactId,
        csrfToken: "csrf-memory-only",
        expectedCaseVersion: 4,
        idempotencyKey: "case-contact-link-0003",
        role: "primary",
        tenantId,
      }),
    ).rejects.toMatchObject({
      message:
        "The Case or contact relationship changed. Reload the current snapshot before retrying.",
      status: 412,
    });
  });
});

function archiveInput(current: CaseContactLink): CaseContactArchiveInput {
  return {
    caseId,
    csrfToken: "csrf-memory-only",
    expectedCaseVersion: 4,
    idempotencyKey: "case-contact-archive-01",
    link: current,
    reason: "No longer an active incident contact",
    tenantId,
  };
}

function link(): CaseContactLink {
  return {
    contactId,
    createdAt: "2026-09-02T08:00:00Z",
    id: linkId,
    origin: "manual",
    resourceId: caseId,
    resourceKind: "case",
    role: "primary",
    tenantId,
    version: 1,
  };
}

function contact(id = contactId): Record<string, unknown> {
  return {
    active: true,
    contactClass: "customer",
    createdAt: "2026-09-01T08:00:00Z",
    email: id === contactId ? "case.owner@example.test" : "backup@example.test",
    emailAllowed: true,
    escalationPriority: 1,
    firstName: id === contactId ? "Case" : "Backup",
    function: "Incident owner",
    id,
    language: "en",
    lastName: "Owner",
    notificationCategories: ["incident"],
    notificationWindows: [{ endMinute: 1020, isoWeekday: 1, startMinute: 540 }],
    tags: ["primary"],
    tenantId,
    timezone: "Europe/Rome",
    updatedAt: "2026-09-01T08:00:00Z",
    version: 1,
  };
}

function jsonResponse(
  body: unknown,
  status = 200,
  extraHeaders: HeadersInit = {},
): Response {
  return new Response(JSON.stringify(body), {
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      ...Object.fromEntries(new Headers(extraHeaders)),
    },
    status,
  });
}
