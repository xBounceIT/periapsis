import type { CustomFieldDefinitionSpec } from "@periapsis/contracts";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  CustomFieldApiError,
  customFieldAdministrationApi,
  customFieldObjectApi,
  listAllCustomFieldDefinitions,
  type CustomFieldAdministrationApi,
} from "./custom-field-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const definitionId = "0198c97d-cf4f-7000-8000-000000000002";
const objectId = "0198c97d-cf4f-7000-8000-000000000003";
const etag = '"cf-AAAAAAAAAAAAAAAAAAAAAA"';

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("customFieldAdministrationApi", () => {
  it("projects a bounded no-store definition page and preserves query scope", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        return jsonResponse({ items: [definitionEnvelope()] });
      }),
    );

    const page = await customFieldAdministrationApi.list({
      includeArchived: true,
      objectType: "alert",
      tenantId,
    });

    expect(page.items).toEqual([
      expect.objectContaining({
        id: definitionId,
        key: "incident_owner",
        objectType: "alert",
        schemaVersion: 3,
        tenantId,
      }),
    ]);
    const request = requests[0]!;
    const url = new URL(request.url);
    expect(url.searchParams.get("objectType")).toBe("alert");
    expect(url.searchParams.get("includeArchived")).toBe("true");
    expect(url.searchParams.get("limit")).toBe("100");
    expect(request.cache).toBe("no-store");
  });

  it("never requests more than the canonical PageSize maximum", async () => {
    let page = 0;
    const list = vi.fn<CustomFieldAdministrationApi["list"]>(async () => {
      page += 1;
      return { items: [], nextCursor: `page-${page}` };
    });

    await expect(
      listAllCustomFieldDefinitions(
        {
          archive: async () => ({ etag }),
          create: async () => ({ etag, value: projectDefinitionView() }),
          get: async () => ({ etag, value: projectDefinitionView() }),
          list,
          replace: async () => ({ etag, value: projectDefinitionView() }),
        },
        { objectType: "alert", tenantId },
      ),
    ).rejects.toThrow(/bounded form projection/u);

    expect(list).toHaveBeenCalledTimes(10);
    expect(list.mock.calls.every(([input]) => input.limit === 100)).toBe(true);
  });

  it("rejects cross-tenant and cacheable projections", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          items: [
            definitionEnvelope({
              tenantId: "0198c97d-cf4f-7000-8000-000000000099",
            }),
          ],
        }),
      ),
    );
    await expect(
      customFieldAdministrationApi.list({ objectType: "alert", tenantId }),
    ).rejects.toBeInstanceOf(CustomFieldApiError);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ items: [] }), {
          status: 200,
          headers: { "Cache-Control": "private" },
        }),
      ),
    );
    await expect(
      customFieldAdministrationApi.list({ objectType: "alert", tenantId }),
    ).rejects.toBeInstanceOf(CustomFieldApiError);
  });

  it("binds create identity, CSRF, and idempotency to the canonical request", async () => {
    let request: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        request = input;
        return jsonResponse(definitionEnvelope(), 201, { ETag: etag });
      }),
    );

    await expect(
      customFieldAdministrationApi.create({
        csrfToken: "csrf-token",
        definition: definitionSpec,
        definitionId,
        idempotencyKey: "custom-field-create-1",
        tenantId,
      }),
    ).resolves.toMatchObject({ etag, value: { id: definitionId } });

    expect(request?.method).toBe("POST");
    expect(request?.headers.get("X-CSRF-Token")).toBe("csrf-token");
    expect(request?.headers.get("Idempotency-Key")).toBe(
      "custom-field-create-1",
    );
    await expect(request?.clone().json()).resolves.toEqual({
      definition: definitionSpec,
      definitionId,
    });
  });

  it("requires a current strong ETag for replacement and archival", async () => {
    await expect(
      customFieldAdministrationApi.replace({
        csrfToken: "csrf-token",
        definition: definitionSpec,
        definitionId,
        etag: 'W/"stale"',
        expectedVersion: 3,
        idempotencyKey: "custom-field-replace-1",
        tenantId,
      }),
    ).rejects.toBeInstanceOf(TypeError);

    let request: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        request = input;
        return new Response(undefined, {
          status: 204,
          headers: { "Cache-Control": "no-store", ETag: etag },
        });
      }),
    );
    await customFieldAdministrationApi.archive({
      csrfToken: "csrf-token",
      definitionId,
      etag,
      expectedVersion: 3,
      idempotencyKey: "custom-field-archive-1",
      objectType: "alert",
      reason: "Retired by tenant administrator",
      tenantId,
    });
    expect(request?.method).toBe("DELETE");
    expect(request?.headers.get("If-Match")).toBe(etag);
  });

  it("rejects duplicate identities across opaque cursor pages", async () => {
    let calls = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => {
        calls += 1;
        return jsonResponse({
          items: [definitionEnvelope()],
          ...(calls === 1 ? { nextCursor: "next-page" } : {}),
        });
      }),
    );

    await expect(
      listAllCustomFieldDefinitions(customFieldAdministrationApi, {
        objectType: "alert",
        tenantId,
      }),
    ).rejects.toBeInstanceOf(CustomFieldApiError);
  });

  it("requires replacement responses to advance the immutable revision", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse(definitionEnvelope(), 200, { ETag: etag }),
        ),
    );

    await expect(
      customFieldAdministrationApi.replace({
        csrfToken: "csrf-token",
        definition: definitionSpec,
        definitionId,
        etag,
        expectedVersion: 3,
        idempotencyKey: "custom-field-replace-2",
        tenantId,
      }),
    ).rejects.toBeInstanceOf(CustomFieldApiError);
  });

  it("binds an object projection to exact definition identities and version ETag", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        return jsonResponse(
          {
            objectType: "alert",
            objectId,
            definitions: [definitionEnvelope()],
            values: [projectedValue("present", "Ada")],
            version: 7,
          },
          200,
          { ETag: '"v7"' },
        );
      }),
    );

    await expect(
      customFieldObjectApi.get({ objectId, objectType: "alert", tenantId }),
    ).resolves.toMatchObject({
      drafts: { incident_owner: { presence: "present", value: "Ada" } },
      etag: '"v7"',
      objectId,
      objectType: "alert",
      version: 7,
    });
    const url = new URL(requests[0]!.url);
    expect(url.searchParams.get("surface")).toBe("detail");
  });

  it("replaces an object value set with exact optimistic and idempotency binding", async () => {
    let request: Request | undefined;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        request = input;
        return jsonResponse(
          { values: [projectedValue("present", "Grace")], version: 8 },
          200,
          { ETag: '"v8"' },
        );
      }),
    );
    const current = {
      definitions: [projectDefinitionView()],
      drafts: {
        incident_owner: { presence: "present" as const, value: "Ada" },
      },
      etag: '"v7"',
      objectId,
      objectType: "alert" as const,
      tenantId,
      version: 7,
    };
    const controller = new AbortController();

    await expect(
      customFieldObjectApi.replace({
        csrfToken: "csrf-token",
        current,
        idempotencyKey: "custom-values-update-1",
        signal: controller.signal,
        tenantId,
        values: { incident_owner: "Grace" },
      }),
    ).resolves.toMatchObject({
      drafts: { incident_owner: { presence: "present", value: "Grace" } },
      etag: '"v8"',
      version: 8,
    });
    expect(request?.headers.get("If-Match")).toBe('"v7"');
    expect(request?.headers.get("Idempotency-Key")).toBe(
      "custom-values-update-1",
    );
    await expect(request?.clone().json()).resolves.toEqual({
      expectedVersion: 7,
      phase: "update",
      values: { incident_owner: "Grace" },
    });
    controller.abort();
    expect(request?.signal.aborted).toBe(true);
  });

  it("rejects replacement outside the tenant-bound editable detail projection", async () => {
    const current = {
      definitions: [projectDefinitionView()],
      drafts: {
        incident_owner: { presence: "present" as const, value: "Ada" },
      },
      etag: '"v7"',
      objectId,
      objectType: "alert" as const,
      tenantId,
      version: 7,
    };

    await expect(
      customFieldObjectApi.replace({
        csrfToken: "csrf-token",
        current,
        idempotencyKey: "custom-values-update-2",
        tenantId: "0198c97d-cf4f-7000-8000-000000000099",
        values: { incident_owner: "Grace" },
      }),
    ).rejects.toBeInstanceOf(CustomFieldApiError);
    await expect(
      customFieldObjectApi.replace({
        csrfToken: "csrf-token",
        current: {
          ...current,
          definitions: [
            {
              ...current.definitions[0]!,
              editPolicy: {
                ...current.definitions[0]!.editPolicy,
                operatorUpdate: false,
              },
            },
          ],
        },
        idempotencyKey: "custom-values-update-3",
        tenantId,
        values: { incident_owner: "Grace" },
      }),
    ).rejects.toBeInstanceOf(TypeError);
  });

  it("rejects presence/value drift before exposing an object projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            objectType: "alert",
            objectId,
            definitions: [definitionEnvelope()],
            values: [projectedValue("missing", "leak")],
            version: 7,
          },
          200,
          { ETag: '"v7"' },
        ),
      ),
    );

    await expect(
      customFieldObjectApi.get({ objectId, objectType: "alert", tenantId }),
    ).rejects.toBeTruthy();
  });

  it("rejects colliding definition identities in an object projection", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse(
          {
            objectType: "alert",
            objectId,
            definitions: [
              definitionEnvelope(),
              definitionEnvelope({
                definition: { ...definitionSpec, key: "secondary_owner" },
              }),
            ],
            values: [
              projectedValue("present", "Ada"),
              {
                ...projectedValue("present", "Grace"),
                key: "secondary_owner",
              },
            ],
            version: 7,
          },
          200,
          { ETag: '"v7"' },
        ),
      ),
    );

    await expect(
      customFieldObjectApi.get({ objectId, objectType: "alert", tenantId }),
    ).rejects.toBeInstanceOf(CustomFieldApiError);
  });
});

const definitionSpec: CustomFieldDefinitionSpec = {
  objectType: "alert",
  key: "incident_owner",
  label: "Incident owner",
  description: "Customer-safe incident ownership.",
  dataType: "short_text",
  required: false,
  nullable: true,
  visibility: { customer: true, operator: true },
  editPolicy: {
    customerCreate: false,
    customerUpdate: false,
    operatorCreate: true,
    operatorUpdate: true,
  },
  placement: {
    showInCreate: true,
    showInDetail: true,
    showInList: true,
    showInExport: true,
  },
  requiredOnTransitions: [],
  searchable: true,
  filterable: true,
  sortable: true,
  allowStructuredJson: false,
};

function definitionEnvelope(overrides: Record<string, unknown> = {}) {
  return {
    id: definitionId,
    tenantId,
    schemaVersion: 3,
    archived: false,
    definition: definitionSpec,
    ...overrides,
  };
}

function projectDefinitionView() {
  return {
    id: definitionId,
    tenantId,
    schemaVersion: 3,
    archived: false,
    ...definitionSpec,
  };
}

function projectedValue(
  presence: "missing" | "null" | "present",
  value?: unknown,
) {
  return {
    key: definitionSpec.key,
    definitionId,
    schemaVersion: 3,
    presence,
    ...(value === undefined ? {} : { value }),
  };
}

function jsonResponse(
  body: unknown,
  status = 200,
  headers: Record<string, string> = {},
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
      ...headers,
    },
  });
}
