import { afterEach, describe, expect, it, vi } from "vitest";

import {
  TicketColumnCatalogApiError,
  ticketColumnCatalogApi,
} from "./ticket-column-catalog-api";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const customFieldId = "0198c97d-cf4f-7000-8000-000000000002";
const slaColumnId = "0198c97d-cf4f-7000-8000-000000000003";

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("ticketColumnCatalogApi", () => {
  it("projects only current list-visible operator custom fields", async () => {
    const requests: Request[] = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        if (!(input instanceof Request))
          throw new TypeError("Request required");
        requests.push(input);
        return jsonResponse({
          items: [
            customFieldDefinition({}),
            customFieldDefinition({
              id: "0198c97d-cf4f-7000-8000-000000000004",
              definition: {
                ...customFieldDefinition({}).definition,
                key: "hidden_field",
                label: "Hidden field",
                placement: {
                  ...customFieldDefinition({}).definition.placement,
                  showInList: false,
                },
              },
            }),
          ],
          nextCursor: "catalog-cursor-1",
        });
      }),
    );

    await expect(
      ticketColumnCatalogApi.listCustomFields({ kind: "alert", tenantId }),
    ).resolves.toEqual({
      items: [
        {
          definitionId: customFieldId,
          definitionKey: "incident_owner",
          definitionLabel: "Incident owner",
          definitionVersion: 3,
          source: "custom_field",
        },
      ],
      nextCursor: "catalog-cursor-1",
    });
    const request = requests[0]!;
    const url = new URL(request.url);
    expect(url.pathname).toBe(
      `/api/v1/tenants/${tenantId}/custom-field-definitions`,
    );
    expect(url.searchParams.get("objectType")).toBe("alert");
    expect(url.searchParams.get("includeArchived")).toBe("false");
    expect(url.searchParams.get("limit")).toBe("100");
    expect(request.cache).toBe("no-store");
  });

  it("projects current SLA revisions and rejects cross-tenant envelopes", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(jsonResponse({ tenantId, items: [slaColumn({})] })),
    );
    await expect(
      ticketColumnCatalogApi.listSlaColumns({ tenantId }),
    ).resolves.toEqual({
      items: [
        {
          definitionId: slaColumnId,
          definitionKey: "response_due",
          definitionLabel: "Response due",
          definitionVersion: 5,
          source: "sla",
        },
      ],
    });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        jsonResponse({
          tenantId: "0198c97d-cf4f-7000-8000-000000000099",
          items: [slaColumn({})],
        }),
      ),
    );
    await expect(
      ticketColumnCatalogApi.listSlaColumns({ tenantId }),
    ).rejects.toBeInstanceOf(TicketColumnCatalogApiError);
  });

  it("preserves non-oracular authorization failures", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(undefined, {
          status: 403,
          headers: { "Cache-Control": "no-store" },
        }),
      ),
    );
    await expect(
      ticketColumnCatalogApi.listCustomFields({ kind: "case", tenantId }),
    ).rejects.toMatchObject({ status: 403 });
  });
});

function customFieldDefinition(overrides: Record<string, unknown>) {
  return {
    id: customFieldId,
    tenantId,
    schemaVersion: 3,
    archived: false,
    definition: {
      objectType: "alert",
      key: "incident_owner",
      label: "Incident owner",
      description: "",
      dataType: "short_text",
      required: false,
      nullable: true,
      visibility: { customer: false, operator: true },
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
    },
    ...overrides,
  };
}

function slaColumn(overrides: Record<string, unknown>) {
  return {
    tenantId,
    id: slaColumnId,
    version: 5,
    resourceVersion: 8,
    revisionDigest: "a".repeat(64),
    createdAt: "2026-08-30T10:00:00.000Z",
    updatedAt: "2026-08-30T10:00:00.000Z",
    key: "response_due",
    label: "Response due",
    metricDefinitionId: "0198c97d-cf4f-7000-8000-000000000005",
    calculation: "due_at",
    format: "datetime",
    sortable: true,
    filterable: true,
    customerVisible: false,
    visibleRoleKeys: [],
    position: 0,
    styleRules: [],
    ...overrides,
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json",
    },
  });
}
