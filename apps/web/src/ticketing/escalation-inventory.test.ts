import type { TicketCustomerContactLink } from "@periapsis/contracts";
import { describe, expect, it, vi } from "vitest";

import {
  projectAlertWorkspace,
  type AlertDfirApi,
} from "../dfir/alert-dfir-api";
import {
  alertDfirAlertId,
  alertDfirTenantId,
  alertDfirWorkspaceFixture,
} from "../dfir/alert-dfir-test-fixtures";
import type { TicketComment } from "../lib/ticketing-api";
import { createTicketingApi, membershipId } from "./ticketing-test-fixtures";
import {
  EscalationInventoryError,
  loadEscalationInventory,
  setBoundedSelection,
} from "./escalation-inventory";

const snapshot = projectAlertWorkspace(
  alertDfirWorkspaceFixture(),
  alertDfirTenantId,
  alertDfirAlertId,
);
const contactId = "0198c97d-cf4f-7000-8000-000000000030";
const contactLink = {
  id: "0198c97d-cf4f-7000-8000-000000000031",
  tenantId: alertDfirTenantId,
  resourceKind: "alert",
  resourceId: alertDfirAlertId,
  contactId,
  role: "primary",
  origin: "manual",
  version: 1,
  createdAt: "2026-08-30T09:00:00Z",
} satisfies TicketCustomerContactLink;

describe("bounded escalation inventory", () => {
  it("follows bounded comment cursors and never exposes private comments", async () => {
    const firstPublic = comment(
      "0198c97d-cf4f-7000-8000-000000000040",
      "public",
    );
    const privateComment = comment(
      "0198c97d-cf4f-7000-8000-000000000041",
      "private",
    );
    const secondPublic = comment(
      "0198c97d-cf4f-7000-8000-000000000042",
      "public",
    );
    const listComments = vi
      .fn()
      .mockResolvedValueOnce({
        items: [firstPublic, privateComment],
        nextCursor: "next_page",
      })
      .mockResolvedValueOnce({ items: [secondPublic] });
    const controller = new AbortController();

    const inventory = await loadEscalationInventory({
      alertId: alertDfirAlertId,
      dfirApi: createDfirApi(),
      signal: controller.signal,
      tenantId: alertDfirTenantId,
      ticketingApi: createTicketingApi({
        listAlertContactLinks: async () => ({ items: [contactLink] }),
        listComments,
      }),
    });

    expect(inventory.publicComments.map((item) => item.id)).toEqual([
      firstPublic.id,
      secondPublic.id,
    ]);
    expect(inventory.publicComments).not.toContainEqual(privateComment);
    expect(inventory.contacts).toEqual([contactLink]);
    expect(listComments).toHaveBeenNthCalledWith(
      1,
      "alert",
      alertDfirTenantId,
      alertDfirAlertId,
      undefined,
      controller.signal,
    );
    expect(listComments).toHaveBeenNthCalledWith(
      2,
      "alert",
      alertDfirTenantId,
      alertDfirAlertId,
      "next_page",
      controller.signal,
    );
  });

  it("fails closed when comments or contacts exceed a bounded inventory", async () => {
    const ticketingApi = createTicketingApi({
      listAlertContactLinks: async () => ({
        items: [contactLink],
        nextCursor: "more_contacts",
      }),
      listComments: async () => ({ items: [] }),
    });
    await expect(
      loadEscalationInventory({
        alertId: alertDfirAlertId,
        dfirApi: createDfirApi(),
        signal: new AbortController().signal,
        tenantId: alertDfirTenantId,
        ticketingApi,
      }),
    ).rejects.toThrow(EscalationInventoryError);

    let page = 0;
    await expect(
      loadEscalationInventory({
        alertId: alertDfirAlertId,
        dfirApi: createDfirApi(),
        signal: new AbortController().signal,
        tenantId: alertDfirTenantId,
        ticketingApi: createTicketingApi({
          listAlertContactLinks: async () => ({ items: [] }),
          listComments: async () => ({
            items: [],
            nextCursor: `page_${++page}`,
          }),
        }),
      }),
    ).rejects.toThrow(/Public-comment selection exceeds/u);
  });

  it("enforces the contract's 100-ID cap per explicit category", () => {
    const selected = new Set(
      Array.from({ length: 100 }, (_, index) => `id-${index}`),
    );
    expect(() => setBoundedSelection(selected, "one-too-many", true)).toThrow(
      EscalationInventoryError,
    );
    expect(setBoundedSelection(selected, "id-3", false)).not.toContain("id-3");
  });
});

function comment(id: string, visibility: "private" | "public"): TicketComment {
  return {
    projection: "operator",
    id,
    tenantId: alertDfirTenantId,
    resourceKind: "alert",
    resourceId: alertDfirAlertId,
    visibility,
    bodyMarkdown: `${visibility} comment`,
    author: {
      audience: "operator",
      displayName: "Analyst",
      membershipId,
    },
    attachments: [],
    canEdit: false,
    editableUntil: "2026-08-30T09:15:00Z",
    mentions: [],
    origin: "api",
    revision: 1,
    createdAt: "2026-08-30T09:00:00Z",
    updatedAt: "2026-08-30T09:00:00Z",
  };
}

function createDfirApi(): AlertDfirApi {
  return {
    appendCustody: async () => undefined,
    changeLink: async () => undefined,
    assignTask: async () => undefined,
    create: async () => undefined,
    getWorkspace: async () => snapshot,
    prepareDownload: async () => {
      throw new Error("unexpected prepare download");
    },
    prepareUpload: async () => {
      throw new Error("unexpected prepare upload");
    },
    replaceTaskDetails: async () => undefined,
    replaceTaskChecklist: async () => undefined,
    replaceTaskComments: async () => undefined,
    replace: async () => undefined,
    rescheduleTask: async () => undefined,
    retractRelationship: async () => undefined,
    transitionTask: async () => undefined,
    upload: async () => undefined,
  };
}
