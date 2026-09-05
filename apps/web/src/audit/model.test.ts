import { describe, expect, it } from "vitest";

import {
  AuditFilterError,
  emptyAuditFilterDraft,
  normalizeAuditFilters,
  platformAuditRouteDescriptor,
  tenantAuditRouteDescriptor,
} from "./model";

describe("audit reader model", () => {
  it("normalizes the complete bounded filter set", () => {
    expect(
      normalizeAuditFilters(
        {
          ...emptyAuditFilterDraft,
          actionPrefix: "  case.transition  ",
          actorType: "user",
          actorUserId: "01991C20-7D5F-7000-8000-000000000002",
          limit: 25,
          occurredBefore: "2026-08-26T00:00:00Z",
          occurredFrom: "2026-08-25T00:00:00Z",
          outcome: "success",
          resourceType: "case",
          search: "  approved  ",
        },
        "tenant",
      ),
    ).toEqual({
      actionPrefix: "case.transition",
      actorType: "user",
      actorUserId: "01991c20-7d5f-7000-8000-000000000002",
      limit: 25,
      occurredBefore: "2026-08-26T00:00:00Z",
      occurredFrom: "2026-08-25T00:00:00Z",
      outcome: "success",
      resourceType: "case",
      search: "approved",
    });
  });

  it.each([
    {
      name: "mixed actor identifiers",
      mutate: () => ({
        actorServiceAccountId: "01991c20-7d5f-7000-8000-000000000003",
        actorUserId: "01991c20-7d5f-7000-8000-000000000002",
      }),
      surface: "tenant" as const,
    },
    {
      name: "service-account identifier on platform",
      mutate: () => ({
        actorServiceAccountId: "01991c20-7d5f-7000-8000-000000000003",
      }),
      surface: "platform" as const,
    },
    {
      name: "inverted time interval",
      mutate: () => ({
        occurredBefore: "2026-08-25T00:00:00Z",
        occurredFrom: "2026-08-26T00:00:00Z",
      }),
      surface: "tenant" as const,
    },
    {
      name: "unbounded page",
      mutate: () => ({ limit: 101 }),
      surface: "tenant" as const,
    },
  ])("rejects $name", ({ mutate, surface }) => {
    expect(() =>
      normalizeAuditFilters({ ...emptyAuditFilterDraft, ...mutate() }, surface),
    ).toThrow(AuditFilterError);
  });

  it("exports exact live-permission route descriptors for root wiring", () => {
    expect(tenantAuditRouteDescriptor).toEqual({
      path: "/tenant/audit",
      permission: "audit.read",
      scope: "tenant",
      title: "Audit ledger",
    });
    expect(platformAuditRouteDescriptor).toEqual({
      path: "/platform/audit",
      permission: "platform.audit.read",
      scope: "platform",
      title: "Platform audit",
    });
  });
});
