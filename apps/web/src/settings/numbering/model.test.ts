import { describe, expect, it } from "vitest";

import {
  isTicketNumberingPolicyProjection,
  isTicketNumberingPreviewProjection,
  normalizeTicketNumberingForm,
  ticketNumberingDraftFromForm,
  ticketNumberingFieldErrors,
  ticketNumberingReasonIsValid,
} from "./model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000091";

describe("ticket numbering model", () => {
  it("normalizes the public grammar and enforces width-specific start limits", () => {
    const normalized = normalizeTicketNumberingForm({
      period: "annual",
      prefix: " alt7 ",
      separator: "/",
      start: " 42 ",
      width: " 6 ",
    });
    expect(ticketNumberingDraftFromForm(normalized)).toEqual({
      period: "annual",
      prefix: "ALT7",
      separator: "/",
      start: 42,
      width: 6,
    });
    expect(
      ticketNumberingFieldErrors({
        ...normalized,
        start: "10000",
        width: "4",
      }),
    ).toMatchObject({ start: expect.stringContaining("9,999") });
    expect(
      ticketNumberingFieldErrors({ ...normalized, start: "0001" }),
    ).toHaveProperty("start");
  });

  it("accepts only exact policy projections with coherent publisher provenance", () => {
    const policy = policyFixture();
    expect(isTicketNumberingPolicyProjection(policy, tenantId, "alert")).toBe(
      true,
    );
    expect(
      isTicketNumberingPolicyProjection(
        { ...policy, publisher: { membershipId: null, type: "membership" } },
        tenantId,
        "alert",
      ),
    ).toBe(false);
    expect(
      isTicketNumberingPolicyProjection(
        {
          ...policy,
          publisher: { membershipId: null, type: "system" },
          version: 7,
        },
        tenantId,
        "alert",
      ),
    ).toBe(false);
    expect(
      isTicketNumberingPolicyProjection(
        { ...policy, unexpected: "leak" },
        tenantId,
        "alert",
      ),
    ).toBe(false);
  });

  it("requires the preview to be the exact server-time rendering of the draft", () => {
    const draft = {
      period: "annual" as const,
      prefix: "ALT",
      separator: "-" as const,
      start: 1,
      width: 6,
    };
    const preview = {
      ...draft,
      at: "2026-09-03T10:30:00Z",
      example: "ALT-2026-000001",
      kind: "alert",
      maximumSequence: 999_999,
      periodKey: 2026,
      tenantId,
    };
    expect(
      isTicketNumberingPreviewProjection(preview, tenantId, "alert", draft),
    ).toBe(true);
    expect(
      isTicketNumberingPreviewProjection(
        { ...preview, example: "ALT-2026/000001" },
        tenantId,
        "alert",
        draft,
      ),
    ).toBe(false);
    expect(
      isTicketNumberingPreviewProjection(
        { ...preview, periodKey: 2025 },
        tenantId,
        "alert",
        draft,
      ),
    ).toBe(false);
  });

  it("keeps audit reasons non-secret-header-safe", () => {
    expect(ticketNumberingReasonIsValid("Approved under SEC-2048")).toBe(true);
    expect(ticketNumberingReasonIsValid(" surrounding ")).toBe(false);
    expect(ticketNumberingReasonIsValid("contains,comma")).toBe(false);
    expect(ticketNumberingReasonIsValid("a".repeat(2049))).toBe(false);
  });
});

function policyFixture() {
  return {
    kind: "alert",
    period: "annual",
    prefix: "ALT",
    publishedAt: "2026-09-01T18:30:00.123456Z",
    publisher: {
      membershipId: "0198c97d-cf4f-7000-8000-000000000020",
      type: "membership",
    },
    separator: "-",
    start: 1,
    tenantId,
    version: 7,
    versionId: "0198c97d-cf4f-7000-8000-000000000092",
    width: 6,
  };
}
