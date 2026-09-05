import { describe, expect, it } from "vitest";

import {
  validatePlatformIdentityAccountPrelinkConfirmation,
  validatePlatformIdentityAccountPrelinkDraft,
  validatePlatformIdentityAccountPrelinkIssuer,
  validatePlatformIdentityAccountRetirement,
} from "./platform-auth-provider-account-model";

const accountId = "0198c97d-cf4f-7000-8000-000000000089";

describe("platform identity-account form validation", () => {
  it("accepts an exact case-sensitive subject and UUIDv7 target", () => {
    expect(
      validatePlatformIdentityAccountPrelinkDraft({
        auditReason: "Prelink workforce identity",
        subject: " Subject/Case-Sensitive ",
        userId: "0198c97d-cf4f-7000-8000-000000000090",
      }),
    ).toEqual([]);
  });

  it.each([
    "",
    "subject\u0000value",
    "subject\u061cvalue",
    "subject\u202evalue",
    "x".repeat(1025),
  ])("rejects a hostile or overlong subject %j", (subject) => {
    expect(
      validatePlatformIdentityAccountPrelinkDraft({
        auditReason: "Prelink workforce identity",
        subject,
        userId: "0198c97d-cf4f-7000-8000-000000000090",
      }),
    ).not.toEqual([]);
  });

  it("rejects non-v7 targets and unsafe audit headers", () => {
    expect(
      validatePlatformIdentityAccountPrelinkDraft({
        auditReason: "Includes,comma",
        subject: "subject",
        userId: "0198c97d-cf4f-4000-8000-000000000090",
      }),
    ).toHaveLength(2);
  });

  it("requires an exact HTTPS issuer and exact second-entry confirmation", () => {
    const draft = {
      auditReason: "Prelink workforce identity",
      subject: "Subject/Case-Sensitive",
      userId: "0198c97d-cf4f-7000-8000-000000000090",
    } as const;
    expect(
      validatePlatformIdentityAccountPrelinkIssuer(
        "https://identity.example.com/tenant",
      ),
    ).toEqual([]);
    expect(
      validatePlatformIdentityAccountPrelinkIssuer(
        "https://identity.example.com/tenant?unsafe=true",
      ),
    ).not.toEqual([]);
    expect(
      validatePlatformIdentityAccountPrelinkConfirmation(draft, {
        subject: draft.subject,
        userId: draft.userId,
      }),
    ).toEqual([]);
    expect(
      validatePlatformIdentityAccountPrelinkConfirmation(draft, {
        subject: draft.subject.toLowerCase(),
        userId: `${draft.userId} `,
      }),
    ).toHaveLength(2);
  });

  it("requires exact account confirmation and a safe retirement reason", () => {
    expect(
      validatePlatformIdentityAccountRetirement(
        accountId,
        accountId,
        "Retire compromised identity link",
      ),
    ).toEqual([]);
    expect(
      validatePlatformIdentityAccountRetirement(
        accountId,
        `${accountId} `,
        "Retire,identity",
      ),
    ).toHaveLength(2);
  });
});
