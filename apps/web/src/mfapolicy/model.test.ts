import { describe, expect, it } from "vitest";

import {
  bindMfaPolicyCommand,
  clearMfaPolicyCommand,
  isCanonicalUuidV7,
  type MfaPolicyCommandReference,
} from "./model";

describe("MFA policy command binding", () => {
  it("keeps one UUIDv7 for an uncertain semantic retry", () => {
    const reference: MfaPolicyCommandReference = { current: null };
    const input = {
      expectedRevision: 0 as const,
      requirement: {
        enrollmentDeadline: null,
        freshnessSeconds: 300,
        level: "mfa" as const,
        localRequired: true,
      },
      target: { scope: "platform_floor" as const },
    };

    const first = bindMfaPolicyCommand(
      reference,
      { kind: "platform" },
      "publish",
      "Reviewed recovery floor",
      input,
    );
    const retry = bindMfaPolicyCommand(
      reference,
      { kind: "platform" },
      "publish",
      "Reviewed recovery floor",
      { ...input, requirement: { ...input.requirement } },
    );

    expect(isCanonicalUuidV7(first)).toBe(true);
    expect(retry).toBe(first);
  });

  it("rotates the command after a semantic change or confirmed success", () => {
    const reference: MfaPolicyCommandReference = { current: null };
    const input = {
      expectedRevision: 1,
      requirement: {
        enrollmentDeadline: null,
        freshnessSeconds: 300,
        level: "mfa" as const,
        localRequired: true,
      },
      target: { scope: "platform_floor" as const },
    };
    const first = bindMfaPolicyCommand(
      reference,
      { kind: "platform" },
      "publish",
      "Replace floor",
      input,
    );
    const changed = bindMfaPolicyCommand(
      reference,
      { kind: "platform" },
      "publish",
      "Replace floor",
      {
        ...input,
        requirement: { ...input.requirement, freshnessSeconds: 60 },
      },
    );
    clearMfaPolicyCommand(reference);
    const afterSuccess = bindMfaPolicyCommand(
      reference,
      { kind: "platform" },
      "publish",
      "Replace floor",
      {
        ...input,
        requirement: { ...input.requirement, freshnessSeconds: 60 },
      },
    );

    expect(changed).not.toBe(first);
    expect(afterSuccess).not.toBe(changed);
  });
});
