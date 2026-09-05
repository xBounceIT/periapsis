import { afterEach, describe, expect, it, vi } from "vitest";

import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import { credentialInput } from "./service-account-model";

describe("credentialInput", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("canonicalizes network order before binding the idempotency payload", () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-08-25T10:00:00Z"));
    const first = credentialInput(
      "Collector",
      "2026-09-20T10:00:00Z",
      "2001:db8::/48\n10.0.0.0/8\n2.0.0.0/8\n2001:db8::/32",
    );
    const reordered = credentialInput(
      "Collector",
      "2026-09-20T10:00:00Z",
      "2.0.0.0/8\n2001:db8::/32\n10.0.0.0/8\n2001:db8::/48",
    );
    if (!first.ok || !reordered.ok) {
      throw new Error("canonical credential input was rejected");
    }

    expect(first.allowedNetworks).toEqual([
      "2.0.0.0/8",
      "10.0.0.0/8",
      "2001:db8::/32",
      "2001:db8::/48",
    ]);
    expect(reordered.allowedNetworks).toEqual(first.allowedNetworks);

    const reference: {
      current: { fingerprint: string; key: string } | null;
    } = { current: null };
    const firstKey = idempotencyKeyForPayload(reference, first);
    const reorderedKey = idempotencyKeyForPayload(reference, reordered);
    expect(reorderedKey).toBe(firstKey);
  });
});
