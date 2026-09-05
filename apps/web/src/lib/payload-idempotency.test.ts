import { describe, expect, it } from "vitest";

import {
  idempotencyKeyForPayload,
  isPayloadBoundToIdempotencyKey,
} from "./payload-idempotency";

describe("idempotencyKeyForPayload", () => {
  it("reuses a key across object ordering and rotates it when canonical input changes", () => {
    const reference: {
      current: { fingerprint: string; key: string } | null;
    } = { current: null };

    expect(
      isPayloadBoundToIdempotencyKey(reference, {
        tenantId: "tenant-one",
        input: { policy: { permissions: [] }, name: "Triage" },
      }),
    ).toBe(false);

    const first = idempotencyKeyForPayload(reference, {
      input: { name: "Triage", policy: { permissions: [] } },
      tenantId: "tenant-one",
    });
    const reordered = idempotencyKeyForPayload(reference, {
      tenantId: "tenant-one",
      input: { policy: { permissions: [] }, name: "Triage" },
    });

    expect(
      isPayloadBoundToIdempotencyKey(reference, {
        tenantId: "tenant-one",
        input: { policy: { permissions: [] }, name: "Triage" },
      }),
    ).toBe(true);
    expect(
      isPayloadBoundToIdempotencyKey(reference, {
        tenantId: "tenant-one",
        input: { policy: { permissions: [] }, name: "Escalation" },
      }),
    ).toBe(false);
    const changed = idempotencyKeyForPayload(reference, {
      input: { name: "Escalation", policy: { permissions: [] } },
      tenantId: "tenant-one",
    });

    expect(reordered).toBe(first);
    expect(changed).not.toBe(first);
  });
});
