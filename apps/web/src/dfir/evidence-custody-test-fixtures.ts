import type { DfirCustodyEvent } from "@periapsis/contracts";

// Synthetic wire hashes test linkage only; cryptographic verification is server-owned.
export function evidenceCustodyFixture(
  first: DfirCustodyEvent,
  length: number,
): DfirCustodyEvent[] {
  return Array.from({ length }, (_, index) => ({
    ...first,
    action: index === 0 ? "collected" : "accessed",
    id: `0198c97d-cf4f-7000-8000-${(index + 100).toString(16).padStart(12, "0")}`,
    sequence: index + 1,
    previousHash: (index + 1).toString(16).padStart(64, "0"),
    eventHash: (index + 2).toString(16).padStart(64, "0"),
  }));
}
