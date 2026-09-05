import type { DfirCustodyEvent } from "@periapsis/contracts";

export const maximumDfirCustodyEvents = 1_000;

// Wire-shape consistency, not cryptographic verification of the server's hashes.
export function validEvidenceCustody(
  version: number,
  custody: readonly DfirCustodyEvent[],
): boolean {
  return (
    Number.isInteger(version) &&
    version >= 1 &&
    version <= maximumDfirCustodyEvents &&
    custody.length === version &&
    new Set(custody.map((event) => event.id)).size === custody.length &&
    custody[0]?.previousHash !== "0".repeat(64) &&
    custody.every(
      (event, index) =>
        event.sequence === index + 1 &&
        (index === 0 || event.previousHash === custody[index - 1]?.eventHash),
    )
  );
}
