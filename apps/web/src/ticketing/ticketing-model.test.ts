import { describe, expect, it } from "vitest";

import {
  codePointCompare,
  hasAllTicketPermissionsAtOneScope,
  parseStatusFilter,
  parseTagInput,
} from "./ticketing-model";

describe("ticketing-model", () => {
  it("normalizes, deduplicates, and code-point sorts tags deterministically", () => {
    expect(parseTagInput(" zeta,alpha, zeta, 🕵, ångström, ")).toEqual([
      "alpha",
      "zeta",
      "ångström",
      "🕵",
    ]);
  });

  it.each([
    ["", undefined],
    [" new, investigating, new ", ["investigating", "new"]],
  ] as const)("parses workflow filters from %j", (source, expected) => {
    expect(parseStatusFilter(source)).toEqual(expected);
  });

  it("does not depend on locale collation", () => {
    expect(["🕵", "z", "a", "å"].toSorted(codePointCompare)).toEqual([
      "a",
      "z",
      "å",
      "🕵",
    ]);
  });

  it("requires compound permissions at the same authorization scope", () => {
    const grants = new Set([
      "alert.read:assigned",
      "alert.activity.read:operator_team",
    ]);
    const hasPermission = (permission: string, scope?: string) =>
      grants.has(`${permission}:${scope}`);

    expect(
      hasAllTicketPermissionsAtOneScope(hasPermission, [
        "alert.read",
        "alert.activity.read",
      ]),
    ).toBe(false);

    grants.add("alert.activity.read:assigned");
    expect(
      hasAllTicketPermissionsAtOneScope(hasPermission, [
        "alert.read",
        "alert.activity.read",
      ]),
    ).toBe(true);
  });
});
