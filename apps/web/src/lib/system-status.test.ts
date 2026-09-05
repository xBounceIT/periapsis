import { describe, expect, it } from "vitest";

import { formatCheckedAt } from "./system-status";

describe("formatCheckedAt", () => {
  it("returns an explicit fallback for an invalid timestamp", () => {
    expect(formatCheckedAt("not-a-date", "en-US")).toBe(
      "Check time unavailable",
    );
  });

  it("includes a localized date for a valid UTC timestamp", () => {
    expect(formatCheckedAt("2026-08-23T10:30:00Z", "en-GB")).toContain(
      "23 Aug 2026",
    );
  });
});
