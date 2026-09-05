import { describe, expect, it } from "vitest";

import { hasInstantReached, parseRfc3339Instant } from "./rfc3339-instant";

describe("RFC3339 instants", () => {
  it("preserves nanoseconds when comparing contract-valid response timestamps", () => {
    const now = parseRfc3339Instant("2035-01-01T00:00:00.123Z");
    const oneNanosecondLater = parseRfc3339Instant(
      "2035-01-01T00:00:00.123000001Z",
    );
    expect(now).toBeDefined();
    expect(oneNanosecondLater).toBeDefined();
    if (now === undefined || oneNanosecondLater === undefined) return;

    expect(oneNanosecondLater - now).toBe(1n);
    expect(hasInstantReached(oneNanosecondLater, now)).toBe(false);
    expect(hasInstantReached(oneNanosecondLater, oneNanosecondLater)).toBe(
      true,
    );
  });

  it.each([
    "2035-01-01T00:00:00.123456789Z",
    "2035-01-01T00:00:00.1234567890Z",
    "2035-01-01T00:00:00.123456789000000000Z",
    "2035-01-01T02:30:00.000000001+02:30",
    "2035-01-01T02:30:00.000000001000+02:30",
  ])("accepts a timezone-qualified nanosecond instant (%s)", (value) => {
    expect(parseRfc3339Instant(value)).toBeDefined();
  });

  it("preserves the first nine fractional digits when finer precision is all zero", () => {
    expect(parseRfc3339Instant("2035-01-01T00:00:00.1234567890000Z")).toBe(
      parseRfc3339Instant("2035-01-01T00:00:00.123456789Z"),
    );
  });

  it.each([
    "2035-02-29T00:00:00Z",
    "2035-01-01T00:00:00.1234567891Z",
    "2035-01-01T00:00:00+24:00",
  ])("rejects a malformed instant (%s)", (value) => {
    expect(parseRfc3339Instant(value)).toBeUndefined();
  });
});
