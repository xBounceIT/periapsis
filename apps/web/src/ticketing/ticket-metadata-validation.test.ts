import { describe, expect, it } from "vitest";

import {
  containsDisallowedMetadataControl,
  hasMetadataEdgeWhitespace,
  metadataCodePointLength,
  trimMetadataEdges,
} from "./ticket-metadata-validation";

const canonicalEdgeWhitespace = [
  "\u0009",
  "\u000A",
  "\u000B",
  "\u000C",
  "\u000D",
  "\u0020",
  "\u0085",
  "\u00A0",
  "\u1680",
  "\u2000",
  "\u2001",
  "\u2002",
  "\u2003",
  "\u2004",
  "\u2005",
  "\u2006",
  "\u2007",
  "\u2008",
  "\u2009",
  "\u200A",
  "\u2028",
  "\u2029",
  "\u202F",
  "\u205F",
  "\u3000",
] as const;

describe("ticket metadata validation parity", () => {
  it("uses the canonical Unicode White_Space edge set without treating FEFF as whitespace", () => {
    for (const whitespace of canonicalEdgeWhitespace) {
      expect(hasMetadataEdgeWhitespace(`${whitespace}value`)).toBe(true);
      expect(hasMetadataEdgeWhitespace(`value${whitespace}`)).toBe(true);
      expect(trimMetadataEdges(`${whitespace}value${whitespace}`)).toBe(
        "value",
      );
    }

    expect(hasMetadataEdgeWhitespace("\uFEFFvalue\uFEFF")).toBe(false);
    expect(trimMetadataEdges("\uFEFFvalue\uFEFF")).toBe("\uFEFFvalue\uFEFF");
  });

  it("allows only TAB, LF, and CR as internal multiline controls", () => {
    expect(
      containsDisallowedMetadataControl("first\tsecond\nthird\rfourth", true),
    ).toBe(false);
    expect(containsDisallowedMetadataControl("first\vsecond", true)).toBe(true);
    expect(containsDisallowedMetadataControl("first\nsecond", false)).toBe(
      true,
    );
    expect(containsDisallowedMetadataControl("first\u0085second", true)).toBe(
      true,
    );
  });

  it("counts Unicode code points instead of UTF-16 code units", () => {
    expect(metadataCodePointLength("😀".repeat(240))).toBe(240);
  });
});
