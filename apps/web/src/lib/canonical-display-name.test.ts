import { describe, expect, it } from "vitest";

import {
  hasGoTrimSpaceAtEdge,
  hasUnpairedSurrogate,
  isCanonicalDisplayName,
} from "./canonical-display-name";

describe("isCanonicalDisplayName", () => {
  it.each(["\u200e", "\u200f", "\u202e", "\u2066", "\u2069"])(
    "rejects bidi control %j in a frozen comment or watcher name",
    (character) => {
      expect(isCanonicalDisplayName(`Analyst${character}One`, 200)).toBe(false);
    },
  );

  it("preserves ordinary internal Unicode spacing", () => {
    expect(isCanonicalDisplayName("Analyst\u2003One", 200)).toBe(true);
  });

  it("rejects every unpaired surrogate position without rejecting a pair", () => {
    const high = String.fromCharCode(0xd800);
    const low = String.fromCharCode(0xdc00);

    expect(hasUnpairedSurrogate(high)).toBe(true);
    expect(hasUnpairedSurrogate(`Analyst${high}`)).toBe(true);
    expect(hasUnpairedSurrogate(`${low}Analyst`)).toBe(true);
    expect(hasUnpairedSurrogate(`${high}${low}`)).toBe(false);
    expect(isCanonicalDisplayName(`Analyst${high}`, 200)).toBe(false);
  });

  it("matches Go TrimSpace at Unicode edges without rejecting internal spacing", () => {
    for (const value of [
      " Analyst",
      "Analyst\u00a0",
      "\u1680Analyst",
      "Analyst\u3000",
    ]) {
      expect(hasGoTrimSpaceAtEdge(value)).toBe(true);
      expect(isCanonicalDisplayName(value, 200)).toBe(false);
    }
    expect(hasGoTrimSpaceAtEdge("Analyst\u2003One")).toBe(false);
  });
});
