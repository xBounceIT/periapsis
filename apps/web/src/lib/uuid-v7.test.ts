import { describe, expect, it } from "vitest";

import { generateUuidV7 } from "./uuid-v7";

describe("generateUuidV7", () => {
  it("pins the 48-bit timestamp and RFC variant without weakening randomness", () => {
    const value = generateUuidV7(0x0199_1c20_7d5f, (target) => {
      target.fill(0xff);
    });
    expect(value).toBe("01991c20-7d5f-7fff-bfff-ffffffffffff");
    expect(value).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );
  });

  it("rejects timestamps that cannot be represented by UUIDv7", () => {
    expect(() => generateUuidV7(-1)).toThrow(RangeError);
    expect(() => generateUuidV7(Number.MAX_SAFE_INTEGER)).toThrow(RangeError);
    expect(() => generateUuidV7(1.5)).toThrow(RangeError);
  });
});
