import { describe, expect, it } from "vitest";

import { cn } from "./utils";

describe("cn", () => {
  it("merges conditional and conflicting Tailwind classes deterministically", () => {
    expect(cn("px-2", false, "px-4")).toBe("px-4");
  });
});
