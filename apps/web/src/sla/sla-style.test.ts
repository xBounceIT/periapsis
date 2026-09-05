import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const stylesheet = readFileSync(
  resolve(process.cwd(), "src", "sla", "sla.css"),
  "utf8",
);

describe("SLA workspace visual contract", () => {
  it("keeps responsive, dark, keyboard-focus, and reduced-motion states explicit", () => {
    expect(stylesheet).toContain(".sla-rail > button:focus-visible");
    expect(stylesheet).toContain("@media (max-width: 52rem)");
    expect(stylesheet).toContain("@media (prefers-color-scheme: dark)");
    expect(stylesheet).toContain("@media (prefers-reduced-motion: reduce)");
  });

  it("uses textual states in addition to color-coded clock borders", () => {
    expect(stylesheet).toContain(".sla-metric--at_risk");
    expect(stylesheet).toContain(".sla-metric--breached");
    expect(stylesheet).toContain(".sla-metric--completed");
  });
});
