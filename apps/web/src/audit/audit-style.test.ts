import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const stylesheet = readFileSync(
  resolve(process.cwd(), "src", "audit", "audit.css"),
  "utf8",
);

describe("audit workspace style contract", () => {
  it("keeps bounded responsive layouts and reduced-motion behavior", () => {
    expect(stylesheet).toContain("@media (max-width: 62rem)");
    expect(stylesheet).toContain("@media (max-width: 42rem)");
    expect(stylesheet).toContain("@media (prefers-reduced-motion: reduce)");
    expect(stylesheet).toMatch(
      /\.audit-event:hover\s*\{[^}]*transform:\s*none;/su,
    );
  });

  it("uses dark surfaces for fields, events, and evidence detail", () => {
    const darkMode = stylesheet.slice(
      stylesheet.indexOf("@media (prefers-color-scheme: dark)"),
      stylesheet.indexOf("@media (prefers-reduced-motion: reduce)"),
    );

    expect(darkMode).toContain("--audit-paper: #182634");
    expect(darkMode).toMatch(
      /\.audit-field input,[\s\S]*?\.audit-event,[\s\S]*?\.audit-detail\s*\{[\s\S]*?background:\s*#1d2e3c;/u,
    );
    expect(darkMode).toMatch(
      /\.audit-document pre\s*\{[^}]*color:\s*#dce7ec;/su,
    );
  });
});
