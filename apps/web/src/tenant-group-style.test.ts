import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("tenant security-group mobile layout", () => {
  it("turns the two-edge rail and provenance grids into one readable 390px column", () => {
    const stylesheet = readFileSync(
      resolve(process.cwd(), "src", "app.css"),
      "utf8",
    );
    const mobileStart = stylesheet.indexOf("@media (max-width: 48rem)");
    const mobileEnd = stylesheet.indexOf(
      "@media (prefers-color-scheme: dark)",
      mobileStart,
    );
    const mobileRules = stylesheet.slice(mobileStart, mobileEnd);

    expect(mobileRules).toContain(
      ".access-path-rail {\n    grid-template-columns: 1fr;",
    );
    expect(mobileRules).toContain(
      ".access-path-rail__connector {\n    width: 1px;\n    height: 0.8rem;",
    );
    expect(mobileRules).toContain(
      ".edge-lifetime-fields,\n  .edge-provenance-grid,\n  .provenance-columns,\n  .inherited-edge-provenance,\n  .provenance-record dl {\n    grid-template-columns: 1fr;",
    );
    expect(mobileRules).toContain("width: calc(100vw - 1rem);");
  });
});
