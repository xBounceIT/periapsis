import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("tenant authority matrix mobile layout", () => {
  it("stacks tuple identity above two flexible actions without clipping at 390px", () => {
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
      ".authority-matrix__header {\n    display: none;\n  }",
    );
    expect(mobileRules).toContain(
      "grid-template-columns: repeat(2, minmax(0, 1fr));",
    );
    expect(mobileRules).toContain(
      ".authority-matrix__row > div:first-child {\n    grid-column: 1 / -1;\n  }",
    );
    expect(mobileRules).not.toContain(
      "grid-template-columns: minmax(8rem, 1fr) 5.5rem 5.5rem;",
    );
  });
});
