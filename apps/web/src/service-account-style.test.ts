import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

function source(path: string): string {
  return readFileSync(resolve(process.cwd(), "src", path), "utf8");
}

describe("service-account administration presentation contracts", () => {
  it("keeps one-time secrets in explicit no-store dialogs with readable tokens", () => {
    const credentialSource = source("pages/service-account-credentials.tsx");
    const stylesheet = source("app.css");
    const secretRule =
      /\.service-account-secret-boundary \.secret-value code\s*\{(?<body>[^}]*)\}/u.exec(
        stylesheet,
      )?.groups?.["body"];

    expect(
      credentialSource.match(/data-cache-policy="no-store"/gu),
    ).toHaveLength(2);
    expect(credentialSource).toContain("<SecretValue");
    expect(credentialSource).not.toMatch(
      /localStorage|sessionStorage|indexedDB|queryClient|useQuery|navigate\(|toast\(/u,
    );
    expect(secretRule).toContain("overflow: auto");
    expect(secretRule).toContain("white-space: normal");
    expect(secretRule).toContain("overflow-wrap: anywhere");
    expect(secretRule).not.toContain("text-overflow: ellipsis");
  });

  it("stacks the authority path, facts, and credential grid at mobile width", () => {
    const stylesheet = source("app.css");
    const mobileStart = stylesheet.indexOf("@media (max-width: 48rem)");
    const mobileEnd = stylesheet.indexOf(
      "@media (prefers-color-scheme: dark)",
      mobileStart,
    );
    const mobileRules = stylesheet.slice(mobileStart, mobileEnd);

    expect(mobileRules).toContain(
      ".service-account-authority-rail {\n    grid-template-columns: 1fr;",
    );
    expect(mobileRules).toContain(
      ".service-account-authority-connector {\n    width: 1px;\n    height: 0.8rem;",
    );
    expect(mobileRules).toContain(
      ".service-account-secret-boundary dl,\n  .service-account-two-column-form,\n  .service-account-credential-grid {\n    grid-template-columns: 1fr;",
    );
    expect(mobileRules).toContain("width: calc(100vw - 1rem);");
  });

  it("retains keyboard focus and a dark-mode secret boundary", () => {
    const stylesheet = source("app.css");
    const darkStart = stylesheet.indexOf("@media (prefers-color-scheme: dark)");
    const darkRules = stylesheet.slice(darkStart);

    expect(stylesheet).toContain(
      '.service-account-tabs button[aria-selected="true"]',
    );
    expect(stylesheet).toContain(
      ".service-account-tabs button:focus-visible,\n.service-account-tab-panel:focus-visible",
    );
    expect(darkRules).toContain(
      ".service-account-select,\n  .service-account-secret-boundary .secret-value",
    );
  });
});
