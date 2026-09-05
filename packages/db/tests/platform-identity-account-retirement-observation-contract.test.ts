import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const sealedV36 = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0168_platform_identity_account_security.sql",
  ),
  "utf8",
);
const repair = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0170_platform_identity_account_retirement_observation_fix.sql",
  ),
  "utf8",
);

describe("platform identity-account retirement observation repair", () => {
  it("keeps the sealed v36 implementation byte-identical", () => {
    expect(createHash("sha256").update(sealedV36).digest("hex")).toBe(
      "3b476e993bbd630fa60e1c01b9bea7e44a7b7ddc580e43581b1d089f34793eeb",
    );
  });

  it("supersedes the identity guard forward-only and preserves observations on retirement", () => {
    expect(repair).toContain(
      "CREATE FUNCTION app.guard_platform_federated_external_identity_v2()",
    );
    expect(repair).toContain(
      "DROP TRIGGER platform_federated_external_identities_guard_v1",
    );
    expect(repair).toContain(
      "CREATE TRIGGER platform_federated_external_identities_guard_v2",
    );
    expect(repair).toContain("NEW.last_observed_at := OLD.last_observed_at");
    expect(repair).toContain("NEW.version <> OLD.version + 1");
    expect(repair).toContain("NEW.version <> OLD.version");
    expect(repair).toContain(
      "REVOKE ALL ON FUNCTION app.guard_platform_federated_external_identity_v2()",
    );
  });
});
