import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const repositoryRoot = resolve(import.meta.dirname, "../../..");
const schemaMigration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0171_platform_identity_account_resource_version.sql",
  ),
  "utf8",
);
const securityMigration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0172_platform_identity_account_representation_security.sql",
  ),
  "utf8",
);
const observationSchemaMigration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0174_platform_identity_account_observation_state.sql",
  ),
  "utf8",
);
const observationSecurityMigration = readFileSync(
  resolve(
    repositoryRoot,
    "packages/db/migrations/0175_platform_identity_account_observation_security.sql",
  ),
  "utf8",
);

function functionBody(source: string, name: string): string {
  const start = source.indexOf(`FUNCTION app.${name}(`);
  const bodyStart = source.indexOf("AS $function$", start);
  const end = source.indexOf("$function$;", bodyStart);

  expect(start, name).toBeGreaterThanOrEqual(0);
  expect(bodyStart, name).toBeGreaterThan(start);
  expect(end, name).toBeGreaterThan(bodyStart);
  return source.slice(bodyStart, end);
}

describe("platform identity-account v37 representation predecessor", () => {
  it("adds both representation counters through the canonical schema migration", () => {
    expect(schemaMigration).toContain(
      'ALTER TABLE "users" ADD COLUMN "version" bigint DEFAULT 1 NOT NULL',
    );
    expect(schemaMigration).toContain(
      'ALTER TABLE "platform_federated_external_identities" ADD COLUMN "resource_version" bigint DEFAULT 1 NOT NULL',
    );
    expect(schemaMigration).toContain('"users_version_check"');
    expect(schemaMigration).toContain(
      '"platform_federated_external_identities"."resource_version" between 1 and 2147483647',
    );
  });

  it("advances only the representation revision for observations", () => {
    const guard = functionBody(
      securityMigration,
      "guard_platform_federated_external_identity_v3",
    );

    expect(guard).toContain("IF NEW.retired_at IS NULL THEN");
    expect(guard).toContain("NEW.version <> OLD.version");
    expect(guard).toContain("NEW.resource_version := OLD.resource_version + 1");
    expect(guard).toContain("NEW.version <> OLD.version + 1");
    expect(guard).toContain("NEW.last_observed_at := OLD.last_observed_at");
    expect(securityMigration).toContain(
      "DROP TRIGGER platform_federated_external_identities_guard_v2",
    );
    expect(securityMigration).toContain(
      "CREATE TRIGGER platform_federated_external_identities_guard_v3",
    );
  });

  it("versions the joined user projection without a cross-table trigger", () => {
    const guard = functionBody(
      securityMigration,
      "guard_user_platform_identity_projection_v1",
    );

    expect(guard).toContain("ROW(NEW.display_name, NEW.email, NEW.active)");
    expect(guard).toContain("NEW.version := OLD.version + 1");
    expect(guard).toContain("NEW.updated_at := transaction_timestamp()");
    expect(guard).not.toContain("platform_federated_external_identities");
    expect(securityMigration).toContain(
      "BEFORE UPDATE OF display_name, email, active, version ON public.users",
    );
  });

  it("projects both components of the strong composite validator", () => {
    const document = functionBody(
      securityMigration,
      "private_platform_identity_account_document_v1",
    );

    expect(document).toContain("'version', local_user.version");
    expect(document).toContain("'version', identity.resource_version");
    expect(document).not.toContain("'version', identity.version");
  });

  it("retires with an atomic identity-then-user composite CAS", () => {
    const retirement = functionBody(
      securityMigration,
      "retire_platform_identity_account_v2",
    );
    const identityLock = retirement.indexOf(
      "FROM ONLY public.platform_federated_external_identities AS identity",
    );
    const userLock = retirement.indexOf("FROM ONLY public.users AS local_user");

    expect(securityMigration).toContain("p_expected_user_version bigint");
    expect(identityLock).toBeGreaterThanOrEqual(0);
    expect(userLock).toBeGreaterThan(identityLock);
    expect(retirement).toContain(
      "identity_record.resource_version <> p_expected_version",
    );
    expect(retirement).toContain(
      "user_record.version <> p_expected_user_version",
    );
    expect(retirement).toContain(
      "resource_version = identity.resource_version + 1",
    );
    expect(retirement).toContain("version = identity.version + 1");
    expect(retirement).toContain("'user_version', user_record.version");
    expect(retirement).toContain(
      "'previous_security_revision', identity_record.version",
    );
    expect(securityMigration).toContain(
      "app.retire_platform_identity_account_v1(\n    uuid, uuid, uuid, bigint, uuid",
    );
    expect(securityMigration).toContain(
      "GRANT EXECUTE ON FUNCTION app.retire_platform_identity_account_v2(",
    );
  });
});

describe("platform identity-account observation representation", () => {
  it("adds a deny-by-default provenance discriminator to the canonical relation", () => {
    expect(observationSchemaMigration).toContain(
      "ADD COLUMN \"last_observation_state\" text DEFAULT 'known' NOT NULL",
    );
    expect(observationSchemaMigration).toContain(
      'CONSTRAINT "platform_federated_external_identities_observation_state_check"',
    );
    expect(observationSchemaMigration).toContain(
      "\"last_observation_state\" in ('known', 'legacy_unknown')",
    );
    expect(observationSchemaMigration).toContain(
      "\"last_observation_state\" = 'known' or (",
    );
    expect(observationSchemaMigration).toContain('"resource_version" = 1');
    expect(observationSchemaMigration).toContain(
      '"last_observed_at" = "platform_federated_external_identities"."retired_at"',
    );
  });

  it("classifies only the exact irreversible v36 retirement shape", () => {
    const classificationStart = observationSecurityMigration.indexOf(
      "UPDATE ONLY public.platform_federated_external_identities AS identity",
    );
    const classificationEnd = observationSecurityMigration.indexOf(
      "ALTER TABLE ONLY public.platform_federated_external_identities\n  ENABLE TRIGGER",
      classificationStart,
    );
    const classification = observationSecurityMigration.slice(
      classificationStart,
      classificationEnd,
    );

    expect(classificationStart).toBeGreaterThanOrEqual(0);
    expect(classificationEnd).toBeGreaterThan(classificationStart);
    expect(classification).toContain(
      "SET last_observation_state = 'legacy_unknown'",
    );
    expect(classification).toContain("identity.retired_at IS NOT NULL");
    expect(classification).toContain("identity.resource_version = 1");
    expect(classification).toContain(
      "identity.last_observed_at = identity.retired_at",
    );
    expect(classification).not.toContain("resource_version >= 2");
  });

  it("projects explicit observation provenance and nulls only legacy-unknown timestamps", () => {
    const document = functionBody(
      observationSecurityMigration,
      "private_platform_identity_account_document_v2",
    );

    expect(document).toContain(
      "'lastObservationState', identity.last_observation_state",
    );
    expect(document).toContain("'lastObservedAt', CASE");
    expect(document).toContain(
      "WHEN identity.last_observation_state = 'known'",
    );
    expect(document).toContain("THEN identity.last_observed_at");
    expect(document).toContain("ELSE NULL");
  });

  it("keeps provenance immutable across observations and retirement", () => {
    const guard = functionBody(
      observationSecurityMigration,
      "guard_platform_federated_external_identity_v4",
    );

    expect(guard).toContain("NEW.last_observation_state <> 'known'");
    expect(guard).toContain("NEW.last_observation_state,");
    expect(guard).toContain("OLD.last_observation_state,");
    expect(guard).toContain(
      "NEW.last_observation_state := OLD.last_observation_state",
    );
    expect(observationSecurityMigration).toContain(
      "DROP TRIGGER platform_federated_external_identities_guard_v3",
    );
    expect(observationSecurityMigration).toContain(
      "CREATE TRIGGER platform_federated_external_identities_guard_v4",
    );
  });

  it("publishes only the observation-aware v2/v3 account ABI to the API", () => {
    for (const name of [
      "list_platform_identity_accounts_v2",
      "get_platform_identity_account_v2",
      "prelink_platform_identity_account_v2",
      "retire_platform_identity_account_v3",
    ]) {
      expect(observationSecurityMigration).toContain(
        `CREATE FUNCTION app.${name}(`,
      );
    }
    for (const name of [
      "list_platform_identity_accounts_v2",
      "get_platform_identity_account_v2",
      "prelink_platform_identity_account_v2",
      "retire_platform_identity_account_v3",
    ]) {
      expect(observationSecurityMigration).toMatch(
        new RegExp(
          `GRANT EXECUTE ON FUNCTION[\\s\\S]*app\\.${name}\\([\\s\\S]*TO periapsis_api;`,
          "u",
        ),
      );
    }

    const revokeStart = observationSecurityMigration.indexOf(
      "REVOKE ALL ON FUNCTION",
    );
    const revokeEnd = observationSecurityMigration.indexOf(
      "FROM PUBLIC, periapsis_api",
      revokeStart,
    );
    const revokedAbi = observationSecurityMigration.slice(
      revokeStart,
      revokeEnd,
    );
    for (const retiredName of [
      "list_platform_identity_accounts_v1",
      "get_platform_identity_account_v1",
      "prelink_platform_identity_account_v1",
      "retire_platform_identity_account_v2",
    ]) {
      expect(revokedAbi).toContain(`app.${retiredName}(`);
    }
  });

  it("reprojects the wrapped mutations with the observation-aware document", () => {
    const prelink = functionBody(
      observationSecurityMigration,
      "prelink_platform_identity_account_v2",
    );
    const retirement = functionBody(
      observationSecurityMigration,
      "retire_platform_identity_account_v3",
    );

    expect(prelink).toContain("FROM app.prelink_platform_identity_account_v1(");
    expect(prelink).toContain(
      "app.private_platform_identity_account_document_v2(",
    );
    expect(retirement).toContain(
      "FROM app.retire_platform_identity_account_v2(",
    );
    expect(retirement).toContain(
      "app.private_platform_identity_account_document_v2(",
    );
  });
});
