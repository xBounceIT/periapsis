import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  platformFederatedExternalIdentities,
  platformFederatedExternalIdentityAliases,
  platformIdentityAccountCommands,
  users,
} from "../src/schema/index.js";

const runtimeSource = readFileSync(
  resolve(import.meta.dirname, "../src/schema/identity-platform-runtime.ts"),
  "utf8",
);
const packageManifest = readFileSync(
  resolve(import.meta.dirname, "../package.json"),
  "utf8",
);
const runtimeHarness = readFileSync(
  resolve(import.meta.dirname, "security/platform-identity-account-runtime.ts"),
  "utf8",
);

const columnNames = (
  table:
    | typeof platformFederatedExternalIdentities
    | typeof platformFederatedExternalIdentityAliases
    | typeof platformIdentityAccountCommands
    | typeof users,
): string[] => getTableConfig(table).columns.map((column) => column.name);

describe("platform identity-account canonical schema", () => {
  it("reuses the provider-global identity tombstone as the account aggregate", () => {
    const identity = getTableConfig(platformFederatedExternalIdentities);
    const aliases = getTableConfig(platformFederatedExternalIdentityAliases);

    expect(columnNames(platformFederatedExternalIdentities)).toEqual(
      expect.arrayContaining([
        "id",
        "platform_provider_id",
        "user_id",
        "subject_format",
        "subject_ciphertext",
        "subject_nonce",
        "key_version",
        "admitted_configuration_revision",
        "admitted_security_revision",
        "last_observation_state",
        "last_observed_at",
        "retired_at",
        "version",
        "resource_version",
        "created_at",
        "updated_at",
      ]),
    );
    expect(columnNames(platformFederatedExternalIdentities)).not.toEqual(
      expect.arrayContaining(["retired_by_user_id", "retire_reason"]),
    );
    expect(identity.enableRLS).toBe(true);
    expect(identity.policies).toHaveLength(0);
    expect(aliases.enableRLS).toBe(true);
    expect(aliases.policies).toHaveLength(0);
    expect(identity.indexes.map((item) => item.config.name)).toContain(
      "platform_federated_external_identities_live_provider_cursor_idx",
    );
    expect(
      identity.uniqueConstraints.map((constraint) => constraint.name),
    ).toEqual(
      expect.arrayContaining([
        "platform_federated_external_identities_provider_key",
        "platform_federated_external_identities_exact_key",
      ]),
    );
    expect(
      aliases.foreignKeys.map((foreignKey) => foreignKey.getName()),
    ).toContain("platform_federated_external_identity_aliases_identity_fk");
  });

  it("models representation revisions independently from provenance", () => {
    const identity = getTableConfig(platformFederatedExternalIdentities);
    const localUsers = getTableConfig(users);

    expect(columnNames(users)).toEqual(
      expect.arrayContaining([
        "display_name",
        "email",
        "active",
        "version",
        "updated_at",
      ]),
    );
    expect(identity.checks.map((constraint) => constraint.name)).toContain(
      "platform_federated_external_identities_lifecycle_check",
    );
    expect(identity.checks.map((constraint) => constraint.name)).toContain(
      "platform_federated_external_identities_observation_state_check",
    );
    expect(runtimeSource).toContain(
      'lastObservationState: text("last_observation_state")',
    );
    expect(runtimeSource).toContain(
      "${table.lastObservationState} in ('known', 'legacy_unknown')",
    );
    expect(runtimeSource).toContain(
      "${table.lastObservationState} = 'known' or (",
    );
    expect(runtimeSource).toContain("${table.resourceVersion} = 1");
    expect(runtimeSource).toContain(
      "${table.lastObservedAt} = ${table.retiredAt}",
    );
    expect(localUsers.checks.map((constraint) => constraint.name)).toContain(
      "users_version_check",
    );
  });

  it("binds bounded prelink replay to actor, operation, provider, and public payload", () => {
    const command = getTableConfig(platformIdentityAccountCommands);
    const replayKey = command.uniqueConstraints.find(
      (constraint) =>
        constraint.name === "platform_identity_account_commands_replay_key",
    );

    expect(columnNames(platformIdentityAccountCommands)).toEqual([
      "id",
      "actor_user_id",
      "operation",
      "platform_provider_id",
      "key_digest",
      "public_request_digest",
      "result_account_id",
      "result_version",
      "created_at",
      "expires_at",
    ]);
    expect(columnNames(platformIdentityAccountCommands)).not.toEqual(
      expect.arrayContaining([
        "tenant_id",
        "issuer",
        "subject_ciphertext",
        "subject_nonce",
        "subject_digest",
        "key_version",
      ]),
    );
    expect(command.enableRLS).toBe(true);
    expect(command.policies).toHaveLength(0);
    expect(replayKey?.columns.map((column) => column.name)).toEqual([
      "actor_user_id",
      "operation",
      "platform_provider_id",
      "key_digest",
    ]);
    expect(command.indexes.map((item) => item.config.name)).toEqual(
      expect.arrayContaining([
        "platform_identity_account_commands_expiry_idx",
        "platform_identity_account_commands_result_idx",
      ]),
    );
    expect(command.foreignKeys).toHaveLength(3);
    expect(
      command.foreignKeys.map((foreignKey) => foreignKey.getName()),
    ).toContain("platform_identity_account_commands_result_fk");
    expect(command.checks.map((constraint) => constraint.name)).toEqual([
      "platform_identity_account_commands_id_uuidv7_check",
      "platform_identity_account_commands_operation_check",
      "platform_identity_account_commands_digest_check",
      "platform_identity_account_commands_result_check",
      "platform_identity_account_commands_retention_check",
    ]);
  });

  it("defaults replay retention to 24 hours and caps it at seven days", () => {
    const start = runtimeSource.indexOf(
      "export const platformIdentityAccountCommands",
    );
    const end = runtimeSource.indexOf("/** Tenant-owned admission", start);
    const commandSource = runtimeSource.slice(start, end);

    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    expect(commandSource).toContain('"platform_identity_account_commands"');
    expect(commandSource).toContain(
      "sql`${table.operation} = 'account.prelink'`",
    );
    expect(commandSource).toContain(
      'publicRequestDigest: bytea("public_request_digest")',
    );
    expect(commandSource).toContain(
      "default(sql`now() + interval '24 hours'`)",
    );
    expect(commandSource).toContain(
      "${table.expiresAt} <= ${table.createdAt} + interval '7 days'",
    );
    expect(commandSource).not.toMatch(
      /issuer|subjectCiphertext|subjectNonce|subjectDigest|keyVersion/u,
    );
  });

  it("keeps the focused PostgreSQL 18 account proof in the aggregate gate", () => {
    expect(packageManifest).toContain(
      '"test:security:platform-identity-accounts": "tsx tests/security/platform-identity-account-runtime.ts"',
    );
    expect(packageManifest).toContain(
      "corepack pnpm run test:security:platform-identity-accounts",
    );
    for (const invariant of [
      "platform_identity_account_commands",
      "platform.identity_account.read",
      "platform.identity_account.manage",
      "missing persisted alias",
      "changed issuer payload",
      "exact replay advanced audit or account timestamps",
      "exact replay after provider archive",
      "exact replay after subject key retirement",
      "platform identity account commands are immutable",
      "subject_material_included",
      "auth_session_tenant_platform_federated_provenance",
      "compositeRepresentationValidator",
      "observation changed the representation validator",
      "user projection changed the representation validator",
      "observation invalidated security provenance",
      "tenant_post_primary_continuations",
      "tenant_platform_federated_provider_access_grants",
      "tenant_mfa_subjects",
      "tenant.platform_identity_account.retired",
      "platform.identity_account.retired",
      "failed final audit append did not roll back dependent invalidation",
    ]) {
      expect(runtimeHarness).toContain(invariant);
    }
  });
});
