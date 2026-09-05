import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  operatorTeamAssignmentEpochs,
  operatorTeamRosterEntries,
  operatorTeams,
  platformCommands,
  tenantAuthorizationCommands,
} from "../src/schema/index.js";

const packageRoot = resolve(import.meta.dirname, "..");
const structuralMigrationNames = readdirSync(
  resolve(packageRoot, "migrations"),
).filter((fileName) => /^0027_[a-z0-9_]+\.sql$/.test(fileName));
const structuralMigration =
  structuralMigrationNames.length === 1
    ? readFileSync(
        resolve(packageRoot, "migrations", structuralMigrationNames[0]!),
        "utf8",
      )
    : "";
const hardeningStructuralMigration = readFileSync(
  resolve(packageRoot, "migrations/0030_operator_team_hardening.sql"),
  "utf8",
);

describe("Phase 2B.2b operator-team structural database contract", () => {
  it("keeps global team identity and payload-bound platform replay separate from tenants", () => {
    for (const table of [operatorTeams, platformCommands]) {
      const config = getTableConfig(table);
      expect(config.columns.map((column) => column.name)).not.toContain(
        "tenant_id",
      );
      expect(config.enableRLS).toBe(true);
      expect(config.policies).toHaveLength(0);
    }

    const commandConfig = getTableConfig(platformCommands);
    const teamConfig = getTableConfig(operatorTeams);
    expect(teamConfig.columns.map((column) => column.name)).toEqual(
      expect.arrayContaining([
        "created_by_user_id",
        "archived_at",
        "archived_by_user_id",
        "archive_reason",
        "version",
      ]),
    );
    expect(teamConfig.checks.map((constraint) => constraint.name)).toContain(
      "operator_teams_archive_check",
    );
    expect(
      teamConfig.columns.find((column) => column.name === "created_by_user_id")
        ?.notNull,
    ).toBe(false);
    expect(teamConfig.foreignKeys).toHaveLength(2);

    expect(commandConfig.columns.map((column) => column.name)).toEqual(
      expect.arrayContaining([
        "actor_user_id",
        "operation",
        "key_digest",
        "request_digest",
        "result_resource_id",
        "result_version",
        "expires_at",
      ]),
    );
    expect(
      commandConfig.uniqueConstraints.map((constraint) => constraint.name),
    ).toContain("platform_commands_replay_key");
    expect(commandConfig.checks.map((constraint) => constraint.name)).toEqual(
      expect.arrayContaining([
        "platform_commands_operation_check",
        "platform_commands_digest_check",
        "platform_commands_result_version_check",
        "platform_commands_retention_check",
      ]),
    );
  });

  it("models tenant assignment epochs with one active epoch per tenant and team", () => {
    const config = getTableConfig(operatorTeamAssignmentEpochs);
    const tenantColumn = config.columns.find(
      (column) => column.name === "tenant_id",
    );
    const activeIndex = config.indexes.find(
      (index) =>
        index.config.name === "operator_team_assignment_epochs_active_key",
    );
    const activeTeamIndex = config.indexes.find(
      (index) =>
        index.config.name === "operator_team_assignment_epochs_active_team_idx",
    );

    expect(tenantColumn?.notNull).toBe(true);
    expect(config.enableRLS).toBe(true);
    expect(config.policies).toHaveLength(0);
    expect(activeIndex?.config.unique).toBe(true);
    expect(activeIndex?.config.where).toBeDefined();
    expect(activeTeamIndex?.config.unique).toBe(false);
    expect(activeTeamIndex?.config.where).toBeDefined();
    expect(config.checks.map((constraint) => constraint.name)).toEqual(
      expect.arrayContaining([
        "operator_team_assignment_epochs_id_uuidv7_check",
        "operator_team_assignment_epochs_assignment_reason_check",
        "operator_team_assignment_epochs_end_check",
        "operator_team_assignment_epochs_version_check",
        "operator_team_assignment_epochs_updated_check",
      ]),
    );
    expect(
      config.foreignKeys.map((foreignKey) => foreignKey.getName()),
    ).toEqual(
      expect.arrayContaining([
        "operator_team_assignment_epochs_assigner_fk",
        "operator_team_assignment_epochs_ender_fk",
      ]),
    );
  });

  it("keeps active-team lifecycle scans on a team-leading partial index", () => {
    expect(hardeningStructuralMigration).toContain(
      'CREATE INDEX "operator_team_assignment_epochs_active_team_idx" ON "operator_team_assignment_epochs" USING btree ("operator_team_id") WHERE "operator_team_assignment_epochs"."ended_at" is null',
    );
    expect(hardeningStructuralMigration).not.toMatch(
      /CREATE TABLE|ALTER TABLE|CREATE FUNCTION|GRANT /,
    );
  });

  it("binds every roster edge to its exact tenant epoch and provenance", () => {
    const config = getTableConfig(operatorTeamRosterEntries);
    const tenantColumn = config.columns.find(
      (column) => column.name === "tenant_id",
    );
    const activeIndex = config.indexes.find(
      (index) =>
        index.config.name === "operator_team_roster_entries_active_key",
    );

    expect(tenantColumn?.notNull).toBe(true);
    expect(config.enableRLS).toBe(true);
    expect(config.policies).toHaveLength(0);
    expect(activeIndex?.config.unique).toBe(true);
    expect(activeIndex?.config.where).toBeDefined();
    expect(
      config.foreignKeys.map((foreignKey) => foreignKey.getName()),
    ).toEqual(
      expect.arrayContaining([
        "operator_team_roster_entries_epoch_fk",
        "operator_team_roster_entries_membership_fk",
        "operator_team_roster_entries_source_fk",
        "operator_team_roster_entries_grantor_fk",
        "operator_team_roster_entries_revoker_fk",
      ]),
    );
    expect(config.checks.map((constraint) => constraint.name)).toEqual(
      expect.arrayContaining([
        "operator_team_roster_entries_id_uuidv7_check",
        "operator_team_roster_entries_expiry_check",
        "operator_team_roster_entries_reason_check",
        "operator_team_roster_entries_revocation_check",
        "operator_team_roster_entries_version_check",
        "operator_team_roster_entries_updated_check",
      ]),
    );
  });

  it("generates only structural DDL and exact composite tenant constraints", () => {
    expect(structuralMigrationNames).toHaveLength(1);
    for (const table of [
      "operator_teams",
      "platform_commands",
      "operator_team_assignment_epochs",
      "operator_team_roster_entries",
    ]) {
      expect(structuralMigration).toContain(`CREATE TABLE "${table}"`);
      expect(structuralMigration).toContain(
        `ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY`,
      );
    }

    expect(structuralMigration).toContain(
      'CONSTRAINT "operator_team_roster_entries_epoch_fk" FOREIGN KEY ("tenant_id","assignment_epoch_id") REFERENCES "public"."operator_team_assignment_epochs"("tenant_id","id")',
    );
    expect(structuralMigration).toContain(
      'CONSTRAINT "operator_team_roster_entries_membership_fk" FOREIGN KEY ("tenant_id","membership_id") REFERENCES "public"."tenant_memberships"("tenant_id","id")',
    );
    expect(structuralMigration).toContain(
      'CONSTRAINT "operator_team_roster_entries_source_fk" FOREIGN KEY ("tenant_id","source_id") REFERENCES "public"."tenant_authorization_sources"("tenant_id","id")',
    );
    expect(structuralMigration).toContain('"created_by_user_id" uuid,');
    expect(structuralMigration).not.toContain(
      '"created_by_user_id" uuid NOT NULL',
    );
    expect(structuralMigration).toContain(
      'CONSTRAINT "operator_teams_archive_check" CHECK (("operator_teams"."archived_at" is null and "operator_teams"."archived_by_user_id" is null and "operator_teams"."archive_reason" is null)',
    );
    expect(structuralMigration).toContain(
      'CREATE UNIQUE INDEX "operator_team_assignment_epochs_active_key" ON "operator_team_assignment_epochs" USING btree ("tenant_id","operator_team_id")',
    );
    expect(structuralMigration).toContain(
      'CREATE INDEX "operator_team_roster_entries_effective_idx" ON "operator_team_roster_entries" USING btree ("tenant_id","membership_id","assignment_epoch_id","expires_at")',
    );
    expect(structuralMigration).not.toMatch(
      /FORCE ROW LEVEL SECURITY|CREATE POLICY|CREATE FUNCTION|GRANT |INSERT INTO/,
    );
  });

  it("reserves exact payload-bound tenant replay operations", () => {
    const commandChecks = getTableConfig(
      tenantAuthorizationCommands,
    ).checks.map((constraint) => constraint.name);
    expect(commandChecks).toContain(
      "tenant_authorization_commands_operation_check",
    );
    expect(structuralMigration).toContain("'operator_team_assignment.create'");
    expect(structuralMigration).toContain(
      "'operator_team_roster_entry.create'",
    );
    expect(structuralMigration).toContain("'operator_team.create'");
  });
});
