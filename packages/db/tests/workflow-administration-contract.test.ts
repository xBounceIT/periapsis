import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { getTableConfig } from "drizzle-orm/pg-core";
import { describe, expect, it } from "vitest";

import {
  ticketWorkflowCommands,
  ticketWorkflows,
  ticketWorkflowVersions,
} from "../src/schema/ticket-workflows.js";

const source = readFileSync(
  resolve(import.meta.dirname, "../src/schema/ticket-workflows.ts"),
  "utf8",
);

describe("workflow administration canonical storage", () => {
  it("separates mutable administration revisions from immutable publications", () => {
    const workflow = getTableConfig(ticketWorkflows);
    const publication = getTableConfig(ticketWorkflowVersions);

    expect(workflow.columns.map((column) => column.name)).toEqual(
      expect.arrayContaining(["revision", "current_version"]),
    );
    expect(workflow.checks.map((constraint) => constraint.name)).toEqual(
      expect.arrayContaining([
        "ticket_workflows_revision_check",
        "ticket_workflows_current_version_check",
      ]),
    );
    expect(
      publication.uniqueConstraints.map((constraint) => constraint.name),
    ).toContain("ticket_workflow_versions_identity_key");
  });

  it("keeps replay evidence tenant-bound and inaccessible by table grants", () => {
    const commands = getTableConfig(ticketWorkflowCommands);
    const tenant = commands.columns.find(
      (column) => column.name === "tenant_id",
    );

    expect(tenant?.notNull).toBe(true);
    expect(commands.enableRLS).toBe(true);
    expect(commands.policies).toHaveLength(0);
    expect(
      commands.foreignKeys.map((foreignKey) => foreignKey.getName()),
    ).toEqual(
      expect.arrayContaining([
        "ticket_workflow_commands_actor_fk",
        "ticket_workflow_commands_result_fk",
      ]),
    );
    expect(
      commands.uniqueConstraints.map((constraint) => constraint.name),
    ).toContain("ticket_workflow_commands_replay_key");
  });

  it("persists a bounded immutable result instead of rereading mutable state", () => {
    const commands = getTableConfig(ticketWorkflowCommands);
    expect(commands.columns.map((column) => column.name)).toEqual(
      expect.arrayContaining([
        "key_digest",
        "request_digest",
        "result_workflow_id",
        "result_revision",
        "result_snapshot",
        "expires_at",
      ]),
    );
    expect(commands.checks.map((constraint) => constraint.name)).toEqual(
      expect.arrayContaining([
        "ticket_workflow_commands_digest_check",
        "ticket_workflow_commands_result_check",
        "ticket_workflow_commands_retention_check",
      ]),
    );
    expect(source).toContain(
      "pg_column_size(${table.resultSnapshot}) <= 524288",
    );
    expect(source).not.toMatch(/password|token|assertion|secret/i);
  });
});
