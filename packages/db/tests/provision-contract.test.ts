import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

const source = readFileSync(
  resolve(import.meta.dirname, "../src/admin/provision-runtime-roles.ts"),
  "utf8",
);
const deploymentTask = readFileSync(
  resolve(import.meta.dirname, "../../../deploy/compose/database-task.mjs"),
  "utf8",
);

describe("runtime database role provisioning", () => {
  it("replaces all direct memberships transactionally with the intended group", () => {
    expect(source).toContain("client.begin(async (transaction)");
    expect(source).toContain("pg_catalog.pg_auth_members");
    expect(source).toContain("membership.member");
    expect(source).toContain("membership.roleid");

    const revokeIndex = source.indexOf(
      "`REVOKE ${quoteIdentifier(membership.roleName)} FROM",
    );
    const grantIndex = source.indexOf("`GRANT ${quoteIdentifier");
    expect(revokeIndex).toBeGreaterThan(-1);
    expect(grantIndex).toBeGreaterThan(revokeIndex);
    expect(source).toContain("connectionLimit: 40");
    expect(source.match(/connectionLimit: 20/gu)).toHaveLength(2);
    expect(source).toContain("connectionLimit: -1");
    expect(source).toContain(
      "CONNECTION LIMIT ${credential.role.connectionLimit}",
    );
    expect(source.match(/VALID UNTIL 'infinity'/gu)).toHaveLength(2);
    expect(source).toContain("RESET ALL");
    expect(source).toContain("membership.grantor");
    expect(source).toContain("GRANTED BY ${quoteIdentifier");
    expect(source).toContain("CASCADE`");
    expect(source).toContain("WITH ADMIN FALSE, INHERIT TRUE, SET TRUE");
  });

  it("keeps the deployment provisioner on the same exact PG18 role edge", () => {
    expect(deploymentTask).toContain("connectionLimit: 40");
    expect(deploymentTask.match(/connectionLimit: 20/gu)).toHaveLength(2);
    expect(deploymentTask).toContain("VALID UNTIL ''infinity''");
    expect(deploymentTask).toContain("RESET ALL");
    expect(deploymentTask).toContain("membership.grantor");
    expect(deploymentTask).toContain("GRANTED BY %I CASCADE");
    expect(deploymentTask).toContain(
      "WITH ADMIN FALSE, INHERIT TRUE, SET TRUE",
    );
  });

  it("preflights file-backed secrets and never embeds a password", () => {
    expect(source.indexOf("runtimeRoles.map")).toBeLessThan(
      source.indexOf("client.begin"),
    );
    expect(source).toContain("_FILE");
    expect(source).not.toMatch(/PASSWORD\s+'[^']+'/i);
  });

  it("owns the durable webhook localhost opt-in and keeps production closed", () => {
    expect(source.indexOf("requireWebhookPlainLocalOptIn()")).toBeLessThan(
      source.indexOf("client.begin"),
    );
    expect(source).toContain("public.webhook_plain_local_runtime_role_opt_ins");
    expect(source).toContain("to_regclass(");
    expect(source).toContain('"periapsis_api_login"');
    expect(source).toContain('"periapsis_notifier_login"');
    expect(source).toContain("upsertWebhookPlainLocalRoleOptIn(");
    expect(source).toContain(
      "PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL cannot be enabled in production",
    );
  });
});
