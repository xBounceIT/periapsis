import { describe, expect, it } from "vitest";

import { phaseOneFixtures } from "../src/testing/fixtures.js";

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe("Phase 1 fixtures", () => {
  it("uses unique application-supplied UUIDv7-compatible identifiers", () => {
    const ids = [
      phaseOneFixtures.tenants.acme.id,
      phaseOneFixtures.tenants.globex.id,
      phaseOneFixtures.users.acmeAnalyst.id,
      phaseOneFixtures.users.globexAnalyst.id,
      phaseOneFixtures.users.acmeAdmin.id,
      phaseOneFixtures.users.globexAdmin.id,
      phaseOneFixtures.memberships.acmeAnalyst,
      phaseOneFixtures.memberships.globexAnalyst,
      phaseOneFixtures.memberships.acmeAdmin,
      phaseOneFixtures.memberships.globexAdmin,
      phaseOneFixtures.alerts.acme,
      phaseOneFixtures.alerts.globex,
      phaseOneFixtures.operatorTeams.socL1.id,
      phaseOneFixtures.operatorTeams.socL2.id,
      ...Object.values(phaseOneFixtures.demo.roles),
      ...Object.values(phaseOneFixtures.demo.contacts),
      ...Object.values(phaseOneFixtures.demo.ldap),
      ...Object.values(phaseOneFixtures.demo.customField),
      ...Object.values(phaseOneFixtures.demo.sla),
      ...Object.values(phaseOneFixtures.demo.notifications),
      phaseOneFixtures.demo.case,
      ...Object.values(phaseOneFixtures.demo.ioc),
      ...Object.values(phaseOneFixtures.demo.asset),
      ...Object.values(phaseOneFixtures.demo.evidence),
    ];

    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(uuidV7Pattern);
    }
  });

  it("defines the canonical demo operator teams without customer data", () => {
    expect(phaseOneFixtures.operatorTeams.socL1).toMatchObject({
      key: "soc_l1",
      displayName: "SOC L1",
    });
    expect(phaseOneFixtures.operatorTeams.socL2).toMatchObject({
      key: "soc_l2",
      displayName: "SOC L2",
    });
  });

  it("uses reserved invalid domains and contains no credential", () => {
    expect(phaseOneFixtures.users.acmeAnalyst.email.endsWith(".invalid")).toBe(
      true,
    );
    expect(
      phaseOneFixtures.users.globexAnalyst.email.endsWith(".invalid"),
    ).toBe(true);
    expect(phaseOneFixtures.users.acmeAdmin.email.endsWith(".invalid")).toBe(
      true,
    );
    expect(phaseOneFixtures.users.globexAdmin.email.endsWith(".invalid")).toBe(
      true,
    );
    expect(JSON.stringify(phaseOneFixtures)).not.toMatch(
      /password|secret|token/i,
    );
  });
});
