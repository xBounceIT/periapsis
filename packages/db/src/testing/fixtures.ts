export const phaseOneFixtures = {
  tenants: {
    acme: {
      id: "01993ea0-0000-7000-8000-000000000001",
      slug: "acme",
      name: "Acme Corporation",
      timezone: "America/New_York",
      locale: "en",
    },
    globex: {
      id: "01993ea0-0000-7000-8000-000000000002",
      slug: "globex",
      name: "Globex",
      timezone: "Europe/Rome",
      locale: "it",
    },
  },
  users: {
    acmeAdmin: {
      id: "01993ea0-0000-7000-8000-000000000103",
      email: "admin.acme@example.invalid",
      displayName: "Acme Administrator",
    },
    globexAdmin: {
      id: "01993ea0-0000-7000-8000-000000000104",
      email: "admin.globex@example.invalid",
      displayName: "Globex Administrator",
    },
    acmeAnalyst: {
      id: "01993ea0-0000-7000-8000-000000000101",
      email: "analyst.acme@example.invalid",
      displayName: "Acme Analyst",
    },
    globexAnalyst: {
      id: "01993ea0-0000-7000-8000-000000000102",
      email: "analyst.globex@example.invalid",
      displayName: "Globex Analyst",
    },
  },
  memberships: {
    acmeAdmin: "01993ea0-0000-7000-8000-000000000203",
    globexAdmin: "01993ea0-0000-7000-8000-000000000204",
    acmeAnalyst: "01993ea0-0000-7000-8000-000000000201",
    globexAnalyst: "01993ea0-0000-7000-8000-000000000202",
  },
  tenantProfiles: {
    acmeAdmin: {
      tenantId: "01993ea0-0000-7000-8000-000000000001",
      membershipId: "01993ea0-0000-7000-8000-000000000203",
      userId: "01993ea0-0000-7000-8000-000000000103",
      displayName: "Acme Administrator",
      email: "admin.acme@example.invalid",
    },
    globexAdmin: {
      tenantId: "01993ea0-0000-7000-8000-000000000002",
      membershipId: "01993ea0-0000-7000-8000-000000000204",
      userId: "01993ea0-0000-7000-8000-000000000104",
      displayName: "Globex Administrator",
      email: "admin.globex@example.invalid",
    },
    acmeAnalyst: {
      tenantId: "01993ea0-0000-7000-8000-000000000001",
      membershipId: "01993ea0-0000-7000-8000-000000000201",
      userId: "01993ea0-0000-7000-8000-000000000101",
      displayName: "Acme Analyst",
      email: "analyst.acme@example.invalid",
    },
    globexAnalyst: {
      tenantId: "01993ea0-0000-7000-8000-000000000002",
      membershipId: "01993ea0-0000-7000-8000-000000000202",
      userId: "01993ea0-0000-7000-8000-000000000102",
      displayName: "Globex Analyst",
      email: "analyst.globex@example.invalid",
    },
  },
  alerts: {
    acme: "01993ea0-0000-7000-8000-000000000301",
    globex: "01993ea0-0000-7000-8000-000000000302",
  },
  operatorTeams: {
    socL1: {
      id: "01993ea0-0000-7000-8000-000000000401",
      key: "soc_l1",
      displayName: "SOC L1",
      description: "Demo first-line security operations team.",
    },
    socL2: {
      id: "01993ea0-0000-7000-8000-000000000402",
      key: "soc_l2",
      displayName: "SOC L2",
      description: "Demo escalation security operations team.",
    },
  },
  demo: {
    roles: {
      acmeResponder: "01993ea0-0000-7000-8000-000000000501",
      globexResponder: "01993ea0-0000-7000-8000-000000000502",
    },
    contacts: {
      acme: "01993ea0-0000-7000-8000-000000000601",
      globex: "01993ea0-0000-7000-8000-000000000602",
    },
    ldap: {
      provider: "01993ea0-0000-7000-8000-000000000701",
      securityGroup: "01993ea0-0000-7000-8000-000000000702",
      binding: "01993ea0-0000-7000-8000-000000000703",
    },
    customField: {
      definition: "01993ea0-0000-7000-8000-000000000801",
      revision: "01993ea0-0000-7000-8000-000000000802",
    },
    sla: {
      calendar: "01993ea0-0000-7000-8000-000000000901",
      policy: "01993ea0-0000-7000-8000-000000000902",
      metric: "01993ea0-0000-7000-8000-000000000903",
      trigger: "01993ea0-0000-7000-8000-000000000904",
    },
    notifications: {
      template: "01993ea0-0000-7000-8000-000000001001",
      rule: "01993ea0-0000-7000-8000-000000001002",
    },
    case: "01993ea0-0000-7000-8000-000000001101",
    ioc: {
      resource: "01993ea0-0000-7000-8000-000000001201",
      link: "01993ea0-0000-7000-8000-000000001202",
    },
    asset: {
      resource: "01993ea0-0000-7000-8000-000000001301",
      link: "01993ea0-0000-7000-8000-000000001302",
    },
    evidence: {
      storageObject: "01993ea0-0000-7000-8000-000000001401",
      resource: "01993ea0-0000-7000-8000-000000001402",
      custodyEvent: "01993ea0-0000-7000-8000-000000001403",
    },
  },
} as const;
