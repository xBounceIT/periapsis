import { and, eq, sql, type SQL } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import postgres from "postgres";

import { requireDatabaseUrl } from "../src/admin/database-url.js";
import {
  alerts,
  auditEvents,
  operatorTeams,
  outboxEvents,
  platformAuditEvents,
  ticketWorkflows,
  tenantMemberships,
  tenantUserProfiles,
  tenants,
  users,
} from "../src/schema/index.js";
import { phaseOneFixtures } from "../src/testing/fixtures.js";
import {
  demoSlaCalendarDocument,
  demoSlaPolicyDocument,
} from "./sla-fixture.js";

const client = postgres(requireDatabaseUrl(), {
  max: 1,
  onnotice: () => undefined,
});

const now = new Date();
const demoOccurredAt = new Date("2026-01-02T12:00:00.000Z");
const demoRetentionUntil = new Date("2027-01-02T12:00:00.000Z");

const ldapConfiguration = {
  template: "openldap",
  verifyCertificate: true,
  customCaPem: null,
  connectTimeoutMs: 1_000,
  operationTimeoutMs: 5_000,
  bindDn: "cn=demo-bind,dc=example,dc=invalid",
  userBaseDn: "ou=users,dc=example,dc=invalid",
  groupBaseDn: "ou=groups,dc=example,dc=invalid",
  userSearchFilter: "(uid={username})",
  groupSearchFilter: "(objectClass=groupOfNames)",
  userDnTemplate: null,
  pageSize: 100,
  maxPages: 10,
  maxEntries: 1_000,
  maxResponseBytes: 1_048_576,
  referralMode: "disabled",
  maxReferralHops: 0,
  nestedGroupMode: "disabled",
  maxNestedGroupDepth: 0,
  maxGroups: 100,
  firstNameAttribute: "givenName",
  lastNameAttribute: "sn",
  displayNameAttribute: "displayName",
  usernameAttribute: "uid",
  alternateUsernameAttribute: null,
  emailAttribute: "mail",
  immutableSubjectAttribute: "entryUUID",
  immutableSubjectFormat: "entry_uuid",
  groupMembershipAttribute: "memberOf",
  posixMemberUidAttribute: null,
  posixGidNumberAttribute: null,
  accountStatusMode: "none",
  accountStatusAttribute: null,
  accountDisabledValue: null,
  jitMode: "disabled",
  noMatchPolicy: "deny",
  deprovisionMode: "retain",
  deprovisionGraceSeconds: 0,
  syncIntervalSeconds: null,
} as const;

const ldapEndpoints = [
  {
    priority: 1,
    host: "ldap.demo.example.invalid",
    port: 636,
    transport: "ldaps",
    tlsServerName: "ldap.demo.example.invalid",
    referralAllowed: false,
    enabled: false,
  },
] as const;

const demoContacts = {
  acme: {
    firstName: "Morgan",
    lastName: "Acme",
    email: "security.contact.acme@example.invalid",
    phone: null,
    function: "Security contact",
    language: "en",
    timezone: "America/New_York",
    escalationPriority: 0,
    contactClass: "standard",
    notificationCategories: ["security"],
    notificationWindows: [],
    emailAllowed: true,
    active: true,
    tags: ["demo", "security"],
    linkedMembershipId: null,
    linkedUserId: null,
    version: 1,
    createdAt: demoOccurredAt.toISOString(),
    updatedAt: demoOccurredAt.toISOString(),
    archivedAt: null,
  },
  globex: {
    firstName: "Giulia",
    lastName: "Globex",
    email: "security.contact.globex@example.invalid",
    phone: null,
    function: "Security contact",
    language: "it",
    timezone: "Europe/Rome",
    escalationPriority: 0,
    contactClass: "standard",
    notificationCategories: ["security"],
    notificationWindows: [],
    emailAllowed: true,
    active: true,
    tags: ["demo", "security"],
    linkedMembershipId: null,
    linkedUserId: null,
    version: 1,
    createdAt: demoOccurredAt.toISOString(),
    updatedAt: demoOccurredAt.toISOString(),
    archivedAt: null,
  },
} as const;

const demoNotificationTemplate = {
  key: "demo.case-update",
  name: "Demo case update",
  language: "en",
  subject: "A demo case requires attention",
  html: "<p>A synthetic demo case requires attention.</p>",
  plainText: "A synthetic demo case requires attention.",
  sampleData: {},
  placeholders: [],
} as const;

const demoNotificationRule = {
  name: "Demo Alert created notification",
  description: "Notifies tenant administrators about synthetic demo Alerts.",
  eventType: "alert.created",
  objectType: "alert",
  condition: {
    kind: "predicate",
    path: "alert.severity",
    operator: "exists",
  },
  recipients: [{ kind: "tenant_admin", audience: "operator" }],
  templateId: phaseOneFixtures.demo.notifications.template,
  templateVersion: 1,
  channel: "email",
  priority: 50,
  delayMs: 0,
  deduplicationWindowMs: 60_000,
  grouping: { mode: "object", windowMs: 60_000, maximumItems: 25 },
  retry: {
    maximumAttempts: 3,
    initialDelayMs: 30_000,
    maximumDelayMs: 3_600_000,
    multiplier: 2,
    jitterPercent: 10,
  },
  enabled: true,
  effectiveFrom: demoOccurredAt.toISOString(),
} as const;

try {
  await client`set timezone to 'UTC'`;
  await client`set role periapsis_migrator`;

  await drizzle(client).transaction(async (tx) => {
    const setTenantContext = async (
      tenantId: string,
      userId: string,
    ): Promise<void> => {
      // SET LOCAL is transaction-scoped. Re-establish both the privileged seed
      // role and the exact tenant/user context before every tenant-owned slice:
      // security-definer triggers still validate app.tenant_id even though the
      // seed itself runs as the migrator.
      await tx.execute(sql.raw('SET LOCAL ROLE "periapsis_migrator"'));
      await tx.execute(sql`
        SELECT set_config('app.tenant_id', ${tenantId}, true),
               set_config('app.user_id', ${userId}, true),
               set_config('app.service_account_id', '', true)
      `);
    };

    const runApiMutationIfMissing = async (
      missingQuery: SQL,
      mutation: SQL,
    ): Promise<void> => {
      await tx.execute(sql.raw('SET LOCAL ROLE "periapsis_migrator"'));
      const missingRows = await tx.execute(missingQuery);
      if (missingRows.length === 0) {
        return;
      }
      await tx.execute(sql.raw('SET LOCAL ROLE "periapsis_api"'));
      await tx.execute(mutation);
    };

    const seedTenantAlert = async (input: {
      tenantId: string;
      workflowId: string;
      alertId: string;
      externalId: string;
      title: string;
      description: string;
      severity: "high" | "medium";
      createdBy: string;
      createdByMembershipId: string;
      number: string;
    }): Promise<void> => {
      await setTenantContext(input.tenantId, input.createdBy);

      const [insertedAlert] = await tx
        .insert(alerts)
        .values({
          id: input.alertId,
          tenantId: input.tenantId,
          number: input.number,
          workflowId: input.workflowId,
          externalId: input.externalId,
          title: input.title,
          description: input.description,
          severity: input.severity,
          createdBy: input.createdBy,
          createdByMembershipId: input.createdByMembershipId,
        })
        .onConflictDoNothing({
          target: [alerts.tenantId, alerts.externalId],
        })
        .returning({
          id: alerts.id,
          tenantId: alerts.tenantId,
          createdBy: alerts.createdBy,
        });

      if (insertedAlert === undefined) {
        return;
      }

      await tx.insert(auditEvents).values({
        tenantId: insertedAlert.tenantId,
        // The sealing trigger replaces this placeholder while allocating the tenant-local tail.
        sequence: 0n,
        actorType: "user",
        actorUserId: insertedAlert.createdBy,
        action: "alert.created",
        resourceType: "alert",
        resourceId: insertedAlert.id,
        outcome: "success",
        after: { id: insertedAlert.id },
        metadata: { source: "phase-one-seed" },
      });

      await tx.insert(outboxEvents).values({
        tenantId: insertedAlert.tenantId,
        aggregateType: "alert",
        aggregateId: insertedAlert.id,
        eventType: "alert.created.v1",
        payload: { alertId: insertedAlert.id },
        deduplicationKey: `phase-one-seed:${insertedAlert.id}`,
      });
    };

    const [acme] = await tx
      .insert(tenants)
      .values({
        ...phaseOneFixtures.tenants.acme,
      })
      .onConflictDoUpdate({
        target: tenants.slug,
        set: {
          name: phaseOneFixtures.tenants.acme.name,
          timezone: phaseOneFixtures.tenants.acme.timezone,
          locale: phaseOneFixtures.tenants.acme.locale,
          updatedAt: now,
        },
      })
      .returning({ id: tenants.id });

    const [globex] = await tx
      .insert(tenants)
      .values({
        ...phaseOneFixtures.tenants.globex,
      })
      .onConflictDoUpdate({
        target: tenants.slug,
        set: {
          name: phaseOneFixtures.tenants.globex.name,
          timezone: phaseOneFixtures.tenants.globex.timezone,
          locale: phaseOneFixtures.tenants.globex.locale,
          updatedAt: now,
        },
      })
      .returning({ id: tenants.id });

    const [acmeUser] = await tx
      .insert(users)
      .values({
        ...phaseOneFixtures.users.acmeAnalyst,
      })
      .onConflictDoUpdate({
        target: users.id,
        set: {
          email: phaseOneFixtures.users.acmeAnalyst.email,
          displayName: phaseOneFixtures.users.acmeAnalyst.displayName,
          active: true,
          updatedAt: now,
        },
      })
      .returning({ id: users.id });

    const [globexUser] = await tx
      .insert(users)
      .values({
        ...phaseOneFixtures.users.globexAnalyst,
      })
      .onConflictDoUpdate({
        target: users.id,
        set: {
          email: phaseOneFixtures.users.globexAnalyst.email,
          displayName: phaseOneFixtures.users.globexAnalyst.displayName,
          active: true,
          updatedAt: now,
        },
      })
      .returning({ id: users.id });

    const [acmeAdmin] = await tx
      .insert(users)
      .values({
        ...phaseOneFixtures.users.acmeAdmin,
      })
      .onConflictDoUpdate({
        target: users.id,
        set: {
          email: phaseOneFixtures.users.acmeAdmin.email,
          displayName: phaseOneFixtures.users.acmeAdmin.displayName,
          active: true,
          updatedAt: now,
        },
      })
      .returning({ id: users.id });

    const [globexAdmin] = await tx
      .insert(users)
      .values({
        ...phaseOneFixtures.users.globexAdmin,
      })
      .onConflictDoUpdate({
        target: users.id,
        set: {
          email: phaseOneFixtures.users.globexAdmin.email,
          displayName: phaseOneFixtures.users.globexAdmin.displayName,
          active: true,
          updatedAt: now,
        },
      })
      .returning({ id: users.id });

    if (
      acme === undefined ||
      globex === undefined ||
      acmeUser === undefined ||
      globexUser === undefined ||
      acmeAdmin === undefined ||
      globexAdmin === undefined
    ) {
      throw new Error("Demo tenant or user upsert returned no row");
    }

    const insertedOperatorTeams = await tx
      .insert(operatorTeams)
      .values([
        {
          ...phaseOneFixtures.operatorTeams.socL1,
          createdByUserId: null,
        },
        {
          ...phaseOneFixtures.operatorTeams.socL2,
          createdByUserId: null,
        },
      ])
      .onConflictDoNothing({ target: operatorTeams.key })
      .returning({
        id: operatorTeams.id,
        key: operatorTeams.key,
        displayName: operatorTeams.displayName,
      });

    if (insertedOperatorTeams.length > 0) {
      await tx.insert(platformAuditEvents).values(
        insertedOperatorTeams.map((operatorTeam) => ({
          sequence: 1n,
          actorType: "system" as const,
          action: "platform.operator_team.created",
          resourceType: "operator_team",
          resourceId: operatorTeam.id,
          authenticationMethod: "database_seed",
          outcome: "success" as const,
          metadata: {
            key: operatorTeam.key,
            name: operatorTeam.displayName,
            source: "phase_one_demo_seed",
          },
        })),
      );
    }

    await tx
      .insert(tenantMemberships)
      .values([
        {
          id: phaseOneFixtures.memberships.acmeAdmin,
          tenantId: acme.id,
          userId: acmeAdmin.id,
          role: "tenant_admin",
          status: "active",
        },
        {
          id: phaseOneFixtures.memberships.globexAdmin,
          tenantId: globex.id,
          userId: globexAdmin.id,
          role: "tenant_admin",
          status: "active",
        },
        {
          id: phaseOneFixtures.memberships.acmeAnalyst,
          tenantId: acme.id,
          userId: acmeUser.id,
          role: "analyst",
          status: "active",
        },
        {
          id: phaseOneFixtures.memberships.globexAnalyst,
          tenantId: globex.id,
          userId: globexUser.id,
          role: "analyst",
          status: "active",
        },
      ])
      .onConflictDoUpdate({
        target: [tenantMemberships.tenantId, tenantMemberships.userId],
        set: {
          role: sql`excluded.role`,
          status: "active",
          updatedAt: now,
        },
      });

    await tx
      .insert(tenantUserProfiles)
      .values([
        { ...phaseOneFixtures.tenantProfiles.acmeAdmin },
        { ...phaseOneFixtures.tenantProfiles.globexAdmin },
        { ...phaseOneFixtures.tenantProfiles.acmeAnalyst },
        { ...phaseOneFixtures.tenantProfiles.globexAnalyst },
      ])
      .onConflictDoUpdate({
        target: [tenantUserProfiles.tenantId, tenantUserProfiles.membershipId],
        set: {
          displayName: sql`excluded.display_name`,
          email: sql`excluded.email`,
          updatedAt: now,
        },
      });

    // The historical bootstrap chain is intentionally one-shot: later
    // compatibility layers add permissions to protected built-in roles, so
    // invoking the legacy initializer again would reject its own evolved
    // state. Re-enter it only for a tenant whose authorization state has not
    // completed initialization; all subsequent demo rows remain independently
    // idempotent below.
    await tx.execute(sql`
      SELECT app.seed_tenant_authorization(
        seeded_tenant.tenant_id,
        seeded_tenant.initial_admin_membership_id
      )
      FROM (
        VALUES
          (${acme.id}::uuid, ${phaseOneFixtures.memberships.acmeAdmin}::uuid),
          (${globex.id}::uuid, ${phaseOneFixtures.memberships.globexAdmin}::uuid)
      ) AS seeded_tenant(tenant_id, initial_admin_membership_id)
      LEFT JOIN public.tenant_authorization_states AS authorization_state
        ON authorization_state.tenant_id = seeded_tenant.tenant_id
      WHERE authorization_state.tenant_id IS NULL
         OR authorization_state.initialized_at IS NULL
      ORDER BY seeded_tenant.tenant_id
    `);

    const [acmeAlertWorkflow] = await tx
      .select({ id: ticketWorkflows.id })
      .from(ticketWorkflows)
      .where(
        and(
          eq(ticketWorkflows.tenantId, acme.id),
          eq(ticketWorkflows.aggregateKind, "alert"),
          eq(ticketWorkflows.key, "default_alert"),
        ),
      );
    const [globexAlertWorkflow] = await tx
      .select({ id: ticketWorkflows.id })
      .from(ticketWorkflows)
      .where(
        and(
          eq(ticketWorkflows.tenantId, globex.id),
          eq(ticketWorkflows.aggregateKind, "alert"),
          eq(ticketWorkflows.key, "default_alert"),
        ),
      );
    const [acmeCaseWorkflow] = await tx
      .select({ id: ticketWorkflows.id })
      .from(ticketWorkflows)
      .where(
        and(
          eq(ticketWorkflows.tenantId, acme.id),
          eq(ticketWorkflows.aggregateKind, "case"),
          eq(ticketWorkflows.key, "default_case"),
        ),
      );
    const [globexCaseWorkflow] = await tx
      .select({ id: ticketWorkflows.id })
      .from(ticketWorkflows)
      .where(
        and(
          eq(ticketWorkflows.tenantId, globex.id),
          eq(ticketWorkflows.aggregateKind, "case"),
          eq(ticketWorkflows.key, "default_case"),
        ),
      );
    if (
      acmeAlertWorkflow === undefined ||
      globexAlertWorkflow === undefined ||
      acmeCaseWorkflow === undefined ||
      globexCaseWorkflow === undefined
    ) {
      throw new Error("Demo Alert or Case workflow seed returned no row");
    }

    // The authorization helper initializes protected recovery authority but is
    // deliberately too low-level to append an audit event itself. Record the
    // seed-owned initialization in this transaction, in tenant order, and do
    // not manufacture a second initialization event on an idempotent rerun.
    await tx.execute(sql`
      INSERT INTO public.audit_events (
        tenant_id, sequence, actor_type, action, resource_type, resource_id,
        authentication_method, outcome, after, metadata
      )
      SELECT seeded_tenant.tenant_id, 0, 'system',
             'tenant.authorization.initialized', 'tenant', seeded_tenant.tenant_id,
             'database_seed', 'success',
             jsonb_build_object(
               'authorization_initialized', true,
               'recovery_grant_initialized', true
             ),
             jsonb_build_object(
               'source', 'database_seed',
               'seed', 'phase_one_demo'
             )
      FROM (
        VALUES (${acme.id}::uuid), (${globex.id}::uuid)
      ) AS seeded_tenant(tenant_id)
      WHERE NOT EXISTS (
        SELECT 1
        FROM public.audit_events AS existing
        WHERE existing.tenant_id = seeded_tenant.tenant_id
          AND existing.action = 'tenant.authorization.initialized'
          AND existing.resource_type = 'tenant'
          AND existing.resource_id = seeded_tenant.tenant_id
          AND existing.outcome = 'success'
      )
      ORDER BY seeded_tenant.tenant_id
    `);

    // Ticket-number allocation and downstream insert triggers are context-bound,
    // so seed the two tenant Alerts serially under their own transaction-local
    // tenant/user context instead of issuing one cross-tenant INSERT.
    await seedTenantAlert({
      tenantId: acme.id,
      workflowId: acmeAlertWorkflow.id,
      alertId: phaseOneFixtures.alerts.acme,
      externalId: "phase-1-acme-alert",
      title: "Suspicious sign-in requiring triage",
      description:
        "Synthetic seed data; it contains no credential or production secret.",
      severity: "high",
      createdBy: acmeUser.id,
      createdByMembershipId: phaseOneFixtures.memberships.acmeAnalyst,
      number: `ALT-${now.getUTCFullYear()}-900001`,
    });
    await seedTenantAlert({
      tenantId: globex.id,
      workflowId: globexAlertWorkflow.id,
      alertId: phaseOneFixtures.alerts.globex,
      externalId: "phase-1-globex-alert",
      title: "Unusual endpoint process tree",
      description:
        "Synthetic seed data; it contains no credential or production secret.",
      severity: "medium",
      createdBy: globexUser.id,
      createdByMembershipId: phaseOneFixtures.memberships.globexAnalyst,
      number: `ALT-${now.getUTCFullYear()}-900002`,
    });

    // The rest of the catalog intentionally forms one coherent tenant-owned
    // vertical slice under Acme. Globex receives its own example role and
    // customer contact as a cross-tenant isolation witness. Every ABI call is
    // guarded by durable resource state as well as its command receipt so the
    // seed remains safe after receipt-retention windows have elapsed.
    await setTenantContext(acme.id, acmeAdmin.id);
    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.sla_business_calendars
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.sla.calendar}::uuid
        )
      `,
      sql`
      SELECT * FROM app.publish_sla_calendar_v2(
        ${acme.id}::uuid, ${phaseOneFixtures.demo.sla.calendar}::uuid, 0,
        ${JSON.stringify(demoSlaCalendarDocument)}::jsonb,
        sha256(convert_to('demo-seed:acme:sla-calendar:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:sla-calendar:request', 'UTF8')),
        uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.sla_policies
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.sla.policy}::uuid
        )
      `,
      sql`
      SELECT * FROM app.publish_sla_policy_v2(
        ${acme.id}::uuid, ${phaseOneFixtures.demo.sla.policy}::uuid, 0,
        ${JSON.stringify(demoSlaPolicyDocument)}::jsonb,
        sha256(convert_to('demo-seed:acme:sla-policy:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:sla-policy:request', 'UTF8')),
        uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.tenant_notification_templates
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.notifications.template}::uuid
        )
      `,
      sql`
      SELECT * FROM app.mutate_tenant_notification_definition_v1(
        'template.create', ${phaseOneFixtures.demo.notifications.template}::uuid,
        NULL,
        ${JSON.stringify(demoNotificationTemplate)}::jsonb,
        sha256(convert_to('demo-seed:acme:notification-template:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:notification-template:request', 'UTF8')),
        transaction_timestamp(), uuidv7(), uuidv7(),
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.tenant_notification_rules
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.notifications.rule}::uuid
        )
      `,
      sql`
      SELECT * FROM app.mutate_tenant_notification_definition_v1(
        'rule.create', ${phaseOneFixtures.demo.notifications.rule}::uuid,
        NULL,
        ${JSON.stringify(demoNotificationRule)}::jsonb,
        sha256(convert_to('demo-seed:acme:notification-rule:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:notification-rule:request', 'UTF8')),
        transaction_timestamp(), uuidv7(), uuidv7(),
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await tx.execute(sql.raw('SET LOCAL ROLE "periapsis_migrator"'));

    await tx.execute(sql`
      WITH inserted_definition AS MATERIALIZED (
        INSERT INTO public.custom_field_definitions (
          id, tenant_id, object_type, key, label, description, data_type,
          required, nullable, has_default, default_value,
          minimum_length, maximum_length, validation_pattern,
          show_in_create, show_in_detail, show_in_list, show_in_export,
          required_on_transitions, searchable, filterable, sortable,
          allow_structured_json, schema_version,
          created_by_membership_id, updated_by_membership_id,
          created_at, updated_at
        ) VALUES (
          ${phaseOneFixtures.demo.customField.definition}::uuid,
          ${acme.id}::uuid, 'case', 'demo_affected_service',
          'Affected service',
          'Synthetic service label used by the complete demo Case.',
          'short_text', false, false, false, NULL,
          1, 120, NULL, true, true, true, true,
          ARRAY[]::text[], true, true, true, false, 1,
          ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
          ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
          ${demoOccurredAt.toISOString()}::timestamptz, ${demoOccurredAt.toISOString()}::timestamptz
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING id
      )
      SELECT app.append_phase4_mutation_effects_v1(
        'custom_field.manage', 'custom_field.created',
        'custom_field_definition', inserted_definition.id, 1,
        NULL, NULL, NULL, NULL,
        'Created synthetic Case custom field.',
        NULL,
        jsonb_build_object(
          'key', 'demo_affected_service', 'objectType', 'case',
          'schemaVersion', 1
        ),
        jsonb_build_object('source', 'database_seed', 'demo', true),
        uuidv7(), uuidv7(), uuidv7(), uuidv7(),
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      FROM inserted_definition
    `);

    await tx.execute(sql`
      INSERT INTO public.custom_field_permissions (
        tenant_id, definition_id, audience, can_read, can_create,
        can_update, schema_version, updated_at
      ) VALUES (
        ${acme.id}::uuid,
        ${phaseOneFixtures.demo.customField.definition}::uuid,
        'operator', true, true, true, 1, ${demoOccurredAt.toISOString()}::timestamptz
      )
      ON CONFLICT (tenant_id, definition_id, audience) DO NOTHING
    `);

    await tx.execute(sql`
      INSERT INTO public.custom_field_definition_revisions (
        id, tenant_id, definition_id, object_type, schema_version,
        snapshot, created_by_membership_id, created_at
      ) VALUES (
        ${phaseOneFixtures.demo.customField.revision}::uuid,
        ${acme.id}::uuid,
        ${phaseOneFixtures.demo.customField.definition}::uuid,
        'case', 1,
        ${JSON.stringify({
          key: "demo_affected_service",
          label: "Affected service",
          description:
            "Synthetic service label used by the complete demo Case.",
          dataType: "short_text",
          required: false,
          nullable: false,
          defaultPresence: "missing",
          constraints: { minimumLength: 1, maximumLength: 120 },
          options: [],
          permissions: [
            {
              audience: "operator",
              canRead: true,
              canCreate: true,
              canUpdate: true,
            },
          ],
          placement: {
            showInCreate: true,
            showInDetail: true,
            showInList: true,
            showInExport: true,
          },
          capabilities: {
            searchable: true,
            filterable: true,
            sortable: true,
            allowStructuredJson: false,
          },
          requiredOnTransitions: [],
        })}::jsonb,
        ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
        ${demoOccurredAt.toISOString()}::timestamptz
      )
      ON CONFLICT (id) DO NOTHING
    `);

    // This directory provider is deliberately disabled and contains only a
    // reserved .invalid endpoint. No bind-secret envelope is created.
    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.tenant_auth_providers
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.ldap.provider}::uuid
        )
      `,
      sql`
      SELECT * FROM app.create_tenant_ldap_provider_v1(
        ${phaseOneFixtures.demo.ldap.provider}::uuid,
        sha256(convert_to('demo-seed:acme:ldap-provider', 'UTF8')),
        'demo_ldap', 'Demo LDAP',
        'Disabled synthetic directory provider without a bind secret.',
        ${JSON.stringify(ldapConfiguration)}::jsonb,
        ${JSON.stringify(ldapEndpoints)}::jsonb,
        uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
            SELECT 1 FROM public.tenant_auth_provider_bindings AS binding
            WHERE binding.tenant_id = ${acme.id}::uuid
              AND binding.id = ${phaseOneFixtures.demo.ldap.binding}::uuid
              AND binding.key = 'demo_ldap'
          )
      `,
      sql`
      SELECT * FROM app.create_tenant_auth_provider_binding_v1(
        ${phaseOneFixtures.demo.ldap.binding}::uuid,
        ${phaseOneFixtures.demo.ldap.provider}::uuid,
        'demo_ldap', false, 100,
        uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.tenant_security_groups
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.ldap.securityGroup}::uuid
        )
      `,
      sql`
      SELECT * FROM app.create_tenant_security_group(
        ${phaseOneFixtures.demo.ldap.securityGroup}::uuid,
        sha256(convert_to('demo-seed:acme:ldap-security-group', 'UTF8')),
        'demo_ldap_responders', 'Demo LDAP Responders',
        'Synthetic LDAP-mapped security group.',
        uuidv7(), uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.tenant_roles
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.roles.acmeResponder}::uuid
        )
      `,
      sql`
      SELECT * FROM app.create_tenant_role(
        ${phaseOneFixtures.demo.roles.acmeResponder}::uuid,
        sha256(convert_to('demo-seed:acme:role:responder', 'UTF8')),
        'demo_responder', 'Demo Responder',
        'Example least-privilege incident responder role.',
        ARRAY[
          'alert.read', 'case.read', 'dfir.ioc.read', 'dfir.asset.read',
          'dfir.evidence.read'
        ]::text[],
        ARRAY[
          'tenant', 'tenant', 'tenant', 'tenant', 'tenant'
        ]::public.authorization_scope[],
        ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
        uuidv7(), uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
            SELECT 1 FROM public.tenant_ldap_mapping_rules AS mapping
            WHERE mapping.tenant_id = ${acme.id}::uuid
              AND mapping.binding_id = ${phaseOneFixtures.demo.ldap.binding}::uuid
              AND mapping.matcher_type = 'exact_cn'
              AND mapping.matcher_value = 'demo-responders'
              AND mapping.archived_at IS NULL
          )
      `,
      sql`
      SELECT * FROM app.create_tenant_ldap_mapping_rule_v2(
        sha256(convert_to('demo-seed:acme:ldap-mapping', 'UTF8')),
        ${phaseOneFixtures.demo.ldap.binding}::uuid,
        'exact_cn', 'demo-responders',
        'insensitive', 10,
        ${phaseOneFixtures.demo.ldap.securityGroup}::uuid,
        'additive',
        ARRAY[${phaseOneFixtures.demo.roles.acmeResponder}::uuid]::uuid[],
        NULL, NULL, 'Synthetic disabled example mapping.',
        'Create the demo LDAP mapping.',
        uuidv7(), uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.customer_contacts
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.contacts.acme}::uuid
        )
      `,
      sql`
      SELECT * FROM app.commit_customer_contact_v1(
        'contact.create', ${phaseOneFixtures.demo.contacts.acme}::uuid, 0,
        ${JSON.stringify(demoContacts.acme)}::jsonb,
        sha256(convert_to('demo-seed:acme:contact:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:contact:request', 'UTF8')),
        '', uuidv7(), uuidv7(),
        ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await setTenantContext(globex.id, globexAdmin.id);

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.tenant_roles
          WHERE tenant_id = ${globex.id}::uuid
            AND id = ${phaseOneFixtures.demo.roles.globexResponder}::uuid
        )
      `,
      sql`
      SELECT * FROM app.create_tenant_role(
        ${phaseOneFixtures.demo.roles.globexResponder}::uuid,
        sha256(convert_to('demo-seed:globex:role:responder', 'UTF8')),
        'demo_responder', 'Demo Responder',
        'Example least-privilege incident responder role.',
        ARRAY[
          'alert.read', 'case.read', 'dfir.ioc.read', 'dfir.asset.read',
          'dfir.evidence.read'
        ]::text[],
        ARRAY[
          'tenant', 'tenant', 'tenant', 'tenant', 'tenant'
        ]::public.authorization_scope[],
        ARRAY[]::text[], ARRAY[]::public.authorization_scope[],
        uuidv7(), uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.customer_contacts
          WHERE tenant_id = ${globex.id}::uuid
            AND id = ${phaseOneFixtures.demo.contacts.globex}::uuid
        )
      `,
      sql`
      SELECT * FROM app.commit_customer_contact_v1(
        'contact.create', ${phaseOneFixtures.demo.contacts.globex}::uuid, 0,
        ${JSON.stringify(demoContacts.globex)}::jsonb,
        sha256(convert_to('demo-seed:globex:contact:key', 'UTF8')),
        sha256(convert_to('demo-seed:globex:contact:request', 'UTF8')),
        '', uuidv7(), uuidv7(),
        ${phaseOneFixtures.memberships.globexAdmin}::uuid,
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await setTenantContext(acme.id, acmeAdmin.id);

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.cases
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.case}::uuid
        )
      `,
      sql`
      SELECT * FROM app.create_tenant_case_v1(
        ${phaseOneFixtures.demo.case}::uuid,
        ${acmeCaseWorkflow.id}::uuid, 1,
        'Synthetic credential-phishing investigation',
        'Demo Case that joins a synthetic Alert, IOC, Asset, and Evidence metadata.',
        'Validate the synthetic sign-in and affected demo workstation.',
        'high', 'high', 'identity', 'internal',
        ARRAY['demo', 'phishing']::text[],
        jsonb_build_object('demo_affected_service', 'customer-portal'),
        true, ${demoOccurredAt.toISOString()}::timestamptz, NULL, NULL,
        sha256(convert_to('demo-seed:acme:case:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:case:request', 'UTF8')),
        uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await tx.execute(sql.raw('SET LOCAL ROLE "periapsis_migrator"'));

    await tx.execute(sql`
      WITH inserted_ioc AS MATERIALIZED (
        INSERT INTO public.dfir_iocs (
          id, tenant_id, type, value, normalized_value, description,
          source, confidence, tlp, first_seen, last_seen,
          malicious_state, tags, enrichment,
          created_by_membership_id, updated_by_membership_id,
          version, created_at, updated_at
        )
        SELECT
          ${phaseOneFixtures.demo.ioc.resource}::uuid, ${acme.id}::uuid,
          'domain', 'malicious.demo.invalid', 'malicious.demo.invalid',
          'Synthetic indicator; reserved .invalid domain.', 'database_seed',
          75, 'amber', ${demoOccurredAt.toISOString()}::timestamptz, ${demoOccurredAt.toISOString()}::timestamptz, 'suspicious',
          ARRAY['demo', 'phishing']::text[],
          jsonb_build_object('synthetic', true, 'provider', 'database_seed'),
          ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
          ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
          1, ${demoOccurredAt.toISOString()}::timestamptz, ${demoOccurredAt.toISOString()}::timestamptz
        WHERE NOT EXISTS (
          SELECT 1 FROM public.dfir_iocs
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.ioc.resource}::uuid
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING id
      ), inserted_link AS MATERIALIZED (
        INSERT INTO public.dfir_ioc_links (
          id, tenant_id, ioc_id, case_id, created_by_membership_id, created_at
        )
        SELECT ${phaseOneFixtures.demo.ioc.link}::uuid, ${acme.id}::uuid,
               inserted_ioc.id, ${phaseOneFixtures.demo.case}::uuid,
               ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
               ${demoOccurredAt.toISOString()}::timestamptz
        FROM inserted_ioc
        ON CONFLICT (id) DO NOTHING
        RETURNING ioc_id
      )
      SELECT app.append_phase4_mutation_effects_v1(
        'dfir.ioc.manage', 'dfir.ioc.created', 'dfir_ioc',
        inserted_ioc.id, 1, ${phaseOneFixtures.demo.case}::uuid,
        uuidv7(), 'ioc', inserted_ioc.id,
        'Created and linked synthetic IOC.', NULL,
        jsonb_build_object('type', 'domain', 'version', 1),
        jsonb_build_object('source', 'database_seed', 'demo', true),
        uuidv7(), uuidv7(), uuidv7(), uuidv7(),
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      FROM inserted_ioc
      JOIN inserted_link ON inserted_link.ioc_id = inserted_ioc.id
    `);

    await tx.execute(sql`
      WITH inserted_asset AS MATERIALIZED (
        INSERT INTO public.dfir_assets (
          id, tenant_id, hostname, normalized_hostname, fqdn,
          normalized_fqdn, ip_addresses, mac_addresses, mac8_addresses,
          original_identifiers, asset_type, operating_system, owner,
          business_unit, criticality, environment, external_id, tags,
          first_seen, last_seen, custom_attributes,
          created_by_membership_id, updated_by_membership_id,
          version, created_at, updated_at
        )
        SELECT
          ${phaseOneFixtures.demo.asset.resource}::uuid, ${acme.id}::uuid,
          'demo-workstation', 'demo-workstation',
          'demo-workstation.acme.example.invalid',
          'demo-workstation.acme.example.invalid',
          ARRAY['192.0.2.50'::inet]::inet[], ARRAY[]::macaddr[],
          ARRAY[]::macaddr8[],
          jsonb_build_object(
            'hostname', 'demo-workstation',
            'fqdn', 'demo-workstation.acme.example.invalid',
            'ipAddresses', jsonb_build_array('192.0.2.50'),
            'macAddresses', '[]'::jsonb
          ),
          'workstation', 'Synthetic OS', 'Acme Security',
          'Security', 'high', 'demo', 'demo-asset-001',
          ARRAY['demo', 'workstation']::text[],
          ${demoOccurredAt.toISOString()}::timestamptz, ${demoOccurredAt.toISOString()}::timestamptz,
          jsonb_build_object('synthetic', true),
          ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
          ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
          1, ${demoOccurredAt.toISOString()}::timestamptz, ${demoOccurredAt.toISOString()}::timestamptz
        WHERE NOT EXISTS (
          SELECT 1 FROM public.dfir_assets
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.asset.resource}::uuid
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING id
      ), inserted_link AS MATERIALIZED (
        INSERT INTO public.dfir_asset_links (
          id, tenant_id, asset_id, case_id,
          created_by_membership_id, created_at
        )
        SELECT ${phaseOneFixtures.demo.asset.link}::uuid, ${acme.id}::uuid,
               inserted_asset.id, ${phaseOneFixtures.demo.case}::uuid,
               ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
               ${demoOccurredAt.toISOString()}::timestamptz
        FROM inserted_asset
        ON CONFLICT (id) DO NOTHING
        RETURNING asset_id
      )
      SELECT app.append_phase4_mutation_effects_v1(
        'dfir.asset.manage', 'dfir.asset.created', 'dfir_asset',
        inserted_asset.id, 1, ${phaseOneFixtures.demo.case}::uuid,
        uuidv7(), 'asset', inserted_asset.id,
        'Created and linked synthetic Asset.', NULL,
        jsonb_build_object('criticality', 'high', 'version', 1),
        jsonb_build_object('source', 'database_seed', 'demo', true),
        uuidv7(), uuidv7(), uuidv7(), uuidv7(),
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      FROM inserted_asset
      JOIN inserted_link ON inserted_link.asset_id = inserted_asset.id
    `);

    await tx.execute(sql`
      WITH inserted_storage AS MATERIALIZED (
        INSERT INTO public.dfir_storage_objects (
          id, tenant_id, bucket, object_key, original_filename,
          classification, state, expected_size_bytes, upload_expires_at,
          content_sha256, size_bytes, detected_mime, verified_at,
          retention_until, legal_hold, created_by_membership_id,
          version, created_at, updated_at
        )
        SELECT
          ${phaseOneFixtures.demo.evidence.storageObject}::uuid,
          ${acme.id}::uuid, 'periapsis-demo',
          ${`${acme.id}/evidence/synthetic-evidence.json`},
          'synthetic-evidence.json', 'internal', 'available', 128,
          ${new Date(demoOccurredAt.getTime() + 30 * 60_000).toISOString()}::timestamptz,
          sha256(convert_to('synthetic demo evidence metadata', 'UTF8')), 128,
          'application/json',
          ${new Date(demoOccurredAt.getTime() + 60_000).toISOString()}::timestamptz,
          ${demoRetentionUntil.toISOString()}::timestamptz, false,
          ${phaseOneFixtures.memberships.acmeAdmin}::uuid,
          1, ${demoOccurredAt.toISOString()}::timestamptz,
          ${new Date(demoOccurredAt.getTime() + 60_000).toISOString()}::timestamptz
        WHERE NOT EXISTS (
          SELECT 1 FROM public.dfir_storage_objects
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.evidence.storageObject}::uuid
        )
        ON CONFLICT (id) DO NOTHING
        RETURNING id
      )
      SELECT app.append_phase4_mutation_effects_v1(
        'dfir.evidence.manage', 'dfir.evidence.storage_prepared',
        'dfir_storage_object', inserted_storage.id, 1,
        NULL, NULL, NULL, NULL,
        'Prepared synthetic Evidence storage metadata.', NULL,
        jsonb_build_object(
          'classification', 'internal', 'state', 'available', 'version', 1
        ),
        jsonb_build_object('source', 'database_seed', 'demo', true),
        uuidv7(), uuidv7(), uuidv7(), uuidv7(),
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      )
      FROM inserted_storage
    `);

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        WHERE NOT EXISTS (
          SELECT 1 FROM public.dfir_evidence
          WHERE tenant_id = ${acme.id}::uuid
            AND id = ${phaseOneFixtures.demo.evidence.resource}::uuid
        )
      `,
      sql`
      SELECT created.*
      FROM app.create_dfir_evidence_v1(
        ${phaseOneFixtures.demo.evidence.resource}::uuid,
        ${phaseOneFixtures.demo.case}::uuid,
        ${phaseOneFixtures.demo.evidence.storageObject}::uuid,
        'Synthetic sign-in evidence metadata',
        'Metadata-only Evidence fixture; no customer or credential data.',
        'json_report', 'internal',
        ${new Date(demoOccurredAt.getTime() + 2 * 60_000).toISOString()}::timestamptz,
        'database_seed', ${demoRetentionUntil.toISOString()}::timestamptz, false,
        ${phaseOneFixtures.demo.evidence.custodyEvent}::uuid,
        sha256(convert_to('demo-seed:evidence:anchor', 'UTF8')),
        sha256(convert_to('demo-seed:evidence:event', 'UTF8')),
        uuidv7(), uuidv7(), uuidv7(), uuidv7(), uuidv7(),
        '127.0.0.1'::inet, 'periapsis-demo-seed', 'bootstrap_totp'
      ) AS created
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        FROM public.cases AS case_row
        WHERE case_row.tenant_id = ${acme.id}::uuid
          AND case_row.id = ${phaseOneFixtures.demo.case}::uuid
          AND NOT EXISTS (
            SELECT 1 FROM public.ticket_comments AS comment
            WHERE comment.tenant_id = case_row.tenant_id
              AND comment.case_id = case_row.id
              AND comment.visibility = 'public'
              AND comment.body_markdown =
                'Synthetic public update: investigation started.'
          )
      `,
      sql`
      SELECT * FROM app.create_tenant_ticket_comment_v2(
        'case', ${phaseOneFixtures.demo.case}::uuid, 'public',
        'Synthetic public update: investigation started.',
        '<p>Synthetic public update: investigation started.</p>',
        ARRAY[]::uuid[], ARRAY[]::uuid[],
        sha256(convert_to('demo-seed:acme:public-comment:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:public-comment:request', 'UTF8')),
        uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );

    await runApiMutationIfMissing(
      sql`
        SELECT 1
        FROM public.cases AS case_row
        WHERE case_row.tenant_id = ${acme.id}::uuid
          AND case_row.id = ${phaseOneFixtures.demo.case}::uuid
          AND NOT EXISTS (
            SELECT 1 FROM public.ticket_comments AS comment
            WHERE comment.tenant_id = case_row.tenant_id
              AND comment.case_id = case_row.id
              AND comment.visibility = 'private'
              AND comment.body_markdown =
                'Synthetic private analyst note: correlate the demo IOC.'
          )
      `,
      sql`
      SELECT * FROM app.create_tenant_ticket_comment_v2(
        'case', ${phaseOneFixtures.demo.case}::uuid, 'private',
        'Synthetic private analyst note: correlate the demo IOC.',
        '<p>Synthetic private analyst note: correlate the demo IOC.</p>',
        ARRAY[]::uuid[], ARRAY[]::uuid[],
        sha256(convert_to('demo-seed:acme:private-comment:key', 'UTF8')),
        sha256(convert_to('demo-seed:acme:private-comment:request', 'UTF8')),
        uuidv7(), uuidv7(), '127.0.0.1'::inet,
        'periapsis-demo-seed', 'bootstrap_totp'
      )
      `,
    );
  });
} finally {
  await client.end();
}
