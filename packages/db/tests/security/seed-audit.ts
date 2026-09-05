import assert from "node:assert/strict";

import postgres, { type Sql } from "postgres";

import { requireDatabaseUrl } from "../../src/admin/database-url.js";
import { phaseOneFixtures } from "../../src/testing/fixtures.js";

type SeedAuditRow = {
  tenant_id: string;
  slug: string;
  initialized: boolean;
  actor_type: string;
  actor_user_id: string | null;
  impersonated_by_user_id: string | null;
  resource_id: string | null;
  authentication_method: string | null;
  outcome: string;
  after: Record<string, unknown> | null;
  metadata: Record<string, unknown>;
};

type OperatorTeamSeedRow = {
  id: string;
  key: string;
  display_name: string;
  created_by_user_id: string | null;
  actor_type: string;
  actor_user_id: string | null;
  authentication_method: string | null;
  outcome: string;
  metadata: Record<string, unknown>;
};

type DemoCatalogRow = {
  tenant_count: number;
  operator_team_count: number;
  example_role_count: number;
  customer_contact_count: number;
  unsafe_customer_contact_count: number;
  workflow_count: number;
  ldap_provider_count: number;
  ldap_binding_count: number;
  ldap_mapping_count: number;
  ldap_secret_count: number;
  enabled_ldap_component_count: number;
  unsafe_ldap_endpoint_count: number;
  custom_field_count: number;
  custom_field_revision_count: number;
  custom_field_permission_count: number;
  sla_calendar_count: number;
  sla_policy_count: number;
  sla_metric_count: number;
  sla_trigger_count: number;
  notification_template_count: number;
  notification_rule_count: number;
  alert_count: number;
  case_count: number;
  ioc_count: number;
  ioc_link_count: number;
  asset_count: number;
  asset_link_count: number;
  storage_object_count: number;
  evidence_count: number;
  custody_event_count: number;
  public_comment_count: number;
  private_comment_count: number;
};

type DemoRlsProjectionRow = {
  alert_count: number;
  asset_count: number;
  case_count: number;
  custom_field_count: number;
  customer_contact_count: number;
  evidence_count: number;
  ioc_count: number;
  storage_object_count: number;
};

type DemoAuditActionRow = {
  action: string;
  event_count: number;
  tenant_id: string;
};

type DemoActorAuditRow = {
  actor_type: string;
  actor_user_id: string | null;
  authentication_method: string | null;
  event_count: number;
  outcome: string;
  tenant_id: string;
};

async function assertAuditChain(sql: Sql, tenantID: string): Promise<void> {
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantID}, true)
    `;
    const rows = await transaction<{ valid: boolean }[]>`
      SELECT valid
      FROM app.verify_audit_chain(${tenantID}::uuid)
    `;
    assert(rows.length >= 2, `audit chain for ${tenantID} has no sealed event`);
    assert(
      rows.every((row) => row.valid),
      `audit chain for ${tenantID} failed verification`,
    );
  });
}

async function readDemoRlsProjection(
  sql: Sql,
  tenantID: string,
  userID: string,
): Promise<DemoRlsProjectionRow> {
  return sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction`
      SELECT set_config('app.tenant_id', ${tenantID}, true),
             set_config('app.user_id', ${userID}, true),
             set_config('app.service_account_id', '', true)
    `;
    const [projection] = await transaction<DemoRlsProjectionRow[]>`
      SELECT
        (SELECT count(*)::integer FROM public.alerts
         WHERE id IN (
           ${phaseOneFixtures.alerts.acme}::uuid,
           ${phaseOneFixtures.alerts.globex}::uuid
         )) AS alert_count,
        (SELECT count(*)::integer FROM public.cases
         WHERE id = ${phaseOneFixtures.demo.case}::uuid) AS case_count,
        (SELECT count(*)::integer FROM public.dfir_iocs
         WHERE id = ${phaseOneFixtures.demo.ioc.resource}::uuid) AS ioc_count,
        (SELECT count(*)::integer FROM public.dfir_assets
         WHERE id = ${phaseOneFixtures.demo.asset.resource}::uuid) AS asset_count,
        (SELECT count(*)::integer FROM public.dfir_evidence
         WHERE id = ${phaseOneFixtures.demo.evidence.resource}::uuid)
          AS evidence_count,
        (SELECT count(*)::integer FROM public.dfir_storage_objects
         WHERE id = ${phaseOneFixtures.demo.evidence.storageObject}::uuid)
          AS storage_object_count,
        (SELECT count(*)::integer FROM public.custom_field_definitions
         WHERE id = ${phaseOneFixtures.demo.customField.definition}::uuid)
          AS custom_field_count,
        (SELECT count(*)::integer FROM public.customer_contacts
         WHERE id IN (
           ${phaseOneFixtures.demo.contacts.acme}::uuid,
           ${phaseOneFixtures.demo.contacts.globex}::uuid
         )) AS customer_contact_count
    `;
    assert(projection, `RLS projection for ${tenantID} returned no row`);
    return projection;
  });
}

const databaseURL = requireDatabaseUrl();
const client = postgres(databaseURL, { max: 1, onnotice: () => undefined });
const tenantIDs = [
  phaseOneFixtures.tenants.acme.id,
  phaseOneFixtures.tenants.globex.id,
].toSorted();

try {
  const [catalog] = await client<DemoCatalogRow[]>`
    SELECT
      (SELECT count(*)::integer FROM public.tenants
       WHERE id IN (
         ${phaseOneFixtures.tenants.acme.id}::uuid,
         ${phaseOneFixtures.tenants.globex.id}::uuid
       )) AS tenant_count,
      (SELECT count(*)::integer FROM public.operator_teams
       WHERE id IN (
         ${phaseOneFixtures.operatorTeams.socL1.id}::uuid,
         ${phaseOneFixtures.operatorTeams.socL2.id}::uuid
       )) AS operator_team_count,
      (SELECT count(*)::integer FROM public.tenant_roles
       WHERE id IN (
         ${phaseOneFixtures.demo.roles.acmeResponder}::uuid,
         ${phaseOneFixtures.demo.roles.globexResponder}::uuid
       )) AS example_role_count,
      (SELECT count(*)::integer FROM public.customer_contacts
       WHERE id IN (
         ${phaseOneFixtures.demo.contacts.acme}::uuid,
         ${phaseOneFixtures.demo.contacts.globex}::uuid
       )) AS customer_contact_count,
      (SELECT count(*)::integer FROM public.customer_contacts
       WHERE id IN (
         ${phaseOneFixtures.demo.contacts.acme}::uuid,
         ${phaseOneFixtures.demo.contacts.globex}::uuid
       ) AND (email IS NULL OR email NOT LIKE '%.invalid'))
        AS unsafe_customer_contact_count,
      (SELECT count(*)::integer FROM public.ticket_workflows
       WHERE tenant_id IN (
         ${phaseOneFixtures.tenants.acme.id}::uuid,
         ${phaseOneFixtures.tenants.globex.id}::uuid
       ) AND key IN ('default_alert','default_case')) AS workflow_count,
      (SELECT count(*)::integer FROM public.tenant_auth_providers
       WHERE id = ${phaseOneFixtures.demo.ldap.provider}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND kind = 'ldap') AS ldap_provider_count,
      (SELECT count(*)::integer FROM public.tenant_auth_provider_bindings
       WHERE id = ${phaseOneFixtures.demo.ldap.binding}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS ldap_binding_count,
      (SELECT count(*)::integer FROM public.tenant_ldap_mapping_rules
       WHERE tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND binding_id = ${phaseOneFixtures.demo.ldap.binding}::uuid
         AND matcher_type = 'exact_cn'
         AND matcher_value = 'demo-responders'
         AND archived_at IS NULL) AS ldap_mapping_count,
      (SELECT count(*)::integer FROM public.tenant_ldap_provider_secrets
       WHERE tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND provider_id = ${phaseOneFixtures.demo.ldap.provider}::uuid) AS ldap_secret_count,
      ((SELECT count(*) FROM public.tenant_auth_providers
        WHERE id = ${phaseOneFixtures.demo.ldap.provider}::uuid AND enabled)
       + (SELECT count(*) FROM public.tenant_auth_provider_bindings
          WHERE id = ${phaseOneFixtures.demo.ldap.binding}::uuid AND enabled)
       + (SELECT count(*) FROM public.tenant_ldap_mapping_rules
          WHERE binding_id = ${phaseOneFixtures.demo.ldap.binding}::uuid
            AND enabled))::integer AS enabled_ldap_component_count,
      (SELECT count(*)::integer FROM public.tenant_ldap_provider_urls
       WHERE tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND provider_id = ${phaseOneFixtures.demo.ldap.provider}::uuid
         AND (enabled OR host NOT LIKE '%.invalid')) AS unsafe_ldap_endpoint_count,
      (SELECT count(*)::integer FROM public.custom_field_definitions
       WHERE id = ${phaseOneFixtures.demo.customField.definition}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS custom_field_count,
      (SELECT count(*)::integer FROM public.custom_field_definition_revisions
       WHERE id = ${phaseOneFixtures.demo.customField.revision}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS custom_field_revision_count,
      (SELECT count(*)::integer FROM public.custom_field_permissions
       WHERE tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND definition_id = ${phaseOneFixtures.demo.customField.definition}::uuid
         AND audience = 'operator') AS custom_field_permission_count,
      (SELECT count(*)::integer FROM public.sla_business_calendars
       WHERE id = ${phaseOneFixtures.demo.sla.calendar}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS sla_calendar_count,
      (SELECT count(*)::integer FROM public.sla_policies
       WHERE id = ${phaseOneFixtures.demo.sla.policy}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS sla_policy_count,
      (SELECT count(*)::integer FROM public.sla_metric_definitions
       WHERE id = ${phaseOneFixtures.demo.sla.metric}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS sla_metric_count,
      (SELECT count(*)::integer FROM public.sla_trigger_definitions
       WHERE id = ${phaseOneFixtures.demo.sla.trigger}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS sla_trigger_count,
      (SELECT count(*)::integer FROM public.tenant_notification_templates
       WHERE id = ${phaseOneFixtures.demo.notifications.template}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS notification_template_count,
      (SELECT count(*)::integer FROM public.tenant_notification_rules
       WHERE id = ${phaseOneFixtures.demo.notifications.rule}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS notification_rule_count,
      (SELECT count(*)::integer FROM public.alerts
       WHERE id IN (
         ${phaseOneFixtures.alerts.acme}::uuid,
         ${phaseOneFixtures.alerts.globex}::uuid
       )) AS alert_count,
      (SELECT count(*)::integer FROM public.cases
       WHERE id = ${phaseOneFixtures.demo.case}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS case_count,
      (SELECT count(*)::integer FROM public.dfir_iocs
       WHERE id = ${phaseOneFixtures.demo.ioc.resource}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS ioc_count,
      (SELECT count(*)::integer FROM public.dfir_ioc_links
       WHERE id = ${phaseOneFixtures.demo.ioc.link}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND case_id = ${phaseOneFixtures.demo.case}::uuid) AS ioc_link_count,
      (SELECT count(*)::integer FROM public.dfir_assets
       WHERE id = ${phaseOneFixtures.demo.asset.resource}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS asset_count,
      (SELECT count(*)::integer FROM public.dfir_asset_links
       WHERE id = ${phaseOneFixtures.demo.asset.link}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND case_id = ${phaseOneFixtures.demo.case}::uuid) AS asset_link_count,
      (SELECT count(*)::integer FROM public.dfir_storage_objects
       WHERE id = ${phaseOneFixtures.demo.evidence.storageObject}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND state = 'available') AS storage_object_count,
      (SELECT count(*)::integer FROM public.dfir_evidence
       WHERE id = ${phaseOneFixtures.demo.evidence.resource}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND case_id = ${phaseOneFixtures.demo.case}::uuid) AS evidence_count,
      (SELECT count(*)::integer FROM public.dfir_custody_events
       WHERE id = ${phaseOneFixtures.demo.evidence.custodyEvent}::uuid
         AND tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid) AS custody_event_count,
      (SELECT count(*)::integer FROM public.ticket_comments
       WHERE tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND case_id = ${phaseOneFixtures.demo.case}::uuid
         AND visibility = 'public') AS public_comment_count,
      (SELECT count(*)::integer FROM public.ticket_comments
       WHERE tenant_id = ${phaseOneFixtures.tenants.acme.id}::uuid
         AND case_id = ${phaseOneFixtures.demo.case}::uuid
         AND visibility = 'private') AS private_comment_count
  `;
  assert(catalog, "complete demo catalog query returned no row");
  assert.deepEqual(catalog, {
    tenant_count: 2,
    operator_team_count: 2,
    example_role_count: 2,
    customer_contact_count: 2,
    unsafe_customer_contact_count: 0,
    workflow_count: 4,
    ldap_provider_count: 1,
    ldap_binding_count: 1,
    ldap_mapping_count: 1,
    ldap_secret_count: 0,
    enabled_ldap_component_count: 0,
    unsafe_ldap_endpoint_count: 0,
    custom_field_count: 1,
    custom_field_revision_count: 1,
    custom_field_permission_count: 1,
    sla_calendar_count: 1,
    sla_policy_count: 1,
    sla_metric_count: 1,
    sla_trigger_count: 1,
    notification_template_count: 1,
    notification_rule_count: 1,
    alert_count: 2,
    case_count: 1,
    ioc_count: 1,
    ioc_link_count: 1,
    asset_count: 1,
    asset_link_count: 1,
    storage_object_count: 1,
    evidence_count: 1,
    custody_event_count: 1,
    public_comment_count: 1,
    private_comment_count: 1,
  });

  const acmeProjection = await readDemoRlsProjection(
    client,
    phaseOneFixtures.tenants.acme.id,
    phaseOneFixtures.users.acmeAdmin.id,
  );
  assert.deepEqual(acmeProjection, {
    alert_count: 1,
    asset_count: 1,
    case_count: 1,
    custom_field_count: 1,
    customer_contact_count: 1,
    evidence_count: 1,
    ioc_count: 1,
    storage_object_count: 1,
  });

  const globexProjection = await readDemoRlsProjection(
    client,
    phaseOneFixtures.tenants.globex.id,
    phaseOneFixtures.users.globexAdmin.id,
  );
  assert.deepEqual(globexProjection, {
    alert_count: 1,
    asset_count: 0,
    case_count: 0,
    custom_field_count: 0,
    customer_contact_count: 1,
    evidence_count: 0,
    ioc_count: 0,
    storage_object_count: 0,
  });

  const demoAuditActions = await client<DemoAuditActionRow[]>`
    SELECT tenant_id::text, action, count(*)::integer AS event_count
    FROM public.audit_events
    WHERE tenant_id IN (
      ${phaseOneFixtures.tenants.acme.id}::uuid,
      ${phaseOneFixtures.tenants.globex.id}::uuid
    )
      AND action <> 'tenant.authorization.initialized'
      AND (
        metadata ->> 'source' IN ('database_seed', 'phase-one-seed')
        OR user_agent = 'periapsis-demo-seed'
      )
    GROUP BY tenant_id, action
    ORDER BY tenant_id, action
  `;
  assert.deepEqual(
    [...demoAuditActions],
    [
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "alert.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "custom_field.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "dfir.asset.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "dfir.evidence.collected",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "dfir.evidence.storage_prepared",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "dfir.ioc.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "sla.calendar.published",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "sla.policy.published",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.case.commented",
        event_count: 2,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.case.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.contact.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.identity_mapping.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.identity_provider.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.identity_provider_binding.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.notification.rule_create",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.notification.template_create",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.role.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        action: "tenant.security_group.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.globex.id,
        action: "alert.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.globex.id,
        action: "tenant.contact.created",
        event_count: 1,
      },
      {
        tenant_id: phaseOneFixtures.tenants.globex.id,
        action: "tenant.role.created",
        event_count: 1,
      },
    ],
  );

  const demoActorAudits = await client<DemoActorAuditRow[]>`
    SELECT tenant_id::text, actor_type::text,
           actor_user_id::text, authentication_method,
           outcome::text, count(*)::integer AS event_count
    FROM public.audit_events
    WHERE user_agent = 'periapsis-demo-seed'
      AND tenant_id IN (
        ${phaseOneFixtures.tenants.acme.id}::uuid,
        ${phaseOneFixtures.tenants.globex.id}::uuid
      )
    GROUP BY tenant_id, actor_type, actor_user_id,
             authentication_method, outcome
    ORDER BY tenant_id
  `;
  assert.deepEqual(
    [...demoActorAudits],
    [
      {
        tenant_id: phaseOneFixtures.tenants.acme.id,
        actor_type: "user",
        actor_user_id: phaseOneFixtures.users.acmeAdmin.id,
        authentication_method: "bootstrap_totp",
        outcome: "success",
        event_count: 18,
      },
      {
        tenant_id: phaseOneFixtures.tenants.globex.id,
        actor_type: "user",
        actor_user_id: phaseOneFixtures.users.globexAdmin.id,
        authentication_method: "bootstrap_totp",
        outcome: "success",
        event_count: 2,
      },
    ],
  );

  const events = await client<SeedAuditRow[]>`
    SELECT tenant.id::text AS tenant_id,
           tenant.slug,
           state.initialized_at IS NOT NULL AS initialized,
           event.actor_type::text AS actor_type,
           event.actor_user_id::text AS actor_user_id,
           event.impersonated_by_user_id::text AS impersonated_by_user_id,
           event.resource_id::text AS resource_id,
           event.authentication_method,
           event.outcome::text AS outcome,
           event.after,
           event.metadata
    FROM public.tenants AS tenant
    JOIN public.tenant_authorization_states AS state
      ON state.tenant_id = tenant.id
    JOIN public.audit_events AS event
      ON event.tenant_id = tenant.id
     AND event.action = 'tenant.authorization.initialized'
     AND event.resource_type = 'tenant'
     AND event.resource_id = tenant.id
    WHERE tenant.id IN (
      ${phaseOneFixtures.tenants.acme.id}::uuid,
      ${phaseOneFixtures.tenants.globex.id}::uuid
    )
    ORDER BY tenant.id, event.sequence
  `;

  assert.deepEqual(
    events.map((event) => event.tenant_id),
    tenantIDs,
    "each demo tenant must have exactly one authorization initialization audit",
  );
  for (const event of events) {
    assert.equal(event.initialized, true);
    assert.equal(event.actor_type, "system");
    assert.equal(event.actor_user_id, null);
    assert.equal(event.impersonated_by_user_id, null);
    assert.equal(event.resource_id, event.tenant_id);
    assert.equal(event.authentication_method, "database_seed");
    assert.equal(event.outcome, "success");
    assert.deepEqual(event.after, {
      authorization_initialized: true,
      recovery_grant_initialized: true,
    });
    assert.deepEqual(event.metadata, {
      seed: "phase_one_demo",
      source: "database_seed",
    });
  }

  const operatorTeamEvents = await client<OperatorTeamSeedRow[]>`
    SELECT team.id::text,
           team.key,
           team.display_name,
           team.created_by_user_id::text,
           event.actor_type::text,
           event.actor_user_id::text,
           event.authentication_method,
           event.outcome::text,
           event.metadata
    FROM public.operator_teams AS team
    JOIN public.platform_audit_events AS event
      ON event.action = 'platform.operator_team.created'
     AND event.resource_type = 'operator_team'
     AND event.resource_id = team.id
    WHERE team.id IN (
      ${phaseOneFixtures.operatorTeams.socL1.id}::uuid,
      ${phaseOneFixtures.operatorTeams.socL2.id}::uuid
    )
    ORDER BY team.id, event.sequence
  `;

  assert.deepEqual(
    operatorTeamEvents.map((event) => event.id),
    [
      phaseOneFixtures.operatorTeams.socL1.id,
      phaseOneFixtures.operatorTeams.socL2.id,
    ],
    "each demo operator team must have exactly one platform creation audit",
  );
  for (const event of operatorTeamEvents) {
    assert.equal(event.created_by_user_id, null);
    assert.equal(event.actor_type, "system");
    assert.equal(event.actor_user_id, null);
    assert.equal(event.authentication_method, "database_seed");
    assert.equal(event.outcome, "success");
    assert.equal(event.metadata.key, event.key);
    assert.equal(event.metadata.name, event.display_name);
    assert.equal(event.metadata.source, "phase_one_demo_seed");
  }

  await client.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_auditor"');
    const rows = await transaction<{ valid: boolean }[]>`
      SELECT valid FROM app.verify_platform_audit_chain()
    `;
    assert(
      rows.length >= 2,
      "platform audit chain has no operator-team events",
    );
    assert(
      rows.every((row) => row.valid),
      "platform audit chain failed verification after demo operator-team seed",
    );
  });

  await Promise.all(
    tenantIDs.map((tenantID) => assertAuditChain(client, tenantID)),
  );
  process.stdout.write(
    "complete demo catalog, RLS projections, exact audit multiplicity, and tenant chains verified\n",
  );
} finally {
  await client.end();
}
