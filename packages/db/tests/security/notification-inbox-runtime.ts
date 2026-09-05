import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type PgError = Error & { code?: string };
type JsonValue =
  null | string | number | boolean | Date | JsonValue[] | JsonObject;
type JsonObject = { readonly [key: string]: JsonValue | undefined };

function isJsonObject(value: JsonValue | undefined): value is JsonObject {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    !(value instanceof Date)
  );
}

function requireJsonObject(
  value: JsonValue | undefined,
  message: string,
): JsonObject {
  assert(isJsonObject(value), message);
  return value;
}

function requireJsonObjectArray(
  value: JsonValue | undefined,
  message: string,
): JsonObject[] {
  assert(Array.isArray(value), message);
  const objects = value.filter(isJsonObject);
  assert.equal(objects.length, value.length, message);
  return objects;
}

function requireString(value: JsonValue | undefined, message: string): string {
  assert(typeof value === "string", message);
  return value;
}

const databaseUrl = process.env.PERIAPSIS_NOTIFICATION_INBOX_TEST_DATABASE_URL;
if (!databaseUrl?.trim()) {
  throw new Error(
    "PERIAPSIS_NOTIFICATION_INBOX_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d7600-2300-7000-8000-${(sequence + BigInt(offset)).toString(16).padStart(12, "0")}`;
const ids = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  operator: uuid(101),
  ambiguousOne: uuid(102),
  ambiguousTwo: uuid(103),
  customer: uuid(104),
  foreignUser: uuid(105),
  operatorMembership: uuid(201),
  ambiguousOneMembership: uuid(202),
  ambiguousTwoMembership: uuid(203),
  customerMembership: uuid(204),
  foreignMembership: uuid(205),
  ambiguousOneGrant: uuid(206),
  operatorSession: uuid(301),
  customerSession: uuid(302),
  foreignSession: uuid(303),
  operatorRotation: uuid(304),
  customerRotation: uuid(305),
  foreignRotation: uuid(306),
  ambiguousSession: uuid(307),
  ambiguousRotation: uuid(308),
  template: uuid(401),
  smtpSecret: uuid(402),
  smtpConfiguration: uuid(403),
  operatorRule: uuid(410),
  duplicateOperatorRule: uuid(411),
  taskRule: uuid(412),
  evidenceRule: uuid(413),
  webhookRule: uuid(414),
  contactRule: uuid(415),
  customerAlertRule: uuid(416),
  privateCustomerRule: uuid(417),
  alert: uuid(501),
  linkedContact: uuid(502),
  unlinkedContact: uuid(503),
  transitionContact: uuid(504),
  linkedContactEdge: uuid(505),
  unlinkedContactEdge: uuid(506),
  normalEvent: uuid(601),
  futureEvent: uuid(602),
  olderEvent: uuid(603),
  taskEvent: uuid(604),
  evidenceEvent: uuid(605),
  webhookEvent: uuid(606),
  noAccountEvent: uuid(607),
  ambiguousEvent: uuid(608),
  mixedAudienceEvent: uuid(609),
  privateCustomerEvent: uuid(610),
  invalidMappingEvent: uuid(611),
} as const;

const database = postgres(databaseUrl, { max: 8, onnotice: () => undefined });
const suffix = sequence.toString(36);
const operatorEmail = `inbox-operator-${suffix}@example.invalid`;
const ambiguousEmail = `inbox-ambiguous-${suffix}@example.invalid`;
const customerEmail = `inbox-customer-${suffix}@example.invalid`;
const foreignEmail = `inbox-foreign-${suffix}@example.invalid`;
const digest = (label: string): Buffer =>
  createHash("sha256")
    .update(`notification-inbox:${sequence}:${label}`)
    .digest();
const hexDigest = (label: string): string => digest(label).toString("hex");
const errorCode = (error: unknown): string | undefined =>
  error instanceof Error ? (error as PgError).code : undefined;

async function rejects(
  operation: Promise<unknown>,
  code: string,
  message: string,
): Promise<void> {
  await assert.rejects(operation, (error) => {
    assert(error instanceof Error, message);
    assert.equal(errorCode(error), code, error.message);
    return true;
  });
}

async function asRole<T>(
  role:
    | "periapsis_api"
    | "periapsis_notification_dispatch_owner"
    | "periapsis_notification_inbox_owner"
    | "periapsis_notifier",
  tenantID: string | undefined,
  userID: string | undefined,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await database.begin(async (transaction) => {
    await transaction.unsafe(`SET LOCAL ROLE "${role}"`);
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    if (tenantID !== undefined && userID !== undefined) {
      await transaction`
        SELECT set_config('app.tenant_id',${tenantID},true),
               set_config('app.user_id',${userID},true),
               set_config('app.service_account_id','',true),
               set_config(
                 'app.traceparent',
                 '00-11111111111111111111111111111111-2222222222222222-01',
                 true
               ),
               set_config('app.tracestate','notification_inbox=runtime',true)
      `;
    }
    return { value: await operation(transaction) };
  });
  return result.value;
}

const asApi = <T>(
  tenantID: string,
  userID: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> => asRole("periapsis_api", tenantID, userID, operation);

async function setup(): Promise<void> {
  const createdAt = new Date(Date.now() - 10 * 60_000);
  await database.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants(id,slug,name) VALUES
        (${ids.tenant}::uuid,${`notification-inbox-${suffix}`},
         'Notification inbox runtime'),
        (${ids.foreignTenant}::uuid,${`notification-inbox-foreign-${suffix}`},
         'Foreign notification inbox runtime')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id) VALUES
        (${ids.tenant}::uuid),(${ids.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active) VALUES
        (${ids.operator}::uuid,${operatorEmail},'Inbox operator',true),
        (${ids.ambiguousOne}::uuid,${`ambiguous-one-${suffix}@example.invalid`},
         'Ambiguous operator one',true),
        (${ids.ambiguousTwo}::uuid,${`ambiguous-two-${suffix}@example.invalid`},
         'Ambiguous operator two',true),
        (${ids.customer}::uuid,${customerEmail},'Inbox customer',true),
        (${ids.foreignUser}::uuid,${foreignEmail},'Foreign inbox user',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(id,tenant_id,user_id,role,status)
      VALUES
        (${ids.operatorMembership}::uuid,${ids.tenant}::uuid,
         ${ids.operator}::uuid,'tenant_admin','active'),
        (${ids.ambiguousOneMembership}::uuid,${ids.tenant}::uuid,
         ${ids.ambiguousOne}::uuid,'analyst','active'),
        (${ids.ambiguousTwoMembership}::uuid,${ids.tenant}::uuid,
         ${ids.ambiguousTwo}::uuid,'analyst','active'),
        (${ids.customerMembership}::uuid,${ids.tenant}::uuid,
         ${ids.customer}::uuid,'customer_user','active'),
        (${ids.foreignMembership}::uuid,${ids.foreignTenant}::uuid,
         ${ids.foreignUser}::uuid,'tenant_admin','active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${ids.tenant}::uuid,${ids.operatorMembership}::uuid
      )
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${ids.foreignTenant}::uuid,${ids.foreignMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants(
        id,tenant_id,membership_id,role_id,source_id,
        granted_by_membership_id,grant_reason
      )
      SELECT ${ids.ambiguousOneGrant}::uuid,${ids.tenant}::uuid,
             ${ids.ambiguousOneMembership}::uuid,role.id,source.id,
             ${ids.operatorMembership}::uuid,
             'Notification inbox runtime operator authority'
      FROM public.tenant_roles AS role
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id=role.tenant_id
       AND source.key='manual' AND source.retired_at IS NULL
      WHERE role.tenant_id=${ids.tenant}::uuid
        AND role.key='analyst' AND role.archived_at IS NULL
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(
        tenant_id,membership_id,user_id,display_name,email
      ) VALUES
        (${ids.tenant}::uuid,${ids.operatorMembership}::uuid,
         ${ids.operator}::uuid,'Inbox operator',${operatorEmail}),
        (${ids.tenant}::uuid,${ids.ambiguousOneMembership}::uuid,
         ${ids.ambiguousOne}::uuid,'Ambiguous one',${ambiguousEmail}),
        (${ids.tenant}::uuid,${ids.ambiguousTwoMembership}::uuid,
         ${ids.ambiguousTwo}::uuid,'Ambiguous two',${ambiguousEmail}),
        (${ids.tenant}::uuid,${ids.customerMembership}::uuid,
         ${ids.customer}::uuid,'Inbox customer',${customerEmail}),
        (${ids.foreignTenant}::uuid,${ids.foreignMembership}::uuid,
         ${ids.foreignUser}::uuid,'Foreign inbox user',${foreignEmail})
    `;
    await Promise.all(
      (
        [
          [
            ids.operatorSession,
            ids.operator,
            ids.tenant,
            "operator",
            ids.operatorRotation,
          ],
          [
            ids.customerSession,
            ids.customer,
            ids.tenant,
            "customer",
            ids.customerRotation,
          ],
          [
            ids.foreignSession,
            ids.foreignUser,
            ids.foreignTenant,
            "foreign",
            ids.foreignRotation,
          ],
          [
            ids.ambiguousSession,
            ids.ambiguousOne,
            ids.tenant,
            "ambiguous",
            ids.ambiguousRotation,
          ],
        ] as const
      ).map(
        (session) => transaction`
        INSERT INTO public.auth_sessions(
          id,user_id,rotation_family_id,active_tenant_id,token_digest,
          csrf_secret_digest,authentication_method,mfa_satisfied_at,last_seen_at,
          idle_expires_at,absolute_expires_at,created_at
        ) VALUES (
          ${session[0]}::uuid,${session[1]}::uuid,${session[4]}::uuid,
          ${session[2]}::uuid,${digest(`${session[3]}:token`)},
          ${digest(`${session[3]}:csrf`)},'totp',
          date_trunc('milliseconds',transaction_timestamp())-interval '2 minutes',
          date_trunc('milliseconds',transaction_timestamp())-interval '1 minute',
          date_trunc('milliseconds',transaction_timestamp())+interval '1 hour',
          date_trunc('milliseconds',transaction_timestamp())+interval '8 hours',
          date_trunc('milliseconds',transaction_timestamp())-interval '10 minutes'
        )
      `,
      ),
    );
    await transaction`
      INSERT INTO public.customer_contacts(
        id,tenant_id,first_name,last_name,email,function,language,timezone,
        contact_class,notification_categories,email_allowed,active,
        linked_membership_id,linked_user_id
      ) VALUES
        (${ids.linkedContact}::uuid,${ids.tenant}::uuid,'Linked','Customer',
         ${customerEmail},'customer','en','UTC','standard',
         ARRAY['alert.created','alert.watcher_added','contact.changed']::text[],
         true,true,${ids.customerMembership}::uuid,${ids.customer}::uuid),
        (${ids.unlinkedContact}::uuid,${ids.tenant}::uuid,'Unlinked','Customer',
         ${customerEmail},'customer','en','UTC','standard',
         ARRAY['alert.created','alert.watcher_added','contact.changed']::text[],
         true,true,NULL,NULL)
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${ids.tenant},true),
             set_config('app.user_id',${ids.operator},true)
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,
        customer_visible,title,created_by,created_by_membership_id,version,
        updated_at
      )
      SELECT ${ids.alert}::uuid,${ids.tenant}::uuid,
             ${`ALT-2026-${(sequence % 900_000n).toString().padStart(6, "0")}`},
             workflow.id,workflow.current_version,state.value->>'key',true,
             'Notification inbox runtime Alert',${ids.operator}::uuid,
             ${ids.operatorMembership}::uuid,1,transaction_timestamp()
      FROM public.ticket_workflows AS workflow
      JOIN public.ticket_workflow_versions AS version
        ON version.tenant_id=workflow.tenant_id
       AND version.workflow_id=workflow.id
       AND version.aggregate_kind=workflow.aggregate_kind
       AND version.version=workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
      WHERE workflow.tenant_id=${ids.tenant}::uuid
        AND workflow.key='default_alert'
        AND (state.value->>'initial')::boolean
    `;
    await transaction`
      INSERT INTO public.ticket_customer_contacts(
        id,tenant_id,alert_id,contact_id,role,origin,
        created_by_membership_id,created_by_user_id
      ) VALUES
        (${ids.linkedContactEdge}::uuid,${ids.tenant}::uuid,${ids.alert}::uuid,
         ${ids.linkedContact}::uuid,'primary','manual',
         ${ids.operatorMembership}::uuid,${ids.operator}::uuid),
        (${ids.unlinkedContactEdge}::uuid,${ids.tenant}::uuid,${ids.alert}::uuid,
         ${ids.unlinkedContact}::uuid,'watcher','manual',
         ${ids.operatorMembership}::uuid,${ids.operator}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_notification_secret_versions(
        tenant_id,secret_id,version,kind,key_version,nonce,ciphertext,
        created_at,created_by_membership_id,created_by_user_id
      ) VALUES (
        ${ids.tenant}::uuid,${ids.smtpSecret}::uuid,1,'smtp_password',1,
        decode(repeat('11',12),'hex'),decode(repeat('22',17),'hex'),
        ${createdAt},${ids.operatorMembership}::uuid,${ids.operator}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_smtp_configurations(
        id,tenant_id,current_version,created_at,created_by_membership_id,
        created_by_user_id,updated_at
      ) VALUES (
        ${ids.smtpConfiguration}::uuid,${ids.tenant}::uuid,1,${createdAt},
        ${ids.operatorMembership}::uuid,${ids.operator}::uuid,${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_smtp_configuration_versions(
        tenant_id,configuration_id,version,name,host,port,security,username,
        password_secret_id,password_secret_version,from_name,from_email,
        timeout_ms,maximum_connections,maximum_messages_per_connection,
        rate_limit_per_second,enabled,created_at,created_by_membership_id,
        created_by_user_id
      ) VALUES (
        ${ids.tenant}::uuid,${ids.smtpConfiguration}::uuid,1,'Inbox SMTP',
        'smtp.example.invalid',465,'tls','inbox-runtime',${ids.smtpSecret}::uuid,
        1,'Periapsis','notifications@example.invalid',10000,1,100,10,true,
        ${createdAt},${ids.operatorMembership}::uuid,${ids.operator}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_templates(
        id,tenant_id,key,current_version,created_at,created_by_membership_id,
        created_by_user_id,updated_at
      ) VALUES (
        ${ids.template}::uuid,${ids.tenant}::uuid,'notification.inbox.runtime',1,
        ${createdAt},${ids.operatorMembership}::uuid,${ids.operator}::uuid,
        ${createdAt}
      )
    `;
    await transaction`
      INSERT INTO public.tenant_notification_template_versions(
        tenant_id,template_id,version,key,name,language,subject,html,plain_text,
        css,sample_data,placeholders,created_at,created_by_membership_id,
        created_by_user_id
      ) VALUES (
        ${ids.tenant}::uuid,${ids.template}::uuid,1,
        'notification.inbox.runtime','Inbox runtime','en','Inbox runtime',
        '<p>Inbox runtime</p>','Inbox runtime','', '{}'::jsonb,ARRAY[]::text[],
        ${createdAt},${ids.operatorMembership}::uuid,${ids.operator}::uuid
      )
    `;

    const rules = [
      [ids.operatorRule, "alert.created", "alert", "actor", "operator"],
      [
        ids.duplicateOperatorRule,
        "alert.created",
        "alert",
        "actor",
        "operator",
      ],
      [ids.taskRule, "task.assigned", "task", "actor", "operator"],
      [ids.evidenceRule, "evidence.added", "evidence", "actor", "operator"],
      [ids.webhookRule, "webhook.custom", "contact", "actor", "operator"],
      [
        ids.contactRule,
        "contact.changed",
        "contact",
        "customer_contacts",
        "customer",
      ],
      [
        ids.customerAlertRule,
        "alert.created",
        "alert",
        "customer_contacts",
        "customer",
      ],
      [
        ids.privateCustomerRule,
        "alert.watcher_added",
        "alert",
        "customer_contacts",
        "customer",
      ],
    ] as const;
    await Promise.all(
      rules.map(async ([ruleID, eventType, objectType, selector, audience]) => {
        await transaction`
        INSERT INTO public.tenant_notification_rules(
          id,tenant_id,current_version,created_at,created_by_membership_id,
          created_by_user_id,updated_at
        ) VALUES (
          ${ruleID}::uuid,${ids.tenant}::uuid,1,${createdAt},
          ${ids.operatorMembership}::uuid,${ids.operator}::uuid,${createdAt}
        )
      `;
        await transaction`
        INSERT INTO public.tenant_notification_rule_versions(
          tenant_id,rule_id,version,name,description,event_type,object_type,
          condition,recipients,template_id,template_version,channel,priority,
          delay_ms,quiet_hours,deduplication_window_ms,grouping,retry,enabled,
          effective_from,created_at,created_by_membership_id,created_by_user_id
        ) VALUES (
          ${ids.tenant}::uuid,${ruleID}::uuid,1,${`Inbox ${eventType}`},'',
          ${eventType}::public.notification_event_type,
          ${objectType}::public.notification_object_type,
          ${transaction.json({ kind: "all", children: [] })}::jsonb,
          ${transaction.json([{ kind: selector, audience }])}::jsonb,
          ${ids.template}::uuid,1,'email',50,0,NULL,0,
          ${transaction.json({ mode: "none", windowMs: 0, maximumItems: 1 })}::jsonb,
          ${transaction.json({ maximumAttempts: 3, initialDelayMs: 1000, maximumDelayMs: 30000, multiplier: 2, jitterPercent: 10 })}::jsonb,
          true,${createdAt},${createdAt},${ids.operatorMembership}::uuid,
          ${ids.operator}::uuid
        )
      `;
      }),
    );
  });
}

type EventInput = {
  aggregateID: string;
  aggregateType: "alert" | "contact" | "evidence" | "task";
  eventID: string;
  eventType: string;
  maximumAudience?: "customer" | "operator";
  occurredAt: Date;
  actorID?: string;
};

let nextFenceOffset = 1_500;
async function stageEvent(input: EventInput): Promise<string> {
  const fence = uuid(nextFenceOffset++);
  const maximumAudience = input.maximumAudience ?? "operator";
  const operatorContext = { source: "notification-inbox-runtime" };
  const payload = {
    operatorContext,
    ...(maximumAudience === "customer"
      ? { customerContext: { source: "notification-inbox-customer-runtime" } }
      : {}),
  };
  await database`
    INSERT INTO public.outbox_events(
      id,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_type,
      schema_version,payload,deduplication_key,actor_kind,actor_id,producer,
      maximum_audience,occurred_at,available_at,attempts,locked_at,locked_by,
      lease_token,lease_until,created_at
    ) VALUES (
      ${input.eventID}::uuid,${ids.tenant}::uuid,${input.aggregateType},
      ${input.aggregateID}::uuid,1,${`notification.${input.eventType}`},2,
      ${database.json(payload)}::jsonb,${`inbox-runtime-${input.eventID}`},
      ${input.actorID === undefined ? "system" : "human"}::public.ticket_principal_kind,
      ${input.actorID ?? null}::uuid,'notification.inbox_runtime',
      ${maximumAudience}::public.notification_audience,${input.occurredAt},
      transaction_timestamp()-interval '1 second',1,transaction_timestamp(),
      'notification-inbox-runtime',${fence}::uuid,
      transaction_timestamp()+interval '5 minutes',transaction_timestamp()
    )
  `;
  return fence;
}

function plannedDelivery(input: {
  audience: "customer" | "operator";
  eventID: string;
  principalID?: string;
  recipient: string;
  ruleID: string;
}): JsonObject {
  const context =
    input.audience === "operator"
      ? { source: "notification-inbox-runtime" }
      : { source: "notification-inbox-customer-runtime" };
  return {
    deliveryKey: hexDigest(
      `delivery:${input.eventID}:${input.ruleID}:${input.recipient}:${input.audience}`,
    ),
    tenantId: ids.tenant,
    eventId: input.eventID,
    ruleId: input.ruleID,
    ruleVersion: 1,
    smtpConfigurationScope: "tenant",
    smtpConfigurationId: ids.smtpConfiguration,
    smtpConfigurationVersion: 1,
    template: { id: ids.template, version: 1 },
    recipient: input.recipient,
    audience: input.audience,
    context,
    priority: 50,
    deliverAfter: new Date().toISOString(),
    deduplicationKey: `inbox-${input.eventID}-${input.ruleID}`,
    groupingKey: "",
    groupingWindowMs: 0,
    groupingMaximumItems: 1,
    retry: {
      maximumAttempts: 3,
      initialDelayMs: 1000,
      maximumDelayMs: 30000,
      multiplier: 2,
      jitterPercent: 10,
    },
    ...(input.principalID === undefined
      ? {}
      : { principalId: input.principalID }),
  };
}

async function commit(
  eventID: string,
  fence: string,
  deliveries: readonly JsonObject[],
): Promise<JsonObject> {
  return asRole(
    "periapsis_notifier",
    undefined,
    undefined,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
        SELECT app.commit_notification_fanout_v3(
          ${eventID}::uuid,${fence}::uuid,
          ${transaction.json(deliveries)}::jsonb,
          transaction_timestamp()
        ) AS result
      `;
      assert(row, "fanout commit returned no result");
      return row.result;
    },
  );
}

const listRequest = (sessionID: string, after: string | null, limit = 101) => ({
  schemaVersion: 1,
  tenantId: ids.tenant,
  userId: ids.operator,
  sessionId: sessionID,
  after,
  limit,
  unreadOnly: false,
});
const audit = (label: string) => ({
  requestId: uuid(900 + label.length),
  correlationId: uuid(950 + label.length),
  remoteAddress: "127.0.0.1",
  userAgent: "notification-inbox-runtime",
});

async function run(): Promise<void> {
  await setup();

  const [catalog] = await database<
    Array<{
      all_forced: boolean;
      api_direct_select: boolean;
      helper_bypasses_rls: boolean;
      helper_owner: string;
    }>
  >`
    SELECT
      bool_and(class.relrowsecurity AND class.relforcerowsecurity) AS all_forced,
      bool_or(has_table_privilege(
        'periapsis_api',class.oid,'SELECT,INSERT,UPDATE,DELETE'
      )) AS api_direct_select,
      owner.rolbypassrls AS helper_bypasses_rls,
      owner.rolname AS helper_owner
    FROM pg_catalog.pg_class AS class
    CROSS JOIN LATERAL (
      SELECT role.rolname,role.rolbypassrls
      FROM pg_catalog.pg_proc AS function
      JOIN pg_catalog.pg_roles AS role ON role.oid=function.proowner
      WHERE function.oid=
        'app.private_notification_inbox_live_principal_v1(uuid,uuid)'::regprocedure
    ) AS owner
    WHERE class.oid IN (
      'public.tenant_notification_inbox_states'::regclass,
      'public.tenant_notification_inbox_items'::regclass,
      'public.tenant_notification_inbox_commands'::regclass
    )
    GROUP BY owner.rolname,owner.rolbypassrls
  `;
  assert(catalog, "notification inbox catalog proof returned no row");
  assert.equal(catalog.all_forced, true);
  assert.equal(catalog.api_direct_select, false);
  assert.equal(catalog.helper_owner, "periapsis_notification_dispatch_owner");
  assert.equal(catalog.helper_bypasses_rls, false);

  await rejects(
    asApi(
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
      SELECT id FROM public.tenant_notification_inbox_items LIMIT 1
    `,
    ),
    "42501",
    "API gained direct notification inbox table access",
  );

  await rejects(
    asRole(
      "periapsis_notification_dispatch_owner",
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
        SELECT app.private_notification_inbox_live_principal_v1(
          ${ids.foreignTenant}::uuid,${ids.foreignUser}::uuid
        )
      `,
    ),
    "42501",
    "dispatch helper crossed its current tenant",
  );

  const normalFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    actorID: ids.operator,
    eventID: ids.normalEvent,
    eventType: "alert.created",
    occurredAt: new Date(Date.now() - 60_000),
  });
  const normalResult = await commit(ids.normalEvent, normalFence, [
    plannedDelivery({
      audience: "operator",
      eventID: ids.normalEvent,
      principalID: ids.operator,
      recipient: operatorEmail,
      ruleID: ids.operatorRule,
    }),
    plannedDelivery({
      audience: "operator",
      eventID: ids.normalEvent,
      principalID: ids.operator,
      recipient: operatorEmail,
      ruleID: ids.duplicateOperatorRule,
    }),
  ]);
  assert.equal(normalResult.outcome, "committed");
  assert.equal(normalResult.emailCount, 2);
  const [dedupe] = await database<
    Array<{ item_count: string; title: string; summary: string }>
  >`
    SELECT count(*)::text AS item_count,min(title) AS title,min(summary) AS summary
    FROM public.tenant_notification_inbox_items
    WHERE tenant_id=${ids.tenant}::uuid AND event_id=${ids.normalEvent}::uuid
  `;
  assert.equal(
    dedupe?.item_count,
    "1",
    "rules duplicated a personal inbox item",
  );
  assert.equal(dedupe.title, "Alert created");
  assert.equal(dedupe.summary, "");

  const futureOccurredAt = new Date(Date.now() + 45_000);
  const futureFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    actorID: ids.operator,
    eventID: ids.futureEvent,
    eventType: "alert.created",
    occurredAt: futureOccurredAt,
  });
  await commit(ids.futureEvent, futureFence, [
    plannedDelivery({
      audience: "operator",
      eventID: ids.futureEvent,
      principalID: ids.operator,
      recipient: operatorEmail,
      ruleID: ids.operatorRule,
    }),
  ]);
  const [futureState] = await database<Array<{ updated_at: Date }>>`
    SELECT updated_at FROM public.tenant_notification_inbox_states
    WHERE tenant_id=${ids.tenant}::uuid AND user_id=${ids.operator}::uuid
  `;
  assert(futureState);
  assert(futureState.updated_at >= futureOccurredAt);

  const olderFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    actorID: ids.operator,
    eventID: ids.olderEvent,
    eventType: "alert.created",
    occurredAt: new Date(Date.now() - 120_000),
  });
  await commit(ids.olderEvent, olderFence, [
    plannedDelivery({
      audience: "operator",
      eventID: ids.olderEvent,
      principalID: ids.operator,
      recipient: operatorEmail,
      ruleID: ids.operatorRule,
    }),
  ]);
  const [olderState] = await database<Array<{ updated_at: Date }>>`
    SELECT updated_at FROM public.tenant_notification_inbox_states
    WHERE tenant_id=${ids.tenant}::uuid AND user_id=${ids.operator}::uuid
  `;
  assert(olderState);
  assert.equal(
    olderState.updated_at.toISOString(),
    futureState.updated_at.toISOString(),
    "an out-of-order event regressed the inbox state timestamp",
  );

  const [mappingContract] = await database<
    Array<{ definition: string; check: string }>
  >`
    SELECT
      pg_get_functiondef(
        'app.commit_notification_fanout_v3(uuid,uuid,jsonb,timestamp with time zone)'::regprocedure
      ) AS definition,
      pg_get_constraintdef(oid) AS check
    FROM pg_catalog.pg_constraint
    WHERE conname='tenant_notification_inbox_items_event_resource_check'
  `;
  assert(mappingContract);
  for (const token of [
    "comment.public_added",
    "comment.private_added",
    "task.assigned",
    "evidence.added",
    "webhook.custom",
    "resource_kind_value",
  ]) {
    assert(
      mappingContract.definition.includes(token),
      `fanout mapping omitted ${token}`,
    );
    if (token !== "resource_kind_value") {
      assert(
        mappingContract.check.includes(token),
        `table mapping omitted ${token}`,
      );
    }
  }

  const invalidFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "task",
    actorID: ids.operator,
    eventID: ids.invalidMappingEvent,
    eventType: "alert.created",
    occurredAt: new Date(),
  });
  await rejects(
    commit(ids.invalidMappingEvent, invalidFence, []),
    "42501",
    "fanout accepted an event/resource mismatch",
  );

  const ambiguousFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    actorID: ids.ambiguousOne,
    eventID: ids.ambiguousEvent,
    eventType: "alert.created",
    occurredAt: new Date(),
  });
  await rejects(
    commit(ids.ambiguousEvent, ambiguousFence, [
      plannedDelivery({
        audience: "operator",
        eventID: ids.ambiguousEvent,
        principalID: ids.ambiguousOne,
        recipient: ambiguousEmail,
        ruleID: ids.operatorRule,
      }),
    ]),
    "42501",
    "fanout let a shared email select one of two account principals",
  );

  const mixedFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    actorID: ids.operator,
    eventID: ids.mixedAudienceEvent,
    eventType: "alert.created",
    maximumAudience: "customer",
    occurredAt: new Date(),
  });
  await rejects(
    commit(ids.mixedAudienceEvent, mixedFence, [
      plannedDelivery({
        audience: "operator",
        eventID: ids.mixedAudienceEvent,
        principalID: ids.operator,
        recipient: operatorEmail,
        ruleID: ids.operatorRule,
      }),
      plannedDelivery({
        audience: "customer",
        eventID: ids.mixedAudienceEvent,
        principalID: ids.operator,
        recipient: operatorEmail,
        ruleID: ids.customerAlertRule,
      }),
    ]),
    "42501",
    "fanout accepted one principal with two audiences",
  );

  const customerAmbiguousFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    eventID: uuid(612),
    eventType: "alert.created",
    maximumAudience: "customer",
    occurredAt: new Date(),
  });
  await rejects(
    commit(uuid(612), customerAmbiguousFence, [
      plannedDelivery({
        audience: "customer",
        eventID: uuid(612),
        principalID: ids.customer,
        recipient: customerEmail,
        ruleID: ids.customerAlertRule,
      }),
    ]),
    "42501",
    "fanout let an account candidate override a same-email no-account contact",
  );

  const noAccountFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    eventID: ids.noAccountEvent,
    eventType: "alert.created",
    maximumAudience: "customer",
    occurredAt: new Date(),
  });
  const noAccountResult = await commit(ids.noAccountEvent, noAccountFence, [
    plannedDelivery({
      audience: "customer",
      eventID: ids.noAccountEvent,
      recipient: customerEmail,
      ruleID: ids.customerAlertRule,
    }),
  ]);
  assert.equal(noAccountResult.outcome, "committed");
  const [noAccountRows] = await database<
    Array<{ delivery_count: string; item_count: string }>
  >`
    SELECT
      (SELECT count(*)::text FROM public.tenant_notification_deliveries
       WHERE event_id=${ids.noAccountEvent}::uuid) AS delivery_count,
      (SELECT count(*)::text FROM public.tenant_notification_inbox_items
       WHERE event_id=${ids.noAccountEvent}::uuid) AS item_count
  `;
  assert.deepEqual(noAccountRows, { delivery_count: "1", item_count: "0" });

  const privateFence = await stageEvent({
    aggregateID: ids.alert,
    aggregateType: "alert",
    eventID: ids.privateCustomerEvent,
    eventType: "alert.watcher_added",
    maximumAudience: "customer",
    occurredAt: new Date(),
  });
  await rejects(
    commit(ids.privateCustomerEvent, privateFence, [
      plannedDelivery({
        audience: "customer",
        eventID: ids.privateCustomerEvent,
        principalID: ids.customer,
        recipient: customerEmail,
        ruleID: ids.privateCustomerRule,
      }),
    ]),
    "42501",
    "fanout created a customer inbox item for an operator-only event",
  );

  const firstPage = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.list_notification_inbox_v1(
        ${transaction.json(listRequest(ids.operatorSession, null, 2))}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert(firstPage);
  const firstItems = requireJsonObjectArray(
    firstPage.items,
    "first page has invalid items",
  );
  assert.equal(firstItems.length, 2);
  const firstCursor = requireString(
    firstItems[1]?.id,
    "first page cursor is invalid",
  );
  const secondPage = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.list_notification_inbox_v1(
        ${transaction.json(listRequest(ids.operatorSession, firstCursor, 2))}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert(secondPage);
  const secondItems = requireJsonObjectArray(
    secondPage.items,
    "second page has invalid items",
  );
  assert.equal(secondItems.length, 1);
  assert(
    !firstItems.some((item) => secondItems.some((next) => item.id === next.id)),
  );
  assert(
    firstItems.every(
      (item, index) =>
        index === 0 ||
        requireString(
          firstItems[index - 1]?.id,
          "previous item id is invalid",
        ) > requireString(item.id, "item id is invalid"),
    ),
  );
  assert(
    secondItems.every(
      (item) =>
        requireString(item.id, "second page item id is invalid") < firstCursor,
    ),
  );

  await rejects(
    asApi(
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
      SELECT app.list_notification_inbox_v1(
        ${transaction.json({ ...listRequest(ids.operatorSession, null), tenantId: ids.foreignTenant })}::jsonb
      )
    `,
    ),
    "22023",
    "cross-tenant list was accepted",
  );
  await rejects(
    asApi(
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
      SELECT app.list_notification_inbox_v1(
        ${transaction.json(listRequest(ids.foreignSession, null))}::jsonb
      )
    `,
    ),
    "42501",
    "wrong-user session was accepted",
  );

  await database`
    UPDATE public.auth_sessions SET revoked_at=transaction_timestamp(),
      revoke_reason='notification inbox runtime'
    WHERE id=${ids.operatorSession}::uuid
  `;
  await rejects(
    asApi(
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
      SELECT app.count_notification_inbox_unread_v1(
        ${transaction.json({ schemaVersion: 1, tenantId: ids.tenant, userId: ids.operator, sessionId: ids.operatorSession })}::jsonb
      )
    `,
    ),
    "42501",
    "revoked session was accepted",
  );
  await database`
    UPDATE public.auth_sessions SET revoked_at=NULL,revoke_reason=NULL
    WHERE id=${ids.operatorSession}::uuid
  `;
  const ambiguousCountRequest = {
    schemaVersion: 1,
    tenantId: ids.tenant,
    userId: ids.ambiguousOne,
    sessionId: ids.ambiguousSession,
  };
  await asApi(
    ids.tenant,
    ids.ambiguousOne,
    (transaction) => transaction`
    SELECT app.count_notification_inbox_unread_v1(
      ${transaction.json(ambiguousCountRequest)}::jsonb
    )
  `,
  );
  await database`
    UPDATE public.tenant_memberships SET status='suspended'
    WHERE tenant_id=${ids.tenant}::uuid AND user_id=${ids.ambiguousOne}::uuid
  `;
  await rejects(
    asApi(
      ids.tenant,
      ids.ambiguousOne,
      (transaction) => transaction`
      SELECT app.count_notification_inbox_unread_v1(
        ${transaction.json(ambiguousCountRequest)}::jsonb
      )
    `,
    ),
    "42501",
    "revoked membership was accepted",
  );
  await database`
    UPDATE public.tenant_memberships SET status='active'
    WHERE tenant_id=${ids.tenant}::uuid AND user_id=${ids.ambiguousOne}::uuid
  `;

  const [futureItem] = await database<Array<{ id: string; revision: number }>>`
    SELECT id,revision FROM public.tenant_notification_inbox_items
    WHERE tenant_id=${ids.tenant}::uuid AND user_id=${ids.operator}::uuid
      AND event_id=${ids.futureEvent}::uuid
  `;
  assert(futureItem);
  const setRequest = {
    schemaVersion: 1,
    tenantId: ids.tenant,
    userId: ids.operator,
    sessionId: ids.operatorSession,
    itemId: futureItem.id,
    read: true,
    expectedRevision: futureItem.revision,
    operation: "notification_inbox.set_read_state",
    keyDigest: hexDigest("set-read-key"),
    requestDigest: hexDigest("set-read-request"),
    audit: audit("set-read"),
  };
  const setResult = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.set_notification_inbox_read_state_v1(
        ${transaction.json(setRequest)}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert.equal(setResult?.changed, true);
  const setItem = requireJsonObject(
    setResult?.item,
    "set-read result has no item",
  );
  assert(
    new Date(requireString(setItem.readAt, "set-read timestamp is invalid")) >=
      futureOccurredAt,
  );
  const replayedSet = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.set_notification_inbox_read_state_v1(
        ${transaction.json(setRequest)}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert.equal(replayedSet?.replayed, true);

  const noopRequest = {
    ...setRequest,
    expectedRevision: 2,
    keyDigest: hexDigest("set-read-noop-key"),
    requestDigest: hexDigest("set-read-noop-request"),
  };
  const noop = await asApi(ids.tenant, ids.operator, async (transaction) => {
    const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.set_notification_inbox_read_state_v1(
        ${transaction.json(noopRequest)}::jsonb
      ) AS result
    `;
    return row?.result;
  });
  assert.equal(noop?.changed, false);
  await rejects(
    asApi(
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
      SELECT app.set_notification_inbox_read_state_v1(
        ${transaction.json({ ...setRequest, read: false, keyDigest: hexDigest("stale-key"), requestDigest: hexDigest("stale-request") })}::jsonb
      )
    `,
    ),
    "40001",
    "stale item revision was accepted",
  );

  const beforeMark = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.count_notification_inbox_unread_v1(
        ${transaction.json({ schemaVersion: 1, tenantId: ids.tenant, userId: ids.operator, sessionId: ids.operatorSession })}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert(beforeMark);
  const markRequest = {
    schemaVersion: 1,
    tenantId: ids.tenant,
    userId: ids.operator,
    sessionId: ids.operatorSession,
    expectedRevision: Number(beforeMark.inboxRevision),
    operation: "notification_inbox.mark_all_read",
    keyDigest: hexDigest("mark-all-key"),
    requestDigest: hexDigest("mark-all-request"),
    audit: audit("mark-all"),
  };
  const markResult = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.mark_all_notification_inbox_read_v1(
        ${transaction.json(markRequest)}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert.equal(markResult?.changed, true);
  assert(Number(markResult?.affected) > 0);
  const markReplay = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.mark_all_notification_inbox_read_v1(
        ${transaction.json(markRequest)}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert.equal(markReplay?.replayed, true);
  const markNoop = await asApi(
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
      SELECT app.mark_all_notification_inbox_read_v1(
        ${transaction.json({ ...markRequest, expectedRevision: Number(markResult?.inboxRevision), keyDigest: hexDigest("mark-noop-key"), requestDigest: hexDigest("mark-noop-request") })}::jsonb
      ) AS result
    `;
      return row?.result;
    },
  );
  assert.equal(markNoop?.changed, false);
  assert.equal(markNoop?.affected, 0);

  const auditRows = await database<Array<{ serialized: string }>>`
    SELECT concat_ws('|',action,resource_type,before::text,after::text,metadata::text) AS serialized
    FROM public.audit_events
    WHERE tenant_id=${ids.tenant}::uuid
      AND action IN ('notification_inbox.read_state_set','notification_inbox.marked_all_read')
    ORDER BY sequence
  `;
  assert.equal(auditRows.length, 2);
  const serializedAudit = auditRows.map((row) => row.serialized).join("|");
  for (const forbidden of [
    operatorEmail,
    customerEmail,
    "Alert created",
    hexDigest("set-read-key"),
  ]) {
    assert(!serializedAudit.includes(forbidden), `audit leaked ${forbidden}`);
  }

  await database`
    INSERT INTO public.customer_contacts(
      id,tenant_id,first_name,last_name,email,function,language,timezone,
      contact_class,notification_categories,email_allowed,active,
      linked_membership_id,linked_user_id
    ) VALUES (
      ${ids.transitionContact}::uuid,${ids.tenant}::uuid,'Transition','Customer',
      ${operatorEmail},'customer','en','UTC','standard',ARRAY[]::text[],true,true,
      ${ids.operatorMembership}::uuid,${ids.operator}::uuid
    )
  `;
  await rejects(
    asApi(
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
      SELECT app.list_notification_inbox_v1(
        ${transaction.json(listRequest(ids.operatorSession, null))}::jsonb
      )
    `,
    ),
    "42501",
    "dual customer and operator evidence was accepted",
  );
  await rejects(
    asApi(
      ids.tenant,
      ids.operator,
      (transaction) => transaction`
      SELECT app.set_notification_inbox_read_state_v1(
        ${transaction.json(setRequest)}::jsonb
      )
    `,
    ),
    "42501",
    "an operator command replay leaked data after a customer transition",
  );

  const customerAccess = await asApi(
    ids.tenant,
    ids.customer,
    async (transaction) => {
      const [row] = await transaction<{ result: JsonObject }[]>`
        SELECT app.resolve_notification_inbox_access_v1(
          ${ids.customerSession}::uuid
        ) AS result
      `;
      return row?.result;
    },
  );
  assert.equal(customerAccess?.principal, "customer");
  await database`
    UPDATE public.customer_contacts
    SET active=false,archived_at=transaction_timestamp(),
        updated_at=transaction_timestamp()
    WHERE tenant_id=${ids.tenant}::uuid AND id=${ids.linkedContact}::uuid
  `;
  await rejects(
    asApi(
      ids.tenant,
      ids.customer,
      (transaction) => transaction`
      SELECT app.resolve_notification_inbox_access_v1(
        ${ids.customerSession}::uuid
      )
    `,
    ),
    "42501",
    "an archived customer contact was reclassified as operator",
  );

  const ownerVisible = await asRole(
    "periapsis_notification_inbox_owner",
    ids.tenant,
    ids.operator,
    async (transaction) => {
      const [row] = await transaction<{ count: string }[]>`
        SELECT count(*)::text AS count
        FROM public.tenant_notification_inbox_items
      `;
      return row?.count;
    },
  );
  assert(Number(ownerVisible) > 0);
  const ownerForeign = await asRole(
    "periapsis_notification_inbox_owner",
    ids.foreignTenant,
    ids.foreignUser,
    async (transaction) => {
      const [row] = await transaction<{ count: string }[]>`
        SELECT count(*)::text AS count
        FROM public.tenant_notification_inbox_items
      `;
      return row?.count;
    },
  );
  assert.equal(ownerForeign, "0");
}

try {
  await run();
  process.stdout.write("notification inbox runtime security proof passed\n");
} finally {
  await database.end();
}
