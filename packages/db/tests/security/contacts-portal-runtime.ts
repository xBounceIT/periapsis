import assert from "node:assert/strict";

import postgres from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_CONTACTS_PORTAL_SECURITY_TEST_DATABASE_URL;
const notifierDatabaseUrl =
  process.env.PERIAPSIS_CONTACTS_PORTAL_SECURITY_NOTIFIER_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_CONTACTS_PORTAL_SECURITY_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}
if (notifierDatabaseUrl === undefined || notifierDatabaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_CONTACTS_PORTAL_SECURITY_NOTIFIER_DATABASE_URL must authenticate as the exact least-privileged periapsis_notifier_login role",
  );
}

const fixture = {
  tenant: "01a10700-1000-7000-8000-000000000001",
  foreignTenant: "01a10700-1000-7000-8000-000000000002",
  customerUser: "01a10700-1000-7000-8000-000000000101",
  secondUser: "01a10700-1000-7000-8000-000000000102",
  foreignUser: "01a10700-1000-7000-8000-000000000103",
  customerMembership: "01a10700-1000-7000-8000-000000000201",
  secondMembership: "01a10700-1000-7000-8000-000000000202",
  foreignMembership: "01a10700-1000-7000-8000-000000000203",
  contact: "01a10700-1000-7000-8000-000000000301",
  foreignContact: "01a10700-1000-7000-8000-000000000302",
  crossTenantContact: "01a10700-1000-7000-8000-000000000303",
  mismatchedIdentityContact: "01a10700-1000-7000-8000-000000000304",
  apiWriteContact: "01a10700-1000-7000-8000-000000000305",
  customerRosterUser: "01a10700-1000-7000-8000-000000000104",
  portalOnlyUser: "01a10700-1000-7000-8000-000000000105",
  readOnlyOperatorUser: "01a10700-1000-7000-8000-000000000106",
  revokedOperatorUser: "01a10700-1000-7000-8000-000000000107",
  adminUser: "01a10700-1000-7000-8000-000000000108",
  revokedCustomerUser: "01a10700-1000-7000-8000-000000000109",
  customerRosterMembership: "01a10700-1000-7000-8000-000000000204",
  portalOnlyMembership: "01a10700-1000-7000-8000-000000000205",
  readOnlyOperatorMembership: "01a10700-1000-7000-8000-000000000206",
  revokedOperatorMembership: "01a10700-1000-7000-8000-000000000207",
  adminMembership: "01a10700-1000-7000-8000-000000000208",
  revokedCustomerMembership: "01a10700-1000-7000-8000-000000000209",
  customerRosterContact: "01a10700-1000-7000-8000-000000000306",
  replayContact: "01a10700-1000-7000-8000-000000000307",
  unlinkedRecipientContact: "01a10700-1000-7000-8000-000000000308",
  revokedRecipientContact: "01a10700-1000-7000-8000-000000000309",
  inactiveRecipientContact: "01a10700-1000-7000-8000-00000000030a",
  deniedRecipientContact: "01a10700-1000-7000-8000-00000000030b",
  categoryRecipientContact: "01a10700-1000-7000-8000-00000000030c",
  windowRecipientContact: "01a10700-1000-7000-8000-00000000030d",
  partialLinkContact: "01a10700-1000-7000-8000-00000000030e",
  portalOnlyRole: "01a10700-1000-7000-8000-000000000401",
  teamReaderRole: "01a10700-1000-7000-8000-000000000402",
  tenantReaderRole: "01a10700-1000-7000-8000-000000000403",
  customerRoleGrant: "01a10700-1000-7000-8000-000000000501",
  customerRosterRoleGrant: "01a10700-1000-7000-8000-000000000502",
  portalOnlyRoleGrant: "01a10700-1000-7000-8000-000000000503",
  teamReaderRoleGrant: "01a10700-1000-7000-8000-000000000504",
  revokedRoleGrant: "01a10700-1000-7000-8000-000000000505",
  operatorTeam: "01a10700-1000-7000-8000-000000000601",
  operatorTeamEpoch: "01a10700-1000-7000-8000-000000000602",
  customerRosterEntry: "01a10700-1000-7000-8000-000000000603",
  readOnlyOperatorRosterEntry: "01a10700-1000-7000-8000-000000000604",
  alertCustomerRoster: "01a10700-1000-7000-8000-000000000701",
  alertPortalOnly: "01a10700-1000-7000-8000-000000000702",
  alertRevokedOperator: "01a10700-1000-7000-8000-000000000703",
  alertCustomerComment: "01a10700-1000-7000-8000-000000000704",
  alertRecipientFanout: "01a10700-1000-7000-8000-000000000705",
  customerRosterLink: "01a10700-1000-7000-8000-000000000801",
  customerCommentLink: "01a10700-1000-7000-8000-000000000802",
  liveRecipientLink: "01a10700-1000-7000-8000-000000000803",
  unlinkedRecipientLink: "01a10700-1000-7000-8000-000000000804",
  revokedRecipientLink: "01a10700-1000-7000-8000-000000000805",
  inactiveRecipientLink: "01a10700-1000-7000-8000-000000000806",
  deniedRecipientLink: "01a10700-1000-7000-8000-000000000807",
  categoryRecipientLink: "01a10700-1000-7000-8000-000000000808",
  windowRecipientLink: "01a10700-1000-7000-8000-000000000809",
  crossTenantRecipientLink: "01a10700-1000-7000-8000-00000000080a",
  eventCustomerRoster: "01a10700-1000-7000-8000-000000000901",
  eventPortalOnly: "01a10700-1000-7000-8000-000000000902",
  eventRevokedOperator: "01a10700-1000-7000-8000-000000000903",
  eventCustomerComment: "01a10700-1000-7000-8000-000000000904",
  eventServiceActor: "01a10700-1000-7000-8000-000000000905",
  eventRecipientFanout: "01a10700-1000-7000-8000-000000000906",
  eventRecipientOperatorOnly: "01a10700-1000-7000-8000-000000000907",
  replayRequest1: "01a10700-1000-7000-8000-000000000a01",
  replayRequest2: "01a10700-1000-7000-8000-000000000a02",
  replayRequest3: "01a10700-1000-7000-8000-000000000a03",
  replayRequest4: "01a10700-1000-7000-8000-000000000a04",
  replayRequest5: "01a10700-1000-7000-8000-000000000a05",
  replayCorrelation: "01a10700-1000-7000-8000-000000000a10",
  manualRecipientGroup: "01a10700-1000-7000-8000-000000000b01",
  dynamicRecipientGroup: "01a10700-1000-7000-8000-000000000b02",
  customerSession: "01a10700-1000-7000-8000-000000000c01",
  portalStorage: "01a10700-1000-7000-8000-000000000c02",
  portalAttachment: "01a10700-1000-7000-8000-000000000c03",
  portalDownloadEventA: "01a10700-1000-7000-8000-000000000c04",
  portalDownloadEventB: "01a10700-1000-7000-8000-000000000c05",
  portalDownloadRequestA: "01a10700-1000-7000-8000-000000000c06",
  portalDownloadRequestB: "01a10700-1000-7000-8000-000000000c07",
  portalDownloadCorrelation: "01a10700-1000-7000-8000-000000000c08",
  customerRotation: "01a10700-1000-7000-8000-000000000c09",
  portalCase: "01a10700-1000-7000-8000-000000000d01",
  portalCaseStorage: "01a10700-1000-7000-8000-000000000d02",
  portalCaseAttachment: "01a10700-1000-7000-8000-000000000d03",
  portalCaseDownloadEventA: "01a10700-1000-7000-8000-000000000d04",
  portalCaseDownloadEventB: "01a10700-1000-7000-8000-000000000d05",
  portalCaseDownloadRequestA: "01a10700-1000-7000-8000-000000000d06",
  portalCaseDownloadRequestB: "01a10700-1000-7000-8000-000000000d07",
  portalCaseContactLink: "01a10700-1000-7000-8000-000000000d08",
  otherPortalCase: "01a10700-1000-7000-8000-000000000d09",
  otherPortalCaseContactLink: "01a10700-1000-7000-8000-000000000d0a",
} as const;

const portalDownloadTargets = [
  {
    kind: "alert",
    rootId: fixture.alertCustomerComment,
    otherRootId: fixture.alertRecipientFanout,
    contactLinkId: fixture.customerCommentLink,
    attachmentId: fixture.portalAttachment,
    storageId: fixture.portalStorage,
    eventIds: [fixture.portalDownloadEventA, fixture.portalDownloadEventB],
    requestIds: [
      fixture.portalDownloadRequestA,
      fixture.portalDownloadRequestB,
    ],
    deniedIdBase: 0xc10,
  },
  {
    kind: "case",
    rootId: fixture.portalCase,
    otherRootId: fixture.otherPortalCase,
    contactLinkId: fixture.portalCaseContactLink,
    attachmentId: fixture.portalCaseAttachment,
    storageId: fixture.portalCaseStorage,
    eventIds: [
      fixture.portalCaseDownloadEventA,
      fixture.portalCaseDownloadEventB,
    ],
    requestIds: [
      fixture.portalCaseDownloadRequestA,
      fixture.portalCaseDownloadRequestB,
    ],
    deniedIdBase: 0xd10,
  },
] as const;
type PortalDownloadTarget = (typeof portalDownloadTargets)[number];

const protectedRelations = [
  "customer_contacts",
  "customer_contact_notification_windows",
  "customer_contact_groups",
  "customer_contact_group_versions",
  "customer_contact_group_version_members",
  "ticket_customer_contacts",
  "ticket_comment_author_snapshots",
  "ticket_activity_author_snapshots",
  "customer_contact_commands",
] as const;

const sql = postgres(databaseUrl, { max: 3, onnotice: () => undefined });
const notifier = postgres(notifierDatabaseUrl, {
  max: 2,
  onnotice: () => undefined,
});

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

async function setApiContext(
  transaction: postgres.TransactionSql,
  userId: string,
  tenantId: string,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantId}, true),
           set_config('app.user_id', ${userId}, true)
  `;
}

type ContactCommandResult = {
  contact_id: string;
  replayed: boolean;
  version: number;
};

type ContactPayload = { readonly [key: string]: postgres.JSONValue };

async function commitContact(input: {
  contactId: string;
  expectedVersion: number;
  keyDigest: Buffer;
  membershipId: string;
  operation:
    | "contact.archive"
    | "contact.create"
    | "contact.replace"
    | "portal.preference.replace";
  payload: ContactPayload;
  reason?: string;
  requestDigest: Buffer;
  requestId: string;
  userId: string;
}): Promise<ContactCommandResult> {
  return sql.begin(async (transaction) => {
    await setApiContext(transaction, input.userId, fixture.tenant);
    const [result] = await transaction<ContactCommandResult[]>`
      SELECT contact_id::text, version, replayed
      FROM app.commit_customer_contact_v1(
        ${input.operation}, ${input.contactId}::uuid,
        ${input.expectedVersion}::bigint, ${sql.json(input.payload)}::jsonb,
        ${input.keyDigest}, ${input.requestDigest}, ${input.reason ?? ""},
        ${input.requestId}::uuid, ${fixture.replayCorrelation}::uuid,
        ${input.membershipId}::uuid, '192.0.2.42'::inet,
        'contacts-portal-runtime', 'totp'
      )
    `;
    assert(result, "contact commit returned no result");
    return result;
  });
}

async function replayContact(input: {
  contactId?: string;
  keyDigest: Buffer;
  operation: "contact.create" | "portal.preference.replace";
  requestDigest: Buffer;
  userId: string;
}): Promise<{
  projection: string;
  resource: Record<string, unknown>;
  resource_id: string;
  version: number;
}> {
  return sql.begin(async (transaction) => {
    await setApiContext(transaction, input.userId, fixture.tenant);
    const [result] = await transaction<
      {
        projection: string;
        resource: Record<string, unknown>;
        resource_id: string;
        version: number;
      }[]
    >`
      SELECT resource_id::text, version, projection, resource
      FROM app.replay_customer_contact_command_v1(
        ${input.operation}, ${input.keyDigest}, ${input.requestDigest},
        ${input.contactId ?? null}::uuid,
        NULL::public.ticket_aggregate_kind, NULL::uuid
      )
    `;
    assert(result, "contact replay returned no result");
    return result;
  });
}

async function functionDefinition(signature: string): Promise<string> {
  const [row] = await sql<{ definition: string }[]>`
    SELECT pg_catalog.pg_get_functiondef(procedure.oid) AS definition
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = pg_catalog.to_regprocedure(${signature})
  `;
  assert(row, `missing required function ${signature}`);
  return row.definition;
}

type FanoutCandidate = {
  audience: "customer" | "operator";
  email: string;
  kinds: string[];
  principalId?: string;
  values?: Record<string, string[]>;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isStringArrayRecord(
  value: unknown,
): value is Record<string, string[]> {
  return (
    isRecord(value) &&
    Object.values(value).every(
      (items) =>
        Array.isArray(items) &&
        items.every((item: unknown) => typeof item === "string"),
    )
  );
}

function fanoutCandidates(value: unknown): FanoutCandidate[] {
  assert(isRecord(value), "fanout inputs must be an object");
  const candidates = value["candidates"];
  assert(Array.isArray(candidates), "fanout inputs omitted candidates");
  return candidates.map((candidate): FanoutCandidate => {
    assert(isRecord(candidate), "fanout candidate must be an object");
    const audience = candidate["audience"];
    assert(
      audience === "customer" || audience === "operator",
      "fanout candidate has an invalid audience",
    );
    const email = candidate["email"];
    assert(typeof email === "string", "fanout candidate has an invalid email");
    const kinds = candidate["kinds"];
    assert(
      Array.isArray(kinds) &&
        kinds.every(
          (kind: unknown): kind is string => typeof kind === "string",
        ),
      "fanout candidate has invalid kinds",
    );
    const principalId = candidate["principalId"];
    assert(
      principalId === undefined || typeof principalId === "string",
      "fanout candidate has an invalid principal",
    );
    const values = candidate["values"];
    assert(
      values === undefined || isStringArrayRecord(values),
      "fanout candidate has invalid selector values",
    );
    const selectorValues =
      values !== undefined && Object.keys(values).length > 0
        ? values
        : undefined;
    return {
      audience,
      email,
      kinds,
      ...(principalId === undefined ? {} : { principalId }),
      ...(selectorValues === undefined ? {} : { values: selectorValues }),
    };
  });
}

async function loadClaimedFanout(eventId: string): Promise<FanoutCandidate[]> {
  const [claim] = await notifier.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return transaction<{ claim: Record<string, unknown> }[]>`
      SELECT claim
      FROM app.claim_notification_fanout_batch_v1(
        ${`contacts-portal-${eventId}`}, 1, 5000,
        transaction_timestamp()
      )
    `;
  });
  assert.equal(claim?.claim.id, eventId, "claimed the wrong fanout event");
  const fenceToken = claim.claim.fenceToken;
  assert.equal(typeof fenceToken, "string", "fanout claim omitted its fence");

  const [loaded] = await notifier.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    return transaction<{ inputs: unknown }[]>`
      SELECT app.load_notification_fanout_inputs_v3(
        ${eventId}::uuid, ${String(fenceToken)}::uuid
      ) AS inputs
    `;
  });
  assert(loaded, "fanout loader returned no inputs");

  await notifier.begin(async (transaction) => {
    await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
    await transaction`
      SELECT app.dead_letter_notification_fanout_v1(
        ${eventId}::uuid, ${String(fenceToken)}::uuid,
        'security', transaction_timestamp()
      )
    `;
  });
  return fanoutCandidates(loaded.inputs);
}

function candidatesFor(
  candidates: readonly FanoutCandidate[],
  email: string,
): FanoutCandidate[] {
  return candidates.filter((candidate) => candidate.email === email);
}

async function enqueueTicketNotification(input: {
  actorId?: string;
  actorKind: "human" | "service_account" | "system";
  alertId: string;
  customerAudience: boolean;
  eventId: string;
  eventType?: "comment.private_added" | "comment.public_added";
  occurredAt: Date;
  routing?: Record<string, string>;
}): Promise<void> {
  const eventType = input.eventType ?? "comment.public_added";
  const operatorContext = {
    action: "commented",
    actor: input.actorId === undefined ? undefined : { id: input.actorId },
    alert: { id: input.alertId, version: 1 },
    metadata: { content_redacted: true },
    routing: input.routing ?? {},
  };
  const payload = input.customerAudience
    ? {
        customerContext: {
          alert: { id: input.alertId, version: 1 },
          comment: { id: input.eventId, visibility: "public" },
        },
        operatorContext,
      }
    : { operatorContext };
  await sql`
    INSERT INTO public.outbox_events (
      id, tenant_id, aggregate_type, aggregate_id, aggregate_version,
      event_type, schema_version, payload, deduplication_key,
      actor_kind, actor_id, producer, maximum_audience,
      occurred_at, available_at, created_at
    ) VALUES (
      ${input.eventId}::uuid, ${fixture.tenant}::uuid, 'alert',
      ${input.alertId}::uuid, 1, ${`notification.${eventType}`}, 2,
      ${sql.json(payload)}::jsonb, ${`contacts-portal-${input.eventId}`},
      ${input.actorKind}::public.ticket_principal_kind,
      ${input.actorId ?? null}::uuid, 'contacts.portal.security',
      ${input.customerAudience ? "customer" : "operator"}::public.notification_audience,
      ${input.occurredAt}, ${input.occurredAt}, ${input.occurredAt}
    )
  `;
}

type PortalDownloadAuditInput = {
  target: PortalDownloadTarget;
  attachmentId?: string;
  attachmentState?: "available" | "quarantined";
  attachmentVersion?: number;
  eventId: string;
  expiresAt: Date;
  portalContactId?: string;
  requestId: string;
  rootId?: string;
  rootVersion?: number;
  storageState?: "available" | "quarantined";
  storageId?: string;
  storageVersion?: number;
};

async function callPortalDownloadAudit(
  transaction: postgres.TransactionSql,
  input: PortalDownloadAuditInput,
): Promise<string> {
  const [row] = await transaction<{ event_id: string }[]>`
    SELECT app.append_dfir_download_grant_audit_v1(
      ${input.eventId}::uuid, 'customer', ${fixture.customerSession}::uuid,
      ${fixture.customerMembership}::uuid,
      ${input.target.kind}::public.ticket_aggregate_kind,
      ${input.rootId ?? input.target.rootId}::uuid,
      ${input.rootVersion ?? 1}::bigint,
      ${input.target.kind}::public.dfir_entity_kind,
      ${input.target.rootId}::uuid,
      ${input.attachmentId ?? input.target.attachmentId}::uuid,
      ${input.attachmentVersion ?? 1}::bigint,
      ${input.storageId ?? input.target.storageId}::uuid,
      ${input.storageVersion ?? 1}::bigint,
      ${input.attachmentState ?? "available"}::public.dfir_scan_state,
      ${input.storageState ?? "available"}::public.dfir_scan_state,
      'customer', 'own'::public.authorization_scope,
      ${input.portalContactId ?? fixture.contact}::uuid,
      ${input.expiresAt}::timestamptz, ${input.requestId}::uuid,
      ${fixture.portalDownloadCorrelation}::uuid, '192.0.2.91'::inet,
      'contacts-portal-download-runtime', 'totp'
    )::text AS event_id
  `;
  assert(row, "portal download audit returned no event identifier");
  return row.event_id;
}

async function appendPortalDownloadAudit(
  input: PortalDownloadAuditInput,
): Promise<string> {
  return sql.begin(async (transaction) => {
    await setApiContext(transaction, fixture.customerUser, fixture.tenant);
    return callPortalDownloadAudit(transaction, input);
  });
}

async function portalDownloadState(): Promise<
  Record<string, postgres.JSONValue>
> {
  const relations = [
    "audit_events",
    "audit_chain_heads",
    "alerts",
    "cases",
    "dfir_attachments",
    "dfir_storage_objects",
    "customer_contacts",
    "ticket_customer_contacts",
    "tenant_memberships",
  ] as const;
  return Object.fromEntries(
    await Promise.all(
      relations.map(async (relation) => {
        const [row] = await sql.unsafe<{ rows: postgres.JSONValue }[]>(
          `SELECT coalesce(jsonb_agg(to_jsonb(row) ORDER BY to_jsonb(row)::text), '[]'::jsonb) AS rows
       FROM public.${relation} AS row WHERE tenant_id = $1::uuid`,
          [fixture.tenant],
        );
        assert(row);
        return [relation, row.rows] as const;
      }),
    ),
  );
}

async function verifyPortalDownloadGrantAuditing(
  target: PortalDownloadTarget,
): Promise<void> {
  const expiresAt = new Date(Date.now() + 4 * 60_000);
  const first = {
    target,
    eventId: target.eventIds[0],
    expiresAt,
    requestId: target.requestIds[0],
  };
  const second = {
    target,
    eventId: target.eventIds[1],
    expiresAt,
    requestId: target.requestIds[1],
  };
  assert.equal(await appendPortalDownloadAudit(first), target.eventIds[0]);
  assert.equal(await appendPortalDownloadAudit(second), target.eventIds[1]);

  const auditRows = await sql<
    {
      action: string;
      actor_user_id: string;
      after: postgres.JSONValue | null;
      authentication_method: string;
      before: postgres.JSONValue | null;
      correlation_id: string;
      event_json: postgres.JSONValue;
      id: string;
      ip_address: string;
      metadata: Record<string, unknown>;
      request_id: string;
      resource_id: string;
      resource_type: string;
      user_agent: string;
    }[]
  >`
    SELECT event.id::text, event.action, event.resource_type,
           event.resource_id::text, event.actor_user_id::text,
           event.request_id::text, event.correlation_id::text,
           event.ip_address::text, event.user_agent,
           event.authentication_method, event.before, event.after,
           event.metadata, to_jsonb(event) AS event_json
    FROM public.audit_events AS event
    WHERE event.id = ANY(
      ${[...target.eventIds]}::uuid[]
    )
    ORDER BY event.id
  `;
  assert.equal(auditRows.length, 2);
  const requests = new Map<string, string>([
    [target.eventIds[0], target.requestIds[0]],
    [target.eventIds[1], target.requestIds[1]],
  ]);
  for (const row of auditRows) {
    assert.equal(row.action, "dfir.portal.attachment.download_grant_issued");
    assert.equal(row.resource_type, "dfir_attachment");
    assert.equal(row.resource_id, target.attachmentId);
    assert.equal(row.actor_user_id, fixture.customerUser);
    assert.equal(row.request_id, requests.get(row.id));
    assert.equal(row.correlation_id, fixture.portalDownloadCorrelation);
    assert.equal(row.ip_address, "192.0.2.91/32");
    assert.equal(row.user_agent, "contacts-portal-download-runtime");
    assert.equal(row.authentication_method, "totp");
    assert.equal(row.before, null);
    assert.equal(row.after, null);
    assert.deepEqual(Object.keys(row.metadata).toSorted(), [
      "actorMembershipId",
      "actorSessionId",
      "actorUserId",
      "attachmentId",
      "audience",
      "expiresAt",
      "rootId",
      "rootKind",
      "storageObjectId",
      "tenantId",
    ]);
    assert.equal(row.metadata["tenantId"], fixture.tenant);
    assert.equal(row.metadata["actorUserId"], fixture.customerUser);
    assert.equal(row.metadata["actorSessionId"], fixture.customerSession);
    assert.equal(row.metadata["actorMembershipId"], fixture.customerMembership);
    assert.equal(row.metadata["rootKind"], target.kind);
    assert.equal(row.metadata["rootId"], target.rootId);
    assert.equal(row.metadata["attachmentId"], target.attachmentId);
    assert.equal(row.metadata["storageObjectId"], target.storageId);
    assert.equal(row.metadata["audience"], "customer");
    assert.equal(
      new Date(String(row.metadata["expiresAt"])).getTime(),
      expiresAt.getTime(),
    );
    assert.doesNotMatch(
      JSON.stringify(row.event_json),
      /must-never-leak|x-amz-(?:credential|signature)|sha256/iu,
    );
  }

  let deniedId = target.deniedIdBase;
  async function assertDenied(
    label: string,
    expected: string,
    input: Partial<PortalDownloadAuditInput> = {},
    mutate?: (transaction: postgres.TransactionSql) => Promise<unknown>,
  ): Promise<void> {
    const before = await portalDownloadState();
    const eventId = `01a10700-1000-7000-8000-${(deniedId++).toString(16).padStart(12, "0")}`;
    const requestId = `01a10700-1000-7000-8000-${(deniedId++).toString(16).padStart(12, "0")}`;
    let calledAudit = false;
    await assert.rejects(
      sql.begin(async (transaction) => {
        await mutate?.(transaction);
        await setApiContext(transaction, fixture.customerUser, fixture.tenant);
        calledAudit = true;
        return callPortalDownloadAudit(transaction, {
          target,
          eventId,
          expiresAt,
          requestId,
          ...input,
        });
      }),
      (error: unknown) => {
        assert(
          calledAudit,
          new Error(`${target.kind}: ${label} failed during fixture setup`, {
            cause: error,
          }),
        );
        return assertSqlState(error, expected);
      },
      `${target.kind}: ${label} emitted a grant audit`,
    );
    assert.deepEqual(
      await portalDownloadState(),
      before,
      `${target.kind}: ${label} changed state despite denial`,
    );
  }

  await assertDenied("foreign contact", "42501", {
    portalContactId: fixture.foreignContact,
  });
  await assertDenied("non-linked same-tenant contact", "42501", {
    portalContactId: fixture.unlinkedRecipientContact,
  });
  await assertDenied("stale root revision", "40001", { rootVersion: 2 });
  await assertDenied("stale attachment revision", "40001", {
    attachmentVersion: 2,
  });
  await assertDenied("stale storage revision", "40001", { storageVersion: 2 });
  // Both roots are visible to this same customer: only the attachment path differs.
  await assertDenied("attachment outside the requested root", "42501", {
    rootId: target.otherRootId,
  });
  const otherTarget = portalDownloadTargets.find(
    (item) => item.kind !== target.kind,
  );
  assert(otherTarget);
  await assertDenied("mismatched attachment", "55000", {
    attachmentId: otherTarget.attachmentId,
  });
  await assertDenied("mismatched storage", "55000", {
    storageId: otherTarget.storageId,
  });
  await assertDenied(
    "suspended customer",
    "42501",
    {},
    (transaction) => transaction`
    UPDATE public.tenant_memberships SET status = 'suspended'
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.customerMembership}::uuid
  `,
  );
  await assertDenied(
    "revoked contact",
    "42501",
    {},
    (transaction) => transaction`
    UPDATE public.customer_contacts SET active = false
    WHERE tenant_id = ${fixture.tenant}::uuid AND id = ${fixture.contact}::uuid
  `,
  );
  await assertDenied(
    "archived root contact link",
    "42501",
    {},
    (transaction) => transaction`
    UPDATE public.ticket_customer_contacts SET archived_at = transaction_timestamp()
    WHERE tenant_id = ${fixture.tenant}::uuid AND id = ${target.contactLinkId}::uuid
  `,
  );
  await assertDenied(
    "storage-state drift",
    "40001",
    {},
    (transaction) => transaction`
    UPDATE public.dfir_storage_objects SET state = 'quarantined'
    WHERE tenant_id = ${fixture.tenant}::uuid AND id = ${target.storageId}::uuid
  `,
  );
  await assertDenied(
    "attachment-state drift",
    "40001",
    {},
    async (transaction) => {
      // Quarantine must keep the storage projection coherent and cannot stay public.
      await transaction`
        UPDATE public.dfir_storage_objects SET state = 'quarantined'
        WHERE tenant_id = ${fixture.tenant}::uuid AND id = ${target.storageId}::uuid
      `;
      await transaction`
        UPDATE public.dfir_attachments SET scan_state = 'quarantined', visibility = 'private'
        WHERE tenant_id = ${fixture.tenant}::uuid AND id = ${target.attachmentId}::uuid
      `;
    },
  );

  const [successfulCount] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND action = 'dfir.portal.attachment.download_grant_issued'
      AND metadata->>'rootKind' = ${target.kind}
      AND metadata->>'rootId' = ${target.rootId}
  `;
  assert.equal(successfulCount?.count, 2);
}

try {
  const relationCatalog = await sql<
    {
      api_delete: boolean;
      api_insert: boolean;
      api_update: boolean;
      force_row_security: boolean;
      owner: string;
      relation_name: string;
      row_security: boolean;
      tenant_not_null: boolean;
    }[]
  >`
    SELECT relation.relname AS relation_name,
           relation.relrowsecurity AS row_security,
           relation.relforcerowsecurity AS force_row_security,
           pg_catalog.pg_get_userbyid(relation.relowner) AS owner,
           tenant_column.attnotnull AS tenant_not_null,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'INSERT'
           ) AS api_insert,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'UPDATE'
           ) AS api_update,
           pg_catalog.has_table_privilege(
             'periapsis_api', relation.oid, 'DELETE'
           ) AS api_delete
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_attribute AS tenant_column
      ON tenant_column.attrelid = relation.oid
     AND tenant_column.attname = 'tenant_id'
     AND NOT tenant_column.attisdropped
    WHERE namespace.nspname = 'public'
      AND relation.relname = ANY(${[...protectedRelations]}::text[])
      AND relation.relkind = 'r'
    ORDER BY relation.relname
  `;
  assert.equal(
    relationCatalog.length,
    protectedRelations.length,
    "the complete contacts/portal relation set must remain catalog-visible",
  );
  for (const relation of relationCatalog) {
    assert.equal(
      relation.owner,
      relation.relation_name === "ticket_comment_author_snapshots"
        ? "periapsis_ticket_runtime_owner"
        : "periapsis_migrator",
      relation.relation_name,
    );
    assert.equal(relation.tenant_not_null, true, relation.relation_name);
    assert.equal(relation.row_security, true, relation.relation_name);
    assert.equal(relation.force_row_security, true, relation.relation_name);
    assert.equal(relation.api_insert, false, relation.relation_name);
    assert.equal(relation.api_update, false, relation.relation_name);
    assert.equal(relation.api_delete, false, relation.relation_name);
  }

  const [permissionCatalog] = await sql<
    { canonical_count: number; legacy_count: number }[]
  >`
    SELECT count(*) FILTER (
             WHERE permission.key IN (
               'contact_group.read', 'contact_group.manage'
             )
           )::integer AS canonical_count,
           count(*) FILTER (
             WHERE permission.key IN (
               'contact.group.read', 'contact.group.manage'
             )
           )::integer AS legacy_count
    FROM public.tenant_permissions AS permission
  `;
  assert.deepEqual(permissionCatalog, {
    canonical_count: 2,
    legacy_count: 0,
  });

  const [permissionGrant] = await sql<
    {
      context_dispatch_owner: boolean;
      context_notifier: boolean;
      dispatch_owner: boolean;
      notifier: boolean;
    }[]
  >`
    SELECT pg_catalog.has_function_privilege(
             'periapsis_notification_dispatch_owner',
             'app.tenant_human_has_exact_permission_v3(uuid,uuid,text,public.authorization_scope)',
             'EXECUTE'
           ) AS dispatch_owner,
           pg_catalog.has_function_privilege(
             'periapsis_notifier',
             'app.tenant_human_has_exact_permission_v3(uuid,uuid,text,public.authorization_scope)',
             'EXECUTE'
           ) AS notifier,
           pg_catalog.has_function_privilege(
             'periapsis_notification_dispatch_owner',
             'app.context_tenant_id()', 'EXECUTE'
           ) AS context_dispatch_owner,
           pg_catalog.has_function_privilege(
             'periapsis_notifier', 'app.context_tenant_id()', 'EXECUTE'
           ) AS context_notifier
  `;
  assert.deepEqual(permissionGrant, {
    context_dispatch_owner: true,
    context_notifier: false,
    dispatch_owner: true,
    notifier: false,
  });

  const groupCommit = await functionDefinition(
    "app.commit_customer_contact_group_v1(text,uuid,bigint,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text)",
  );
  assert.match(groupCommit, /'contact_group\.manage'/u);
  assert.doesNotMatch(groupCommit, /'contact\.group\.manage'/u);
  assert.doesNotMatch(groupCommit, /membership\.role/u);

  const contactCommit = await functionDefinition(
    "app.commit_customer_contact_v1(text,uuid,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)",
  );
  assert.match(contactCommit, /'contact\.manage'/u);
  assert.match(contactCommit, /'portal\.contact\.preference\.manage'/u);
  assert.match(
    contactCommit,
    /locked\.linked_membership_id\s+IS DISTINCT FROM actor_membership/u,
  );
  assert.doesNotMatch(contactCommit, /membership\.role/u);
  assert.doesNotMatch(contactCommit, /actor_is_customer/u);

  const linkCommit = await functionDefinition(
    "app.commit_ticket_customer_contact_v1(text,uuid,bigint,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)",
  );
  assert.match(linkCommit, /'contact\.read'/u);
  assert.match(linkCommit, /private_current_ticket_scope_allows_v1/u);
  assert.doesNotMatch(linkCommit, /membership\.role/u);

  const portalCommentScope = await functionDefinition(
    "app.private_ticket_comment_portal_scope_allows_v1(public.ticket_aggregate_kind,uuid,uuid)",
  );
  assert.match(portalCommentScope, /'portal\.comment\.public'/u);
  assert.match(portalCommentScope, /'portal\.(?:alert|case)\.read'/u);
  assert.match(
    portalCommentScope,
    /contact\.linked_membership_id\s*=\s*actor\.membership_id/u,
  );
  assert.match(
    portalCommentScope,
    /contact\.linked_user_id\s*=\s*actor\.user_id/u,
  );
  assert.match(portalCommentScope, /link\.contact_id\s*=\s*contact\.id/u);
  assert.match(portalCommentScope, /ticket_workflow_versions/u);
  assert.match(
    portalCommentScope,
    /state\.value\s*->>\s*'visibility'\s*=\s*'customer'/u,
  );
  assert.match(
    portalCommentScope,
    /membership\.role\s+IN\s*\(\s*'customer_manager',\s*'customer_user',\s*'read_only'/u,
  );

  const commitPrivileges = await sql<
    {
      api_execute: boolean;
      function_name: string;
      notifier_execute: boolean;
      owner: string;
      public_execute: boolean;
    }[]
  >`
    SELECT procedure.proname AS function_name,
           pg_catalog.pg_get_userbyid(procedure.proowner) AS owner,
           pg_catalog.has_function_privilege(
             'periapsis_api', procedure.oid, 'EXECUTE'
           ) AS api_execute,
           pg_catalog.has_function_privilege(
             'periapsis_notifier', procedure.oid, 'EXECUTE'
           ) AS notifier_execute,
           EXISTS (
             SELECT 1
             FROM pg_catalog.aclexplode(coalesce(
               procedure.proacl,
               pg_catalog.acldefault('f', procedure.proowner)
             )) AS privilege
             WHERE privilege.grantee = 0
               AND privilege.privilege_type = 'EXECUTE'
           ) AS public_execute
    FROM pg_catalog.pg_proc AS procedure
    WHERE procedure.oid = ANY(ARRAY[
      'app.commit_customer_contact_v1(text,uuid,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)'::regprocedure,
      'app.commit_customer_contact_group_v1(text,uuid,bigint,jsonb,bytea,bytea,uuid,uuid,uuid,inet,text,text)'::regprocedure,
      'app.commit_ticket_customer_contact_v1(text,uuid,bigint,bigint,jsonb,bytea,bytea,text,uuid,uuid,uuid,inet,text,text)'::regprocedure,
      'app.create_customer_portal_ticket_comment_v2(public.ticket_aggregate_kind,uuid,uuid,text,text,uuid[],bytea,bytea,uuid,uuid,inet,text,text)'::regprocedure
    ]::oid[])
    ORDER BY procedure.proname
  `;
  assert.equal(commitPrivileges.length, 4);
  for (const privilege of commitPrivileges) {
    assert.equal(
      privilege.owner,
      "periapsis_migrator",
      privilege.function_name,
    );
    assert.equal(privilege.api_execute, true, privilege.function_name);
    assert.equal(privilege.notifier_execute, false, privilege.function_name);
    assert.equal(privilege.public_execute, false, privilege.function_name);
  }

  const readiness = await functionDefinition(
    "app.private_contacts_portal_schema_readiness_v2()",
  );
  assert.match(readiness, /'contact_group\.read'/u);
  assert.match(readiness, /'contact_group\.manage'/u);
  assert.match(
    readiness,
    /WHERE permission\.key IN \('contact\.group\.read', 'contact\.group\.manage'\)/u,
  );

  const ticketSideEffects = await functionDefinition(
    "app.private_append_ticket_side_effects_v1(public.ticket_aggregate_kind,uuid,text,integer,text[],uuid,uuid,inet,text,text,jsonb,jsonb,jsonb)",
  );
  assert.match(ticketSideEffects, /ticket_workflow_versions/u);
  assert.match(
    ticketSideEffects,
    /state\.value\s*->>\s*'visibility'\s*=\s*'customer'/u,
  );
  assert.match(
    ticketSideEffects,
    /notification_type\s*=\s*'comment\.public_added'/u,
  );

  const notificationAppend = await functionDefinition(
    "app.private_append_tenant_notification_event_v3(uuid,public.notification_event_type,public.notification_object_type,uuid,integer,timestamp with time zone,public.ticket_principal_kind,uuid,text,public.notification_audience,jsonb,jsonb,text,uuid,uuid,text,text)",
  );
  assert.match(
    notificationAppend,
    /p_event_type\s*=\s*'comment\.private_added'.*p_maximum_audience\s*<>\s*'operator'/su,
  );

  const fanout = await functionDefinition(
    "app.load_notification_fanout_inputs_v3(uuid,uuid)",
  );
  assert.match(fanout, /private_notification_operator_candidates_v2/u);
  assert.doesNotMatch(
    fanout,
    /membership\.role\s+IN\s*\(\s*'customer_manager'/u,
  );
  assert.match(fanout, /ticket_customer_contacts/u);
  assert.match(fanout, /link\.contact_id\s*=\s*contact\.id/u);

  const operatorCandidates = await functionDefinition(
    "app.private_notification_operator_candidates_v2(uuid,uuid)",
  );
  assert.match(
    operatorCandidates,
    /private_ticket_comment_user_scope_allows_v1/u,
  );
  assert.match(
    operatorCandidates,
    /membership\.role\s+NOT\s+IN\s*\(\s*'customer_manager',\s*'customer_user',\s*'read_only'/u,
  );

  const fanoutCommit = await functionDefinition(
    "app.commit_notification_fanout_v1(uuid,uuid,jsonb,timestamp with time zone)",
  );
  assert.match(
    fanoutCommit,
    /WHEN\s+'customer'\s+THEN\s+source_event\.payload\s*->\s*'customerContext'/u,
  );
  assert.match(
    fanoutCommit,
    /delivery_value\s*->>\s*'audience'\s*=\s*'customer'.*source_event\.maximum_audience\s*<>\s*'customer'/su,
  );
  assert.match(
    fanoutCommit,
    /pinned\.audience\s*=\s*'operator'\s+OR\s+source_event\.maximum_audience\s*=\s*'customer'/u,
  );
  const fanoutCommitV2 = await functionDefinition(
    "app.commit_notification_fanout_v2(uuid,uuid,jsonb,timestamp with time zone)",
  );
  assert.match(fanoutCommitV2, /load_notification_fanout_inputs_v3/u);
  assert.match(
    fanoutCommitV2,
    /delivery_value\s*->\s*'context'\s+IS\s+DISTINCT\s+FROM\s+expected_context/u,
  );
  assert.match(fanoutCommitV2, /commit_notification_fanout_v1/u);

  const [schemaReady] = await sql<{ ready: boolean }[]>`
    SELECT app.private_contacts_portal_schema_readiness_v2() AS ready
  `;
  assert.equal(schemaReady?.ready, true);

  const [existing] = await sql<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenants AS tenant
    WHERE tenant.id IN (
      ${fixture.tenant}::uuid, ${fixture.foreignTenant}::uuid
    ) OR tenant.slug IN (
      'contacts-portal-security-proof',
      'contacts-portal-security-foreign-proof'
    )
  `;
  assert.equal(
    existing?.count,
    0,
    "contacts/portal proof requires a fresh disposable database",
  );

  const authorizationGrantedAt = new Date(Date.now() - 5 * 60_000);
  const occurredAt = new Date(Date.now() - 10_000);
  const eventIsoWeekday =
    occurredAt.getUTCDay() === 0 ? 7 : occurredAt.getUTCDay();
  const excludedIsoWeekday = (eventIsoWeekday % 7) + 1;
  await sql.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      INSERT INTO public.tenants (id, slug, name)
      VALUES
        (${fixture.tenant}::uuid, 'contacts-portal-security-proof',
         'Contacts portal security proof'),
        (${fixture.foreignTenant}::uuid,
         'contacts-portal-security-foreign-proof',
         'Contacts portal foreign proof')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads (tenant_id)
      VALUES (${fixture.tenant}::uuid), (${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users (id, email, display_name)
      VALUES
        (${fixture.customerUser}::uuid,
         'contacts.portal.customer@example.invalid', 'Portal customer'),
        (${fixture.secondUser}::uuid,
         'contacts.portal.second@example.invalid', 'Second identity'),
        (${fixture.foreignUser}::uuid,
         'contacts.portal.foreign@example.invalid', 'Foreign customer'),
        (${fixture.customerRosterUser}::uuid,
         'contacts.portal.roster@example.invalid', 'Roster customer'),
        (${fixture.portalOnlyUser}::uuid,
         'contacts.portal.only@example.invalid', 'Portal-only analyst'),
        (${fixture.readOnlyOperatorUser}::uuid,
         'contacts.readonly.operator@example.invalid', 'Read-only operator'),
        (${fixture.revokedOperatorUser}::uuid,
         'contacts.revoked.operator@example.invalid', 'Revoked operator'),
        (${fixture.adminUser}::uuid,
         'contacts.portal.admin@example.invalid', 'Contacts proof admin'),
        (${fixture.revokedCustomerUser}::uuid,
         'contacts.recipient.revoked@example.invalid', 'Revoked customer')
    `;
    await transaction`
      INSERT INTO public.tenant_memberships (
        id, tenant_id, user_id, role, status
      ) VALUES
        (${fixture.customerMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.customerUser}::uuid, 'customer_user', 'active'),
        (${fixture.secondMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.secondUser}::uuid, 'read_only', 'active'),
        (${fixture.foreignMembership}::uuid, ${fixture.foreignTenant}::uuid,
         ${fixture.foreignUser}::uuid, 'customer_user', 'active'),
        (${fixture.customerRosterMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.customerRosterUser}::uuid, 'customer_user', 'active'),
        (${fixture.portalOnlyMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.portalOnlyUser}::uuid, 'analyst', 'active'),
        (${fixture.readOnlyOperatorMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.readOnlyOperatorUser}::uuid, 'read_only', 'active'),
        (${fixture.revokedOperatorMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.revokedOperatorUser}::uuid, 'analyst', 'active'),
        (${fixture.adminMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid, 'tenant_admin', 'active'),
        (${fixture.revokedCustomerMembership}::uuid, ${fixture.tenant}::uuid,
         ${fixture.revokedCustomerUser}::uuid, 'customer_user', 'active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid, ${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.auth_sessions (
        id, user_id, rotation_family_id, active_tenant_id, token_digest,
        csrf_secret_digest, authentication_method, mfa_satisfied_at,
        last_seen_at, idle_expires_at, absolute_expires_at, created_at
      ) VALUES (
        ${fixture.customerSession}::uuid, ${fixture.customerUser}::uuid,
        ${fixture.customerRotation}::uuid, ${fixture.tenant}::uuid,
        ${Buffer.alloc(32, 0x61)}, ${Buffer.alloc(32, 0x62)}, 'totp',
        date_trunc('milliseconds', transaction_timestamp()) - interval '2 minutes',
        date_trunc('milliseconds', transaction_timestamp()) - interval '1 minute',
        date_trunc('milliseconds', transaction_timestamp()) + interval '1 hour',
        date_trunc('milliseconds', transaction_timestamp()) + interval '8 hours',
        date_trunc('milliseconds', transaction_timestamp()) - interval '10 minutes'
      )
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles (
        tenant_id, membership_id, user_id, display_name, email
      ) VALUES
        (${fixture.tenant}::uuid, ${fixture.customerMembership}::uuid,
         ${fixture.customerUser}::uuid, 'Portal customer',
         'contacts.portal.customer@example.invalid'),
        (${fixture.tenant}::uuid,
         ${fixture.customerRosterMembership}::uuid,
         ${fixture.customerRosterUser}::uuid, 'Roster customer',
         'contacts.portal.roster@example.invalid'),
        (${fixture.tenant}::uuid, ${fixture.portalOnlyMembership}::uuid,
         ${fixture.portalOnlyUser}::uuid, 'Portal-only analyst',
         'contacts.portal.only@example.invalid'),
        (${fixture.tenant}::uuid,
         ${fixture.readOnlyOperatorMembership}::uuid,
         ${fixture.readOnlyOperatorUser}::uuid, 'Read-only operator',
         'contacts.readonly.operator@example.invalid'),
        (${fixture.tenant}::uuid,
         ${fixture.revokedOperatorMembership}::uuid,
         ${fixture.revokedOperatorUser}::uuid, 'Revoked operator',
         'contacts.revoked.operator@example.invalid')
    `;
    await transaction`
      INSERT INTO public.customer_contacts (
        id, tenant_id, first_name, last_name, email, function, language,
        timezone, contact_class, notification_categories,
        linked_membership_id, linked_user_id
      ) VALUES
        (${fixture.contact}::uuid, ${fixture.tenant}::uuid, 'Portal',
         'Customer', 'contacts.portal.customer@example.invalid',
         'customer', 'en', 'UTC', 'standard',
         ARRAY['comment.public_added']::text[],
         ${fixture.customerMembership}::uuid, ${fixture.customerUser}::uuid),
        (${fixture.foreignContact}::uuid, ${fixture.foreignTenant}::uuid,
         'Foreign', 'Customer', 'contacts.portal.foreign@example.invalid',
         'customer', 'en', 'UTC', 'standard', ARRAY[]::text[],
         ${fixture.foreignMembership}::uuid, ${fixture.foreignUser}::uuid),
        (${fixture.customerRosterContact}::uuid, ${fixture.tenant}::uuid,
         'Roster', 'Customer', 'contacts.portal.roster@example.invalid',
         'customer', 'en', 'UTC', 'standard',
         ARRAY['comment.public_added']::text[],
         ${fixture.customerRosterMembership}::uuid,
         ${fixture.customerRosterUser}::uuid)
    `;
    await transaction`
      INSERT INTO public.customer_contacts (
        id, tenant_id, first_name, last_name, email, function, language,
        timezone, contact_class, notification_categories, email_allowed,
        active, tags, linked_membership_id, linked_user_id
      ) VALUES
        (${fixture.unlinkedRecipientContact}::uuid, ${fixture.tenant}::uuid,
         'Unlinked', 'Recipient', 'contacts.recipient.unlinked@example.invalid',
         'customer', 'en', 'UTC', 'standard',
         ARRAY['comment.private_added', 'comment.public_added']::text[],
         true, true,
         ARRAY['priority', 'vip']::text[], NULL, NULL),
        (${fixture.revokedRecipientContact}::uuid, ${fixture.tenant}::uuid,
         'Revoked', 'Recipient', 'contacts.recipient.revoked@example.invalid',
         'customer', 'en', 'UTC', 'standard',
         ARRAY['comment.private_added', 'comment.public_added']::text[],
         true, true, ARRAY[]::text[],
         ${fixture.revokedCustomerMembership}::uuid,
         ${fixture.revokedCustomerUser}::uuid),
        (${fixture.inactiveRecipientContact}::uuid, ${fixture.tenant}::uuid,
         'Inactive', 'Recipient', 'contacts.recipient.inactive@example.invalid',
         'customer', 'en', 'UTC', 'standard',
         ARRAY['comment.public_added']::text[], true, false, ARRAY[]::text[],
         NULL, NULL),
        (${fixture.deniedRecipientContact}::uuid, ${fixture.tenant}::uuid,
         'Denied', 'Recipient', 'contacts.recipient.denied@example.invalid',
         'customer', 'en', 'UTC', 'standard',
         ARRAY['comment.public_added']::text[], false, true, ARRAY[]::text[],
         NULL, NULL),
        (${fixture.categoryRecipientContact}::uuid, ${fixture.tenant}::uuid,
         'Category', 'Recipient', 'contacts.recipient.category@example.invalid',
         'customer', 'en', 'UTC', 'standard', ARRAY['alert.created']::text[],
         true, true, ARRAY[]::text[], NULL, NULL),
        (${fixture.windowRecipientContact}::uuid, ${fixture.tenant}::uuid,
         'Window', 'Recipient', 'contacts.recipient.window@example.invalid',
         'customer', 'en', 'UTC', 'standard',
         ARRAY['comment.public_added']::text[], true, true, ARRAY[]::text[],
         NULL, NULL)
    `;
    await transaction`
      INSERT INTO public.customer_contact_notification_windows (
        tenant_id, contact_id, iso_weekday, start_minute, end_minute
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.windowRecipientContact}::uuid,
        ${excludedIsoWeekday}, 0, 1440
      )
    `;
    await transaction`
      INSERT INTO public.customer_contact_groups (
        id, tenant_id, key, current_version
      ) VALUES
        (${fixture.manualRecipientGroup}::uuid, ${fixture.tenant}::uuid,
         'manual_recipients', 1),
        (${fixture.dynamicRecipientGroup}::uuid, ${fixture.tenant}::uuid,
         'vip_recipients', 1)
    `;
    await transaction`
      INSERT INTO public.customer_contact_group_versions (
        tenant_id, group_id, version, name, mode, rule,
        created_by_membership_id, created_by_user_id
      ) VALUES
        (${fixture.tenant}::uuid, ${fixture.manualRecipientGroup}::uuid, 1,
         'Manual recipients', 'manual', NULL,
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.tenant}::uuid, ${fixture.dynamicRecipientGroup}::uuid, 1,
         'VIP recipients', 'dynamic',
         ${sql.json({
           field: "tag",
           kind: "predicate",
           operator: "contains",
           values: ["vip"],
         })}::jsonb,
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid)
    `;
    await transaction`
      INSERT INTO public.customer_contact_group_version_members (
        tenant_id, group_id, group_version, contact_id
      ) VALUES (
        ${fixture.tenant}::uuid, ${fixture.manualRecipientGroup}::uuid, 1,
        ${fixture.unlinkedRecipientContact}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_roles (
        id, tenant_id, key, display_name, description,
        created_by_membership_id
      ) VALUES
        (${fixture.portalOnlyRole}::uuid, ${fixture.tenant}::uuid,
         'portal_only', 'Portal only', 'Portal permission without operator read.',
         ${fixture.adminMembership}::uuid),
        (${fixture.teamReaderRole}::uuid, ${fixture.tenant}::uuid,
         'team_reader', 'Team reader', 'Exact operator-team ticket reader.',
         ${fixture.adminMembership}::uuid),
        (${fixture.tenantReaderRole}::uuid, ${fixture.tenant}::uuid,
         'tenant_reader', 'Tenant reader', 'Tenant-wide ticket reader.',
         ${fixture.adminMembership}::uuid)
    `;
    await transaction`
      INSERT INTO public.tenant_role_permissions (
        tenant_id, role_id, permission_id, scope, created_by_membership_id
      )
      SELECT ${fixture.tenant}::uuid, policy.role_id::uuid,
             permission.id, policy.scope::public.authorization_scope,
             ${fixture.adminMembership}::uuid
      FROM (VALUES
        (${fixture.portalOnlyRole}, 'portal.alert.read', 'own'),
        (${fixture.teamReaderRole}, 'alert.read', 'operator_team'),
        (${fixture.tenantReaderRole}, 'alert.read', 'tenant')
      ) AS policy(role_id, permission_key, scope)
      JOIN public.tenant_permissions AS permission
        ON permission.key = policy.permission_key
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants (
        id, tenant_id, membership_id, role_id, source_id,
        granted_by_membership_id, grant_reason, granted_at
      )
      SELECT grant_row.id::uuid, ${fixture.tenant}::uuid,
             grant_row.membership_id::uuid, role.id, source.id,
             ${fixture.adminMembership}::uuid,
             'Contacts portal notification authorization proof.',
             ${authorizationGrantedAt}
      FROM (VALUES
        (${fixture.customerRoleGrant}, ${fixture.customerMembership},
         'customer_user'),
        (${fixture.customerRosterRoleGrant},
         ${fixture.customerRosterMembership}, 'customer_user'),
        (${fixture.portalOnlyRoleGrant}, ${fixture.portalOnlyMembership},
         'portal_only'),
        (${fixture.teamReaderRoleGrant},
         ${fixture.readOnlyOperatorMembership}, 'team_reader'),
        (${fixture.revokedRoleGrant}, ${fixture.revokedOperatorMembership},
         'tenant_reader')
      ) AS grant_row(id, membership_id, role_key)
      JOIN public.tenant_roles AS role
        ON role.tenant_id = ${fixture.tenant}::uuid
       AND role.key = grant_row.role_key
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = ${fixture.tenant}::uuid
       AND source.key = 'manual' AND source.kind = 'manual'
       AND source.retired_at IS NULL
    `;
    await transaction`
      INSERT INTO public.operator_teams (
        id, key, display_name, description, created_by_user_id
      ) VALUES (
        ${fixture.operatorTeam}::uuid, 'contacts_proof_team',
        'Contacts proof team', 'Contacts portal fanout proof.',
        ${fixture.adminUser}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_assignment_epochs (
        id, tenant_id, operator_team_id, assigned_by_membership_id,
        assignment_reason, assigned_at
      ) VALUES (
        ${fixture.operatorTeamEpoch}::uuid, ${fixture.tenant}::uuid,
        ${fixture.operatorTeam}::uuid, ${fixture.adminMembership}::uuid,
        'Contacts portal fanout proof.', ${authorizationGrantedAt}
      )
    `;
    await transaction`
      INSERT INTO public.operator_team_roster_entries (
        id, tenant_id, assignment_epoch_id, membership_id, source_id,
        granted_by_membership_id, grant_reason, granted_at
      )
      SELECT roster.id::uuid, ${fixture.tenant}::uuid,
             ${fixture.operatorTeamEpoch}::uuid,
             roster.membership_id::uuid, source.id,
             ${fixture.adminMembership}::uuid,
             'Contacts portal fanout proof.', ${authorizationGrantedAt}
      FROM (VALUES
        (${fixture.customerRosterEntry},
         ${fixture.customerRosterMembership}),
        (${fixture.readOnlyOperatorRosterEntry},
         ${fixture.readOnlyOperatorMembership})
      ) AS roster(id, membership_id)
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id = ${fixture.tenant}::uuid
       AND source.key = 'manual' AND source.kind = 'manual'
       AND source.retired_at IS NULL
    `;
    await transaction`
      SELECT set_config('app.tenant_id', ${fixture.tenant}, true),
             set_config('app.user_id', ${fixture.adminUser}, true)
    `;
    await transaction`
      INSERT INTO public.alerts (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        customer_visible, title, assigned_team_id, assigned_team_epoch_id,
        created_by, created_by_membership_id
      )
      SELECT alert_row.id::uuid, ${fixture.tenant}::uuid,
             alert_row.number, workflow.id, workflow.current_version,
             'new', true, alert_row.title,
             alert_row.team_id::uuid, alert_row.team_epoch_id::uuid,
             alert_row.creator_user_id::uuid,
             alert_row.creator_membership_id::uuid
      FROM (VALUES
        (${fixture.alertCustomerRoster}, 'ALT-2026-000001',
         'Customer roster proof', ${fixture.operatorTeam},
         ${fixture.operatorTeamEpoch}, ${fixture.adminUser},
         ${fixture.adminMembership}),
        (${fixture.alertPortalOnly}, 'ALT-2026-000002',
         'Portal-only actor proof', NULL, NULL,
         ${fixture.portalOnlyUser}, ${fixture.portalOnlyMembership}),
        (${fixture.alertRevokedOperator}, 'ALT-2026-000003',
         'Revoked operator proof', NULL, NULL,
         ${fixture.revokedOperatorUser},
         ${fixture.revokedOperatorMembership}),
        (${fixture.alertCustomerComment}, 'ALT-2026-000004',
         'Customer comment proof', NULL, NULL, ${fixture.adminUser},
         ${fixture.adminMembership}),
        (${fixture.alertRecipientFanout}, 'ALT-2026-000005',
         'Customer recipient fanout proof', NULL, NULL, ${fixture.adminUser},
         ${fixture.adminMembership})
      ) AS alert_row(
        id, number, title, team_id, team_epoch_id,
        creator_user_id, creator_membership_id
      )
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id = ${fixture.tenant}::uuid
       AND workflow.aggregate_kind = 'alert'
       AND workflow.is_default AND workflow.archived_at IS NULL
    `;
    const portalCases = await transaction<{ id: string }[]>`
      INSERT INTO public.cases (
        id, tenant_id, number, workflow_id, workflow_version, state_key,
        customer_visible, title, created_by_user_id, created_by_membership_id
      )
      SELECT case_row.id::uuid, ${fixture.tenant}::uuid, case_row.number,
             workflow.id, workflow.current_version, state.value->>'key',
             true, 'Customer Case download proof', ${fixture.adminUser}::uuid,
             ${fixture.adminMembership}::uuid
      FROM (VALUES
        (${fixture.portalCase}, 'CAS-2026-000001'),
        (${fixture.otherPortalCase}, 'CAS-2026-000002')
      ) AS case_row(id, number)
      JOIN public.ticket_workflows AS workflow
        ON workflow.tenant_id = ${fixture.tenant}::uuid
       AND workflow.aggregate_kind = 'case'
       AND workflow.is_default AND workflow.archived_at IS NULL
      JOIN public.ticket_workflow_versions AS version
        ON version.tenant_id = workflow.tenant_id
       AND version.workflow_id = workflow.id
       AND version.aggregate_kind = workflow.aggregate_kind
       AND version.version = workflow.current_version
      CROSS JOIN LATERAL jsonb_array_elements(version.states) AS state(value)
      WHERE (state.value->>'initial')::boolean
        AND state.value->>'visibility' = 'customer'
      RETURNING id::text
    `;
    assert.equal(
      portalCases.length,
      2,
      "expected two customer-visible Case roots",
    );
    await transaction`
      INSERT INTO public.ticket_customer_contacts (
        id, tenant_id, case_id, contact_id, role, origin,
        created_by_membership_id, created_by_user_id
      ) VALUES
        (${fixture.portalCaseContactLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.portalCase}::uuid, ${fixture.contact}::uuid, 'primary', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.otherPortalCaseContactLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.otherPortalCase}::uuid, ${fixture.contact}::uuid, 'primary', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid)
    `;
    await transaction`
      INSERT INTO public.ticket_customer_contacts (
        id, tenant_id, alert_id, contact_id, role, origin,
        created_by_membership_id, created_by_user_id
      ) VALUES
        (${fixture.customerRosterLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertCustomerRoster}::uuid,
         ${fixture.customerRosterContact}::uuid, 'primary', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.customerCommentLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertCustomerComment}::uuid, ${fixture.contact}::uuid,
         'primary', 'manual', ${fixture.adminMembership}::uuid,
         ${fixture.adminUser}::uuid),
        (${fixture.liveRecipientLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertRecipientFanout}::uuid, ${fixture.contact}::uuid,
         'primary', 'manual', ${fixture.adminMembership}::uuid,
         ${fixture.adminUser}::uuid),
        (${fixture.unlinkedRecipientLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertRecipientFanout}::uuid,
         ${fixture.unlinkedRecipientContact}::uuid, 'watcher', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.revokedRecipientLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertRecipientFanout}::uuid,
         ${fixture.revokedRecipientContact}::uuid, 'watcher', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.inactiveRecipientLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertRecipientFanout}::uuid,
         ${fixture.inactiveRecipientContact}::uuid, 'watcher', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.deniedRecipientLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertRecipientFanout}::uuid,
         ${fixture.deniedRecipientContact}::uuid, 'watcher', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.categoryRecipientLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertRecipientFanout}::uuid,
         ${fixture.categoryRecipientContact}::uuid, 'watcher', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid),
        (${fixture.windowRecipientLink}::uuid, ${fixture.tenant}::uuid,
         ${fixture.alertRecipientFanout}::uuid,
         ${fixture.windowRecipientContact}::uuid, 'watcher', 'manual',
         ${fixture.adminMembership}::uuid, ${fixture.adminUser}::uuid)
    `;
    for (const target of portalDownloadTargets) {
      // Each attachment must follow its storage row in this fixture transaction.
      // eslint-disable-next-line no-await-in-loop
      await transaction`
      INSERT INTO public.dfir_storage_objects (
        id, tenant_id, bucket, object_key, original_filename,
        classification, state, expected_size_bytes, upload_expires_at,
        content_sha256, size_bytes, detected_mime, verified_at,
        created_by_membership_id, created_at, updated_at
      ) VALUES (
        ${target.storageId}::uuid, ${fixture.tenant}::uuid,
        'must-never-leak-portal-bucket',
        ${`${fixture.tenant}/${target.storageId}`},
        'must-never-leak-portal-filename.bin', 'internal', 'available',
        48, transaction_timestamp() + interval '30 minutes',
        ${Buffer.alloc(32, 0x63)}, 48, 'application/x-must-never-leak',
        transaction_timestamp(), ${fixture.adminMembership}::uuid,
        transaction_timestamp(), transaction_timestamp()
      )
    `;
      // eslint-disable-next-line no-await-in-loop
      await transaction`
      INSERT INTO public.dfir_attachments (
        id, tenant_id, subject_kind, alert_id, case_id, storage_object_id,
        original_filename, visibility, scan_state,
        uploaded_by_membership_id, uploaded_at, version
      ) VALUES (
        ${target.attachmentId}::uuid, ${fixture.tenant}::uuid,
        ${target.kind}::public.dfir_entity_kind,
        ${target.kind === "alert" ? target.rootId : null}::uuid,
        ${target.kind === "case" ? target.rootId : null}::uuid,
        ${target.storageId}::uuid,
        'must-never-leak-portal-filename.bin', 'public', 'available',
        ${fixture.adminMembership}::uuid, transaction_timestamp(), 1
      )
    `;
    }
  });

  // Serialize the matrices: each denial compares the complete tenant audit chain.
  await verifyPortalDownloadGrantAuditing(portalDownloadTargets[0]);
  await verifyPortalDownloadGrantAuditing(portalDownloadTargets[1]);
  const issuedDownloadAudits = await sql<{ id: string }[]>`
    SELECT id::text FROM public.audit_events
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND action = 'dfir.portal.attachment.download_grant_issued'
    ORDER BY id
  `;
  assert.deepEqual(
    Array.from(issuedDownloadAudits, (row) => row.id),
    portalDownloadTargets.flatMap((target) => [...target.eventIds]).toSorted(),
    "only the two grants for each exact customer-visible root may be audited",
  );

  const tenantProjection = await sql.begin(async (transaction) => {
    await setApiContext(transaction, fixture.customerUser, fixture.tenant);
    return transaction<{ id: string; tenant_id: string }[]>`
      SELECT contact.id::text, contact.tenant_id::text
      FROM public.customer_contacts AS contact
      ORDER BY contact.id
    `;
  });
  assert.deepEqual(
    [...tenantProjection],
    [
      { id: fixture.contact, tenant_id: fixture.tenant },
      { id: fixture.customerRosterContact, tenant_id: fixture.tenant },
      { id: fixture.unlinkedRecipientContact, tenant_id: fixture.tenant },
      { id: fixture.revokedRecipientContact, tenant_id: fixture.tenant },
      { id: fixture.inactiveRecipientContact, tenant_id: fixture.tenant },
      { id: fixture.deniedRecipientContact, tenant_id: fixture.tenant },
      { id: fixture.categoryRecipientContact, tenant_id: fixture.tenant },
      { id: fixture.windowRecipientContact, tenant_id: fixture.tenant },
    ],
  );

  const tenantOverrideProjection = await sql.begin(async (transaction) => {
    await setApiContext(
      transaction,
      fixture.customerUser,
      fixture.foreignTenant,
    );
    return transaction<{ id: string }[]>`
      SELECT contact.id::text
      FROM public.customer_contacts AS contact
    `;
  });
  assert.deepEqual([...tenantOverrideProjection], []);

  await assert.rejects(
    sql.begin(async (transaction) => {
      await setApiContext(transaction, fixture.customerUser, fixture.tenant);
      await transaction`
        INSERT INTO public.customer_contacts (
          id, tenant_id, first_name, last_name, email, function, language,
          timezone, contact_class
        ) VALUES (
          ${fixture.apiWriteContact}::uuid, ${fixture.tenant}::uuid,
          'Forbidden', 'Write', 'forbidden.write@example.invalid',
          'customer', 'en', 'UTC', 'standard'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.customer_contacts (
          id, tenant_id, first_name, last_name, email, function, language,
          timezone, contact_class, linked_membership_id, linked_user_id
        ) VALUES (
          ${fixture.crossTenantContact}::uuid, ${fixture.tenant}::uuid,
          'Cross', 'Tenant', 'cross.tenant@example.invalid', 'customer',
          'en', 'UTC', 'standard', ${fixture.foreignMembership}::uuid,
          ${fixture.foreignUser}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23503"),
  );

  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.customer_contacts (
          id, tenant_id, first_name, last_name, email, function, language,
          timezone, contact_class, linked_membership_id, linked_user_id
        ) VALUES (
          ${fixture.mismatchedIdentityContact}::uuid,
          ${fixture.tenant}::uuid, 'Mismatched', 'Identity',
          'mismatched.identity@example.invalid', 'customer', 'en', 'UTC',
          'standard', ${fixture.secondMembership}::uuid,
          ${fixture.customerUser}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23503"),
  );

  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.customer_contacts (
          id, tenant_id, first_name, last_name, email, function, language,
          timezone, contact_class, linked_membership_id, linked_user_id
        ) VALUES (
          ${fixture.partialLinkContact}::uuid, ${fixture.tenant}::uuid,
          'Partial', 'Link', 'contacts.partial.link@example.invalid',
          'customer', 'en', 'UTC', 'standard',
          ${fixture.customerMembership}::uuid, NULL
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23514"),
  );

  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        INSERT INTO public.ticket_customer_contacts (
          id, tenant_id, alert_id, contact_id, role, origin,
          created_by_membership_id, created_by_user_id
        ) VALUES (
          ${fixture.crossTenantRecipientLink}::uuid, ${fixture.tenant}::uuid,
          ${fixture.alertRecipientFanout}::uuid, ${fixture.foreignContact}::uuid,
          'watcher', 'manual', ${fixture.adminMembership}::uuid,
          ${fixture.adminUser}::uuid
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "23503"),
  );

  await enqueueTicketNotification({
    actorKind: "system",
    alertId: fixture.alertCustomerRoster,
    customerAudience: true,
    eventId: fixture.eventCustomerRoster,
    occurredAt,
    routing: {
      operatorTeamEpochId: fixture.operatorTeamEpoch,
      operatorTeamId: fixture.operatorTeam,
    },
  });
  const rosterCandidates = await loadClaimedFanout(fixture.eventCustomerRoster);
  assert.deepEqual(
    candidatesFor(rosterCandidates, "contacts.portal.roster@example.invalid"),
    [
      {
        audience: "customer",
        email: "contacts.portal.roster@example.invalid",
        kinds: ["customer_contacts"],
        principalId: fixture.customerRosterUser,
      },
    ],
    "a customer in an operator roster must remain customer-only through the exact linked-contact projection",
  );
  assert.deepEqual(
    candidatesFor(
      rosterCandidates,
      "contacts.readonly.operator@example.invalid",
    ),
    [],
    "a read_only membership remains customer-classified even when a stale operator-team grant survives",
  );
  assert.equal(
    rosterCandidates.some((candidate) => candidate.kinds.includes("actor")),
    false,
    "a system event with no actor identity must never synthesize a user actor candidate",
  );

  await enqueueTicketNotification({
    actorKind: "system",
    alertId: fixture.alertRecipientFanout,
    customerAudience: true,
    eventId: fixture.eventRecipientFanout,
    occurredAt: new Date(occurredAt.getTime() + 500),
  });
  await sql`
    UPDATE public.tenant_memberships
    SET status = 'suspended', updated_at = transaction_timestamp()
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.revokedCustomerMembership}::uuid
      AND status = 'active'
  `;
  const recipientCandidates = await loadClaimedFanout(
    fixture.eventRecipientFanout,
  );
  assert.deepEqual(
    recipientCandidates.filter(
      (candidate) => candidate.audience === "customer",
    ),
    [
      {
        audience: "customer",
        email: "contacts.portal.customer@example.invalid",
        kinds: ["customer_contacts"],
        principalId: fixture.customerUser,
      },
      {
        audience: "customer",
        email: "contacts.recipient.revoked@example.invalid",
        kinds: ["customer_contacts"],
      },
      {
        audience: "customer",
        email: "contacts.recipient.unlinked@example.invalid",
        kinds: ["customer_contacts", "contact_group", "contact_tag"],
        values: {
          contact_group: ["manual_recipients", "vip_recipients"],
          contact_tag: ["priority", "vip"],
        },
      },
    ],
    "contact delivery must not require an account and each contact must remain deduplicated across group and tag selectors",
  );
  for (const excludedEmail of [
    "contacts.portal.foreign@example.invalid",
    "contacts.recipient.category@example.invalid",
    "contacts.recipient.denied@example.invalid",
    "contacts.recipient.inactive@example.invalid",
    "contacts.recipient.window@example.invalid",
  ]) {
    assert.deepEqual(
      candidatesFor(recipientCandidates, excludedEmail),
      [],
      `${excludedEmail} must fail closed before customer fanout`,
    );
  }

  await enqueueTicketNotification({
    actorKind: "system",
    alertId: fixture.alertRecipientFanout,
    customerAudience: false,
    eventId: fixture.eventRecipientOperatorOnly,
    eventType: "comment.private_added",
    occurredAt: new Date(occurredAt.getTime() + 750),
  });
  const operatorOnlyCandidates = await loadClaimedFanout(
    fixture.eventRecipientOperatorOnly,
  );
  assert.deepEqual(
    operatorOnlyCandidates.filter(
      (candidate) => candidate.audience === "customer",
    ),
    [],
    "private/operator-only events must never expose customer contacts",
  );

  await enqueueTicketNotification({
    actorId: fixture.portalOnlyUser,
    actorKind: "human",
    alertId: fixture.alertPortalOnly,
    customerAudience: false,
    eventId: fixture.eventPortalOnly,
    occurredAt: new Date(occurredAt.getTime() + 1_000),
  });
  const portalOnlyCandidates = await loadClaimedFanout(fixture.eventPortalOnly);
  assert.deepEqual(
    candidatesFor(portalOnlyCandidates, "contacts.portal.only@example.invalid"),
    [],
    "a legacy analyst with only portal permission must not become an operator recipient",
  );

  await enqueueTicketNotification({
    actorId: fixture.revokedOperatorUser,
    actorKind: "human",
    alertId: fixture.alertRevokedOperator,
    customerAudience: false,
    eventId: fixture.eventRevokedOperator,
    occurredAt: new Date(occurredAt.getTime() + 2_000),
  });
  await sql`
    UPDATE public.tenant_membership_role_grants
    SET revoked_at = transaction_timestamp(),
        revoked_by_membership_id = ${fixture.adminMembership}::uuid,
        revoke_reason = 'Revoked before notification dispatch.',
        version = version + 1,
        updated_at = transaction_timestamp()
    WHERE tenant_id = ${fixture.tenant}::uuid
      AND id = ${fixture.revokedRoleGrant}::uuid
      AND revoked_at IS NULL
  `;
  const revokedCandidates = await loadClaimedFanout(
    fixture.eventRevokedOperator,
  );
  assert.deepEqual(
    candidatesFor(
      revokedCandidates,
      "contacts.revoked.operator@example.invalid",
    ),
    [],
    "notification dispatch must re-authorize live after a ticket read grant is revoked",
  );

  await enqueueTicketNotification({
    actorId: fixture.customerUser,
    actorKind: "human",
    alertId: fixture.alertCustomerComment,
    customerAudience: true,
    eventId: fixture.eventCustomerComment,
    occurredAt: new Date(occurredAt.getTime() + 3_000),
  });
  const customerCommentCandidates = await loadClaimedFanout(
    fixture.eventCustomerComment,
  );
  assert.deepEqual(
    candidatesFor(
      customerCommentCandidates,
      "contacts.portal.customer@example.invalid",
    ),
    [
      {
        audience: "customer",
        email: "contacts.portal.customer@example.invalid",
        kinds: ["customer_contacts"],
        principalId: fixture.customerUser,
      },
    ],
    "a customer author of a public comment must receive only the exact linked-contact customer projection",
  );

  await enqueueTicketNotification({
    actorId: fixture.portalOnlyUser,
    actorKind: "service_account",
    alertId: fixture.alertPortalOnly,
    customerAudience: false,
    eventId: fixture.eventServiceActor,
    occurredAt: new Date(occurredAt.getTime() + 4_000),
  });
  const serviceActorCandidates = await loadClaimedFanout(
    fixture.eventServiceActor,
  );
  assert.deepEqual(
    candidatesFor(
      serviceActorCandidates,
      "contacts.portal.only@example.invalid",
    ),
    [],
    "a service-account actor ID must never be reinterpreted as a colliding human user ID",
  );

  const replayKey = Buffer.alloc(32, 0x31);
  const replayRequest = Buffer.alloc(32, 0x41);
  const replayCreatedAt = new Date(Date.now() - 60_000).toISOString();
  const originalReplayPayload: ContactPayload = {
    firstName: "Exact",
    lastName: "Snapshot",
    email: "contacts.replay.original@example.invalid",
    phone: null,
    function: "customer",
    language: "en",
    timezone: "UTC",
    escalationPriority: 0,
    contactClass: "standard",
    notificationCategories: [],
    notificationWindows: [],
    emailAllowed: true,
    active: true,
    tags: [],
    linkedMembershipId: null,
    linkedUserId: null,
    version: 1,
    createdAt: replayCreatedAt,
    updatedAt: replayCreatedAt,
    archivedAt: null,
  };
  assert.deepEqual(
    await commitContact({
      contactId: fixture.replayContact,
      expectedVersion: 0,
      keyDigest: replayKey,
      membershipId: fixture.adminMembership,
      operation: "contact.create",
      payload: originalReplayPayload,
      requestDigest: replayRequest,
      requestId: fixture.replayRequest1,
      userId: fixture.adminUser,
    }),
    { contact_id: fixture.replayContact, replayed: false, version: 1 },
  );
  const updatedReplayPayload = {
    ...originalReplayPayload,
    email: "contacts.replay.updated@example.invalid",
    version: 2,
  };
  await commitContact({
    contactId: fixture.replayContact,
    expectedVersion: 1,
    keyDigest: Buffer.alloc(32, 0x32),
    membershipId: fixture.adminMembership,
    operation: "contact.replace",
    payload: updatedReplayPayload,
    requestDigest: Buffer.alloc(32, 0x42),
    requestId: fixture.replayRequest2,
    userId: fixture.adminUser,
  });
  await commitContact({
    contactId: fixture.replayContact,
    expectedVersion: 2,
    keyDigest: Buffer.alloc(32, 0x33),
    membershipId: fixture.adminMembership,
    operation: "contact.archive",
    payload: {
      ...updatedReplayPayload,
      active: false,
      archivedAt: new Date().toISOString(),
      version: 3,
    },
    reason: "Replay after archive proof.",
    requestDigest: Buffer.alloc(32, 0x43),
    requestId: fixture.replayRequest3,
    userId: fixture.adminUser,
  });
  const originalReplay = await replayContact({
    keyDigest: replayKey,
    operation: "contact.create",
    requestDigest: replayRequest,
    userId: fixture.adminUser,
  });
  assert.equal(originalReplay.resource_id, fixture.replayContact);
  assert.equal(originalReplay.version, 1);
  assert.equal(originalReplay.projection, "operator");
  assert.equal(
    originalReplay.resource["email"],
    "contacts.replay.original@example.invalid",
    "replay must return the committed snapshot, not current archived state",
  );
  await assert.rejects(
    replayContact({
      keyDigest: replayKey,
      operation: "contact.create",
      requestDigest: Buffer.alloc(32, 0x7f),
      userId: fixture.adminUser,
    }),
    (error: unknown) => assertSqlState(error, "23505"),
  );
  await assert.rejects(
    sql.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        UPDATE public.customer_contact_commands
        SET result_version = result_version + 1
        WHERE tenant_id = ${fixture.tenant}::uuid
          AND key_digest = ${replayKey}
      `;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );

  const portalReplayKey = Buffer.alloc(32, 0x34);
  const portalReplayRequest = Buffer.alloc(32, 0x44);
  const portalPreferencePayload: ContactPayload = {
    firstName: "Portal",
    lastName: "Customer",
    email: "contacts.portal.customer@example.invalid",
    phone: null,
    function: "customer",
    language: "en",
    timezone: "UTC",
    escalationPriority: 0,
    contactClass: "standard",
    notificationCategories: ["comment.public_added"],
    notificationWindows: [],
    emailAllowed: false,
    active: true,
    tags: [],
    linkedMembershipId: fixture.customerMembership,
    linkedUserId: fixture.customerUser,
    version: 2,
    createdAt: replayCreatedAt,
    updatedAt: replayCreatedAt,
    archivedAt: null,
  };
  await commitContact({
    contactId: fixture.contact,
    expectedVersion: 1,
    keyDigest: portalReplayKey,
    membershipId: fixture.customerMembership,
    operation: "portal.preference.replace",
    payload: portalPreferencePayload,
    requestDigest: portalReplayRequest,
    requestId: fixture.replayRequest4,
    userId: fixture.customerUser,
  });
  const portalReplay = await replayContact({
    contactId: fixture.contact,
    keyDigest: portalReplayKey,
    operation: "portal.preference.replace",
    requestDigest: portalReplayRequest,
    userId: fixture.customerUser,
  });
  assert.equal(portalReplay.projection, "customer");
  assert.deepEqual(Object.keys(portalReplay.resource).toSorted(), [
    "active",
    "email",
    "emailAllowed",
    "firstName",
    "function",
    "id",
    "language",
    "lastName",
    "notificationCategories",
    "notificationWindows",
    "phone",
    "timezone",
    "version",
  ]);

  await commitContact({
    contactId: fixture.contact,
    expectedVersion: 2,
    keyDigest: Buffer.alloc(32, 0x35),
    membershipId: fixture.adminMembership,
    operation: "contact.replace",
    payload: {
      ...portalPreferencePayload,
      linkedMembershipId: null,
      linkedUserId: null,
      version: 3,
    },
    requestDigest: Buffer.alloc(32, 0x45),
    requestId: fixture.replayRequest5,
    userId: fixture.adminUser,
  });
  await assert.rejects(
    replayContact({
      contactId: fixture.contact,
      keyDigest: portalReplayKey,
      operation: "portal.preference.replace",
      requestDigest: portalReplayRequest,
      userId: fixture.customerUser,
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
} finally {
  await Promise.allSettled([sql.end(), notifier.end()]);
}
