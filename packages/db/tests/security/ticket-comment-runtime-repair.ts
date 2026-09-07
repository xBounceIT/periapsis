import assert from "node:assert/strict";
import { createHash } from "node:crypto";

import postgres, { type TransactionSql } from "postgres";

type ErrorWithCode = Error & { code?: string };

const databaseUrl =
  process.env.PERIAPSIS_TICKET_COMMENT_REPAIR_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_TICKET_COMMENT_REPAIR_TEST_DATABASE_URL must name a fresh PostgreSQL 18 database migrated through 0209",
  );
}

const sequence = BigInt(Date.now()) * 100n + BigInt(process.pid % 100);
const uuid = (offset: number): string =>
  `019d4d00-9000-7000-8000-${(sequence + BigInt(offset))
    .toString(16)
    .padStart(12, "0")}`;
const fixture = {
  tenant: uuid(1),
  foreignTenant: uuid(2),
  adminUser: uuid(11),
  customerUser: uuid(12),
  adminMembership: uuid(21),
  customerMembership: uuid(22),
  customerRoleGrant: uuid(23),
  customerContact: uuid(31),
  customerContactLink: uuid(32),
  alert: uuid(41),
  session: uuid(51),
  sessionFamily: uuid(52),
  publicCommentRequest1: uuid(61),
  publicCommentRequest2: uuid(62),
  privateCommentRequest: uuid(63),
  publicEditRequest: uuid(64),
  privateEditRequest: uuid(65),
  correlation: uuid(70),
  forgedRevision: uuid(81),
  forgedMention: uuid(82),
} as const;

const database = postgres(databaseUrl, { max: 4, onnotice: () => undefined });

function digest(label: string): Buffer {
  return createHash("sha256")
    .update(`ticket-comment-runtime-repair:${label}`)
    .digest();
}

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected, error.message);
  return true;
}

async function asApi<T>(
  tenantId: string,
  userId: string,
  operation: (transaction: TransactionSql) => Promise<T>,
): Promise<T> {
  const result = await database.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
    await transaction.unsafe("SET LOCAL statement_timeout = '20s'");
    await transaction`
      SELECT set_config('app.tenant_id',${tenantId},true),
             set_config('app.user_id',${userId},true),
             set_config('app.service_account_id','',true),
             set_config(
               'app.traceparent',
               '00-11111111111111111111111111111111-2222222222222222-01',
               true
             ),
             set_config('app.tracestate','ticket_comment=repair',true)
    `;
    return { value: await operation(transaction) };
  });
  return result.value;
}

type CommentReceipt = {
  comment_id: string;
  replayed: boolean;
  result_revision: number;
};

type CommentItem = {
  id: string;
  visibility: "private" | "public";
  revision: number;
};

type CommentPage = {
  next_cursor: string | null;
  result_items: CommentItem[];
};

async function createComment(
  visibility: "private" | "public",
  label: string,
  requestId: string,
): Promise<CommentReceipt> {
  return asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
    const [receipt] = await transaction<CommentReceipt[]>`
      SELECT comment_id::text,result_revision,replayed
      FROM app.create_tenant_ticket_comment_v2(
        'alert',${fixture.alert}::uuid,${visibility},
        ${label},${`<p>${label}</p>`},ARRAY[]::uuid[],ARRAY[]::uuid[],
        ${digest(`${label}:key`)},${digest(`${label}:request`)},
        ${requestId}::uuid,${fixture.correlation}::uuid,
        '192.0.2.90'::inet,'ticket-comment-runtime-repair','totp'
      )
    `;
    assert(receipt, "comment create returned no receipt");
    return receipt;
  });
}

async function editComment(
  receipt: CommentReceipt,
  label: string,
  requestId: string,
): Promise<CommentReceipt> {
  return asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
    const [edited] = await transaction<CommentReceipt[]>`
      SELECT comment_id::text,result_revision,replayed
      FROM app.edit_tenant_ticket_comment_v2(
        'alert',${fixture.alert}::uuid,${receipt.comment_id}::uuid,
        ${receipt.result_revision},${label},${`<p>${label}</p>`},
        ARRAY[]::uuid[],ARRAY[]::uuid[],'Focused runtime repair proof',
        ${digest(`${label}:key`)},${digest(`${label}:request`)},
        ${requestId}::uuid,${fixture.correlation}::uuid,
        '192.0.2.90'::inet,'ticket-comment-runtime-repair','totp'
      )
    `;
    assert(edited, "comment edit returned no receipt");
    return edited;
  });
}

async function listTenantComments(
  limit: number,
  after: string | null = null,
): Promise<CommentPage> {
  return asApi(fixture.tenant, fixture.adminUser, async (transaction) => {
    const [page] = await transaction<CommentPage[]>`
      SELECT result_items,next_cursor::text
      FROM app.list_tenant_ticket_comments_v2(
        'alert',${fixture.alert}::uuid,${after}::uuid,${limit}
      )
    `;
    assert(page, "tenant comment list returned no page");
    return page;
  });
}

async function listCustomerComments(
  limit: number,
  after: string | null = null,
): Promise<CommentPage> {
  return asApi(fixture.tenant, fixture.customerUser, async (transaction) => {
    const [page] = await transaction<CommentPage[]>`
      SELECT result_items,next_cursor::text
      FROM app.list_customer_portal_ticket_comments_v2(
        'alert',${fixture.alert}::uuid,${after}::uuid,${limit}
      )
    `;
    assert(page, "customer comment list returned no page");
    return page;
  });
}

try {
  const [readyBefore] = await database<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v56() AS ready
  `;
  assert.equal(readyBefore?.ready, true, "0209 readiness is false");

  const [existing] = await database<{ count: number }[]>`
    SELECT count(*)::integer AS count
    FROM public.tenants AS tenant
    WHERE tenant.id IN (
      ${fixture.tenant}::uuid,${fixture.foreignTenant}::uuid
    )
  `;
  assert.equal(
    existing?.count,
    0,
    "ticket comment repair proof requires a fresh disposable database",
  );

  await database.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    const now = new Date();
    const expires = new Date(now.getTime() + 60 * 60_000);
    await transaction`
      INSERT INTO public.tenants(id,slug,name,timezone)
      VALUES
        (${fixture.tenant}::uuid,'ticket-comment-repair-proof',
         'Ticket comment repair proof','Europe/Rome'),
        (${fixture.foreignTenant}::uuid,'ticket-comment-repair-foreign',
         'Ticket comment repair foreign','UTC')
    `;
    await transaction`
      INSERT INTO public.audit_chain_heads(tenant_id)
      VALUES (${fixture.tenant}::uuid),(${fixture.foreignTenant}::uuid)
    `;
    await transaction`
      INSERT INTO public.users(id,email,display_name,active)
      VALUES
        (${fixture.adminUser}::uuid,'comment.repair.admin@example.invalid',
         'Comment repair admin',true),
        (${fixture.customerUser}::uuid,'comment.repair.customer@example.invalid',
         'Comment repair customer',true)
    `;
    await transaction`
      INSERT INTO public.tenant_memberships(
        id,tenant_id,user_id,role,status
      ) VALUES
        (${fixture.adminMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.adminUser}::uuid,'tenant_admin','active'),
        (${fixture.customerMembership}::uuid,${fixture.tenant}::uuid,
         ${fixture.customerUser}::uuid,'customer_user','active')
    `;
    await transaction`
      SELECT app.seed_tenant_authorization(
        ${fixture.tenant}::uuid,${fixture.adminMembership}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.tenant_user_profiles(
        tenant_id,membership_id,user_id,display_name,email
      ) VALUES
        (${fixture.tenant}::uuid,${fixture.adminMembership}::uuid,
         ${fixture.adminUser}::uuid,'Comment repair admin',
         'comment.repair.admin@example.invalid'),
        (${fixture.tenant}::uuid,${fixture.customerMembership}::uuid,
         ${fixture.customerUser}::uuid,'Comment repair customer',
         'comment.repair.customer@example.invalid')
    `;
    await transaction`
      INSERT INTO public.tenant_membership_role_grants(
        id,tenant_id,membership_id,role_id,source_id,
        granted_by_membership_id,grant_reason,granted_at,updated_at
      )
      SELECT ${fixture.customerRoleGrant}::uuid,${fixture.tenant}::uuid,
             ${fixture.customerMembership}::uuid,role.id,source.id,
              ${fixture.adminMembership}::uuid,
              'Ticket comment customer projection proof.',${now},${now}
      FROM public.tenant_roles AS role
      JOIN public.tenant_authorization_sources AS source
        ON source.tenant_id=role.tenant_id
       AND source.key='manual' AND source.kind='manual'
       AND source.retired_at IS NULL
      WHERE role.tenant_id=${fixture.tenant}::uuid
        AND role.key='customer_user'
    `;
    await transaction`
      INSERT INTO public.auth_sessions(
        id,user_id,rotation_family_id,active_tenant_id,
        token_digest,csrf_secret_digest,authentication_method,
        mfa_satisfied_at,last_seen_at,idle_expires_at,
        absolute_expires_at,created_at
      ) VALUES (
        ${fixture.session}::uuid,${fixture.customerUser}::uuid,
        ${fixture.sessionFamily}::uuid,${fixture.tenant}::uuid,
        ${digest("session-token")},${digest("session-csrf")},'totp',
        ${now},${now},${expires},${expires},${now}
      )
    `;
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.tenant},true),
             set_config('app.user_id',${fixture.adminUser},true)
    `;
    await transaction`
      INSERT INTO public.alerts(
        id,tenant_id,number,workflow_id,workflow_version,state_key,
        customer_visible,title,source,severity,priority,category,
        created_by,created_by_membership_id
      )
      SELECT ${fixture.alert}::uuid,${fixture.tenant}::uuid,
             'ALT-2026-920001',workflow.id,workflow.current_version,'new',
             true,'Ticket comment runtime repair','manual','high','high',
             'incident',${fixture.adminUser}::uuid,
             ${fixture.adminMembership}::uuid
      FROM public.ticket_workflows AS workflow
      WHERE workflow.tenant_id=${fixture.tenant}::uuid
        AND workflow.aggregate_kind='alert'
        AND workflow.is_default AND workflow.archived_at IS NULL
    `;
    await transaction`
      INSERT INTO public.customer_contacts(
        id,tenant_id,first_name,last_name,email,function,language,
        timezone,contact_class,notification_categories,
        linked_membership_id,linked_user_id
      ) VALUES (
        ${fixture.customerContact}::uuid,${fixture.tenant}::uuid,
        'Comment','Customer','comment.repair.customer@example.invalid',
        'customer','en','UTC','standard',ARRAY['comment.public_added']::text[],
        ${fixture.customerMembership}::uuid,${fixture.customerUser}::uuid
      )
    `;
    await transaction`
      INSERT INTO public.ticket_customer_contacts(
        id,tenant_id,alert_id,contact_id,role,origin,
        created_by_membership_id,created_by_user_id
      ) VALUES (
        ${fixture.customerContactLink}::uuid,${fixture.tenant}::uuid,
        ${fixture.alert}::uuid,${fixture.customerContact}::uuid,
        'primary','manual',${fixture.adminMembership}::uuid,
        ${fixture.adminUser}::uuid
      )
    `;
  });

  const publicOne = await createComment(
    "public",
    "Public comment one",
    fixture.publicCommentRequest1,
  );
  const publicTwo = await createComment(
    "public",
    "Public comment two",
    fixture.publicCommentRequest2,
  );
  const privateOne = await createComment(
    "private",
    "Private operator note",
    fixture.privateCommentRequest,
  );
  for (const receipt of [publicOne, publicTwo, privateOne]) {
    assert.equal(receipt.result_revision, 1);
    assert.equal(receipt.replayed, false);
  }

  const editedPublic = await editComment(
    publicOne,
    "Edited public comment",
    fixture.publicEditRequest,
  );
  const editedPrivate = await editComment(
    privateOne,
    "Edited private operator note",
    fixture.privateEditRequest,
  );
  assert.equal(editedPublic.result_revision, 2);
  assert.equal(editedPrivate.result_revision, 2);

  const firstTenantPage = await listTenantComments(1);
  assert.equal(firstTenantPage.result_items.length, 1);
  assert(firstTenantPage.next_cursor, "tenant UUID cursor was not produced");
  const allTenantComments = await listTenantComments(100);
  assert.equal(allTenantComments.result_items.length, 3);
  assert.deepEqual(
    allTenantComments.result_items.map((item) => item.visibility).toSorted(),
    ["private", "public", "public"],
  );
  const remainingTenantComments = await listTenantComments(
    100,
    firstTenantPage.next_cursor,
  );
  assert.equal(remainingTenantComments.result_items.length, 2);
  assert(
    remainingTenantComments.result_items.every(
      (comment) => comment.id !== firstTenantPage.result_items[0]?.id,
    ),
    "tenant UUID cursor repeated the first page",
  );

  const firstCustomerPage = await listCustomerComments(1);
  assert.equal(firstCustomerPage.result_items.length, 1);
  assert(
    firstCustomerPage.next_cursor,
    "customer UUID cursor was not produced",
  );
  const allCustomerComments = await listCustomerComments(100);
  assert.equal(allCustomerComments.result_items.length, 2);
  assert(
    allCustomerComments.result_items.every(
      (comment) => comment.visibility === "public",
    ),
    "customer projection exposed a private comment",
  );
  const remainingCustomerComments = await listCustomerComments(
    100,
    firstCustomerPage.next_cursor,
  );
  assert.equal(remainingCustomerComments.result_items.length, 1);
  assert.notEqual(
    remainingCustomerComments.result_items[0]?.id,
    firstCustomerPage.result_items[0]?.id,
    "customer UUID cursor repeated the first page",
  );

  await assert.rejects(
    asApi(
      fixture.foreignTenant,
      fixture.adminUser,
      async (transaction) =>
        transaction`
          SELECT * FROM app.list_tenant_ticket_comments_v2(
            'alert',${fixture.alert}::uuid,NULL,100
          )
        `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const foreignProjectionResult = await database.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_sla_worker_owner"');
    await transaction`
      SELECT set_config('app.tenant_id',${fixture.foreignTenant},true),
             set_config('app.user_id','',true),
             set_config('app.service_account_id','',true)
    `;
    const rows = await transaction<{ id: string }[]>`
      SELECT comment.id::text
      FROM public.ticket_comments AS comment
      WHERE comment.id IN (
        ${publicOne.comment_id}::uuid,${privateOne.comment_id}::uuid
      )
    `;
    return { rows };
  });
  const foreignProjection = foreignProjectionResult.rows;
  assert.deepEqual([...foreignProjection], [], "RLS exposed cross-tenant rows");

  const actor = {
    userId: fixture.customerUser,
    sessionId: fixture.session,
    activeTenantId: fixture.tenant,
    authenticationMethod: "totp",
  } as const;
  const accessRequest = {
    schemaVersion: 1,
    actor,
    tenantId: fixture.tenant,
    kind: "alert",
    audience: "customer",
    capability: "ticket_export.read",
  } as const;
  await assert.rejects(
    asApi(
      fixture.tenant,
      fixture.customerUser,
      (transaction) =>
        transaction`
        SELECT response
        FROM app.resolve_ticket_export_access_v1(
          ${transaction.json(accessRequest)}
        )
      `,
    ),
    (error: unknown) => assertSqlState(error, "42501"),
    "retired export V1 unexpectedly remained API-callable",
  );
  const response = await asApi(
    fixture.tenant,
    fixture.customerUser,
    async (transaction) => {
      const [row] = await transaction<
        Array<{ response: Record<string, unknown> }>
      >`
        SELECT response
        FROM app.resolve_ticket_export_access_v2(
          ${transaction.json(accessRequest)}
        )
      `;
      assert(row, "ticket export access V2 returned no row");
      return row.response;
    },
  );
  assert.equal(response.allowed, true);
  assert.equal(response.customerContactId, fixture.customerContact);
  assert.equal(response.privateComments, false);

  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        SELECT set_config('app.ticket_runtime_write_v1','enabled',true)
      `;
      await transaction`
        INSERT INTO public.ticket_comment_revisions(
          id,tenant_id,comment_id,revision,body_markdown,body_html,reason,
          edited_by_membership_id,edited_by_user_id,edited_at
        )
        SELECT ${fixture.forgedRevision}::uuid,comment.tenant_id,comment.id,
               comment.revision+1,'Forged revision','<p>Forged revision</p>',
               'Forged aggregate revision',comment.author_membership_id,
               comment.author_user_id,comment.updated_at+interval '1 microsecond'
        FROM public.ticket_comments AS comment
        WHERE comment.tenant_id=${fixture.tenant}::uuid
          AND comment.id=${privateOne.comment_id}::uuid
      `;
    }),
    (error: unknown) => assertSqlState(error, "23514"),
    "a detached revision survived the deferred aggregate guard",
  );

  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction`
        SELECT set_config('app.ticket_runtime_write_v1','enabled',true)
      `;
      await transaction`
        INSERT INTO public.ticket_comment_revision_mentions(
          id,tenant_id,revision_id,mentioned_membership_id,
          mentioned_user_id,display_name
        )
        SELECT ${fixture.forgedMention}::uuid,revision.tenant_id,revision.id,
               ${fixture.adminMembership}::uuid,${fixture.adminUser}::uuid,
               'Comment repair admin'
        FROM public.ticket_comment_revisions AS revision
        WHERE revision.tenant_id=${fixture.tenant}::uuid
          AND revision.comment_id=${privateOne.comment_id}::uuid
        ORDER BY revision.revision DESC
        LIMIT 1
      `;
    }),
    (error: unknown) => assertSqlState(error, "23514"),
    "an unbound mention survived the deferred aggregate guard",
  );

  const aclRollback = new Error("intentional readiness ACL rollback");
  await assert.rejects(
    database.begin(async (transaction) => {
      await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
      await transaction.unsafe(
        "GRANT EXECUTE ON FUNCTION app.guard_ticket_comment_aggregate_v1() TO periapsis_api",
      );
      const [tampered] = await transaction<{ ready: boolean }[]>`
        SELECT app.release_runtime_schema_readiness_v56() AS ready
      `;
      assert.equal(tampered?.ready, false, "readiness accepted a widened ACL");
      throw aclRollback;
    }),
    (error: unknown) => error === aclRollback,
  );
  const [readyAfter] = await database<{ ready: boolean }[]>`
    SELECT app.release_runtime_schema_readiness_v56() AS ready
  `;
  assert.equal(
    readyAfter?.ready,
    true,
    "readiness did not recover after rollback",
  );

  process.stdout.write("ticket comment runtime repair security proof passed\n");
} finally {
  await database.end();
}
