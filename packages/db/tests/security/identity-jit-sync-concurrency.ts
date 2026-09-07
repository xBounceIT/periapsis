import assert from "node:assert/strict";

import postgres from "postgres";

import {
  expectedMigrationCount,
  expectedMigrationCreatedAt,
  expectedMigrationFingerprint,
  expectedMigrationHash,
} from "../../src/admin/schema-compatibility-manifest.gen.js";

type ErrorWithCode = Error & { code?: string };

const databaseUrl = process.env.PERIAPSIS_IDENTITY_JIT_SYNC_TEST_DATABASE_URL;
if (databaseUrl === undefined || databaseUrl.trim() === "") {
  throw new Error(
    "PERIAPSIS_IDENTITY_JIT_SYNC_TEST_DATABASE_URL must name a fresh migrated PostgreSQL 18 database",
  );
}

// Reuse the preceding directory-operation security fixture so this proof also
// exercises the complete directory-to-JIT flow on the current schema.
process.env.PERIAPSIS_IDENTITY_DIRECTORY_OPERATION_TEST_DATABASE_URL =
  databaseUrl;
await import("./identity-directory-operations-concurrency.js");

const fixture = {
  tenant: "0199f300-1000-7000-8000-000000000001",
  foreignTenant: "0199f300-1000-7000-8000-000000000002",
  targetMembership: "0199f300-1000-7000-8000-000000000203",
  externalIdentity: "0199f300-1000-7000-8000-000000000501",
  accessGrant: "0199f300-1000-7000-8000-000000000503",
  provider: "0199f300-1000-7000-8000-000000000301",
} as const;

const ids = {
  jitRun: "01a03891-0000-7000-8000-000000000001",
  jitBeginAudit: "01a03891-0000-7000-8000-000000000002",
  jitRequest: "01a03891-0000-7000-8000-000000000003",
  jitCorrelation: "01a03891-0000-7000-8000-000000000004",
  jitClaimAudit: "01a03891-0000-7000-8000-000000000005",
  jitApplication: "01a03891-0000-7000-8000-000000000006",
  jitApplyAudit: "01a03891-0000-7000-8000-000000000007",
  failedJitRun: "01a03891-0000-7000-8000-000000000011",
  failedJitBeginAudit: "01a03891-0000-7000-8000-000000000012",
  failedJitRequest: "01a03891-0000-7000-8000-000000000013",
  failedJitCorrelation: "01a03891-0000-7000-8000-000000000014",
  failedJitAudit: "01a03891-0000-7000-8000-000000000015",
  staleJitRun: "01a03891-0000-7000-8000-000000000021",
  staleJitBeginAudit: "01a03891-0000-7000-8000-000000000022",
  staleJitRequest: "01a03891-0000-7000-8000-000000000023",
  staleJitCorrelation: "01a03891-0000-7000-8000-000000000024",
  staleJitAudit: "01a03891-0000-7000-8000-000000000025",
  missingJitRun: "01a03891-0000-7000-8000-000000000031",
  missingJitAudit: "01a03891-0000-7000-8000-000000000032",
  missingJitRequest: "01a03891-0000-7000-8000-000000000033",
  missingJitCorrelation: "01a03891-0000-7000-8000-000000000034",
  syncRunA: "01a03892-0000-7000-8000-000000000001",
  syncRunB: "01a03892-0000-7000-8000-000000000002",
  syncQueuedAuditA: "01a03892-0000-7000-8000-000000000003",
  syncQueuedAuditB: "01a03892-0000-7000-8000-000000000004",
  syncRequestA: "01a03892-0000-7000-8000-000000000005",
  syncRequestB: "01a03892-0000-7000-8000-000000000006",
  syncCorrelationA: "01a03892-0000-7000-8000-000000000007",
  syncCorrelationB: "01a03892-0000-7000-8000-000000000008",
  syncObservation: "01a03892-0000-7000-8000-000000000009",
  syncEnumerationAudit: "01a03892-0000-7000-8000-00000000000a",
  syncEnumerationRequest: "01a03892-0000-7000-8000-00000000000b",
  syncEnumerationCorrelation: "01a03892-0000-7000-8000-00000000000c",
  syncAbsenceAudit: "01a03892-0000-7000-8000-00000000000d",
  failedSyncRun: "01a03892-0000-7000-8000-000000000011",
  failedSyncQueuedAudit: "01a03892-0000-7000-8000-000000000012",
  failedSyncRequest: "01a03892-0000-7000-8000-000000000013",
  failedSyncCorrelation: "01a03892-0000-7000-8000-000000000014",
  failedSyncAudit: "01a03892-0000-7000-8000-000000000015",
  completedSyncRun: "01a03892-0000-7000-8000-000000000021",
  completedSyncQueuedAudit: "01a03892-0000-7000-8000-000000000022",
  completedSyncRequest: "01a03892-0000-7000-8000-000000000023",
  completedSyncCorrelation: "01a03892-0000-7000-8000-000000000024",
  completedEnumerationAudit: "01a03892-0000-7000-8000-000000000025",
  completedEnumerationRequest: "01a03892-0000-7000-8000-000000000026",
  completedEnumerationCorrelation: "01a03892-0000-7000-8000-000000000027",
  completedSyncAudit: "01a03892-0000-7000-8000-000000000028",
  staleSyncRun: "01a03892-0000-7000-8000-000000000031",
  staleSyncQueuedAudit: "01a03892-0000-7000-8000-000000000032",
  staleSyncRequest: "01a03892-0000-7000-8000-000000000033",
  staleSyncCorrelation: "01a03892-0000-7000-8000-000000000034",
  staleSyncObservation: "01a03892-0000-7000-8000-000000000035",
  staleSyncAudit: "01a03892-0000-7000-8000-000000000036",
  accessStateSyncRun: "01a03892-0000-7000-8000-000000000041",
  accessStateSyncQueuedAudit: "01a03892-0000-7000-8000-000000000042",
  accessStateSyncRequest: "01a03892-0000-7000-8000-000000000043",
  accessStateSyncCorrelation: "01a03892-0000-7000-8000-000000000044",
  absentSyncObservation: "01a03892-0000-7000-8000-000000000045",
  revokedSyncObservation: "01a03892-0000-7000-8000-000000000046",
  accessStateSyncAudit: "01a03892-0000-7000-8000-000000000047",
  accessStateSyncFailRequest: "01a03892-0000-7000-8000-000000000048",
  accessStateSyncFailCorrelation: "01a03892-0000-7000-8000-000000000049",
  syncClaimA: "01a03893-0000-7000-8000-000000000001",
  syncClaimB: "01a03893-0000-7000-8000-000000000002",
  syncClaimReclaim: "01a03893-0000-7000-8000-000000000003",
  failedSyncClaim: "01a03893-0000-7000-8000-000000000011",
  completedSyncClaim: "01a03893-0000-7000-8000-000000000021",
  staleSyncClaim: "01a03893-0000-7000-8000-000000000031",
  accessStateSyncClaim: "01a03893-0000-7000-8000-000000000041",
} as const;

const digests = {
  receipt: Buffer.alloc(32, 0xa1),
  failedReceipt: Buffer.alloc(32, 0xa2),
  staleReceipt: Buffer.alloc(32, 0xa3),
  missingReceipt: Buffer.alloc(32, 0xa4),
  network: Buffer.alloc(32, 0xb1),
  account: Buffer.alloc(32, 0xb2),
  provider: Buffer.alloc(32, 0xb3),
  missingNetwork: Buffer.alloc(32, 0xb4),
  missingAccount: Buffer.alloc(32, 0xb5),
  missingProvider: Buffer.alloc(32, 0xb6),
  subject: Buffer.alloc(32, 0xee),
  deniedPlan: Buffer.alloc(32, 0xc1),
  observation: Buffer.alloc(32, 0xd1),
  cursor: Buffer.alloc(32, 0xd2),
  syncClaimA: Buffer.alloc(32, 0xe1),
  syncClaimB: Buffer.alloc(32, 0xe2),
  syncClaimReclaim: Buffer.alloc(32, 0xe3),
  failedSyncClaim: Buffer.alloc(32, 0xe4),
  completedSyncClaim: Buffer.alloc(32, 0xe5),
  staleSyncClaim: Buffer.alloc(32, 0xe6),
  accessStateSyncClaim: Buffer.alloc(32, 0xe7),
  absentSubject: Buffer.alloc(32, 0xef),
  absentObservation: Buffer.alloc(32, 0xd3),
  revokedObservation: Buffer.alloc(32, 0xd4),
} as const;

type JitSnapshot = {
  operation_run_id: string;
  tenant_id: string;
  provider_id: string;
  binding_id: string;
  bind_secret_ciphertext: Buffer;
  bind_secret_nonce: Buffer;
};

type JitPlan = {
  operation_run_id: string;
  tenant_id: string;
  external_identity_id: string | null;
  membership_id: string | null;
  rules: unknown[];
};

type AppliedPlan = {
  application_id: string;
  decision: "admitted" | "denied";
  external_identity_id: string | null;
  user_id: string | null;
  membership_id: string | null;
  access_grant_id: string | null;
  ensured_edge_count: number;
  revoked_edge_count: number;
  replayed: boolean;
};

type SyncStart = {
  sync_run_id: string;
  status: string;
  replayed: boolean;
};

type SyncClaim = {
  sync_run_id: string;
  tenant_id: string;
  binding_id: string;
  bind_secret_ciphertext: Buffer;
  bind_secret_nonce: Buffer;
  mapping_revisions: unknown[];
  staged_observations: unknown[];
  claim_id: string;
  claim_fence: string;
  run_version: number;
};

type SyncEnumeration = {
  status: string;
  version: number;
  observed_count: number;
  absence_allowed: boolean;
};

type SyncFailure = {
  status: string;
  version: number;
  replayed: boolean;
};

function assertSqlState(error: unknown, expected: string): true {
  assert(error instanceof Error, "expected a PostgreSQL error");
  assert.equal((error as ErrorWithCode).code, expected);
  return true;
}

const admin = postgres(databaseUrl, { max: 12, onnotice: () => undefined });

async function setApiContext(
  transaction: postgres.TransactionSql,
  tenantId: string = fixture.foreignTenant,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_api"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantId}, true),
           set_config('app.user_id', '', true)
  `;
}

async function setWorkerContext(
  transaction: postgres.TransactionSql,
  tenantId: string = fixture.tenant,
): Promise<void> {
  await transaction.unsafe('SET LOCAL ROLE "periapsis_worker"');
  await transaction.unsafe("SET LOCAL statement_timeout = '15s'");
  await transaction`
    SELECT set_config('app.tenant_id', ${tenantId}, true),
           set_config('app.user_id', '', true)
  `;
}

async function beginJit(
  runId: string,
  receipt: Buffer,
  auditId: string,
  requestId: string,
  correlationId: string,
  tenantSlug = "directory-operation-proof",
  loginKey = "bounded_ldap",
  networkDigest: Buffer = digests.network,
  accountDigest: Buffer = digests.account,
  providerDigest: Buffer = digests.provider,
): Promise<JitSnapshot[]> {
  return admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<JitSnapshot[]>`
      SELECT * FROM app.begin_tenant_ldap_jit_authentication_v1(
        ${runId}::uuid, ${receipt}, ${tenantSlug}, ${loginKey},
        ${networkDigest}, ${accountDigest}, ${providerDigest},
        ${auditId}::uuid, ${requestId}::uuid, ${correlationId}::uuid,
        '192.0.2.210'::inet, 'Periapsis D5 security proof'
      )
    `;
  });
}

async function claimJit(
  runId: string,
  receipt: Buffer,
  auditId: string,
  requestId: string,
  correlationId: string,
): Promise<JitPlan[]> {
  return admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<JitPlan[]>`
      SELECT * FROM app.claim_tenant_ldap_jit_planning_v1(
        ${runId}::uuid, ${receipt}, ARRAY[2]::integer[],
        ARRAY[${digests.subject}::bytea]::bytea[], ${auditId}::uuid,
        ${requestId}::uuid, ${correlationId}::uuid,
        '192.0.2.210'::inet, 'Periapsis D5 security proof'
      )
    `;
  });
}

async function beginScheduledSync(
  runId: string,
  bindingId: string,
  auditId: string,
  requestId: string,
  correlationId: string,
): Promise<SyncStart[]> {
  return admin.begin(async (transaction) => {
    await setWorkerContext(transaction);
    return transaction<SyncStart[]>`
      SELECT * FROM app.begin_tenant_ldap_scheduled_sync_run_v1(
        ${runId}::uuid, ${bindingId}::uuid, 'scheduled_sync',
        ${auditId}::uuid, ${requestId}::uuid, ${correlationId}::uuid,
        'Periapsis D5 security proof'
      )
    `;
  });
}

async function claimSync(
  claimId: string,
  receipt: Buffer,
  leaseSeconds = 30,
): Promise<SyncClaim[]> {
  return admin.begin(async (transaction) => {
    await setWorkerContext(transaction, fixture.foreignTenant);
    return transaction<SyncClaim[]>`
      SELECT * FROM app.claim_next_tenant_ldap_sync_run_v2(
        ${claimId}::uuid, ${receipt}, ${leaseSeconds},
        'Periapsis D5 security proof'
      )
    `;
  });
}

try {
  const [compatibility] = await admin<
    {
      applied_count: string;
      latest_created_at: string;
      latest_hash: string;
      migration_fingerprint: string;
    }[]
  >`SELECT applied_count::text, latest_created_at::text, latest_hash,
           migration_fingerprint
    FROM app.schema_compatibility_v57()`;
  assert.equal(compatibility?.applied_count, String(expectedMigrationCount));
  assert.equal(
    compatibility.latest_created_at,
    String(expectedMigrationCreatedAt),
  );
  assert.equal(compatibility.latest_hash, expectedMigrationHash);
  assert.equal(
    compatibility.migration_fingerprint,
    expectedMigrationFingerprint,
  );

  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_memberships
      SET status = 'active', updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.targetMembership}::uuid
    `;
  });

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setApiContext(transaction, fixture.tenant);
      await transaction`SELECT count(*) FROM public.tenant_ldap_jit_authentication_runs`;
    }),
    (error: unknown) => assertSqlState(error, "42501"),
  );
  const [planningPrivileges] = await admin<{ v2: boolean; v3: boolean }[]>`
    SELECT
      has_function_privilege(
        'periapsis_worker',
        'app.claim_tenant_ldap_sync_observation_planning_v2(uuid,uuid,uuid,bytea,bigint,integer[],bytea[])',
        'EXECUTE'
      ) AS v2,
      has_function_privilege(
        'periapsis_worker',
        'app.claim_tenant_ldap_sync_observation_planning_v3(uuid,uuid,uuid,bytea,bigint,integer[],bytea[])',
        'EXECUTE'
      ) AS v3
  `;
  assert.deepEqual(planningPrivileges, { v2: false, v3: true });

  const concurrentBegins = await Promise.all([
    beginJit(
      ids.jitRun,
      digests.receipt,
      ids.jitBeginAudit,
      ids.jitRequest,
      ids.jitCorrelation,
    ),
    beginJit(
      ids.jitRun,
      digests.receipt,
      ids.jitBeginAudit,
      ids.jitRequest,
      ids.jitCorrelation,
    ),
  ]);
  assert.equal(concurrentBegins[0]?.length, 1);
  assert.equal(concurrentBegins[1]?.length, 1);
  const jitSnapshot = concurrentBegins[0][0]!;
  assert.equal(jitSnapshot.tenant_id, fixture.tenant);
  assert.equal(jitSnapshot.provider_id, fixture.provider);
  assert(jitSnapshot.bind_secret_ciphertext.length >= 17);
  assert.equal(jitSnapshot.bind_secret_nonce.length, 12);

  const [meterCount] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    return transaction<{ attempt_count: number }[]>`
      SELECT attempt_count
      FROM public.auth_rate_limits
      WHERE scope = 'ldap_network' AND key_digest = ${digests.network}
    `;
  });
  assert.equal(meterCount?.attempt_count, 1);

  const wrongReceiptRead = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction`
      SELECT * FROM app.read_tenant_ldap_jit_network_snapshot_v1(
        ${ids.jitRun}::uuid, ${digests.failedReceipt}
      )
    `;
  });
  assert.equal(wrongReceiptRead.length, 0);

  const planningClaims = await Promise.all([
    claimJit(
      ids.jitRun,
      digests.receipt,
      ids.jitClaimAudit,
      ids.jitRequest,
      ids.jitCorrelation,
    ),
    claimJit(
      ids.jitRun,
      digests.receipt,
      ids.jitClaimAudit,
      ids.jitRequest,
      ids.jitCorrelation,
    ),
  ]);
  assert.deepEqual(
    planningClaims
      .map((rows) => rows.length)
      .toSorted((left, right) => left - right),
    [0, 1],
  );
  const planning = planningClaims.find((rows) => rows.length === 1)![0]!;
  assert.equal(planning.tenant_id, fixture.tenant);
  assert.equal(planning.external_identity_id, fixture.externalIdentity);
  assert.equal(planning.membership_id, fixture.targetMembership);
  assert(planning.rules.length > 0);

  const denied = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<AppliedPlan[]>`
      SELECT * FROM app.apply_tenant_ldap_jit_identity_plan_v1(
        ${ids.jitRun}::uuid, ${digests.receipt}, ${ids.jitApplication}::uuid,
        ${digests.deniedPlan}, 'denied', 'no_matching_rule',
        NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid,
        NULL::public.identity_subject_format, NULL::bytea, NULL::bytea,
        NULL::integer, ARRAY[]::uuid[], ARRAY[]::integer[], ARRAY[]::bytea[],
        NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
        ARRAY[]::uuid[], transaction_timestamp(), ${ids.jitApplyAudit}::uuid,
        ${ids.jitRequest}::uuid, ${ids.jitCorrelation}::uuid,
        '192.0.2.210'::inet, 'Periapsis D5 security proof'
      )
    `;
  });
  assert.deepEqual(denied[0], {
    application_id: ids.jitApplication,
    decision: "denied",
    external_identity_id: null,
    user_id: null,
    membership_id: null,
    access_grant_id: null,
    ensured_edge_count: 0,
    revoked_edge_count: 0,
    replayed: false,
  });
  const deniedReplay = await admin.begin(async (transaction) => {
    await setApiContext(transaction);
    return transaction<AppliedPlan[]>`
      SELECT * FROM app.apply_tenant_ldap_jit_identity_plan_v1(
        ${ids.jitRun}::uuid, ${digests.receipt}, ${ids.jitApplication}::uuid,
        ${digests.deniedPlan}, 'denied', 'no_matching_rule',
        NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid, NULL::uuid,
        NULL::public.identity_subject_format, NULL::bytea, NULL::bytea,
        NULL::integer, ARRAY[]::uuid[], ARRAY[]::integer[], ARRAY[]::bytea[],
        NULL::text, NULL::text, NULL::text, NULL::text, NULL::text,
        ARRAY[]::uuid[], transaction_timestamp(), ${ids.jitApplyAudit}::uuid,
        ${ids.jitRequest}::uuid, ${ids.jitCorrelation}::uuid,
        '192.0.2.210'::inet, 'Periapsis D5 security proof'
      )
    `;
  });
  assert.equal(deniedReplay[0]?.replayed, true);

  const failedSnapshot = await beginJit(
    ids.failedJitRun,
    digests.failedReceipt,
    ids.failedJitBeginAudit,
    ids.failedJitRequest,
    ids.failedJitCorrelation,
    "directory-operation-proof",
    "bounded_ldap",
    Buffer.alloc(32, 0xc2),
    Buffer.alloc(32, 0xc3),
    digests.provider,
  );
  assert.equal(failedSnapshot.length, 1);
  const completeFailedJit = async (): Promise<boolean> => {
    const [completion] = await admin.begin(async (transaction) => {
      await setApiContext(transaction);
      return transaction<{ completed: boolean }[]>`
        SELECT app.complete_tenant_ldap_jit_authentication_v1(
          ${ids.failedJitRun}::uuid, ${digests.failedReceipt},
          'invalid_credentials', ${ids.failedJitAudit}::uuid,
          ${ids.failedJitRequest}::uuid, ${ids.failedJitCorrelation}::uuid,
          '192.0.2.210'::inet, 'Periapsis D5 security proof'
        ) AS completed
      `;
    });
    return completion?.completed ?? false;
  };
  assert.equal(await completeFailedJit(), true);
  assert.equal(await completeFailedJit(), true);

  const missing = await beginJit(
    ids.missingJitRun,
    digests.missingReceipt,
    ids.missingJitAudit,
    ids.missingJitRequest,
    ids.missingJitCorrelation,
    "missing-tenant",
    "bounded_ldap",
    digests.missingNetwork,
    digests.missingAccount,
    digests.missingProvider,
  );
  assert.equal(missing.length, 0);
  const [missingMeter] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    return transaction<{ attempt_count: number }[]>`
      SELECT attempt_count FROM public.auth_rate_limits
      WHERE scope = 'ldap_account' AND key_digest = ${digests.missingAccount}
    `;
  });
  assert.equal(missingMeter?.attempt_count, 1);

  const staleSnapshot = await beginJit(
    ids.staleJitRun,
    digests.staleReceipt,
    ids.staleJitBeginAudit,
    ids.staleJitRequest,
    ids.staleJitCorrelation,
    "directory-operation-proof",
    "bounded_ldap",
    Buffer.alloc(32, 0xc4),
    Buffer.alloc(32, 0xc5),
    digests.provider,
  );
  assert.equal(staleSnapshot.length, 1);
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_ldap_provider_configs
      SET sync_interval_seconds = 300, version = version + 1,
          updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND provider_id = ${fixture.provider}::uuid
    `;
  });
  const staleClaim = await claimJit(
    ids.staleJitRun,
    digests.staleReceipt,
    ids.staleJitAudit,
    ids.staleJitRequest,
    ids.staleJitCorrelation,
  );
  assert.equal(staleClaim.length, 0);
  const [staleState] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    return transaction<{ status: string }[]>`
      SELECT status FROM public.tenant_ldap_jit_authentication_runs
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${ids.staleJitRun}::uuid
    `;
  });
  assert.equal(staleState?.status, "stale");

  const [binding] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    return transaction<{ id: string }[]>`
      SELECT id FROM public.tenant_auth_provider_bindings
      WHERE tenant_id = ${fixture.tenant}::uuid AND key = 'bounded_ldap'
    `;
  });
  assert(binding, "LDAP binding fixture is missing");

  const competingStarts = await Promise.allSettled([
    beginScheduledSync(
      ids.syncRunA,
      binding.id,
      ids.syncQueuedAuditA,
      ids.syncRequestA,
      ids.syncCorrelationA,
    ),
    beginScheduledSync(
      ids.syncRunB,
      binding.id,
      ids.syncQueuedAuditB,
      ids.syncRequestB,
      ids.syncCorrelationB,
    ),
  ]);
  const started = competingStarts.filter(
    (result): result is PromiseFulfilledResult<SyncStart[]> =>
      result.status === "fulfilled",
  );
  const rejectedStart = competingStarts.filter(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  assert.equal(started.length, 1);
  assert.equal(rejectedStart.length, 1);
  assertSqlState(rejectedStart[0]!.reason, "23505");
  const activeSyncRun = started[0]!.value[0]!.sync_run_id;

  const claimProofs = [
    { id: ids.syncClaimA, receipt: digests.syncClaimA },
    { id: ids.syncClaimB, receipt: digests.syncClaimB },
  ] as const;
  const competingClaims = await Promise.all(
    claimProofs.map((proof) => claimSync(proof.id, proof.receipt, 1)),
  );
  assert.deepEqual(
    competingClaims
      .map((rows) => rows.length)
      .toSorted((left, right) => left - right),
    [0, 1],
  );
  const winningClaimIndex = competingClaims.findIndex(
    (rows) => rows.length === 1,
  );
  const firstClaimProof = claimProofs[winningClaimIndex]!;
  const syncClaim = competingClaims[winningClaimIndex]![0]!;
  assert.equal(syncClaim.sync_run_id, activeSyncRun);
  assert.equal(syncClaim.tenant_id, fixture.tenant);
  assert.equal(syncClaim.run_version, 2);
  assert.equal(syncClaim.claim_fence, "1");
  assert(syncClaim.bind_secret_ciphertext.length >= 17);
  assert.equal(syncClaim.bind_secret_nonce.length, 12);
  assert(syncClaim.mapping_revisions.length > 0);
  assert.deepEqual(syncClaim.staged_observations, []);

  const [responseLostReplay] = await claimSync(
    firstClaimProof.id,
    firstClaimProof.receipt,
    1,
  );
  assert.equal(responseLostReplay?.sync_run_id, activeSyncRun);
  assert.equal(responseLostReplay?.claim_fence, syncClaim.claim_fence);
  assert.deepEqual(
    responseLostReplay?.mapping_revisions,
    syncClaim.mapping_revisions,
  );

  await new Promise((resolve) => setTimeout(resolve, 1_100));
  const [reclaimedClaim] = await claimSync(
    ids.syncClaimReclaim,
    digests.syncClaimReclaim,
  );
  assert.equal(reclaimedClaim?.sync_run_id, activeSyncRun);
  assert.equal(reclaimedClaim?.claim_fence, "2");
  assert.deepEqual(reclaimedClaim?.staged_observations, []);
  assert(reclaimedClaim, "expired LDAP sync run was not reclaimed");

  await assert.rejects(
    admin.begin(async (transaction) => {
      await setWorkerContext(transaction, fixture.foreignTenant);
      await transaction`
        SELECT app.stage_tenant_ldap_sync_observation_v2(
          ${activeSyncRun}::uuid, ${firstClaimProof.id}::uuid,
          ${firstClaimProof.receipt}, ${syncClaim.claim_fence}::bigint,
          ${ids.syncObservation}::uuid, 1, 2,
          ${digests.subject}, ${digests.observation}
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );

  const stageObservation = async (): Promise<string | null | undefined> => {
    const [observation] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction);
      return transaction<{ external_identity_id: string | null }[]>`
        SELECT app.stage_tenant_ldap_sync_observation_v2(
          ${activeSyncRun}::uuid, ${reclaimedClaim.claim_id}::uuid,
          ${digests.syncClaimReclaim}, ${reclaimedClaim.claim_fence}::bigint,
          ${ids.syncObservation}::uuid, 1, 2,
          ${digests.subject}, ${digests.observation}
        ) AS external_identity_id
      `;
    });
    return observation?.external_identity_id;
  };
  assert.equal(await stageObservation(), fixture.externalIdentity);
  assert.equal(await stageObservation(), fixture.externalIdentity);

  const claimPlanningSnapshot = async () => {
    const [snapshot] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction, fixture.foreignTenant);
      return transaction<
        {
          tenant_id: string;
          external_identity_id: string | null;
          access_grant_id: string | null;
          access_grant_live: boolean;
          rules: unknown[];
        }[]
      >`
        SELECT * FROM app.claim_tenant_ldap_sync_observation_planning_v3(
          ${activeSyncRun}::uuid, ${ids.syncObservation}::uuid,
          ${reclaimedClaim.claim_id}::uuid, ${digests.syncClaimReclaim},
          ${reclaimedClaim.claim_fence}::bigint, ARRAY[2]::integer[],
          ARRAY[${digests.subject}::bytea]::bytea[]
        )
      `;
    });
    return snapshot;
  };
  for (const planningSnapshot of [
    await claimPlanningSnapshot(),
    await claimPlanningSnapshot(),
  ]) {
    assert.equal(planningSnapshot?.tenant_id, fixture.tenant);
    assert.equal(
      planningSnapshot?.external_identity_id,
      fixture.externalIdentity,
    );
    assert.equal(planningSnapshot?.access_grant_live, true);
    assert.equal(planningSnapshot?.access_grant_id, fixture.accessGrant);
    assert((planningSnapshot?.rules.length ?? 0) > 0);
  }

  const completePartialEnumeration = async (): Promise<
    SyncEnumeration | undefined
  > => {
    const [partial] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction);
      return transaction<SyncEnumeration[]>`
        SELECT * FROM app.complete_tenant_ldap_sync_enumeration_v3(
          ${activeSyncRun}::uuid, ${reclaimedClaim.claim_id}::uuid,
          ${digests.syncClaimReclaim}, ${reclaimedClaim.claim_fence}::bigint,
          2, false, true, ${digests.cursor},
          'result_truncated', ${ids.syncEnumerationAudit}::uuid,
          ${ids.syncEnumerationRequest}::uuid,
          ${ids.syncEnumerationCorrelation}::uuid,
          'Periapsis D5 security proof'
        )
      `;
    });
    return partial;
  };
  for (const partial of [
    await completePartialEnumeration(),
    await completePartialEnumeration(),
  ]) {
    assert.equal(partial?.status, "failed");
    assert.equal(partial?.version, 3);
    assert.equal(partial?.observed_count, 1);
    assert.equal(partial?.absence_allowed, false);
  }
  await assert.rejects(
    admin.begin(async (transaction) => {
      await setWorkerContext(transaction);
      await transaction`
        SELECT * FROM app.apply_tenant_ldap_sync_absence_chunk_v3(
          ${activeSyncRun}::uuid, ${reclaimedClaim.claim_id}::uuid,
          ${digests.syncClaimReclaim}, ${reclaimedClaim.claim_fence}::bigint,
          25, ${ids.syncAbsenceAudit}::uuid,
          uuidv7(), uuidv7(), 'Periapsis D5 security proof'
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const [retainedAccess] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    return transaction<{ ended: boolean }[]>`
      SELECT ended_at IS NOT NULL AS ended
      FROM public.tenant_ldap_provider_access_grants
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.accessGrant}::uuid
    `;
  });
  assert.equal(retainedAccess?.ended, false);

  await beginScheduledSync(
    ids.failedSyncRun,
    binding.id,
    ids.failedSyncQueuedAudit,
    ids.failedSyncRequest,
    ids.failedSyncCorrelation,
  );
  const [failedClaim] = await claimSync(
    ids.failedSyncClaim,
    digests.failedSyncClaim,
  );
  assert(failedClaim);
  assert.equal(failedClaim.sync_run_id, ids.failedSyncRun);
  const failSync = async (): Promise<SyncFailure | undefined> => {
    const [failure] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction);
      return transaction<SyncFailure[]>`
        SELECT * FROM app.fail_tenant_ldap_sync_run_v2(
          ${ids.failedSyncRun}::uuid, ${failedClaim.claim_id}::uuid,
          ${digests.failedSyncClaim}, ${failedClaim.claim_fence}::bigint,
          2, 'directory_error',
          ${ids.failedSyncAudit}::uuid, ${ids.failedSyncRequest}::uuid,
          ${ids.failedSyncCorrelation}::uuid,
          'Periapsis D5 security proof'
        )
      `;
    });
    return failure;
  };
  assert.deepEqual(await failSync(), {
    status: "failed",
    version: 3,
    replayed: false,
  });
  assert.deepEqual(await failSync(), {
    status: "failed",
    version: 3,
    replayed: true,
  });

  await beginScheduledSync(
    ids.completedSyncRun,
    binding.id,
    ids.completedSyncQueuedAudit,
    ids.completedSyncRequest,
    ids.completedSyncCorrelation,
  );
  const [completedClaim] = await claimSync(
    ids.completedSyncClaim,
    digests.completedSyncClaim,
  );
  assert(completedClaim);
  assert.equal(completedClaim.sync_run_id, ids.completedSyncRun);
  const finishEnumeration = async (): Promise<SyncEnumeration | undefined> => {
    const [completeEnumeration] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction);
      return transaction<SyncEnumeration[]>`
        SELECT * FROM app.complete_tenant_ldap_sync_enumeration_v3(
          ${ids.completedSyncRun}::uuid, ${completedClaim.claim_id}::uuid,
          ${digests.completedSyncClaim}, ${completedClaim.claim_fence}::bigint,
          2, true, false, NULL::bytea,
          NULL::text, ${ids.completedEnumerationAudit}::uuid,
          ${ids.completedEnumerationRequest}::uuid,
          ${ids.completedEnumerationCorrelation}::uuid,
          'Periapsis D5 security proof'
        )
      `;
    });
    return completeEnumeration;
  };
  for (const completeEnumeration of [
    await finishEnumeration(),
    await finishEnumeration(),
  ]) {
    assert.equal(completeEnumeration?.status, "applying");
    assert.equal(completeEnumeration?.version, 3);
    assert.equal(completeEnumeration?.observed_count, 0);
    assert.equal(completeEnumeration?.absence_allowed, true);
  }
  const finishSync = async (): Promise<number | undefined> => {
    const [completed] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction);
      return transaction<{ version: number }[]>`
        SELECT app.complete_tenant_ldap_sync_run_v2(
          ${ids.completedSyncRun}::uuid, ${completedClaim.claim_id}::uuid,
          ${digests.completedSyncClaim}, ${completedClaim.claim_fence}::bigint,
          3, ${ids.completedSyncAudit}::uuid,
          ${ids.completedSyncRequest}::uuid,
          ${ids.completedSyncCorrelation}::uuid,
          'Periapsis D5 security proof'
        ) AS version
      `;
    });
    return completed?.version;
  };
  assert.equal(await finishSync(), 4);
  assert.equal(await finishSync(), 4);

  await beginScheduledSync(
    ids.staleSyncRun,
    binding.id,
    ids.staleSyncQueuedAudit,
    ids.staleSyncRequest,
    ids.staleSyncCorrelation,
  );
  const [staleSyncClaim] = await claimSync(
    ids.staleSyncClaim,
    digests.staleSyncClaim,
  );
  assert(staleSyncClaim);
  assert.equal(staleSyncClaim.sync_run_id, ids.staleSyncRun);
  await admin.begin(async (transaction) => {
    await setWorkerContext(transaction, fixture.foreignTenant);
    await transaction`
      SELECT app.stage_tenant_ldap_sync_observation_v2(
        ${ids.staleSyncRun}::uuid, ${staleSyncClaim.claim_id}::uuid,
        ${digests.staleSyncClaim}, ${staleSyncClaim.claim_fence}::bigint,
        ${ids.staleSyncObservation}::uuid, 1, 2,
        ${digests.subject}, ${digests.observation}
      )
    `;
  });
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_ldap_provider_configs
      SET sync_interval_seconds = CASE
            WHEN sync_interval_seconds = 300 THEN 301 ELSE 300
          END,
          version = version + 1,
          updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND provider_id = ${fixture.provider}::uuid
    `;
  });
  await assert.rejects(
    admin.begin(async (transaction) => {
      await setWorkerContext(transaction, fixture.foreignTenant);
      await transaction`
        SELECT * FROM app.claim_tenant_ldap_sync_observation_planning_v3(
          ${ids.staleSyncRun}::uuid, ${ids.staleSyncObservation}::uuid,
          ${staleSyncClaim.claim_id}::uuid, ${digests.staleSyncClaim},
          ${staleSyncClaim.claim_fence}::bigint, ARRAY[2]::integer[],
          ARRAY[${digests.subject}::bytea]::bytea[]
        )
      `;
    }),
    (error: unknown) => assertSqlState(error, "40001"),
  );
  const failStaleSync = async (): Promise<SyncFailure | undefined> => {
    const [failure] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction, fixture.foreignTenant);
      return transaction<SyncFailure[]>`
        SELECT * FROM app.fail_tenant_ldap_sync_run_v2(
          ${ids.staleSyncRun}::uuid, ${staleSyncClaim.claim_id}::uuid,
          ${digests.staleSyncClaim}, ${staleSyncClaim.claim_fence}::bigint,
          2, 'planning_error', ${ids.staleSyncAudit}::uuid,
          ${ids.staleSyncRequest}::uuid, ${ids.staleSyncCorrelation}::uuid,
          'Periapsis D5 security proof'
        )
      `;
    });
    return failure;
  };
  assert.deepEqual(await failStaleSync(), {
    status: "stale",
    version: 3,
    replayed: false,
  });
  assert.deepEqual(await failStaleSync(), {
    status: "stale",
    version: 3,
    replayed: true,
  });

  await beginScheduledSync(
    ids.accessStateSyncRun,
    binding.id,
    ids.accessStateSyncQueuedAudit,
    ids.accessStateSyncRequest,
    ids.accessStateSyncCorrelation,
  );
  const [accessStateClaim] = await claimSync(
    ids.accessStateSyncClaim,
    digests.accessStateSyncClaim,
  );
  assert(accessStateClaim);
  assert.equal(accessStateClaim.sync_run_id, ids.accessStateSyncRun);
  await admin.begin(async (transaction) => {
    await setWorkerContext(transaction, fixture.foreignTenant);
    await transaction`
      SELECT app.stage_tenant_ldap_sync_observation_v2(
        ${ids.accessStateSyncRun}::uuid,
        ${accessStateClaim.claim_id}::uuid,
        ${digests.accessStateSyncClaim},
        ${accessStateClaim.claim_fence}::bigint,
        ${ids.absentSyncObservation}::uuid, 1, 2,
        ${digests.absentSubject}, ${digests.absentObservation}
      )
    `;
    await transaction`
      SELECT app.stage_tenant_ldap_sync_observation_v2(
        ${ids.accessStateSyncRun}::uuid,
        ${accessStateClaim.claim_id}::uuid,
        ${digests.accessStateSyncClaim},
        ${accessStateClaim.claim_fence}::bigint,
        ${ids.revokedSyncObservation}::uuid, 2, 2,
        ${digests.subject}, ${digests.revokedObservation}
      )
    `;
  });
  const claimAccessStatePlanning = async (
    observationId: string,
    subjectDigest: Buffer,
  ): Promise<
    | {
        tenant_id: string;
        external_identity_id: string | null;
        access_grant_id: string | null;
        access_grant_live: boolean;
      }
    | undefined
  > => {
    const [snapshot] = await admin.begin(async (transaction) => {
      await setWorkerContext(transaction, fixture.foreignTenant);
      return transaction<
        {
          tenant_id: string;
          external_identity_id: string | null;
          access_grant_id: string | null;
          access_grant_live: boolean;
        }[]
      >`
        SELECT tenant_id, external_identity_id, access_grant_id,
               access_grant_live
        FROM app.claim_tenant_ldap_sync_observation_planning_v3(
          ${ids.accessStateSyncRun}::uuid, ${observationId}::uuid,
          ${accessStateClaim.claim_id}::uuid,
          ${digests.accessStateSyncClaim},
          ${accessStateClaim.claim_fence}::bigint,
          ARRAY[2]::integer[], ARRAY[${subjectDigest}::bytea]::bytea[]
        )
      `;
    });
    return snapshot;
  };
  for (const absentPlanning of [
    await claimAccessStatePlanning(
      ids.absentSyncObservation,
      digests.absentSubject,
    ),
    await claimAccessStatePlanning(
      ids.absentSyncObservation,
      digests.absentSubject,
    ),
  ]) {
    assert.equal(absentPlanning?.tenant_id, fixture.tenant);
    assert.equal(absentPlanning?.external_identity_id, null);
    assert.equal(absentPlanning?.access_grant_live, false);
    assert.equal(absentPlanning?.access_grant_id, null);
  }
  await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    await transaction`
      UPDATE public.tenant_ldap_provider_access_grants
      SET ended_at = transaction_timestamp(), end_reason = 'security proof',
          version = version + 1, updated_at = transaction_timestamp()
      WHERE tenant_id = ${fixture.tenant}::uuid
        AND id = ${fixture.accessGrant}::uuid
    `;
  });
  for (const revokedPlanning of [
    await claimAccessStatePlanning(ids.revokedSyncObservation, digests.subject),
    await claimAccessStatePlanning(ids.revokedSyncObservation, digests.subject),
  ]) {
    assert.equal(revokedPlanning?.tenant_id, fixture.tenant);
    assert.equal(
      revokedPlanning?.external_identity_id,
      fixture.externalIdentity,
    );
    assert.equal(revokedPlanning?.access_grant_live, false);
    assert.equal(revokedPlanning?.access_grant_id, null);
  }
  const [accessStateFailure] = await admin.begin(async (transaction) => {
    await setWorkerContext(transaction, fixture.foreignTenant);
    return transaction<SyncFailure[]>`
      SELECT * FROM app.fail_tenant_ldap_sync_run_v2(
        ${ids.accessStateSyncRun}::uuid,
        ${accessStateClaim.claim_id}::uuid,
        ${digests.accessStateSyncClaim},
        ${accessStateClaim.claim_fence}::bigint, 2, 'planning_error',
        ${ids.accessStateSyncAudit}::uuid,
        ${ids.accessStateSyncFailRequest}::uuid,
        ${ids.accessStateSyncFailCorrelation}::uuid,
        'Periapsis D5 security proof'
      )
    `;
  });
  assert.equal(accessStateFailure?.status, "failed");

  const [rawAuditLeak] = await admin.begin(async (transaction) => {
    await transaction.unsafe('SET LOCAL ROLE "periapsis_migrator"');
    return transaction<{ count: number }[]>`
      SELECT count(*)::integer AS count
      FROM public.audit_events AS audit
      WHERE audit.tenant_id = ${fixture.tenant}::uuid
        AND audit.action LIKE 'tenant.identity.ldap_%'
        AND audit.metadata::text ~* (
          'subject|ciphertext|nonce|password|secret|bind_dn|directory_value|'
          'distinguished_name|profile|email|username|first_name|last_name|'
          'display_name|filter|cursor'
        )
    `;
  });
  assert.equal(rawAuditLeak?.count, 0);
} finally {
  await admin.end();
}
