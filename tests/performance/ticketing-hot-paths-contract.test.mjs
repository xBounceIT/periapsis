import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { phaseOneFixtures } from "../../packages/db/src/testing/fixtures.ts";

const repositoryRoot = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../..",
);

const readRepositoryFile = (path) =>
  readFile(resolve(repositoryRoot, path), "utf8");
const normalizeSql = (sql) => sql.replace(/\s+/gu, " ").trim();

test("100k fixture is fixed-size and cannot mask schema performance gaps", async () => {
  const fixture = await readRepositoryFile(
    "tests/performance/ticketing-100k-fixture.sql",
  );
  assert.match(
    fixture,
    /generate_series\(batch_start, least\(batch_start \+ 999, 99999\)\)/,
  );
  assert.match(fixture, /count\(\*\).*public\.alerts[\s\S]*<> 100000/);
  assert.match(fixture, /count\(\*\).*public\.cases[\s\S]*<> 100000/);
  for (const forbidden of [
    /\bCREATE\s+(?:UNIQUE\s+)?INDEX\b/i,
    /\bALTER\s+TABLE\b/i,
    /\bDISABLE\s+TRIGGER\b/i,
    /\bsession_replication_role\b/i,
    /\bSET\s+(?:LOCAL\s+)?row_security\s*=\s*off\b/i,
  ]) {
    assert.doesNotMatch(fixture, forbidden);
  }
  assert.match(fixture, /current_database\(\).*periapsis_performance_/s);
  assert.match(fixture, /current_setting\('server_version_num'\).*180006/s);
});

test("fixture preserves the exact canonical seed and admits current numbering", async () => {
  const fixture = await readRepositoryFile(
    "tests/performance/ticketing-100k-fixture.sql",
  );
  const guard = fixture.slice(
    fixture.indexOf("DO $fixture_guard$"),
    fixture.indexOf("$fixture_guard$;"),
  );
  assert.match(guard, /existing_alerts <> 1/);
  assert.match(guard, /existing_cases <> 1/);
  assert.ok(guard.includes(phaseOneFixtures.alerts.acme));
  assert.ok(guard.includes(phaseOneFixtures.demo.case));
  assert.match(
    guard,
    /set_config\('app\.tenant_id', target_tenant::text, false\)/,
  );
  assert.match(
    guard,
    /set_config\('app\.user_id', administrator_user::text, false\)/,
  );
  assert.match(guard, /set_config\('app\.service_account_id', '', false\)/);
  assert.deepEqual(
    [...fixture.matchAll(/FOR batch_start IN 1\.\.99999 BY (\d+) LOOP/gu)].map(
      (match) => Number(match[1]),
    ),
    [1_000, 1_000],
  );
  assert.equal(
    [...fixture.matchAll(/transaction_timestamp\(\) AS occurred_at/g)].length,
    2,
  );
  assert.doesNotMatch(
    fixture,
    /\b(?:DELETE\s+FROM\s+public\.(?:alerts|cases)|TRUNCATE)\b/iu,
  );
  assert.doesNotMatch(fixture, /fixture\.(?:active_state|terminal_state)/u);
  assert.match(fixture, /performance fixture state distribution drifted/u);
  assert.match(
    fixture,
    /performance fixture ticket numbering receipt drifted/u,
  );
  assert.equal(
    [...fixture.matchAll(/receipt\.number = ticket\.number/gu)].length,
    2,
  );
});

test("ticket fixture commits bounded numbering batches without losing rows", async () => {
  const fixture = await readRepositoryFile(
    "tests/performance/ticketing-100k-fixture.sql",
  );
  for (const root of ["alert", "case"]) {
    const start = fixture.indexOf(`DO $load_${root}_batches$`);
    const end = fixture.indexOf(`$load_${root}_batches$;`, start);
    assert.ok(start >= 0 && end > start);
    const batch = fixture.slice(start, end);
    assert.match(batch, /FOR batch_start IN 1\.\.99999 BY 1000 LOOP/u);
    assert.match(
      batch,
      /FROM generate_series\(batch_start, least\(batch_start \+ 999, 99999\)\) AS series/u,
    );
    assert.match(batch, /CROSS JOIN fixture;\s+COMMIT;[\s\S]*END LOOP;/u);
  }
  let generatedCount = 0;
  for (let start = 1; start <= 99_999; start += 1_000) {
    const count = Math.min(start + 999, 99_999) - start + 1;
    assert.ok(count > 0 && count <= 1_000);
    generatedCount += count;
  }
  assert.equal(generatedCount + 1, 100_000);
});

test("selective-state plans require interleaved canonical transitions and exact populations", async () => {
  const [fixture, runner] = await Promise.all([
    readRepositoryFile("tests/performance/ticketing-100k-fixture.sql"),
    readRepositoryFile("scripts/performance/run-ticketing-hot-paths.mjs"),
  ]);
  const batch = fixture.slice(
    fixture.indexOf("DO $load_alert_batches$"),
    fixture.indexOf("$load_alert_batches$;"),
  );
  assert.match(batch, /COMMIT;\s+SET LOCAL ROLE periapsis_api;/u);
  assert.match(batch, /app\.apply_tenant_ticket_mutation_v2\(/u);
  assert.match(batch, /'transition', 1, 2/u);
  assert.match(batch, /ticket\.assigned_team_id IS NULL/u);
  assert.match(batch, /LIMIT 10/u);
  assert.match(batch, /transitioned_rows <> 10/u);
  assert.doesNotMatch(fixture, /UPDATE public\.alerts|DISABLE TRIGGER/u);
  assert.match(fixture, /transitioned_count <> 1000/u);
  assert.match(fixture, /transitioned_critical_count <> 200/u);
  assert.match(fixture, /batch_count <> 100/u);
  assert.match(fixture, /last_update >= next_created_at/u);
  assert.match(runner, /workflowStateLiteral\(value\.activeState\)/u);
  assert.match(runner, /value\.activeStateCount !== 1_000/u);
  assert.match(runner, /value\.activeCriticalCount !== 200/u);
  assert.equal(
    [...runner.matchAll(/workflowStateLiteral\(facts\.activeState\)/gu)].length,
    2,
  );
});

test("Alert setup refreshes trigger-ingress statistics between committed batches", async () => {
  const fixture = await readRepositoryFile(
    "tests/performance/ticketing-100k-fixture.sql",
  );
  const batch = fixture.slice(
    fixture.indexOf("DO $load_alert_batches$"),
    fixture.indexOf("$load_alert_batches$;"),
  );
  assert.match(
    batch,
    /CROSS JOIN fixture;\s+COMMIT;[\s\S]*ANALYZE public\.sla_object_event_ingress;\s+END LOOP;/u,
  );
  assert.doesNotMatch(
    fixture,
    /\b(?:enable_seqscan|plan_cache_mode|autovacuum)\b/u,
  );
  assert.match(fixture, /SET statement_timeout = '15min';/u);
});

test("ingest detection time is bounded by the canonical transaction clock", async () => {
  const [runner, migration] = await Promise.all([
    readRepositoryFile("scripts/performance/run-ticketing-hot-paths.mjs"),
    readRepositoryFile(
      "packages/db/migrations/0086_ticketing_transaction_abi.sql",
    ),
  ]);
  const ingest = runner.slice(
    runner.indexOf("function ingestSql("),
    runner.indexOf("function claimBatchSql("),
  );
  assert.match(migration, /p_detected_at > transaction_timestamp\(\)/u);
  assert.match(ingest, /NULL, transaction_timestamp\(\),/u);
  assert.doesNotMatch(ingest, /clock_timestamp\(\)|statement_timestamp\(\)/u);
});

test("SLA benchmark matches the current worker claim eligibility and ABI", async () => {
  const [runner, migration, worker] = await Promise.all([
    readRepositoryFile("scripts/performance/run-ticketing-hot-paths.mjs"),
    readRepositoryFile(
      "packages/db/migrations/0205_sla_object_event_ingress.sql",
    ),
    readRepositoryFile("services/worker/internal/postgres/sla.go"),
  ]);
  const plan = runner.slice(
    runner.indexOf('name: "sla_worker_claim_candidates"'),
    runner.indexOf('name: "notification_fanout_claim_candidates"'),
  );
  const currentClaim = migration.slice(
    migration.indexOf("CREATE FUNCTION app.claim_sla_evaluation_jobs_v3("),
    migration.indexOf("ALTER FUNCTION app.claim_sla_evaluation_jobs_v3("),
  );
  const candidate = currentClaim.slice(
    currentClaim.indexOf("SELECT job.tenant_id, job.id"),
    currentClaim.indexOf("LIMIT p_batch_size") + "LIMIT p_batch_size".length,
  );
  const expected = normalizeSql(candidate)
    .replaceAll("p_observed_at", "${observedAtLiteral}")
    .replace("p_batch_size", "100");
  assert.ok(normalizeSql(plan).includes(expected));
  assert.match(worker, /app\.claim_sla_evaluation_jobs_v3\(/u);
  assert.match(runner, /runSlaWorker\("timers"/u);
  assert.doesNotMatch(runner, /app\.claim_sla_evaluation_jobs_v2\(/u);
});

test("runner exercises every required real PostgreSQL hot path", async () => {
  const runner = await readRepositoryFile(
    "scripts/performance/run-ticketing-hot-paths.mjs",
  );
  for (const operation of [
    "alert_updated_page",
    "alert_created_page",
    "case_updated_page",
    "alert_state_severity_page",
    "alert_state_page",
    "alert_severity_page",
    "alert_assignee_page",
    "alert_custom_integer_filter",
    "alert_sla_due_sort",
    "sla_worker_claim_candidates",
    "notification_fanout_claim_candidates",
    "concurrent_ingest",
    "concurrent_claim",
    "claim_race",
    "sla_worker_claim",
    "notification_fanout_claim",
  ]) {
    assert.match(runner, new RegExp(`\\b${operation}\\b`));
  }
  for (const abi of [
    "app.create_tenant_alert_as_human_v3",
    "app.apply_tenant_ticket_mutation_v2",
    "app.claim_notification_fanout_batch_v1",
  ]) {
    assert.match(runner, new RegExp(abi.replaceAll(".", "\\.")));
  }
  assert.match(
    runner,
    /EXPLAIN \(ANALYZE, BUFFERS, WAL, SETTINGS, SUMMARY, FORMAT JSON\)/,
  );
  assert.match(runner, /ticket\.state_key = ANY/);
  assert.doesNotMatch(runner, /ticket\.status\s*=/);
  assert.match(runner, /SET LOCAL ROLE periapsis_api/);
  assert.match(runner, /app\.ticket_service_account_attributions_v1/);
  assert.match(runner, /app\.ticket_sla_instant_sort_values_v1/);
  assert.match(runner, /apiSlaProjectionValues !== 99_999/);
  assert.match(
    runner,
    /apiSlaProjectionValues = parseSingleInteger\([\s\S]{0,300}API SLA projection cardinality/,
  );
  assert.doesNotMatch(runner, /\boperationCount\(/);
  assert.match(runner, /projected\.instant_value IS NOT NULL/);
  assert.doesNotMatch(runner, /LEFT JOIN public\.tenant_service_accounts/);
  assert.doesNotMatch(
    runner,
    /LEFT JOIN public\.sla_materialized_column_values AS saved_view_sort/,
  );
  for (const bypass of [
    /SET LOCAL ROLE periapsis_migrator/,
    /row_security\s*=\s*off/,
    /enable_seqscan\s*=\s*off/,
    /session_replication_role/,
  ]) {
    assert.doesNotMatch(runner, bypass);
  }
  assert.match(
    runner,
    /name: "alert_updated_page"[\s\S]*ORDER BY ticket\.updated_at DESC, ticket\.id DESC/,
  );
  assert.match(
    runner,
    /name: "case_updated_page"[\s\S]*caseProjection\(facts\)[\s\S]*ORDER BY ticket\.updated_at DESC, ticket\.id DESC/,
  );
  assert.match(runner, /periapsis_sla_worker_owner/);
  assert.match(runner, /periapsis_notification_dispatch_owner/);
  assert.match(runner, /DROP DATABASE .* WITH \(FORCE\)/);
  assert.match(runner, /assertDisposableDatabaseName/);
  assert.match(runner, /assertPostgresVersion/);
  assert.match(runner, /preflightPsqlExecutable/);
  assert.doesNotMatch(
    runner,
    /PERIAPSIS_PERFORMANCE_PSQL\?\.trim\(\) \|\| "psql"/,
  );
  assert.match(runner, /assertFreshClusterFacts/);
  assert.match(runner, /assertExpectedClusterDataDirectory/);
  assert.match(runner, /PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY/);
  assert.match(runner, /current_setting\('data_directory'\)/);
  assert.match(runner, /migrationFingerprint/);
  assert.match(runner, /WHERE NOT database\.datistemplate/);
  assert.match(runner, /userRelationCount/);
  assert.match(runner, /host\(inet_server_addr\(\)\)/);
  assert.match(runner, /Promise\.allSettled\(/);
  assert.match(runner, /distinctOperations/);
  assert.match(runner, /committedPostcondition/);
  assert.match(runner, /passwordlessConnectionUrl\(connectionUrl\)/);
  assert.match(runner, /PGPASSFILE/);
  assert.match(runner, /wait_event = 'PgSleep'/);
  assert.match(runner, /attemptSkewMs/);
  assert.match(runner, /catchableShutdownSignals\(\)/);
  assert.match(runner, /process\.on\(signal, handler\)/);
  assert.doesNotMatch(runner, /process\.once\(signal, handler\)/);
  assert.match(runner, /activePsqlChildren/);
  assert.match(runner, /gate and evidence write failed/);
  assert.match(runner, /pg_terminate_backend\(matching\.pid, 5000\)/);
  assert.match(runner, /createApplicationName/);
  assert.match(runner, /finalDatabaseCount/);
  assert.match(runner, /cleanupError\?\.cleanupEvidence\?\.status/);
  assert.match(
    runner,
    /evidence\.cleanupEvidence = cleanupError\.cleanupEvidence/,
  );
  assert.match(runner, /await handle\.sync\(\)/);
  assert.match(runner, /await publishFileNoReplace\(staging, target\)/);
  assert.doesNotMatch(
    runner,
    /catch \(cleanupError\)[\s\S]{0,200}failureStage = "cleanup"/,
  );
  assert.match(
    runner,
    /job\.available_at <= \$\{observedAtLiteral\}[\s\S]*job\.lease_expires_at <= \$\{observedAtLiteral\}/,
  );
  assert.match(
    runner,
    /event\.available_at <= \$\{observedAtLiteral\}[\s\S]*event\.lease_until <= \$\{observedAtLiteral\}/,
  );
});

test("Windows invocation aborts before the gate when cluster startup fails", async () => {
  const runbook = await readRepositoryFile(
    "docs/operations/performance-gates.md",
  );
  assert.match(
    runbook,
    /initdb\.exe[\s\S]{0,300}if \(\$LASTEXITCODE -ne 0\) \{ exit \$LASTEXITCODE \}/,
  );
  assert.match(runbook, /\$serverStarted = \$false/);
  assert.match(
    runbook,
    /\$starter\.WaitForExit\(\)\s+\$startExit = \$starter\.ExitCode[\s\S]{0,200}if \(\$startExit -eq 0\)/,
  );
  assert.match(
    runbook,
    /Start-Process -FilePath "\$pgBin\\pg_ctl\.exe" -WindowStyle Hidden -PassThru/u,
  );
  assert.match(
    runbook,
    /-RedirectStandardOutput "\$dataDir\\pg-start.stdout.log"/u,
  );
  assert.match(
    runbook,
    /if \(\$serverStarted\) \{[\s\S]{0,200}pg_ctl\.exe[\s\S]{0,100}-m fast -w stop/,
  );
  assert.match(
    runbook,
    /PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY = \$expectedDataDirectory/,
  );
  assert.match(runbook, /-c timezone=UTC/);
});

test("UTC is a server prerequisite, not a persistent role or database mutation", async () => {
  const runner = await readRepositoryFile(
    "scripts/performance/run-ticketing-hot-paths.mjs",
  );
  assert.match(runner, /'serverTimezone', current_setting\('TimeZone'\)/);
  assert.match(
    runner,
    /'databaseRoleSettingCount',[\s\S]{0,120}FROM pg_catalog\.pg_db_role_setting/,
  );
  assert.ok(
    runner.indexOf("assertFreshClusterFacts(rawClusterFacts)") <
      runner.indexOf("databaseCreationAttempted = true"),
  );
  assert.doesNotMatch(runner, /\bALTER\s+(?:DATABASE|ROLE)\b/iu);
  assert.match(runner, /value\.databaseTimezone !== "UTC"/);
});

test("independent claim partition covers every worker evenly", async () => {
  const runner = await readRepositoryFile(
    "scripts/performance/run-ticketing-hot-paths.mjs",
  );
  assert.match(
    runner,
    /\(\(right\(ticket\.external_id, 6\)::integer \/ 10\) - 1\) % \$\{workerCount\} = \$\{worker\}/,
  );
  const workerCount = 8;
  const candidateCounts = Array.from({ length: workerCount }, () => 0);
  for (let suffix = 10; suffix <= 99_999; suffix += 10) {
    candidateCounts[(suffix / 10 - 1) % workerCount] += 1;
  }
  assert.deepEqual(
    candidateCounts,
    [1_250, 1_250, 1_250, 1_250, 1_250, 1_250, 1_250, 1_249],
  );
  assert.ok(candidateCounts.every((count) => count >= 20));
});

test("database package commands run in a killable tracked process tree", async () => {
  const [runner, trackedCommand, childLifecycle, postgresCredential] =
    await Promise.all([
      readRepositoryFile("scripts/performance/run-ticketing-hot-paths.mjs"),
      readRepositoryFile("scripts/performance/tracked-command.mjs"),
      readRepositoryFile("scripts/performance/child-lifecycle.mjs"),
      readRepositoryFile("scripts/performance/postgres-credential.mjs"),
    ]);
  assert.match(runner, /await runTrackedCommand\(command, args/);
  assert.match(runner, /requireFromHarness\.resolve\("tsx\/cli"/);
  assert.doesNotMatch(runner, /cmd\.exe|corepack[^\n]*db:migrate/);
  assert.match(runner, /terminateActiveProcessTrees\(\)/);
  assert.match(runner, /await terminateAndAwaitActiveProcessTrees\(\)/);
  assert.match(runner, /processTreeQuiescenceEstablished/);
  assert.match(trackedCommand, /detached: true/);
  assert.match(trackedCommand, /windowsTaskkillPath\(systemRoot\)/);
  assert.match(trackedCommand, /"\/T", "\/F"/);
  assert.match(trackedCommand, /result\.status !== 0/);
  assert.match(runner, /preflightWindowsSystemTools\(\)/);
  assert.match(runner, /windowsSystemTools\.whoami/);
  assert.match(runner, /windowsSystemTools\.icacls/);
  assert.doesNotMatch(runner, /runSync\("(?:whoami|icacls)\.exe"/);
  assert.match(runner, /trackChildUntilClose\(child, activePsqlChildren\)/);
  assert.doesNotMatch(
    runner,
    /child\.once\("error"[\s\S]{0,300}activePsqlChildren\.delete/,
  );
  assert.match(
    runner,
    /terminateAndAwaitActiveChildren\([\s\S]{0,100}activePsqlChildren/,
  );
  assert.match(
    runner,
    /cleanupClientsQuiesced[\s\S]*databaseCreationAttempted && cleanupClientsQuiesced/,
  );
  assert.match(runner, /blockedCleanupIdentifiers/);
  assert.match(runner, /active psql PIDs/);
  assert.match(runner, /active tracked process-tree PIDs/);
  assert.match(runner, /credential directory/);
  assert.match(runner, /credentialFromPreparationError/);
  assert.match(runner, /temporary_pgpass_setup_failed/);
  assert.match(childLifecycle, /child\.once\("close"/);
  assert.match(childLifecycle, /activeChildren\.delete\(child\)/);
  assert.match(childLifecycle, /activeChildren\.size !== 0/);
  assert.match(
    trackedCommand,
    /process\.kill\(-entry\.child\.pid, "SIGKILL"\)/,
  );
  assert.match(trackedCommand, /closeDeadlineExpired/);
  assert.match(trackedCommand, /detachUnquiescedProcessTree/);
  assert.match(postgresCredential, /postgresCredential/);
  assert.match(postgresCredential, /credentialCleanupEvidence/);
  assert.match(postgresCredential, /"not_present"/);
});

test("both claim workloads use the current backend ABI, never the retired entrypoint", async () => {
  const [runner, backend] = await Promise.all([
    readRepositoryFile("scripts/performance/run-ticketing-hot-paths.mjs"),
    readRepositoryFile(
      "services/api/internal/postgres/ticketing_repository.go",
    ),
  ]);
  assert.match(backend, /FROM app\.apply_tenant_ticket_mutation_v2\(/u);
  assert.equal(
    [...runner.matchAll(/app\.apply_tenant_ticket_mutation_v2\(/gu)].length,
    2,
  );
  assert.doesNotMatch(runner, /app\.apply_tenant_ticket_mutation_v1\b/u);
});

test("required query indexes and mutation ABIs exist in the canonical bundle", async () => {
  const schemaDirectory = resolve(repositoryRoot, "packages/db/src/schema");
  const schemaNames = (await readdir(schemaDirectory))
    .filter((name) => name.endsWith(".ts"))
    .toSorted();
  const canonicalSchema = (
    await Promise.all(
      schemaNames.map((name) =>
        readFile(resolve(schemaDirectory, name), "utf8"),
      ),
    )
  ).join("\n");
  const migrationsDirectory = resolve(repositoryRoot, "packages/db/migrations");
  const migrationNames = (await readdir(migrationsDirectory))
    .filter((name) => /^\d{4}_.+\.sql$/.test(name))
    .toSorted();
  assert.ok(migrationNames.length > 0);
  const migrationBundle = (
    await Promise.all(
      migrationNames.map((name) =>
        readFile(resolve(migrationsDirectory, name), "utf8"),
      ),
    )
  ).join("\n");
  for (const index of [
    "alerts_tenant_created_idx",
    "alerts_tenant_updated_idx",
    "alerts_tenant_state_priority_idx",
    "alerts_tenant_assignment_idx",
    "cases_tenant_updated_idx",
    "custom_field_values_definition_integer_idx",
    "sla_materialized_projection_instant_sort_idx",
    "sla_evaluation_jobs_claim_idx",
    "outbox_events_dequeue_idx",
  ]) {
    assert.match(canonicalSchema, new RegExp(`index\\(\\"${index}\\"\\)`));
  }
  for (const abi of [
    "app.create_tenant_alert_as_human_v3",
    "app.apply_tenant_ticket_mutation_v2",
    "app.claim_sla_evaluation_jobs_v2",
    "app.claim_notification_fanout_batch_v1",
  ]) {
    assert.match(migrationBundle, new RegExp(abi.replaceAll(".", "\\.")));
  }
});
