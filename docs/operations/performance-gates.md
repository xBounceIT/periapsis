# Ticketing performance gates

Status: harness and scheduled workflow implemented; retained candidate reference run pending

The ticketing performance gate is a real PostgreSQL 18.6 workload. It creates a
fresh disposable database, applies the canonical migrations and seed, loads
exactly 100,000 Alerts and 100,000 Cases, measures the hot paths, writes
sanitized JSON evidence, and drops the database after it proves every owned
client has quiesced. If client quiescence cannot be proven, it fails closed and
retains the database and credential boundary for explicit recovery. An
in-memory substitute is not a valid result.

## Current local diagnostic evidence

The latest full native run on 2026-09-05 is retained as
`tmp/performance/periapsis_performance_1788636376158_54b2296ad3c9.json`.
It passes full fixture validation and processes all 101,003 immutable ingress events
through the real SLA worker (1,011 batches, 508.539 seconds, zero retry/dead-letter/fence
loss). Snapshot hashes remain stable; the actual API SLA projection contains 99,999
generated values, with 1,000 completed and 98,999 running metrics. SQL fixture setup took
255.244 seconds. These setup durations are separate from measured query/load budgets.

Four plans passed. The fifth, `alert_state_page`, returned 101 rows in 10.832 ms with
2,984 shared blocks, zero temporary blocks and no Alert sequential scan or disk sort.
It failed only the exact `alerts_tenant_created_idx` assertion. The real plan instead
uses `alerts_tenant_state_priority_idx` with tenant and state index conditions, reads
the fixture's verified 1,000 state matches, and performs an in-memory top-N sort by
created time and ID. Both indexes match legitimate access paths for the backend query;
the assertion must account for selectivity without forcing the planner or altering the
dataset. The original artifact remains failed. Remaining plans and concurrent loads
were not executed. Database and worker-credential cleanup succeeded, the owned server
stopped, and the outer completion proof records stable source hashes. This is native
Windows/loopback-trust evidence, not a reference-host or Docker result.

The state-only gate now requires a contributing `alerts` Index Scan or Index Only Scan
using one of those two exact indexes. An index name from another relation, a dead or
zero-row branch, an unbound bitmap scan, or malformed alternatives cannot satisfy it.
Only this gate admits alternatives. All latency, planning, buffer, row-window, spill,
sequential-scan, tenant/RLS, SQL, fixture and planner controls are unchanged. The full
performance contract suite passes 96 tests, including the alternative-index regression
and fixed-budget checks for all 11 plan gates:
`.tmp/performance-plan-alternatives-all-final-20260905.log`.
A fresh full benchmark is still required; changing the checker does not convert the
retained failed run into an accepted result.

### Earlier diagnostic sequence

The native Windows PostgreSQL 18.6 run on 2026-09-05 failed before loading data:
`tmp/performance/periapsis_performance_1788622712967_ec28c5ab94d1.json` records
migration 0183 rejecting the predecessor readiness source hash. A controlled comparison
through migrations 0181 and 0182 used identical journal prefixes, separate fresh clusters
and UTC sessions. The only extra dependency-transcript entry was the harness's persistent
database `TimeZone=UTC` setting. Removing only that entry from the in-memory comparison
restored the exact control digest; the predecessor source differed only by the embedded
digest. Both diagnostic clusters are stopped and their data/logs retained under
`C:/Users/dange/AppData/Local/Temp/periapsis-v6-timezone-cause-ae1df089cc834be7b61b154e941094c4/`.
No migration or readiness function was changed.

The harness now requires server-level UTC and no database/role settings before database
creation. It also excludes inherited `DATABASE_URL_FILE` without reading it: the canonical
migrate/seed resolver gives that file precedence over `DATABASE_URL`, so retaining it
could redirect those subprocesses outside the preflighted target. The five RED harness
checks now pass with the complete 45-test suite (`.tmp/performance-utc-boundary-green.log`).
Two additional real preflight runs reject a non-UTC server and a persistent UTC database
setting before creating any database or application role (`failureStage=server_preflight`,
`cleanup=not_created`). Their stopped isolated cluster and proof are retained under
`C:/Users/dange/AppData/Local/Temp/periapsis-performance-preflight-negative-bc0cc2c7b157490c9554172818ada476/`.

The subsequent fresh run passed all migrations and seed even with an intentionally
nonexistent inherited URL-file path, proving that override is not consumed. It then failed
at fixture setup because the fixture expects zero Cases but the canonical seed now creates
a demo Case. Evidence: `tmp/performance/periapsis_performance_1788624313525_082d82ba29f3.json`.
The disposable database was dropped after client quiescence and its server stopped;
source hashes remained stable. Exact 100k fixture alignment and a successful benchmark
were still open at that checkpoint. The fixture has since been aligned to the exact
canonical Alert/Case seed identities and adds 99,999 records of each type. Its dedicated
psql session establishes the tenant/user context required by numbering triggers; generated
creation times no longer precede the active policy publication. Every resulting ticket
must have its exact canonical numbering receipt. Generated Alerts remain in the initial
workflow state enforced by creation, with matching `new` status; severity and assignment
distributions are retained. No triggers, numbering policies, indexes or existing seed
records are bypassed or removed.

The next run (`tmp/performance/periapsis_performance_1788625605815_d2069468257b.json`)
reached ticket insertion but exhausted shared lock memory: one transaction held a numbering
advisory lock for each of 99,999 new tickets. Fixture setup now commits at most 1,000 tickets
per batch. This uses transaction control in top-level `DO` blocks, as supported by
[PostgreSQL 18](https://www.postgresql.org/docs/18/plpgsql-transactions.html); invoke the
fixture through the harness's autocommit psql file path, not a wrapping transaction.
It changes neither server lock limits nor production numbering locks, and still requires
exactly 100,000 tickets per kind and all numbering receipts.

The batched run (`tmp/performance/periapsis_performance_1788626374156_43e3e5a7119c.json`)
then reached the 15-minute fixture timeout inside the SLA ingress creation trigger, before
any query or load measurement. Cleanup dropped its disposable database, stopped its owned
server, and preserved unchanged source hashes. A controlled pair of fresh canonical
template clones loaded 9,999 synthetic Alerts each with all triggers intact. Refreshing
only `sla_object_event_ingress` statistics between committed batches reduced cumulative
`private_enqueue_sla_object_event_v1` time from 14,829.325 ms to 6,217.792 ms. Both clones
were dropped; the template remained at 230 migrations and zero tenants. The bounded
diagnostic and per-batch/function timings are retained in
`.tmp/profile-ticket-fixture-20260905.log`; this is setup evidence, not a release benchmark.

The fixture now runs `ANALYZE` on that trigger-populated table after each committed Alert
batch. This follows PostgreSQL's [bulk-load statistics guidance](https://www.postgresql.org/docs/18/populate.html#POPULATE-ANALYZE)
without adding indexes, changing planner controls, disabling triggers, or raising any
timeout/budget. The initial fix passed all 48 harness tests
(`.tmp/performance-ingress-statistics-green.log`), including the regression that failed
before the fix.

The retained pre-SLA-repair run (`tmp/performance/periapsis_performance_1788628846858_4b08c9ad04a9.json`)
passed migrations, seed, the full fixture and dataset verification: exactly 100,000
Alerts, 100,000 Cases, 100,000 custom-field values, 1,000 custom-field matches, 100,000
materialized SLA values visible through the API projection, and 10,000 jobs/events in each
explicit workload queue. The Alert updated page, Alert created page and Case updated page
passed their retained budgets at 5.918 ms, 5.706 ms and 2.458 ms respectively. These are native
local observations, not accepted reference-host performance. Cleanup dropped the database,
stopped its owned server and verified stable source hashes.

The overall run is still **failed** at `alert_state_severity_page`: its 101-row result took
9.841 ms and 1,910 shared blocks with no Alert sequential scan, but used
`alerts_tenant_updated_idx` rather than the required `alerts_tenant_state_priority_idx`.
The backend really filters state/severity and sorts by updated time; the required index
instead has `(tenant_id,state_key,priority,id)`. Do not force that plan or add an index
without evidence. That run's fixture was also insufficient for selective-state proof:
every generated Alert was in the initial state. The revised fixture performs ten canonical
API-role transitions after each creation batch, excluding team-assigned claim candidates.
It requires 1,000 active-state Alerts, including 200 critical Alerts, across 100 creation
batches, and verifies each batch's updates precede the next batch's creation. The runner
uses that selective state in both state-filter plans. A real two-batch proof passed all
scaled cardinality and chronology assertions (1,999 generated Alerts; 20 transitions,
four critical), with exact clone cleanup and an unchanged canonical template:
`.tmp/performance-selective-states-runtime.log`. This is not a new full 100k run. Reassess
index requirements against the real backend query after the complete revised fixture has
passed; the earlier failed artifact remains historical evidence.

Review of the subsequent claim workloads found a separate ABI drift: both still invoked
`apply_tenant_ticket_mutation_v1`, whose API grant migration 0204 revokes. They now invoke
the same v2 entrypoint as the backend, with unchanged arguments, CAS receipts and budgets.
The canonical 230-migration template confirms v1 denied/v2 granted; a fresh seeded clone
also proves the old call denied and the v2 claim committed with exact version/assignee/
claimant postconditions (`.tmp/performance-current-claim-abi-runtime.log`). The clone was
dropped and the untouched template retained. All 49 harness tests pass after the ABI fix
(`.tmp/performance-claim-abi-green.log`); the red regression retained two failures before it.
The full concurrent workload has not yet run successfully on this candidate.

Subsequent harness alignment also corrected ingest detection time from `clock_timestamp()`
to `transaction_timestamp()`: the canonical mutation rejects detection after transaction
start. A fresh seeded clone executing SQL extracted from the current runner proves the old
clock rejected with SQLSTATE 22023 and no rows committed, while the current clock creates
three distinct Alerts with detection no later than creation. Exact clone cleanup, unchanged
template and stable runner hash are retained in
`.tmp/performance-ingest-clock-runtime-20260905.log`.

The SLA candidate plan now matches the actual v3 worker query, including its instance join,
pending-object-event exclusion and `FOR UPDATE OF job SKIP LOCKED`; concurrent claims call
v3 directly. The previous plan omitted this barrier and could measure timers that the
worker could not acquire. All 52 harness tests pass, including exact normalized candidate
SQL comparison with migration 0205 (`.tmp/performance-current-ingest-sla-green.log`).
Timer fixture setup still needs canonical ingress settlement before its jobs become
eligible. Diagnostics exposed non-restorable seeded SLA documents and a worker failure
query referencing an unbound `trace` alias (SQLSTATE 42P01). The alias is now bound and
covered by a red/green repository regression; all worker Go tests pass. A real canonical
clone then proves four invalid projections are durably dead-lettered and two no-policy
events complete, without changing any frozen snapshot. The clone was dropped and the
230-migration/zero-tenant template retained. Evidence:
`.tmp/canonical-sla-deadletter-exact-green-20260905.log` and
`.tmp/worker-sla-failure-fix-all-20260905.log`.

The subsequent seed repair now generates publication documents and digests from the real
Go kernel, with identity-bound loading that needs no Go runtime in the database-task image.
`generate:sla-fixture` and `verify:sla-fixture` are wired into the root commands; both CI
generated-drift jobs run the check, standalone Go tests and vet. The initial real-worker
run then exposed two further production adapter defects: complete tenant calendar/column
inventories were passed unchanged to a strict policy-specific assignment planner, and
cursor timestamps were not normalized to UTC before restoring their kernel state.

Object-event planning now validates the whole inventory, selects the policy's dependencies,
and retains strict assignment/version/tenant/duplicate checks. Cursor decoding uses the
existing instant normalizers, preserving instant/precision and rejecting invalid history.
The fresh canonical proof in
`.tmp/canonical-sla-seed-twice-cursor-utc-green-20260905.log` passes two seed runs, seed audit,
five Alert no-policy completions, Case assignment and the following Case update. All seven
events complete with zero queued/leased/retry/dead-letter rows and unchanged snapshots;
13 source hashes remain stable, the exact clone is dropped and the template stays at
230 migrations and zero tenants. This is native bounded real-worker evidence, not a
100k performance result or a container acceptance run.

The performance preset now uses kernel-generated policy, metric and column documents,
published through the current v2 API-role entrypoints before source ticket creation.
The fixture contains no SLA table mutations. The runner settles ingress through the
compiled `performance-sla` adapter, then measures four concurrent real timer workers.
No numeric budget or required index was relaxed.

After the seed/worker fixes, both bounded harness proofs were repeated successfully with
the current seed: `.tmp/performance-ingest-clock-current-seed-20260905.log` and
`.tmp/performance-selective-states-current-seed-20260905.log`. They retain three valid
ingestions and the same 1,999-Alert/twenty-transition/four-critical two-batch distribution,
respectively; both disposable clones were dropped and the template remained unchanged.

The fixture preserves the seeded Alert's frozen no-policy decision and transition
completion effects. Its full-load assertions expect 99,999 performance SLA instances
and materialized values: 1,000 completed and 98,999 running metrics before timers.
All ingress must complete with unchanged assignment snapshots. Eligibility uses real
UTC microsecond wall time and the existing ingress barrier. Queue cardinalities come
from worker output, including the demo Case policy; the artificial 10,000-job population
is no longer a requirement.

A fresh bounded CLI proof passes two seed runs/audit, 104/104 ingress events and 100/100
real timer finalizations with database-verified receipts. A wrong data-directory pin
fails before claiming. Clone and URL file were removed, source hashes and the template
remained unchanged: `.tmp/performance-sla-cli-runtime-final-20260905.log`.
The first partial run of the actual fixture exposed a preset-event mismatch:
nonterminal transitions emit `ticket.<state_key>`, not `ticket.transitioned`.
Both generated presets now explicitly declare the matching `ticket.in_progress` key.
This does not establish a successful 100k result.

The corrected actual fixture passes on a fresh native clone with two Alert batches:
1,999 new Alerts and twenty canonical transitions, all 2,023 ingress events, unchanged
snapshots, 1,999 instances/materialized columns, 1,979 running/twenty completed metrics,
and seed Alert no-policy preservation. The subsequent timer CLI finalizes 100 jobs.
Two seeds/audit pass; the clone and URL file were removed, all twenty source hashes and
the 230-migration/zero-tenant template stayed unchanged. Log:
`.tmp/actual-performance-fixture-sla-canonical-event-20260905.log`.

The subsequent full `pnpm verify` also passes
(`.tmp/verify-sla-seed-inventory-cursor-20260905.log`): 1,993 web tests, 616 DB tests,
174 notifier tests plus the conditional Mailpit skip, 44 operations checks, generated
drift including the SLA fixture, builds, Go vet/tests. All 52 performance harness tests
pass separately; neither result substitutes for the next real full-scale benchmark.

These native runs use Node 24.14.1 and do not substitute for the pinned
Node 24.19.0 containerized reference run.

Current integration checks pass: the complete `pnpm verify` at
`.tmp/verify-performance-real-worker-final-20260905.log` and all 90 performance
tests at `.tmp/performance-real-worker-contract-final-timed-20260905.log`.
The process tests caught and now cover the two explicit worker environment overrides and
the tracker's 30-minute-plus-grace timeout. The Docker context includes the performance
workflow required by its tests and excludes local `.tmp` diagnostics; no actual Docker
build is claimed on this host.

The first native full-run attempt stalled in the Windows startup wrapper before any
workload database was created: the direct captured pg_ctl invocation retained descendant
output handles. After verifying the exact owned server was still empty, stopping only
that server released the wrapper; its connection-refused artifact is not a benchmark
result. The Windows invocation below redirects startup output to files and waits only
for the pg_ctl process, not the long-lived server tree. A new attempt reached canonical
migration on `periapsis_performance_1788636376158_54b2296ad3c9`; final acceptance
still requires its terminal immutable artifact. Log:
`.tmp/performance-real-worker-full-direct-start-20260905.log`.

## Safety boundary

Run the gate only against an explicitly disposable PostgreSQL server on the
local machine. `PERIAPSIS_PERFORMANCE_ADMIN_URL` must use `postgres` or
`postgresql`, target the numeric loopback address `127.0.0.1` or `::1`, and
name database/user `postgres`, an explicit port and `?sslmode=disable`.
Hostnames such as `localhost` are
rejected because name resolution is not a destructive-operation boundary. The
runner also verifies `inet_server_addr()` is loopback before creating anything.
It creates only a database named
`periapsis_performance_<timestamp>_<random>` and validates that exact pattern
again before either `CREATE DATABASE` or `DROP DATABASE ... WITH (FORCE)`.
`PERIAPSIS_PERFORMANCE_PSQL` is mandatory and must resolve to an explicit,
absolute `psql` executable; the harness never searches `PATH` for it.
`PERIAPSIS_PERFORMANCE_SLA_WORKER` must name an absolute compiled
`performance-sla` executable (`.exe` on Windows). Its digest is retained and
checked again before success. The CLI receives a complete URL only through a
private file, rejects inherited connection options/default passfiles, and rechecks
the disposable database, PostgreSQL version and exact data-directory pin before
assuming the production worker role. Its administrative connection is read-only.
`PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY` is also mandatory and must
resolve to the exact fresh cluster directory returned by PostgreSQL. This pin
prevents a failed server start or port collision from redirecting the
destructive gate to another loopback PostgreSQL instance.
The create and drop clients use run-unique `application_name` values. Cleanup
first quiesces or terminates only the owned create backend, then probes and
drops the exact database, quiesces any uncertain drop backend, and requires a
final catalog count of zero. A lost client response therefore cannot turn into
an orphaned database after an early `count = 0` observation.

The fixture refuses any server except PostgreSQL 18.6, any non-disposable
database name, a reused seed, or a schema whose required ABIs/cardinalities have
drifted. It does not create indexes, alter tables, disable triggers, or disable
row-level security. A missing tool, migration mismatch, stale compatibility
manifest, unavailable ABI, plan regression, partial load, or cleanup failure is
a failed gate.

The server must be fresh and disposable: the only non-template database is the
empty administrative database `postgres`, the connected user is a local
superuser, and no `periapsis_*` role or prior performance database exists.
Start the dedicated server with `-c timezone=UTC`. Preflight requires UTC and
zero `pg_db_role_setting` rows before creating the workload database. Do not use
`ALTER DATABASE` or `ALTER ROLE` to set UTC: persistent settings participate in
the canonical migration dependency seal. Migration/seed session settings and
the workload's UTC provenance check remain unchanged.
PostgreSQL connection variables inherited from the caller, including
`PGOPTIONS`, `DATABASE_URL_FILE`, and `PERIAPSIS_PERFORMANCE_ADMIN_URL`, are removed before every
subprocess. If the URL carries a password, `psql` receives a passwordless URL
in argv and a harness-owned temporary `PGPASSFILE`: mode 0600 on POSIX, or an
inheritance-free current-user ACL on Windows. The file and its bounded
temporary directory are removed after every exit path that proves all clients
closed; a cleanup failure fails the gate. Migrate/seed scripts run directly
through the pinned Node + `tsx` entrypoint in a detached, tracked process tree;
Windows uses the boundary-validated absolute System32
`taskkill /T /F` and POSIX uses the owned process group. Timeout,
bounded-output failure, and signals actually delivered to the Node listener
(POSIX `SIGINT`/`SIGTERM`, or a Windows console Ctrl+C event delivered to the
registered `SIGINT` listener) quiesce
that tree and active asynchronous load/race `psql` children before database or
`PGPASSFILE` cleanup. The listener remains installed through cleanup, so a
second delivered Ctrl+C/signal is caught without interrupting the first
quiescence attempt. Windows `TerminateProcess`, `taskkill /F` against the
harness itself, POSIX `SIGKILL`, power loss, and an operating-system crash are
uncatchable and carry no cleanup guarantee. After one, stop and discard the
dedicated cluster; if a password URL was used, confirm no harness process
survives before removing only the exact
`periapsis-performance-pgpass-*` temporary directory created by that run. A
safety timeout that cannot prove every tracked `psql` child or migrate/seed
process tree closed follows the same conservative boundary: the evidence
records `blocked_by_active_clients` plus the bounded owned PIDs and credential
directory basename, the runner deliberately leaves both its database and
`PGPASSFILE` in place, and the operator must terminate those exact
harness-owned children, stop/discard the dedicated cluster, then remove only
that run's exact credential directory. A
synchronous direct fixture/plan `psql` has no wrapper or grandchild and is
allowed to return or reach its bounded timeout first. The disposable database
is created with UTF-8 and `C` collation/ctype and is pinned to UTC.
The SLA URL file has the same private permission and quiescence requirements. It is
removed nonrecursively only after both tracked trees and psql clients have closed.
Failed cleanup retains its bounded directory basename in evidence. Ingress runs with
a 30-minute CLI deadline plus five seconds of process grace; timer batches keep the
30-second processing budget. No URL or child stderr is retained in worker reports.

The runner never prints the database URL. Evidence contains schema fingerprints,
aggregate timings, query plans, synthetic UUIDs, and synthetic workload facts;
it contains no password or customer payload.

## Invocation

Start a fresh PostgreSQL 18.6 instance on a free loopback port. On Windows, the
portable toolchain used by repository database tests can be started as follows
(choose a new directory and free port for every run):

```powershell
$pgBin = Join-Path $env:LOCALAPPDATA 'Temp\periapsis-postgres-18.6\pgsql\bin'
$dataDir = Join-Path $env:TEMP ('periapsis-performance-pg-' + [guid]::NewGuid())
$port = 55493
$workerDir = Join-Path $env:TEMP ('periapsis-performance-worker-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $workerDir | Out-Null
$workerBinary = Join-Path $workerDir 'performance-sla.exe'
go build -buildvcs=false -trimpath -o $workerBinary ./services/worker/cmd/performance-sla
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& "$pgBin\initdb.exe" -D $dataDir -U postgres -A trust --no-locale --encoding=UTF8
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$expectedDataDirectory = (Resolve-Path -LiteralPath $dataDir).Path

$gateExit = 1
$serverStarted = $false
try {
  $starter = Start-Process -FilePath "$pgBin\pg_ctl.exe" -WindowStyle Hidden -PassThru -ArgumentList @('-D', ('"' + $dataDir + '"'), '-l', ('"' + $dataDir + '\postgres.log"'), '-o', ('"-p ' + $port + ' -c listen_addresses=127.0.0.1 -c timezone=UTC"'), '-t', '30', '-w', 'start') -RedirectStandardOutput "$dataDir\pg-start.stdout.log" -RedirectStandardError "$dataDir\pg-start.stderr.log"
  $starter.WaitForExit()
  $startExit = $starter.ExitCode
  if ($startExit -eq 0) {
    $serverStarted = $true
    $env:PERIAPSIS_PERFORMANCE_ADMIN_URL = "postgres://postgres@127.0.0.1:$port/postgres?sslmode=disable"
    $env:PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY = $expectedDataDirectory
    $env:PERIAPSIS_PERFORMANCE_PSQL = "$pgBin\psql.exe"
    $env:PERIAPSIS_PERFORMANCE_SLA_WORKER = $workerBinary
    node scripts/performance/run-ticketing-hot-paths.mjs
    $gateExit = $LASTEXITCODE
  } else {
    $gateExit = $startExit
  }
} finally {
  if ($serverStarted) {
    & "$pgBin\pg_ctl.exe" -D $dataDir -m fast -w stop
    if ($LASTEXITCODE -ne 0 -and $gateExit -eq 0) {
      $gateExit = $LASTEXITCODE
    }
  }
  Remove-Item Env:PERIAPSIS_PERFORMANCE_ADMIN_URL -ErrorAction SilentlyContinue
  Remove-Item Env:PERIAPSIS_PERFORMANCE_EXPECTED_DATA_DIRECTORY -ErrorAction SilentlyContinue
  Remove-Item Env:PERIAPSIS_PERFORMANCE_PSQL -ErrorAction SilentlyContinue
  Remove-Item Env:PERIAPSIS_PERFORMANCE_SLA_WORKER -ErrorAction SilentlyContinue
}
exit $gateExit
```

The caller owns the PostgreSQL instance and its data directory. The harness
drops only the database it created; it never stops a server or removes a data
directory. Canonical migrations create cluster-global runtime roles, so discard
the fresh server after every successful or failed run; the harness deliberately
does not attempt to remove those roles. On Linux, build the same Go command into a
dedicated absolute `performance-sla` path, set the same four environment variables,
and invoke the same Node command with PostgreSQL 18.6 `psql`.

Run the non-database safety and source-contract tests separately:

```text
node --test tests/performance/*.test.mjs
```

The pinned CI entrypoint is `.github/workflows/ticketing-performance.yml`. It
runs weekly and on explicit dispatch. The workflow builds
`deploy/performance/Dockerfile`, which compiles the CLI with pinned Go 1.26.7,
combines immutable Node 24.19.0 and PostgreSQL 18.6 images, initializes a fresh cluster inside that disposable
container, and invokes this same runner with its direct PostgreSQL 18.6 `psql`
binary. It always uploads `tmp/performance/` under a run-and-attempt-specific
artifact name. A workflow run that lacks an immutable evidence file fails; a
green source-contract test or image build is not a substitute for a green
database artifact.

Successful and failed database runs write one immutable evidence file below
`tmp/performance/`. The JSON is fsynced to an exclusive staging file and then
published through a same-directory no-replace hard link, so a partial file
cannot advertise `passed` and an existing artifact cannot be overwritten. If
unlinking the staging name fails after that commit, the gate keeps the valid
final outcome and emits a warning about the harmless second link. CI should
retain that directory as an artifact whether the command passes or fails.
Every measured plan records the exact canonical
migration count/timestamp/hash plus the full ordered journal fingerprint,
selected indexes, per-scan actual rows/loops/total rows, root buffers and
timing, and any residual sequential scans.

## Dataset and budgets

The tenant fixture contains 100,000 Alerts and 100,000 Cases, one pinned integer
custom-field value per Alert, 99,999 real performance SLA datetime values, and
10,000 synthetic notification-v2 outbox events. The seeded Alert is intentionally
excluded from the later policy. The real worker produces the SLA jobs, whose
counts are recorded rather than manufactured. API projections
run as `periapsis_api`; queue candidate plans run as the exact NOLOGIN owner
assumed by their SECURITY DEFINER claim function. Row-level security remains
enabled, API plans carry tenant/user context, and every plan uses `jit=off`, no
parallel gather, and `work_mem=16MB`. Each plan is warmed once and then measured
with `EXPLAIN (ANALYZE, BUFFERS, WAL, SETTINGS, SUMMARY, FORMAT JSON)`.

| Gate                           | Time budget | Shared blocks | Required index                                                                                  | Additional invariant    |
| ------------------------------ | ----------: | ------------: | ----------------------------------------------------------------------------------------------- | ----------------------- |
| Alert default updated page     |      500 ms |        20,000 | `alerts_tenant_updated_idx`                                                                     | no Alert seq scan       |
| Alert created-order page       |      500 ms |        20,000 | `alerts_tenant_created_idx`                                                                     | exactly 101 rows        |
| Case default updated page      |      500 ms |        20,000 | `cases_tenant_updated_idx`                                                                      | no Case seq scan        |
| workflow-state filter page     |      500 ms |        20,000 | `alerts_tenant_created_idx` or `alerts_tenant_state_priority_idx`, on a contributing Alert scan | no Alert seq scan       |
| severity filter page           |      500 ms |        20,000 | `alerts_tenant_created_idx`                                                                     | no Alert seq scan       |
| workflow-state + severity page |      750 ms |        30,000 | `alerts_tenant_state_priority_idx`                                                              | no Alert seq scan       |
| team + assignee page           |      500 ms |        20,000 | `alerts_tenant_assignment_idx`                                                                  | no Alert seq scan       |
| integer custom-field filter    |    1,000 ms |        50,000 | `custom_field_values_definition_integer_idx`                                                    | no Alert/value seq scan |
| pinned SLA due-at sort         |    1,000 ms |        60,000 | `sla_materialized_projection_instant_sort_idx`                                                  | no Alert/value seq scan |
| SLA claim candidates           |      500 ms |        10,000 | `sla_evaluation_jobs_claim_idx`                                                                 | exactly 100 rows        |
| notification fanout candidates |      500 ms |        20,000 | `outbox_events_dequeue_idx`                                                                     | exactly 100 rows        |

Every plan also has a 100 ms planning budget, zero temporary blocks, and no disk
sort. Every list projection must return the full 101-row cursor window and each
queue projection the full 100-row claim window, preventing an empty RLS or
permission projection from passing on timing alone. Index use and forbidden
sequential scans are structural requirements, not only timing observations.

The concurrent gates use independent PostgreSQL connections. Every worker
returns the exact synthetic UUIDv7 receipts it committed; the runner rejects a
partial worker, a duplicate within or across workers, or an overlap between
claim batches. It then performs an untimed administrative postcondition check
that every returned ID is in its expected committed version/lease/fence state.
Throughput is calculated from successful distinct operations, never attempted
operations. Per-worker status, duration, returned count, and a receipt digest
remain in the evidence even when another worker fails.

| Gate                       |                              Work | Wall budget |                          Minimum throughput |
| -------------------------- | --------------------------------: | ----------: | ------------------------------------------: |
| Alert ingest               |        160 creates over 8 clients |        60 s |                                         4/s |
| independent Alert claims   |         160 claims over 8 clients |        60 s |                                         4/s |
| same-Alert claim race      |                      8 contenders | 60 s/client | exactly one winner, seven stale CAS results |
| SLA worker processing      | 400 finalized jobs over 4 clients |        30 s |                                        10/s |
| notification fanout claims |         400 events over 4 clients |        20 s |                                        20/s |

The same-Alert race is not inferred from eight processes starting near one
another. Each contender opens a transaction, advertises a unique
`application_name`, and sleeps until a shared absolute release timestamp. The
administrative observer must see all eight sessions blocked in `PgSleep` at
least 500 ms before release; attempt timestamps must then have at most 500 ms
skew. Only one committed version-2 claim and seven stale-CAS (`40001`) outcomes
pass.

SLA timer reports expose digests, not receipt IDs. Each CLI verifies its own
completed job IDs/fences after finalization. After all four processes close, the
runner independently requires exactly 400 new completed jobs, no leased/retry/dead-letter
jobs, and actual SLA aggregate-version progress. Ingress is drained again after ticket
ingest/claim loads before those timer processes start. The notification queue gate
continues to measure claims only; SMTP acceptance requires the separate live Mailpit gate.

Treat hardware metadata in the evidence as part of result interpretation. A
budget failure on the reference CI runner is a release blocker until the real
query/index design is corrected and a new passing evidence artifact is recorded;
do not relax a threshold to hide an inefficient plan.
