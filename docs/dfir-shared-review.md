# Shared DFIR review ledger

Last updated: 2026-09-05. This is an in-flight implementation ledger, not release
acceptance. The complete objective and release gates remain in `TASKS.md` and
`release-acceptance.md`.

## Validated findings

| ID    | Priority | Reachable failure and invariant                                                                                                                                                                                              | Disposition and verification                                                                                                                                                                                                                                                                                                                                               |
| ----- | -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SR-01 | P1       | Case upload/download inferred a unique Case from a shared IOC/asset; linking the resource to a second Case rejected legitimate operations. Attachment-only escalation copies could also require copying the parent resource. | Go fixed: explicit Case subject lookup, exact Case/attachment/storage read, and independent explicit-copy resolution. Service and PostgreSQL-adapter regression tests pass. Final database/HTTP stack proof remains pending.                                                                                                                                               |
| SR-02 | P1       | Preparing an attachment on a shared IOC/asset makes it visible through every linked root, but only the path's attachment permission was checked. A retry must also respect revocation on another root.                       | SQL enforcement now binds fresh shared attachment inserts and replay to all current roots, including the legacy Alert effect ABI. PostgreSQL 18.6 runtime passes for Case/Alert paths on IOC and asset, three-root redacted activity, exact replay, and privilege loss.                                                                                                    |
| SR-03 | P2       | Case attachment inventory selected attachments on archived IOC/assets or deleted source Alerts, then the stricter subject loader rejected the entire workspace.                                                              | Go query filters now match live subject resolution; independent attachment copies remain selectable. Query-contract and mapper tests pass; final runtime proof pending.                                                                                                                                                                                                    |
| SR-04 | P2       | Escalation could lock ticket roots before shared resources, inverting the shared mutation order. PostgreSQL deadlock `40P01` was mapped to unavailable rather than conflict.                                                 | Go now batch-locks distinct selected assets then IOC UUIDs in order before calling the escalation/link ABI; `40P01` maps to conflict. Focused ordering/deduplication/missing-resource tests pass. SQL direct-call concurrency and replay checks remain part of the lifecycle runtime gate.                                                                                 |
| SR-05 | P2       | Attachment mapper accepted revisions above the JSON-safe ceiling and did not independently check the returned tenant/attachment identity.                                                                                    | Go mapper rejects both; regression coverage passes.                                                                                                                                                                                                                                                                                                                        |
| SR-06 | —        | Candidate: an IOC/asset archive mutation could invalidate additional activity lookup.                                                                                                                                        | Rejected: the current IOC/asset input and replacement commands do not perform archival, so the proposed path is unreachable. Keep live-resource checks; no authorization broadening is justified.                                                                                                                                                                          |
| SR-07 | P1       | Escalation/link replay has only an identity and fingerprint in the Go lookup port; shared selectors are stored in immutable link provenance. An insert trigger alone cannot reauthorize replay.                              | Closed: SQL resolves immutable linkIds and canonical iocIds/assetIds, locks and reauthorizes all current roots before early lookup or direct commit replay. Actual existing-Case ticket.link and create-newCase escalation v4 with selected IOC/asset pass, including exact direct/lookup replay and lost authority on another root while the new Case remains authorized. |
| SR-08 | P2       | Navigating to a cached Case/Alert or tenant kept the shared-link form mounted, reusing another root's draft and caller-owned operation identity.                                                                             | Both panel mounts are keyed by tenant, root kind, and root ID. Four mounted regression cases reproduce the failure before the fix and check draft reset, new identity on navigation, stable identity on same-root retry, and no workspace fetch.                                                                                                                           |

## Current local evidence

- Shared content repository closure (2026-09-05): the new real Go/PostgreSQL matrix
  passes IOC and asset replacement through both Case and Alert, with one resource linked
  to two Cases and one Alert. It checks exact redacted activity on all three roots,
  immutable historical replay after later writes, stale CAS, independent loss of a
  non-path root's manage permission, unchanged 16-table denial snapshots and restoration.
  Evidence: `.tmp/periapsis_dfir_shared_content_be02d97a6a7f4fc3acc3929782d4644e.log`
  and `-proof.json`; source hashes and the 230-migration template stayed stable, and the
  exact clone was dropped. This is native PostgreSQL evidence, not container acceptance.
  The earlier RED clones exposed three production adapter defects: omitted tags/MAC
  lists were sent as SQL NULL; asset readback compared equivalent nil/empty tags as
  different JSON; and an Alert legacy-ledger revision collision surfaced as conflict
  instead of stale-precondition. Narrow Go fixes preserve all other error categories,
  meaningful asset differences and exact replay. The same omitted-tag fix covers the
  shared Case/Alert timeline writer. Twenty-two array mapping cases plus codec proof,
  readback/receipt tests, eleven collision-category cases and the focused DFIR/application
  suites pass. Logs: `.tmp/dfir-array-mapping-timeline-red-20260905.log`,
  `.tmp/dfir-readback-cas-red-20260905.log`, `.tmp/dfir-readback-cas-green-20260905.log`
  and `.tmp/dfir-readback-cas-dfir-unit-20260905.log`. No SQL or seal changed.
- Remaining mutable-receipt closure (2026-09-05): all 12 Case/Alert Task mutations,
  both custody append actions and both relationship retractions now compare the receipt
  against the originally requested revision plus one. The shared validators retain
  identity, ETag and structural checks; the request revision is captured before awaiting
  the response. Ninety-two new cases include historical replay, last legal increments,
  stale/skipped but internally valid snapshots and input mutation after serialization.
  RED reproduced 46 failures; GREEN passes 139 transport tests, or 196 with adjacent
  suites, plus lint and format. Logs: `.tmp/dfir-mutable-receipts-green-20260905.log`
  and `.tmp/dfir-mutable-receipts-adjacent-20260905.log`. No SQL/seal changed. Full-tree
  verification must be repeated after this delta; database last-increment proof is separate.
- Remaining shared-resource integration gate (audit 2026-09-05): separately exercise
  `LoadWorkspace`/`LoadAlertWorkspace` with real authorization hydration to prove
  hidden-root exclusion, IOC/asset capability differences, revocation and cross-tenant
  denial. Existing projection tests use mocked transactions; lower-level attachment
  inventory integration is not a substitute. This is a proof gap, not an asserted defect.
- Remaining SAML runtime gate (audit 2026-09-05): the original real PostgreSQL logout cases
  establish local revocation, replay, credential mismatch and retired-ABI fences, but all
  admitted SAML variants deliberately produced zero upstream continuations. Add one
  permitted SLO positive per supported origin: create the continuation using the public
  local-revoke ABI, claim the exact pinned SAML material/configuration through the public
  claim ABI, and reject a second claim. The new tenant-origin positive passes after the
  Go actor-context correction; direct platform is RED because the SQL envelope rejects
  the required `tenantId:null`. See the current logout regression and retained proof in
  `release-acceptance.md`. Full three-origin closure needs a forward migration/seal and
  rerun, independently of the external IdP/browser gate.
- IOC/asset receipt and request-boundary closure (2026-09-05): both Case and Alert web
  replacements now require the receipt revision to equal the originally requested
  revision plus one, without consulting later resource state. The 24-case matrix covers
  the last safe increment, exact historical replay, stale and skipped receipts with
  otherwise matching ETags; both transport files pass all 47 tests. The canonical
  OpenAPI now uses a separate incrementable revision schema (MAX_SAFE-1) for all 16
  DFIR mutation request shapes and preserves terminal-safe responses (MAX_SAFE).
  Nineteen semantic schema tests pass, TypeScript/Go artifacts are regenerated, and
  custody/legacy ticket ceilings remain unchanged. No SQL or seal changed. This is
  transport/contract evidence, not a new database or Docker gate.
  Logs: `.tmp/dfir-replacement-receipt-green-20260905.log` and
  `.tmp/dfir-revision-contract-green-20260905.log`.
- Role/effective-authority hydration closure (2026-09-05): web reads reject malformed
  or unknown permission/scope tuples, duplicates and delegation outside the exact
  permission set; the 500-tuple read limit and 100-tuple custom write boundary are
  preserved. Forty-one regression failures preceded the fix; the complete transport
  file now passes 231 tests. Permission-specific scope/principal eligibility remains
  server-owned. Log: `.tmp/role-policy-hydration-final-20260905.log`.
  The subsequent full-tree verification passed with 2,060 web tests in
  `.tmp/verify-dfir-role-plan-final-20260905.log`; the later mutable-receipt extension
  above still requires its own full-tree verification.
- SR-18 (P2, fixed and repository-verified): the Case/Alert web
  decoders accepted evidence revisions above the canonical 1,000-event ceiling and
  append commands above the incrementable 999 boundary. The Case projection also did
  not bind revision to custody cardinality, contiguous sequence, unique event IDs and
  linked wire hashes. A shared bounded validator now covers both workspace decoders,
  initial collection responses and append responses. Exact ETag and requested
  tenant/root/resource checks remain in place. These checks validate wire consistency;
  they do not replace the server's cryptographic custody verification.
  The original transport RED run failed 21 cases. The expanded transport suite passes
  48 cases, including 999-to-1,000, rejection before network I/O, malformed snapshots,
  initial collection/replay and mismatched ETags. Mounted Case/Alert tests additionally
  reproduced two terminal-limit UI failures: the form still offered an impossible
  append. Both forms now show the limit without an append control, while preserving
  the final legal append and dialog closure. All four mounted boundary cases pass.
  Evidence: `.tmp/dfir-custody-web-red.log`, `.tmp/dfir-custody-limit-ui-red.log` and
  `.tmp/dfir-custody-ui-transport-final.log` (16 files, 194 tests passed).
  Web typecheck and lint also pass. Full `pnpm verify` then completed with exit 0
  (`.tmp/verify-custody-web-final-20260905.log`): 155 web files/1,990 tests, 613 DB
  unit tests, 174 notifier tests (conditional Mailpit skipped), 42 operations checks,
  contract/generated drift, builds, Go vet and Go tests. The eleven redirect-only
  OpenAPI warnings and the web entry chunk warning remain (865.50 kB, 217.46 kB gzip).
  The SQL journal and seal are unchanged by SR-18.
  Local reuse, efficiency and quality inspection retained the shared wire validator
  and a test-only chain fixture, with no broad form refactor or client-side duplicate
  of the cryptographic state machine. Two bounded review readings (contract-to-client,
  then tests-to-consumers) and three local reuse/efficiency/quality cycles found no
  further accepted issue in the SR-18 delta after the terminal-form fix. Those local
  checks do not certify the complete shared DFIR implementation or the full product;
  global review closure remains unproven.
- Download-audit evidence gap (closed locally, 2026-09-05): the old PostgreSQL portal
  helper fixed the root to Alert. The new shared matrix exercises both customer Alert
  and Case with two authorized grants and 13 denials each. It checks exact audit fields,
  wrong-root access, attachment/storage mismatch, contact/link/membership revocation,
  stale revisions and unavailable states. Every denial must reach the actual audit
  writer and preserve complete snapshots of nine tenant tables after rollback.
  The entire contacts/portal runtime passed on a fresh sealed clone; proof and log are
  in `C:/Users/dange/AppData/Local/Temp/periapsis-portal-case-download-c636a9c47de84edba2710e17c50f9801/`.
  DB typecheck, targeted lint and format passed; SQL and seal are unchanged. This adds
  real customer Case proof to the previous operator/shared-root Go/PostgreSQL coverage,
  not a new full 58-suite run or composed object-storage test.
- Current-candidate checkpoint, 2026-09-05, SR-17 (P2): the final SQL download-audit
  boundary still inferred a unique Case after SR-01 corrected the Go read path. The new
  PostgreSQL regression first proves the real attachment and exact-storage reads succeed,
  then reproduces four `42501` audit denials for IOC/asset shared between two Cases. It
  also reproduces two SQL successes for archived resources that the Go loader denies.
  `append_dfir_download_grant_audit_v1` now uses direct live associations on the requested
  Case, preserves explicit attachment copies independently of the original resource,
  and does not infer IOC/asset copies through Alert links. Direct Alert attachments use
  the requested live Alert-to-Case association instead of a unique-Case inference.
  The complete Go PostgreSQL fixture passes with 16 audit cases, including explicit-copy
  survival after archival, unselected IOC attachments, multiple Case links, source Alert
  deletion through its public writer, wrong roots and exact audit root/attachment effects.
  RED evidence: `.tmp/dfir-download-shared-red.log`; full-journal GREEN evidence:
  `.tmp/dfir-download-shared-full-journal-green.log`. Focused Go race tests and vet pass.
  A fresh 230-migration derivation and a second normal `db:migrate` database agree on
  catalog digest `048078bb2a5c69057ec356857e323d55d0b97a43a5894e620140eab1f758414e`.
  The canonical template is sealed, ready and tenant-free. The complete 58-suite
  aggregate, RLS, updated 13-test Go CI selection and all 19 upgrade entries pass with
  stable source hashes on this seal. Proof directories are
  `C:/Users/dange/AppData/Local/Temp/periapsis-final-pg-security-048006c7c6a84125a4d4fc6a2988b2da`
  and
  `C:/Users/dange/AppData/Local/Temp/periapsis-final-upgrade-matrix-cfa46fd3ab0d49308efa3b5cb155f4d0`.
  These are native PostgreSQL 18.6 loopback-trust gates, not Docker/SCRAM acceptance.
  Repository verification passed after canonical API-documentation regeneration
  (`.tmp/verify-download-audit-ci-final-20260905.log`), before the subsequent SR-18
  frontend edits. A fresh final-tree verification is required. No global clean-review
  or production acceptance is claimed.
- Task, relationship and receipt implementation audit: source, real SQL runtime and
  mounted UI evidence cover Case/Alert task updates, append-only Case retraction and
  arbitrary authorized endpoint pairs. The worker scan/cleanup, immutable receipt and
  retention paths are implemented and had passing focused gates on the previous sealed
  candidate. Their implementation backlog entries are closed; final-candidate and external
  acceptance entries remain open. The live Playwright journey now additionally exercises
  all six task updates on both roots, Alert task SLA set/clear, historical replay and
  IOC-to-asset create plus Case retraction/audit. Typecheck, lint, discovery and the six
  source-contract checks pass. The extended live journey has not run without Docker.
- Pre-SR-17 checkpoint, 2026-09-05: the full fix batch passed `pnpm verify`
  (exit 0, `.tmp/verify-mfa-final-20260905.log`), including all 613 DB unit tests.
  The raw 230-migration derivation and a second empty database using normal `db:migrate`
  agree on catalog digest `5bd290d0f9982f202b918ebe41e6aac5ada83c8e919b61c4c63bae2d0b7a0fa5`.
  The canonical database is sealed, readiness is true and the fixture-free template has
  zero tenants. Sources stayed stable at 0228 SHA256 `5061e3d0ba587112d3419d3a011a7b4912b5db774707d3519ead368c03070678`
  and 0229 SHA256 `150d56d66daa9e4a5f076b9114be6e2eb56a78f86307573151367bde799ea70d`.
  The full Go authorization-repository runtime also passes on a dedicated sealed clone
  (`.tmp/authorization-final-sealed.log`). All 58 PostgreSQL suites, RLS, Go CI and all
  19 upgrade entries passed with stable source hashes. These runs predate SR-17 and do not
  certify the new candidate. No production acceptance is claimed.
  Residual warnings are the eleven redirect-only OpenAPI responses and the web entry
  chunk above 500 kB (865.50 kB minified, 217.45 kB gzip).
- Historical checkpoint: the complete repository `pnpm verify`
  passed on the earlier sealed 230-migration baseline (`.tmp/verify-final-20260905-1204.log`,
  exit 0). Subsequent shared-unlink, scan-limit, seed, authentication and authorization
  corrections invalidate the affected evidence. The fresh PostgreSQL diagnostic matrix
  reported 48/58 passing suites before those corrections; it was not a stable-source
  release run. Final seal, all security suites, all 19 upgrade entries and full repository
  verification must be rerun after the current SQL owners release their changes.
- Historical pre-MFA scratch database applied all 230 migrations without
  per-function patches. Its unsealed catalog digest is
  `cf441cc8f5fd76c4735317e00f19ade9f0d525f35b8ee0582dd8e198c63d4922`:
  353 public tables plus the Drizzle journal match the 354 canonical snapshot entries.
  Independent clones pass the complete shared DFIR, scan, generic-relationship and
  mutation-retention runtimes, including schema/index/FK parity. The complete Go
  authorization-repository runtime also passes against that full-journal baseline,
  not a function-patched database. Evidence is in `.tmp/*-current-full-migration.log`.
  This is a diagnostic migration, not the sealed canonical-runner gate. A newly proven
  tenant-provider OIDC material-less MFA failure requires another SQL correction and
  invalidates this digest as a final candidate; it has deliberately not been pinned in 0229.
- Cross-scenario authorization repair (backend gates included in the post-SR-17 seal above): the
  administrator's 176 exact permission tuples no longer collide with the 100-tuple
  custom-policy write bound. Read hydration is bounded at 500 with overflow detection,
  while canonical OpenAPI, generated transports and web reads agree with Go. Six current
  human grant/revoke/member-read ABIs preserve machine-role rejection, exact live
  delegation and lifetime, replay authority, manual-source ownership, CAS, audit and
  last-recovery-administrator protection. Member responses carry their real lifecycle
  revision/ETag and stable cursor order. Focused contract/web/Go tests, Go race/vet and
  the actual PostgreSQL authorization-repository suite pass; legacy ABI guards remain.
- Cross-scenario MFA finding (P1, fixed; included in the post-SR-17 aggregate above): a tenant-provider OIDC initial
  application legitimately permits absent material with refresh disabled and no pinned
  logout endpoint, but its public MFA completion unconditionally required a
  material row. The real initial-apply, authority, challenge creation/claim and public
  TOTP completion path reproduces `40001`, with the continuation left pending and no
  promoted session after rollback. All three continuation/rotation/step-up guards now
  require the bounded immutable-origin/lineage attestation when no material is transferred.
  The full public initial-MFA/rotation/step-up/second-MFA flow and direct initial-login
  rotations pass, with exact replay, required-material denial and restored positive
  controls, factor/lineage revocation and complete rollback snapshots. Root authentication
  time and duplicate OIDC revision pins are also compared with immutable login/transaction
  evidence; deliberately altered fixtures fail and pass again after restoration.
  These are exact-lineage checks, not a blanket exception for missing material rows.
- SR-15 (P2, fixed; final-journal rerun pending): unlinking a shared IOC/asset did not
  consider root-local relationships whose endpoint is an attachment on that resource.
  `guard_shared_dfir_link_v1` now preserves those endpoint associations, while an explicit
  attachment copy to the Case remains independently valid. All eight Case/Alert,
  IOC/asset, source/target endpoint cases failed before the fix. The corrected function
  passes the complete shared-resource runtime on an isolated PostgreSQL clone, including
  unchanged resource revisions on denial and four explicit-copy positive controls.
- SR-16 (P2, fixed; final-journal rerun pending): the scan worker used the JSON-safe
  resource revision ceiling for evidence custody, whose canonical maximum is 1,000.
  At the maximum it attempted an illegal 1,001st event and could keep retrying a state
  transition that can never succeed. `advance_dfir_storage_scan_job_v1` now reports a
  dedicated custody-limit result before any projection changes. The worker ends that
  exact leased queue item as a recorded dead letter; the completion function independently
  locks and verifies the evidence limit and keeps evidence, storage and attachment state
  unchanged and unavailable. PostgreSQL reproduces the old constraint error and passes
  the corrected full scan runtime: 999-to-1,000 success, exact-limit failure, below-limit
  completion denial, stale lease denial, released terminal queue lease and no reclaim.
  Worker/repository unit and race tests plus Go vet pass; failed completion never reports
  success. The scan fan-out fixture now first proves the association writer rejects root
  65, then deliberately injects that invalid graph inside the disposable admin fixture
  with its exact trigger restored, proving the independent worker bound as well.
  The local worker review also covers custody-limit termination from `pending_upload`,
  `uploaded`, `verifying`, `quarantined` and `scan_failed`, before malware scanning:
  one failed transition, one exact-fence dead letter, no retry, and closure of any opened
  object stream. These five additional cases and worker/repository race tests pass.
  Separate local reuse, efficiency and quality passes found no justified production-code
  simplification in this worker change; this is not a whole-candidate clean review gate.
- Earlier static/unit evidence (superseded by the final verify above): workspace lint
  and TypeScript checks passed after the authentication and
  authorization repairs (`.tmp/lint-current-auth-dfir.log` and
  `.tmp/typecheck-current-auth-dfir.log`). The eleven redirect-only OpenAPI warnings
  remain unchanged. The complete `pnpm go:test` command also passes
  (`.tmp/go-test-current-auth-dfir.log`); environment-gated PostgreSQL tests are not
  included in that result. These checks do not certify the in-progress SQL seal or
  replace the complete final `pnpm verify` run.
  The separate non-DB unit aggregate also passes: web 1,938/1,938, UI 2/2,
  notifier 174 passed with the conditional Mailpit test skipped, and the contract/config
  suites (`.tmp/unit-nondb-current-auth-dfir.log`). PostgreSQL and its pending bundle
  fingerprint were deliberately excluded from this command, not waived.
- V49 runtime fixture repairs: a valid login-membership edge is compared against the
  same edge under another authorized grantor, not against a missing edge (which must
  change the digest). The test explicitly preserves missing-edge detection. The separate
  ACL-grantor fixture now has schema USAGE before granting its test function; production
  grants and catalog normalization are unchanged. The first corrected run passed the
  membership comparison and exposed the fixture-only missing USAGE; the full rerun is
  now passing on an isolated clone of the earlier sealed baseline (exit 0,
  `.tmp/v49-grantor-green2.log`). That validates the test repairs, not the newer unsealed
  SQL candidate. The pre-regeneration DB unit run had 612 passes and one expected
  packaged-bundle fingerprint failure at ordinal 229. Regeneration removed that
  mismatch; the final verify above passes all 613 tests without weakening the assertion.
  A further V49 regression now verifies that the new tenant-provider material-absence
  helper exists, remains migrator-owned and is not directly runtime-executable. It replaces
  only that helper body inside a rolled-back test transaction, expects catalog/readiness
  rejection, then checks full readiness restoration. Typecheck, lint and formatting pass;
  the actual runtime proof awaits the newly sealed candidate.
- SR-09 (P2, accepted; Go/UI fixed, SQL integration pending): general relationships
  required a source or target equal to the owning ticket, rejecting IOC-to-asset links
  required by the specification. Case retraction also inferred its root from the first
  Case endpoint. Root context now flows explicitly through Go, receipt envelopes,
  workspace queries, OpenAPI, decoders, and forms. Module, application, repository,
  receipt, and mounted UI regressions pass. See ADR-0012; the database slice remains open.
- SR-10 (P2, fixed): after navigating away from an in-flight mutation/download, its late
  completion could clear the new ticket's busy state or set an unrelated error. Both
  panels now let only the active request update UI state, including after workspace
  refresh. Twelve mounted cases cover Case/Alert, mutation/download, and late success,
  abort, or failure. Six mutation cases reproduced the bug before the correction.
- SR-11 (P2, fixed): live manage-permission revocation did not abort a shared-link
  request, and Case read-permission revocation left its request/cache alive. Both panels
  now bind the active request to its exact required permission, clear revoked read data,
  and ignore late settlements. Unrelated manage revocation does not abort an authorized
  download. Twelve new cases reproduced missing cancellation; the mounted lifecycle
  matrix now has 36 cases, plus direct Case workspace-fetch cancellation coverage.
- SR-12 (P2, fixed): the worker pruner accepted a NULL batch
  because SQL `NOT BETWEEN` evaluates to NULL. `LIMIT NULL` removes the required bound
  from all three cleanup families. Reproduced directly as `periapsis_worker` on the fresh
  PostgreSQL 18.6 retention cluster inside a rolled-back transaction; the call succeeded
  instead of rejecting with `22023`. Explicit NULL rejection and runtime coverage now pass
  on a fresh PostgreSQL 18.6 database, including an independent rolled-back boundary check.
- SR-13 (P2, fixed): a Case task receipt lookup accepted a
  NULL result version and returned a successful nullable coordinate. Reproduced as the
  authorized API role in a rolled-back transaction. Both new Case/Alert retention wrappers
  now reject NULL revisions with `22023` at the SQL boundary, independently of Go validation.
  The retention runtime and an independent direct Case/Alert API-role check pass.
- SR-14 (P2, fixed): five new receipt-table
  tenant foreign keys differed from canonical Drizzle in both name and update action
  (`CASCADE` instead of `NO ACTION`). A direct catalog comparison against newly generated
  snapshots reproduced all five differences among fifteen foreign keys in six new DFIR
  tables. SQL is aligned to the unchanged canonical model. The runtime regression failed
  on exactly those five old foreign keys and passes on a fresh PostgreSQL 18.6 database:
  six tables, 53 column types/nullability/order, primary/unique coordinates and fifteen
  complete foreign keys. An independent snapshot/catalog FK comparison also passes.
  Partial unique-index semantics also pass a PostgreSQL-normalized comparison against
  transactionally rolled-back temporary indexes generated from Drizzle. A scratch clone
  with the secondary-resource predicate inverted fails exactly that comparison; the
  unchanged candidate passes, including key definitions, predicates and validity flags.
- Earlier sealed baseline (superseded by the corrections above): generation produced
  354-table Drizzle snapshots for 0228/0229;
  the pinned generation drift check passes. A new, empty PostgreSQL 18.6 C/C cluster
  applied all 230 migrations, yielding catalog digest
  `5329a4dea8f35f17dcf16dd8bbe908c111338377d7b9fcc0c5960502fa49646c`.
  After deriving that exact digest into the unreleased 0229 source and regenerating
  application manifests, a second empty cluster passed the normal `db:migrate` runner
  including sealing: `release_runtime_schema_readiness_v49()` is true with applied count
  230 and the same catalog digest. Database unit tests now pass 612/612. Full runtime,
  upgrade-matrix and Docker evidence remain separate gates, not implied by this result.
- The fresh V49 runtime gate exposed a test-container mismatch: `postgres.js` returns
  a `Result` array subclass, while the notifier catalog assertion expects a plain array.
  The catalog helper now returns `Array.from(rows)`; exact row, owner and ACL assertions
  are unchanged. The rerun reached the login-role tests and stopped because this direct
  invocation had not provisioned the required runtime-login fixture. The CI-equivalent
  aggregate now owns the complete rerun after the normal four-role provisioning step.
- `dfir_shared_attachments_integration_test.go`: four real PostgreSQL scenarios pass on
  an isolated clone of the current shared-lifecycle journal through 0228. They execute
  direct reads from two Cases, wrong-root/tenant and RLS denial, archived filtering,
  independent copied attachments, exact storage-purpose binding, and safe revision bounds.
- Updated OpenAPI generation, contract tests, build, and generated-drift verification
  pass. The eleven pre-existing redirect-only SSO response warnings remain unchanged.
- Historical pre-seal evidence: retention was applied on a fresh PostgreSQL 18.6 database
  through 0229, with isolated
  retention/Case/Alert/shared runtime clones passing. This is migration and focused-runtime
  evidence, not a compatibility-seal pass. The new general relationship SQL still requires
  another fresh-candidate run. Database unit tests pass 611/612; only the expected packaged
  migration-fingerprint mismatch remains. The moved Case-subject retraction check is now
  asserted in its actual shared helper instead of by counting strings in the former file.
- Historical pre-seal evidence: the complete frontend suite passed 154 files / 1,932
  tests after SR-11; targeted
  DFIR verification passes 15 files / 142 tests. Repository type checking, lint, build,
  Go race tests and vet pass. Build retains the existing large-chunk warning; OpenAPI
  lint retains the eleven redirect-only response warnings. Formatting remains pending
  on the independently owned retention files; no complete `verify` pass is claimed.
  The two ticket-page fixture failures were corrected by rebinding shared resource roots,
  preserving fail-closed production projection validation.
- Local simplify review: reuse and efficiency passes retained the separate Case/Alert
  orchestration instead of introducing a cross-panel abstraction. Removed one redundant
  metadata clone in canonical relationship validation; the getter already returns an
  owned copy. The quality pass produced SR-11, with regression evidence above.

- Shared lifecycle was applied from an empty isolated PostgreSQL 18.6 cluster through
  0228 (229 migrations), then `shared-dfir-resource-runtime.ts` passed: both resource
  kinds and ticket roots, CAS/concurrency, 64-root bound, dangling references,
  revoked/cross-tenant authority, immutable history/identifier reuse, unlink replay,
  attachment fan-out, and closed escalation selection/replay. The final compatibility
  seal, retention integration, complete upgrade matrix, and container acceptance remain
  separate gates.
- Review additionally closed raw API link inserts without a pending mutation command,
  and generic link/unlink receipts without their exact immutable lifecycle event;
  PostgreSQL runtime proves both fail before commit.

- `go test ./services/api/...`: passed after the path-bound attachment and escalation
  changes. Environment-gated database tests remain skipped without their explicit URLs.
- Focused Go tests, race tests, and vet for API DFIR, PostgreSQL, HTTP, and ticketing:
  passed. These do not prove that the in-flight SQL migration or a container stack works.
- Source-contract tests explicitly check direct/live Case attachment selection and
  tenant/root bindings. They are not substitutes for executing the query on PostgreSQL.
- No final adversarial/simplify clean-gate count is claimed while lifecycle/retention
  source changes and accepted findings remain open.

Next proof boundary: finish global closing review, repeat affected final-candidate
gates after any further change, then
obtain Docker-backed live acceptance, reference-performance and restore evidence.
