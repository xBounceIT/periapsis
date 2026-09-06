# Release evidence backlog

Last audited: 2026-09-06

This is the authoritative release backlog. A checked item means the implementation and a
focused repository gate exist; it does not mean every database-runtime gate is green for
the in-flight candidate or that a particular CI run or production drill has been retained.
Unchecked items include final repository verification and evidence that must be produced
on an external runtime or production trust boundary. The current
candidate state and the requirement-to-test map are in
[`docs/release-acceptance.md`](docs/release-acceptance.md), including the completed
final-journal database gates and the remaining release boundaries.

## Repository implementation

- [x] Canonical Drizzle schema, generated migrations/sqlc, OpenAPI 3.1, generated Go and
      TypeScript clients, and drift gates.
- [x] Shared-schema multi-tenancy with non-null tenant ownership, deny-by-default backend
      authorization, forced RLS, explicit platform-to-tenant access, and cross-tenant tests.
- [x] Separate tenant/platform audit streams with recursive redaction, append-only runtime
      grants, tamper-evident chains, authorized export, and retention controls.
- [x] Local break-glass recovery, secure sessions, tenant and platform LDAP, OIDC, SAML 2.0,
      TOTP, WebAuthn/passkeys, recovery/device lifecycle, JIT/pre-link, IdP-assurance trust,
      step-up, live provenance, and session revalidation.
- [x] Tenant roles, exact delegation ceilings, security groups, source-owned identity
      reconciliation, operator-team assignment epochs, service accounts, API-key rotation,
      and tenant-membership lifecycle.
- [x] Alert/Case API and operator UI with server-side search/filter/table state, saved views,
      dynamic custom/SLA columns, workflow administration, explicit claim/release/assign/
      transfer/transition/close/reopen/escalate/link/unlink actions, watchers, comments,
      metadata, activity, idempotency, and optimistic concurrency.
- [x] Escalation to new or existing Case with selected tags, custom fields, IOC, assets,
      attachments, public comments, and contacts; immutable copy/link provenance; exact replay;
      append-only unlink retraction; bidirectional active-link projections.
- [x] Customer contacts and portal-safe ticket, attachment, activity, comment, notification,
      webhook, and export projections, including private-comment exclusion at every downstream
      boundary.
- [x] Case and Alert IOC, assets, evidence, timeline, tasks, attachments, and relationships,
      with S3-compatible transfer, scan state, SHA-256 integrity, and chain of custody.
- [x] Versioned custom fields, workflows, business calendars, multi-metric SLA policies,
      materialized columns, DST-safe simulator, pause/override, event ingress, fenced workers,
      trigger actions, no-loop system Alerts, and transactional audit.
- [x] Versioned notification rules/templates, safe HTML/CSS and placeholders, preview,
      plaintext, SMTP/webhook delivery, a conditional Mailpit acceptance gate,
      retry/fencing/dead-letter, delivery evidence, and trace propagation.
- [x] Bounded ticket bulk-action jobs and asynchronous CSV exports with immutable reviewed
      selections, exact CAS, cancellation, S3 artifact reconciliation, authorized download,
      cleanup, retention, and worker observability.
- [x] Tenant branding/settings and platform tenant lifecycle, global settings, tenant access,
      health, job queues, failed-notification operations, feature flags, and audit operations.
- [x] Structured JSON logs, request/correlation/trace identifiers, bounded OpenTelemetry,
      Prometheus endpoints and queue/auth/API/SLA/notification/bulk/export metrics, validated
      alert rules, and a Grafana dashboard.
- [x] Non-root/read-only multi-stage images, Compose profiles, Swarm template, Kustomize
      base/dev/prod, health probes, least-privilege security contexts, secret mounts, SBOM,
      vulnerability/secret scans, and multi-architecture evidence jobs.
- [x] A composed full-stack acceptance job with five non-intercepted Playwright scenarios,
      focused PostgreSQL 18 security suites, and a scheduled
      100,000-Alert/100,000-Case performance harness with bounded evidence output.

## Completed closing slices and final repository verification

- [x] Finish and verify the operator Alert duplicate/correlation UI against the explicit,
      audited Alert-to-Alert relation API introduced by migration 0221.
- [x] Add the personal Notification Center persistence, HTTP API, fan-out projection, route,
      navigation, and cross-tenant/customer-safety runtime coverage.
- [x] Replace the hard-coded Alert/Case number allocator with an atomic, versioned,
      tenant-configurable numbering policy and administration surface.
- [x] Add Alert evidence, tasks, and general DFIR relationships with the same authorization,
      custody, audit, and UI guarantees already implemented for Case.
- [x] Add authorized custom-field bulk import with immutable definition pins, validation or
      dry-run evidence, bounded asynchronous execution, per-row results, and exact replay.
- [x] Add configurable webhook URL allow/deny policy on top of the existing SSRF controls,
      and revalidate the pinned policy at delivery time.
- [x] Bind every browser evidence PUT to a signed `If-None-Match: *` precondition and the
      exact CORS header allowlist, preventing replay or concurrent overwrite of an opaque
      object key between verification and scanning.
- [x] Wire the production DFIR upload verification, exact-stream hash/MIME policy, malware
      scan, retry/recovery queue, and fenced orphan cleanup into the worker runtime.
- [x] Make Case and Alert DFIR mutation receipts immutable and key-bound across later
      mutations, including IOC, asset, timeline, evidence/custody, relationship lifecycle,
      and consumed upload-prepare results.
- [ ] Close shared IOC/asset authorization across every linked Alert/Case and emit activity
      for every affected root; add explicit authorized link-existing/unlink lifecycle and a
      visibility-filtered related-root projection. Include all-root attachment prepare/replay
      authority, exact path-bound attachment/storage reads, and shared attachment activity.
      Track validated closing findings in `docs/dfir-shared-review.md`.
      The actual Go/PostgreSQL replacement matrix now passes IOC/asset through both Case
      and Alert across three shared roots: exact activity, historical replay, stale CAS,
      non-path permission revocation, 18-table denial snapshots and restored positive
      controls. It exposed and corrected nil-array SQL mapping, asset empty-tag readback
      comparison and the Alert legacy revision-collision error category; SQL is unchanged.
      Repeated on V50: `.tmp/v50-go-5a6d0dfd9ab94f2c8011b15cf5191520.log`
      and its proof JSON. The remaining native integration gap is authorized workspace
      loading with hidden roots, capability differences, revocation and cross-tenant
      denial; lower-level attachment reads do not replace that projection test.
- [x] Complete Case/Alert task parity: safe create, core details, assignment, due date,
      checklist, lifecycle/completion, generic comment association, optional SLA, and the
      corresponding operator UI.
- [x] Add append-only Case relationship retraction with CAS, exact replay, audit, activity,
      outbox, API, and UI parity with Alert relationships.
- [x] Permit typed relationships between any authorized endpoint pair in a Case/Alert
      workspace, including IOC-to-asset, using the persisted root context rather than
      requiring an endpoint to be the root. Verify endpoint scope/liveness, exact replay,
      retraction, and SQL enforcement without weakening dedicated Alert correlation rules.
- [x] Audit download-capability issuance atomically for operator and customer Case/Alert
      paths without recording object locations, filenames, URLs, or signed headers.
      The final sealed SQL customer matrix now covers Alert and Case: four positive
      grants and 26 denials, exact safe audit metadata, and nine-table rollback snapshots.
      The complete contacts/portal runtime passed on a fresh clone, supplementing the
      prior operator/shared-attachment Go/PostgreSQL proof; no production SQL changed.
- [x] Publish a reproducible current permission matrix (25 platform and 85 tenant keys),
      including catalog scopes and principal types, without inferring role assignments.
      Generate from Go evaluator metadata and the checked OpenAPI bundle; run drift,
      generator tests and vet in local verification and both CI workflows.
- [ ] Align every mutable DFIR API, ETag parser, generated client, server mapper, and web
      decoder with the shared JSON-safe bigint revision limit while preserving legacy ticket
      version bounds.
      Supplemental Case-task transport proof passes: HTTP preserves MAX_SAFE-1 to MAX_SAFE
      as an exact JSON number and ETag, while terminal/unsafe body and header inputs never
      reach the service. All six generated-client task actions accept the last increment;
      the web blocks terminal/unsafe task-detail requests before fetch. This does not close
      every resource family or replace a database mutation test.
      The IOC/asset replacement transport now also binds immutable receipts to the
      requested revision plus one on both Case and Alert, including historical replay
      and the last safe increment (24 new cases; both transport files pass 47 tests).
      OpenAPI now separates all 16 incrementing DFIR request schemas from terminal-safe
      response revisions; 19 AJV/schema tests pass, with TypeScript/Go artifacts regenerated.
      Custody's 999/1000 ceiling and legacy ticket bounds are unchanged.
      The same original-request receipt binding now covers the remaining 12 Task
      mutations, both custody append operations and both relationship retractions.
      Ninety-two new cases verify stale/skipped receipts, historical replay and caller
      mutation after request serialization; 139 transport tests and 196 tests with
      adjacent suites pass. A real all-family last-increment database matrix remains
      distinct from these client/contract proofs.
- [x] Define and enforce a bounded DFIR idempotency-retention window and cleanup behavior,
      including caller-owned identifiers and expired/consumed upload grants.
- [x] Restore canonical demo SLA processing through the actual worker. Generate the seed's
      calendar/rule/metric/trigger/policy documents and digests from the Go kernel, check
      identity bindings, and wire regeneration/drift/Go tests into root commands and both
      CI workflows. Project the tenant's complete valid calendar/column inventory onto the
      selected policy without relaxing strict assignment, tenant or duplicate checks.
      Bind the failure-query trace alias and normalize cursor instants to UTC before
      restoration. A fresh canonical clone passes two seed runs, seed audit and all seven
      real worker events (five Alert no-policy, Case assigned, Case updated), with no
      remaining/retry/dead-letter ingress and unchanged snapshots. This does not prove
      the 100k timer workload or container acceptance.
- [ ] Close the final-candidate authentication/authorization regressions: full built-in
      role-policy hydration across OpenAPI, Go and web; current human-role grant/revoke
      ABIs and group-member lifecycle revisions; federated MFA material-less lineage and
      current SAML logout coverage. Preserve retired ABI fences and repeat the real
      PostgreSQL gates after the fixes. Current diagnostics are recorded in
      `docs/release-acceptance.md` and `docs/dfir-shared-review.md`.
      Role/effective-authority web hydration now rejects unknown permission/scope enums,
      duplicate exact tuples and delegation outside the permission set, preserving the
      500-tuple read bound. The complete transport file passes 231 tests; stricter
      permission-to-scope/principal eligibility remains enforced by the backend.
      Remaining concrete runtime gap: a permitted SAML SLO configuration must create a
      continuation through `revoke_local_session_for_logout_v1`, then return the exact
      pinned material/configuration once through `claim_session_logout_continuation_v1`.
      The original real SAML matrix ended local-only with zero continuations, while
      positive SAML claim tests used Go fakes. This PostgreSQL gate does not require an
      external IdP; the added tenant-origin positive now passes, with platform blocked below.
      The added upstream-positive probe exposed a real audit-context failure. The Go
      adapter now installs the verified actor/tenant in its own short transaction;
      17 unit scenarios and a fresh-connection Go/PostgreSQL proof pass for two tenants,
      exact replay, rejected credentials, context isolation and cancellation during a
      locked audit write. Forward migration 0230 now permits explicit `tenantId:null`
      for platform logout without accepting an omitted tenant coordinate; 0231 seals
      the 232-migration V50 journal. The complete Go logout matrix passes both tenants,
      platform-local, invalid credentials, exact replay and cancellation. Fresh normal
      migration/restart and isolated V49/V50 upgrades pass with unchanged data/audit.
      The expanded SAML matrix now reaches its third origin but remains RED: the
      inherited typed-primary-provenance constraint accepts only OIDC platform-provider
      sessions, conflicting with the real SAML tenant-switch writer. Its synthetic third
      origin also needs complete identity/binding/epoch/access-grant fixture rows.
      Repair both without weakening provenance, then repeat all three origins. Evidence:
      `.tmp/v50-saml-d3084f1a1c4f4ffb9692011b600c66cd.log`; no SQL hotpatch was applied.
- [ ] Rebuild the final compatibility seal on the stable journal, then run the fresh full
      PostgreSQL 18.6 `test:security` aggregate and complete upgrade/compatibility matrix,
      replacing all pre-seal database evidence.
      Historical V49 seal `048078bb2a5c69057ec356857e323d55d0b97a43a5894e620140eab1f758414e`
      passed all 58 security suites in one aggregate, RLS, repeated seed/audit, the expanded
      13-test Go CI selection and all 19 upgrade entries with stable source hashes.
      These are native PostgreSQL 18.6 Windows/loopback `trust` results, not Docker or SCRAM
      authentication evidence. Exact source hashes and proof locations are recorded in
      `docs/release-acceptance.md`; these results do not cover current V50. Repeat the
      current 58-suite aggregate, RLS, seed/audit and 20-entry upgrade matrix after the
      SAML provenance correction; isolated V49/V50 upgrade proofs already pass.
- [x] Repeat the complete `pnpm verify` command after the final frontend/SR-18 changes.
      V50 verification passed with exit 0: web 155 files/2,152 tests, DB 73 files/627
      tests, notifier 175 with conditional Mailpit skipped, operations 52, generated
      drift (including permission catalog and canonical SLA fixtures), builds, Go
      vet/tests. Evidence: `.tmp/verify-v50-candidate-formatted-20260906.log`.
      Subsequent current-upgrade assertions also pass DB unit/typecheck/lint; MFA35's
      complete upgrade passes actual TCP SCRAM with wrong-password rejection and
      verified session-drain fencing. Proof:
      `.tmp/mfa35-scram-79787bed140846c4aeab45db07cf642b-proof.json`.
      The earlier performance and V49 gates are retained as historical evidence.
      Further source edits still require affected gates; this is not release acceptance.

## GitHub CI repair evidence

- [x] Create the private `xBounceIT/periapsis` repository and publish `main`; preserve
      subsequent user-authored README edits when integrating local work.
- [x] Restore the canonical historical bytes of migration 0198 in Git with an exact-path
      `-text` attribute. Its one embedded CRLF is part of its deployed SHA256; do not
      rewrite its SQL or normalize that file. Real Git tests pass with all three
      `core.autocrlf` modes; every other migration retains the normal LF policy.
- [x] Build exported contracts before type-aware lint, correct the worker elapsed-clock
      assertion and MFA35 fixture credentials, update pinned x/crypto and gRPC patches,
      quote workflow shell arguments and export the selected Docker daemon to scanners.
      DB unit tests: 627 PASS; operations: 52 PASS; actionlint plus ShellCheck: PASS.
      Local checks are not a successful rerun of the affected remote container jobs.
- [ ] Obtain green remote CI for the candidate. Gitleaks fixture/generated-source
      false positives, the disposable performance image's root wrapper, web multi-arch
      timeout, actual image vulnerability scans/SBOM, and composed acceptance still need
      verified resolution/evidence. Do not add broad scanner suppressions.

## Release evidence to obtain

- [ ] Run the candidate digests on the Docker-enabled release trust boundary and retain the
      successful Compose health/startup, live scenario journeys identified by the acceptance
      matrix (including LDAP/SSO, service-account HTTP/UI, concurrent claim, object storage,
      Swagger, and Mailpit), image scan/SBOM, and AMD64/ARM64 UID/GID 10001 read-only-root
      artifacts. Include one redacted sampled API → PostgreSQL/outbox → worker/notifier trace
      when tracing is enabled for the release.
- [ ] Execute the scheduled PostgreSQL 18.6 reference-performance job for the candidate and
      retain its sanitized 100,000-Alert/100,000-Case `EXPLAIN ANALYZE`, throughput, and
      concurrency evidence.
      Native diagnosis fixed the harness's persistent UTC setting (which changed a
      historical readiness hash) and removed inherited `DATABASE_URL_FILE` precedence.
      The next real run passed migration and seed but exposed fixture drift. The fixture
      now preserves the exact demo Case, adds 99,999 records per type, establishes tenant
      context, uses current creation times and checks canonical numbering receipts.
      The next runtime reached insertion but exhausted shared lock memory because of
      one 99,999-row transaction. Setup now commits batches of at most 1,000 tickets;
      the batched run then timed out in SLA ingress setup. A controlled 9,999-Alert
      comparison verified the benefit of refreshing ingress statistics between batches;
      the fresh full run now validates the complete dataset and passes the first three
      page plans. That run failed the state/severity index requirement. The revised
      fixture now interleaves canonical transitions and checks state/severity populations
      and chronology; both the two-batch proof and the subsequent full revised load pass.
      Ticket claims use the granted v2 ABI; ingest uses the transaction clock (old clock
      rejected/new clock committed on a fresh clone). SLA claims and candidate plans match
      the current v3 ingress barrier. All 52 harness tests pass. Canonical ingress settlement
      remains open at performance scale. The performance preset now uses generated kernel
      documents, published before ticket creation; all SLA fixture table writes are removed.
      The bounded CLI uses actual event/timer workers, file-only connection/pin validation
      and database-verified finalization receipts. Runner and image integration now include
      tracked worker processes, immutable snapshot checks, post-load ingress settlement,
      four concurrent timer batches and exact cleanup. A real two-batch proof passes
      2,023 ingress events, 1,999 materialized columns, 1,979 running/20 completed metrics,
      seed Alert no-policy preservation, and 100 real timer finalizations. It exposed and
      corrected the preset completion key to canonical `ticket.in_progress`; both demo
      and performance inputs declare the key explicitly and were regenerated.
      Source hashes/template remain unchanged after the proof and the clone was dropped.
      Log: `.tmp/actual-performance-fixture-sla-canonical-event-20260905.log`.
      The new full run settled all 101,003 events through the actual worker in 508.539s,
      with zero retry/dead-letter/fence loss, unchanged snapshots and 99,999 materialized
      values (1,000 completed/98,999 running metrics). The first four plans pass; the
      fifth fails only its exact-index assertion: the selective state page uses the
      existing state/priority index instead of the created index, at 10.832ms and 2,984
      shared blocks. Its full evidence is
      `tmp/performance/periapsis_performance_1788636376158_54b2296ad3c9.json`.
      Cleanup dropped the owned database, removed its private worker credential, stopped
      the owned server and proved stable source hashes. The run remains failed, not an
      accepted full-load/reference result. Remaining plans and concurrent loads are open.
      The state-only gate now admits either exact index on a contributing Alert scan;
      all other index requirements and every numeric/security/query/fixture control
      remain unchanged. All 96 performance tests pass, including full-budget pins and
      rejection of wrong-relation, dead, empty and malformed alternatives. A new complete
      run is required; the old failed evidence has not been rewritten.
      No barrier or numeric budget was weakened; see the performance runbook.
- [ ] Execute an approved isolated production-boundary restore drill and retain signed
      backup/object-storage, RPO/RTO, audit-retention, and export evidence.

## Handoff rule

Do not label the candidate production-accepted until every unchecked evidence item above is
attached to the exact immutable application and database-task digests. A source change after
evidence capture invalidates the affected artifact and requires that gate to be repeated.
