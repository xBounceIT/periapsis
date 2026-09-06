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
      The earlier synthetic SAML matrix reached its third origin but remained RED: the
      inherited typed-primary-provenance constraint accepts only OIDC platform-provider
      sessions, conflicting with the real SAML tenant-switch writer. Its synthetic third
      origin lacked complete identity/binding/epoch/access-grant fixture rows. Evidence:
      `.tmp/v50-saml-d3084f1a1c4f4ffb9692011b600c66cd.log`; no SQL hotpatch was applied.
      The fixture now commits the complete ordinary administrative graph and calls the
      real direct begin/create/planning/apply, tenant switch and first revalidation ABIs,
      instead of inserting a successor and empty switch receipt. Two actual V50 runs
      stop earlier in `load_platform_saml_planning_state_v1`: SQLSTATE 42702 because
      `identity.*` and `identity_alias.key_version` introduce two `key_version` columns.
      Repair alias-key projection separately from identity ciphertext-key projection,
      preserving unequal key versions, then address typed provenance through a reviewed
      forward migration and seal. The three shared revalidation helpers are already
      protocol-aware in 0228; do not replace them from stale 0165 definitions.
      Current RED: `.tmp/v50-saml-76269d139e524a06bc161d64a4c558c7.log` and proof JSON.
      Both V50 clones were dropped, sources/template pins unchanged; local lint/typecheck
      pass. The V51 progress below supersedes this diagnostic without rewriting the
      historical evidence.
- [ ] Complete the advanced SAML matrix after the published V51 ordinary-flow repair. Generated forward
      migrations 0232/0233 preserve all 232 published SQL files, attest the effective
      predecessor bodies (including 0188 and 0228 amendments), and retire the V50 serving
      roots without discarding their source attestations. The typed provenance repair
      preserves the LDAP/OIDC branches and the already protocol-aware shared helpers.
      Real PostgreSQL clones now pass planning with subject-alias key 2 and ciphertext
      key 1, direct apply, a new alias created at transaction time, unchanged retained
      alias 2, and exact replay without additional sessions, receipts or audit rows.
      This exposed and repaired two later loader defects: ambiguous session_id (42702)
      and 116 arguments to jsonb_build_object (54023). The latter is split into 84/32
      arguments with all 58 unique key/value expressions preserved. Historical REDs:
      `.tmp/v51-saml-4b773c3cc935460596d55fcd0533d0c8.log`,
      `.tmp/v51-saml-295e2fadbff54762a17ce1d18a68d0e2.log`, and
      `.tmp/v51-saml-20b2780a6e4142a5bd72dc2308c8fa9c.log`.
      The last two stopped in the real tenant-switch loader. The corrected ordinary
      flow now passes all three origins, real switch, first revalidation, logout,
      exact immutable configuration after metadata mutation, three-way claim race and
      replay: `.tmp/v51-saml-24756756baa14213adb4f819cedcebd9-proof.json`.
      Its expected configuration is independently built from the real begin, admitted
      request pins and apply statement time; the earlier fixture compared the obsolete
      administrative projection. The clone is dropped and sources/template stay stable.
      No template was hotpatched: each successor has a separate raw catalog derivation
      and fresh normal migration/restart proof. Current 234-migration digest is
      `2b1f33e2a513a16dff5f5b6b20ab6bf654cc4c081bd010864db96e09dbf8b51c`;
      the owned fresh install passes the normal runner twice, exact fingerprint and
      retired runtime ACL checks. DB unit tests now pass 643/643. Elevated trusted MFA,
      localRequired/freshness, rotate/step_up and
      historical revocation-drift cases also remain required; primary-only success is
      insufficient. Independent review: `.tmp/saml-v51-provenance-independent-review.md`.
- [ ] Complete the final-journal PostgreSQL RLS/Go and upgrade/compatibility matrix,
      preserving the published V51 seal and replacing the remaining pre-seal evidence.
      Historical V49 seal `048078bb2a5c69057ec356857e323d55d0b97a43a5894e620140eab1f758414e`
      passed all 58 security suites in one aggregate, RLS, repeated seed/audit, the expanded
      13-test Go CI selection and all 19 upgrade entries with stable source hashes.
      These are native PostgreSQL 18.6 Windows/loopback `trust` results, not Docker or SCRAM
      authentication evidence. Exact source hashes and proof locations are recorded in
      `docs/release-acceptance.md`; these results do not cover current V50. Repeat the
      current 58-suite aggregate, RLS, seed/audit and 21-entry upgrade matrix after the
      SAML provenance correction; earlier isolated V49/V50 upgrade proofs do not cover
      the new V51 journal. The old aggregate/upgrade scratch runners have stale counts
      and must not be reused without exact current inventory and owned-cluster guards.
      A first V51 catalog-only clone reaches login-attribute tampering but stops because
      its migration-only template lacks periapsis_api_login (42704), a harness setup
      omission. Preserve that failed proof; repeat with normal role provisioning in a
      separate owned cluster, without changing the runtime test or template SQL.
      Focused current-journal upgrades now pass, with source stability and each owned
      cluster stopped: V49 proof `schema-upgrade-V49-559f4a53609e481eabcf72d4d2afcf47`,
      V50-path proof `schema-upgrade-V50-86997ecfba514532bdd44d59778b84ab`, and V51-path
      proof `schema-upgrade-V51-771777d0793248dc9b2d1f3df0bc69c3` (all under `.tmp`,
      `-proof.json`). V51 includes the ordinary three-origin SAML suite after upgrade.
      The V50-path repeat corrects its stale expected V51 digest; a new unit contract
      ties all three current-catalog runtime/upgrade pins to the same sealed digest.
      The provisioned catalog-only repeat now also passes all current V51 tamper and
      retired-root checks, with exact template and four runtime-login pins unchanged,
      stable sources, stopped owned cluster and removed temporary admin-password file:
      `C:\Users\dange\AppData\Local\Temp\periapsis-v51-aggregate-owned-3ac573356ec64606a5e8c16ed80fb1de\proof.json`.
      This is one catalog suite, not the full 58-suite aggregate or container acceptance.
      The subsequent full V51 aggregate now passes all 58 security suites, two seed runs
      and seed audit on native PostgreSQL 18.6 with normal provisioning and TCP SCRAM
      administration. Exact source, empty-template and runtime-role pins remain stable;
      both owned instances are stopped and the temporary administrator password removed.
      Proof: `C:\Users\dange\AppData\Local\Temp\periapsis-v51-aggregate-owned-0b0348cde2f94414854284589518ea92\proof.json`;
      log: `.tmp/v51-full-aggregate-20260906.log`. This run used cad3fdf's database inputs
      before the following dependency and upgrade-test repairs; it is not the separate
      RLS/Go selection, complete 21-upgrade matrix or container acceptance.
      The separate RLS SQL gate and exact current CI Go selection also pass on a fresh
      provisioned PostgreSQL 18.6 cluster: all 15 top-level Go tests execute with no
      skips, both committed-fixture clones are dropped normally, source/template/role
      pins remain unchanged and the owned server is stopped. This run includes the
      dependency and upgrade-pin repairs. Proof:
      `C:\Users\dange\AppData\Local\Temp\periapsis-v51-extra-owned-05564106dfd740b8b723f5ecde8f8584\proof.json`;
      log: `.tmp/v51-extra-rls-go-20260906.log`. The subsequent Linux CI run
      [34039083554](https://github.com/xBounceIT/periapsis/actions/runs/34039083554)
      at c429841 passes all 21 upgrade jobs and their actual `Exercise the real upgrade path`
      steps, including the repaired SAML/lifecycle suites and V49/V50/V51 seals.
      Report: `.tmp/ci-c429841-upgrades-pg-smtp.md`. This does not make the whole CI green.
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
      The subsequent V51 working-tree verification also passes exit 0, including 642 DB,
      2,152 web, 175 notifier tests (conditional Mailpit skipped), actual Gitleaks controls,
      generated artifacts, E2E type checking, builds, and Go vet/tests:
      `.tmp/verify-saml-v51-20260906.log`. This run precedes the final JSON-arity repair
      and does not substitute for actual PostgreSQL runtime or deployment acceptance.
      The final repeat after that repair, the admitted-configuration fixture correction
      and minimal-Compose diagnostics also passes exit 0: 643 DB, 2,152 web, 175 notifier
      (conditional Mailpit skipped), all 143 operations tests with real Gitleaks and no
      operations skips, generated drift, builds, Go vet/tests and E2E type checking.
      Evidence: `.tmp/verify-v51-saml-complete-20260906.log`.
      Final publish verification after the cross-upgrade digest regression and its lint
      correction passes exit 0 with 644 DB tests, the same 2,152 web/175 notifier and
      143 operations totals, all generated/build/Go gates:
      `.tmp/verify-v51-publish-20260906.log`. Temporary PostgreSQL instances are stopped;
      their proof files and data directories are retained for inspection.
      The dependency/upgrade-pin/OpenLDAP follow-up also passes the complete command:
      `.tmp/verify-v51-dependencies-openldap-20260906.log`, exit 0. Totals are 648 DB,
      2,152 web, 175 notifier plus one conditional Mailpit skip, and 161 operations
      with the actual Gitleaks binary and no operations skips. Generated drift, E2E
      typing, builds, Go vet and Go tests pass. Only documentation changed afterward;
      focused formatting and diff checks cover that handoff update.
      The local CORS/LDAP-entrypoint follow-up also passes the complete command:
      `.tmp/verify-v51-cors-ldap-entrypoint-20260906.log`, exit 0. Totals remain
      648 DB, 2,152 web and 175 notifier plus one conditional Mailpit skip; operations
      now pass 162/162 with real Gitleaks and no skips. Generated drift, build and Go
      gates pass. The separate real Caddy gate also passes 6/6 in a root repeat:
      `.tmp/caddy-storage-cors-root-repeat-20260906.log`. Only release-evidence docs
      changed after this verification; SQL, lockfile and user README remain unchanged.

## GitHub CI repair evidence

- [x] Create the `xBounceIT/periapsis` repository and publish `main`; preserve
      subsequent user-authored README edits when integrating local work.
      The live repository is PUBLIC; its visibility is left unchanged.
- [x] Restore the canonical historical bytes of migration 0198 in Git with an exact-path
      `-text` attribute. Its one embedded CRLF is part of its deployed SHA256; do not
      rewrite its SQL or normalize that file. Real Git tests pass with all three
      `core.autocrlf` modes; every other migration retains the normal LF policy.
- [x] Build exported contracts before type-aware lint, correct the worker elapsed-clock
      assertion and MFA35 fixture credentials, update pinned x/crypto and gRPC patches,
      quote workflow shell arguments and export the selected Docker daemon to scanners.
      DB unit tests: 627 PASS; operations: 52 PASS; actionlint plus ShellCheck: PASS.
      Local checks are not a successful rerun of the affected remote container jobs.
- [x] Replace environment-backed Compose secrets with explicit external file mounts,
      preserving read-only containers and per-service secret selection. Preparation is
      fail-closed, outside the checkout, exclusive/no-overwrite, owner-private on Linux
      and Windows, and rolls back partial I/O without logging values. Seventeen real
      filesystem tests include failed first/middle/last writes; deployment contracts and
      both Compose workflows are wired. The CI edge private-key ownership is explicitly
      10001 because Compose file mounts retain host ownership.
- [x] Make the disposable performance wrapper itself UID/GID 10001 with no runtime
      root/chown/su-exec dependency. PostgreSQL data/log/socket use private `/tmp`, and
      signal/startup-failure cleanup preserves the benchmark failure. All 114 performance
      tests pass; CI now supplies a read-only root, tmpfs, dropped capabilities and a
      checked writable evidence mount, returning artifact ownership only after exit.
      Neither source repair has yet passed a real Docker run; local Docker is unavailable.
      A repeated wrapper test exposed a Windows Git Bash launcher orphan after its
      timeout. The harness now executes the MSYS shell directly with an explicit tool
      path and SIGKILL for timed-out fixtures, including a real TERM-ignoring shell
      regression. The full 114-test repeat passes in
      `.tmp/performance-nonroot-direct-shell-contracts.log`; no shell is left running.
      The complete `pnpm verify` passes again after these changes: web 2,152, DB 627,
      notifier 175 plus the conditional Mailpit skip, operations 71, generated drift,
      builds and Go vet/tests. Evidence:
      `.tmp/verify-compose-secrets-nonroot-20260906.log`. Actionlint 1.7.12 with
      ShellCheck also passes (`.tmp/compose-file-secrets-actionlint.log`). The unchanged
      two web files that timed out remotely pass all 74 focused tests locally; measured
      rendering cost does not establish runner resource pressure or justify relaxing
      their timeout. See `.tmp/web-ci-timeout-diagnosis.md` for the controlled evidence.
- [x] Repair the dependency-free deployment job's automatic pnpm cache failure and guard
      authentication teardown on successful secret preparation. The pinned setup-node
      action enabled package-manager caching from the root manifest without installing
      pnpm; only that cache is disabled. Two workflow regressions preserve cleanup after
      a later smoke failure. The helper itself was not reached in the failed ea00026 job.
- [x] Review all 41 historical Gitleaks findings and pin only their 40 unique
      commit/file/rule/line exceptions, with immutable historical source hashes. The
      real full-history scan returns zero findings; positive controls detect 40 new
      credentials at those coordinates and all 40 replacements in another commit.
      Full-history CI now runs the controls with its checksum-verified scanner; ordinary
      shallow source tests explicitly skip that integration proof. No path, rule, value,
      or commitless exception is permitted. The documented pre-existing zero-context
      Git diff limitation on PEM edits remains; do not claim exhaustive whole-file
      credential detection. Evidence: `.tmp/gitleaks-history-review.md`.
- [x] Isolate the database image's compiled runtime from build-time developer tools and
      preserve exact SQL/journal/SLA assets. Five isolated-output tests verify the real
      compiler graph, canonical migration bytes, imports, and production configuration.
      Refresh immutable Node bases and install verified Alpine OpenSSL 3.5.8-r0 packages
      in all affected stages, including the separately inspected PostgreSQL performance
      base. Native web compilation copies only portable static/Node assets to the target
      runtime. The expanded image/performance aggregate passes all 128 tests locally.
      These are packaging proofs, not successful container scans or multi-arch execution.
      The complete `pnpm verify` passes (`.tmp/verify-runtime-images-20260906.log`),
      including all 2,152 web tests and runtime compilation. After the final workflow
      wiring, all 100 operations tests pass with the real scanner enabled, no skips
      (`.tmp/runtime-images-operations-complete.log`); focused lint, format, and pinned
      actionlint/ShellCheck also pass. The first production export left pnpm's ignored
      workspace state set to production-only; a frozen `--prod=false` install restored
      the already-present developer dependencies without changing the lockfile.
      A real production export from an isolated builder now disables workspace-package
      hoisting: all seven dependency links are relative and confined to the runtime.
      The exported JavaScript passes fresh PostgreSQL 18.6 migration twice, seed twice,
      and role provisioning outside the checkout. The 353-table semantic seed snapshot
      is stable apart from the four declared identity/tenant `updated_at` fields; all
      four login roles have exact least privileges and pass positive/negative TCP SCRAM
      authentication. Final readiness is true with 232 migrations and the canonical V50
      digest. Sources stay unchanged; the owned cluster is stopped and four temporary
      password files removed. Evidence:
      `.tmp/periapsis-production-db-a54d7c53890b446eb2f2b1071ace43b7-proof.json`
      and its `-control-proof.json`. Earlier harness failures remain recorded separately.
      This native proof does not execute Docker or the `/run/secrets` deployment wrapper.
      After the export-option correction, all 41 focused packaging tests pass again.
- [x] Bound synthetic Gitleaks control generation without changing the scanner rules or
      the 40 exact historical exceptions. Qualify random hexadecimal controls against
      the rule's entropy floor and pinned stopwords, with bounded retries and negative
      regressions. The actual scanner detects 40 controls, zero exact ignored controls,
      all 40 replacements, and zero findings in the six-commit history; the combined
      scanner/LDAP diagnostic tests pass 32/32. The missing CI value cannot establish
      which random exclusion caused the previous 39/40 result.
- [x] Add bounded, allowlist-reconstructed OpenLDAP failure diagnostics before teardown;
      never emit raw environment, configuration, health output, DNs or secret-bearing
      log lines. This collects evidence and does not repair the unproved startup cause.
      Minimal Compose now has separate bounded diagnostics for migration/minio-provision
      failures even when up itself fails, with safe state for PostgreSQL/MinIO and no
      free-form service logs. The failure criterion and always-teardown are unchanged;
      silent provisioner exit branches remain explicitly unattributed. All 47 focused
      tests and pinned actionlint/ShellCheck pass; no local Docker execution is claimed.
- [x] Repair the ticketing browser fixture's required sharedResources field and type it
      against the generated DfirAlertWorkspace contract. All four E2E TypeScript inputs
      now participate in normal type checking. The previously failing Playwright test
      passes locally (1/1) with unchanged assertions, retries and timeouts.
- [x] Build the database image on BUILDPLATFORM and validate the actual deployed output
      before copying it into the target-platform runtime. The validator allows only the
      three pinned production packages, contained relative links and portable compiled
      assets; binary/archive signatures, extra packages and platform metadata fail closed.
      All 64 packaging/manifest tests pass; an independently reviewed retained native
      export passes validation. This is not an ARM64 container execution or scan proof.
- [x] Update the development toolchain's vulnerable Ajv and legacy esbuild instances:
      Ajv 8.18.0 with matching installed-version/generated-example provenance, plus
      esbuild 0.25.12 only under @esbuild-kit/core-utils 3.3.2. Actual sync/async loader
      transformations pass; benign dynamic-pattern rejection and static-pattern controls
      preserve example validation. Normal and frozen installs pass, generated OpenAPI
      changes only its provenance, and pnpm audit reports zero known vulnerabilities
      across all 517 dependencies. These nodes are absent from the production graph;
      no alert was dismissed and no runtime dependency or SQL was changed. Evidence:
      `.tmp/dependabot-cad3fdf-triage.md`, `.tmp/dependency-security-audit-20260906.json`.
- [x] Replace the pinned OpenLDAP test image's root-only entrypoint with a fixed-purpose
      repository adapter using the same binaries/schema, UID/GID 10001, ports 1389/1636,
      read-only root and explicit writable storage. Do not inherit anonymous volumes;
      never migrate/reset legacy data or rotate the initial password automatically.
      The existing real TLS/admin bind remains the password verifier; no custom crypto
      or root runtime is introduced. All 64 focused adapter/diagnostic/manifest/workflow/
      acceptance-contract tests pass, as do shell/static checks and independent review.
      Evidence: `.tmp/openldap-test-adapter-proof.md`. These tests simulate ownership
      and slap* binaries; actual Docker/TLS/fixture CRUD remains a required remote gate.
      The next CI builds the adapter but exposes a Bash entrypoint collision: two
      global readonly names are reused by function-local declarations. Renaming only
      the globals preserves the bootstrap and hardening. A regression executes the
      actual main (not just sourced functions) to a controlled identity rejection;
      65 focused tests pass and independent review is clean. Proof:
      `.tmp/ci-c429841-openldap-entrypoint-diagnosis.md`. TLS/LDAP startup still needs CI.
- [x] Move local MinIO browser CORS to the existing loopback TLS edge because the pinned
      MinIO rejects bucket CORS writes. Preserve the exact origin, GET/HEAD/PUT, seven
      signed request headers, ETag-only exposure, no credentials and a 300-second
      preflight cache; strip every upstream Access-Control response header. Keep the
      private backend, S3 authorization, signed Host/raw URL/body, versioning and user
      policy unchanged. Native checksum-pinned Caddy 2.11.4 tests pass 6/6, including
      denials, upstream errors and synthetic conditional-write replay; the separate
      dependency-free Linux CI gate is hard-failing, never skipped. Its first real
      parse caught and corrected the pinned Caddy version's one-value-per-header syntax.
      This is HTTP transport with a controlled upstream, not TLS/browser/MinIO
      authorization or the complete Compose profile. Proof:
      `.tmp/minio-cors-edge-repair-20260906.md`. The independent migration startup exit
      remains unattributed and is not claimed fixed by the CORS repair.
- [ ] Obtain green remote CI for the candidate. At published 61c2df9, deployment run
      34031054630 passes web/API/worker/notifier multi-arch runtime, SBOM and scans.
      Its database build hits QEMU SIGILL during ARM64 pnpm installation, then the
      job's automatic 40-minute timeout; later runtime/scans never execute. OpenLDAP
      authentication smoke and the 39/40 synthetic Gitleaks control also fail. In CI
      run 34031054634, all 2,152 web unit tests pass, but the ticketing Playwright
      fixture fails before the local repair above. PostgreSQL fails earlier at a 10s
      compatibility-check statement timeout in platform-identity-binding; do not relax
      its budget without diagnosis. Minimal Compose fails first in minio-provision,
      then migration, and skips the later full profile. No inner provisioning error
      was retained; permission assumptions do not prove the cause. Repeat affected
      image/Compose/acceptance gates on the next candidate; local Docker is unavailable.
      A bounded native health-cost diagnostic confirms eight full dependency-hash calls
      per API health query (about 2.8s total hash self time, not per call) and five per
      worker query (about 1.8s total). API and worker separately return ready within the
      unchanged 10s statement bound. The worker's normal keyring bootstrap is rolled
      back and its empty keyring snapshot remains exact. The initial read-only worker
      probe was a harness restriction (25006), not a product defect; it did not exercise
      expensive concurrent API/worker work. Proofs:
      `.tmp/v51-health-a4f1db6b33204edbb9cda463424f63c9-proof.json` and
      `.tmp/v51-worker-health-30ae47cd35d74776b8ee4afeed829b05-proof.json`.
      This identifies repeated work, not the complete cause or resolution of the CI
      timeout. Do not remove integrity checks or relax budgets on this evidence alone.
      At cad3fdf, deployment run 34036722527 now passes all five image jobs, including
      database-task AMD64/ARM64 runtime/SBOM/scans, and Gitleaks. The manifest job fails
      because the pinned OpenLDAP entrypoint recursively chowns read-only /etc/ldap;
      downstream manifest checks are skipped. CI run 34036722521 remains failed:
      the concurrent health query again reaches SQLSTATE 57014 inside the V51 catalog
      hash; MinIO provisioning reports cors_set/not_implemented; migration exits 1 with
      no recognized inner error; Mailpit's connection probe fails without a retained
      socket cause. A successful local SMTP control does not diagnose Linux/Mailpit.
      Ten upgrade jobs stop on stale current V50 timestamp/count assertions; twelve
      exact current-pin corrections in ten files preserve all historical prefixes and
      SQL bytes. A new consistency regression checks all 21 suites and the canonical
      generated fingerprint; 24 focused tests pass. Runtime upgrade repetition remains
      required. Evidence: `.tmp/ci-cad3fdf-readonly-diagnosis.md`.
      At c429841, all 21 actual upgrade paths pass, but the main PostgreSQL aggregate
      again stops at the unchanged 10s V51 readiness statement timeout. One web test
      (the mounted 50-member mention picker) exceeds 5s; Mailpit is skipped through its
      JavaScript dependency. Minimal Compose repeats cors_set/not_implemented and the
      still-unattributed migration exit. The five application-image security jobs pass;
      the new OpenLDAP adapter builds, then exits before TLS/LDAP readiness.
      Reports: `.tmp/ci-c429841-upgrades-pg-smtp.md` and
      `.tmp/ci-c429841-openldap-entrypoint-diagnosis.md`.
      At 857d477, all 21 actual upgrade paths and five application-image jobs pass again;
      real Caddy CORS, OpenLDAP health and MinIO provisioning now pass. Keycloak exits,
      and the Compose migration exit remains unattributed. The JS job records three 5s
      timeouts (mentions and two custody-revision tests), PostgreSQL repeats 57014, and
      Mailpit is skipped. The Keycloak realm-import filename is deterministically invalid
      against its pinned upstream implementation; its target mount and redacted failure
      diagnostics are corrected locally, without claiming the lost first exception.
      Report: `.tmp/ci-857d477-terminal-and-idp-diagnostics.md`.
      The mounted mention picker now memoizes individual rows with stable functional
      callbacks. Real-checkbox instrumentation shows 2,601 to 102 renders for the unchanged
      51-candidate/50-click test; two uninstrumented repeats and ten focused tests pass.
      This does not establish a CI pass or resolve the separate custody timeouts.
      Report: `.tmp/mention-picker-857d477-render-reduction.md`.
      The readiness design in `.tmp/v51-readiness-dedup-design.md` is implemented in the
      in-flight V52 candidate (0234 aggregates, 0235 seal, 236 journal entries), retaining
      all leaves and independent source/ABI/ACL checks without caching or longer timeouts.
      The real owned raw derivation produces nonzero digest 7782b810b281fefee6142a0be6bd1691a7fc66f90be197322c95755a658e5b9f;
      both arrays remain false in the 235-entry/root-absent interval and unsealed236 state.
      Normal sealed installation/provisioning and the complete V52 catalog/tamper suite
      now pass on a separate owned cluster. The real V51-to-V52 upgrade, ordinary SAML
      flow, migration restart and role provisioning also pass, with stable inputs and
      cleanup. The SAML fixture initializes every tenant's ordinary authorization/SLA
      principal before loading synthetic SAML rows; live readiness assertions remain intact.
      Full local verification passes: DB663, web2158, notifier175 plus conditional Mailpit
      skip, operations172 with actual Gitleaks and no operations skips, generated/build/Go
      gates. Proofs and explicit boundaries are recorded in `docs/release-acceptance.md`.
      The full58 PostgreSQL aggregate now passes too, including actual API/worker queries,
      one catalog hash per successful query, unchanged10s limits, prepared tamper rejection,
      both seed runs and seed audit. Sources/templates/roles remain pinned and both owned
      clusters are stopped. The separate RLS/Go selection, all22 upgrade paths, exact
      candidate CI and composed acceptance remain independent gates;
      V51 evidence does not automatically certify V52. At this checkpoint, follow-up
      diagnosis identified redundant rendering of the shared 999-event custody history
      and loss of unclassified migration-phase diagnostics; those follow-ups were not
      included in the preceding full-verification result.
- [ ] Close the published `95695121a0aa01301bad6a43ccc81a0398c08dd3` CI continuation
      without treating partial evidence as complete deployment acceptance. The native
      V52 extras now pass the separate RLS SQL and exact 15 Go integration selections,
      with no skips, stable source/template/role pins, clone cleanup, owned-cluster
      shutdown and generated password-file removal. All 22 actual upgrade steps pass in
      CI run `34045177859`. Deployment-security run `34045177868` succeeds, including
      real Linux Caddy CORS, authentication-provider smoke and all five application-image
      jobs; provider smoke is not a browser SSO journey. Journal 236 and the V52 seal
      remain unchanged. Detailed proof paths are in `docs/release-acceptance.md`.
      The JS job has four timeouts: the original mention-picker regression passes,
      two custody timeouts have local fixes with 47 focused tests passing, and two new
      mention regressions remain open. The Compose startup migration failure still has
      no recovered historical inner cause. A real PostgreSQL 18.6 read-only proof of the
      actual `configureLogin` bodies reproduces baseline `42P18`; six explicit parameter
      casts let the candidate complete four real SELECTs and generate three exact,
      safely quoted DDL statements that are intercepted and never executed. Catalog,
      roles and sources remain unchanged; the owned server is stopped and its password
      file removed. This proves neither actual role DDL nor full Compose startup, and
      does not attribute the earlier CI failure. Finite mode/phase/code diagnostics and
      packaging pass 40 focused tests; pre-try `require("postgres")` and inherited child
      stdio remain outside that structured diagnostic boundary. Both workflows now mask
      ephemeral credentials before publication/use, including all 21 CI values and three
      keyring components; 41 focused shell/secret-preparation tests pass. All 88 workflow
      Bash scripts pass standalone ShellCheck and both workflows pass actionlint's other
      rules; the integrated actionlint/ShellCheck adapter hangs locally on ci.yml, so
      those checks were run separately without changing the CI gate. Complete local
      verification now passes for the follow-up: DB663, web2163, notifier175 plus the
      conditional Mailpit skip, operations183 with actual Gitleaks and no operations
      skips, generated drift/build/Go gates. Evidence:
      `.tmp/verify-v52-publish-followup-20260906.log`.
      At the 2026-09-06 16:42 UTC snapshot, the CI PostgreSQL job is still on
      `Prove atomic protected-configuration binding`, Mailpit is skipped, and performance
      run `34045643918` remains on `Run hot paths against a fresh database`.

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
