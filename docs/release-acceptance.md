# Release acceptance evidence

Last audited: 2026-09-07

This matrix maps the 13 required end-to-end scenarios to source, focused tests, and the
remaining proof boundary. The open source items in [`TASKS.md`](../TASKS.md) remain release
blockers even where an adjacent scenario already has focused evidence. “Source present” does
not mean a database-runtime gate is green,
and a green repository gate does not replace a retained container/CI or production-boundary
artifact. The current candidate state appears after the matrix; external evidence is also
tracked in [`TASKS.md`](../TASKS.md).

The 2026-09-06 remote-proxy slice adds HTTP-origin deployment variants without local web
certificates. It retains an HTTPS public origin, explicit immediate-peer CIDR trust, secure
cookies and CSRF checks; it does not alter migrations, the V52 seal, or tenant policy.
Focused evidence covers real Node HTTP requests, the production Go router on a plaintext
backend socket, 14 real Compose config checks and 16 real Caddy HTTP/CORS checks. These
are local transport/configuration tests, not a running Docker stack, authenticated S3/IdP
acceptance, production rollout, or verification of a site's NAT/firewall rules. The
[deployment runbook](operations/deployment.md#remote-reverse-proxy-with-an-http-origin)
defines those remaining checks.

Root `pnpm verify` completed successfully for this slice; the final entrypoint-test/CI
wiring addition was followed by a clean 189-test operations rerun. Compose and Caddy
runtime/configuration gates also passed separately; the conditional Mailpit test still
requires its external fixture. See the dated slice in `TASKS.md` for exact local evidence.

The matrix retains earlier focused and final-journal results. Those labels do not
carry forward to a new seal automatically: only the explicitly versioned evidence below
applies to the named candidate. V53 is currently under verification, not production-validated.

| Scenario                         | Repository evidence                                                                                                                                                                                                                                             | Automated repository gate                                                                                                                                                                                                                                                                                                                                                                                                      | Current proof boundary                                                            |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------- |
| 1. Tenant isolation              | Forced-RLS tenant schema, application authorization, customer-safe ticket/DFIR projections, explicit platform-to-tenant access, and tenant-aware bulk/export/download paths                                                                                     | [`tests/security/rls.sql`](../tests/security/rls.sql), [`ticket-query-projections-runtime.ts`](../packages/db/tests/security/ticket-query-projections-runtime.ts), [`ticket-bulk-export-runtime.ts`](../packages/db/tests/security/ticket-bulk-export-runtime.ts), [`contacts-portal-runtime.ts`](../packages/db/tests/security/contacts-portal-runtime.ts)                                                                    | Final-journal PG/RLS passes; composed tenant-isolation proof remains external     |
| 2. LDAP and role mapping         | Tenant LDAP and physically separate platform-global LDAP, AD/OpenLDAP/POSIX templates, diagnostics, dry-run/login shared planning, JIT/pre-link, group/role/team reconciliation, removal revocation, audit, and session revalidation                            | [`ldap-auth-acceptance.mjs`](../tests/integration/ldap-auth-acceptance.mjs), [`interactive-ldap-authentication-runtime.ts`](../packages/db/tests/security/interactive-ldap-authentication-runtime.ts), [`ldap-denied-reconciliation-runtime.ts`](../packages/db/tests/security/ldap-denied-reconciliation-runtime.ts)                                                                                                          | Focused platform-LDAP slice passes; composed browser evidence is external         |
| 3. SSO and MFA                   | Tenant/platform OIDC and SAML transactions, JIT/pre-link planning, exact IdP-assurance trust, TOTP/WebAuthn/recovery/device lifecycle, local step-up, and live session provenance                                                                               | [`federated-authentication-runtime.ts`](../packages/db/tests/security/federated-authentication-runtime.ts), [`platform-saml-direct-runtime.ts`](../packages/db/tests/security/platform-saml-direct-runtime.ts), [`identity-mfa-runtime.ts`](../packages/db/tests/security/identity-mfa-runtime.ts), [`tenant-provider-mfa-continuation-runtime.ts`](../packages/db/tests/security/tenant-provider-mfa-continuation-runtime.ts) | Final-journal SSO/MFA and readiness pass; real IdP/browser evidence external      |
| 4. Alert API                     | Tenant service accounts and one-time keys, scoped `alert.create`, custom fields/tags/raw payload, idempotent receipts, list filters, generated contract, and operator rendering                                                                                 | [`service-principal-alert-concurrency.ts`](../packages/db/tests/security/service-principal-alert-concurrency.ts), [`verify-ticketing-contract.mjs`](../packages/contracts/scripts/verify-ticketing-contract.mjs), web ticket tests under [`apps/web/src/ticketing`](../apps/web/src/ticketing)                                                                                                                                 | Final-journal PG gate passes; live HTTP/Swagger/UI evidence external              |
| 5. Claim race                    | Versioned ticket command kernel commits one claim winner with activity, audit, outbox, and SLA ingress; stale competitors conflict                                                                                                                              | [`service_test.go`](../services/api/internal/ticketing/service_test.go), [`commands_test.go`](../modules/ticketing/commands_test.go), [`ticketing_handlers_test.go`](../services/api/internal/httpserver/ticketing_handlers_test.go)                                                                                                                                                                                           | Unit/fake-repository proofs exist; concurrent live result is external             |
| 6. Escalation and links          | Alert and Case remain separate; escalation/link copies only selected tags, custom fields, IOC, assets, attachments, public comments, and contacts with immutable provenance; replay returns the same identities; unlink is an append-only double-CAS retraction | [`escalation_test.go`](../modules/ticketing/escalation_test.go), [`phase-three-live.spec.ts`](../tests/e2e/phase-three-live.spec.ts), [`0217_alert_case_link_lifecycle.sql`](../packages/db/migrations/0217_alert_case_link_lifecycle.sql)                                                                                                                                                                                     | Final-journal link lifecycle and seal pass; live replay is external               |
| 7. Comment visibility            | Immutable comment/revision/author snapshots and a shared fail-closed visibility policy drive API, portal, notification, webhook, export, and attachment projections                                                                                             | [`ticket-comment-runtime-repair.ts`](../packages/db/tests/security/ticket-comment-runtime-repair.ts), [`contacts-portal-runtime.ts`](../packages/db/tests/security/contacts-portal-runtime.ts), [`fanout.test.ts`](../services/notifier/src/fanout.test.ts), [`customer_portal_export_test.go`](../services/api/internal/ticketing/customer_portal_export_test.go)                                                             | Focused projection/component proofs exist; all-channel live proof external        |
| 8. DFIR                          | Case and Alert have IOC, assets, evidence, timeline, tasks, attachments, and relationships. Implemented resources include S3 metadata, scan state, SHA-256, custody, activity, audit, and outbox boundaries.                                                    | [`alert-dfir-runtime.ts`](../packages/db/tests/security/alert-dfir-runtime.ts), Go tests under [`modules/dfir`](../modules/dfir), web tests under [`apps/web/src/dfir`](../apps/web/src/dfir)                                                                                                                                                                                                                                  | Focused repository/runtime proofs exist; Docker-backed object storage is external |
| 9. SLA                           | Immutable policy/calendar versions, multiple metrics and columns, Europe/Rome/DST business time, pause/override, simulator, fenced workers, warnings/breaches, notification/webhook/ticket/team/task actions, no-loop system Alerts, and audit                  | [`sla-runtime.ts`](../packages/db/tests/security/sla-runtime.ts), [`sla-trigger-actions-runtime.ts`](../packages/db/tests/security/sla-trigger-actions-runtime.ts), Go tests under [`modules/sla`](../modules/sla), web tests under [`apps/web/src/sla`](../apps/web/src/sla)                                                                                                                                                  | Final-journal PG SLA gates pass; live warning delivery is external                |
| 10. Email templates              | Versioned HTML/CSS templates, allowlisted placeholders, sample preview, script/handler sanitization, plaintext, SMTP/webhook delivery, retries, and delivery evidence                                                                                           | [`template.test.ts`](../services/notifier/src/template.test.ts), [`mailpit.acceptance.test.ts`](../services/notifier/src/mailpit.acceptance.test.ts), [`notification-concurrency.ts`](../packages/db/tests/security/notification-concurrency.ts)                                                                                                                                                                               | Unit proof exists; Mailpit test is conditional and needs retained CI output       |
| 11. Swagger and generated API    | `/openapi.json`, optional `/docs`, canonical OpenAPI 3.1, generated Go/TypeScript, endpoint inventories, and drift detection                                                                                                                                    | [`openapi.yaml`](../packages/contracts/openapi/openapi.yaml), contract scripts under [`packages/contracts/scripts`](../packages/contracts/scripts), generated job in [`ci.yml`](../.github/workflows/ci.yml)                                                                                                                                                                                                                   | Contract/drift proof exists; live route rendering belongs to stack evidence       |
| 12. Audit                        | Separate tenant/platform append-only streams, recursive redaction, self-audited readers/exports, tamper-evident chains, constrained retention, and runtime-role update/delete denial cover login, ticket, LDAP, SLA, and delivery events                        | [`audit-reader.ts`](../packages/db/tests/security/audit-reader.ts), [`audit-operations-runtime.ts`](../packages/db/tests/security/audit-operations-runtime.ts), [`audit_test.go`](../services/api/internal/postgres/audit_test.go)                                                                                                                                                                                             | Final-journal PG audit gates pass; signed retention proof external                |
| 13. Containers and orchestrators | Numeric UID/GID 10001 images, read-only roots, explicit tmpfs, health probes, dropped capabilities, Compose profiles, Swarm template, Kustomize overlays, SBOM and scanning jobs                                                                                | [`ci.yml`](../.github/workflows/ci.yml), [`deployment-security.yml`](../.github/workflows/deployment-security.yml), [`validate-manifests.test.mjs`](../scripts/deploy/validate-manifests.test.mjs), deployment runbooks under [`deploy`](../deploy)                                                                                                                                                                            | Static manifest proof exists; container runtime and multi-arch are external       |

## Cross-scenario release gates

The root `verify` command covers formatting, lint, TypeScript checks, unit tests, operations
contracts, generated drift, builds, Go vet, and Go tests. It does not run the PostgreSQL
security matrix or the Docker-backed acceptance jobs. PostgreSQL security suites use a real
PostgreSQL 18 database and are intentionally separate because they require an explicit
disposable database authority. The composed full-stack CI profile starts API, worker,
notifier, edge, PostgreSQL, OpenLDAP, Keycloak, MinIO, ClamAV, Mailpit, and a browser. Its five
non-intercepted Playwright scenarios cover Swagger and tenant isolation, comment privacy
across API/UI/export, object storage and DFIR, LDAP claim plus idempotent escalation, and
Keycloak OIDC/JIT/MFA. Workflow wiring and test discovery are not evidence that the job
passed for the current candidate.

The repository also includes static/runtime-boundary coverage for structured logging,
OpenTelemetry propagation, queue and delivery metrics, Prometheus rules, and the Grafana
dashboard. These controls are implementation evidence, not substitutes for observing a
sampled trace or alert in the release environment.

## Current candidate database evidence

### V53 tenant LDAP configuration candidate

Migration 0236 adds V2 tenant LDAP configuration writes for the JIT, admission,
deprovisioning and synchronization policies already exposed by the API. It preserves
authorization, transactional audit, certificate verification and relational constraints.
Migration 0237 seals the 238-entry journal with catalog digest
`25836ab746715d3cec731946d6c5730998b42ca4cf48185346c5254823ef0b51`.
Published migrations 0000-0235 remain byte-identical.

Raw native PostgreSQL 18 derivation retains false readiness before sealing
(`.tmp/ci-fix/derive-v53-native.log`). Normal installation and the complete V53
catalog, role, ACL, credential and retirement tamper suite pass with the real
runtime-role provisioner (`.tmp/ci-fix/v53-runtime-native2.log`). The V52-to-V53 upgrade preserves existing
sessions, audit events and logout receipts, including replay after runner restart
(`.tmp/ci-fix/v53-upgrade-native.log`). The retained upgrade suites starting from
V49, V50 and V51 also pass through the current V53 seal
(`.tmp/ci-fix/v50-current-upgrade-native.log`,
`.tmp/ci-fix/v51-current-upgrade-native.log`,
`.tmp/ci-fix/v52-current-upgrade-native.log`). Native Go provider create/update,
denied-mutation and both service readiness suites pass
(`.tmp/ci-fix/v53-go-native-third.log`). Actual HTTP
provider, binding and mapping create/enable flows pass
(`.tmp/ci-fix/ldap-mapping-v53-fixed-native.log`). Full Linux CI and composed LDAP
authentication remain required; earlier V52 evidence below is historical.

### V52 candidate under verification

Forward migration 0234 adds role-specific API/worker readiness aggregates; 0235 seals
the 236-entry journal. The published 0000-0233 prefix remains byte-identical. Each
aggregate performs one release attestation per invocation, retains all ordered live-data
checks and stays inside the full catalog transcript. Serving Go queries independently
attest the aggregate source, complete ABI/owner/ACL and the retained V51 predecessor.
The worker's ordinary keyring write remains outside the stable aggregate; neither
statement timeouts nor cross-statement trust are changed.

The nonzero V52 catalog digest is
`7782b810b281fefee6142a0be6bd1691a7fc66f90be197322c95755a658e5b9f`,
derived on a new PostgreSQL 18.6 UTF8/C cluster with TCP SCRAM. The 235-entry interval
returns fixed false arrays for both services while the V52 release root is absent.
The raw 236-entry candidate also remains unsealed/not ready. Proof:
`C:\Users\dange\AppData\Local\Temp\periapsis-v52-catalog-owned-93520f08e6f14f24bedbd67afef09937\derivation-proof.json`.
The companion transport proof retains stable input hashes, cluster shutdown and removal
of the generated administrator password file. This is catalog derivation, not evidence
of a normal sealed installation, upgrade, runtime matrix, optimized timing or green CI.

The subsequent normal installation and complete V52 catalog/tamper suite pass on a
separate owned PostgreSQL 18.6 cluster, after ordinary migration and runtime-role
provisioning. Journal, catalog, source, template and SCRAM role pins remain unchanged;
the cluster is stopped. This is catalog-only mode, not the full 58-suite aggregate.
Proof:
`C:\Users\dange\AppData\Local\Temp\periapsis-v52-aggregate-owned-a4a2970e5b0d44b59284be8ad9631c34\proof.json`.

The real V51-to-V52 upgrade also passes from the exact published 234-entry prefix:
the 235-entry interval fails closed, final V52 sealing preserves fixture/replay data,
retires historical roots, and passes the ordinary three-origin SAML flow. Normal
migration restart and runtime-role provisioning pass afterward. The SAML test fixture
now initializes each tenant through ordinary authorization/SLA-principal setup before
loading its synthetic SAML graph; no readiness leaf or assertion was relaxed. Stable
source pins, owned-cluster shutdown and removal of all five generated password files
are retained in
`C:\Users\dange\AppData\Local\Temp\periapsis-v52-upgrade-owned-fd452afc0a3347d685dda995502e6ca1\proof.json`.
This is one upgrade path, not a new pass of the complete 22-path matrix.

The full V52 aggregate subsequently passes all 58 PostgreSQL security suites, both
seed runs and seed audit on fresh isolated databases. It includes the actual Go API
and worker readiness queries with unchanged 10-second statement limits, exactly one
catalog-hasher call per successful query, prepared-statement tamper rejection and
rollback restoration. Both unseeded templates and provisioned roles retain their exact
pins; all source hashes are stable, both owned clusters are stopped and the generated
administrator password file is removed. Proof:
`C:\Users\dange\AppData\Local\Temp\periapsis-v52-aggregate-owned-e67d84a794b7437eb5cfc7ad62bf0a41\proof.json`.
The separate RLS SQL and 15-test Go CI selections are not part of these 58 suites.

Complete local `pnpm verify` passes for this V52 source candidate: 663 DB tests,
2,158 web tests, 175 notifier tests plus one conditional Mailpit skip, and all 172
operations tests with the real Gitleaks scanner and no operations skips. Formatting,
lint, TypeScript/E2E checks, generated drift, builds, Go vet and Go tests pass. Evidence:
`.tmp/verify-v52-service-readiness-final-20260906.log`.
The separate RLS/Go selection, complete upgrade matrix, current CI and composed
acceptance remain independent gates; this local verification is not production approval.

### Published V52 continuation: 9569512

The subsequent published candidate is
`95695121a0aa01301bad6a43ccc81a0398c08dd3`. Its 236-entry journal and V52 seal are
unchanged. The repository is PUBLIC; no visibility change is part of this continuation.
The complete local verification recorded above predates the follow-up changes below
and must not be counted as their verification.

The separate native PostgreSQL 18.6 UTF8/C, TCP-SCRAM extras pass the RLS SQL and
exact 15 Go integration selections, with no skips. Normal migration/provisioning,
source/template/role pins and clone cleanup pass; the owned server is stopped and
the generated password files are removed. Proof:
`C:\Users\dange\AppData\Local\Temp\periapsis-v52-extra-owned-f736a61233e04bb2a5e8a96ba2d411fd\proof.json`.
This is native database evidence, not Docker or browser acceptance.

All 22 actual upgrade steps pass in
[CI run 34045177859](https://github.com/xBounceIT/periapsis/actions/runs/34045177859).
[Deployment-security run 34045177868](https://github.com/xBounceIT/periapsis/actions/runs/34045177868)
completes successfully, including the real Linux Caddy CORS gate, authentication-provider
smoke, all five application-image jobs and secret scanning. The external notifier-image
job is intentionally skipped. Provider startup/metadata smoke does not prove the full
application browser SSO journey, and the CORS fixture is not actual MinIO signature
validation.

The same CI run's JavaScript job has four timeouts. The original mounted mention-picker
regression passes; two custody timeouts have local fixes with 47 focused tests passing,
while two new mention regressions remain open. The Compose startup migration job fails,
but its historical inner exception is still unavailable. Neither adjacent provider
success nor the local SQL proof below identifies that lost exception.

A separate fresh owned PostgreSQL 18.6 probe executes the actual AST-extracted
`configureLogin` function from the published wrapper and the corrected candidate.
The baseline fails with `42P18`; six explicit parameter casts across three `format`
queries let the candidate complete four real SELECTs. Three exact, safely quoted
ALTER/RESET/GRANT statements are intercepted and never executed. The transactions are
read-only, and catalog, roles and source hashes remain unchanged. The owned cluster
is stopped and its administrator password file removed. Proof:
`C:\Users\dange\AppData\Local\Temp\periapsis-compose-format-owned-159a20c5b05e4be9ade400759ec1076e\proof.json`.
This does not prove role-DDL application, runtime-login provisioning, full Compose
startup or the historical CI cause.

The local finite mode/phase/code diagnostic and packaging checks pass 40 focused tests.
Unknown errors retain a fixed `UNCLASSIFIED` event without exposing driver messages,
SQL, parameters or credentials. The module's pre-try `require("postgres")` and inherited
child stdio remain outside this structured diagnostic boundary.

Both workflows now mask generated ephemeral credentials before publication/use. The
main CI masks all 21 secret values and the three raw keyring components before writing
`GITHUB_ENV`; the deployment workflow masks its two generated S3 values. Existing
credential bytes, file mounts, preparation rollback and teardown are preserved. All 41
focused shell/secret-preparation tests pass, including real Bash order checks and
sanitized failure assertions. This change does not retroactively redact earlier logs.
Both workflows pass actionlint's internal rules with its ShellCheck adapter decoupled;
all 88 actual Bash scripts pass standalone ShellCheck with the adapter's standard flags.
The integrated adapter stalls locally on `ci.yml` and its bounded attempts were stopped;
no source workaround or CI gate relaxation was applied.

Complete local `pnpm verify` subsequently passes for these follow-up code and workflow
changes: 663 DB tests, 2,163 web tests, 175 notifier tests plus one conditional Mailpit
skip, and all 183 operations tests with the actual Gitleaks scanner and no operations
skips. Formatting, lint, TypeScript/E2E checks, generated drift, builds, Go vet and Go
tests pass. Evidence: `.tmp/verify-v52-publish-followup-20260906.log`. This is local
verification, not proof that the new composed stack or remote CI passes.

At the retained **2026-09-06 16:42 UTC** snapshot, the CI PostgreSQL job is still running
`Prove atomic protected-configuration binding`; Mailpit is skipped.
[Performance run 34045643918](https://github.com/xBounceIT/periapsis/actions/runs/34045643918)
is still running `Run hot paths against a fresh database`. These are pending gates,
not successful results. Full Compose acceptance and the open JavaScript regressions
remain release blockers.

### Published V51 evidence

The published V51 database baseline is `cad3fdf8a8887b865f620eb209025312ba03b83e` on
[`xBounceIT/periapsis`](https://github.com/xBounceIT/periapsis). It has 234 immutable
migrations, ending at 0233, and catalog digest
`2b1f33e2a513a16dff5f5b6b20ab6bf654cc4c081bd010864db96e09dbf8b51c`.
Forward migration 0232 repairs the ordinary SAML planning, typed provenance and
session-material loader paths; 0233 seals V51 and retires the V50 serving roots.
All previously published migration bytes are preserved.
Subsequent development-toolchain, test and OpenLDAP-fixture repairs recorded in
`TASKS.md` do not change this SQL journal or catalog seal.

Verified on isolated native PostgreSQL 18.6 databases:

- Fresh installation through the normal migration runner twice preserves the exact
  journal fingerprint, readiness, catalog digest and retired-runtime ACLs. Proof:
  `C:\Users\dange\AppData\Local\Temp\periapsis-v51-fresh-151597124ea5483982113ea9f9810455\fresh-proof.json`.
- The ordinary three-origin SAML flow passes real administrative setup, admission,
  tenant switch, first revalidation, logout, immutable configuration after metadata
  change, a three-way claim race and exact replay. Its expected configuration is
  independently derived from admitted request pins and apply statement time. Proof:
  `.tmp/v51-saml-24756756baa14213adb4f819cedcebd9-proof.json`.
- Current V51 catalog/tamper checks pass after normal runtime-role provisioning,
  with TCP SCRAM administration and unchanged template, role and source pins. Proof:
  `C:\Users\dange\AppData\Local\Temp\periapsis-v51-aggregate-owned-3ac573356ec64606a5e8c16ed80fb1de\proof.json`.
  This is the catalog-only mode, not all 58 security suites.
- The subsequent full aggregate passes all 58 suites, two seed runs and seed audit
  against cad3fdf's database inputs. Normal provisioning and TCP SCRAM administration,
  unchanged source/template/role pins and shutdown of both owned clusters are retained
  in `C:\Users\dange\AppData\Local\Temp\periapsis-v51-aggregate-owned-0b0348cde2f94414854284589518ea92\proof.json`;
  log: `.tmp/v51-full-aggregate-20260906.log`. This is distinct from the separate
  RLS/Go and upgrade selections, and precedes the later development-dependency and
  upgrade-test repairs.
- The separate RLS SQL gate and exact 15-test Go CI selection pass on a fresh
  provisioned cluster after those repairs, with no skipped Go tests. The two
  committed-fixture clones are dropped normally, source/template/role pins remain
  unchanged and the server is stopped. Proof:
  `C:\Users\dange\AppData\Local\Temp\periapsis-v51-extra-owned-05564106dfd740b8b723f5ecde8f8584\proof.json`;
  log: `.tmp/v51-extra-rls-go-20260906.log`.
- Focused V49, V50-path and V51-path upgrade tests pass with owned-cluster cleanup,
  source stability and preserved historical controls. The V51 path also executes the
  ordinary SAML flow. Proofs: `.tmp/schema-upgrade-V49-559f4a53609e481eabcf72d4d2afcf47-proof.json`,
  `.tmp/schema-upgrade-V50-86997ecfba514532bdd44d59778b84ab-proof.json` and
  `.tmp/schema-upgrade-V51-771777d0793248dc9b2d1f3df0bc69c3-proof.json`.

Complete local `pnpm verify` passes with 644 DB tests, 2,152 web tests, 175 notifier
tests plus the conditional Mailpit skip, and all 143 operations tests with the real
Gitleaks scanner and no operations skips. Generated drift, E2E TypeScript checks,
builds, Go vet and Go tests also pass. Evidence:
`.tmp/verify-v51-publish-20260906.log`.

The follow-up complete verification also passes after those repairs: 648 DB,
2,152 web, 175 notifier plus one conditional Mailpit skip, and 161 operations tests
with no operations skips. Generated drift, builds and Go gates pass; dependency audit
reports zero known vulnerabilities. Evidence:
`.tmp/verify-v51-dependencies-openldap-20260906.log` and
`.tmp/dependency-security-audit-20260906.json`. This does not establish a green
replacement CI run or real OpenLDAP/Compose startup.

The subsequent Linux CI run at c429841 passes all 21 upgrade jobs and every actual
`Exercise the real upgrade path` step, including the corrected current-journal pins:
[run 34039083554](https://github.com/xBounceIT/periapsis/actions/runs/34039083554),
`.tmp/ci-c429841-upgrades-pg-smtp.md`. The overall run still fails on the concurrent
PostgreSQL readiness timeout, one mounted mention-picker web test and minimal Compose;
Mailpit is skipped. The separate deployment run passes all five application-image
security jobs but fails the OpenLDAP startup smoke after successfully building its adapter.

The subsequent local CORS/LDAP-entrypoint repair passes complete `pnpm verify`
(648 DB, 2,152 web, 175 notifier plus one conditional Mailpit skip, 162 operations
without skips, generated/build/Go gates). Evidence:
`.tmp/verify-v51-cors-ldap-entrypoint-20260906.log`. The separate real Caddy 2.11.4
HTTP transport gate passes 6/6, including closed CORS and unchanged synthetic
signed-request/replay transport; it does not prove browser enforcement, TLS or MinIO
authorization. The new Linux gate and repaired LDAP startup still require remote CI.
No SQL, dependency lockfile or production external S3 configuration changed.

Elevated SAML MFA,
trust/freshness/local-required controls, rotate/step-up and historical revocation
drift remain distinct from the passing ordinary flow. The shared DFIR projection and
last-safe-revision matrices, full performance repeat and production-boundary restore
remain open in `TASKS.md`. Do not describe this candidate as production-accepted.

## Historical V50 database evidence

The previous V50 candidate has 232 migrations, ending at 0231, with catalog digest
`e68c7797c4f72188d1ddd4d133e5adff3f099004578fa77ad9f6472027fea9f8`.
Migration 0230 fixes the explicit-null tenant coordinate for platform logout while
preserving required-coordinate validation, actor/tenant authorization and transactional
audit. Migration 0231 retires runtime access to all 12 V49 roots. No historical SQL was
hotpatched or rewritten; the Git attribute correction for 0198 restores its canonical
bytes rather than changing its deployed source.

Verified on isolated native PostgreSQL 18.6 UTF8/C databases:

- Fresh normal migration and a second normal runner call agree on all 232 hashes,
  readiness and catalog digest. Normal runtime-role provisioning preserves that digest.
- The real Go/PostgreSQL logout test passes tenant A, tenant B and platform-local on a
  reused connection, including credential denials, immutable replay and cancelled audit
  rollback. The IOC/asset replacement test passes all four Case/Alert cells and 18-table
  denial snapshots. Proof: `.tmp/v50-go-5a6d0dfd9ab94f2c8011b15cf5191520-proof.json`.
- Historical V49 upgrade and the new V50 230→231→232 upgrade pass. They retain exact
  predecessor sealing, NOLOGIN rejection, unavailable intermediate readiness, immutable
  tenant receipts, nullable platform logout, one audit and normal-runner restart.
  Proofs: `.tmp/schema-upgrade-V49-14aef6997af64314bd3a9aca25ce99e6-proof.json` and
  `.tmp/schema-upgrade-V50-c81fb4cb39784f43ab97529498d22f95-proof.json`.

The full current aggregate is **not green**. The earlier synthetic three-origin SAML test
failed its deferred typed-provenance constraint. The production switch writer in 0186
emits SAML provenance, but the inherited 0165 constraint (renamed in 0207 and delegated
to by 0210) accepts OIDC only. The old fixture lacked complete administrative rows.
Neither relabelling SAML
as OIDC nor disabling triggers is an acceptable repair. Retained failure:
`.tmp/v50-saml-d3084f1a1c4f4ffb9692011b600c66cd-proof.json`.

The revised fixture now commits the complete identity/binding/epoch/grant graph through
ordinary constraints and calls the actual direct admission and tenant-switch ABIs instead
of fabricating the successor. Its begin/create stages pass, but the real planning ABI
stops earlier with SQLSTATE 42702: `identity.*` and `identity_alias.key_version` make
`matched.key_version` ambiguous in `load_platform_saml_planning_state_v1` (0184).
Preserve the distinct identity-ciphertext and subject-alias key versions when repairing
the projection. Both real clones were dropped with stable sources/template pins; repeat
proof: `.tmp/v50-saml-76269d139e524a06bc161d64a4c558c7-proof.json`. The third origin has
not yet reached direct apply, tenant switch, first revalidation or logout. The three
shared revalidation helpers were already made protocol-aware by 0228; reconstructing
them only from 0165 would be stale. Both product defects require a reviewed forward
migration, current seal and complete runtime repetition, not an ad-hoc catalog patch.

The complete V50 catalog tamper corpus passes after normal least-privileged login
provisioning, including all retained scenarios and the new retired-V49 mutations.
Proof: `.tmp/v50-catalog-86fc00ad064b4daba83bbbc0d97b4264-proof.json`; the clone was
dropped and source/template pins stayed unchanged. Complete repository verification
passes (`.tmp/verify-v50-candidate-formatted-20260906.log`): web 2,152, DB 627,
notifier 175 with one conditional Mailpit skip, operations 52, generated drift, builds,
Go vet and Go tests. The MFA35 upgrade additionally passes real TCP SCRAM, including
wrong-password rejection and the non-drained-session guard; proof:
`.tmp/mfa35-scram-79787bed140846c4aeab45db07cf642b-proof.json`.
The earlier 58-suite/19-upgrade results below are historical V49 evidence, not current
V50 acceptance. Native loopback `trust` tests do not prove TCP SCRAM authentication,
Docker startup, production deployment or external IdP/browser flows.

## Historical V49 database evidence

The post-SR-17 candidate completed the local database gates on 2026-09-05. Fresh raw
derivation and a separate empty database using the normal `db:migrate` runner both applied
all 230 migrations and agreed on catalog digest
`048078bb2a5c69057ec356857e323d55d0b97a43a5894e620140eab1f758414e`.
The canonical template remained sealed, ready and tenant-free after the runtime tests.

- The entire `test:security` aggregate passed **58/58** unique suites in one uninterrupted
  run, including V49, followed by RLS. Runtime-role provisioning, two seed runs and the
  seed-audit gate also passed.
- The complete `postgres-security-upgrades` matrix passed **19/19** entries, including
  V49 compatibility, with stable source hashes throughout.
- The expanded Go CI selection passed **13/13** top-level tests: API admission, all
  authorization-repository tests and the shared DFIR attachment/download-audit regression.
  All three database environment variables were set to fresh dedicated clones.

The aggregate started with the earlier workflow's 53 isolated clones and 57 aggregate
database URLs. CI then added a dedicated Go DFIR clone (54 total) without changing the
58-script aggregate or its 57 URLs. After that aggregate finished, the exact updated Go
command below passed separately on three new clones (10.817 seconds). The retained proof
binds it to workflow SHA256
`7f633d5da1ef43cdbac9af11d493a15c0e7ab8b991167046f0c89088c788afbf`.

```text
go test -count=1 -run '^(TestAPIRateLimitRepositoryPostgreSQL|TestAuthorizationRepository.*|TestDFIRSharedAttachmentsStayPathBoundInPostgres)$' ./services/api/internal/postgres
```

These gates used native PostgreSQL 18.6 on Windows, UTF8/`C`, with isolated loopback
clusters and `trust` authentication. They prove the exercised SQL/runtime behavior, not
Docker startup, SCRAM connection authentication, container hardening or production
acceptance. No per-function hotpatch was applied to the canonical test databases.

The source hashes recorded by both the security and upgrade runs still match the audited
files:

| Source                                      | SHA256                                                             |
| ------------------------------------------- | ------------------------------------------------------------------ |
| `0228_tenant_federation_administration.sql` | `f401ba0a4d98c97978c474099685c2666cedf963073ad195625b5d4176c3a6af` |
| `0229_v49_compatibility.sql`                | `a69775fe655ff7795b0aad4688925789d20d59d2bc9c06eb38e79f3a40cf7554` |
| `schema-compatibility-manifest.gen.ts`      | `5e9d9d544d498cc8a62205e8e22f9faa359fce168ea20fa032a72262e39fccc2` |

Retained local proof locations below are relative to
`C:/Users/dange/AppData/Local/Temp`; they are local artifacts, not a retained external CI run:

- `periapsis-download-audit-canonical-ee1400da2b524ad587b5f7e6fcb7b4c4/readiness.json`:
  normal migration, source guard and sealed 230-migration/zero-tenant readiness.
- `periapsis-final-pg-security-048006c7c6a84125a4d4fc6a2988b2da/`:
  `results.json`, `completion-proof.json`, `security-aggregate.log`, `rls.log`,
  `go-ci-current.log` and `go-ci-current-proof.json` retain the full aggregate and
  separately expanded Go CI evidence.
- `periapsis-final-upgrade-matrix-cfa46fd3ab0d49308efa3b5cb155f4d0/results.json`:
  all 19 upgrade results, each with the matching source hashes.

The SR-18 frontend checkpoint passed full `pnpm verify` with exit 0
(`.tmp/verify-custody-web-final-20260905.log`): 155 web files/1,990 tests, 613 DB unit
tests, 174 notifier tests (the conditional Mailpit test skipped), 42 operations checks,
contract/generated drift, builds, Go vet and Go tests. Its focused DFIR run passed
16 files/194 tests, including the 1,000-event custody limit in both mounted forms.
Eleven redirect-only OpenAPI warnings and the web entry chunk warning remain
(865.50 kB minified, 217.46 kB gzip). This checkpoint is not container acceptance;
subsequent test/implementation changes require their affected gates to be repeated.
The subsequent complete contacts/portal PostgreSQL runtime passed with the new customer
Alert/Case download-audit matrix: four successful grants, 26 denials, exact allowlisted
audit metadata, and nine-table rollback snapshots. The canonical sealed template remained
ready, with 230 migrations and zero tenants. This supplements the earlier 58-suite
aggregate; it is not a new full aggregate or a Docker/SCRAM result. Proof and runtime log:
`periapsis-portal-case-download-c636a9c47de84edba2710e17c50f9801/` under the same local
temporary-artifact root. The runtime source SHA256 is
`ffb2e7ef27dc1b24ff1618234852e6e3eda1be6c6fbbeefd329f145d6c51aaa8`.

The [current permission catalog](permission-catalog.md) now derives 25 platform and
85 tenant keys, exact scopes and admitted principal types from the evaluator and checked
OpenAPI bundle. The generator rejects malformed/null metadata and contract drift;
standalone Go tests, vet and the non-mutating catalog check pass. Root generation and
verification plus both CI drift jobs include the catalog, guarded by an operations test.
These changes postdate the SR-18 full-verification checkpoint above.

The subsequent full command (`.tmp/verify-catalog-portal-performance-20260905.log`)
stopped at two 5-second web timeouts: 153/155 files and 1,988/1,990 tests passed.
The same two files passed all 79 tests in isolation. A four-worker comparison eliminated
those timeouts but exposed an operator-team test reading an asynchronously loaded field
too early. Its query now awaits that field, and the web runner caps concurrent DOM
workers at four without changing test timeouts. All 129 tests in the three affected
files pass (`.tmp/web-bounded-async-green.log`). The new complete `pnpm verify` then
passed with exit 0 (`.tmp/verify-catalog-portal-bounded-final-20260905.log`): all
155 web files/1,990 tests, 613 DB tests, 174 notifier tests (conditional Mailpit skipped),
43 operations tests, generated drift including the permission catalog, builds, Go vet
and Go tests. The earlier failed runs are historical diagnostics. The eleven OpenAPI
redirect warnings and unchanged 865.50 kB web entry chunk remain. Performance database
execution and the external container/recovery gates are separate from this command.

The native performance run now passes the canonical migrations and seed after correcting
the harness's UTC configuration. That run exposed a fixture assumption that the seed had
no Cases. The fixture now preserves the canonical demo Case, adds 99,999 per root kind,
sets the tenant context, uses current creation times and verifies policy-bound numbering.
The subsequent runtime reached insertion but exhausted shared lock memory in the single
99,999-row transaction. The fixture now commits at most 1,000 tickets per batch, preserving
the numbering locks and exact final cardinality. The batched run then timed out in SLA
ingress setup. A controlled pair of 9,999-Alert loads verified that refreshing ingress
statistics between batches reduces the creation-trigger cost; the fixture now includes
that maintenance without changing budgets or planner controls. The next real run completed
the exact 100k-Alert/100k-Case dataset and passed the first three page plans, but failed the
state/severity index requirement. Its initial-state-only distribution has since been
replaced with interleaved canonical transitions and exact state/severity and chronology
assertions. A real two-batch proof passes, but a new full 100k run is still required.
Subsequent claim review replaced the retired v1 mutation ABI with the currently granted v2,
verified by a real isolated claim and denied old-entrypoint call. Ingest now uses the
transaction clock: an isolated current-runner proof rejects the old clock without a commit
and accepts three bounded creations. The SLA candidate plan and claim use the current v3
instance/ingress barrier, which the previous candidate plan omitted. All 52 harness tests
pass. Its failure-query alias defect is fixed, with separate real dead-letter proof.
The seed now consumes kernel-generated, identity-bound SLA documents with reproducible
generation/drift checks. Object-event planning projects validated tenant inventories onto
the selected policy; cursor restoration normalizes valid instants to UTC without relaxing
precision or history guards. A fresh canonical database passes two seed runs, seed audit
and the real worker's complete seven-event sequence: five Alert no-policy completions,
Case assignment and its subsequent update. All events complete, with no queued/leased/
retry/dead-letter rows and immutable snapshots; 13 source hashes stay stable and exact
clone cleanup preserves the 230-migration/zero-tenant template. Proof:
`.tmp/canonical-sla-seed-twice-cursor-utc-green-20260905.log`.
This closed the bounded demo ingress path. The performance fixture now publishes
kernel-generated documents before source tickets and has no direct SLA table writes.
The real `performance-sla` CLI is integrated with tracked process/credential cleanup
and the pinned performance image. A two-batch run of the actual fixture passes 1,999
new Alerts, twenty canonical transitions, all 2,023 ingress events, 1,999 materialized
columns, 1,979 running/twenty completed metrics, and 100 real timer finalizations.
It preserves the seed Alert's frozen no-policy decision and all ingress snapshots.
That proof exposed the invalid generic completion-event name; both presets now explicitly
use canonical `ticket.in_progress` and were regenerated from the kernel.
The disposable clone and URL file were removed, and all twenty source hashes and the
230-migration/zero-tenant template stayed unchanged.
Log: `.tmp/actual-performance-fixture-sla-canonical-event-20260905.log`.
This is not full 100k, reference-performance, four-worker concurrency or Docker acceptance.
The [performance runbook](operations/performance-gates.md)
records the causal proof, boundary correction and retained failed artifacts.

The pre-SLA-repair complete repository command passed with exit 0
(`.tmp/verify-performance-statistics-dfir-boundary-20260905.log`): 155 web files/1,993 tests,
613 DB tests, 174 notifier tests plus the conditional Mailpit skip, 43 operations tests,
generated drift, builds, Go vet and Go tests. Supplemental Case-task HTTP coverage proves
the final MAX_SAFE-1 to MAX_SAFE increment as an exact JSON integer/ETag and rejects four
terminal/unsafe body-header combinations before the service. The web generated-client
transport covers that last increment for all six Case task actions and blocks terminal or
unsafe task-detail requests before fetch. The focused HTTP log is
`.tmp/dfir-case-task-max-safe-http-20260905.log`; the focused web log is
`.tmp/dfir-case-task-json-boundary-web.log` (14 tests). These use service/fetch test doubles,
not a new database or full-stack proof, and leave the all-family revision audit open.

The preceding post-SLA-seed/inventory/cursor `pnpm verify` passed with exit 0
(`.tmp/verify-sla-seed-inventory-cursor-20260905.log`): web 155 files/1,993 tests,
DB 71 files/616 tests, UI two tests, notifier 174 plus the conditional Mailpit skip,
44 operations tests, generated drift including the permission catalog and canonical SLA
fixture, builds, Go vet and all Go tests. The eleven redirect-only OpenAPI warnings and
unchanged large web entry remain. The 52 performance harness tests also pass separately.
This does not replace the native seven-event SLA proof, the 100k performance run, or
Docker/recovery acceptance.

The subsequent full `pnpm verify` after real-worker integration and explicit canonical
completion events passes with exit 0, with the same 1,993 web/616 DB/174 notifier
counts and 44 operations checks, both generated SLA presets, builds and all Go
checks including the new CLI:
`.tmp/verify-performance-real-worker-final-20260905.log`.
All 90 performance tests pass separately
(`.tmp/performance-real-worker-contract-final-timed-20260905.log`), covering the
actual child-process invocation, environment allowlist, timeout limits, report validation,
private credential cleanup and Docker context inputs. Docker execution remains unverified.

The next full native run completed the canonical 100,000-Alert/100,000-Case dataset and
all 101,003 ingress events through the real SLA worker (1,011 batches, 508.539 seconds).
There were no retries, dead letters, replays or lost fences; policy/calendar/column
snapshots stayed unchanged. The API projection exposes 99,999 generated SLA values,
with 1,000 completed and 98,999 running metrics, while the pre-policy seed Alert remains
no-policy. Four query plans passed. The fifth, `alert_state_page`, returned 101 rows in
10.832 ms with 2,984 shared blocks and no sequential scan, temporary blocks or disk sort,
but failed the requirement to use `alerts_tenant_created_idx`: PostgreSQL chose the
existing tenant/state/priority index for the verified 1,000-row selective state.
The immutable artifact remains **failed**:
`tmp/performance/periapsis_performance_1788636376158_54b2296ad3c9.json`.
It records exact database/credential cleanup; the outer completion proof records stable
source hashes and an owned-server stop. Remaining plans, concurrent timer/ingest/claim
loads and reference-host acceptance have not been proved by this run.
The state-only index gate now accepts either exact index on a contributing Alert scan,
with every numerical budget and all other index/security/query/fixture controls intact.
The 96-test performance suite passes, including wrong-relation and non-contributing-scan
denials and immutable numeric-budget checks. This does not retroactively accept the
failed run; a fresh full workload must still pass.

Subsequent focused web/contract fixes close three demonstrated consistency gaps, not
the complete release checklist. Role and effective-authority hydration now validate
canonical permission/scope enums, exact tuple uniqueness and delegation subset while
preserving the 500-tuple read limit (231 transport tests pass). Case and Alert IOC/asset
replacement receipts must equal the originally requested version plus one, including
historical idempotent replay and MAX_SAFE-1 to MAX_SAFE (47 transport tests, including
24 new cases, pass). OpenAPI separates all 16 incrementing DFIR request schemas into
`DfirExpectedResourceVersion` (maximum MAX_SAFE-1), while responses retain MAX_SAFE;
19 AJV/schema tests pass and TypeScript/Go outputs were regenerated. Legacy ticket and
bounded custody revisions are unchanged. Focused lint/format and contract tests pass.
Logs: `.tmp/role-policy-hydration-final-20260905.log`,
`.tmp/dfir-replacement-receipt-green-20260905.log`,
`.tmp/dfir-revision-contract-green-20260905.log`, and
`.tmp/dfir-incrementable-contract-tests-20260905.log`.
The complete repository verification after those changes passed with exit 0:
`.tmp/verify-dfir-role-plan-final-20260905.log` (155 web files/2,060 tests, 616 DB
tests, 174 notifier tests plus conditional Mailpit skip, 27 contract pretests,
44 operations checks, all generated drift, builds, Go vet/tests). The 96 performance
tests pass separately. SQL and compatibility-seal hashes are unchanged.

A subsequent audit extended original-request receipt checks to 12 Task mutations,
two custody appends and two relationship retractions. All methods capture the revision
before awaiting the response, so caller changes after serialization cannot alter the
receipt expectation. Ninety-two new cases cover stale/skipped responses, historical
replay and the last legal revision; the two transports pass 139 tests, with 196 passing
across the adjacent four-file selection. Lint and format pass. Logs:
`.tmp/dfir-mutable-receipts-green-20260905.log` and
`.tmp/dfir-mutable-receipts-adjacent-20260905.log`.
This later delta requires another full repository verification; it does not prove
all-family MAX_SAFE database mutations or composed container behavior.

The composed live scenario has also been extended with task
update/replay and IOC-to-asset relationship/retraction checks. Static validation and
discovery pass, but its Docker execution remains unverified.

### Additional logout regressions

The newly added shared-content Go/PostgreSQL replacement test also passes all four
IOC/asset × Case/Alert cells on a three-root fixture, including current all-root
authorization, redacted activity, immutable replay, stale CAS, denial snapshots and
authority restoration. The probe exposed nil-array persistence, asset readback
nil/empty-tag equivalence and Alert revision-collision classification defects; the
corrections are narrow Go changes with focused regression tests. Shared timeline
inserts use the same non-null empty-tag treatment. Evidence:
`.tmp/periapsis_dfir_shared_content_be02d97a6a7f4fc3acc3929782d4644e.log` and its
`-proof.json`. The exact clone was dropped and source/template pins stayed stable.
Related-root workspace visibility remains a separate open integration gate.

The new permitted-upstream SAML tenant probe reached the public
`revoke_local_session_for_logout_v1` call without preinstalled actor context and failed
with SQLSTATE 23514: the audit trigger requires `app.user_id`. The previous Go
`RevokeLocalSession` adapter called the ABI directly on its pool rather than
installing transaction-local context. Its transport returns on persistence failure
before clearing the session cookie. This is a reproduced database-boundary regression
and a source-confirmed adapter mismatch, not yet a complete HTTP reproduction.

Evidence: `.tmp/saml_upstream_61aa133d00d9419bb8c3c963da839611.log` and its
`-proof.json`. The exact synthetic clone was dropped; migration count, empty template,
compatibility seal and source hashes were unchanged. The earlier green aggregate does
not cover this newly added case.

The adapter now establishes verified actor/tenant context in a short transaction and
returns a receipt only after validation and commit. Seventeen unit scenarios pass,
including begin/context/query/projection/commit failures and cancellation. A real
`NewFederatedAuthRepository` probe on one reused, initially context-free API connection
passes two distinct tenants, wrong user/tenant/digest denials, exact replay, retry,
context isolation and cancellation while blocked on the actual audit head. The latter
proves that revocation and audit roll back together and the pool remains usable.
Evidence: `.tmp/session-logout-context-unit-green.log` and
`.tmp/periapsis_session_logout_1221c058b4764e038897689666c09579.log` / `-proof.json`.
This explicitly selected tenant proof does not cover platform logout or full HTTP login.

The full Go probe remains RED at platform-local logout, and the SAML matrix remains RED
at direct platform logout: `tenantId:null` is emitted by the canonical Go builder, but
the SQL envelope puts `tenantId` in its required-non-null list before the branch that
intends to accept null. The tenant SAML origin passed its upstream continuation and
one-time consumption checks before this failure. Retained evidence:
`.tmp/periapsis_session_logout_06ac461a1c9043789ecb6d56b847ece4.log` and
`.tmp/saml_upstream_d91fb5fd1a3a42e3a041519765d9a688.log`, with corresponding proof JSON.
A forward migration and successor compatibility seal are required before repeating
the complete authentication matrix. Original migrations and canonical template remain
unchanged; every owned clone above was dropped and no SQL hotpatch was applied.

Both new Go repository tests (fresh-connection logout and shared content) are now
explicitly selected in CI with separate unseeded clones, a live cluster-directory pin,
and unconditional exact-clone cleanup. Five security-wiring source tests pass; this is
not evidence that the new Docker runtime gates have executed or that the RED cases pass.

### Historical diagnostics, not current-candidate acceptance

The earlier 2026-09-05 PostgreSQL diagnostic run passed 48/58 suites and failed 10; RLS
passed separately. Seed idempotency, notification/SLA isolation, shared unlink, custody
limits, authorization and federated MFA/material-lineage corrections subsequently gained
focused regression coverage. Those partial and hotpatch-clone proofs are historical,
not substitutes for the complete canonical runs above.

The pre-SR-17 seal
`5bd290d0f9982f202b918ebe41e6aac5ada83c8e919b61c4c63bae2d0b7a0fa5`
passed `pnpm verify` (exit 0, `.tmp/verify-mfa-final-20260905.log`, 613 DB unit tests),
all 58 PostgreSQL suites, RLS, the prior Go CI selection and all 19 upgrades. A later real
PostgreSQL regression exposed shared Case IOC/asset download-audit cardinality and
archived-resource mismatches. SR-17 corrected that SQL boundary and added 16 focused
audit cases. Only the new seal and full reruns above cover that correction. The earlier
complete `verify` also predates the final frontend changes and is not current-tree proof.
The eleven redirect-only OpenAPI warnings and web bundle-size warning were visible in
that historical verification.

## Local repository evidence

The operations and Playwright-discovery rows were rerun on 2026-09-04. The remaining rows
retain focused evidence from the 2026-09-02 audit and must not be read as a current full-tree
or release-runtime result.

| Command                                                                                                               | Result                        | Scope proved locally                                                                                            |
| --------------------------------------------------------------------------------------------------------------------- | ----------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `corepack pnpm test:operations`                                                                                       | 41/41 passed                  | Deployment source contracts, recovery-evidence tooling, security-CI wiring, and live-acceptance source contract |
| `corepack pnpm test:e2e:live:list`                                                                                    | 5 tests listed successfully   | The real Playwright configuration discovers five non-intercepted journeys; it does not start Compose            |
| `go test ./services/api/internal/httpserver -count=1`                                                                 | Passed                        | Complete HTTP handler package after platform-operations and explicit ticket-action changes                      |
| `go test ./services/api/internal/platformoperations ./services/api/internal/platform ./services/api/cmd/api -count=1` | Passed                        | Platform settings, health, queues, failures, feature flags, and API composition                                 |
| `go test ./services/api/internal/platformldapauth ./services/api/internal/platformidentityprovider -count=1`          | Passed                        | Platform-global LDAP login and provider/diagnostic application boundaries                                       |
| `go test ./services/api/internal/postgres -run 'PlatformLDAP\|PlatformIdentityProvider' -count=1`                     | Passed                        | Platform LDAP/provider PostgreSQL adapter contracts                                                             |
| `kustomize build deploy/k8s/overlays/dev \| kubeconform -strict -summary -kubernetes-version 1.35.0`                  | 34 valid, 0 invalid, 0 errors | Development overlay render/schema validation                                                                    |
| `kustomize build deploy/k8s/overlays/prod \| kubeconform -strict -summary -kubernetes-version 1.35.0`                 | 34 valid, 0 invalid, 0 errors | Production overlay render/schema validation                                                                     |

The platform-global LDAP closing slice also passed its seven-file web suite (253 tests),
web lint, and web typecheck. Its focused PostgreSQL 18.6 smoke returned the expected table
and entry-point function, 20 platform-LDAP functions, zero invalid indexes, and 10
forced-RLS platform-LDAP tables. These are focused slice results, not the composed
LDAP/browser acceptance artifact.

The local host had no Docker/Podman/nerdctl runtime, so no local result is claimed for
Compose startup, Mailpit, the composed LDAP/browser journey, image execution, multi-arch,
or the containerized reference-performance workload. Their workflow definitions and source
contract tests are present, but a retained external run is still required.

## Evidence still required outside this workspace

1. Retain a successful Docker-enabled release run covering Compose startup/health and the
   live-only scenario gaps above, including LDAP/SSO, service-account HTTP/UI, concurrent
   claim, object storage, Swagger, Mailpit, and the configured Playwright journey. Retain
   image scan/SBOM and AMD64/ARM64 UID/GID 10001 read-only-root artifacts. When tracing is
   enabled for the release, retain one redacted sampled API → PostgreSQL/outbox →
   worker/notifier continuity trace as part of the same runtime evidence.
2. Retain one green reference run of the scheduled PostgreSQL 18.6 100,000-Alert/100,000-Case
   performance workflow, including its sanitized `EXPLAIN ANALYZE` and concurrency artifacts.
3. Execute an approved isolated restore and retain signed backup, RPO/RTO, audit-retention,
   export, and object-storage evidence inside the production trust boundary.

Until the remaining repository gates pass and those artifacts exist for the candidate digests,
describe only the proven source or focused gate, never the candidate as production-accepted.
