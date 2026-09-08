# Release evidence backlog

Last audited: 2026-09-07

This is the authoritative release backlog. A checked item means the implementation and a
focused repository gate exist; it does not mean every database-runtime gate is green for
the in-flight candidate or that a particular CI run or production drill has been retained.
Unchecked items include final repository verification and evidence that must be produced
on an external runtime or production trust boundary. The current
candidate state and the requirement-to-test map are in
[`docs/release-acceptance.md`](docs/release-acceptance.md), including the completed
final-journal database gates and the remaining release boundaries.

## CI consolidation (2026-09-07)

- [ ] Run `34232473336` reaches browser export creation and returns 503.
      Native API/PostgreSQL reproduction identifies read-only transactions that
      reject the authority helper's `FOR SHARE` locks. Keep repeatable-read
      isolation but allow these locks for export and bulk reads. V59 also aligns
      inline, saved and persisted query snapshots with the existing strict
      unpadded Base64 codec; the former decoder rejects valid canonical inputs.
      Preserve a missing idempotency receipt through transaction error mapping,
      and locate the job at `record.job.definition.id` during replay/read checks.
      Complete native request/replay and composed browser acceptance are required.
- [ ] Run `34230418815` passes LDAP setup and the direct RLS probe, then
      reaches browser acceptance. Read the canonical `alertNumber` property
      from the operator projection when checking the exported CSV; `number`
      belongs to a different response shape. Retain the exact CSV comparison.
      Complete composed browser acceptance remains required.
- [ ] Run `34228500759` still fails the direct RLS probe: Compose initializes
      local PostgreSQL sockets with peer authentication. Connect the API login
      over loopback TCP using its password, including the audit immutability
      probes so authentication failure cannot masquerade as denied mutation.
      Complete composed browser acceptance remains required.
- [ ] Run `34226289187` completes Globex LDAP setup and fails in the direct
      RLS probe. Feed SQL through psql stdin so quoted psql variables expand;
      install transaction-local contexts in separate statements before querying.
      Require one visible source row followed by zero rows in the second tenant,
      preventing an always-empty query from passing the isolation check.
      Complete composed browser acceptance remains required.
- [ ] Run `34223903645` reaches Globex LDAP mapping creation. Mapping the
      protected administrator role exceeds the LDAP delegation policy; reproduce
      the 403 with native API/PostgreSQL. Give the isolation fixture an explicit
      human role with tenant-scoped `alert.read`, which also authorizes operator
      exports. Retain the own-tenant search, foreign-resource/export denial and
      RLS assertions, and verify the effective permission scope after login.
      Complete composed browser acceptance remains required.
- [ ] Run `34222173605` completes tenant OIDC configuration and reaches the
      second tenant's LDAP setup. Its update incorrectly repeats the creation-only
      `kind` field, rejected by the strict update contract. Send `kind` only on
      creation, preserving provider enablement and tenant-isolation assertions.
      Complete composed browser acceptance remains required.
- [ ] Run `34220144226` passes OIDC document parsing but rejects snapshot
      admission: native Keycloak returns immediately stale discovery/JWKS cache
      metadata. The disposable realm's edge now publishes only successful GETs
      of those two public documents with a bounded ten-minute lifetime. A real
      Caddy test retains upstream bodies/statuses and verifies that authentication,
      token, other-realm, POST and error responses keep their original no-store
      policy. Complete composed OIDC/browser acceptance remains required.
- [ ] Run `34218132866` reaches OIDC trust refresh, where the default Keycloak
      realm's mixed RS256/RSA-OAEP JWKS is rejected by the signing-only trust policy.
      Configure the disposable realm's generated key provider explicitly for RS256.
      Native Keycloak 26.7.2 with the imported realm publishes one signing key; the
      real OIDC parser accepts that document and rejects the default mixed set.
      Complete composed OIDC/browser acceptance remains required.
- [ ] Run `34216477706` passes SLA email, audit and DFIR setup, then rejects
      the OIDC fixture's root post-logout URL. Use the required same-origin
      `/signed-out` destination in the provider, its projection assertion and the
      Keycloak client registration. Complete Linux acceptance remains required.
- [ ] Run `34216477706` exposes a worker test synchronization race: readiness
      and metrics become observable before the failure log is written. Wait for
      the bounded failure log as well in the SLA engine/action/ingress tests,
      preserving readiness, shutdown and redaction assertions. Complete Linux
      acceptance on the successor commit remains required.
- [ ] Run `34214756368` encounters an intermittent 412 while two SLA columns
      are created concurrently during fixture setup. Serialize these configuration
      writes and retain both successful-creation assertions. The deliberate ticket
      claim-race acceptance remains concurrent. Complete Linux acceptance on the
      successor commit remains required.
- [ ] Run `34213161528` passes real SLA email capture, system-Alert creation
      and non-recursive SLA checks. Its next audit request uses an invalid trailing
      dot in `actionPrefix`. Use the canonical `tenant.sla.action` namespace;
      the API and SQL already match its dotted descendants. Keep the occurrence,
      action-kind and exactly-once audit/activity assertions unchanged.
      Complete Linux acceptance on the successor commit remains required.
- [ ] Run `34210260958` reaches the live SLA email assertion, but Mailpit
      receives no warning. Native API/worker/notifier reproduction identifies
      fanout validation rejecting PostgreSQL's canonical ungrouped defaults
      (`windowMs: 0`, `maximumItems: 1`). Decode those defaults to the input
      representation while rejecting real grouping settings in `none` mode.
      Allow the three bounded fanout delivery counters in the structured logger;
      logging a committed fanout must not enter the dead-letter failure path.
      Decoder regressions and fanout tests using the production logger cover both
      defects. Complete Linux acceptance on the successor commit remains required.
- [ ] Run `34201899933` passes 34 of 35 jobs, including the V58 upgrade,
      full PostgreSQL/RLS suite and Mailpit acceptance. Compose hits a concurrent
      assignment conflict on the separate claim-race Alert. Retry only setup
      assignment conflicts with bounded backoff and a freshly read ETag;
      retain the simultaneous claim winner, version, activity and audit assertions.
      Native HTTP also reproduces a 503 reading activities after IOC/asset writes:
      admit the exact persisted DFIR event inventory in the operator contract
      and validator while preserving the closed customer event list.
      Complete Linux acceptance on the successor commit remains required.
- [ ] Run `34163097509` passes ingestion, typed-field import, concurrent claim
      and SLA projection, then the activity feed returns 503. Preserve the
      namespaces of `custom_field.imported` and `sla.action.executed`, publish
      those operator activity kinds in OpenAPI, and accept bounded camelCase
      event metadata separately from custom-field keys. Customer feeds retain
      their closed public event list and redacted projection.
      Native concurrent requests also expose `40001` authority-lock contention:
      classify aborted transient statements only for the session-revalidation
      ABI. Retry usable-session conflicts with bounded, cancellable backoff,
      rereading the current version, authority and time before each decision.
      Credential transitions are not restarted by this retry path; revocation
      discovered during the retry remains authoritative.
      Contact creation requires a UTC microsecond clock and the canonical
      language casing already specified by OpenAPI and PostgreSQL (`it-IT`).
      The contact-link acceptance step must use the current Alert ETag after
      import and assignment. V58 grants the SLA owner column-scoped lock
      privileges on notification configurations while retaining tenant/revocation
      filtering and a false UPDATE check. Contact-link commit and replay now expose
      the same creator field for Alert and Case authorization records. Published
      migrations remain unchanged; 0246/0247 introduce and attest these repairs.
      Contact metadata uses the exact ticket update permission, not the separate
      Alert-to-Case workflow link action; stale versions and read-only operators
      remain denied. SLA timer events can independently advance the projection
      version beyond the claim's ticket version.
      IOC and asset projections normalize PostgreSQL inet host prefixes and
      scanned observation times to canonical host addresses and UTC; network
      prefixes remain rejected. Native HTTP acceptance covers both writes.
      Retain complete Linux acceptance for these repairs.
- [ ] Run `34159066895` passes composed notification preview/test-send and SLA
      setup/simulation, then acceptance includes operator-team assignment in
      machine Alert ingestion and correctly receives 403. Create/replay through
      the bearer boundary first, then assign through the authorized human endpoint.
      Derive concurrent claim and SLA projection versions from that assignment.
      The native preflight also exposes a 503 after persistence: HTTP retains
      json.Number while the Alert mapper used float64, so numeric payloads fail
      equality checks. Preserve exact numbers in the Alert projection and compare
      decimal values across PostgreSQL jsonb spelling changes, including large
      integers and nested arrays/objects. Keep machine assignment forbidden.
      Exercise the implemented operator custom-field import and its worker before
      querying the typed filter index; raw ingestion and typed value publication
      are separate boundaries. Automatic typed-field publication during machine
      ingestion still needs explicit machine attribution in the typed-value schema.
      Individual object-field editing also remains product work: its current
      CommitObjectFields adapter is deliberately disabled until an object-scoped
      mutation ABI exists. Neither boundary is enabled by broadening privileges.
      Preserve empty Alert tags as an empty SQL array for both human and machine
      adapters; cloning into a nil slice caused otherwise valid minimal creates
      to violate the database's non-null payload contract.
      A concurrent claim loser may return the contract's 412 when If-Match is
      stale, or 409 for an already claimed resource. Acceptance still requires
      exactly one 200, one claimed activity and the winner's exact SLA version.
      Existing SLA state carries policy-global trigger positions within each
      metric's subset. Restore increasing positions without requiring a zero
      origin; reject duplicate positions, identities and descending order.
      Apply the same rule to API runtime reads and normalize persisted cursor
      instants to UTC without changing their value or microsecond precision.
      The native API/worker preflight now passes exact bearer replay, typed-field
      import/search, operator assignment, concurrent claim and SLA projection.
      One preceding native run returned 401 for the losing LDAP session; retain
      the exact Linux result rather than accepting authentication failure as a
      valid claim conflict.
      Retain the subsequent complete Linux acceptance result.
- [ ] Native SLA administration exposes a forbidden direct read of identity
      authority tables. Migration 0244 adds a current-tenant/current-membership
      epoch reader with API-only execution; direct table reads remain forbidden.
      Migration 0245 seals the 246-entry V57 journal. PostgreSQL security coverage
      rejects foreign tenant and membership arguments and checks the live epochs.
      SLA use cases also validate fresh authority against the clock after its
      repository call, retaining expiry, future-time and clock-rollback rejection.
      Preserve json.RawMessage decoding for nested policy rules, warnings and
      actions; a distinct byte-slice type had incorrectly required base64 strings.
      Acceptance binds all three declared metrics in its simulation input.
      Retain the final Linux Compose and PostgreSQL results for this candidate.
- [x] Run `34154984623` completes the entire PostgreSQL migration/RLS aggregate
      and its final Compose provisioner regression. Supply-chain run `34154984620`
      passes all seven jobs, including both notifier runtime architectures.
      The same candidate's Compose job still fails at notification preview;
      these results do not establish full-stack acceptance.
- [ ] Run `34154984623` passes real LDAP and SMTP creation, then rejects the
      customer template preview because acceptance omits `context.customer`.
      Preserve the audience boundary; put custom fields under the Case object,
      use an allowed HTML wrapper for CSS, and exercise this exact fixture with
      the actual notifier renderer before repeating Compose acceptance.
- [ ] Native replay exposes the notifier's nested `ERR_INVALID_ARG_TYPE`:
      Drizzle replaces postgres-js timestamp serializers with pass-through
      functions, but raw SQL still supplied Date objects. Encode valid dates
      as ISO strings at the shared parameter boundary and reject invalid dates.
      Cover fanout, email and webhook claims and verify the native runtime.
      The runtime now completes polling iterations without the previous errors.
- [ ] The real SMTP failure path also exposes a retry timestamp race: computing
      the next attempt and persisting failure with separate clock reads can
      violate the database's one-second minimum. Email and webhook workers now
      share one failure instant; advancing-clock regressions cover both paths.
- [ ] The native notification preflight catches update-only password/DKIM clearing
      flags in the first SMTP creation request. Correct the acceptance payload;
      retain the application's rejection of clearing secrets during creation.
      Complete the actual notifier/Mailpit boundary in Linux acceptance.
- [ ] SMTP persistence succeeds but projection validation rejects PostgreSQL's
      numeric UTC offset because Go can decode it with a location other than
      the `time.UTC` pointer. Validate the actual zero offset and microsecond
      precision, retaining rejection of nonzero offsets and zero timestamps.
      The real native HTTP SMTP creation now returns 201; notifier preview and
      Mailpit delivery remain part of the Linux Compose acceptance gate.
- [ ] Supply-chain run `34149341870` times out after ARM64 QEMU raises SIGILL
      during the notifier dependency installation. Build its architecture-neutral
      TypeScript and production dependencies on `BUILDPLATFORM`, matching the
      existing web/database-task pattern, while retaining the target-platform
      runtime image and both architecture runtime checks. Disable workspace
      hoisting and verify the whole production export has only confined links,
      portable package metadata and no native/opaque binaries. The actual local
      8,663-file production export passes. Retain Linux evidence.
- [ ] Run `34149341882` exposes stale LDAP authorization pins after importing a
      second user. Migration 0242 projects the immutable session pin and permits
      a guarded rotation only after current lifecycle and assurance checks;
      its planning v2 reader returns the exact existing access grant for repeat
      logins. Migration 0243 seals V56. Native HTTP tests prove two usable users,
      repeat login, rotation and a successful operator custom-field write.
      Acceptance refreshes committed rotations and proves both sessions live
      immediately before deprovisioning. Retain the final Linux result.
- [ ] The custom-field revision writer omitted `defaultPresence`, `permissions`
      and `capabilities`, so the database rejected its first write with 23514.
      Preserve the complete snapshot contract and all three default-presence
      states. Unit coverage and native PostgreSQL HTTP creation now pass.
- [ ] Run `34149341882` completes the PostgreSQL security aggregate in 38 minutes,
      then the Compose provisioner regression fails `initial_attestation` because
      it calls the retired V54 root. Advance that check to the current seal and
      include this standalone script in the selected-root regression coverage.
- [ ] Run `34147994065` passes all LDAP logins and profile/authority/group/roster
      checks, then its audit assertion uses `tenant.identity.ldap` as a prefix.
      The audit API deliberately matches complete dot-separated components;
      `ldap_jit_started` belongs to `tenant.identity`, not its `ldap` child.
      Page through the identity namespace and select the exact `ldap_` family.
      Native PostgreSQL confirms all three required login events were appended.
- [ ] Run `34147994122` flags one base64 chunk in the generated OpenAPI blob
      from commit `d451eab`. The reviewed deflate payload is a public OpenAPI 3.1
      document with 360 paths, not credential material. Add only its exact
      commit/file/rule/line fingerprint; attest both historical contract hashes
      independently. Gitleaks 8.30.1 detects all 41 fresh and replacement controls
      and reports zero findings for actual history with those exact exceptions
      (`.tmp/ci-fix/gitleaks-generated-green.log`). Retain the Linux scan result.
- [ ] The tenant-user API also reads the nullable global email and returns 503
      for LDAP identities. Migration 0240 adds tenant-profile user/group/roster
      read ABIs; 0241 seals V55 without rewriting published migrations. SQL
      readers and the HTTP contract accept absent email. Native HTTP admission,
      session resolution and imported tenant profile now pass. Retain Linux
      acceptance and the PostgreSQL aggregate for this candidate. Run
      `34144629182` cancelled that aggregate at the exact 30-minute job limit,
      before its final three checks; allow 60 minutes for the complete gate.
- [ ] Run `34144629182` reaches real LDAP login and session resolution, then
      incorrectly expects tenant email in the global authentication identity.
      ADR 0009 keeps LDAP contact data in tenant profiles; the native database
      confirms the global email is absent and the tenant email/name are correct.
      Verify all four LDAP acceptance identities through the tenant user API,
      retaining session method/tenant checks and active membership/profile checks.
      Complete the remaining composed acceptance on Linux.
- [ ] Run `34143162684` passes all 24 upgrades, HTTPS bootstrap/login, runtime
      reprovisioning and full-profile health. Real LDAP authentication now returns
      303, but acceptance selects the first `Set-Cookie`, which clears the MFA
      ceremony before the actual session cookie. Select exactly one cookie by its
      expected session name and retain HttpOnly, Secure, SameSite and path checks.
      A regression executes the actual helper with reordered cleanup headers,
      duplicates, missing session cookies and weakened attributes. The complete
      repository gate passes (`.tmp/ci-fix/verify-cookie-selection.log`). Complete
      the remaining live browser acceptance on Linux.
- [ ] Run `34137704187` passes 29 of 30 jobs, including all 23 upgrades and the
      full PostgreSQL security aggregate. LDAP acceptance reaches the real
      directory but its new tenants have no explicit baseline MFA policy. The
      policy API also rejects a freshly verified bootstrap TOTP after tenant
      selection. Migration 0238 preserves the exact local break-glass proof for
      legacy sessions without tenant MFA state; existing tenant state must still
      satisfy its own evidence boundary. Publish the two disposable baselines
      through the real API. Migration 0239 seals V54 without changing published
      migrations. The regression fails on V53; the complete native MFA policy
      suite passes on V54, including mismatched factor timestamps, disabled
      factors/credentials, stale MFA and restricted tenant state
      (`.tmp/ci-fix/mfa-legacy-green-native.log`). Fresh V54 catalog/ACL/body/config
      tamper coverage and the V53-to-V54 upgrade pass. Actual HTTP baseline and
      LDAP administration pass. The final session decoder also rejected the
      database's LDAP-only `authorizationRevision`; accept its exact bounded
      shape while preserving strict unknown-field rejection. Native repository
      loading and atomic revalidation now pass, and HTTP returns 303 with a
      controlled directory observation (`.tmp/ci-fix/ldap-login-v54-field-native.log`).
      `corepack pnpm verify` passes (`.tmp/ci-fix/verify-v54-third.log`), as do
      all 16 Compose model checks and actionlint. Complete real Linux LDAP/browser
      acceptance before closure; the controlled observation is not a network proof.
- [x] Run `34136485615` passes all 23 PostgreSQL upgrade jobs, but ordinary
      TOTP login still loses readiness after the identity-keyring verifier
      exhausts its 250ms retry window (258ms retained latency). Retry transient
      false results within the caller's deadline, capped at 5s, while preserving
      immediate database-error denial and cancellation. A regression requiring
      more than ten attempts fails before the fix; native PostgreSQL now proves
      successful verification after a 750ms session write lock
      (`.tmp/ci-fix/identity-contention-long-native.log`). The PostgreSQL aggregate
      also exposes a historical test assumption that the service source hash is
      last: V53 appends the retired V52 root. Locate the aggregate by its unique
      catalog source hash while retaining all prepared-query tamper checks. The
      complete native platform-binding runtime suite passes with this helper
      (`.tmp/ci-fix/binding-aggregate-native.log`).
- [x] Complete `corepack pnpm verify` passes for published candidate `6e71150`
      (`.tmp/ci-fix/verify-6e71150.log`); its CodeQL workflow is also green.
- [x] Native HTTP acceptance exposes the foundation-only LDAP configuration ABI:
      provider creation rejects supported JIT, admission and synchronization
      policies. Append migration 0236 with authorized, audited V2 writes and
      retain certificate verification and all relational constraints. Append the
      V53 compatibility seal without changing any published migration. Fresh
      PostgreSQL 18 repository tests and the V49/V50/V51/V52-to-V53 upgrades pass,
      including existing session, audit and logout-receipt preservation. Direct
      V2 repository calls reject missing authority, foreign tenant access,
      disabled certificate verification and invalid deprovisioning grace, with
      no provider mutation (`.tmp/ci-fix/v53-go-native-third.log`). The acceptance
      customer role uses the required own scope. Coalesce absent LDAP mapping
      epoch sequences to the zero value already required by the Go projection;
      actual HTTP provider/binding/mapping creation and enablement now pass
      (`.tmp/ci-fix/ldap-mapping-v53-fixed-native.log`). Linux LDAP authentication
      acceptance remains required.
- [x] Run `34129373887` passes minimal HTTPS authentication, reprovisioning and
      full-profile health, then rejects the live operator role with HTTP 409.
      Remove the unused `alert.create` permission from that custom human role:
      the legacy role-creation ABI intentionally rejects it, while acceptance
      already creates Alerts using the dedicated service account and credential.
      Actual API HTTP role creation passes against fresh native PostgreSQL 18
      (`.tmp/ci-fix/ldap-role-native2.log`). Collect bounded redacted full-profile
      diagnostics after acceptance failures as well as startup failures.
- [x] Run `34127843591` intermittently fails ordinary TOTP login with a 503 and
      retains an immediate identity-keyring readiness failure. The sealed keyring
      verifier returns false on NOWAIT contention with ordinary session writes.
      Retry false results up to ten times with cancellable 25ms waits, retaining
      fail-closed behavior until a positive database verification. A fresh native
      PostgreSQL regression holds the real session write lock, proves the initial
      denial and then successful verification after release, rolling back all
      generated key bindings (`.tmp/ci-fix/identity-contention-native.log`).
      Persistent mismatch, cancellation, all Go tests and vet pass.
- [ ] Confirm full-profile notifier health on Linux: run `34126074120` passes
      minimal HTTPS authentication and stale-membership reprovisioning, then
      reports an unhealthy notifier while Keycloak is healthy. Native PostgreSQL
      and the real notifier entrypoint return readiness HTTP 200 in 0.4-0.6s
      (`.tmp/ci-fix/notifier-runtime-native.log`), so no timeout or schema cause is
      yet established. Retain finite readiness failure categories and duration,
      and collect notifier/provisioner state and redacted logs for the full
      profile. The collector uses at most 25 bounded read-only commands.
      Run `34129373887` subsequently passes full-profile notifier health. Run
      `34131570408` reproduces the failure and retains seven readiness deadline
      expirations at 2009-2024ms. Give Compose readiness a 10s budget, with its
      HTTP probe and container timeout outside that budget, as for the API.
      Preserve the application's default and require a new Linux runtime pass.
- [x] Run `34124857324` passes the complete HTTPS authentication smoke, then
      rejects migration resealing after the stale-membership fixture adds extra
      runtime privileges. Remove only noncanonical memberships from the three
      existing runtime logins before migration attestation. Keep role creation,
      canonical grants and password provisioning after successful migration.
      Native PostgreSQL proves repeated cleanup, unchanged login credentials and
      attributes, restored v52 readiness and successful migration resealing
      through the real migration CLI (`.tmp/ci-fix/provision-preseal-native2.log`).
      Producer tests cover ordering,
      cleanup failure redaction and the absence of authority-granting statements.
- [x] Run `34121834068` reaches healthy containers and host HTTPS, then fails
      bootstrap confirmation. Native PostgreSQL reproduces three independent
      blockers: bootstrap TOTP AAD must match the sealed unversioned bootstrap
      ABI, live session deadlines must have millisecond precision, and session
      hydration must accept the complete closed platform permission catalog.
      Preserve revision-bound administrative TOTP enrollment, absolute session
      limits and denial of unknown permissions. Cover creation, touch, rotation
      and tenant switching with focused regressions. Update the auth smoke cookie
      assertion to require the secure `__Host-` policy on HTTPS while preserving
      its HTTP development check. Deny non-v7 tenant targets before the database
      ABI and prove both non-v7 and unknown-v7 denials in the smoke. Accept the
      HTTP request ID as the default logout audit correlation, as the database
      contract already does. Full native authentication smoke passes on a fresh
      PostgreSQL 18 database with the real API binary and loopback proxy headers
      (`.tmp/ci-fix/auth-logout-native.log`); the full repository gate passes
      (`.tmp/ci-fix/verify-bootstrap-session.log`), followed by focused tests and
      vet for the tenant/logout follow-ups. Linux Compose acceptance remains required.
- [x] Run `34120394216` shows the edge exits before serving HTTPS. The pinned
      official Caddy image history confirms `cap_net_bind_service=+ep` on its
      executable, incompatible with the required empty capability bounding set.
      Derive the TLS and external-proxy edge from that same digest and remove
      the file capability at build time. Preserve UID/GID 10001, read-only root,
      no-new-privileges and `cap_drop: ALL`. CI must execute `caddy version` under
      those restrictions before stack startup, then exercise actual HTTPS.
- [x] Run `34119421135` confirms healthy API, web and worker containers. Its
      host HTTPS probe runs immediately after the edge starts because the health
      loop omits the edge. Include edge health before the host probe, and retain
      its bounded state and redacted startup failure categories in diagnostics.
      A fresh Compose run must distinguish startup timing from an edge failure.
- [x] Run `34118176844` starts the minimal API and web successfully but the
      worker repeatedly rejects ticket readiness. Replace its separate bulk and
      export v52 attestations with the existing sealed worker projection, still
      requiring release, bulk and export readiness. Preserve context failures
      instead of reporting them as generic internal failures. Use the configured
      database deadline in the worker monitor instead of an independent fixed
      two-second cutoff. Focused cancellation, projection and monitor tests,
      all Go tests and vet pass; native PostgreSQL verifies one ticket query
      in 0.43s (`.tmp/ci-fix/worker-aggregate-postgres.log`).
- [x] Run the new Compose provisioning regression after the existing readiness
      lifecycle proof, which requires absent runtime login roles and removes
      its temporary roles on completion. Run `34116943594` exposed their ordering
      conflict on the isolated port-5433 cluster. Preserve both assertions and
      add a CI ordering contract; do not reuse the main security cluster.
- [x] Run `34116943594` confirms API readiness after the Compose deadline fix,
      then exposes the web entrypoint exiting before startup. Reproduce the
      `TrustedProxySet` temporal-dead-zone error with the compiled Node entrypoint;
      move CLI startup below module initialization. Add a subprocess regression
      that executes the real source entrypoint and probes its HTTP liveness.
      All 12 server tests, web lint and typecheck pass locally
      (`.tmp/ci-fix/web-entrypoint.log`), followed by a complete `pnpm verify`
      (`.tmp/ci-fix/verify-web-entrypoint.log`) and HTTP 200 from the rebuilt
      JavaScript entrypoint. Linux Compose acceptance remains required.
- [x] Separate dynamic Compose address pools from static service/proxy IPs on
      frontend, identity and storage. The storage worker could otherwise claim
      the API address during concurrent startup. Validate the resolved TLS and
      external-proxy models in every profile and retain redacted API/worker
      startup diagnostics as well as migration/provisioning diagnostics.
      Local `pnpm verify`, 28 focused model/diagnostic tests and Actionlint pass;
      evidence: `.tmp/ci-fix/verify.log` and `.tmp/ci-fix/focused.log`.
- [x] Fix the federation editor hydration test race exposed by run `34106220160`:
      wait for the mapping/assurance textareas to become enabled before checking
      loaded data in OIDC and SAML tests. All 20 page tests and a fresh full
      `pnpm verify` pass locally (`.tmp/ci-fix/verify-final.log`).
- [x] Run `34106220160` reaches API startup after the IPAM correction, then exits
      with an unclassified API error. Expand the exact-message diagnostic allowlist
      to reviewed API source literals and handle Go joined errors without emitting
      arbitrary text. Focused redaction tests preserve canary secrecy.
- [x] Identify the API startup failure in `34107293392` as federated runtime
      initialization (with a secondary telemetry shutdown error). Reproduce it
      locally with an isolated PostgreSQL runtime: the public OIDC callback used
      port 18081 outside the configured 443/18090 allowlist. Include configured
      web and IdP ports in the Compose default for both API and worker, update
      the example environment and validate public callback admission in every
      resolved deployment model. With the corrected port list the native API
      reaches `api started`; this empty-database probe does not prove readiness.
      All 14 model tests pass. Complete the local gate after updating its old
      manifest marker: `.tmp/ci-fix/verify-ports.log`,
      `.tmp/ci-fix/operations-ports.log`, `.tmp/ci-fix/verify-ports-remaining.log`.
- [ ] Confirm the address-pool repair on a fresh Linux/Docker CI run. Run
      `34104325346` failed during Docker network setup (`Address already in use`);
      `34057493882` instead reached API startup and exited with code 1 without
      API diagnostics. Also retain a separate investigation of scheduled
      performance run `34100419297`: its SLA adapter failed `database_preflight`.
- [x] After startup succeeds in `34108546780`, diagnose unhealthy API/worker
      checks: eleven repository queries still called revoked v51 readiness
      functions after the v52 migration seal. Move all affected callers to v52
      without changing migrations or grants, including SLA ingress used by the
      performance adapter. Add real PostgreSQL API/worker readiness tests to CI,
      retaining an assertion that retired v51 functions remain inaccessible.
      All eight adapter cases pass against a newly migrated native PostgreSQL
      18.6 database (`.tmp/ci-fix/readiness-postgres.log`).
      The complete local verification gate passes after aligning its CI selector
      contract (`.tmp/ci-fix/verify-readiness.log`,
      `.tmp/ci-fix/operations-readiness.log`,
      `.tmp/ci-fix/verify-readiness-remaining.log`).
- [x] Remove duplicate API readiness attestations within one bounded probe.
      A native run with correctly provisioned runtime-role attributes reaches
      the two-second deadline before ticket/local-account checks. Reuse the
      complete v52 aggregate only for the same PostgreSQL pool and original
      live probe context; keep standalone repository checks and authorization
      unchanged. PostgreSQL integration proves all five adapters reuse the
      aggregate without acquiring another connection (0.41s aggregate versus
      3.01s of repeated adapter checks in this local sample). Cover canceled
      probes, different pools and failed refreshes, and emit only finite
      readiness dependency/failure labels in Compose failure diagnostics.
      Evidence: `.tmp/ci-fix/probe-postgres.log`; fresh Docker confirmation is pending.
- [x] Wire the migration-installed global ticket runtime principal into local
      Compose. Without its identifier the worker deliberately leaves ticket
      and custom-field import readiness false. Preserve explicit overrides,
      retain fail-closed worker behavior, and exercise the configured principal
      through the real PostgreSQL custom-field import adapter.
      The full local gate passes (`.tmp/ci-fix/verify-probe.log`); all 15 resolved
      Compose models and native principal checks pass. CI `34110348026` completes
      every job except Docker successfully, including the complete PostgreSQL
      security suite. The updated Compose startup still needs a fresh runner.
- [x] Reproduce run `34112717759` using the actual Compose role provisioner:
      its inactive notifier placeholder lacked the sealed connection limit and
      membership, invalidating every runtime attestation. Initialize and repair
      inactive placeholders to the canonical shape without activating them or
      replacing credentials. Preserve active logins during minimal reprovisioning.
      The old provisioner fails the native API/worker readiness cases; the repaired
      provisioner passes (`.tmp/ci-fix/provision-before.log`,
      `.tmp/ci-fix/provision-after.log`). Add a dedicated real PostgreSQL CI
      regression for legacy placeholder repair, repeated minimal provisioning,
      notifier activation, and preservation of active notifier access.
      The real regression passes (`.tmp/ci-fix/provision-regression.log`).
      Full verification exposed an independent LDAP test race: its 100ms
      operation budget could expire before TLS completed under parallel package
      load. Give that blocked-bind test one second for setup/operation while
      retaining the timeout category, secret clearing and server-close assertions.
      Twenty repetitions pass, followed by the complete uncached Go suite.
      The full local gate is covered by `.tmp/ci-fix/verify-roles.log` and
      `.tmp/ci-fix/verify-roles-go.log`; Actionlint also passes.
- [x] Run `34114592946` proves the Compose provisioning regression and a healthy
      worker. API PostgreSQL readiness still fails. Retain finite failure
      categories and bounded latency in its diagnostic output to distinguish
      deadline exhaustion from catalog/runtime or migration mismatches.
- [x] Run `34115704986` confirms every API PostgreSQL failure is a deadline at
      exactly 2,000ms while the worker is healthy. Set the local Compose API
      readiness budget to 10s and coordinate its HTTP/container probe at 12s.
      The shell-free probe accepts an optional bounded timeout; existing callers
      retain their two-second default. Cover timeout validation and resolved
      default/overridden Compose budgets without weakening schema attestation.
      All Go tests/vet, 16 actual Compose models, operational checks, formatting
      and Actionlint pass. A delayed local HTTP server verifies the compiled
      probe succeeds/fails according to its configured deadline and rejects
      unbounded/invalid values. Fresh Docker confirmation remains pending.

- [x] Share the TypeScript, Go and generation jobs between PR and complete CI;
      remove `pull-request-fast.yml` and guard expensive jobs/steps by event.
      Run the complete operations aggregate on both PRs and main/tag candidates.
- [x] Keep Kubernetes render/schema validation in deployment security, preserving
      both 1.32 and 1.35 schema checks. Keep application-image scans in its five-image
      matrix; remove their duplicate execution from the Compose acceptance job.
- [x] Remove the unused OCI archive export while retaining separate AMD64 and ARM64
      builds, loaded images and hardened runtime probes. Remove the optional external
      notifier job now covered by the repository-owned notifier image in the matrix.
- [x] Remove duplicate release-published triggers; main/tag push and manual dispatch
      remain. Retain the distinct performance benchmark, CodeQL, dependency analysis,
      historical secret scanning, database migration/RLS/upgrade and live acceptance gates.
- [x] Complete all local `pnpm verify` stages: the initial run passed formatting,
      lint, types and package tests (web 2,223; DB 656; notifier 180; UI 2), then
      exposed the old direct-command assertion for startup diagnostics. Update it
      to verify the operations aggregate, rerun operations (187 pass, one conditional
      Gitleaks skip), and complete generation/drift, build, Go vet and uncached Go tests.
      Mailpit remains a conditional skip. Actionlint and separate ShellCheck pass
      (83 Bash steps); actual Kustomize/kubeconform validate 34 resources in each of
      six environment/schema combinations. Optional CRDs retain three schema skips.
      Logs: `.tmp/verify-ci-prune-20260907.log`, `.tmp/ci-prune-operations.log`,
      `.tmp/verify-ci-prune-remaining-20260907.log`.
- [ ] Retain fresh Linux/Docker CI and deployment-security results after publishing
      this change. The consolidated PR check names replace the former `Fast ...` names;
      live GitHub inspection found no repository rulesets or main branch protection.
      Local checks cannot establish container or hosted-runner acceptance.

## React Doctor remediation (2026-09-06)

- [x] Address the initial 901 diagnostics across the web application and shared UI:
      split controllers, editors and inventories; extract pure models; consolidate
      navigation and repeated markup; retain strict validation; publish request refs
      only after a committed render; and group related state transitions.
- [x] Preserve tenant/session authorization, cancellation, version and idempotency
      boundaries. Add regressions for suspended tenant renders, stale pagination and
      metadata responses, editor row identity, table callbacks and route failures.
      Independent comparison confirms all 36 navigation entries and their permission
      conditions, and keeps webhook editor identities outside API payloads.
- [x] Keep React Doctor rules enabled globally. Document only specific analyzer
      limitations next to owned request finalizers, server snapshots and lifecycle
      effects. Reproduction and scope:
      [`docs/frontend-quality.md`](docs/frontend-quality.md).
- [x] Complete a full, uncached React Doctor 0.9.13 scan of both React projects and
      rebuilt browser artifacts: web **100/100**, UI **100/100**, zero errors,
      zero warnings, both scans complete and no skipped checks.
- [x] Pass root `pnpm verify`: web 2,223, DB 656, notifier 180, UI 2, operations
      187, contract checks, generated drift, builds, Go vet and uncached Go tests.
      Mailpit acceptance and the actual Gitleaks binary control retain their
      conditional skips; the 11 existing OpenAPI warnings and Vite chunk-size
      warning remain. This frontend slice does not rerun container acceptance.

## Test-suite pruning (2026-09-06)

- [x] Remove 22 low-value cases: nine CSS/source presentation checks, one redundant
      React-context probe, seven database fixture/test-source checks, two tests of
      hardcoded transport stubs, and three inventories of live-test source strings.
      Retain mounted credential/export behavior, HTTP boundaries, exact seed-wrapper
      assertions, generated-fixture verification, security-suite wiring, real database
      and browser scenarios, and crash-detecting fuzz targets. No production code changes.
- [x] Complete three clean review cycles covering duplication, execution cost and
      lost-coverage risks after preserving the exact seed match-rule assertion.
- [x] Pass root `pnpm verify` on top of `2da01ba`: web 2,204, DB 656,
      notifier 180, UI 2, contract checks, operations 187, generated drift, builds,
      Go vet and uncached Go tests. Mailpit acceptance and the actual Gitleaks binary
      control remain conditional skips; 11 existing OpenAPI warnings and the existing
      Vite chunk-size warning remain. This does not rerun database/container acceptance.

## GitHub CodeQL remediation slice (2026-09-06)

- [x] Triage all 25 open alerts against actual code/data flows. Implement CSS and
      plaintext-entity fixes, explicit fixed-origin web requests, reproducible generated
      parameter hardening, checked numeric/allocation operations, and shared canonical
      redirect validation with decoded-path checks. Add focused regressions without
      altering migration/seal bytes, authentication protocols or dependency versions.
      Details: [`docs/security/code-scanning-remediation.md`](docs/security/code-scanning-remediation.md).
- [x] Prove and document the context of seven false positives (#3, #4, #15, #22–25)
      with source inspection, response-boundary tests and encrypted-receipt checks.
      The user authorized explained per-alert dismissals; never disable whole rules.
- [x] Pass root `pnpm verify`: formatting, lint, type checking, tests (web 2214,
      notifier 180 plus one conditional skip, DB 663, UI 2, contracts 45), operations
      checks, generated-artifact drift, builds, Go vet and Go tests. This does not
      substitute for PostgreSQL/container deployment gates; Go used cached package
      results, including the deployment-contract failure subsequently seen in CI below.
- [x] Publish remediation commit `00a73a0` to `main` and dismiss exactly #3, #4,
      #15, #22–25 as false positives with explained, user-authorized dispositions
      linking to the committed triage evidence.
- [x] Confirm the first fresh CodeQL analyses of `00a73a0` (run `34050762175`):
      Go `1732426930`, JavaScript/TypeScript `1732423388`, Actions `1732418382`,
      all without analysis errors. Seventeen alerts are fixed; the seven approved
      false positives remain dismissed. Only generated-helper alert #6 remains.
- [x] Verify the generated-helper follow-up against fresh CodeQL analyses.
      Follow-up `de3b093` uses literal reads/replacements for the four allowed slots;
      contracts pretests (48/48), typecheck, lint, focused runtime tests (19/19),
      reproducible generation and independent review passed before publication.
      Repeated root `pnpm verify` also exited successfully after publication
      (web 2214, notifier 180 plus one conditional skip, DB 663, UI 2; same Go-cache
      caveat as above). JavaScript analysis `1732444198` closed #6 without dismissal.
      Final analyses of `de3b093` in run `34051313196`: JavaScript/TypeScript
      `1732444198`, Go `1732447231`, Actions `1732439090`, all with empty errors.
      GitHub reports zero open alerts, 18 fixed and seven explained false-positive
      dismissals. CodeQL rules and default setup remain enabled and unchanged.
- [x] Separate pre-existing CI follow-up (resolved by the slice below): adapt
      `TestOIDCMaintenanceConfigurationIsWiredAcrossDeployments` to the Compose
      include/base/TLS layout (`service worker is missing`, line 47), and diagnose
      the Mailpit acceptance connection failure (`healthy=false`, `connect=failed`,
      `errorClass=connectivity`, before template rendering). Both exact signatures
      occur in baseline `ff5b800` run `34049766601` and remediation `00a73a0` run
      `34050762310`; neither is caused by this CodeQL slice. Local cached Go results
      are not evidence that the deployment-contract check passes on fresh execution:
      `go test ./internal/config -run TestOIDCMaintenanceConfigurationIsWiredAcrossDeployments -count=1`
      from `services/worker` reproduced the same failure locally on `de3b093`.

## Compose and SMTP CI follow-up (2026-09-06)

- [x] Repair the OIDC deployment source contract for the actual ordered
      include/base/TLS and certificate-free HTTP layouts without removing CA,
      HTTPS/SSRF, numeric identity, Swarm or Kubernetes checks. Cover 14 invalid
      layer-graph variants. Focused Go tests and race tests pass with `-count=1`;
      vet and 14 real Compose configuration-model checks pass.
- [x] Give only the optional Mailpit fixture a non-internal `mailpit-host` bridge
      while retaining the internal integrations network and loopback-only SMTP/UI
      ports. Docker 28.0.4 on the failed runner skips external-connectivity setup
      for internal-only endpoints. Add resolved-model assertions and CI checks of
      actual Docker port mappings before acceptance, with seven executable Bash
      regression cases. No application SMTP code or authentication policy changes.
- [x] Run the unchanged acceptance against checksum-verified native Mailpit 1.30.3:
      one test passes without skips, including the health probe, customer-safe
      delivery and captured-message assertions. The owned processes/listeners and
      temporary captured-message database were removed. This does not substitute
      for the Docker/Linux publication gate. Evidence: `.tmp/mailpit-native-16070c541b7044ebb75e0e48f5398a2f/REPORT.md`.
- [x] Disable Go test-result caching in repository verification, Make and both CI
      workflows (`-count=1`) because deployment contracts read files outside their
      module directories. Keep compiled-build caching and all test selections/race
      checks unchanged. Wiring and real Bash regression checks pass (27/27).
- [x] Pass root `pnpm verify` with uncached Go tests: format, lint, types, web
      2214, notifier 180 plus its conditional skip, DB 663, UI 2, contracts 48,
      operations 191, generated drift, build and Go vet/tests. Separate real native
      Mailpit acceptance passes without skips. Log: `.tmp/verify-ci-followup-20260906.log`.
- [x] Publish `2da01ba` to `main` and confirm both repaired jobs in run
      `34052447684`: Go vet/race job `101538397690` and Mailpit job `101538984702`
      pass, including real Docker loopback publication, unchanged SMTP acceptance
      and teardown. CodeQL run `34052447026` passes all three analyses of this same
      commit (`1732486372`, `1732482606`, `1732477657`) with no errors and zero open
      alerts. The later test-pruning commit `ab94a84` cancelled the remaining jobs;
      these results are scoped to `2da01ba`, not a claim that the entire CI is green.
- [ ] Separate remaining container-startup diagnosis: job `101538397554` in run
      `34052447684` failed at `Start hardened minimal stack` with Docker
      `failed to set up container networking: Address already in use`. The daemon
      did not identify the container or address. Migration and MinIO provisioning
      had exited successfully; PostgreSQL and MinIO were healthy. Mailpit is not
      started in the minimal profile, whose service networks/runtime were unchanged
      by this repair. Do not infer the occupied address or a Mailpit causal link
      without fresh network evidence.

## Remote reverse-proxy deployment slice (2026-09-06)

- [x] Add an opt-in certificate-free HTTP application origin for a trusted TLS proxy on
      another machine, with public URL and exact proxy CIDRs supplied by environment.
      Compose splits shared services from its unchanged default local TLS entry; the
      alternative never interpolates or mounts local edge certificates. Swarm opts into
      host publication, one web task per node and stop-first replacement.
- [x] Enforce proxy-only admission before web assets/API routing, validate singular Host
      and forwarding headers, and retain canonical client-IP attribution through the
      independently trusted web-to-API hop. Public HTTPS cookies and origin/CSRF checks
      remain unchanged when the backend socket is HTTP. Add real HTTP web tests, a Go
      router regression, real Compose-model checks and real Caddy peer/CORS checks.
- [x] Verify this slice locally: root `pnpm verify` exits 0 (663 DB, 2,213 web,
      175 notifier tests plus its conditional Mailpit skip; generated drift, builds,
      Go vet and Go tests pass). After the final entrypoint test/CI wiring addition,
      operations pass 189/189 with no skips. Separate actual Compose and Caddy gates
      pass 14/14 and 16/16; the entrypoint test covers 24 real shell invocations.
      Workflow syntax and 89 embedded Bash scripts pass; changed-source Gitleaks is
      clean. Logs: `.tmp/verify-external-reverse-proxy-repeat-20260906.log`,
      `.tmp/reverse-proxy-operations-final.log`, `.tmp/reverse-proxy-caddy-final.log`.
- [ ] Retain a dedicated-host trial with the actual external proxy, observed NAT peers,
      restricted firewall and private/encrypted cross-machine transport. Verify client-IP
      spoof resistance, login/callbacks, CSRF and signed uploads. No server was deployed
      in this slice; Compose test dependencies do not become production services.

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
