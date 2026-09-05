# Changelog

All notable changes are documented here. This project follows Keep a Changelog and will adopt semantic versioning at the first release.

## [Unreleased]

### Added

- Repository, architecture, security, CI, and deployment foundations.
- Canonical PostgreSQL/Drizzle tenancy schema with RLS and audit primitives.
- Go API and worker foundations with health, shutdown, and tenant context boundaries.
- React/Vite operator shell with repository-owned shadcn components.
- Phase 2A local bootstrap, session, and authorization security decision.
- One-time email-bound break-glass enrollment with mandatory TOTP, Argon2id passwords, and ten one-use recovery codes.
- Server-side browser sessions with secure cookie policy, CSRF/origin checks, shared throttling, tenant switching, rotation, listing, and revocation.
- Deny-by-default platform tenant create/list authorization, generated Go and TypeScript contracts, and the authenticated Phase 2A web flows.
- Cursor-paginated session and tenant-membership management with explicit incremental loading and stale-session response guards.
- Fail-closed, database-bound verification that every API replica uses the configured bootstrap authority and the same domain-separated master-key identity.
- Phase 2B.1 direct-human tenant RBAC with live authority projection, customizable roles, exact delegation ceilings, direct grants, protected recovery administration, optimistic concurrency, transactional audit, generated clients, and Roles/Users administration.
- Phase 2B.2a tenant security groups with direct-only membership, independent source-owned membership and role edges, consequence-complete delegation and lifetime checks, group-derived authority provenance, forced-RLS isolation, transactional audit, generated clients, and Groups administration.
- Phase 2B.2b global operator teams with immutable tenant assignment epochs, exact-epoch source-owned rosters, live team-scope authority, correlated platform/tenant audit, optimistic concurrency, generated clients, and platform/tenant administration.
- Tenant and platform LDAP with AD/OpenLDAP/POSIX templates, diagnostics, mapping dry-runs, JIT/pre-linked login, scheduled reconciliation, deny-result revocation, session revalidation, and a composed OpenLDAP acceptance journey.
- OIDC and SAML 2.0 tenant/platform authentication with one-time browser transactions, replay protection, pinned provider material, exact tenant bindings, JIT or pre-linked admission, session provenance, and live revalidation.
- Published platform/tenant/role/group/action MFA policies, TOTP, WebAuthn/passkeys, recovery-code and device lifecycle, session-bound local step-up, and explicit IdP-assurance trust rules.
- Governed Alert and Case APIs and operator UI, including separate aggregates, workflow administration, assignment/claim/release/transfer, close/reopen, idempotent escalation, explicit link/unlink lifecycle, comments, watchers, metadata, activity, and full-text/list projections.
- Alert and Case DFIR resources for IOC, assets, evidence, timeline, tasks, attachments, relationships, S3-compatible transfer, malware-scan state, SHA-256 integrity, and append-only chain of custody.
- Version-pinned business calendars and SLA policies, materialized custom columns, DST-safe simulation, pause/override behavior, worker evaluation, warning/breach action execution, notification/webhook/ticket actions, no-loop system Alerts, and transactional audit.
- Customer contacts and portal-safe Alert/Case, attachment, comment, activity, SLA, notification, webhook, and export projections with public/private visibility enforced at every downstream boundary.
- Notification and webhook administration with safe HTML/CSS templates, allowlisted placeholders, preview, SMTP test/delivery, Mailpit acceptance, retry, fencing, dead letter, delivery evidence, and trace propagation.
- Private saved views, dynamic custom/SLA columns, bounded bulk jobs, asynchronous CSV exports, S3 artifact reconciliation, authorized downloads, cancellation, retention, and worker/runtime observability.
- Tenant branding/settings, tenant-membership lifecycle, explicit platform-to-tenant access, global settings, health, job queues, failed-notification operations, feature flags, and tenant/platform audit export and retention controls.
- Structured logging, bounded OpenTelemetry, Prometheus metrics, Grafana dashboard and alert-rule examples, and operational validation for API, worker, notifier, SLA, notification, bulk/export, and authentication paths.
- A real Playwright journey configured against the composed API, PostgreSQL, and OpenLDAP stack; focused PostgreSQL 18 security suites; and a scheduled 100,000-Alert/Case performance harness that emits bounded `EXPLAIN ANALYZE` evidence.
- Versioned PostgreSQL readiness roots advanced with each protected runtime slice. Current binaries pin the generated journal fingerprint and trusted dependency probes; incompatible predecessors are retained only as immutable evidence and receive no application execution grant.
- Hardened non-root/read-only application images, Compose profiles, Swarm template, Kustomize overlays, SBOM/vulnerability/secret scanning, and AMD64/ARM64 runtime-evidence jobs.

### Changed

- Kept global operator teams separate from tenant security groups and bound tenant authority to immutable assignment epochs and exact-epoch rosters.
- Kept role-policy self-demotion atomic by returning its stored representation from the protected mutation; made direct-grant inventory show every source owner while keeping revocation manual-only, including cleanup after expiry or role archival; made database optimistic locks fail closed on omitted versions; and uniquely labeled every grant-specific revoke control.
- Distinguished authority path from source ownership so future reconciliation can remove only the membership and role-grant edges owned by its exact provider or mapping source.
- Made legacy tenant rotation fail closed for typed passkey and federated provenance until a dedicated exact-provenance switch can atomically authorize and rotate the target context.
- Replaced stale phase/readiness claims in release documentation with a requirement-to-evidence matrix and an external-evidence-only release backlog.
