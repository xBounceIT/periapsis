# Periapsis Incident Management Platform

Periapsis is an original, self-hosted incident-management and DFIR platform for SOC, MSSP,
and CSIRT teams. The repository contains implementation and focused automated gates for the
tenant and platform control planes, interactive and machine authentication, governed
Alert/Case workflows, DFIR resources, SLA automation, notifications, bulk operations,
asynchronous exports, audit operations, and hardened Compose, Swarm, and Kubernetes
deployment definitions. Candidate acceptance still depends on the final database-runtime
gate and the retained external evidence described below.

## Current delivery state

Implemented identity paths include local break-glass recovery, tenant and platform LDAP,
OIDC, SAML 2.0, TOTP, WebAuthn/passkeys, recovery codes, session-bound step-up, JIT or
pre-linked admission as configured, and explicit IdP-MFA trust policy. Provider claims are
admission/profile evidence; they never create platform roles, tenant roles, groups, or teams.
Human and service-account authorization is deny-by-default and is re-evaluated by backend
use cases, with forced PostgreSQL RLS as an independent tenant boundary.

Alert and Case are separate versioned aggregates. Repository source covers their explicit
claim, assignment, transition, close/reopen, escalation, link/unlink, comment, watcher,
metadata, DFIR, SLA, bulk, and export operations, with optimistic concurrency and
idempotency where required. Mutations are designed to couple domain activity, redacted
audit, and transactional outbox effects; the current gate state for each acceptance
scenario is recorded in the evidence matrix.

Database readiness is versioned, sealed, and fail-closed. The authoritative current root is
the one embedded in the API/worker health checks and generated from the committed migration
journal; operators must not pin an older root copied from release notes. Use only the
canonical migration runner and follow the
[upgrade runbook](docs/operations/migration-bootstrap-upgrade.md).

Source implementation and repository gates are mapped to the 13 release scenarios in the
[acceptance evidence matrix](docs/release-acceptance.md). A source-complete scenario is not
the same as retained production evidence: the remaining Docker-host, reference-performance,
and approved restore/retention evidence is listed in [TASKS.md](TASKS.md).

## Prerequisites

- Node.js 24 LTS
- Corepack and pnpm 11
- Go 1.26
- Docker Engine with Compose v2 for integration and local services
- GNU Make (optional on Windows; every target maps to a package or Go command)

## Quick start

```bash
corepack enable
corepack pnpm install --frozen-lockfile
corepack pnpm generate
corepack pnpm verify
node scripts/deploy/prepare-compose-secrets.mjs --env-file .env
docker compose --env-file .env -f deploy/compose/compose.yaml --profile minimal up --build
```

For Compose, copy `deploy/compose/.env.example` to the repository-root `.env`, fill every
blank value, and configure the external local certificate paths. Generate independent
bootstrap and master-key values as documented in
[authentication.md](docs/authentication.md), then follow the
[Compose TLS setup](deploy/compose/README.md#create-the-local-tls-material). Production
credentials must be mounted as files. For local Compose, the preparation command creates
the external secret files before startup; Docker cannot materialize environment-backed
secrets inside read-only containers. Preparation refuses to overwrite existing files.

The web application is served through the local TLS edge at `https://localhost:8443`.
OpenAPI JSON is available at `/openapi.json` and Swagger UI at `/docs` when documentation
exposure is enabled. Under the `auth-test` or `full` profile, the Keycloak test realm uses
`https://idp.localhost:18090`; browser evidence transfers use
`https://storage.localhost:19000`. The web, API, Keycloak HTTP listener, and MinIO API are
not bound directly to host HTTP ports.

## Useful commands

```bash
make bootstrap          # install and generate
make lint               # TypeScript and Go lint
make typecheck          # TypeScript and generated-contract checks
make test               # unit tests
make test-integration   # auth smoke against a running local stack
make test-e2e           # local browser suite, not the composed release journey
make test-security      # PostgreSQL RLS/runtime matrix; requires disposable DB URLs
make build              # all application builds
make verify             # required local quality gate
make dev                # minimal Compose profile
make up                 # alias for the minimal Compose profile
make dev-down           # stop the local stack
make down               # alias for stopping the local stack
make reset              # recreate the minimal stack and its volumes
make logs               # follow logs from the minimal Compose profile
```

`make test-integration` defaults to the bounded `auth` suite and requires a running
minimal stack plus `PERIAPSIS_BOOTSTRAP_TOKEN` and `PERIAPSIS_SMOKE_ADMIN_PASSWORD`.
It targets `https://localhost:8443`; set `NODE_EXTRA_CA_CERTS` to
`PERIAPSIS_DEV_TLS_CA_FILE` when the development CA is not trusted by the host.
Select `PERIAPSIS_INTEGRATION_SUITE=ldap` for the composed LDAP acceptance journey and
provide the acceptance variables documented in [`deploy/compose/README.md`](deploy/compose/README.md).

On Windows without GNU Make, use `corepack pnpm verify`; its root scripts enumerate every
Go workspace module explicitly. Use the exact Compose commands shown in the Makefile for
container-backed gates.

## CI matrix

| Event                                    | Pipeline                                        | Required scope                                                                                                                                                                                                                        |
| ---------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Pull request                             | `CI`                                            | Reproducible install, TypeScript lint/format/typecheck/tests/build, operations and generated-drift contracts, and Go vet/tests without the race detector                                                                              |
| `main` push, any tag, or manual dispatch | `CI` and `Deployment and supply-chain security` | The fast checks plus race tests, real PostgreSQL migration/RLS/upgrade suites, integration and browser E2E, Compose/container runtime checks, multi-arch builds, Kubernetes validation, secret/vulnerability scans, and SBOM evidence |
| Weekly or manual dispatch                | `PostgreSQL ticketing performance`              | Disposable PostgreSQL 18.6 reference benchmark and retained 100,000-ticket performance evidence                                                                                                                                       |

CI shares the same TypeScript, Go and generated-drift jobs across events. Pull requests
skip Docker-backed, PostgreSQL runtime, race, scanner and browser-install work. The complete
gates are mandatory on every main/tag candidate; a fast PR result is not release evidence.
Publishing a release does not rerun its tag checks. If a release tag was created without
triggering a push workflow, dispatch both complete workflows against that tag before release.

Deployment security owns image vulnerability scans, per-image SBOMs, AMD64/ARM64 runtime
proof and Kubernetes validation (schemas 1.32 and 1.35). CI owns composed application
acceptance and source dependency/SBOM scanning. GitHub-managed CodeQL and dependency
analysis remain separate because they cover different risks.

## Architecture

The Go API is a modular monolith with a separate Go worker and a focused Node notifier.
PostgreSQL 18 provides durable state, RLS, transactional outbox queues, and concurrent work
claiming. S3-compatible object storage holds evidence; MinIO is local-only. Start with the
[documentation index](docs/README.md), then see [architecture.md](docs/architecture.md),
[domain-model.md](docs/domain-model.md), [authentication.md](docs/authentication.md),
[permissions.md](docs/permissions.md), and the accepted decisions in [docs/adr](docs/adr).

## Security

Report vulnerabilities using the private process in [SECURITY.md](SECURITY.md). Do not include exploit details or customer data in a public issue.
