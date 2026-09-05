# Periapsis repository guidance

These rules apply to the entire repository.

## Product invariants

- Periapsis is a multi-tenant incident-management and DFIR platform. Every customer-owned row has a non-null `tenant_id` and is protected by both application authorization and PostgreSQL row-level security.
- Authorization is deny-by-default and enforced by backend use cases. UI visibility is never an authorization boundary.
- OpenAPI 3.1 in `packages/contracts/openapi/openapi.yaml` is the canonical HTTP contract. Generated Go and TypeScript artifacts must be reproducible and committed when the generator policy requires it.
- Drizzle schema in `packages/db/src/schema` is the canonical database model. SQL migrations are generated from that model and are the only schema consumed by Go/sqlc.
- Audit events are append-only, redacted, transactionally coupled to mutations where possible, and tamper-evident.
- Secrets come from environment variables only for local development and from `*_FILE` mounts in deployed environments. Never add credentials, tokens, assertions, or customer data to source, fixtures, logs, or snapshots.
- All application containers run as numeric UID/GID 10001 with a read-only root filesystem and explicit writable temporary storage.

## Engineering workflow

1. Read the nearest `AGENTS.md`, relevant ADRs, and `TASKS.md` before editing.
2. Keep changes scoped to one vertical slice and preserve a green build.
3. Add focused unit tests plus integration/security coverage whenever an invariant crosses process or database boundaries.
4. Run `make verify` (or the equivalent `pnpm` and `go` commands on Windows) before handoff.
5. Record deferred product work and risk in `TASKS.md`; do not leave critical-path TODO comments or stub endpoints.
6. Use parameterized SQL, context deadlines, cancellation, graceful shutdown, structured logs, and RFC 9457 Problem Details.
7. Do not hand-edit generated artifacts. Update the source contract/schema and regenerate.

## Code layout

- `apps/web`: React/Vite client and a non-root Node static/reverse-proxy server.
- `services/api`: Go modular monolith HTTP API.
- `services/worker`: Go asynchronous worker.
- `services/notifier`: Node/TypeScript PostgreSQL notification consumer using Drizzle at runtime.
- `packages/ui`: repository-owned shadcn primitives and domain compositions.
- `packages/db`: Drizzle schema, migrations, seeds, fixtures, and database checks.
- `packages/contracts`: OpenAPI source and generated clients/interfaces.
- `deploy`: Compose, Swarm, and Kubernetes deployment definitions.
