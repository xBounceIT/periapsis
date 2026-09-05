# ADR-0001: Use a Go modular monolith with separate runtime processes

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Architecture and Security
- Applies from: Phase 0; enforceable in code from the first implementation slice

## Context

Periapsis spans tenancy, identity, authorization, Alerts, Cases, DFIR artifacts,
workflows, custom fields, SLA, notifications, webhooks, search, reporting, and audit.
These capabilities have many consistency boundaries: claim must update assignment,
activity, SLA, audit, and outbox atomically; Alert escalation must create a separate Case
and provenance link once; identity mapping must reconcile grants in one transaction.

Splitting these capabilities into networked microservices before their boundaries and
load profiles are known would introduce distributed transactions, duplicated policy,
contract/version overhead, operational cost, and more opportunities for tenant context to
be lost. An unstructured monolith would avoid network complexity but allow domain logic,
SQL, and authorization to spread across handlers.

The mandatory stack also has deliberate process boundaries:

- the primary backend is Go;
- synchronous API and background worker must be independently runnable;
- the notifier is Node.js/TypeScript and must use Drizzle ORM at runtime;
- the web build is React/Vite with a small production Node asset/proxy server.

## Decision

Build the business backend as a **modular monolith in Go**. Domain and application modules
share one source tree and database but enforce explicit code and table ownership. Produce
separate Go executables for:

- `services/api`: synchronous versioned HTTP API;
- `services/worker`: durable background domain jobs.

Keep two narrow Node runtime units required by their responsibilities:

- `services/notifier`: PostgreSQL notification consumer, safe template renderer, SMTP
  delivery, retry/dead-letter recording, using Drizzle ORM at runtime;
- `apps/web/server`: static Vite asset server, health endpoint, runtime-safe public
  configuration, and same-origin API reverse proxy only.

The notifier is an integration boundary, not evidence that each domain module should be a
microservice. The web server never makes authorization decisions.

## Module shape

Each Go business module owns:

1. domain types, invariants, commands, and events;
2. application use cases and transaction requirements;
3. repository/clock/ID/event interfaces (ports);
4. PostgreSQL and external-system adapters;
5. HTTP request/response mapping where exposed;
6. backend authorization policy for its actions and representations;
7. unit and PostgreSQL integration tests.

Expected dependency direction is:

```text
transport/adapters -> application -> domain
                         |
                         v
                    declared ports
```

Domain code does not import HTTP, pgx, generated transport types, or another module's
internal adapter. Transport handlers decode/validate and call a use case; they do not
contain domain decisions or SQL. A module may call another module only through a declared
application interface or a versioned domain event.

Modules may share small technical packages for transaction context, telemetry, Problem
Details, authorization primitives, and generated identifiers, but a `common` package may
not become a dumping ground for business behavior.

## Persistence and transactions

The modules share PostgreSQL and one canonical Drizzle schema. Sharing a database does not
authorize arbitrary table access in code. Each module declares owned tables and queries;
cross-module writes go through the owning application service.

An application-layer transaction coordinator supports use cases crossing aggregates or
requiring audit/outbox coupling. The transaction boundary remains in the orchestrating
use case, not in an HTTP handler or repository. Network calls such as SMTP, webhooks, LDAP,
or object scanning do not occur while a domain transaction is open; an outbox job carries
the durable intent.

## Runtime characteristics

API, worker, notifier, and web server are independently deployable/scalable but are
released from one repository and compatible contract set. They are stateless outside
PostgreSQL/object storage and propagate cancellation, deadlines, request/correlation/trace
IDs, tenant context, and graceful shutdown.

All images are multi-stage and non-root with numeric UID/GID, unprivileged ports,
read-only-root compatibility, dropped capabilities, no privilege escalation, explicit
temporary directories, and no embedded secrets. Database migrations run through a
separate one-shot job, never automatically in each replica.

## Security invariants imposed by this decision

- Authorization lives in backend application policy and is invoked by every transport or
  worker path; frontend hiding is advisory only.
- Tenant context is a required application input and transaction-local database context,
  including for background work.
- Domain state, activity, audit, and required outbox records commit atomically.
- A module cannot create an alternate unscoped repository or bypass another module's
  visibility projection for search, export, notification, or webhook convenience.
- Runtime database roles are least-privileged and cannot bypass RLS or mutate/delete
  audit events.
- External delivery occurs outside domain transactions through idempotent consumers.

## Consequences

### Positive

- Strong transaction boundaries for claim, escalation, identity reconciliation, SLA, and
  audit/outbox behavior.
- One place to apply tenant, RBAC, visibility, and observability conventions.
- Lower deployment and local-development complexity than premature microservices.
- Straightforward in-process refactoring while domain boundaries mature.
- API and worker can scale independently without duplicating domain logic.
- A narrow Node notifier satisfies the runtime Drizzle requirement without moving the
  primary backend away from Go.

### Costs and constraints

- Architectural boundaries need tests, import rules, review discipline, and clear table
  ownership; the compiler alone cannot prevent all cross-module coupling.
- A shared database can create coordination around migrations and hot tables.
- API and worker normally release together, so backward compatibility is still needed
  during rolling deployment.
- The notifier requires a small versioned internal job contract and separate Node
  dependency/security lifecycle.
- A fault in a shared Go dependency may affect multiple modules; resource limits and
  process separation reduce but do not eliminate this blast radius.

## Alternatives considered

### Microservice per capability

Rejected for the initial product. It would force distributed consistency and repeated
tenant/auth policy before traffic, team ownership, or independent scaling justify the
cost. It remains a future extraction option, not the default design style.

### Single unstructured Go service

Rejected because handler/domain/SQL coupling would make authorization and consistency
hard to review and test. Separate executables without module boundaries would not solve
that problem.

### All-TypeScript backend

Rejected because the required primary backend is Go. TypeScript remains appropriate for
the web and notifier responsibilities.

### All-Go runtime including notifier and asset server

Rejected because the required notifier must use Drizzle ORM at runtime and the web
production server is intentionally Node-based. Their scopes remain narrow.

## Staged delivery

- Phase 0 establishes module conventions, executable boundaries, and repository layout.
- Phase 1 creates tenancy/audit/outbox foundations and proves transaction/RLS patterns.
- Phases 2–6 add complete modules in dependency order; no placeholder service is created
  solely to resemble the target architecture.
- Phase 7 verifies independent scaling, resource controls, graceful shutdown,
  observability, and deployment security across all processes.

Each phase must keep the repository buildable and testable and must rerun prior boundary,
tenant, and security tests.

## Revisit criteria

Consider extracting a module only when measurements and ownership show at least one of:

- independent scale/resource/isolation needs that process-level API/worker separation
  cannot meet;
- a materially different availability or release cadence;
- a stable domain/event contract and an owning team able to operate it;
- a security boundary requiring separate credentials/data access;
- repeated database contention that a well-designed storage boundary can actually solve.

Extraction requires a new ADR covering tenant-context propagation, authorization,
versioning, failure semantics, idempotency, observability, data ownership/migration, and
operational cost. It must not replace an atomic invariant with an unexamined distributed
transaction.
