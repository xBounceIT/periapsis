# ADR-0003: Drizzle and OpenAPI are the canonical schema and API contract sources

- Status: Accepted
- Date: 2026-08-23
- Decision owners: Architecture, Data, API, and Frontend
- Applies from: Phase 1 for the database and the first exposed API slice for OpenAPI

## Context

Periapsis has a Go API/worker, a TypeScript React client, a TypeScript Node notifier, and
PostgreSQL. The required database tooling places canonical schema definitions and
migrations in `packages/db` using Drizzle/Drizzle Kit, while Go uses pgx and generated,
verified queries. The public API must be versioned and documented using OpenAPI 3.1, with
generated Go transport types/interfaces and a generated TypeScript client.

Without explicit sources of truth, teams can accidentally maintain:

- a Drizzle schema plus a divergent hand-written SQL schema;
- migrations that do not represent the current schema;
- Go queries tested against a different database shape;
- handwritten frontend types that differ from runtime JSON;
- an OpenAPI document added after implementation and missing real behavior;
- generated output that is stale or edited manually.

These drift modes are correctness and security risks, especially for RLS, non-null tenant
ownership, visibility fields, optimistic concurrency, and idempotency.

## Decision

### PostgreSQL

The **Drizzle schema in `packages/db/src/schema` is the canonical declarative PostgreSQL
schema source**. It owns tables, columns, relations, indexes, constraints, and RLS
definitions. Drizzle Kit generates ordered SQL migrations in
`packages/db/migrations`; migrations are committed, reviewed as security-sensitive code,
and are the only mechanism used to change deployed databases.

There is no separately maintained full SQL schema. Handwritten SQL is allowed only for a
reviewed migration fragment or PostgreSQL feature that Drizzle cannot express faithfully,
and it remains inside the generated/committed migration sequence with a corresponding
canonical schema representation or documented adapter. RLS, roles/grants, extensions,
and append-only protections may require such explicit SQL; they are never omitted merely
because an ORM abstraction is inconvenient.

Go persistence uses pgx plus sqlc (or a documented equivalent generator). Application
query files are legitimate query source, not a second schema source. They compile and run
against a database built by the committed Drizzle migrations. Runtime Go code does not use
Drizzle or concatenate untrusted SQL.

The Node notifier uses Drizzle ORM at runtime against its least-privileged notification
tables/projections. That does not make notifier code a separate owner of the schema.

### HTTP API

The **OpenAPI 3.1 document in `packages/contracts/openapi` is the canonical public HTTP
contract**. It defines paths, actions, schemas, security requirements, Problem Details,
pagination/filtering, optimistic concurrency, idempotency, request/response examples, and
version/deprecation metadata.

From OpenAPI generate and commit (where repository policy requires committed artifacts):

- Go transport/server interfaces and request/response types;
- the TypeScript API client and types used by the web application;
- the validated `/openapi.json` or YAML artifact consumed by Swagger UI.

Generated files have a clear header and are never edited manually. Domain models remain
handwritten and are not generated from transport schemas; explicit mappers keep HTTP
concerns out of domain code.

## Change workflow

### Database change

1. Change the Drizzle canonical schema, including tenant ownership, constraints, RLS,
   indexes, and grants affected by the feature.
2. Generate a named migration with the pinned toolchain.
3. Review SQL for data loss, locks, backfill safety, downgrade/roll-forward strategy,
   least privilege, RLS coverage, and compatibility with rolling application versions.
4. Apply all migrations to an empty PostgreSQL 18 database.
5. Apply the migration from the previous-release fixture and verify preserved data and
   constraints.
6. Generate/compile sqlc output and execute repository/integration/RLS tests against the
   migrated schema.
7. Re-run generation and require a clean Git diff.

Migrations that have shipped are immutable. A correction is a new forward migration.
Destructive changes use an expand/backfill/contract sequence where rolling deployment or
data volume requires it. Application replicas never migrate automatically.

### API change

1. Update the OpenAPI operation and schemas before or with implementation, including
   permission, tenant path, errors, idempotency/concurrency, limits, and examples.
2. Validate the document and run compatibility checks against the released baseline.
3. Regenerate Go transport artifacts and the TypeScript client using pinned tools.
4. Implement domain/application behavior and explicit mapping behind the generated
   interface.
5. Run contract, authorization, integration, and frontend tests.
6. Re-run generation and require a clean Git diff.

An operation is not documented until it works, and it is not complete if implementation
exists outside the contract. No placeholder endpoint is added merely to make the contract
look complete.

## Source-of-truth matrix

| Concern                     | Canonical source                                     | Derived/validated artifacts                                  |
| --------------------------- | ---------------------------------------------------- | ------------------------------------------------------------ |
| PostgreSQL structure        | Drizzle schema                                       | SQL migrations, schema snapshot/introspection                |
| Deployed DB history         | Committed ordered migrations                         | Empty/upgrade test databases                                 |
| Go SQL queries              | Reviewed sqlc query sources                          | Generated Go query code compiled against migrated schema     |
| Public HTTP API             | OpenAPI 3.1                                          | Go server/transport types, TS client/types, Swagger artifact |
| Domain behavior             | Handwritten Go domain/application code and tests     | Transport mappings and events                                |
| UI forms/local validation   | OpenAPI client types plus domain-specific UI schemas | React forms; server validation remains authoritative         |
| Internal domain events/jobs | Versioned event/job schemas owned by producer module | Consumer decoders and compatibility tests                    |

Zod schemas used for UI behavior can refine user interaction but cannot redefine the
public server contract. Drizzle runtime types in notifier code cannot redefine database
columns. Domain types can be stricter than transport input and are reached through
explicit validation/mapping.

## CI drift and compatibility gates

CI fails when:

- the Drizzle schema changes without a migration;
- applying migrations does not reproduce the expected canonical schema;
- a clean or previous-release database cannot migrate;
- a tenant-owned table lacks non-null tenant ownership/RLS or runtime roles gain
  unintended privileges;
- Go queries do not compile/run against the migrated schema;
- OpenAPI is invalid or introduces an unapproved breaking change;
- generated Go or TypeScript output differs after regeneration;
- generated artifacts contain uncommitted manual changes;
- the implemented API fails contract tests or returns undocumented shapes/errors.

Tool versions, Node/Go/PostgreSQL baselines, generators, and formatters are pinned in the
workspace/CI. Reproducible install and generation run from a clean checkout.

## Security implications

- RLS, tenant constraints, audit grants, and outbox ownership are schema requirements and
  participate in drift checks; they are not deployment-time manual steps.
- OpenAPI declares authentication and tenant paths, but generated server interfaces do not
  replace backend authorization policy.
- Sensitive response schemas are allowlists. Private/operator and customer-safe
  representations are distinct where visibility differs.
- Examples and fixtures contain no real credentials, tokens, assertions, private payloads,
  or production personal data.
- Generated clients do not embed secrets or server-only configuration.
- Migration SQL and generator binaries are supply-chain-sensitive and receive review,
  version pinning, checksums/lockfiles, scanning, and SBOM coverage.

## Consequences

### Positive

- One database definition feeds both TypeScript tooling and the PostgreSQL migration
  history consumed by Go.
- API changes are reviewable before they become handwritten client assumptions.
- Drift is mechanically detectable in CI.
- RLS/constraints and visibility/idempotency fields are treated as contract, not tribal
  knowledge.
- Generated clients reduce duplicate type/serialization maintenance.

### Costs and constraints

- Every schema/API change includes generation and review steps.
- Some PostgreSQL features may need carefully reviewed SQL migration fragments.
- Domain and transport models require mapping code, intentionally avoiding accidental
  coupling.
- Rolling compatibility and old migrations require ongoing tests and artifact retention.
- Generator upgrades are explicit changes with potentially large reviewed diffs.

## Alternatives considered

### Handwritten SQL schema as canonical, Drizzle as a mirror

Rejected because the required stack designates Drizzle in `packages/db` for schema and
migrations. Maintaining both would create immediate drift risk.

### Go structs or sqlc schema as the canonical database model

Rejected for the same reason and because query generation describes data access, not the
full migration/RLS history.

### Code-first HTTP handlers with generated OpenAPI afterward

Rejected. It produces incomplete error/security/idempotency contracts and lets clients
depend on undocumented behavior.

### Handwritten TypeScript client and types

Rejected because duplication is likely to drift and hides breaking API changes.

### Generate database migrations automatically on application startup

Rejected because concurrent replicas, unreviewed destructive changes, and excessive
runtime privileges are unacceptable. A one-shot migration job is explicit and auditable.

## Staged delivery

Phase 0 records the rule and establishes generation/drift command contracts. Phase 1 adds
the canonical Drizzle schema, first reviewed migration, sqlc validation, and RLS/schema
drift tests. Each later vertical slice extends the schema and OpenAPI only as working
behavior is delivered. Phase 7 adds release compatibility, provenance, and full supply-
chain verification, while the basic drift gates remain mandatory from their first use.

Changing either source of truth requires a replacement ADR and a migration plan that
leaves no interval with two authoritative definitions.
