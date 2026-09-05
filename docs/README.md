# Documentation index

This index separates architecture and operating contracts from release evidence. The
canonical HTTP contract is OpenAPI and the canonical database model is Drizzle; prose does
not override either source.

## Release and API

- [Release acceptance evidence](release-acceptance.md) maps scenarios 1–13 to implementation,
  automated gates, and the external evidence still required.
- [API usage](api.md) explains Swagger, authentication, concurrency, idempotency, and common
  domain-action conventions.
- [Delivery backlog](../TASKS.md) contains only unresolved release evidence, not an obsolete
  feature roadmap.

## Architecture and security

- [Architecture](architecture.md)
- [Domain model](domain-model.md)
- [Entity relationship model](erd.md)
- [Authorization and permissions](permissions.md)
- [Current permission catalog](permission-catalog.md), generated from OpenAPI and backend policy metadata
- [Authentication, federation, and MFA](authentication.md)
- [Threat model](threat-model.md)
- [Security audit log](audit-log.md)
- [Accepted architecture decisions](adr/)

## Product engines

- [Workflow conditions](workflow-conditions.md) and
  [workflow administration](workflow-administration-proposal.md)
- [SLA engine](sla-engine.md)
- [Notification engine](notification-engine.md)
- [Saved ticket views](saved-ticket-views.md)
- [Bulk ticket operations](bulk-ticket-operations.md)
- [Asynchronous ticket exports](async-ticket-exports.md)
- [Ticket bulk/export database ABI](ticket-runtime-database-abi-v1.md)

## Operations and deployment

- [Operations index](operations/README.md)
- [Compose](../deploy/compose/README.md)
- [Swarm](../deploy/swarm/README.md)
- [Kubernetes](../deploy/k8s/README.md)

## Evidence vocabulary

“Implemented” means the source, contract, persistence boundary, and focused automated gate
exist in this repository. “Green” is used only for a command actually executed in the stated
environment. “Release-accepted” additionally requires retained external evidence identified
in [TASKS.md](../TASKS.md). File or test names alone are not proof that a particular CI run or
production drill succeeded.
