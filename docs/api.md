# HTTP API and generated clients

OpenAPI 3.1 at
[`packages/contracts/openapi/openapi.yaml`](../packages/contracts/openapi/openapi.yaml) is
the canonical HTTP contract. The Go server contract, TypeScript client, and vendored Swagger
assets are generated from it. Handwritten prose and handlers may not introduce an endpoint,
field, or error shape that is absent from OpenAPI.

When documentation exposure is enabled, the same contract is served as:

- `GET /openapi.json` for machines;
- `GET /docs` for Swagger UI.

`corepack pnpm --filter @periapsis/contracts test` validates the contract inventories.
`corepack pnpm verify:generated` and `corepack pnpm verify:go-generated` fail when OpenAPI,
generated TypeScript, generated Go, sqlc output, or schema artifacts drift.

## Request boundaries

Tenant resources use `/api/v1/tenants/{tenantId}/...`. The path tenant is checked against
the authenticated principal, live membership, permission scope, operator-team assignment,
and token scope. A client-supplied tenant header never widens access.

Browser mutations use the secure server-side session cookie plus the exact Origin/CSRF
boundary. Service accounts use the one-time bearer credential issued by the API-key
administration flow and are restricted to their live tenant and permission scopes.

Commands documented as idempotent require `Idempotency-Key`. Reusing a key with the exact
canonical request returns the pinned result; reusing it with another fingerprint returns a
conflict. Versioned mutations require both `If-Match` and the matching expected version in
the request body when the operation schema defines one. Omitting either boundary does not
turn the write into last-write-wins.

Important domain actions are explicit routes, including `claim`, `release`, `assign`,
`transfer`, `transition`, `close`, `reopen`, `escalate`, `link`, `unlink`, and `sla/override`.
They are not hidden behind a generic patch.

Errors use `application/problem+json` with a stable code and request identifier. Public
authentication and authorization failures remain non-oracular.

## Example service-account Alert ingest

Replace every placeholder with values issued or returned by your installation. The
`source_ticket` definition must already be published for Alerts and writable by this
principal. Never place a production credential in shell history; the inline variable below
is only a shape example.

```bash
curl --request POST \
  --url "https://periapsis.example/api/v1/tenants/00000000-0000-7000-8000-000000000001/alerts" \
  --header "Authorization: Bearer ${PERIAPSIS_API_KEY}" \
  --header "Content-Type: application/json" \
  --header "Idempotency-Key: ingest-2026-09-02-000001" \
  --data '{
    "title": "Suspicious sign-in",
    "severity": "high",
    "source": "example-siem",
    "tags": ["identity"],
    "customFields": {"source_ticket": "SIEM-42"},
    "rawPayload": {"eventVersion": 1}
  }'
```

Use the generated TypeScript client in application code rather than copying request types
from this example. Check Swagger for the exact current required fields and enum values.
