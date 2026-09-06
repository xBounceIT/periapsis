# Deployment and secret integration

Periapsis has four independently scalable application units: web, API, worker, and
notifier. Database migrations use a fifth one-shot image. Application images are immutable,
numeric UID/GID 10001, read-only-root compatible, unprivileged, and expose only their
documented health ports.

The database image compiles its migration, role-provisioning, and seed entrypoints during
the build. Its final stage receives only the compiled JavaScript graph, production
dependencies, the byte-preserved canonical migrations/journal, and the generated SLA seed
JSON. It does not ship TypeScript, tsx, Drizzle Kit, lint tools, or the build workspace.
Production export disables workspace-package hoisting so dependency links cannot refer
back to a builder-only package; ordinary dependency hoisting is preserved.
The deployed `migrate`, `seed`, and `provision-notifier` commands and mounted-secret
configuration remain unchanged. Local development database commands still use tsx;
`corepack pnpm --filter @periapsis/db build:runtime` checks the emitted runtime graph.
Image build, SBOM, vulnerability scans, and non-root/read-only execution must still pass
for each candidate digest; a source packaging check is not container acceptance.

## Environment choices

- Compose is for local development and deterministic authentication/integration tests.
- Swarm uses external PostgreSQL/S3, external versioned Docker Secrets, encrypted overlay
  networks, an operator-managed HTTPS edge with a firewall-restricted origin port, and
  explicit zero-to-ready rollout.
- Kubernetes uses external PostgreSQL/S3, a native or externally reconciled Secret,
  restricted pod security, default-deny networking, Ingress TLS, HPA, and PDB.

Never run local MinIO, Mailpit, OpenLDAP, or Keycloak profiles as production dependencies.
Use supported managed/self-operated services with backups, TLS, monitoring, and a separate
security lifecycle.

## Remote reverse proxy with an HTTP origin

TLS may terminate on a trusted proxy on another machine. Periapsis web can listen on
HTTP without any local web certificate; the public origin must remain HTTPS. Set site
values through environment variables, for example:

```dotenv
PERIAPSIS_PUBLIC_URL=https://incidents.example.com
PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS=192.0.2.10/32
```

Replace the documentation address with the actual proxy source observed by web. Use
canonical lowercase origins without a trailing slash or redundant `:443`. The proxy must
overwrite incoming forwarding headers with the actual client IP in `X-Forwarded-For`,
exactly `X-Forwarded-Proto: https`, and the public origin's `Host`. Do not blindly append
untrusted caller-supplied XFF. Web validates the entire bounded chain, resolves it from
right to left, and forwards only the canonical client address to the API. This identity
feeds existing audit, credential-network restrictions and shared request limits.

- For a dedicated-host **compatibility/staging trial**, select
  `deploy/compose/compose.reverse-proxy.yaml` instead of `compose.yaml`. Apply
  [`deploy/compose/.env.reverse-proxy.example`](../../deploy/compose/.env.reverse-proxy.example)
  alongside the existing file-backed secrets. Set the host bind IP/HTTP port, and public
  storage/IdP HTTPS origins when using those bundled test services. The TLS fragment is
  not loaded, so no dummy certificate paths or local application CA are required.
- For **Swarm**, use `stack.yml` followed by `stack.reverse-proxy.yml` on every
  validation/deployment. Also set `PERIAPSIS_TRUSTED_PROXY_CIDRS` to the reviewed web
  peers seen by API. Host-mode publication preserves the external peer boundary; it
  permits at most one web task per node and uses stop-first updates. Follow the
  [Swarm rollout procedure](../../deploy/swarm/README.md#opt-in-remote-reverse-proxy-without-local-certificates).

Both variants enable `PERIAPSIS_WEB_PROXY_ONLY=true`; web denies non-proxy application
requests. This is not transport encryption or a firewall. Restrict origin ports to the
proxy and use a private network or encrypted tunnel between machines, never public
plaintext transport. Do not publish the API or database. PostgreSQL, S3, LDAP, scanners
and federation keep their independent outbound TLS and trust requirements. Kubernetes'
existing HTTP ClusterIP/HTTPS Ingress setup is unchanged.

Before accepting traffic, verify a real request through the proxy retains its client IP,
caller-injected XFF cannot replace it, direct origin application requests are rejected,
and login, CSRF, callback URLs and signed uploads still work at the public origin. The
repository's tests do not replace this site-specific NAT/firewall/browser acceptance.

## Secret lifecycle

Inventory each secret by owner, purpose, creation time, version, consumers, and rotation
deadline. At minimum keep each runtime database URL/password pair mutually independent,
including a dedicated `periapsis_notifier_login` credential, plus the bootstrap token, master key, API
credential keyring, identity keyring, notification keyring, notifier preview token,
S3 credential, and ingress/LDAP trust material separate. Tenant SMTP passwords and
webhook HMAC keys are write-only inputs stored only as encrypted database envelopes; they
are not deployment secrets or file mounts.

1. Create a new version in the deployment secret store.
2. Mount it as a file with the exact `*_FILE` variable expected by the process.
3. Roll one consumer class at a time and verify readiness plus decryptability checks.
4. Revoke the prior credential only after all old tasks have stopped.
5. Retain historical keyring roots while any live credential or ciphertext references
   them; key rotation is not key deletion.

Construct the notifier runtime URL with `periapsis_notifier_login` and its dedicated
password. Store the same password separately for the one-shot migration role-provisioning
step; never substitute the API or worker credential.

The notification keyring uses the literal runtime ABI `NOTIFICATION_KEYRING_FILE` and is
mounted read-only on API and notifier, never supplied as a direct production environment
value. Its versioned roots seal write-only SMTP passwords and webhook HMAC keys stored in
the database. Rotate the API first so it writes with the new active version, then notifier;
retain every old root until a bounded re-encryption job and decryptability audit prove it
unused.

Template preview is a separate trust path. API receives the private notifier Service URL
as `PERIAPSIS_NOTIFIER_INTERNAL_URL`; API and notifier mount the same independent bearer
through `PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE`. Keep the endpoint off public ingress and
allow only the API-to-notifier hop in the deployment network policy. Do not derive or
reuse this bearer from any keyring or tenant credential.

Kubernetes External Secrets is optional. Its controller and SecretStore require their own
threat model, namespace restrictions, workload identity, audit, and outage behavior.
Docker Secrets and Kubernetes Secrets are transport/mount mechanisms, not encrypted backup
systems by themselves.

## Webhook egress policy and local development opt-in

Tenant administrators can publish an immutable, versioned HTTPS webhook URL policy. Each
webhook configuration stores the canonical endpoint digest and the exact policy version it
was admitted against. The notifier revalidates the current policy when it claims a delivery
and immediately before connecting, so a revoked destination fails closed. DNS and resolved
address checks still reject loopback, private, link-local, metadata, and other non-public
addresses for HTTPS destinations.

Plain HTTP is disabled by default and is forbidden in production. Local development requires
both of these independent controls:

1. Set `PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL=true` on the API, notifier, and the privileged
   one-shot database task. The database task records durable opt-in only for the exact
   `periapsis_api_login` and `periapsis_notifier_login` login roles.
2. The API/notifier sets transaction-local database consent only when its own validated
   environment flag is enabled. A tenant request, SQL `SET ROLE`, or forged session setting
   cannot create durable consent.

Even with both controls enabled, only exact `localhost`, `127.0.0.1`, or `[::1]` endpoints
are accepted, and DNS resolution of `localhost` must yield exactly `127.0.0.1` or `::1`;
aliases, other loopback addresses, public addresses, private networks, and link-local
addresses remain denied. Compose enables the pair for its isolated development network and
sets an explicit development-only `80,443,8080` notifier port allowlist. Swarm and Kubernetes
defaults stay `false`, while the notifier defaults to HTTPS port `443`; do not override them
in a production deployment. To revoke
the exception, set the variable to `false` and rerun the database task for both API and
notifier credentials before rolling the runtime processes. The opt-in table contains only a
role name, boolean, and timestamp—never tenant data or secrets—and runtime roles cannot
insert, update, or delete it.

## External dependencies

- PostgreSQL 18 must enforce TLS, least-privileged logins, connection limits, forced RLS,
  append-only audit permissions, encrypted backups, and tested PITR.
- S3 must enforce TLS, bucket versioning/object lock according to retention policy,
  server-side encryption, lifecycle rules, tenant-prefix least privilege where supported,
  exact-origin CORS, and access logging. ClamAV signatures must remain fresh and scanning
  fails closed. Follow the [DFIR evidence storage runbook](dfir-evidence-storage.md).
- SMTP credentials may send only through approved domains/relays. Mailpit is local only.
- LDAP/OIDC/SAML egress is restricted by NetworkPolicy/firewall and application SSRF
  policy. Permit private LDAP CIDRs only after review; metadata/link-local destinations
  stay blocked.
- The telemetry backend must not have broader human access than the data classifications
  represented in its attributes.

Label Kubernetes ingress and observability namespaces exactly as documented in
`deploy/k8s/README.md`. Narrow production egress CIDRs before applying manifests. A CNI
without NetworkPolicy enforcement is not an equivalent control.

## Capacity and availability

Size KDF concurrency against replica memory, then load-test login bursts. Scale API/web on
latency/CPU, and worker/notifier primarily on queue age/depth when an approved metrics
adapter is available. Preserve PostgreSQL connection headroom across maximum replica
counts. PDBs protect voluntary disruption but do not replace multi-zone scheduling,
backups, or a dependency availability plan.
