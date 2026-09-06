# Local Compose environment

The Compose model exposes three application profiles while keeping migrations as a
one-shot unit:

| Profile     | Services                                                                              |
| ----------- | ------------------------------------------------------------------------------------- |
| `minimal`   | PostgreSQL 18.6, migration, API, worker, web, TLS edge, MinIO provisioner, and ClamAV |
| `auth-test` | `minimal` plus OpenLDAP 2.6 and a Keycloak realm with OIDC PKCE and SAML clients      |
| `full`      | `auth-test` plus Mailpit, notifier reference, Prometheus, and OpenTelemetry Collector |

The optional `seed` profile runs the idempotent synthetic Acme/Globex seed separately;
replicas never migrate or seed on startup.

Compose enables `PERIAPSIS_WEBHOOK_ALLOW_PLAIN_LOCAL` only for local development. The
database task records the matching opt-in for the exact API and notifier login roles, while
each runtime must independently enable transaction-local consent. This permits only exact
`localhost`, `127.0.0.1`, and `[::1]` HTTP webhook URLs; aliases and private/link-local
destinations remain blocked. The Compose-only `PERIAPSIS_WEBHOOK_ALLOWED_PORTS` default is
the explicit `80,443,8080` allowlist; resolved addresses for the HTTP exception must still be
exactly `127.0.0.1` or `::1`. Production Swarm and Kubernetes manifests keep the flag false
and the notifier's production port default remains `443`;
see [the deployment runbook](../../docs/operations/deployment.md#webhook-egress-policy-and-local-development-opt-in)
for enablement and revocation.

## Configure secrets

Copy `deploy/compose/.env.example` to the repository-root `.env`. Generate independent random values
for every blank entry; do not commit `.env` or reuse these local values elsewhere. The
master key is standard padded Base64 for exactly 32 random bytes. API credential and
identity keyrings are one-line JSON documents with independent roots, for example:

```json
{
  "activeVersion": 1,
  "keys": [{ "version": 1, "key": "PADDED_STANDARD_BASE64_32_BYTE_ROOT" }]
}
```

API and worker replicas must receive the same active and retained identity-keyring
versions during a rolling update. Never reuse the bootstrap, master, API-credential, or
identity roots. `PERIAPSIS_NOTIFIER_DATABASE_PASSWORD` provisions and connects only
`periapsis_notifier_login`; using the API or worker password violates least privilege.
Keep local database passwords lowercase hexadecimal so URL construction is unambiguous.
The independent notifier preview token must contain 32-512 allowlisted characters.
Compose mounts the same
`PERIAPSIS_NOTIFIER_PREVIEW_TOKEN` value as a file in API and notifier; it is never
committed to the realm or fixtures. API reaches the preview endpoint only through the
internal `notification-preview` network alias. The endpoint is available when the `full`
profile runs the referenced notifier image; other profiles fail preview requests closed.

`PERIAPSIS_NOTIFICATION_KEYRING` is materialized only as the
`NOTIFICATION_KEYRING_FILE` Docker Secret for API and notifier. Its closed JSON form is
`{"activeVersion":1,"keys":[{"version":1,"key":"BASE64URL_NO_PADDING_32_BYTE_ROOT"}]}`.
It permits at most 16 unique versions in the range 1..32767; every decoded key is exactly
32 bytes. Keep retained versions until all database ciphertext has been rotated, and
never reuse auth, identity, master, or notification roots.

Set `PERIAPSIS_COMPOSE_SECRETS_DIR` in `.env` to a new absolute directory outside the
checkout whose parent exists. Fill all 15 secret values, including those used only by
`auth-test` or `full`, then run once from the repository root:

```text
node scripts/deploy/prepare-compose-secrets.mjs --env-file .env
```

Process environment values take precedence over `.env`, as with Compose. The helper
validates every value before creating files, never prints them, and refuses an existing
directory, file or symlink. It does not rotate credentials in place: stop the affected
services and prepare a new directory when deliberately rotating local secrets, keeping
`.env` and the files consistent. Never remove old files while containers still mount them.

On Linux, the directory is private mode `0700`; individual files use `0444` so the
different non-root application and infrastructure UIDs can read their explicitly granted
bind mounts. Other host users cannot traverse the private parent. On Windows the helper
removes inherited directory ACLs and grants only the current user's SID before writing
secrets. Do not share that directory, relax its permissions, or mount it wholesale.
Docker/host administrators remain trusted. TLS files are configured independently below.

Compose mounts those files under `/run/secrets`, without trying to create them inside
read-only containers. Environment-only application
database URLs are intentional only in this local-development model. The `full` profile
runs `notifier-provision` after the schema migration and before notifier startup. Swarm and Kubernetes
mount complete URLs and set `PERIAPSIS_DATABASE_URL_FILE`, which production mode requires.

The API's generic request limiter is shared through PostgreSQL across every replica. The
Compose defaults are `100` requests/second per IPv4 `/32` or IPv6 `/64`, `60` per opaque
credential, and `40` per bounded tenant/credential-or-network tuple. Override them with
the three `PERIAPSIS_API_RATE_LIMIT_*_RPS` values in `.env` (each must remain in `1..100`).
The configured web-service peer is the only source allowed to supply the sanitized client
address. Health, metrics, and documentation paths are exempt; database admission failures
make ordinary requests fail closed.

## Incompatible local upgrades

When the candidate migration does not explicitly publish a sealed immediate-predecessor
edge, do not run it against an already-running application profile. Resolve the handoff
classification from the candidate manifest and health source, then stop
edge/web/API/worker/notifier and use the local administrator connection to set
`periapsis_api_login`, `periapsis_worker_login`, and `periapsis_notifier_login` to
`NOLOGIN`, and verify that `pg_stat_activity` has no rows for those users before rerunning
the one-shot migration service. The current incompatible-handoff migration must reject any
weaker state. A successful database task reprovisions the login roles before the application
profile is started again; a failed task intentionally leaves them closed. The exact SQL and
recovery rules are in the
[upgrade runbook](../../docs/operations/migration-bootstrap-upgrade.md#current-compatibility-handoff).

## Remote TLS proxy without local edge certificates

Use `compose.reverse-proxy.yaml` explicitly when HTTPS terminates on another
machine. It includes the same `compose.base.yaml` service model with
`reverse-proxy.override.yaml`, never the TLS fragment. The normal `compose.yaml`
entry remains local TLS by default. Docker Compose 2.39.4 or later is required
for this documented multi-file setup; do not pass the TLS entry as an additional
`-f` file or supply dummy certificate paths.

Prepare the same 15 file-backed secrets, then apply the non-secret site settings
from `.env.reverse-proxy.example` to your `.env`. Set the dedicated host's bind IP,
HTTP port, canonical public **HTTPS** application origin and exact proxy peer
CIDRs. The three `PERIAPSIS_DEV_TLS_*_FILE` values are unused in this mode and may
remain empty. No container's security flags, secret files, database provisioning
or application authorization are replaced by the remote proxy.

```text
docker compose --env-file .env --file deploy/compose/compose.reverse-proxy.yaml --profile full config --quiet
docker compose --env-file .env --file deploy/compose/compose.reverse-proxy.yaml --profile full up --build --detach --wait
```

The external proxy forwards application traffic directly to the web HTTP port.
It must replace client-supplied forwarding headers with one canonical
`X-Forwarded-Proto: https`, a valid `X-Forwarded-For` client address, and the public
origin's `Host` (including its non-default port, when applicable). Web admits only
the configured socket peers and canonical public origin; the API still trusts
only the fixed web container address. Inspect the actual peer address seen after
host NAT and configure that exact address, not a universal CIDR or a whole LAN.

Restrict the host firewall to that proxy on the web, IdP and storage listener
ports. The HTTP connection between machines must traverse a trusted private
network or encrypted tunnel; do not expose this plaintext hop over the public
Internet. A default `0.0.0.0` bind is not a substitute for firewall rules.

The auxiliary HTTP Caddy serves only the compatibility MinIO/Keycloak targets,
with the same proxy-peer restriction and exact application-origin storage CORS
policy. The external proxy must publish `PERIAPSIS_S3_PUBLIC_ENDPOINT` and
`PERIAPSIS_IDP_PUBLIC_URL` as HTTPS origins and preserve the storage Host, raw URI,
signed headers and body. Only local `GET /health/live` bypasses the auxiliary
peer gate. Keycloak's hostname remains an invalid placeholder until explicitly
configured for `auth-test`/`full`; never treat that placeholder as a working IdP.
The test-only auxiliary Keycloak sees the external proxy's IP; its audit records
are not evidence of the application's original-client IP attribution.
Existing Keycloak data may already contain an imported realm: changing an env
value does not update an existing realm. Update its callback origins deliberately
through its supported administration flow; do not reset volumes to rotate them.

API and worker continue to validate outbound HTTPS normally. The worker receives
only an additional egress network, not published ports. The containers must resolve
and reach the remote IdP's public hostname; if it resolves to a private proxy IP,
set `PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS` to explicitly admit that destination
and retain any needed existing identity targets. Keep HTTPS-port and LDAP/S3 SSRF
allowlists independent. This remains the Compose compatibility environment, not
a conversion of local test IdP/storage components into production services.

## Create the local TLS material

The default `compose.yaml` entry includes the common model and local TLS fragment.
These default profiles have one public application edge. They will not interpolate until
all three `PERIAPSIS_DEV_TLS_*_FILE` values name readable, absolute paths outside this
repository. The certificate must cover `localhost`, `idp.localhost`,
`storage.localhost`, `127.0.0.1`, and `::1`. One convenient workflow uses
[mkcert](https://github.com/FiloSottile/mkcert):

```bash
tls_dir="${XDG_CONFIG_HOME:-$HOME/.config}/periapsis/dev-tls"
mkdir -p "$tls_dir"
mkcert -install
mkcert \
  -cert-file "$tls_dir/periapsis-dev.crt" \
  -key-file "$tls_dir/periapsis-dev.key" \
  localhost idp.localhost storage.localhost 127.0.0.1 ::1
cp "$(mkcert -CAROOT)/rootCA.pem" "$tls_dir/periapsis-dev-ca.crt"
chmod 0444 "$tls_dir/periapsis-dev.crt" "$tls_dir/periapsis-dev-ca.crt"
chmod 0400 "$tls_dir/periapsis-dev.key"
```

Set the three `.env` entries to those absolute paths. On native Linux, file-backed
Compose secrets preserve host ownership; make the private key readable by numeric
UID/GID `10001:10001` without making it group- or world-readable (for example, use a
dedicated root-owned directory, `chown 10001:10001`, and mode `0400`). Docker Desktop
handles the secret mount inside its VM. Copy only `rootCA.pem`: mkcert's CA private key
must never be copied, mounted, or committed.

The pinned Caddy edge mounts the leaf certificate, key, and public CA through Compose
secrets. It runs as UID/GID 10001 with a read-only root, no Linux capabilities, and only
explicit `/tmp`, `/data`, and `/config` tmpfs mounts. It accepts TLS 1.2 or 1.3 and does
not enable HTTP access logging. Caddy terminates TLS while the private, container-only
web, Keycloak, MinIO, and API hops remain HTTP. The API receives only the public CA file
and allows the local Keycloak port `18090` for federated HTTPS validation.

LDAP private-network access is explicitly limited to the dedicated local identity subnet
`172.30.241.0/28`. The API and worker receive identical LDAP SSRF/concurrency/port bounds;
the worker additionally receives all bounded synchronization lease, backoff, timeout,
absence-batch, and parallelism settings. Reserved, link-local, loopback, metadata,
multicast, and documentation ranges remain rejected by application policy.

## Local evidence storage and scanner

Every runtime profile starts local MinIO and ClamAV because DFIR readiness must fail closed
when either boundary is absent. Set independent MinIO root and application credentials;
the one-shot `minio-provision` service creates only the `periapsis-evidence` bucket,
enables versioning, and grants the application user only bucket location/list plus object
get/put/delete. The pinned local MinIO does not implement per-bucket CORS. The TLS edge
therefore owns the browser policy and removes every upstream `Access-Control-*` response
header; MinIO's global origin setting is additionally limited to the same local origin.
The edge policy permits the exact `https://localhost:PERIAPSIS_WEB_PORT`
origin, `GET`/`HEAD`/`PUT`, and the closed signed-header set including `Content-Type`,
`Content-Length`, `If-None-Match`, `X-Amz-Meta-Periapsis-Declared-Mime`, and
`X-Amz-Meta-Periapsis-Expected-Size`. It never enables wildcard or
credentialed CORS. Preflights receive only this static header allowlist, never a reflection
of requested headers: a browser rejects an unlisted header. Foreign origins, unsupported
methods and paths outside the evidence bucket are rejected at the edge. Requests without
an Origin receive no CORS grant and still require normal S3 authorization. Only `ETag` is
exposed, with a 300-second preflight lifetime and origin/method/header cache variation.
Changing the web port recreates the edge/MinIO configuration on the next profile start;
resource provisioning remains idempotent and never resets existing storage.

`pnpm test:storage-cors` runs the deployed policy with real Caddy 2.11.4 against an
owned loopback HTTP fixture; set `PERIAPSIS_CADDY_BINARY` to the checksum-verified
executable returned by `node scripts/deploy/install-caddy-test-binary.mjs`. Missing
or wrong-version binaries fail the gate. Deployment CI installs and runs this check
independently of database/LDAP startup. It does not replace the live browser/S3 tests.

The API and worker reach MinIO only on the internal `storage` network while browser grants
use `https://storage.localhost:PERIAPSIS_MINIO_API_PORT` through the loopback-only TLS
edge. Uploads are create-only, exact-size, single-PUT operations capped
at decimal `5_000_000_000` bytes; see the
[evidence-storage runbook](../../docs/operations/dfir-evidence-storage.md). The browser
derives `Content-Length` from the `File` body even though the signature binds it.

ClamAV uses the pinned `clamav-debian` base image and `/init-unprivileged` as UID/GID 1000.
Its root/config remain read-only, signature data lives only in the dedicated
`clamav_signatures` volume, and temporary/log paths are explicit. The daemon's unencrypted
TCP port exists only on the internal storage network; only ClamAV joins the separate
outbound update network. Health requires clamd plus signatures no older than 26 hours,
and application readiness/scanning remains closed during initial download, stale updates,
or scanner failure. Budget several GiB of memory and temporary storage for this profile;
do not expose port 3310 to the host.

## Run profiles

```text
docker compose --env-file .env -f deploy/compose/compose.yaml --profile minimal up --build
docker compose --env-file .env -f deploy/compose/compose.yaml --profile auth-test up --build
docker compose --env-file .env -f deploy/compose/compose.yaml --profile full up --build
docker compose --env-file .env -f deploy/compose/compose.yaml --profile seed run --rm db-seed
docker compose --env-file .env -f deploy/compose/compose.yaml --profile full down --volumes --remove-orphans
```

All published ports bind to loopback. The TLS edge defaults are web
`https://localhost:8443`, Keycloak `https://idp.localhost:18090`, and MinIO API
`https://storage.localhost:19000`. Each configured edge value is both its host and
container listener port and must remain in `1024..65535`; if the Keycloak port changes,
include the same value in `PERIAPSIS_FEDERATED_HTTPS_PORTS`. The API, web upstream,
Keycloak HTTP listener, and MinIO API have no direct host binding. Auxiliary defaults are
Mailpit HTTP `18025`, the loopback-only Mailpit acceptance SMTP port `11025`, MinIO
console `19001`, and Prometheus `19090`. PostgreSQL, LDAP, production SMTP, and OTLP
ports are not published.

OIDC timestamp validation uses `PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=1m` for both tenant and
platform providers. Keep it within the validated `0s..5m` range; increasing it tolerates
greater identity-provider clock drift but does not relax token-age or lifetime ceilings.

The Keycloak import creates only public OIDC/SAML client metadata, never users or
passwords. Its strict public hostname is `https://idp.localhost:PERIAPSIS_IDP_PORT`, it
trusts forwarded headers only from the fixed edge address, and its imported OIDC/SAML
callbacks resolve `PERIAPSIS_WEB_PORT` to the HTTPS web origin. Create disposable
identities through its admin console after startup. The repository-owned OpenLDAP test
adapter reuses binaries and schemas from the pinned image, but not its root-only bootstrap
or sample directory. It imports only the fixed organization entry; create disposable
directory identities explicitly after startup. No known user password is inherited.
Mailpit is allowlisted only
for local administration validation and notifier delivery on port 1025. Both the API and
notifier opt into that mode only in Compose; plaintext SMTP remains rejected in
production.

Run the real SMTP fixture acceptance after starting Mailpit from the `full` profile:

```text
PERIAPSIS_MAILPIT_ACCEPTANCE=1 pnpm --filter @periapsis/notifier test:mailpit
```

The test uses only the loopback SMTP and HTTP bindings, validates the exact health probe,
delivers a customer-projected rendered message, and checks Mailpit without logging message
contents or recipients.

Mailpit also joins its own non-internal `mailpit-host` bridge: Docker does not activate
published host ports for a container connected only to internal networks. Only this
optional local fixture joins that bridge; `integrations` remains internal, and both host
ports remain bound exclusively to `127.0.0.1`. The bridge also permits outbound routing
from Mailpit, so it is not a fully isolated capture appliance. No other service receives
that route, and no SMTP relay or forwarding destination is configured. The CI acceptance
checks Docker's actual loopback port bindings before probing and delivering.

Startup realm import deliberately skips an existing realm. A `keycloak_data` volume
created by the former HTTP profile therefore retains its old client redirects; update both
test clients through the admin console or remove only that disposable volume while the
stack is down before running the HTTPS authentication smoke. Do not remove PostgreSQL or
MinIO volumes as part of that reset.

The `ldap-tls` one-shot dependency generates a 30-day local CA and an `openldap` server
certificate into a named volume without committing private material. OpenLDAP requires
that material and enables both verified STARTTLS and LDAPS. Periapsis providers must use
one of those encrypted transports; the profile does not expose an LDAP port to the host.
Copy only the public `/run/secrets/ldap/ca.crt` to an operator-owned temporary path and
submit it as the LDAP provider `customCaPem`. Removing `openldap_tls` rotates the CA, so
update the provider pin before retrying connectivity.

The adapter is intentionally limited to this test directory, not general-purpose LDAP
hosting, replication, or migration of existing upstream configurations. Image construction
sets UID/GID `10001:10001`; runtime has no capabilities, a read-only root, only the declared
private temporary mounts, and the `openldap_data` volume at `/var/lib/periapsis-ldap`.
Inherited upstream anonymous-volume declarations are removed. STARTTLS uses internal port
`1389` and LDAPS `1636`; neither needs privileged-port capabilities. API/worker local egress
allowlists, health probes and acceptance fixtures use those exact ports. Use
`deploy/compose/.env.example`, not the general repository-root production defaults, and
update an existing Compose `.env` to those two port values when upgrading this fixture.

The first bootstrap hashes the administrator password directly from its mounted file with
the pinned OpenLDAP tool and retains the initial hash. The prepared password file must be
nonempty and contain no NUL, CR or LF. Changing the mount does **not** rotate existing LDAP
credentials: the real TLS/admin-bind healthcheck then fails and Compose remains unhealthy.
There is no custom password verifier. Fresh bootstrap imports `cn=config` and the empty
account tree offline as UID 10001, then starts slapd directly without root administration.

An incompatible, foreign-owned or partially initialized volume is rejected without any
deletion or reseeding. Existing `openldap_config` volumes are no longer mounted and are not
migrated or removed automatically. Back up any needed disposable directory entries before
explicitly replacing only the old LDAP test volumes; never delete PostgreSQL, MinIO or
other application volumes as part of this fixture reset. Bootstrap diagnostics emit fixed
stage codes only, without directory content, credentials or raw slapd output.

### Composed LDAP acceptance

Run the composed acceptance only against a fresh disposable `auth-test` database because
it consumes one-time bootstrap enrollment. Generate
`PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD` independently in the shell or CI secret store;
the repository contains no fixture password and the value is passed only to the one-shot
OpenLDAP provisioning command. After the profile is healthy, export the generated public
LDAP CA and execute the API-level flow:

```bash
ldap_container="$(docker compose --env-file .env -f deploy/compose/compose.yaml --profile auth-test ps -q openldap)"
ldap_ca="$(mktemp)"
docker cp "${ldap_container}:/run/secrets/ldap/ca.crt" "${ldap_ca}"

PERIAPSIS_LDAP_ACCEPTANCE_CA_FILE="${ldap_ca}" \
PERIAPSIS_LDAP_ACCEPTANCE_BASE_URL="https://localhost:${PERIAPSIS_WEB_PORT:-8443}" \
NODE_EXTRA_CA_CERTS="${PERIAPSIS_DEV_TLS_CA_FILE}" \
node tests/integration/ldap-auth-acceptance.mjs
rm -f "${ldap_ca}"
```

The test provisions one `soc-l2-user` and `SOC-L2` group inside the ephemeral directory,
configures the tenant provider, encrypted bind secret, binding, authoritative mapping,
role, security group, and exact operator-team assignment through the public API, and then
performs a real LDAP login. It compares dry-run plans with the imported profile and
authority, removes the directory group, waits for the real worker sync, and verifies edge
retirement, session revalidation, login denial, and tenant audit events. Neither the bind
password nor the user password is printed or persisted in the repository.

`full` builds the notifier from `deploy/images/Dockerfile.notifier` by default. Set
`PERIAPSIS_NOTIFIER_IMAGE` when the profile must use an immutable published image instead.
MinIO is the final open-source compatibility release and is
strictly local-test-only; production must use a maintained external S3-compatible service.

Application containers run as UID/GID 10001, drop all Linux capabilities, prohibit
privilege escalation, use read-only roots, and receive only explicit temporary storage.
The deploy-owned API packaging copies the contacts, identity, ticketing, custom-fields,
SLA, and DFIR Go modules; the worker packaging copies the repository module tree. This keeps every
committed `replace ../../modules/...` directive resolvable inside the build context.
Third-party infrastructure images use their documented non-root identities where
supported. The local MinIO wrapper pre-creates its named-volume mount with non-root
ownership; it does not change the pinned upstream binary. Named volumes hold PostgreSQL,
LDAP, Keycloak, MinIO, ClamAV signatures, and Prometheus state.

## TLS smoke test

After the selected profile is healthy, verify the three public names with the external
CA and confirm that the old direct HTTP listeners are absent:

```bash
tls_ca="${PERIAPSIS_DEV_TLS_CA_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/periapsis/dev-tls/periapsis-dev-ca.crt}"
web_port="${PERIAPSIS_WEB_PORT:-8443}"
idp_port="${PERIAPSIS_IDP_PORT:-18090}"
storage_port="${PERIAPSIS_MINIO_API_PORT:-19000}"

curl --fail --cacert "$tls_ca" "https://localhost:${web_port}/health/live"
curl --fail --cacert "$tls_ca" \
  "https://idp.localhost:${idp_port}/realms/periapsis-test/.well-known/openid-configuration"
curl --fail --cacert "$tls_ca" \
  "https://storage.localhost:${storage_port}/minio/health/live"
curl --fail --tlsv1.2 --tls-max 1.2 --cacert "$tls_ca" \
  "https://localhost:${web_port}/health/live"
curl --fail --tlsv1.3 --cacert "$tls_ca" "https://localhost:${web_port}/health/live"

# These must fail to connect; no application HTTP listener is host-published.
curl --fail --max-time 2 http://127.0.0.1:8080/health/live && exit 1 || true
curl --fail --max-time 2 http://127.0.0.1:8081/health/live && exit 1 || true
```

When ports are overridden, substitute the `.env` values in the smoke URLs. A TLS failure
is not bypassed with `--insecure`: regenerate a certificate with all three SANs, verify
the CA path, and restart the edge.
