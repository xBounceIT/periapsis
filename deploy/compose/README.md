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

Compose materializes host values under `/run/secrets`. Environment-only application
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

## Create the local TLS material

The Compose profiles have one public application edge. They will not interpolate until
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
get/put/delete. Its CORS policy permits the exact `https://localhost:PERIAPSIS_WEB_PORT`
origin, `GET`/`HEAD`/`PUT`, and the closed signed-header set including `Content-Type`,
`Content-Length`, `If-None-Match`, `X-Amz-Meta-Periapsis-Declared-Mime`, and
`X-Amz-Meta-Periapsis-Expected-Size`. It never enables wildcard or
credentialed CORS. Changing the web port reruns this idempotent provisioner on the next
profile start.

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
identities through its admin console after startup. OpenLDAP
uses the admin password supplied through the Compose secret and overrides the upstream
sample-entry LDIF with a credential-free file. Create disposable directory identities
explicitly after startup; no known user password is inherited. Mailpit is allowlisted only
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
