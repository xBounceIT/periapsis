# Docker Swarm deployment

`stack.yml` is a production-oriented template for external PostgreSQL and external
S3-compatible storage. It deliberately defaults every replicated service to zero. This
prevents a first deployment from accepting traffic before secrets and migrations have
been verified.

The stack is an origin behind an operator-managed HTTPS load balancer; it does not manage
public certificates. The Swarm routing mesh publishes only the web origin port. Firewall
that node port so only approved load-balancer addresses can reach it, terminate modern TLS
at the edge, and set `PERIAPSIS_PUBLIC_URL` to the canonical HTTPS origin. Keep
`PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS` empty unless the exact proxy source CIDRs are known;
never expose the plain origin port directly to the Internet.

Every API task uses the external PostgreSQL database for one shared request-admission
budget; there is no task-local fallback. Set the three
`PERIAPSIS_API_RATE_LIMIT_*_RPS` values in the non-secret environment file (defaults
`100` per network, `60` per opaque credential, and `40` per bounded tenant subject; valid
range `1..100`). Preserve the same master-key Secret across replicas so the HMAC meter
identities remain stable, and pin `PERIAPSIS_TRUSTED_PROXY_CIDRS` to the exact web-task
peers so the network dimension cannot be spoofed. Health, metrics, and documentation
remain exempt; PostgreSQL admission errors fail ordinary requests closed.

## Prepare immutable inputs

Copy `.env.example` outside the repository and replace every image with an immutable
registry digest. Create versioned Docker Secrets from files or a secret manager; never put
secret values in the environment file or stack. The required external secret names are
listed at the bottom of `stack.yml`. Complete API/worker/notifier URLs must enforce TLS and
least-privileged database roles. Build `notifier_database_url` with the exact
`periapsis_notifier_login` username and the independent password stored in
`notifier_database_password`; never reuse an API or worker credential. The independent
migration URL must use `sslmode=verify-full` and a hostname covered by the database
certificate.

API and worker each mount the same least-privileged `s3_access_key` and `s3_secret_key`
files plus reviewed `s3_ca_bundle`, `dfir_scanner_ca_bundle`, and
`federated_ca_bundle` PEM files. The PEM bundles are versioned Docker Secrets even though
they are public trust material, so tasks cannot silently fall back to a different
operator-provided file. Never place credential or PEM contents in the environment file.

Label eligible nodes before deployment. Keep the migration on a manager only if that
manager is approved to reach the database, and label persistent observability storage:

```text
docker node update --label-add periapsis.runtime=true NODE
docker node update --label-add periapsis.migration=true MANAGER_NODE
docker node update --label-add periapsis.observability=true NODE
```

Set the corresponding placement constraints in the environment file. Validate without
deploying. `docker stack` does not consume a Compose `--env-file`; load the non-secret
values into the current shell explicitly and keep that shell for validation/deployment:

```text
set -a
. /secure/operator-path/periapsis-swarm.env
set +a
docker stack config --compose-file deploy/swarm/stack.yml >/dev/null
```

## Migrate, bootstrap, and start

1. Deploy at zero replicas: `docker stack deploy --with-registry-auth -c deploy/swarm/stack.yml periapsis`.
2. Start the one-shot task: `docker service scale periapsis_migration=1`.
3. Wait for one completed task and inspect its redacted JSON logs. Any failure blocks rollout.
4. Scale notifier and API to one, verify both `/health/ready` endpoints, then scale web/worker and observability to the reviewed counts. API and notifier require the same independent preview-token file secret; notifier also requires its least-privileged database URL. The migration task provisions `periapsis_notifier_login` from the separate notifier-password secret before either service is scaled.
5. Perform one-time bootstrap through the HTTPS web origin using the bootstrap secret; revoke/rotate it immediately afterward.

On later releases, first classify the handoff from the release runbook. A release with an
explicitly sealed predecessor may retain the current runtime image digests and replica
counts while selecting the new database-task digest. A handoff without an explicitly
sealed rolling predecessor must instead be quiesced: remove ingress traffic, scale
web/API/worker/notifier to zero, set `periapsis_api_login`,
`periapsis_worker_login`, and `periapsis_notifier_login` to `NOLOGIN` through the approved
administrator channel, and verify that `pg_stat_activity` contains no backend for those
exact users. Only then deploy and run the new migration task. The candidate's incompatible
handoff migration must reject a login-enabled role or residual runtime backend; the
successful database task reprovisions the three logins before new replicas start. A failed
task leaves the login gate closed.

After a compatible migration, or after the quiesced candidate task has sealed successfully,
deploy the release environment containing the new runtime digests. Updating all digests
in one pre-migration stack deployment would roll application services too early. For
handoffs that explicitly retain a predecessor, runtime services use start-first rolling
updates and automatic rollback; worker/notifier use stop-first to avoid overlapping
consumers where a release changes job semantics.

Swarm config objects are immutable snapshots at deployment time. Changing Prometheus or
collector files requires a stack update; keep prior versions until rollback is no longer
needed. Rotate secrets by creating a new versioned object, changing only the external
secret name, deploying, and retiring the old object after every task uses the new one.

API and notifier both require the external `notification-keyring` Docker Secret, exposed
only through the literal `NOTIFICATION_KEYRING_FILE`. Its closed JSON document is
`{"activeVersion":1,"keys":[{"version":1,"key":"BASE64URL_NO_PADDING_32_BYTE_ROOT"}]}`:
at most 16 unique versions from 1 through 32767, with each unpadded Base64URL value
decoding to exactly 32 bytes. Rotate by adding a version and changing `activeVersion`;
retain old roots until all sealed endpoint credentials have been re-encrypted. Missing or
invalid keyring material must keep readiness false. Never reuse master/auth/identity roots
or place the JSON in the Swarm environment file.

The independent API-credential and identity keyrings use standard padded Base64 and the
closed document `{"activeVersion":1,"keys":[{"version":1,"key":"PADDED_STANDARD_BASE64_32_BYTE_ROOT"}]}`.
API mounts both; worker mounts only identity. Preserve retained versions during rolling
rotation and never reuse roots between keyring classes.

The independent preview bearer is mounted from the same external
`notifier_preview_token` Docker Secret into API and notifier through
`PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE`. API calls
`http://notifier-preview:8083/internal/v1/notification-preview`; the alias exists only on
the encrypted, non-attachable `notification-preview` overlay and no notifier port is
published. Never reuse this bearer as a notification keyring root or tenant credential.

The database task reads the complete administrator URL only from the external
`database_admin_url` secret and rejects production startup unless its single `sslmode` is
`verify-full`. Never reuse that privileged URL for a runtime service.

Tenant SMTP endpoints and their encrypted credential envelopes come only from pinned
database configuration, never global host/password environment variables or a file-secret
fallback. The notifier decrypts an envelope only with `NOTIFICATION_KEYRING_FILE` and the
stored tenant/resource/kind binding. Production permits only reviewed SMTP ports and
denies private destinations unless their canonical hostnames are explicitly listed.
Never add plaintext tenant credentials to this stack or its external secrets.

## External DFIR storage and scanner

Set `PERIAPSIS_S3_ENDPOINT` to the internal API/worker HTTPS endpoint and
`PERIAPSIS_S3_PUBLIC_ENDPOINT` to the browser-reachable HTTPS endpoint. They may be equal,
but both must identify the same versioned bucket. Keep private endpoint access denied by
default; if it is required, set `PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS` to the smallest exact
reviewed CIDRs and enforce the same ranges in host/firewall policy. Ambient proxies,
redirects, and credential discovery are not used by the application adapter.

Provision object-store CORS for the single canonical `PERIAPSIS_PUBLIC_URL` origin. Permit
only `GET`, `HEAD`, and `PUT`; allow `Content-Length`, `Content-Type`, `Cache-Control`,
`Content-Disposition`, `If-None-Match`, `X-Amz-Meta-Periapsis-Declared-Mime`, and
`X-Amz-Meta-Periapsis-Expected-Size`; expose `ETag`; never use a
wildcard origin/header or credentials. Enable versioning and least-privilege object
get/put/delete plus bucket location/list. The single-PUT ceremony signs the exact size and
`If-None-Match: *`, making the opaque key create-only, and
is capped at decimal `5_000_000_000` bytes. Follow the
[evidence-storage runbook](../../docs/operations/dfir-evidence-storage.md) for length,
hash, custody, retention, and fenced orphan cleanup checks.

Native clamd TCP is unencrypted, so this Swarm stack never deploys or connects to it
directly. `PERIAPSIS_DFIR_SCANNER_ENDPOINT` must be a `tls://` endpoint provided by an
operator-managed clamd TLS gateway, pinned by the mounted scanner CA bundle. Place that
gateway on a restricted backend, expose no public listener, bind concurrency/body size to
the Periapsis limit, and operate ClamAV unprivileged with a dedicated writable signature
volume. Run FreshClam at least twelve times daily; readiness must reject signatures older
than 26 hours and clamd must reject databases older than two days. Scanner, TLS, freshness,
or object-store failure keeps DFIR readiness and scan transitions fail-closed.

Prometheus uses a local Swarm volume by default. For multi-node failover select a reviewed
volume driver or remote metrics backend; a local driver is not highly available and must
not be scaled above one replica. No database or object data is stored in the stack. The
bundled collector configuration is a fail-safe example that exports metrics locally and
discards traces/logs; replace its versioned Swarm Config with the validated production
example only after provisioning the approved TLS telemetry backend and authentication.
