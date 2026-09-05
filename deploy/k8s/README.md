# Kubernetes deployment

The Kustomize base contains a restricted namespace, tokenless ServiceAccount, ConfigMap,
API/worker/notifier/web Deployments and Services, TLS Ingress, one-shot migration Job,
HPA, PDB, default-deny NetworkPolicies, explicit resources/probes, topology spread, and
preferred pod anti-affinity. Every Periapsis container runs as UID/GID 10001 with
`RuntimeDefault` seccomp, a read-only root, no privilege escalation, and all capabilities
dropped. Only bounded memory-backed `/tmp` volumes are writable.

Use Kustomize 5.7.1 or newer and validate against the supported Kubernetes schemas before
applying:

```text
kustomize build deploy/k8s/overlays/dev
kustomize build deploy/k8s/overlays/prod
```

### Development TLS

The development overlay exposes the canonical origin only as
`https://periapsis.local`. Map `periapsis.local` to the local ingress address and provision
the `periapsis-ingress-tls-dev` Secret in namespace `periapsis-dev` before applying the
Ingress. For a locally trusted certificate and private key held outside the repository:

```text
kubectl -n periapsis-dev create secret tls periapsis-ingress-tls-dev \
  --cert=/operator-owned/path/periapsis.local.crt \
  --key=/operator-owned/path/periapsis.local.key
```

Alternatively, configure cert-manager to issue for `periapsis.local` into that exact
Secret name by adding the approved `cert-manager.io/issuer` or
`cert-manager.io/cluster-issuer` annotation in a site-specific overlay. Trust the issuing
development CA in the test browser or operating system; do not bypass certificate
verification. The development Ingress retains TLS and explicitly forces HTTP-to-HTTPS
redirects, so provider redirect URLs, WebAuthn origins, cookies, and storage CORS are
exercised against the same secure-origin boundary required in production.

### Proxy trust boundary

The base ConfigMap deliberately gives both proxy trust settings invalid startup markers:

- `PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS` must be replaced with only the exact
  ingress-controller immediate-peer CIDRs seen by the web pods;
- `PERIAPSIS_TRUSTED_PROXY_CIDRS` must be replaced with only the exact web-pod
  immediate-peer CIDRs seen by the API pods.

Every cluster must replace both markers in a site-specific overlay. They cannot be filled
portably because pod and ingress-controller networks are cluster-specific. Leaving either
marker in a rendered workload makes that process reject its configuration and fail startup;
an empty value instead silently discards the original client address. Never use
`0.0.0.0/0`, `::/0`, a whole VPC, or a whole cluster network as a shortcut.

Patch the runtime ConfigMap with the reviewed comma-separated CIDR lists before applying
the overlay:

```yaml
patches:
  - target:
      kind: ConfigMap
      name: periapsis-runtime
    patch: |-
      - op: replace
        path: /data/PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS
        value: REPLACE_WITH_EXACT_INGRESS_CONTROLLER_IMMEDIATE_PEER_CIDRS
      - op: replace
        path: /data/PERIAPSIS_TRUSTED_PROXY_CIDRS
        value: REPLACE_WITH_EXACT_WEB_POD_IMMEDIATE_PEER_CIDRS
```

The values shown in that patch are also intentionally invalid placeholders. Replace them
with the cluster's actual narrow CIDRs, render the final site overlay, and verify that
neither placeholder, an empty value, nor a wildcard remains. The NetworkPolicies restrict
which workloads may reach each port, but they do not configure application-level proxy
trust.

### Shared API admission

The base ConfigMap sets one-second limits of `100` per resolved client network, `60` per
opaque credential, and `40` per bounded tenant/credential-or-network tuple. Site overlays
may replace `PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS`,
`PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS`, and
`PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS` only with integers in `1..100`. Every API pod
uses the external PostgreSQL database for one replica-independent decision and derives
stable HMAC meter identities from the shared master-key Secret. There is no in-memory
fallback: a database admission error fails ordinary requests closed. Liveness, readiness,
metrics, and documentation are exempt so Kubernetes and monitoring retain visibility.
The resolved network identity is trustworthy only after the proxy boundary above has been
replaced with the exact immediate-peer CIDRs.

The production overlay intentionally contains documentation registry/host/CIDR values.
Replace images with immutable digests, external service endpoints with reviewed values,
and the RFC 5737 NetworkPolicy ranges with the exact dependency CIDRs. In the API/worker
policy, `192.0.2.0/24` is PostgreSQL on 5432, `198.51.100.0/24` is HTTPS IdP/S3 on 443,
and `203.0.113.0/24` is LDAP STARTTLS/LDAPS on 389/636. In the notifier policy those three
ranges represent PostgreSQL, SMTP on 465/587, and HTTPS webhooks respectively. The
placeholders are non-routable so an unreviewed production render fails closed.

## Secret boundary

Create a namespace Secret named `periapsis-runtime` out-of-band. It must contain these
keys:

- `api-database-url`, `worker-database-url`, and `notifier-database-url` with independent
  least-privileged TLS URLs;
- `database-admin-url` as a complete migration URL with `sslmode=verify-full`, plus
  `api-database-password`, `worker-database-password`, and
  `notifier-database-password` for one-shot role provisioning;
- `bootstrap-token`, `master-key`, `api-credential-keyring`, and `identity-keyring`;
- `notifier-preview-token`, `s3-access-key`, `s3-secret-key`, and the reviewed PEM
  `s3-ca-bundle` and `federated-ca-bundle` trust stores used by both API and worker.

The API-credential and identity keyrings are closed documents shaped as
`{"activeVersion":1,"keys":[{"version":1,"key":"PADDED_STANDARD_BASE64_32_BYTE_ROOT"}]}`.
Their 32-byte roots use standard padded Base64, unlike the notification keyring's
unpadded Base64URL roots. Keep these keyring classes cryptographically independent.

Build `notifier-database-url` with the exact `periapsis_notifier_login` username and the
same dedicated value stored as `notifier-database-password`. Never reuse the API or
worker credential. The migration Job provisions this login before notifier rollout.

The `notifier-preview-token` key is projected read-only into both API and notifier. API
uses only its file path and the internal `http://periapsis-notifier:8083` Service URL;
paired NetworkPolicies allow API egress to notifier ingress on 8083. The notifier Service
is ClusterIP-only and is absent from Ingress. The bearer still remains mandatory because
the metrics scraper may share the HTTP port but never receives this Secret.

Create a separate Secret named `periapsis-notification-keyring` with exactly one key named
`notification-keyring`. API and notifier mount the same file read-only at
`/run/notification-secrets/notification-keyring` and receive only its path through the
literal `NOTIFICATION_KEYRING_FILE`; a missing Secret prevents pod startup and an invalid
document must keep readiness false. The closed JSON form is
`{"activeVersion":1,"keys":[{"version":1,"key":"BASE64URL_NO_PADDING_32_BYTE_ROOT"}]}`:
at most 16 unique versions from 1 through 32767, each decoding to exactly 32 bytes. Add a
new version before changing `activeVersion`; retain old versions until every database
ciphertext has been rotated. Never reuse the master, API-credential, or identity roots.

Mount sources are mode `0440` and readable only through the pod `fsGroup`. Do not use
`env.value` for secret material. `optional/external-secret.example.yaml` shows External
Secrets integration without making its CRD mandatory or embedding remote values. A native
Secret can instead be created from operator-owned files with `kubectl create secret
generic --from-file`; keep the command and source files out of shell history, Git, and CI
logs.

The identity keyring is shared by API and worker; the notification keyring and preview
bearer are each shared by API and notifier for different purposes. Preserve every
retained key version during rolling rotation. Rotate one secret class at a time and do
not delete an old version until every pod and ciphertext dependency has moved forward.

Notifier delivery and fanout worker IDs come from the pod UID, so leases stay distinct
across replicas. Tenant SMTP endpoints and encrypted credential envelopes are pinned
database configuration. No file-secret fallback is mounted: notifier decrypts the
tenant/resource/kind-bound envelope through `NOTIFICATION_KEYRING_FILE`. Production
allows only reviewed ports and denies private SMTP hosts by default.

## Ordered migration and rollout

Render the chosen overlay once so the migration and runtime use identical images and
configuration. With `yq` v4, apply the foundation/network boundary and Job before runtime:

```text
kustomize build deploy/k8s/overlays/prod > periapsis-rendered.yaml
yq eval-all 'select(.kind == "Namespace" or .kind == "ServiceAccount" or .kind == "ConfigMap" or .kind == "NetworkPolicy")' periapsis-rendered.yaml | kubectl apply --server-side -f -
yq eval-all 'select(.kind == "Job")' periapsis-rendered.yaml | kubectl apply --server-side -f -
kubectl -n periapsis wait --for=condition=complete job/periapsis-migration --timeout=30m
yq eval-all 'select(.kind != "Job")' periapsis-rendered.yaml | kubectl apply --server-side -f -
```

For a compatible upgrade, delete only the completed `periapsis-migration` Job, apply the
new rendered Job, wait for completion, and then apply the non-Job resources. When the
candidate does not explicitly publish a sealed immediate-predecessor edge, treat the
handoff as incompatible: suspend ingress and HPA/GitOps reconciliation, scale
web/API/worker/notifier to zero, set the three supported runtime database logins to
`NOLOGIN`, and verify that no matching row remains in `pg_stat_activity` before creating
the Job. The candidate's incompatible-handoff migration must enforce that gate; the
successful Job reprovisions the logins only after sealing, while failure leaves them
closed. GitOps controllers should model the same ordering with a blocking pre-sync
quiescence gate and migration Job. Never run migrations from application init containers
or every replica.

The migration Job accepts its complete administrator URL only through
`PERIAPSIS_DATABASE_ADMIN_URL_FILE` and rejects production URLs unless
`sslmode=verify-full`. Keep that URL independent from every runtime login and use a
hostname covered by the database certificate.

## Cluster integrations

- Label the ingress-controller namespace
  `networking.periapsis.io/ingress-client=true`; otherwise default-deny correctly blocks
  ingress. Set `ingressClassName`, hostname, and TLS secret for the chosen controller.
- cert-manager may own `periapsis-ingress-tls`; otherwise provision the TLS Secret through
  the cluster secret workflow. TLS terminates only at an approved ingress.
- Label the Prometheus namespace `observability.periapsis.io/scrape=true`. Install
  `optional/servicemonitor.yaml` only when the Prometheus Operator CRD exists.
- The DNS policy assumes CoreDNS pods carry `k8s-app=kube-dns`; patch it for a provider
  with different labels before enabling default-deny.
- Pod Security Admission is pinned to the validated `v1.32` restricted baseline; review
  and update that pin deliberately with the supported cluster version.
- HPA requires Metrics Server. Queue-depth external metrics are preferable for worker and
  notifier once the metric adapter is approved; CPU scaling is the safe portable base.
- PostgreSQL and S3 are external managed dependencies. Require encryption in transit,
  private connectivity where available, backups/versioning, least-privileged identities,
  and provider-side audit. Do not deploy MinIO from this production overlay.
- NetworkPolicy enforcement requires a compatible CNI. Validate actual packet flow with a
  disposable probe pod before directing traffic.

The optional manifests deliberately stay outside the base so clusters without their CRDs
can still validate and apply the canonical resources.

## DFIR storage and ClamAV sidecars

`PERIAPSIS_S3_ENDPOINT` is the internal API/worker HTTPS endpoint and
`PERIAPSIS_S3_PUBLIC_ENDPOINT` is the browser-reachable HTTPS endpoint. Configure both for
the same versioned bucket and replace their example values before rollout. The runtime
Secret supplies credentials and an optional private CA only through file mounts. If an
endpoint resolves to private space, add only its exact reviewed CIDRs to both
`PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS` and the production NetworkPolicy patch.

Configure provider-side CORS for the single `PERIAPSIS_PUBLIC_URL` origin, without
credentials or wildcard origin/headers. Permit only `GET`, `HEAD`, and `PUT`; allow
`Content-Length`, `Content-Type`, `Cache-Control`, `Content-Disposition`, `If-None-Match`, and
`X-Amz-Meta-Periapsis-Declared-Mime` and `X-Amz-Meta-Periapsis-Expected-Size`; expose only
`ETag`. The exact-size single PUT is
capped at decimal `5_000_000_000` bytes and binds `If-None-Match: *` so its opaque key
cannot be overwritten. Follow the
[evidence-storage runbook](../../docs/operations/dfir-evidence-storage.md) before enabling
uploads.

API and worker pods each include the pinned `clamav-debian` base image as an unprivileged
sidecar. The application uses `/run/clamav/clamd.sock`, backed by the sidecar's `/tmp`
volume, so unencrypted clamd TCP is loopback-only and never crosses the pod boundary.
Config and root filesystem are read-only; `clamav-signatures` is a dedicated writable
volume and `clamav-logs` is bounded memory storage. Startup/readiness require clamd and a
daily signature file no older than 26 hours; clamd independently rejects a database older
than two days. Initial signature download or update failure therefore keeps the pod
unready and scanning fails closed.

FreshClam needs DNS plus reviewed HTTPS egress to `database.clamav.net` or an approved
internal mirror/proxy. The production placeholder policy intentionally permits no real
address until operators replace it. Because NetworkPolicy applies to the whole pod, keep
the S3/IdP/update CIDR set minimal and enforce destination identity again at the TLS
gateway/firewall. Do not expose port 3310 through a Service. Monitor signature age and
update failures, and budget the sidecar's multi-GiB memory and temporary-storage limits per
API/worker replica.
