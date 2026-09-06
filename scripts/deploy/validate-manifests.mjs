import { readFile, readdir } from "node:fs/promises";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { composeSecretVariables } from "./prepare-compose-secrets.mjs";
import {
  readDevelopmentComposeSources,
  readDevelopmentCaddySources,
} from "./compose-sources.mjs";

export function validateComposeFileSecrets(contents, path = "Compose") {
  const errors = [];
  const secrets = contents.split(/^secrets:\s*\r?$/mu);
  if (secrets.length !== 2)
    return [`${path}: expected one top-level secret inventory`];
  const inventory = secrets[1].split(/^[a-z][a-z_-]*:/mu)[0];
  if (/^\s+environment:/mu.test(inventory)) {
    errors.push(
      `${path}: read-only services require file-backed Compose secrets`,
    );
  }
  for (const name of Object.keys(composeSecretVariables)) {
    const expected = `  ${name}:\n    file: \${PERIAPSIS_COMPOSE_SECRETS_DIR:?prepare an external Compose secret directory}/${name}`;
    if (
      (inventory.replaceAll("\r\n", "\n") + "\n").split(`${expected}\n`)
        .length !== 2 ||
      (inventory.match(new RegExp(`^  ${name}:`, "gmu")) ?? []).length !== 1
    ) {
      errors.push(
        `${path}: ${name} must mount its distinct prepared external file`,
      );
    }
  }
  return errors;
}

const requiredFiles = [
  "apps/web/Dockerfile",
  "deploy/compose/compose.yaml",
  "deploy/compose/compose.base.yaml",
  "deploy/compose/compose.tls.yaml",
  "deploy/compose/compose.reverse-proxy.yaml",
  "deploy/compose/reverse-proxy.override.yaml",
  "deploy/compose/edge/Caddyfile.reverse-proxy",
  "deploy/compose/edge/storage-cors.caddy",
  "deploy/compose/edge/reverse-proxy-entrypoint.sh",
  "deploy/compose/database-task.mjs",
  "deploy/compose/database-task-config.mjs",
  "deploy/compose/Dockerfile.database",
  "deploy/compose/Dockerfile.keycloak",
  "deploy/compose/Dockerfile.ldap-tls",
  "deploy/compose/Dockerfile.openldap-test",
  "deploy/compose/Dockerfile.minio",
  "deploy/compose/Dockerfile.minio-provision",
  "deploy/compose/edge/Caddyfile",
  "deploy/compose/auth/openldap-empty-entries.ldif",
  "deploy/compose/auth/openldap-bootstrap.sh",
  "deploy/compose/auth/openldap-config.ldif",
  "deploy/compose/auth/openldap-database.ldif",
  "deploy/compose/auth/openldap-tree.ldif",
  "deploy/compose/auth/generate-openldap-tls.sh",
  "deploy/compose/clamav/clamd.conf",
  "deploy/compose/clamav/freshclam.conf",
  "deploy/compose/storage/provision-minio.sh",
  "deploy/images/Dockerfile.api",
  "deploy/images/Dockerfile.notifier",
  "deploy/images/Dockerfile.worker",
  "services/api/Dockerfile",
  "services/worker/Dockerfile",
  "deploy/swarm/stack.yml",
  "deploy/k8s/base/kustomization.yaml",
  "deploy/k8s/base/clamav-config.yaml",
  "deploy/k8s/overlays/dev/kustomization.yaml",
  "deploy/k8s/overlays/prod/kustomization.yaml",
  "deploy/k8s/README.md",
  "deploy/observability/otel-collector.yaml",
  "deploy/observability/prometheus.yaml",
  "deploy/observability/alert-rules.yaml",
  "deploy/observability/grafana-dashboard.json",
  "docs/operations/backup-restore.md",
  "docs/operations/dfir-evidence-storage.md",
  "docs/operations/migration-bootstrap-upgrade.md",
];

const workerLDAPVariables = [
  "PERIAPSIS_LDAP_PRIVATE_EGRESS_CIDRS",
  "PERIAPSIS_LDAP_STARTTLS_PORTS",
  "PERIAPSIS_LDAP_LDAPS_PORTS",
  "PERIAPSIS_LDAP_MAX_CONCURRENT",
  "PERIAPSIS_LDAP_SYNC_ABSENCE_BATCH_SIZE",
  "PERIAPSIS_LDAP_SYNC_LEASE",
  "PERIAPSIS_LDAP_SYNC_MIN_BACKOFF",
  "PERIAPSIS_LDAP_SYNC_MAX_BACKOFF",
  "PERIAPSIS_LDAP_SYNC_OPERATION_TIMEOUT",
  "PERIAPSIS_LDAP_SYNC_PARALLELISM",
];

const workerSLAVariables = [
  "PERIAPSIS_SLA_BATCH_SIZE",
  "PERIAPSIS_SLA_LEASE_DURATION",
  "PERIAPSIS_SLA_MAXIMUM_ATTEMPTS",
  "PERIAPSIS_SLA_OPERATION_TIMEOUT",
  "PERIAPSIS_SLA_POLL_INTERVAL",
  "PERIAPSIS_SLA_RETRY_BASE_DELAY",
  "PERIAPSIS_SLA_RETRY_MAXIMUM_DELAY",
  "PERIAPSIS_SLA_RUN_TIMEOUT",
  "PERIAPSIS_SLA_ACTION_BATCH_SIZE",
  "PERIAPSIS_SLA_ACTION_LEASE_DURATION",
  "PERIAPSIS_SLA_ACTION_LEASE_SAFETY",
  "PERIAPSIS_SLA_ACTION_OPERATION_TIMEOUT",
  "PERIAPSIS_SLA_ACTION_POLL_INTERVAL",
  "PERIAPSIS_SLA_ACTION_QUEUE_LIMIT",
  "PERIAPSIS_SLA_ACTION_RUN_TIMEOUT",
];

const workerTicketExportReconciliationVariables = [
  "PERIAPSIS_TICKET_EXPORT_RECONCILE_BATCH_SIZE",
  "PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_DURATION",
  "PERIAPSIS_TICKET_EXPORT_RECONCILE_LEASE_SAFETY",
  "PERIAPSIS_TICKET_EXPORT_RECONCILE_MAXIMUM_ATTEMPTS",
  "PERIAPSIS_TICKET_EXPORT_RECONCILE_OPERATION_TIMEOUT",
  "PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_BASE_DELAY",
  "PERIAPSIS_TICKET_EXPORT_RECONCILE_RETRY_MAXIMUM_DELAY",
];

const federatedEgressVariables = [
  "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE",
  "PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS",
  "PERIAPSIS_FEDERATED_HTTPS_PORTS",
  "PERIAPSIS_FEDERATED_MAX_CONCURRENT",
  "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW",
  "PERIAPSIS_FEDERATED_OPERATION_TIMEOUT",
];

const federatedOIDCClockSkewDefaults = new Map([
  [".env.example", "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=1m"],
  [
    "deploy/compose/compose.yaml",
    "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: ${PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW:-1m}",
  ],
  ["deploy/compose/.env.example", "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=1m"],
  [
    "deploy/swarm/stack.yml",
    "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: ${PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW:-1m}",
  ],
  ["deploy/swarm/.env.example", "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=1m"],
  [
    "deploy/k8s/base/config-map.yaml",
    "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: 1m",
  ],
]);

const notifierRuntimeVariables = [
  "PERIAPSIS_LOG_LEVEL",
  "PERIAPSIS_NOTIFIER_BATCH_SIZE",
  "PERIAPSIS_NOTIFIER_BUSY_POLL_MS",
  "PERIAPSIS_NOTIFIER_CONCURRENCY",
  "PERIAPSIS_NOTIFIER_DELIVERY_TIMEOUT_MS",
  "PERIAPSIS_NOTIFIER_FAILURE_POLL_MS",
  "PERIAPSIS_NOTIFIER_FANOUT_BATCH_SIZE",
  "PERIAPSIS_NOTIFIER_FANOUT_CONCURRENCY",
  "PERIAPSIS_NOTIFIER_FANOUT_HEARTBEAT_MS",
  "PERIAPSIS_NOTIFIER_FANOUT_INITIAL_RETRY_MS",
  "PERIAPSIS_NOTIFIER_FANOUT_LEASE_MS",
  "PERIAPSIS_NOTIFIER_FANOUT_MAX_RETRY_MS",
  "PERIAPSIS_NOTIFIER_FANOUT_TIMEOUT_MS",
  "PERIAPSIS_NOTIFIER_HEARTBEAT_MS",
  "PERIAPSIS_NOTIFIER_IDLE_POLL_MS",
  "PERIAPSIS_NOTIFIER_LEASE_MS",
  "PERIAPSIS_NOTIFIER_MAX_OUTPUT_BYTES",
  "PERIAPSIS_NOTIFIER_READINESS_TIMEOUT_MS",
  "PERIAPSIS_NOTIFIER_RENDER_TIMEOUT_MS",
];

const dfirRuntimeVariables = [
  "PERIAPSIS_DFIR_MAX_OBJECT_BYTES",
  "PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS",
  "PERIAPSIS_DFIR_SCANNER_ENDPOINT",
  "PERIAPSIS_DFIR_SCANNER_TIMEOUT",
  "PERIAPSIS_S3_BUCKET",
  "PERIAPSIS_S3_ENDPOINT",
  "PERIAPSIS_S3_MAX_CONCURRENT",
  "PERIAPSIS_S3_PUBLIC_ENDPOINT",
  "PERIAPSIS_S3_REGION",
];

const workloadSecurityMarkers = [
  "automountServiceAccountToken: false",
  "runAsNonRoot: true",
  "runAsUser: 10001",
  "runAsGroup: 10001",
  "type: RuntimeDefault",
  "allowPrivilegeEscalation: false",
  "readOnlyRootFilesystem: true",
  "capabilities:",
  "- ALL",
  "resources:",
];

const kubernetesProxyTrustMarkers = [
  [
    "PERIAPSIS_TRUSTED_PROXY_CIDRS",
    "REPLACE_WITH_WEB_POD_IMMEDIATE_PEER_CIDRS",
  ],
  [
    "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS",
    "REPLACE_WITH_INGRESS_CONTROLLER_IMMEDIATE_PEER_CIDRS",
  ],
];

export function validateActionPins(contents, path = "workflow") {
  const errors = [];
  for (const [index, line] of contents.split(/\r?\n/u).entries()) {
    const match = line.match(
      /^\s*-?\s*uses:\s*(?:(["'])([^"']+)\1|([^\s#]+))\s*(?:#.*)?$/u,
    );
    const reference = match?.[2] ?? match?.[3];
    if (reference === undefined || reference.startsWith("./")) {
      continue;
    }
    if (!/@[0-9a-f]{40}$/u.test(reference)) {
      errors.push(
        `${path}:${index + 1}: action reference is not pinned to a full commit SHA`,
      );
    }
  }
  return errors;
}

export function validateMultiarchRuntimeWorkflow(
  contents,
  path = ".github/workflows/deployment-security.yml",
) {
  return requireMarkers(contents, path, [
    "platforms: arm64",
    "--platform linux/amd64,linux/arm64",
    "--load --platform linux/arm64",
    '--platform "linux/${architecture}" --read-only --cap-drop ALL',
    "docker image inspect --format '{{.Config.User}}' \"${image}\"",
    "for manager in apk corepack npm npx pnpm pnpx yarn yarnpkg",
    'test ! -e "${path}"',
    "test -s /lib/apk/db/installed",
    "observed_uid=%s read_only=true package_managers_absent=true package_inventory_present=true",
    "${{ matrix.name }}.runtime.txt",
  ]);
}

export function validateInlineSecrets(contents, path = "manifest") {
  const errors = [];
  const forbiddenPrivateKey = /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u;
  if (forbiddenPrivateKey.test(contents)) {
    errors.push(`${path}: contains private key material`);
  }

  for (const [index, line] of contents.split(/\r?\n/u).entries()) {
    const match = line.match(
      /^\s*["']?(?:(?:[A-Z0-9_.-]+_)?(?:PASSWORD|TOKEN|KEYRING|API_KEY)|password|passwd|userPassword|clientSecret|secret|apiKey)["']?\s*:\s*(.+?)\s*,?\s*$/iu,
    );
    if (match === null) {
      continue;
    }
    let value = match[1].trim();
    if (
      value.length >= 2 &&
      ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'")))
    ) {
      value = value.slice(1, -1).trim();
    }
    if (
      value === "" ||
      value.startsWith("${") ||
      value.startsWith("/run/secrets/")
    ) {
      continue;
    }
    errors.push(`${path}:${index + 1}: possible inline secret value`);
  }
  return errors;
}

export function validateDFIRStorageCORS(contents, path = "local storage CORS") {
  const storage = contents.slice(contents.indexOf("(periapsis_storage_cors)"));
  const errors = requireMarkers(storage, path, [
    "@preflight {",
    "method OPTIONS",
    "path /periapsis-evidence/*",
    "header Origin {args[0]}",
    "header Access-Control-Request-Method GET",
    "header Access-Control-Request-Method HEAD",
    "header Access-Control-Request-Method PUT",
    'respond "" 204',
    "respond @options 403",
    "respond @foreign_origin 403",
    "respond @browser_method_denied 403",
    "respond @browser_path_denied 403",
    '+Vary "Origin, Access-Control-Request-Method, Access-Control-Request-Headers"',
    "header_down -Access-Control-*",
  ]);
  const expected = new Map([
    ["Access-Control-Allow-Origin", "{args[0]}"],
    ["Access-Control-Allow-Methods", '"GET, HEAD, PUT"'],
    [
      "Access-Control-Allow-Headers",
      '"Cache-Control, Content-Disposition, Content-Length, Content-Type, If-None-Match, X-Amz-Meta-Periapsis-Declared-Mime, X-Amz-Meta-Periapsis-Expected-Size"',
    ],
    ["Access-Control-Expose-Headers", "ETag"],
    ["Access-Control-Max-Age", "300"],
  ]);
  const counts = new Map();
  for (const [, name, value] of storage.matchAll(
    /^\s*(Access-Control-[\w-]+)\s+([^\r\n]+)$/gmu,
  )) {
    counts.set(name, (counts.get(name) ?? 0) + 1);
    if (expected.get(name) !== value.trim()) {
      errors.push(`${path}: unexpected CORS header or value: ${name}`);
    }
  }
  for (const name of expected.keys()) {
    if (counts.get(name) !== (name === "Access-Control-Allow-Origin" ? 2 : 1)) {
      errors.push(`${path}: missing or duplicate CORS header: ${name}`);
    }
  }
  return errors;
}

export function validateWorkloadSecurity(
  contents,
  path = "workload",
  { probes = true } = {},
) {
  const errors = [];
  for (const marker of workloadSecurityMarkers) {
    if (!contents.includes(marker)) {
      errors.push(`${path}: missing security marker ${JSON.stringify(marker)}`);
    }
  }
  if (probes) {
    for (const probe of [
      "startupProbe:",
      "livenessProbe:",
      "readinessProbe:",
    ]) {
      if (!contents.includes(probe)) {
        errors.push(`${path}: missing ${probe.slice(0, -1)}`);
      }
    }
  }
  return errors;
}

export function validateProductionImagePins(
  contents,
  path = "production overlay",
) {
  const errors = [];
  if (/^\s*newTag:/mu.test(contents)) {
    errors.push(`${path}: production image uses a mutable tag`);
  }
  const digests = [
    ...contents.matchAll(/^\s*digest:\s*([^\s#]+)\s*(?:#.*)?$/gmu),
  ];
  if (digests.length !== 5) {
    errors.push(`${path}: expected exactly five application image digests`);
  }
  for (const match of digests) {
    if (!/^sha256:[0-9a-f]{64}$/u.test(match[1])) {
      errors.push(`${path}: production image digest is malformed`);
    }
  }
  return errors;
}

export function validateKubernetesDevelopmentTLS(
  contents,
  path = "deploy/k8s/overlays/dev/kustomization.yaml",
) {
  const normalized = contents.replaceAll("\r\n", "\n");
  const errors = requireMarkers(normalized, path, [
    "path: /data/PERIAPSIS_PUBLIC_URL\n        value: https://periapsis.local",
    'path: /metadata/annotations/nginx.ingress.kubernetes.io~1ssl-redirect\n        value: "true"',
    'path: /metadata/annotations/nginx.ingress.kubernetes.io~1force-ssl-redirect\n        value: "true"',
    "path: /spec/rules/0/host\n        value: periapsis.local",
    "path: /spec/tls/0/hosts/0\n        value: periapsis.local",
    "path: /spec/tls/0/secretName\n        value: periapsis-ingress-tls-dev",
  ]);
  if (/- op:\s*remove\s*\r?\n\s*path:\s*\/spec\/tls(?:\s|$)/mu.test(contents)) {
    errors.push(`${path}: development Ingress removes TLS`);
  }
  if (/value:\s*http:\/\/periapsis\.local(?:\s|$)/mu.test(contents)) {
    errors.push(`${path}: development public origin permits plaintext HTTP`);
  }
  return errors;
}

function normalizeYamlScalar(rawValue) {
  const trimmed = rawValue.trim();
  return trimmed.length >= 2 &&
    ((trimmed.startsWith('"') && trimmed.endsWith('"')) ||
      (trimmed.startsWith("'") && trimmed.endsWith("'")))
    ? trimmed.slice(1, -1).trim()
    : trimmed;
}

function isWildcardProxyTrustValue(value) {
  return value
    .split(",")
    .map((part) => part.trim())
    .some((cidr) => cidr === "*" || /\/0+$/u.test(cidr));
}

export function validateKubernetesProxyTrustConfiguration(
  contents,
  path = "deploy/k8s/base/config-map.yaml",
) {
  const errors = [];
  for (const [key, failClosedMarker] of kubernetesProxyTrustMarkers) {
    const escapedKey = escapeRegularExpression(key);
    const matches = [
      ...contents.matchAll(
        new RegExp(`^\\s*${escapedKey}:\\s*([^#\\r\\n]*?)(?:\\s+#.*)?$`, "gmu"),
      ),
    ];
    if (matches.length !== 1) {
      errors.push(`${path}: expected exactly one ${key} proxy trust setting`);
      continue;
    }
    const value = normalizeYamlScalar(matches[0]?.[1] ?? "");
    if (value === "") {
      errors.push(`${path}: ${key} must not be empty when Ingress is enabled`);
      continue;
    }
    if (isWildcardProxyTrustValue(value)) {
      errors.push(`${path}: ${key} must not trust a wildcard CIDR`);
    }
    if (value !== failClosedMarker) {
      errors.push(
        `${path}: ${key} must retain fail-closed marker ${failClosedMarker} until a site-specific overlay replaces it`,
      );
    }
  }
  return errors;
}

export function validateKubernetesProxyTrustOverrides(
  contents,
  path = "Kubernetes overlay",
) {
  const normalized = contents.replaceAll("\r\n", "\n");
  const errors = [];
  const operationBlocks = normalized.split(/(?=^\s*-\s+op:)/mu);
  const overriddenKeys = new Set();
  for (const [key] of kubernetesProxyTrustMarkers) {
    const keyPath = `/data/${key}`;
    const matchingBlocks = operationBlocks.filter((block) =>
      [...block.matchAll(/^\s*path:\s*([^#\n]*?)\s*$/gmu)].some(
        (match) => normalizeYamlScalar(match[1] ?? "") === keyPath,
      ),
    );
    if (matchingBlocks.length > 1) {
      errors.push(`${path}: ${key} must have at most one overlay operation`);
    }
    if (matchingBlocks.length > 0) {
      overriddenKeys.add(key);
    }
    for (const block of matchingBlocks) {
      const operations = [...block.matchAll(/^\s*-\s+op:\s*([^\s#]+)\s*$/gmu)];
      const paths = [...block.matchAll(/^\s*path:\s*([^#\n]*?)\s*$/gmu)];
      if (operations.length !== 1 || paths.length !== 1) {
        errors.push(
          `${path}: ${key} overlay operation must contain one op and one path`,
        );
        continue;
      }
      const operation = normalizeYamlScalar(operations[0]?.[1] ?? "");
      if (operation !== "add" && operation !== "replace") {
        errors.push(
          `${path}: ${key} must not be removed from an Ingress deployment`,
        );
        continue;
      }
      const values = [
        ...block.matchAll(/^\s*value:\s*([^#\n]*?)(?:\s+#.*)?$/gmu),
      ];
      if (values.length !== 1) {
        errors.push(`${path}: ${key} overlay operation must provide one value`);
        continue;
      }
      const value = normalizeYamlScalar(values[0]?.[1] ?? "");
      if (value === "" || value === "null" || value === "~") {
        errors.push(
          `${path}: ${key} must not be empty when Ingress is enabled`,
        );
        continue;
      }
      if (isWildcardProxyTrustValue(value)) {
        errors.push(`${path}: ${key} must not trust a wildcard CIDR`);
      }
    }
  }
  if (
    [...normalized.matchAll(/^\s*path:\s*([^#\n]*?)\s*$/gmu)].some(
      (match) => normalizeYamlScalar(match[1] ?? "") === "/data",
    )
  ) {
    errors.push(
      `${path}: whole ConfigMap data replacement bypasses proxy trust validation`,
    );
  }
  if (overriddenKeys.size === 1) {
    errors.push(
      `${path}: a site overlay must override both proxy boundaries together`,
    );
  }
  return errors;
}

export function validateComposeDevelopmentTLS(
  compose,
  caddyfile,
  composePath = "deploy/compose/compose.yaml",
  caddyfilePath = "deploy/compose/edge/Caddyfile",
) {
  const publicStorageEndpoint =
    "PERIAPSIS_S3_PUBLIC_ENDPOINT: https://storage.localhost:${PERIAPSIS_MINIO_API_PORT:-19000}";
  const edge = composeServiceBlock(compose, "edge");
  const errors = [
    ...requireMarkers(compose, composePath, [
      "  edge:",
      "PERIAPSIS_PUBLIC_URL: https://localhost:${PERIAPSIS_WEB_PORT:-8443}",
      publicStorageEndpoint,
      "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE: /run/secrets/periapsis-dev-tls-ca.crt",
      "PERIAPSIS_FEDERATED_HTTPS_PORTS: ${PERIAPSIS_FEDERATED_HTTPS_PORTS:-443,18090}",
      "file: ${PERIAPSIS_DEV_TLS_CERT_FILE:?set PERIAPSIS_DEV_TLS_CERT_FILE to an external PEM certificate path}",
      "file: ${PERIAPSIS_DEV_TLS_KEY_FILE:?set PERIAPSIS_DEV_TLS_KEY_FILE to an external PEM private-key path}",
      "file: ${PERIAPSIS_DEV_TLS_CA_FILE:?set PERIAPSIS_DEV_TLS_CA_FILE to an external PEM CA path}",
    ]),
    ...requireMarkers(edge, `${composePath} edge service`, [
      "<<: *application-security",
      "image: caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648",
      "./edge/Caddyfile:/etc/caddy/Caddyfile:ro",
      "./edge/storage-cors.caddy:/etc/caddy/storage-cors.caddy:ro",
      "source: dev_tls_certificate",
      "target: periapsis-dev-tls.crt",
      "source: dev_tls_private_key",
      "target: periapsis-dev-tls.key",
      "source: dev_tls_ca",
      "target: periapsis-dev-tls-ca.crt",
      "/tmp:uid=10001,gid=10001,mode=1770",
      "/data:uid=10001,gid=10001,mode=0700",
      "/config:uid=10001,gid=10001,mode=0700",
      "127.0.0.1:${PERIAPSIS_WEB_PORT:-8443}:${PERIAPSIS_WEB_PORT:-8443}",
      "127.0.0.1:${PERIAPSIS_IDP_PORT:-18090}:${PERIAPSIS_IDP_PORT:-18090}",
      "127.0.0.1:${PERIAPSIS_MINIO_API_PORT:-19000}:${PERIAPSIS_MINIO_API_PORT:-19000}",
      "curl --fail --silent --show-error --max-time 2 --cacert /run/secrets/periapsis-dev-tls-ca.crt",
    ]),
    ...requireMarkerCount(compose, composePath, publicStorageEndpoint, 2),
    ...requireMarkers(caddyfile, caddyfilePath, [
      "auto_https off",
      "tls /run/secrets/periapsis-dev-tls.crt /run/secrets/periapsis-dev-tls.key",
      "protocols tls1.2 tls1.3",
      "https://localhost:{$PERIAPSIS_WEB_PORT:8443}",
      "reverse_proxy http://web:8081",
      "https://idp.localhost:{$PERIAPSIS_IDP_PORT:18090}",
      "reverse_proxy http://identity-provider:8080",
      "https://storage.localhost:{$PERIAPSIS_MINIO_API_PORT:19000}",
      "reverse_proxy http://minio:9000",
      "import /etc/caddy/storage-cors.caddy",
      "import periapsis_storage_cors https://localhost:{$PERIAPSIS_WEB_PORT:8443}",
    ]),
  ];
  if (
    /PERIAPSIS_(?:PUBLIC_URL|S3_PUBLIC_ENDPOINT):\s*http:\/\//mu.test(compose)
  ) {
    errors.push(`${composePath}: a browser-facing development URL uses HTTP`);
  }
  for (const [service, targetPort] of [
    ["web", "8081"],
    ["identity-provider", "8080"],
    ["minio", "9000"],
  ]) {
    const serviceBlock = composeServiceBlock(compose, service);
    if (
      new RegExp(`^\\s*-\\s+[^\\r\\n]+:${targetPort}\\s*$`, "mu").test(
        serviceBlock,
      )
    ) {
      errors.push(
        `${composePath}: ${service} publishes backend port ${targetPort} around the development TLS edge`,
      );
    }
  }
  if (/^\s*tls\s+internal\s*$/mu.test(caddyfile)) {
    errors.push(
      `${caddyfilePath}: development TLS must use operator-owned certificate files`,
    );
  }
  return errors;
}

export function validateApplicationShutdownBudget(
  contents,
  path = "deployment manifest",
) {
  const normalized = contents.replaceAll("\r\n", "\n");
  const lines = normalized.split("\n");
  const start = lines.findIndex(
    (line) => line.trim() === "x-application-security: &application-security",
  );
  if (start < 0) {
    return [`${path}: application security anchor is missing`];
  }
  let end = lines.length;
  for (let index = start + 1; index < lines.length; index += 1) {
    const line = lines[index];
    if (line !== "" && !/^\s/u.test(line) && !/^\s*#/u.test(line)) {
      end = index;
      break;
    }
  }
  const block = lines.slice(start + 1, end);
  return block.some((line) => /^\s+stop_grace_period:\s+30s\s*$/u.test(line))
    ? []
    : [`${path}: application stop_grace_period must be 30s`];
}

export function validateCredentialReferenceIsolation(
  references,
  path = "database credentials",
) {
  const errors = [];
  const ownersByReference = new Map();
  for (const [owner, reference] of references) {
    const priorOwner = ownersByReference.get(reference);
    if (priorOwner !== undefined) {
      errors.push(
        `${path}: ${owner} reuses the credential reference owned by ${priorOwner}`,
      );
    } else {
      ownersByReference.set(reference, owner);
    }
  }
  return errors;
}

export function validateDockerfileBasePins(contents, path = "Dockerfile") {
  const errors = [];
  const pinnedArguments = new Set();
  for (const [index, line] of contents.split(/\r?\n/u).entries()) {
    const argument = line.match(/^ARG\s+([A-Z0-9_]+_IMAGE)=(\S+)\s*$/u);
    if (argument !== null) {
      if (!/@sha256:[0-9a-f]{64}$/u.test(argument[2])) {
        errors.push(`${path}:${index + 1}: base image argument is not pinned`);
      } else {
        pinnedArguments.add(argument[1]);
      }
      continue;
    }

    const stage = line.match(/^FROM(?:\s+--platform=\S+)?\s+(\S+)/u);
    const reference = stage?.[1];
    if (reference === undefined || reference === "scratch") {
      continue;
    }
    const argumentReference = reference.match(/^\$\{([A-Z0-9_]+)\}$/u);
    if (argumentReference !== null) {
      if (!pinnedArguments.has(argumentReference[1])) {
        errors.push(
          `${path}:${index + 1}: base image argument is undefined or unpinned`,
        );
      }
    } else if (!/@sha256:[0-9a-f]{64}$/u.test(reference)) {
      errors.push(`${path}:${index + 1}: base image is not pinned`);
    }
  }
  return errors;
}

export function validateGoPackagingDockerfile(
  contents,
  service,
  path = `Dockerfile.${service}`,
) {
  const moduleCopies =
    service === "api"
      ? [
          "contacts",
          "customfields",
          "dfir",
          "identity",
          "sla",
          "ticketing",
        ].map(
          (module) => `COPY modules/${module}/ /workspace/modules/${module}/`,
        )
      : ["COPY modules/ /workspace/modules/"];
  return requireMarkers(contents, path, [
    "ARG TARGETARCH",
    "ARG TARGETOS",
    "CGO_ENABLED=0",
    ...moduleCopies,
    `COPY services/${service}/go.mod services/${service}/go.sum ./`,
    `COPY services/${service}/ ./`,
    "FROM scratch",
    "USER 10001:10001",
    "STOPSIGNAL SIGTERM",
    "HEALTHCHECK",
  ]);
}

export function validateNotifierPackagingDockerfile(
  contents,
  path = "Dockerfile.notifier",
) {
  return requireMarkers(contents, path, [
    "ARG NODE_IMAGE=node:24.20.0-alpine3.23@sha256:",
    "ENV CI=true",
    "COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./",
    "COPY services/notifier/package.json services/notifier/package.json",
    "COPY packages/tsconfig/package.json packages/tsconfig/package.json",
    "corepack pnpm install --frozen-lockfile --filter @periapsis/notifier...",
    "corepack pnpm --filter @periapsis/notifier build",
    "corepack pnpm --filter @periapsis/notifier deploy --legacy --prod /out",
    "test -f /out/dist/main.js",
    "COPY --from=build --chown=10001:10001 /out/node_modules ./node_modules",
    "COPY --from=build --chown=10001:10001 /out/dist ./dist",
    "USER 10001:10001",
    "HEALTHCHECK",
    'ENTRYPOINT ["node", "dist/main.js"]',
  ]);
}

export function validateDatabaseTaskPackaging(contents, path) {
  const errors = requireMarkers(contents, path, [
    "corepack pnpm --filter @periapsis/db build:runtime",
    "corepack pnpm --filter @periapsis/db deploy --legacy --prod --config.hoist-workspace-packages=false /out",
    "test -f packages/db/dist/src/admin/migrate.js",
    "test -f packages/db/dist/seeds/seed.js",
    "COPY --from=build --chown=10001:10001 /out/node_modules /workspace/packages/db/node_modules",
    "COPY --from=build --chown=10001:10001 /workspace/packages/db/dist/ /workspace/packages/db/",
    "COPY --from=build --chown=10001:10001 /workspace/packages/db/migrations/ /workspace/packages/db/migrations/",
    "COPY --from=build --chown=10001:10001 /workspace/packages/db/seeds/sla-fixture.generated.json /workspace/packages/db/seeds/sla-fixture.generated.json",
  ]);
  const finalStage = contents.slice(contents.lastIndexOf("\nFROM "));
  if (/^COPY\b.*\s(?:\/workspace|\/out)\/?\s+\S+$/gmu.test(finalStage)) {
    errors.push(`${path}: the final image must not copy the build workspace`);
  }
  return errors;
}

export function validateNodeRuntimePackageManagers(contents, path) {
  const stages = [...contents.matchAll(/^FROM\b.*$/gmu)];
  const finalStageStart = stages.at(-1)?.index;
  if (finalStageStart === undefined) {
    return [`${path}: final runtime stage is missing`];
  }

  const finalStage = contents.slice(finalStageStart);
  const removalMarkers = [
    "/usr/local/lib/node_modules/corepack",
    "/usr/local/lib/node_modules/npm",
    "/usr/local/bin/corepack",
    "/usr/local/bin/npm",
    "/usr/local/bin/npx",
    "/usr/local/bin/pnpm",
    "/usr/local/bin/pnpx",
    "/usr/local/bin/yarn",
    "/usr/local/bin/yarnpkg",
    "/etc/apk",
    "/var/cache/apk",
    "/sbin/apk",
    "/usr/bin/apk",
  ];
  const errors = requireMarkers(finalStage, `${path} final stage`, [
    "rm -rf /usr/local/lib/node_modules/corepack /usr/local/lib/node_modules/npm",
    "/etc/apk /var/cache/apk",
    "rm -f /usr/local/bin/corepack /usr/local/bin/npm /usr/local/bin/npx",
    "/usr/local/bin/pnpm /usr/local/bin/pnpx /usr/local/bin/yarn /usr/local/bin/yarnpkg",
    "/sbin/apk /usr/bin/apk",
  ]);
  if (finalStage.includes("/lib/apk")) {
    errors.push(
      `${path}: Alpine's installed-package inventory must remain available to scanners`,
    );
  }
  const removalPositions = removalMarkers.map((marker) =>
    finalStage.lastIndexOf(marker),
  );
  if (removalPositions.some((position) => position < 0)) {
    return errors;
  }

  const finalRemovalPosition = Math.max(...removalPositions);
  const finalRuntimeCopyPosition = finalStage.lastIndexOf("COPY --from=");
  if (finalRemovalPosition <= finalRuntimeCopyPosition) {
    errors.push(
      `${path}: package managers must be removed after the final runtime copy`,
    );
  }
  const runtimeUserPosition = finalStage.indexOf("USER 10001:10001");
  if (runtimeUserPosition < 0 || finalRemovalPosition >= runtimeUserPosition) {
    errors.push(
      `${path}: package managers must be removed before the non-root runtime user`,
    );
  }
  if (
    /\b(?:apk|corepack|npm|npx|pnpm|pnpx|yarn|yarnpkg)\b/u.test(
      finalStage.slice(finalRemovalPosition + "/usr/bin/apk".length),
    )
  ) {
    errors.push(`${path}: package manager use remains after runtime cleanup`);
  }
  return errors;
}

async function listFiles(root, directory) {
  const absolute = join(root, directory);
  const entries = await readdir(absolute, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const child = join(absolute, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await listFiles(root, relative(root, child))));
    } else if (entry.isFile()) {
      files.push(relative(root, child).replaceAll("\\", "/"));
    }
  }
  return files;
}

async function load(root, path) {
  if (path === "deploy/compose/compose.yaml")
    return readDevelopmentComposeSources(root);
  if (path === "deploy/compose/edge/Caddyfile")
    return readDevelopmentCaddySources(root);
  return readFile(join(root, path), "utf8");
}

function composeServiceBlock(contents, service) {
  const normalized = contents.replaceAll("\r\n", "\n");
  const marker = `  ${service}:\n`;
  const start = normalized.indexOf(marker);
  if (start < 0) {
    return "";
  }
  const bodyStart = start + marker.length;
  const nextService = normalized.slice(bodyStart).search(/^  [\w-]+:\s*$/mu);
  return nextService < 0
    ? normalized.slice(bodyStart)
    : normalized.slice(bodyStart, bodyStart + nextService);
}

function requireMarkers(contents, path, markers) {
  return markers
    .filter((marker) => !contents.includes(marker))
    .map(
      (marker) => `${path}: missing required marker ${JSON.stringify(marker)}`,
    );
}

function requireMarkerCount(contents, path, marker, expected) {
  const actual = contents.split(marker).length - 1;
  return actual === expected
    ? []
    : [
        `${path}: expected ${String(expected)} occurrences of ${JSON.stringify(marker)}, found ${String(actual)}`,
      ];
}

function requireTrimmedLineCount(contents, path, line, expected) {
  const actual = contents
    .split(/\r?\n/u)
    .filter((candidate) => candidate.trim() === line).length;
  return actual === expected
    ? []
    : [
        `${path}: expected ${String(expected)} exact lines ${JSON.stringify(line)}, found ${String(actual)}`,
      ];
}

function escapeRegularExpression(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function requireYamlKeyCount(contents, path, key, expected) {
  const escapedKey = escapeRegularExpression(key);
  const actual = (
    contents.match(new RegExp(`^\\s*${escapedKey}:`, "gmu")) ?? []
  ).length;
  return actual === expected
    ? []
    : [
        `${path}: expected ${String(expected)} YAML mappings for ${JSON.stringify(key)}, found ${String(actual)}`,
      ];
}

function requireConfigurationKeyCount(contents, path, key, expected) {
  const escapedKey = escapeRegularExpression(key);
  const keyPattern =
    path.endsWith(".yaml") || path.endsWith(".yml")
      ? `(?:${escapedKey}|"${escapedKey}"|'${escapedKey}')\\s*:`
      : `(?:export\\s+)?${escapedKey}\\s*=`;
  const actual = (contents.match(new RegExp(`^\\s*${keyPattern}`, "gmu")) ?? [])
    .length;
  return actual === expected
    ? []
    : [
        `${path}: expected ${String(expected)} configuration assignments for ${JSON.stringify(key)}, found ${String(actual)}`,
      ];
}

export function validateFederatedOIDCClockSkewDefault(contents, path) {
  const expectedLine = federatedOIDCClockSkewDefaults.get(path);
  if (expectedLine === undefined) {
    return [`${path}: no federated OIDC clock-skew default is defined`];
  }
  const key = "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW";
  return [
    ...requireTrimmedLineCount(contents, path, expectedLine, 1),
    ...requireConfigurationKeyCount(contents, path, key, 1),
  ];
}

export function validateSLAObservability(alertRules, dashboard) {
  const metricFamilies = [
    "periapsis_sla_queue_oldest_pending_seconds",
    "periapsis_sla_queue_pending_jobs",
    "periapsis_worker_sla_ready",
    "periapsis_sla_worker_runs_total",
    "periapsis_sla_worker_jobs_total",
    "periapsis_sla_action_queue_oldest_pending_seconds",
    "periapsis_sla_action_queue_pending_actions",
    "periapsis_worker_sla_action_ready",
    "periapsis_sla_action_worker_runs_total",
    "periapsis_sla_action_worker_actions_total",
    "periapsis_worker_sla_event_ingress_ready",
    "periapsis_sla_event_ingress_worker_runs_total",
    "periapsis_sla_event_ingress_worker_events_total",
    "periapsis_sla_event_ingress_queue_pending_events",
    "periapsis_sla_event_ingress_queue_reclaimable_events",
    "periapsis_sla_event_ingress_queue_dead_lettered_events",
    "periapsis_sla_event_ingress_queue_oldest_pending_seconds",
    "periapsis_worker_ticket_runtime_ready",
    "periapsis_ticket_bulk_worker_runs_total",
    "periapsis_ticket_export_worker_runs_total",
    "periapsis_ticket_export_reconcile_worker_runs_total",
    "periapsis_ticket_export_reconcile_artifacts_total",
    "periapsis_ticket_export_reconcile_queue_pending_eligible",
    "periapsis_ticket_export_reconcile_queue_reclaimable",
    "periapsis_ticket_export_reconcile_queue_dead_lettered",
    "periapsis_ticket_export_reconcile_queue_oldest_pending_seconds",
    "periapsis_worker_oidc_maintenance_ready",
    "periapsis_worker_oidc_maintenance_runs_total",
    "periapsis_worker_oidc_maintenance_work_total",
    "periapsis_worker_oidc_maintenance_queue_due",
    "periapsis_worker_oidc_maintenance_queue_reclaimable",
    "periapsis_worker_oidc_maintenance_queue_dead_lettered",
    "periapsis_worker_oidc_maintenance_queue_oldest_due_seconds",
  ];
  return [
    ...requireMarkers(
      alertRules,
      "deploy/observability/alert-rules.yaml",
      metricFamilies,
    ),
    ...requireMarkers(
      dashboard,
      "deploy/observability/grafana-dashboard.json",
      metricFamilies,
    ),
    ...requireMarkers(alertRules, "deploy/observability/alert-rules.yaml", [
      "absent(periapsis_sla_queue_oldest_pending_seconds)",
      "absent(periapsis_sla_queue_pending_jobs)",
      "max(periapsis_sla_queue_oldest_pending_seconds) > 120",
      "absent(periapsis_sla_action_queue_oldest_pending_seconds)",
      "absent(periapsis_sla_action_queue_pending_actions)",
      "max(periapsis_sla_action_queue_oldest_pending_seconds) > 120",
      "absent(periapsis_worker_sla_event_ingress_ready)",
      "absent(periapsis_sla_event_ingress_worker_runs_total)",
      "absent(periapsis_sla_event_ingress_worker_events_total)",
      "absent(periapsis_sla_event_ingress_queue_pending_events)",
      "absent(periapsis_sla_event_ingress_queue_reclaimable_events)",
      "absent(periapsis_sla_event_ingress_queue_dead_lettered_events)",
      "absent(periapsis_sla_event_ingress_queue_oldest_pending_seconds)",
      "absent(periapsis_worker_ticket_runtime_ready)",
      "absent(periapsis_ticket_export_reconcile_worker_runs_total)",
      "absent(periapsis_ticket_export_reconcile_artifacts_total)",
      "absent(periapsis_ticket_export_reconcile_queue_pending_eligible)",
      "absent(periapsis_ticket_export_reconcile_queue_reclaimable)",
      "absent(periapsis_ticket_export_reconcile_queue_dead_lettered)",
      "absent(periapsis_ticket_export_reconcile_queue_oldest_pending_seconds)",
      "min(periapsis_worker_ticket_runtime_ready) < 1",
      'periapsis_ticket_export_reconcile_artifacts_total{outcome="dead_lettered"}',
      "max(periapsis_ticket_export_reconcile_queue_oldest_pending_seconds) > 120",
      "max(periapsis_ticket_export_reconcile_queue_dead_lettered) > 0",
      "absent(periapsis_worker_oidc_maintenance_ready)",
      "absent(periapsis_worker_oidc_maintenance_queue_due)",
      "absent(periapsis_worker_oidc_maintenance_queue_reclaimable)",
      "absent(periapsis_worker_oidc_maintenance_queue_dead_lettered)",
      "absent(periapsis_worker_oidc_maintenance_queue_oldest_due_seconds)",
      "min(periapsis_worker_oidc_maintenance_ready) < 1",
      "max(periapsis_worker_oidc_maintenance_queue_oldest_due_seconds) > 120",
      "max(periapsis_worker_oidc_maintenance_queue_reclaimable) > 0",
      'periapsis_worker_oidc_maintenance_queue_dead_lettered{kind="logout_retry"}',
    ]),
    ...requireMarkers(
      dashboard,
      "deploy/observability/grafana-dashboard.json",
      [
        "max(periapsis_sla_queue_oldest_pending_seconds)",
        "max(periapsis_sla_queue_pending_jobs)",
        "max(periapsis_sla_action_queue_oldest_pending_seconds)",
        "max(periapsis_sla_action_queue_pending_actions)",
        "min(periapsis_worker_sla_event_ingress_ready)",
        "periapsis_sla_event_ingress_worker_runs_total",
        "periapsis_sla_event_ingress_worker_events_total",
        "max(periapsis_sla_event_ingress_queue_pending_events)",
        "max(periapsis_sla_event_ingress_queue_reclaimable_events)",
        "max(periapsis_sla_event_ingress_queue_dead_lettered_events)",
        "max(periapsis_sla_event_ingress_queue_oldest_pending_seconds)",
        "min(periapsis_worker_ticket_runtime_ready)",
        "periapsis_ticket_export_reconcile_artifacts_total",
        "max(periapsis_ticket_export_reconcile_queue_pending_eligible)",
        "max(periapsis_ticket_export_reconcile_queue_reclaimable)",
        "max(periapsis_ticket_export_reconcile_queue_dead_lettered)",
        "max(periapsis_ticket_export_reconcile_queue_oldest_pending_seconds)",
        "min(periapsis_worker_oidc_maintenance_ready)",
        "periapsis_worker_oidc_maintenance_runs_total",
        "max by (kind) (periapsis_worker_oidc_maintenance_queue_due)",
        "max by (kind) (periapsis_worker_oidc_maintenance_queue_reclaimable)",
        "max by (kind) (periapsis_worker_oidc_maintenance_queue_dead_lettered)",
        "max by (kind) (periapsis_worker_oidc_maintenance_queue_oldest_due_seconds)",
      ],
    ),
  ];
}

export async function validateRepository(rootDirectory) {
  const root = resolve(rootDirectory);
  const errors = [];
  const contentsByPath = new Map();

  for (const path of requiredFiles) {
    try {
      contentsByPath.set(path, await load(root, path));
    } catch {
      errors.push(`${path}: required file is missing or unreadable`);
    }
  }
  errors.push(
    ...validateSLAObservability(
      contentsByPath.get("deploy/observability/alert-rules.yaml") ?? "",
      contentsByPath.get("deploy/observability/grafana-dashboard.json") ?? "",
    ),
  );

  const workloadFiles = [
    ["deploy/k8s/base/api-deployment.yaml", true],
    ["deploy/k8s/base/worker-deployment.yaml", true],
    ["deploy/k8s/base/notifier-deployment.yaml", true],
    ["deploy/k8s/base/web-deployment.yaml", true],
    ["deploy/k8s/base/migration-job.yaml", false],
  ];
  for (const [path, probes] of workloadFiles) {
    try {
      const contents = await load(root, path);
      errors.push(...validateWorkloadSecurity(contents, path, { probes }));
    } catch {
      errors.push(`${path}: workload file is missing or unreadable`);
    }
  }

  const deploymentFiles = await listFiles(root, "deploy");
  for (const path of deploymentFiles.filter((deploymentPath) =>
    basename(deploymentPath).startsWith("Dockerfile"),
  )) {
    errors.push(...validateDockerfileBasePins(await load(root, path), path));
  }
  for (const path of deploymentFiles) {
    const extension = extname(path).toLowerCase();
    if (![".yaml", ".yml", ".json", ".ldif"].includes(extension)) {
      continue;
    }
    const contents = await load(root, path);
    errors.push(...validateInlineSecrets(contents, path));
    if (/^\s*image:\s*\S+:latest(?:\s|$)/mu.test(contents)) {
      errors.push(`${path}: contains an unpinned latest image tag`);
    }
    if (
      /^kind:\s*Secret\s*$/mu.test(contents) &&
      /^\s*(?:data|stringData):\s*$/mu.test(contents)
    ) {
      errors.push(`${path}: commits a Kubernetes Secret payload`);
    }
  }

  const workflowFiles = (await listFiles(root, ".github/workflows")).filter(
    (path) => [".yaml", ".yml"].includes(extname(path).toLowerCase()),
  );
  for (const path of workflowFiles) {
    const contents = await load(root, path);
    errors.push(...validateActionPins(contents, path));
    if (path === ".github/workflows/deployment-security.yml") {
      errors.push(...validateMultiarchRuntimeWorkflow(contents, path));
    }
  }

  const composePath = "deploy/compose/compose.yaml";
  const compose = contentsByPath.get(composePath) ?? "";
  errors.push(...validateApplicationShutdownBudget(compose, composePath));
  errors.push(
    ...validateComposeDevelopmentTLS(
      compose,
      contentsByPath.get("deploy/compose/edge/Caddyfile") ?? "",
      composePath,
      "deploy/compose/edge/Caddyfile",
    ),
  );
  errors.push(
    ...requireMarkers(compose, composePath, [
      "- minimal",
      "- auth-test",
      "- full",
      "openldap:",
      "identity-provider:",
      "ldap-tls:",
      "LDAP_INIT_ROOT_USER_PW_FILE: /run/secrets/ldap-admin-password",
      "dockerfile: deploy/compose/Dockerfile.openldap-test",
      "LDAPTLS_REQCERT: demand",
      'LDAP_TLS_ENABLED: "true"',
      'LDAP_TLS_SSF: "128"',
      "ldap://openldap:1389",
      "openldap_tls:/run/secrets/ldap:ro",
      "mailpit:",
      "minio:",
      "minio-provision:",
      "clamav:",
      "notifier:",
      "otel-collector:",
      "prometheus:",
    ]),
  );
  errors.push(
    ...requireMarkers(
      contentsByPath.get("deploy/compose/auth/generate-openldap-tls.sh") ?? "",
      "deploy/compose/auth/generate-openldap-tls.sh",
      [
        "valid_material()",
        'stat -c %a "$directory/server.key"',
        "-checkhost openldap",
        "certificate_modulus=",
        "private_modulus=",
        'valid_material "$target"',
      ],
    ),
  );
  errors.push(
    ...requireMarkers(compose, composePath, [
      "dockerfile: deploy/images/Dockerfile.api",
      "dockerfile: deploy/images/Dockerfile.worker",
      "dockerfile: deploy/images/Dockerfile.notifier",
      'user: "10001:10001"',
      "read_only: true",
      "cap_drop:",
      "no-new-privileges:true",
      "/tmp:uid=10001,gid=10001,mode=1770",
    ]),
  );
  errors.push(
    ...requireYamlKeyCount(
      compose,
      composePath,
      "PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL",
      2,
    ),
    ...requireYamlKeyCount(compose, composePath, "PERIAPSIS_LOG_LEVEL", 3),
  );
  if (
    (
      compose.match(/^\s*PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL:\s*"true"\s*$/gmu) ??
      []
    ).length !== 2
  ) {
    errors.push(
      `${composePath}: local plaintext SMTP must be enabled only for API and notifier`,
    );
  }
  errors.push(
    ...requireMarkers(compose, composePath, [
      "notifier-provision:",
      "- provision-notifier",
      "PERIAPSIS_DATABASE_URL: postgresql://periapsis_notifier_login:${PERIAPSIS_NOTIFIER_DATABASE_PASSWORD:-}",
      "notifier_database_password:",
      "file: ${PERIAPSIS_COMPOSE_SECRETS_DIR:?prepare an external Compose secret directory}/notifier_database_password",
    ]),
  );
  errors.push(
    ...validateComposeFileSecrets(
      contentsByPath.get("deploy/compose/compose.base.yaml") ?? "",
      "deploy/compose/compose.base.yaml",
    ),
  );
  errors.push(
    ...requireMarkers(
      contentsByPath.get("deploy/compose/database-task.mjs") ?? "",
      "deploy/compose/database-task.mjs",
      [
        'mode === "provision-notifier"',
        'readSecret("notifier_database_password")',
        'login: "periapsis_notifier_login"',
        'memberOf: "periapsis_notifier"',
        "provisionWebhookPlainLocalRoleOptIns",
        "webhook_plain_local_runtime_role_opt_ins",
        "WEBHOOK_PLAIN_LOCAL_PRODUCTION_FORBIDDEN",
      ],
    ),
  );
  try {
    errors.push(
      ...validateDatabaseTaskPackaging(
        contentsByPath.get("deploy/compose/Dockerfile.database") ?? "",
        "deploy/compose/Dockerfile.database",
      ),
    );
    errors.push(
      ...requireMarkers(
        contentsByPath.get("deploy/compose/Dockerfile.database") ?? "",
        "deploy/compose/Dockerfile.database",
        [
          "COPY deploy/compose/database-task-config.mjs",
          "node --check deploy/compose/database-task-config.mjs",
          "USER 10001:10001",
        ],
      ),
    );
  } catch {
    errors.push(
      "deploy/compose/Dockerfile.database: file is missing or unreadable",
    );
  }
  if ((compose.match(/<<: \*application-security/gu) ?? []).length !== 5) {
    errors.push(
      `${composePath}: expected the security anchor on API, worker, web, edge, and notifier`,
    );
  }
  errors.push(
    ...requireMarkers(compose, composePath, [
      "PERIAPSIS_DFIR_MAX_OBJECT_BYTES: ${PERIAPSIS_DFIR_MAX_OBJECT_BYTES:-5000000000}",
      'PERIAPSIS_DFIR_SCANNER_ALLOW_PLAINTEXT_LOCAL: "true"',
      "PERIAPSIS_DFIR_SCANNER_ENDPOINT: tcp://clamav:3310",
      "PERIAPSIS_S3_PUBLIC_ENDPOINT: https://storage.localhost:${PERIAPSIS_MINIO_API_PORT:-19000}",
      "minio-provision:",
      "condition: service_completed_successfully",
      "clamav/clamav-debian:1.5.4_base@sha256:",
      'user: "1000:1000"',
      "/init-unprivileged",
      "clamav_signatures:/var/lib/clamav",
      "clamav-updates: {}",
      "subnet: 172.30.242.0/28",
    ]),
  );
  const minioProvisionPath = "deploy/compose/storage/provision-minio.sh";
  const minioProvision = contentsByPath.get(minioProvisionPath) ?? "";
  errors.push(
    ...validateDFIRStorageCORS(
      contentsByPath.get("deploy/compose/edge/Caddyfile") ?? "",
      "deploy/compose/edge/Caddyfile",
    ),
    ...requireMarkers(minioProvision, minioProvisionPath, [
      '[ "$bucket" = "periapsis-evidence" ] || exit 1',
      "version enable",
      '"s3:DeleteObject", "s3:GetObject", "s3:PutObject"',
      '"s3:ListBucketVersions"',
      '"s3:DeleteObjectVersion"',
      '"s3:prefix": ["????????-????-7???-????-????????????/????????-????-7???-????-????????????"]',
      "admin policy attach",
    ]),
    ...requireMarkers(compose, composePath, [
      "MINIO_API_CORS_ALLOW_ORIGIN: https://localhost:${PERIAPSIS_WEB_PORT:-8443}",
    ]),
  );
  if (/\bmc\b[^\r\n]*\bcors\s+set\b/u.test(minioProvision)) {
    errors.push(
      `${minioProvisionPath}: the pinned local MinIO does not implement bucket CORS`,
    );
  }
  for (const [path, markers] of [
    [
      "deploy/compose/clamav/clamd.conf",
      [
        "StreamMaxLength 5000000000",
        "MaxScanSize 5000000000",
        "MaxFileSize 5000000000",
        "FailIfCvdOlderThan 2",
      ],
    ],
    ["deploy/compose/clamav/freshclam.conf", ["Checks 12", "NotifyClamd"]],
  ]) {
    errors.push(
      ...requireMarkers(contentsByPath.get(path) ?? "", path, markers),
    );
  }

  const swarmPath = "deploy/swarm/stack.yml";
  const swarm = contentsByPath.get(swarmPath) ?? "";
  errors.push(...validateApplicationShutdownBudget(swarm, swarmPath));
  errors.push(
    ...requireMarkers(swarm, swarmPath, [
      "replicas: 0",
      "PERIAPSIS_DATABASE_ADMIN_URL_FILE: /run/secrets/database_admin_url",
      "PERIAPSIS_DATABASE_TASK_IMAGE:?set immutable database-task image digest",
      "PERIAPSIS_API_IMAGE:?set immutable API image digest",
      "PERIAPSIS_WORKER_IMAGE:?set immutable worker image digest",
      "PERIAPSIS_NOTIFIER_IMAGE:?set immutable notifier image digest",
      "PERIAPSIS_WEB_IMAGE:?set immutable web image digest",
      "external: true",
      "driver: overlay",
      'encrypted: "true"',
      "update_config:",
      "rollback_config:",
      "read_only: true",
      "cap_drop:",
      "configs:",
      "replicas: ${PERIAPSIS_API_REPLICAS:-0}",
      "replicas: ${PERIAPSIS_WORKER_REPLICAS:-0}",
      "replicas: ${PERIAPSIS_NOTIFIER_REPLICAS:-0}",
      "replicas: ${PERIAPSIS_WEB_REPLICAS:-0}",
      "replicas: ${PERIAPSIS_OTEL_REPLICAS:-0}",
      "replicas: ${PERIAPSIS_PROMETHEUS_REPLICAS:-0}",
      'PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL: "false"',
      "source: notifier_database_password",
      "target: notifier_database_password",
      "PERIAPSIS_NOTIFIER_DATABASE_PASSWORD_SECRET:-periapsis_notifier_database_password_v1",
      "PERIAPSIS_DFIR_SCANNER_CA_BUNDLE_FILE: /run/secrets/dfir_scanner_ca_bundle",
      "PERIAPSIS_DFIR_SCANNER_ENDPOINT:?set TLS clamd gateway endpoint",
      "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE: /run/secrets/federated_ca_bundle",
      "PERIAPSIS_FEDERATED_CA_BUNDLE_SECRET:-periapsis_federated_ca_bundle_v1",
      "PERIAPSIS_S3_CA_BUNDLE_FILE: /run/secrets/s3_ca_bundle",
      "PERIAPSIS_S3_PUBLIC_ENDPOINT:?set browser-reachable S3 endpoint",
      "PERIAPSIS_S3_CA_BUNDLE_SECRET:-periapsis_s3_ca_bundle_v1",
      "PERIAPSIS_DFIR_SCANNER_CA_BUNDLE_SECRET:-periapsis_dfir_scanner_ca_bundle_v1",
    ]),
  );
  errors.push(
    ...requireYamlKeyCount(
      swarm,
      swarmPath,
      "PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL",
      1,
    ),
    ...requireYamlKeyCount(swarm, swarmPath, "PERIAPSIS_LOG_LEVEL", 3),
  );
  if (swarm.includes('PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL: "true"')) {
    errors.push(`${swarmPath}: plaintext SMTP is enabled in production`);
  }
  if ((swarm.match(/<<: \*application-security/gu) ?? []).length !== 4) {
    errors.push(
      `${swarmPath}: expected the security anchor on API, worker, web, and notifier`,
    );
  }
  if ((swarm.match(/<<: \*application-secret/gu) ?? []).length !== 26) {
    errors.push(
      `${swarmPath}: expected owner-only mode on every application secret mount`,
    );
  }

  for (const service of ["api", "worker"]) {
    const path = `deploy/images/Dockerfile.${service}`;
    const compatibilityPath = `services/${service}/Dockerfile`;
    try {
      const canonical = await load(root, path);
      const compatibility = await load(root, compatibilityPath);
      errors.push(
        ...validateGoPackagingDockerfile(canonical, service, path),
        ...validateGoPackagingDockerfile(
          compatibility,
          service,
          compatibilityPath,
        ),
      );
      if (
        canonical.replaceAll("\r\n", "\n") !==
        compatibility.replaceAll("\r\n", "\n")
      ) {
        errors.push(
          `${compatibilityPath}: compatibility Dockerfile drifted from ${path}`,
        );
      }
    } catch {
      errors.push(`${path}: packaging Dockerfiles are missing or unreadable`);
    }
  }

  const notifierDockerfilePath = "deploy/images/Dockerfile.notifier";
  try {
    errors.push(
      ...validateNotifierPackagingDockerfile(
        await load(root, notifierDockerfilePath),
        notifierDockerfilePath,
      ),
    );
  } catch {
    errors.push(
      `${notifierDockerfilePath}: packaging Dockerfile is missing or unreadable`,
    );
  }

  for (const path of [
    "apps/web/Dockerfile",
    "deploy/compose/Dockerfile.database",
    notifierDockerfilePath,
  ]) {
    const contents = contentsByPath.get(path) ?? "";
    if (path === "apps/web/Dockerfile") {
      errors.push(...validateDockerfileBasePins(contents, path));
    }
    errors.push(...validateNodeRuntimePackageManagers(contents, path));
  }

  for (const module of [
    "contacts",
    "customfields",
    "dfir",
    "identity",
    "sla",
    "ticketing",
  ]) {
    const path = `modules/${module}/go.mod`;
    try {
      await load(root, path);
    } catch {
      errors.push(`${path}: required local image-build module is unavailable`);
    }
  }
  try {
    const apiModule = await load(root, "services/api/go.mod");
    for (const module of [
      "contacts",
      "customfields",
      "dfir",
      "identity",
      "sla",
      "ticketing",
    ]) {
      errors.push(
        ...requireMarkers(apiModule, "services/api/go.mod", [
          `replace github.com/periapsis-im/periapsis/modules/${module} => ../../modules/${module}`,
        ]),
      );
    }
  } catch {
    errors.push("services/api/go.mod: API packaging module is unreadable");
  }

  const kustomizationPath = "deploy/k8s/base/kustomization.yaml";
  const kustomization = contentsByPath.get(kustomizationPath) ?? "";
  errors.push(
    ...requireMarkers(kustomization, kustomizationPath, [
      "namespace.yaml",
      "service-account.yaml",
      "config-map.yaml",
      "migration-job.yaml",
      "hpa.yaml",
      "pdb.yaml",
      "network-policies.yaml",
      "clamav-config.yaml",
    ]),
  );
  try {
    const runtimeConfig = await load(root, "deploy/k8s/base/config-map.yaml");
    errors.push(
      ...validateKubernetesProxyTrustConfiguration(runtimeConfig),
      ...requireMarkers(runtimeConfig, "deploy/k8s/base/config-map.yaml", [
        'PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL: "false"',
        'PERIAPSIS_DFIR_MAX_OBJECT_BYTES: "5000000000"',
        "PERIAPSIS_DFIR_SCANNER_ENDPOINT: unix:///run/clamav/clamd.sock",
        "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE: /run/secrets/federated-ca-bundle",
        "PERIAPSIS_S3_PUBLIC_ENDPOINT: https://evidence.example.com",
      ]),
    );
    errors.push(
      ...requireYamlKeyCount(
        runtimeConfig,
        "deploy/k8s/base/config-map.yaml",
        "PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL",
        1,
      ),
    );
    if (runtimeConfig.includes('PERIAPSIS_SMTP_ALLOW_PLAIN_LOCAL: "true"')) {
      errors.push(
        "deploy/k8s/base/config-map.yaml: plaintext SMTP is enabled in production",
      );
    }
  } catch {
    errors.push(
      "deploy/k8s/base/config-map.yaml: runtime config is unreadable",
    );
  }
  for (const path of [
    "deploy/k8s/base/api-deployment.yaml",
    "deploy/k8s/base/worker-deployment.yaml",
  ]) {
    try {
      errors.push(
        ...requireMarkers(await load(root, path), path, [
          "key: federated-ca-bundle",
          "path: federated-ca-bundle",
        ]),
      );
    } catch {
      errors.push(`${path}: federated CA projection is unreadable`);
    }
  }
  try {
    errors.push(
      ...requireMarkers(
        await load(root, "deploy/k8s/base/migration-job.yaml"),
        "deploy/k8s/base/migration-job.yaml",
        [
          "PERIAPSIS_DATABASE_ADMIN_URL_FILE",
          "database-admin-url",
          "notifier-database-password",
          "notifier_database_password",
        ],
      ),
    );
  } catch {
    errors.push(
      "deploy/k8s/base/migration-job.yaml: file is missing or unreadable",
    );
  }
  try {
    const externalSecret = await load(
      root,
      "deploy/k8s/optional/external-secret.example.yaml",
    );
    errors.push(
      ...requireMarkers(
        externalSecret,
        "deploy/k8s/optional/external-secret.example.yaml",
        [
          "secretKey: database-admin-url",
          "secretKey: notifier-database-url",
          "secretKey: notifier-database-password",
          "secretKey: notification-keyring",
          "secretKey: s3-ca-bundle",
          "secretKey: federated-ca-bundle",
        ],
      ),
    );
    if (externalSecret.includes("database-admin-password")) {
      errors.push(
        "deploy/k8s/optional/external-secret.example.yaml: legacy plaintext admin-password source remains",
      );
    }
  } catch {
    errors.push(
      "deploy/k8s/optional/external-secret.example.yaml: file is missing or unreadable",
    );
  }

  const parityPaths = [
    "deploy/compose/compose.yaml",
    "deploy/compose/.env.example",
    "deploy/swarm/stack.yml",
    "deploy/swarm/.env.example",
    "deploy/k8s/base/config-map.yaml",
  ];
  const dfirParityPaths = [
    "deploy/compose/compose.yaml",
    "deploy/swarm/stack.yml",
    "deploy/swarm/.env.example",
    "deploy/k8s/base/config-map.yaml",
  ];
  const federatedEgressParityPaths = [
    ".env.example",
    "deploy/compose/compose.yaml",
    "deploy/compose/.env.example",
    "deploy/swarm/stack.yml",
    "deploy/swarm/.env.example",
    "deploy/k8s/base/config-map.yaml",
  ];
  for (const path of parityPaths) {
    let contents;
    try {
      contents = await load(root, path);
    } catch {
      errors.push(`${path}: LDAP parity source is missing or unreadable`);
      continue;
    }
    for (const variable of workerLDAPVariables) {
      if (!contents.includes(variable)) {
        errors.push(
          `${path}: worker LDAP setting ${variable} is not forwarded`,
        );
      }
    }
    for (const variable of workerSLAVariables) {
      if (!contents.includes(variable)) {
        errors.push(`${path}: worker SLA setting ${variable} is not forwarded`);
      }
    }
    for (const variable of workerTicketExportReconciliationVariables) {
      if (!contents.includes(variable)) {
        errors.push(
          `${path}: ticket export reconciliation setting ${variable} is not forwarded`,
        );
      }
    }
  }
  try {
    const rootEnvironment = await load(root, ".env.example");
    for (const variable of workerSLAVariables) {
      if (!rootEnvironment.includes(variable)) {
        errors.push(
          `.env.example: worker SLA setting ${variable} is not documented`,
        );
      }
    }
    for (const variable of workerTicketExportReconciliationVariables) {
      if (!rootEnvironment.includes(variable)) {
        errors.push(
          `.env.example: ticket export reconciliation setting ${variable} is not documented`,
        );
      }
    }
  } catch {
    errors.push(".env.example: worker SLA settings are unreadable");
  }
  try {
    const composeEnvironment = await load(root, "deploy/compose/.env.example");
    errors.push(
      ...requireMarkers(composeEnvironment, "deploy/compose/.env.example", [
        "PERIAPSIS_DEV_TLS_CERT_FILE=",
        "PERIAPSIS_DEV_TLS_KEY_FILE=",
        "PERIAPSIS_DEV_TLS_CA_FILE=",
        "PERIAPSIS_WEB_PORT=8443",
        "PERIAPSIS_FEDERATED_HTTPS_PORTS=443,18090",
      ]),
    );
    for (const variable of [
      "PERIAPSIS_DFIR_MAX_OBJECT_BYTES",
      "PERIAPSIS_DFIR_PRIVATE_EGRESS_CIDRS",
      "PERIAPSIS_DFIR_SCANNER_TIMEOUT",
      "PERIAPSIS_S3_MAX_CONCURRENT",
    ]) {
      if (!composeEnvironment.includes(variable)) {
        errors.push(
          `deploy/compose/.env.example: local DFIR override ${variable} is not documented`,
        );
      }
    }
  } catch {
    errors.push(
      "deploy/compose/.env.example: local DFIR overrides are unreadable",
    );
  }

  for (const path of dfirParityPaths) {
    let contents;
    try {
      contents = await load(root, path);
    } catch {
      errors.push(`${path}: DFIR parity source is missing or unreadable`);
      continue;
    }
    for (const variable of dfirRuntimeVariables) {
      if (!contents.includes(variable)) {
        errors.push(`${path}: DFIR runtime bound ${variable} is not forwarded`);
      }
    }
  }

  const federatedEgressContentsByPath = new Map();
  for (const path of federatedEgressParityPaths) {
    let contents;
    try {
      contents = await load(root, path);
      federatedEgressContentsByPath.set(path, contents);
    } catch {
      errors.push(
        `${path}: federated egress parity source is missing or unreadable`,
      );
      continue;
    }
    for (const variable of federatedEgressVariables) {
      if (
        path === "deploy/swarm/.env.example" &&
        variable === "PERIAPSIS_FEDERATED_CA_BUNDLE_FILE"
      ) {
        if (!contents.includes("PERIAPSIS_FEDERATED_CA_BUNDLE_SECRET")) {
          errors.push(
            `${path}: versioned federated CA Docker Secret name is not forwarded`,
          );
        }
        continue;
      }
      if (!contents.includes(variable)) {
        errors.push(
          `${path}: federated egress bound ${variable} is not forwarded`,
        );
      }
    }
  }
  for (const [path] of federatedOIDCClockSkewDefaults) {
    const contents = federatedEgressContentsByPath.get(path);
    if (contents !== undefined) {
      errors.push(...validateFederatedOIDCClockSkewDefault(contents, path));
    }
  }
  errors.push(
    ...requireMarkers(swarm, swarmPath, [
      "PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS: ${PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS:-}",
      "PERIAPSIS_FEDERATED_HTTPS_PORTS: ${PERIAPSIS_FEDERATED_HTTPS_PORTS:-443}",
    ]),
  );
  try {
    const runtimeConfig = await load(root, "deploy/k8s/base/config-map.yaml");
    errors.push(
      ...requireMarkers(runtimeConfig, "deploy/k8s/base/config-map.yaml", [
        'PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS: ""',
        'PERIAPSIS_FEDERATED_HTTPS_PORTS: "443"',
      ]),
    );
  } catch {
    // The unreadable source is already reported by the parity loop.
  }

  for (const path of [
    "deploy/compose/compose.yaml",
    "deploy/swarm/stack.yml",
  ]) {
    try {
      const contents = await load(root, path);
      for (const variable of dfirRuntimeVariables) {
        if (variable === "PERIAPSIS_S3_BUCKET" && path.includes("compose")) {
          continue;
        }
        errors.push(...requireYamlKeyCount(contents, path, variable, 2));
      }
    } catch {
      // The parity loop above already reports unreadable sources.
    }
  }

  for (const [path, markers] of [
    [
      "deploy/k8s/base/api-deployment.yaml",
      [
        "PERIAPSIS_S3_CA_BUNDLE_FILE",
        "clamav/clamav-debian:1.5.4_base@sha256:",
        "/init-unprivileged",
        "name: clamav-signatures",
        "name: clamav-socket",
      ],
    ],
    [
      "deploy/k8s/base/worker-deployment.yaml",
      [
        "PERIAPSIS_S3_CA_BUNDLE_FILE",
        "clamav/clamav-debian:1.5.4_base@sha256:",
        "/init-unprivileged",
        "name: clamav-signatures",
        "name: clamav-socket",
      ],
    ],
    [
      "deploy/k8s/base/clamav-config.yaml",
      [
        "TCPAddr 127.0.0.1",
        "LocalSocket /tmp/clamd.sock",
        "StreamMaxLength 5000000000",
        "MaxScanSize 5000000000",
        "MaxFileSize 5000000000",
        "FailIfCvdOlderThan 2",
        "DatabaseMirror database.clamav.net",
        "Checks 12",
      ],
    ],
  ]) {
    try {
      errors.push(...requireMarkers(await load(root, path), path, markers));
    } catch {
      errors.push(`${path}: DFIR runtime source is missing or unreadable`);
    }
  }

  for (const path of [
    "deploy/compose/compose.yaml",
    "deploy/swarm/stack.yml",
  ]) {
    try {
      const contents = await load(root, path);
      for (const variable of workerLDAPVariables) {
        const expected = variable.startsWith("PERIAPSIS_LDAP_SYNC_") ? 1 : 2;
        errors.push(...requireYamlKeyCount(contents, path, variable, expected));
      }
      for (const variable of workerSLAVariables) {
        errors.push(...requireYamlKeyCount(contents, path, variable, 1));
      }
      for (const variable of workerTicketExportReconciliationVariables) {
        errors.push(...requireYamlKeyCount(contents, path, variable, 1));
      }
    } catch {
      // The parity loop above already reports unreadable sources.
    }
  }

  for (const path of parityPaths) {
    let contents;
    try {
      contents = await load(root, path);
    } catch {
      continue;
    }
    for (const variable of notifierRuntimeVariables) {
      if (!contents.includes(variable)) {
        errors.push(
          `${path}: notifier runtime bound ${variable} is not forwarded`,
        );
      }
    }
  }

  for (const path of [
    "deploy/compose/compose.yaml",
    "deploy/swarm/stack.yml",
    "deploy/k8s/base/notifier-deployment.yaml",
    "deploy/k8s/optional/external-secret.example.yaml",
  ]) {
    try {
      const contents = await load(root, path);
      for (const obsolete of [
        "PERIAPSIS_SMTP_SECRET_DIR",
        "smtp_credential",
        "smtp-secrets",
        "periapsis-smtp-credentials",
      ]) {
        if (contents.includes(obsolete)) {
          errors.push(
            `${path}: obsolete SMTP file-secret fallback ${obsolete} remains`,
          );
        }
      }
    } catch {
      errors.push(`${path}: notification credential boundary is unreadable`);
    }
  }

  for (const [path, markers] of [
    [
      "deploy/compose/compose.yaml",
      [
        "PERIAPSIS_NOTIFIER_INTERNAL_URL: http://notifier-preview:8083",
        "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE",
        "file: ${PERIAPSIS_COMPOSE_SECRETS_DIR:?prepare an external Compose secret directory}/notifier_preview_token",
        "notification-preview:",
        "- notifier-preview",
      ],
    ],
    [
      "deploy/swarm/stack.yml",
      [
        "PERIAPSIS_NOTIFIER_INTERNAL_URL: http://notifier-preview:8083",
        "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE",
        "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_SECRET",
        "notification-preview:",
        "- notifier-preview",
      ],
    ],
    [
      "deploy/k8s/base/api-deployment.yaml",
      [
        "PERIAPSIS_NOTIFIER_INTERNAL_URL",
        "http://periapsis-notifier:8083",
        "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE",
        "notifier-preview-token",
      ],
    ],
    [
      "deploy/k8s/base/notifier-deployment.yaml",
      ["PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE", "notifier-preview-token"],
    ],
    [
      "deploy/k8s/base/network-policies.yaml",
      [
        "allow-api-to-notifier-preview",
        "allow-notifier-preview-from-api",
        "port: 8083",
      ],
    ],
  ]) {
    try {
      const contents = await load(root, path);
      errors.push(...requireMarkers(contents, path, markers));
      if (
        (path === "deploy/compose/compose.yaml" ||
          path === "deploy/swarm/stack.yml") &&
        (contents.match(/PERIAPSIS_NOTIFIER_PREVIEW_TOKEN_FILE/gu) ?? [])
          .length !== 2
      ) {
        errors.push(
          `${path}: preview-token file must be mounted by exactly API and notifier`,
        );
      }
    } catch {
      errors.push(`${path}: notifier preview-token source is missing`);
    }
  }

  for (const [path, markers] of [
    [
      "deploy/compose/compose.yaml",
      [
        "NOTIFICATION_KEYRING_FILE: /run/secrets/notification-keyring",
        "file: ${PERIAPSIS_COMPOSE_SECRETS_DIR:?prepare an external Compose secret directory}/notification-keyring",
      ],
    ],
    [
      "deploy/swarm/stack.yml",
      ["NOTIFICATION_KEYRING_FILE", "PERIAPSIS_NOTIFICATION_KEYRING_SECRET"],
    ],
    [
      "deploy/k8s/base/api-deployment.yaml",
      ["NOTIFICATION_KEYRING_FILE", "periapsis-notification-keyring"],
    ],
    [
      "deploy/k8s/base/notifier-deployment.yaml",
      ["NOTIFICATION_KEYRING_FILE", "periapsis-notification-keyring"],
    ],
  ]) {
    try {
      const contents = await load(root, path);
      errors.push(...requireMarkers(contents, path, markers));
      if (
        path === "deploy/compose/compose.yaml" ||
        path === "deploy/swarm/stack.yml"
      ) {
        errors.push(
          ...requireYamlKeyCount(
            contents,
            path,
            "NOTIFICATION_KEYRING_FILE",
            2,
          ),
        );
      }
    } catch {
      errors.push(`${path}: notification keyring source is missing`);
    }
  }

  const developmentOverlay =
    contentsByPath.get("deploy/k8s/overlays/dev/kustomization.yaml") ?? "";
  errors.push(
    ...validateKubernetesDevelopmentTLS(
      developmentOverlay,
      "deploy/k8s/overlays/dev/kustomization.yaml",
    ),
    ...validateKubernetesProxyTrustOverrides(
      developmentOverlay,
      "deploy/k8s/overlays/dev/kustomization.yaml",
    ),
  );
  errors.push(
    ...requireMarkers(
      contentsByPath.get("deploy/k8s/README.md") ?? "",
      "deploy/k8s/README.md",
      [
        "https://periapsis.local",
        "periapsis-ingress-tls-dev",
        "cert-manager.io/cluster-issuer",
        "HTTP-to-HTTPS",
        "PERIAPSIS_TRUSTED_PROXY_CIDRS",
        "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS",
        "site-specific overlay",
      ],
    ),
  );

  const productionOverlay =
    contentsByPath.get("deploy/k8s/overlays/prod/kustomization.yaml") ?? "";
  errors.push(
    ...validateProductionImagePins(
      productionOverlay,
      "deploy/k8s/overlays/prod/kustomization.yaml",
    ),
    ...validateKubernetesProxyTrustOverrides(
      productionOverlay,
      "deploy/k8s/overlays/prod/kustomization.yaml",
    ),
  );
  if (productionOverlay.includes("cidr: 0.0.0.0/0")) {
    errors.push(
      "deploy/k8s/overlays/prod/kustomization.yaml: production egress is fail-open",
    );
  }
  errors.push(
    ...requireMarkers(
      productionOverlay,
      "deploy/k8s/overlays/prod/kustomization.yaml",
      ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"],
    ),
  );

  for (const path of [
    "deploy/compose/auth/keycloak-realm.json",
    "deploy/observability/grafana-dashboard.json",
  ]) {
    try {
      JSON.parse(await load(root, path));
    } catch {
      errors.push(`${path}: JSON is missing or invalid`);
    }
  }

  return [...new Set(errors)].toSorted((left, right) =>
    left.localeCompare(right, "en"),
  );
}

const invokedPath =
  process.argv[1] === undefined ? "" : resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
  const errors = await validateRepository(root);
  if (errors.length > 0) {
    for (const error of errors) {
      process.stderr.write(`ERROR ${error}\n`);
    }
    process.exitCode = 1;
  } else {
    process.stdout.write("Deployment manifest source checks passed.\n");
  }
}
