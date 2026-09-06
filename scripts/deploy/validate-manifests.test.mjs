import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import {
  validateActionPins,
  validateApplicationShutdownBudget,
  validateCredentialReferenceIsolation,
  validateComposeDevelopmentTLS,
  validateDFIRStorageCORS,
  validateDockerfileBasePins,
  validateFederatedOIDCClockSkewDefault,
  validateInlineSecrets,
  validateKubernetesDevelopmentTLS,
  validateKubernetesProxyTrustConfiguration,
  validateKubernetesProxyTrustOverrides,
  validateMultiarchRuntimeWorkflow,
  validateNodeRuntimePackageManagers,
  validateGoPackagingDockerfile,
  validateNotifierPackagingDockerfile,
  validateProductionImagePins,
  validateRepository,
  validateSLAObservability,
  validateWorkloadSecurity,
} from "./validate-manifests.mjs";
import {
  parseDeploymentEnvironment,
  validateAdministratorDatabaseUrl,
} from "../../deploy/compose/database-task-config.mjs";

const kubernetesConfigMapOperation = (
  key,
  value,
  verb = "replace",
) => `      - op: ${verb}
        path: /data/${key}${value === undefined ? "" : `\n        value: ${value}`}`;

const kubernetesConfigMapOverlay = (...operations) => `
patches:
  - target:
      kind: ConfigMap
      name: periapsis-runtime
    patch: |-
${operations.join("\n")}
`;

test("repository deployment sources satisfy security contracts", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  assert.deepEqual(await validateRepository(root), []);
});

test("application shutdown budget preserves worker completion and telemetry flush", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  for (const path of [
    "deploy/compose/compose.yaml",
    "deploy/swarm/stack.yml",
  ]) {
    const source = await readFile(resolve(root, path), "utf8");
    assert.deepEqual(validateApplicationShutdownBudget(source, path), []);
    assert.ok(
      validateApplicationShutdownBudget(
        source.replace("  stop_grace_period: 30s", "  stop_grace_period: 15s"),
        path,
      ).some((error) => error.includes("stop_grace_period must be 30s")),
    );
  }
});

test("federated OIDC clock-skew defaults reject drift and shadow assignments", () => {
  const cases = [
    [
      ".env.example",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=1m",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=5m",
    ],
    [
      "deploy/compose/compose.yaml",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: ${PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW:-1m}",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: ${PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW:-5m}",
    ],
    [
      "deploy/compose/.env.example",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=1m",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=5m",
    ],
    [
      "deploy/swarm/stack.yml",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: ${PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW:-1m}",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: ${PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW:-5m}",
    ],
    [
      "deploy/swarm/.env.example",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=1m",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW=5m",
    ],
    [
      "deploy/k8s/base/config-map.yaml",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: 1m",
      "PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW: 5m",
    ],
  ];

  for (const [path, expected, shadow] of cases) {
    assert.deepEqual(validateFederatedOIDCClockSkewDefault(expected, path), []);
    assert.deepEqual(
      validateFederatedOIDCClockSkewDefault(
        `${expected}\n# ${shadow} is intentionally documented`,
        path,
      ),
      [],
    );
    assert.ok(
      validateFederatedOIDCClockSkewDefault(shadow, path).some((error) =>
        error.includes("expected 1 exact lines"),
      ),
    );
    assert.ok(
      validateFederatedOIDCClockSkewDefault(
        `${expected}\n${shadow}`,
        path,
      ).some((error) => error.includes("configuration assignments")),
    );
    const alternateShadow =
      path.endsWith(".yaml") || path.endsWith(".yml")
        ? '"PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW" : 5m'
        : "export PERIAPSIS_FEDERATED_OIDC_CLOCK_SKEW = 5m";
    assert.ok(
      validateFederatedOIDCClockSkewDefault(
        `${expected}\n${alternateShadow}`,
        path,
      ).some((error) => error.includes("configuration assignments")),
    );
  }
});

test("Makefile exposes every required local Compose command", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  const makefile = await readFile(resolve(root, "Makefile"), "utf8");

  for (const target of ["dev", "up", "down", "reset", "logs", "test"]) {
    assert.match(makefile, new RegExp(`^${target}:(?:\\s|$)`, "mu"));
  }
  assert.match(makefile, /^up:\s+dev\s*$/mu);
  assert.match(makefile, /^down:\s+dev-down\s*$/mu);
  assert.match(makefile, /^reset:\s+db-reset\s*$/mu);
  assert.match(
    makefile,
    /^logs:\s*\r?\n\t\$\(COMPOSE\) --profile minimal logs --follow\s*$/mu,
  );
  assert.match(
    makefile,
    /^docker-build:\s*\r?\n\t\$\(COMPOSE\) --profile full build\s*$/mu,
  );
});

test("SLA observability cannot replace unavailable queue evidence with zero", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  const alertRules = await readFile(
    resolve(root, "deploy/observability/alert-rules.yaml"),
    "utf8",
  );
  const dashboard = await readFile(
    resolve(root, "deploy/observability/grafana-dashboard.json"),
    "utf8",
  );
  assert.deepEqual(validateSLAObservability(alertRules, dashboard), []);
  assert.ok(
    validateSLAObservability(
      alertRules.replaceAll(
        "periapsis_sla_queue_pending_jobs",
        "removed_queue_depth",
      ),
      dashboard,
    ).some((error) => error.includes("periapsis_sla_queue_pending_jobs")),
  );
  assert.ok(
    validateSLAObservability(
      alertRules.replaceAll(
        "periapsis_sla_event_ingress_queue_dead_lettered_events",
        "removed_sla_event_ingress_dead_letters",
      ),
      dashboard,
    ).some((error) =>
      error.includes("periapsis_sla_event_ingress_queue_dead_lettered_events"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules,
      dashboard.replace(
        "max(periapsis_sla_event_ingress_queue_oldest_pending_seconds)",
        "vector(0)",
      ),
    ).some((error) =>
      error.includes(
        "max(periapsis_sla_event_ingress_queue_oldest_pending_seconds)",
      ),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules,
      dashboard.replace(
        "max(periapsis_sla_queue_oldest_pending_seconds)",
        "vector(0)",
      ),
    ).some((error) =>
      error.includes("max(periapsis_sla_queue_oldest_pending_seconds)"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules.replaceAll(
        "periapsis_sla_action_queue_pending_actions",
        "removed_action_queue_depth",
      ),
      dashboard,
    ).some((error) =>
      error.includes("periapsis_sla_action_queue_pending_actions"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules,
      dashboard.replace(
        "max(periapsis_sla_action_queue_oldest_pending_seconds)",
        "vector(0)",
      ),
    ).some((error) =>
      error.includes("max(periapsis_sla_action_queue_oldest_pending_seconds)"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules.replaceAll(
        "periapsis_ticket_export_reconcile_artifacts_total",
        "removed_ticket_export_reconciliation",
      ),
      dashboard,
    ).some((error) =>
      error.includes("periapsis_ticket_export_reconcile_artifacts_total"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules,
      dashboard.replace(
        "min(periapsis_worker_ticket_runtime_ready)",
        "vector(0)",
      ),
    ).some((error) =>
      error.includes("min(periapsis_worker_ticket_runtime_ready)"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules.replaceAll(
        "periapsis_ticket_export_reconcile_queue_dead_lettered",
        "removed_reconciliation_dead_letters",
      ),
      dashboard,
    ).some((error) =>
      error.includes("periapsis_ticket_export_reconcile_queue_dead_lettered"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules,
      dashboard.replace(
        "max(periapsis_ticket_export_reconcile_queue_oldest_pending_seconds)",
        "vector(0)",
      ),
    ).some((error) =>
      error.includes(
        "max(periapsis_ticket_export_reconcile_queue_oldest_pending_seconds)",
      ),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules.replaceAll(
        "periapsis_worker_oidc_maintenance_queue_dead_lettered",
        "removed_oidc_logout_dead_letters",
      ),
      dashboard,
    ).some((error) =>
      error.includes("periapsis_worker_oidc_maintenance_queue_dead_lettered"),
    ),
  );
  assert.ok(
    validateSLAObservability(
      alertRules,
      dashboard.replace(
        "max by (kind) (periapsis_worker_oidc_maintenance_queue_oldest_due_seconds)",
        "vector(0)",
      ),
    ).some((error) =>
      error.includes(
        "max by (kind) (periapsis_worker_oidc_maintenance_queue_oldest_due_seconds)",
      ),
    ),
  );
});

test("multi-architecture runtime evidence gate cannot regress to build-only", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  const path = resolve(root, ".github/workflows/deployment-security.yml");
  const workflow = await readFile(path, "utf8");
  assert.deepEqual(validateMultiarchRuntimeWorkflow(workflow), []);
  assert.ok(
    validateMultiarchRuntimeWorkflow(
      workflow.replace(
        "--load --platform linux/arm64",
        "--platform linux/arm64",
      ),
    ).some((error) => error.includes("--load --platform linux/arm64")),
  );
  assert.ok(
    validateMultiarchRuntimeWorkflow(
      workflow.replace("observed_uid=%s read_only=true", "observed_uid=%s"),
    ).some((error) => error.includes("read_only=true")),
  );
  assert.ok(
    validateMultiarchRuntimeWorkflow(
      workflow.replace(
        "for manager in apk corepack npm npx pnpm pnpx yarn yarnpkg",
        "for manager in corepack npm npx pnpm pnpx yarn yarnpkg",
      ),
    ).some((error) => error.includes("for manager in apk")),
  );
});

test("action references fail closed unless local or SHA pinned", () => {
  assert.deepEqual(validateActionPins("- uses: ./local-action"), []);
  assert.deepEqual(
    validateActionPins(`- uses: actions/checkout@${"a".repeat(40)}`),
    [],
  );
  assert.equal(validateActionPins("- uses: actions/checkout@v5").length, 1);
  assert.equal(validateActionPins("- uses: 'actions/checkout@v5'").length, 1);
  assert.deepEqual(
    validateActionPins(`- uses: "actions/checkout@${"b".repeat(40)}"`),
    [],
  );
});

test("inline secret detection accepts indirection and rejects literals", () => {
  assert.deepEqual(
    validateInlineSecrets("password: ${PASSWORD_FROM_OPERATOR_ENV}"),
    [],
  );
  assert.deepEqual(validateInlineSecrets("token: /run/secrets/token"), []);
  assert.equal(
    validateInlineSecrets("clientSecret: hostile-literal").length,
    1,
  );
  assert.equal(validateInlineSecrets("-----BEGIN PRIVATE KEY-----").length, 1);
  assert.equal(
    validateInlineSecrets("PERIAPSIS_NOTIFICATION_KEYRING: hostile-literal")
      .length,
    1,
  );
  assert.equal(validateInlineSecrets("userPassword: changeit").length, 1);
  assert.equal(validateInlineSecrets('"clientSecret": "hostile"').length, 1);
});

test("local DFIR storage CORS source has exact closed headers and upstream isolation", async () => {
  const valid = await readFile(
    new URL("../../deploy/compose/edge/Caddyfile", import.meta.url),
    "utf8",
  );
  assert.deepEqual(validateDFIRStorageCORS(valid), []);
  for (const [before, after] of [
    ["If-None-Match, ", ""],
    ["X-Amz-Meta-Periapsis-Declared-Mime, ", ""],
    [
      "Access-Control-Allow-Origin https://localhost:{$PERIAPSIS_WEB_PORT:8443}",
      "Access-Control-Allow-Origin *",
    ],
    [
      'Access-Control-Allow-Methods "GET, HEAD, PUT"',
      'Access-Control-Allow-Methods "GET, HEAD, PUT, DELETE"',
    ],
    ["Content-Length, Content-Type,", "*,"],
    ["Access-Control-Expose-Headers ETag", "Access-Control-Expose-Headers *"],
    ["Access-Control-Max-Age 300", "Access-Control-Max-Age 86400"],
    ["header_down -Access-Control-*", ""],
    ["respond @options 403", ""],
    ["respond @foreign_origin 403", ""],
    ["respond @browser_method_denied 403", ""],
    ["respond @browser_path_denied 403", ""],
  ]) {
    assert.notEqual(valid.replace(before, after), valid, before);
    assert.ok(
      validateDFIRStorageCORS(valid.replace(before, after)).length > 0,
      before,
    );
  }
  for (const added of [
    "Access-Control-Allow-Credentials true",
    "Access-Control-Allow-Private-Network true",
    "Access-Control-Expose-Headers ETag",
  ]) {
    assert.ok(
      validateDFIRStorageCORS(`${valid}\n${added}\n`).length > 0,
      added,
    );
  }
});

test("workload security check reports missing closed markers", () => {
  assert.ok(validateWorkloadSecurity("kind: Deployment").length > 3);
});

test("production images require a closed set of immutable digests", () => {
  const digest = `digest: sha256:${"a".repeat(64)}`;
  assert.deepEqual(
    validateProductionImagePins(
      Array.from({ length: 5 }, () => digest).join("\n"),
    ),
    [],
  );
  assert.ok(validateProductionImagePins("newTag: stable").length > 0);
  assert.ok(
    validateProductionImagePins(
      Array.from({ length: 5 }, () => "digest: sha256:not-a-digest").join("\n"),
    ).length > 0,
  );
});

test("development Kubernetes ingress preserves its HTTPS origin and TLS secret", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  const overlay = await readFile(
    resolve(root, "deploy/k8s/overlays/dev/kustomization.yaml"),
    "utf8",
  );
  assert.deepEqual(validateKubernetesDevelopmentTLS(overlay), []);
  assert.ok(
    validateKubernetesDevelopmentTLS(
      overlay.replace("https://periapsis.local", "http://periapsis.local"),
    ).some((error) => error.includes("plaintext HTTP")),
  );
  assert.ok(
    validateKubernetesDevelopmentTLS(
      overlay.replace(
        "path: /spec/tls/0/secretName",
        "path: /spec/tls/0/removedSecretName",
      ),
    ).some((error) => error.includes("periapsis-ingress-tls-dev")),
  );
  assert.ok(
    validateKubernetesDevelopmentTLS(
      overlay.replace(
        "- op: replace\n        path: /spec/tls/0/hosts/0",
        "- op: remove\n        path: /spec/tls",
      ),
    ).some((error) => error.includes("removes TLS")),
  );
});

test("Kubernetes proxy trust stays fail-closed until a site overlay supplies exact peers", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  const runtimeConfig = await readFile(
    resolve(root, "deploy/k8s/base/config-map.yaml"),
    "utf8",
  );
  assert.deepEqual(
    validateKubernetesProxyTrustConfiguration(`
data:
  PERIAPSIS_TRUSTED_PROXY_CIDRS: REPLACE_WITH_WEB_POD_IMMEDIATE_PEER_CIDRS
  PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS: REPLACE_WITH_INGRESS_CONTROLLER_IMMEDIATE_PEER_CIDRS
`),
    [],
  );
  assert.deepEqual(
    validateKubernetesProxyTrustConfiguration(runtimeConfig),
    [],
  );

  for (const [marker, replacement, expectedError] of [
    ["REPLACE_WITH_WEB_POD_IMMEDIATE_PEER_CIDRS", '""', "must not be empty"],
    [
      "REPLACE_WITH_INGRESS_CONTROLLER_IMMEDIATE_PEER_CIDRS",
      '""',
      "must not be empty",
    ],
    [
      "REPLACE_WITH_WEB_POD_IMMEDIATE_PEER_CIDRS",
      "10.20.0.0/0",
      "must not trust a wildcard CIDR",
    ],
    [
      "REPLACE_WITH_INGRESS_CONTROLLER_IMMEDIATE_PEER_CIDRS",
      "::/0",
      "must not trust a wildcard CIDR",
    ],
  ]) {
    assert.ok(
      validateKubernetesProxyTrustConfiguration(
        runtimeConfig.replace(marker, replacement),
      ).some((error) => error.includes(expectedError)),
    );
  }

  assert.ok(
    validateKubernetesProxyTrustConfiguration(
      runtimeConfig.replace(
        "REPLACE_WITH_WEB_POD_IMMEDIATE_PEER_CIDRS",
        "10.0.0.0/24",
      ),
    ).some((error) => error.includes("must retain fail-closed marker")),
  );

  const swappedMarkers = runtimeConfig
    .replace("REPLACE_WITH_WEB_POD_IMMEDIATE_PEER_CIDRS", "SWAP_MARKER")
    .replace(
      "REPLACE_WITH_INGRESS_CONTROLLER_IMMEDIATE_PEER_CIDRS",
      "REPLACE_WITH_WEB_POD_IMMEDIATE_PEER_CIDRS",
    )
    .replace(
      "SWAP_MARKER",
      "REPLACE_WITH_INGRESS_CONTROLLER_IMMEDIATE_PEER_CIDRS",
    );
  assert.equal(
    validateKubernetesProxyTrustConfiguration(swappedMarkers).filter((error) =>
      error.includes("must retain fail-closed marker"),
    ).length,
    2,
  );
});

test("Kubernetes overlays cannot empty, remove, or wildcard proxy trust", () => {
  assert.deepEqual(
    validateKubernetesProxyTrustOverrides(
      kubernetesConfigMapOverlay(
        kubernetesConfigMapOperation(
          "PERIAPSIS_TRUSTED_PROXY_CIDRS",
          "10.20.30.0/28",
        ),
        kubernetesConfigMapOperation(
          "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS",
          "10.20.40.0/28",
        ),
      ),
    ),
    [],
  );
  for (const [key, value, verb, expectedError] of [
    ["PERIAPSIS_TRUSTED_PROXY_CIDRS", '""', "replace", "must not be empty"],
    [
      "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS",
      "0.0.0.0/0",
      "replace",
      "must not trust a wildcard CIDR",
    ],
    [
      "PERIAPSIS_TRUSTED_PROXY_CIDRS",
      "2001:db8::/0",
      "replace",
      "must not trust a wildcard CIDR",
    ],
    [
      "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS",
      undefined,
      "remove",
      "must not be removed",
    ],
  ]) {
    assert.ok(
      validateKubernetesProxyTrustOverrides(
        kubernetesConfigMapOverlay(
          kubernetesConfigMapOperation(key, value, verb),
        ),
      ).some((error) => error.includes(expectedError)),
    );
  }
  assert.ok(
    validateKubernetesProxyTrustOverrides(
      kubernetesConfigMapOverlay(
        kubernetesConfigMapOperation(
          "PERIAPSIS_TRUSTED_PROXY_CIDRS",
          "10.20.30.0/28",
        ),
      ),
    ).some((error) => error.includes("override both proxy boundaries")),
  );
  assert.ok(
    validateKubernetesProxyTrustOverrides(
      kubernetesConfigMapOverlay(
        kubernetesConfigMapOperation(
          "PERIAPSIS_TRUSTED_PROXY_CIDRS",
          "10.20.30.0/28",
        ),
        kubernetesConfigMapOperation(
          "PERIAPSIS_TRUSTED_PROXY_CIDRS",
          "10.20.31.0/28",
        ),
        kubernetesConfigMapOperation(
          "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS",
          "10.20.40.0/28",
        ),
      ),
    ).some((error) => error.includes("at most one overlay operation")),
  );
  assert.ok(
    validateKubernetesProxyTrustOverrides(`
patches:
  - patch: |-
      - op: replace
        path: /data
        value: {}
`).some((error) => error.includes("whole ConfigMap data replacement")),
  );
});

test("Compose browser flows stay behind the local TLS edge", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  const compose = await readFile(
    resolve(root, "deploy/compose/compose.yaml"),
    "utf8",
  );
  const caddyfile = await readFile(
    resolve(root, "deploy/compose/edge/Caddyfile"),
    "utf8",
  );
  assert.deepEqual(validateComposeDevelopmentTLS(compose, caddyfile), []);
  assert.ok(
    validateComposeDevelopmentTLS(
      compose.replace(
        "PERIAPSIS_PUBLIC_URL: https://localhost",
        "PERIAPSIS_PUBLIC_URL: http://localhost",
      ),
      caddyfile,
    ).some((error) => error.includes("browser-facing development URL")),
  );
  assert.ok(
    validateComposeDevelopmentTLS(
      compose.replace("source: dev_tls_private_key", "source: removed_key"),
      caddyfile,
    ).some((error) => error.includes("dev_tls_private_key")),
  );
  assert.ok(
    validateComposeDevelopmentTLS(
      compose.replace(
        "  edge:\n    <<: *application-security",
        "  edge:\n    # security anchor removed",
      ),
      caddyfile,
    ).some((error) => error.includes("application-security")),
  );
  assert.ok(
    validateComposeDevelopmentTLS(
      compose.replace(
        "  identity-provider:\n",
        `  identity-provider:\n    ports:\n      - 127.0.0.1:${"${PERIAPSIS_IDP_PORT:-29999}"}:8080\n`,
      ),
      caddyfile,
    ).some((error) => error.includes("publishes backend port 8080")),
  );
  assert.ok(
    validateComposeDevelopmentTLS(
      compose,
      caddyfile.replace("protocols tls1.2 tls1.3", "protocols tls1.0"),
    ).some((error) => error.includes("protocols tls1.2 tls1.3")),
  );
});

test("Compose local webhook development keeps an explicit bounded port allowlist", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  const compose = await readFile(
    resolve(root, "deploy/compose/compose.yaml"),
    "utf8",
  );
  const environment = await readFile(
    resolve(root, "deploy/compose/.env.example"),
    "utf8",
  );

  assert.match(
    compose,
    /PERIAPSIS_WEBHOOK_ALLOWED_PORTS:\s+\$\{PERIAPSIS_WEBHOOK_ALLOWED_PORTS:-80,443,8080\}/u,
  );
  assert.match(environment, /^PERIAPSIS_WEBHOOK_ALLOWED_PORTS=80,443,8080$/mu);
});

test("database credential references cannot be reused across runtimes", () => {
  assert.deepEqual(
    validateCredentialReferenceIsolation([
      ["api", "api-password"],
      ["worker", "worker-password"],
      ["notifier", "notifier-password"],
    ]),
    [],
  );
  assert.deepEqual(
    validateCredentialReferenceIsolation([
      ["api", "shared-password"],
      ["notifier", "shared-password"],
    ]),
    [
      "database credentials: notifier reuses the credential reference owned by api",
    ],
  );
});

test("Dockerfile base images require immutable SHA-256 digests", () => {
  const digest = "a".repeat(64);
  assert.deepEqual(
    validateDockerfileBasePins(
      [
        `ARG NODE_IMAGE=node:24-alpine@sha256:${digest}`,
        "FROM ${NODE_IMAGE} AS build",
        `FROM alpine:3.23@sha256:${digest}`,
        "FROM scratch",
      ].join("\n"),
    ),
    [],
  );
  assert.equal(validateDockerfileBasePins("FROM node:24-alpine").length, 1);
  assert.equal(
    validateDockerfileBasePins(
      "ARG NODE_IMAGE=node:24-alpine@sha256:deadbeef\nFROM ${NODE_IMAGE}",
    ).length,
    2,
  );
  assert.equal(validateDockerfileBasePins("FROM ${MISSING_IMAGE}").length, 1);
});

test("Go packaging Dockerfiles close build context and runtime identity", () => {
  const valid = [
    "ARG TARGETARCH",
    "ARG TARGETOS",
    "CGO_ENABLED=0",
    "COPY modules/contacts/ /workspace/modules/contacts/",
    "COPY modules/customfields/ /workspace/modules/customfields/",
    "COPY modules/dfir/ /workspace/modules/dfir/",
    "COPY modules/identity/ /workspace/modules/identity/",
    "COPY modules/sla/ /workspace/modules/sla/",
    "COPY modules/ticketing/ /workspace/modules/ticketing/",
    "COPY services/api/go.mod services/api/go.sum ./",
    "COPY services/api/ ./",
    "FROM scratch",
    "USER 10001:10001",
    "STOPSIGNAL SIGTERM",
    "HEALTHCHECK",
  ].join("\n");
  assert.deepEqual(validateGoPackagingDockerfile(valid, "api"), []);
  for (const module of [
    "contacts",
    "customfields",
    "dfir",
    "identity",
    "sla",
    "ticketing",
  ]) {
    assert.ok(
      validateGoPackagingDockerfile(
        valid.replace(
          `COPY modules/${module}/ /workspace/modules/${module}/`,
          `# missing ${module} module`,
        ),
        "api",
      ).some((error) => error.includes(`modules/${module}`)),
      `missing ${module} copy was not rejected`,
    );
  }
});

test("notifier packaging is pinned and fails closed without its entrypoint", () => {
  const valid = `
ARG NODE_IMAGE=node:24.20.0-alpine3.23@sha256:deadbeef
ENV CI=true
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY services/notifier/package.json services/notifier/package.json
COPY packages/tsconfig/package.json packages/tsconfig/package.json
RUN corepack pnpm install --frozen-lockfile --filter @periapsis/notifier...
RUN corepack pnpm --filter @periapsis/notifier build
RUN corepack pnpm --filter @periapsis/notifier deploy --legacy --prod /out
RUN test -f /out/dist/main.js
COPY --from=build --chown=10001:10001 /out/node_modules ./node_modules
COPY --from=build --chown=10001:10001 /out/dist ./dist
USER 10001:10001
HEALTHCHECK NONE
ENTRYPOINT ["node", "dist/main.js"]
`;
  assert.deepEqual(validateNotifierPackagingDockerfile(valid), []);
  assert.ok(
    validateNotifierPackagingDockerfile(
      valid.replace("dist/main.js", "dist/index.js"),
    ).length > 0,
  );
});

test("Node final stages remove package managers after runtime copies", async () => {
  const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
  for (const path of [
    "apps/web/Dockerfile",
    "deploy/compose/Dockerfile.database",
    "deploy/images/Dockerfile.notifier",
  ]) {
    const dockerfile = await readFile(resolve(root, path), "utf8");
    assert.deepEqual(validateNodeRuntimePackageManagers(dockerfile, path), []);
    assert.ok(
      validateNodeRuntimePackageManagers(
        dockerfile.replace("/sbin/apk /usr/bin/apk", "/sbin/removed"),
        path,
      ).some((error) => error.includes("/sbin/apk /usr/bin/apk")),
    );
    assert.ok(
      validateNodeRuntimePackageManagers(
        dockerfile.replace("/etc/apk", "/etc/apk /lib/apk"),
        path,
      ).some((error) => error.includes("installed-package inventory")),
    );
    assert.ok(
      validateNodeRuntimePackageManagers(
        dockerfile.replace(
          "USER 10001:10001",
          "COPY --from=synthetic /late-runtime-file /late-runtime-file\n\nUSER 10001:10001",
        ),
        path,
      ).some((error) => error.includes("after the final runtime copy")),
    );
  }
});

test("production migration URLs require unambiguous verified TLS", () => {
  const strongPassword = "synthetic-password-0000000000000000";
  const verified = `postgresql://migrator:${strongPassword}@postgres.example.invalid/periapsis?sslmode=verify-full`;
  assert.equal(
    validateAdministratorDatabaseUrl(verified, { production: true }),
    verified,
  );
  for (const unsafe of [
    verified.replace("verify-full", "require"),
    verified.replace("verify-full", "disable"),
    `${verified}&ssl=false`,
    `${verified}&sslmode=disable`,
    verified.replace(strongPassword, `${strongPassword}%00`),
    verified.replace("postgres.example.invalid", "postgres.example.invalid\n"),
  ]) {
    assert.throws(() =>
      validateAdministratorDatabaseUrl(unsafe, { production: true }),
    );
  }
  assert.equal(parseDeploymentEnvironment(undefined), "production");
  assert.throws(() => parseDeploymentEnvironment("staging"));
});
