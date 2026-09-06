import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const integration = readFileSync(
  new URL("../integration/ldap-auth-acceptance.mjs", import.meta.url),
  "utf8",
);
const specification = readFileSync(
  new URL("phase-three-live.spec.ts", import.meta.url),
  "utf8",
);
const configuration = readFileSync(
  new URL("playwright.live.config.ts", import.meta.url),
  "utf8",
);
const workflow = readFileSync(
  new URL("../../.github/workflows/ci.yml", import.meta.url),
  "utf8",
);
const packageManifest = readFileSync(
  new URL("../../package.json", import.meta.url),
  "utf8",
);

test("live Phase 3 acceptance uses the composed API and database without interception", () => {
  assert.doesNotMatch(specification, /\.(?:route|routeFromHAR)\s*\(/u);
  assert.doesNotMatch(
    specification,
    /\broute\.(?:fulfill|abort|continue)\s*\(/u,
  );
  const manualContexts = [
    ...specification.matchAll(/browser\.newContext\(\{(?<options>[^}]*)\}\)/gu),
  ];
  assert.ok(manualContexts.length > 0);
  for (const context of manualContexts) {
    assert.match(
      context.groups?.options ?? "",
      /baseURL:\s*state\.baseUrl/u,
      "manually created contexts must carry the live HTTPS base URL",
    );
  }
  assert.match(configuration, /phase-three-live\.spec\.ts/u);
  assert.doesNotMatch(configuration, /\bwebServer\s*:/u);
  assert.match(configuration, /PERIAPSIS_LIVE_E2E_BASE_URL/u);
  assert.match(configuration, /PERIAPSIS_LIVE_E2E_OUTPUT_DIR/u);
  assert.match(integration, /playwright\.live\.config\.ts/u);
  assert.match(integration, /PERIAPSIS_LIVE_E2E_OUTPUT_DIR/u);
  assert.match(integration, /mode:\s*0o600/u);
  assert.match(workflow, /PERIAPSIS_LDAP_ACCEPTANCE_RUN_LIVE_PLAYWRIGHT=1/u);
});

test("CI transpiles the live spec and provisions its isolated browser runner", () => {
  assert.match(packageManifest, /"test:e2e:live:list"/u);
  assert.match(workflowJob("javascript"), /pnpm test:e2e:live:list/u);
  const containersJob = workflowJob("containers");
  assert.match(containersJob, /pnpm\/action-setup@/u);
  assert.match(containersJob, /pnpm install --frozen-lockfile/u);
  assert.match(containersJob, /playwright install --with-deps chromium/u);
  assert.match(
    containersJob,
    /--profile minimal down --volumes --remove-orphans/u,
  );
  assert.match(workflow, /--profile full up --detach --no-build --wait/u);
  assert.match(
    workflow,
    /build api worker web migration ldap-tls openldap identity-provider minio minio-provision/u,
  );
  assert.match(
    workflow,
    /edge openldap identity-provider worker notifier mailpit/u,
  );
  assert.match(workflow, /ps --quiet identity-provider/u);
  assert.match(workflow, /\.HostConfig\.ReadonlyRootfs/u);
  assert.match(workflow, /identity_user%%:\*/u);
  assert.match(workflow, /PERIAPSIS_LDAP_ACCEPTANCE_COMPOSE_PROFILE=full/u);
  assert.match(workflow, /cannot mutate append-only tenant audit rows/u);
});

test("ephemeral browser authority is never committed as a fixture", () => {
  assert.match(integration, /mkdtempSync/u);
  assert.match(integration, /rmSync\(resolvedTemporaryRoot/u);
  assert.match(
    integration,
    /!name\.toUpperCase\(\)\.startsWith\("PERIAPSIS_"\)/u,
  );
  assert.match(integration, /__Host-periapsis_session/u);
  assert.match(integration, /;\\s\*Secure/u);
  assert.match(specification, /__Host-periapsis_session/u);
  assert.doesNotMatch(specification, /\.allHeaders\s*\(/u);
  assert.doesNotMatch(specification, /console\.(?:log|info|debug|error)/u);
  assert.doesNotMatch(integration, /cookieValue[^\n]*stdout/u);
  assert.doesNotMatch(specification, /expect\(secret\)/u);
  assert.match(configuration, /screenshot:\s*"off"/u);
  assert.match(configuration, /trace:\s*"off"/u);
  assert.match(configuration, /video:\s*"off"/u);
  assert.doesNotMatch(configuration, /only-on-failure|retain-on-failure/u);
});

function workflowJob(name) {
  const marker = `\n  ${name}:\n`;
  const start = workflow.indexOf(marker);
  assert.notEqual(start, -1, `workflow job ${name} must exist`);
  const bodyStart = start + marker.length;
  const remainder = workflow.slice(bodyStart);
  const nextJob = remainder.search(/\n  [a-z][a-z0-9-]*:\n/u);
  return nextJob === -1 ? remainder : remainder.slice(0, nextJob);
}
