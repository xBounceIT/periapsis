import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));

test("Go verification reruns source contracts outside module directories", async () => {
  const manifest = JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  );
  for (const name of ["go:test", "go:test:race"]) {
    assert.match(manifest.scripts[name], /^go test (?:-race )?-count=1 /u);
    assert.ok(manifest.scripts[name].includes("./services/worker/..."));
  }
  const makefile = await readFile(resolve(root, "Makefile"), "utf8");
  assert.match(
    makefile,
    /^\tgo test -count=1 .*\.\/services\/worker\/\.\.\./mu,
  );
  for (const path of [
    ".github/workflows/ci.yml",
    ".github/workflows/pull-request-fast.yml",
  ]) {
    const workflow = await readFile(resolve(root, path), "utf8");
    assert.match(
      workflow,
      /run: go test (?:-race )?-count=1 .*\.\/services\/worker\/\.\.\./u,
    );
  }
});

test("certificate-free proxy deployment keeps runtime and real-model gates wired", async () => {
  const ignore = await readFile(resolve(root, ".gitignore"), "utf8");
  assert.match(ignore, /^!deploy\/compose\/\.env\.reverse-proxy\.example$/mu);
  const example = await readFile(
    resolve(root, "deploy/compose/.env.reverse-proxy.example"),
    "utf8",
  );
  assert.match(
    example,
    /^PERIAPSIS_PUBLIC_URL=https:\/\/incidents\.example\.com$/mu,
  );
  assert.match(
    example,
    /^PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS=192\.0\.2\.10\/32$/mu,
  );
  const manifest = JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  );
  assert.ok(
    manifest.scripts["test:operations"]
      .split(" ")
      .includes("scripts/deploy/swarm-reverse-proxy.test.mjs"),
  );
  assert.ok(
    manifest.scripts["test:operations"]
      .split(" ")
      .includes("scripts/deploy/reverse-proxy-entrypoint.test.mjs"),
  );
  assert.equal(
    manifest.scripts["test:compose-models"],
    "node --test scripts/deploy/compose-models.test.mjs",
  );
  const workflows = await Promise.all(
    [
      ".github/workflows/ci.yml",
      ".github/workflows/deployment-security.yml",
    ].map((path) => readFile(resolve(root, path), "utf8")),
  );
  for (const workflow of workflows) {
    assert.match(
      workflow,
      /node --test scripts\/deploy\/compose-models\.test\.mjs/u,
    );
  }
  const deployment = await readFile(
    resolve(root, ".github/workflows/deployment-security.yml"),
    "utf8",
  );
  assert.match(
    deployment,
    /node --test scripts\/deploy\/storage-cors-runtime\.test\.mjs/u,
  );
  assert.match(
    deployment,
    /node --test scripts\/deploy\/reverse-proxy-entrypoint\.test\.mjs/u,
  );
  assert.match(
    deployment,
    /docker stack config --compose-file deploy\/swarm\/stack\.yml\s*\\\s*--compose-file deploy\/swarm\/stack\.reverse-proxy\.yml/u,
  );
});

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function triggerBlock(workflow) {
  const normalized = workflow.replaceAll("\r\n", "\n");
  const start = normalized.indexOf("on:\n");
  const end = normalized.indexOf("\npermissions:\n", start);
  assert.ok(start >= 0 && end > start, "workflow trigger block is unreadable");
  return normalized.slice(start, end);
}

test("type-aware lint builds exported contracts before checking their consumers", async () => {
  const manifest = JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  );
  const contracts = JSON.parse(
    await readFile(resolve(root, "packages/contracts/package.json"), "utf8"),
  );
  assert.equal(contracts.exports["."].types, "./dist/index.d.ts");
  assert.deepEqual(manifest.scripts.lint.split(" && "), [
    "corepack pnpm --filter @periapsis/contracts build",
    "corepack pnpm -r --if-present lint",
  ]);
});

test("canonical SLA fixture generation and checks run in Go-pinned gates", async () => {
  const manifest = JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  );
  assert.deepEqual(manifest.scripts["verify:sla-fixture"]?.split(" && "), [
    "go run packages/db/seeds/sla-fixture.go --input packages/db/seeds/sla-fixture-input.json --check packages/db/seeds/sla-fixture.generated.json",
    "go run packages/db/seeds/sla-fixture.go --input tests/performance/sla-fixture-input.json --check tests/performance/sla-fixture.generated.json",
    "go test packages/db/seeds/sla-fixture.go packages/db/seeds/sla-fixture_test.go",
    "go vet packages/db/seeds/sla-fixture.go packages/db/seeds/sla-fixture_test.go",
  ]);
  assert.ok(
    manifest.scripts.generate
      .split(" && ")
      .includes("corepack pnpm generate:sla-fixture"),
  );
  assert.ok(
    manifest.scripts.verify
      .split(" && ")
      .includes("corepack pnpm verify:sla-fixture"),
  );
  assert.equal(
    manifest.scripts["generate:sla-fixture"],
    "go run packages/db/seeds/sla-fixture.go --input packages/db/seeds/sla-fixture-input.json --output packages/db/seeds/sla-fixture.generated.json && go run packages/db/seeds/sla-fixture.go --input tests/performance/sla-fixture-input.json --output tests/performance/sla-fixture.generated.json && prettier --write packages/db/seeds/sla-fixture.generated.json tests/performance/sla-fixture.generated.json",
  );
  for (const path of [
    ".github/workflows/ci.yml",
    ".github/workflows/pull-request-fast.yml",
  ]) {
    const workflow = (await readFile(resolve(root, path), "utf8")).replaceAll(
      "\r\n",
      "\n",
    );
    const start = workflow.indexOf("  generated:\n");
    assert.ok(start >= 0);
    const tail = workflow.slice(start + "  generated:\n".length);
    const end = tail.search(/^  [a-z][a-z-]*:\n/mu);
    const job = end < 0 ? tail : tail.slice(0, end);
    const goSetup = job.indexOf("uses: actions/setup-go@");
    const tests = job.indexOf("run: pnpm verify:sla-fixture\n");
    assert.ok(
      goSetup >= 0 && tests > goSetup,
      `${path} must pin Go in the same job before fixture drift and kernel tests`,
    );
    const setupStep = job.slice(
      goSetup,
      job.indexOf("\n      - name:", goSetup),
    );
    assert.match(setupStep, /go-version: 1\.26\.7\n/u);
    assert.match(setupStep, /check-latest: false\n/u);
    assert.match(setupStep, /modules\/sla\/go\.sum/u);
  }
});

test("permission catalog generation and checks follow verified contract sources", async () => {
  const manifest = JSON.parse(
    await readFile(resolve(root, "package.json"), "utf8"),
  );
  assert.equal(
    manifest.scripts["generate:permission-catalog"],
    "go run scripts/docs/permission-catalog.go --write",
  );
  assert.deepEqual(
    manifest.scripts["verify:permission-catalog"]?.split(" && "),
    [
      "go run scripts/docs/permission-catalog.go --check",
      "go test scripts/docs/permission-catalog.go scripts/docs/permission-catalog_test.go",
      "go vet scripts/docs/permission-catalog.go scripts/docs/permission-catalog_test.go",
    ],
  );
  for (const [script, prerequisite, command] of [
    [
      "generate",
      "corepack pnpm -r --if-present generate",
      "corepack pnpm generate:permission-catalog",
    ],
    [
      "verify",
      "corepack pnpm verify:generated",
      "corepack pnpm verify:permission-catalog",
    ],
  ]) {
    const commands = manifest.scripts[script].split(" && ");
    assert.ok(
      commands.includes(prerequisite),
      `${script} omits canonical generation/drift`,
    );
    assert.ok(
      commands.indexOf(command) > commands.indexOf(prerequisite),
      `${script} does not check canonical sources before the permission catalog`,
    );
  }
  for (const workflowPath of [
    ".github/workflows/pull-request-fast.yml",
    ".github/workflows/ci.yml",
  ]) {
    const workflow = await readFile(resolve(root, workflowPath), "utf8");
    assert.match(
      workflow,
      /run: pnpm verify:generated\s+- name: Verify permission catalog\s+run: pnpm verify:permission-catalog/u,
      `${workflowPath} omits the ordered permission-catalog check`,
    );
  }
});

test("pull requests use fast checks while main, tags, and releases keep the full gates", async () => {
  const pullRequestWorkflow = await readFile(
    resolve(root, ".github/workflows/pull-request-fast.yml"),
    "utf8",
  );
  const fullWorkflow = await readFile(
    resolve(root, ".github/workflows/ci.yml"),
    "utf8",
  );
  const deploymentWorkflow = await readFile(
    resolve(root, ".github/workflows/deployment-security.yml"),
    "utf8",
  );
  const [composeManifest, swarmManifest] = await Promise.all([
    readFile(resolve(root, "deploy/compose/compose.base.yaml"), "utf8"),
    readFile(resolve(root, "deploy/swarm/stack.yml"), "utf8"),
  ]);

  const pullRequestTriggers = triggerBlock(pullRequestWorkflow);
  assert.match(pullRequestTriggers, /^  pull_request:\s*$/mu);
  assert.doesNotMatch(pullRequestTriggers, /^  (?:push|release):/mu);
  for (const marker of [
    "pnpm install --frozen-lockfile",
    "pnpm lint",
    "pnpm format:check",
    "pnpm typecheck",
    "pnpm test",
    "pnpm test:operations",
    "pnpm build",
    "go vet ",
    "go test ",
    "pnpm verify:generated",
    "pnpm verify:go-generated",
  ]) {
    assert.ok(
      pullRequestWorkflow.includes(marker),
      `fast pull-request checks are missing ${marker}`,
    );
  }
  for (const forbidden of [
    /docker (?:build|compose|run)/u,
    /pnpm test:security/u,
    /pnpm test:e2e(?:\s|$)/mu,
    /go test -race/u,
    /(?:trivy|gitleaks|syft)/iu,
  ]) {
    assert.doesNotMatch(
      pullRequestWorkflow,
      forbidden,
      `fast pull-request workflow contains a full-suite gate: ${forbidden}`,
    );
  }

  for (const [name, workflow] of [
    ["CI", fullWorkflow],
    ["deployment security", deploymentWorkflow],
  ]) {
    const triggers = triggerBlock(workflow);
    assert.doesNotMatch(triggers, /^  pull_request:/mu, `${name} runs on PRs`);
    assert.match(triggers, /^  push:\s*$/mu, `${name} omits push`);
    assert.match(triggers, /^      - main\s*$/mu, `${name} omits main`);
    assert.match(
      triggers,
      /^    tags:\s*\n      - "\*"\s*$/mu,
      `${name} omits tags`,
    );
    assert.doesNotMatch(
      triggers,
      /^    paths(?:-ignore)?:/mu,
      `${name} can skip a main or tag candidate by path`,
    );
    assert.match(
      triggers,
      /^  release:\s*\n    types:\s*\n      - published\s*$/mu,
      `${name} omits published releases`,
    );
    assert.match(
      triggers,
      /^  workflow_dispatch:/mu,
      `${name} omits manual release verification`,
    );
  }

  const completeGates = `${fullWorkflow}\n${deploymentWorkflow}`;
  for (const marker of [
    "pnpm install --frozen-lockfile",
    "pnpm lint",
    "pnpm typecheck",
    "pnpm test",
    "pnpm build",
    "go vet ",
    "go test -race",
    "pnpm verify:generated",
    "pnpm verify:go-generated",
    "pnpm test:e2e",
    "node tests/integration/ldap-auth-acceptance.mjs",
    "pnpm --filter @periapsis/db db:migrate",
    "pnpm --filter @periapsis/db test:security",
    "docker compose",
    "docker buildx build",
    "process.getuid()",
    "aquasecurity/trivy-action@",
    "anchore/sbom-action@",
    '"${RUNNER_TEMP}/gitleaks" detect',
    "kustomize build",
    "kubeconform -strict",
  ]) {
    assert.ok(
      completeGates.includes(marker),
      `complete main/tag/release gates are missing ${marker}`,
    );
  }

  for (const marker of [
    "PERIAPSIS_DEV_TLS_CA_FILE: /dev/null",
    "PERIAPSIS_DEV_TLS_CERT_FILE: /dev/null",
    "PERIAPSIS_DEV_TLS_KEY_FILE: /dev/null",
    "PERIAPSIS_DFIR_SCANNER_ENDPOINT: tls://clamd-gateway.example.invalid:3310",
    "PERIAPSIS_S3_PUBLIC_ENDPOINT: https://storage.example.invalid",
    "exec -T identity-provider bash -ceu",
    "/dev/tcp/127.0.0.1/8080",
    "/realms/periapsis-test/.well-known/openid-configuration",
    "/realms/periapsis-test/protocol/saml/descriptor",
  ]) {
    assert.ok(
      deploymentWorkflow.includes(marker),
      `deployment manifest and IdP smoke gate is missing ${marker}`,
    );
  }
  assert.doesNotMatch(
    deploymentWorkflow,
    /curl[^\n]*http:\/\/127\.0\.0\.1:18090/u,
    "the IdP smoke must not probe an unpublished clear-text host port",
  );

  const environmentStart = deploymentWorkflow.indexOf("\nenv:\n");
  const environmentEnd = deploymentWorkflow.indexOf(
    "\njobs:\n",
    environmentStart,
  );
  assert.ok(
    environmentStart >= 0 && environmentEnd > environmentStart,
    "deployment workflow global render environment is unreadable",
  );
  const renderEnvironment = deploymentWorkflow.slice(
    environmentStart,
    environmentEnd,
  );
  const declaredVariables = new Set(
    [...renderEnvironment.matchAll(/^  ([A-Z][A-Z0-9_]+):/gmu)].map(
      (match) => match[1],
    ),
  );
  const prepareStart = deploymentWorkflow.indexOf(
    "      - name: Prepare private file-backed Compose secrets\n",
  );
  const renderStart = deploymentWorkflow.indexOf(
    "      - name: Validate Compose profiles and Swarm model\n",
  );
  assert.ok(prepareStart >= 0 && renderStart > prepareStart);
  const preparation = deploymentWorkflow.slice(prepareStart, renderStart);
  assert.match(
    preparation,
    /export PERIAPSIS_COMPOSE_SECRETS_DIR="\$\{RUNNER_TEMP\}\/periapsis-compose-secrets"/u,
  );
  assert.match(
    preparation,
    /node scripts\/deploy\/prepare-compose-secrets.mjs/u,
  );
  assert.match(
    preparation,
    /echo "PERIAPSIS_COMPOSE_SECRETS_DIR=\$\{PERIAPSIS_COMPOSE_SECRETS_DIR\}" >> "\$\{GITHUB_ENV\}"/u,
  );
  declaredVariables.add("PERIAPSIS_COMPOSE_SECRETS_DIR");
  for (const [path, manifest] of [
    ["deploy/compose/compose.yaml", composeManifest],
    ["deploy/swarm/stack.yml", swarmManifest],
  ]) {
    const requiredVariables = new Set(
      [...manifest.matchAll(/\$\{([A-Z][A-Z0-9_]+):\?[^}]+\}/gu)].map(
        (match) => match[1],
      ),
    );
    for (const variable of requiredVariables) {
      assert.ok(
        declaredVariables.has(variable),
        `deployment workflow cannot render ${path}: ${variable} is unset`,
      );
    }
  }
});

test("the PostgreSQL security aggregate and CI matrix cover every fresh runtime suite", async () => {
  const packagePath = resolve(root, "packages/db/package.json");
  const workflowPath = resolve(root, ".github/workflows/ci.yml");
  const packageJson = JSON.parse(await readFile(packagePath, "utf8"));
  const workflow = await readFile(workflowPath, "utf8");
  const scripts = packageJson.scripts ?? {};
  const aggregate = scripts["test:security"];

  assert.equal(typeof aggregate, "string", "test:security must be defined");
  assert.doesNotMatch(
    aggregate,
    /test:security:[a-z0-9-]*upgrade(?:\s|$)/u,
    "rolling-upgrade suites require isolated predecessor databases",
  );

  // Retain the previous release's source corpus as a historical reference. Its
  // predecessors are exercised by isolated upgrade jobs, never on V52 clones.
  const historical = new Set([
    "test:security:schema-compatibility-v49",
    "test:security:schema-compatibility-v50",
    "test:security:schema-compatibility-v51",
  ]);
  const standalone = new Set(["test:security:seed-audit", ...historical]);
  for (const name of historical) {
    const suite = name.slice("test:security:".length);
    const version = suite.slice("schema-compatibility-v".length);
    assert.equal(scripts[name], `tsx tests/security/${suite}-runtime.ts`);
    assert.doesNotMatch(
      aggregate,
      new RegExp(`(?:^|\\s)run ${escapeRegExp(name)}(?:\\s|$)`, "u"),
    );
    assert.match(
      workflow,
      new RegExp(
        `script: ${escapeRegExp(name)}-upgrade\\s+database_env: PERIAPSIS_SCHEMA_COMPATIBILITY_V${version}_UPGRADE_TEST_DATABASE_URL`,
        "u",
      ),
    );
  }
  assert.match(
    aggregate,
    /(?:^|\s)run test:security:schema-compatibility-v52(?:\s|$)/u,
  );
  const securityScripts = Object.entries(scripts).filter(([name]) =>
    name.startsWith("test:security:"),
  );
  const scriptedSources = new Set();
  for (const [name, command] of securityScripts) {
    assert.equal(typeof command, "string", `${name} must have a command`);
    const sourcePath = command.match(
      /^tsx\s+(tests\/security\/\S+\.ts)$/u,
    )?.[1];
    assert.ok(sourcePath, `${name} must identify one bounded tsx suite`);
    assert.ok(
      !scriptedSources.has(sourcePath),
      `${sourcePath} must not be hidden behind multiple script aliases`,
    );
    scriptedSources.add(sourcePath);
  }

  const securityFiles = (
    await readdir(resolve(root, "packages/db/tests/security"))
  )
    .filter((name) => name.endsWith(".ts"))
    .map((name) => `tests/security/${name}`)
    .toSorted((left, right) => left.localeCompare(right, "en"));
  assert.deepEqual(
    [...scriptedSources].toSorted((left, right) =>
      left.localeCompare(right, "en"),
    ),
    securityFiles,
    "every PostgreSQL security suite must have one explicit package script",
  );

  assert.match(
    workflow,
    /pnpm --filter @periapsis\/db test:security:seed-audit(?:\s|$)/u,
    "the standalone seed-audit suite must remain wired into CI",
  );
  assert.equal(
    scripts["test:security:tenant-federation-administration-upgrade"],
    "tsx tests/security/tenant-federation-administration-upgrade.ts",
    "the exact 0227 to 0228 tenant-federation upgrade suite must remain explicit",
  );
  assert.match(
    workflow,
    /script: test:security:tenant-federation-administration-upgrade\s+database_env: PERIAPSIS_TENANT_FEDERATION_ADMIN_UPGRADE_TEST_DATABASE_URL/u,
    "CI must give the tenant-federation upgrade its own empty PostgreSQL 18 database",
  );
  for (const [name, command] of securityScripts.filter(([scriptName]) =>
    scriptName.endsWith("-upgrade"),
  )) {
    assert.match(
      workflow,
      new RegExp(`(?:^|\\s)${escapeRegExp(name)}(?:\\s|$)`, "u"),
      `${name} requires an isolated predecessor-database CI job`,
    );
    const sourcePath = command.match(/^tsx\s+(\S+)$/u)?.[1];
    const source = await readFile(
      resolve(root, "packages/db", sourcePath),
      "utf8",
    );
    const databaseVariables = new Set(
      [...source.matchAll(/process\.env\.([A-Z0-9_]+DATABASE_URL)/gu)].map(
        (match) => match[1],
      ),
    );
    assert.ok(
      databaseVariables.size > 0,
      `${name} must declare its isolated predecessor database variable`,
    );
    for (const variable of databaseVariables) {
      assert.match(
        workflow,
        new RegExp(`(?:^|\\s)${escapeRegExp(variable)}(?:\\s|$)`, "mu"),
        `${name} is not paired with ${variable} in the CI matrix`,
      );
    }
  }

  const runtimeSuites = Object.entries(scripts)
    .filter(
      ([name]) =>
        name.startsWith("test:security:") &&
        !name.endsWith("-upgrade") &&
        !standalone.has(name),
    )
    .toSorted(([left], [right]) => left.localeCompare(right, "en"));

  for (const [name, command] of runtimeSuites) {
    assert.match(
      aggregate,
      new RegExp(`(?:^|\\s)run ${escapeRegExp(name)}(?:\\s|$)`, "u"),
      `${name} is missing from the fresh-database security aggregate`,
    );
    const sourcePath = command.match(/^tsx\s+(\S+)$/u)?.[1];
    const source = await readFile(
      resolve(root, "packages/db", sourcePath),
      "utf8",
    );
    const databaseVariables = new Set(
      [...source.matchAll(/process\.env\.([A-Z0-9_]+DATABASE_URL)/gu)].map(
        (match) => match[1],
      ),
    );
    for (const variable of databaseVariables) {
      const assignment = workflow.match(
        new RegExp(
          `^\\s+${escapeRegExp(variable)}:\\s+(postgresql:\\/\\/[^\\r\\n]+)$`,
          "mu",
        ),
      );
      assert.ok(assignment, `${variable} is missing from the CI security step`);
      const database = assignment[1].match(
        /@127\.0\.0\.1:5432\/([a-z0-9_]+)\?sslmode=disable$/u,
      )?.[1];
      if (database && database !== "periapsis") {
        assert.match(
          workflow,
          new RegExp(`^\\s+${escapeRegExp(database)}(?: \\\\|; do)$`, "mu"),
          `${database} is not cloned from the migrated and provisioned template`,
        );
      }
    }
  }

  const provisionIndex = workflow.indexOf(
    "- name: Provision least-privileged runtime logins",
  );
  const cloneIndex = workflow.indexOf(
    "- name: Clone isolated security databases from the migrated template",
  );
  assert.ok(provisionIndex >= 0, "runtime-login provisioning step is missing");
  assert.ok(
    cloneIndex >= 0,
    "isolated security database clone step is missing",
  );
  assert.ok(
    provisionIndex < cloneIndex,
    "security databases must inherit the least-privileged runtime ACLs",
  );
});

test("the PostgreSQL Go gate selects authorization, shared DFIR and fresh-connection logout regressions with isolated databases", async () => {
  const workflow = (
    await readFile(resolve(root, ".github/workflows/ci.yml"), "utf8")
  ).replaceAll("\r\n", "\n");
  const job = workflow.match(
    /^  postgres-rls:\n(?:(?!^  [a-z][a-z0-9-]*:)[\s\S])*/mu,
  )?.[0];
  assert.ok(job, "the PostgreSQL runtime job must exist");
  const steps = job.split(/^      - /mu).slice(1);
  const cloneStep = steps.find((step) =>
    step.startsWith(
      "name: Clone isolated security databases from the migrated template\n",
    ),
  );
  assert.ok(cloneStep, "the migrated-template clone step must exist");
  assert.match(
    cloneStep,
    /createdb -U postgres -T periapsis "\$\{database\}"/u,
  );
  const goSteps = steps.filter((step) =>
    /^        run: go test .*\.\/services\/api\/internal\/postgres$/mu.test(
      step,
    ),
  );
  assert.equal(goSteps.length, 1, "one bounded PostgreSQL Go gate must exist");
  const goStep = goSteps[0];
  assert.doesNotMatch(goStep, /^        (?:if|continue-on-error):/mu);
  assert.match(goStep, /run: go test -count=1 /u);
  const selector = goStep.match(/ -run '([^']+)' /u)?.[1];
  assert.ok(selector, "the Go gate must declare its bounded test selector");
  const selected = new RegExp(selector, "u");
  const postgresDirectory = resolve(root, "services/api/internal/postgres");
  const sources = await Promise.all(
    (await readdir(postgresDirectory))
      .filter((name) => name.endsWith("_test.go"))
      .map((name) => readFile(resolve(postgresDirectory, name), "utf8")),
  );
  const tests = sources.flatMap((source) =>
    [...source.matchAll(/^func (Test\w+)\(t \*testing\.T\)/gmu)].map(
      (match) => match[1],
    ),
  );
  const requiredTests = [
    "TestAPIRateLimitRepositoryPostgreSQL",
    "TestDFIRSharedAttachmentsStayPathBoundInPostgres",
    "TestDFIRSharedContentReplacementsPostgreSQL",
    "TestSessionLogoutRepositoryFreshConnectionPostgreSQL",
    ...tests.filter((name) => name.startsWith("TestAuthorizationRepository")),
  ];
  assert.ok(requiredTests.length > 2, "authorization regressions must exist");
  assert.deepEqual(
    tests.filter((name) => selected.test(name)).toSorted(),
    requiredTests.toSorted(),
    "the real Go gate must include all authorization, shared-resource and fresh-connection logout regressions",
  );
  for (const [variable, database] of [
    ["PERIAPSIS_API_RATE_LIMIT_TEST_DATABASE_URL", "periapsis_api_rate_limit"],
    ["PERIAPSIS_AUTHORIZATION_TEST_DATABASE_URL", "periapsis_go_authorization"],
    [
      "PERIAPSIS_DFIR_SHARED_ATTACHMENTS_TEST_DATABASE_URL",
      "periapsis_go_dfir_shared",
    ],
    [
      "PERIAPSIS_DFIR_SHARED_CONTENT_TEST_DATABASE_URL",
      "periapsis_dfir_shared_content_ci",
    ],
    [
      "PERIAPSIS_SESSION_LOGOUT_TEST_DATABASE_URL",
      "periapsis_session_logout_ci",
    ],
  ]) {
    assert.match(
      goStep,
      new RegExp(
        `^          ${variable}: postgresql://[^\\n]+@127\\.0\\.0\\.1:5432/${database}\\?sslmode=disable$`,
        "mu",
      ),
      `${variable} must be available in the executing Go step`,
    );
    assert.equal(
      [
        ...cloneStep.matchAll(
          new RegExp(`^            ${database}(?: \\\\|; do)$`, "gmu"),
        ),
      ].length,
      1,
      `${database} must be cloned exactly once before the Go gate`,
    );
  }
  assert.ok(steps.indexOf(cloneStep) < steps.indexOf(goStep));
  const pinStep = steps.find((step) =>
    step.startsWith("name: Pin the isolated PostgreSQL test cluster\n"),
  );
  assert.ok(
    pinStep,
    "committing repository tests require a current cluster pin",
  );
  assert.match(pinStep, /^        id: postgres_test_pin$/mu);
  assert.match(
    pinStep,
    /psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d postgres -c 'SHOW data_directory'/u,
  );
  assert.ok(
    pinStep.includes(
      '[[ "$task_data_directory" =~ ^/[a-zA-Z0-9_./-]+$ && "$task_data_directory" != "/" ]]',
    ),
  );
  assert.ok(
    pinStep.includes(
      'printf \'data_directory=%s\\n\' "$task_data_directory" >> "$GITHUB_OUTPUT"',
    ),
  );
  assert.ok(steps.indexOf(pinStep) < steps.indexOf(cloneStep));
  for (const variable of [
    "PERIAPSIS_DFIR_SHARED_CONTENT_EXPECTED_DATA_DIRECTORY",
    "PERIAPSIS_SESSION_LOGOUT_EXPECTED_DATA_DIRECTORY",
  ]) {
    assert.ok(
      goStep.includes(
        `${variable}: \${{ steps.postgres_test_pin.outputs.data_directory }}`,
      ),
    );
  }
  const seedStep = steps.find((step) =>
    step.startsWith("name: Prove idempotent seed authorization auditing\n"),
  );
  assert.ok(
    seedStep && steps.indexOf(cloneStep) < steps.indexOf(seedStep),
    "committing tests must clone the unseeded template",
  );
  const cleanupStep = steps.find((step) =>
    step.startsWith("name: Drop the committed repository test databases\n"),
  );
  assert.ok(
    cleanupStep,
    "owned committed fixtures require unconditional exact-clone cleanup",
  );
  assert.match(cleanupStep, /^        if: \$\{\{ always\(\) \}\}$/mu);
  assert.doesNotMatch(cleanupStep, /continue-on-error/u);
  assert.ok(steps.indexOf(cleanupStep) > steps.indexOf(goStep));
  assert.match(
    cleanupStep,
    /for database in periapsis_dfir_shared_content_ci periapsis_session_logout_ci; do/u,
  );
  assert.match(cleanupStep, /dropdb -U postgres --if-exists "\$\{database\}"/u);
  assert.ok(
    cleanupStep.includes(
      "SELECT count(*) FROM pg_database WHERE datname IN ('periapsis_dfir_shared_content_ci','periapsis_session_logout_ci')",
    ),
  );
  assert.ok(cleanupStep.includes('[[ "$task_remaining" == "0" ]]'));
});
