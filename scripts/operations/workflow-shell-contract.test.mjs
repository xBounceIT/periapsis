import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const security = (
  await readFile(
    new URL("../../.github/workflows/deployment-security.yml", import.meta.url),
    "utf8",
  )
).replaceAll("\r\n", "\n");
const performance = (
  await readFile(
    new URL(
      "../../.github/workflows/ticketing-performance.yml",
      import.meta.url,
    ),
    "utf8",
  )
).replaceAll("\r\n", "\n");

function job(source, name) {
  const marker = `\n  ${name}:\n`;
  assert.equal(source.split(marker).length, 2, `${name} must appear once`);
  const tail = source.slice(source.indexOf(marker) + marker.length);
  const end = tail.search(/^  [a-z][a-z-]*:\n/mu);
  return end < 0 ? tail : tail.slice(0, end);
}

function step(source, name) {
  const marker = `      - name: ${name}\n`;
  assert.equal(source.split(marker).length, 2, `${name} must appear once`);
  const tail = source.slice(source.indexOf(marker) + marker.length);
  const end = tail.indexOf("\n      - name:");
  return end < 0 ? tail : tail.slice(0, end);
}

function script(source) {
  const match = /\n        run: (?:\||>-)\n([\s\S]+)$/u.exec(`\n${source}`);
  assert.ok(match, "the checked shell script must be a YAML block scalar");
  return match[1]
    .split("\n")
    .map((line) => line.replace(/^ {10}/u, ""))
    .join("\n")
    .trim();
}

for (const name of ["application-images", "notifier-image"]) {
  test(`${name} exports the pinned daemon socket before scanners run`, () => {
    const imageJob = job(security, name);
    const dockerSetup = step(imageJob, "Set up pinned Docker Engine and CLI");
    assert.match(
      dockerSetup,
      /uses: docker\/setup-docker-action@77e84dbf09b47d1e29270283c22f16145aa85ca1\b/u,
    );
    assert.match(dockerSetup, /^          version: v28\.5\.2$/mu);
    assert.match(dockerSetup, /^          set-host: true$/mu);
    assert.ok(
      imageJob.indexOf("Set up pinned Docker Engine and CLI") <
        imageJob.indexOf("${RUNNER_TEMP}/syft"),
    );
    assert.doesNotMatch(imageJob, /^\s+DOCKER_HOST:/mu);
    assert.match(imageJob, /--exit-code 1\s+\\\n/u);
    assert.match(imageJob, /--severity HIGH,CRITICAL\s+\\\n/u);
    assert.match(imageJob, /--scanners vuln,secret\s+\\\n/u);
  });
}

test("history scanning quotes the executable and retains redacted full-history scanning", () => {
  const secretsJob = job(security, "secrets");
  assert.match(secretsJob, /fetch-depth: 0/u);
  assert.equal(
    script(step(secretsJob, "Scan Git history with redacted output")),
    '"${RUNNER_TEMP}/gitleaks" detect --source . --redact --no-banner --verbose',
  );
});

test("SBOM generation keeps executable, image and output as quoted shell arguments", () => {
  assert.equal(
    script(step(job(security, "application-images"), "Generate SPDX SBOM")),
    '"${RUNNER_TEMP}/syft" "docker:${IMAGE}" --output "spdx-json=${RUNNER_TEMP}/${{ matrix.name }}.spdx.json"',
  );
});

test("LDAP DNs remain single arguments and only the container script defers expansion", () => {
  const probe = script(
    step(
      job(security, "manifests"),
      "Smoke-test local LDAP, OIDC, and SAML providers",
    ),
  );
  assert.match(
    probe,
    /^common=\(-LLL -x -D "uid=admin,DC=periapsis,DC=test" -y \/run\/secrets\/ldap-admin-password -b "DC=periapsis,DC=test"\)$/mu,
  );
  assert.equal((security.match(/shellcheck disable=/gu) ?? []).length, 1);
  assert.match(
    probe,
    /# Expand probe variables only inside the container's Bash process\.\n  # shellcheck disable=SC2016\n  "\$\{compose\[@\]\}" exec -T identity-provider bash -ceu '/u,
  );
  assert.match(
    probe,
    /' probe-identity-provider "\$\{path\}" "\$\{expected\}"/u,
  );
  assert.match(
    step(job(security, "manifests"), "Validate workflow syntax"),
    /^        run: actionlint$/mu,
  );
});

test("the performance build quotes revision and the complete image tag", () => {
  const build = script(step(performance, "Build the pinned disposable gate"));
  assert.match(build, /--build-arg "REVISION=\$\{GITHUB_SHA\}"/u);
  assert.match(
    build,
    /--tag "periapsis-performance:\$\{GITHUB_RUN_ID\}-\$\{GITHUB_RUN_ATTEMPT\}"/u,
  );
});

test("the performance run quotes its name, image and evidence mount", () => {
  const run = script(
    step(performance, "Run hot paths against a fresh database"),
  );
  assert.match(
    run,
    /--name "periapsis-performance-\$\{GITHUB_RUN_ID\}-\$\{GITHUB_RUN_ATTEMPT\}"/u,
  );
  assert.match(
    run,
    /--volume "\$\{GITHUB_WORKSPACE\}\/tmp\/performance:\/workspace\/tmp\/performance"/u,
  );
  assert.match(
    run,
    /\n  "periapsis-performance:\$\{GITHUB_RUN_ID\}-\$\{GITHUB_RUN_ATTEMPT\}"$/u,
  );
  assert.match(run, /--rm --init --stop-timeout 120/u);
});

test("the disposable performance process is non-root with only explicit writable mounts", () => {
  const run = script(
    step(performance, "Run hot paths against a fresh database"),
  );
  assert.match(run, /--read-only --user 10001:10001/u);
  assert.match(run, /--cap-drop ALL --security-opt no-new-privileges/u);
  assert.match(
    run,
    /--tmpfs \/tmp:rw,nosuid,nodev,uid=10001,gid=10001,mode=1770/u,
  );
  assert.match(
    run,
    /sudo chown 10001:10001 "\$\{GITHUB_WORKSPACE\}\/tmp\/performance"/u,
  );
  const cleanup = step(
    performance,
    "Return evidence ownership to the artifact uploader",
  );
  assert.match(cleanup, /if: \$\{\{ always\(\) \}\}/u);
  assert.match(script(cleanup), /test ! -L "\$\{evidence_directory\}"/u);
  assert.match(
    script(cleanup),
    /test "\$\(realpath "\$\{evidence_directory\}"\)" = "\$\{GITHUB_WORKSPACE\}\/tmp\/performance"/u,
  );
  assert.match(
    script(cleanup),
    /sudo chown -R --no-dereference "\$\(id -u\):\$\(id -g\)" "\$\{evidence_directory\}"/u,
  );
  assert.ok(
    performance.indexOf("Return evidence ownership") <
      performance.indexOf("Retain immutable performance evidence"),
  );
  assert.doesNotMatch(cleanup, /chmod|0777|0644/u);
});

test("both Compose workflows prepare file-backed secrets before the first authenticated profile start", async () => {
  const ci = await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  );
  for (const [source, startup] of [
    [security, "Validate Compose profiles and Swarm model"],
    [ci, "Validate resolved Compose model"],
  ]) {
    const prepare = step(source, "Prepare private file-backed Compose secrets");
    assert.match(prepare, /node scripts\/deploy\/prepare-compose-secrets.mjs/u);
    assert.ok(
      source.indexOf("Prepare private file-backed Compose secrets") <
        source.indexOf(startup),
    );
    assert.match(
      source,
      /PERIAPSIS_COMPOSE_SECRETS_DIR="?\$\{RUNNER_TEMP\}\/periapsis-compose-secrets/u,
    );
  }
});

test("dependency-free secret preparation disables automatic package-manager caching", () => {
  const setup = step(
    job(security, "manifests"),
    "Install Node.js for secret preparation",
  );
  assert.match(
    setup,
    /^        uses: actions\/setup-node@a0853c24544627f65ddf259abe73b1d18a591444 # v5$/mu,
  );
  assert.match(setup, /^          package-manager-cache: false$/mu);
  // An explicit cache input takes precedence over the automatic-cache opt-out.
  assert.doesNotMatch(setup, /^          cache:/mu);
});

test("authentication teardown requires prepared secrets but still runs after smoke failure", () => {
  const manifests = job(security, "manifests");
  const prepare = step(
    manifests,
    "Prepare private file-backed Compose secrets",
  );
  assert.match(prepare, /^        id: prepare-compose-secrets$/mu);
  assert.doesNotMatch(prepare, /^        continue-on-error:/mu);
  const teardown = step(manifests, "Tear down authentication smoke profile");
  assert.match(
    teardown,
    /^        if: \$\{\{ always\(\) && steps\.prepare-compose-secrets\.outcome == 'success' \}\}$/mu,
  );
  assert.match(
    teardown,
    /^        run: docker compose --file deploy\/compose\/compose.yaml --profile auth-test down --volumes --remove-orphans$/mu,
  );
  const prepareIndex = manifests.indexOf(
    "Prepare private file-backed Compose secrets",
  );
  const smokeIndex = manifests.indexOf(
    "Smoke-test local LDAP, OIDC, and SAML providers",
  );
  const teardownIndex = manifests.indexOf(
    "Tear down authentication smoke profile",
  );
  assert.ok(prepareIndex < smokeIndex && smokeIndex < teardownIndex);
});

test("full-history secret scanning executes positive controls with the verified binary", () => {
  const secrets = job(security, "secrets");
  assert.match(step(secrets, "Check out full history"), /fetch-depth: 0/u);
  const setup = step(secrets, "Install Node.js for secret-scan controls");
  assert.match(setup, /^          package-manager-cache: false$/mu);
  assert.doesNotMatch(setup, /^          cache:/mu);
  const installation = step(secrets, "Install checksum-verified Gitleaks");
  assert.match(installation, /sha256sum --check/u);
  assert.match(
    installation,
    /v8\.30\.1\/gitleaks_8\.30\.1_linux_x64\.tar\.gz/u,
  );
  const controls = step(
    secrets,
    "Verify exact historical exceptions and fresh-secret detection",
  );
  assert.match(
    controls,
    /^          PERIAPSIS_GITLEAKS_BINARY: \$\{\{ runner\.temp \}\}\/gitleaks$/mu,
  );
  assert.match(
    controls,
    /^        run: node --test scripts\/deploy\/gitleaks-history\.test\.mjs$/mu,
  );
  assert.doesNotMatch(controls, /^        (?:if|continue-on-error):/mu);
  assert.ok(
    secrets.indexOf("Install checksum-verified Gitleaks") <
      secrets.indexOf("Verify exact historical exceptions"),
  );
  assert.ok(
    secrets.indexOf("Verify exact historical exceptions") <
      secrets.indexOf("Scan Git history with redacted output"),
  );
});
