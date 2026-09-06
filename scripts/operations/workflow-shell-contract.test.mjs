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
