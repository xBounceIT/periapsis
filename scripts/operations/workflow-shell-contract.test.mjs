import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

const ci = (
  await readFile(
    new URL("../../.github/workflows/ci.yml", import.meta.url),
    "utf8",
  )
).replaceAll("\r\n", "\n");
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

const credentialGeneration = script(
  step(ci, "Generate ephemeral integration credentials"),
);
const credentialFunctions = ["mask_secret", "publish_secret"]
  .map((name) => {
    const match = new RegExp(`^${name}\\(\\) \\{\\n[\\s\\S]*?^\\}`, "mu").exec(
      credentialGeneration,
    );
    assert.ok(match, `${name} must remain an inspectable workflow function`);
    return match[0];
  })
  .join("\n");
const secretNames = [
  "PERIAPSIS_API_DATABASE_PASSWORD",
  "PERIAPSIS_API_CREDENTIAL_KEYRING",
  "PERIAPSIS_BOOTSTRAP_TOKEN",
  "PERIAPSIS_IDENTITY_KEYRING",
  "PERIAPSIS_IDP_ADMIN_PASSWORD",
  "PERIAPSIS_LDAP_ACCEPTANCE_CUSTOMER_PASSWORD",
  "PERIAPSIS_LDAP_ACCEPTANCE_ISOLATION_PASSWORD",
  "PERIAPSIS_LDAP_ACCEPTANCE_SECOND_USER_PASSWORD",
  "PERIAPSIS_LDAP_ACCEPTANCE_USER_PASSWORD",
  "PERIAPSIS_LDAP_ADMIN_PASSWORD",
  "PERIAPSIS_MASTER_KEY",
  "PERIAPSIS_MINIO_ROOT_PASSWORD",
  "PERIAPSIS_MINIO_ROOT_USER",
  "PERIAPSIS_MINIO_KMS_SECRET_KEY",
  "PERIAPSIS_NOTIFIER_DATABASE_PASSWORD",
  "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN",
  "PERIAPSIS_NOTIFICATION_KEYRING",
  "PERIAPSIS_POSTGRES_PASSWORD",
  "PERIAPSIS_S3_ACCESS_KEY",
  "PERIAPSIS_S3_SECRET_KEY",
  "PERIAPSIS_SMOKE_ADMIN_PASSWORD",
  "PERIAPSIS_WORKER_DATABASE_PASSWORD",
];
const bash =
  process.platform === "win32"
    ? join(
        process.env.ProgramFiles ?? "C:/Program Files",
        "Git/usr/bin/bash.exe",
      )
    : "/bin/bash";
const bashPath = (path) =>
  path
    .replaceAll("\\", "/")
    .replace(/^([A-Za-z]):/u, (_, drive) => `/${drive.toLowerCase()}`);

test("Mailpit publication preflight requires both actual loopback bindings before delivery", () => {
  const smtpJob = job(ci, "smtp-mailpit-acceptance");
  const preflight = script(
    step(smtpJob, "Verify loopback SMTP and HTTP publication"),
  );
  assert.ok(
    smtpJob.indexOf("Verify loopback SMTP and HTTP publication") <
      smtpJob.indexOf("Probe, deliver, and inspect the captured message"),
  );
  assert.ok(
    smtpJob.indexOf("Start the full-profile SMTP fixture") <
      smtpJob.indexOf("Verify loopback SMTP and HTTP publication"),
  );
  const dockerFixture = `
docker() {
  if [[ "$*" == 'compose --file deploy/compose/compose.yaml --profile full port mailpit 1025' ]]; then
    [[ "\${FAIL_SMTP:-0}" == 0 ]] || return 17
    printf '%s\\n' "$SMTP_BINDING"
  elif [[ "$*" == 'compose --file deploy/compose/compose.yaml --profile full port mailpit 8025' ]]; then
    printf '%s\\n' "$HTTP_BINDING"
  else
    return 19
  fi
}
`;
  for (const [name, extra, success] of [
    ["exact overridden loopback ports", {}, true],
    ["SMTP not published", { SMTP_BINDING: "" }, false],
    ["HTTP not published", { HTTP_BINDING: "" }, false],
    ["SMTP wildcard bind", { SMTP_BINDING: "0.0.0.0:21025" }, false],
    ["HTTP wildcard bind", { HTTP_BINDING: "0.0.0.0:28025" }, false],
    ["wrong SMTP port", { SMTP_BINDING: "127.0.0.1:11025" }, false],
    ["Docker command failed", { FAIL_SMTP: "1" }, false],
  ]) {
    const result = spawnSync(
      bash,
      ["--noprofile", "--norc", "-c", `${dockerFixture}\n${preflight}`],
      {
        encoding: "utf8",
        timeout: 5000,
        killSignal: "SIGKILL",
        windowsHide: true,
        maxBuffer: 8192,
        env: {
          PATH:
            process.platform === "win32" ? "/usr/bin:/bin" : process.env.PATH,
          SystemRoot: process.env.SystemRoot,
          BASH_ENV: "",
          ENV: "",
          PERIAPSIS_MAILPIT_SMTP_PORT: "21025",
          PERIAPSIS_MAILPIT_PORT: "28025",
          SMTP_BINDING: "127.0.0.1:21025",
          HTTP_BINDING: "127.0.0.1:28025",
          ...extra,
        },
      },
    );
    assert.equal(result.error, undefined, name);
    assert.equal(result.signal, null, name);
    assert.equal(result.status === 0, success, name);
    assert.equal(result.stdout, "", name);
    assert.equal(result.stderr, "", name);
  }
});

// Execute the actual Bash functions. Observe printf at the call boundary so a
// removed or late mask fails before the corresponding environment line is written.
const orderedMaskHarness = `
observed_masks=()
printf() {
  local format="$1"
  shift
  if [[ "\${format}" == '::add-mask::%s\\n' ]]; then
    [[ "\${MASK_WRITE_FAIL:-0}" != 1 ]] || return 1
    observed_masks+=("$@")
  elif [[ "\${format}" == '%s=%s\\n' ]]; then
    [[ $# == 2 && \${#observed_masks[@]} -gt 0 ]] || return 91
    [[ "\${observed_masks[-1]}" == "\${2//%/%25}" ]] || return 92
  fi
  builtin printf "\${format}" "$@"
}
`;

async function runCredentialShell(t, source, extra = {}) {
  const directory = await mkdtemp(
    join(tmpdir(), "periapsis-workflow-mask-test-"),
  );
  t.after(() => rm(directory, { recursive: true, force: true }));
  const envFile = join(directory, "github-env");
  await writeFile(envFile, "EXISTING_NON_SECRET=unchanged\n");
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(
      ([name]) =>
        !/^(?:PERIAPSIS_|GITHUB_|RUNNER_|BASH_FUNC_|SHELLOPTS$|BASHOPTS$)/u.test(
          name,
        ),
    ),
  );
  const result = spawnSync(
    bash,
    [
      "--noprofile",
      "--norc",
      "-c",
      `set -euo pipefail\n${orderedMaskHarness}\n${source}`,
    ],
    {
      encoding: "utf8",
      timeout: 5000,
      killSignal: "SIGKILL",
      windowsHide: true,
      maxBuffer: 32_768,
      env: {
        ...environment,
        BASH_ENV: "",
        ENV: "",
        PATH: process.platform === "win32" ? "/usr/bin:/bin" : process.env.PATH,
        GITHUB_ENV: bashPath(envFile),
        RUNNER_TEMP: bashPath(directory),
        PERIAPSIS_IMAGE_TAG: "fixture-image-tag",
        ...extra,
      },
    },
  );
  assert.ok(
    !result.error,
    "the real Bash fixture must finish within its bound",
  );
  assert.equal(result.signal, null);
  assert.ok(result.stderr === "", "no raw failure detail may be emitted");
  const published = await readFile(envFile, "utf8");
  assert.ok(published.startsWith("EXISTING_NON_SECRET=unchanged\n"));
  return {
    result,
    published: published.slice("EXISTING_NON_SECRET=unchanged\n".length),
  };
}

test("Compose generation masks all 22 secrets and three keyring components before environment publication", async (t) => {
  const start = credentialGeneration.indexOf(
    'api_credential_root="$(openssl rand',
  );
  assert.ok(start > 0);
  const generation = credentialGeneration.slice(start);
  assert.deepEqual(
    [...generation.matchAll(/^publish_secret (PERIAPSIS_[A-Z0-9_]+) /gmu)].map(
      (match) => match[1],
    ),
    secretNames,
  );
  assert.doesNotMatch(credentialGeneration, /set -[^\n]*x|set -o xtrace/u);
  assert.ok(
    ci.indexOf("Generate ephemeral integration credentials") <
      ci.indexOf("Prepare private file-backed Compose secrets"),
  );
  const { result, published } = await runCredentialShell(
    t,
    `${credentialFunctions}\ntls_directory="\${RUNNER_TEMP}/periapsis-compose-tls"\n${generation}`,
  );
  assert.equal(result.status, 0);
  const entries = published
    .trimEnd()
    .split("\n")
    .map((line) => {
      const separator = line.indexOf("=");
      return [line.slice(0, separator), line.slice(separator + 1)];
    });
  assert.equal(entries.length, 28);
  const values = Object.fromEntries(entries);
  assert.match(
    values.PERIAPSIS_MINIO_KMS_SECRET_KEY,
    /^ci-export:[A-Za-z0-9+/]{43}=$/u,
  );
  const masks = result.stdout
    .trimEnd()
    .split("\n")
    .map((line) => {
      assert.ok(
        line.startsWith("::add-mask::"),
        "stdout may contain only masking commands",
      );
      return line.slice("::add-mask::".length);
    });
  assert.equal(masks.length, 25);
  for (const name of secretNames) {
    assert.ok(values[name]?.length > 0, `${name} must be published`);
    assert.equal(
      masks.filter((mask) => mask === values[name]).length,
      1,
      `${name} must be masked exactly once with unchanged bytes`,
    );
  }
  for (const [index, name] of [
    "PERIAPSIS_API_CREDENTIAL_KEYRING",
    "PERIAPSIS_IDENTITY_KEYRING",
    "PERIAPSIS_NOTIFICATION_KEYRING",
  ].entries()) {
    let envelope;
    try {
      envelope = JSON.parse(values[name]);
    } catch {
      assert.fail("generated keyring must be valid JSON");
    }
    assert.ok(
      JSON.stringify(envelope) === values[name],
      "keyring JSON must remain compact and unchanged",
    );
    assert.ok(envelope?.activeVersion === 1);
    assert.ok(Array.isArray(envelope.keys) && envelope.keys.length === 1);
    assert.ok(envelope.keys[0]?.version === 1);
    const key = envelope.keys[0].key;
    assert.ok(typeof key === "string");
    assert.ok(
      masks[index] === key,
      "each raw key is masked before the first secret publication",
    );
    assert.equal(
      Buffer.from(key, index === 2 ? "base64url" : "base64").length,
      32,
    );
    assert.ok(
      index === 2
        ? /^[A-Za-z0-9_-]{43}$/u.test(key)
        : /^[A-Za-z0-9+/]{43}=$/u.test(key),
    );
  }
  assert.ok(values.PERIAPSIS_IDP_ADMIN_USERNAME === "admin");
  assert.ok(
    values.PERIAPSIS_NOTIFIER_IMAGE === "periapsis/notifier:fixture-image-tag",
  );
  assert.ok(
    values.PERIAPSIS_COMPOSE_SECRETS_DIR.endsWith("/periapsis-compose-secrets"),
  );
  for (const name of ["CA", "CERT", "KEY"]) {
    assert.ok(
      values[`PERIAPSIS_DEV_TLS_${name}_FILE`].includes(
        "/periapsis-compose-tls/",
      ),
    );
  }
});

test("real Bash masking preserves percent, quotes, whitespace and JSON bytes without command injection", async (t) => {
  const canary = `canary-${randomBytes(24).toString("hex")}: +/= %0A%25 ' \\" $(false) ::warning::`;
  const { result, published } = await runCredentialShell(
    t,
    `${credentialFunctions}\npublish_secret PERIAPSIS_TEST_SECRET "$TEST_CANARY"`,
    { TEST_CANARY: JSON.stringify({ key: canary }) },
  );
  assert.equal(result.status, 0);
  assert.ok(
    published === `PERIAPSIS_TEST_SECRET=${JSON.stringify({ key: canary })}\n`,
    "published bytes must not be escaped or evaluated",
  );
  assert.ok(
    result.stdout ===
      `::add-mask::${JSON.stringify({ key: canary }).replaceAll("%", "%25")}\n`,
    "only workflow command data is escaped",
  );
});

test("invalid or unmaskable secrets are never published by the real Bash function", async (t) => {
  await Promise.all(
    [
      ["PERIAPSIS_TEST_SECRET", ""],
      ["PERIAPSIS_TEST_SECRET", "line\nbreak"],
      ["PERIAPSIS_TEST_SECRET", "line\rbreak"],
      ["GITHUB_ENV", "invalid-name-canary"],
      ["PERIAPSIS_TEST\nNEXT", "invalid-name-canary"],
      ["PERIAPSIS_TEST=value", "invalid-name-canary"],
    ].map(async ([name, value]) => {
      const { result, published } = await runCredentialShell(
        t,
        `${credentialFunctions}\npublish_secret "$TEST_SECRET_NAME" "$TEST_CANARY"`,
        { TEST_SECRET_NAME: name, TEST_CANARY: value },
      );
      assert.equal(result.status, 1);
      assert.ok(published === "", "invalid input must not be published");
      assert.ok(result.stdout === "", "invalid input must not be printed");
    }),
  );
  const { result, published } = await runCredentialShell(
    t,
    `${credentialFunctions}\npublish_secret PERIAPSIS_TEST_SECRET "$TEST_CANARY"`,
    { TEST_CANARY: randomBytes(24).toString("hex"), MASK_WRITE_FAIL: "1" },
  );
  assert.equal(result.status, 1);
  assert.ok(published === "", "failed masking must not publish input");
  assert.ok(result.stdout === "", "failed masking must not print input");
});

test("the Bash order probe rejects an absent or late mask", async (t) => {
  const mutations = [
    credentialFunctions.replace('  mask_secret "${value}" || return 1\n', ""),
    credentialFunctions
      .replace('  mask_secret "${value}" || return 1\n', "")
      .replace(
        ' >> "${GITHUB_ENV}"',
        ' >> "${GITHUB_ENV}"\n  mask_secret "${value}" || return 1',
      ),
  ];
  await Promise.all(
    mutations.map(async (functions) => {
      assert.notEqual(functions, credentialFunctions);
      const { result, published } = await runCredentialShell(
        t,
        `${functions}\npublish_secret PERIAPSIS_TEST_SECRET "$TEST_CANARY"`,
        { TEST_CANARY: randomBytes(24).toString("hex") },
      );
      assert.equal(result.status, 91);
      assert.ok(
        published === "",
        "an absent or late mask must block publication",
      );
      assert.ok(
        result.stdout === "",
        "an absent or late mask must not print input",
      );
    }),
  );
});

test("deployment S3 generation masks credentials and encryption key before the preparer and publishes only its path", async (t) => {
  const prepare = script(
    step(
      job(security, "manifests"),
      "Prepare private file-backed Compose secrets",
    ),
  );
  assert.match(
    prepare,
    /^PERIAPSIS_S3_ACCESS_KEY="ciapp\$\(openssl rand -hex 8\)"$/mu,
  );
  assert.match(
    prepare,
    /^PERIAPSIS_S3_SECRET_KEY="\$\(openssl rand -hex 32\)"$/mu,
  );
  const probe = `
node() {
  [[ $# == 1 && "$1" == scripts/deploy/prepare-compose-secrets.mjs ]]
  [[ \${#observed_masks[@]} == 3 ]]
  [[ "\${observed_masks[0]}" == "\${PERIAPSIS_S3_ACCESS_KEY}" ]]
  [[ "\${observed_masks[1]}" == "\${PERIAPSIS_S3_SECRET_KEY}" ]]
  [[ "\${observed_masks[2]}" == "\${PERIAPSIS_MINIO_KMS_SECRET_KEY}" ]]
  [[ "\${PERIAPSIS_MINIO_KMS_SECRET_KEY}" =~ ^ci-export:[A-Za-z0-9+/]{43}=$ ]]
  export -p | grep -q 'declare -x PERIAPSIS_MINIO_KMS_SECRET_KEY='
}
`;
  const { result, published } = await runCredentialShell(
    t,
    `${probe}\n${prepare}`,
  );
  assert.equal(result.status, 0);
  assert.ok(
    /^PERIAPSIS_COMPOSE_SECRETS_DIR=[^\r\n]+\/periapsis-compose-secrets\n$/u.test(
      published,
    ),
  );
  assert.ok(
    /^::add-mask::ciapp[0-9a-f]{16}\n::add-mask::[0-9a-f]{64}\n::add-mask::ci-export:[A-Za-z0-9+/]{43}=\n$/u.test(
      result.stdout,
    ),
  );
});

for (const name of ["application-images"]) {
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

test("failed LDAP smoke collects bounded redacted diagnostics before unconditional teardown", () => {
  const manifests = job(security, "manifests");
  const smokeName = "Smoke-test local LDAP, OIDC, and SAML providers";
  const diagnosticName =
    "Collect bounded redacted OpenLDAP startup diagnostics";
  const teardownName = "Tear down authentication smoke profile";
  assert.match(
    step(manifests, smokeName),
    /^        id: auth-provider-smoke$/mu,
  );
  const diagnostic = step(manifests, diagnosticName);
  assert.match(
    diagnostic,
    /^        if: \$\{\{ failure\(\) && steps\.auth-provider-smoke\.outcome == 'failure' \}\}$/mu,
  );
  assert.match(diagnostic, /^        timeout-minutes: 1$/mu);
  assert.match(
    diagnostic,
    /^        run: node scripts\/deploy\/openldap-diagnostics\.mjs$/mu,
  );
  assert.ok(manifests.indexOf(smokeName) < manifests.indexOf(diagnosticName));
  assert.ok(
    manifests.indexOf(diagnosticName) < manifests.indexOf(teardownName),
  );
  assert.match(
    step(manifests, teardownName),
    /if: \$\{\{ always\(\) && steps\.prepare-compose-secrets\.outcome == 'success' \}\}/u,
  );
  assert.match(
    step(manifests, "Run dependency-free deployment contract tests"),
    /node --test scripts\/deploy\/openldap-diagnostics\.test\.mjs/u,
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

test("both Compose workflows prepare file-backed secrets before the first authenticated profile start", () => {
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
