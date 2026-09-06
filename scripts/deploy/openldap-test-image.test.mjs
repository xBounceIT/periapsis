import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const auth = join(root, "deploy/compose/auth");
const bootstrap = join(auth, "openldap-bootstrap.sh");
const shell =
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
const source = (path) =>
  readFile(join(root, path), "utf8").then((text) =>
    text.replaceAll("\r\n", "\n"),
  );

// Use real Bash and filesystem operations. Only
// Linux ownership and the unavailable slap* executables are simulated here.
const harness = `
source "$1"
fixture=$2
id() { printf '%s\n' "\${TEST_UID:-10001}"; }
stat() {
  if [[ $2 == '%u:%g:%a' ]]; then
    if [[ $3 == */server.key ]]; then printf '10001:10001:400';
    elif [[ -d $3 ]]; then printf '10001:10001:%s' "\${TEST_MODE:-700}";
    else printf '10001:10001:600'; fi
  else command stat "$@"; fi
}
slappasswd() {
  [[ $1 == -h && $2 == '{SSHA}' && $3 == -T && $4 == "$fixture/password" && $# == 4 ]]
  printf 'hash\n' >>"$fixture/calls"
  cat "$fixture/generated-hash"
}
slapadd() {
  [[ $1 == -n && $3 == -F && $4 == "$fixture/storage/config" && $5 == -l && $# == 6 ]]
  printf 'import:%s\n' "$2" >>"$fixture/calls"
  if [[ \${TEST_FAIL:-} == "import:$2" ]]; then
    printf 'raw-private-tool-output-must-not-escape\n' >&2
    return 1
  fi
  if [[ $2 == 0 ]]; then cp "$6" "$fixture/storage/config/imported.ldif"; fi
}
slaptest() {
  [[ $1 == -u && $2 == -F && $3 == "$fixture/storage/config" && $# == 3 ]]
  printf 'validate\n' >>"$fixture/calls"
  [[ \${TEST_FAIL:-} != validate ]]
}
ldap_bootstrap "$fixture/storage" "$fixture/runtime" "$fixture/assets" "$fixture/password" "$fixture/schema" "$fixture/tls"
`;

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), "periapsis-ldap-test-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await Promise.all(
    ["storage", "runtime", "assets", "schema", "tls"].map((name) =>
      mkdir(join(directory, name)),
    ),
  );
  const password = randomBytes(40).toString("base64");
  await Promise.all([
    writeFile(join(directory, "password"), password),
    writeFile(
      join(directory, "generated-hash"),
      `{SSHA}${randomBytes(28).toString("base64")}`,
    ),
    ...["ca.crt", "server.crt", "server.key"].map((name) =>
      writeFile(join(directory, "tls", name), "filesystem-presence-only"),
    ),
    ...["core", "cosine", "inetorgperson"].map((name) =>
      writeFile(
        join(directory, "schema", `${name}.ldif`),
        `dn: cn=${name},cn=schema,cn=config\nobjectClass: olcSchemaConfig\ncn: ${name}\n`,
      ),
    ),
    ...["config", "database", "tree"].map(async (name) =>
      writeFile(
        join(directory, "assets", `openldap-${name}.ldif`),
        await source(`deploy/compose/auth/openldap-${name}.ldif`),
      ),
    ),
  ]);
  return { directory, password };
}

function run(directory, extra = {}) {
  const result = spawnSync(
    shell,
    [
      "--noprofile",
      "--norc",
      "-c",
      harness,
      "ldap-bootstrap-test",
      bashPath(bootstrap),
      bashPath(directory),
    ],
    {
      encoding: "utf8",
      timeout: 5000,
      killSignal: "SIGKILL",
      windowsHide: true,
      maxBuffer: 32768,
      env: {
        ...process.env,
        ...extra,
        BASH_ENV: "",
        ENV: "",
        PATH: process.platform === "win32" ? "/usr/bin:/bin" : process.env.PATH,
      },
    },
  );
  assert.equal(
    result.error,
    undefined,
    "Bash/bootstrap commands must finish within the bounded test",
  );
  assert.equal(result.signal, null);
  return result;
}

test("OpenLDAP image fixes numeric identity at build time and never uses root bootstrap", async () => {
  const dockerfile = await source("deploy/compose/Dockerfile.openldap-test");
  const script = await source("deploy/compose/auth/openldap-bootstrap.sh");
  assert.match(
    dockerfile,
    /ARG OPENLDAP_IMAGE=vegardit\/openldap:2\.6\.10@sha256:8161e8fa74c518697776fff27b403cc4c273aede07b6d87f473a45201050d0de/u,
  );
  assert.match(dockerfile, /USER 10001:10001\nEXPOSE 1389 1636/u);
  assert.match(dockerfile, /FROM scratch\nCOPY --from=prepared \/ \/\n/u);
  assert.doesNotMatch(dockerfile, /^VOLUME\b/mu);
  assert.match(
    dockerfile,
    /org\.opencontainers\.image\.licenses="UNLICENSED"/u,
  );
  assert.match(
    dockerfile,
    /ENTRYPOINT .*"-u", "BASH_ENV", "-u", "ENV".*"--noprofile", "--norc"/u,
  );
  assert.doesNotMatch(
    script,
    /\b(?:chown|chmod|usermod|groupmod|setpriv|runuser|su-exec)\b|source \/opt\/|slapd[^\n]+ -[ug] /u,
  );
  assert.match(
    script,
    /exec slapd -d 0 -F "\$storage\/config" -h 'ldap:\/\/0\.0\.0\.0:1389\/ ldaps:\/\/0\.0\.0\.0:1636\/'/u,
  );
  assert.doesNotMatch(script, /openssl dgst|sha1|sha256|ldap_verify_password/u);
});

test("Compose, its env, both workloads, smoke and integration use exact unprivileged LDAP ports", async () => {
  const compose = await source("deploy/compose/compose.yaml");
  const ldap = compose
    .split("\n  openldap:\n")[1]
    .split(/^  [a-z][a-z-]*:\n/mu)[0];
  assert.match(ldap, /dockerfile: deploy\/compose\/Dockerfile\.openldap-test/u);
  assert.match(
    ldap,
    /user: "10001:10001"\n    read_only: true\n    cap_drop:\n      - ALL/u,
  );
  assert.match(ldap, /no-new-privileges:true/u);
  assert.doesNotMatch(
    ldap,
    /cap_add:|sysctls:|ports:|openldap_config:|\/etc\/ldap\/slapd\.d|\/var\/lib\/ldap/u,
  );
  assert.match(ldap, /openldap_data:\/var\/lib\/periapsis-ldap/u);
  assert.match(ldap, /\/run\/periapsis-ldap:uid=10001,gid=10001,mode=0700/u);
  assert.match(ldap, /- -ZZ\n        - -H\n        - ldap:\/\/openldap:1389/u);
  assert.match(ldap, /- -y\n        - \/run\/secrets\/ldap-admin-password/u);
  assert.match(ldap, /start_period: 20s/u);
  assert.match(ldap, /retries: 12/u);
  assert.equal(
    (
      compose.match(
        /PERIAPSIS_LDAP_STARTTLS_PORTS:\s+\$\{PERIAPSIS_LDAP_STARTTLS_PORTS:-1389\}/gu,
      ) ?? []
    ).length,
    2,
  );
  assert.equal(
    (
      compose.match(
        /PERIAPSIS_LDAP_LDAPS_PORTS:\s+\$\{PERIAPSIS_LDAP_LDAPS_PORTS:-1636\}/gu,
      ) ?? []
    ).length,
    2,
  );
  const example = await source("deploy/compose/.env.example");
  assert.match(example, /^PERIAPSIS_LDAP_STARTTLS_PORTS=1389$/mu);
  assert.match(example, /^PERIAPSIS_LDAP_LDAPS_PORTS=1636$/mu);
  assert.match(
    await source("deploy/compose/auth/openldap-acceptance-fixture.sh"),
    /directory_uri="ldaps:\/\/openldap:1636"/u,
  );
  assert.match(
    await source("tests/integration/ldap-auth-acceptance.mjs"),
    /host: "openldap",\n    port: 1636,/u,
  );
  const workflow = await source(".github/workflows/deployment-security.yml");
  assert.match(workflow, /up --build --wait openldap identity-provider/u);
  assert.match(workflow, /exec -T openldap id -u/u);
  assert.match(workflow, /json \.Config\.Volumes/u);
  assert.match(workflow, /-ZZ -H ldap:\/\/openldap:1389/u);
  assert.match(workflow, /-H ldaps:\/\/openldap:1636/u);
  assert.match(
    workflow,
    /if "\$\{compose\[@\]\}" exec -T openldap ldapsearch .* -H ldap:\/\/openldap:1389/u,
  );
  assert.match(
    workflow,
    /node --test scripts\/deploy\/openldap-test-image\.test\.mjs/u,
  );
  assert.doesNotMatch(workflow, /openldap:(?:389|636)\b/u);
});

test("fixed LDAP configuration requires encryption, denies anonymous/config access, and contains no users", async () => {
  const config = await source("deploy/compose/auth/openldap-config.ldif");
  const database = await source("deploy/compose/auth/openldap-database.ldif");
  const tree = await source("deploy/compose/auth/openldap-tree.ldif");
  assert.match(config, /^olcSecurity: ssf=128 simple_bind=128$/mu);
  assert.match(config, /^olcDisallows: bind_anon$/mu);
  assert.match(config, /^olcTLSProtocolMin: 3\.3$/mu);
  assert.match(
    config,
    /^olcTLSCertificateKeyFile: \/run\/secrets\/ldap\/server\.key$/mu,
  );
  assert.match(
    database,
    /olcDatabase: \{0\}config\nolcAccess: \{0\}to \* by \* none/u,
  );
  assert.match(
    database,
    /to attrs=userPassword by self write by anonymous auth by \* none/u,
  );
  assert.match(database, /olcRootDN: uid=admin,DC=periapsis,DC=test/u);
  assert.equal((tree.match(/^dn:/gmu) ?? []).length, 1);
  assert.doesNotMatch(tree, /userPassword|inetOrgPerson|uid:|groupOfNames/u);
});

test("bootstrap imports one configuration and an empty account tree; restart preserves all state", async (t) => {
  const { directory, password } = await fixture(t);
  const first = run(directory);
  assert.equal(first.status, 0, first.stderr);
  assert.equal((first.stdout + first.stderr).includes(password), false);
  const config = await readFile(
    join(directory, "storage/config/imported.ldif"),
    "utf8",
  );
  const records = config.trim().split(/\n\s*\n/u);
  assert.match(records.at(-1), /^dn: olcDatabase=\{1\}mdb,cn=config\n/u);
  assert.match(records.at(-1), /^olcRootPW: \{SSHA\}[A-Za-z0-9+/]+=*$/mu);
  assert.equal(
    (await readFile(join(directory, "calls"), "utf8")).split("import:").length -
      1,
    2,
  );
  const second = run(directory);
  assert.equal(second.status, 0, second.stderr);
  assert.equal(
    await readFile(join(directory, "storage/config/imported.ldif"), "utf8"),
    config,
  );
  assert.equal(
    (await readFile(join(directory, "calls"), "utf8")).split("import:").length -
      1,
    2,
  );
  assert.deepEqual(await readdir(join(directory, "runtime")), []);
});

test("changed mounted password never rotates or reseeds; real LDAP health remains the verifier", async (t) => {
  const { directory } = await fixture(t);
  assert.equal(run(directory).status, 0);
  const before = await readFile(join(directory, "storage/rootpw"));
  const beforeConfig = await readFile(
    join(directory, "storage/config/imported.ldif"),
  );
  await writeFile(
    join(directory, "password"),
    randomBytes(40).toString("base64"),
  );
  const result = run(directory);
  assert.equal(result.status, 0);
  assert.equal(result.stderr, "");
  assert.deepEqual(await readFile(join(directory, "storage/rootpw")), before);
  assert.deepEqual(
    await readFile(join(directory, "storage/config/imported.ldif")),
    beforeConfig,
  );
  assert.deepEqual(await readdir(join(directory, "runtime")), []);
});

for (const [label, extra, stage] of [
  ["root identity", { TEST_UID: "0" }, "identity"],
  ["world-readable storage", { TEST_MODE: "755" }, "storage"],
  ["configuration import failure", { TEST_FAIL: "import:0" }, "config_import"],
  ["tree import failure", { TEST_FAIL: "import:1" }, "tree_import"],
  [
    "configuration validation failure",
    { TEST_FAIL: "validate" },
    "config_validation",
  ],
]) {
  test(`bootstrap rejects ${label} and withholds raw tool errors`, async (t) => {
    const { directory } = await fixture(t);
    const result = run(directory, extra);
    assert.equal(result.status, 1);
    assert.equal(
      result.stderr.trim(),
      `PERIAPSIS_OPENLDAP_ERROR stage=${stage}`,
    );
    assert.doesNotMatch(result.stdout + result.stderr, /raw-private/u);
    assert.ok(
      !(await readdir(join(directory, "storage"))).includes("initialized"),
    );
    assert.deepEqual(await readdir(join(directory, "runtime")), []);
  });
}

test("legacy/partial state and malformed persisted hashes never trigger an automatic reset", async (t) => {
  const { directory } = await fixture(t);
  await writeFile(join(directory, "storage/foreign-data"), randomBytes(32));
  assert.equal(
    run(directory).stderr.trim(),
    "PERIAPSIS_OPENLDAP_ERROR stage=existing_state",
  );
  assert.deepEqual(await readdir(join(directory, "storage")), ["foreign-data"]);
  await rm(join(directory, "storage/foreign-data"));
  assert.equal(run(directory).status, 0);
  await writeFile(
    join(directory, "storage/rootpw"),
    "{SSHA}not-canonical\nextra-line",
  );
  assert.equal(
    run(directory).stderr.trim(),
    "PERIAPSIS_OPENLDAP_ERROR stage=existing_state",
  );
});

for (const [name, value] of [
  ["empty", ""],
  ["LF", "line\n"],
  ["CR", "line\r"],
  ["NUL", "line\0"],
  ["oversized", "x".repeat(65_537)],
]) {
  test(`bootstrap rejects a ${name} password file before hashing or writes`, async (t) => {
    const { directory } = await fixture(t);
    await writeFile(join(directory, "password"), value);
    const result = run(directory);
    assert.equal(result.status, 1);
    assert.equal(
      result.stderr.trim(),
      "PERIAPSIS_OPENLDAP_ERROR stage=password_file",
    );
    assert.deepEqual(await readdir(join(directory, "storage")), []);
    assert.deepEqual(await readdir(join(directory, "runtime")), []);
  });
}

test("bootstrap requires mounted TLS material before any directory initialization", async (t) => {
  const { directory } = await fixture(t);
  await rm(join(directory, "tls/server.key"));
  const result = run(directory);
  assert.equal(result.status, 1);
  assert.equal(result.stderr.trim(), "PERIAPSIS_OPENLDAP_ERROR stage=tls");
  assert.deepEqual(await readdir(join(directory, "storage")), []);
});
