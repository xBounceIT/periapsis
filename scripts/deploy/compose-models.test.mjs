import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { BlockList } from "node:net";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const composeDirectory = join(root, "deploy/compose");
const tlsVariables = [
  "PERIAPSIS_DEV_TLS_CERT_FILE",
  "PERIAPSIS_DEV_TLS_KEY_FILE",
  "PERIAPSIS_DEV_TLS_CA_FILE",
];
const proxyVariables = [
  "PERIAPSIS_PUBLIC_URL",
  "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS",
  "PERIAPSIS_S3_PUBLIC_ENDPOINT",
];
const profiles = {
  minimal: [
    "api",
    "clamav",
    "edge",
    "migration",
    "minio",
    "minio-provision",
    "postgres",
    "web",
    "worker",
  ],
  "auth-test": [
    "api",
    "clamav",
    "edge",
    "identity-provider",
    "ldap-tls",
    "migration",
    "minio",
    "minio-provision",
    "openldap",
    "postgres",
    "web",
    "worker",
  ],
  full: [
    "api",
    "clamav",
    "edge",
    "identity-provider",
    "ldap-tls",
    "mailpit",
    "migration",
    "minio",
    "minio-provision",
    "notifier",
    "notifier-provision",
    "openldap",
    "otel-collector",
    "postgres",
    "prometheus",
    "web",
    "worker",
  ],
};
profiles["*"] = [...profiles.full, "db-seed"].toSorted();

async function fixture(t) {
  // Included subprojects can load their own default dotenv independently of the
  // explicit CLI env file. Refuse that local file before invoking Compose.
  let dotenvAbsent = false;
  try {
    await lstat(join(composeDirectory, ".env"));
  } catch (error) {
    assert.ok(
      error?.code === "ENOENT",
      "cannot attest the included project's dotenv isolation",
    );
    dotenvAbsent = true;
  }
  assert.ok(
    dotenvAbsent,
    "move any deploy/compose/.env aside before isolated model tests",
  );
  const directory = await mkdtemp(join(tmpdir(), "periapsis-compose-model-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const envFile = join(directory, "empty.env");
  await writeFile(envFile, "# Configuration-only test; no host dotenv.\n");
  // Never inherit deployment credentials, proxy/TLS settings, COMPOSE_FILE,
  // COMPOSE_PROFILES, or Docker contexts from the invoking user's environment.
  const environment = Object.fromEntries(
    Object.entries(process.env).filter(([name]) =>
      /^(?:PATH|SystemRoot|WINDIR|TEMP|TMP|USERPROFILE|HOMEDRIVE|HOMEPATH|APPDATA|LOCALAPPDATA)$/iu.test(
        name,
      ),
    ),
  );
  Object.assign(environment, {
    DOCKER_HOST: "tcp://127.0.0.1:1",
    PERIAPSIS_COMPOSE_SECRETS_DIR: join(directory, "unread-secrets"),
    PERIAPSIS_API_DATABASE_PASSWORD: "model-only-not-an-account",
    PERIAPSIS_WORKER_DATABASE_PASSWORD: "model-only-not-an-account",
    PERIAPSIS_NOTIFIER_DATABASE_PASSWORD: "model-only-not-an-account",
    PERIAPSIS_WEB_PORT: "18443",
  });
  const tls = Object.fromEntries(
    tlsVariables.map((name) => [name, join(directory, `${name}.unread.pem`)]),
  );
  const proxy = {
    PERIAPSIS_PUBLIC_URL: "https://incident.example.test",
    PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS: "192.0.2.10/32,2001:db8::10/128",
    PERIAPSIS_S3_PUBLIC_ENDPOINT: "https://storage.example.test",
    PERIAPSIS_IDP_PUBLIC_URL: "https://identity.example.test",
    PERIAPSIS_HTTP_BIND_ADDRESS: "192.0.2.20",
    PERIAPSIS_HTTP_PORT: "18081",
  };
  return { environment, envFile, tls, proxy };
}

function render(inputs, file, profile, values) {
  const standalone = process.env.PERIAPSIS_COMPOSE_BINARY;
  const result = spawnSync(
    standalone || "docker",
    [
      ...(standalone ? [] : ["compose"]),
      "--env-file",
      inputs.envFile,
      "--project-directory",
      composeDirectory,
      "--project-name",
      "periapsis-model-test",
      "--file",
      join(composeDirectory, file),
      "--profile",
      profile,
      "config",
      "--format",
      "json",
    ],
    {
      cwd: composeDirectory,
      env: { ...inputs.environment, ...values },
      input: "",
      encoding: "utf8",
      timeout: 15000,
      killSignal: "SIGKILL",
      windowsHide: true,
      maxBuffer: 512 * 1024,
    },
  );
  assert.ok(
    !result.error,
    "a working Compose CLI is required; config must finish within its bound",
  );
  assert.equal(result.signal, null);
  return result;
}

function resolved(result) {
  assert.equal(result.status, 0, "the complete Compose model must resolve");
  assert.ok(
    result.stderr === "",
    "Compose must not emit warnings or raw configuration diagnostics",
  );
  try {
    return JSON.parse(result.stdout);
  } catch {
    assert.fail("Compose must return a valid JSON model");
  }
}

function assertApplicationHardening(model) {
  assertAddressPools(model);
  const publicOrigin = new URL(
    model.services.api.environment.PERIAPSIS_PUBLIC_URL,
  );
  for (const name of ["api", "worker"]) {
    assert.ok(
      model.services[name].environment.PERIAPSIS_FEDERATED_HTTPS_PORTS.split(
        ",",
      ).includes(publicOrigin.port || "443"),
      `${name} must admit the deployment-owned OIDC callback port`,
    );
  }
  assertMailpitHostPublication(model);
  for (const name of [
    "api",
    "worker",
    "web",
    "migration",
    "edge",
    "minio-provision",
    "db-seed",
    "notifier-provision",
    "notifier",
  ]) {
    const service = model.services[name];
    if (!service) continue;
    assert.equal(service.user, "10001:10001", `${name} numeric identity`);
    assert.equal(service.read_only, true, `${name} read-only root`);
    assert.deepEqual(service.cap_drop, ["ALL"]);
    assert.deepEqual(service.security_opt, ["no-new-privileges:true"]);
    assert.ok(service.tmpfs.includes("/tmp:uid=10001,gid=10001,mode=1770"));
  }
  assert.equal(
    model.services.api.environment.PERIAPSIS_TRUSTED_PROXY_CIDRS,
    "172.30.240.3/32",
  );
  assert.equal(
    model.services.web.networks.frontend.ipv4_address,
    "172.30.240.3",
  );
  assert.equal(
    model.services.api.networks.frontend.ipv4_address,
    "172.30.240.2",
  );
  assert.equal(
    model.services.edge.networks.frontend.ipv4_address,
    "172.30.240.4",
  );
  assert.equal(
    model.services.api.depends_on.migration.condition,
    "service_completed_successfully",
  );
  assert.equal(
    model.services.api.depends_on["minio-provision"].condition,
    "service_completed_successfully",
  );
  assert.equal(
    model.services.api.depends_on.clamav.condition,
    "service_healthy",
  );
  assert.equal(model.services.web.depends_on.api.condition, "service_healthy");
  assert.ok(!model.services.api.ports && !model.services.worker.ports);
  assert.equal(
    model.services.postgres.environment.POSTGRES_PASSWORD_FILE,
    "/run/secrets/postgres_password",
  );
  assert.equal(
    model.services.minio.environment.MINIO_ROOT_PASSWORD_FILE,
    "/run/secrets/minio_root_password",
  );
  assert.ok(
    Object.values(model.secrets).every(
      (secret) => typeof secret.file === "string" && !secret.environment,
    ),
  );
}

function assertAddressPools(model) {
  for (const name of ["frontend", "identity", "storage"]) {
    const [config] = model.networks[name].ipam.config;
    assert.ok(config.ip_range, `${name} needs a separate dynamic pool`);
    const [address, prefix] = config.ip_range.split("/");
    const pool = new BlockList();
    pool.addSubnet(address, Number(prefix), "ipv4");
    assert.ok(
      !pool.check(config.gateway, "ipv4"),
      `${name} gateway outside pool`,
    );
    const staticAddresses = new Set();
    for (const [service, definition] of Object.entries(model.services)) {
      const fixed = definition.networks?.[name]?.ipv4_address;
      if (!fixed) continue;
      assert.ok(
        !pool.check(fixed, "ipv4"),
        `${service}/${name} static IP outside dynamic pool`,
      );
      assert.ok(
        !staticAddresses.has(fixed),
        `${service}/${name} unique static IP`,
      );
      staticAddresses.add(fixed);
    }
  }
}

function assertMailpitHostPublication(model) {
  const mailpit = model.services.mailpit;
  if (!mailpit) return;
  assert.equal(model.networks.integrations.internal, true);
  assert.ok(
    model.networks["mailpit-host"],
    "Mailpit needs a host-publication bridge",
  );
  assert.notEqual(model.networks["mailpit-host"].internal, true);
  assert.deepEqual(Object.keys(mailpit.networks).toSorted(), [
    "integrations",
    "mailpit-host",
  ]);
  assert.deepEqual(
    Object.entries(model.services)
      .filter(([, service]) =>
        Object.hasOwn(service.networks ?? {}, "mailpit-host"),
      )
      .map(([name]) => name),
    ["mailpit"],
    "only the local SMTP fixture may join the host-publication bridge",
  );
  assert.deepEqual(
    mailpit.ports
      .map(({ host_ip, target, published, protocol }) => ({
        host_ip,
        target,
        published,
        protocol,
      }))
      .toSorted((left, right) => left.target - right.target),
    [
      {
        host_ip: "127.0.0.1",
        target: 1025,
        published: "11025",
        protocol: "tcp",
      },
      {
        host_ip: "127.0.0.1",
        target: 8025,
        published: "18025",
        protocol: "tcp",
      },
    ],
  );
  assert.equal(mailpit.user, "10001:10001");
  assert.equal(mailpit.read_only, true);
  assert.equal(mailpit.environment.MP_SMTP_AUTH_ACCEPT_ANY, "false");
}

function mount(service, target) {
  const matches =
    service.volumes?.filter((volume) => volume.target === target) ?? [];
  assert.equal(matches.length, 1, "expected one readonly configuration mount");
  assert.equal(matches[0].read_only, true);
  return matches[0];
}

for (const [profile, services] of Object.entries(profiles)) {
  test(`${profile}: default TLS entry retains the complete hardened merged model`, async (t) => {
    const inputs = await fixture(t);
    const model = resolved(render(inputs, "compose.yaml", profile, inputs.tls));
    assert.deepEqual(Object.keys(model.services).toSorted(), services);
    assertApplicationHardening(model);
    assert.ok(!model.networks["proxy-egress"]);
    assert.ok(!model.services.web.ports);
    assert.equal(
      model.services.web.environment.PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS,
      "172.30.240.4/32",
    );
    assert.ok(!model.services.web.environment.PERIAPSIS_WEB_PROXY_ONLY);
    assert.equal(
      model.services.api.environment.PERIAPSIS_PUBLIC_URL,
      "https://localhost:18443",
    );
    assert.equal(
      model.services.api.environment.PERIAPSIS_S3_PUBLIC_ENDPOINT,
      "https://storage.localhost:19000",
    );
    assert.equal(
      model.services.worker.environment.PERIAPSIS_S3_PUBLIC_ENDPOINT,
      "https://storage.localhost:19000",
    );
    for (const name of ["api", "worker"]) {
      assert.equal(
        model.services[name].environment.PERIAPSIS_FEDERATED_CA_BUNDLE_FILE,
        "/run/secrets/periapsis-dev-tls-ca.crt",
      );
      const ca = model.services[name].secrets.find(
        (secret) => secret.source === "dev_tls_ca",
      );
      assert.deepEqual(ca, {
        source: "dev_tls_ca",
        target: "periapsis-dev-tls-ca.crt",
        uid: "10001",
        gid: "10001",
        mode: "0444",
      });
    }
    assert.deepEqual(
      model.services.edge.secrets.map((secret) => secret.source).toSorted(),
      ["dev_tls_ca", "dev_tls_certificate", "dev_tls_private_key"],
    );
    assert.equal(
      model.services.edge.secrets.find(
        (secret) => secret.source === "dev_tls_private_key",
      ).mode,
      "0400",
    );
    assert.deepEqual(
      model.services.edge.ports.map((port) => [
        port.host_ip,
        port.published,
        port.target,
      ]),
      [
        ["127.0.0.1", "18443", 18443],
        ["127.0.0.1", "18090", 18090],
        ["127.0.0.1", "19000", 19000],
      ],
    );
    assert.equal(
      mount(model.services.edge, "/etc/caddy/Caddyfile").source,
      join(composeDirectory, "edge/Caddyfile"),
    );
    assert.equal(
      mount(model.services.edge, "/etc/caddy/storage-cors.caddy").source,
      join(composeDirectory, "edge/storage-cors.caddy"),
    );
    if (model.services["identity-provider"]) {
      assert.equal(
        model.services["identity-provider"].environment.KC_HOSTNAME,
        "https://idp.localhost:18090",
      );
      assert.equal(
        model.services["identity-provider"].environment.PERIAPSIS_PUBLIC_URL,
        "https://localhost:18443",
      );
    }
  });

  test(`${profile}: external proxy entry resolves every service with no local edge certificate inputs`, async (t) => {
    const inputs = await fixture(t);
    assert.ok(
      tlsVariables.every(
        (name) => !(name in inputs.environment) && !(name in inputs.proxy),
      ),
    );
    const model = resolved(
      render(inputs, "compose.reverse-proxy.yaml", profile, inputs.proxy),
    );
    assert.deepEqual(Object.keys(model.services).toSorted(), services);
    assertApplicationHardening(model);
    assert.ok(
      !Object.keys(model.secrets).some((name) => name.startsWith("dev_tls_")),
    );
    for (const service of Object.values(model.services)) {
      assert.ok(!service.environment?.PERIAPSIS_FEDERATED_CA_BUNDLE_FILE);
      assert.ok(!JSON.stringify(service).includes("periapsis-dev-tls"));
    }
    assert.equal(
      model.services.web.environment.PERIAPSIS_WEB_PROXY_ONLY,
      "true",
    );
    assert.equal(
      model.services.web.environment.PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS,
      inputs.proxy.PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS,
    );
    for (const name of ["api", "web"])
      assert.equal(
        model.services[name].environment.PERIAPSIS_PUBLIC_URL,
        inputs.proxy.PERIAPSIS_PUBLIC_URL,
      );
    for (const name of ["api", "worker"]) {
      assert.equal(
        model.services[name].environment.PERIAPSIS_S3_PUBLIC_ENDPOINT,
        inputs.proxy.PERIAPSIS_S3_PUBLIC_ENDPOINT,
      );
      assert.equal(
        model.services[name].environment.PERIAPSIS_FEDERATED_HTTPS_PORTS,
        "443,18090,18443",
      );
      assert.equal(
        model.services[name].environment
          .PERIAPSIS_FEDERATED_PRIVATE_EGRESS_CIDRS,
        "172.30.241.0/28",
      );
    }
    assert.deepEqual(
      Object.entries(model.services)
        .filter(([, service]) => service.networks?.["proxy-egress"])
        .map(([name]) => name),
      ["worker"],
    );
    assert.ok(!model.networks["proxy-egress"].internal);
    assert.deepEqual(Object.keys(model.services.worker.networks).toSorted(), [
      "backend",
      "identity",
      "proxy-egress",
      "storage",
    ]);
    assert.deepEqual(
      model.services.web.ports.map((port) => [
        port.host_ip,
        port.published,
        port.target,
      ]),
      [["192.0.2.20", "18081", 8081]],
    );
    assert.deepEqual(
      model.services.edge.ports.map((port) => [
        port.host_ip,
        port.published,
        port.target,
      ]),
      [
        ["192.0.2.20", "18090", 18090],
        ["192.0.2.20", "19000", 19000],
      ],
    );
    assert.deepEqual(Object.keys(model.services.edge.networks).toSorted(), [
      "frontend",
      "identity",
      "storage",
    ]);
    assert.equal(
      model.services.edge.networks.identity.ipv4_address,
      "172.30.241.6",
    );
    assert.equal(
      model.services.edge.networks.storage.ipv4_address,
      "172.30.242.6",
    );
    assert.equal(
      model.services.edge.environment.PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS,
      inputs.proxy.PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS,
    );
    assert.ok(!model.services.edge.secrets);
    assert.deepEqual(model.services.edge.entrypoint, [
      "/bin/sh",
      "/etc/caddy/reverse-proxy-entrypoint.sh",
    ]);
    assert.equal(
      mount(model.services.edge, "/etc/caddy/Caddyfile").source,
      join(composeDirectory, "edge/Caddyfile.reverse-proxy"),
    );
    assert.equal(
      mount(model.services.edge, "/etc/caddy/reverse-proxy-entrypoint.sh")
        .source,
      join(composeDirectory, "edge/reverse-proxy-entrypoint.sh"),
    );
    assert.equal(
      mount(model.services.edge, "/etc/caddy/storage-cors.caddy").source,
      join(composeDirectory, "edge/storage-cors.caddy"),
    );
    assert.equal(
      model.services.minio.environment.MINIO_API_CORS_ALLOW_ORIGIN,
      inputs.proxy.PERIAPSIS_PUBLIC_URL,
    );
    if (model.services["identity-provider"]) {
      assert.equal(
        model.services["identity-provider"].environment.KC_HOSTNAME,
        inputs.proxy.PERIAPSIS_IDP_PUBLIC_URL,
      );
      assert.equal(
        model.services["identity-provider"].environment.PERIAPSIS_PUBLIC_URL,
        inputs.proxy.PERIAPSIS_PUBLIC_URL,
      );
      assert.equal(
        model.services["identity-provider"].environment
          .KC_PROXY_TRUSTED_ADDRESSES,
        "172.30.241.6/32",
      );
    }
  });
}

for (const variable of [...tlsVariables, ...proxyVariables]) {
  test(`configuration fails closed when required ${variable} is absent`, async (t) => {
    const inputs = await fixture(t);
    const localTls = tlsVariables.includes(variable);
    const values = { ...(localTls ? inputs.tls : inputs.proxy) };
    delete values[variable];
    const result = render(
      inputs,
      localTls ? "compose.yaml" : "compose.reverse-proxy.yaml",
      "full",
      values,
    );
    assert.notEqual(result.status, 0);
    assert.ok(
      result.stdout === "",
      "failed interpolation must not publish a model",
    );
    assert.ok(
      result.stderr.includes(variable),
      "failure must identify the missing variable without printing its value",
    );
  });
}
