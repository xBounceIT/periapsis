import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  composeSecretVariables,
  prepareComposeSecrets,
  run,
} from "./prepare-compose-secrets.mjs";
import { validateComposeFileSecrets } from "./validate-manifests.mjs";

async function fixture(t) {
  const parent = await mkdtemp(
    join(tmpdir(), "periapsis-compose-secret-test-"),
  );
  t.after(async () => {
    // This is the exact directory owned by this test, never the configured
    // application secret directory. Clear Windows read-only file attributes.
    await Promise.all(
      (
        await readdir(parent, {
          recursive: true,
          withFileTypes: true,
        })
      ).map(async (entry) => {
        if (entry.isFile())
          await chmod(join(entry.parentPath, entry.name), 0o600);
      }),
    );
    await rm(parent, { recursive: true, force: true });
  });
  const environment = Object.fromEntries(
    Object.values(composeSecretVariables).map((name) => [
      name,
      randomBytes(32).toString("hex"),
    ]),
  );
  environment.PERIAPSIS_COMPOSE_SECRETS_DIR = join(parent, "secrets");
  return { parent, environment };
}

test("preparation creates exactly the 15 distinct files with unchanged bytes and private parent", async (t) => {
  const { environment } = await fixture(t);
  const directory = environment.PERIAPSIS_COMPOSE_SECRETS_DIR;
  assert.equal(await prepareComposeSecrets(environment), 15);
  assert.equal(new Set(Object.values(composeSecretVariables)).size, 15);
  assert.deepEqual(
    (await readdir(directory)).toSorted(),
    Object.keys(composeSecretVariables).toSorted(),
  );
  if (process.platform !== "win32")
    assert.equal((await lstat(directory)).mode & 0o777, 0o700);
  await Promise.all(
    Object.entries(composeSecretVariables).map(async ([name, variable]) => {
      const file = join(directory, name);
      assert.equal(await readFile(file, "utf8"), environment[variable]);
      if (process.platform !== "win32")
        assert.equal((await lstat(file)).mode & 0o777, 0o444);
    }),
  );
});

test("preparation refuses existing material instead of silently rotating it", async (t) => {
  const { environment } = await fixture(t);
  await prepareComposeSecrets(environment);
  const file = join(
    environment.PERIAPSIS_COMPOSE_SECRETS_DIR,
    "ldap_admin_password",
  );
  const original = await readFile(file);
  await assert.rejects(
    prepareComposeSecrets({
      ...environment,
      PERIAPSIS_LDAP_ADMIN_PASSWORD: randomBytes(32).toString("hex"),
    }),
    { code: "EEXIST" },
  );
  assert.deepEqual(await readFile(file), original);
});

for (const failureAt of [1, 8, 15]) {
  test(`partial I/O failure at file ${failureAt} rolls back completed and incomplete material`, async (t) => {
    const { parent, environment } = await fixture(t);
    const probe = await open(join(parent, "empty-handle-probe"), "wx");
    const prototype = Object.getPrototypeOf(probe);
    const originalWriteFile = prototype.writeFile;
    await probe.close();
    let writes = 0;
    t.mock.method(prototype, "writeFile", async function (data, options) {
      writes += 1;
      if (writes !== failureAt)
        return originalWriteFile.call(this, data, options);
      await originalWriteFile.call(this, data.slice(0, 4), options);
      throw Object.assign(new Error("synthetic disk-full"), { code: "ENOSPC" });
    });
    await assert.rejects(prepareComposeSecrets(environment), {
      code: "ENOSPC",
    });
    assert.equal(writes, failureAt);
    await assert.rejects(lstat(environment.PERIAPSIS_COMPOSE_SECRETS_DIR), {
      code: "ENOENT",
    });
  });
}

for (const value of [
  undefined,
  "",
  " \t",
  "line\nbreak",
  "line\rbreak",
  "null\0byte",
  "a".repeat(65_537),
]) {
  test(`invalid input ${value === undefined ? "missing" : `${value.length} bytes`} leaves no partial secret directory`, async (t) => {
    const { environment } = await fixture(t);
    environment.PERIAPSIS_S3_SECRET_KEY = value;
    await assert.rejects(
      prepareComposeSecrets(environment),
      /PERIAPSIS_S3_SECRET_KEY/u,
    );
    await assert.rejects(lstat(environment.PERIAPSIS_COMPOSE_SECRETS_DIR), {
      code: "ENOENT",
    });
  });
}

test("absolute paths outside the checkout are mandatory, including through parent aliases", async (t) => {
  const { parent, environment } = await fixture(t);
  const root = fileURLToPath(new URL("../../", import.meta.url));
  await Promise.all(
    ["", "relative-secret-directory", join(root, "forbidden-test-secrets")].map(
      async (directory) => {
        await assert.rejects(
          prepareComposeSecrets({
            ...environment,
            PERIAPSIS_COMPOSE_SECRETS_DIR: directory,
          }),
          /absolute external path|outside the repository/u,
        );
      },
    ),
  );
  const alias = join(parent, "checkout-alias");
  await symlink(root, alias, process.platform === "win32" ? "junction" : "dir");
  await assert.rejects(
    prepareComposeSecrets({
      ...environment,
      PERIAPSIS_COMPOSE_SECRETS_DIR: join(alias, "forbidden-test-secrets"),
    }),
    /outside the repository/u,
  );
});

test("an existing symlink target is never followed or populated", async (t) => {
  const { parent, environment } = await fixture(t);
  const destination = join(parent, "untouched");
  await mkdir(destination);
  await symlink(
    destination,
    environment.PERIAPSIS_COMPOSE_SECRETS_DIR,
    process.platform === "win32" ? "junction" : "dir",
  );
  await assert.rejects(prepareComposeSecrets(environment), { code: "EEXIST" });
  assert.deepEqual(await readdir(destination), []);
});

test("dotenv preserves JSON and process environment takes precedence", async (t) => {
  const { parent, environment } = await fixture(t);
  const keyring = JSON.stringify({
    activeVersion: 1,
    keys: [{ version: 1, key: randomBytes(32).toString("base64") }],
  });
  environment.PERIAPSIS_IDENTITY_KEYRING = keyring;
  const envFile = join(parent, "input.env");
  await writeFile(
    envFile,
    Object.entries(environment)
      .map(([key, value]) => `${key}='${value}'`)
      .join("\n"),
  );
  const overridden = randomBytes(32).toString("hex");
  assert.equal(
    await run(["--env-file", envFile], {
      PERIAPSIS_LDAP_ADMIN_PASSWORD: overridden,
    }),
    15,
  );
  assert.equal(
    await readFile(
      join(environment.PERIAPSIS_COMPOSE_SECRETS_DIR, "ldap_admin_password"),
      "utf8",
    ),
    overridden,
  );
  assert.equal(
    await readFile(
      join(
        environment.PERIAPSIS_COMPOSE_SECRETS_DIR,
        "periapsis_identity_keyring",
      ),
      "utf8",
    ),
    keyring,
  );
});

test("CLI errors never print values and reject unknown options", async (t) => {
  const { environment } = await fixture(t);
  environment.PERIAPSIS_S3_SECRET_KEY = "";
  const result = spawnSync(
    process.execPath,
    [fileURLToPath(new URL("./prepare-compose-secrets.mjs", import.meta.url))],
    {
      env: { ...process.env, ...environment },
      encoding: "utf8",
      windowsHide: true,
    },
  );
  assert.equal(result.status, 1);
  assert.match(result.stderr, /PERIAPSIS_S3_SECRET_KEY/u);
  assert.equal(result.stdout, "");
  for (const variable of Object.values(composeSecretVariables)) {
    if (environment[variable])
      assert.ok(!result.stderr.includes(environment[variable]));
  }
  await assert.rejects(run(["--overwrite"], environment), /Usage:/u);
});

test("every Compose secret maps to its own file and environment-backed regressions are rejected", async () => {
  const source = await readFile(
    new URL("../../deploy/compose/compose.base.yaml", import.meta.url),
    "utf8",
  );
  assert.deepEqual(validateComposeFileSecrets(source), []);
  for (const name of Object.keys(composeSecretVariables)) {
    const file = `file: \${PERIAPSIS_COMPOSE_SECRETS_DIR:?prepare an external Compose secret directory}/${name}`;
    assert.ok(
      validateComposeFileSecrets(
        source.replace(file, `environment: ${composeSecretVariables[name]}`),
      ).length >= 1,
    );
    assert.ok(
      validateComposeFileSecrets(source.replace(file, `${file}-wrong-file`))
        .length >= 1,
    );
  }
});
