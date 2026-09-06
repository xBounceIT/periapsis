/* oxlint-disable no-await-in-loop -- Ordered secret creation and rollback prevent a failed write from outliving cleanup. */
import { spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  open,
  readFile,
  realpath,
  rmdir,
  unlink,
} from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseEnv } from "node:util";

export const composeSecretVariables = Object.freeze({
  postgres_password: "PERIAPSIS_POSTGRES_PASSWORD",
  api_database_password: "PERIAPSIS_API_DATABASE_PASSWORD",
  worker_database_password: "PERIAPSIS_WORKER_DATABASE_PASSWORD",
  notifier_database_password: "PERIAPSIS_NOTIFIER_DATABASE_PASSWORD",
  notifier_preview_token: "PERIAPSIS_NOTIFIER_PREVIEW_TOKEN",
  "notification-keyring": "PERIAPSIS_NOTIFICATION_KEYRING",
  periapsis_bootstrap_token: "PERIAPSIS_BOOTSTRAP_TOKEN",
  periapsis_master_key: "PERIAPSIS_MASTER_KEY",
  periapsis_api_credential_keyring: "PERIAPSIS_API_CREDENTIAL_KEYRING",
  periapsis_identity_keyring: "PERIAPSIS_IDENTITY_KEYRING",
  ldap_admin_password: "PERIAPSIS_LDAP_ADMIN_PASSWORD",
  minio_root_user: "PERIAPSIS_MINIO_ROOT_USER",
  minio_root_password: "PERIAPSIS_MINIO_ROOT_PASSWORD",
  minio_access_key: "PERIAPSIS_S3_ACCESS_KEY",
  minio_secret_key: "PERIAPSIS_S3_SECRET_KEY",
});

const repositoryRoot = fileURLToPath(new URL("../../", import.meta.url));

async function restrictDirectory(directory) {
  if (process.platform !== "win32") {
    await chmod(directory, 0o700);
    return;
  }
  // Node's POSIX mode is not an ACL on Windows. Restrict the directory before
  // creating any files; descendants inherit only the current user's grant.
  const identity = spawnSync("whoami.exe", ["/user", "/fo", "csv", "/nh"], {
    encoding: "utf8",
    windowsHide: true,
  });
  const sid = identity.stdout?.match(/"(S-1-[0-9-]+)"\s*$/)?.[1];
  if (identity.status !== 0 || !sid)
    throw new Error("Cannot identify the secret-file owner");
  const acl = spawnSync(
    "icacls.exe",
    [directory, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`],
    { encoding: "utf8", windowsHide: true },
  );
  if (acl.status !== 0)
    throw new Error("Cannot restrict the secret directory ACL");
}

export async function prepareComposeSecrets(environment) {
  const requested = environment.PERIAPSIS_COMPOSE_SECRETS_DIR;
  if (typeof requested !== "string" || !isAbsolute(requested)) {
    throw new Error(
      "PERIAPSIS_COMPOSE_SECRETS_DIR must be an absolute external path",
    );
  }
  const entries = Object.entries(composeSecretVariables).map(
    ([name, variable]) => {
      const value = environment[variable];
      if (
        typeof value !== "string" ||
        !value.trim() ||
        /[\r\n\0]/.test(value) ||
        Buffer.byteLength(value, "utf8") > 65_536
      ) {
        throw new Error(
          `Set a nonempty, single-line ${variable} before preparing secrets`,
        );
      }
      return [name, value];
    },
  );
  // Resolve existing ancestors to reject aliases into the checkout, not just
  // lexical paths. mkdir below is exclusive: never follow/replace an existing
  // directory, file or link, and never rotate running containers' credentials.
  const target = resolve(requested);
  const parent = await realpath(dirname(target));
  const directory = resolve(parent, relative(dirname(target), target));
  const relation = relative(await realpath(repositoryRoot), directory);
  if (
    !relation ||
    (!isAbsolute(relation) &&
      relation !== ".." &&
      !relation.startsWith(`..${sep}`))
  ) {
    throw new Error("Compose secrets must be outside the repository");
  }
  await mkdir(directory, { mode: 0o700 });
  const created = [];
  try {
    await restrictDirectory(directory);
    for (const [name, value] of entries) {
      const file = resolve(directory, name);
      // Compose bind-mounts files and ignores secret uid/gid remapping. The
      // private parent prevents host traversal; 0444 permits the distinct
      // non-root service UIDs to read only their explicitly selected mounts.
      const handle = await open(file, "wx", 0o444);
      created.push(file);
      try {
        await handle.writeFile(value, "utf8");
      } finally {
        await handle.close();
      }
      await chmod(file, 0o444);
    }
  } catch (error) {
    for (const file of created) {
      await chmod(file, 0o600);
      await unlink(file);
    }
    await rmdir(directory);
    throw error;
  }
  return entries.length;
}

export async function run(arguments_, environment = process.env) {
  if (
    arguments_.length !== 0 &&
    !(
      arguments_.length === 2 &&
      arguments_[0] === "--env-file" &&
      arguments_[1]
    )
  ) {
    throw new Error(
      "Usage: node scripts/deploy/prepare-compose-secrets.mjs [--env-file .env]",
    );
  }
  const fileEnvironment = arguments_.length
    ? parseEnv(await readFile(arguments_[1], "utf8"))
    : {};
  return prepareComposeSecrets({ ...fileEnvironment, ...environment });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const count = await run(process.argv.slice(2));
    process.stdout.write(
      `Prepared ${count} external Compose secret files; existing files were not overwritten.\n`,
    );
  } catch (error) {
    // Do not print arguments, file contents or child-process output on failure.
    const message =
      error instanceof Error && !("code" in error)
        ? error.message
        : "Cannot prepare Compose secrets; check the external path, permissions and existing files.";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
