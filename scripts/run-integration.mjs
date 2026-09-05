import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const integrationSuites = Object.freeze({
  auth: fileURLToPath(
    new URL("../tests/integration/auth-smoke.mjs", import.meta.url),
  ),
  ldap: fileURLToPath(
    new URL("../tests/integration/ldap-auth-acceptance.mjs", import.meta.url),
  ),
});

export function selectIntegrationSuite(environment = process.env) {
  const selected = environment.PERIAPSIS_INTEGRATION_SUITE?.trim() || "auth";
  const script = integrationSuites[selected];
  if (!script) {
    throw new Error(
      `unsupported PERIAPSIS_INTEGRATION_SUITE ${JSON.stringify(selected)}; choose exactly one of: auth, ldap`,
    );
  }
  return { name: selected, script };
}

export function runIntegrationSuite(
  environment = process.env,
  spawn = spawnSync,
) {
  const suite = selectIntegrationSuite(environment);
  const result = spawn(process.execPath, [suite.script], {
    cwd: repositoryRoot,
    env: environment,
    stdio: "inherit",
  });
  if (result.error) throw result.error;
  if (result.signal) {
    throw new Error(
      `integration suite ${suite.name} terminated by signal ${result.signal}`,
    );
  }
  if (!Number.isInteger(result.status)) {
    throw new Error(`integration suite ${suite.name} returned no exit status`);
  }
  return result.status;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  try {
    process.exitCode = runIntegrationSuite();
  } catch (error) {
    process.stderr.write(
      `integration runner: ${error instanceof Error ? error.message : "unknown failure"}\n`,
    );
    process.exitCode = 2;
  }
}
