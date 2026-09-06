import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import test from "node:test";

const root = resolve(fileURLToPath(new URL("../../", import.meta.url)));
const read = (path) => readFile(resolve(root, path), "utf8");
const defaults = {
  PERIAPSIS_API_RATE_LIMIT_NETWORK_RPS: "100",
  PERIAPSIS_API_RATE_LIMIT_CREDENTIAL_RPS: "60",
  PERIAPSIS_API_RATE_LIMIT_TENANT_SUBJECT_RPS: "40",
};

test("API rate-limit defaults are wired through every deployment surface", async () => {
  const [rootEnv, composeEnv, swarmEnv, compose, swarm, kubernetes, main] =
    await Promise.all([
      read(".env.example"),
      read("deploy/compose/.env.example"),
      read("deploy/swarm/.env.example"),
      read("deploy/compose/compose.base.yaml"),
      read("deploy/swarm/stack.yml"),
      read("deploy/k8s/base/config-map.yaml"),
      read("services/api/cmd/api/main.go"),
    ]);

  for (const [name, value] of Object.entries(defaults)) {
    for (const source of [rootEnv, composeEnv, swarmEnv]) {
      assert.match(source, new RegExp(`^${name}=${value}$`, "mu"));
    }
    for (const source of [compose, swarm]) {
      assert.ok(
        source.includes(`${name}: \${${name}:-${value}}`),
        `${name} must keep its documented deployment default`,
      );
    }
    assert.match(kubernetes, new RegExp(`^  ${name}: "${value}"$`, "mu"));
  }

  assert.match(main, /postgres\.NewAPIRateLimitRepository\(pool\)/u);
  assert.match(main, /cfg\.APIRateLimitPolicy/u);
  assert.match(main, /RateLimiter:\s+apiRateLimiter/u);
});
