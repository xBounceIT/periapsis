import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { parsers } from "prettier/plugins/yaml";

const readSource = (path) =>
  readFile(new URL(`../../${path}`, import.meta.url), "utf8");

// Use the existing pinned YAML parser for structural contracts, not an imitation
// of Docker's legacy merge/interpolation engine. A real stack config is separate.
function documentMapping(source) {
  const root = parsers.yaml.parse(source);
  assert.equal(root.children.length, 1);
  const body = root.children[0].children.find(
    (node) => node.type === "documentBody",
  );
  assert.equal(body.children.length, 1);
  const mapping = body.children[0];
  assert.equal(mapping.type, "mapping");
  return mapping;
}

function entries(mapping) {
  assert.equal(mapping.type, "mapping");
  const result = new Map();
  for (const item of mapping.children) {
    assert.equal(item.type, "mappingItem");
    const [key, value] = item.children;
    assert.equal(key.children.length, 1);
    assert.equal(value.children.length, 1);
    const name = key.children[0].value;
    assert.equal(typeof name, "string");
    assert.equal(result.has(name), false, `duplicate YAML key: ${name}`);
    result.set(name, value.children[0]);
  }
  return result;
}

function at(mapping, ...path) {
  return path.reduce((node, key) => {
    const result = entries(node).get(key);
    assert.ok(result, `missing YAML field: ${key}`);
    return result;
  }, mapping);
}

function fields(mapping) {
  return Object.fromEntries(
    [...entries(mapping)].map(([key, node]) => {
      assert.ok(["plain", "quoteDouble", "quoteSingle"].includes(node.type));
      assert.equal(node.tag, null);
      return [key, node.value];
    }),
  );
}

function sequence(mapping, ...path) {
  const node = at(mapping, ...path);
  assert.equal(node.type, "sequence");
  return node.children.map((item) => {
    assert.equal(item.type, "sequenceItem");
    assert.equal(item.children.length, 1);
    return item.children[0];
  });
}

const [baseSource, variantSource, environment, readme] = await Promise.all([
  readSource("deploy/swarm/stack.yml"),
  readSource("deploy/swarm/stack.reverse-proxy.yml"),
  readSource("deploy/swarm/.env.example"),
  readSource("deploy/swarm/README.md"),
]);
const base = documentMapping(baseSource);
const variant = documentMapping(variantSource);

test("Swarm reverse-proxy variant changes only the opt-in web boundary and API peer trust", () => {
  assert.deepEqual([...entries(variant).keys()], ["services"]);
  assert.deepEqual(
    [...entries(at(variant, "services")).keys()],
    ["api", "web"],
  );
  assert.deepEqual(
    [...entries(at(variant, "services", "api")).keys()],
    ["environment"],
  );
  assert.deepEqual(
    [...entries(at(variant, "services", "web")).keys()],
    ["environment", "ports", "deploy"],
  );
  assert.deepEqual(fields(at(variant, "services", "api", "environment")), {
    PERIAPSIS_TRUSTED_PROXY_CIDRS:
      "${PERIAPSIS_TRUSTED_PROXY_CIDRS:?set exact web immediate-peer CIDRs seen by API}",
  });
  assert.deepEqual(fields(at(variant, "services", "web", "environment")), {
    PERIAPSIS_PUBLIC_URL:
      "${PERIAPSIS_PUBLIC_URL:?set canonical public HTTPS origin}",
    PERIAPSIS_WEB_PROXY_ONLY: "true",
    PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS:
      "${PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS:?set exact remote reverse-proxy immediate-peer CIDRs}",
  });
  assert.equal(
    at(variant, "services", "web", "environment", "PERIAPSIS_WEB_PROXY_ONLY")
      .type,
    "quoteDouble",
  );
  assert.equal(
    at(base, "services", "web", "environment", "PERIAPSIS_API_URL").value,
    "http://api:8080",
  );
  assert.equal(
    at(base, "services", "web", "environment", "PERIAPSIS_ENV").value,
    "production",
  );
});

test("Swarm host publication retains the exact base port identity without a second origin", () => {
  const basePorts = sequence(base, "services", "web", "ports");
  const variantPorts = sequence(variant, "services", "web", "ports");
  assert.equal(basePorts.length, 1);
  assert.equal(variantPorts.length, 1);
  const port = fields(variantPorts[0]);
  assert.deepEqual(fields(basePorts[0]), {
    target: "8081",
    published: "${PERIAPSIS_WEB_PORT:-8081}",
    protocol: "tcp",
    mode: "ingress",
  });
  assert.deepEqual(port, { ...fields(basePorts[0]), mode: "host" });
  assert.doesNotMatch(variantSource, /!(?:override|reset)\b/u);
});

test("Swarm fixed host port requires one task per node and stop-first update plus rollback", () => {
  const deploy = at(variant, "services", "web", "deploy");
  assert.deepEqual(
    [...entries(deploy).keys()],
    ["placement", "update_config", "rollback_config"],
  );
  assert.deepEqual(fields(at(deploy, "placement")), {
    max_replicas_per_node: "1",
  });
  assert.deepEqual(fields(at(deploy, "update_config")), {
    order: "stop-first",
  });
  assert.deepEqual(fields(at(deploy, "rollback_config")), {
    order: "stop-first",
  });

  // These retained anchor values must not be shadowed by a replacement deployment
  // object in the variant. The actual CLI still has to verify the merged output.
  assert.equal(at(base, "services", "web", "deploy", "<<").type, "alias");
  assert.equal(
    at(base, "services", "web", "deploy", "<<").value,
    "runtime-deploy",
  );
  assert.deepEqual(
    sequence(base, "x-runtime-deploy", "placement", "constraints").map(
      (node) => node.value,
    ),
    [
      "node.platform.os == linux",
      "${PERIAPSIS_RUNTIME_PLACEMENT_CONSTRAINT:-node.labels.periapsis.runtime == true}",
    ],
  );
  assert.deepEqual(fields(at(base, "x-runtime-deploy", "update_config")), {
    parallelism: "1",
    delay: "10s",
    monitor: "30s",
    failure_action: "rollback",
    order: "start-first",
  });
  assert.deepEqual(fields(at(base, "x-runtime-deploy", "rollback_config")), {
    parallelism: "1",
    delay: "5s",
    monitor: "30s",
    failure_action: "pause",
    order: "stop-first",
  });
  assert.equal(
    at(base, "services", "web", "deploy", "replicas").value,
    "${PERIAPSIS_WEB_REPLICAS:-0}",
  );
});

test("Swarm operator inputs keep both trust lists explicit and leave the public origin HTTPS", () => {
  const values = new Map(
    environment
      .split(/\r?\n/u)
      .filter((line) => /^[A-Z_]+=/u.test(line))
      .map((line) => {
        const separator = line.indexOf("=");
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
  assert.equal(
    values.get("PERIAPSIS_PUBLIC_URL"),
    "https://periapsis.example.com",
  );
  assert.equal(
    values.get("PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS"),
    "REPLACE_WITH_EXACT_REVERSE_PROXY_IMMEDIATE_PEER_CIDRS",
  );
  assert.equal(
    values.get("PERIAPSIS_TRUSTED_PROXY_CIDRS"),
    "REPLACE_WITH_EXACT_WEB_IMMEDIATE_PEER_CIDRS",
  );
  assert.match(
    readme,
    /docker stack config\s+\\\s+--compose-file deploy\/swarm\/stack\.yml\s+\\\s+--compose-file deploy\/swarm\/stack\.reverse-proxy\.yml/u,
  );
  assert.match(
    readme,
    /docker stack deploy --with-registry-auth\s+\\\s+--compose-file deploy\/swarm\/stack\.yml\s+\\\s+--compose-file deploy\/swarm\/stack\.reverse-proxy\.yml periapsis/u,
  );
  for (const boundary of [
    "brief downtime",
    "single published port",
    "exact remote proxy sources",
    "Secure cookies",
    "X-Forwarded-Proto: https",
    "!override",
    "!reset",
    "every",
    "PostgreSQL",
  ]) {
    assert.ok(
      readme.includes(boundary),
      `missing operator boundary: ${boundary}`,
    );
  }
});
