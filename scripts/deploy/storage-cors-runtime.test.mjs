import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

/* eslint-disable no-await-in-loop -- Ordered real HTTP probes share upstream observations and conditional-write state; startup retries must remain sequential and bounded. */

const allowedHeaders = [
  "cache-control",
  "content-disposition",
  "content-length",
  "content-type",
  "if-none-match",
  "x-amz-meta-periapsis-declared-mime",
  "x-amz-meta-periapsis-expected-size",
];
const vary = [
  "origin",
  "access-control-request-method",
  "access-control-request-headers",
];
const sourcePath = new URL(
  "../../deploy/compose/edge/Caddyfile",
  import.meta.url,
);
const snippetPath = new URL(
  "../../deploy/compose/edge/storage-cors.caddy",
  import.meta.url,
);
const auxiliaryPath = new URL(
  "../../deploy/compose/edge/Caddyfile.reverse-proxy",
  import.meta.url,
);
const storageSite =
  "https://storage.localhost:{$PERIAPSIS_MINIO_API_PORT:19000} {";
const etag = '"fixture-etag"';
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const tokens = (value = "") =>
  value.split(",").map((part) => part.trim().toLowerCase());

test(
  "the real identity edge bounds caching to successful public trust documents",
  { timeout: 30_000 },
  async () => {
    const binary = process.env.PERIAPSIS_CADDY_BINARY;
    assert.ok(
      binary && path.isAbsolute(binary),
      "the actual Caddy binary is required",
    );
    const upstream = http.createServer((request, response) => {
      response.writeHead(Number(request.headers["x-fixture-status"] ?? 200), {
        "Cache-Control": "no-store, no-cache",
        "Content-Type": "application/json",
      });
      response.end('{"fixture":"unchanged"}');
    });
    let child;
    let childClosed;
    try {
      upstream.listen(0, "127.0.0.1");
      await once(upstream, "listening");
      const reservation = http.createServer();
      reservation.listen(0, "127.0.0.1");
      await once(reservation, "listening");
      const port = reservation.address().port;
      await new Promise((resolve) => reservation.close(resolve));
      const source = await readFile(sourcePath, "utf8");
      const marker = "https://idp.localhost:{$PERIAPSIS_IDP_PORT:18090} {";
      const start = source.indexOf(marker);
      assert.ok(start >= 0);
      const site = source
        .slice(start, source.indexOf("\n}", start) + 2)
        .replace(marker, `http://127.0.0.1:${port} {`)
        .replace("import periapsis_dev_tls", "")
        .replaceAll(
          "http://identity-provider:8080",
          `http://127.0.0.1:${upstream.address().port}`,
        );
      const configuration = execFileSync(
        binary,
        ["adapt", "--config", "-", "--adapter", "caddyfile"],
        {
          input: `{\n admin off\n auto_https off\n}\n${site}`,
          encoding: "utf8",
          windowsHide: true,
          timeout: 5_000,
          stdio: ["pipe", "pipe", "ignore"],
        },
      );
      child = spawn(binary, ["run", "--config", "-"], {
        windowsHide: true,
        stdio: ["pipe", "ignore", "ignore"],
      });
      childClosed = once(child, "close");
      child.stdin.end(configuration);
      const origin = `http://127.0.0.1:${port}`;
      let ready = false;
      for (let attempt = 0; attempt < 50 && !ready; attempt += 1) {
        try {
          const response = await fetch(origin, {
            signal: AbortSignal.timeout(500),
          });
          await response.arrayBuffer();
          ready = response.ok;
        } catch {
          await delay(50);
        }
      }
      assert.ok(ready, "owned identity edge did not start");
      const paths = [
        "/realms/periapsis-test/.well-known/openid-configuration",
        "/realms/periapsis-test/protocol/openid-connect/certs",
        "/realms/periapsis-test/protocol/openid-connect/auth",
        "/realms/periapsis-test/protocol/openid-connect/token",
        "/realms/other/.well-known/openid-configuration",
      ];
      for (const [index, target] of paths.entries()) {
        for (const method of ["GET", "POST"]) {
          for (const status of [200, 400, 503]) {
            const response = await fetch(origin + target, {
              method,
              headers: { "x-fixture-status": String(status) },
            });
            assert.equal(response.status, status);
            assert.equal(await response.text(), '{"fixture":"unchanged"}');
            assert.equal(
              response.headers.get("cache-control"),
              index < 2 && method === "GET" && status === 200
                ? "public, max-age=600"
                : "no-store, no-cache",
              `${method} ${target} ${status}`,
            );
          }
        }
      }
    } finally {
      if (child) {
        child.kill();
        await childClosed;
      }
      upstream.closeAllConnections();
      if (upstream.listening)
        await new Promise((resolve) => upstream.close(resolve));
    }
  },
);

function replaceExactlyOnce(source, from, to) {
  assert.equal(
    source.split(from).length,
    2,
    "deployment fixture anchor must be unique",
  );
  return source.replace(from, () => to);
}

test(
  "the real auxiliary HTTP edge enforces socket-peer trust before CORS and upstream routing",
  { timeout: 90_000 },
  async (t) => {
    const binary = process.env.PERIAPSIS_CADDY_BINARY;
    assert.ok(
      binary && path.isAbsolute(binary),
      "the actual Caddy binary is required; no skip",
    );
    assert.match(
      execFileSync(binary, ["version"], {
        timeout: 5_000,
        windowsHide: true,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      }),
      /^v2\.11\.4(?:\s|$)/u,
    );
    const source = await readFile(auxiliaryPath, "utf8");
    const snippet = await readFile(snippetPath, "utf8");
    const origin = "https://incidents.example.test:9443";
    const directory = await mkdtemp(
      path.join(tmpdir(), "periapsis-auxiliary-edge-"),
    );
    const seen = [];
    const sockets = new Set();
    const upstreams = ["identity", "storage"].map((kind) => {
      const server = http.createServer(async (incoming, outgoing) => {
        const chunks = [];
        for await (const chunk of incoming) chunks.push(chunk);
        seen.push({
          kind,
          method: incoming.method,
          target: incoming.url,
          headers: incoming.headers,
          body: Buffer.concat(chunks),
        });
        outgoing.setHeader("X-Fixture-Upstream", kind);
        outgoing.setHeader("Access-Control-Allow-Origin", "*");
        outgoing.setHeader("Access-Control-Allow-Credentials", "true");
        outgoing.end(kind);
      });
      server.on("connection", (socket) => {
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
      });
      return server;
    });
    const reservations = [http.createServer(), http.createServer()];
    let child;
    let childClosed;
    let childDone = false;
    const cleanup = [];
    try {
      const [identityUpstream, storageUpstream] = await Promise.all(
        upstreams.map(listen),
      );
      const [identityPort, storagePort] = await Promise.all(
        reservations.map(listen),
      );
      let configSource = replaceExactlyOnce(
        source,
        "import /etc/caddy/storage-cors.caddy",
        "import storage-cors.caddy",
      );
      configSource = replaceExactlyOnce(
        configSource,
        "http://:{$PERIAPSIS_IDP_PORT:18090} {",
        `http://:${identityPort} {\n\tbind 127.0.0.1`,
      );
      configSource = replaceExactlyOnce(
        configSource,
        "http://:{$PERIAPSIS_MINIO_API_PORT:19000} {",
        `http://:${storagePort} {\n\tbind 127.0.0.1`,
      );
      configSource = replaceExactlyOnce(
        configSource,
        "http://identity-provider:8080",
        `http://127.0.0.1:${identityUpstream}`,
      );
      const config = path.join(directory, "Caddyfile");
      await writeFile(config, configSource, { flag: "wx", mode: 0o600 });
      await writeFile(
        path.join(directory, "storage-cors.caddy"),
        replaceExactlyOnce(
          snippet,
          "http://minio:9000",
          `http://127.0.0.1:${storageUpstream}`,
        ),
        { flag: "wx", mode: 0o600 },
      );
      const env = {
        ...process.env,
        // Real loopback source bindings distinguish the allowed proxy, a local
        // health probe, and an untrusted peer; no forwarding-header policy mock.
        PERIAPSIS_CADDY_TRUSTED_PROXY_CIDRS: "127.0.0.2/32",
        PERIAPSIS_PUBLIC_URL: origin,
        XDG_CONFIG_HOME: directory,
        XDG_DATA_HOME: directory,
        APPDATA: directory,
      };
      const adapted = JSON.parse(
        execFileSync(
          binary,
          ["adapt", "--config", config, "--adapter", "caddyfile", "--validate"],
          {
            cwd: directory,
            env,
            timeout: 10_000,
            windowsHide: true,
            encoding: "utf8",
            maxBuffer: 1024 * 1024,
            stdio: ["ignore", "pipe", "ignore"],
          },
        ),
      );
      const dials = [];
      const collectDials = (node) => {
        if (Array.isArray(node)) node.forEach(collectDials);
        else if (node && typeof node === "object") {
          if (node.handler === "reverse_proxy")
            dials.push(...node.upstreams.map((upstream) => upstream.dial));
          Object.values(node).forEach(collectDials);
        }
      };
      collectDials(adapted);
      assert.deepEqual(
        dials.toSorted(),
        [
          `127.0.0.1:${identityUpstream}`,
          `127.0.0.1:${storageUpstream}`,
        ].toSorted(),
        "the actual Caddy configuration must have no application upstream or additional listener route",
      );
      assert.deepEqual(
        Object.values(adapted.apps.http.servers)
          .flatMap((server) => server.listen)
          .toSorted(),
        [`127.0.0.1:${identityPort}`, `127.0.0.1:${storagePort}`].toSorted(),
      );
      await Promise.all(
        reservations.map(
          (server) =>
            new Promise((resolve, reject) =>
              server.close((error) => (error ? reject(error) : resolve())),
            ),
        ),
      );
      const signal = AbortSignal.any([t.signal, AbortSignal.timeout(60_000)]);
      const send = (port, options = {}) => request(port, options, signal);
      child = spawn(
        binary,
        ["run", "--config", config, "--adapter", "caddyfile"],
        { cwd: directory, env, windowsHide: true, stdio: "ignore" },
      );
      childClosed = new Promise((resolve) => {
        child.once("error", () => {
          childDone = true;
          resolve();
        });
        child.once("close", () => {
          childDone = true;
          resolve();
        });
      });
      const deadline = Date.now() + 10_000;
      let ready = false;
      while (Date.now() < deadline) {
        if (childDone || signal.aborted) break;
        try {
          const response = await send(identityPort, {
            target: "/health/live",
            localAddress: "127.0.0.1",
          });
          if (response.status === 200 && response.body.toString() === "ok") {
            ready = true;
            break;
          }
        } catch {
          /* The startup retry is bounded and never skips. */
        }
        await delay(50);
      }
      assert.ok(
        ready && !childDone,
        "owned auxiliary Caddy must start within 10 seconds",
      );

      await t.test(
        "only exact loopback GET health bypasses peer admission",
        async () => {
          const before = seen.length;
          for (const port of [identityPort, storagePort]) {
            const healthy = await send(port, {
              target: "/health/live",
              localAddress: "127.0.0.1",
            });
            assert.equal(healthy.status, 200);
            assert.equal(healthy.body.toString(), "ok");
            for (const denied of [
              { method: "HEAD", target: "/health/live" },
              { method: "POST", target: "/health/live" },
              { method: "OPTIONS", target: "/health/live" },
              { target: "/health/ready" },
              { target: "/health/live/" },
              { target: "/api/v1/auth/session" },
            ]) {
              const response = await send(port, {
                ...denied,
                localAddress: "127.0.0.1",
              });
              assert.equal(response.status, 403);
            }
            const remoteHealth = await send(port, {
              target: "/health/live",
              localAddress: "127.0.0.3",
            });
            assert.equal(remoteHealth.status, 403);
          }
          assert.equal(
            seen.length,
            before,
            "health exceptions cannot reach an upstream",
          );
        },
      );

      await t.test(
        "untrusted socket peers cannot forge their way into preflight or either upstream",
        async () => {
          const before = seen.length;
          for (const port of [identityPort, storagePort]) {
            for (const target of [
              "/periapsis-evidence/object",
              "/realms/periapsis-test/.well-known/openid-configuration",
              "/api/v1/auth/session",
            ]) {
              for (const method of ["GET", "HEAD", "PUT", "OPTIONS"]) {
                const response = await send(port, {
                  target,
                  method,
                  localAddress: "127.0.0.3",
                  headers: {
                    Origin: origin,
                    "Access-Control-Request-Method": "PUT",
                    "X-Forwarded-For": "127.0.0.2",
                    "X-Forwarded-Proto": "https",
                    "X-Real-IP": "127.0.0.2",
                    Forwarded: "for=127.0.0.2;proto=https",
                  },
                });
                assert.equal(response.status, 403);
                assertCorsPolicy(response, { browser: false });
              }
            }
          }
          assert.equal(
            seen.length,
            before,
            "peer rejection must precede CORS and reverse_proxy",
          );
        },
      );

      await t.test(
        "trusted proxy reaches the intended auxiliary services with the remote HTTPS origin",
        async () => {
          const before = seen.length;
          const preflight = await send(storagePort, {
            method: "OPTIONS",
            localAddress: "127.0.0.2",
            headers: {
              Origin: origin,
              "Access-Control-Request-Method": "PUT",
              "Access-Control-Request-Headers": "If-None-Match",
            },
          });
          assert.equal(preflight.status, 204);
          assertCorsPolicy(preflight, { preflight: true, origin });
          assertVary(preflight);
          assert.equal(seen.length, before);
          const storage = await send(storagePort, {
            localAddress: "127.0.0.2",
            headers: { Origin: origin, Host: "evidence.example.test:9444" },
          });
          assert.equal(storage.status, 200);
          assert.equal(storage.body.toString(), "storage");
          assertCorsPolicy(storage, { origin });
          assert.equal(seen.at(-1).kind, "storage");
          assert.equal(seen.at(-1).headers.host, "evidence.example.test:9444");
          const identityTarget =
            "/realms/periapsis-test/.well-known/openid-configuration?fixture=%2F";
          const identity = await send(identityPort, {
            target: identityTarget,
            localAddress: "127.0.0.2",
            headers: {
              Host: "identity.example.test:9445",
              "X-Forwarded-Proto": "http",
            },
          });
          assert.equal(identity.status, 200);
          assert.equal(identity.body.toString(), "identity");
          assert.equal(seen.at(-1).kind, "identity");
          assert.equal(seen.at(-1).target, identityTarget);
          assert.equal(seen.at(-1).headers.host, "identity.example.test:9445");
          assert.equal(seen.at(-1).headers["x-forwarded-proto"], "https");
          // An application-shaped path cannot select a hidden application upstream.
          for (const [port, kind] of [
            [identityPort, "identity"],
            [storagePort, "storage"],
          ]) {
            const response = await send(port, {
              target: "/api/v1/auth/session",
              localAddress: "127.0.0.2",
              headers: { Host: "incidents.example.test:9443" },
            });
            assert.equal(response.headers["x-fixture-upstream"], kind);
            assert.equal(seen.at(-1).kind, kind);
          }
        },
      );
    } catch (error) {
      cleanup.push(error);
    } finally {
      try {
        if (child && !childDone) {
          child.kill("SIGTERM");
          await Promise.race([
            childClosed,
            delay(3_000, undefined, { ref: false }),
          ]);
          if (!childDone) {
            child.kill("SIGKILL");
            await Promise.race([
              childClosed,
              delay(3_000, undefined, { ref: false }),
            ]);
          }
          if (!childDone)
            cleanup.push(
              new Error("owned auxiliary Caddy process did not stop"),
            );
        }
      } catch (error) {
        cleanup.push(error);
      }
      for (const socket of sockets) socket.destroy();
      await Promise.all(
        [...reservations, ...upstreams]
          .filter((server) => server.listening)
          .map((server) => new Promise((resolve) => server.close(resolve))),
      );
      try {
        assert.equal(
          digest(await readFile(auxiliaryPath)),
          digest(source),
          "auxiliary deployment changed during proof",
        );
        assert.equal(
          digest(await readFile(snippetPath)),
          digest(snippet),
          "shared CORS policy changed during proof",
        );
      } catch (error) {
        cleanup.push(error);
      }
      try {
        await rm(directory, { recursive: true, force: true });
      } catch (error) {
        cleanup.push(error);
      }
    }
    if (cleanup.length)
      throw new AggregateError(
        cleanup,
        "auxiliary edge runtime proof or cleanup failed",
      );
  },
);

function storageConfig(source, snippet, port, upstreamPort) {
  assert.equal(
    source.split("import /etc/caddy/storage-cors.caddy").length,
    2,
    "deployment must import the shared storage policy exactly once",
  );
  assert.equal(
    source.split(storageSite).length,
    2,
    "storage site must exist exactly once",
  );
  const suffix = source.slice(source.indexOf(storageSite));
  // Top-level closing braces are unindented; environment placeholders contain
  // braces too, so a character-counting parser would incorrectly slice the site.
  const closing = suffix.indexOf("\n}");
  assert.notEqual(closing, -1, "storage site closing brace is required");
  let block = suffix.slice(0, closing + 2);
  block = replaceExactlyOnce(block, storageSite, `http://:${port} {`);
  block = replaceExactlyOnce(
    block,
    "\timport periapsis_dev_tls",
    "\tbind 127.0.0.1",
  );
  const policy = replaceExactlyOnce(
    snippet,
    "reverse_proxy http://minio:9000",
    `reverse_proxy http://127.0.0.1:${upstreamPort}`,
  );
  block = replaceExactlyOnce(
    block,
    "import periapsis_storage_cors https://localhost:{$PERIAPSIS_WEB_PORT:8443}",
    "import periapsis_storage_cors {$PERIAPSIS_PUBLIC_URL}",
  );
  // Change only transport addresses/TLS import and the snippet's origin argument.
  // The shared policy body is the actual deployment source in both origin cases.
  return `{\n\tadmin off\n\tauto_https off\n}\n\n${policy}\n${block}\n`;
}

async function listen(server) {
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return server.address().port;
}

function request(
  port,
  {
    method = "GET",
    target = "/periapsis-evidence/object",
    headers = {},
    body = Buffer.alloc(0),
    localAddress,
  } = {},
  signal,
) {
  return new Promise((resolve, reject) => {
    const outgoing = http.request(
      {
        host: "127.0.0.1",
        port,
        method,
        path: target,
        headers,
        agent: false,
        signal,
        localAddress,
      },
      (incoming) => {
        const chunks = [];
        incoming.on("data", (chunk) => chunks.push(chunk));
        incoming.on("error", reject);
        incoming.on("end", () =>
          resolve({
            status: incoming.statusCode,
            headers: incoming.headers,
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    const timer = setTimeout(
      () => outgoing.destroy(new Error("fixture request deadline exceeded")),
      3_000,
    );
    outgoing.on("close", () => clearTimeout(timer));
    outgoing.on("error", reject);
    outgoing.end(body);
  });
}

function assertVary(response, upstream = false) {
  assert.deepEqual(
    new Set(tokens(response.headers.vary)),
    new Set(upstream ? [...vary, "accept-encoding"] : vary),
  );
}

function assertCorsPolicy(
  response,
  { preflight = false, browser = true, origin } = {},
) {
  const expected = browser
    ? preflight
      ? [
          "access-control-allow-origin",
          "access-control-allow-methods",
          "access-control-allow-headers",
          "access-control-max-age",
        ]
      : ["access-control-allow-origin", "access-control-expose-headers"]
    : [];
  assert.deepEqual(
    Object.keys(response.headers)
      .filter((name) => name.startsWith("access-control-"))
      .toSorted(),
    expected.toSorted(),
  );
  if (browser)
    assert.equal(response.headers["access-control-allow-origin"], origin);
  if (preflight) {
    assert.deepEqual(tokens(response.headers["access-control-allow-methods"]), [
      "get",
      "head",
      "put",
    ]);
    assert.deepEqual(
      tokens(response.headers["access-control-allow-headers"]),
      allowedHeaders,
    );
    assert.equal(response.headers["access-control-max-age"], "300");
  } else if (browser) {
    assert.equal(response.headers["access-control-expose-headers"], "ETag");
  }
  assert.equal(response.headers["access-control-allow-credentials"], undefined);
}

for (const origin of [
  "https://localhost:8443",
  "https://incidents.example.test:9443",
]) {
  test(
    `the deployed storage CORS boundary works with real Caddy 2.11.4 for ${origin}`,
    { timeout: 90_000 },
    async (t) => {
      const assertCors = (response, options) =>
        assertCorsPolicy(response, { ...options, origin });
      const binary = process.env.PERIAPSIS_CADDY_BINARY;
      assert.ok(
        binary && path.isAbsolute(binary),
        "PERIAPSIS_CADDY_BINARY must name the installed Caddy 2.11.4 binary; this gate cannot skip",
      );
      const version = execFileSync(binary, ["version"], {
        timeout: 5_000,
        windowsHide: true,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      assert.match(
        version,
        /^v2\.11\.4(?:\s|$)/,
        "the actual deployed Caddy version is required",
      );
      const source = await readFile(sourcePath, "utf8");
      const snippet = await readFile(snippetPath, "utf8");
      const directory = await mkdtemp(
        path.join(tmpdir(), "periapsis-storage-cors-"),
      );
      const seen = [];
      const objects = new Map();
      const sockets = new Set();
      const upstream = http.createServer(async (incoming, outgoing) => {
        const chunks = [];
        for await (const chunk of incoming) chunks.push(chunk);
        const body = Buffer.concat(chunks);
        seen.push({
          method: incoming.method,
          target: incoming.url,
          headers: incoming.headers,
          body,
        });
        // Intentionally more permissive than the browser boundary. None may leak.
        outgoing.setHeader("Access-Control-Allow-Origin", "*");
        outgoing.setHeader("Access-Control-Allow-Credentials", "true");
        outgoing.setHeader(
          "Access-Control-Allow-Methods",
          "GET, HEAD, PUT, DELETE, POST",
        );
        outgoing.setHeader("Access-Control-Allow-Headers", "*");
        outgoing.setHeader(
          "Access-Control-Expose-Headers",
          "ETag, X-Internal-Fixture",
        );
        outgoing.setHeader("Access-Control-Max-Age", "86400");
        outgoing.setHeader("Access-Control-Allow-Private-Network", "true");
        outgoing.setHeader("Vary", "Accept-Encoding");
        outgoing.setHeader("ETag", etag);
        outgoing.setHeader("X-Internal-Fixture", "not-browser-exposed");
        if (incoming.url.startsWith("/periapsis-evidence/error/")) {
          outgoing.statusCode = Number(incoming.url.split("/").at(-1));
          outgoing.end("fixture upstream error");
        } else if (incoming.method === "PUT") {
          if (
            objects.has(incoming.url) &&
            incoming.headers["if-none-match"] === "*"
          ) {
            outgoing.statusCode = 412;
            outgoing.end("fixture conditional write rejected");
          } else {
            objects.set(incoming.url, body);
            outgoing.end();
          }
        } else {
          outgoing.end(
            objects.get(incoming.url) ?? Buffer.from("fixture object"),
          );
        }
      });
      upstream.on("connection", (socket) => {
        sockets.add(socket);
        socket.on("close", () => sockets.delete(socket));
      });
      let child;
      let childClosed;
      let childDone = false;
      let reservation;
      const cleanup = [];
      try {
        const upstreamPort = await listen(upstream);
        reservation = http.createServer();
        const port = await listen(reservation);
        const signal = AbortSignal.any([t.signal, AbortSignal.timeout(60_000)]);
        const send = (options) => request(port, options, signal);
        await new Promise((resolve, reject) =>
          reservation.close((error) => (error ? reject(error) : resolve())),
        );
        const config = path.join(directory, "Caddyfile");
        await writeFile(
          config,
          storageConfig(source, snippet, port, upstreamPort),
          {
            flag: "wx",
            mode: 0o600,
          },
        );
        child = spawn(
          binary,
          ["run", "--config", config, "--adapter", "caddyfile"],
          {
            cwd: directory,
            windowsHide: true,
            stdio: "ignore",
            env: {
              ...process.env,
              PERIAPSIS_WEB_PORT: "8443",
              PERIAPSIS_PUBLIC_URL: origin,
              XDG_CONFIG_HOME: directory,
              XDG_DATA_HOME: directory,
              APPDATA: directory,
            },
          },
        );
        childClosed = new Promise((resolve) => {
          child.once("error", () => {
            childDone = true;
            resolve();
          });
          child.once("close", () => {
            childDone = true;
            resolve();
          });
        });
        const deadline = Date.now() + 10_000;
        let ready = false;
        while (Date.now() < deadline) {
          if (childDone || signal.aborted) break;
          try {
            const response = await send({
              target: "/minio/health/live",
            });
            if (
              response.status === 200 &&
              response.headers["x-internal-fixture"] === "not-browser-exposed"
            ) {
              ready = true;
              break;
            }
          } catch {
            /* Startup connection refusal is bounded, not a skipped gate. */
          }
          await delay(50);
        }
        assert.ok(
          ready && !childDone,
          "owned Caddy must start and reach the fixture within 10 seconds",
        );
        seen.length = 0;

        await t.test(
          "GET/HEAD/PUT preflights have the exact seven-header policy",
          async () => {
            for (const method of ["GET", "HEAD", "PUT"]) {
              for (const requested of [
                allowedHeaders.join(", "),
                "If-None-Match",
                "content-type",
              ]) {
                const response = await send({
                  method: "OPTIONS",
                  headers: {
                    Origin: origin,
                    "Access-Control-Request-Method": method,
                    "Access-Control-Request-Headers": requested,
                  },
                });
                assert.equal(response.status, 204);
                assert.equal(response.body.length, 0);
                assertCors(response, { preflight: true });
                assertVary(response);
              }
            }
            assert.equal(
              seen.length,
              0,
              "preflights must never reach object storage",
            );
          },
        );

        await t.test(
          "unsupported headers cannot be reflected into a successful browser grant",
          async () => {
            const response = await send({
              method: "OPTIONS",
              headers: {
                Origin: origin,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers":
                  "If-None-Match, Authorization, X-Fixture-Forbidden",
              },
            });
            assert.equal(response.status, 204);
            assertCors(response, { preflight: true });
            assert.equal(
              tokens(response.headers["access-control-allow-headers"]).includes(
                "authorization",
              ),
              false,
            );
            assert.equal(
              tokens(response.headers["access-control-allow-headers"]).includes(
                "x-fixture-forbidden",
              ),
              false,
            );
            assert.equal(seen.length, 0);
          },
        );

        await t.test(
          "wrong origins, methods and browser paths fail closed without upstream access",
          async () => {
            const before = seen.length;
            for (const wrongOrigin of [
              "https://attacker.invalid",
              "http://localhost:8443",
              "https://localhost:8444",
              "https://localhost:8443/",
              "",
              "null",
              `${origin}, https://attacker.invalid`,
              `${origin}/`,
              origin.replace("https:", "http:"),
            ]) {
              for (const method of ["OPTIONS", "GET", "HEAD", "PUT"]) {
                const response = await send({
                  method,
                  headers: {
                    Origin: wrongOrigin,
                    "Access-Control-Request-Method": "PUT",
                  },
                });
                assert.equal(response.status, 403);
                assertCors(response, { browser: false });
                assertVary(response);
              }
            }
            for (const denied of [
              {
                method: "OPTIONS",
                headers: {
                  Origin: origin,
                  "Access-Control-Request-Method": "DELETE",
                },
              },
              { method: "OPTIONS", headers: { Origin: origin } },
              {
                method: "OPTIONS",
                headers: { "Access-Control-Request-Method": "PUT" },
              },
              { method: "DELETE", headers: { Origin: origin } },
              { method: "POST", headers: { Origin: origin } },
              { target: "/other-bucket/object", headers: { Origin: origin } },
              {
                method: "OPTIONS",
                target: "/other-bucket/object",
                headers: {
                  Origin: origin,
                  "Access-Control-Request-Method": "PUT",
                },
              },
            ]) {
              const response = await send(denied);
              assert.equal(response.status, 403);
              assertCors(response, { browser: false });
              assertVary(response);
            }
            assert.equal(seen.length, before);
          },
        );

        await t.test(
          "signed URL, Host, headers, body, ETag and conditional replay survive the proxy",
          async () => {
            // Deliberately invalid synthetic signature; this is a transport proof, not
            // MinIO authentication or browser enforcement acceptance.
            const target =
              "/periapsis-evidence/fixture%2Fobject%20name?part=2&part=1&X-Amz-Signature=invalid-fixture&x=%2F%2b";
            const body = Buffer.from([0, 1, 2, 127, 128, 254, 255]);
            const headers = {
              Host: "storage.localhost:19000",
              Origin: origin,
              "Cache-Control": "private, max-age=0",
              "Content-Disposition": 'attachment; filename="fixture.bin"',
              "Content-Length": String(body.length),
              "Content-Type": "application/octet-stream",
              "If-None-Match": "*",
              "X-Amz-Meta-Periapsis-Declared-Mime": "application/octet-stream",
              "X-Amz-Meta-Periapsis-Expected-Size": String(body.length),
            };
            const first = await send({
              method: "PUT",
              target,
              headers,
              body,
            });
            assert.equal(first.status, 200);
            assertCors(first);
            assertVary(first, true);
            assert.equal(first.headers.etag, etag);
            const forwarded = seen.at(-1);
            assert.equal(forwarded.method, "PUT");
            assert.equal(forwarded.target, target);
            assert.deepEqual(forwarded.body, body);
            for (const [name, value] of Object.entries(headers))
              assert.equal(
                forwarded.headers[name.toLowerCase()],
                value,
                `forwarded ${name}`,
              );
            const replay = await send({
              method: "PUT",
              target,
              headers,
              body: Buffer.alloc(body.length, 9),
            });
            assert.equal(replay.status, 412);
            assert.equal(
              replay.body.toString(),
              "fixture conditional write rejected",
            );
            assertCors(replay);
            assertVary(replay, true);
            for (const method of ["GET", "HEAD"]) {
              const response = await send({
                method,
                target,
                headers: { Host: headers.Host, Origin: origin },
              });
              assert.equal(response.status, 200);
              assert.deepEqual(
                response.body,
                method === "GET" ? body : Buffer.alloc(0),
              );
              assert.equal(response.headers.etag, etag);
              assertCors(response);
              assertVary(response, true);
            }
          },
        );

        await t.test(
          "originless server-side traffic and upstream errors remain unchanged without upstream CORS",
          async () => {
            for (const method of ["GET", "HEAD", "PUT", "DELETE"]) {
              const target =
                "/server-side/fixture%2Fkey?X-Amz-Signature=invalid-fixture&x=%2B";
              const body =
                method === "PUT"
                  ? Buffer.from("fixture server-side body")
                  : Buffer.alloc(0);
              const headers = {
                Host: "storage.localhost:19000",
                "If-None-Match": "*",
                ...(method === "PUT"
                  ? {
                      "Content-Type": "application/octet-stream",
                      "Content-Length": String(body.length),
                    }
                  : {}),
              };
              const response = await send({
                method,
                target,
                headers,
                body,
              });
              assert.equal(response.status, 200);
              assertCors(response, { browser: false });
              assertVary(response, true);
              const forwarded = seen.at(-1);
              assert.equal(forwarded.target, target);
              assert.equal(forwarded.method, method);
              assert.deepEqual(forwarded.body, body);
              for (const [name, value] of Object.entries(headers))
                assert.equal(forwarded.headers[name.toLowerCase()], value);
              assert.equal(forwarded.headers.origin, undefined);
            }
            for (const status of [403, 404, 500]) {
              for (const browser of [true, false]) {
                const response = await send({
                  target: `/periapsis-evidence/error/${status}`,
                  headers: browser ? { Origin: origin } : {},
                });
                assert.equal(response.status, status);
                assert.equal(
                  response.body.toString(),
                  "fixture upstream error",
                );
                assertCors(response, { browser });
                assertVary(response, true);
              }
            }
          },
        );
      } catch (error) {
        cleanup.push(error);
      } finally {
        try {
          if (child && !childDone) {
            child.kill("SIGTERM");
            await Promise.race([
              childClosed,
              delay(3_000, undefined, { ref: false }),
            ]);
            if (!childDone) {
              child.kill("SIGKILL");
              await Promise.race([
                childClosed,
                delay(3_000, undefined, { ref: false }),
              ]);
            }
            if (!childDone)
              cleanup.push(new Error("owned Caddy process did not stop"));
          }
        } catch (error) {
          cleanup.push(error);
        }
        if (reservation?.listening)
          await new Promise((resolve) => reservation.close(resolve));
        for (const socket of sockets) socket.destroy();
        if (upstream.listening)
          await new Promise((resolve) => upstream.close(resolve));
        try {
          assert.equal(
            digest(await readFile(sourcePath)),
            digest(source),
            "deployment source changed during runtime proof",
          );
          assert.equal(
            digest(await readFile(snippetPath)),
            digest(snippet),
            "shared storage policy changed during runtime proof",
          );
        } catch (error) {
          cleanup.push(error);
        }
        try {
          await rm(directory, { recursive: true, force: true });
        } catch (error) {
          cleanup.push(error);
        }
      }
      if (cleanup.length)
        throw new AggregateError(
          cleanup,
          "storage CORS runtime proof or cleanup failed",
        );
    },
  );
}
