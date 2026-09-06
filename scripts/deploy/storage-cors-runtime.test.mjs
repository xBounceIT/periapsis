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

const origin = "https://localhost:8443";
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
const storageSite =
  "https://storage.localhost:{$PERIAPSIS_MINIO_API_PORT:19000} {";
const etag = '"fixture-etag"';
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const tokens = (value = "") =>
  value.split(",").map((part) => part.trim().toLowerCase());

function replaceExactlyOnce(source, from, to) {
  assert.equal(
    source.split(from).length,
    2,
    "deployment fixture anchor must be unique",
  );
  return source.replace(from, () => to);
}

function storageConfig(source, port, upstreamPort) {
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
  block = replaceExactlyOnce(
    block,
    "reverse_proxy http://minio:9000",
    `reverse_proxy http://127.0.0.1:${upstreamPort}`,
  );
  // Only transport addresses/TLS import change; all deployed CORS rules remain.
  return `{\n\tadmin off\n\tauto_https off\n}\n\n${block}\n`;
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

function assertCors(response, { preflight = false, browser = true } = {}) {
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

test(
  "the deployed storage CORS boundary works with real Caddy 2.11.4",
  { timeout: 90_000 },
  async (t) => {
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
      await writeFile(config, storageConfig(source, port, upstreamPort), {
        flag: "wx",
        mode: 0o600,
      });
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
              assert.equal(response.body.toString(), "fixture upstream error");
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
