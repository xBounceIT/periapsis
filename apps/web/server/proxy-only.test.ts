// @vitest-environment node

import { createServer, request as httpRequest } from "node:http";
import type { IncomingHttpHeaders } from "node:http";
import { connect } from "node:net";

import { afterEach, describe, expect, it, vi } from "vitest";

import { createWebServer, isLoopbackReadinessProbe } from "./index.js";

const servers = new Set<ReturnType<typeof createServer>>();
const publicUrl = "https://periapsis.example.test";
const proxyHeaders = {
  host: "periapsis.example.test",
  "x-forwarded-for": "198.51.100.42",
  "x-forwarded-proto": "https",
};

afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(
    [...servers].map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve());
          server.closeAllConnections();
        }),
    ),
  );
  servers.clear();
});

describe("explicit proxy-only web origin", () => {
  it.each([
    "",
    " ",
    "0.0.0.0/0",
    "127.0.0.1/0",
    "::/0",
    "2001:db8::1/0",
    "127.0.0.1/32, ::/0",
    "127.0.0.1",
    "127.0.0.1/33",
  ])("rejects missing, universal or invalid proxy CIDRs (%s)", (cidrs) => {
    expect(() =>
      createWebServer({ proxyOnly: true, publicUrl, trustedProxyCIDRs: cidrs }),
    ).toThrow(/PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS/);
  });

  it.each([
    "",
    "http://periapsis.example.test",
    "https://PERIAPSIS.example.test",
    "https://periapsis.example.test/",
    "https://periapsis.example.test:443",
    "https://periapsis.example.test:0",
    "https://periapsis.example.test.",
    "https://bad_host.example.test",
    "https://user@periapsis.example.test",
    "https://periapsis.example.test/path",
    "https://periapsis.example.test?",
    "https://periapsis.example.test#fragment",
    " https://periapsis.example.test",
    "https://127.1",
    "https://0177.0.0.1",
    "https://0x7f000001",
    "https://[0:0:0:0:0:0:0:1]",
  ])("requires a canonical public HTTPS origin (%s)", (origin) => {
    expect(() =>
      createWebServer({
        proxyOnly: true,
        publicUrl: origin,
        trustedProxyCIDRs: "127.0.0.1/32",
      }),
    ).toThrow(/PERIAPSIS_PUBLIC_URL/);
  });

  it.each(["1", "TRUE", "True", "yes", "", "false "])(
    "rejects an ambiguous mode environment value (%s)",
    (mode) => {
      vi.stubEnv("PERIAPSIS_WEB_PROXY_ONLY", mode);
      expect(() => createWebServer()).toThrow(/PERIAPSIS_WEB_PROXY_ONLY/);
    },
  );

  it("loads all proxy-only policy pins from the environment", async () => {
    vi.stubEnv("PERIAPSIS_WEB_PROXY_ONLY", "true");
    vi.stubEnv("PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS", "127.0.0.1/32");
    vi.stubEnv("PERIAPSIS_PUBLIC_URL", publicUrl);
    const port = await listen(createWebServer());
    expect(
      (await request(port, "/runtime-config.json", proxyHeaders)).status,
    ).toBe(200);
    vi.stubEnv("PERIAPSIS_PUBLIC_URL", undefined);
    expect(() => createWebServer()).toThrow(/PERIAPSIS_PUBLIC_URL/);
    vi.stubEnv("PERIAPSIS_PUBLIC_URL", publicUrl);
    vi.stubEnv("PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS", undefined);
    expect(() => createWebServer()).toThrow(
      /PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS/,
    );
  });

  it("keeps default direct HTTP behavior without requiring a public origin", async () => {
    vi.stubEnv("PERIAPSIS_WEB_PROXY_ONLY", undefined);
    vi.stubEnv("PERIAPSIS_PUBLIC_URL", "not-a-public-origin");
    const fixture = await createFixture({
      proxyOnly: false,
      trustedProxyCIDRs: "",
    });
    const response = await request(fixture.port, "/api/check", {
      ...proxyHeaders,
      host: "not-the-public-host.example.test",
    });
    expect(response.status).toBe(200);
    expect(fixture.calls[0]?.headers["x-forwarded-for"]).toBe("127.0.0.1");
    expect(fixture.calls[0]?.headers["x-forwarded-proto"]).toBe("http");
    expect((await request(fixture.port, "/runtime-config.json")).status).toBe(
      200,
    );
    expect(
      (await request(fixture.port, "/health/live", {}, "HEAD")).status,
    ).toBe(404);
  });

  it("rejects an untrusted actual socket before static assets and API routing", async () => {
    const fixture = await createFixture({ trustedProxyCIDRs: "127.0.0.2/32" });
    await Promise.all(
      ["/", "/index.html", "/runtime-config.json", "/api/check"].map(
        async (path) => {
          const response = await request(fixture.port, path, proxyHeaders);
          expect(response.status).toBe(403);
          expect(response.body).toContain("Trusted proxy required");
          expect(response.body).not.toContain(proxyHeaders["x-forwarded-for"]);
        },
      ),
    );
    expect(fixture.calls).toHaveLength(0);
  });

  it("preserves exact loopback GET readiness through the actual API upstream", async () => {
    const fixture = await createFixture();
    const response = await request(fixture.port, "/health/ready", {
      host: "local-probe.invalid",
      "x-forwarded-for": "203.0.113.250",
      "x-forwarded-proto": "https",
    });
    expect(response.status).toBe(200);
    expect(response.body).toBe("upstream reached");
    expect(fixture.calls).toHaveLength(1);
    expect(fixture.calls[0]?.path).toBe("/health/ready");
    expect(fixture.calls[0]?.headers["x-forwarded-for"]).toBe("127.0.0.1");
    expect(fixture.calls[0]?.headers["x-forwarded-proto"]).toBe("http");
    await Promise.all(
      (
        [
          ["HEAD", "/health/ready"],
          ["POST", "/health/ready"],
          ["GET", "/health/ready?probe=1"],
          ["GET", "/other/../health/ready"],
          ["GET", "http://local-probe.invalid/health/ready"],
          ["GET", "/api/health/ready"],
        ] as const
      ).map(async ([method, target]) => {
        expect((await request(fixture.port, target, {}, method)).status).toBe(
          400,
        );
      }),
    );
    expect(fixture.calls).toHaveLength(1);
  });

  it("does not exempt non-loopback or merely adjacent readiness peers", async () => {
    for (const peer of [
      "127.0.0.1",
      "::1",
      "::ffff:127.0.0.1",
      "::ffff:7f00:1",
    ]) {
      expect(isLoopbackReadinessProbe("GET", "/health/ready", peer)).toBe(true);
    }
    for (const peer of [
      "127.0.0.2",
      "198.51.100.42",
      "2001:db8::42",
      "::ffff:198.51.100.42",
      "fe80::1%eth0",
      "invalid",
      undefined,
    ]) {
      expect(isLoopbackReadinessProbe("GET", "/health/ready", peer)).toBe(
        false,
      );
    }
    const fixture = await createFixture();
    const response = await request(
      fixture.port,
      "/health/ready",
      proxyHeaders,
      "GET",
      "127.0.0.1",
      "127.0.0.2",
    );
    expect(response.status).toBe(403);
    expect(fixture.calls).toHaveLength(0);
  });

  it("preserves an unhealthy API result for the direct readiness probe", async () => {
    const fixture = await createFixture({}, "127.0.0.1", 503);
    expect((await request(fixture.port, "/health/ready")).status).toBe(503);
    expect(fixture.calls).toHaveLength(1);
  });

  it("exempts only exact direct GET and HEAD liveness probes", async () => {
    const fixture = await createFixture({ trustedProxyCIDRs: "127.0.0.2/32" });
    await Promise.all(
      ["GET", "HEAD"].map(async (method) => {
        const response = await request(
          fixture.port,
          "/health/live",
          {},
          method,
        );
        expect(response.status).toBe(200);
        if (method === "HEAD") expect(response.body).toBe("");
      }),
    );
    await Promise.all(
      (
        [
          ["POST", "/health/live"],
          ["OPTIONS", "/health/live"],
          ["GET", "/health/live?probe=1"],
          ["GET", "/other/../health/live"],
          ["GET", "/health/%6cive"],
          ["HEAD", "/health/ready"],
          ["POST", "/api/mutation"],
        ] as const
      ).map(async ([method, path]) => {
        expect((await request(fixture.port, path, {}, method)).status).toBe(
          403,
        );
      }),
    );
    expect(fixture.calls).toHaveLength(0);
  });

  it("validates forwarding metadata before serving non-API public configuration", async () => {
    const fixture = await createFixture();
    expect((await request(fixture.port, "/runtime-config.json")).status).toBe(
      400,
    );
    expect((await request(fixture.port, "/index.html")).status).toBe(400);
    expect(
      (await request(fixture.port, "/runtime-config.json", proxyHeaders))
        .status,
    ).toBe(200);
    expect(fixture.calls).toHaveLength(0);
  });

  it("forwards one canonical right-to-left client IP and strips alternate metadata", async () => {
    const fixture = await createFixture();
    const response = await request(fixture.port, "/api/check?kept=yes", {
      ...proxyHeaders,
      "x-forwarded-for": "203.0.113.250, 198.51.100.42, 127.0.0.1",
      forwarded: "for=203.0.113.250;proto=http",
      "x-forwarded-host": "spoof.example.test",
      "x-forwarded-port": "80",
      "x-forwarded-server": "spoof.example.test",
      "x-original-forwarded-for": "203.0.113.250",
      "x-real-ip": "203.0.113.250",
      "x-client-ip": "203.0.113.250",
      "true-client-ip": "203.0.113.250",
      "cf-connecting-ip": "203.0.113.250",
      "fastly-client-ip": "203.0.113.250",
      "x-cluster-client-ip": "203.0.113.250",
      "x-request-id": "retained-marker",
    });
    expect(response.status).toBe(200);
    expect(fixture.calls).toHaveLength(1);
    const actual = fixture.calls[0];
    expect(actual.path).toBe("/api/check?kept=yes");
    expect(actual.headers["x-forwarded-for"]).toBe("198.51.100.42");
    expect(actual.headers["x-forwarded-proto"]).toBe("https");
    expect(actual.headers.host).toBe(`127.0.0.1:${fixture.apiPort}`);
    expect(actual.headers["x-request-id"]).toBe("retained-marker");
    for (const name of [
      "forwarded",
      "x-forwarded-host",
      "x-forwarded-port",
      "x-forwarded-server",
      "x-original-forwarded-for",
      "x-real-ip",
      "x-client-ip",
      "true-client-ip",
      "cf-connecting-ip",
      "fastly-client-ip",
      "x-cluster-client-ip",
    ])
      expect(actual.headers).not.toHaveProperty(name);
  });

  it.each([
    ["::ffff:198.51.100.42", "198.51.100.42"],
    ["::ffff:c633:642a", "198.51.100.42"],
    ["0:0:0:0:0:ffff:c633:642a", "198.51.100.42"],
    ["2001:0db8:0:0:0:0:0:42", "2001:db8::42"],
  ] as const)(
    "canonicalizes client %s on the real HTTP path",
    async (forwarded, expected) => {
      const fixture = await createFixture();
      expect(
        (
          await request(fixture.port, "/api/check", {
            ...proxyHeaders,
            "x-forwarded-for": forwarded,
          })
        ).status,
      ).toBe(200);
      expect(fixture.calls.at(-1)?.headers["x-forwarded-for"]).toBe(expected);
    },
  );

  it("uses an explicitly trusted actual IPv6 loopback peer", async () => {
    const fixture = await createFixture(
      { trustedProxyCIDRs: "::1/128" },
      "::1",
    );
    expect(
      (await request(fixture.port, "/api/check", proxyHeaders, "GET", "::1"))
        .status,
    ).toBe(200);
    expect(fixture.calls[0]?.headers["x-forwarded-for"]).toBe("198.51.100.42");
    expect(
      (await request(fixture.port, "/health/ready", {}, "GET", "::1")).status,
    ).toBe(200);
    expect(fixture.calls[1]?.headers["x-forwarded-for"]).toBe("::1");
    expect(fixture.calls[1]?.headers["x-forwarded-proto"]).toBe("http");
  });

  it("rejects malformed, absent and oversized chains and protocols without reaching API", async () => {
    const fixture = await createFixture();
    const invalid: Array<Record<string, string | undefined>> = [
      { "x-forwarded-for": undefined },
      { "x-forwarded-for": "" },
      { "x-forwarded-for": "198.51.100.42, invalid" },
      { "x-forwarded-for": "invalid, 198.51.100.42" },
      { "x-forwarded-for": "198.51.100.42," },
      { "x-forwarded-for": "198.51.100.42:80" },
      { "x-forwarded-for": "[2001:db8::42]" },
      { "x-forwarded-for": "fe80::42%eth0" },
      { "x-forwarded-for": "127.1" },
      {
        "x-forwarded-for": Array.from(
          { length: 33 },
          () => "198.51.100.42",
        ).join(","),
      },
      { "x-forwarded-for": "1".repeat(2049) },
      { "x-forwarded-proto": undefined },
      { "x-forwarded-proto": "" },
      { "x-forwarded-proto": "http" },
      { "x-forwarded-proto": "HTTPS" },
      { "x-forwarded-proto": "https,http" },
    ];
    await Promise.all(
      invalid.map(async (delta) => {
        const headers = Object.fromEntries(
          Object.entries({ ...proxyHeaders, ...delta }).filter(
            (entry): entry is [string, string] => entry[1] !== undefined,
          ),
        );
        const response = await request(fixture.port, "/api/check", headers);
        expect(response.status).toBe(400);
        expect(response.body).toContain("Invalid trusted proxy request");
      }),
    );
    expect(fixture.calls).toHaveLength(0);
  });

  it("rejects duplicate raw headers even when Node would join their values", async () => {
    const fixture = await createFixture();
    await Promise.all(
      [
        "Host: periapsis.example.test",
        "x-FoRwArDeD-fOr: 198.51.100.42",
        "X-Forwarded-Proto: https",
      ].map(async (duplicate) => {
        const response = await rawRequest(
          fixture.port,
          [
            "GET /api/check HTTP/1.1",
            "Host: periapsis.example.test",
            "X-Forwarded-For: 198.51.100.42",
            "X-Forwarded-Proto: https",
            duplicate,
            "Connection: close",
            "",
            "",
          ].join("\r\n"),
        );
        expect(response).toMatch(/^HTTP\/1\.1 400 /);
      }),
    );
    expect(fixture.calls).toHaveLength(0);
  });

  it("requires the public authority but accepts equivalent host case and default port", async () => {
    const fixture = await createFixture();
    await Promise.all(
      ["periapsis.example.test", "PERIAPSIS.example.test:443"].map(
        async (host) => {
          expect(
            (
              await request(fixture.port, "/api/check", {
                ...proxyHeaders,
                host,
              })
            ).status,
          ).toBe(200);
        },
      ),
    );
    await Promise.all(
      [
        "other.example.test",
        "periapsis.example.test:8443",
        "periapsis.example.test.",
        "periapsis.example.test:0443",
        "user@periapsis.example.test",
        "periapsis.example.test/path",
        "%70eriapsis.example.test",
        "periapsis.example.test?query",
        "periapsis.example.test#fragment",
      ].map(async (host) => {
        expect(
          (await request(fixture.port, "/api/check", { ...proxyHeaders, host }))
            .status,
        ).toBe(400);
      }),
    );
    expect(fixture.calls).toHaveLength(2);
    await Promise.all(
      [
        "//other.example.test/api/check",
        "https://other.example.test/api/check",
        "/api/check#fragment",
      ].map(async (path) => {
        expect((await request(fixture.port, path, proxyHeaders)).status).toBe(
          400,
        );
      }),
    );
    expect(fixture.calls).toHaveLength(2);
  });

  it("pins explicit public ports and IPv6 authorities without legacy IPv4 aliases", async () => {
    const ipv6 = await createFixture({
      publicUrl: "https://[2001:db8::1]:8443",
    });
    expect(
      (
        await request(ipv6.port, "/api/check", {
          ...proxyHeaders,
          host: "[2001:0db8:0:0:0:0:0:1]:8443",
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await request(ipv6.port, "/api/check", {
          ...proxyHeaders,
          host: "[2001:db8::1]",
        })
      ).status,
    ).toBe(400);
    const ipv4 = await createFixture({ publicUrl: "https://127.0.0.1" });
    await Promise.all(
      ["127.1", "0177.0.0.1", "0x7f000001"].map(async (host) => {
        expect(
          (await request(ipv4.port, "/api/check", { ...proxyHeaders, host }))
            .status,
        ).toBe(400);
      }),
    );
    expect(ipv4.calls).toHaveLength(0);
  });
});

async function createFixture(
  options: Parameters<typeof createWebServer>[0] = {},
  listenHost = "127.0.0.1",
  apiStatus = 200,
) {
  const calls: Array<{
    headers: IncomingHttpHeaders;
    path: string | undefined;
  }> = [];
  const apiPort = await listen(
    createServer((incoming, response) => {
      calls.push({ headers: incoming.headers, path: incoming.url });
      response.statusCode = apiStatus;
      response.end("upstream reached");
    }),
  );
  const port = await listen(
    createWebServer({
      proxyOnly: true,
      publicUrl,
      trustedProxyCIDRs: "127.0.0.1/32",
      ...options,
      apiBaseUrl: new URL(`http://127.0.0.1:${apiPort}`),
    }),
    listenHost,
  );
  return { port, apiPort, calls };
}

async function listen(
  server: ReturnType<typeof createServer>,
  host = "127.0.0.1",
) {
  servers.add(server);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, resolve);
  });
  const address = server.address();
  if (address === null || typeof address === "string")
    throw new Error("Expected owned loopback listener");
  return address.port;
}

function request(
  port: number,
  path: string,
  headers: Record<string, string> = {},
  method = "GET",
  host = "127.0.0.1",
  localAddress?: string,
) {
  return new Promise<{ status: number | undefined; body: string }>(
    (resolve, reject) => {
      const outgoing = httpRequest(
        { host, port, path, headers, method, timeout: 2000, localAddress },
        (response) => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.once("error", reject);
          response.once("end", () =>
            resolve({
              status: response.statusCode,
              body: Buffer.concat(chunks).toString("utf8"),
            }),
          );
        },
      );
      outgoing.once("timeout", () =>
        outgoing.destroy(new Error("Owned request timed out")),
      );
      outgoing.once("error", reject);
      outgoing.end();
    },
  );
}

function rawRequest(port: number, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const socket = connect(port, "127.0.0.1", () => socket.end(payload));
    socket.setTimeout(2000, () =>
      socket.destroy(new Error("Owned raw request timed out")),
    );
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("error", reject);
    socket.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}
