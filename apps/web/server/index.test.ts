// @vitest-environment node

import { createServer, request as httpRequest } from "node:http";
import { connect } from "node:net";

import { afterEach, describe, expect, it } from "vitest";

import {
  buildProxyHeaders,
  createWebServer,
  parseApiBaseUrl,
  parseEnvironment,
  parseListenAddress,
  parseTrustedProxyCIDRs,
  resolveClientAddress,
  resolveForwardedProtocol,
} from "./index.js";

const servers = new Set<ReturnType<typeof createWebServer>>();

afterEach(async () => {
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

describe("web server trust boundary", () => {
  it("drops client-supplied forwarding metadata", () => {
    const headers = buildProxyHeaders(
      {
        forwarded: "for=203.0.113.9;proto=https",
        host: "attacker.example",
        connection: "keep-alive, x-client-hop",
        "x-client-hop": "must-not-cross",
        "x-forwarded-for": "203.0.113.9",
        "x-forwarded-host": "attacker.example",
        "x-forwarded-port": "443",
        "x-forwarded-proto": "https",
      },
      "127.0.0.7",
    );

    expect(headers).not.toHaveProperty("forwarded");
    expect(headers).not.toHaveProperty("host");
    expect(headers).not.toHaveProperty("x-client-hop");
    expect(headers).not.toHaveProperty("x-forwarded-host");
    expect(headers).not.toHaveProperty("x-forwarded-port");
    expect(headers["x-forwarded-for"]).toBe("127.0.0.7");
    expect(headers["x-forwarded-proto"]).toBe("http");
  });

  it("walks a configured trusted proxy chain from right to left", () => {
    const trusted = parseTrustedProxyCIDRs(
      "172.30.240.0/29, 10.20.0.0/16, 2001:db8:1::/48",
    );

    expect(
      resolveClientAddress(
        { "x-forwarded-for": "198.51.100.40, 10.20.4.8" },
        "172.30.240.3",
        trusted,
      ),
    ).toBe("198.51.100.40");
    expect(
      resolveClientAddress(
        { "x-forwarded-for": "2001:db8:ffff::5, 2001:db8:1::8" },
        "172.30.240.3",
        trusted,
      ),
    ).toBe("2001:db8:ffff::5");
  });

  it("propagates a canonical protocol only from an allowlisted peer", () => {
    const trusted = parseTrustedProxyCIDRs("172.30.240.0/29");

    expect(
      buildProxyHeaders(
        {
          "x-forwarded-for": "198.51.100.40, 172.30.240.2",
          "x-forwarded-proto": "https",
        },
        "172.30.240.3",
        trusted,
      ),
    ).toMatchObject({
      "x-forwarded-for": "198.51.100.40",
      "x-forwarded-proto": "https",
    });
    expect(
      resolveForwardedProtocol(
        { "x-forwarded-proto": "http" },
        "172.30.240.3",
        trusted,
      ),
    ).toBe("http");
  });

  it("ignores spoofed forwarding metadata from an untrusted peer", () => {
    const trusted = parseTrustedProxyCIDRs("172.30.240.0/29");

    expect(
      resolveClientAddress(
        { "x-forwarded-for": "10.0.0.1" },
        "198.51.100.22",
        trusted,
      ),
    ).toBe("198.51.100.22");
    expect(
      buildProxyHeaders(
        {
          "x-forwarded-for": "10.0.0.1",
          "x-forwarded-proto": "https",
        },
        "::ffff:198.51.100.22",
        trusted,
      ),
    ).toMatchObject({
      "x-forwarded-for": "198.51.100.22",
      "x-forwarded-proto": "http",
    });
  });

  it("fails closed on malformed trusted forwarding configuration and chains", () => {
    expect(() => parseTrustedProxyCIDRs("10.0.0.0/33")).toThrow(
      /TRUSTED_PROXY_CIDRS/,
    );
    const trusted = parseTrustedProxyCIDRs("172.30.240.0/29");
    expect(() =>
      resolveClientAddress(
        { "x-forwarded-for": "198.51.100.22, not-an-address" },
        "172.30.240.3",
        trusted,
      ),
    ).toThrow(/client address/);
    expect(() =>
      resolveClientAddress(
        { "x-forwarded-for": ["198.51.100.22", "198.51.100.22"] },
        "172.30.240.3",
        trusted,
      ),
    ).toThrow(/forwarding chain/);
    for (const forwardedProtocol of [
      undefined,
      "HTTPS",
      " https",
      "https ",
      "https,http",
      ["https", "https"],
    ]) {
      expect(() =>
        resolveForwardedProtocol(
          { "x-forwarded-proto": forwardedProtocol },
          "172.30.240.3",
          trusted,
        ),
      ).toThrow(/canonical forwarding protocol/);
    }
  });

  it("preserves duplicate Authorization fields for upstream rejection", async () => {
    let markAuthorization: ((value: string | undefined) => void) | undefined;
    const authorization = new Promise<string | undefined>((resolve) => {
      markAuthorization = resolve;
    });
    const upstream = createServer((request, response) => {
      markAuthorization?.(request.headers.authorization);
      response.end();
    });
    servers.add(upstream);
    await listenOnLoopback(upstream);
    const upstreamAddress = upstream.address();
    if (upstreamAddress === null || typeof upstreamAddress === "string") {
      throw new Error("Expected an upstream TCP listener");
    }

    const server = createWebServer({
      apiBaseUrl: new URL(`http://127.0.0.1:${upstreamAddress.port}`),
    });
    servers.add(server);
    await listenOnLoopback(server);
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Expected a web TCP listener");
    }

    const first = `Bearer ${"a".repeat(64)}`;
    const second = `Bearer ${"b".repeat(64)}`;
    const client = connect(address.port, "127.0.0.1");
    await new Promise<void>((resolve, reject) => {
      client.once("error", reject);
      client.once("connect", () => {
        client.write(
          `GET /api/header-check HTTP/1.1\r\nHost: test\r\nAuthorization: ${first}\r\nAuthorization: ${second}\r\nConnection: close\r\n\r\n`,
          resolve,
        );
      });
    });

    await expect(authorization).resolves.toBe(`${first}, ${second}`);
    client.destroy();
  });

  it("rejects ambiguous runtime configuration", () => {
    expect(() => parseEnvironment("Production")).toThrow(/PERIAPSIS_ENV/);
    expect(() => parseListenAddress("0.0.0.0:8081garbage")).toThrow(
      /PERIAPSIS_WEB_ADDR/,
    );
    expect(() =>
      parseApiBaseUrl("https://api.example.invalid/?token=secret"),
    ).toThrow(/PERIAPSIS_API_URL/);
    expect(parseListenAddress("[::1]:8081")).toEqual({
      host: "::1",
      port: 8081,
    });
  });

  it("bounds a malformed request target and continues serving", async () => {
    const server = createWebServer();
    servers.add(server);
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Expected a TCP listener");
    }

    const response = await sendRawRequest(
      address.port,
      "GET //[ HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
    );
    expect(response).toContain("400 Bad Request");
    expect(response).toContain("Malformed request target");

    const healthStatus = await getStatus(address.port, "/health/live");
    expect(healthStatus).toBe(200);

    const unknownHealthStatus = await getStatus(
      address.port,
      "/health/not-a-check",
    );
    expect(unknownHealthStatus).toBe(404);
  });

  it("cancels an upstream request when the downstream client disconnects", async () => {
    let markUpstreamReached: (() => void) | undefined;
    const upstreamReached = new Promise<void>((resolve) => {
      markUpstreamReached = resolve;
    });
    let markUpstreamClosed: (() => void) | undefined;
    const upstreamClosed = new Promise<void>((resolve) => {
      markUpstreamClosed = resolve;
    });
    const upstream = createServer((request) => {
      request.socket.once("close", () => markUpstreamClosed?.());
      markUpstreamReached?.();
    });
    servers.add(upstream);
    await listenOnLoopback(upstream);
    const upstreamAddress = upstream.address();
    if (upstreamAddress === null || typeof upstreamAddress === "string") {
      throw new Error("Expected an upstream TCP listener");
    }

    const server = createWebServer({
      apiBaseUrl: new URL(`http://127.0.0.1:${upstreamAddress.port}`),
    });
    servers.add(server);
    await listenOnLoopback(server);
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Expected a web TCP listener");
    }

    const client = httpRequest({
      host: "127.0.0.1",
      path: "/api/slow",
      port: address.port,
    });
    client.once("error", () => undefined);
    client.end();
    await upstreamReached;
    client.destroy();

    await expect(
      Promise.race([
        upstreamClosed.then(() => true),
        new Promise<false>((resolve) =>
          setTimeout(() => resolve(false), 1_000),
        ),
      ]),
    ).resolves.toBe(true);
  });

  it("terminates the downstream response when the API body is truncated", async () => {
    const upstream = createServer((_request, response) => {
      response.writeHead(200, { "Content-Length": "100" });
      response.write("x");
      setImmediate(() => response.socket?.destroy());
    });
    servers.add(upstream);
    await listenOnLoopback(upstream);
    const upstreamAddress = upstream.address();
    if (upstreamAddress === null || typeof upstreamAddress === "string") {
      throw new Error("Expected an upstream TCP listener");
    }

    const server = createWebServer({
      apiBaseUrl: new URL(`http://127.0.0.1:${upstreamAddress.port}`),
    });
    servers.add(server);
    await listenOnLoopback(server);
    const address = server.address();
    if (address === null || typeof address === "string") {
      throw new Error("Expected a web TCP listener");
    }

    const downstreamTerminated = new Promise<boolean>((resolve) => {
      const request = httpRequest(
        { host: "127.0.0.1", path: "/api/truncated", port: address.port },
        (response) => {
          response.resume();
          response.once("aborted", () => resolve(true));
          response.once("error", () => resolve(true));
          response.once("close", () => resolve(true));
          response.once("end", () => resolve(true));
        },
      );
      request.once("error", () => resolve(true));
      request.end();
    });

    await expect(
      Promise.race([
        downstreamTerminated,
        new Promise<false>((resolve) =>
          setTimeout(() => resolve(false), 1_000),
        ),
      ]),
    ).resolves.toBe(true);
  });
});

function listenOnLoopback(
  server: ReturnType<typeof createWebServer>,
): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
}

function sendRawRequest(port: number, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const socket = connect(port, "127.0.0.1", () => socket.end(payload));
    socket.on("data", (chunk: Buffer) => chunks.push(chunk));
    socket.once("error", reject);
    socket.once("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
  });
}

function getStatus(port: number, path: string): Promise<number | undefined> {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { host: "127.0.0.1", port, path },
      (response) => {
        response.resume();
        response.once("end", () => resolve(response.statusCode));
      },
    );
    request.once("error", reject);
    request.end();
  });
}
