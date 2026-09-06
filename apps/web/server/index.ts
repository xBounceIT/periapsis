import { createReadStream, statSync } from "node:fs";
import { request as httpRequest } from "node:http";
import type {
  IncomingHttpHeaders,
  IncomingMessage,
  ServerResponse,
} from "node:http";
import { createServer } from "node:http";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP, SocketAddress } from "node:net";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const distDirectory = fileURLToPath(new URL("../dist", import.meta.url));
const release = process.env["PERIAPSIS_RELEASE"] ?? "development";
const environment = parseEnvironment(
  process.env["PERIAPSIS_ENV"] ?? "production",
);
const configuredApiBaseUrl = parseApiBaseUrl(
  process.env["PERIAPSIS_API_URL"] ?? "http://127.0.0.1:8080",
);
const listen = parseListenAddress(
  process.env["PERIAPSIS_WEB_ADDR"] ?? "0.0.0.0:8081",
);
let configuredTrustedProxies: TrustedProxySet | undefined;

const maximumForwardedForSize = 2_048;
const maximumForwardedHops = 32;

interface WebServerOptions {
  apiBaseUrl?: URL;
  proxyOnly?: boolean;
  publicUrl?: string;
  trustedProxyCIDRs?: string;
}

export function createWebServer(options: WebServerOptions = {}) {
  const apiBaseUrl = new URL(options.apiBaseUrl ?? configuredApiBaseUrl);
  const proxyOnly =
    options.proxyOnly ??
    parseProxyOnly(process.env["PERIAPSIS_WEB_PROXY_ONLY"] ?? "false");
  const trustedProxies =
    options.trustedProxyCIDRs === undefined && !proxyOnly
      ? getConfiguredTrustedProxies()
      : parseTrustedProxyCIDRs(
          options.trustedProxyCIDRs ??
            process.env["PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS"] ??
            "",
          proxyOnly,
        );
  const publicOrigin = proxyOnly
    ? parseProxyPublicOrigin(
        options.publicUrl ?? process.env["PERIAPSIS_PUBLIC_URL"] ?? "",
      )
    : undefined;
  const directProbeTrust = new TrustedProxySet();
  const server = createServer(
    { joinDuplicateHeaders: true },
    (request, response) => {
      const startedAt = performance.now();
      setSecurityHeaders(response);

      response.once("finish", () => {
        writeLog("info", "http_request", {
          method: request.method ?? "UNKNOWN",
          path: request.url?.split("?", 1)[0] ?? "/",
          status: response.statusCode,
          durationMs: Math.round((performance.now() - startedAt) * 100) / 100,
        });
      });

      const directReadinessProbe =
        proxyOnly &&
        isLoopbackReadinessProbe(
          request.method,
          request.url,
          request.socket.remoteAddress,
        );
      if (
        publicOrigin !== undefined &&
        !isDirectLivenessProbe(request) &&
        !directReadinessProbe &&
        !acceptProxyOnlyRequest(request, response, trustedProxies, publicOrigin)
      ) {
        return;
      }

      void route(
        request,
        response,
        apiBaseUrl,
        directReadinessProbe ? directProbeTrust : trustedProxies,
        proxyOnly,
      ).catch((error: unknown) => {
        writeLog("error", "request_failed", {
          error: error instanceof Error ? error.message : "unknown error",
          path: request.url?.split("?", 1)[0] ?? "/",
        });
        if (response.headersSent) {
          response.destroy(error instanceof Error ? error : undefined);
          return;
        }
        sendProblem(response, 500, "Internal server error");
      });
    },
  );

  server.requestTimeout = 30_000;
  server.headersTimeout = 31_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

export function startWebServer(): void {
  const server = createWebServer();
  server.listen(listen.port, listen.host, () => {
    const address = server.address();
    const boundHost =
      address !== null && typeof address !== "string"
        ? address.address
        : listen.host;
    const boundPort =
      address !== null && typeof address !== "string"
        ? address.port
        : listen.port;
    writeLog("info", "web_started", {
      host: boundHost,
      port: boundPort,
      release,
    });
  });

  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => {
      writeLog("info", "shutdown_started", { signal });
      server.close((error) => {
        if (error) {
          writeLog("error", "shutdown_failed", { error: error.message });
          process.exitCode = 1;
        }
      });
      setTimeout(() => server.closeAllConnections(), 10_000).unref();
    });
  }
}

if (
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  startWebServer();
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  apiBaseUrl: URL,
  trustedProxies: TrustedProxySet,
  proxyOnly: boolean,
): Promise<void> {
  const method = request.method ?? "GET";
  let requestUrl: URL;
  try {
    requestUrl = new URL(request.url ?? "/", "http://web.internal");
  } catch {
    sendProblem(response, 400, "Malformed request target");
    return;
  }

  if (
    (method === "GET" || (proxyOnly && method === "HEAD")) &&
    requestUrl.pathname === "/health/live"
  ) {
    sendJson(response, 200, {
      status: "alive",
      service: "web",
      version: release,
    });
    return;
  }

  if (method === "GET" && requestUrl.pathname === "/runtime-config.json") {
    response.setHeader("Cache-Control", "no-store");
    sendJson(response, 200, {
      apiBasePath: "/api",
      environment,
      release,
    });
    return;
  }

  if (
    requestUrl.pathname.startsWith("/health/") &&
    requestUrl.pathname !== "/health/ready"
  ) {
    sendProblem(response, 404, "Resource not found");
    return;
  }

  if (shouldProxy(requestUrl.pathname)) {
    proxyToApi(request, response, requestUrl, apiBaseUrl, trustedProxies);
    return;
  }

  if (method !== "GET" && method !== "HEAD") {
    sendProblem(response, 405, "Method not allowed");
    return;
  }

  serveStatic(requestUrl.pathname, method === "HEAD", response);
}

function isDirectLivenessProbe(request: IncomingMessage): boolean {
  return (
    (request.method === "GET" || request.method === "HEAD") &&
    request.url === "/health/live"
  );
}

export function isLoopbackReadinessProbe(
  method: string | undefined,
  target: string | undefined,
  remoteAddress: string | undefined,
): boolean {
  if (
    method !== "GET" ||
    target !== "/health/ready" ||
    remoteAddress === undefined
  ) {
    return false;
  }
  try {
    const peer = canonicalIPAddress(remoteAddress).address;
    return peer === "127.0.0.1" || peer === "::1";
  } catch {
    return false;
  }
}

function acceptProxyOnlyRequest(
  request: IncomingMessage,
  response: ServerResponse,
  trustedProxies: TrustedProxySet,
  publicOrigin: string,
): boolean {
  const peer = request.socket.remoteAddress;
  let trustedPeer = false;
  try {
    trustedPeer =
      peer !== undefined && trustedProxies.contains(canonicalIPAddress(peer));
  } catch {
    // Missing or malformed socket metadata can never establish proxy authority.
  }
  if (!trustedPeer) {
    sendProblem(response, 403, "Trusted proxy required");
    return false;
  }
  try {
    for (const name of ["host", "x-forwarded-for", "x-forwarded-proto"]) {
      let occurrences = 0;
      for (let index = 0; index < request.rawHeaders.length; index += 2) {
        if (request.rawHeaders[index]?.toLowerCase() === name) occurrences++;
      }
      if (occurrences !== 1) throw new Error("ambiguous proxy header");
    }
    const host = request.headers.host;
    if (
      host === undefined ||
      !matchesPublicOrigin(host, publicOrigin) ||
      !request.url?.startsWith("/") ||
      request.url.startsWith("//") ||
      request.url.includes("#")
    ) {
      throw new Error("invalid proxy origin");
    }
    resolveClientAddress(request.headers, peer, trustedProxies);
    if (
      resolveForwardedProtocol(request.headers, peer, trustedProxies) !==
      "https"
    ) {
      throw new Error("HTTPS proxy required");
    }
  } catch {
    sendProblem(response, 400, "Invalid trusted proxy request");
    return false;
  }
  return true;
}

function matchesPublicOrigin(host: string, publicOrigin: string): boolean {
  const match = /^(\[[a-f\d:.]+\]|[a-z\d.-]+)(?::([1-9]\d{0,4}))?$/i.exec(host);
  const hostname = match?.[1];
  if (hostname === undefined) return false;
  const parsed = new URL(`https://${host}`);
  if (
    hostname.startsWith("[")
      ? isIP(hostname.slice(1, -1)) !== 6
      : hostname.toLowerCase() !== parsed.hostname
  ) {
    return false;
  }
  return parsed.origin === publicOrigin;
}

function shouldProxy(pathname: string): boolean {
  return (
    pathname === "/openapi.json" ||
    pathname === "/health/ready" ||
    pathname === "/docs" ||
    pathname.startsWith("/docs/") ||
    pathname === "/api" ||
    pathname.startsWith("/api/")
  );
}

function proxyToApi(
  incoming: IncomingMessage,
  outgoing: ServerResponse,
  requestUrl: URL,
  apiBaseUrl: URL,
  trustedProxies: TrustedProxySet,
): void {
  const headers = buildProxyHeaders(
    incoming.headers,
    incoming.socket.remoteAddress,
    trustedProxies,
  );

  // The configured URL alone selects the network endpoint. Request data may
  // supply the already-routed path/query, never an outgoing URL authority.
  const transport =
    apiBaseUrl.protocol === "https:" ? httpsRequest : httpRequest;
  const upstream = transport(
    apiBaseUrl,
    {
      path: `${requestUrl.pathname}${requestUrl.search}`,
      method: incoming.method,
      headers,
      timeout: 30_000,
    },
    (upstreamResponse) => {
      outgoing.statusCode = upstreamResponse.statusCode ?? 502;
      copyResponseHeaders(upstreamResponse.headers, outgoing);
      let upstreamResponseFinished = false;
      const failUpstreamResponse = (error: Error) => {
        if (upstreamResponseFinished || outgoing.destroyed) {
          return;
        }
        upstreamResponseFinished = true;
        writeLog("error", "api_proxy_response_failed", {
          error: error.message,
          path: requestUrl.pathname,
        });
        if (outgoing.headersSent) {
          outgoing.destroy(error);
          return;
        }
        sendProblem(
          outgoing,
          502,
          "API service returned an incomplete response",
        );
      };
      upstreamResponse.once("end", () => {
        upstreamResponseFinished = true;
      });
      upstreamResponse.once("aborted", () => {
        failUpstreamResponse(new Error("API response was aborted"));
      });
      upstreamResponse.once("error", failUpstreamResponse);
      upstreamResponse.once("close", () => {
        if (!upstreamResponse.complete) {
          failUpstreamResponse(
            new Error("API response closed before completion"),
          );
        }
      });
      upstreamResponse.pipe(outgoing);
    },
  );

  upstream.once("timeout", () => {
    upstream.destroy(new Error("API proxy timeout"));
  });
  upstream.once("error", (error) => {
    if (outgoing.destroyed) {
      return;
    }
    writeLog("error", "api_proxy_failed", {
      error: error.message,
      path: requestUrl.pathname,
    });
    if (!outgoing.headersSent) {
      sendProblem(outgoing, 502, "API service unavailable");
    } else {
      outgoing.destroy(error);
    }
  });
  incoming.once("aborted", () => upstream.destroy());
  outgoing.once("close", () => {
    if (!outgoing.writableFinished) {
      upstream.destroy(new Error("Downstream client disconnected"));
    }
  });
  incoming.pipe(upstream);
}

export function buildProxyHeaders(
  headers: IncomingHttpHeaders,
  remoteAddress: string | undefined,
  trustedProxies: TrustedProxySet = getConfiguredTrustedProxies(),
): IncomingHttpHeaders {
  const forwarded = { ...headers };
  const connectionTokens = Array.isArray(headers.connection)
    ? headers.connection
    : (headers.connection?.split(",") ?? []);
  for (const token of connectionTokens) {
    delete forwarded[token.trim().toLowerCase()];
  }
  for (const name of [
    "connection",
    "forwarded",
    "host",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "x-real-ip",
    "x-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-cluster-client-ip",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-port",
    "x-forwarded-proto",
  ]) {
    delete forwarded[name];
  }
  for (const name of Object.keys(forwarded)) {
    if (
      name.startsWith("x-forwarded-") ||
      name.startsWith("x-original-forwarded-")
    ) {
      delete forwarded[name];
    }
  }
  forwarded["x-forwarded-for"] = resolveClientAddress(
    headers,
    remoteAddress,
    trustedProxies,
  );
  forwarded["x-forwarded-proto"] = resolveForwardedProtocol(
    headers,
    remoteAddress,
    trustedProxies,
  );
  return forwarded;
}

interface CanonicalIPAddress {
  address: string;
  family: "ipv4" | "ipv6";
}

export class TrustedProxySet {
  readonly #ranges = new BlockList();

  add(address: string, prefix: number, family: "ipv4" | "ipv6"): void {
    this.#ranges.addSubnet(address, prefix, family);
  }

  contains(value: CanonicalIPAddress): boolean {
    return this.#ranges.check(value.address, value.family);
  }
}

function getConfiguredTrustedProxies(): TrustedProxySet {
  configuredTrustedProxies ??= parseTrustedProxyCIDRs(
    process.env["PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS"] ?? "",
  );
  return configuredTrustedProxies;
}

export function parseTrustedProxyCIDRs(
  raw: string,
  requireRestricted = false,
): TrustedProxySet {
  const trusted = new TrustedProxySet();
  const value = raw.trim();
  if (value === "") {
    if (requireRestricted) {
      throw new Error(
        "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS is required in proxy-only mode",
      );
    }
    return trusted;
  }
  const entries = value.split(",");
  if (entries.length > maximumForwardedHops) {
    throw new Error(
      "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS must contain at most 32 entries",
    );
  }
  for (const rawEntry of entries) {
    const entry = rawEntry.trim();
    const separator = entry.lastIndexOf("/");
    if (separator <= 0 || entry.indexOf("/") !== separator) {
      throw new Error(
        "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS must be a comma-separated CIDR list",
      );
    }
    const address = canonicalIPAddress(entry.slice(0, separator));
    const prefixText = entry.slice(separator + 1);
    if (!/^(?:0|[1-9]\d*)$/.test(prefixText)) {
      throw new Error(
        "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS must be a comma-separated CIDR list",
      );
    }
    const prefix = Number(prefixText);
    const maximumPrefix = address.family === "ipv4" ? 32 : 128;
    if (!Number.isSafeInteger(prefix) || prefix > maximumPrefix) {
      throw new Error(
        "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS must be a comma-separated CIDR list",
      );
    }
    if (requireRestricted && prefix === 0) {
      throw new Error(
        "PERIAPSIS_WEB_TRUSTED_PROXY_CIDRS must not contain universal ranges in proxy-only mode",
      );
    }
    trusted.add(address.address, prefix, address.family);
  }
  return trusted;
}

export function resolveClientAddress(
  headers: IncomingHttpHeaders,
  remoteAddress: string | undefined,
  trustedProxies: TrustedProxySet,
): string {
  if (remoteAddress === undefined || remoteAddress === "") {
    throw new Error("client socket address is unavailable");
  }
  const peer = canonicalIPAddress(remoteAddress);
  if (!trustedProxies.contains(peer)) {
    return peer.address;
  }
  const forwarded = headers["x-forwarded-for"];
  if (
    typeof forwarded !== "string" ||
    forwarded.length === 0 ||
    forwarded.length > maximumForwardedForSize
  ) {
    throw new Error("trusted proxy did not provide one forwarding chain");
  }
  const values = forwarded.split(",");
  if (values.length === 0 || values.length > maximumForwardedHops) {
    throw new Error("trusted proxy provided an invalid forwarding chain");
  }
  const chain = values.map((value) => canonicalIPAddress(value.trim()));
  chain.push(peer);
  for (let index = chain.length - 1; index >= 0; index -= 1) {
    const address = chain[index];
    if (address !== undefined && !trustedProxies.contains(address)) {
      return address.address;
    }
  }
  const first = chain[0];
  if (first === undefined) {
    throw new Error("trusted proxy provided an empty forwarding chain");
  }
  return first.address;
}

export function resolveForwardedProtocol(
  headers: IncomingHttpHeaders,
  remoteAddress: string | undefined,
  trustedProxies: TrustedProxySet,
): "http" | "https" {
  if (remoteAddress === undefined || remoteAddress === "") {
    throw new Error("client socket address is unavailable");
  }
  const peer = canonicalIPAddress(remoteAddress);
  if (!trustedProxies.contains(peer)) {
    return "http";
  }
  const forwarded = headers["x-forwarded-proto"];
  if (forwarded !== "http" && forwarded !== "https") {
    throw new Error(
      "trusted proxy did not provide one canonical forwarding protocol",
    );
  }
  return forwarded;
}

function canonicalIPAddress(raw: string): CanonicalIPAddress {
  if (raw === "" || raw.includes("%")) {
    throw new Error("client address is invalid");
  }
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(raw)?.[1];
  const candidate = mapped ?? raw;
  const version = isIP(candidate);
  const socketAddress =
    version === 4
      ? SocketAddress.parse(candidate)
      : version === 6
        ? SocketAddress.parse(`[${candidate}]`)
        : undefined;
  if (socketAddress === undefined) {
    throw new Error("client address is invalid");
  }
  return {
    address:
      /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(socketAddress.address)?.[1] ??
      socketAddress.address,
    family: socketAddress.address.startsWith("::ffff:")
      ? "ipv4"
      : socketAddress.family,
  };
}

function copyResponseHeaders(
  headers: IncomingHttpHeaders,
  response: ServerResponse,
): void {
  for (const [name, value] of Object.entries(headers)) {
    if (
      value !== undefined &&
      !["connection", "keep-alive", "transfer-encoding", "upgrade"].includes(
        name.toLowerCase(),
      )
    ) {
      response.setHeader(name, value);
    }
  }
}

function serveStatic(
  pathname: string,
  headOnly: boolean,
  response: ServerResponse,
): void {
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    sendProblem(response, 400, "Malformed request path");
    return;
  }

  const relativePath =
    decodedPath === "/" ? "index.html" : decodedPath.replace(/^\/+/, "");
  let candidate = resolve(distDirectory, relativePath);
  if (!isInsideDist(candidate)) {
    sendProblem(response, 404, "Resource not found");
    return;
  }

  try {
    const details = statSync(candidate);
    if (!details.isFile()) {
      throw new Error("Not a file");
    }
  } catch {
    if (extname(relativePath) !== "") {
      sendProblem(response, 404, "Resource not found");
      return;
    }
    candidate = resolve(distDirectory, "index.html");
  }

  const details = statSync(candidate);
  response.statusCode = 200;
  response.setHeader("Content-Type", contentType(candidate));
  response.setHeader("Content-Length", details.size);
  response.setHeader(
    "Cache-Control",
    candidate.includes(`${sep}assets${sep}`)
      ? "public, max-age=31536000, immutable"
      : "no-cache",
  );

  if (headOnly) {
    response.end();
    return;
  }
  createReadStream(candidate).pipe(response);
}

function isInsideDist(candidate: string): boolean {
  return (
    candidate === distDirectory ||
    candidate.startsWith(`${distDirectory}${sep}`)
  );
}

function contentType(path: string): string {
  const types: Record<string, string> = {
    ".css": "text/css; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".ico": "image/x-icon",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
  };
  return types[extname(path).toLowerCase()] ?? "application/octet-stream";
}

function setSecurityHeaders(response: ServerResponse): void {
  response.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'",
  );
  response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
  response.setHeader(
    "Permissions-Policy",
    "camera=(), geolocation=(), microphone=()",
  );
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: Record<string, unknown>,
  mediaType = "application/json; charset=utf-8",
): void {
  const payload = JSON.stringify(body);
  response.statusCode = status;
  response.setHeader("Content-Type", mediaType);
  response.setHeader("Content-Length", Buffer.byteLength(payload));
  response.end(payload);
}

function sendProblem(
  response: ServerResponse,
  status: number,
  title: string,
): void {
  sendJson(
    response,
    status,
    {
      type: "about:blank",
      title,
      status,
    },
    "application/problem+json; charset=utf-8",
  );
}

export function parseApiBaseUrl(raw: string): URL {
  const parsed = new URL(raw);
  if (
    !["http:", "https:"].includes(parsed.protocol) ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== ""
  ) {
    throw new Error(
      "PERIAPSIS_API_URL must be an HTTP(S) origin without credentials, path, query, or fragment",
    );
  }
  return parsed;
}

export function parseListenAddress(raw: string): {
  host: string;
  port: number;
} {
  const hostPortMatch = /^(?:\[([^\]]+)\]|([^:]*)):(\d+)$/.exec(raw);
  const portOnlyMatch = /^(\d+)$/.exec(raw);
  const portText = hostPortMatch?.[3] ?? portOnlyMatch?.[1];
  const host = hostPortMatch?.[1] ?? hostPortMatch?.[2] ?? "0.0.0.0";
  const port = Number(portText);
  if (!Number.isSafeInteger(port) || port < 1024 || port > 65_535) {
    throw new Error(
      "PERIAPSIS_WEB_ADDR must be host:port with a non-privileged TCP port",
    );
  }
  return { host: host === "" ? "0.0.0.0" : host, port };
}

export function parseEnvironment(
  raw: string,
): "development" | "test" | "production" {
  if (raw === "development" || raw === "test" || raw === "production") {
    return raw;
  }
  throw new Error("PERIAPSIS_ENV must be development, test, or production");
}

function parseProxyOnly(raw: string): boolean {
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error("PERIAPSIS_WEB_PROXY_ONLY must be true or false");
}

function parseProxyPublicOrigin(raw: string): string {
  const error = new Error(
    "PERIAPSIS_PUBLIC_URL must be a canonical HTTPS origin in proxy-only mode",
  );
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw error;
  }
  const hostname = parsed.hostname;
  const isIPAddress = isIP(
    hostname.startsWith("[") ? hostname.slice(1, -1) : hostname,
  );
  const isDNSName =
    hostname.length <= 253 &&
    hostname
      .split(".")
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
  if (
    parsed.protocol !== "https:" ||
    raw !== parsed.origin ||
    parsed.port === "0" ||
    (!isIPAddress && !isDNSName)
  ) {
    throw error;
  }
  return parsed.origin;
}

function writeLog(
  level: "error" | "info",
  event: string,
  fields: Record<string, unknown>,
): void {
  const line = `${JSON.stringify({
    timestamp: new Date().toISOString(),
    level,
    service: "web",
    event,
    ...fields,
  })}\n`;
  (level === "error" ? process.stderr : process.stdout).write(line);
}
