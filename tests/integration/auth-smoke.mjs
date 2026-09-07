import { createHmac, randomUUID } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";

const baseUrl =
  process.env.PERIAPSIS_SMOKE_BASE_URL ?? "https://localhost:8443";
const browserOrigin = new URL(baseUrl).origin;
const bootstrapToken = process.env.PERIAPSIS_BOOTSTRAP_TOKEN;
const administratorPassword = process.env.PERIAPSIS_SMOKE_ADMIN_PASSWORD;

if (!bootstrapToken || !administratorPassword) {
  throw new Error(
    "PERIAPSIS_BOOTSTRAP_TOKEN and PERIAPSIS_SMOKE_ADMIN_PASSWORD are required for the auth smoke test",
  );
}

const administrator = {
  email: "bootstrap-admin@periapsis.example",
  displayName: "CI Bootstrap Administrator",
  password: administratorPassword,
};

let cookie;
let csrfToken;

const initialStatus = await request("/api/v1/bootstrap/status");
expectStatus(initialStatus, 200, "bootstrap availability");
assert(
  initialStatus.body?.available === true,
  "bootstrap must initially be available",
);

expectStatus(
  await request("/api/v1/platform/tenants"),
  401,
  "anonymous platform access",
);

expectStatus(
  await request("/api/v1/bootstrap/enroll", {
    method: "POST",
    json: { email: administrator.email },
  }),
  401,
  "bootstrap enrollment without deployment authority",
);

const enrollment = await request("/api/v1/bootstrap/enroll", {
  method: "POST",
  headers: bootstrapHeaders(),
  json: { email: administrator.email },
});
expectStatus(enrollment, 201, "bootstrap enrollment");
assertString(enrollment.body?.enrollmentToken, "enrollment token");
assertString(enrollment.body?.totpSecret, "TOTP secret");
assertString(enrollment.body?.totpUri, "TOTP URI");
const totpUri = new URL(enrollment.body.totpUri);
assert(totpUri.protocol === "otpauth:", "TOTP URI must use the otpauth scheme");
assert(
  totpUri.searchParams.get("secret") === enrollment.body.totpSecret,
  "TOTP URI and one-time secret must agree",
);

expectStatus(
  await request("/api/v1/bootstrap/enroll", {
    method: "POST",
    headers: bootstrapHeaders(),
    json: { email: "other-admin@periapsis.example" },
  }),
  409,
  "concurrent bootstrap enrollment",
);

const reservedStatus = await request("/api/v1/bootstrap/status");
expectStatus(reservedStatus, 200, "reserved bootstrap status");
assert(
  reservedStatus.body?.available === true,
  "bootstrap must remain required while an enrollment reservation is active",
);

await avoidTotpBoundary();
const bootstrapTotpCounter = currentTotpCounter();
const bootstrap = await request("/api/v1/bootstrap/confirm", {
  method: "POST",
  headers: bootstrapHeaders(),
  json: {
    enrollmentToken: enrollment.body.enrollmentToken,
    email: administrator.email,
    displayName: administrator.displayName,
    password: administrator.password,
    code: totp(enrollment.body.totpSecret, bootstrapTotpCounter),
  },
});
expectStatus(bootstrap, 201, "bootstrap confirmation");
cookie = issuedCookie(bootstrap, "bootstrap confirmation");
csrfToken = requiredSessionCsrf(bootstrap.body?.session);
const recoveryCodes = bootstrap.body?.recoveryCodes;
assert(Array.isArray(recoveryCodes), "bootstrap must return recovery codes");
assert(
  recoveryCodes.length === 10,
  "bootstrap must return exactly ten recovery codes",
);
assert(new Set(recoveryCodes).size === 10, "recovery codes must be unique");
for (const code of recoveryCodes) assertString(code, "recovery code");

const completedStatus = await request("/api/v1/bootstrap/status");
expectStatus(completedStatus, 200, "completed bootstrap status");
assert(
  completedStatus.body?.available === false,
  "bootstrap must close after confirmation",
);

expectStatus(
  await request("/api/v1/bootstrap/confirm", {
    method: "POST",
    headers: bootstrapHeaders(),
    json: {
      enrollmentToken: enrollment.body.enrollmentToken,
      email: administrator.email,
      displayName: administrator.displayName,
      password: administrator.password,
      code: "000000",
    },
  }),
  409,
  "bootstrap replay",
);

const currentSession = await request("/api/v1/auth/session", { cookie });
expectStatus(currentSession, 200, "current session");
assert(
  currentSession.body?.user?.email === administrator.email,
  "session must resolve the bootstrapped user",
);
cookie = refreshedCookie(currentSession, cookie);
csrfToken = requiredSessionCsrf(currentSession.body);

const tenantInput = {
  slug: `ci-${process.env.GITHUB_RUN_ID ?? "local"}-${process.env.GITHUB_RUN_ATTEMPT ?? "1"}`,
  name: "CI Security Operations",
  timezone: "Europe/Rome",
  locale: "it-IT",
};

expectStatus(
  await request("/api/v1/platform/tenants", {
    method: "POST",
    cookie,
    json: tenantInput,
    origin: browserOrigin,
  }),
  403,
  "tenant mutation without CSRF token",
);

expectStatus(
  await request("/api/v1/platform/tenants", {
    method: "POST",
    cookie,
    csrfToken,
    json: tenantInput,
    origin: "http://attacker.invalid",
  }),
  403,
  "tenant mutation from an untrusted origin",
);

const createdTenant = await request("/api/v1/platform/tenants", {
  method: "POST",
  cookie,
  csrfToken,
  json: tenantInput,
  origin: browserOrigin,
});
expectStatus(createdTenant, 201, "authorized tenant creation");
assertString(createdTenant.body?.id, "created tenant ID");

const tenants = await request("/api/v1/platform/tenants?limit=100", { cookie });
expectStatus(tenants, 200, "platform tenant listing");
assert(
  tenants.body?.items?.some((tenant) => tenant.id === createdTenant.body.id),
  "created tenant must appear in the authorized platform listing",
);

const memberships = await request("/api/v1/auth/tenant-memberships", {
  cookie,
});
expectStatus(memberships, 200, "tenant membership listing");
assert(
  memberships.body?.items?.some(
    (membership) =>
      membership.tenant?.id === createdTenant.body.id &&
      membership.role === "tenant_admin",
  ),
  "tenant creation must atomically grant the creator tenant_admin membership",
);

const unknownTenantID = randomUUID();
const unknownV7TenantID =
  unknownTenantID.slice(0, 14) + "7" + unknownTenantID.slice(15);
for (const tenantId of [unknownTenantID, unknownV7TenantID]) {
  expectStatus(
    await request("/api/v1/auth/session/tenant", {
      method: "PUT",
      cookie,
      csrfToken,
      json: { tenantId },
      origin: browserOrigin,
    }),
    403,
    "switching to a tenant without membership",
  );
}

const switched = await request("/api/v1/auth/session/tenant", {
  method: "PUT",
  cookie,
  csrfToken,
  json: { tenantId: createdTenant.body.id },
  origin: browserOrigin,
});
expectStatus(switched, 200, "authorized tenant switch");
cookie = refreshedCookie(switched, cookie);
csrfToken = requiredSessionCsrf(switched.body);
assert(
  switched.body.activeTenantId === createdTenant.body.id,
  "session must expose only the selected authorized tenant",
);

expectStatus(
  await request("/api/v1/auth/session", {
    method: "DELETE",
    cookie,
    csrfToken,
    origin: browserOrigin,
  }),
  204,
  "logout",
);
expectStatus(
  await request("/api/v1/auth/session", { cookie }),
  401,
  "revoked session after logout",
);

const passwordChallenge = await request("/api/v1/auth/login", {
  method: "POST",
  json: { email: administrator.email, password: administrator.password },
});
expectStatus(passwordChallenge, 202, "password login challenge");
assertString(passwordChallenge.body?.challengeToken, "MFA challenge token");

await waitForTotpCounterAfter(bootstrapTotpCounter);
const acceptedLoginTotp = totp(
  enrollment.body.totpSecret,
  currentTotpCounter(),
);
const totpLogin = await request("/api/v1/auth/mfa", {
  method: "POST",
  json: {
    challengeToken: passwordChallenge.body.challengeToken,
    method: "totp",
    code: acceptedLoginTotp,
  },
});
expectStatus(totpLogin, 200, "ordinary TOTP MFA login");
cookie = issuedCookie(totpLogin, "ordinary TOTP MFA login");
csrfToken = requiredSessionCsrf(totpLogin.body);

expectStatus(
  await request("/api/v1/auth/session", {
    method: "DELETE",
    cookie,
    csrfToken,
    origin: browserOrigin,
  }),
  204,
  "ordinary TOTP session logout",
);

const recoveryChallenge = await request("/api/v1/auth/login", {
  method: "POST",
  json: { email: administrator.email, password: administrator.password },
});
expectStatus(recoveryChallenge, 202, "recovery login challenge");
expectStatus(
  await request("/api/v1/auth/mfa", {
    method: "POST",
    json: {
      challengeToken: recoveryChallenge.body.challengeToken,
      method: "totp",
      code: acceptedLoginTotp,
    },
  }),
  401,
  "ordinary TOTP counter replay",
);

const recoveryLogin = await request("/api/v1/auth/mfa", {
  method: "POST",
  json: {
    challengeToken: recoveryChallenge.body.challengeToken,
    method: "recovery_code",
    code: recoveryCodes[0],
  },
});
expectStatus(recoveryLogin, 200, "recovery-code MFA login");
cookie = issuedCookie(recoveryLogin, "recovery-code MFA login");
csrfToken = requiredSessionCsrf(recoveryLogin.body);

const replayChallenge = await request("/api/v1/auth/login", {
  method: "POST",
  json: { email: administrator.email, password: administrator.password },
});
expectStatus(replayChallenge, 202, "recovery replay challenge");
expectStatus(
  await request("/api/v1/auth/mfa", {
    method: "POST",
    json: {
      challengeToken: replayChallenge.body.challengeToken,
      method: "recovery_code",
      code: recoveryCodes[0],
    },
  }),
  401,
  "one-use recovery-code replay",
);

const sessions = await request("/api/v1/auth/sessions", { cookie });
expectStatus(sessions, 200, "session listing");
const current = sessions.body?.items?.find(
  (session) => session.current === true,
);
assertString(current?.id, "current listed session ID");
const alreadyRevoked = sessions.body?.items?.find(
  (session) =>
    session.current === false && typeof session.revokedAt === "string",
);
assertString(alreadyRevoked?.id, "historical revoked session ID");

expectStatus(
  await request(
    `/api/v1/auth/sessions/${encodeURIComponent(alreadyRevoked.id)}`,
    {
      method: "DELETE",
      cookie,
      csrfToken,
      origin: browserOrigin,
    },
  ),
  204,
  "idempotent historical session revocation",
);
const sessionAfterIdempotentRevoke = await request("/api/v1/auth/session", {
  cookie,
});
expectStatus(
  sessionAfterIdempotentRevoke,
  200,
  "current session after idempotent historical revocation",
);
csrfToken = requiredSessionCsrf(sessionAfterIdempotentRevoke.body);

expectStatus(
  await request(`/api/v1/auth/sessions/${encodeURIComponent(current.id)}`, {
    method: "DELETE",
    cookie,
    csrfToken,
    origin: browserOrigin,
  }),
  204,
  "server-side session revocation",
);
expectStatus(
  await request("/api/v1/auth/session", { cookie }),
  401,
  "explicitly revoked session",
);

process.stdout.write("Phase 2A authentication smoke passed\n");

async function request(
  path,
  {
    method = "GET",
    headers = {},
    json,
    cookie: requestCookie,
    csrfToken: csrf,
    origin,
  } = {},
) {
  const requestHeaders = new Headers({
    Accept: "application/json",
    ...headers,
  });
  if (json !== undefined)
    requestHeaders.set("Content-Type", "application/json");
  if (requestCookie) requestHeaders.set("Cookie", requestCookie);
  if (csrf) requestHeaders.set("X-CSRF-Token", csrf);
  if (origin) requestHeaders.set("Origin", origin);
  const response = await fetch(new URL(path, baseUrl), {
    method,
    headers: requestHeaders,
    body: json === undefined ? undefined : JSON.stringify(json),
    redirect: "manual",
  });
  const text = await response.text();
  let body;
  if (text !== "") {
    try {
      body = JSON.parse(text);
    } catch {
      body = undefined;
    }
  }
  return { response, body };
}

function bootstrapHeaders() {
  return { "X-Periapsis-Bootstrap-Token": bootstrapToken };
}

function expectStatus(result, expected, operation) {
  if (result.response.status !== expected) {
    const code =
      typeof result.body?.code === "string" ? ` (${result.body.code})` : "";
    throw new Error(
      `${operation} returned ${result.response.status}${code}; expected ${expected}`,
    );
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertString(value, label) {
  assert(
    typeof value === "string" && value.length > 0,
    `${label} must be a non-empty string`,
  );
}

function issuedCookie(result, operation) {
  const setCookie = result.response.headers.getSetCookie()[0];
  assertString(setCookie, `${operation} Set-Cookie`);
  assert(
    /;\s*HttpOnly(?:;|$)/i.test(setCookie),
    `${operation} cookie must be HttpOnly`,
  );
  assert(
    /;\s*SameSite=Strict(?:;|$)/i.test(setCookie),
    `${operation} cookie must be SameSite=Strict`,
  );
  assert(
    /;\s*Path=\/(?:;|$)/i.test(setCookie),
    `${operation} cookie must use Path=/`,
  );
  const secureOrigin = new URL(browserOrigin).protocol === "https:";
  assert(
    secureOrigin
      ? setCookie.startsWith("__Host-periapsis_session=") &&
          /;\s*Secure(?:;|$)/i.test(setCookie) &&
          !/;\s*Domain=/i.test(setCookie)
      : !setCookie.startsWith("__Host-"),
    `${operation} cookie must match the browser origin security`,
  );
  return setCookie.split(";", 1)[0];
}

function refreshedCookie(result, previous) {
  return result.response.headers.getSetCookie().length > 0
    ? issuedCookie(result, "session rotation")
    : previous;
}

function requiredSessionCsrf(session) {
  assertString(session?.csrfToken, "session CSRF token");
  return session.csrfToken;
}

async function avoidTotpBoundary() {
  const remaining = 30_000 - (Date.now() % 30_000);
  if (remaining < 8_000) await delay(remaining + 250);
}

async function waitForTotpCounterAfter(previousCounter) {
  if (currentTotpCounter() <= previousCounter) {
    const remaining = 30_000 - (Date.now() % 30_000);
    await delay(remaining + 250);
  }
  await avoidTotpBoundary();
  assert(
    currentTotpCounter() > previousCounter,
    "ordinary TOTP login must use a counter after bootstrap",
  );
}

function currentTotpCounter() {
  return Math.floor(Date.now() / 30_000);
}

function totp(base32Secret, counterValue = currentTotpCounter()) {
  const key = decodeBase32(base32Secret);
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(counterValue));
  const digest = createHmac("sha1", key).update(counter).digest();
  const offset = digest.at(-1) & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

function decodeBase32(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = value.toUpperCase().replace(/=+$/u, "");
  let accumulator = 0;
  let bitCount = 0;
  const bytes = [];
  for (const character of normalized) {
    const digit = alphabet.indexOf(character);
    if (digit < 0)
      throw new Error("server returned an invalid Base32 TOTP secret");
    accumulator = (accumulator << 5) | digit;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((accumulator >>> bitCount) & 0xff);
      accumulator &= (1 << bitCount) - 1;
    }
  }
  return Buffer.from(bytes);
}
