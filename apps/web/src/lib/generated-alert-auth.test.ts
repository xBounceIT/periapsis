import { describe, expect, it } from "vitest";

import { createTenantAlert } from "@periapsis/contracts";
import { createClient } from "@periapsis/contracts/client";

const tenantId = "00000000-0000-4000-8000-000000000001";

describe("generated Alert authentication", () => {
  it("never expands one static auth value into mixed principal credentials", async () => {
    let captured: Request | undefined;
    const testClient = createClient({
      auth: "one-static-auth-value",
      baseUrl: "https://example.invalid",
      fetch: async (request) => {
        captured = request instanceof Request ? request : new Request(request);
        return unauthorizedResponse();
      },
    });

    await createTenantAlert({
      body: { severity: "high", title: "Generated auth regression" },
      client: testClient,
      headers: { "Idempotency-Key": "generated-auth-regression" },
      path: { tenantId },
    });

    expect(captured).toBeInstanceOf(Request);
    expect(captured?.credentials).toBe("same-origin");
    expect(captured?.headers.has("Authorization")).toBe(false);
    expect(captured?.headers.has("Cookie")).toBe(false);
    expect(captured?.headers.has("X-CSRF-Token")).toBe(false);
  });

  it("preserves an explicitly selected bearer mode in isolation", async () => {
    let captured: Request | undefined;
    const testClient = createClient({
      auth: "unused-static-auth-value",
      baseUrl: "https://example.invalid",
      fetch: async (request) => {
        captured = request instanceof Request ? request : new Request(request);
        return unauthorizedResponse();
      },
    });

    await createTenantAlert({
      body: { severity: "high", title: "Explicit bearer regression" },
      client: testClient,
      credentials: "omit",
      headers: {
        Authorization: "Bearer explicit-service-account-token",
        "Idempotency-Key": "explicit-bearer-regression",
      },
      path: { tenantId },
    });

    expect(captured?.headers.get("Authorization")).toBe(
      "Bearer explicit-service-account-token",
    );
    expect(captured?.credentials).toBe("omit");
    expect(captured?.headers.has("Cookie")).toBe(false);
    expect(captured?.headers.has("X-CSRF-Token")).toBe(false);
  });
});

function unauthorizedResponse(): Response {
  return new Response(
    JSON.stringify({
      detail: "authentication failed",
      status: 401,
      title: "Unauthorized",
      type: "about:blank",
    }),
    { headers: { "Content-Type": "application/problem+json" }, status: 401 },
  );
}
