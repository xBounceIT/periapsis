import { afterEach, describe, expect, it, vi } from "vitest";

import {
  createSessionAwareFetch,
  federatedMfaContinuationPath,
  subscribeToSessionTransitions,
  type SessionTransitionNotice,
} from "./session-transition-transport";

describe("session transition transport", () => {
  const removers: Array<() => void> = [];

  afterEach(() => {
    for (const remove of removers.splice(0)) remove();
  });

  it("retries an exact rotated GET once and publishes the new authority", async () => {
    const notices: SessionTransitionNotice[] = [];
    removers.push(
      subscribeToSessionTransitions((notice) => notices.push(notice)),
    );
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(transitionResponse("session_rotated"))
      .mockResolvedValueOnce(
        new Response('{"items":[]}', {
          headers: { "Content-Type": "application/json" },
          status: 200,
        }),
      );

    const response = await createSessionAwareFetch(transport)(
      `${location.origin}/api/v1/alerts`,
      { credentials: "same-origin", method: "GET" },
    );

    expect(response.status).toBe(200);
    expect(transport).toHaveBeenCalledTimes(2);
    expect(
      transport.mock.calls.map(([request]) =>
        request instanceof Request ? request.method : undefined,
      ),
    ).toEqual(["GET", "GET"]);
    expect(notices).toEqual([{ kind: "session_rotated" }]);
  });

  it("never replays an unsafe mutation after session rotation", async () => {
    const notices: SessionTransitionNotice[] = [];
    removers.push(
      subscribeToSessionTransitions((notice) => notices.push(notice)),
    );
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValue(transitionResponse("session_rotated"));

    const response = await createSessionAwareFetch(transport)(
      `${location.origin}/api/v1/alerts`,
      { method: "POST" },
    );

    expect(response.status).toBe(401);
    expect(transport).toHaveBeenCalledTimes(1);
    expect(notices).toEqual([{ kind: "session_rotated" }]);
  });

  it("routes step-up without retrying even a GET", async () => {
    const notices: SessionTransitionNotice[] = [];
    removers.push(
      subscribeToSessionTransitions((notice) => notices.push(notice)),
    );
    const transport = vi
      .fn<typeof fetch>()
      .mockResolvedValue(transitionResponse("mfa_step_up_required"));

    await createSessionAwareFetch(transport)(
      `${location.origin}/api/v1/cases`,
      { method: "GET" },
    );

    expect(transport).toHaveBeenCalledTimes(1);
    expect(notices).toEqual([
      {
        kind: "mfa_step_up_required",
        location: federatedMfaContinuationPath,
      },
    ]);
  });

  it("ignores cross-origin and mismatched transition claims", async () => {
    const listener = vi.fn();
    removers.push(subscribeToSessionTransitions(listener));
    const crossOrigin = vi
      .fn<typeof fetch>()
      .mockResolvedValue(transitionResponse("session_rotated"));
    const mismatched = vi.fn<typeof fetch>().mockResolvedValue(
      transitionResponse("session_rotated", {
        "X-Periapsis-Session-Transition": "mfa_step_up_required",
      }),
    );

    await createSessionAwareFetch(crossOrigin)(
      "https://other.invalid/api/v1/cases",
    );
    await createSessionAwareFetch(mismatched)(
      `${location.origin}/api/v1/cases`,
      { method: "POST" },
    );

    expect(crossOrigin).toHaveBeenCalledTimes(1);
    expect(mismatched).toHaveBeenCalledTimes(1);
    expect(listener).not.toHaveBeenCalled();
  });
});

function transitionResponse(
  code: "mfa_step_up_required" | "session_rotated",
  headers: HeadersInit = {},
): Response {
  const responseHeaders = new Headers({
    "Cache-Control": "no-store",
    "Content-Type": "application/problem+json",
    "X-Periapsis-Session-Transition": code,
    ...(code === "mfa_step_up_required"
      ? { Location: federatedMfaContinuationPath }
      : {}),
  });
  new Headers(headers).forEach((value, name) => {
    responseHeaders.set(name, value);
  });
  return new Response(JSON.stringify({ code, status: 401, title: "Denied" }), {
    headers: responseHeaders,
    status: 401,
  });
}
