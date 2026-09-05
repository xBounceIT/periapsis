export const federatedMfaContinuationPath = "/?auth=federated-mfa";

export type SessionTransitionNotice =
  | { kind: "session_rotated" }
  | {
      kind: "mfa_step_up_required";
      location: typeof federatedMfaContinuationPath;
    };

type SessionTransitionListener = (notice: SessionTransitionNotice) => void;

const transitionHeader = "X-Periapsis-Session-Transition";
const listeners = new Set<SessionTransitionListener>();

export function subscribeToSessionTransitions(
  listener: SessionTransitionListener,
): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function createSessionAwareFetch(transport: typeof fetch): typeof fetch {
  return async (input, init) => {
    const request = canonicalRequest(input, init);
    const retryRequest = request.method === "GET" ? request.clone() : null;
    const response = await transport(request);
    if (!isSameOriginApiRequest(request)) return response;

    const transition = await readTransition(response);
    if (!transition) return response;
    publish(transition);

    // A rotated cookie makes an idempotent GET safe to repeat exactly once.
    // Mutations are never replayed: the caller must review and resubmit them.
    if (transition.kind !== "session_rotated" || !retryRequest) {
      return response;
    }
    const retried = await transport(retryRequest);
    const retryTransition = await readTransition(retried);
    if (retryTransition) publish(retryTransition);
    return retried;
  };
}

export const sessionAwareFetch = createSessionAwareFetch((input, init) =>
  globalThis.fetch(input, init),
);

function canonicalRequest(
  input: RequestInfo | URL,
  init?: RequestInit,
): Request {
  if (input instanceof Request) return new Request(input, init);
  const target =
    typeof input === "string"
      ? new URL(input, globalThis.location.origin)
      : input;
  return new Request(target, init);
}

function isSameOriginApiRequest(request: Request): boolean {
  const target = new URL(request.url);
  return (
    target.origin === globalThis.location.origin &&
    (target.pathname === "/api" || target.pathname.startsWith("/api/"))
  );
}

async function readTransition(
  response: Response,
): Promise<SessionTransitionNotice | null> {
  if (
    response.status !== 401 ||
    response.headers.get("Cache-Control") !== "no-store" ||
    !response.headers
      .get("Content-Type")
      ?.toLowerCase()
      .startsWith("application/problem+json")
  ) {
    return null;
  }
  const header = response.headers.get(transitionHeader);
  if (header !== "session_rotated" && header !== "mfa_step_up_required") {
    return null;
  }

  let problem: unknown;
  try {
    problem = await response.clone().json();
  } catch {
    return null;
  }
  if (!isRecord(problem) || problem["code"] !== header) return null;

  const location = response.headers.get("Location");
  if (header === "session_rotated") {
    return location === null ? { kind: header } : null;
  }
  return location === federatedMfaContinuationPath
    ? { kind: header, location }
    : null;
}

function publish(notice: SessionTransitionNotice): void {
  for (const listener of listeners) listener(notice);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
