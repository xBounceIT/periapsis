interface IdempotencyBinding {
  fingerprint: string;
  key: string;
}

export interface IdempotencyReference {
  current: IdempotencyBinding | null;
}

export function idempotencyKeyForPayload(
  reference: IdempotencyReference,
  payload: unknown,
): string {
  const fingerprint = canonicalJson(payload);
  if (reference.current?.fingerprint !== fingerprint) {
    reference.current = {
      fingerprint,
      key: globalThis.crypto.randomUUID(),
    };
  }
  return reference.current.key;
}

export function isPayloadBoundToIdempotencyKey(
  reference: IdempotencyReference,
  payload: unknown,
): boolean {
  return reference.current?.fingerprint === canonicalJson(payload);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    const serialized = JSON.stringify(value);
    if (serialized === undefined) {
      throw new TypeError("Idempotency payloads must be JSON serializable.");
    }
    return serialized;
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalJson(item)).join(",")}]`;
  }

  if (!isJsonRecord(value)) {
    throw new TypeError("Idempotency payloads must be plain JSON objects.");
  }
  const entries = Object.entries(value)
    .filter(([, item]) => item !== undefined)
    .toSorted(([first], [second]) => first.localeCompare(second));
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(",")}}`;
}

function isJsonRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
