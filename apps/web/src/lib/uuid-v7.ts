const maximumUnixMilliseconds = 0xffff_ffff_ffff;
const canonicalUuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export type SecureRandomFill = (target: Uint8Array<ArrayBuffer>) => void;

export function isCanonicalUuidV7(value: unknown): value is string {
  return typeof value === "string" && canonicalUuidV7Pattern.test(value);
}

export function generateUuidV7(
  unixMilliseconds = Date.now(),
  fill: SecureRandomFill = secureRandomFill,
): string {
  if (
    !Number.isSafeInteger(unixMilliseconds) ||
    unixMilliseconds < 0 ||
    unixMilliseconds > maximumUnixMilliseconds
  ) {
    throw new RangeError("UUIDv7 timestamp is outside the 48-bit range.");
  }

  const bytes = new Uint8Array(new ArrayBuffer(16));
  fill(bytes);
  if (bytes.length !== 16) {
    throw new TypeError("UUIDv7 randomness must fill exactly 16 bytes.");
  }

  let timestamp = unixMilliseconds;
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = timestamp & 0xff;
    timestamp = Math.floor(timestamp / 256);
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;

  const hex = Array.from(bytes, (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function secureRandomFill(target: Uint8Array<ArrayBuffer>): void {
  globalThis.crypto.getRandomValues(target);
}
