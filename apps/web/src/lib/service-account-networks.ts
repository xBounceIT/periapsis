interface ParsedCredentialNetwork {
  address: Uint8Array;
  bits: number;
  canonical: string;
  family: 4 | 6;
}

const maximumCredentialNetworks = 32;

/**
 * Validates canonical CIDR spelling and returns PostgreSQL's native cidr
 * order: address family, network address, then prefix length.
 */
export function canonicalizeServiceAccountCredentialNetworks(
  values: unknown,
): string[] | undefined {
  if (!Array.isArray(values) || values.length > maximumCredentialNetworks) {
    return undefined;
  }

  const parsed: ParsedCredentialNetwork[] = [];
  for (const value of values) {
    if (typeof value !== "string" || value.length < 3 || value.length > 43) {
      return undefined;
    }
    const network = parseCredentialNetwork(value);
    if (!network) return undefined;
    parsed.push(network);
  }

  parsed.sort(compareCredentialNetworks);
  for (let index = 1; index < parsed.length; index += 1) {
    if (parsed[index - 1]?.canonical === parsed[index]?.canonical) {
      return undefined;
    }
  }
  return parsed.map(({ canonical }) => canonical);
}

function parseCredentialNetwork(
  value: string,
): ParsedCredentialNetwork | undefined {
  const slash = value.indexOf("/");
  if (slash <= 0 || slash !== value.lastIndexOf("/")) return undefined;

  const addressText = value.slice(0, slash);
  const bitsText = value.slice(slash + 1);
  if (!/^(0|[1-9][0-9]{0,2})$/u.test(bitsText)) return undefined;
  const bits = Number(bitsText);

  if (addressText.includes(":")) {
    if (bits > 128) return undefined;
    const address = parseIPv6Address(addressText);
    if (
      !address ||
      isIPv4MappedAddress(address) ||
      !hasNoHostBits(address, bits)
    ) {
      return undefined;
    }
    const canonical = `${formatIPv6Address(address)}/${bits}`;
    return canonical === value
      ? { address, bits, canonical, family: 6 }
      : undefined;
  }

  if (bits > 32) return undefined;
  const address = parseIPv4Address(addressText);
  if (!address || !hasNoHostBits(address, bits)) return undefined;
  const canonical = `${address.join(".")}/${bits}`;
  return canonical === value
    ? { address, bits, canonical, family: 4 }
    : undefined;
}

function parseIPv4Address(value: string): Uint8Array | undefined {
  const octets = value.split(".");
  if (octets.length !== 4) return undefined;

  const result = new Uint8Array(4);
  for (const [index, octet] of octets.entries()) {
    if (!/^(0|[1-9][0-9]{0,2})$/u.test(octet)) return undefined;
    const parsed = Number(octet);
    if (parsed > 255) return undefined;
    result[index] = parsed;
  }
  return result;
}

function parseIPv6Address(value: string): Uint8Array | undefined {
  if (
    value.includes("%") ||
    value.includes(".") ||
    !/^[0-9A-Fa-f:]+$/u.test(value)
  ) {
    return undefined;
  }

  const compression = value.indexOf("::");
  if (compression !== -1 && compression !== value.lastIndexOf("::")) {
    return undefined;
  }

  const leftText = compression === -1 ? value : value.slice(0, compression);
  const rightText = compression === -1 ? "" : value.slice(compression + 2);
  const left = leftText === "" ? [] : leftText.split(":");
  const right = rightText === "" ? [] : rightText.split(":");
  if (
    left.some((word) => !validIPv6Word(word)) ||
    right.some((word) => !validIPv6Word(word))
  ) {
    return undefined;
  }

  const missing = 8 - left.length - right.length;
  if (
    (compression === -1 && missing !== 0) ||
    (compression !== -1 && missing < 1)
  ) {
    return undefined;
  }

  const words = [
    ...left.map((word) => Number.parseInt(word, 16)),
    ...Array.from({ length: missing }, () => 0),
    ...right.map((word) => Number.parseInt(word, 16)),
  ];
  if (words.length !== 8) return undefined;

  const result = new Uint8Array(16);
  for (const [index, word] of words.entries()) {
    result[index * 2] = word >>> 8;
    result[index * 2 + 1] = word & 0xff;
  }
  return result;
}

function validIPv6Word(value: string): boolean {
  return /^[0-9A-Fa-f]{1,4}$/u.test(value);
}

function formatIPv6Address(address: Uint8Array): string {
  const words = Array.from(
    { length: 8 },
    (_, index) =>
      (address[index * 2] ?? 0) * 256 + (address[index * 2 + 1] ?? 0),
  );
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < words.length;) {
    if (words[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index + 1;
    while (end < words.length && words[end] === 0) end += 1;
    if (end - index > bestLength) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }

  if (bestLength < 2) return words.map((word) => word.toString(16)).join(":");
  const left = words
    .slice(0, bestStart)
    .map((word) => word.toString(16))
    .join(":");
  const right = words
    .slice(bestStart + bestLength)
    .map((word) => word.toString(16))
    .join(":");
  if (left && right) return `${left}::${right}`;
  if (left) return `${left}::`;
  if (right) return `::${right}`;
  return "::";
}

function hasNoHostBits(address: Uint8Array, bits: number): boolean {
  const completeBytes = Math.floor(bits / 8);
  const remainingBits = bits % 8;
  if (remainingBits !== 0) {
    const hostMask = (1 << (8 - remainingBits)) - 1;
    if (((address[completeBytes] ?? 0) & hostMask) !== 0) return false;
  }
  const firstHostByte = completeBytes + (remainingBits === 0 ? 0 : 1);
  return address.slice(firstHostByte).every((value) => value === 0);
}

function isIPv4MappedAddress(address: Uint8Array): boolean {
  return (
    address.slice(0, 10).every((value) => value === 0) &&
    address[10] === 0xff &&
    address[11] === 0xff
  );
}

function compareCredentialNetworks(
  left: ParsedCredentialNetwork,
  right: ParsedCredentialNetwork,
): number {
  if (left.family !== right.family) return left.family - right.family;
  for (let index = 0; index < left.address.length; index += 1) {
    const difference = (left.address[index] ?? 0) - (right.address[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.bits - right.bits;
}
