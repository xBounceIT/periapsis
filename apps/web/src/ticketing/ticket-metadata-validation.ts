const metadataWhitespaceClass = String.raw`\u0009-\u000D\u0020\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000`;
const metadataLeadingWhitespacePattern = new RegExp(
  `^[${metadataWhitespaceClass}]+`,
  "u",
);
const metadataTrailingWhitespacePattern = new RegExp(
  `[${metadataWhitespaceClass}]+$`,
  "u",
);

export const ticketMetadataTagPattern = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$/u;

export function trimMetadataEdges(value: string): string {
  return value
    .replace(metadataLeadingWhitespacePattern, "")
    .replace(metadataTrailingWhitespacePattern, "");
}

export function hasMetadataEdgeWhitespace(value: string): boolean {
  return (
    metadataLeadingWhitespacePattern.test(value) ||
    metadataTrailingWhitespacePattern.test(value)
  );
}

export function metadataCodePointLength(value: string): number {
  return Array.from(value).length;
}

export function containsDisallowedMetadataControl(
  value: string,
  multiline: boolean,
): boolean {
  for (const character of value) {
    if (
      multiline &&
      (character === "\n" || character === "\r" || character === "\t")
    ) {
      continue;
    }
    const codePoint = character.codePointAt(0);
    if (
      codePoint !== undefined &&
      (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f))
    ) {
      return true;
    }
  }
  return false;
}

export function compareMetadataCodePoints(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}
