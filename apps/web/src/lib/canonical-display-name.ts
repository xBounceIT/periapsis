import { hasBidiControlCharacters } from "./text-validation";

const goTrimSpaceCodePoints = new Set([
  0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x0020, 0x0085, 0x00a0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008,
  0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
]);

export function isCanonicalDisplayName(
  value: unknown,
  maximumCodePoints: number,
): value is string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Array.from(value).length > maximumCodePoints ||
    hasUnpairedSurrogate(value) ||
    hasBidiControlCharacters(value)
  ) {
    return false;
  }
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint === undefined ||
      codePoint <= 0x001f ||
      (codePoint >= 0x007f && codePoint <= 0x009f)
    ) {
      return false;
    }
  }
  return !hasGoTrimSpaceAtEdge(value);
}

export function hasGoTrimSpaceAtEdge(value: string): boolean {
  const first = value.codePointAt(0);
  const last = value.codePointAt(value.length - 1);
  return (
    (first !== undefined && goTrimSpaceCodePoints.has(first)) ||
    (last !== undefined && goTrimSpaceCodePoints.has(last))
  );
}

export function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      if (index + 1 >= value.length) return true;
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) return true;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}
