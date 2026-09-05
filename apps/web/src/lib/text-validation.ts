export function hasControlCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit <= 0x1f || (codeUnit >= 0x7f && codeUnit <= 0x9f)) {
      return true;
    }
  }
  return false;
}

export function hasBidiControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0);
    if (
      codePoint === 0x200e ||
      codePoint === 0x200f ||
      (codePoint !== undefined && codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint !== undefined && codePoint >= 0x2066 && codePoint <= 0x2069)
    ) {
      return true;
    }
  }
  return false;
}

export function hasForbiddenCommentMarkdownCharacters(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (
      (codeUnit <= 0x1f && codeUnit !== 0x09 && codeUnit !== 0x0a) ||
      (codeUnit >= 0x7f && codeUnit <= 0x9f)
    ) {
      return true;
    }
  }
  return hasBidiControlCharacters(value);
}
