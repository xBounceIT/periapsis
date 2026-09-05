import { domainToASCII } from "node:url";

import { NotificationValidationError } from "./errors.js";

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const keyPattern = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/u;
const localPartPattern = /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/iu;

export function requireUuidV7(value: string, field: string): string {
  if (!uuidV7Pattern.test(value)) {
    throw new NotificationValidationError(
      `${field} must be a canonical UUIDv7`,
    );
  }
  return value;
}

export function requireKey(
  value: string,
  field: string,
  maximum = 128,
): string {
  if (value.length > maximum || !keyPattern.test(value)) {
    throw new NotificationValidationError(`${field} must be a canonical key`);
  }
  return value;
}

export function requireText(
  value: string,
  field: string,
  maximum: number,
  options: { allowEmpty?: boolean; allowNewlines?: boolean } = {},
): string {
  const normalized = value.normalize("NFC");
  if (
    normalized !== value ||
    (!options.allowEmpty && normalized.length === 0) ||
    normalized.length > maximum ||
    containsForbiddenText(normalized) ||
    (!options.allowNewlines && /[\r\n]/u.test(normalized))
  ) {
    throw new NotificationValidationError(`${field} contains invalid text`);
  }
  return normalized;
}

export function canonicalEmail(value: string, field = "email"): string {
  requireText(value, field, 320);
  const separator = value.lastIndexOf("@");
  if (separator <= 0 || separator === value.length - 1) {
    throw new NotificationValidationError(
      `${field} is not a valid email address`,
    );
  }
  const local = value.slice(0, separator);
  const sourceDomain = value.slice(separator + 1);
  const domain = domainToASCII(sourceDomain).toLowerCase();
  if (
    local.length > 64 ||
    !localPartPattern.test(local) ||
    local.startsWith(".") ||
    local.endsWith(".") ||
    local.includes("..") ||
    domain.length === 0 ||
    domain.length > 253 ||
    !domain.split(".").every(validDomainLabel)
  ) {
    throw new NotificationValidationError(
      `${field} is not a valid email address`,
    );
  }
  return `${local.toLowerCase()}@${domain}`;
}

function validDomainLabel(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(value)
  );
}

function containsForbiddenText(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (
      codePoint <= 0x08 ||
      codePoint === 0x0b ||
      codePoint === 0x0c ||
      (codePoint >= 0x0e && codePoint <= 0x1f) ||
      codePoint === 0x7f ||
      (codePoint >= 0x202a && codePoint <= 0x202e) ||
      (codePoint >= 0x2066 && codePoint <= 0x2069)
    ) {
      return true;
    }
  }
  return false;
}

export function requireInstant(value: Date, field: string): Date {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) {
    throw new NotificationValidationError(`${field} must be a finite instant`);
  }
  return new Date(value.getTime());
}

export function requireInteger(
  value: number,
  field: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new NotificationValidationError(
      `${field} is outside its supported range`,
    );
  }
  return value;
}

export function exhaustive(value: never): never {
  throw new NotificationValidationError(`unsupported value: ${String(value)}`);
}

// JSON.parse silently accepts duplicate object names. Configuration and
// internal protocol documents reject them, including escaped aliases, before
// decoding so an upstream signer and this process cannot interpret different
// values for the same field.
export function parseStrictJson(input: string): unknown {
  let offset = 0;
  const skipWhitespace = (): void => {
    while (
      input[offset] === " " ||
      input[offset] === "\t" ||
      input[offset] === "\r" ||
      input[offset] === "\n"
    ) {
      offset += 1;
    }
  };
  const parseString = (): string => {
    const start = offset;
    if (input[offset] !== '"') invalidJson();
    offset += 1;
    while (offset < input.length) {
      const character = input[offset];
      if (character === '"') {
        offset += 1;
        const decoded = JSON.parse(input.slice(start, offset)) as unknown;
        if (typeof decoded !== "string") invalidJson();
        return decoded;
      }
      if (character === "\\") {
        offset += 1;
        if (offset >= input.length) invalidJson();
        if (input[offset] === "u") {
          if (!/^[0-9A-Fa-f]{4}$/u.test(input.slice(offset + 1, offset + 5))) {
            invalidJson();
          }
          offset += 5;
        } else {
          offset += 1;
        }
      } else {
        offset += 1;
      }
    }
    return invalidJson();
  };
  const parseValue = (): void => {
    skipWhitespace();
    const character = input[offset];
    if (character === "{") {
      offset += 1;
      skipWhitespace();
      const names = new Set<string>();
      if (input[offset] === "}") {
        offset += 1;
        return;
      }
      for (;;) {
        skipWhitespace();
        const name = parseString();
        if (names.has(name)) invalidJson();
        names.add(name);
        skipWhitespace();
        if (input[offset] !== ":") invalidJson();
        offset += 1;
        parseValue();
        skipWhitespace();
        if (input[offset] === "}") {
          offset += 1;
          return;
        }
        if (input[offset] !== ",") invalidJson();
        offset += 1;
      }
    }
    if (character === "[") {
      offset += 1;
      skipWhitespace();
      if (input[offset] === "]") {
        offset += 1;
        return;
      }
      for (;;) {
        parseValue();
        skipWhitespace();
        if (input[offset] === "]") {
          offset += 1;
          return;
        }
        if (input[offset] !== ",") invalidJson();
        offset += 1;
      }
    }
    if (character === '"') {
      parseString();
      return;
    }
    for (const literal of ["true", "false", "null"]) {
      if (input.startsWith(literal, offset)) {
        offset += literal.length;
        return;
      }
    }
    const number =
      /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/u.exec(
        input.slice(offset),
      );
    if (number === null) invalidJson();
    offset += number[0].length;
  };

  parseValue();
  skipWhitespace();
  if (offset !== input.length) invalidJson();
  return JSON.parse(input) as unknown;
}

function invalidJson(): never {
  throw new SyntaxError("JSON document is invalid or ambiguous");
}
