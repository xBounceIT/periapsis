/// <reference types="node" />

import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

const darkTokens = [
  "background",
  "foreground",
  "card",
  "card-foreground",
  "popover",
  "popover-foreground",
  "primary",
  "primary-foreground",
  "secondary",
  "secondary-foreground",
  "muted",
  "muted-foreground",
  "accent",
  "accent-foreground",
  "destructive",
  "border",
  "input",
  "ring",
] as const;

describe("shared dark theme", () => {
  it("uses the explicit dark palette when the operating system prefers dark", () => {
    const stylesheet = readFileSync(
      new URL("./styles.css", import.meta.url),
      "utf8",
    );
    const explicit = /\.dark\s*\{(?<tokens>[^}]+)\}/u.exec(stylesheet)
      ?.groups?.["tokens"];
    const automatic =
      /@media\s*\(prefers-color-scheme:\s*dark\)\s*\{\s*:root\s*\{(?<tokens>[^}]+)\}/u.exec(
        stylesheet,
      )?.groups?.["tokens"];

    expect(explicit).toBeDefined();
    expect(automatic).toBeDefined();
    for (const token of darkTokens) {
      expect(tokenValue(automatic, token)).toBe(tokenValue(explicit, token));
    }
  });
});

function tokenValue(source: string | undefined, token: string): string {
  const value = new RegExp(`--${token}:\\s*(?<value>[^;]+);`, "u").exec(
    source ?? "",
  )?.groups?.["value"];
  expect(value, `missing --${token}`).toBeDefined();
  return value?.trim() ?? "";
}
