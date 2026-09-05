import { describe, expect, it } from "vitest";

import {
  hasBidiControlCharacters,
  hasControlCharacters,
  hasForbiddenCommentMarkdownCharacters,
} from "./text-validation";

describe("hasControlCharacters", () => {
  it.each(["\u0000", "\n", "\u001f", "\u007f", "\u0085", "\u009f"])(
    "rejects the OpenAPI control range represented by %j",
    (character) => {
      expect(hasControlCharacters(`before${character}after`)).toBe(true);
    },
  );

  it("allows printable Unicode outside the control ranges", () => {
    expect(hasControlCharacters("Operational handoff · Δ")).toBe(false);
  });
});

describe("comment text controls", () => {
  it.each([
    "\u200e",
    "\u200f",
    "\u202a",
    "\u202b",
    "\u202c",
    "\u202d",
    "\u202e",
    "\u2066",
    "\u2067",
    "\u2068",
    "\u2069",
  ])("rejects bidi control %j", (character) => {
    expect(hasBidiControlCharacters(`before${character}after`)).toBe(true);
    expect(
      hasForbiddenCommentMarkdownCharacters(`before${character}after`),
    ).toBe(true);
  });

  it("allows only tab and LF from the ASCII control range in comment Markdown", () => {
    expect(hasForbiddenCommentMarkdownCharacters("one\ttwo\nthree")).toBe(
      false,
    );
    expect(hasForbiddenCommentMarkdownCharacters("one\rtwo")).toBe(true);
  });
});
