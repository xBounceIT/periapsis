/// <reference types="node" />

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

describe("one-time recovery-code presentation", () => {
  it("keeps complete codes readable instead of clipping them", () => {
    const stylesheet = readFileSync(
      resolve(process.cwd(), "src", "app.css"),
      "utf8",
    );
    const rule = /\.recovery-code-list code\s*\{(?<body>[^}]*)\}/u.exec(
      stylesheet,
    )?.groups?.["body"];

    expect(rule).toBeDefined();
    expect(rule).toContain("overflow-wrap: anywhere");
    expect(rule).toContain("white-space: normal");
    expect(rule).not.toContain("text-overflow: ellipsis");
  });
});
