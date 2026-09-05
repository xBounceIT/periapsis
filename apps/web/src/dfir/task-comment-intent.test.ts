import { describe, expect, it } from "vitest";

import { parseTaskCommentIntent } from "./task-comment-intent";

describe("parseTaskCommentIntent", () => {
  it("accepts an empty full replacement and canonicalizes UUIDv7 order", () => {
    expect(parseTaskCommentIntent(" \n", "Case")).toEqual([]);
    expect(
      parseTaskCommentIntent(
        "0198c97d-cf4f-7000-8000-000000000002\n0198c97d-cf4f-7000-8000-000000000001",
        "Alert",
      ),
    ).toEqual([
      "0198c97d-cf4f-7000-8000-000000000001",
      "0198c97d-cf4f-7000-8000-000000000002",
    ]);
  });

  it("rejects duplicates, non-v7 IDs, and more than 1000 links", () => {
    const id = "0198c97d-cf4f-7000-8000-000000000001";
    expect(() => parseTaskCommentIntent(`${id}\n${id}`, "Case")).toThrow(
      /unique/u,
    );
    expect(() =>
      parseTaskCommentIntent("0198c97d-cf4f-4000-8000-000000000001", "Alert"),
    ).toThrow(/UUIDv7/u);
    expect(() =>
      parseTaskCommentIntent(
        Array.from(
          { length: 1_001 },
          (_, index) =>
            `0198c97d-cf4f-7000-8000-${index.toString().padStart(12, "0")}`,
        ).join("\n"),
        "Case",
      ),
    ).toThrow(/at most 1000/u);
  });
});
