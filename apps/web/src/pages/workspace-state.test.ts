import { describe, expect, it } from "vitest";
import { reduceWorkspaceState } from "./workspace-state";

describe("workspace state transitions", () => {
  it("resets related editor fields atomically without changing the previous snapshot", () => {
    const previous = {
      editing: true,
      reason: "pending change",
      error: "conflict" as string | null,
    };
    expect(
      reduceWorkspaceState(previous, {
        editing: false,
        reason: "",
        error: null,
      }),
    ).toEqual({ editing: false, reason: "", error: null });
    expect(previous).toEqual({
      editing: true,
      reason: "pending change",
      error: "conflict",
    });
  });
  it("applies field updaters to the previous snapshot and retains untouched fields", () => {
    const previous = { revision: 2, items: ["one"], sessionId: "session" };
    expect(
      reduceWorkspaceState(previous, {
        revision: (value) => value + 1,
        items: (values) => [...values, "two"],
      }),
    ).toEqual({ revision: 3, items: ["one", "two"], sessionId: "session" });
  });
  it("retains referential equality for unchanged transitions and supports explicit undefined", () => {
    const previous = { selection: "one" as string | undefined, busy: false };
    expect(reduceWorkspaceState(previous, { busy: false })).toBe(previous);
    expect(
      reduceWorkspaceState(previous, { selection: undefined }).selection,
    ).toBeUndefined();
  });
});
