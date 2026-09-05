import { describe, expect, it } from "vitest";

import { parseTaskChecklistIntent } from "./task-checklist-intent";

describe("parseTaskChecklistIntent", () => {
  it("reserves unchanged identities before assigning a positional rename", () => {
    expect(
      parseTaskChecklistIntent(
        "[ ] Renamed first item\n[x] First item",
        [
          { id: "first-id", title: "First item" },
          { id: "second-id", title: "Second item" },
        ],
        ["new-first-id", "new-second-id"],
        "Case",
      ),
    ).toEqual([
      {
        completed: false,
        id: "new-first-id",
        title: "Renamed first item",
      },
      { completed: true, id: "first-id", title: "First item" },
    ]);
  });

  it("keeps a positional identity when it is not reserved", () => {
    expect(
      parseTaskChecklistIntent(
        "[x] Renamed first item\n[ ] Second item",
        [
          { id: "first-id", title: "First item" },
          { id: "second-id", title: "Second item" },
        ],
        ["new-first-id", "new-second-id"],
        "Alert",
      ),
    ).toEqual([
      { completed: true, id: "first-id", title: "Renamed first item" },
      { completed: false, id: "second-id", title: "Second item" },
    ]);
  });

  it("does not accept an existing identity as a generated id", () => {
    expect(
      parseTaskChecklistIntent(
        "[ ] Existing\n[ ] New item",
        [{ id: "existing-id", title: "Existing" }],
        ["existing-id", "new-id"],
        "Case",
      ),
    ).toEqual([
      { completed: false, id: "existing-id", title: "Existing" },
      { completed: false, id: "new-id", title: "New item" },
    ]);
  });
});
