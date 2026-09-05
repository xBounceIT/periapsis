export interface TaskChecklistIntentItem {
  completed: boolean;
  id: string;
  title: string;
}

interface CurrentTaskChecklistItem {
  id: string;
  title: string;
}

export function parseTaskChecklistIntent(
  value: string,
  current: readonly CurrentTaskChecklistItem[],
  generatedIds: readonly string[],
  resource: "Case" | "Alert",
): TaskChecklistIntentItem[] {
  const lines = value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean);
  const article = resource === "Case" ? "A" : "An";
  if (lines.length > 100) {
    throw new Error(
      `${article} ${resource} task checklist can contain at most 100 items.`,
    );
  }

  const parsed = lines.map((line) => {
    const match = /^\[([ xX])\]\s+(.+)$/u.exec(line);
    const title = match?.[2]?.trim();
    if (!match || !title || title.length > 512) {
      throw new Error(
        "Write each checklist item as [ ] title or [x] title (512 characters maximum).",
      );
    }
    return { completed: match[1]?.toLowerCase() === "x", title };
  });

  // Reserve exact title matches before positional fallback. Otherwise an
  // earlier rename can steal the identity of a later unchanged item.
  const reservedIds = new Set<string>();
  const exactIds = parsed.map(({ title }) => {
    const exact = current.find(
      (item) => item.title === title && !reservedIds.has(item.id),
    );
    if (exact) reservedIds.add(exact.id);
    return exact?.id;
  });
  const existingIds = new Set(current.map(({ id }) => id));
  const usedIds = new Set(reservedIds);
  let generatedIndex = 0;

  return parsed.map(({ completed, title }, index) => {
    const positional = current[index];
    let id = exactIds[index];
    if (!id && positional && !usedIds.has(positional.id)) {
      id = positional.id;
    }
    if (!id) {
      while (
        generatedIndex < generatedIds.length &&
        (!generatedIds[generatedIndex] ||
          existingIds.has(generatedIds[generatedIndex]!) ||
          usedIds.has(generatedIds[generatedIndex]!))
      ) {
        generatedIndex += 1;
      }
      id = generatedIds[generatedIndex];
      generatedIndex += 1;
    }
    if (!id) {
      throw new Error(
        "Write each checklist item as [ ] title or [x] title (512 characters maximum).",
      );
    }
    usedIds.add(id);
    return { completed, id, title };
  });
}
