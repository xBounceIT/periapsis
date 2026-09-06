import type { ActivityProjection } from "@periapsis/contracts";
import { type CursorPage } from "../lib/ticketing-api";

export type OperatorActivity = Extract<
  ActivityProjection,
  { projection: "operator" }
>;

interface FeedProjection {
  invalid: boolean;
  items: OperatorActivity[];
}

export function mergeActivityPages(
  pages: readonly CursorPage<OperatorActivity>[],
): FeedProjection {
  const items: OperatorActivity[] = [];
  const seen = new Set<string>();
  let previousId: string | undefined;
  for (const page of pages) {
    for (const item of page.items) {
      if (
        seen.has(item.id) ||
        (previousId !== undefined && previousId <= item.id)
      ) {
        return { invalid: true, items: [] };
      }
      seen.add(item.id);
      previousId = item.id;
      items.push(item);
    }
  }
  return { invalid: false, items };
}
