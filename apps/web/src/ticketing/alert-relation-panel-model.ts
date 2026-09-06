import type { AlertRelation } from "@periapsis/contracts";
import { type AlertRelationPage } from "./alert-relation-api";

export function flattenAlertRelationPages(
  pages: readonly AlertRelationPage[] | undefined,
): { canonical: boolean; items: readonly AlertRelation[] } {
  if (!pages) return { canonical: true, items: [] };
  const items: AlertRelation[] = [];
  const ids = new Set<string>();
  const pairs = new Set<string>();
  let previousId: string | undefined;
  for (const page of pages) {
    for (const item of page.items) {
      const pair = [item.sourceAlertId, item.targetAlertId]
        .toSorted()
        .join(":");
      if (
        ids.has(item.id) ||
        pairs.has(pair) ||
        (previousId !== undefined && previousId <= item.id)
      ) {
        return { canonical: false, items: [] };
      }
      ids.add(item.id);
      pairs.add(pair);
      previousId = item.id;
      items.push(item);
    }
  }
  return { canonical: true, items };
}
