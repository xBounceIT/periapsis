import type { SavedTicketView } from "@periapsis/contracts";
import {
  type SavedTicketViewPageView,
  type TicketKind,
} from "../lib/ticketing-api";

interface SavedViewInventory {
  invalid: boolean;
  items: SavedTicketView[];
}

interface SavedViewInventoryBoundary {
  kind: TicketKind;
  ownerMembershipId: string;
  tenantId: string;
}

export function mergeReportSavedViewPages(
  pages: readonly SavedTicketViewPageView[],
  boundary: SavedViewInventoryBoundary,
): SavedViewInventory {
  const items: SavedTicketView[] = [];
  let previousId: string | undefined;
  for (const page of pages) {
    for (const item of page.items) {
      if (
        item.status !== "active" ||
        item.kind !== boundary.kind ||
        item.ownerMembershipId !== boundary.ownerMembershipId ||
        item.tenantId !== boundary.tenantId ||
        (previousId !== undefined && previousId >= item.id)
      ) {
        return { invalid: true, items: [] };
      }
      items.push(item);
      previousId = item.id;
    }
  }
  return { invalid: false, items };
}
