import type { TicketCustomerContactLink } from "@periapsis/contracts";

import type { AlertDfirApi } from "../dfir/alert-dfir-api";
import type { AssetView, AttachmentView, IOCView } from "../dfir/model";
import type { TicketComment, TicketingApi } from "../lib/ticketing-api";

const maximumCommentPages = 2;
const maximumCommentPageSize = 50;
const maximumSelectionsPerCategory = 100;

export class EscalationInventoryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EscalationInventoryError";
  }
}

export interface EscalationInventory {
  assets: readonly AssetView[];
  attachments: readonly AttachmentView[];
  contacts: readonly TicketCustomerContactLink[];
  iocs: readonly IOCView[];
  publicComments: readonly TicketComment[];
}

export async function loadEscalationInventory(input: {
  alertId: string;
  dfirApi: AlertDfirApi;
  signal: AbortSignal;
  tenantId: string;
  ticketingApi: TicketingApi;
}): Promise<EscalationInventory> {
  const [workspace, contacts, publicComments] = await Promise.all([
    input.dfirApi.getWorkspace({
      alertId: input.alertId,
      signal: input.signal,
      tenantId: input.tenantId,
    }),
    input.ticketingApi.listAlertContactLinks(
      input.tenantId,
      input.alertId,
      input.signal,
    ),
    loadPublicComments(input),
  ]);
  if (contacts.nextCursor !== undefined) {
    throw new EscalationInventoryError(
      "Linked-contact selection exceeds the bounded inventory. Narrow the Alert before escalating.",
    );
  }
  return {
    assets: uniqueById(workspace.data.assets, "assets"),
    attachments: uniqueById(workspace.data.attachments, "attachments"),
    contacts: uniqueContacts(contacts.items),
    iocs: uniqueById(workspace.data.iocs, "IOCs"),
    publicComments,
  };
}

async function loadPublicComments(input: {
  alertId: string;
  signal: AbortSignal;
  tenantId: string;
  ticketingApi: TicketingApi;
}): Promise<TicketComment[]> {
  const comments: TicketComment[] = [];
  const seenCommentIds = new Set<string>();
  const seenCursors = new Set<string>();
  let after: string | undefined;
  for (let pageNumber = 0; pageNumber < maximumCommentPages; pageNumber += 1) {
    // oxlint-disable-next-line no-await-in-loop -- Cursor pages are causally ordered and capped at two requests.
    const page = await input.ticketingApi.listComments(
      "alert",
      input.tenantId,
      input.alertId,
      after,
      input.signal,
    );
    if (page.items.length > maximumCommentPageSize) {
      throw new EscalationInventoryError(
        "The public-comment inventory exceeded its page bound.",
      );
    }
    for (const comment of page.items) {
      if (seenCommentIds.has(comment.id)) {
        throw new EscalationInventoryError(
          "The public-comment inventory contained duplicates.",
        );
      }
      seenCommentIds.add(comment.id);
      if (comment.visibility === "public") comments.push(comment);
    }
    if (!page.nextCursor) return comments;
    if (seenCursors.has(page.nextCursor)) {
      throw new EscalationInventoryError(
        "The public-comment inventory cursor repeated.",
      );
    }
    seenCursors.add(page.nextCursor);
    after = page.nextCursor;
  }
  throw new EscalationInventoryError(
    "Public-comment selection exceeds the bounded inventory. Narrow the Alert before escalating.",
  );
}

function uniqueById<T extends { id: string }>(
  values: readonly T[],
  label: string,
): readonly T[] {
  const ids = new Set<string>();
  for (const value of values) {
    if (ids.has(value.id)) {
      throw new EscalationInventoryError(
        `The ${label} inventory contained duplicate identities.`,
      );
    }
    ids.add(value.id);
  }
  return values;
}

function uniqueContacts(
  values: readonly TicketCustomerContactLink[],
): readonly TicketCustomerContactLink[] {
  if (values.length > maximumSelectionsPerCategory) {
    throw new EscalationInventoryError(
      "The linked-contact inventory exceeded its selection bound.",
    );
  }
  const contactIds = new Set<string>();
  for (const value of values) {
    if (contactIds.has(value.contactId)) {
      throw new EscalationInventoryError(
        "The linked-contact inventory contained duplicate contact identities.",
      );
    }
    contactIds.add(value.contactId);
  }
  return values;
}

export function setBoundedSelection(
  current: ReadonlySet<string>,
  id: string,
  checked: boolean,
): Set<string> {
  const next = new Set(current);
  if (!checked) {
    next.delete(id);
    return next;
  }
  if (!next.has(id) && next.size >= maximumSelectionsPerCategory) {
    throw new EscalationInventoryError(
      "Select no more than 100 items in each category.",
    );
  }
  next.add(id);
  return next;
}
