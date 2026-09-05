export const notificationAudiences = ["operator", "customer"] as const;
export type NotificationAudience = (typeof notificationAudiences)[number];

export const notificationResourceKinds = [
  "alert",
  "case",
  "task",
  "evidence",
  "contact",
] as const;

export const notificationInboxRouteDescriptor = {
  path: "/notifications",
  label: "Notification center",
} as const;
export type NotificationResourceKind =
  (typeof notificationResourceKinds)[number];

export const notificationEventTypes = [
  "alert.created",
  "alert.assigned",
  "alert.claimed",
  "alert.status_changed",
  "alert.escalated",
  "alert.watcher_added",
  "alert.watcher_removed",
  "case.created",
  "case.assigned",
  "case.claimed",
  "case.transferred",
  "case.status_changed",
  "case.watcher_added",
  "case.watcher_removed",
  "comment.public_added",
  "comment.private_added",
  "contact.changed",
  "sla.warning",
  "sla.breached",
  "task.assigned",
  "evidence.added",
  "webhook.custom",
] as const;
export type NotificationEventType = (typeof notificationEventTypes)[number];

export interface NotificationInboxCoordinate {
  tenantId: string;
  userId: string;
}

export interface NotificationInboxItemView extends NotificationInboxCoordinate {
  audience: NotificationAudience;
  eventType: NotificationEventType;
  id: string;
  occurredAt: string;
  readAt: string | null;
  resourceId: string;
  resourceKind: NotificationResourceKind;
  resourceVersion: number;
  revision: number;
  summary: string;
  title: string;
}

export interface NotificationInboxPageView {
  inboxRevision: number;
  items: readonly NotificationInboxItemView[];
  nextCursor?: string;
  tenantId: string;
  userId: string;
}

export interface NotificationUnreadStateView {
  count: number;
  inboxRevision: number;
  tenantId: string;
  userId: string;
}

export interface NotificationReadStateResultView {
  changed: boolean;
  inboxRevision: number;
  item: NotificationInboxItemView;
  replayed: boolean;
}

export interface NotificationMarkAllReadResultView {
  affected: number;
  changed: boolean;
  inboxRevision: number;
  replayed: boolean;
  tenantId: string;
  userId: string;
}

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function isCanonicalUuidV7(value: unknown): value is string {
  return typeof value === "string" && uuidV7Pattern.test(value);
}

export function notificationResourcePath(
  item: Readonly<{
    audience: unknown;
    resourceId: unknown;
    resourceKind: unknown;
  }>,
): string | undefined {
  if (!isCanonicalUuidV7(item.resourceId)) return undefined;
  if (item.audience === "customer") {
    if (item.resourceKind !== "alert" && item.resourceKind !== "case") {
      return undefined;
    }
    const parameters = new URLSearchParams({
      kind: item.resourceKind,
      ticket: item.resourceId,
    });
    return `/portal?${parameters.toString()}`;
  }
  if (item.audience !== "operator") return undefined;
  switch (item.resourceKind) {
    case "alert":
      return `/alerts/${item.resourceId}`;
    case "case":
      return `/cases/${item.resourceId}`;
    default:
      return undefined;
  }
}

export function notificationResourceLabel(
  kind: NotificationResourceKind,
): string {
  return notificationResourceLabels[kind];
}

const notificationResourceLabels = {
  alert: "Alert",
  case: "Case",
  contact: "Contact",
  evidence: "Evidence",
  task: "Task",
} as const satisfies Record<NotificationResourceKind, string>;

export function notificationEventLabel(
  eventType: NotificationEventType,
): string {
  return eventType
    .split(".")
    .map((part) => part.replaceAll("_", " "))
    .join(" · ");
}
