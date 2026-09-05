import { createContext, useContext, useMemo, type ReactNode } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import type { NotificationInboxApi } from "./inbox-api";
import {
  isCanonicalUuidV7,
  type NotificationInboxCoordinate,
} from "./inbox-model";

export type NotificationInboxAccessStatus =
  "error" | "forbidden" | "inactive" | "loading" | "ready";

export interface NotificationInboxBoundary extends NotificationInboxCoordinate {
  csrfToken: string;
  identityKey: string;
  key: string;
  sessionId: string;
}

interface NotificationInboxContextValue {
  api: NotificationInboxApi;
  boundary?: NotificationInboxBoundary;
  clearCurrentSession: () => void;
  message?: string;
  reloadAuthority: () => void;
  status: NotificationInboxAccessStatus;
}

const NotificationInboxContext =
  createContext<NotificationInboxContextValue | null>(null);

export function NotificationInboxProvider({
  api,
  children,
}: {
  api: NotificationInboxApi;
  children: ReactNode;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;

  const snapshot = useMemo<
    Pick<NotificationInboxContextValue, "boundary" | "message" | "status">
  >(() => {
    if (!tenantId) {
      return { status: "inactive" };
    }
    if (authority.status === "loading") return { status: "loading" };
    if (authority.status !== "ready" || !authority.authority) {
      return {
        message:
          authority.message ??
          "Live tenant authority is unavailable. No inbox request was sent.",
        status: authority.status === "forbidden" ? "forbidden" : "error",
      };
    }

    if (
      !isCanonicalUuidV7(tenantId) ||
      !isCanonicalUuidV7(session.id) ||
      !isCanonicalUuidV7(session.user.id) ||
      authority.authority.tenantId !== tenantId ||
      authority.authority.userId !== session.user.id
    ) {
      return {
        message:
          "The live authority projection did not match this personal inbox coordinate.",
        status: "error",
      };
    }

    const identityKey = JSON.stringify([session.id, tenantId, session.user.id]);
    const boundaryKey = JSON.stringify([
      identityKey,
      authority.pairKey,
      authority.revision,
      authority.explicitRevision,
    ]);
    return {
      boundary: {
        csrfToken: session.csrfToken,
        identityKey,
        key: boundaryKey,
        sessionId: session.id,
        tenantId,
        userId: session.user.id,
      },
      status: "ready",
    };
  }, [
    authority.authority,
    authority.explicitRevision,
    authority.message,
    authority.pairKey,
    authority.revision,
    authority.status,
    session.csrfToken,
    session.id,
    session.user.id,
    tenantId,
  ]);

  const value = useMemo<NotificationInboxContextValue>(
    () => ({
      api,
      ...snapshot,
      clearCurrentSession: () => clearSession(session.id),
      reloadAuthority: authority.reload,
    }),
    [api, authority.reload, clearSession, session.id, snapshot],
  );

  return (
    <NotificationInboxContext.Provider value={value}>
      {children}
    </NotificationInboxContext.Provider>
  );
}

export function useNotificationInbox(): NotificationInboxContextValue {
  const value = useContext(NotificationInboxContext);
  if (!value) {
    throw new Error(
      "NotificationInboxContext is unavailable outside NotificationInboxProvider",
    );
  }
  return value;
}
