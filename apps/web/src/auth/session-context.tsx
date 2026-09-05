import { createContext, useContext } from "react";

import type { PhaseTwoApi, SessionView } from "../lib/phase-two-types";

interface SessionContextValue {
  api: PhaseTwoApi;
  clearSession: (expectedSessionId: string) => void;
  membershipRevision: number;
  refreshMemberships: () => void;
  session: SessionView;
  updateSession: (expectedSessionId: string, session: SessionView) => void;
}

export const SessionContext = createContext<SessionContextValue | null>(null);

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) {
    throw new Error(
      "SessionContext is unavailable outside the authenticated shell",
    );
  }
  return value;
}
