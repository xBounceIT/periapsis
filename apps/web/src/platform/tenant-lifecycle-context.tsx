import {
  TenantLifecycleClientError,
  tenantLifecycleExpectedVersion,
} from "./tenant-lifecycle-model";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { useSession } from "../auth/session-context";
import {
  etagForVersion,
  PhaseTwoApiError,
  type TenantLifecycleAction,
  type TenantLifecycleReceiptView,
  type TenantView,
} from "../lib/phase-two-types";

interface TenantLifecycleContextValue {
  isPending(tenantId: string): boolean;
  transition(
    tenant: TenantView,
    action: TenantLifecycleAction,
    reason: string,
  ): Promise<TenantLifecycleReceiptView | undefined>;
}

const TenantLifecycleContext =
  createContext<TenantLifecycleContextValue | null>(null);

export function TenantLifecycleProvider({
  children,
}: {
  children: React.ReactNode;
}): React.JSX.Element {
  const { api, clearSession, session } = useSession();
  const [pendingTenantIds, setPendingTenantIds] = useState<ReadonlySet<string>>(
    () => new Set(),
  );
  const pendingRef = useRef(new Set<string>());
  const sessionIdRef = useRef(session.id);
  useLayoutEffect(() => {
    sessionIdRef.current = session.id;
  }, [session.id]);

  useEffect(() => {
    pendingRef.current.clear();
    setPendingTenantIds(new Set());
  }, [session.id]);

  const transition = useCallback(
    async (
      tenant: TenantView,
      action: TenantLifecycleAction,
      reason: string,
    ): Promise<TenantLifecycleReceiptView | undefined> => {
      const expectedVersion = tenantLifecycleExpectedVersion(
        tenant,
        action,
        reason,
      );
      if (pendingRef.current.has(tenant.id)) {
        throw new TenantLifecycleClientError(
          "A lifecycle change is already pending for this tenant.",
        );
      }
      const expectedSessionId = session.id;
      pendingRef.current.add(tenant.id);
      setPendingTenantIds(new Set(pendingRef.current));
      try {
        const result = await (action === "suspend"
          ? api.suspendTenant(
              session.csrfToken,
              tenant.id,
              etagForVersion(expectedVersion),
              { expectedVersion, reason },
            )
          : api.reactivateTenant(
              session.csrfToken,
              tenant.id,
              etagForVersion(expectedVersion),
              { expectedVersion, reason },
            ));
        if (sessionIdRef.current !== expectedSessionId) {
          return undefined;
        }
        return result.value;
      } catch (caught) {
        if (sessionIdRef.current !== expectedSessionId) {
          return undefined;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(expectedSessionId);
          return undefined;
        }
        throw caught;
      } finally {
        if (sessionIdRef.current === expectedSessionId) {
          pendingRef.current.delete(tenant.id);
          setPendingTenantIds(new Set(pendingRef.current));
        }
      }
    },
    [api, clearSession, session.csrfToken, session.id],
  );

  const isPending = useCallback(
    (tenantId: string): boolean => pendingTenantIds.has(tenantId),
    [pendingTenantIds],
  );

  const value = useMemo(
    () => ({ isPending, transition }),
    [isPending, transition],
  );

  return (
    <TenantLifecycleContext.Provider value={value}>
      {children}
    </TenantLifecycleContext.Provider>
  );
}

export function useTenantLifecycle(): TenantLifecycleContextValue {
  const value = useContext(TenantLifecycleContext);
  if (!value) {
    throw new TenantLifecycleClientError(
      "Tenant lifecycle controls require TenantLifecycleProvider.",
    );
  }
  return value;
}
