import {
  createContext,
  useCallback,
  useContext,
  useEffect,
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

const forbiddenReasonCodePoint = /[\p{Cc}\p{Cf}]/u;

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
  sessionIdRef.current = session.id;

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

  return (
    <TenantLifecycleContext.Provider value={{ isPending, transition }}>
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

export class TenantLifecycleClientError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantLifecycleClientError";
  }
}

function tenantLifecycleExpectedVersion(
  tenant: TenantView,
  action: TenantLifecycleAction,
  reason: string,
): number {
  const targetMatches =
    (action === "suspend" && tenant.status === "active") ||
    (action === "reactivate" && tenant.status === "suspended");
  const version = tenant.version;
  if (
    !targetMatches ||
    !isMutableTenantLifecycleVersion(version) ||
    validateTenantLifecycleReason(reason) !== null
  ) {
    throw new TenantLifecycleClientError(
      "The tenant lifecycle confirmation is incomplete or no longer current.",
    );
  }
  return version;
}

export function isMutableTenantLifecycleVersion(
  version: number | undefined,
): version is number {
  return (
    version !== undefined &&
    Number.isSafeInteger(version) &&
    version >= 1 &&
    version <= 2_147_483_646
  );
}

export function tenantLifecycleReasonBytes(reason: string): number {
  return new TextEncoder().encode(reason).byteLength;
}

export function validateTenantLifecycleReason(reason: string): string | null {
  if (reason.trim() === "") return "Enter an administrative reason.";
  if (reason.trim() !== reason)
    return "Remove leading or trailing whitespace from the reason.";
  if (forbiddenReasonCodePoint.test(reason))
    return "Remove control or formatting characters from the reason.";
  if (tenantLifecycleReasonBytes(reason) > 2 * 1024)
    return "Keep the reason within 2048 UTF-8 bytes.";
  return null;
}
