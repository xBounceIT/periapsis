import { useCallback, useEffect, useState } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { hasPermission, PhaseTwoApiError } from "../lib/phase-two-types";
import type { AuditReaderApi } from "./audit-api";
import type { AuditOperationsApi } from "./audit-operations-api";
import {
  PlatformAuditWorkspace,
  TenantAuditWorkspace,
} from "./audit-workspace";
import {
  platformAuditExportPermission,
  platformAuditPermission,
  platformAuditRetentionPermission,
  tenantAuditExportPermission,
  tenantAuditPermission,
  tenantAuditRetentionPermission,
} from "./model";

interface AuditPageProps {
  api?: AuditReaderApi;
  operationsApi?: AuditOperationsApi;
}

export function TenantAuditPage({
  api,
  operationsApi,
}: AuditPageProps = {}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId ?? "";
  const pairKey = authority.pairKey;
  const [deniedPairKey, setDeniedPairKey] = useState<string | null>(null);

  useEffect(() => setDeniedPairKey(null), [pairKey]);

  const handleUnauthorized = useCallback(
    () => clearSession(session.id),
    [clearSession, session.id],
  );
  const handleForbidden = useCallback(() => {
    setDeniedPairKey(pairKey);
    authority.reload();
  }, [authority, pairKey]);

  const loading = Boolean(tenantId) && authority.status === "loading";
  const canRead =
    authority.status === "ready" &&
    deniedPairKey !== pairKey &&
    authority.hasPermission(tenantAuditPermission, "tenant");

  return (
    <TenantAuditWorkspace
      {...(api ? { api } : {})}
      {...(operationsApi ? { operationsApi } : {})}
      authorizationStatus={loading ? "loading" : "ready"}
      canRead={canRead}
      canExport={
        canRead &&
        authority.hasPermission(tenantAuditExportPermission, "tenant")
      }
      canManageRetention={
        canRead &&
        authority.hasPermission(tenantAuditRetentionPermission, "tenant")
      }
      csrfToken={session.csrfToken}
      onForbidden={handleForbidden}
      onUnauthorized={handleUnauthorized}
      tenantId={tenantId}
    />
  );
}

export function PlatformAuditPage({
  api,
  operationsApi,
}: AuditPageProps = {}): React.JSX.Element {
  const {
    api: sessionApi,
    clearSession,
    session,
    updateSession,
  } = useSession();
  const [deniedSessionId, setDeniedSessionId] = useState<string | null>(null);

  useEffect(() => setDeniedSessionId(null), [session.id]);

  const handleUnauthorized = useCallback(
    () => clearSession(session.id),
    [clearSession, session.id],
  );
  const handleForbidden = useCallback(() => {
    const expectedSessionId = session.id;
    setDeniedSessionId(expectedSessionId);
    void sessionApi.getSession().then(
      (current) => {
        if (current) updateSession(expectedSessionId, current);
        else clearSession(expectedSessionId);
      },
      (error: unknown) => {
        if (error instanceof PhaseTwoApiError && error.status === 401) {
          clearSession(expectedSessionId);
          return;
        }
        // The bounded audit error remains visible. A failed revalidation must
        // not restore a server-denied capability from stale session claims.
      },
    );
  }, [clearSession, session.id, sessionApi, updateSession]);

  return (
    <PlatformAuditWorkspace
      {...(api ? { api } : {})}
      {...(operationsApi ? { operationsApi } : {})}
      canExport={
        deniedSessionId !== session.id &&
        hasPermission(session, platformAuditExportPermission)
      }
      canManageRetention={
        deniedSessionId !== session.id &&
        hasPermission(session, platformAuditRetentionPermission)
      }
      canRead={
        deniedSessionId !== session.id &&
        hasPermission(session, platformAuditPermission)
      }
      csrfToken={session.csrfToken}
      onForbidden={handleForbidden}
      onUnauthorized={handleUnauthorized}
    />
  );
}
