import { Button } from "@periapsis/ui/components/ui/button";
import { RefreshCw, ShieldAlert } from "lucide-react";
import { useEffect, useLayoutEffect, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type TenantMembershipView,
} from "../lib/phase-two-types";

type MembershipState =
  | { kind: "error"; message: string }
  | {
      items: readonly TenantMembershipView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

function useTenantSwitcher() {
  const { api, clearSession, membershipRevision, session, updateSession } =
    useSession();
  const [membershipState, setMembershipState] = useState<MembershipState>({
    kind: "loading",
  });
  const [switchError, setSwitchError] = useState<string | null>(null);
  const [isSwitching, setIsSwitching] = useState(false);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [paginationError, setPaginationError] = useState<string | null>(null);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const sessionIdRef = useRef(session.id);
  useLayoutEffect(() => {
    sessionIdRef.current = session.id;
  }, [session.id]);

  useEffect(() => {
    setIsLoadingMore(false);
    setPaginationError(null);
    setIsSwitching(false);
    setSwitchError(null);
  }, [session.id]);

  useEffect(() => {
    let cancelled = false;
    setMembershipState({ kind: "loading" });

    void api
      .listMemberships()
      .then((page) => {
        if (!cancelled) {
          setMembershipState({ kind: "ready", ...page });
        }
      })
      .catch((caught: unknown) => {
        if (cancelled) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        setMembershipState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "Tenant memberships could not be loaded.",
          ),
        });
      });

    return () => {
      cancelled = true;
    };
  }, [api, clearSession, loadAttempt, membershipRevision, session.id]);

  async function loadMore(): Promise<void> {
    if (
      membershipState.kind !== "ready" ||
      !membershipState.nextCursor ||
      isLoadingMore
    ) {
      return;
    }
    const requestedCursor = membershipState.nextCursor;
    const requestedSessionId = session.id;
    setIsLoadingMore(true);
    setPaginationError(null);
    try {
      const page = await api.listMemberships(requestedCursor);
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (page.nextCursor === requestedCursor) {
        throw new Error("The membership cursor did not advance.");
      }
      setMembershipState((current) =>
        current.kind === "ready" && current.nextCursor === requestedCursor
          ? {
              items: appendUniqueMemberships(current.items, page.items),
              kind: "ready",
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (sessionIdRef.current !== requestedSessionId) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(requestedSessionId);
        return;
      }
      setPaginationError(
        describePhaseTwoError(
          caught,
          "More tenant memberships could not be loaded.",
        ),
      );
    } finally {
      if (sessionIdRef.current === requestedSessionId) {
        // eslint-disable-next-line react-doctor/no-loading-flag-reset-outside-finally -- This reset is inside finally and only the originating session may clear its pending flag.
        setIsLoadingMore(false);
      }
    }
  }

  async function selectTenant(tenantId: string): Promise<void> {
    if (membershipState.kind !== "ready") {
      return;
    }
    if (!membershipState.items.some((item) => item.tenantId === tenantId)) {
      setSwitchError(
        "That tenant is not present in the server-returned membership list.",
      );
      return;
    }

    setSwitchError(null);
    setIsSwitching(true);
    const expectedSessionId = session.id;
    try {
      const updated = await api.switchTenant(session.csrfToken, tenantId);
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      updateSession(expectedSessionId, updated);
    } catch (caught) {
      if (sessionIdRef.current !== expectedSessionId) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(expectedSessionId);
        return;
      }
      setSwitchError(
        describePhaseTwoError(
          caught,
          "The tenant context could not be changed. Your current context is unchanged.",
        ),
      );
    } finally {
      if (sessionIdRef.current === expectedSessionId) {
        setIsSwitching(false);
      }
    }
  }

  return {
    membershipState,
    switchError,
    isSwitching,
    isLoadingMore,
    paginationError,
    setLoadAttempt,
    session,
    selectTenant,
    loadMore,
  };
}

export function TenantSwitcher(): React.JSX.Element {
  const {
    membershipState,
    switchError,
    isSwitching,
    isLoadingMore,
    paginationError,
    setLoadAttempt,
    session,
    selectTenant,
    loadMore,
  } = useTenantSwitcher();
  if (membershipState.kind === "loading") {
    return (
      <div
        className="tenant-switcher tenant-switcher--loading"
        aria-busy="true"
      >
        <span>Tenant context</span>
        <strong>Loading assigned access…</strong>
      </div>
    );
  }

  if (membershipState.kind === "error") {
    return (
      <div className="tenant-switcher tenant-switcher--error" role="alert">
        <span>Tenant context</span>
        <strong>
          <ShieldAlert aria-hidden="true" /> Memberships unavailable
        </strong>
        <small>{membershipState.message}</small>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => setLoadAttempt((attempt) => attempt + 1)}
        >
          <RefreshCw aria-hidden="true" /> Retry
        </Button>
      </div>
    );
  }

  if (
    membershipState.items.length === 0 &&
    membershipState.nextCursor === undefined
  ) {
    return (
      <div className="tenant-switcher">
        <span>Tenant context</span>
        <strong>No assigned tenant</strong>
        <small>
          Platform permissions do not create tenant membership automatically.
        </small>
      </div>
    );
  }

  return (
    <MembershipSelector
      controller={{
        membershipState,
        switchError,
        isSwitching,
        isLoadingMore,
        paginationError,
        setLoadAttempt,
        session,
        selectTenant,
        loadMore,
      }}
      membershipState={membershipState}
    />
  );
}

function MembershipSelector({
  controller,
  membershipState,
}: {
  controller: ReturnType<typeof useTenantSwitcher>;
  membershipState: Extract<MembershipState, { kind: "ready" }>;
}): React.JSX.Element {
  const {
    session,
    isSwitching,
    selectTenant,
    switchError,
    isLoadingMore,
    loadMore,
    paginationError,
  } = controller;
  const activeMembership = membershipState.items.find(
    (item) => item.tenantId === session.activeTenantId,
  );

  return (
    <div className="tenant-switcher">
      <label htmlFor="active-tenant">Tenant context</label>
      <select
        id="active-tenant"
        value={activeMembership?.tenantId ?? ""}
        disabled={isSwitching}
        onChange={(event) => void selectTenant(event.currentTarget.value)}
        aria-describedby={switchError ? "tenant-switch-error" : undefined}
        aria-invalid={switchError ? true : undefined}
      >
        <option value="" disabled>
          Choose an assigned tenant
        </option>
        {membershipState.items.map((membership) => (
          <option key={membership.tenantId} value={membership.tenantId}>
            {membership.tenantName}
          </option>
        ))}
      </select>
      <small>
        {isSwitching
          ? "Verifying membership…"
          : activeMembership
            ? `${activeMembership.tenantSlug} · ${formatRole(activeMembership.role)}`
            : session.activeTenantId
              ? "Active tenant selected; load more to view details"
              : "No active tenant selected"}
      </small>
      {membershipState.nextCursor ? (
        <Button
          type="button"
          variant="ghost"
          size="sm"
          disabled={isLoadingMore}
          onClick={() => void loadMore()}
        >
          {isLoadingMore ? "Loading more tenants…" : "Load more tenants"}
        </Button>
      ) : null}
      {paginationError ? (
        <small className="tenant-switcher__error" role="alert">
          {paginationError}
        </small>
      ) : null}
      {switchError ? (
        <small
          id="tenant-switch-error"
          className="tenant-switcher__error"
          role="alert"
        >
          {switchError}
        </small>
      ) : null}
    </div>
  );
}

function formatRole(value: string): string {
  return value.replaceAll("_", " ");
}

function appendUniqueMemberships(
  current: readonly TenantMembershipView[],
  incoming: readonly TenantMembershipView[],
): readonly TenantMembershipView[] {
  const seen = new Set(current.map((membership) => membership.membershipId));
  return [
    ...current,
    ...incoming.filter((membership) => {
      if (seen.has(membership.membershipId)) {
        return false;
      }
      seen.add(membership.membershipId);
      return true;
    }),
  ];
}
