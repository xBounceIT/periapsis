import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

import {
  describePhaseTwoError,
  hasTenantPermission,
  PhaseTwoApiError,
  type TenantAuthorityView,
  type TenantAuthorizationScopeView,
  type TenantPermissionKeyView,
} from "../lib/phase-two-types";
import {
  idempotencyKeyForPayload,
  isPayloadBoundToIdempotencyKey,
} from "../lib/payload-idempotency";
import { useSession } from "./session-context";

export type TenantAuthorityStatus =
  "error" | "forbidden" | "inactive" | "loading" | "ready";

interface TenantAuthorityContextValue {
  authority?: TenantAuthorityView;
  bindIdempotentPayload: (
    pairKey: string,
    namespace: TenantIdempotencyNamespace,
    identityKey: string,
    request: object,
    payload: unknown,
  ) => string | undefined;
  clearIdempotentPayloadBindings: (
    pairKey: string,
    namespace: TenantIdempotencyNamespace,
    identityKey?: string,
  ) => void;
  detachMutation: (pairKey: string, request: object) => void;
  explicitRevision: number;
  hasPermission: (
    permission: TenantPermissionKeyView,
    scope?: TenantAuthorizationScopeView,
  ) => boolean;
  hasPendingMutation: (pairKey: string) => boolean;
  isIdempotentPayloadBound: (
    pairKey: string,
    namespace: TenantIdempotencyNamespace,
    identityKey: string,
    payload: unknown,
  ) => boolean;
  message?: string;
  pairKey: string;
  registerMutation: (pairKey: string, request: object) => boolean;
  reload: () => void;
  requestMutationReload: (pairKey: string, request: object) => void;
  releaseIdempotentPayload: (
    pairKey: string,
    namespace: TenantIdempotencyNamespace,
    identityKey: string,
    request: object,
    expectedKey: string,
    payload: unknown,
  ) => void;
  revision: number;
  settleMutation: (pairKey: string, request: object) => void;
  status: TenantAuthorityStatus;
}

type TenantIdempotencyNamespace =
  "operator-team-roster-add" | "operator-team-start";

interface AuthoritySnapshot {
  authority?: TenantAuthorityView;
  message?: string;
  pairKey: string;
  status: TenantAuthorityStatus;
}

interface MutationRegistration {
  owner: object;
  pairKey: string;
  sessionId: string;
}

interface IdempotencyBindingReference {
  current: { fingerprint: string; key: string } | null;
}

interface IdempotencyBindingBucket {
  bindings: IdempotencyBindingReference[];
  identityKey: string;
  namespace: TenantIdempotencyNamespace;
  pairKey: string;
}

interface IdempotencyBindingOwnership {
  bucketKey: string;
  key: string;
  owner: object;
}

interface ReloadAttempt {
  id: number;
  pairKey: string;
}

const TenantAuthorityContext =
  createContext<TenantAuthorityContextValue | null>(null);

export function TenantAuthorityProvider({
  children,
}: {
  children: ReactNode;
}): React.JSX.Element {
  const { api, clearSession, session } = useSession();
  const tenantId = session.activeTenantId;
  const pairKey = authorityPairKey(session.id, tenantId);
  const currentPairRef = useRef(pairKey);
  currentPairRef.current = pairKey;
  const currentTenantRef = useRef(tenantId);
  currentTenantRef.current = tenantId;
  const currentSessionIdRef = useRef(session.id);
  currentSessionIdRef.current = session.id;
  const requestGenerationRef = useRef(0);
  const [reloadRevision, setReloadRevision] = useState(0);
  const reloadSequenceRef = useRef(0);
  const reloadAttemptRef = useRef<ReloadAttempt | null>(null);
  const [explicitRevision, setExplicitRevision] = useState(0);
  const [mutationRevision, setMutationRevision] = useState(0);
  const mutationRegistrationsRef = useRef(
    new WeakMap<object, MutationRegistration>(),
  );
  const activeMutationsRef = useRef(new Map<string, object>());
  const dirtyPairVersionsRef = useRef(new Map<string, number>());
  const idempotencyBindingBucketsRef = useRef(
    new Map<string, IdempotencyBindingBucket>(),
  );
  const idempotencyBindingOwnershipRef = useRef(
    new WeakMap<IdempotencyBindingReference, IdempotencyBindingOwnership>(),
  );
  const coordinatorSessionRef = useRef(session.id);
  const idempotencyPairRef = useRef(pairKey);
  const providerMountedRef = useRef(false);
  const [snapshot, setSnapshot] = useState<AuthoritySnapshot>(() =>
    tenantId ? { pairKey, status: "loading" } : { pairKey, status: "inactive" },
  );
  const currentStatus: TenantAuthorityStatus =
    snapshot.pairKey === pairKey
      ? snapshot.status
      : tenantId
        ? "loading"
        : "inactive";
  const currentStatusRef = useRef(currentStatus);
  currentStatusRef.current = currentStatus;

  if (coordinatorSessionRef.current !== session.id) {
    coordinatorSessionRef.current = session.id;
    mutationRegistrationsRef.current = new WeakMap();
    activeMutationsRef.current.clear();
    dirtyPairVersionsRef.current.clear();
    idempotencyBindingBucketsRef.current.clear();
    idempotencyBindingOwnershipRef.current = new WeakMap();
    idempotencyPairRef.current = pairKey;
    reloadAttemptRef.current = null;
  } else if (idempotencyPairRef.current !== pairKey) {
    idempotencyPairRef.current = pairKey;
    idempotencyBindingBucketsRef.current.clear();
    idempotencyBindingOwnershipRef.current = new WeakMap();
  }
  if (reloadAttemptRef.current?.pairKey !== pairKey) {
    reloadAttemptRef.current = null;
  }

  const triggerReload = useCallback(
    (expectedPair: string, coordinated: boolean): boolean => {
      if (
        !providerMountedRef.current ||
        currentPairRef.current !== expectedPair ||
        reloadAttemptRef.current !== null
      ) {
        return false;
      }
      const id = reloadSequenceRef.current + 1;
      reloadSequenceRef.current = id;
      reloadAttemptRef.current = { id, pairKey: expectedPair };
      if (!coordinated) {
        idempotencyBindingBucketsRef.current.clear();
        idempotencyBindingOwnershipRef.current = new WeakMap();
      }
      requestGenerationRef.current += 1;
      currentStatusRef.current = currentTenantRef.current
        ? "loading"
        : "inactive";
      setSnapshot(
        currentTenantRef.current
          ? { pairKey: expectedPair, status: "loading" }
          : { pairKey: expectedPair, status: "inactive" },
      );
      if (!coordinated) {
        setExplicitRevision((revision) => revision + 1);
      }
      setReloadRevision(id);
      return true;
    },
    [],
  );

  const flushMutationReload = useCallback(
    (expectedPair: string): void => {
      if (
        !providerMountedRef.current ||
        currentPairRef.current !== expectedPair ||
        currentStatusRef.current !== "ready" ||
        !dirtyPairVersionsRef.current.has(expectedPair) ||
        activeMutationsRef.current.has(expectedPair) ||
        reloadAttemptRef.current !== null
      ) {
        return;
      }
      triggerReload(expectedPair, true);
    },
    [triggerReload],
  );

  const mutationRegistration = useCallback(
    (expectedPair: string, request: object): MutationRegistration | null => {
      const registration = mutationRegistrationsRef.current.get(request);
      return registration?.pairKey === expectedPair &&
        registration.sessionId === currentSessionIdRef.current
        ? registration
        : null;
    },
    [],
  );

  const registerMutation = useCallback(
    (expectedPair: string, request: object): boolean => {
      if (
        !providerMountedRef.current ||
        currentPairRef.current !== expectedPair ||
        currentStatusRef.current !== "ready" ||
        reloadAttemptRef.current !== null ||
        activeMutationsRef.current.has(expectedPair)
      ) {
        return false;
      }
      mutationRegistrationsRef.current.set(request, {
        owner: {},
        pairKey: expectedPair,
        sessionId: currentSessionIdRef.current,
      });
      activeMutationsRef.current.set(expectedPair, request);
      setMutationRevision((revision) => revision + 1);
      return true;
    },
    [],
  );

  const bindIdempotentPayload = useCallback(
    (
      expectedPair: string,
      namespace: TenantIdempotencyNamespace,
      identityKey: string,
      request: object,
      payload: unknown,
    ): string | undefined => {
      const currentRegistration = mutationRegistration(expectedPair, request);
      if (
        !providerMountedRef.current ||
        currentPairRef.current !== expectedPair ||
        activeMutationsRef.current.get(expectedPair) !== request ||
        !currentRegistration
      ) {
        return undefined;
      }
      const bucketKey = idempotencyBucketKey(
        expectedPair,
        namespace,
        identityKey,
      );
      let bucket = idempotencyBindingBucketsRef.current.get(bucketKey);
      if (!bucket) {
        bucket = {
          bindings: [],
          identityKey,
          namespace,
          pairKey: expectedPair,
        };
        idempotencyBindingBucketsRef.current.set(bucketKey, bucket);
      }
      let binding = bucket.bindings.find((candidate) =>
        isPayloadBoundToIdempotencyKey(candidate, payload),
      );
      if (!binding) {
        binding = { current: null };
        bucket.bindings.push(binding);
      }
      const key = idempotencyKeyForPayload(binding, payload);
      idempotencyBindingOwnershipRef.current.set(binding, {
        bucketKey,
        key,
        owner: currentRegistration.owner,
      });
      return key;
    },
    [mutationRegistration],
  );

  const isIdempotentPayloadBound = useCallback(
    (
      expectedPair: string,
      namespace: TenantIdempotencyNamespace,
      identityKey: string,
      payload: unknown,
    ): boolean => {
      if (currentPairRef.current !== expectedPair) return false;
      const bucket = idempotencyBindingBucketsRef.current.get(
        idempotencyBucketKey(expectedPair, namespace, identityKey),
      );
      return (
        bucket?.bindings.some((binding) =>
          isPayloadBoundToIdempotencyKey(binding, payload),
        ) ?? false
      );
    },
    [],
  );

  const releaseIdempotentPayload = useCallback(
    (
      expectedPair: string,
      namespace: TenantIdempotencyNamespace,
      identityKey: string,
      request: object,
      expectedKey: string,
      payload: unknown,
    ): void => {
      const currentRegistration = mutationRegistration(expectedPair, request);
      if (!currentRegistration) return;
      const bucketKey = idempotencyBucketKey(
        expectedPair,
        namespace,
        identityKey,
      );
      const bucket = idempotencyBindingBucketsRef.current.get(bucketKey);
      const binding = bucket?.bindings.find(
        (candidate) =>
          candidate.current?.key === expectedKey &&
          isPayloadBoundToIdempotencyKey(candidate, payload),
      );
      const ownership = binding
        ? idempotencyBindingOwnershipRef.current.get(binding)
        : undefined;
      if (
        !bucket ||
        !binding ||
        ownership?.bucketKey !== bucketKey ||
        ownership.key !== expectedKey ||
        ownership.owner !== currentRegistration.owner
      ) {
        return;
      }
      bucket.bindings = bucket.bindings.filter(
        (candidate) => candidate !== binding,
      );
      binding.current = null;
      idempotencyBindingOwnershipRef.current.delete(binding);
      if (bucket.bindings.length === 0) {
        idempotencyBindingBucketsRef.current.delete(bucketKey);
      }
    },
    [mutationRegistration],
  );

  const clearIdempotentPayloadBindings = useCallback(
    (
      expectedPair: string,
      namespace: TenantIdempotencyNamespace,
      identityKey?: string,
    ): void => {
      if (currentPairRef.current !== expectedPair) return;
      for (const [bucketKey, bucket] of idempotencyBindingBucketsRef.current) {
        if (
          bucket.pairKey !== expectedPair ||
          bucket.namespace !== namespace ||
          (identityKey !== undefined && bucket.identityKey !== identityKey)
        ) {
          continue;
        }
        for (const binding of bucket.bindings) {
          binding.current = null;
          idempotencyBindingOwnershipRef.current.delete(binding);
        }
        idempotencyBindingBucketsRef.current.delete(bucketKey);
      }
    },
    [],
  );

  const detachMutation = useCallback(
    (expectedPair: string, request: object): void => {
      if (!mutationRegistration(expectedPair, request)) return;
      if (activeMutationsRef.current.get(expectedPair) !== request) return;
      activeMutationsRef.current.delete(expectedPair);
      if (providerMountedRef.current) {
        setMutationRevision((revision) => revision + 1);
      }
      flushMutationReload(expectedPair);
    },
    [flushMutationReload, mutationRegistration],
  );

  const settleMutation = useCallback(
    (expectedPair: string, request: object): void => {
      if (!mutationRegistration(expectedPair, request)) return;
      mutationRegistrationsRef.current.delete(request);
      if (activeMutationsRef.current.get(expectedPair) === request) {
        activeMutationsRef.current.delete(expectedPair);
        if (providerMountedRef.current) {
          setMutationRevision((revision) => revision + 1);
        }
      }
      flushMutationReload(expectedPair);
    },
    [flushMutationReload, mutationRegistration],
  );

  const requestMutationReload = useCallback(
    (expectedPair: string, request: object): void => {
      if (
        !providerMountedRef.current ||
        !mutationRegistration(expectedPair, request)
      ) {
        return;
      }
      dirtyPairVersionsRef.current.set(
        expectedPair,
        (dirtyPairVersionsRef.current.get(expectedPair) ?? 0) + 1,
      );
      flushMutationReload(expectedPair);
    },
    [flushMutationReload, mutationRegistration],
  );

  const hasPendingMutation = useCallback(
    (expectedPair: string): boolean =>
      activeMutationsRef.current.has(expectedPair),
    [],
  );

  useEffect(() => {
    providerMountedRef.current = true;
    return () => {
      providerMountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    const requestGeneration = requestGenerationRef.current + 1;
    requestGenerationRef.current = requestGeneration;
    if (!tenantId) {
      setSnapshot({ pairKey, status: "inactive" });
      return undefined;
    }

    const controller = new AbortController();
    const attempt = reloadAttemptRef.current;
    const attemptId = attempt?.id;
    const ownsAttempt =
      attemptId === reloadRevision && attempt?.pairKey === pairKey;
    const dirtyVersionAtStart = dirtyPairVersionsRef.current.get(pairKey);
    setSnapshot({ pairKey, status: "loading" });

    void api
      .getTenantAuthority(tenantId, controller.signal)
      .then((authority) => {
        if (
          controller.signal.aborted ||
          currentPairRef.current !== pairKey ||
          requestGenerationRef.current !== requestGeneration
        ) {
          return;
        }
        if (
          authority.tenantId !== tenantId ||
          authority.userId !== session.user.id
        ) {
          setSnapshot({
            message:
              "The authority projection did not match the active tenant and identity.",
            pairKey,
            status: "error",
          });
          return;
        }
        if (
          dirtyVersionAtStart !== undefined &&
          dirtyPairVersionsRef.current.get(pairKey) === dirtyVersionAtStart
        ) {
          dirtyPairVersionsRef.current.delete(pairKey);
        }
        currentStatusRef.current = "ready";
        setSnapshot({ authority, pairKey, status: "ready" });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          currentPairRef.current !== pairKey ||
          requestGenerationRef.current !== requestGeneration ||
          isAbortError(caught)
        ) {
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 401) {
          clearSession(session.id);
          return;
        }
        if (caught instanceof PhaseTwoApiError && caught.status === 403) {
          currentStatusRef.current = "forbidden";
          setSnapshot({
            message: describePhaseTwoError(
              caught,
              "The server did not return authority for this tenant.",
            ),
            pairKey,
            status: "forbidden",
          });
          return;
        }
        currentStatusRef.current = "error";
        setSnapshot({
          message: describePhaseTwoError(
            caught,
            "Live tenant authority could not be loaded. Tenant administration remains unavailable until it is revalidated.",
          ),
          pairKey,
          status: "error",
        });
      })
      .finally(() => {
        if (
          ownsAttempt &&
          attemptId !== undefined &&
          reloadAttemptRef.current?.id === attemptId
        ) {
          reloadAttemptRef.current = null;
        }
        flushMutationReload(pairKey);
      });

    return () => {
      controller.abort();
      if (
        ownsAttempt &&
        attemptId !== undefined &&
        reloadAttemptRef.current?.id === attemptId
      ) {
        reloadAttemptRef.current = null;
      }
    };
  }, [
    api,
    clearSession,
    flushMutationReload,
    pairKey,
    reloadRevision,
    session.id,
    session.user.id,
    tenantId,
  ]);

  const reload = useCallback(() => {
    triggerReload(pairKey, false);
  }, [pairKey, triggerReload]);

  const currentSnapshot: AuthoritySnapshot =
    snapshot.pairKey === pairKey
      ? snapshot
      : tenantId
        ? { pairKey, status: "loading" }
        : { pairKey, status: "inactive" };

  useEffect(() => {
    if (currentSnapshot.status === "ready") flushMutationReload(pairKey);
  }, [currentSnapshot.status, flushMutationReload, pairKey]);

  const value = useMemo<TenantAuthorityContextValue>(
    () => ({
      ...(currentSnapshot.authority
        ? { authority: currentSnapshot.authority }
        : {}),
      bindIdempotentPayload,
      clearIdempotentPayloadBindings,
      detachMutation,
      explicitRevision,
      hasPermission(permission, scope = "tenant") {
        return currentSnapshot.authority
          ? hasTenantPermission(currentSnapshot.authority, permission, scope)
          : false;
      },
      hasPendingMutation,
      isIdempotentPayloadBound,
      ...(currentSnapshot.message ? { message: currentSnapshot.message } : {}),
      pairKey,
      registerMutation,
      reload,
      requestMutationReload,
      releaseIdempotentPayload,
      revision: reloadRevision,
      settleMutation,
      status: currentSnapshot.status,
    }),
    [
      currentSnapshot,
      bindIdempotentPayload,
      clearIdempotentPayloadBindings,
      detachMutation,
      explicitRevision,
      hasPendingMutation,
      isIdempotentPayloadBound,
      mutationRevision,
      pairKey,
      registerMutation,
      reload,
      reloadRevision,
      requestMutationReload,
      releaseIdempotentPayload,
      settleMutation,
    ],
  );

  return (
    <TenantAuthorityContext.Provider value={value}>
      {children}
    </TenantAuthorityContext.Provider>
  );
}

function idempotencyBucketKey(
  pairKey: string,
  namespace: TenantIdempotencyNamespace,
  identityKey: string,
): string {
  return JSON.stringify([pairKey, namespace, identityKey]);
}

export function useTenantAuthority(): TenantAuthorityContextValue {
  const value = useContext(TenantAuthorityContext);
  if (!value) {
    throw new Error(
      "TenantAuthorityContext is unavailable outside the authenticated shell",
    );
  }
  return value;
}

function authorityPairKey(
  sessionId: string,
  tenantId: string | undefined,
): string {
  return JSON.stringify([sessionId, tenantId ?? null]);
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}
