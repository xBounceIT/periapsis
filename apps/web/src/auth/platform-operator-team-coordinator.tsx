import {
  platformOperatorTeamMutationKey,
  platformOperatorTeamResourceKey,
} from "./platform-operator-team-keys";
import {
  createContext,
  type PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  idempotencyKeyForPayload,
  isPayloadBoundToIdempotencyKey,
} from "../lib/payload-idempotency";
import { useSession } from "./session-context";

export interface PlatformCreateBinding {
  current: { fingerprint: string; key: string } | null;
}

export interface PlatformCreateMutationRequest {
  binding: PlatformCreateBinding;
  generation: number;
  kind: "create";
  sessionId: string;
}

export interface PlatformDetailMutationRequest {
  generation: number;
  kind: "archive" | "save";
  sessionId: string;
  teamId: string;
}

export type PlatformOperatorTeamMutationRequest =
  PlatformCreateMutationRequest | PlatformDetailMutationRequest;

interface MutationRegistration {
  key: string;
  owner: object;
  sessionId: string;
}

interface CreateBindingOwnership {
  key: string;
  owner: object;
}

interface BoundCreatePayload {
  binding: PlatformCreateBinding;
  key: string;
}

interface PlatformOperatorTeamCoordinatorValue {
  acknowledgeInventory: (
    sessionId: string,
    versions: ReadonlyMap<string, number>,
  ) => void;
  acknowledgeTeam: (sessionId: string, teamId: string, version: number) => void;
  bindCreatePayload: (payload: unknown) => BoundCreatePayload;
  clearCreateBindings: (sessionId: string) => void;
  detachMutation: (request: PlatformOperatorTeamMutationRequest) => void;
  inventoryVersions: () => ReadonlyMap<string, number>;
  isMutationActive: (key: string) => boolean;
  markMutationCommitted: (request: PlatformOperatorTeamMutationRequest) => void;
  registerMutation: (request: PlatformOperatorTeamMutationRequest) => boolean;
  releaseCreateBinding: (request: PlatformCreateMutationRequest) => void;
  revision: number;
  sessionId: string;
  settleMutation: (request: PlatformOperatorTeamMutationRequest) => void;
  teamVersion: (teamId: string) => number | undefined;
}

const PlatformOperatorTeamCoordinatorContext =
  createContext<PlatformOperatorTeamCoordinatorValue | null>(null);

export function PlatformOperatorTeamCoordinatorProvider({
  children,
}: PropsWithChildren): React.JSX.Element {
  const { session } = useSession();
  const [revision, setRevision] = useState(0);
  const mountedRef = useRef(false);
  const sessionIdRef = useRef(session.id);
  const registrationsRef = useRef(
    new WeakMap<PlatformOperatorTeamMutationRequest, MutationRegistration>(),
  );
  const activeMutationsRef = useRef(
    new Map<string, PlatformOperatorTeamMutationRequest>(),
  );
  const dirtyInventoryVersionsRef = useRef(new Map<string, number>());
  const dirtyTeamVersionsRef = useRef(new Map<string, number>());
  const dirtySequenceRef = useRef(0);
  const createBindingsRef = useRef<PlatformCreateBinding[]>([]);
  const createBindingOwnershipRef = useRef(
    new WeakMap<PlatformCreateBinding, CreateBindingOwnership>(),
  );

  const reset = useCallback((sessionId: string): void => {
    sessionIdRef.current = sessionId;
    registrationsRef.current = new WeakMap();
    activeMutationsRef.current.clear();
    dirtyInventoryVersionsRef.current.clear();
    dirtyTeamVersionsRef.current.clear();
    dirtySequenceRef.current = 0;
    createBindingsRef.current = [];
    createBindingOwnershipRef.current = new WeakMap();
  }, []);

  if (sessionIdRef.current !== session.id) reset(session.id);

  const notify = useCallback((): void => {
    if (mountedRef.current) setRevision((value) => value + 1);
  }, []);

  const registration = useCallback(
    (
      request: PlatformOperatorTeamMutationRequest,
    ): MutationRegistration | null => {
      const current = registrationsRef.current.get(request);
      return current?.sessionId === sessionIdRef.current &&
        request.sessionId === sessionIdRef.current
        ? current
        : null;
    },
    [],
  );

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const registerMutation = useCallback(
    (request: PlatformOperatorTeamMutationRequest): boolean => {
      const key = platformOperatorTeamMutationKey(request);
      if (
        !mountedRef.current ||
        request.sessionId !== sessionIdRef.current ||
        activeMutationsRef.current.has(key)
      ) {
        return false;
      }
      const owner = {};
      registrationsRef.current.set(request, {
        key,
        owner,
        sessionId: request.sessionId,
      });
      activeMutationsRef.current.set(key, request);
      if (request.kind === "create") {
        createBindingOwnershipRef.current.set(request.binding, { key, owner });
      }
      notify();
      return true;
    },
    [notify],
  );

  const detachMutation = useCallback(
    (request: PlatformOperatorTeamMutationRequest): void => {
      const current = registration(request);
      if (!current) return;
      if (activeMutationsRef.current.get(current.key) === request) {
        activeMutationsRef.current.delete(current.key);
        notify();
      }
    },
    [notify, registration],
  );

  const settleMutation = useCallback(
    (request: PlatformOperatorTeamMutationRequest): void => {
      const current = registration(request);
      if (!current) return;
      registrationsRef.current.delete(request);
      if (activeMutationsRef.current.get(current.key) === request) {
        activeMutationsRef.current.delete(current.key);
        notify();
      }
    },
    [notify, registration],
  );

  const markMutationCommitted = useCallback(
    (request: PlatformOperatorTeamMutationRequest): void => {
      const current = registration(request);
      if (!mountedRef.current || !current) return;
      dirtySequenceRef.current += 1;
      const version = dirtySequenceRef.current;
      dirtyInventoryVersionsRef.current.set(current.key, version);
      if (request.kind !== "create") {
        dirtyTeamVersionsRef.current.set(request.teamId, version);
      }
      notify();
    },
    [notify, registration],
  );

  const inventoryVersions = useCallback((): ReadonlyMap<string, number> => {
    const eligible = new Map<string, number>();
    for (const [key, version] of dirtyInventoryVersionsRef.current) {
      if (!activeMutationsRef.current.has(key)) eligible.set(key, version);
    }
    return eligible;
  }, []);

  const teamVersion = useCallback((teamId: string): number | undefined => {
    return activeMutationsRef.current.has(
      platformOperatorTeamResourceKey(teamId),
    )
      ? undefined
      : dirtyTeamVersionsRef.current.get(teamId);
  }, []);

  const acknowledgeInventory = useCallback(
    (
      requestedSessionId: string,
      versions: ReadonlyMap<string, number>,
    ): void => {
      if (!mountedRef.current || requestedSessionId !== sessionIdRef.current) {
        return;
      }
      let changed = false;
      for (const [key, version] of versions) {
        if (
          !activeMutationsRef.current.has(key) &&
          dirtyInventoryVersionsRef.current.get(key) === version
        ) {
          dirtyInventoryVersionsRef.current.delete(key);
          changed = true;
        }
      }
      if (changed) notify();
    },
    [notify],
  );

  const acknowledgeTeam = useCallback(
    (requestedSessionId: string, teamId: string, version: number): void => {
      if (
        !mountedRef.current ||
        requestedSessionId !== sessionIdRef.current ||
        activeMutationsRef.current.has(
          platformOperatorTeamResourceKey(teamId),
        ) ||
        dirtyTeamVersionsRef.current.get(teamId) !== version
      ) {
        return;
      }
      dirtyTeamVersionsRef.current.delete(teamId);
      notify();
    },
    [notify],
  );

  const bindCreatePayload = useCallback(
    (payload: unknown): BoundCreatePayload => {
      let binding = createBindingsRef.current.find((candidate) =>
        isPayloadBoundToIdempotencyKey(candidate, payload),
      );
      if (!binding) {
        binding = { current: null };
        createBindingsRef.current.push(binding);
      }
      return {
        binding,
        key: idempotencyKeyForPayload(binding, payload),
      };
    },
    [],
  );

  const releaseCreateBinding = useCallback(
    (request: PlatformCreateMutationRequest): void => {
      const current = registration(request);
      const ownership = createBindingOwnershipRef.current.get(request.binding);
      if (
        !current ||
        ownership?.key !== current.key ||
        ownership.owner !== current.owner
      ) {
        return;
      }
      createBindingsRef.current = createBindingsRef.current.filter(
        (candidate) => candidate !== request.binding,
      );
      createBindingOwnershipRef.current.delete(request.binding);
    },
    [registration],
  );

  const clearCreateBindings = useCallback(
    (requestedSessionId: string): void => {
      if (requestedSessionId === sessionIdRef.current) {
        createBindingsRef.current = [];
        createBindingOwnershipRef.current = new WeakMap();
      }
    },
    [],
  );

  const isMutationActive = useCallback(
    (key: string): boolean => activeMutationsRef.current.has(key),
    [],
  );

  const value = useMemo<PlatformOperatorTeamCoordinatorValue>(
    () => ({
      acknowledgeInventory,
      acknowledgeTeam,
      bindCreatePayload,
      clearCreateBindings,
      detachMutation,
      inventoryVersions,
      isMutationActive,
      markMutationCommitted,
      registerMutation,
      releaseCreateBinding,
      revision,
      sessionId: session.id,
      settleMutation,
      teamVersion,
    }),
    [
      acknowledgeInventory,
      acknowledgeTeam,
      bindCreatePayload,
      clearCreateBindings,
      detachMutation,
      inventoryVersions,
      isMutationActive,
      markMutationCommitted,
      registerMutation,
      releaseCreateBinding,
      revision,
      session.id,
      settleMutation,
      teamVersion,
    ],
  );

  return (
    <PlatformOperatorTeamCoordinatorContext.Provider value={value}>
      {children}
    </PlatformOperatorTeamCoordinatorContext.Provider>
  );
}

export function usePlatformOperatorTeamCoordinator(): PlatformOperatorTeamCoordinatorValue {
  const value = useContext(PlatformOperatorTeamCoordinatorContext);
  if (!value) {
    throw new Error(
      "PlatformOperatorTeamCoordinator is unavailable outside the authenticated shell",
    );
  }
  return value;
}
