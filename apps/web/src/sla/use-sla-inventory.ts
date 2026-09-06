import { useCallback, useEffect, useRef, useState } from "react";

import type { SlaCursorPage } from "./model";

interface InventoryState<T> {
  error: unknown;
  items: T[];
  kind: "error" | "loading" | "ready";
  nextCursor?: string;
}

export interface SlaInventory<T> extends InventoryState<T> {
  loadMore: () => Promise<void>;
  loadingMore: boolean;
  refresh: () => void;
  upsert: (item: T) => void;
}

export function useSlaInventory<T>(
  load: (
    after: string | undefined,
    signal: AbortSignal,
  ) => Promise<SlaCursorPage<T>>,
  identity: (candidate: T) => string,
): SlaInventory<T> {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<InventoryState<T>>({
    error: null,
    items: [],
    kind: "loading",
  });
  const [loadingMore, setLoadingMore] = useState(false);
  const cursors = useRef(new Set<string>());
  const pagination = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    pagination.current?.abort();
    pagination.current = null;
    cursors.current = new Set();
    setLoadingMore(false);
    setState({ error: null, items: [], kind: "loading" });
    void load(undefined, controller.signal).then(
      (page) => {
        if (controller.signal.aborted) return;
        if (page.nextCursor) cursors.current.add(page.nextCursor);
        setState({
          error: null,
          items: page.items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      },
      (error: unknown) => {
        if (!controller.signal.aborted)
          setState({ error, items: [], kind: "error" });
      },
    );
    return () => {
      controller.abort();
      pagination.current?.abort();
    };
  }, [load, revision]);

  const loadMore = useCallback(async (): Promise<void> => {
    const after = state.nextCursor;
    if (!after || loadingMore) return;
    const controller = new AbortController();
    pagination.current?.abort();
    pagination.current = controller;
    setLoadingMore(true);
    setState((current) => ({ ...current, error: null }));
    try {
      const page = await load(after, controller.signal);
      if (controller.signal.aborted) return;
      if (page.nextCursor && cursors.current.has(page.nextCursor)) {
        throw new TypeError("The SLA catalog returned a cursor cycle.");
      }
      const currentIdentities = new Set(state.items.map(identity));
      if (page.items.some((item) => currentIdentities.has(identity(item)))) {
        throw new TypeError(
          "The SLA catalog returned a duplicate identity across pages.",
        );
      }
      const nextCursor = page.nextCursor;
      if (nextCursor) cursors.current.add(nextCursor);
      setState((current) => ({
        error: null,
        items: [...current.items, ...page.items],
        kind: "ready",
        ...(nextCursor ? { nextCursor } : {}),
      }));
    } catch (error: unknown) {
      if (!controller.signal.aborted)
        setState((current) => ({ ...current, error }));
    } finally {
      if (pagination.current === controller) {
        pagination.current = null;
        // react-doctor-disable-next-line react-doctor/no-loading-flag-reset-outside-finally -- This finally runs on success and failure; its request-ownership guard prevents an older request clearing a newer loading flag.
        setLoadingMore(false);
      }
    }
  }, [identity, load, loadingMore, state.items, state.nextCursor]);

  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const upsert = useCallback(
    (item: T): void => {
      setState((current) => {
        const id = identity(item);
        const index = current.items.findIndex(
          (candidate) => identity(candidate) === id,
        );
        return {
          ...current,
          items:
            index < 0
              ? [item, ...current.items]
              : current.items.map((candidate, candidateIndex) =>
                  candidateIndex === index ? item : candidate,
                ),
        };
      });
    },
    [identity],
  );

  return { ...state, loadMore, loadingMore, refresh, upsert };
}
