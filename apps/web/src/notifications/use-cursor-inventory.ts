import { useCallback, useEffect, useRef, useState } from "react";

import type { CursorPage } from "./notification-api";

interface InventoryState<T> {
  error: unknown;
  items: T[];
  kind: "error" | "loading" | "ready";
  nextCursor?: string;
}

export interface CursorInventory<T> extends InventoryState<T> {
  loadMore: () => Promise<void>;
  loadingMore: boolean;
  refresh: () => void;
  upsert: (item: T, identity: (value: T) => string) => void;
}

export function useCursorInventory<T>(
  load: (
    after: string | undefined,
    signal: AbortSignal,
  ) => Promise<CursorPage<T>>,
): CursorInventory<T> {
  const [revision, setRevision] = useState(0);
  const [state, setState] = useState<InventoryState<T>>({
    error: null,
    items: [],
    kind: "loading",
  });
  const [loadingMore, setLoadingMore] = useState(false);
  const seenCursors = useRef(new Set<string>());
  const paginationController = useRef<AbortController | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    paginationController.current?.abort();
    paginationController.current = null;
    setLoadingMore(false);
    seenCursors.current = new Set();
    setState({ error: null, items: [], kind: "loading" });
    void load(undefined, controller.signal).then(
      (page) => {
        if (controller.signal.aborted) return;
        if (page.nextCursor) seenCursors.current.add(page.nextCursor);
        setState({
          error: null,
          items: page.items,
          kind: "ready",
          ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
        });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) {
          setState({ error, items: [], kind: "error" });
        }
      },
    );
    return () => {
      controller.abort();
      paginationController.current?.abort();
    };
  }, [load, revision]);

  const loadMore = useCallback(async (): Promise<void> => {
    const after = state.nextCursor;
    if (!after || loadingMore) return;
    setLoadingMore(true);
    const controller = new AbortController();
    paginationController.current = controller;
    setState((current) => ({ ...current, error: null }));
    try {
      const page = await load(after, controller.signal);
      if (controller.signal.aborted) return;
      const nextCursor =
        page.nextCursor && !seenCursors.current.has(page.nextCursor)
          ? page.nextCursor
          : undefined;
      if (nextCursor) seenCursors.current.add(nextCursor);
      setState((current) => ({
        error: null,
        items: [...current.items, ...page.items],
        kind: "ready",
        ...(nextCursor ? { nextCursor } : {}),
      }));
    } catch (error: unknown) {
      if (!controller.signal.aborted) {
        setState((current) => ({ ...current, error }));
      }
    } finally {
      if (
        !controller.signal.aborted &&
        paginationController.current === controller
      ) {
        paginationController.current = null;
        setLoadingMore(false);
      }
    }
  }, [load, loadingMore, state.nextCursor]);

  const refresh = useCallback(() => setRevision((value) => value + 1), []);
  const upsert = useCallback(
    (item: T, identity: (value: T) => string): void => {
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
    [],
  );

  return { ...state, loadMore, loadingMore, refresh, upsert };
}
