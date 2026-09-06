import type { SetStateAction } from "react";

/** Expose a server snapshot only while it belongs to the active authority pair. */
export function selectPairState<State>(
  snapshot: { pairKey: string; state: State },
  pairKey: string,
  fallback: State,
  active = true,
): State {
  return active && snapshot.pairKey === pairKey ? snapshot.state : fallback;
}

/** Keep selections from another session or tenant outside the rendered view. */
export function selectPairValue<Value extends { pairKey: string }>(
  value: Value | null,
  pairKey: string,
  active: boolean,
): Value | null {
  return active && value?.pairKey === pairKey ? value : null;
}

export type WorkspaceStatePatch<State> = {
  [Field in keyof State]?: SetStateAction<State[Field]>;
};

function isFieldUpdater<Value>(
  update: SetStateAction<Value> | undefined,
): update is (current: Value) => Value {
  return typeof update === "function";
}

/** Apply one coherent workspace transition without mutating its prior snapshot. */
export function reduceWorkspaceState<State extends object>(
  state: State,
  patch: WorkspaceStatePatch<State>,
): State {
  const updates: Partial<State> = {};
  let changed = false;
  for (const field in patch) {
    if (!Object.hasOwn(patch, field)) continue;
    const update = patch[field];
    const value = isFieldUpdater(update) ? update(state[field]) : update;
    Object.assign(updates, { [field]: value });
    changed ||= !Object.is(state[field], value);
  }
  return changed ? { ...state, ...updates } : state;
}
