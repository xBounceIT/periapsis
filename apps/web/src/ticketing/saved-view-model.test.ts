import { afterEach, describe, expect, it, vi } from "vitest";

import { savedAlertView, savedViewId } from "./ticketing-test-fixtures";
import {
  acquireSavedViewAttempt,
  defaultTicketTableColumns,
  inlineSavedViewSpec,
  parseSavedViewURL,
  savedViewSpecInput,
  savedViewURL,
  tableColumnsFromSavedView,
} from "./saved-view-model";

afterEach(() => vi.restoreAllMocks());

describe("saved-view model", () => {
  it("accepts only one standalone canonical UUIDv7 URL selection", () => {
    expect(parseSavedViewURL(new URLSearchParams())).toEqual({ kind: "none" });
    expect(parseSavedViewURL(savedViewURL(savedViewId))).toEqual({
      kind: "selected",
      viewId: savedViewId,
    });
    expect(
      parseSavedViewURL(new URLSearchParams(`view=${savedViewId}&search=x`)),
    ).toEqual({
      kind: "invalid",
    });
    expect(parseSavedViewURL(new URLSearchParams("view=not-a-uuid"))).toEqual({
      kind: "invalid",
    });
    expect(
      parseSavedViewURL(
        new URLSearchParams(`view=${savedViewId}&view=${savedViewId}`),
      ),
    ).toEqual({ kind: "invalid" });
  });

  it("builds a bounded inline definition without cursor or transport state", () => {
    const spec = inlineSavedViewSpec(
      {
        customerVisible: false,
        limit: 30,
        priority: ["urgent"],
        queue: "unassigned",
        search: "powershell",
        severity: ["high"],
        sort: "created_at_asc",
        status: ["new"],
      },
      defaultTicketTableColumns,
    );

    expect(spec.filters).toMatchObject({
      customerVisible: false,
      custom: [],
      priorities: ["urgent"],
      queue: "unassigned",
      search: "powershell",
      severities: ["high"],
      states: ["new"],
    });
    expect(spec.sort).toEqual({
      coreKey: "created_at",
      direction: "asc",
      nulls: "last",
      source: "core",
    });
    expect(spec.columns[0]).toMatchObject({
      coreKey: "ticket",
      pin: "start",
      visible: true,
      width: 360,
    });
    expect(() =>
      inlineSavedViewSpec(
        { after: "opaque-cursor", limit: 30 },
        defaultTicketTableColumns,
      ),
    ).toThrow("not persistable");
  });

  it("preserves exact dynamic definition versions while stripping server-only pins", () => {
    const columns = tableColumnsFromSavedView(savedAlertView.spec.columns);
    const input = savedViewSpecInput(savedAlertView.spec, columns);

    expect(input.filters.custom[0]).toEqual({
      definitionId: savedAlertView.spec.filters.custom[0]!.definition.id,
      expectedDefinitionVersion: 4,
      operator: "equal",
      value: "finance",
    });
    expect(input.sort).toEqual({
      definitionId: savedAlertView.spec.sort.definition.id,
      direction: "asc",
      expectedDefinitionVersion: 2,
      nulls: "last",
      source: "sla",
    });
    expect(input.columns.at(-1)).toMatchObject({
      definitionId: savedAlertView.spec.sort.definition.id,
      expectedDefinitionVersion: 2,
      pin: "end",
      source: "sla",
    });
  });

  it("round-trips an omitted persisted width without inventing a mutation", () => {
    const columns = tableColumnsFromSavedView([
      { ...savedAlertView.spec.columns[0]!, width: 0 },
      ...savedAlertView.spec.columns.slice(1),
    ]);
    const input = savedViewSpecInput(savedAlertView.spec, columns);

    expect(columns[0]).toMatchObject({ storedWidth: 0, width: 360 });
    expect(input.columns[0]).not.toHaveProperty("width");
  });

  it("reuses an idempotency key only for the same intent and canonical payload", () => {
    const randomUUID = vi
      .spyOn(globalThis.crypto, "randomUUID")
      .mockReturnValueOnce("0198c97d-cf4f-7000-8000-000000000090")
      .mockReturnValueOnce("0198c97d-cf4f-7000-8000-000000000091");

    const first = acquireSavedViewAttempt(undefined, "create", {
      name: "Mine",
      spec: { b: 2, a: 1 },
    });
    const replay = acquireSavedViewAttempt(first, "create", {
      spec: { a: 1, b: 2 },
      name: "Mine",
    });
    const changed = acquireSavedViewAttempt(replay, "create", {
      name: "Mine revised",
      spec: { a: 1, b: 2 },
    });

    expect(replay.key).toBe(first.key);
    expect(changed.key).not.toBe(first.key);
    expect(randomUUID).toHaveBeenCalledTimes(2);
  });
});
