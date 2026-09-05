import { describe, expect, it } from "vitest";

import {
  buildCustomFieldImportRequest,
  customFieldImportExample,
  isCustomFieldImportTerminal,
  parseCustomFieldImportRows,
} from "./custom-field-import-model";

describe("custom-field import model", () => {
  it("preserves missing, null, and empty-string values as distinct requests", () => {
    const parsed = parseCustomFieldImportRows(customFieldImportExample);

    expect(parsed.summary).toEqual({
      rows: 1,
      fields: 4,
      missingValues: 1,
      nullValues: 1,
      emptyValues: 1,
    });
    expect(parsed.rows[0]?.fields).toEqual([
      { key: "triage.owner", value: "incident-response" },
      { key: "triage.note", value: "" },
      { key: "triage.reviewed_at", value: null },
      { key: "triage.preserve_existing" },
    ]);
    expect(Object.hasOwn(parsed.rows[0]!.fields[3]!, "value")).toBe(false);
  });

  it.each([
    ["duplicate targets", duplicateTargetRows(), "repeats targetId"],
    ["duplicate field keys", duplicateFieldRows(), "repeats field key"],
    ["unknown row members", unknownRowMember(), "unsupported or missing"],
    [
      "unknown field members",
      unknownFieldMember(),
      "only key and optional value",
    ],
    ["non-v7 targets", nonV7Target(), "canonical UUIDv7"],
    ["unsafe versions", unsafeVersion(), "positive, safe expectedVersion"],
    [
      "uncommittable versions",
      uncommittableVersion(),
      "positive, safe expectedVersion",
    ],
    [
      "duplicate JSON properties",
      duplicateJsonProperty(),
      "repeats object property",
    ],
  ])("rejects %s", (_label, source, message) => {
    expect(() => parseCustomFieldImportRows(source)).toThrow(message);
  });

  it("freezes a bounded request without sharing mutable rows", () => {
    const parsed = parseCustomFieldImportRows(customFieldImportExample);
    const request = buildCustomFieldImportRequest({
      mode: "dry_run",
      objectType: "alert",
      retentionSeconds: 86_400,
      rows: parsed.rows,
    });

    parsed.rows[0]!.fields[0]!.value = "changed";
    expect(request.rows[0]!.fields[0]!.value).toBe("incident-response");
  });

  it("rejects values that would silently change during serialization", () => {
    const parsed = parseCustomFieldImportRows(customFieldImportExample);
    parsed.rows[0]!.fields[0]!.value = Number.NaN;
    expect(() =>
      buildCustomFieldImportRequest({
        mode: "commit",
        objectType: "alert",
        retentionSeconds: 86_400,
        rows: parsed.rows,
      }),
    ).toThrow("cannot be sent safely");

    parsed.rows[0]!.fields[0]!.value = new Date();
    expect(() =>
      buildCustomFieldImportRequest({
        mode: "commit",
        objectType: "alert",
        retentionSeconds: 86_400,
        rows: parsed.rows,
      }),
    ).toThrow("not JSON serializable");
  });

  it("enforces the canonical per-cell JSON budget", () => {
    const parsed = parseCustomFieldImportRows(customFieldImportExample);
    parsed.rows[0]!.fields[0]!.value = "x".repeat(65_536);
    expect(() =>
      buildCustomFieldImportRequest({
        mode: "dry_run",
        objectType: "alert",
        retentionSeconds: 86_400,
        rows: parsed.rows,
      }),
    ).toThrow("must not exceed 64 KiB");
  });

  it("classifies every durable terminal state", () => {
    expect(isCustomFieldImportTerminal("running")).toBe(false);
    expect(isCustomFieldImportTerminal("cancellation_requested")).toBe(false);
    for (const state of [
      "completed",
      "failed",
      "cancelled",
      "authorization_revoked",
      "expired",
    ] as const) {
      expect(isCustomFieldImportTerminal(state)).toBe(true);
    }
  });
});

function row(fields = '[{"key":"triage.owner","value":"ops"}]'): string {
  return `{"targetId":"0198c97d-cf4f-7000-8000-000000000101","expectedVersion":7,"fields":${fields}}`;
}

function duplicateTargetRows(): string {
  return `[${row()},${row()}]`;
}

function duplicateFieldRows(): string {
  return `[${row('[{"key":"triage.owner"},{"key":"triage.owner","value":null}]')}]`;
}

function unknownRowMember(): string {
  const source = row();
  return `[${source.slice(0, -1)},"tenantId":"forged"}]`;
}

function unknownFieldMember(): string {
  return `[${row('[{"key":"triage.owner","presence":"missing"}]')}]`;
}

function nonV7Target(): string {
  return `[${row().replace("0198c97d-cf4f-7000", "0198c97d-cf4f-4000")}]`;
}

function unsafeVersion(): string {
  return `[${row().replace('"expectedVersion":7', '"expectedVersion":0')}]`;
}

function uncommittableVersion(): string {
  return `[${row().replace(
    '"expectedVersion":7',
    `"expectedVersion":${Number.MAX_SAFE_INTEGER}`,
  )}]`;
}

function duplicateJsonProperty(): string {
  return `[${row('[{"key":"triage.owner","value":null,"value":""}]')}]`;
}
