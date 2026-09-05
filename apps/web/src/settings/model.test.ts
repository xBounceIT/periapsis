import { describe, expect, it } from "vitest";

import {
  isTenantSettingsProjection,
  normalizeTenantSettingsDraft,
  tenantSettingsDraftDiffers,
  tenantSettingsDraftErrors,
  tenantSettingsDraftFrom,
  tenantSettingsReasonIsValid,
  tenantSettingsUpdateRequest,
} from "./model";

const tenantId = "0198c97d-cf4f-7000-8000-000000000091";

describe("tenant settings model", () => {
  it("normalizes bounded presentation input and binds the exact version", () => {
    const draft = {
      accentColor: " #DC6843 ",
      brandMark: " orb ",
      brandName: " Orbit Response ",
      locale: "it-IT",
      primaryColor: " #103B53 ",
      timezone: "Europe/Rome",
    };
    expect(normalizeTenantSettingsDraft(draft)).toEqual({
      accentColor: "#dc6843",
      brandMark: "ORB",
      brandName: "Orbit Response",
      locale: "it-IT",
      primaryColor: "#103b53",
      timezone: "Europe/Rome",
    });
    expect(tenantSettingsUpdateRequest(7, draft)).toMatchObject({
      expectedVersion: 7,
      brandMark: "ORB",
    });
  });

  it("does not treat formatting-only input as an auditable change", () => {
    const settings = {
      accentColor: "#dc6843",
      brandMark: "ORB",
      brandName: "Orbit Response",
      locale: "it-IT",
      primaryColor: "#103b53",
      tenantId,
      timezone: "Europe/Rome",
      updatedAt: "2026-09-01T18:30:00Z",
      version: 7,
    };
    expect(
      tenantSettingsDraftDiffers(settings, {
        accentColor: " #DC6843 ",
        brandMark: " orb ",
        brandName: " Orbit Response ",
        locale: " it-IT ",
        primaryColor: " #103B53 ",
        timezone: " Europe/Rome ",
      }),
    ).toBe(false);
    expect(
      tenantSettingsDraftDiffers(settings, {
        ...tenantSettingsDraftFrom(settings),
        brandName: "Orbit Incident Response",
      }),
    ).toBe(true);
  });

  it("rejects equal colors, remote-like values, invalid regional tags, and terminal versions", () => {
    expect(
      tenantSettingsDraftErrors({
        accentColor: "#103b53",
        brandMark: "bad!",
        brandName: "Brand\u200e",
        locale: "und",
        primaryColor: "#103b53",
        timezone: "Local",
      }),
    ).toEqual({
      accentColor: "Choose an accent distinct from the primary color.",
      brandMark: "Use 1–4 uppercase letters or digits.",
      brandName: "Use 1–80 visible characters.",
      locale: "Use a BCP 47 language tag such as it-IT.",
      timezone: "Use a canonical IANA timezone such as Europe/Rome.",
    });
    expect(() =>
      tenantSettingsUpdateRequest(2_147_483_647, {
        accentColor: "#dc6843",
        brandMark: "ORB",
        brandName: "Orbit Response",
        locale: "it-IT",
        primaryColor: "#103b53",
        timezone: "Europe/Rome",
      }),
    ).toThrow("invalid");
  });

  it("accepts only one exact safe response shape", () => {
    const value = {
      accentColor: "#dc6843",
      brandMark: "ORB",
      brandName: "Orbit Response",
      locale: "it-IT",
      primaryColor: "#103b53",
      tenantId,
      timezone: "Europe/Rome",
      updatedAt: "2026-09-01T18:30:00.123456Z",
      version: 7,
    };
    expect(isTenantSettingsProjection(value, tenantId)).toBe(true);
    expect(
      isTenantSettingsProjection(
        { ...value, logoUrl: "https://tracker.invalid/pixel" },
        tenantId,
      ),
    ).toBe(false);
    expect(
      isTenantSettingsProjection(value, tenantId.replace("91", "92")),
    ).toBe(false);
  });

  it("keeps audit reasons within one transport-safe header", () => {
    expect(tenantSettingsReasonIsValid("Approved SEC-2048")).toBe(true);
    expect(tenantSettingsReasonIsValid(" contains spaces ")).toBe(false);
    expect(tenantSettingsReasonIsValid("two,values")).toBe(false);
    expect(tenantSettingsReasonIsValid("line\nbreak")).toBe(false);
    expect(tenantSettingsReasonIsValid("A".repeat(501))).toBe(false);
  });
});
