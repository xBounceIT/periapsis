import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import {
  formatTenantInstant,
  resolveTenantDateTimePreferences,
  TenantDateTimeProvider,
  TenantInstant,
} from "./tenant-date-time-context";

afterEach(cleanup);

const boundaryInstant = "2026-01-01T23:30:00Z";

describe("tenant date-time presentation", () => {
  it("uses the tenant timezone when the same instant changes calendar day", () => {
    const utc = formatTenantInstant(boundaryInstant, {
      locale: "en-GB",
      timeZone: "UTC",
    });
    const rome = formatTenantInstant(boundaryInstant, {
      locale: "en-GB",
      timeZone: "Europe/Rome",
    });

    expect(utc).toContain("01 Jan 2026");
    expect(utc).toContain("UTC");
    expect(rome).toContain("02 Jan 2026");
    expect(rome).toContain("Europe/Rome");
  });

  it("updates immediately when the active tenant preferences change", () => {
    const view = render(
      <TenantDateTimeProvider locale="en-GB" timeZone="UTC">
        <TenantInstant value={boundaryInstant} />
      </TenantDateTimeProvider>,
    );
    expect(screen.getByText(/01 Jan 2026/u)).toHaveTextContent("· UTC");

    view.rerender(
      <TenantDateTimeProvider locale="it-IT" timeZone="Europe/Rome">
        <TenantInstant value={boundaryInstant} />
      </TenantDateTimeProvider>,
    );
    expect(screen.getByText(/02 gen 2026/u)).toHaveTextContent("· Europe/Rome");
  });

  it("falls back independently to explicit safe locale and timezone values", () => {
    expect(
      resolveTenantDateTimePreferences({
        locale: "zz-ZZ",
        timeZone: "Mars/Olympus",
      }),
    ).toEqual({ locale: "en-GB", timeZone: "UTC" });
    expect(
      resolveTenantDateTimePreferences({
        locale: "not_a_locale",
        timeZone: "Europe/Rome",
      }),
    ).toEqual({ locale: "en-GB", timeZone: "Europe/Rome" });
    expect(
      resolveTenantDateTimePreferences({
        locale: "it-IT",
        timeZone: "Mars/Olympus",
      }),
    ).toEqual({ locale: "it-IT", timeZone: "UTC" });
    expect(
      formatTenantInstant(boundaryInstant, {
        locale: "zz-ZZ",
        timeZone: "Mars/Olympus",
      }),
    ).toMatch(/01 Jan 2026.*· UTC/u);

    render(<TenantInstant value={boundaryInstant} />);
    expect(screen.getByText(/01 Jan 2026/u)).toHaveTextContent("· UTC");
  });
});
