import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { StatusPanel } from "./status-panel";

describe("StatusPanel", () => {
  it("communicates readiness without relying on color", () => {
    render(
      <StatusPanel
        status={{
          product: "Periapsis",
          service: "api",
          status: "ready",
          version: "test",
          checkedAt: "2026-08-23T10:30:00Z",
          tenancyMode: "shared-schema-rls",
        }}
      />,
    );

    expect(screen.getByText("Ready")).toBeVisible();
    expect(screen.getByText("Shared schema + RLS")).toBeVisible();
    expect(
      screen.getByText(
        "This check is returned by the running Go API, not fixture data.",
      ),
    ).toBeVisible();
  });
});
