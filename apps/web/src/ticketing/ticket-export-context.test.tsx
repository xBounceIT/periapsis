import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { TicketExportApi } from "../lib/ticket-export-api";
import {
  TicketExportApiProvider,
  useTicketExportApi,
} from "./ticket-export-context";

afterEach(() => vi.restoreAllMocks());

describe("TicketExportApiProvider", () => {
  it("keeps the asynchronous export boundary independently injectable", () => {
    const request = vi.fn();
    const api: TicketExportApi = {
      cancel: vi.fn(),
      download: vi.fn(),
      get: vi.fn(),
      request,
    };

    function Probe(): React.JSX.Element {
      const current = useTicketExportApi();
      return (
        <output>{current.request === request ? "injected" : "default"}</output>
      );
    }

    render(
      <TicketExportApiProvider api={api}>
        <Probe />
      </TicketExportApiProvider>,
    );

    expect(screen.getByText("injected")).toBeVisible();
  });
});
