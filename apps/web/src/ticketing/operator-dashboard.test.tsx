import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TicketingApiError } from "../lib/ticketing-api";
import { OperatorQueueBoard } from "./operator-dashboard";
import {
  createTicketingApi,
  operatorAlert,
  operatorCase,
  tenantId,
} from "./ticketing-test-fixtures";

afterEach(cleanup);

describe("OperatorQueueBoard", () => {
  it("loads each authorized queue with a bounded exact server filter", async () => {
    const listTickets = vi.fn(async (kind, _tenant, filters) => ({
      items: kind === "alert" ? [operatorAlert] : [operatorCase],
      ...(filters.queue === "assigned_to_me" ? { nextCursor: "next" } : {}),
    }));
    renderBoard({ api: createTicketingApi({ listTickets }) });

    expect(await screen.findAllByText(operatorAlert.title)).toHaveLength(3);
    expect(screen.getAllByText(operatorCase.title)).toHaveLength(3);
    await waitFor(() => expect(listTickets).toHaveBeenCalledTimes(6));
    for (const queue of ["assigned_to_me", "my_operator_teams", "unassigned"]) {
      for (const kind of ["alert", "case"]) {
        expect(listTickets).toHaveBeenCalledWith(
          kind,
          tenantId,
          { limit: 5, queue, sort: "updated_at_desc" },
          expect.any(AbortSignal),
        );
      }
    }
    expect(screen.getAllByText("1+")).toHaveLength(2);
    expect(
      screen.getByRole("link", { name: "Open my alerts" }),
    ).toHaveAttribute("href", "/alerts?queue=assigned_to_me");
  });

  it("keeps denied and unavailable lanes non-oracular while other queues remain usable", async () => {
    const listTickets = vi.fn(async (kind, _tenant, filters) => {
      if (kind === "alert" && filters.queue === "unassigned") {
        throw new TicketingApiError("forbidden", 403, "denied");
      }
      if (kind === "case" && filters.queue === "my_operator_teams") {
        throw new Error("database detail that must not render");
      }
      return { items: [] };
    });
    renderBoard({ api: createTicketingApi({ listTickets }) });

    expect(
      await screen.findByText("Server denied alerts access."),
    ).toBeVisible();
    expect(screen.getByText("Cases are unavailable.")).toBeVisible();
    expect(screen.queryByText(/database detail/u)).toBeNull();
    expect(screen.getAllByText("No visible alerts.").length).toBeGreaterThan(0);
  });

  it("does not request ticket data without tenant context or live read authority", () => {
    const listTickets = vi.fn();
    const { rerender } = renderBoard({
      api: createTicketingApi({ listTickets }),
      tenant: null,
    });
    expect(
      screen.getByText("Select a tenant to enter incident orbit."),
    ).toBeVisible();
    expect(listTickets).not.toHaveBeenCalled();

    rerender(
      <MemoryRouter>
        <QueryClientProvider client={new QueryClient()}>
          <OperatorQueueBoard
            api={createTicketingApi({ listTickets })}
            canReadAlerts={false}
            canReadCases={false}
            tenantId={tenantId}
          />
        </QueryClientProvider>
      </MemoryRouter>,
    );
    expect(
      screen.getByText("No ticket inventory is delegated here."),
    ).toBeVisible();
    expect(listTickets).not.toHaveBeenCalled();
  });
});

function renderBoard({
  api,
  tenant = tenantId,
}: {
  api: ReturnType<typeof createTicketingApi>;
  tenant?: string | null;
}) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>
        <OperatorQueueBoard
          api={api}
          canReadAlerts
          canReadCases
          tenantId={tenant ?? undefined}
        />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}
