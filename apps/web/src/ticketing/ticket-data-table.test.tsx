import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  defaultTicketTableColumns,
  type TicketTableColumnSpec,
} from "./saved-view-model";
import {
  TicketDataTable,
  type TicketDataTableProps,
} from "./ticket-data-table";
import { operatorAlert } from "./ticketing-test-fixtures";

afterEach(cleanup);

describe("TicketDataTable state ownership", () => {
  it("reports column changes once per event and resets to the original layout after parent echoes", () => {
    const onChange = vi.fn();
    render(
      <MemoryRouter>
        <ControlledColumns onChange={onChange} />
      </MemoryRouter>,
    );
    expect(onChange).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("button", { name: "Unpin Ticket column" }),
    );
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(
      screen.getByRole("columnheader", { name: "Ticket" }),
    ).not.toHaveAttribute("data-pinned");
    fireEvent.keyDown(
      screen.getByRole("separator", { name: "Resize State column" }),
      { key: "ArrowRight" },
    );
    expect(onChange).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("separator", { name: "Resize State column" }),
    ).toHaveAttribute("aria-valuenow", "200");
    fireEvent.click(screen.getByRole("button", { name: "Reset columns" }));
    expect(onChange).toHaveBeenCalledTimes(3);
    expect(
      screen.getByRole("columnheader", { name: "Ticket" }),
    ).toHaveAttribute("data-pinned", "start");
    expect(
      screen.getByRole("separator", { name: "Resize State column" }),
    ).toHaveAttribute("aria-valuenow", "190");
  });

  it("refreshes selected version pins and permanently prunes rows that leave the loaded snapshot", () => {
    const onSelectionChange = vi.fn();
    const view = render(table({ onSelectionChange }));
    expect(onSelectionChange).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Select ALT-2026-0042" }),
    );
    expect(onSelectionChange).toHaveBeenCalledExactlyOnceWith([
      { id: operatorAlert.id, expectedVersion: operatorAlert.version },
    ]);
    const refreshed = { ...operatorAlert, version: operatorAlert.version + 1 };
    view.rerender(table({ onSelectionChange, items: [refreshed] }));
    expect(onSelectionChange).toHaveBeenLastCalledWith([
      { id: operatorAlert.id, expectedVersion: refreshed.version },
    ]);
    expect(onSelectionChange).toHaveBeenCalledTimes(2);
    view.rerender(table({ onSelectionChange, items: [] }));
    expect(onSelectionChange).toHaveBeenLastCalledWith([]);
    expect(onSelectionChange).toHaveBeenCalledTimes(3);
    view.rerender(table({ onSelectionChange, items: [refreshed] }));
    expect(
      screen.getByRole("checkbox", { name: "Select ALT-2026-0042" }),
    ).toHaveAttribute("aria-checked", "false");
    expect(onSelectionChange).toHaveBeenCalledTimes(3);
  });

  it("clears selection across both external reset tokens and queue scopes", () => {
    const onSelectionChange = vi.fn();
    const view = render(table({ onSelectionChange }));
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Select ALT-2026-0042" }),
    );
    view.rerender(table({ onSelectionChange, selectionResetToken: 1 }));
    expect(
      screen.getByRole("checkbox", { name: "Select ALT-2026-0042" }),
    ).toHaveAttribute("aria-checked", "false");
    expect(onSelectionChange).toHaveBeenLastCalledWith([]);
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Select ALT-2026-0042" }),
    );
    view.rerender(
      table({
        onSelectionChange,
        selectionResetToken: 1,
        selectionScope: "different-view",
      }),
    );
    expect(
      screen.getByRole("checkbox", { name: "Select ALT-2026-0042" }),
    ).toHaveAttribute("aria-checked", "false");
    expect(onSelectionChange).toHaveBeenLastCalledWith([]);
    expect(onSelectionChange).toHaveBeenCalledTimes(4);
  });

  it("takes a new layout baseline when the selected view changes", () => {
    const view = render(table());
    fireEvent.keyDown(
      screen.getByRole("separator", { name: "Resize State column" }),
      { key: "ArrowRight" },
    );
    const columns = defaultTicketTableColumns.map((column) =>
      column.source === "core" && column.coreKey === "state"
        ? { ...column, width: 300 }
        : { ...column },
    );
    view.rerender(table({ selectionScope: "different-view", columns }));
    expect(
      screen.getByRole("separator", { name: "Resize State column" }),
    ).toHaveAttribute("aria-valuenow", "300");
    fireEvent.keyDown(
      screen.getByRole("separator", { name: "Resize State column" }),
      { key: "ArrowRight" },
    );
    fireEvent.click(screen.getByRole("button", { name: "Reset columns" }));
    expect(
      screen.getByRole("separator", { name: "Resize State column" }),
    ).toHaveAttribute("aria-valuenow", "300");
  });
});

function table(props: Partial<TicketDataTableProps> = {}): React.JSX.Element {
  return (
    <MemoryRouter>
      <TicketDataTable
        items={[operatorAlert]}
        kind="alert"
        selectionScope="initial-view"
        {...props}
      />
    </MemoryRouter>
  );
}

function ControlledColumns({
  onChange,
}: {
  onChange: (columns: TicketTableColumnSpec[]) => void;
}): React.JSX.Element {
  const [columns, setColumns] = useState(() =>
    defaultTicketTableColumns.map((column) => ({ ...column })),
  );
  return (
    <TicketDataTable
      items={[operatorAlert]}
      kind="alert"
      selectionScope="initial-view"
      columns={columns}
      onColumnsChange={(next) => {
        onChange(next);
        setColumns(next);
      }}
    />
  );
}
