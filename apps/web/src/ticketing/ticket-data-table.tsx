import {
  columnPinningFeature,
  columnResizingFeature,
  columnSizingFeature,
  columnVisibilityFeature,
  createColumnHelper,
  rowSelectionFeature,
  tableFeatures,
  useTable,
  type Column,
  type ColumnPinningState,
  type ColumnSizingState,
  type ColumnVisibilityState,
  type Header,
  type RowSelectionState,
} from "@tanstack/react-table";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import type { TicketBulkTargetPin } from "@periapsis/contracts";
import {
  Columns3,
  LoaderCircle,
  Pin,
  PinOff,
  Plus,
  RotateCcw,
  Rows3,
  Trash2,
} from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type KeyboardEvent,
  type MouseEvent,
  type ReactNode,
} from "react";
import { Link, useNavigate } from "react-router";

import { TenantInstant } from "../lib/tenant-date-time-context";
import type { TicketKind, TicketProjection } from "../lib/ticketing-api";
import type { TicketDynamicColumnCatalogItem } from "../lib/ticket-column-catalog-api";
import {
  compactIdentifier,
  humanizeKey,
  kindLabel,
  priorityTone,
  severityTone,
  ticketNumber,
} from "./ticketing-model";
import {
  defaultTicketTableColumns,
  savedViewColumnIdentity,
  savedViewColumnLabel,
  type TicketTableColumnSpec,
} from "./saved-view-model";

const ticketTableFeatures = tableFeatures({
  columnPinningFeature,
  columnResizingFeature,
  columnSizingFeature,
  columnVisibilityFeature,
  rowSelectionFeature,
});
const ticketColumnHelper = createColumnHelper<
  typeof ticketTableFeatures,
  TicketProjection
>();

export interface TicketDataTableProps {
  availableDynamicColumns?: readonly TicketDynamicColumnCatalogItem[];
  columnCatalogError?: unknown;
  columnCatalogHasMore?: boolean;
  columnCatalogLoading?: boolean;
  columnCatalogLoadingMore?: boolean;
  columns?: readonly TicketTableColumnSpec[];
  items: TicketProjection[];
  kind: TicketKind;
  onColumnsChange?: (columns: TicketTableColumnSpec[]) => void;
  onColumnCatalogRequested?: () => void;
  onLoadMoreColumns?: () => void;
  onSelectionChange?: (targets: TicketBulkTargetPin[]) => void;
  selectionResetToken?: number;
  selectionScope: string;
}

export function TicketDataTable({
  availableDynamicColumns = [],
  columnCatalogError,
  columnCatalogHasMore = false,
  columnCatalogLoading = false,
  columnCatalogLoadingMore = false,
  columns: layoutColumns = defaultTicketTableColumns,
  items,
  kind,
  onColumnsChange,
  onColumnCatalogRequested,
  onLoadMoreColumns,
  onSelectionChange,
  selectionResetToken = 0,
  selectionScope,
}: TicketDataTableProps): React.JSX.Element {
  const navigate = useNavigate();
  const layoutColumnsRef = useRef(layoutColumns);
  layoutColumnsRef.current = layoutColumns;
  const [baselineColumns, setBaselineColumns] = useState(() =>
    cloneColumns(layoutColumns),
  );
  const [columnPinning, setColumnPinning] = useState<ColumnPinningState>(() =>
    pinningFromColumns(layoutColumns),
  );
  const [columnSizing, setColumnSizing] = useState<ColumnSizingState>(() =>
    sizingFromColumns(layoutColumns),
  );
  const [columnVisibility, setColumnVisibility] =
    useState<ColumnVisibilityState>(() => visibilityFromColumns(layoutColumns));
  const [rowSelection, setRowSelection] = useState<RowSelectionState>({});
  const [activeRowId, setActiveRowId] = useState<string | null>(null);
  const reportedSelectionRef = useRef("");
  const loadedRowIdSignature = items.map((item) => item.id).join("|");
  const layoutColumnIdentitySignature = layoutColumns
    .map(savedViewColumnIdentity)
    .join("|");

  useEffect(() => {
    const next = cloneColumns(layoutColumnsRef.current);
    setBaselineColumns(next);
    setColumnPinning(pinningFromColumns(next));
    setColumnSizing(sizingFromColumns(next));
    setColumnVisibility(visibilityFromColumns(next));
    setActiveRowId(null);
    setRowSelection({});
  }, [selectionScope]);
  useEffect(() => {
    const next = cloneColumns(layoutColumnsRef.current);
    setBaselineColumns(next);
    setColumnPinning(pinningFromColumns(next));
    setColumnSizing(sizingFromColumns(next));
    setColumnVisibility(visibilityFromColumns(next));
  }, [layoutColumnIdentitySignature]);
  useEffect(() => {
    onColumnsChange?.(
      columnsFromTableState(
        layoutColumnsRef.current,
        columnPinning,
        columnSizing,
        columnVisibility,
      ),
    );
  }, [
    columnPinning,
    columnSizing,
    columnVisibility,
    layoutColumnIdentitySignature,
    onColumnsChange,
  ]);
  useEffect(() => {
    const loaded = new Set(
      loadedRowIdSignature === "" ? [] : loadedRowIdSignature.split("|"),
    );
    setRowSelection((current) => {
      const next = Object.fromEntries(
        Object.entries(current).filter(([id]) => loaded.has(id)),
      );
      return Object.keys(next).length === Object.keys(current).length
        ? current
        : next;
    });
    setActiveRowId((current) =>
      current !== null && loaded.has(current) ? current : null,
    );
  }, [loadedRowIdSignature]);
  useEffect(() => {
    setRowSelection({});
  }, [selectionResetToken]);
  const selectedTargets = items
    .filter((item) => rowSelection[item.id] === true)
    .map((item) => ({ id: item.id, expectedVersion: item.version }));
  const selectedTargetSignature = selectedTargets
    .map((target) => `${target.id}:${target.expectedVersion}`)
    .join("|");
  useEffect(() => {
    if (reportedSelectionRef.current === selectedTargetSignature) return;
    reportedSelectionRef.current = selectedTargetSignature;
    onSelectionChange?.(selectedTargets);
  }, [onSelectionChange, selectedTargetSignature, selectedTargets]);

  const columns = useMemo(
    () =>
      ticketColumnHelper.columns([
        ticketColumnHelper.display({
          cell: ({ row }) => (
            <RowSelectionCheckbox
              checked={row.getIsSelected()}
              label={`Select ${ticketNumber(kind, row.original)}`}
              onClick={(event) => {
                const handler = row.getToggleSelectedHandler({
                  selectChildren: false,
                });
                handler({
                  nativeEvent: event.nativeEvent,
                  shiftKey: event.shiftKey,
                  target: { checked: !row.getIsSelected() },
                });
              }}
            />
          ),
          enableHiding: false,
          enablePinning: false,
          enableResizing: false,
          header: ({ table }) => (
            <Checkbox
              aria-label="Select all loaded tickets"
              checked={
                table.getIsAllRowsSelected()
                  ? true
                  : table.getIsSomeRowsSelected()
                    ? "indeterminate"
                    : false
              }
              onCheckedChange={(checked) =>
                table.toggleAllRowsSelected(checked === true, {
                  deselectAll: checked !== true,
                })
              }
            />
          ),
          id: "selection",
          maxSize: 52,
          minSize: 52,
          size: 52,
        }),
        ...layoutColumns.map((column) =>
          ticketColumnHelper.display({
            cell: ({ row }) => renderTicketColumn(column, row.original, kind),
            enableHiding:
              column.source !== "core" || column.coreKey !== "ticket",
            header: savedViewColumnLabel(column),
            id: savedViewColumnIdentity(column),
            maxSize: 1_200,
            minSize: 80,
            size: column.width,
          }),
        ),
      ]),
    [kind, layoutColumns],
  );
  const columnLabels = useMemo(
    () =>
      Object.fromEntries(
        layoutColumns.map((column) => [
          savedViewColumnIdentity(column),
          savedViewColumnLabel(column),
        ]),
      ),
    [layoutColumns],
  );

  const table = useTable({
    columnResizeMode: "onChange",
    columns,
    data: items,
    enableSubRowSelection: false,
    features: ticketTableFeatures,
    getRowId: (row) => row.id,
    onColumnPinningChange: setColumnPinning,
    onColumnSizingChange: setColumnSizing,
    onColumnVisibilityChange: setColumnVisibility,
    onRowSelectionChange: setRowSelection,
    state: {
      columnPinning,
      columnSizing,
      columnVisibility,
      rowSelection,
    },
  });
  const selectedCount = table.getSelectedRowIds().length;
  const activeDynamicColumnIdentities = new Set(
    layoutColumns
      .filter((column) => column.source !== "core")
      .map(savedViewColumnIdentity),
  );
  const addableDynamicColumns = availableDynamicColumns.filter(
    (item) =>
      !activeDynamicColumnIdentities.has(`${item.source}:${item.definitionId}`),
  );

  function resetColumns(): void {
    setColumnPinning(pinningFromColumns(baselineColumns));
    setColumnSizing(sizingFromColumns(baselineColumns));
    setColumnVisibility(visibilityFromColumns(baselineColumns));
  }

  function addDynamicColumn(item: TicketDynamicColumnCatalogItem): void {
    if (!onColumnsChange || layoutColumns.length >= 64) return;
    const identity = `${item.source}:${item.definitionId}`;
    if (
      layoutColumns.some(
        (column) => savedViewColumnIdentity(column) === identity,
      )
    ) {
      return;
    }
    onColumnsChange([
      ...cloneColumns(layoutColumns),
      {
        source: item.source,
        definitionId: item.definitionId,
        definitionKey: item.definitionKey,
        expectedDefinitionVersion: item.definitionVersion,
        pin: "none",
        visible: true,
        width: 220,
      },
    ]);
  }

  function removeDynamicColumn(identity: string): void {
    if (!onColumnsChange) return;
    const next = layoutColumns.filter(
      (column) =>
        column.source === "core" ||
        savedViewColumnIdentity(column) !== identity,
    );
    if (next.length !== layoutColumns.length)
      onColumnsChange(cloneColumns(next));
  }

  function handleRowKeyDown(
    event: KeyboardEvent<HTMLTableRowElement>,
    item: TicketProjection,
  ): void {
    if (event.target !== event.currentTarget) return;
    const rows = Array.from(
      event.currentTarget.parentElement?.querySelectorAll<HTMLTableRowElement>(
        "tr[data-ticket-row]",
      ) ?? [],
    );
    const index = rows.indexOf(event.currentTarget);
    let next: HTMLTableRowElement | undefined;
    switch (event.key) {
      case "ArrowDown":
        next = rows[Math.min(index + 1, rows.length - 1)];
        break;
      case "ArrowUp":
        next = rows[Math.max(index - 1, 0)];
        break;
      case "End":
        next = rows.at(-1);
        break;
      case "Home":
        next = rows[0];
        break;
      case "Enter":
        event.preventDefault();
        void navigate(`/${kind === "alert" ? "alerts" : "cases"}/${item.id}`);
        return;
      default:
        return;
    }
    if (next !== undefined) {
      event.preventDefault();
      next.focus();
    }
  }

  return (
    <div className="ticket-data-grid">
      <div className="ticket-table-toolbar">
        <details
          className="ticket-column-menu"
          onToggle={(event) => {
            if (event.currentTarget.open) onColumnCatalogRequested?.();
          }}
        >
          <summary>
            <Columns3 aria-hidden="true" /> Columns
          </summary>
          <div aria-label="Ticket table columns">
            {table
              .getAllLeafColumns()
              .filter((column) => column.id !== "selection")
              .map((column) => (
                <div key={column.id}>
                  <Checkbox
                    aria-label={`Show ${columnLabels[column.id] ?? columnLabel(column.id)} column`}
                    checked={column.getIsVisible()}
                    disabled={!column.getCanHide()}
                    onCheckedChange={(checked) =>
                      column.toggleVisibility(checked === true)
                    }
                  />
                  <span>
                    {columnLabels[column.id] ?? columnLabel(column.id)}
                  </span>
                  {column.getCanPin() ? (
                    column.getIsPinned() ? (
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        aria-label={`Unpin ${columnLabels[column.id] ?? columnLabel(column.id)} column`}
                        onClick={() => column.pin(false)}
                      >
                        <PinOff aria-hidden="true" />
                      </Button>
                    ) : (
                      <span className="ticket-column-pin-actions">
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          aria-label={`Pin ${columnLabels[column.id] ?? columnLabel(column.id)} column to start`}
                          onClick={() => column.pin("start")}
                        >
                          <Pin aria-hidden="true" />
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="ghost"
                          aria-label={`Pin ${columnLabels[column.id] ?? columnLabel(column.id)} column to end`}
                          onClick={() => column.pin("end")}
                        >
                          <Pin aria-hidden="true" />
                        </Button>
                      </span>
                    )
                  ) : null}
                  {layoutColumns.some(
                    (candidate) =>
                      candidate.source !== "core" &&
                      savedViewColumnIdentity(candidate) === column.id,
                  ) ? (
                    <Button
                      type="button"
                      size="sm"
                      variant="ghost"
                      aria-label={`Remove ${columnLabels[column.id] ?? columnLabel(column.id)} column`}
                      onClick={() => removeDynamicColumn(column.id)}
                    >
                      <Trash2 aria-hidden="true" />
                    </Button>
                  ) : null}
                </div>
              ))}
            <div className="ticket-column-catalog" aria-live="polite">
              <p>
                <strong>Available dynamic columns</strong>
                <small>Exact current custom-field and SLA revisions</small>
              </p>
              {columnCatalogLoading ? (
                <span role="status">
                  <LoaderCircle className="is-spinning" aria-hidden="true" />
                  Loading column catalog…
                </span>
              ) : null}
              {columnCatalogError ? (
                <span role="alert">
                  The authorized dynamic-column catalog could not be loaded.
                </span>
              ) : null}
              {!columnCatalogLoading &&
              !columnCatalogError &&
              addableDynamicColumns.length === 0 ? (
                <span>
                  Every available dynamic column is already in this view.
                </span>
              ) : null}
              {addableDynamicColumns.map((item) => (
                <Button
                  key={`${item.source}:${item.definitionId}:${item.definitionVersion}`}
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={!onColumnsChange || layoutColumns.length >= 64}
                  aria-label={`Add ${item.definitionLabel} column`}
                  onClick={() => addDynamicColumn(item)}
                >
                  <Plus aria-hidden="true" />
                  <span>{item.definitionLabel}</span>
                  <small>
                    {item.source === "custom_field" ? "Custom field" : "SLA"} ·
                    v{item.definitionVersion}
                  </small>
                </Button>
              ))}
              {columnCatalogHasMore ? (
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={columnCatalogLoadingMore || !onLoadMoreColumns}
                  onClick={onLoadMoreColumns}
                >
                  {columnCatalogLoadingMore ? (
                    <LoaderCircle className="is-spinning" aria-hidden="true" />
                  ) : null}
                  Load more columns
                </Button>
              ) : null}
            </div>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={resetColumns}
            >
              <RotateCcw aria-hidden="true" /> Reset columns
            </Button>
          </div>
        </details>
        <span className="ticket-table-toolbar__hint">
          <Rows3 aria-hidden="true" /> Arrow keys move between rows; Enter
          opens.
        </span>
      </div>

      {selectedCount > 0 ? (
        <div
          className="ticket-bulk-selection"
          role="status"
          aria-label={`${selectedCount} loaded ticket${selectedCount === 1 ? "" : "s"} selected`}
        >
          <span>
            <strong>{selectedCount}</strong> loaded ticket
            {selectedCount === 1 ? "" : "s"} selected
          </span>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            onClick={() => table.resetRowSelection(true)}
          >
            Clear selection
          </Button>
        </div>
      ) : null}

      <div className="ticket-table-wrap">
        <Table
          className="ticket-table ticket-table--interactive"
          style={{ width: `${table.getTotalSize()}px` }}
        >
          <TableCaption className="sr-only">
            {kindLabel(kind)} queue. Columns can be resized and pinned; only
            loaded rows can be selected from this table.
          </TableCaption>
          <TableHeader>
            {table.getHeaderGroups().map((headerGroup) => (
              <TableRow key={headerGroup.id}>
                {headerGroup.headers.map((header) => (
                  <TableHead
                    key={header.id}
                    aria-label={
                      columnLabels[header.column.id] ??
                      columnLabel(header.column.id)
                    }
                    data-pinned={header.column.getIsPinned() || undefined}
                    style={columnStyle(header.column)}
                  >
                    <span className="ticket-table-header-content">
                      {header.isPlaceholder ? null : (
                        <table.FlexRender header={header} />
                      )}
                    </span>
                    {header.column.getCanResize() ? (
                      <ColumnResizeHandle
                        header={header}
                        label={
                          columnLabels[header.column.id] ??
                          columnLabel(header.column.id)
                        }
                        table={table}
                      />
                    ) : null}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {table.getRowModel().rows.map((row) => (
              <TableRow
                key={row.id}
                aria-label={`Open ${ticketNumber(kind, row.original)} ${row.original.title}`}
                aria-selected={row.getIsSelected()}
                data-state={row.getIsSelected() ? "selected" : undefined}
                data-ticket-row=""
                onFocus={() => setActiveRowId(row.id)}
                onKeyDown={(event) => handleRowKeyDown(event, row.original)}
                tabIndex={
                  activeRowId === row.id ||
                  (activeRowId === null && row.getDisplayIndex() === 0)
                    ? 0
                    : -1
                }
              >
                {row.getVisibleCells().map((cell) => (
                  <TableCell
                    key={cell.id}
                    data-pinned={cell.column.getIsPinned() || undefined}
                    style={columnStyle(cell.column)}
                  >
                    <table.FlexRender cell={cell} />
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

function RowSelectionCheckbox({
  checked,
  label,
  onClick,
}: {
  checked: boolean;
  label: string;
  onClick: (event: MouseEvent<HTMLButtonElement>) => void;
}): React.JSX.Element {
  return (
    <Checkbox
      aria-label={label}
      checked={checked}
      onClick={(event) => {
        event.stopPropagation();
        onClick(event);
      }}
    />
  );
}

function ColumnResizeHandle({
  header,
  label,
  table,
}: {
  header: Header<typeof ticketTableFeatures, TicketProjection>;
  label: string;
  table: ReturnType<
    typeof useTable<typeof ticketTableFeatures, TicketProjection>
  >;
}): React.JSX.Element {
  const minimum = header.column.columnDef.minSize ?? 40;
  const maximum = header.column.columnDef.maxSize ?? 1_000;

  function resizeBy(delta: number): void {
    const size = Math.min(
      maximum,
      Math.max(minimum, header.column.getSize() + delta),
    );
    table.setColumnSizing((current) => ({
      ...current,
      [header.column.id]: size,
    }));
  }

  return (
    <span
      className={
        header.column.getIsResizing()
          ? "ticket-column-resizer is-resizing"
          : "ticket-column-resizer"
      }
      role="separator"
      aria-label={`Resize ${label} column`}
      aria-orientation="vertical"
      aria-valuemax={maximum}
      aria-valuemin={minimum}
      aria-valuenow={header.column.getSize()}
      onDoubleClick={() => header.column.resetSize()}
      onKeyDown={(event) => {
        if (event.key === "ArrowLeft") {
          event.preventDefault();
          resizeBy(-10);
        } else if (event.key === "ArrowRight") {
          event.preventDefault();
          resizeBy(10);
        } else if (event.key === "Home") {
          event.preventDefault();
          resizeBy(minimum - header.column.getSize());
        } else if (event.key === "End") {
          event.preventDefault();
          resizeBy(maximum - header.column.getSize());
        }
      }}
      onMouseDown={header.getResizeHandler()}
      onTouchStart={header.getResizeHandler()}
      tabIndex={0}
    />
  );
}

function columnStyle(
  column: Column<typeof ticketTableFeatures, TicketProjection>,
): CSSProperties {
  const pinned = column.getIsPinned();
  return {
    ...(pinned === "start"
      ? { insetInlineStart: `${column.getStart("start")}px` }
      : {}),
    ...(pinned === "end"
      ? { insetInlineEnd: `${column.getAfter("end")}px` }
      : {}),
    maxWidth: `${column.getSize()}px`,
    minWidth: `${column.getSize()}px`,
    position: pinned ? "sticky" : "relative",
    width: `${column.getSize()}px`,
    zIndex: pinned ? 2 : 0,
  };
}

function columnLabel(id: string): string {
  switch (id) {
    case "ticket":
      return "Ticket";
    case "state":
      return "State";
    case "risk":
      return "Risk";
    case "assignment":
      return "Assignment";
    case "updated":
      return "Updated";
    default:
      return humanizeKey(id.includes(":") ? id.slice(id.indexOf(":") + 1) : id);
  }
}

function renderTicketColumn(
  column: TicketTableColumnSpec,
  item: TicketProjection,
  kind: TicketKind,
): ReactNode {
  if (column.source !== "core") {
    if (item.projection !== "operator") {
      return <span className="ticket-redacted-value">Not exposed</span>;
    }
    const value = item.dynamicColumns?.find(
      (candidate) =>
        candidate.source === column.source &&
        candidate.definitionId === column.definitionId &&
        candidate.definitionVersion === column.expectedDefinitionVersion,
    );
    if (!value) return <span className="ticket-redacted-value">No value</span>;
    return (
      <span className="ticket-dynamic-value">
        <strong>{formatDynamicValue(value.value)}</strong>
        {value.source === "sla" ? (
          <small>
            {value.styleKey ? humanizeKey(value.styleKey) : "SLA"} · as of{" "}
            <TenantInstant value={value.materializedAt} />
          </small>
        ) : null}
      </span>
    );
  }

  switch (column.coreKey) {
    case "ticket":
      return (
        <Link
          className="ticket-title-link"
          to={`/${kind === "alert" ? "alerts" : "cases"}/${item.id}`}
        >
          <span>{ticketNumber(kind, item)}</span>
          <strong>{item.title}</strong>
          <small>{item.category || "Uncategorized"}</small>
        </Link>
      );
    case "state":
      return (
        <>
          <Badge variant="outline">{humanizeKey(item.workflow.stateKey)}</Badge>
          <small className="ticket-projection-label">
            {item.projection === "customer"
              ? "Customer view"
              : item.customerVisible
                ? "Customer visible"
                : "Internal"}
          </small>
        </>
      );
    case "risk":
      return (
        <>
          <span className={severityTone(item.severity)}>
            {humanizeKey(item.severity)}
          </span>
          <span className={priorityTone(item.priority)}>
            {humanizeKey(item.priority)} priority
          </span>
        </>
      );
    case "assignment":
      return item.projection === "operator" ? (
        <span className="ticket-assignment-cell">
          <strong>{compactIdentifier(item.assignment.assignedTeamId)}</strong>
          <small>
            {item.assignment.claimedBy
              ? `Claimed by ${compactIdentifier(item.assignment.claimedBy)}`
              : "Not claimed"}
          </small>
        </span>
      ) : (
        <span className="ticket-redacted-value">Not exposed</span>
      );
    case "category":
      return item.category || "Uncategorized";
    case "source":
      return kind === "alert" && "source" in item
        ? item.source
        : "Not applicable";
    case "customer_visibility":
      return item.customerVisible ? "Customer visible" : "Internal only";
    case "created":
      return <TenantInstant value={item.createdAt} />;
    case "updated":
      return <TenantInstant value={item.updatedAt} />;
    default:
      return <span className="ticket-redacted-value">Unavailable</span>;
  }
}

function formatDynamicValue(value: boolean | number | string): string {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  return String(value);
}

function cloneColumns(
  columns: readonly TicketTableColumnSpec[],
): TicketTableColumnSpec[] {
  return columns.map((column) => ({ ...column }));
}

function pinningFromColumns(
  columns: readonly TicketTableColumnSpec[],
): ColumnPinningState {
  return {
    start: [
      "selection",
      ...columns
        .filter((column) => column.pin === "start")
        .map(savedViewColumnIdentity),
    ],
    end: columns
      .filter((column) => column.pin === "end")
      .map(savedViewColumnIdentity),
  };
}

function sizingFromColumns(
  columns: readonly TicketTableColumnSpec[],
): ColumnSizingState {
  return Object.fromEntries(
    columns.map((column) => [savedViewColumnIdentity(column), column.width]),
  );
}

function visibilityFromColumns(
  columns: readonly TicketTableColumnSpec[],
): ColumnVisibilityState {
  return Object.fromEntries(
    columns.map((column) => [savedViewColumnIdentity(column), column.visible]),
  );
}

function columnsFromTableState(
  columns: readonly TicketTableColumnSpec[],
  pinning: ColumnPinningState,
  sizing: ColumnSizingState,
  visibility: ColumnVisibilityState,
): TicketTableColumnSpec[] {
  const start = new Set(pinning.start ?? []);
  const end = new Set(pinning.end ?? []);
  return columns.map((column) => {
    const identity = savedViewColumnIdentity(column);
    const width = Math.max(
      80,
      Math.min(1_200, Math.round(sizing[identity] ?? column.width)),
    );
    return {
      ...column,
      pin: end.has(identity) ? "end" : start.has(identity) ? "start" : "none",
      visible:
        column.source === "core" && column.coreKey === "ticket"
          ? true
          : (visibility[identity] ?? column.visible),
      ...(width === column.width
        ? column.storedWidth === undefined
          ? {}
          : { storedWidth: column.storedWidth }
        : { storedWidth: width }),
      width,
    };
  });
}
