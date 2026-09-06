import type { TicketBulkTargetPin } from "@periapsis/contracts";
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
  useLayoutEffect,
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
import type { TicketDynamicColumnCatalogItem } from "../lib/ticket-column-catalog-api";
import type { TicketKind, TicketProjection } from "../lib/ticketing-api";
import {
  defaultTicketTableColumns,
  savedViewColumnIdentity,
  savedViewColumnLabel,
  type TicketTableColumnSpec,
} from "./saved-view-model";
import {
  compactIdentifier,
  humanizeKey,
  kindLabel,
  priorityTone,
  severityTone,
  ticketNumber,
} from "./ticketing-model";

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

export function TicketDataTable(
  props: TicketDataTableProps,
): React.JSX.Element {
  const model = useTicketDataTable(props);
  return <TicketDataTableView model={model} />;
}

function useTicketDataTable({
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
}: TicketDataTableProps) {
  const navigate = useNavigate();
  const schemaSignature = layoutColumns.map(savedViewColumnIdentity).join("|");
  const loadedIdSignature = items.map((item) => item.id).join("|");
  const [savedLayout, setSavedLayout] = useState(() =>
    tableLayoutSnapshot(layoutColumns, selectionScope, schemaSignature),
  );
  let layout = savedLayout;
  if (
    layout.selectionScope !== selectionScope ||
    layout.schemaSignature !== schemaSignature
  ) {
    layout = tableLayoutSnapshot(
      layoutColumns,
      selectionScope,
      schemaSignature,
    );
    setSavedLayout(layout);
  }
  const [savedInteraction, setSavedInteraction] =
    useState<TableInteractionSnapshot>(() => ({
      selectionScope,
      selectionResetToken,
      loadedIdSignature,
      rowSelection: {},
      activeRowId: null,
    }));
  let interaction = savedInteraction;
  if (
    interaction.selectionScope !== selectionScope ||
    interaction.selectionResetToken !== selectionResetToken ||
    interaction.loadedIdSignature !== loadedIdSignature
  ) {
    interaction = reconcileTableInteraction(
      interaction,
      selectionScope,
      selectionResetToken,
      loadedIdSignature,
    );
    setSavedInteraction(interaction);
  }
  const layoutRef = useRef(layout);
  const interactionRef = useRef(interaction);
  useLayoutEffect(() => {
    layoutRef.current = layout;
    interactionRef.current = interaction;
  }, [layout, interaction]);
  const { columnPinning, columnSizing, columnVisibility } = layout;
  const { rowSelection, activeRowId } = interaction;
  const reportedSelectionRef = useRef("");
  const selectedTargets = useMemo(
    () => selectedTicketTargets(items, rowSelection),
    [items, rowSelection],
  );
  const selectedTargetSignature = selectedTargets
    .map((target) => `${target.id}:${target.expectedVersion}`)
    .join("|");

  // Server refreshes can change loaded rows and version pins without a selection event.
  // Reconcile that external snapshot with the parent's reviewed bulk-action selection.
  useEffect(() => {
    if (reportedSelectionRef.current === selectedTargetSignature) return;
    reportedSelectionRef.current = selectedTargetSignature;
    // eslint-disable-next-line react-doctor/no-pass-data-to-parent, react-doctor/no-pass-live-state-to-parent, react-doctor/no-prop-callback-in-effect -- Local selection events notify synchronously; this effect propagates only changed server row/version pins or an external reset.
    onSelectionChange?.(selectedTargets);
  }, [onSelectionChange, selectedTargetSignature, selectedTargets]);

  function changeColumns<Key extends keyof TableColumnState>(
    key: Key,
    update: StateUpdater<TableColumnState[Key]>,
  ): void {
    const current = layoutRef.current;
    const next = {
      ...current,
      [key]: resolveStateUpdate(update, current[key]),
    };
    layoutRef.current = next;
    setSavedLayout(next);
    onColumnsChange?.(
      columnsFromTableState(
        layoutColumns,
        next.columnPinning,
        next.columnSizing,
        next.columnVisibility,
      ),
    );
  }

  function changeRowSelection(update: StateUpdater<RowSelectionState>): void {
    const current = interactionRef.current;
    const next = {
      ...current,
      rowSelection: resolveStateUpdate(update, current.rowSelection),
    };
    interactionRef.current = next;
    setSavedInteraction(next);
    const targets = selectedTicketTargets(items, next.rowSelection);
    const signature = targets
      .map((target) => `${target.id}:${target.expectedVersion}`)
      .join("|");
    if (reportedSelectionRef.current !== signature) {
      reportedSelectionRef.current = signature;
      onSelectionChange?.(targets);
    }
  }

  function setActiveRowId(activeId: string): void {
    const next = { ...interactionRef.current, activeRowId: activeId };
    interactionRef.current = next;
    setSavedInteraction(next);
  }

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
    onColumnPinningChange: (update) => changeColumns("columnPinning", update),
    onColumnSizingChange: (update) => changeColumns("columnSizing", update),
    onColumnVisibilityChange: (update) =>
      changeColumns("columnVisibility", update),
    onRowSelectionChange: changeRowSelection,
    state: {
      columnPinning,
      columnSizing,
      columnVisibility,
      rowSelection,
    },
  });
  const selectedCount = table.getSelectedRowIds().length;
  const activeDynamicColumnIdentities = new Set<string>();
  for (const column of layoutColumns) {
    if (column.source !== "core")
      activeDynamicColumnIdentities.add(savedViewColumnIdentity(column));
  }
  const addableDynamicColumns = availableDynamicColumns.filter(
    (item) =>
      !activeDynamicColumnIdentities.has(`${item.source}:${item.definitionId}`),
  );

  function resetColumns(): void {
    const current = layoutRef.current;
    const next = tableLayoutSnapshot(
      current.baselineColumns,
      current.selectionScope,
      current.schemaSignature,
    );
    layoutRef.current = next;
    setSavedLayout(next);
    onColumnsChange?.(
      columnsFromTableState(
        layoutColumns,
        next.columnPinning,
        next.columnSizing,
        next.columnVisibility,
      ),
    );
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

  return {
    table,
    columnLabels,
    layoutColumns,
    columnCatalogError,
    columnCatalogHasMore,
    columnCatalogLoading,
    columnCatalogLoadingMore,
    onColumnCatalogRequested,
    onLoadMoreColumns,
    onColumnsChange,
    addableDynamicColumns,
    addDynamicColumn,
    removeDynamicColumn,
    resetColumns,
    selectedCount,
    kind,
    activeRowId,
    setActiveRowId,
    handleRowKeyDown,
  };
}

function TicketDataTableView({
  model,
}: {
  model: ReturnType<typeof useTicketDataTable>;
}): React.JSX.Element {
  const {
    table,
    columnLabels,
    selectedCount,
    kind,
    activeRowId,
    setActiveRowId,
    handleRowKeyDown,
  } = model;
  return (
    <div className="ticket-data-grid">
      <TicketTableToolbar model={model} />

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
  const start = ["selection"];
  const end: string[] = [];
  for (const column of columns) {
    if (column.pin === "start") start.push(savedViewColumnIdentity(column));
    if (column.pin === "end") end.push(savedViewColumnIdentity(column));
  }
  return { start, end };
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

function TicketTableToolbar({
  model,
}: {
  model: ReturnType<typeof useTicketDataTable>;
}): React.JSX.Element {
  const {
    table,
    columnLabels,
    layoutColumns,
    columnCatalogError,
    columnCatalogHasMore,
    columnCatalogLoading,
    columnCatalogLoadingMore,
    onColumnCatalogRequested,
    onLoadMoreColumns,
    onColumnsChange,
    addableDynamicColumns,
    addDynamicColumn,
    removeDynamicColumn,
    resetColumns,
  } = model;
  return (
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
          {table.getAllLeafColumns().map((column) =>
            column.id === "selection" ? null : (
              <div key={column.id}>
                <Checkbox
                  aria-label={`Show ${columnLabels[column.id] ?? columnLabel(column.id)} column`}
                  checked={column.getIsVisible()}
                  disabled={!column.getCanHide()}
                  onCheckedChange={(checked) =>
                    column.toggleVisibility(checked === true)
                  }
                />
                <span>{columnLabels[column.id] ?? columnLabel(column.id)}</span>
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
            ),
          )}
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
                  {item.source === "custom_field" ? "Custom field" : "SLA"} · v
                  {item.definitionVersion}
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
        <Rows3 aria-hidden="true" /> Arrow keys move between rows; Enter opens.
      </span>
    </div>
  );
}

type StateUpdater<T> = T | ((current: T) => T);
interface TableColumnState {
  columnPinning: ColumnPinningState;
  columnSizing: ColumnSizingState;
  columnVisibility: ColumnVisibilityState;
}
interface TableLayoutSnapshot extends TableColumnState {
  baselineColumns: TicketTableColumnSpec[];
  schemaSignature: string;
  selectionScope: string;
}
interface TableInteractionSnapshot {
  activeRowId: string | null;
  loadedIdSignature: string;
  rowSelection: RowSelectionState;
  selectionResetToken: number;
  selectionScope: string;
}
function resolveStateUpdate<T extends object>(
  update: StateUpdater<T>,
  current: T,
): T {
  return typeof update === "function" ? update(current) : update;
}
function tableLayoutSnapshot(
  columns: readonly TicketTableColumnSpec[],
  selectionScope: string,
  schemaSignature: string,
): TableLayoutSnapshot {
  return {
    baselineColumns: cloneColumns(columns),
    columnPinning: pinningFromColumns(columns),
    columnSizing: sizingFromColumns(columns),
    columnVisibility: visibilityFromColumns(columns),
    selectionScope,
    schemaSignature,
  };
}
function reconcileTableInteraction(
  current: TableInteractionSnapshot,
  selectionScope: string,
  selectionResetToken: number,
  loadedIdSignature: string,
): TableInteractionSnapshot {
  const loadedIds = new Set(
    loadedIdSignature === "" ? [] : loadedIdSignature.split("|"),
  );
  const scopeChanged = current.selectionScope !== selectionScope;
  const resetSelection =
    scopeChanged || current.selectionResetToken !== selectionResetToken;
  const rowSelection = resetSelection
    ? {}
    : Object.fromEntries(
        Object.entries(current.rowSelection).filter(([id]) =>
          loadedIds.has(id),
        ),
      );
  const activeRowId =
    !scopeChanged &&
    current.activeRowId !== null &&
    loadedIds.has(current.activeRowId)
      ? current.activeRowId
      : null;
  return {
    selectionScope,
    selectionResetToken,
    loadedIdSignature,
    rowSelection,
    activeRowId,
  };
}
function selectedTicketTargets(
  items: readonly TicketProjection[],
  rowSelection: RowSelectionState,
): TicketBulkTargetPin[] {
  const targets: TicketBulkTargetPin[] = [];
  for (const item of items) {
    if (rowSelection[item.id] === true)
      targets.push({ id: item.id, expectedVersion: item.version });
  }
  return targets;
}
