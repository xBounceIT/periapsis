import {
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";

export function TableColumnHeaders({
  columns,
  actionLabel,
  actionPresentation = "hidden",
}: {
  columns: readonly string[];
  actionLabel?: string;
  actionPresentation?: "hidden" | "visible";
}): React.JSX.Element {
  return (
    <TableHeader>
      <TableRow>
        {columns.map((column) => (
          <TableHead key={column}>{column}</TableHead>
        ))}
        {actionLabel ? (
          <TableHead
            className={
              actionPresentation === "visible" ? "text-right" : undefined
            }
          >
            {actionPresentation === "visible" ? (
              actionLabel
            ) : (
              <span className="sr-only">{actionLabel}</span>
            )}
          </TableHead>
        ) : null}
      </TableRow>
    </TableHeader>
  );
}
