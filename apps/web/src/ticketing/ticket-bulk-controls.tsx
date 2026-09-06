import {
  TicketBulkControlsScope,
  type TicketBulkControlsProps,
} from "./ticket-bulk-controls-scope";
export type {
  TicketBulkAction,
  TicketBulkControlsProps,
} from "./ticket-bulk-controls-scope";

export function TicketBulkControls(
  props: TicketBulkControlsProps,
): React.JSX.Element {
  return (
    <TicketBulkControlsScope
      key={JSON.stringify([props.tenantId, props.kind])}
      {...props}
    />
  );
}
