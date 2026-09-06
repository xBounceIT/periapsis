import {
  TicketExportControlsScope,
  type TicketExportControlsProps,
} from "./ticket-export-controls-scope";
export type { TicketExportControlsProps } from "./ticket-export-controls-scope";

export function TicketExportControls(
  props: TicketExportControlsProps,
): React.JSX.Element {
  return (
    <TicketExportControlsScope
      key={JSON.stringify([props.tenantId, props.kind])}
      {...props}
    />
  );
}
