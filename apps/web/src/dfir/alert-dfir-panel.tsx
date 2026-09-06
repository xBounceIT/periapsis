import {
  AlertDfirPanelScope,
  type AlertDfirPanelProps,
} from "./alert-dfir-panel-scope";
export type { AlertDfirPanelProps } from "./alert-dfir-panel-scope";

export function AlertDfirPanel(props: AlertDfirPanelProps): React.JSX.Element {
  return (
    <AlertDfirPanelScope
      key={JSON.stringify([props.tenantId, props.alertId])}
      {...props}
    />
  );
}
