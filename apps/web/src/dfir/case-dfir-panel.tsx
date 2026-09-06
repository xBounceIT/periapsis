import {
  CaseDfirPanelScope,
  type CaseDfirPanelProps,
} from "./case-dfir-panel-scope";
export type { CaseDfirPanelProps } from "./case-dfir-panel-scope";

export function CaseDfirPanel(props: CaseDfirPanelProps): React.JSX.Element {
  return (
    <CaseDfirPanelScope
      key={JSON.stringify([props.tenantId, props.caseId])}
      {...props}
    />
  );
}
