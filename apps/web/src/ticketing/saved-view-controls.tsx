import {
  SavedViewControlsScope,
  type SavedViewControlsProps,
} from "./saved-view-controls-scope";
export type { SavedViewControlsProps } from "./saved-view-controls-scope";

export function SavedViewControls(
  props: SavedViewControlsProps,
): React.JSX.Element {
  return (
    <SavedViewControlsScope
      key={JSON.stringify([
        props.tenantId,
        props.kind,
        props.selection.kind === "selected" ? props.selection.viewId : "",
      ])}
      {...props}
    />
  );
}
