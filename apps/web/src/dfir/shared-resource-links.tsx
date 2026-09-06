import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { useId, useRef, useState } from "react";

import { generateUuidV7 } from "../lib/uuid-v7";

export interface SharedLinkIntent {
  eventId: string;
  expectedVersion: number;
  linked: boolean;
  resourceId: string;
  resourceKind: "ioc" | "asset";
}

export function SharedResourceLinks({
  assets,
  busy,
  canManageAssets,
  canManageIndicators,
  indicators,
  onSubmit,
}: {
  assets: readonly { id: string; version: number }[];
  busy: boolean;
  canManageAssets: boolean;
  canManageIndicators: boolean;
  indicators: readonly { id: string; version: number }[];
  onSubmit: (intent: SharedLinkIntent) => void;
}): React.JSX.Element | null {
  const formId = useId();
  const [kind, setKind] = useState<"ioc" | "asset">("ioc");
  const [linked, setLinked] = useState(true);
  const [resourceId, setResourceId] = useState("");
  const [version, setVersion] = useState("1");
  const [selectedId, setSelectedId] = useState("");
  const intentRef = useRef<{ fingerprint: string; eventId: string } | null>(
    null,
  );
  if (!canManageAssets && !canManageIndicators) return null;
  const resourceKind =
    canManageIndicators && (!canManageAssets || kind === "ioc")
      ? "ioc"
      : "asset";
  const inventory = resourceKind === "ioc" ? indicators : assets;
  const selected = inventory.find((item) => item.id === selectedId);
  function submit(event: React.FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    const expectedVersion = linked ? Number(version) : selected?.version;
    const id = linked ? resourceId : selected?.id;
    if (
      busy ||
      !id ||
      expectedVersion === undefined ||
      !Number.isSafeInteger(expectedVersion) ||
      expectedVersion < 1 ||
      expectedVersion >= Number.MAX_SAFE_INTEGER
    )
      return;
    const fingerprint = JSON.stringify({
      expectedVersion,
      linked,
      resourceId: id,
      resourceKind,
    });
    if (intentRef.current?.fingerprint !== fingerprint) {
      intentRef.current = { fingerprint, eventId: generateUuidV7() };
    }
    onSubmit({
      expectedVersion,
      linked,
      resourceId: id,
      resourceKind,
      eventId: intentRef.current.eventId,
    });
  }
  return (
    <details className="dfir-shared-link-controls">
      <summary>Shared resource links</summary>
      <p>
        Link an existing IOC or asset using its identifier and current version.
        Managing a shared resource requires access to every linked ticket.
      </p>
      <form className="dfir-resource-form" onSubmit={submit}>
        <div className="dfir-resource-form__field">
          <Label htmlFor={`${formId}-action`}>Link action</Label>
          <select
            id={`${formId}-action`}
            disabled={busy}
            value={linked ? "link" : "unlink"}
            onChange={(event) =>
              setLinked(event.currentTarget.value === "link")
            }
          >
            <option value="link">Link existing resource</option>
            <option value="unlink">Unlink from this ticket</option>
          </select>
        </div>
        <div className="dfir-resource-form__field">
          <Label htmlFor={`${formId}-kind`}>Resource type</Label>
          <select
            id={`${formId}-kind`}
            disabled={busy}
            value={resourceKind}
            onChange={(event) =>
              setKind(event.currentTarget.value === "asset" ? "asset" : "ioc")
            }
          >
            {canManageIndicators ? <option value="ioc">IOC</option> : null}
            {canManageAssets ? <option value="asset">Asset</option> : null}
          </select>
        </div>
        {linked ? (
          <>
            <div className="dfir-resource-form__field">
              <Label htmlFor={`${formId}-resource`}>Existing resource ID</Label>
              <Input
                id={`${formId}-resource`}
                disabled={busy}
                required
                pattern="[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                value={resourceId}
                onChange={(event) => setResourceId(event.currentTarget.value)}
              />
            </div>
            <div className="dfir-resource-form__field">
              <Label htmlFor={`${formId}-version`}>
                Current resource version
              </Label>
              <Input
                id={`${formId}-version`}
                disabled={busy}
                type="number"
                min={1}
                max={Number.MAX_SAFE_INTEGER - 1}
                step={1}
                required
                value={version}
                onChange={(event) => setVersion(event.currentTarget.value)}
              />
            </div>
          </>
        ) : (
          <SharedResourceUnlinkFields
            busy={busy}
            formId={formId}
            inventory={inventory}
            selected={selected}
            setSelectedId={setSelectedId}
          />
        )}
        <Button type="submit" disabled={busy || (!linked && !selected)}>
          {linked ? "Link resource" : "Confirm unlink"}
        </Button>
      </form>
    </details>
  );
}

interface SharedResourceUnlinkFieldsProps {
  busy: boolean;
  formId: string;
  inventory: readonly { id: string; version: number }[];
  selected: { id: string; version: number } | undefined;
  setSelectedId: React.Dispatch<React.SetStateAction<string>>;
}

function SharedResourceUnlinkFields({
  busy,
  formId,
  inventory,
  selected,
  setSelectedId,
}: SharedResourceUnlinkFieldsProps): React.JSX.Element {
  return (
    <>
      <div className="dfir-resource-form__field">
        <Label htmlFor={`${formId}-existing`}>Linked resource</Label>
        <select
          id={`${formId}-existing`}
          disabled={busy}
          required
          value={selected?.id ?? ""}
          onChange={(event) => setSelectedId(event.currentTarget.value)}
        >
          <option value="">Choose a resource</option>
          {inventory.map((item) => (
            <option key={item.id} value={item.id}>
              {item.id} · version {item.version}
            </option>
          ))}
        </select>
      </div>
      <p>
        The last link and links required by this ticket’s timeline or
        relationships cannot be removed.
      </p>
      <Label htmlFor={`${formId}-confirm`}>
        <input
          key={selected?.id ?? "empty"}
          id={`${formId}-confirm`}
          type="checkbox"
          required
          disabled={busy}
        />
        Remove this resource from this ticket
      </Label>
    </>
  );
}
