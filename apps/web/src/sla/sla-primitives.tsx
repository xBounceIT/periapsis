import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { LoaderCircle, RefreshCw, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import { safeSlaError } from "./model";

export function SlaError({
  error,
  fallback,
}: {
  error: unknown;
  fallback: string;
}): React.JSX.Element {
  return (
    <Alert variant="destructive">
      <ShieldAlert aria-hidden="true" />
      <AlertTitle>SLA action not completed</AlertTitle>
      <AlertDescription>{safeSlaError(error, fallback)}</AlertDescription>
    </Alert>
  );
}

export function SlaLoading({ label }: { label: string }): React.JSX.Element {
  return (
    <div className="sla-loading" role="status">
      <LoaderCircle aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function SlaEmpty({
  action,
  detail,
  title,
}: {
  action?: ReactNode;
  detail: string;
  title: string;
}): React.JSX.Element {
  return (
    <div className="sla-empty">
      <span className="sla-empty__orbit" aria-hidden="true">
        <i />
      </span>
      <div>
        <strong>{title}</strong>
        <p>{detail}</p>
      </div>
      {action}
    </div>
  );
}

export function SlaInventoryHeading({
  busy,
  count,
  eyebrow,
  label,
  onRefresh,
}: {
  busy: boolean;
  count: number;
  eyebrow: string;
  label: string;
  onRefresh: () => void;
}): React.JSX.Element {
  return (
    <div className="sla-inventory__heading">
      <div>
        <p className="section-label">{eyebrow}</p>
        <h2>{label}</h2>
      </div>
      <div className="sla-inventory__meta">
        <Badge variant="outline">{count} loaded</Badge>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={busy}
          onClick={onRefresh}
        >
          <RefreshCw aria-hidden="true" /> Refresh
        </Button>
      </div>
    </div>
  );
}

export function SlaNativeSelect<T extends string>({
  disabled = false,
  id,
  label,
  onChange,
  options,
  value,
}: {
  disabled?: boolean;
  id: string;
  label: string;
  onChange: (value: T) => void;
  options: readonly T[];
  value: T;
}): React.JSX.Element {
  return (
    <label className="sla-native-select" htmlFor={id}>
      <span>{label}</span>
      <select
        disabled={disabled}
        id={id}
        value={value}
        onChange={(event) => {
          const selected = options.find(
            (option) => option === event.target.value,
          );
          if (selected !== undefined) onChange(selected);
        }}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {option.replaceAll("_", " ")}
          </option>
        ))}
      </select>
    </label>
  );
}
