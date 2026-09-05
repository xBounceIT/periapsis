import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { LoaderCircle, RefreshCw, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import { safeNotificationError } from "./model";

export function NotificationError({
  error,
  fallback,
}: {
  error: unknown;
  fallback: string;
}): React.JSX.Element {
  return (
    <Alert variant="destructive">
      <ShieldAlert aria-hidden="true" />
      <AlertTitle>Notification action not completed</AlertTitle>
      <AlertDescription>
        {safeNotificationError(error, fallback)}
      </AlertDescription>
    </Alert>
  );
}

export function NotificationLoading({ label }: { label: string }) {
  return (
    <div className="notification-loading" role="status">
      <LoaderCircle aria-hidden="true" />
      <span>{label}</span>
    </div>
  );
}

export function NotificationEmpty({
  action,
  detail,
  title,
}: {
  action?: ReactNode;
  detail: string;
  title: string;
}) {
  return (
    <div className="notification-empty">
      <span className="notification-pulse" aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <p>{detail}</p>
      </div>
      {action}
    </div>
  );
}

export function InventoryHeading({
  busy,
  count,
  label,
  onRefresh,
}: {
  busy: boolean;
  count: number;
  label: string;
  onRefresh: () => void;
}) {
  return (
    <div className="notification-inventory__heading">
      <div>
        <p className="section-label">Authorized projection</p>
        <h2>{label}</h2>
      </div>
      <div className="notification-inventory__meta">
        <Badge variant="outline">{count} loaded</Badge>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={busy}
          onClick={onRefresh}
        >
          <RefreshCw
            className={busy ? "is-spinning" : undefined}
            aria-hidden="true"
          />
          Refresh
        </Button>
      </div>
    </div>
  );
}

export function EditorActions({
  busy,
  children,
  submitLabel,
}: {
  busy: boolean;
  children?: ReactNode;
  submitLabel: string;
}) {
  return (
    <div className="notification-editor__actions">
      <Button type="submit" disabled={busy}>
        {busy ? (
          <LoaderCircle className="is-spinning" aria-hidden="true" />
        ) : null}
        {submitLabel}
      </Button>
      {children}
    </div>
  );
}
