import type { SystemStatus } from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Database, Radar, ShieldCheck } from "lucide-react";

import { formatCheckedAt } from "../lib/system-status";

interface StatusPanelProps {
  status: SystemStatus;
}

export function StatusPanel({ status }: StatusPanelProps): React.JSX.Element {
  const ready = status.status === "ready";

  return (
    <Card className="status-card" aria-labelledby="system-status-title">
      <CardHeader className="status-card__header">
        <div>
          <p className="section-label">Live telemetry</p>
          <CardTitle id="system-status-title" className="status-card__title">
            Platform boundary
          </CardTitle>
          <CardDescription>
            This check is returned by the running Go API, not fixture data.
          </CardDescription>
        </div>
        <Badge variant={ready ? "secondary" : "destructive"}>
          <span className="status-dot" aria-hidden="true" />
          {ready ? "Ready" : "Degraded"}
        </Badge>
      </CardHeader>
      <CardContent className="status-grid">
        <StatusDatum
          icon={<Radar aria-hidden="true" />}
          label="API service"
          value={status.version}
        />
        <StatusDatum
          icon={<Database aria-hidden="true" />}
          label="Tenant boundary"
          value="Shared schema + RLS"
        />
        <StatusDatum
          icon={<ShieldCheck aria-hidden="true" />}
          label="Last verified"
          value={formatCheckedAt(status.checkedAt, navigator.language)}
        />
      </CardContent>
    </Card>
  );
}

interface StatusDatumProps {
  icon: React.ReactNode;
  label: string;
  value: string;
}

function StatusDatum({
  icon,
  label,
  value,
}: StatusDatumProps): React.JSX.Element {
  return (
    <div className="status-datum">
      <div className="status-datum__icon">{icon}</div>
      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}
