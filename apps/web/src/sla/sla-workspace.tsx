import { Badge } from "@periapsis/ui/components/ui/badge";
import {
  CalendarClock,
  Columns3,
  FlaskConical,
  Gauge,
  Radar,
} from "lucide-react";
import { useState, type KeyboardEvent } from "react";

import type { SlaAdminPanel } from "./model";
import type { SlaAdminApi } from "./sla-api";
import { CalendarPanel } from "./calendar-panel";
import { ColumnPanel } from "./column-panel";
import { PolicyPanel } from "./policy-panel";
import { SimulatorPanel } from "./simulator-panel";
import { SlaEmpty } from "./sla-primitives";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this module-owned stylesheet.
import "./sla.css";

const panels = [
  {
    id: "policies",
    label: "Policies",
    detail: "Match + metric clocks",
    icon: Gauge,
  },
  {
    id: "calendars",
    label: "Calendars",
    detail: "Business time + DST",
    icon: CalendarClock,
  },
  {
    id: "columns",
    label: "Columns",
    detail: "Materialized signals",
    icon: Columns3,
  },
  {
    id: "simulator",
    label: "Simulator",
    detail: "Pure timeline replay",
    icon: FlaskConical,
  },
] as const satisfies readonly {
  detail: string;
  icon: typeof Gauge;
  id: SlaAdminPanel;
  label: string;
}[];

export interface TenantSlaWorkspaceProps {
  api: SlaAdminApi;
  canManage: boolean;
  canRead: boolean;
  canSimulate: boolean;
  csrfToken: string;
  initialPanel?: SlaAdminPanel;
  tenantId: string;
  tenantLabel?: string;
}

export function TenantSlaWorkspace({
  api,
  canManage,
  canRead,
  canSimulate,
  csrfToken,
  initialPanel = "policies",
  tenantId,
  tenantLabel = "Active tenant",
}: TenantSlaWorkspaceProps): React.JSX.Element {
  const [active, setActive] = useState<SlaAdminPanel>(initialPanel);

  if (!canRead) {
    return (
      <section className="sla-workspace sla-workspace--denied">
        <SlaEmpty
          title="SLA authority required"
          detail="The administration API requires sla.read and revalidates every mutation with sla.manage or sla.simulate."
        />
      </section>
    );
  }

  function moveTab(
    event: KeyboardEvent<HTMLButtonElement>,
    index: number,
  ): void {
    let next = index;
    if (event.key === "ArrowDown" || event.key === "ArrowRight")
      next = (index + 1) % panels.length;
    else if (event.key === "ArrowUp" || event.key === "ArrowLeft")
      next = (index - 1 + panels.length) % panels.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = panels.length - 1;
    else return;
    event.preventDefault();
    setActive(panels[next]!.id);
    document.getElementById(`sla-tab-${panels[next]!.id}`)?.focus();
  }

  return (
    <section className="sla-workspace" aria-labelledby="sla-workspace-title">
      <header className="sla-workspace__heading">
        <div>
          <p className="section-label">Phase 5 / governed service clocks</p>
          <h1 id="sla-workspace-title">SLA control room</h1>
          <p>
            Publish immutable policy, calendar, and column versions; then prove
            deadlines and trigger schedules against a bounded timeline before
            activation.
          </p>
        </div>
        <div className="sla-workspace__context">
          <Radar aria-hidden="true" />
          <span>Tenant boundary</span>
          <strong>{tenantLabel}</strong>
          <div>
            <Badge variant="outline">sla.read</Badge>
            {canManage ? <Badge variant="outline">sla.manage</Badge> : null}
          </div>
        </div>
      </header>

      <div className="sla-console">
        <div
          className="sla-rail"
          role="tablist"
          aria-label="SLA administration sections"
          aria-orientation="vertical"
        >
          <div className="sla-rail__orbit" aria-hidden="true">
            <span />
            <i />
            <b />
          </div>
          {panels.map((panel, index) => {
            const Icon = panel.icon;
            const unavailable = panel.id === "simulator" && !canSimulate;
            return (
              <button
                key={panel.id}
                id={`sla-tab-${panel.id}`}
                type="button"
                role="tab"
                aria-controls={`sla-panel-${panel.id}`}
                aria-selected={active === panel.id}
                aria-disabled={unavailable}
                tabIndex={active === panel.id ? 0 : -1}
                onClick={() => setActive(panel.id)}
                onKeyDown={(event) => moveTab(event, index)}
              >
                <Icon aria-hidden="true" />
                <span>
                  <strong>{panel.label}</strong>
                  <small>{panel.detail}</small>
                </span>
              </button>
            );
          })}
          <p>
            Published versions are append-only. Browser visibility never
            authorizes an SLA operation.
          </p>
        </div>

        <div
          id={`sla-panel-${active}`}
          role="tabpanel"
          aria-labelledby={`sla-tab-${active}`}
          className="sla-console__panel"
        >
          {active === "policies" ? (
            <PolicyPanel
              key={tenantId}
              api={api}
              canManage={canManage}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "calendars" ? (
            <CalendarPanel
              key={tenantId}
              api={api}
              canManage={canManage}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "columns" ? (
            <ColumnPanel
              key={tenantId}
              api={api}
              canManage={canManage}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "simulator" ? (
            <SimulatorPanel
              key={tenantId}
              api={api}
              canSimulate={canSimulate}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
        </div>
      </div>
    </section>
  );
}
