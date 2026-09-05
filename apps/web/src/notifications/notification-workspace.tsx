import { Badge } from "@periapsis/ui/components/ui/badge";
import {
  BellRing,
  Cable,
  FileText,
  MailCheck,
  RadioTower,
  Route,
  ShieldCheck,
} from "lucide-react";
import { useState, type KeyboardEvent } from "react";

import { DeliveriesPanel } from "./deliveries-panel";
import {
  notificationAdminApi,
  type NotificationAdminApi,
} from "./notification-api";
import { NotificationEmpty } from "./notification-primitives";
import { RulesPanel } from "./rules-panel";
import { TenantSmtpPanel } from "./smtp-panel";
import { TemplatesPanel } from "./templates-panel";
import { WebhooksPanel } from "./webhooks-panel";
import { WebhookUrlPolicyPanel } from "./webhook-url-policy-panel";
import type { NotificationPanel } from "./model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this module-owned stylesheet.
import "./notifications.css";

const panels = [
  { id: "rules", label: "Rules", detail: "Event routing", icon: Route },
  {
    id: "templates",
    label: "Templates",
    detail: "Rendered messages",
    icon: FileText,
  },
  { id: "smtp", label: "SMTP", detail: "Tenant relay", icon: MailCheck },
  {
    id: "deliveries",
    label: "Deliveries",
    detail: "Immutable ledger",
    icon: RadioTower,
  },
  { id: "webhooks", label: "Webhooks", detail: "Signed egress", icon: Cable },
  {
    id: "egress-policy",
    label: "Egress policy",
    detail: "Allow / deny hosts",
    icon: ShieldCheck,
  },
] as const satisfies readonly {
  detail: string;
  icon: typeof Route;
  id: NotificationPanel;
  label: string;
}[];

export interface TenantNotificationWorkspaceProps {
  api?: NotificationAdminApi;
  canManage: boolean;
  csrfToken: string;
  initialPanel?: NotificationPanel;
  tenantId: string;
  tenantLabel?: string;
}

export function TenantNotificationWorkspace({
  api = notificationAdminApi,
  canManage,
  csrfToken,
  initialPanel = "rules",
  tenantId,
  tenantLabel = "Active tenant",
}: TenantNotificationWorkspaceProps): React.JSX.Element {
  const [active, setActive] = useState<NotificationPanel>(initialPanel);

  if (!canManage) {
    return (
      <section className="notification-workspace notification-workspace--denied">
        <NotificationEmpty
          title="Notification authority required"
          detail="This client-side visibility check is advisory. Every operation is revalidated by the tenant API with notification.manage."
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
    document.getElementById(`notification-tab-${panels[next]!.id}`)?.focus();
  }

  return (
    <section
      className="notification-workspace"
      aria-labelledby="notification-workspace-title"
    >
      <header className="notification-workspace__heading">
        <div>
          <p className="section-label">Dispatch control / Phase 6</p>
          <h1 id="notification-workspace-title">Notification operations</h1>
          <p>
            Version routing and providers, inspect redacted delivery history,
            and test outbound paths without exposing protected material.
          </p>
        </div>
        <div className="notification-workspace__context">
          <BellRing aria-hidden="true" />
          <span>Tenant boundary</span>
          <strong>{tenantLabel}</strong>
          <Badge variant="outline">notification.manage</Badge>
        </div>
      </header>

      <div className="notification-console">
        <div
          className="notification-rail"
          role="tablist"
          aria-label="Notification administration sections"
          aria-orientation="vertical"
        >
          <div className="notification-rail__signal" aria-hidden="true">
            <span />
            <i />
          </div>
          {panels.map((panel, index) => {
            const Icon = panel.icon;
            return (
              <button
                key={panel.id}
                id={`notification-tab-${panel.id}`}
                type="button"
                role="tab"
                aria-controls={`notification-panel-${panel.id}`}
                aria-selected={active === panel.id}
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
            UI permission visibility reduces dead ends; it never authorizes a
            request.
          </p>
        </div>

        <div
          id={`notification-panel-${active}`}
          role="tabpanel"
          aria-labelledby={`notification-tab-${active}`}
          className="notification-console__panel"
        >
          {active === "rules" ? (
            <RulesPanel
              key={tenantId}
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "templates" ? (
            <TemplatesPanel
              key={tenantId}
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "smtp" ? (
            <TenantSmtpPanel
              key={tenantId}
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "deliveries" ? (
            <DeliveriesPanel
              key={tenantId}
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "webhooks" ? (
            <WebhooksPanel
              key={tenantId}
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
          {active === "egress-policy" ? (
            <WebhookUrlPolicyPanel
              key={tenantId}
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
            />
          ) : null}
        </div>
      </div>
    </section>
  );
}
