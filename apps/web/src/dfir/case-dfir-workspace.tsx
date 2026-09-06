import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import {
  FileKey2,
  Fingerprint,
  Link2,
  ListChecks,
  MonitorCog,
  Network,
  Plus,
  ShieldCheck,
} from "lucide-react";
import { memo, useState, type KeyboardEvent, type ReactNode } from "react";

import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  compactDigest,
  formatEvidenceBytes,
  safeAlertDfirProblem,
  safeDfirProblem,
  type DfirAlertData,
  type DfirAlertPanel,
  type DfirCaseData,
  type DfirPanel,
  type DfirPermission,
  type DfirProblem,
  type EvidenceView,
} from "./model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./case-dfir-workspace.css";

const panels = [
  {
    id: "iocs",
    label: "IOC",
    permission: "dfir.ioc.manage",
    icon: Fingerprint,
  },
  {
    id: "assets",
    label: "Assets",
    permission: "dfir.asset.manage",
    icon: MonitorCog,
  },
  {
    id: "evidence",
    label: "Evidence",
    permission: "dfir.evidence.manage",
    icon: ShieldCheck,
  },
  {
    id: "timeline",
    label: "Timeline",
    permission: "dfir.timeline.manage",
    icon: Network,
  },
  {
    id: "tasks",
    label: "Tasks",
    permission: "dfir.task.manage",
    icon: ListChecks,
  },
  {
    id: "attachments",
    label: "Files",
    permission: "dfir.attachment.manage",
    icon: FileKey2,
  },
  {
    id: "relationships",
    label: "Links",
    permission: "dfir.relationship.manage",
    icon: Link2,
  },
] as const satisfies readonly {
  id: DfirPanel;
  label: string;
  permission: DfirPermission;
  icon: typeof Fingerprint;
}[];

const alertPanels = panels;

export interface CaseDfirWorkspaceProps {
  data: DfirCaseData;
  hasPermission: (permission: DfirPermission) => boolean;
  problem?: DfirProblem;
  busy?: boolean;
  initialPanel?: DfirPanel;
  onCreate: (panel: DfirPanel) => void;
  onOpen: (panel: DfirPanel, id: string) => void;
}

export function CaseDfirWorkspace({
  data,
  hasPermission,
  problem,
  busy = false,
  initialPanel = "iocs",
  onCreate,
  onOpen,
}: CaseDfirWorkspaceProps) {
  const [active, setActive] = useState<DfirPanel>(initialPanel);
  const activeConfig = panels.find((panel) => panel.id === active) ?? panels[0];
  const canManage = hasPermission(activeConfig.permission);

  return (
    <section
      className="dfir-workspace"
      aria-labelledby="dfir-workspace-title"
      aria-busy={busy || undefined}
    >
      <header className="dfir-workspace__heading">
        <div>
          <p className="section-label">Investigation record</p>
          <h2 id="dfir-workspace-title">Case evidence room</h2>
          <p>
            Correlate observables, systems, evidence provenance, and response
            work in one record.
          </p>
        </div>
        {canManage ? (
          <Button
            type="button"
            disabled={busy}
            onClick={() => onCreate(active)}
          >
            <Plus aria-hidden="true" /> Add {activeConfig.label.toLowerCase()}
          </Button>
        ) : null}
      </header>

      {problem ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Investigation action not completed</AlertTitle>
          <AlertDescription>{safeDfirProblem(problem)}</AlertDescription>
        </Alert>
      ) : null}

      <div
        className="dfir-workspace__tabs"
        role="tablist"
        aria-label="Case investigation sections"
      >
        {panels.map((panel) => {
          const Icon = panel.icon;
          const count = data[panel.id].length;
          return (
            <button
              key={panel.id}
              id={`dfir-tab-${panel.id}`}
              type="button"
              role="tab"
              aria-selected={active === panel.id}
              aria-controls={`dfir-panel-${panel.id}`}
              tabIndex={active === panel.id ? 0 : -1}
              onClick={() => setActive(panel.id)}
              onKeyDown={moveTabFocus}
            >
              <Icon aria-hidden="true" />
              <span>{panel.label}</span>
              <strong>{count}</strong>
            </button>
          );
        })}
      </div>

      <div
        id={`dfir-panel-${active}`}
        className="dfir-workspace__panel"
        role="tabpanel"
        aria-labelledby={`dfir-tab-${active}`}
      >
        <PanelContent panel={active} data={data} onOpen={onOpen} />
      </div>
    </section>
  );
}

export interface AlertDfirWorkspaceProps {
  data: DfirAlertData;
  hasPermission: (permission: DfirPermission) => boolean;
  problem?: DfirProblem;
  busy?: boolean;
  initialPanel?: DfirAlertPanel;
  onCreate: (panel: DfirAlertPanel) => void;
  onOpen: (panel: DfirAlertPanel, id: string) => void;
}

export function AlertDfirWorkspace({
  data,
  hasPermission,
  problem,
  busy = false,
  initialPanel = "iocs",
  onCreate,
  onOpen,
}: AlertDfirWorkspaceProps): React.JSX.Element {
  const [active, setActive] = useState<DfirAlertPanel>(initialPanel);
  const activeConfig =
    alertPanels.find((panel) => panel.id === active) ?? alertPanels[0];
  const canManage = hasPermission(activeConfig.permission);
  return (
    <section
      className="dfir-workspace"
      aria-labelledby="alert-dfir-workspace-title"
      aria-busy={busy || undefined}
    >
      <header className="dfir-workspace__heading">
        <div>
          <p className="section-label">Triage record</p>
          <h2 id="alert-dfir-workspace-title">Alert investigation room</h2>
          <p>
            Preserve observables, affected systems, chronology, and protected
            source files before choosing exactly what crosses into a Case.
          </p>
        </div>
        {canManage ? (
          <Button
            type="button"
            disabled={busy}
            onClick={() => onCreate(active)}
          >
            <Plus aria-hidden="true" /> Add {activeConfig.label.toLowerCase()}
          </Button>
        ) : null}
      </header>

      {problem ? (
        <Alert variant="destructive" role="alert">
          <AlertTitle>Investigation action not completed</AlertTitle>
          <AlertDescription>{safeAlertDfirProblem(problem)}</AlertDescription>
        </Alert>
      ) : null}

      <div
        className="dfir-workspace__tabs"
        role="tablist"
        aria-label="Alert investigation sections"
      >
        {alertPanels.map((panel) => {
          const Icon = panel.icon;
          return (
            <button
              key={panel.id}
              id={`alert-dfir-tab-${panel.id}`}
              type="button"
              role="tab"
              aria-selected={active === panel.id}
              aria-controls={`alert-dfir-panel-${panel.id}`}
              tabIndex={active === panel.id ? 0 : -1}
              onClick={() => setActive(panel.id)}
              onKeyDown={moveTabFocus}
            >
              <Icon aria-hidden="true" />
              <span>{panel.label}</span>
              <strong>{data[panel.id].length}</strong>
            </button>
          );
        })}
      </div>

      <div
        id={`alert-dfir-panel-${active}`}
        className="dfir-workspace__panel"
        role="tabpanel"
        aria-labelledby={`alert-dfir-tab-${active}`}
      >
        <PanelContent
          panel={active}
          data={data}
          onOpen={onOpen}
          subjectLabel="Alert"
        />
      </div>
    </section>
  );
}

function RelatedTickets({
  roots,
}: {
  roots: readonly { kind: "case" | "alert"; id: string }[];
}) {
  if (roots.length === 0) return null;
  return (
    <details className="dfir-related-tickets">
      <summary>Linked tickets ({roots.length})</summary>
      <ul>
        {roots.map((root) => (
          <li key={`${root.kind}:${root.id}`}>
            <a
              href={`/${root.kind === "case" ? "cases" : "alerts"}/${root.id}`}
            >
              {root.kind === "case" ? "Case" : "Alert"} {root.id}
            </a>
          </li>
        ))}
      </ul>
    </details>
  );
}

function PanelContent({
  panel,
  data,
  onOpen,
  subjectLabel = "Case",
}: Pick<CaseDfirWorkspaceProps, "data" | "onOpen"> & {
  panel: DfirPanel;
  subjectLabel?: "Alert" | "Case";
}) {
  switch (panel) {
    case "iocs":
      return (
        <RecordGrid
          empty={`No indicators are linked to this ${subjectLabel} yet.`}
        >
          {data.iocs.map((ioc) => (
            <RecordCard
              key={ioc.id}
              title={ioc.value}
              eyebrow={ioc.type}
              onOpen={() => onOpen(panel, ioc.id)}
            >
              <div className="dfir-record__badges">
                <Badge>{ioc.malicious}</Badge>
                <Badge variant="outline">TLP {ioc.tlp}</Badge>
                <Badge variant="secondary">{ioc.confidence}%</Badge>
              </div>
              <p>
                {ioc.tags.length > 0 ? ioc.tags.join(" · ") : "No analyst tags"}
              </p>
              <RelatedTickets roots={ioc.relatedRoots} />
            </RecordCard>
          ))}
        </RecordGrid>
      );
    case "assets":
      return (
        <RecordGrid
          empty={`No systems or identities are linked to this ${subjectLabel} yet.`}
        >
          {data.assets.map((asset) => (
            <RecordCard
              key={asset.id}
              title={asset.hostname || asset.fqdn || "Addressed asset"}
              eyebrow={asset.assetType}
              onOpen={() => onOpen(panel, asset.id)}
            >
              <div className="dfir-record__badges">
                <Badge>{asset.criticality}</Badge>
                <Badge variant="outline">{asset.environment}</Badge>
              </div>
              <p>
                {asset.addresses.length > 0
                  ? asset.addresses.join(" · ")
                  : "No network address recorded"}
              </p>
              <RelatedTickets roots={asset.relatedRoots} />
            </RecordCard>
          ))}
        </RecordGrid>
      );
    case "evidence":
      return (
        <EvidencePanel
          evidence={data.evidence}
          onOpen={(id) => onOpen(panel, id)}
          subjectLabel={subjectLabel}
        />
      );
    case "timeline":
      return (
        <ol className="dfir-timeline">
          {data.timeline.map((event) => (
            <li key={event.id}>
              <TenantInstant value={event.eventTime} />
              <button type="button" onClick={() => onOpen(panel, event.id)}>
                <span>
                  {event.category} · {event.precision}
                </span>
                <strong>{event.title}</strong>
                <small>{event.source}</small>
              </button>
            </li>
          ))}
          {data.timeline.length === 0 ? (
            <EmptyRecord>No timeline events are recorded.</EmptyRecord>
          ) : null}
        </ol>
      );
    case "tasks":
      return (
        <RecordGrid empty="No investigation tasks are open.">
          {data.tasks.map((task) => (
            <RecordCard
              key={task.id}
              title={task.title}
              eyebrow={task.priority}
              onOpen={() => onOpen(panel, task.id)}
            >
              <div className="dfir-record__badges">
                <Badge>{task.status.replaceAll("_", " ")}</Badge>
                <Badge variant="outline">
                  {task.checklistCompleted}/{task.checklistTotal} checks
                </Badge>
              </div>
              <p>
                {task.assigneeLabel ?? "Unassigned"}
                {task.dueAt ? (
                  <>
                    {" "}
                    · Due <TenantInstant value={task.dueAt} />
                  </>
                ) : null}
              </p>
            </RecordCard>
          ))}
        </RecordGrid>
      );
    case "attachments":
      return (
        <RecordGrid
          empty={`No files are attached to this ${subjectLabel} record.`}
        >
          {data.attachments.map((attachment) => (
            <RecordCard
              key={attachment.id}
              title={attachment.filename}
              eyebrow={attachment.visibility}
              onOpen={() => onOpen(panel, attachment.id)}
            >
              <div className="dfir-record__badges">
                <Badge>{attachment.scanState.replaceAll("_", " ")}</Badge>
                {attachment.sizeBytes === undefined ? null : (
                  <Badge variant="outline">
                    {formatEvidenceBytes(attachment.sizeBytes)}
                  </Badge>
                )}
              </div>
              <p>
                Added <TenantInstant value={attachment.uploadedAt} />
              </p>
            </RecordCard>
          ))}
        </RecordGrid>
      );
    case "relationships":
      return (
        <div className="dfir-relationships">
          {data.relationships.map((relationship) => (
            <button
              key={relationship.id}
              type="button"
              onClick={() => onOpen(panel, relationship.id)}
            >
              <span>{relationship.sourceLabel}</span>
              <strong>
                {relationship.relationshipType.replaceAll("_", " ")}
              </strong>
              <span>{relationship.targetLabel}</span>
            </button>
          ))}
          {data.relationships.length === 0 ? (
            <EmptyRecord>
              No investigation relationships are recorded.
            </EmptyRecord>
          ) : null}
        </div>
      );
    default:
      return null;
  }
}

function EvidencePanel({
  evidence,
  onOpen,
  subjectLabel,
}: {
  evidence: readonly EvidenceView[];
  onOpen: (id: string) => void;
  subjectLabel: "Alert" | "Case";
}) {
  if (evidence.length === 0)
    return (
      <EmptyRecord>
        No evidence has entered custody for this {subjectLabel}.
      </EmptyRecord>
    );
  return (
    <div className="dfir-evidence-grid">
      {evidence.map((item) => (
        <Card key={item.id} className="dfir-evidence">
          <CardHeader>
            <div>
              <p className="section-label">
                {item.evidenceType.replaceAll("_", " ")}
              </p>
              <CardTitle>{item.title}</CardTitle>
            </div>
            <Badge variant={item.legalHold ? "destructive" : "secondary"}>
              {item.legalHold
                ? "Legal hold"
                : item.scanState.replaceAll("_", " ")}
            </Badge>
          </CardHeader>
          <CardContent>
            <dl className="dfir-evidence__facts">
              <div>
                <dt>Classification</dt>
                <dd>{item.classification}</dd>
              </div>
              <div>
                <dt>Size</dt>
                <dd>{formatEvidenceBytes(item.sizeBytes)}</dd>
              </div>
              <div>
                <dt>SHA-256</dt>
                <dd>
                  <code title="Full digest available in the authorized evidence detail">
                    {compactDigest(item.sha256)}
                  </code>
                </dd>
              </div>
            </dl>
            <CustodyHistory title={item.title} custody={item.custody} />
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpen(item.id)}
            >
              Open custody record
            </Button>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

const CustodyHistory = memo(function CustodyHistory({
  title,
  custody,
}: Pick<EvidenceView, "title" | "custody">) {
  return (
    <div className="dfir-custody" aria-label={`Custody history for ${title}`}>
      {custody.map((event) => (
        <div key={event.id}>
          <span aria-hidden="true">{event.sequence}</span>
          <p>
            <strong>{event.action.replaceAll("_", " ")}</strong>
            <small>
              <TenantInstant value={event.occurredAt} /> · {event.actorLabel}
            </small>
          </p>
        </div>
      ))}
    </div>
  );
});

function RecordGrid({
  children,
  empty,
}: {
  children: ReactNode;
  empty: string;
}) {
  const items = Array.isArray(children)
    ? children.filter(Boolean)
    : children
      ? [children]
      : [];
  if (items.length === 0) return <EmptyRecord>{empty}</EmptyRecord>;
  return <div className="dfir-record-grid">{children}</div>;
}

function RecordCard({
  title,
  eyebrow,
  children,
  onOpen,
}: {
  title: string;
  eyebrow: string;
  children: ReactNode;
  onOpen: () => void;
}) {
  return (
    <button type="button" className="dfir-record" onClick={onOpen}>
      <span className="section-label">{eyebrow}</span>
      <strong>{title}</strong>
      {children}
    </button>
  );
}

function EmptyRecord({ children }: { children: ReactNode }) {
  return (
    <p className="dfir-empty" role="status">
      {children}
    </p>
  );
}

function moveTabFocus(event: KeyboardEvent<HTMLButtonElement>) {
  if (
    event.key !== "ArrowLeft" &&
    event.key !== "ArrowRight" &&
    event.key !== "Home" &&
    event.key !== "End"
  )
    return;
  const tabs = Array.from(
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>(
      "[role=tab]",
    ) ?? [],
  );
  const current = tabs.indexOf(event.currentTarget);
  if (current < 0 || tabs.length === 0) return;
  event.preventDefault();
  const next =
    event.key === "Home"
      ? 0
      : event.key === "End"
        ? tabs.length - 1
        : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) %
          tabs.length;
  tabs[next]?.focus();
  tabs[next]?.click();
}
