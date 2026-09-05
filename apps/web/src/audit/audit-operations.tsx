import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import type { AuditExportJob, AuditRetentionState } from "@periapsis/contracts";
import {
  Archive,
  Ban,
  Download,
  FileDown,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  ShieldAlert,
  ShieldOff,
} from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";

import { TenantInstant } from "../lib/tenant-date-time-context";
import { AuditApiError } from "./audit-api";
import {
  auditOperationsApi,
  type AuditOperationsApi,
  type AuditOperationsScope,
} from "./audit-operations-api";
import { compactAuditIdentifier, type AuditQuery } from "./model";

interface AuditOperationsProps {
  api?: AuditOperationsApi;
  canExport: boolean;
  canManageRetention: boolean;
  csrfToken: string;
  filters: AuditQuery;
  onBoundaryError: (error: unknown) => void;
  scope: AuditOperationsScope;
}

type DialogKind = "export" | "retention" | null;

export function AuditOperations({
  api = auditOperationsApi,
  canExport,
  canManageRetention,
  csrfToken,
  filters,
  onBoundaryError,
  scope,
}: AuditOperationsProps): React.JSX.Element | null {
  const [dialog, setDialog] = useState<DialogKind>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exportReason, setExportReason] = useState("");
  const [retentionSeconds, setRetentionSeconds] = useState(86_400);
  const [job, setJob] = useState<AuditExportJob | null>(null);
  const [cancelReason, setCancelReason] = useState("");
  const [retention, setRetention] = useState<AuditRetentionState | null>(null);
  const [retentionDays, setRetentionDays] = useState(365);
  const [retentionReason, setRetentionReason] = useState("");
  const [holdConfirmed, setHoldConfirmed] = useState(false);
  const controller = useRef<AbortController | null>(null);

  useEffect(() => () => controller.current?.abort(), []);

  if (!canExport && !canManageRetention) return null;

  function beginRequest(): AbortController {
    controller.current?.abort();
    const next = new AbortController();
    controller.current = next;
    setBusy(true);
    setError(null);
    return next;
  }

  function finishRequest(current: AbortController): void {
    if (controller.current === current) {
      controller.current = null;
      setBusy(false);
    }
  }

  function report(errorValue: unknown, fallback: string): void {
    onBoundaryError(errorValue);
    setError(
      errorValue instanceof AuditApiError ? errorValue.message : fallback,
    );
  }

  async function createExport(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const current = beginRequest();
    try {
      const result = await api.createExport({
        csrfToken,
        filters,
        idempotencyKey: operationKey("export"),
        reason: exportReason,
        retentionSeconds,
        scope,
        signal: current.signal,
      });
      if (!current.signal.aborted) {
        setJob(result.job);
        setCancelReason("");
      }
    } catch (errorValue: unknown) {
      if (!current.signal.aborted) {
        report(errorValue, "The export could not be queued.");
      }
    } finally {
      finishRequest(current);
    }
  }

  async function refreshExport(): Promise<void> {
    if (!job) return;
    const current = beginRequest();
    try {
      const next = await api.getExport({
        exportId: job.id,
        scope,
        signal: current.signal,
      });
      if (!current.signal.aborted) setJob(next);
    } catch (errorValue: unknown) {
      if (!current.signal.aborted) {
        report(errorValue, "The export status could not be refreshed.");
      }
    } finally {
      finishRequest(current);
    }
  }

  async function cancelExport(): Promise<void> {
    if (!job) return;
    const current = beginRequest();
    try {
      const result = await api.cancelExport({
        csrfToken,
        expectedRevision: job.revision,
        exportId: job.id,
        idempotencyKey: operationKey("cancel"),
        reason: cancelReason,
        scope,
        signal: current.signal,
      });
      if (!current.signal.aborted) setJob(result.job);
    } catch (errorValue: unknown) {
      if (!current.signal.aborted) {
        report(errorValue, "The export could not be cancelled.");
      }
    } finally {
      finishRequest(current);
    }
  }

  async function downloadExport(): Promise<void> {
    if (!job || job.state !== "succeeded") return;
    const current = beginRequest();
    try {
      const file = await api.downloadExport({
        exportId: job.id,
        scope,
        signal: current.signal,
      });
      if (!current.signal.aborted) saveBlob(file.blob, file.filename);
    } catch (errorValue: unknown) {
      if (!current.signal.aborted) {
        report(
          errorValue,
          "The manifest-bound artifact could not be downloaded.",
        );
      }
    } finally {
      finishRequest(current);
    }
  }

  async function openRetention(): Promise<void> {
    setDialog("retention");
    const current = beginRequest();
    try {
      const next = await api.getRetention({ scope, signal: current.signal });
      if (!current.signal.aborted) {
        setRetention(next);
        setRetentionDays(next.policy.retentionDays);
        setRetentionReason("");
        setHoldConfirmed(false);
      }
    } catch (errorValue: unknown) {
      if (!current.signal.aborted) {
        report(errorValue, "The retention state could not be loaded.");
      }
    } finally {
      finishRequest(current);
    }
  }

  async function updateRetentionPolicy(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!retention) return;
    const current = beginRequest();
    try {
      const result = await api.updateRetention({
        csrfToken,
        expectedRevision: retention.policy.revision,
        idempotencyKey: operationKey("retention"),
        reason: retentionReason,
        retentionDays,
        scope,
        signal: current.signal,
      });
      if (!current.signal.aborted) {
        setRetention(result.state);
        setRetentionReason("");
      }
    } catch (errorValue: unknown) {
      if (!current.signal.aborted) {
        report(errorValue, "The retention policy could not be changed.");
      }
    } finally {
      finishRequest(current);
    }
  }

  async function mutateHold(): Promise<void> {
    if (!retention || !holdConfirmed) return;
    const current = beginRequest();
    try {
      if (retention.activeLegalHold) {
        await api.releaseLegalHold({
          csrfToken,
          expectedRevision: 1,
          holdId: retention.activeLegalHold.id,
          idempotencyKey: operationKey("hold-release"),
          reason: retentionReason,
          scope,
          signal: current.signal,
        });
      } else {
        await api.placeLegalHold({
          csrfToken,
          idempotencyKey: operationKey("hold-place"),
          reason: retentionReason,
          scope,
          signal: current.signal,
        });
      }
      if (!current.signal.aborted) {
        const next = await api.getRetention({ scope, signal: current.signal });
        if (!current.signal.aborted) {
          setRetention(next);
          setRetentionReason("");
          setHoldConfirmed(false);
        }
      }
    } catch (errorValue: unknown) {
      if (!current.signal.aborted) {
        report(errorValue, "The legal hold could not be changed.");
      }
    } finally {
      finishRequest(current);
    }
  }

  const canCancel =
    job !== null &&
    ["pending", "running", "cancellation_requested"].includes(job.state);

  return (
    <section className="audit-custody" aria-labelledby="audit-custody-title">
      <div className="audit-custody__mark" aria-hidden="true">
        <LockKeyhole />
      </div>
      <div className="audit-custody__copy">
        <p className="section-label">Chain custody / governed operations</p>
        <h2 id="audit-custody-title">Export & retention controls</h2>
        <p>
          Every command rechecks live authority and records a redacted reason.
        </p>
      </div>
      <div className="audit-custody__signals" aria-label="Custody state">
        {job ? (
          <Badge variant="outline">
            Export {job.state.replaceAll("_", " ")}
          </Badge>
        ) : null}
        {retention?.activeLegalHold ? (
          <Badge variant="outline">Legal hold active</Badge>
        ) : null}
      </div>
      <div className="audit-custody__actions">
        {canExport ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => setDialog("export")}
          >
            <FileDown aria-hidden="true" /> Export current view
          </Button>
        ) : null}
        {canManageRetention ? (
          <Button
            type="button"
            variant="outline"
            onClick={() => void openRetention()}
          >
            <Archive aria-hidden="true" /> Retention & hold
          </Button>
        ) : null}
      </div>

      <Dialog
        open={dialog === "export"}
        onOpenChange={(open) => setDialog(open ? "export" : null)}
      >
        <DialogContent className="audit-operation-dialog">
          <DialogHeader>
            <DialogTitle>Export the current redacted view</DialogTitle>
            <DialogDescription>
              The server snapshots these normalized filters, pins your live
              authority, and builds a JSONL artifact asynchronously.
            </DialogDescription>
          </DialogHeader>
          {job ? (
            <ExportStatus job={job} />
          ) : (
            <form
              id="audit-export-form"
              className="audit-operation-form"
              onSubmit={(event) => void createExport(event)}
            >
              <div className="audit-operation-form__field">
                <Label htmlFor="audit-export-reason">Redacted reason</Label>
                <Input
                  id="audit-export-reason"
                  value={exportReason}
                  onChange={(event) =>
                    setExportReason(event.currentTarget.value)
                  }
                  placeholder="Incident evidence review"
                  autoComplete="off"
                  maxLength={500}
                  required
                />
                <p>No names, customer payloads, credentials, or tokens.</p>
              </div>
              <div className="audit-operation-form__field">
                <Label htmlFor="audit-export-retention">
                  Artifact lifetime
                </Label>
                <select
                  id="audit-export-retention"
                  value={retentionSeconds}
                  onChange={(event) =>
                    setRetentionSeconds(Number(event.currentTarget.value))
                  }
                >
                  <option value={3_600}>1 hour</option>
                  <option value={86_400}>24 hours</option>
                  <option value={604_800}>7 days</option>
                </select>
              </div>
            </form>
          )}
          {error ? (
            <p className="audit-operation-error" role="alert">
              {error}
            </p>
          ) : null}
          {job ? (
            <div className="audit-operation-form">
              {canCancel ? (
                <div className="audit-operation-form__field">
                  <Label htmlFor="audit-export-cancel-reason">
                    Cancellation reason
                  </Label>
                  <Input
                    id="audit-export-cancel-reason"
                    value={cancelReason}
                    onChange={(event) =>
                      setCancelReason(event.currentTarget.value)
                    }
                    placeholder="Export no longer required"
                    autoComplete="off"
                    maxLength={500}
                  />
                </div>
              ) : null}
              <div className="audit-operation-inline-actions">
                <Button
                  type="button"
                  variant="outline"
                  disabled={busy}
                  onClick={() => void refreshExport()}
                >
                  <RefreshCw aria-hidden="true" /> Refresh status
                </Button>
                {canCancel ? (
                  <Button
                    type="button"
                    variant="destructive"
                    disabled={busy || !cancelReason.trim()}
                    onClick={() => void cancelExport()}
                  >
                    <Ban aria-hidden="true" /> Cancel export
                  </Button>
                ) : null}
                {job.state === "succeeded" ? (
                  <Button
                    type="button"
                    disabled={busy}
                    onClick={() => void downloadExport()}
                  >
                    <Download aria-hidden="true" /> Download via API
                  </Button>
                ) : null}
              </div>
            </div>
          ) : null}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setDialog(null)}
            >
              Close
            </Button>
            {!job ? (
              <Button
                type="submit"
                form="audit-export-form"
                disabled={busy || !exportReason.trim()}
              >
                {busy ? (
                  <LoaderCircle className="is-spinning" aria-hidden="true" />
                ) : (
                  <FileDown aria-hidden="true" />
                )}
                Queue export
              </Button>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={dialog === "retention"}
        onOpenChange={(open) => setDialog(open ? "retention" : null)}
      >
        <DialogContent className="audit-operation-dialog">
          <DialogHeader>
            <DialogTitle>Retention boundary & legal hold</DialogTitle>
            <DialogDescription>
              Pruning remains worker-only and is blocked until a closed segment
              is signed, preserved, verified, and covered by the protected
              anchor.
            </DialogDescription>
          </DialogHeader>
          {busy && !retention ? (
            <p className="audit-operation-loading">
              <LoaderCircle className="is-spinning" aria-hidden="true" />{" "}
              Loading governed state
            </p>
          ) : null}
          {retention ? (
            <form
              id="audit-retention-form"
              className="audit-operation-form"
              onSubmit={(event) => void updateRetentionPolicy(event)}
            >
              <RetentionSummary state={retention} />
              <div className="audit-operation-form__field">
                <Label htmlFor="audit-retention-days">Retention days</Label>
                <Input
                  id="audit-retention-days"
                  type="number"
                  min={30}
                  max={3_650}
                  step={1}
                  value={retentionDays}
                  onChange={(event) =>
                    setRetentionDays(Number(event.currentTarget.value))
                  }
                  required
                />
              </div>
              <div className="audit-operation-form__field">
                <Label htmlFor="audit-retention-reason">
                  Redacted change reason
                </Label>
                <Input
                  id="audit-retention-reason"
                  value={retentionReason}
                  onChange={(event) =>
                    setRetentionReason(event.currentTarget.value)
                  }
                  placeholder="Policy review approved"
                  autoComplete="off"
                  maxLength={500}
                  required
                />
              </div>
              <label className="audit-operation-confirmation">
                <input
                  type="checkbox"
                  checked={holdConfirmed}
                  onChange={(event) =>
                    setHoldConfirmed(event.currentTarget.checked)
                  }
                />
                <span>
                  I confirm this{" "}
                  {retention.activeLegalHold ? "release" : "hold"} is authorized
                  and the reason contains no protected data.
                </span>
              </label>
            </form>
          ) : null}
          {error ? (
            <p className="audit-operation-error" role="alert">
              {error}
            </p>
          ) : null}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setDialog(null)}
            >
              Close
            </Button>
            {retention ? (
              <>
                <Button
                  type="button"
                  variant={
                    retention.activeLegalHold ? "destructive" : "outline"
                  }
                  disabled={busy || !holdConfirmed || !retentionReason.trim()}
                  onClick={() => void mutateHold()}
                >
                  {retention.activeLegalHold ? (
                    <ShieldOff aria-hidden="true" />
                  ) : (
                    <ShieldAlert aria-hidden="true" />
                  )}
                  {retention.activeLegalHold
                    ? "Release legal hold"
                    : "Place legal hold"}
                </Button>
                <Button
                  type="submit"
                  form="audit-retention-form"
                  disabled={busy || !retentionReason.trim()}
                >
                  Save retention policy
                </Button>
              </>
            ) : null}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function ExportStatus({ job }: { job: AuditExportJob }): React.JSX.Element {
  return (
    <dl className="audit-operation-summary">
      <div>
        <dt>Job</dt>
        <dd>{compactAuditIdentifier(job.id)}</dd>
      </div>
      <div>
        <dt>State</dt>
        <dd>{job.state.replaceAll("_", " ")}</dd>
      </div>
      <div>
        <dt>Revision</dt>
        <dd>v{job.revision}</dd>
      </div>
      <div>
        <dt>Expires</dt>
        <dd>
          <TenantInstant value={job.expiresAt} precision="second" />
        </dd>
      </div>
      {job.artifact ? (
        <div>
          <dt>Manifest</dt>
          <dd>
            {job.artifact.rows} rows · {formatBytes(job.artifact.bytes)}
          </dd>
        </div>
      ) : null}
    </dl>
  );
}

function RetentionSummary({
  state,
}: {
  state: AuditRetentionState;
}): React.JSX.Element {
  return (
    <dl className="audit-operation-summary">
      <div>
        <dt>Policy revision</dt>
        <dd>v{state.policy.revision}</dd>
      </div>
      <div>
        <dt>Protected through</dt>
        <dd>SEQ {state.anchor.retainedThroughSequence}</dd>
      </div>
      <div>
        <dt>Anchor revision</dt>
        <dd>v{state.anchor.revision}</dd>
      </div>
      <div>
        <dt>Legal hold</dt>
        <dd>
          {state.activeLegalHold ? "Active — pruning blocked" : "None active"}
        </dd>
      </div>
    </dl>
  );
}

function operationKey(kind: string): string {
  return `audit-${kind}-${globalThis.crypto.randomUUID()}`;
}

function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  anchor.click();
  URL.revokeObjectURL(url);
}

function formatBytes(value: number): string {
  if (value < 1_024) return `${value} B`;
  if (value < 1_048_576) return `${Math.ceil(value / 1_024)} KiB`;
  return `${Math.ceil(value / 1_048_576)} MiB`;
}
