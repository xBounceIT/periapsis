import type {
  TicketBulkJobRequest,
  TicketBulkMutationRequest,
  TicketBulkQuerySourceRequest,
  TicketBulkTargetPin,
} from "@periapsis/contracts";
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
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Layers3,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";

import {
  type TicketBulkJobView,
  type TicketBulkMutationView,
} from "../lib/ticket-bulk-api";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import {
  TicketingApiError,
  describeTicketingError,
  type TicketKind,
} from "../lib/ticketing-api";
import { useTicketBulkApi } from "./ticket-bulk-context";
import { humanizeKey, kindLabelPlural } from "./ticketing-model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this module-owned stylesheet.
import "./ticket-bulk-controls.css";

export type TicketBulkAction =
  "assign" | "claim" | "release" | "transfer" | "transition";

export interface TicketBulkControlsProps {
  availableActions: readonly TicketBulkAction[];
  csrfToken: string;
  kind: TicketKind;
  onClearSelection: () => void;
  onForbidden?: () => void;
  onUnauthorized?: () => void;
  query: TicketBulkQuerySourceRequest;
  selectedTargets: readonly TicketBulkTargetPin[];
  tenantId: string;
}

type SelectionMode = "explicit" | "query";
const selectionModes = [
  "explicit",
  "query",
] as const satisfies readonly SelectionMode[];

const uuidV7Pattern =
  /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const workflowKeyPattern = /^[a-z][a-z0-9_-]{0,63}$/u;
const terminalStates = new Set([
  "authorization_revoked",
  "cancelled",
  "completed",
  "failed",
]);

export function TicketBulkControls({
  availableActions,
  csrfToken,
  kind,
  onClearSelection,
  onForbidden,
  onUnauthorized,
  query,
  selectedTargets,
  tenantId,
}: TicketBulkControlsProps): React.JSX.Element {
  const api = useTicketBulkApi();
  const queryClient = useQueryClient();
  const requestAttempt = useRef<IdempotencyReference>({ current: null });
  const cancelAttempt = useRef<IdempotencyReference>({ current: null });
  const handledBackgroundError = useRef<unknown>(undefined);
  const [selectionMode, setSelectionMode] = useState<SelectionMode>("explicit");
  const [action, setAction] = useState<TicketBulkAction>(
    availableActions[0] ?? "release",
  );
  const [teamId, setTeamId] = useState("");
  const [assigneeId, setAssigneeId] = useState("");
  const [transition, setTransition] = useState("");
  const [to, setTo] = useState("");
  const [retentionSeconds, setRetentionSeconds] = useState(86_400);
  const [reviewedRequest, setReviewedRequest] =
    useState<TicketBulkJobRequest>();
  const [pending, setPending] = useState(false);
  const [mutationError, setMutationError] = useState<unknown>();
  const [jobSeed, setJobSeed] = useState<TicketBulkJobView>();
  const reviewOpen = reviewedRequest !== undefined;

  useEffect(() => {
    if (!availableActions.includes(action)) {
      setAction(availableActions[0] ?? "release");
    }
  }, [action, availableActions]);
  useEffect(() => {
    requestAttempt.current.current = null;
    cancelAttempt.current.current = null;
    setJobSeed(undefined);
    setMutationError(undefined);
    setReviewedRequest(undefined);
  }, [kind, tenantId]);
  const jobQuery = useQuery({
    enabled: jobSeed !== undefined,
    queryKey: ["ticket-bulk-job", tenantId, kind, jobSeed?.id],
    queryFn: ({ signal }) =>
      api.get({ jobId: jobSeed!.id, kind, signal, tenantId }),
    refetchInterval: (queryState) =>
      terminalStates.has(queryState.state.data?.state ?? "") ? false : 2_000,
  });
  const job = jobQuery.data ?? jobSeed;
  const terminal = job ? terminalStates.has(job.state) : false;
  const resultsQuery = useQuery({
    enabled: Boolean(job?.id) && terminal,
    queryKey: ["ticket-bulk-results", tenantId, kind, job?.id],
    queryFn: ({ signal }) =>
      api.listResults({ jobId: job!.id, kind, limit: 50, signal, tenantId }),
  });
  const backgroundError = jobQuery.error ?? resultsQuery.error;

  useEffect(() => {
    if (
      backgroundError === null ||
      backgroundError === undefined ||
      handledBackgroundError.current === backgroundError
    ) {
      return;
    }
    handledBackgroundError.current = backgroundError;
    handleAccessError(backgroundError, onForbidden, onUnauthorized);
  }, [backgroundError, onForbidden, onUnauthorized]);

  function review(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setMutationError(undefined);
    try {
      setReviewedRequest(structuredClone(buildRequestBody()));
    } catch (error) {
      setMutationError(error);
    }
  }

  function buildRequestBody(): TicketBulkJobRequest {
    if (!availableActions.includes(action)) {
      throw new TypeError(
        "The current live authority does not expose that bulk action.",
      );
    }
    const mutation = buildMutation(action, {
      assigneeId,
      teamId,
      to,
      transition,
    });
    if (selectionMode === "explicit" && selectedTargets.length === 0) {
      throw new TypeError(
        "Select at least one loaded ticket, or choose all matching results.",
      );
    }
    if (selectionMode === "explicit" && selectedTargets.length > 1_000) {
      throw new TypeError(
        "Select at most 1,000 loaded tickets, or choose all matching results.",
      );
    }
    return {
      kind,
      mutation,
      retentionSeconds,
      selection:
        selectionMode === "explicit"
          ? {
              source: "explicit",
              targets: selectedTargets.map((target) => ({ ...target })),
            }
          : { source: "query", query },
    };
  }

  async function submit(): Promise<void> {
    if (pending || csrfToken.trim() === "" || reviewedRequest === undefined)
      return;
    const body = reviewedRequest;
    setPending(true);
    setMutationError(undefined);
    try {
      const idempotencyKey = idempotencyKeyForPayload(
        requestAttempt.current,
        body,
      );
      const result = await api.request({
        body,
        csrfToken,
        idempotencyKey,
        tenantId,
      });
      publishJob(result);
      requestAttempt.current.current = null;
      setReviewedRequest(undefined);
      if (body.selection.source === "explicit") onClearSelection();
    } catch (error) {
      handleAccessError(error, onForbidden, onUnauthorized);
      setMutationError(error);
    } finally {
      setPending(false);
    }
  }

  async function cancel(): Promise<void> {
    if (!job || pending || (job.state !== "pending" && job.state !== "running"))
      return;
    const payload = { expectedRevision: job.revision, jobId: job.id, kind };
    setPending(true);
    setMutationError(undefined);
    try {
      const result = await api.cancel({
        csrfToken,
        expectedRevision: job.revision,
        idempotencyKey: idempotencyKeyForPayload(
          cancelAttempt.current,
          payload,
        ),
        jobId: job.id,
        kind,
        tenantId,
      });
      publishJob(result);
    } catch (error) {
      handleAccessError(error, onForbidden, onUnauthorized);
      setMutationError(error);
      if (error instanceof TicketingApiError && error.status === 412) {
        void jobQuery.refetch();
      }
    } finally {
      setPending(false);
    }
  }

  function publishJob(result: TicketBulkMutationView): void {
    setJobSeed(result.job);
    queryClient.setQueryData(
      ["ticket-bulk-job", tenantId, kind, result.job.id],
      result.job,
    );
  }

  if (availableActions.length === 0) {
    return <></>;
  }

  return (
    <section
      className="ticket-bulk-console"
      aria-labelledby="ticket-bulk-title"
    >
      <div className="ticket-bulk-console__heading">
        <span className="ticket-bulk-console__icon">
          <Layers3 aria-hidden="true" />
        </span>
        <div>
          <p className="section-label">Asynchronous control plane</p>
          <h3 id="ticket-bulk-title">Bulk operation</h3>
          <p>
            Targets are version-pinned once; workers recheck live authority for
            every mutation.
          </p>
        </div>
      </div>

      <form className="ticket-bulk-form" onSubmit={review}>
        <label>
          <span>Selection</span>
          <select
            value={selectionMode}
            onChange={(event) => {
              const selected = selectionModes.find(
                (candidate) => candidate === event.target.value,
              );
              if (selected !== undefined) setSelectionMode(selected);
            }}
          >
            <option value="explicit" disabled={selectedTargets.length === 0}>
              Selected loaded rows ({selectedTargets.length})
            </option>
            <option value="query">All matching results (up to 100,000)</option>
          </select>
        </label>
        <label>
          <span>Action</span>
          <select
            value={action}
            onChange={(event) => {
              const selected = availableActions.find(
                (candidate) => candidate === event.target.value,
              );
              if (selected !== undefined) setAction(selected);
            }}
          >
            {availableActions.map((value) => (
              <option key={value} value={value}>
                {humanizeKey(value)}
              </option>
            ))}
          </select>
        </label>
        <BulkMutationFields
          action={action}
          assigneeId={assigneeId}
          onAssigneeId={setAssigneeId}
          onTeamId={setTeamId}
          onTo={setTo}
          onTransition={setTransition}
          teamId={teamId}
          to={to}
          transition={transition}
        />
        <label>
          <span>Receipt retention</span>
          <select
            value={retentionSeconds}
            onChange={(event) =>
              setRetentionSeconds(Number(event.target.value))
            }
          >
            <option value={3_600}>1 hour</option>
            <option value={86_400}>24 hours</option>
            <option value={604_800}>7 days</option>
            <option value={2_592_000}>30 days</option>
          </select>
        </label>
        <Button
          type="submit"
          disabled={
            pending ||
            csrfToken.trim() === "" ||
            (selectionMode === "explicit" && selectedTargets.length === 0)
          }
        >
          <ShieldCheck aria-hidden="true" /> Review operation
        </Button>
      </form>

      {selectionMode === "query" ? (
        <p className="ticket-bulk-console__warning">
          <CircleAlert aria-hidden="true" /> The server will materialize the
          current{" "}
          {query.source === "saved_view"
            ? "exact Saved View revision"
            : "inline filter and definition pins"}
          ; later queue changes cannot expand the job.
        </p>
      ) : null}
      {(mutationError ?? backgroundError) ? (
        <p className="ticket-bulk-console__error" role="alert">
          <CircleAlert aria-hidden="true" />
          {describeTicketingError(
            mutationError ?? backgroundError,
            mutationError instanceof Error
              ? mutationError.message
              : backgroundError instanceof Error
                ? backgroundError.message
                : "The bulk operation could not be submitted.",
          )}
        </p>
      ) : null}

      {job ? (
        <BulkJobStatus
          job={job}
          loading={jobQuery.isFetching}
          onCancel={() => void cancel()}
          onRefresh={() => void jobQuery.refetch()}
          pending={pending}
        />
      ) : null}
      {terminal && resultsQuery.data ? (
        <div className="ticket-bulk-results">
          <strong>
            First {resultsQuery.data.items.length} durable result receipts
          </strong>
          <ul>
            {resultsQuery.data.items.map((item) => (
              <li key={item.sequence}>
                <span>#{item.sequence}</span>
                <Badge variant="outline">{humanizeKey(item.result)}</Badge>
                <span>
                  {item.targetId.slice(0, 8)}… · v{item.targetVersion}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <Dialog
        open={reviewOpen}
        onOpenChange={(open) => {
          if (!pending && !open) setReviewedRequest(undefined);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Confirm bulk{" "}
              {humanizeKey(
                reviewedRequest?.mutation.action ?? action,
              ).toLowerCase()}
            </DialogTitle>
            <DialogDescription>
              {reviewedRequest?.selection.source === "explicit"
                ? `${reviewedRequest.selection.targets?.length ?? 0} loaded ${kindLabelPlural(kind)} will be pinned to their reviewed versions.`
                : `Every currently matching ${kindLabelPlural(kind).toLowerCase()}—up to 100,000—will be materialized under one database snapshot.`}
            </DialogDescription>
          </DialogHeader>
          <div className="ticket-bulk-review">
            <ShieldCheck aria-hidden="true" />
            <p>
              No later row, Saved View, catalog, or permission change silently
              broadens this receipt. Per-target authority is checked again by
              the worker.
            </p>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => setReviewedRequest(undefined)}
              disabled={pending}
            >
              Keep editing
            </Button>
            <Button
              type="button"
              onClick={() => void submit()}
              disabled={pending}
            >
              {pending ? (
                <LoaderCircle className="is-spinning" aria-hidden="true" />
              ) : (
                <Layers3 aria-hidden="true" />
              )}
              Queue operation
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function BulkMutationFields({
  action,
  assigneeId,
  onAssigneeId,
  onTeamId,
  onTo,
  onTransition,
  teamId,
  to,
  transition,
}: {
  action: TicketBulkAction;
  assigneeId: string;
  onAssigneeId: (value: string) => void;
  onTeamId: (value: string) => void;
  onTo: (value: string) => void;
  onTransition: (value: string) => void;
  teamId: string;
  to: string;
  transition: string;
}): React.JSX.Element {
  if (action === "transition") {
    return (
      <>
        <label>
          <span>Transition key</span>
          <Input
            value={transition}
            maxLength={64}
            onChange={(event) => onTransition(event.target.value)}
            placeholder="start_investigation"
          />
        </label>
        <label>
          <span>Destination state</span>
          <Input
            value={to}
            maxLength={64}
            onChange={(event) => onTo(event.target.value)}
            placeholder="investigating"
          />
        </label>
      </>
    );
  }
  if (action === "assign" || action === "transfer") {
    return (
      <>
        <label>
          <span>Team UUIDv7</span>
          <Input
            value={teamId}
            onChange={(event) => onTeamId(event.target.value)}
            placeholder="019…"
          />
        </label>
        <label>
          <span>
            Assignee UUIDv7 <small>optional</small>
          </span>
          <Input
            value={assigneeId}
            onChange={(event) => onAssigneeId(event.target.value)}
            placeholder="019…"
          />
        </label>
      </>
    );
  }
  if (action === "claim") {
    return (
      <label>
        <span>Team UUIDv7</span>
        <Input
          value={teamId}
          onChange={(event) => onTeamId(event.target.value)}
          placeholder="019…"
        />
      </label>
    );
  }
  return <></>;
}

function buildMutation(
  action: TicketBulkAction,
  values: {
    assigneeId: string;
    teamId: string;
    to: string;
    transition: string;
  },
): TicketBulkMutationRequest {
  switch (action) {
    case "transition": {
      const transition = values.transition.trim(),
        to = values.to.trim();
      if (!workflowKeyPattern.test(transition) || !workflowKeyPattern.test(to))
        throw new TypeError(
          "Enter canonical transition and destination-state keys.",
        );
      return { action, to, transition };
    }
    case "assign":
    case "transfer": {
      const teamId = canonicalUUID(values.teamId, "team");
      const assignee = values.assigneeId.trim();
      return {
        action,
        teamId,
        ...(assignee === ""
          ? {}
          : { assigneeId: canonicalUUID(assignee, "assignee") }),
      };
    }
    case "claim":
      return { action, teamId: canonicalUUID(values.teamId, "team") };
    case "release":
      return { action };
    default:
      return unsupportedBulkAction(action);
  }
}

function unsupportedBulkAction(action: never): never {
  throw new TypeError(
    `The bulk mutation action ${String(action)} is not supported.`,
  );
}

function canonicalUUID(value: string, label: string): string {
  const canonical = value.trim().toLowerCase();
  if (!uuidV7Pattern.test(canonical))
    throw new TypeError(`Enter a canonical UUIDv7 ${label} identifier.`);
  return canonical;
}

function BulkJobStatus({
  job,
  loading,
  onCancel,
  onRefresh,
  pending,
}: {
  job: TicketBulkJobView;
  loading: boolean;
  onCancel: () => void;
  onRefresh: () => void;
  pending: boolean;
}): React.JSX.Element {
  const processed =
    job.progress.succeeded +
    job.progress.noChange +
    job.progress.versionConflict +
    job.progress.notFoundOrHidden +
    job.progress.authorizationDenied +
    job.progress.rejected +
    job.progress.cancelled +
    job.progress.authorizationRevoked +
    job.progress.internalFailure;
  const cancellable = job.state === "pending" || job.state === "running";
  return (
    <article className="ticket-bulk-job" aria-live="polite">
      <div>
        <span className="ticket-bulk-job__state">
          {terminalStates.has(job.state) ? (
            <CheckCircle2 aria-hidden="true" />
          ) : (
            <Clock3 aria-hidden="true" />
          )}
          <Badge variant="outline">{humanizeKey(job.state)}</Badge>
        </span>
        <strong>
          {processed} of {job.progress.total} processed
        </strong>
        <small>
          Revision {job.revision} · expires{" "}
          <TenantInstant value={job.expiresAt} />
        </small>
      </div>
      <progress max={job.progress.total} value={processed}>
        {processed} / {job.progress.total}
      </progress>
      <div className="ticket-bulk-job__actions">
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={onRefresh}
          disabled={loading}
        >
          <RefreshCw
            className={loading ? "is-spinning" : undefined}
            aria-hidden="true"
          />{" "}
          Refresh
        </Button>
        {cancellable ? (
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={onCancel}
            disabled={pending}
          >
            <Ban aria-hidden="true" /> Stop future claims
          </Button>
        ) : null}
      </div>
    </article>
  );
}

function handleAccessError(
  error: unknown,
  onForbidden?: () => void,
  onUnauthorized?: () => void,
): void {
  if (!(error instanceof TicketingApiError)) return;
  if (error.status === 401) onUnauthorized?.();
  if (error.status === 403) onForbidden?.();
}
