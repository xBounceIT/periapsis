import type {
  TicketExportCommentScope,
  TicketExportJobRequest,
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
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Ban,
  CheckCircle2,
  CircleAlert,
  Clock3,
  Download,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import {
  type TicketExportJobView,
  type TicketExportMutationView,
  type TicketExportPreparedDownloadView,
} from "../lib/ticket-export-api";
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
import { useTicketExportApi } from "./ticket-export-context";
import { humanizeKey, kindLabelPlural } from "./ticketing-model";
// oxlint-disable-next-line import/no-unassigned-import -- The export console intentionally shares the bounded async-control styling.
import "./ticket-bulk-controls.css";

export interface TicketExportControlsProps {
  allowPrivateComments: boolean;
  allowPublicComments: boolean;
  csrfToken: string;
  kind: TicketKind;
  onForbidden?: () => void;
  onUnauthorized?: () => void;
  source: TicketExportJobRequest["source"];
  tenantId: string;
}

const commentScopes = [
  "none",
  "public",
  "public_and_private",
] as const satisfies readonly TicketExportCommentScope[];
const terminalStates = new Set(["cancelled", "failed", "succeeded"]);

export function TicketExportControls({
  allowPrivateComments,
  allowPublicComments,
  csrfToken,
  kind,
  onForbidden,
  onUnauthorized,
  source,
  tenantId,
}: TicketExportControlsProps): React.JSX.Element {
  const api = useTicketExportApi();
  const queryClient = useQueryClient();
  const requestAttempt = useRef<IdempotencyReference>({ current: null });
  const cancelAttempt = useRef<IdempotencyReference>({ current: null });
  const handledBackgroundError = useRef<unknown>(undefined);
  const [comments, setComments] = useState<TicketExportCommentScope>("none");
  const [maximumRows, setMaximumRows] = useState(10_000);
  const [retentionSeconds, setRetentionSeconds] = useState(86_400);
  const [reviewedRequest, setReviewedRequest] =
    useState<TicketExportJobRequest>();
  const [pending, setPending] = useState(false);
  const [mutationError, setMutationError] = useState<unknown>();
  const [jobSeed, setJobSeed] = useState<TicketExportJobView>();
  const [preparedDownload, setPreparedDownload] =
    useState<TicketExportPreparedDownloadView>();
  const sourceKey = useMemo(() => JSON.stringify(source), [source]);
  const reviewOpen = reviewedRequest !== undefined;

  useEffect(() => {
    requestAttempt.current.current = null;
    cancelAttempt.current.current = null;
    setJobSeed(undefined);
    setPreparedDownload(undefined);
    setMutationError(undefined);
    setReviewedRequest(undefined);
  }, [kind, tenantId]);
  useEffect(() => {
    requestAttempt.current.current = null;
    setReviewedRequest(undefined);
  }, [sourceKey]);
  useEffect(() => {
    setComments((current) =>
      allowedCommentScope(current, allowPublicComments, allowPrivateComments)
        ? current
        : allowPublicComments
          ? "public"
          : "none",
    );
    setReviewedRequest((current) =>
      current &&
      !allowedCommentScope(
        current.comments,
        allowPublicComments,
        allowPrivateComments,
      )
        ? undefined
        : current,
    );
  }, [allowPrivateComments, allowPublicComments]);

  const jobQuery = useQuery({
    enabled: jobSeed !== undefined,
    queryKey: ["ticket-export-job", tenantId, kind, jobSeed?.id],
    queryFn: ({ signal }) =>
      api.get({ jobId: jobSeed!.id, kind, signal, tenantId }),
    refetchInterval: (queryState) =>
      terminalStates.has(queryState.state.data?.state ?? "") ? false : 2_000,
  });
  const job = jobQuery.data ?? jobSeed;
  const backgroundError = jobQuery.error;
  const artifactIdentity = job?.artifact
    ? `${job.id}:${job.revision}:${job.artifact.id}:${job.artifact.sha256}:${job.artifact.expiresAt}`
    : "";

  useEffect(() => {
    setPreparedDownload(undefined);
  }, [artifactIdentity]);

  useEffect(() => {
    if (preparedDownload === undefined) return undefined;
    const remaining = Date.parse(preparedDownload.expiresAt) - Date.now();
    if (!Number.isFinite(remaining) || remaining <= 0) {
      setPreparedDownload(undefined);
      return undefined;
    }
    const timeout = globalThis.setTimeout(
      () => setPreparedDownload(undefined),
      Math.min(remaining, 2_147_483_647),
    );
    return () => globalThis.clearTimeout(timeout);
  }, [preparedDownload]);

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
      setReviewedRequest(
        structuredClone({
          comments,
          kind,
          maximumRows,
          retentionSeconds,
          source,
        } satisfies TicketExportJobRequest),
      );
    } catch (error) {
      setMutationError(error);
    }
  }

  async function submit(): Promise<void> {
    if (pending || csrfToken.trim() === "" || reviewedRequest === undefined)
      return;
    const body = reviewedRequest;
    setPending(true);
    setMutationError(undefined);
    try {
      const result = await api.request({
        body,
        csrfToken,
        idempotencyKey: idempotencyKeyForPayload(requestAttempt.current, body),
        tenantId,
      });
      publishJob(result);
      requestAttempt.current.current = null;
      setReviewedRequest(undefined);
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

  async function prepareDownload(): Promise<void> {
    if (!job?.artifact || pending || csrfToken.trim() === "") return;
    setPending(true);
    setPreparedDownload(undefined);
    setMutationError(undefined);
    try {
      const result = await api.download({
        csrfToken,
        expectedArtifact: job.artifact,
        jobId: job.id,
        kind,
        tenantId,
      });
      setPreparedDownload(result);
    } catch (error) {
      handleAccessError(error, onForbidden, onUnauthorized);
      setMutationError(error);
    } finally {
      setPending(false);
    }
  }

  function publishJob(result: TicketExportMutationView): void {
    setPreparedDownload(undefined);
    setJobSeed(result.job);
    queryClient.setQueryData(
      ["ticket-export-job", tenantId, kind, result.job.id],
      result.job,
    );
  }

  return (
    <section
      className="ticket-bulk-console"
      aria-labelledby="ticket-export-title"
    >
      <div className="ticket-bulk-console__heading">
        <span className="ticket-bulk-console__icon">
          <Download aria-hidden="true" />
        </span>
        <div>
          <p className="section-label">Immutable CSV snapshot</p>
          <h3 id="ticket-export-title">Queue export</h3>
          <p>
            Export the exact current view with server-side tenant and visibility
            enforcement.
          </p>
        </div>
      </div>

      <form className="ticket-bulk-form" onSubmit={review}>
        <label>
          <span>Comments</span>
          <select
            value={comments}
            onChange={(event) => {
              const selected = commentScopes.find(
                (candidate) => candidate === event.target.value,
              );
              if (
                selected !== undefined &&
                allowedCommentScope(
                  selected,
                  allowPublicComments,
                  allowPrivateComments,
                )
              ) {
                setComments(selected);
              }
            }}
          >
            <option value="none">No comments</option>
            {allowPublicComments ? (
              <option value="public">Public comments</option>
            ) : null}
            {allowPublicComments && allowPrivateComments ? (
              <option value="public_and_private">
                Public and private comments
              </option>
            ) : null}
          </select>
        </label>
        <label>
          <span>Maximum rows</span>
          <select
            value={maximumRows}
            onChange={(event) => setMaximumRows(Number(event.target.value))}
          >
            <option value={1_000}>1,000</option>
            <option value={10_000}>10,000</option>
            <option value={50_000}>50,000</option>
            <option value={100_000}>100,000</option>
          </select>
        </label>
        <label>
          <span>Artifact retention</span>
          <select
            value={retentionSeconds}
            onChange={(event) =>
              setRetentionSeconds(Number(event.target.value))
            }
          >
            <option value={900}>15 minutes</option>
            <option value={3_600}>1 hour</option>
            <option value={86_400}>24 hours</option>
            <option value={604_800}>7 days</option>
          </select>
        </label>
        <Button type="submit" disabled={pending || csrfToken.trim() === ""}>
          <ShieldCheck aria-hidden="true" /> Review export
        </Button>
      </form>

      {!allowPublicComments ? (
        <p className="ticket-bulk-console__warning">
          <CircleAlert aria-hidden="true" /> Comments are excluded because the
          live tenant authority does not grant the public-comment permission.
        </p>
      ) : !allowPrivateComments ? (
        <p className="ticket-bulk-console__warning">
          <CircleAlert aria-hidden="true" /> Private comments are excluded
          because the live tenant authority does not grant the corresponding
          permission.
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
                : "The export could not be queued.",
          )}
        </p>
      ) : null}

      {job ? (
        <ExportJobStatus
          job={job}
          loading={jobQuery.isFetching}
          onCancel={() => void cancel()}
          onPrepareDownload={() => void prepareDownload()}
          onRefresh={() => void jobQuery.refetch()}
          pending={pending}
          preparedDownload={preparedDownload}
        />
      ) : null}

      <Dialog
        open={reviewOpen}
        onOpenChange={(open) => {
          if (!pending && !open) setReviewedRequest(undefined);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Confirm CSV export</DialogTitle>
            <DialogDescription>
              Queue an immutable snapshot of up to{" "}
              {reviewedRequest?.maximumRows}{" "}
              {kindLabelPlural(kind).toLowerCase()} with{" "}
              {reviewedRequest
                ? commentScopeLabel(reviewedRequest.comments)
                : "the selected comment scope"}
              .
            </DialogDescription>
          </DialogHeader>
          <div className="ticket-bulk-review">
            <ShieldCheck aria-hidden="true" />
            <p>
              The server pins the query and dynamic definition catalog before
              enqueueing. Later view, catalog, or permission changes cannot
              broaden this export.
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
                <Download aria-hidden="true" />
              )}
              Queue export
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function ExportJobStatus({
  job,
  loading,
  onCancel,
  onPrepareDownload,
  onRefresh,
  pending,
  preparedDownload,
}: {
  job: TicketExportJobView;
  loading: boolean;
  onCancel: () => void;
  onPrepareDownload: () => void;
  onRefresh: () => void;
  pending: boolean;
  preparedDownload: TicketExportPreparedDownloadView | undefined;
}): React.JSX.Element {
  const terminal = terminalStates.has(job.state);
  const cancellable = job.state === "pending" || job.state === "running";
  return (
    <article className="ticket-bulk-job" aria-live="polite">
      <div>
        <span className="ticket-bulk-job__state">
          {terminal ? (
            <CheckCircle2 aria-hidden="true" />
          ) : (
            <Clock3 aria-hidden="true" />
          )}
          <Badge variant="outline">{humanizeKey(job.state)}</Badge>
        </span>
        <strong>
          {job.artifact
            ? `${job.artifact.rows.toLocaleString()} rows · ${formatBytes(job.artifact.bytes)}`
            : `Attempt ${job.attempts} of ${job.maximumAttempts}`}
        </strong>
        <small>
          Revision {job.revision} · expires{" "}
          <TenantInstant value={job.expiresAt} />
        </small>
      </div>
      <div>
        {job.artifact ? (
          <small>
            SHA-256 {job.artifact.sha256.slice(0, 12)}… · each short-lived
            download is reauthorized against live tenant access
          </small>
        ) : job.state === "failed" ? (
          <small>Failure category: {humanizeKey(job.failureCode)}</small>
        ) : (
          <small>The worker status refreshes automatically.</small>
        )}
      </div>
      <div className="ticket-bulk-job__actions">
        {job.artifact ? (
          preparedDownload ? (
            <Button asChild size="sm">
              <a
                download={`ticket-export-${job.id}.csv`}
                href={preparedDownload.downloadUrl}
                referrerPolicy="no-referrer"
                rel="noreferrer"
                target="_blank"
              >
                <Download aria-hidden="true" /> Download CSV
              </a>
            </Button>
          ) : (
            <Button
              type="button"
              size="sm"
              onClick={onPrepareDownload}
              disabled={pending}
            >
              {pending ? (
                <LoaderCircle className="is-spinning" aria-hidden="true" />
              ) : (
                <ShieldCheck aria-hidden="true" />
              )}
              Prepare download
            </Button>
          )
        ) : null}
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
          />
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
            <Ban aria-hidden="true" /> Cancel export
          </Button>
        ) : null}
      </div>
    </article>
  );
}

function commentScopeLabel(scope: TicketExportCommentScope): string {
  switch (scope) {
    case "none":
      return "no comments";
    case "public":
      return "public comments";
    case "public_and_private":
      return "public and private comments";
    default:
      return unsupportedCommentScope(scope);
  }
}

function allowedCommentScope(
  scope: TicketExportCommentScope,
  allowPublic: boolean,
  allowPrivate: boolean,
): boolean {
  return (
    scope === "none" ||
    (scope === "public" && allowPublic) ||
    (scope === "public_and_private" && allowPublic && allowPrivate)
  );
}

function unsupportedCommentScope(scope: never): never {
  throw new TypeError(`Unsupported export comment scope: ${String(scope)}`);
}

function formatBytes(bytes: number): string {
  if (bytes < 1_024) return `${bytes} B`;
  if (bytes < 1_048_576) return `${(bytes / 1_024).toFixed(1)} KiB`;
  return `${(bytes / 1_048_576).toFixed(1)} MiB`;
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
