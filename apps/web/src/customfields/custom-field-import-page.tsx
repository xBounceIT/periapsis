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
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Ban,
  Braces,
  CheckCircle2,
  CircleAlert,
  Clock3,
  FileJson2,
  FlaskConical,
  Layers3,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  ShieldX,
  Sparkles,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { hasAnyTicketPermission } from "../ticketing/ticketing-model";
import {
  CustomFieldImportApiError,
  customFieldImportApi,
  describeCustomFieldImportError,
  type CustomFieldImportApi,
} from "./custom-field-import-api";
import {
  buildCustomFieldImportRequest,
  customFieldImportDefaultRetentionSeconds,
  customFieldImportExample,
  humanizeCustomFieldImportKey,
  isCustomFieldImportTerminal,
  parseCustomFieldImportRows,
  type CustomFieldImportDraftSummary,
  type CustomFieldImportJobView,
  type CustomFieldImportMode,
  type CustomFieldImportRequest,
  type CustomFieldImportResultView,
} from "./custom-field-import-model";
import type { CustomFieldObjectType } from "./model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this route-owned stylesheet.
import "./custom-field-import-page.css";

interface CustomFieldImportPageProps {
  api?: CustomFieldImportApi;
}

interface ReviewedImport {
  request: CustomFieldImportRequest;
  summary: CustomFieldImportDraftSummary;
}

interface MutationBoundary {
  controller: AbortController;
  token: object;
}

const retentionOptions = [
  { label: "1 hour", value: 3_600 },
  { label: "24 hours", value: customFieldImportDefaultRetentionSeconds },
  { label: "7 days", value: 604_800 },
  { label: "30 days", value: 2_592_000 },
] as const;

export function TenantCustomFieldImportPage(
  props: CustomFieldImportPageProps = {},
): React.JSX.Element {
  const model = useTenantCustomFieldImportPageModel(props);
  if (model.kind === "content") return model.content;
  return <TenantCustomFieldImportPageView model={model.data} />;
}

function useTenantCustomFieldImportPageModel({
  api = customFieldImportApi,
}: CustomFieldImportPageProps = {}) {
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const queryClient = useQueryClient();
  const tenantId = session.activeTenantId ?? "";
  const ready = Boolean(tenantId) && authority.status === "ready";
  const canRead =
    ready && authority.hasPermission("custom_field.read", "tenant");
  const canImportAlert =
    canRead && hasAnyTicketPermission(authority.hasPermission, "alert.update");
  const canImportCase =
    canRead && hasAnyTicketPermission(authority.hasPermission, "case.update");
  const [objectType, setObjectType] = useState<CustomFieldObjectType>("alert");
  const [mode, setMode] = useState<CustomFieldImportMode>("dry_run");
  const [source, setSource] = useState(customFieldImportExample);
  const [retentionSeconds, setRetentionSeconds] = useState(
    customFieldImportDefaultRetentionSeconds,
  );
  const [reviewed, setReviewed] = useState<ReviewedImport>();
  const [draftSummary, setDraftSummary] =
    useState<CustomFieldImportDraftSummary>();
  const [problem, setProblem] = useState<unknown>();
  const [pending, setPending] = useState(false);
  const [jobSeed, setJobSeed] = useState<CustomFieldImportJobView>();
  const requestAttempt = useRef<IdempotencyReference>({ current: null });
  const cancelAttempt = useRef<IdempotencyReference>({ current: null });
  const mutation = useRef<MutationBoundary | undefined>(undefined);
  const handledBackgroundError = useRef<unknown>(undefined);
  const invalidatedJob = useRef<string | undefined>(undefined);
  const previousBoundary = useRef(`${session.id}:${tenantId}`);
  const selectedPermission =
    objectType === "alert" ? canImportAlert : canImportCase;
  const membershipId = authority.authority?.membershipId ?? "unresolved";
  const identityKey = `${session.id}:${tenantId}:${membershipId}:${authority.revision}:${objectType}:${selectedPermission}`;
  const [settledIdentity, setSettledIdentity] = useState(identityKey);
  const stateIsCurrent = settledIdentity === identityKey;
  const identity = useRef({ key: identityKey, token: {} });
  useLayoutEffect(() => {
    if (identity.current.key !== identityKey) {
      identity.current = { key: identityKey, token: {} };
    }
  }, [identityKey]);

  useEffect(() => {
    if (!ready) return;
    if (objectType === "alert" && !canImportAlert && canImportCase) {
      setObjectType("case");
    } else if (objectType === "case" && !canImportCase && canImportAlert) {
      setObjectType("alert");
    }
  }, [canImportAlert, canImportCase, objectType, ready]);

  useEffect(() => {
    mutation.current?.controller.abort();
    mutation.current = undefined;
    requestAttempt.current.current = null;
    cancelAttempt.current.current = null;
    setReviewed(undefined);
    setDraftSummary(undefined);
    setProblem(undefined);
    setPending(false);
    setJobSeed(undefined);
    handledBackgroundError.current = undefined;
    invalidatedJob.current = undefined;
    const boundaryKey = `${session.id}:${tenantId}`;
    if (previousBoundary.current !== boundaryKey) {
      previousBoundary.current = boundaryKey;
      setSource(customFieldImportExample);
      setMode("dry_run");
      setRetentionSeconds(customFieldImportDefaultRetentionSeconds);
    }
    setSettledIdentity(identityKey);
  }, [identityKey, session.id, tenantId]);

  useEffect(
    () => () => {
      mutation.current?.controller.abort();
      mutation.current = undefined;
    },
    [],
  );

  const { job, jobQuery, resultsQuery, results } = useImportJobQueries({
    api,
    jobSeed,
    selectedPermission,
    stateIsCurrent,
    tenantId,
    objectType,
  });
  const handleAccessError = useCallback(
    (error: unknown): void => {
      if (!(error instanceof CustomFieldImportApiError)) return;
      if (error.status === 401) clearSession(session.id);
      else if (error.status === 403) authority.reload();
      else if (error.status === 404 || error.code === "projection_mismatch") {
        setProblem(error);
        // react-doctor-disable-next-line react-doctor/no-adjust-state-on-prop-change -- A 404 or rejected projection invalidates the current server job; this is error recovery, not derived prop state.
        setJobSeed(undefined);
      }
    },
    [authority, clearSession, session.id],
  );

  const backgroundError = jobQuery.error ?? resultsQuery.error;

  useEffect(() => {
    if (
      !stateIsCurrent ||
      !backgroundError ||
      handledBackgroundError.current === backgroundError
    ) {
      return;
    }
    handledBackgroundError.current = backgroundError;
    handleAccessError(backgroundError);
  }, [backgroundError, handleAccessError, stateIsCurrent]);

  useEffect(() => {
    if (
      !job ||
      job.mode !== "commit" ||
      job.state !== "completed" ||
      invalidatedJob.current === job.id
    ) {
      return;
    }
    invalidatedJob.current = job.id;
    void Promise.all([
      queryClient.invalidateQueries({
        queryKey: ["tickets", job.objectType, tenantId],
      }),
      queryClient.invalidateQueries({
        queryKey: ["ticket-custom-fields", job.objectType, tenantId],
      }),
    ]);
  }, [job, queryClient, tenantId]);

  if (!stateIsCurrent || (tenantId && authority.status === "loading")) {
    return { kind: "content" as const, content: <ImportBoundary loading /> };
  }
  if (!canImportAlert && !canImportCase)
    return { kind: "content" as const, content: <ImportBoundary /> };

  function review(event: FormEvent<HTMLFormElement>): void {
    event.preventDefault();
    setProblem(undefined);
    try {
      const parsed = parseCustomFieldImportRows(source);
      const request = buildCustomFieldImportRequest({
        mode,
        objectType,
        retentionSeconds,
        rows: parsed.rows,
      });
      setDraftSummary(parsed.summary);
      setReviewed({ request, summary: parsed.summary });
    } catch (error) {
      setDraftSummary(undefined);
      setReviewed(undefined);
      setProblem(error);
    }
  }

  function beginMutation(): MutationBoundary {
    mutation.current?.controller.abort();
    const boundary = {
      controller: new AbortController(),
      token: identity.current.token,
    };
    mutation.current = boundary;
    return boundary;
  }

  function ownsMutation(boundary: MutationBoundary): boolean {
    return (
      mutation.current === boundary &&
      identity.current.token === boundary.token &&
      !boundary.controller.signal.aborted
    );
  }

  async function submit(): Promise<void> {
    if (
      !reviewed ||
      pending ||
      !selectedPermission ||
      session.csrfToken.trim() === ""
    ) {
      return;
    }
    const boundary = beginMutation();
    setPending(true);
    setProblem(undefined);
    try {
      const result = await api.request({
        body: reviewed.request,
        csrfToken: session.csrfToken,
        idempotencyKey: idempotencyKeyForPayload(
          requestAttempt.current,
          reviewed.request,
        ),
        signal: boundary.controller.signal,
        tenantId,
      });
      if (!ownsMutation(boundary)) return;
      queryClient.setQueryData(
        ["custom-field-import-job", tenantId, objectType, result.job.id],
        result.job,
      );
      setJobSeed(result.job);
      setReviewed(undefined);
      requestAttempt.current.current = null;
    } catch (error) {
      if (!ownsMutation(boundary) || isAbortError(error)) return;
      handleAccessError(error);
      setProblem(error);
    } finally {
      if (ownsMutation(boundary)) {
        mutation.current = undefined;
        // react-doctor-disable-next-line react-doctor/no-loading-flag-reset-outside-finally -- This finally runs on success and failure; its request-ownership guard prevents an older request clearing a newer loading flag.
        setPending(false);
      }
    }
  }

  async function cancel(): Promise<void> {
    if (
      !job ||
      pending ||
      !selectedPermission ||
      session.csrfToken.trim() === "" ||
      (job.state !== "pending" && job.state !== "running")
    ) {
      return;
    }
    const payload = {
      expectedRevision: job.revision,
      jobId: job.id,
      objectType,
    };
    const boundary = beginMutation();
    setPending(true);
    setProblem(undefined);
    try {
      const result = await api.cancel({
        csrfToken: session.csrfToken,
        expectedRevision: job.revision,
        idempotencyKey: idempotencyKeyForPayload(
          cancelAttempt.current,
          payload,
        ),
        jobId: job.id,
        objectType,
        signal: boundary.controller.signal,
        tenantId,
      });
      if (!ownsMutation(boundary)) return;
      queryClient.setQueryData(
        ["custom-field-import-job", tenantId, objectType, job.id],
        result.job,
      );
      setJobSeed(result.job);
    } catch (error) {
      if (!ownsMutation(boundary) || isAbortError(error)) return;
      handleAccessError(error);
      setProblem(error);
      if (error instanceof CustomFieldImportApiError && error.status === 412) {
        void jobQuery.refetch();
      }
    } finally {
      if (ownsMutation(boundary)) {
        mutation.current = undefined;
        // react-doctor-disable-next-line react-doctor/no-loading-flag-reset-outside-finally -- This finally runs on success and failure; its request-ownership guard prevents an older request clearing a newer loading flag.
        setPending(false);
      }
    }
  }

  return {
    kind: "ready" as const,
    data: {
      backgroundError,
      canImportAlert,
      canImportCase,
      cancel,
      draftSummary,
      job,
      jobQuery,
      mode,
      objectType,
      pending,
      problem,
      results,
      resultsQuery,
      retentionSeconds,
      review,
      reviewed,
      selectedPermission,
      session,
      setDraftSummary,
      setMode,
      setObjectType,
      setProblem,
      setRetentionSeconds,
      setReviewed,
      setSource,
      source,
      submit,
    },
  };
}

function TenantCustomFieldImportPageView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useTenantCustomFieldImportPageModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    backgroundError,
    canImportAlert,
    canImportCase,
    cancel,
    draftSummary,
    job,
    jobQuery,
    mode,
    objectType,
    pending,
    problem,
    results,
    resultsQuery,
    retentionSeconds,
    review,
    reviewed,
    selectedPermission,
    session,
    setDraftSummary,
    setMode,
    setObjectType,
    setProblem,
    setRetentionSeconds,
    setReviewed,
    setSource,
    source,
    submit,
  } = model;
  return (
    <div className="content content--wide custom-field-import">
      <header className="custom-field-import__hero">
        <div>
          <p className="section-label">Version-pinned data operations</p>
          <h1>Bulk custom-field import</h1>
          <p>
            Validate or apply typed field changes across Alerts and Cases while
            preserving each row’s reviewed resource version.
          </p>
        </div>
        <div className="custom-field-import__hero-mark" aria-hidden="true">
          <FileJson2 />
          <span>10k</span>
          <small>row ceiling</small>
        </div>
      </header>

      <section
        className="custom-field-import__trust-strip"
        aria-label="Import guarantees"
      >
        <span>
          <ShieldCheck aria-hidden="true" /> Live authority per row
        </span>
        <span>
          <Layers3 aria-hidden="true" /> Definition revisions pinned
        </span>
        <span>
          <Braces aria-hidden="true" /> Missing ≠ null ≠ empty
        </span>
      </section>

      <form className="custom-field-import__composer" onSubmit={review}>
        <section
          className="custom-field-import__settings"
          aria-label="Import settings"
        >
          <div>
            <p className="section-label">01 · Target</p>
            <div
              className="custom-field-import__segments"
              role="group"
              aria-label="Object type"
            >
              <button
                aria-pressed={objectType === "alert"}
                disabled={!canImportAlert}
                onClick={() => setObjectType("alert")}
                type="button"
              >
                Alerts
              </button>
              <button
                aria-pressed={objectType === "case"}
                disabled={!canImportCase}
                onClick={() => setObjectType("case")}
                type="button"
              >
                Cases
              </button>
            </div>
          </div>
          <fieldset>
            <legend className="section-label">02 · Execution</legend>
            <label
              className="custom-field-import__mode"
              data-selected={mode === "dry_run" || undefined}
            >
              <input
                checked={mode === "dry_run"}
                name="import-mode"
                onChange={() => setMode("dry_run")}
                type="radio"
              />
              <FlaskConical aria-hidden="true" />
              <span>
                <strong>Dry run</strong>
                <small>Validate without writes</small>
              </span>
            </label>
            <label
              className="custom-field-import__mode"
              data-selected={mode === "commit" || undefined}
            >
              <input
                checked={mode === "commit"}
                name="import-mode"
                onChange={() => setMode("commit")}
                type="radio"
              />
              <Sparkles aria-hidden="true" />
              <span>
                <strong>Commit</strong>
                <small>Apply valid version pins</small>
              </span>
            </label>
          </fieldset>
          <label>
            <span className="section-label">03 · Receipt retention</span>
            <select
              value={retentionSeconds}
              onChange={(event) =>
                setRetentionSeconds(Number(event.target.value))
              }
            >
              {retentionOptions.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
          </label>
        </section>

        <ImportDocumentFields
          job={job}
          pending={pending}
          selectedPermission={selectedPermission}
          setDraftSummary={setDraftSummary}
          setProblem={setProblem}
          setReviewed={setReviewed}
          setSource={setSource}
          source={source}
        />
      </form>

      {draftSummary ? <DraftSummary summary={draftSummary} /> : null}
      {(problem ?? backgroundError) ? (
        <div className="custom-field-import__problem" role="alert">
          <CircleAlert aria-hidden="true" />
          <span>
            {describeCustomFieldImportError(problem ?? backgroundError)}
          </span>
        </div>
      ) : null}
      {job ? (
        <ImportJobStatus
          job={job}
          loading={jobQuery.isFetching}
          onCancel={() => void cancel()}
          onRefresh={() => void jobQuery.refetch()}
          pending={pending}
        />
      ) : null}
      {job && job.progress.processed > 0 ? (
        <ImportResults
          hasMore={resultsQuery.hasNextPage}
          job={job}
          loading={resultsQuery.isFetching}
          onLoadMore={() => void resultsQuery.fetchNextPage()}
          results={results}
        />
      ) : null}

      <ImportReviewDialog
        pending={pending}
        reviewed={reviewed}
        session={session}
        setReviewed={setReviewed}
        submit={submit}
      />
    </div>
  );
}

function DraftSummary({
  compact = false,
  summary,
}: {
  compact?: boolean;
  summary: CustomFieldImportDraftSummary;
}): React.JSX.Element {
  return (
    <section
      className="custom-field-import__summary"
      data-compact={compact || undefined}
      aria-label="Reviewed row summary"
    >
      <div>
        <strong>{summary.rows.toLocaleString("en-US")}</strong>
        <span>unique targets</span>
      </div>
      <div>
        <strong>{summary.fields.toLocaleString("en-US")}</strong>
        <span>field cells</span>
      </div>
      <div>
        <strong>{summary.missingValues.toLocaleString("en-US")}</strong>
        <span>preserved values</span>
      </div>
      <div>
        <strong>{summary.nullValues.toLocaleString("en-US")}</strong>
        <span>explicit nulls</span>
      </div>
      <div>
        <strong>{summary.emptyValues.toLocaleString("en-US")}</strong>
        <span>empty strings</span>
      </div>
    </section>
  );
}

function ImportJobStatus({
  job,
  loading,
  onCancel,
  onRefresh,
  pending,
}: {
  job: CustomFieldImportJobView;
  loading: boolean;
  onCancel: () => void;
  onRefresh: () => void;
  pending: boolean;
}): React.JSX.Element {
  const terminal = isCustomFieldImportTerminal(job.state);
  const cancellable = job.state === "pending" || job.state === "running";
  return (
    <article className="custom-field-import__job" aria-live="polite">
      <header>
        <span
          className="custom-field-import__job-icon"
          data-terminal={terminal || undefined}
        >
          {terminal ? (
            <CheckCircle2 aria-hidden="true" />
          ) : (
            <Clock3 aria-hidden="true" />
          )}
        </span>
        <div>
          <p className="section-label">Durable job receipt</p>
          <h2>{humanizeCustomFieldImportKey(job.state)}</h2>
          <small>
            {job.objectType} · {humanizeCustomFieldImportKey(job.mode)} ·
            revision {job.revision} · attempt {job.attempts}/5
          </small>
        </div>
        <Badge variant="outline">{job.id.slice(0, 8)}…</Badge>
      </header>
      <div className="custom-field-import__progress-copy">
        <strong>
          {job.progress.processed.toLocaleString("en-US")} of{" "}
          {job.progress.total.toLocaleString("en-US")}
        </strong>
        <span>
          {Math.round((job.progress.processed / job.progress.total) * 100)}%
          processed
        </span>
      </div>
      <progress max={job.progress.total} value={job.progress.processed}>
        {job.progress.processed} / {job.progress.total}
      </progress>
      <div className="custom-field-import__outcomes">
        <Outcome
          label="Succeeded"
          value={job.progress.succeeded}
          tone="success"
        />
        <Outcome label="No change" value={job.progress.noChange} />
        <Outcome
          label="Rejected"
          value={job.progress.rejected}
          tone="warning"
        />
        <Outcome
          label="Version conflict"
          value={job.progress.versionConflict}
          tone="warning"
        />
        <Outcome
          label="Hidden / absent"
          value={job.progress.notFoundOrHidden}
        />
        <Outcome
          label="Denied"
          value={job.progress.authorizationDenied}
          tone="danger"
        />
        <Outcome label="Cancelled" value={job.progress.cancelled} />
        <Outcome
          label="Authority revoked"
          value={job.progress.authorizationRevoked}
          tone="danger"
        />
        <Outcome label="Expired" value={job.progress.expired} tone="warning" />
        <Outcome
          label="Internal failure"
          value={job.progress.internalFailure}
          tone="danger"
        />
      </div>
      <footer>
        <span>
          Expires{" "}
          <time dateTime={job.expiresAt}>{formatInstant(job.expiresAt)}</time>
        </span>
        <div>
          <Button
            type="button"
            size="sm"
            variant="ghost"
            disabled={loading}
            onClick={onRefresh}
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
              disabled={pending}
              onClick={onCancel}
            >
              <Ban aria-hidden="true" /> Stop future rows
            </Button>
          ) : null}
        </div>
      </footer>
    </article>
  );
}

function Outcome({
  label,
  tone,
  value,
}: {
  label: string;
  tone?: string;
  value: number;
}): React.JSX.Element {
  return (
    <span data-tone={tone}>
      <strong>{value.toLocaleString("en-US")}</strong>
      {label}
    </span>
  );
}

function ImportResults({
  hasMore,
  job,
  loading,
  onLoadMore,
  results,
}: {
  hasMore: boolean;
  job: CustomFieldImportJobView;
  loading: boolean;
  onLoadMore: () => void;
  results: readonly CustomFieldImportResultView[];
}): React.JSX.Element {
  return (
    <section
      className="custom-field-import__results"
      aria-labelledby="import-results-title"
    >
      <header>
        <div>
          <p className="section-label">Row receipts</p>
          <h2 id="import-results-title">Processed targets</h2>
        </div>
        <Badge variant="secondary">
          {results.length} / {job.progress.processed}
        </Badge>
      </header>
      {results.length === 0 ? (
        <p className="custom-field-import__results-empty">
          Waiting for the first durable row receipt…
        </p>
      ) : (
        <div className="custom-field-import__result-table-wrap">
          <table>
            <thead>
              <tr>
                <th>Row</th>
                <th>Target</th>
                <th>Outcome</th>
                <th>Version</th>
                <th>Field detail</th>
              </tr>
            </thead>
            <tbody>
              {results.map((result) => (
                <tr key={result.sequence}>
                  <td>#{result.sequence}</td>
                  <td>
                    <code title={result.targetId}>
                      {result.targetId.slice(0, 8)}…
                    </code>
                  </td>
                  <td>
                    <Badge variant="outline">
                      {humanizeCustomFieldImportKey(result.outcome)}
                    </Badge>
                  </td>
                  <td>
                    {result.resultingVersion > 0
                      ? `v${result.resultingVersion}`
                      : `expected v${result.expectedVersion}`}
                  </td>
                  <td>
                    {result.fieldErrors.length === 0
                      ? "—"
                      : result.fieldErrors
                          .map(
                            (error) =>
                              `${error.field}: ${humanizeCustomFieldImportKey(error.code)}`,
                          )
                          .join(" · ")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {hasMore ? (
        <Button
          type="button"
          variant="outline"
          disabled={loading}
          onClick={onLoadMore}
        >
          {loading ? (
            <LoaderCircle className="is-spinning" aria-hidden="true" />
          ) : null}
          Load next 100
        </Button>
      ) : null}
    </section>
  );
}

function ImportBoundary({
  loading = false,
}: {
  loading?: boolean;
}): React.JSX.Element {
  return (
    <div
      className="content content--narrow custom-field-import__boundary"
      role={loading ? "status" : undefined}
    >
      {loading ? (
        <LoaderCircle className="is-spinning" aria-hidden="true" />
      ) : (
        <ShieldX aria-hidden="true" />
      )}
      <p className="section-label">Live authorization boundary</p>
      <h1>
        {loading
          ? "Checking import authority…"
          : "Custom-field imports are unavailable."}
      </h1>
      <p>
        {loading
          ? "The import surface stays closed until current tenant authority is ready."
          : "An active tenant, custom_field.read, and Alert or Case update authority are required."}
      </p>
    </div>
  );
}

function formatInstant(value: string): string {
  const instant = new Date(value);
  return Number.isNaN(instant.valueOf()) ? value : instant.toLocaleString();
}

function reviewedImportLabel(reviewed: ReviewedImport): string {
  const count = reviewed.summary.rows;
  const kind = reviewed.request.objectType === "alert" ? "Alert" : "Case";
  return `${count.toLocaleString("en-US")} ${kind} ${count === 1 ? "row" : "rows"}`;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

interface ImportReviewDialogProps {
  pending: boolean;
  reviewed: ReviewedImport | undefined;
  session: ReturnType<typeof useSession>["session"];
  setReviewed: React.Dispatch<React.SetStateAction<ReviewedImport | undefined>>;
  submit: () => Promise<void>;
}

function ImportReviewDialog({
  pending,
  reviewed,
  session,
  setReviewed,
  submit,
}: ImportReviewDialogProps): React.JSX.Element {
  return (
    <Dialog
      open={reviewed !== undefined}
      onOpenChange={(open) => {
        if (!open && !pending) setReviewed(undefined);
      }}
    >
      <DialogContent className="custom-field-import__review">
        <DialogHeader>
          <p className="section-label">Immutable request receipt</p>
          <DialogTitle>
            {reviewed?.request.mode === "commit" ? "Commit" : "Validate"}{" "}
            {reviewed ? reviewedImportLabel(reviewed) : "0 rows"}?
          </DialogTitle>
          <DialogDescription>
            The worker rechecks current authority and each expected version.
            Rows never expand after this review.
          </DialogDescription>
        </DialogHeader>
        {reviewed ? <DraftSummary summary={reviewed.summary} compact /> : null}
        <div className="custom-field-import__presence-key">
          <span>
            <i data-kind="missing" /> {reviewed?.summary.missingValues ?? 0}{" "}
            unchanged
          </span>
          <span>
            <i data-kind="null" /> {reviewed?.summary.nullValues ?? 0} explicit
            null
          </span>
          <span>
            <i data-kind="empty" /> {reviewed?.summary.emptyValues ?? 0} empty
            string
          </span>
        </div>
        <DialogFooter>
          <Button
            type="button"
            variant="ghost"
            disabled={pending}
            onClick={() => setReviewed(undefined)}
          >
            Keep editing
          </Button>
          <Button
            type="button"
            disabled={pending || session.csrfToken.trim() === ""}
            onClick={() => void submit()}
          >
            {pending ? (
              <LoaderCircle className="is-spinning" aria-hidden="true" />
            ) : (
              <Layers3 aria-hidden="true" />
            )}
            Queue {reviewed?.request.mode === "commit" ? "commit" : "dry run"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface ImportDocumentFieldsProps {
  job: CustomFieldImportJobView | undefined;
  pending: boolean;
  selectedPermission: boolean;
  setDraftSummary: React.Dispatch<
    React.SetStateAction<CustomFieldImportDraftSummary | undefined>
  >;
  setProblem: React.Dispatch<unknown>;
  setReviewed: React.Dispatch<React.SetStateAction<ReviewedImport | undefined>>;
  setSource: React.Dispatch<React.SetStateAction<string>>;
  source: string;
}

function ImportDocumentFields({
  job,
  pending,
  selectedPermission,
  setDraftSummary,
  setProblem,
  setReviewed,
  setSource,
  source,
}: ImportDocumentFieldsProps): React.JSX.Element {
  return (
    <section
      className="custom-field-import__editor"
      aria-labelledby="import-editor-title"
    >
      <header>
        <div>
          <p className="section-label">04 · Rows</p>
          <h2 id="import-editor-title">JSON change set</h2>
        </div>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          onClick={() => {
            setSource(customFieldImportExample);
            setDraftSummary(undefined);
            setProblem(undefined);
          }}
        >
          Reset example
        </Button>
      </header>
      <p>
        Omit <code>value</code> to leave a field unchanged. Use explicit{" "}
        <code>null</code> to clear it;
        <code> ""</code> remains an intentional empty string.
      </p>
      <label>
        <span className="sr-only">Import rows JSON</span>
        <Textarea
          aria-describedby="import-editor-help"
          className="custom-field-import__textarea"
          spellCheck={false}
          value={source}
          onChange={(event) => {
            setSource(event.currentTarget.value);
            setDraftSummary(undefined);
            setReviewed(undefined);
            setProblem(undefined);
          }}
        />
      </label>
      <div id="import-editor-help" className="custom-field-import__editor-foot">
        <span>
          {new TextEncoder().encode(source).length.toLocaleString("en-US")}{" "}
          bytes
        </span>
        <span>Maximum 10,000 rows · 100,000 field cells · 32 MiB</span>
      </div>
      <Button
        type="submit"
        disabled={
          pending ||
          !selectedPermission ||
          Boolean(job && !isCustomFieldImportTerminal(job.state))
        }
      >
        <ShieldCheck aria-hidden="true" />{" "}
        {job && !isCustomFieldImportTerminal(job.state)
          ? "Current import is active"
          : "Review pinned import"}
      </Button>
    </section>
  );
}

function useImportJobQueries({
  api,
  jobSeed,
  selectedPermission,
  stateIsCurrent,
  tenantId,
  objectType,
}: {
  api: CustomFieldImportApi;
  jobSeed: CustomFieldImportJobView | undefined;
  selectedPermission: boolean;
  stateIsCurrent: boolean;
  tenantId: string;
  objectType: CustomFieldObjectType;
}) {
  const jobQuery = useQuery({
    enabled: Boolean(jobSeed) && selectedPermission && stateIsCurrent,
    gcTime: 0,
    queryKey: ["custom-field-import-job", tenantId, objectType, jobSeed?.id],
    queryFn: ({ signal }) =>
      api.get({
        jobId: jobSeed!.id,
        objectType,
        signal,
        tenantId,
      }),
    refetchInterval: (query) =>
      isCustomFieldImportTerminal(query.state.data?.state ?? "pending")
        ? false
        : 2_000,
  });
  const job = stateIsCurrent ? (jobQuery.data ?? jobSeed) : undefined;
  const terminal = job ? isCustomFieldImportTerminal(job.state) : false;
  const resultsQuery = useInfiniteQuery({
    enabled:
      Boolean(job) && selectedPermission && Boolean(job?.progress.processed),
    gcTime: 0,
    queryKey: ["custom-field-import-results", tenantId, objectType, job?.id],
    initialPageParam: undefined as number | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listResults({
        ...(pageParam === undefined ? {} : { after: pageParam }),
        jobId: job!.id,
        objectType,
        pageSize: 100,
        signal,
        tenantId,
      }),
    getNextPageParam: (lastPage) => lastPage.nextAfter,
    refetchInterval: terminal ? false : 2_000,
  });
  const results = useMemo(
    () => resultsQuery.data?.pages.flatMap((page) => page.items) ?? [],
    [resultsQuery.data],
  );

  return { job, jobQuery, resultsQuery, results, terminal };
}
