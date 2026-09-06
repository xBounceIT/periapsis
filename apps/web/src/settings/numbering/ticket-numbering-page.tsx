import type {
  TicketNumberingDraft,
  TicketNumberingKind,
  TicketNumberingPreview,
} from "@periapsis/contracts";
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
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Input } from "@periapsis/ui/components/ui/input";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  BellRing,
  BriefcaseBusiness,
  CheckCircle2,
  Clock3,
  Hash,
  RefreshCw,
  Save,
  ShieldCheck,
} from "lucide-react";
import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
  type FormEvent,
} from "react";
import { reduceWorkspaceState } from "../../pages/workspace-state";

import { useSession } from "../../auth/session-context";
import { useTenantAuthority } from "../../auth/tenant-authority-context";
import { FocusedError } from "../../components/focused-error";
import { FormField } from "../../components/form-field";
import { ServerDenied } from "../../components/server-denied";
import { idempotencyKeyForPayload } from "../../lib/payload-idempotency";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
} from "../../lib/phase-two-types";
import { TenantInstant } from "../../lib/tenant-date-time-context";
import {
  normalizeTicketNumberingForm,
  ticketNumberingDraftDiffers,
  ticketNumberingDraftFromForm,
  ticketNumberingFieldErrors,
  ticketNumberingFormFrom,
  ticketNumberingManagePermission,
  ticketNumberingPreviewQueryKey,
  ticketNumberingQueryKey,
  ticketNumberingReadPermission,
  ticketNumberingReasonIsValid,
  type TicketNumberingApi,
  type TicketNumberingDraftField,
  type TicketNumberingFormDraft,
  type VersionedTicketNumberingPolicy,
} from "./model";
import { ticketNumberingApi } from "./ticket-numbering-api";
// oxlint-disable-next-line import/no-unassigned-import -- Page-scoped numbering administration styles.
import "./ticket-numbering.css";

interface TicketNumberingPageProps {
  api?: TicketNumberingApi;
}

interface NumberingCardDefinition {
  description: string;
  kind: TicketNumberingKind;
  label: string;
}

const cards: readonly NumberingCardDefinition[] = [
  {
    description:
      "Numbers assigned to triage records, direct ingest, and system-generated SLA alerts.",
    kind: "alert",
    label: "Alert numbers",
  },
  {
    description:
      "Numbers assigned to human-created cases and new cases created during escalation.",
    kind: "case",
    label: "Case numbers",
  },
];
const draftFields = [
  "prefix",
  "separator",
  "period",
  "width",
  "start",
] as const satisfies readonly TicketNumberingDraftField[];

export function TicketNumberingPage({
  api = ticketNumberingApi,
}: TicketNumberingPageProps = {}): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;

  if (!tenantId || authority.status === "inactive") {
    return (
      <div className="content ticket-numbering-page">
        <Card>
          <CardHeader>
            <CardTitle>Select a tenant to manage ticket numbering.</CardTitle>
            <CardDescription>
              Alert and Case number policies always belong to one explicit
              active tenant.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }
  if (authority.status === "error") {
    return (
      <NumberingBoundaryError
        message={authority.message ?? "Tenant authority could not be resolved."}
        onRetry={authority.reload}
      />
    );
  }
  if (authority.status === "forbidden") {
    return <ServerDenied resource="tenant ticket numbering" />;
  }
  if (authority.status !== "ready") {
    return <NumberingPageSkeleton />;
  }
  const canRead = authority.hasPermission(
    ticketNumberingReadPermission,
    "tenant",
  );
  if (!canRead) return <ServerDenied resource="tenant ticket numbering" />;
  const canManage = authority.hasPermission(
    ticketNumberingManagePermission,
    "tenant",
  );

  return (
    <div className="content ticket-numbering-page">
      <section
        className="page-heading ticket-numbering-page__heading"
        aria-labelledby="ticket-numbering-title"
      >
        <div>
          <p className="section-label">Tenant administration / numbering</p>
          <h1 id="ticket-numbering-title">Ticket number registry</h1>
          <p>
            Publish independent formats for Alerts and Cases. A preview checks
            the complete draft against the running API without reserving a
            number; published versions are immutable and existing tickets keep
            their original number.
          </p>
        </div>
        <Badge variant={canManage ? "default" : "secondary"}>
          {canManage ? "Manage access" : "Read-only access"}
        </Badge>
      </section>

      <Alert className="ticket-numbering-page__assurance">
        <ShieldCheck aria-hidden="true" />
        <AlertTitle>Monotonic by design</AlertTitle>
        <AlertDescription>
          Reusing an older format continues its durable namespace. Lower start
          values never rewind a counter, and UTC annual sequences restart only
          in a new year.
        </AlertDescription>
      </Alert>

      <div className="ticket-numbering-grid">
        {cards.map((card) => (
          <NumberingPolicyCard
            api={api}
            canManage={canManage}
            definition={card}
            key={card.kind}
            tenantId={tenantId}
          />
        ))}
      </div>
    </div>
  );
}

function NumberingPolicyCard(props: {
  api: TicketNumberingApi;
  canManage: boolean;
  definition: NumberingCardDefinition;
  tenantId: string;
}): React.JSX.Element {
  const model = useNumberingPolicyCardModel(props);
  if (model.kind === "content") return model.content;
  return <NumberingPolicyCardView model={model.data} />;
}

function useNumberingPolicyCardModel({
  api,
  canManage,
  definition,
  tenantId,
}: {
  api: TicketNumberingApi;
  canManage: boolean;
  definition: NumberingCardDefinition;
  tenantId: string;
}) {
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const queryClient = useQueryClient();
  const { kind } = definition;
  const pairKey = `${session.id}:${tenantId}:${kind}`;
  const pairKeyRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairKeyRef.current = pairKey;
  }, [pairKey]);
  const loadedPairRef = useRef<string | null>(null);
  const loadedVersionRef = useRef<string | null>(null);
  const updateAttempt = useRef<{
    current: { fingerprint: string; key: string } | null;
  }>({
    current: null,
  });
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<NumberingPolicyCardState>,
    undefined,
    (): NumberingPolicyCardState => ({
      form: (() => emptyForm(kind))(),
      touched: (() => new Set())(),
      reason: "",
      reasonError: null,
      notice: null,
      mutationError: null,
      saving: false,
      previewDraft: null,
    }),
  );
  const {
    form,
    touched,
    reason,
    reasonError,
    notice,
    mutationError,
    saving,
    previewDraft,
  } = workspaceState;
  const {
    setTouched,
    setReason,
    setReasonError,
    setNotice,
    setMutationError,
    setSaving,
    setPreviewDraft,
  } = useMemo(
    () => ({
      setTouched: (
        value: React.SetStateAction<NumberingPolicyCardState["touched"]>,
      ) => updateWorkspaceState({ touched: value }),
      setReason: (
        value: React.SetStateAction<NumberingPolicyCardState["reason"]>,
      ) => updateWorkspaceState({ reason: value }),
      setReasonError: (
        value: React.SetStateAction<NumberingPolicyCardState["reasonError"]>,
      ) => updateWorkspaceState({ reasonError: value }),
      setNotice: (
        value: React.SetStateAction<NumberingPolicyCardState["notice"]>,
      ) => updateWorkspaceState({ notice: value }),
      setMutationError: (
        value: React.SetStateAction<NumberingPolicyCardState["mutationError"]>,
      ) => updateWorkspaceState({ mutationError: value }),
      setSaving: (
        value: React.SetStateAction<NumberingPolicyCardState["saving"]>,
      ) => updateWorkspaceState({ saving: value }),
      setPreviewDraft: (
        value: React.SetStateAction<NumberingPolicyCardState["previewDraft"]>,
      ) => updateWorkspaceState({ previewDraft: value }),
    }),
    [updateWorkspaceState],
  );

  const queryKey = ticketNumberingQueryKey(session.id, tenantId, kind);
  const policyQuery = useQuery({
    queryKey,
    queryFn: ({ signal }) => api.get(tenantId, kind, signal),
    retry: false,
    staleTime: 30_000,
  });
  const normalizedForm = useMemo(
    () => normalizeTicketNumberingForm(form),
    [form],
  );
  const allErrors = useMemo(
    () => ticketNumberingFieldErrors(normalizedForm),
    [normalizedForm],
  );
  const validDraft = useMemo(() => {
    try {
      return ticketNumberingDraftFromForm(normalizedForm);
    } catch {
      return null;
    }
  }, [normalizedForm]);

  useEffect(() => {
    const current = policyQuery.data;
    if (!current) return;
    const identity = `${pairKey}:${current.value.versionId}`;
    if (loadedVersionRef.current === identity) return;
    const changedPair = loadedPairRef.current !== pairKey;
    loadedPairRef.current = pairKey;
    loadedVersionRef.current = identity;
    updateWorkspaceState({
      form: ticketNumberingFormFrom(current.value),
      touched: new Set(),
      reason: "",
      reasonError: null,
    });
    if (changedPair) {
      updateWorkspaceState({ mutationError: null, notice: null });
    }
    updateAttempt.current.current = null;
  }, [pairKey, policyQuery.data]);

  useEffect(() => {
    if (!validDraft) {
      setPreviewDraft(null);
      return undefined;
    }
    const timer = window.setTimeout(() => setPreviewDraft(validDraft), 180);
    return () => window.clearTimeout(timer);
  }, [setPreviewDraft, validDraft]);

  const previewQuery = useQuery({
    queryKey: previewDraft
      ? ticketNumberingPreviewQueryKey(session.id, tenantId, kind, previewDraft)
      : ["ticket-numbering-preview", session.id, tenantId, kind, "invalid"],
    queryFn: ({ signal }) =>
      api.preview(session.csrfToken, tenantId, kind, previewDraft!, signal),
    enabled: previewDraft !== null,
    retry: false,
    staleTime: 15_000,
  });

  function change(field: TicketNumberingDraftField, value: string): void {
    updateWorkspaceState({
      form: (current) => ({ ...current, [field]: value }),
      touched: (current) => new Set(current).add(field),
      mutationError: null,
      notice: null,
    });
  }

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const current = policyQuery.data;
    if (!current || !canManage || saving) return;
    setTouched(new Set(draftFields));
    const nextReasonError = ticketNumberingReasonIsValid(reason)
      ? null
      : "Use 1–2,048 visible ASCII characters, without commas or surrounding spaces.";
    updateWorkspaceState({
      reasonError: nextReasonError,
      mutationError: null,
      notice: null,
    });
    if (!validDraft || nextReasonError) return;
    if (!ticketNumberingDraftDiffers(current.value, validDraft)) {
      setNotice("No values changed; no policy or audit event was created.");
      return;
    }
    const payload = {
      draft: validDraft,
      expectedVersion: current.value.version,
      kind,
      reason,
      tenantId,
    };
    const idempotencyKey = idempotencyKeyForPayload(
      updateAttempt.current,
      payload,
    );
    const expectedPair = pairKey;
    setSaving(true);
    try {
      const updated = await api.update(
        session.csrfToken,
        tenantId,
        kind,
        current,
        idempotencyKey,
        reason,
        validDraft,
      );
      if (pairKeyRef.current !== expectedPair) return;
      queryClient.setQueryData<VersionedTicketNumberingPolicy>(queryKey, {
        etag: updated.etag,
        value: updated.value,
      });
      updateAttempt.current.current = null;
      updateWorkspaceState({
        form: ticketNumberingFormFrom(updated.value),
        touched: new Set(),
        reason: "",
        notice: updated.replayed
          ? "The original successful publication was confirmed again; no duplicate version was created."
          : `Version ${updated.value.version} is published. New ${kind === "alert" ? "Alerts" : "Cases"} use this policy.`,
      });
    } catch (caught) {
      if (pairKeyRef.current !== expectedPair) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        const refreshed = await policyQuery.refetch();
        if (pairKeyRef.current !== expectedPair) return;
        setMutationError(
          refreshed.data
            ? "Someone published this policy first. The latest version is loaded; review it before saving again."
            : "Someone published this policy first, and the latest version could not be reloaded.",
        );
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
      } else if (caught instanceof PhaseTwoApiError && caught.status === 403) {
        authority.reload();
      }
      setMutationError(
        describePhaseTwoError(
          caught,
          "The numbering policy could not be published. No local success is assumed.",
        ),
      );
    } finally {
      if (pairKeyRef.current === expectedPair) setSaving(false);
    }
  }

  if (policyQuery.isLoading) {
    return {
      kind: "content" as const,
      content: <NumberingCardSkeleton definition={definition} />,
    };
  }
  if (!policyQuery.data) {
    return {
      kind: "content" as const,
      content: (
        <Card className="ticket-numbering-card ticket-numbering-card--error">
          <CardHeader>
            <CardTitle>{definition.label}</CardTitle>
            <CardDescription>{definition.description}</CardDescription>
          </CardHeader>
          <CardContent>
            <FocusedError
              title={`${definition.label} could not be loaded`}
              message={describePhaseTwoError(
                policyQuery.error,
                "The current immutable policy is unavailable.",
              )}
            />
            <Button
              type="button"
              variant="outline"
              onClick={() => void policyQuery.refetch()}
            >
              <RefreshCw aria-hidden="true" /> Retry
            </Button>
          </CardContent>
        </Card>
      ),
    };
  }

  const policy = policyQuery.data.value;
  const hasChanges =
    validDraft !== null && ticketNumberingDraftDiffers(policy, validDraft);
  const preview = previewDraft === validDraft ? previewQuery.data : undefined;
  const previewing =
    validDraft !== null &&
    (previewDraft !== validDraft || previewQuery.isFetching);
  const fieldError = (field: TicketNumberingDraftField) =>
    touched.has(field) ? allErrors[field] : undefined;
  const prefixError = fieldError("prefix");
  const separatorError = fieldError("separator");
  const periodError = fieldError("period");
  const widthError = fieldError("width");
  const startError = fieldError("start");
  const prefix = `ticket-numbering-${kind}`;

  return {
    kind: "ready" as const,
    data: {
      canManage,
      change,
      definition,
      form,
      hasChanges,
      kind,
      mutationError,
      notice,
      periodError,
      policy,
      policyQuery,
      prefix,
      prefixError,
      preview,
      previewQuery,
      previewing,
      reason,
      reasonError,
      save,
      saving,
      separatorError,
      setMutationError,
      setNotice,
      setReason,
      setReasonError,
      startError,
      validDraft,
      widthError,
    },
  };
}

function NumberingPolicyCardView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useNumberingPolicyCardModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <NumberingPolicyCardContent model={model} />;
}

function NumberPlacard({
  kind,
  preview,
  previewError,
  previewing,
  valid,
}: {
  kind: TicketNumberingKind;
  preview: TicketNumberingPreview | undefined;
  previewError: unknown;
  previewing: boolean;
  valid: boolean;
}): React.JSX.Element {
  const status = !valid
    ? "Fix the draft to request a preview"
    : previewing
      ? "Checking with the server…"
      : previewError
        ? "Server preview unavailable"
        : preview
          ? "Server-validated · no number allocated"
          : "Waiting for server preview";
  return (
    <aside
      className="ticket-number-placard"
      aria-label={`${kind === "alert" ? "Alert" : "Case"} number preview`}
    >
      <div className="ticket-number-placard__rail" aria-hidden="true" />
      <div className="ticket-number-placard__topline">
        <span>
          <Hash aria-hidden="true" /> Next format specimen
        </span>
        <small>{kind.toUpperCase()}</small>
      </div>
      <output aria-live="polite" aria-atomic="true">
        {preview?.example ?? "—"}
      </output>
      <div className="ticket-number-placard__meta">
        <span>{status}</span>
        {preview ? (
          <span>
            {preview.period === "annual"
              ? `UTC ${preview.periodKey}`
              : "Lifetime"}
            {" · max "}
            {preview.maximumSequence.toLocaleString("en-US")}
          </span>
        ) : null}
      </div>
    </aside>
  );
}

function emptyForm(kind: TicketNumberingKind): TicketNumberingFormDraft {
  return {
    prefix: kind === "alert" ? "ALT" : "CAS",
    separator: "-",
    period: "annual",
    width: "6",
    start: "1",
  };
}

function NumberingCardSkeleton({
  definition,
}: {
  definition: NumberingCardDefinition;
}): React.JSX.Element {
  return (
    <Card className="ticket-numbering-card" aria-busy="true">
      <CardHeader>
        <CardTitle>{definition.label}</CardTitle>
        <CardDescription>
          Resolving the current immutable policy and strong version.
        </CardDescription>
      </CardHeader>
    </Card>
  );
}

function NumberingPageSkeleton(): React.JSX.Element {
  return (
    <div className="content ticket-numbering-page" aria-busy="true">
      <section className="page-heading">
        <div>
          <p className="section-label">Tenant administration / numbering</p>
          <h1>Ticket number registry</h1>
          <p>Resolving live tenant authority.</p>
        </div>
      </section>
    </div>
  );
}

function NumberingBoundaryError({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}): React.JSX.Element {
  return (
    <div className="content ticket-numbering-page ticket-numbering-page__error">
      <FocusedError title="Ticket numbering is unavailable" message={message} />
      <Button type="button" variant="outline" onClick={onRetry}>
        <RefreshCw aria-hidden="true" /> Retry authority check
      </Button>
    </div>
  );
}

function NumberingPolicyCardContent({
  model,
}: {
  model: React.ComponentProps<typeof NumberingPolicyCardView>["model"];
}): React.ReactNode {
  const {
    canManage,
    change,
    definition,
    form,
    kind,
    mutationError,
    notice,
    policy,
    prefix,
    prefixError,
    preview,
    previewQuery,
    previewing,
    save,
    saving,
    validDraft,
  } = model;
  return (
    <Card className={`ticket-numbering-card ticket-numbering-card--${kind}`}>
      <CardHeader className="ticket-numbering-card__header">
        <div className="ticket-numbering-card__identity">
          <span aria-hidden="true">
            {kind === "alert" ? <BellRing /> : <BriefcaseBusiness />}
          </span>
          <div>
            <CardTitle id={`${prefix}-title`} role="heading" aria-level={2}>
              {definition.label}
            </CardTitle>
            <CardDescription>{definition.description}</CardDescription>
          </div>
        </div>
        <Badge variant="outline">Current v{policy.version}</Badge>
      </CardHeader>
      <CardContent>
        <NumberPlacard
          kind={kind}
          preview={preview}
          previewError={previewQuery.error}
          previewing={previewing}
          valid={validDraft !== null}
        />

        {notice ? (
          <Alert className="ticket-numbering-card__notice">
            <CheckCircle2 aria-hidden="true" />
            <AlertTitle>Policy synchronized</AlertTitle>
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        ) : null}
        {mutationError ? (
          <FocusedError
            title={`${definition.label} were not changed`}
            message={mutationError}
          />
        ) : null}

        <form
          className="ticket-numbering-form"
          aria-labelledby={`${prefix}-title`}
          onSubmit={save}
          noValidate
        >
          <fieldset disabled={saving}>
            <legend className="sr-only">{definition.label} policy</legend>
            <div className="ticket-numbering-form__grid">
              <FormField
                htmlFor={`${prefix}-prefix`}
                label="Prefix"
                hint="1–12 uppercase letters or digits; begin with a letter."
                {...(prefixError ? { error: prefixError } : {})}
              >
                <Input
                  id={`${prefix}-prefix`}
                  className="ticket-numbering-form__code"
                  value={form.prefix}
                  maxLength={12}
                  readOnly={!canManage}
                  autoComplete="off"
                  aria-invalid={Boolean(prefixError)}
                  aria-describedby={`${prefix}-prefix-${prefixError ? "error" : "hint"}`}
                  onChange={(event) =>
                    change("prefix", event.currentTarget.value.toUpperCase())
                  }
                />
              </FormField>
              <NumberingSeparatorField model={model} />
              <NumberingCounterPeriodField model={model} />
              <NumberingSequenceWidthField model={model} />
              <NumberingStartValueField model={model} />
            </div>

            {<NumberingPolicyCommitPanel model={model} />}
          </fieldset>
        </form>

        <p className="ticket-numbering-card__provenance">
          <Clock3 aria-hidden="true" /> Published{" "}
          <TenantInstant value={policy.publishedAt} precision="second" /> by{" "}
          {policy.publisher.type === "system"
            ? "the system default"
            : `membership ${policy.publisher.membershipId}`}
        </p>
      </CardContent>
    </Card>
  );
}

interface NumberingPolicyCardState {
  form: TicketNumberingFormDraft;
  touched: Set<TicketNumberingDraftField>;
  reason: string;
  reasonError: string | null;
  notice: string | null;
  mutationError: string | null;
  saving: boolean;
  previewDraft: TicketNumberingDraft | null;
}

function NumberingPolicyCommitPanel({
  model,
}: {
  model: React.ComponentProps<typeof NumberingPolicyCardContent>["model"];
}): React.ReactNode {
  const { canManage } = model;
  return canManage ? (
    <NumberingPolicyCommitActions model={model} />
  ) : (
    <p className="ticket-numbering-form__readonly">
      Manage permission is required to publish a new immutable version. The
      current policy and side-effect-free preview remain visible for operational
      context.
    </p>
  );
}

function NumberingSeparatorField({
  model,
}: {
  model: React.ComponentProps<typeof NumberingPolicyCardContent>["model"];
}): React.ReactNode {
  const { canManage, change, form, prefix, saving, separatorError } = model;
  return (
    <FormField
      htmlFor={`${prefix}-separator`}
      label="Separator"
      hint="The same separator is used throughout the number."
      {...(separatorError ? { error: separatorError } : {})}
    >
      <select
        id={`${prefix}-separator`}
        className="ticket-numbering-form__select ticket-numbering-form__code"
        value={form.separator}
        disabled={!canManage || saving}
        aria-invalid={Boolean(separatorError)}
        aria-describedby={`${prefix}-separator-${separatorError ? "error" : "hint"}`}
        onChange={(event) => change("separator", event.currentTarget.value)}
      >
        <option value="-">Hyphen — -</option>
        <option value="/">Slash — /</option>
        <option value=".">Dot — .</option>
        <option value="_">Underscore — _</option>
      </select>
    </FormField>
  );
}

function NumberingCounterPeriodField({
  model,
}: {
  model: React.ComponentProps<typeof NumberingPolicyCardContent>["model"];
}): React.ReactNode {
  const { canManage, change, form, periodError, prefix, saving } = model;
  return (
    <FormField
      htmlFor={`${prefix}-period`}
      label="Counter period"
      hint="Annual keys use the allocation instant's UTC year."
      {...(periodError ? { error: periodError } : {})}
    >
      <select
        id={`${prefix}-period`}
        className="ticket-numbering-form__select"
        value={form.period}
        disabled={!canManage || saving}
        aria-invalid={Boolean(periodError)}
        aria-describedby={`${prefix}-period-${periodError ? "error" : "hint"}`}
        onChange={(event) => change("period", event.currentTarget.value)}
      >
        <option value="annual">Annual · UTC year</option>
        <option value="lifetime">Lifetime · one sequence</option>
      </select>
    </FormField>
  );
}

function NumberingSequenceWidthField({
  model,
}: {
  model: React.ComponentProps<typeof NumberingPolicyCardContent>["model"];
}): React.ReactNode {
  const { canManage, change, form, prefix, widthError } = model;
  return (
    <FormField
      htmlFor={`${prefix}-width`}
      label="Sequence width"
      hint="Fixed serial width from 4 to 12 digits."
      {...(widthError ? { error: widthError } : {})}
    >
      <Input
        id={`${prefix}-width`}
        className="ticket-numbering-form__code"
        type="number"
        min={4}
        max={12}
        step={1}
        inputMode="numeric"
        value={form.width}
        readOnly={!canManage}
        aria-invalid={Boolean(widthError)}
        aria-describedby={`${prefix}-width-${widthError ? "error" : "hint"}`}
        onChange={(event) => change("width", event.currentTarget.value)}
      />
    </FormField>
  );
}

function NumberingStartValueField({
  model,
}: {
  model: React.ComponentProps<typeof NumberingPolicyCardContent>["model"];
}): React.ReactNode {
  const { canManage, change, form, prefix, startError } = model;
  return (
    <FormField
      htmlFor={`${prefix}-start`}
      label="Start value"
      hint="A lower bound for a fresh period; it never rewinds an existing counter."
      {...(startError ? { error: startError } : {})}
    >
      <Input
        id={`${prefix}-start`}
        className="ticket-numbering-form__code"
        type="number"
        min={1}
        max={999_999_999_999}
        step={1}
        inputMode="numeric"
        value={form.start}
        readOnly={!canManage}
        aria-invalid={Boolean(startError)}
        aria-describedby={`${prefix}-start-${startError ? "error" : "hint"}`}
        onChange={(event) => change("start", event.currentTarget.value)}
      />
    </FormField>
  );
}

function NumberingPolicyCommitActions({
  model,
}: {
  model: React.ComponentProps<typeof NumberingPolicyCommitPanel>["model"];
}): React.ReactNode {
  const {
    hasChanges,
    policyQuery,
    prefix,
    preview,
    previewQuery,
    reason,
    reasonError,
    saving,
    setMutationError,
    setNotice,
    setReason,
    setReasonError,
    validDraft,
  } = model;
  return (
    <div className="ticket-numbering-form__commit">
      <FormField
        htmlFor={`${prefix}-reason`}
        label="Audit reason"
        hint="Non-secret operational reason; recorded in tenant audit and never reflected."
        {...(reasonError ? { error: reasonError } : {})}
      >
        <Input
          id={`${prefix}-reason`}
          value={reason}
          maxLength={2048}
          autoComplete="off"
          aria-invalid={Boolean(reasonError)}
          aria-describedby={`${prefix}-reason-${reasonError ? "error" : "hint"}`}
          onChange={(event) => {
            setReason(event.currentTarget.value);
            setReasonError(null);
            setMutationError(null);
            setNotice(null);
          }}
        />
      </FormField>
      <div className="ticket-numbering-form__actions">
        <p>
          <ShieldCheck aria-hidden="true" /> Strong precondition{" "}
          {policyQuery.data.etag}
        </p>
        <Button
          type="submit"
          disabled={
            saving ||
            !hasChanges ||
            validDraft === null ||
            previewQuery.isFetching ||
            !preview
          }
        >
          <Save aria-hidden="true" />
          {saving ? "Publishing…" : "Publish policy"}
        </Button>
      </div>
    </div>
  );
}
