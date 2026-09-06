import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { useQuery } from "@tanstack/react-query";
import {
  ArrowLeft,
  BellRing,
  BriefcaseBusiness,
  ShieldCheck,
} from "lucide-react";
import {
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { Link, useNavigate } from "react-router";
import { TenantRequiredPage } from "../components/tenant-required-page";
import { TicketCreateMetadataFields } from "./ticket-create-metadata-fields";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import {
  customFieldAdministrationApi,
  listAllCustomFieldDefinitions,
  type CustomFieldAdministrationApi,
} from "../customfields/custom-field-api";
import { DynamicFieldForm } from "../customfields/dynamic-field-form";
import {
  customFieldValuesFromDrafts,
  draftsFromDefaults,
  type CustomFieldDrafts,
} from "../customfields/model";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { describeTicketingError, type TicketKind } from "../lib/ticketing-api";
import { useTicketingApi } from "./ticketing-context";
import {
  type alertSeverities,
  hasAnyTicketPermission,
  kindLabel,
  kindLabelPlural,
  parseTagInput,
  type ticketPriorities,
} from "./ticketing-model";

interface CreateDraft {
  assignedTeamId: string;
  category: string;
  classification: string;
  customerVisible: boolean;
  description: string;
  priority: (typeof ticketPriorities)[number];
  severity: (typeof alertSeverities)[number];
  source: string;
  sourceType: string;
  summary: string;
  tags: string;
  title: string;
  workflowId: string;
}

const initialDraft: CreateDraft = {
  assignedTeamId: "",
  category: "general",
  classification: "",
  customerVisible: false,
  description: "",
  priority: "medium",
  severity: "medium",
  source: "operator-console",
  sourceType: "manual",
  summary: "",
  tags: "",
  title: "",
  workflowId: "",
};

export function AlertCreatePage(): React.JSX.Element {
  return <TicketCreatePage kind="alert" />;
}

export function CaseCreatePage(): React.JSX.Element {
  return <TicketCreatePage kind="case" />;
}

function useTicketCreatePageState({
  customFieldApi = customFieldAdministrationApi,
  kind,
}: {
  customFieldApi?: CustomFieldAdministrationApi;
  kind: TicketKind;
}) {
  const api = useTicketingApi();
  const { session } = useSession();
  const authority = useTenantAuthority();
  const navigate = useNavigate();
  const [draft, setDraft] = useState(initialDraft);
  const [customFieldDrafts, setCustomFieldDrafts] = useState<CustomFieldDrafts>(
    {},
  );
  const [customFieldErrors, setCustomFieldErrors] = useState<
    Readonly<Record<string, string>>
  >({});
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const tenantId = session.activeTenantId;
  const currentDraftContext = `${session.id}:${tenantId ?? ""}:${kind}`;
  const [draftContext, setDraftContext] = useState(currentDraftContext);
  const idempotencyRef = useRef<IdempotencyReference["current"]>(null);
  const contextTokenRef = useRef({ key: currentDraftContext, token: {} });
  const Icon = kind === "alert" ? BellRing : BriefcaseBusiness;
  const canCreate = hasAnyTicketPermission(
    authority.hasPermission,
    kind === "alert" ? "alert.create" : "case.create",
  );
  const canReadCustomFields =
    authority.status === "ready" &&
    authority.hasPermission("custom_field.read", "tenant");
  const customFieldsQuery = useQuery({
    enabled: Boolean(tenantId) && canCreate && canReadCustomFields,
    queryKey: ["custom-field-definitions", tenantId, kind, "create"],
    queryFn: ({ signal }) =>
      listAllCustomFieldDefinitions(customFieldApi, {
        includeArchived: false,
        objectType: kind,
        signal,
        tenantId: tenantId ?? "",
      }),
    staleTime: 30_000,
  });
  const customFieldDefinitions = canReadCustomFields
    ? customFieldsQuery.data
    : undefined;
  useLayoutEffect(() => {
    contextTokenRef.current = { key: currentDraftContext, token: {} };
    setDraft(initialDraft);
    setCustomFieldDrafts({});
    setCustomFieldErrors({});
    setError(null);
    setSaving(false);
    setDraftContext(currentDraftContext);
    idempotencyRef.current = null;
    return () => {
      contextTokenRef.current = { key: "", token: {} };
    };
  }, [currentDraftContext]);
  useEffect(() => {
    if (!customFieldDefinitions) return;
    setCustomFieldDrafts((current) =>
      Object.keys(current).length > 0
        ? current
        : draftsFromDefaults(customFieldDefinitions, "operator"),
    );
  }, [customFieldDefinitions]);
  return {
    customFieldApi,
    kind,
    api,
    session,
    authority,
    navigate,
    draft,
    setDraft,
    customFieldDrafts,
    setCustomFieldDrafts,
    customFieldErrors,
    setCustomFieldErrors,
    error,
    setError,
    saving,
    setSaving,
    tenantId,
    currentDraftContext,
    draftContext,
    setDraftContext,
    idempotencyRef,
    contextTokenRef,
    Icon,
    canCreate,
    canReadCustomFields,
    customFieldsQuery,
    customFieldDefinitions,
  };
}

function createTicketCreatePageActions({
  kind,
  api,
  session,
  navigate,
  draft,
  customFieldDrafts,
  setCustomFieldErrors,
  setError,
  setSaving,
  currentDraftContext,
  draftContext,
  idempotencyRef,
  contextTokenRef,
  canReadCustomFields,
  customFieldDefinitions,
  activeTenantId,
}: ReturnType<typeof useTicketCreatePageState> & { activeTenantId: string }) {
  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (draftContext !== currentDraftContext) {
      setError(
        "The active tenant changed. Wait for the new form context before submitting.",
      );
      return;
    }
    const title = draft.title.trim();
    const description = draft.description.trim();
    if (!title) {
      setError("Enter a title for this ticket.");
      return;
    }
    if (title.length > 240 || description.length > 20_000) {
      setError(
        "Use a title of 240 characters or fewer and a description of 20,000 characters or fewer.",
      );
      return;
    }

    const tags = parseTagInput(draft.tags);
    const invalidTag = tags.find((tag) => !ticketTagPattern.test(tag));
    if (tags.length > 100 || invalidTag) {
      setError(
        invalidTag
          ? `Tag ${invalidTag.slice(0, 64)} is invalid. Use 1–64 letters, numbers, dots, colons, underscores, or hyphens.`
          : "Use no more than 100 unique tags.",
      );
      return;
    }

    if (canReadCustomFields && !customFieldDefinitions) {
      setError(
        "Custom-field definitions are not ready. Reload them before creating the ticket.",
      );
      return;
    }
    const customFields = customFieldValuesFromDrafts(
      customFieldDefinitions ?? [],
      customFieldDrafts,
      "operator",
      "create",
    );
    setCustomFieldErrors(customFields.errors);
    if (Object.keys(customFields.errors).length > 0) {
      setError(
        "Review the highlighted custom fields before creating the ticket.",
      );
      return;
    }

    const common = {
      title,
      description,
      severity: draft.severity,
      priority: draft.priority,
      category: draft.category.trim() || "general",
      customerVisible: draft.customerVisible,
      tags,
      ...(Object.keys(customFields.values).length > 0
        ? { customFields: customFields.values }
        : {}),
      ...(draft.classification.trim()
        ? { classification: draft.classification.trim() }
        : {}),
      ...(draft.workflowId.trim()
        ? { workflowId: draft.workflowId.trim() }
        : {}),
      ...(draft.assignedTeamId.trim()
        ? { assignedTeamId: draft.assignedTeamId.trim() }
        : {}),
    };
    const body =
      kind === "alert"
        ? {
            ...common,
            source: draft.source.trim() || "operator-console",
            sourceType: draft.sourceType.trim() || "manual",
          }
        : {
            ...common,
            ...(draft.summary.trim() ? { summary: draft.summary.trim() } : {}),
          };
    const idempotencyKey = idempotencyKeyForPayload(idempotencyRef, {
      body,
      kind,
      tenantId: activeTenantId,
    });
    const submissionContext = contextTokenRef.current.token;
    setError(null);
    setSaving(true);
    try {
      if (kind === "alert") {
        const created = await api.createAlert({
          body,
          csrfToken: session.csrfToken,
          idempotencyKey,
          tenantId: activeTenantId,
        });
        if (contextTokenRef.current.token !== submissionContext) return;
        idempotencyRef.current = null;
        void navigate(`/alerts/${created.id}`, { replace: true });
      } else {
        const created = await api.createCase({
          body,
          csrfToken: session.csrfToken,
          idempotencyKey,
          tenantId: activeTenantId,
        });
        if (contextTokenRef.current.token !== submissionContext) return;
        idempotencyRef.current = null;
        void navigate(`/cases/${created.value.id}`, { replace: true });
      }
    } catch (caught) {
      if (contextTokenRef.current.token === submissionContext) {
        setError(
          describeTicketingError(
            caught,
            `The ${kindLabel(kind).toLowerCase()} could not be created.`,
          ),
        );
      }
    } finally {
      if (contextTokenRef.current.token === submissionContext) {
        setSaving(false);
      }
    }
  }
  return { submit };
}

export function TicketCreatePage(props: {
  customFieldApi?: CustomFieldAdministrationApi;
  kind: TicketKind;
}): React.JSX.Element {
  const state = useTicketCreatePageState(props);
  const {
    kind,
    authority,
    draft,
    setDraft,
    customFieldDrafts,
    setCustomFieldDrafts,
    customFieldErrors,
    setCustomFieldErrors,
    error,
    saving,
    tenantId,
    currentDraftContext,
    draftContext,
    Icon,
    canCreate,
    canReadCustomFields,
    customFieldsQuery,
    customFieldDefinitions,
  } = state;
  if (!tenantId) {
    return (
      <TenantRequiredPage>
        New {kindLabelPlural(kind).toLowerCase()} require an active tenant.
      </TenantRequiredPage>
    );
  }
  const activeTenantId = tenantId;
  if (draftContext !== currentDraftContext) {
    return (
      <div className="content content--narrow" role="status">
        Resetting the governed create form for the active tenant…
      </div>
    );
  }
  if (authority.status !== "ready" || !canCreate) {
    return (
      <div className="content content--narrow">
        <FocusedError
          title={`${kindLabel(kind)} creation unavailable`}
          message={
            authority.status === "loading"
              ? "Live tenant authority is still being resolved. Creation stays closed until it is current."
              : "The live tenant authority does not expose this creation control. The backend remains the authorization boundary for every request."
          }
        />
      </div>
    );
  }
  const { submit } = createTicketCreatePageActions({
    ...state,
    activeTenantId,
  });
  return (
    <div className="content ticket-create-page">
      <Link
        className="ticket-back-link"
        to={`/${kind === "alert" ? "alerts" : "cases"}`}
      >
        <ArrowLeft aria-hidden="true" /> Back to {kindLabelPlural(kind)}
      </Link>
      <section
        className="ticket-create-layout"
        aria-labelledby="ticket-create-title"
      >
        <div className="ticket-create-intro">
          <span className="ticket-create-intro__icon" aria-hidden="true">
            <Icon />
          </span>
          <p className="section-label">
            New {kindLabel(kind)} / governed intake
          </p>
          <h1 id="ticket-create-title">Open a precise operational record.</h1>
          <p>
            The server pins the published workflow and creates audit, activity,
            SLA, and notification effects as one closed plan. Browser fields do
            not grant authority.
          </p>
          <span className="ticket-integrity-note">
            <ShieldCheck aria-hidden="true" /> One idempotency key is retained
            for each unchanged submission attempt.
          </span>
        </div>

        <form
          className="ticket-create-form"
          onSubmit={(event) => void submit(event)}
        >
          {error ? (
            <FocusedError message={error} title="Ticket not created" />
          ) : null}
          <FormField htmlFor="ticket-title" label="Title">
            <Input
              id="ticket-title"
              autoFocus
              maxLength={240}
              value={draft.title}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  title: event.target.value,
                }))
              }
            />
          </FormField>
          {kind === "case" ? (
            <FormField htmlFor="ticket-summary" label="Summary" optional>
              <Input
                id="ticket-summary"
                maxLength={500}
                value={draft.summary}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    summary: event.target.value,
                  }))
                }
              />
            </FormField>
          ) : null}
          <FormField htmlFor="ticket-description" label="Description" optional>
            <Textarea
              id="ticket-description"
              maxLength={20_000}
              rows={7}
              value={draft.description}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  description: event.target.value,
                }))
              }
            />
          </FormField>

          <TicketCreateMetadataFields
            draft={draft}
            kind={kind}
            setDraft={setDraft}
          />

          <FormField
            htmlFor="ticket-tags"
            label="Tags"
            optional
            hint="Comma-separated; duplicates are removed and values are ordered deterministically."
          >
            <Input
              id="ticket-tags"
              maxLength={1_000}
              value={draft.tags}
              onChange={(event) =>
                setDraft((current) => ({
                  ...current,
                  tags: event.target.value,
                }))
              }
            />
          </FormField>

          <label
            className="ticket-customer-toggle"
            htmlFor="ticket-customer-visible"
          >
            <Checkbox
              id="ticket-customer-visible"
              checked={draft.customerVisible}
              onCheckedChange={(checked) =>
                setDraft((current) => ({
                  ...current,
                  customerVisible: checked === true,
                }))
              }
            />
            <span>
              <strong>Customer visible</strong>
              <small>
                The backend still produces a separate allowlisted customer
                projection.
              </small>
            </span>
          </label>

          <TicketCreateCustomFields
            canReadCustomFields={canReadCustomFields}
            customFieldDefinitions={customFieldDefinitions}
            customFieldDrafts={customFieldDrafts}
            customFieldErrors={customFieldErrors}
            customFieldsQuery={customFieldsQuery}
            saving={saving}
            setCustomFieldDrafts={setCustomFieldDrafts}
            setCustomFieldErrors={setCustomFieldErrors}
          />
          <div className="form-actions">
            <Button
              type="submit"
              disabled={
                saving ||
                (canReadCustomFields && !customFieldsQuery.isSuccess) ||
                draftContext !== currentDraftContext
              }
            >
              {saving
                ? `Creating ${kindLabel(kind).toLowerCase()}…`
                : `Create ${kindLabel(kind).toLowerCase()}`}
            </Button>
            <Button asChild type="button" variant="ghost">
              <Link to={`/${kind === "alert" ? "alerts" : "cases"}`}>
                Cancel
              </Link>
            </Button>
          </div>
        </form>
      </section>
    </div>
  );
}

const ticketTagPattern = /^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,63}$/u;

interface TicketCreateCustomFieldsProps {
  canReadCustomFields: ReturnType<
    typeof useTicketCreatePageState
  >["canReadCustomFields"];
  customFieldDefinitions: ReturnType<
    typeof useTicketCreatePageState
  >["customFieldDefinitions"];
  customFieldDrafts: ReturnType<
    typeof useTicketCreatePageState
  >["customFieldDrafts"];
  customFieldErrors: ReturnType<
    typeof useTicketCreatePageState
  >["customFieldErrors"];
  customFieldsQuery: ReturnType<
    typeof useTicketCreatePageState
  >["customFieldsQuery"];
  saving: ReturnType<typeof useTicketCreatePageState>["saving"];
  setCustomFieldDrafts: ReturnType<
    typeof useTicketCreatePageState
  >["setCustomFieldDrafts"];
  setCustomFieldErrors: ReturnType<
    typeof useTicketCreatePageState
  >["setCustomFieldErrors"];
}

function TicketCreateCustomFields({
  canReadCustomFields,
  customFieldDefinitions,
  customFieldDrafts,
  customFieldErrors,
  customFieldsQuery,
  saving,
  setCustomFieldDrafts,
  setCustomFieldErrors,
}: TicketCreateCustomFieldsProps): React.JSX.Element {
  return (
    <>
      {canReadCustomFields && customFieldsQuery.isPending ? (
        <p className="custom-field-empty" role="status" aria-live="polite">
          Loading the current custom-field schema…
        </p>
      ) : null}
      {canReadCustomFields && customFieldsQuery.isError ? (
        <div>
          <FocusedError
            title="Custom fields unavailable"
            message="The governed field schema could not be loaded. Ticket creation stays closed so required values are never omitted."
          />
          <Button
            type="button"
            variant="outline"
            onClick={() => void customFieldsQuery.refetch()}
          >
            Retry custom fields
          </Button>
        </div>
      ) : null}
      {customFieldDefinitions ? (
        <DynamicFieldForm
          audience="operator"
          definitions={customFieldDefinitions}
          disabled={saving}
          drafts={customFieldDrafts}
          errors={customFieldErrors}
          phase="create"
          onChange={(key, value) => {
            setCustomFieldDrafts((current) => ({
              ...current,
              [key]: value,
            }));
            setCustomFieldErrors((current) => {
              if (!(key in current)) return current;
              return Object.fromEntries(
                Object.entries(current).filter(([entry]) => entry !== key),
              );
            });
          }}
        />
      ) : null}
    </>
  );
}

export type TicketCreatePageState = ReturnType<typeof useTicketCreatePageState>;
