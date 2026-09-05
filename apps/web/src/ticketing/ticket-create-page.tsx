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
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router";

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
  alertSeverities,
  hasAnyTicketPermission,
  humanizeKey,
  kindLabel,
  kindLabelPlural,
  parseTagInput,
  ticketPriorities,
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

export function TicketCreatePage({
  customFieldApi = customFieldAdministrationApi,
  kind,
}: {
  customFieldApi?: CustomFieldAdministrationApi;
  kind: TicketKind;
}): React.JSX.Element {
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
  if (contextTokenRef.current.key !== currentDraftContext) {
    contextTokenRef.current = { key: currentDraftContext, token: {} };
  }
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

  useEffect(() => {
    setDraft(initialDraft);
    setCustomFieldDrafts({});
    setCustomFieldErrors({});
    setError(null);
    setSaving(false);
    setDraftContext(currentDraftContext);
    idempotencyRef.current = null;
  }, [currentDraftContext]);

  useEffect(() => {
    if (!customFieldDefinitions) return;
    setCustomFieldDrafts((current) =>
      Object.keys(current).length > 0
        ? current
        : draftsFromDefaults(customFieldDefinitions, "operator"),
    );
  }, [customFieldDefinitions]);

  if (!tenantId) {
    return (
      <div className="content content--narrow">
        <section className="page-heading">
          <div>
            <p className="section-label">Tenant context required</p>
            <h1>Select a tenant first.</h1>
            <p>
              New {kindLabelPlural(kind).toLowerCase()} require an active
              tenant.
            </p>
          </div>
        </section>
      </div>
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

          <div className="ticket-create-form__grid">
            <NativeField
              label="Severity"
              value={draft.severity}
              options={alertSeverities}
              onChange={(severity) =>
                setDraft((current) => ({ ...current, severity }))
              }
            />
            <NativeField
              label="Priority"
              value={draft.priority}
              options={ticketPriorities}
              onChange={(priority) =>
                setDraft((current) => ({ ...current, priority }))
              }
            />
            <FormField htmlFor="ticket-category" label="Category">
              <Input
                id="ticket-category"
                maxLength={100}
                value={draft.category}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    category: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField
              htmlFor="ticket-classification"
              label="Classification"
              optional
            >
              <Input
                id="ticket-classification"
                maxLength={100}
                value={draft.classification}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    classification: event.target.value,
                  }))
                }
              />
            </FormField>
            {kind === "alert" ? (
              <>
                <FormField htmlFor="ticket-source" label="Source">
                  <Input
                    id="ticket-source"
                    maxLength={120}
                    value={draft.source}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        source: event.target.value,
                      }))
                    }
                  />
                </FormField>
                <FormField htmlFor="ticket-source-type" label="Source type">
                  <Input
                    id="ticket-source-type"
                    maxLength={120}
                    value={draft.sourceType}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        sourceType: event.target.value,
                      }))
                    }
                  />
                </FormField>
              </>
            ) : null}
            <FormField htmlFor="ticket-workflow" label="Workflow ID" optional>
              <Input
                id="ticket-workflow"
                value={draft.workflowId}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    workflowId: event.target.value,
                  }))
                }
              />
            </FormField>
            <FormField htmlFor="ticket-team" label="Assigned team ID" optional>
              <Input
                id="ticket-team"
                value={draft.assignedTeamId}
                onChange={(event) =>
                  setDraft((current) => ({
                    ...current,
                    assignedTeamId: event.target.value,
                  }))
                }
              />
            </FormField>
          </div>

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

function NativeField<T extends string>({
  label,
  onChange,
  options,
  value,
}: {
  label: string;
  onChange: (value: T) => void;
  options: readonly T[];
  value: T;
}): React.JSX.Element {
  return (
    <label className="ticket-native-field">
      <span>{label}</span>
      <select
        value={value}
        onChange={(event) => {
          const selected = options.find(
            (option) => option === event.target.value,
          );
          if (selected !== undefined) onChange(selected);
        }}
      >
        {options.map((option) => (
          <option key={option} value={option}>
            {humanizeKey(option)}
          </option>
        ))}
      </select>
    </label>
  );
}
