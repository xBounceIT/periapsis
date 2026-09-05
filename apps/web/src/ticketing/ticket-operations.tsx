import type {
  AlertCaseEscalationRequest,
  EscalationCopyField,
  EscalationCopySelection,
  WorkflowActionHint,
} from "@periapsis/contracts";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  ArrowRightLeft,
  BadgeCheck,
  GitBranch,
  Hand,
  Handshake,
  Route,
  Trash2,
  UserRoundCog,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { useAlertDfirApi } from "../dfir/alert-dfir-context";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import {
  describeTicketingError,
  TicketingApiError,
  type OperatorTicketProjection,
  type TicketKind,
  type VersionedTicket,
} from "../lib/ticketing-api";
import { useTicketingApi } from "./ticketing-context";
import {
  EscalationInventoryError,
  loadEscalationInventory,
  setBoundedSelection,
  type EscalationInventory,
} from "./escalation-inventory";
import {
  codePointCompare,
  compactIdentifier,
  hasAnyTicketPermission,
  humanizeKey,
  kindLabel,
} from "./ticketing-model";

type Operation =
  | "assign"
  | "claim"
  | "delete"
  | "escalate"
  | "release"
  | "transfer"
  | "transition";

interface OperationDraft {
  assigneeId: string;
  customFields: Record<string, string>;
  deleteConfirmation: string;
  escalationCaseId: string;
  escalationCaseVersion: string;
  escalationMode: "create_case" | "existing_case";
  escalationTitle: string;
  reason: string;
  teamId: string;
  transitionKey: string;
}

type EscalationInventoryState =
  | { status: "idle" }
  | { status: "loading" }
  | { message: string; status: "error" }
  | { status: "ready"; value: EscalationInventory };

type EscalationInventoryCategory =
  "assets" | "attachments" | "contacts" | "iocs" | "publicComments";

const escalationCopyFields = [
  "title",
  "description",
  "severity",
  "priority",
  "category",
  "tags",
] as const satisfies readonly EscalationCopyField[];

export function TicketOperations({
  kind,
  onCommitted,
  onConflict,
  onDeleted,
  onEscalated,
  ticket,
}: {
  kind: TicketKind;
  onCommitted: (value: VersionedTicket<OperatorTicketProjection>) => void;
  onConflict: () => Promise<unknown>;
  onDeleted: () => void;
  onEscalated: (caseId: string) => void;
  ticket: VersionedTicket<OperatorTicketProjection>;
}): React.JSX.Element | null {
  const api = useTicketingApi();
  const dfirApi = useAlertDfirApi();
  const { session } = useSession();
  const authority = useTenantAuthority();
  const [operation, setOperation] = useState<Operation | null>(null);
  const [draft, setDraft] = useState<OperationDraft>(() =>
    initialDraft(ticket),
  );
  const [copyFields, setCopyFields] = useState<Set<EscalationCopyField>>(
    () => new Set(escalationCopyFields),
  );
  const [copyCustomFieldKeys, setCopyCustomFieldKeys] = useState<Set<string>>(
    () => new Set(),
  );
  const [copyIocIds, setCopyIocIds] = useState<Set<string>>(() => new Set());
  const [copyAssetIds, setCopyAssetIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [copyAttachmentIds, setCopyAttachmentIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [copyContactIds, setCopyContactIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [copyPublicCommentIds, setCopyPublicCommentIds] = useState<Set<string>>(
    () => new Set(),
  );
  const [inventoryState, setInventoryState] =
    useState<EscalationInventoryState>({ status: "idle" });
  const [inventoryRevision, setInventoryRevision] = useState(0);
  const inventoryAbortRef = useRef<AbortController | null>(null);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const attemptRef = useRef<IdempotencyReference["current"]>(null);
  const tenantId = session.activeTenantId;
  const value = ticket.value;
  const escalationCustomFieldKeys = useMemo(
    () => Object.keys(value.customFields).toSorted(),
    [value.customFields],
  );
  const transitions = value.availableTransitions ?? [];
  const canTransition = hasAnyTicketPermission(
    authority.hasPermission,
    kind === "alert" ? "alert.update" : "case.transition",
  );
  const canAssign = hasAnyTicketPermission(
    authority.hasPermission,
    kind === "alert" ? "alert.assign" : "case.transfer",
  );
  const canClaim = hasAnyTicketPermission(
    authority.hasPermission,
    kind === "alert" ? "alert.claim" : "case.claim",
  );
  const canEscalate =
    kind === "alert" &&
    hasAnyTicketPermission(authority.hasPermission, "alert.escalate");
  const canDelete =
    kind === "alert" &&
    hasAnyTicketPermission(authority.hasPermission, "alert.delete");
  const eligibleTeams = useMemo(
    () =>
      [
        ...(value.assignment.assignedTeamId
          ? [value.assignment.assignedTeamId]
          : []),
        ...(authority.authority?.operatorTeamRelationships.map(
          (relationship) => relationship.operatorTeamId,
        ) ?? []),
      ].filter((teamId, index, values) => values.indexOf(teamId) === index),
    [
      authority.authority?.operatorTeamRelationships,
      value.assignment.assignedTeamId,
    ],
  );

  useEffect(() => {
    inventoryAbortRef.current?.abort();
    inventoryAbortRef.current = null;
    if (operation !== "escalate" || kind !== "alert" || !tenantId) {
      setInventoryState({ status: "idle" });
      return undefined;
    }
    const controller = new AbortController();
    inventoryAbortRef.current = controller;
    setCopyIocIds(new Set());
    setCopyAssetIds(new Set());
    setCopyAttachmentIds(new Set());
    setCopyContactIds(new Set());
    setCopyPublicCommentIds(new Set());
    attemptRef.current = null;
    setInventoryState({ status: "loading" });
    void loadEscalationInventory({
      alertId: value.id,
      dfirApi,
      signal: controller.signal,
      tenantId,
      ticketingApi: api,
    })
      .then((inventory) => {
        if (!controller.signal.aborted) {
          setInventoryState({ status: "ready", value: inventory });
        }
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        setInventoryState({
          message:
            caught instanceof EscalationInventoryError
              ? caught.message
              : "The bounded escalation inventory is unavailable. Nothing can be selected until a retry succeeds.",
          status: "error",
        });
      });
    return () => {
      controller.abort();
      if (inventoryAbortRef.current === controller) {
        inventoryAbortRef.current = null;
      }
    };
  }, [api, dfirApi, inventoryRevision, kind, operation, tenantId, value.id]);

  if (!tenantId) return null;
  const activeTenantId = tenantId;

  function open(next: Operation): void {
    setDraft(initialDraft(ticket, eligibleTeams));
    setCopyFields(new Set(escalationCopyFields));
    setCopyCustomFieldKeys(new Set());
    setCopyIocIds(new Set());
    setCopyAssetIds(new Set());
    setCopyAttachmentIds(new Set());
    setCopyContactIds(new Set());
    setCopyPublicCommentIds(new Set());
    setInventoryRevision(0);
    setInventoryState({ status: next === "escalate" ? "loading" : "idle" });
    setError(null);
    setSaving(false);
    attemptRef.current = null;
    setOperation(next);
  }

  function close(): void {
    if (saving) return;
    inventoryAbortRef.current?.abort();
    inventoryAbortRef.current = null;
    attemptRef.current = null;
    setOperation(null);
    setError(null);
  }

  function changeInventorySelection(
    category: EscalationInventoryCategory,
    id: string,
    checked: boolean,
  ): void {
    const selections = {
      assets: [copyAssetIds, setCopyAssetIds],
      attachments: [copyAttachmentIds, setCopyAttachmentIds],
      contacts: [copyContactIds, setCopyContactIds],
      iocs: [copyIocIds, setCopyIocIds],
      publicComments: [copyPublicCommentIds, setCopyPublicCommentIds],
    } as const;
    const [current, commit] = selections[category];
    try {
      commit(setBoundedSelection(current, id, checked));
      setError(null);
    } catch (caught) {
      setError(
        caught instanceof EscalationInventoryError
          ? caught.message
          : "The copy selection could not be changed safely.",
      );
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!operation) return;
    setError(null);
    setSaving(true);
    try {
      if (operation === "escalate") {
        await submitEscalation();
        return;
      }
      if (operation === "delete") {
        await submitDelete();
        return;
      }
      const expectedVersion = value.version;
      const reason = draft.reason.trim();
      const common = {
        csrfToken: session.csrfToken,
        etag: ticket.etag,
        kind,
        resourceId: value.id,
        tenantId: activeTenantId,
      } as const;
      let result: VersionedTicket<OperatorTicketProjection>;
      switch (operation) {
        case "assign": {
          const teamId = draft.teamId.trim();
          if (!teamId) throw new Error("Select or enter an assigned team ID.");
          result = await api.mutateTicket({
            ...common,
            action: "assign",
            body: {
              expectedVersion,
              assignedTeamId: teamId,
              ...(draft.assigneeId.trim()
                ? { assigneeUserId: draft.assigneeId.trim() }
                : {}),
              ...(reason ? { reason } : {}),
            },
          });
          break;
        }
        case "claim": {
          const teamId = claimTeam(
            value.assignment.assignedTeamId,
            eligibleTeams,
            draft.teamId,
          );
          if (!teamId) {
            throw new Error(
              "Choose one live operator team before claiming this unassigned ticket.",
            );
          }
          result = await api.mutateTicket({
            ...common,
            action: "claim",
            body: {
              expectedVersion,
              operatorTeamId: teamId,
              ...(reason ? { reason } : {}),
            },
          });
          break;
        }
        case "release":
          if (!reason)
            throw new Error("Enter a reason for releasing the claim.");
          result = await api.mutateTicket({
            ...common,
            action: "release",
            body: { expectedVersion, reason },
          });
          break;
        case "transfer": {
          const teamId = draft.teamId.trim();
          if (!teamId) throw new Error("Enter the destination team ID.");
          if (!reason) throw new Error("Enter a reason for the transfer.");
          result = await api.mutateTicket({
            ...common,
            action: "transfer",
            body: {
              expectedVersion,
              destinationTeamId: teamId,
              ...(draft.assigneeId.trim()
                ? { destinationAssigneeUserId: draft.assigneeId.trim() }
                : {}),
              reason,
            },
          });
          break;
        }
        case "transition": {
          const transition = transitions.find(
            (candidate) => candidate.transitionKey === draft.transitionKey,
          );
          if (!transition)
            throw new Error("Select a server-provided transition.");
          if (transition.commentRequired && !reason) {
            throw new Error("This workflow transition requires a comment.");
          }
          const customFields = transition.requiredCustomFieldKeys.reduce<
            Record<string, string>
          >((fields, key) => {
            const fieldValue = draft.customFields[key]?.trim();
            if (!fieldValue) {
              throw new Error(`Enter the required custom field ${key}.`);
            }
            fields[key] = fieldValue;
            return fields;
          }, {});
          const body = {
            expectedVersion,
            transitionKey: transition.transitionKey,
            targetStateKey: transition.targetStateKey,
            ...(reason ? { comment: reason } : {}),
            ...(Object.keys(customFields).length > 0 ? { customFields } : {}),
          };
          const idempotencyKey = idempotencyKeyForPayload(attemptRef, {
            body,
            operation,
            resourceId: value.id,
            tenantId: activeTenantId,
          });
          result = await api.mutateTicket({
            ...common,
            action: "transition",
            body,
            idempotencyKey,
          });
          break;
        }
      }
      attemptRef.current = null;
      setOperation(null);
      onCommitted(result);
    } catch (caught) {
      if (
        caught instanceof TicketingApiError &&
        [409, 412].includes(caught.status ?? 0)
      ) {
        await onConflict();
      }
      setError(
        describeTicketingError(
          caught,
          caught instanceof Error
            ? caught.message
            : "The ticket operation could not be completed.",
        ),
      );
    } finally {
      setSaving(false);
    }
  }

  async function submitEscalation(): Promise<void> {
    if (kind !== "alert") throw new Error("Only Alerts can be escalated.");
    if (inventoryState.status !== "ready") {
      throw new Error(
        "Wait for every bounded copy-selection inventory to load successfully before escalating.",
      );
    }
    const reason = draft.reason.trim();
    if (!reason) throw new Error("Enter the investigation reason.");
    const customFieldKeys = escalationCustomFieldKeys.filter((key) =>
      copyCustomFieldKeys.has(key),
    );
    const iocIds = selectedInventoryIds(
      copyIocIds,
      inventoryState.value.iocs.map((item) => item.id),
    );
    const assetIds = selectedInventoryIds(
      copyAssetIds,
      inventoryState.value.assets.map((item) => item.id),
    );
    const attachmentIds = selectedInventoryIds(
      copyAttachmentIds,
      inventoryState.value.attachments.map((item) => item.id),
    );
    const contactIds = selectedInventoryIds(
      copyContactIds,
      inventoryState.value.contacts.map((item) => item.contactId),
    );
    const publicCommentIds = selectedInventoryIds(
      copyPublicCommentIds,
      inventoryState.value.publicComments.map((item) => item.id),
    );
    const copySelection: EscalationCopySelection = {
      fields: [...copyFields].toSorted(codePointCompare),
      ...(customFieldKeys.length > 0 ? { customFieldKeys } : {}),
      ...(iocIds.length > 0 ? { iocIds } : {}),
      ...(assetIds.length > 0 ? { assetIds } : {}),
      ...(attachmentIds.length > 0 ? { attachmentIds } : {}),
      ...(contactIds.length > 0 ? { contactIds } : {}),
      ...(publicCommentIds.length > 0 ? { publicCommentIds } : {}),
    };
    const target: AlertCaseEscalationRequest["target"] =
      draft.escalationMode === "create_case"
        ? {
            mode: "create_case",
            case: {
              title: draft.escalationTitle.trim() || value.title,
              summary: `Escalated from ${alertNumber(value)}`,
              description: value.description,
              severity: value.severity,
              priority: value.priority,
              category: value.category,
              customerVisible: value.customerVisible,
            },
          }
        : {
            mode: "existing_case",
            caseId: draft.escalationCaseId.trim(),
            expectedVersion: parsePositiveVersion(draft.escalationCaseVersion),
          };
    if (target.mode === "existing_case" && !target.caseId) {
      throw new Error("Enter the existing Case ID.");
    }
    const body: AlertCaseEscalationRequest = {
      expectedVersion: value.version,
      sources: [
        {
          alertId: value.id,
          expectedVersion: value.version,
          copySelection,
        },
      ],
      target,
      relationType: "escalation",
      reason,
    };
    const idempotencyKey = idempotencyKeyForPayload(attemptRef, {
      body,
      operation: target.mode === "existing_case" ? "link" : "escalate",
      tenantId: activeTenantId,
    });
    const result = await api.escalateAlert({
      body,
      csrfToken: session.csrfToken,
      etag: ticket.etag,
      idempotencyKey,
      resourceId: value.id,
      tenantId: activeTenantId,
    });
    attemptRef.current = null;
    setOperation(null);
    onEscalated(result.case.id);
  }

  async function submitDelete(): Promise<void> {
    if (kind !== "alert") throw new Error("Only Alerts can be deleted.");
    const reason = draft.reason.trim();
    if (!reason) throw new Error("Enter the reason for deleting this Alert.");
    const expectedConfirmation = alertNumber(value);
    if (draft.deleteConfirmation.trim() !== expectedConfirmation) {
      throw new Error(
        `Type ${expectedConfirmation} exactly to confirm deletion.`,
      );
    }
    const body = { expectedVersion: value.version, reason };
    const idempotencyKey = idempotencyKeyForPayload(attemptRef, {
      body,
      operation: "delete",
      resourceId: value.id,
      tenantId: activeTenantId,
    });
    await api.deleteAlert({
      body,
      csrfToken: session.csrfToken,
      etag: ticket.etag,
      idempotencyKey,
      resourceId: value.id,
      tenantId: activeTenantId,
    });
    attemptRef.current = null;
    setOperation(null);
    onDeleted();
  }

  const selectedTransition = transitions.find(
    (transition) => transition.transitionKey === draft.transitionKey,
  );

  return (
    <>
      <div
        className="ticket-action-bar"
        aria-label={`${kindLabel(kind)} actions`}
      >
        {canTransition && transitions.length > 0 ? (
          <Button size="sm" onClick={() => open("transition")}>
            <Route aria-hidden="true" /> Transition
          </Button>
        ) : null}
        {canAssign ? (
          <Button size="sm" variant="outline" onClick={() => open("assign")}>
            <UserRoundCog aria-hidden="true" /> Assign
          </Button>
        ) : null}
        {canClaim && !value.assignment.claimedBy ? (
          <Button size="sm" variant="outline" onClick={() => open("claim")}>
            <Hand aria-hidden="true" /> Claim
          </Button>
        ) : null}
        {canClaim && value.assignment.claimedBy ? (
          <Button size="sm" variant="outline" onClick={() => open("release")}>
            <Handshake aria-hidden="true" /> Release
          </Button>
        ) : null}
        {canAssign && value.assignment.assignedTeamId ? (
          <Button size="sm" variant="outline" onClick={() => open("transfer")}>
            <ArrowRightLeft aria-hidden="true" /> Transfer
          </Button>
        ) : null}
        {canEscalate ? (
          <Button size="sm" variant="outline" onClick={() => open("escalate")}>
            <GitBranch aria-hidden="true" /> Escalate
          </Button>
        ) : null}
        {canDelete ? (
          <Button
            size="sm"
            variant="destructive"
            onClick={() => open("delete")}
          >
            <Trash2 aria-hidden="true" /> Delete Alert
          </Button>
        ) : null}
      </div>

      <Dialog
        open={operation !== null}
        onOpenChange={(openState) => !openState && close()}
      >
        <DialogContent className="ticket-operation-dialog">
          <DialogHeader>
            <DialogTitle>
              {operation ? operationTitle(operation, kind) : "Ticket action"}
            </DialogTitle>
            <DialogDescription>
              {operation === "delete"
                ? `This removes ${alertNumber(value)} from every ordinary view. Audit and retention evidence remain. Server policy and live authority are rechecked.`
                : `This command uses version ${value.version}. Server policy, workflow, and live team authority are rechecked when it runs.`}
            </DialogDescription>
          </DialogHeader>
          <form
            className="ticket-operation-form"
            onSubmit={(event) => void submit(event)}
          >
            {error ? (
              <FocusedError message={error} title="Action not completed" />
            ) : null}
            {operation === "transition" ? (
              <>
                <label className="ticket-native-field">
                  <span>Server-provided transition</span>
                  <select
                    value={draft.transitionKey}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        transitionKey: event.target.value,
                      }))
                    }
                  >
                    <option value="">Select a transition</option>
                    {transitions.map((transition) => (
                      <option
                        value={transition.transitionKey}
                        key={transition.transitionKey}
                      >
                        {humanizeKey(transition.transitionKey)} →{" "}
                        {humanizeKey(transition.targetStateKey)}
                      </option>
                    ))}
                  </select>
                </label>
                {selectedTransition?.requiredCustomFieldKeys.map((key) => (
                  <FormField
                    htmlFor={`transition-${key}`}
                    label={humanizeKey(key)}
                    key={key}
                  >
                    <Input
                      id={`transition-${key}`}
                      value={draft.customFields[key] ?? ""}
                      onChange={(event) =>
                        setDraft((current) => ({
                          ...current,
                          customFields: {
                            ...current.customFields,
                            [key]: event.target.value,
                          },
                        }))
                      }
                    />
                  </FormField>
                ))}
              </>
            ) : null}

            {operation === "assign" || operation === "transfer" ? (
              <>
                <FormField
                  htmlFor="operation-team"
                  label={
                    operation === "transfer"
                      ? "Destination team ID"
                      : "Assigned team ID"
                  }
                >
                  <Input
                    id="operation-team"
                    list="eligible-ticket-teams"
                    value={draft.teamId}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        teamId: event.target.value,
                      }))
                    }
                  />
                  <datalist id="eligible-ticket-teams">
                    {eligibleTeams.map((teamId) => (
                      <option value={teamId} key={teamId} />
                    ))}
                  </datalist>
                </FormField>
                <FormField
                  htmlFor="operation-assignee"
                  label="Assignee user ID"
                  optional
                >
                  <Input
                    id="operation-assignee"
                    value={draft.assigneeId}
                    onChange={(event) =>
                      setDraft((current) => ({
                        ...current,
                        assigneeId: event.target.value,
                      }))
                    }
                  />
                </FormField>
              </>
            ) : null}

            {operation === "claim" ? (
              <ClaimTeamField
                assignedTeamId={value.assignment.assignedTeamId}
                draftTeamId={draft.teamId}
                eligibleTeams={eligibleTeams}
                onChange={(teamId) =>
                  setDraft((current) => ({ ...current, teamId }))
                }
              />
            ) : null}

            {operation === "escalate" ? (
              <EscalationFields
                availableCustomFieldKeys={escalationCustomFieldKeys}
                copyCustomFieldKeys={copyCustomFieldKeys}
                copyFields={copyFields}
                draft={draft}
                inventoryState={inventoryState}
                selections={{
                  assets: copyAssetIds,
                  attachments: copyAttachmentIds,
                  contacts: copyContactIds,
                  iocs: copyIocIds,
                  publicComments: copyPublicCommentIds,
                }}
                onCopyFieldChange={(field, checked) =>
                  setCopyFields((current) => {
                    const next = new Set(current);
                    if (checked) next.add(field);
                    else next.delete(field);
                    return next;
                  })
                }
                onCopyCustomFieldChange={(key, checked) =>
                  setCopyCustomFieldKeys((current) => {
                    const next = new Set(current);
                    if (checked) next.add(key);
                    else next.delete(key);
                    return next;
                  })
                }
                onDraftChange={(change) =>
                  setDraft((current) => ({ ...current, ...change }))
                }
                onInventoryRetry={() => {
                  setError(null);
                  setInventoryRevision((current) => current + 1);
                }}
                onInventorySelectionChange={changeInventorySelection}
              />
            ) : null}

            {operation === "delete" ? (
              <FormField
                htmlFor="operation-delete-confirmation"
                label={`Type ${alertNumber(value)} to confirm`}
              >
                <Input
                  id="operation-delete-confirmation"
                  autoComplete="off"
                  value={draft.deleteConfirmation}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      deleteConfirmation: event.target.value,
                    }))
                  }
                />
              </FormField>
            ) : null}

            {operation ? (
              <FormField
                htmlFor="operation-reason"
                label={operation === "transition" ? "Comment" : "Reason"}
                optional={
                  operation === "assign" ||
                  operation === "claim" ||
                  (operation === "transition" &&
                    !selectedTransition?.commentRequired)
                }
              >
                <Textarea
                  id="operation-reason"
                  rows={3}
                  maxLength={2_000}
                  value={draft.reason}
                  onChange={(event) =>
                    setDraft((current) => ({
                      ...current,
                      reason: event.target.value,
                    }))
                  }
                />
              </FormField>
            ) : null}

            <DialogFooter>
              <Button
                type="button"
                variant="ghost"
                onClick={close}
                disabled={saving}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                variant={operation === "delete" ? "destructive" : "default"}
                disabled={
                  saving ||
                  (operation === "escalate" &&
                    inventoryState.status !== "ready")
                }
              >
                {operation === "delete" ? (
                  <Trash2 aria-hidden="true" />
                ) : (
                  <BadgeCheck aria-hidden="true" />
                )}
                {saving
                  ? operation === "delete"
                    ? "Deleting Alert…"
                    : "Applying action…"
                  : operation === "delete"
                    ? "Delete Alert"
                    : "Apply action"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

function ClaimTeamField({
  assignedTeamId,
  draftTeamId,
  eligibleTeams,
  onChange,
}: {
  assignedTeamId: string | null;
  draftTeamId: string;
  eligibleTeams: string[];
  onChange: (teamId: string) => void;
}): React.JSX.Element {
  if (assignedTeamId) {
    return (
      <div className="ticket-claim-context">
        <small>Assigned team</small>
        <strong>{compactIdentifier(assignedTeamId)}</strong>
      </div>
    );
  }
  if (eligibleTeams.length === 1) {
    return (
      <div className="ticket-claim-context">
        <small>Only live eligible team</small>
        <strong>{compactIdentifier(eligibleTeams[0])}</strong>
      </div>
    );
  }
  return (
    <label className="ticket-native-field">
      <span>Live operator team</span>
      <select
        value={draftTeamId}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">Select one exact team</option>
        {eligibleTeams.map((teamId) => (
          <option value={teamId} key={teamId}>
            {compactIdentifier(teamId)}
          </option>
        ))}
      </select>
      {eligibleTeams.length === 0 ? (
        <small className="form-field__error">
          No live eligible operator team was returned. Claim stays closed.
        </small>
      ) : null}
    </label>
  );
}

function EscalationFields({
  availableCustomFieldKeys,
  copyCustomFieldKeys,
  copyFields,
  draft,
  inventoryState,
  onCopyCustomFieldChange,
  onCopyFieldChange,
  onDraftChange,
  onInventoryRetry,
  onInventorySelectionChange,
  selections,
}: {
  availableCustomFieldKeys: string[];
  copyCustomFieldKeys: Set<string>;
  copyFields: Set<EscalationCopyField>;
  draft: OperationDraft;
  inventoryState: EscalationInventoryState;
  onCopyCustomFieldChange: (key: string, checked: boolean) => void;
  onCopyFieldChange: (field: EscalationCopyField, checked: boolean) => void;
  onDraftChange: (change: Partial<OperationDraft>) => void;
  onInventoryRetry: () => void;
  onInventorySelectionChange: (
    category: EscalationInventoryCategory,
    id: string,
    checked: boolean,
  ) => void;
  selections: Record<EscalationInventoryCategory, ReadonlySet<string>>;
}): React.JSX.Element {
  return (
    <>
      <fieldset className="ticket-choice-group">
        <legend>Escalation target</legend>
        <label>
          <input
            type="radio"
            name="escalation-mode"
            checked={draft.escalationMode === "create_case"}
            onChange={() => onDraftChange({ escalationMode: "create_case" })}
          />
          Create a separate Case
        </label>
        <label>
          <input
            type="radio"
            name="escalation-mode"
            checked={draft.escalationMode === "existing_case"}
            onChange={() => onDraftChange({ escalationMode: "existing_case" })}
          />
          Link an existing Case
        </label>
      </fieldset>
      {draft.escalationMode === "create_case" ? (
        <FormField htmlFor="escalation-title" label="New Case title">
          <Input
            id="escalation-title"
            maxLength={240}
            value={draft.escalationTitle}
            onChange={(event) =>
              onDraftChange({ escalationTitle: event.target.value })
            }
          />
        </FormField>
      ) : (
        <div className="ticket-operation-grid">
          <FormField htmlFor="escalation-case-id" label="Case ID">
            <Input
              id="escalation-case-id"
              value={draft.escalationCaseId}
              onChange={(event) =>
                onDraftChange({ escalationCaseId: event.target.value })
              }
            />
          </FormField>
          <FormField
            htmlFor="escalation-case-version"
            label="Expected Case version"
          >
            <Input
              id="escalation-case-version"
              inputMode="numeric"
              value={draft.escalationCaseVersion}
              onChange={(event) =>
                onDraftChange({ escalationCaseVersion: event.target.value })
              }
            />
          </FormField>
        </div>
      )}
      <fieldset className="ticket-copy-fields">
        <legend>Explicit copied fields</legend>
        {escalationCopyFields.map((field) => (
          <label key={field}>
            <Checkbox
              checked={copyFields.has(field)}
              onCheckedChange={(checked) =>
                onCopyFieldChange(field, checked === true)
              }
            />
            {humanizeKey(field)}
          </label>
        ))}
      </fieldset>
      {availableCustomFieldKeys.length > 0 ? (
        <fieldset className="ticket-copy-fields">
          <legend>Explicit copied custom fields</legend>
          {availableCustomFieldKeys.map((key) => (
            <label key={key}>
              <Checkbox
                checked={copyCustomFieldKeys.has(key)}
                onCheckedChange={(checked) =>
                  onCopyCustomFieldChange(key, checked === true)
                }
              />
              {humanizeKey(key)}
            </label>
          ))}
        </fieldset>
      ) : null}
      <EscalationInventoryFields
        inventoryState={inventoryState}
        onRetry={onInventoryRetry}
        onSelectionChange={onInventorySelectionChange}
        selections={selections}
      />
    </>
  );
}

function EscalationInventoryFields({
  inventoryState,
  onRetry,
  onSelectionChange,
  selections,
}: {
  inventoryState: EscalationInventoryState;
  onRetry: () => void;
  onSelectionChange: (
    category: EscalationInventoryCategory,
    id: string,
    checked: boolean,
  ) => void;
  selections: Record<EscalationInventoryCategory, ReadonlySet<string>>;
}): React.JSX.Element {
  if (inventoryState.status === "idle" || inventoryState.status === "loading") {
    return (
      <div className="ticket-copy-inventory" role="status">
        Loading bounded IOC, asset, attachment, contact, and public-comment
        choices…
      </div>
    );
  }
  if (inventoryState.status === "error") {
    return (
      <div className="ticket-copy-inventory">
        <FocusedError
          message={inventoryState.message}
          title="Copy selections unavailable"
        />
        <Button type="button" variant="outline" onClick={onRetry}>
          Retry selection inventory
        </Button>
      </div>
    );
  }
  const inventory = inventoryState.value;
  return (
    <div className="ticket-copy-inventory">
      <p className="ticket-copy-inventory__note">
        Select exact records to copy. Unselected records are never copied, and
        private comments are never eligible.
      </p>
      <EscalationSelectionGroup
        category="iocs"
        items={inventory.iocs.map((item) => ({
          id: item.id,
          label: `${item.type}: ${item.value}`,
          detail: `${item.malicious} · ${item.confidence}% confidence`,
        }))}
        legend="IOCs"
        onChange={onSelectionChange}
        selected={selections.iocs}
      />
      <EscalationSelectionGroup
        category="assets"
        items={inventory.assets.map((item) => ({
          id: item.id,
          label: item.hostname ?? item.fqdn ?? compactIdentifier(item.id),
          detail: `${item.assetType} · ${item.criticality}`,
        }))}
        legend="Assets"
        onChange={onSelectionChange}
        selected={selections.assets}
      />
      <EscalationSelectionGroup
        category="attachments"
        items={inventory.attachments.map((item) => ({
          id: item.id,
          label: item.filename,
          detail: `${item.visibility} · ${item.scanState}`,
        }))}
        legend="Attachments"
        onChange={onSelectionChange}
        selected={selections.attachments}
      />
      <EscalationSelectionGroup
        category="contacts"
        items={inventory.contacts.map((item) => ({
          id: item.contactId,
          label: `Contact ${compactIdentifier(item.contactId)}`,
          detail: `${humanizeKey(item.role)} linked contact`,
        }))}
        legend="Linked contacts"
        onChange={onSelectionChange}
        selected={selections.contacts}
      />
      <EscalationSelectionGroup
        category="publicComments"
        items={inventory.publicComments.map((item) => ({
          id: item.id,
          label: commentSelectionLabel(item.bodyMarkdown),
          detail: `Public · ${item.author.displayName}`,
        }))}
        legend="Public comments"
        onChange={onSelectionChange}
        selected={selections.publicComments}
      />
    </div>
  );
}

function EscalationSelectionGroup({
  category,
  items,
  legend,
  onChange,
  selected,
}: {
  category: EscalationInventoryCategory;
  items: readonly { detail: string; id: string; label: string }[];
  legend: string;
  onChange: (
    category: EscalationInventoryCategory,
    id: string,
    checked: boolean,
  ) => void;
  selected: ReadonlySet<string>;
}): React.JSX.Element {
  return (
    <fieldset className="ticket-copy-fields">
      <legend>
        {legend} ({items.length} available, {selected.size} selected)
      </legend>
      {items.length === 0 ? (
        <small>
          No eligible {legend.toLowerCase()} are linked to this Alert.
        </small>
      ) : (
        items.map((item) => (
          <label key={item.id}>
            <Checkbox
              aria-label={`${legend}: ${item.label}`}
              checked={selected.has(item.id)}
              onCheckedChange={(checked) =>
                onChange(category, item.id, checked === true)
              }
            />
            <span>
              {item.label}
              <small>{item.detail}</small>
            </span>
          </label>
        ))
      )}
    </fieldset>
  );
}

function initialDraft(
  ticket: VersionedTicket<OperatorTicketProjection>,
  eligibleTeams: string[] = [],
): OperationDraft {
  return {
    assigneeId: "",
    customFields: {},
    deleteConfirmation: "",
    escalationCaseId: "",
    escalationCaseVersion: "",
    escalationMode: "create_case",
    escalationTitle: ticket.value.title,
    reason: "",
    teamId:
      ticket.value.assignment.assignedTeamId ??
      (eligibleTeams.length === 1 ? eligibleTeams[0]! : ""),
    transitionKey: ticket.value.availableTransitions?.[0]?.transitionKey ?? "",
  };
}

function claimTeam(
  assignedTeamId: string | null,
  eligibleTeams: string[],
  selectedTeamId: string,
): string | null {
  if (assignedTeamId) return assignedTeamId;
  if (eligibleTeams.length === 1) return eligibleTeams[0]!;
  const selected = selectedTeamId.trim();
  return eligibleTeams.includes(selected) ? selected : null;
}

function parsePositiveVersion(value: string): number {
  if (!/^[1-9]\d{0,9}$/u.test(value)) {
    throw new Error("Enter a positive expected Case version.");
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > 2_147_483_647) {
    throw new Error("Enter a valid expected Case version.");
  }
  return parsed;
}

function selectedInventoryIds(
  selected: ReadonlySet<string>,
  availableIds: readonly string[],
): string[] {
  const available = new Set(availableIds);
  if ([...selected].some((id) => !available.has(id))) {
    throw new Error(
      "The copy selection no longer matches the loaded Alert inventory.",
    );
  }
  return [...selected].toSorted(codePointCompare);
}

function commentSelectionLabel(bodyMarkdown: string): string {
  const compact = bodyMarkdown.replace(/\s+/gu, " ").trim();
  if (!compact) return "Empty public comment";
  return compact.length <= 120 ? compact : `${compact.slice(0, 119)}…`;
}

function operationTitle(operation: Operation, kind: TicketKind): string {
  const label = kindLabel(kind).toLowerCase();
  const titles: Record<Operation, string> = {
    assign: `Assign ${label}`,
    claim: `Claim ${label}`,
    delete: "Delete Alert",
    escalate: "Escalate Alert to Case",
    release: `Release ${label} claim`,
    transfer: `Transfer ${label}`,
    transition: `Transition ${label}`,
  };
  return titles[operation];
}

function alertNumber(value: OperatorTicketProjection): string {
  if ("alertNumber" in value) return value.alertNumber;
  throw new Error("The Alert projection is inconsistent.");
}

export function transitionLabel(transition: WorkflowActionHint): string {
  return `${humanizeKey(transition.transitionKey)} → ${humanizeKey(transition.targetStateKey)}`;
}
