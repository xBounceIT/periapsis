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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@periapsis/ui/components/ui/select";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  Archive,
  ArrowDown,
  Network,
  Plus,
  RefreshCw,
  Shield,
  Trash2,
  UserRound,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import {
  Controller,
  useForm,
  type UseFormRegisterReturn,
} from "react-hook-form";
import { z } from "zod";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import {
  idempotencyKeyForPayload,
  isPayloadBoundToIdempotencyKey,
} from "../lib/payload-idempotency";
import {
  currentInstant,
  hasInstantReached,
  parseRfc3339Instant,
} from "../lib/rfc3339-instant";
import { hasControlCharacters } from "../lib/text-validation";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type AuthorizationEdgeProvenanceView,
  type AuthorizationEdgeStateView,
  type PhaseTwoApi,
  type TenantAuthorityView,
  type TenantPermissionKeyView,
  type TenantRoleSummaryView,
  type TenantSecurityGroupMembershipCreateInput,
  type TenantSecurityGroupMembershipView,
  type TenantSecurityGroupPatchInput,
  type TenantSecurityGroupRoleGrantInput,
  type TenantSecurityGroupRoleGrantView,
  type TenantSecurityGroupView,
  type TenantUserSummaryView,
  type VersionedView,
} from "../lib/phase-two-types";
import type { TenantGroupDetailState } from "./tenant-groups";

type GroupTab = "members" | "overview" | "provenance" | "roles";

type EdgeInventoryState<T> =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | { kind: "ready"; items: readonly T[]; nextCursor?: string }
  | { kind: "restricted"; message: string };

interface EdgePage<T> {
  items: readonly T[];
  nextCursor?: string;
}

interface EdgePaginationRequest {
  controller: AbortController;
  cursor: string;
  generation: number;
  requestKey: string;
}

interface EdgeInventory<T> {
  loadMore: () => Promise<void>;
  paginationError: string | null;
  paginationLoading: boolean;
  refreshItem: (
    itemId: string,
    rejectedVersion: EdgeResourceVersion,
  ) => Promise<T>;
  reload: () => void;
  state: EdgeInventoryState<T>;
}

interface EdgeResourceVersion {
  entityTag: string;
  version: number;
}

const maximumEdgeResourceVersion = 2_147_483_647;

interface RevokeDraft {
  error: string | null;
  open: boolean;
  reason: string;
}

interface EdgeActionState extends RevokeDraft {
  isRefreshing: boolean;
  isSaving: boolean;
  refreshRequired: boolean;
  rejectedVersion: EdgeResourceVersion | null;
}

type EdgeActionStateUpdate =
  | EdgeActionState
  | null
  | ((current: EdgeActionState) => EdgeActionState | null);

interface EdgeRefreshResult {
  canRevoke: boolean;
}

interface EffectiveAuthorityBlocker {
  explanation: string;
  prerequisite: string;
  state: string;
}

const emptyEdgeActionState: EdgeActionState = {
  error: null,
  isRefreshing: false,
  isSaving: false,
  open: false,
  reason: "",
  refreshRequired: false,
  rejectedVersion: null,
};

const groupMetadataSchema = z.object({
  description: z
    .string()
    .max(500, "Use 500 characters or fewer.")
    .refine(
      (value) => !hasControlCharacters(value),
      "Use a description without control characters.",
    ),
  name: z
    .string()
    .trim()
    .min(1, "Enter a group name.")
    .max(120, "Use 120 characters or fewer.")
    .refine(
      (value) => !hasControlCharacters(value),
      "Use a group name without control characters.",
    ),
});

const reasonSchema = z
  .string()
  .trim()
  .min(1, "Enter an administrative reason.")
  .max(500, "Use 500 characters or fewer.")
  .refine(
    (value) => !hasControlCharacters(value),
    "Use a reason without control characters.",
  );

const addMembershipSchema = z.object({
  expiresAt: z.string(),
  reason: reasonSchema,
  userId: z.string().min(1, "Select a tenant user."),
});

const addRoleSchema = z.object({
  expiresAt: z.string(),
  reason: reasonSchema,
  roleId: z.string().min(1, "Select a tenant role."),
});

type GroupMetadataValues = z.infer<typeof groupMetadataSchema>;
type GroupMetadataDraft = Partial<GroupMetadataValues>;
type GroupMetadataDraftUpdate =
  GroupMetadataDraft | ((current: GroupMetadataDraft) => GroupMetadataDraft);
type AddMembershipValues = z.infer<typeof addMembershipSchema>;
type AddRoleValues = z.infer<typeof addRoleSchema>;

function groupMetadataValues(
  group: TenantSecurityGroupView,
): GroupMetadataValues {
  return {
    description: group.description ?? "",
    name: group.name,
  };
}

function rebaseGroupMetadataDraft(
  group: TenantSecurityGroupView,
  draft: GroupMetadataDraft,
): GroupMetadataValues {
  return { ...groupMetadataValues(group), ...draft };
}

function updateGroupMetadataDraft<K extends keyof GroupMetadataValues>(
  draft: GroupMetadataDraft,
  field: K,
  value: GroupMetadataValues[K],
  serverValue: GroupMetadataValues[K],
): GroupMetadataDraft {
  const next = { ...draft };
  if (value === serverValue) {
    delete next[field];
  } else {
    next[field] = value;
  }
  return next;
}

export function TenantGroupDetailDialog({
  api,
  authority,
  canManage,
  csrfToken,
  detailState,
  groupId,
  onArchived,
  onChanged,
  onOpenChange,
  onReload,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  authority: TenantAuthorityView | undefined;
  canManage: boolean;
  csrfToken: string;
  detailState: TenantGroupDetailState;
  groupId: string;
  onArchived: () => void;
  onChanged: (group: VersionedView<TenantSecurityGroupView>) => void;
  onOpenChange: (open: boolean) => void;
  onReload: () => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const [tab, setTab] = useState<GroupTab>("overview");
  const [edgeActionStates, setEdgeActionStates] = useState<
    Readonly<Record<string, EdgeActionState>>
  >({});
  const [metadataDraft, setMetadataDraft] = useState<GroupMetadataDraft>({});
  const [retainedReadyDetail, setRetainedReadyDetail] = useState<Extract<
    TenantGroupDetailState,
    { kind: "ready" }
  > | null>(() => (detailState.kind === "ready" ? detailState : null));
  const detailGenerationRef = useRef(0);
  const reloadFocusTargetRef = useRef<HTMLHeadingElement | null>(null);
  const restoreReloadFocusRef = useRef(false);
  const mountedRef = useRef(false);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);
  const canReadUsers = hasTenantPermission(authority, "user.read");
  const canReadRoles = hasTenantPermission(authority, "role.read");
  const canGrantRoles = hasTenantPermission(authority, "role.grant");
  const canManageMemberships = hasTenantPermission(
    authority,
    "group.membership.manage",
  );
  const readyDetail =
    detailState.kind === "ready"
      ? detailState
      : detailState.kind === "forbidden"
        ? null
        : retainedReadyDetail;
  const group = readyDetail?.group.value ?? null;
  const membersEnabled = detailState.kind === "ready" && canReadUsers;
  const rolesEnabled = detailState.kind === "ready" && canReadRoles;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    if (detailState.kind === "ready") {
      setRetainedReadyDetail(detailState);
    } else if (detailState.kind === "forbidden") {
      setRetainedReadyDetail(null);
    }
  }, [detailState]);

  useEffect(() => {
    const generation = detailGenerationRef.current + 1;
    detailGenerationRef.current = generation;
    return () => {
      if (detailGenerationRef.current === generation) {
        detailGenerationRef.current += 1;
      }
    };
  }, [groupId, pairKey]);

  useEffect(() => {
    if (!restoreReloadFocusRef.current || detailState.kind !== "ready") {
      return;
    }
    restoreReloadFocusRef.current = false;
    if (document.activeElement !== reloadFocusTargetRef.current) {
      return;
    }
    const selectedTabIndex = groupTabs.findIndex((item) => item.id === tab);
    const selectedTab = tabRefs.current[selectedTabIndex];
    (selectedTab ?? reloadFocusTargetRef.current)?.focus({
      preventScroll: true,
    });
  }, [detailState, tab]);

  const getDetailGeneration = useCallback(
    () => detailGenerationRef.current,
    [],
  );
  const isDetailGenerationActive = useCallback(
    (generation: number) =>
      mountedRef.current && detailGenerationRef.current === generation,
    [],
  );

  const loadMemberships = useCallback(
    async (after: string | undefined, signal: AbortSignal) =>
      api.listTenantSecurityGroupMemberships(tenantId, groupId, {
        ...(after ? { after } : {}),
        includeRevoked: true,
        signal,
      }),
    [api, groupId, tenantId],
  );
  const loadRoleGrants = useCallback(
    async (after: string | undefined, signal: AbortSignal) =>
      api.listTenantSecurityGroupRoleGrants(tenantId, groupId, {
        ...(after ? { after } : {}),
        includeRevoked: true,
        signal,
      }),
    [api, groupId, tenantId],
  );
  const validateMemberships = useCallback(
    (items: readonly TenantSecurityGroupMembershipView[]) => {
      assertGroupEdges(items, tenantId, groupId);
      assertEdgeExpiries(items);
      if (items.some((item) => item.member.tenantId !== tenantId)) {
        throw new Error(
          "The membership-edge response escaped the active tenant user projection.",
        );
      }
    },
    [groupId, tenantId],
  );
  const validateRoleGrants = useCallback(
    (items: readonly TenantSecurityGroupRoleGrantView[]) => {
      assertGroupEdges(items, tenantId, groupId);
      assertEdgeExpiries(items);
      if (items.some((item) => item.role.tenantId !== tenantId)) {
        throw new Error(
          "The role-edge response escaped the active tenant role projection.",
        );
      }
    },
    [groupId, tenantId],
  );
  const members = useEdgeInventory({
    enabled: membersEnabled,
    identify: identifyEdge,
    load: loadMemberships,
    pairKey,
    restrictedMessage:
      "user.read is required to inspect tenant membership identities and their group edges.",
    resourceName: "membership edges",
    versionOf: edgeResourceVersion,
    validate: validateMemberships,
  });
  const roles = useEdgeInventory({
    enabled: rolesEnabled,
    identify: identifyEdge,
    load: loadRoleGrants,
    pairKey,
    restrictedMessage:
      "role.read is required to inspect group role edges and their provenance.",
    resourceName: "role edges",
    versionOf: edgeResourceVersion,
    validate: validateRoleGrants,
  });

  function updateEdgeActionState(
    actionKey: string,
    update: EdgeActionStateUpdate,
  ): void {
    setEdgeActionStates((current) => {
      const actionState = current[actionKey] ?? emptyEdgeActionState;
      const next = typeof update === "function" ? update(actionState) : update;
      if (next) {
        return next === actionState
          ? current
          : { ...current, [actionKey]: next };
      }
      if (!(actionKey in current)) {
        return current;
      }
      const remaining = { ...current };
      delete remaining[actionKey];
      return remaining;
    });
  }

  function moveTabFocus(event: KeyboardEvent<HTMLButtonElement>): void {
    const keys = ["ArrowLeft", "ArrowRight", "Home", "End"];
    if (!keys.includes(event.key)) {
      return;
    }
    event.preventDefault();
    const index = Number(event.currentTarget.dataset.index ?? "0");
    const last = groupTabs.length - 1;
    const nextIndex =
      event.key === "Home"
        ? 0
        : event.key === "End"
          ? last
          : event.key === "ArrowLeft"
            ? (index - 1 + groupTabs.length) % groupTabs.length
            : (index + 1) % groupTabs.length;
    const next = groupTabs[nextIndex];
    if (next) {
      setTab(next.id);
      tabRefs.current[nextIndex]?.focus();
    }
  }

  function reloadFromDialogControl(): void {
    restoreReloadFocusRef.current = true;
    reloadFocusTargetRef.current?.focus({ preventScroll: true });
    onReload();
  }

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="group-detail-dialog">
        <DialogHeader>
          <DialogTitle ref={reloadFocusTargetRef} tabIndex={-1}>
            {group ? `Security group · ${group.name}` : "Security group"}
          </DialogTitle>
          <DialogDescription>
            Group authority is the result of two independently owned edges.
            Browser controls reflect live capabilities; the server remains the
            authorization boundary.
          </DialogDescription>
        </DialogHeader>

        {detailState.kind === "loading" ? <GroupDetailSkeleton /> : null}
        {detailState.kind === "forbidden" ? (
          <FocusedError
            autoFocus={!restoreReloadFocusRef.current}
            title="Group detail denied"
            message="The server denied this security-group detail request."
          />
        ) : null}
        {detailState.kind === "error" ? (
          <div className="tenant-admin-error">
            <FocusedError
              autoFocus={!restoreReloadFocusRef.current}
              message={detailState.message}
            />
            <Button
              type="button"
              variant="outline"
              onClick={reloadFromDialogControl}
            >
              <RefreshCw aria-hidden="true" /> Retry group detail
            </Button>
          </div>
        ) : null}
        {readyDetail && group ? (
          <div
            className="group-detail-ready"
            hidden={detailState.kind !== "ready"}
          >
            <AccessPathRail
              group={group}
              membershipCount={readyCount(members.state)}
              roleCount={readyCount(roles.state)}
            />
            <div
              className="group-tabs"
              role="tablist"
              aria-label="Group detail"
            >
              {groupTabs.map((item, index) => (
                <button
                  aria-controls={`group-panel-${item.id}`}
                  aria-selected={tab === item.id}
                  data-index={index}
                  id={`group-tab-${item.id}`}
                  key={item.id}
                  onClick={() => setTab(item.id)}
                  onKeyDown={moveTabFocus}
                  ref={(node) => {
                    tabRefs.current[index] = node;
                  }}
                  role="tab"
                  tabIndex={tab === item.id ? 0 : -1}
                  type="button"
                >
                  {item.label}
                </button>
              ))}
            </div>

            <section
              aria-labelledby="group-tab-overview"
              hidden={tab !== "overview"}
              id="group-panel-overview"
              role="tabpanel"
              tabIndex={0}
            >
              <GroupOverviewPanel
                api={api}
                canManage={canManage}
                csrfToken={csrfToken}
                draft={metadataDraft}
                group={readyDetail.group}
                onArchived={onArchived}
                onChanged={onChanged}
                onDraftChange={setMetadataDraft}
                onReload={reloadFromDialogControl}
                tenantId={tenantId}
              />
            </section>

            <section
              aria-labelledby="group-tab-members"
              hidden={tab !== "members"}
              id="group-panel-members"
              role="tabpanel"
              tabIndex={0}
            >
              <MembershipPanel
                api={api}
                canAdd={
                  !group.archived &&
                  canReadUsers &&
                  canManageMemberships &&
                  canGrantRoles
                }
                canRevoke={canManageMemberships && canGrantRoles}
                csrfToken={csrfToken}
                group={group}
                getDetailGeneration={getDetailGeneration}
                inventory={members}
                isDetailGenerationActive={isDetailGenerationActive}
                onAuthorityChanged={() => {
                  members.reload();
                }}
                edgeActionStates={edgeActionStates}
                onEdgeActionStateChange={updateEdgeActionState}
                pairKey={pairKey}
                tenantId={tenantId}
              />
            </section>

            <section
              aria-labelledby="group-tab-roles"
              hidden={tab !== "roles"}
              id="group-panel-roles"
              role="tabpanel"
              tabIndex={0}
            >
              <RoleEdgePanel
                api={api}
                canAdd={
                  !group.archived && canManage && canReadRoles && canGrantRoles
                }
                canRevoke={canManage && canGrantRoles}
                csrfToken={csrfToken}
                group={group}
                getDetailGeneration={getDetailGeneration}
                inventory={roles}
                isDetailGenerationActive={isDetailGenerationActive}
                onAuthorityChanged={() => {
                  roles.reload();
                }}
                edgeActionStates={edgeActionStates}
                onEdgeActionStateChange={updateEdgeActionState}
                pairKey={pairKey}
                tenantId={tenantId}
              />
            </section>

            <section
              aria-labelledby="group-tab-provenance"
              hidden={tab !== "provenance"}
              id="group-panel-provenance"
              role="tabpanel"
              tabIndex={0}
            >
              <ProvenancePanel
                group={group}
                memberships={members.state}
                roleGrants={roles.state}
              />
            </section>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

const groupTabs: readonly { id: GroupTab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "members", label: "Members" },
  { id: "roles", label: "Roles" },
  { id: "provenance", label: "Provenance" },
];

function GroupOverviewPanel({
  api,
  canManage,
  csrfToken,
  draft,
  group,
  onArchived,
  onChanged,
  onDraftChange,
  onReload,
  tenantId,
}: {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  draft: GroupMetadataDraft;
  group: VersionedView<TenantSecurityGroupView>;
  onArchived: () => void;
  onChanged: (group: VersionedView<TenantSecurityGroupView>) => void;
  onDraftChange: (update: GroupMetadataDraftUpdate) => void;
  onReload: () => void;
  tenantId: string;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const id = useId();
  const [formError, setFormError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const [archiveOpen, setArchiveOpen] = useState(false);
  const [isArchiving, setIsArchiving] = useState(false);
  const draftRef = useRef(draft);
  draftRef.current = draft;
  const { handleSubmit, register, reset } = useForm<GroupMetadataValues>({
    defaultValues: rebaseGroupMetadataDraft(group.value, draft),
  });
  const nameField = register("name");
  const descriptionField = register("description");

  useEffect(() => {
    setFormError(null);
    setArchiveOpen(false);
    reset(rebaseGroupMetadataDraft(group.value, draftRef.current));
  }, [group.etag, group.value, reset]);

  const submit = handleSubmit(async (rawValues) => {
    const parsed = groupMetadataSchema.safeParse(rawValues);
    if (!parsed.success) {
      setFormError(
        parsed.error.issues[0]?.message ?? "Review the group metadata.",
      );
      return;
    }
    const description = parsed.data.description.trim();
    const input: TenantSecurityGroupPatchInput = {};
    if ("name" in draft && parsed.data.name !== group.value.name) {
      input.name = parsed.data.name;
    }
    if (
      "description" in draft &&
      description !== (group.value.description ?? "")
    ) {
      input.description = description;
    }
    if (Object.keys(input).length === 0) {
      setFormError("Change the group name or description before saving.");
      return;
    }
    onDraftChange(input);
    setFormError(null);
    setIsSaving(true);
    try {
      const updated = await api.updateTenantSecurityGroup(
        csrfToken,
        tenantId,
        group.value.id,
        group.etag,
        input,
      );
      onDraftChange({});
      reset(groupMetadataValues(updated.value));
      onChanged(updated);
    } catch (caught) {
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setFormError(
        mutationMessage(
          caught,
          "The group metadata was not updated. Your input is preserved.",
        ),
      );
    } finally {
      setIsSaving(false);
    }
  });

  async function archive(): Promise<void> {
    setFormError(null);
    setIsArchiving(true);
    try {
      await api.archiveTenantSecurityGroup(
        csrfToken,
        tenantId,
        group.value.id,
        group.etag,
      );
      onArchived();
    } catch (caught) {
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setFormError(
        mutationMessage(
          caught,
          "The group was not archived. The confirmation remains open.",
        ),
      );
    } finally {
      setIsArchiving(false);
    }
  }

  return (
    <div className="group-overview-panel">
      <dl className="role-detail-grid group-detail-grid">
        <div>
          <dt>Stable key</dt>
          <dd>{group.value.key}</dd>
        </div>
        <div>
          <dt>State</dt>
          <dd>{group.value.archived ? "Archived" : "Active"}</dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd>{group.etag}</dd>
        </div>
        <div>
          <dt>Updated</dt>
          <dd>{formatTimestamp(group.value.updatedAt)}</dd>
        </div>
      </dl>
      {formError ? (
        <div className="group-mutation-error">
          <FocusedError title="Group action failed" message={formError} />
          {formError.includes("changed on the server") ||
          formError.includes("strong resource version") ? (
            <Button type="button" variant="outline" onClick={onReload}>
              <RefreshCw aria-hidden="true" /> Load current version
            </Button>
          ) : null}
        </div>
      ) : null}
      <form className="group-form" onSubmit={submit} noValidate>
        <FormField htmlFor={`${id}-overview-name`} label="Group name">
          <Input
            id={`${id}-overview-name`}
            maxLength={120}
            disabled={!canManage || group.value.archived || isSaving}
            {...nameField}
            onChange={(event) => {
              const name = event.currentTarget.value;
              void nameField.onChange(event);
              onDraftChange((current) =>
                updateGroupMetadataDraft(
                  current,
                  "name",
                  name,
                  group.value.name,
                ),
              );
            }}
          />
        </FormField>
        <FormField
          htmlFor={`${id}-overview-description`}
          label="Description"
          optional
        >
          <Textarea
            id={`${id}-overview-description`}
            maxLength={500}
            disabled={!canManage || group.value.archived || isSaving}
            {...descriptionField}
            onChange={(event) => {
              const description = event.currentTarget.value;
              void descriptionField.onChange(event);
              onDraftChange((current) =>
                updateGroupMetadataDraft(
                  current,
                  "description",
                  description,
                  group.value.description ?? "",
                ),
              );
            }}
          />
        </FormField>
        {canManage && !group.value.archived ? (
          <div className="group-overview-actions">
            <Button type="submit" disabled={isSaving || isArchiving}>
              {isSaving ? "Saving changes…" : "Save changes"}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={isSaving || isArchiving}
              onClick={() => setArchiveOpen(true)}
            >
              <Archive aria-hidden="true" /> Archive group
            </Button>
          </div>
        ) : null}
      </form>
      {archiveOpen ? (
        <div className="destructive-confirmation" role="group">
          <p>
            Archiving stops this group from contributing live authority. Every
            source-owned edge remains available as provenance.
          </p>
          <div>
            <Button
              type="button"
              variant="destructive"
              disabled={isSaving || isArchiving}
              onClick={() => void archive()}
            >
              <Archive aria-hidden="true" />
              {isArchiving ? "Archiving…" : "Confirm archive"}
            </Button>
            <Button
              type="button"
              variant="ghost"
              disabled={isArchiving}
              onClick={() => setArchiveOpen(false)}
            >
              Keep group active
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function MembershipPanel({
  api,
  canAdd,
  canRevoke,
  csrfToken,
  edgeActionStates,
  getDetailGeneration,
  group,
  inventory,
  isDetailGenerationActive,
  onAuthorityChanged,
  onEdgeActionStateChange,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  canAdd: boolean;
  canRevoke: boolean;
  csrfToken: string;
  edgeActionStates: Readonly<Record<string, EdgeActionState>>;
  getDetailGeneration: () => number;
  group: TenantSecurityGroupView;
  inventory: EdgeInventory<TenantSecurityGroupMembershipView>;
  isDetailGenerationActive: (generation: number) => boolean;
  onAuthorityChanged: () => void;
  onEdgeActionStateChange: (
    actionKey: string,
    update: EdgeActionStateUpdate,
  ) => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const { reload: reloadAuthority } = useTenantAuthority();
  const [adding, setAdding] = useState(false);

  return (
    <div className="group-edge-panel">
      <div className="section-heading group-edge-heading">
        <div>
          <p className="section-label">Membership edge inventory</p>
          <h3>Direct tenant members</h3>
        </div>
        {canAdd ? (
          <Button type="button" onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" /> Add member edge
          </Button>
        ) : null}
      </div>
      {!canAdd && !group.archived ? (
        <p className="capability-note">
          Adding a member requires group.membership.manage, user.read, and
          role.grant because every active role consequence is rechecked.
        </p>
      ) : null}
      {adding ? (
        <AddMembershipForm
          api={api}
          canSubmit={canAdd}
          csrfToken={csrfToken}
          getDetailGeneration={getDetailGeneration}
          groupId={group.id}
          isDetailGenerationActive={isDetailGenerationActive}
          onCancel={() => setAdding(false)}
          onCommitted={() => {
            onAuthorityChanged();
            reloadAuthority();
          }}
          onCreated={() => setAdding(false)}
          pairKey={pairKey}
          tenantId={tenantId}
        />
      ) : null}
      <EdgeInventoryStatus inventory={inventory} resource="membership edges" />
      {inventory.state.kind === "ready" &&
      inventory.state.items.length === 0 ? (
        <EdgeEmpty icon={<UserRound aria-hidden="true" />}>
          No membership edges were returned for this group.
        </EdgeEmpty>
      ) : null}
      {inventory.state.kind === "ready" && inventory.state.items.length > 0 ? (
        <div className="group-edge-list">
          {inventory.state.items.map((edge) => (
            <AuthorizationEdgeCard
              actionState={
                edgeActionStates[`membership:${edge.id}`] ??
                emptyEdgeActionState
              }
              canRevoke={canManuallyRevokeEdge(canRevoke, edge)}
              etag={edge.etag}
              getDetailGeneration={getDetailGeneration}
              isDetailGenerationActive={isDetailGenerationActive}
              key={edge.id}
              kind="Membership edge"
              managedByAuthorizationApi={edge.managedByAuthorizationApi}
              onActionStateChange={(update) =>
                onEdgeActionStateChange(`membership:${edge.id}`, update)
              }
              onCancel={() =>
                onEdgeActionStateChange(`membership:${edge.id}`, null)
              }
              onRevoked={() => {
                onEdgeActionStateChange(`membership:${edge.id}`, null);
                onAuthorityChanged();
                reloadAuthority();
              }}
              onStale={async (rejectedVersion) => {
                const refreshed = await inventory.refreshItem(
                  edge.id,
                  rejectedVersion,
                );
                return {
                  canRevoke: canManuallyRevokeEdge(canRevoke, refreshed),
                };
              }}
              provenance={edge.provenance}
              revokeReason={edge.revokeReason}
              revokedAt={edge.revokedAt}
              revokedByUserId={edge.revokedByUserId}
              revoke={(etag, input) =>
                api.revokeTenantSecurityGroupMembership(
                  csrfToken,
                  tenantId,
                  group.id,
                  edge.id,
                  etag,
                  input,
                )
              }
              state={edge.state}
              subtitle={edge.member.user.email}
              title={edge.member.user.displayName}
              effectiveAuthorityBlockers={membershipAuthorityBlockers(edge)}
              version={edge.version}
            />
          ))}
        </div>
      ) : null}
      <EdgeLoadMore inventory={inventory} label="membership edges" />
    </div>
  );
}

function RoleEdgePanel({
  api,
  canAdd,
  canRevoke,
  csrfToken,
  edgeActionStates,
  getDetailGeneration,
  group,
  inventory,
  isDetailGenerationActive,
  onAuthorityChanged,
  onEdgeActionStateChange,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  canAdd: boolean;
  canRevoke: boolean;
  csrfToken: string;
  edgeActionStates: Readonly<Record<string, EdgeActionState>>;
  getDetailGeneration: () => number;
  group: TenantSecurityGroupView;
  inventory: EdgeInventory<TenantSecurityGroupRoleGrantView>;
  isDetailGenerationActive: (generation: number) => boolean;
  onAuthorityChanged: () => void;
  onEdgeActionStateChange: (
    actionKey: string,
    update: EdgeActionStateUpdate,
  ) => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const { reload: reloadAuthority } = useTenantAuthority();
  const [adding, setAdding] = useState(false);

  return (
    <div className="group-edge-panel">
      <div className="section-heading group-edge-heading">
        <div>
          <p className="section-label">Role edge inventory</p>
          <h3>Tenant roles</h3>
        </div>
        {canAdd ? (
          <Button type="button" onClick={() => setAdding(true)}>
            <Plus aria-hidden="true" /> Add role edge
          </Button>
        ) : null}
      </div>
      {!canAdd && !group.archived ? (
        <p className="capability-note">
          Adding a role requires group.manage, role.read, and role.grant. The
          server rechecks the exact policy and every affected member path.
        </p>
      ) : null}
      {adding ? (
        <AddRoleEdgeForm
          api={api}
          canSubmit={canAdd}
          csrfToken={csrfToken}
          getDetailGeneration={getDetailGeneration}
          groupId={group.id}
          isDetailGenerationActive={isDetailGenerationActive}
          onCancel={() => setAdding(false)}
          onCommitted={() => {
            onAuthorityChanged();
            reloadAuthority();
          }}
          onCreated={() => setAdding(false)}
          pairKey={pairKey}
          tenantId={tenantId}
        />
      ) : null}
      <EdgeInventoryStatus inventory={inventory} resource="role edges" />
      {inventory.state.kind === "ready" &&
      inventory.state.items.length === 0 ? (
        <EdgeEmpty icon={<Shield aria-hidden="true" />}>
          No role edges were returned for this group.
        </EdgeEmpty>
      ) : null}
      {inventory.state.kind === "ready" && inventory.state.items.length > 0 ? (
        <div className="group-edge-list">
          {inventory.state.items.map((edge) => (
            <AuthorizationEdgeCard
              actionState={
                edgeActionStates[`role:${edge.id}`] ?? emptyEdgeActionState
              }
              canRevoke={canManuallyRevokeEdge(canRevoke, edge)}
              etag={edge.etag}
              getDetailGeneration={getDetailGeneration}
              isDetailGenerationActive={isDetailGenerationActive}
              key={edge.id}
              kind="Role edge"
              managedByAuthorizationApi={edge.managedByAuthorizationApi}
              onActionStateChange={(update) =>
                onEdgeActionStateChange(`role:${edge.id}`, update)
              }
              onCancel={() => onEdgeActionStateChange(`role:${edge.id}`, null)}
              onRevoked={() => {
                onEdgeActionStateChange(`role:${edge.id}`, null);
                onAuthorityChanged();
                reloadAuthority();
              }}
              onStale={async (rejectedVersion) => {
                const refreshed = await inventory.refreshItem(
                  edge.id,
                  rejectedVersion,
                );
                return {
                  canRevoke: canManuallyRevokeEdge(canRevoke, refreshed),
                };
              }}
              provenance={edge.provenance}
              revokeReason={edge.revokeReason}
              revokedAt={edge.revokedAt}
              revokedByUserId={edge.revokedByUserId}
              revoke={(etag, input) =>
                api.revokeTenantSecurityGroupRoleGrant(
                  csrfToken,
                  tenantId,
                  group.id,
                  edge.id,
                  etag,
                  input,
                )
              }
              state={edge.state}
              subtitle={edge.role.key}
              title={edge.role.name}
              effectiveAuthorityBlockers={roleAuthorityBlockers(edge)}
              version={edge.version}
            />
          ))}
        </div>
      ) : null}
      <EdgeLoadMore inventory={inventory} label="role edges" />
    </div>
  );
}

function AddMembershipForm({
  api,
  canSubmit,
  csrfToken,
  getDetailGeneration,
  groupId,
  isDetailGenerationActive,
  onCancel,
  onCommitted,
  onCreated,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  canSubmit: boolean;
  csrfToken: string;
  getDetailGeneration: () => number;
  groupId: string;
  isDetailGenerationActive: (generation: number) => boolean;
  onCancel: () => void;
  onCommitted: () => void;
  onCreated: () => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const id = useId();
  const [formError, setFormError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const mountedRef = useRef(false);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const { control, handleSubmit, register } = useForm<AddMembershipValues>({
    defaultValues: { expiresAt: "", reason: "", userId: "" },
  });
  const loadUsers = useCallback(
    async (after: string | undefined, signal: AbortSignal) => {
      const page = await api.listTenantUsers(tenantId, after, signal);
      if (page.items.some((user) => user.tenantId !== tenantId)) {
        throw new Error("The tenant-user response escaped the active tenant.");
      }
      return {
        items: page.items.filter(
          (user) => user.membershipStatus === "active" && user.user.active,
        ),
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      };
    },
    [api, tenantId],
  );
  const users = useEdgeInventory({
    enabled: true,
    identify: identifyTenantUser,
    load: loadUsers,
    pairKey,
    restrictedMessage: "",
    resourceName: "tenant users",
  });

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const submit = handleSubmit(async (rawValues) => {
    const parsed = addMembershipSchema.safeParse(rawValues);
    if (!parsed.success) {
      setFormError(
        parsed.error.issues[0]?.message ?? "Review the membership edge.",
      );
      return;
    }
    const expiry = parseEdgeExpiry(parsed.data.expiresAt);
    if (expiry.error) {
      setFormError(expiry.error);
      return;
    }
    const input: TenantSecurityGroupMembershipCreateInput = {
      ...(expiry.value ? { expiresAt: expiry.value } : {}),
      reason: parsed.data.reason,
      userId: parsed.data.userId,
    };
    const bindingPayload = { groupId, input, tenantId };
    const boundReplay = isPayloadBoundToIdempotencyKey(
      idempotencyBindingRef,
      bindingPayload,
    );
    if (
      expiry.value &&
      Date.parse(expiry.value) <= Date.now() &&
      !boundReplay
    ) {
      setFormError("Choose a future edge expiry.");
      return;
    }
    setFormError(null);
    setIsSaving(true);
    const generation = getDetailGeneration();
    try {
      await api.createTenantSecurityGroupMembership(
        csrfToken,
        tenantId,
        groupId,
        idempotencyKeyForPayload(idempotencyBindingRef, bindingPayload),
        input,
      );
      if (isDetailGenerationActive(generation)) {
        if (mountedRef.current) {
          onCreated();
        }
        onCommitted();
      }
    } catch (caught) {
      if (!isDetailGenerationActive(generation)) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      if (!mountedRef.current) {
        return;
      }
      setFormError(
        mutationMessage(
          caught,
          "The membership edge was not added. Your input is preserved.",
        ),
      );
    } finally {
      if (mountedRef.current && isDetailGenerationActive(generation)) {
        setIsSaving(false);
      }
    }
  });

  return (
    <form className="edge-create-form" onSubmit={submit} noValidate>
      <div>
        <strong>Add a manual membership edge</strong>
        <small>
          All active group-role consequences are checked atomically.
        </small>
      </div>
      {formError ? (
        <FocusedError title="Membership not added" message={formError} />
      ) : null}
      <EdgeInventoryStatus inventory={users} resource="tenant users" />
      {users.state.kind === "ready" &&
      users.state.items.length === 0 &&
      !users.state.nextCursor ? (
        <EdgeEmpty icon={<UserRound aria-hidden="true" />}>
          No active tenant users are available for a manual membership edge.
        </EdgeEmpty>
      ) : null}
      {users.state.kind === "ready" && users.state.items.length > 0 ? (
        <>
          <FormField htmlFor={`${id}-member-user`} label="Tenant user">
            <Controller
              control={control}
              name="userId"
              render={({ field }) => (
                <Select
                  value={field.value}
                  onValueChange={field.onChange}
                  disabled={isSaving}
                >
                  <SelectTrigger
                    id={`${id}-member-user`}
                    className="edge-select"
                  >
                    <SelectValue placeholder="Select a tenant user" />
                  </SelectTrigger>
                  <SelectContent>
                    {users.state.kind === "ready"
                      ? users.state.items.map((user) => (
                          <SelectItem key={user.user.id} value={user.user.id}>
                            {user.user.displayName} · {user.user.email}
                          </SelectItem>
                        ))
                      : null}
                  </SelectContent>
                </Select>
              )}
            />
          </FormField>
          <EdgeLifetimeFields
            expiresRegistration={register("expiresAt")}
            id={id}
            isSaving={isSaving}
            reasonRegistration={register("reason")}
          />
        </>
      ) : null}
      <EdgeLoadMore inventory={users} label="tenant users" />
      <DialogFooter>
        <Button
          type="button"
          variant="ghost"
          disabled={isSaving}
          onClick={onCancel}
        >
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={
            isSaving ||
            !canSubmit ||
            users.state.kind !== "ready" ||
            users.state.items.length === 0
          }
        >
          {isSaving ? "Adding member…" : "Add member edge"}
        </Button>
      </DialogFooter>
    </form>
  );
}

function AddRoleEdgeForm({
  api,
  canSubmit,
  csrfToken,
  getDetailGeneration,
  groupId,
  isDetailGenerationActive,
  onCancel,
  onCommitted,
  onCreated,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  canSubmit: boolean;
  csrfToken: string;
  getDetailGeneration: () => number;
  groupId: string;
  isDetailGenerationActive: (generation: number) => boolean;
  onCancel: () => void;
  onCommitted: () => void;
  onCreated: () => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const id = useId();
  const [formError, setFormError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const mountedRef = useRef(false);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const { control, handleSubmit, register } = useForm<AddRoleValues>({
    defaultValues: { expiresAt: "", reason: "", roleId: "" },
  });
  const loadRoles = useCallback(
    async (after: string | undefined, signal: AbortSignal) => {
      const page = await api.listTenantRoles(tenantId, {
        ...(after ? { after } : {}),
        signal,
      });
      if (page.items.some((role) => role.tenantId !== tenantId)) {
        throw new Error("The tenant-role response escaped the active tenant.");
      }
      return {
        items: page.items.filter(
          (role) => !role.archived && role.principalKind === "human",
        ),
        ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
      };
    },
    [api, tenantId],
  );
  const roles = useEdgeInventory({
    enabled: true,
    identify: identifyTenantRole,
    load: loadRoles,
    pairKey,
    restrictedMessage: "",
    resourceName: "tenant roles",
  });

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const submit = handleSubmit(async (rawValues) => {
    const parsed = addRoleSchema.safeParse(rawValues);
    if (!parsed.success) {
      setFormError(parsed.error.issues[0]?.message ?? "Review the role edge.");
      return;
    }
    const expiry = parseEdgeExpiry(parsed.data.expiresAt);
    if (expiry.error) {
      setFormError(expiry.error);
      return;
    }
    const input: TenantSecurityGroupRoleGrantInput = {
      ...(expiry.value ? { expiresAt: expiry.value } : {}),
      reason: parsed.data.reason,
      roleId: parsed.data.roleId,
    };
    const bindingPayload = { groupId, input, tenantId };
    const boundReplay = isPayloadBoundToIdempotencyKey(
      idempotencyBindingRef,
      bindingPayload,
    );
    if (
      expiry.value &&
      Date.parse(expiry.value) <= Date.now() &&
      !boundReplay
    ) {
      setFormError("Choose a future edge expiry.");
      return;
    }
    setFormError(null);
    setIsSaving(true);
    const generation = getDetailGeneration();
    try {
      await api.grantTenantSecurityGroupRole(
        csrfToken,
        tenantId,
        groupId,
        idempotencyKeyForPayload(idempotencyBindingRef, bindingPayload),
        input,
      );
      if (isDetailGenerationActive(generation)) {
        if (mountedRef.current) {
          onCreated();
        }
        onCommitted();
      }
    } catch (caught) {
      if (!isDetailGenerationActive(generation)) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      if (!mountedRef.current) {
        return;
      }
      setFormError(
        mutationMessage(
          caught,
          "The role edge was not added. Your input is preserved.",
        ),
      );
    } finally {
      if (mountedRef.current && isDetailGenerationActive(generation)) {
        setIsSaving(false);
      }
    }
  });

  return (
    <form className="edge-create-form" onSubmit={submit} noValidate>
      <div>
        <strong>Add a manual role edge</strong>
        <small>
          Exact policy, lifetime, and affected member paths are rechecked.
        </small>
      </div>
      {formError ? (
        <FocusedError title="Role not added" message={formError} />
      ) : null}
      <EdgeInventoryStatus inventory={roles} resource="tenant roles" />
      {roles.state.kind === "ready" &&
      roles.state.items.length === 0 &&
      !roles.state.nextCursor ? (
        <EdgeEmpty icon={<Shield aria-hidden="true" />}>
          No active tenant roles are available for a manual role edge.
        </EdgeEmpty>
      ) : null}
      {roles.state.kind === "ready" && roles.state.items.length > 0 ? (
        <>
          <FormField htmlFor={`${id}-edge-role`} label="Tenant role">
            <Controller
              control={control}
              name="roleId"
              render={({ field }) => (
                <Select
                  value={field.value}
                  onValueChange={field.onChange}
                  disabled={isSaving}
                >
                  <SelectTrigger id={`${id}-edge-role`} className="edge-select">
                    <SelectValue placeholder="Select a tenant role" />
                  </SelectTrigger>
                  <SelectContent>
                    {roles.state.kind === "ready"
                      ? roles.state.items.map((role) => (
                          <SelectItem key={role.id} value={role.id}>
                            {role.name} · {role.key}
                          </SelectItem>
                        ))
                      : null}
                  </SelectContent>
                </Select>
              )}
            />
          </FormField>
          <EdgeLifetimeFields
            expiresRegistration={register("expiresAt")}
            id={id}
            isSaving={isSaving}
            reasonRegistration={register("reason")}
          />
        </>
      ) : null}
      <EdgeLoadMore inventory={roles} label="tenant roles" />
      <DialogFooter>
        <Button
          type="button"
          variant="ghost"
          disabled={isSaving}
          onClick={onCancel}
        >
          Cancel
        </Button>
        <Button
          type="submit"
          disabled={
            isSaving ||
            !canSubmit ||
            roles.state.kind !== "ready" ||
            roles.state.items.length === 0
          }
        >
          {isSaving ? "Adding role…" : "Add role edge"}
        </Button>
      </DialogFooter>
    </form>
  );
}

function EdgeLifetimeFields({
  expiresRegistration,
  id,
  isSaving,
  reasonRegistration,
}: {
  expiresRegistration: UseFormRegisterReturn<"expiresAt">;
  id: string;
  isSaving: boolean;
  reasonRegistration: UseFormRegisterReturn<"reason">;
}): React.JSX.Element {
  return (
    <div className="edge-lifetime-fields">
      <FormField
        htmlFor={`${id}-edge-expiry`}
        label="Edge expiry"
        optional
        hint="Leave empty for no scheduled expiry. The server may require a shorter delegation horizon."
      >
        <Input
          id={`${id}-edge-expiry`}
          aria-describedby={`${id}-edge-expiry-hint`}
          type="datetime-local"
          min={toLocalDateTime(new Date().toISOString())}
          step={1}
          disabled={isSaving}
          {...expiresRegistration}
        />
      </FormField>
      <FormField htmlFor={`${id}-edge-reason`} label="Reason">
        <Textarea
          id={`${id}-edge-reason`}
          maxLength={500}
          disabled={isSaving}
          {...reasonRegistration}
        />
      </FormField>
    </div>
  );
}

function membershipAuthorityBlockers(
  edge: TenantSecurityGroupMembershipView,
): readonly EffectiveAuthorityBlocker[] {
  const blockers: EffectiveAuthorityBlocker[] = [];
  if (edge.group.archived) {
    blockers.push({
      explanation:
        "This active stored edge cannot participate in an effective authority path while the group is archived.",
      prerequisite: "Group",
      state: "Archived",
    });
  }
  if (edge.member.membershipStatus !== "active") {
    blockers.push({
      explanation:
        "This active stored membership edge cannot participate until the tenant membership is active.",
      prerequisite: "Tenant membership",
      state: formatStatus(edge.member.membershipStatus),
    });
  }
  if (!edge.member.user.active) {
    blockers.push({
      explanation:
        "This active stored membership edge cannot participate while the user is disabled.",
      prerequisite: "User",
      state: "Disabled",
    });
  }
  if (edge.provenance.retiredAt) {
    blockers.push({
      explanation:
        "This active stored edge does not contribute authority because its source is retired.",
      prerequisite: "Source",
      state: "Retired",
    });
  }
  return blockers;
}

function roleAuthorityBlockers(
  edge: TenantSecurityGroupRoleGrantView,
): readonly EffectiveAuthorityBlocker[] {
  const blockers: EffectiveAuthorityBlocker[] = [];
  if (edge.group.archived) {
    blockers.push({
      explanation:
        "This active stored edge cannot participate in an effective authority path while the group is archived.",
      prerequisite: "Group",
      state: "Archived",
    });
  }
  if (edge.role.archived) {
    blockers.push({
      explanation:
        "This active stored role edge does not contribute authority while the role is archived.",
      prerequisite: "Role",
      state: "Archived",
    });
  }
  if (edge.provenance.retiredAt) {
    blockers.push({
      explanation:
        "This active stored edge does not contribute authority because its source is retired.",
      prerequisite: "Source",
      state: "Retired",
    });
  }
  return blockers;
}

const expiredEdgeAuthorityBlocker: EffectiveAuthorityBlocker = {
  explanation:
    "This active stored edge no longer contributes authority because its expiry deadline has passed.",
  prerequisite: "Edge expiry",
  state: "Expired",
};

const malformedEdgeExpiryAuthorityBlocker: EffectiveAuthorityBlocker = {
  explanation:
    "This active stored edge does not contribute authority because its expiry deadline is malformed and cannot be proven current.",
  prerequisite: "Edge expiry",
  state: "Invalid",
};

const maximumDeadlineTimerDelay = 2_147_483_647;

function useDeadlineStatus(expiresAt: string | undefined): {
  invalid: boolean;
  reached: boolean;
} {
  const deadline = expiresAt ? parseRfc3339Instant(expiresAt) : undefined;
  const [reachedDeadline, setReachedDeadline] = useState<bigint | null>(() =>
    deadline !== undefined && hasInstantReached(deadline) ? deadline : null,
  );

  useEffect(() => {
    if (deadline === undefined || hasInstantReached(deadline)) {
      return undefined;
    }
    let timer: ReturnType<typeof setTimeout> | undefined;
    const schedule = (): void => {
      const remainingNanoseconds = deadline - currentInstant();
      if (remainingNanoseconds <= 0n) {
        setReachedDeadline(deadline);
        return;
      }
      const remainingMilliseconds = Number(
        (remainingNanoseconds + 999_999n) / 1_000_000n,
      );
      timer = setTimeout(
        schedule,
        Math.min(remainingMilliseconds, maximumDeadlineTimerDelay),
      );
    };
    schedule();
    return () => {
      if (timer) {
        clearTimeout(timer);
      }
    };
  }, [deadline]);

  return {
    invalid: expiresAt !== undefined && deadline === undefined,
    reached:
      deadline !== undefined &&
      (hasInstantReached(deadline) || reachedDeadline === deadline),
  };
}

function canManuallyRevokeEdge(
  hasPermission: boolean,
  edge: {
    managedByAuthorizationApi: boolean;
    state: AuthorizationEdgeStateView;
  },
): boolean {
  return (
    hasPermission &&
    edge.state !== "revoked" &&
    isManagedByAuthorizationApi(edge.managedByAuthorizationApi)
  );
}

function isManagedByAuthorizationApi(value: unknown): value is true {
  return value === true;
}

function AuthorizationEdgeCard({
  actionState,
  canRevoke,
  effectiveAuthorityBlockers,
  etag,
  getDetailGeneration,
  isDetailGenerationActive,
  kind,
  managedByAuthorizationApi,
  onActionStateChange,
  onCancel,
  onRevoked,
  onStale,
  provenance,
  revokeReason,
  revokedAt,
  revokedByUserId,
  revoke,
  state,
  subtitle,
  title,
  version,
}: {
  actionState: EdgeActionState;
  canRevoke: boolean;
  effectiveAuthorityBlockers: readonly EffectiveAuthorityBlocker[];
  etag: string;
  getDetailGeneration: () => number;
  isDetailGenerationActive: (generation: number) => boolean;
  kind: "Membership edge" | "Role edge";
  managedByAuthorizationApi: boolean;
  onActionStateChange: (update: EdgeActionStateUpdate) => void;
  onCancel: () => void;
  onRevoked: () => void;
  onStale: (rejectedVersion: EdgeResourceVersion) => Promise<EdgeRefreshResult>;
  provenance: AuthorizationEdgeProvenanceView;
  revokeReason?: string | undefined;
  revokedAt?: string | undefined;
  revokedByUserId?: string | undefined;
  revoke: (etag: string, input: { reason: string }) => Promise<void>;
  state: AuthorizationEdgeStateView;
  subtitle: string;
  title: string;
  version: number;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const id = useId();
  const { isRefreshing, isSaving, refreshRequired, rejectedVersion } =
    actionState;
  const target = `${title} (${subtitle})`;
  const action = `${kind.toLowerCase()} for ${target}`;
  const expiryStatus = useDeadlineStatus(
    state === "active" ? provenance.expiresAt : undefined,
  );
  const authorityBlockers = expiryStatus.invalid
    ? [...effectiveAuthorityBlockers, malformedEdgeExpiryAuthorityBlocker]
    : expiryStatus.reached
      ? [...effectiveAuthorityBlockers, expiredEdgeAuthorityBlocker]
      : effectiveAuthorityBlockers;

  async function refreshStaleEdge(
    rejected = rejectedVersion,
    generation = getDetailGeneration(),
  ): Promise<void> {
    if (
      !rejected ||
      isRefreshing ||
      isSaving ||
      !isDetailGenerationActive(generation)
    ) {
      return;
    }
    onActionStateChange((current) => ({
      ...current,
      isRefreshing: true,
    }));
    try {
      const refreshed = await onStale(rejected);
      if (!isDetailGenerationActive(generation)) {
        return;
      }
      if (!refreshed.canRevoke) {
        onActionStateChange(null);
        return;
      }
      onActionStateChange((current) => ({
        ...current,
        error: `This ${kind.toLowerCase()} changed on the server. We reloaded the current edge; your reason is preserved. Review the current edge before retrying with the latest version.`,
        isRefreshing: false,
        open: true,
        refreshRequired: false,
        rejectedVersion: null,
      }));
    } catch (caught) {
      if (!isDetailGenerationActive(generation)) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onActionStateChange((current) => ({
          ...current,
          isRefreshing: false,
        }));
        clearSession(session.id);
        return;
      }
      const refreshError =
        caught instanceof InventoryVersionConflictError
          ? caught.message
          : describePhaseTwoError(
              caught,
              `The current ${kind.toLowerCase()} could not be reloaded.`,
            );
      onActionStateChange((current) => ({
        ...current,
        error: `${refreshError} Your reason is preserved. Retry loading the current edge before revoking.`,
        isRefreshing: false,
        isSaving: false,
        open: true,
        refreshRequired: true,
        rejectedVersion: rejected,
      }));
    }
  }

  async function submitRevoke(): Promise<void> {
    if (isSaving || isRefreshing || refreshRequired) {
      return;
    }
    const generation = getDetailGeneration();
    if (!isDetailGenerationActive(generation)) {
      return;
    }
    const parsed = reasonSchema.safeParse(actionState.reason);
    if (!parsed.success) {
      onActionStateChange((current) => ({
        ...current,
        error: parsed.error.issues[0]?.message ?? "Enter a reason.",
      }));
      return;
    }
    onActionStateChange((current) => ({
      ...current,
      error: null,
      isSaving: true,
    }));
    try {
      await revoke(etag, { reason: parsed.data });
      if (!isDetailGenerationActive(generation)) {
        return;
      }
      onRevoked();
    } catch (caught) {
      if (!isDetailGenerationActive(generation)) {
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        onActionStateChange((current) => ({
          ...current,
          isSaving: false,
        }));
        clearSession(session.id);
        return;
      }
      const stale = caught instanceof PhaseTwoApiError && caught.status === 412;
      if (stale) {
        const rejected = { entityTag: etag, version };
        onActionStateChange((current) => ({
          ...current,
          error: `This ${kind.toLowerCase()} changed on the server. Reloading the current edge; your reason is preserved.`,
          isSaving: false,
          open: true,
          refreshRequired: true,
          rejectedVersion: rejected,
        }));
        await refreshStaleEdge(rejected, generation);
      } else {
        onActionStateChange((current) => ({
          ...current,
          error: mutationMessage(
            caught,
            `The ${kind.toLowerCase()} was not revoked. Your reason is preserved.`,
          ),
          isSaving: false,
          open: true,
        }));
      }
    }
  }

  return (
    <article className="authorization-edge-card">
      <header>
        <div>
          <p>
            {kind} · {formatSourceKind(provenance.sourceKind)}
          </p>
          <strong>{title}</strong>
          <small>{subtitle}</small>
        </div>
        <Badge variant={state === "active" ? "secondary" : "outline"}>
          {formatStatus(state)}
        </Badge>
      </header>
      <EdgeProvenanceDetails
        provenance={provenance}
        revokeReason={revokeReason}
        revokedAt={revokedAt}
        revokedByUserId={revokedByUserId}
        state={state}
      />
      {state === "active" && authorityBlockers.length > 0 ? (
        <div
          className="capability-note"
          aria-label={`Effective authority blockers for ${target}`}
        >
          <strong>
            Edge lifecycle: Active. Effective authority: Does not contribute.
          </strong>
          <ul>
            {authorityBlockers.map((blocker) => (
              <li key={blocker.prerequisite}>
                <strong>
                  {blocker.prerequisite} prerequisite: {blocker.state}.
                </strong>{" "}
                {blocker.explanation}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {!canRevoke &&
      state !== "revoked" &&
      !isManagedByAuthorizationApi(managedByAuthorizationApi) ? (
        <p className="source-owner-note">
          Not managed by the authorization API (source:{" "}
          {formatSourceKind(provenance.sourceKind)}); manual controls cannot
          reconcile or revoke this edge.
        </p>
      ) : null}
      {actionState.error ? (
        <FocusedError title="Edge action failed" message={actionState.error} />
      ) : null}
      {refreshRequired ? (
        <Button
          type="button"
          variant="outline"
          disabled={isRefreshing || isSaving}
          aria-label={`Retry loading current ${action}`}
          onClick={() => void refreshStaleEdge()}
        >
          <RefreshCw aria-hidden="true" />
          {isRefreshing
            ? "Reloading current edge…"
            : "Retry loading current edge"}
        </Button>
      ) : null}
      {actionState.open ? (
        <div
          className="revoke-grant-form"
          role="group"
          aria-label={`Revoke ${action}`}
        >
          <strong id={`${id}-revoke-title`}>Revoke manual {action}</strong>
          <FormField htmlFor={`${id}-revoke-reason`} label="Reason">
            <Textarea
              id={`${id}-revoke-reason`}
              aria-label={`Reason for revoking ${action}`}
              value={actionState.reason}
              maxLength={500}
              disabled={isSaving || isRefreshing}
              onChange={(event) => {
                const reason = event.currentTarget.value;
                onActionStateChange((current) => ({
                  ...current,
                  error: null,
                  reason,
                }));
              }}
            />
          </FormField>
          {!canRevoke ? (
            <p className="capability-note">
              The refreshed edge is no longer eligible for manual revocation.
              Its draft remains open for review.
            </p>
          ) : null}
          <div>
            {canRevoke ? (
              <Button
                type="button"
                variant="destructive"
                disabled={isSaving || isRefreshing || refreshRequired}
                aria-label={`${isSaving ? "Revoking" : "Confirm revoke"} ${action}`}
                onClick={() => void submitRevoke()}
              >
                <Trash2 aria-hidden="true" />
                {isSaving ? "Revoking…" : "Confirm revoke"}
              </Button>
            ) : null}
            <Button
              type="button"
              variant="ghost"
              disabled={isSaving || isRefreshing}
              aria-label={`Keep edge; cancel revoke ${action}`}
              onClick={onCancel}
            >
              Keep edge
            </Button>
          </div>
        </div>
      ) : canRevoke ? (
        <Button
          type="button"
          size="sm"
          variant="outline"
          aria-label={`Revoke ${action}`}
          onClick={() =>
            onActionStateChange((current) => ({ ...current, open: true }))
          }
        >
          <Trash2 aria-hidden="true" /> Revoke
        </Button>
      ) : null}
    </article>
  );
}

function ProvenancePanel({
  group,
  memberships,
  roleGrants,
}: {
  group: TenantSecurityGroupView;
  memberships: EdgeInventoryState<TenantSecurityGroupMembershipView>;
  roleGrants: EdgeInventoryState<TenantSecurityGroupRoleGrantView>;
}): React.JSX.Element {
  return (
    <div className="provenance-panel">
      <div className="provenance-intro">
        <p className="section-label">Authority explanation</p>
        <h3>Two edges, two source owners</h3>
        <p>
          A role reaches a member only through the complete rail. The membership
          edge and role edge retain independent reasons, owners, retirement, and
          expiry. Group-derived administration never replaces the protected
          direct-human recovery path.
        </p>
      </div>
      <AccessPathRail
        group={group}
        membershipCount={readyCount(memberships)}
        roleCount={readyCount(roleGrants)}
        verbose
      />
      <div className="provenance-columns">
        <ProvenanceColumn
          icon={<UserRound aria-hidden="true" />}
          label="Membership edge sources"
          state={memberships}
          values={
            memberships.kind === "ready"
              ? memberships.items.map((edge) => ({
                  id: edge.id,
                  name: edge.member.user.displayName,
                  provenance: edge.provenance,
                  revokeReason: edge.revokeReason,
                  revokedAt: edge.revokedAt,
                  state: edge.state,
                }))
              : []
          }
        />
        <ProvenanceColumn
          icon={<Shield aria-hidden="true" />}
          label="Role edge sources"
          state={roleGrants}
          values={
            roleGrants.kind === "ready"
              ? roleGrants.items.map((edge) => ({
                  id: edge.id,
                  name: edge.role.name,
                  provenance: edge.provenance,
                  revokeReason: edge.revokeReason,
                  revokedAt: edge.revokedAt,
                  state: edge.state,
                }))
              : []
          }
        />
      </div>
    </div>
  );
}

function ProvenanceColumn<T>({
  icon,
  label,
  state,
  values,
}: {
  icon: React.ReactNode;
  label: string;
  state: EdgeInventoryState<T>;
  values: readonly {
    id: string;
    name: string;
    provenance: AuthorizationEdgeProvenanceView;
    revokeReason?: string | undefined;
    revokedAt?: string | undefined;
    state: AuthorizationEdgeStateView;
  }[];
}): React.JSX.Element {
  return (
    <section className="provenance-column">
      <header>
        {icon}
        <h4>{label}</h4>
      </header>
      {state.kind === "loading" ? <EdgeListSkeleton /> : null}
      {state.kind === "error" ? <FocusedError message={state.message} /> : null}
      {state.kind === "restricted" ? (
        <p className="capability-note">{state.message}</p>
      ) : null}
      {state.kind === "ready" && values.length === 0 ? (
        <p className="provenance-empty">No edges returned.</p>
      ) : null}
      {values.map((value) => (
        <article className="provenance-record" key={value.id}>
          <div>
            <strong>{value.name}</strong>
            <Badge variant={value.state === "active" ? "secondary" : "outline"}>
              {formatStatus(value.state)}
            </Badge>
          </div>
          <p>
            <span>{formatSourceKind(value.provenance.sourceKind)}</span>
            <code>{value.provenance.sourceId}</code>
          </p>
          <dl>
            <div>
              <dt>Source mode</dt>
              <dd>
                {value.provenance.authoritative ? "Authoritative" : "Additive"}
              </dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>
                {value.provenance.expiresAt
                  ? formatTimestamp(value.provenance.expiresAt)
                  : "Unbounded"}
              </dd>
            </div>
            <div>
              <dt>Revoked</dt>
              <dd>
                {value.revokedAt
                  ? formatTimestamp(value.revokedAt)
                  : "Not revoked"}
              </dd>
            </div>
            <div>
              <dt>Source retirement</dt>
              <dd>
                {value.provenance.retiredAt
                  ? formatTimestamp(value.provenance.retiredAt)
                  : "Source active"}
              </dd>
            </div>
          </dl>
          {value.provenance.retiredAt ? (
            <p className="capability-note">
              This source is retired, so the stored edge no longer contributes
              authority. The {formatStatus(value.state)} badge describes only
              the edge lifecycle.
            </p>
          ) : null}
          <blockquote>{value.provenance.reason}</blockquote>
          {value.revokeReason ? (
            <p className="provenance-revoke-reason">
              <strong>Revocation reason</strong>
              <span>{value.revokeReason}</span>
            </p>
          ) : null}
        </article>
      ))}
    </section>
  );
}

export function AccessPathRail({
  group,
  membershipCount,
  roleCount,
  verbose = false,
}: {
  group: Pick<TenantSecurityGroupView, "key" | "name">;
  membershipCount?: number | undefined;
  roleCount?: number | undefined;
  verbose?: boolean;
}): React.JSX.Element {
  return (
    <div
      className="access-path-rail"
      aria-label={`Two-edge access path through ${group.name}`}
    >
      <div className="access-path-rail__edge access-path-rail__edge--member">
        <UserRound aria-hidden="true" />
        <span>
          <small>Membership edge</small>
          <strong>
            {membershipCount === undefined
              ? "source-owned"
              : `${membershipCount} loaded ${membershipCount === 1 ? "edge" : "edges"}`}
          </strong>
        </span>
      </div>
      <span className="access-path-rail__connector" aria-hidden="true" />
      <div className="access-path-rail__group">
        <Network aria-hidden="true" />
        <span>
          <small>{verbose ? "Tenant security group" : "Group"}</small>
          <strong>{group.name}</strong>
          <code>{group.key}</code>
        </span>
      </div>
      <span className="access-path-rail__connector" aria-hidden="true" />
      <div className="access-path-rail__edge access-path-rail__edge--role">
        <Shield aria-hidden="true" />
        <span>
          <small>Role edge</small>
          <strong>
            {roleCount === undefined
              ? "source-owned"
              : `${roleCount} loaded ${roleCount === 1 ? "edge" : "edges"}`}
          </strong>
        </span>
      </div>
    </div>
  );
}

function EdgeProvenanceDetails({
  provenance,
  revokeReason,
  revokedAt,
  revokedByUserId,
  state,
}: {
  provenance: AuthorizationEdgeProvenanceView;
  revokeReason?: string | undefined;
  revokedAt?: string | undefined;
  revokedByUserId?: string | undefined;
  state: AuthorizationEdgeStateView;
}): React.JSX.Element {
  return (
    <>
      <dl className="edge-provenance-grid">
        <div>
          <dt>Source kind</dt>
          <dd>{formatSourceKind(provenance.sourceKind)}</dd>
        </div>
        <div>
          <dt>Source ID</dt>
          <dd>{provenance.sourceId}</dd>
        </div>
        <div>
          <dt>Source mode</dt>
          <dd>{provenance.authoritative ? "Authoritative" : "Additive"}</dd>
        </div>
        <div>
          <dt>Granted</dt>
          <dd>{formatTimestamp(provenance.grantedAt)}</dd>
        </div>
        <div>
          <dt>Granted by</dt>
          <dd>{provenance.grantedByUserId ?? "Protected source workflow"}</dd>
        </div>
        <div>
          <dt>Expires</dt>
          <dd>
            {provenance.expiresAt
              ? formatTimestamp(provenance.expiresAt)
              : "No scheduled expiry"}
          </dd>
        </div>
        <div>
          <dt>Edge state</dt>
          <dd>{formatStatus(state)}</dd>
        </div>
        <div>
          <dt>Source retirement</dt>
          <dd>
            {provenance.retiredAt
              ? formatTimestamp(provenance.retiredAt)
              : "Source active"}
          </dd>
        </div>
        <div>
          <dt>Revoked</dt>
          <dd>{revokedAt ? formatTimestamp(revokedAt) : "Not revoked"}</dd>
        </div>
        {revokedByUserId ? (
          <div>
            <dt>Revoked by</dt>
            <dd>{revokedByUserId}</dd>
          </div>
        ) : null}
        {revokeReason ? (
          <div>
            <dt>Revocation reason</dt>
            <dd>{revokeReason}</dd>
          </div>
        ) : null}
      </dl>
      <blockquote>{provenance.reason}</blockquote>
    </>
  );
}

function EdgeInventoryStatus<T>({
  inventory,
  resource,
}: {
  inventory: EdgeInventory<T>;
  resource: string;
}): React.JSX.Element | null {
  if (inventory.state.kind === "loading") {
    return <EdgeListSkeleton />;
  }
  if (inventory.state.kind === "restricted") {
    return <p className="capability-note">{inventory.state.message}</p>;
  }
  if (inventory.state.kind === "error") {
    return (
      <div className="tenant-admin-error">
        <FocusedError message={inventory.state.message} />
        <Button type="button" variant="outline" onClick={inventory.reload}>
          <RefreshCw aria-hidden="true" /> Retry {resource}
        </Button>
      </div>
    );
  }
  return null;
}

function EdgeLoadMore<T>({
  inventory,
  label,
}: {
  inventory: EdgeInventory<T>;
  label: string;
}): React.JSX.Element | null {
  if (inventory.state.kind !== "ready" || !inventory.state.nextCursor) {
    return inventory.paginationError ? (
      <FocusedError
        title={`More ${label} could not be loaded`}
        message={inventory.paginationError}
      />
    ) : null;
  }
  return (
    <div className="edge-pagination">
      {inventory.paginationError ? (
        <FocusedError
          title={`More ${label} could not be loaded`}
          message={inventory.paginationError}
        />
      ) : null}
      <Button
        type="button"
        variant="outline"
        disabled={inventory.paginationLoading}
        onClick={() => void inventory.loadMore()}
      >
        <ArrowDown aria-hidden="true" />
        {inventory.paginationLoading
          ? `Loading ${label}…`
          : `Load more ${label}`}
      </Button>
    </div>
  );
}

function EdgeEmpty({
  children,
  icon,
}: {
  children: React.ReactNode;
  icon: React.ReactNode;
}): React.JSX.Element {
  return (
    <div className="grant-empty">
      {icon}
      <p>{children}</p>
    </div>
  );
}

function useEdgeInventory<T>({
  enabled,
  identify,
  load,
  pairKey,
  resourceName,
  restrictedMessage,
  validate,
  versionOf,
}: {
  enabled: boolean;
  identify: (item: T) => string;
  load: (
    after: string | undefined,
    signal: AbortSignal,
  ) => Promise<EdgePage<T>>;
  pairKey: string;
  resourceName: string;
  restrictedMessage: string;
  validate?: (items: readonly T[]) => void;
  versionOf?: (item: T) => EdgeResourceVersion;
}): EdgeInventory<T> {
  const [revision, setRevision] = useState(0);
  const requestKey = JSON.stringify([pairKey, revision]);
  const requestKeyRef = useRef(requestKey);
  requestKeyRef.current = requestKey;
  const [snapshot, setSnapshot] = useState<{
    requestKey: string;
    state: EdgeInventoryState<T>;
  }>(() => ({ requestKey, state: { kind: "loading" } }));
  const state =
    snapshot.requestKey === requestKey
      ? snapshot.state
      : { kind: "loading" as const };
  const generationRef = useRef(0);
  const acceptedItemsRef = useRef<{
    items: readonly T[];
    requestKey: string;
  } | null>(null);
  const loadedPageDepthRef = useRef(0);
  const paginationRequestRef = useRef<EdgePaginationRequest | null>(null);
  const paginationCursorHistoryRef = useRef<Set<string>>(new Set());
  const refreshControllersRef = useRef<Set<AbortController>>(new Set());
  const [pagination, setPagination] = useState<{
    error?: string;
    loading: boolean;
    requestKey: string;
  }>({ loading: false, requestKey });
  const paginationState =
    pagination.requestKey === requestKey
      ? pagination
      : { loading: false, requestKey };

  useEffect(() => {
    generationRef.current += 1;
    paginationRequestRef.current?.controller.abort();
    paginationRequestRef.current = null;
    paginationCursorHistoryRef.current.clear();
    acceptedItemsRef.current = null;
    loadedPageDepthRef.current = 0;
    for (const refreshController of refreshControllersRef.current) {
      refreshController.abort();
    }
    refreshControllersRef.current.clear();
    setPagination({ loading: false, requestKey });
    if (!enabled) {
      setSnapshot({
        requestKey,
        state: { kind: "restricted", message: restrictedMessage },
      });
      return undefined;
    }
    const controller = new AbortController();
    setSnapshot({ requestKey, state: { kind: "loading" } });
    void load(undefined, controller.signal)
      .then((page) => {
        if (controller.signal.aborted || requestKeyRef.current !== requestKey) {
          return;
        }
        validate?.(page.items);
        const items = mergeInventoryItems([], page.items, identify, versionOf);
        if (page.nextCursor) {
          paginationCursorHistoryRef.current.add(page.nextCursor);
        }
        loadedPageDepthRef.current = 1;
        acceptedItemsRef.current = { items, requestKey };
        setSnapshot({
          requestKey,
          state: {
            items,
            kind: "ready",
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
        });
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted || requestKeyRef.current !== requestKey) {
          return;
        }
        setSnapshot({
          requestKey,
          state: {
            kind: "error",
            message:
              caught instanceof InventoryVersionConflictError
                ? caught.message
                : describePhaseTwoError(
                    caught,
                    `The group ${resourceName} could not be loaded.`,
                  ),
          },
        });
      });
    return () => {
      controller.abort();
      for (const refreshController of refreshControllersRef.current) {
        refreshController.abort();
      }
      refreshControllersRef.current.clear();
    };
  }, [
    enabled,
    identify,
    load,
    requestKey,
    resourceName,
    restrictedMessage,
    validate,
    versionOf,
  ]);

  async function loadMore(): Promise<void> {
    if (
      state.kind !== "ready" ||
      !state.nextCursor ||
      paginationState.loading
    ) {
      return;
    }
    const cursor = state.nextCursor;
    paginationRequestRef.current?.controller.abort();
    const controller = new AbortController();
    const generation = generationRef.current + 1;
    generationRef.current = generation;
    paginationRequestRef.current = {
      controller,
      cursor,
      generation,
      requestKey,
    };
    setPagination({ loading: true, requestKey });
    try {
      const page = await load(cursor, controller.signal);
      if (
        requestKeyRef.current !== requestKey ||
        !isCurrentEdgePaginationRequest(
          paginationRequestRef.current,
          requestKey,
          cursor,
          generation,
        )
      ) {
        return;
      }
      validate?.(page.items);
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          paginationCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error(`The ${resourceName} cursor did not advance.`);
      }
      const accepted = acceptedItemsRef.current;
      if (!accepted || accepted.requestKey !== requestKey) {
        throw new Error(`The ${resourceName} inventory was superseded.`);
      }
      const items = mergeInventoryItems(
        accepted.items,
        page.items,
        identify,
        versionOf,
      );
      if (page.nextCursor) {
        paginationCursorHistoryRef.current.add(page.nextCursor);
      }
      loadedPageDepthRef.current += 1;
      acceptedItemsRef.current = { items, requestKey };
      setSnapshot((current) => {
        if (
          current.requestKey !== requestKey ||
          current.state.kind !== "ready" ||
          current.state.nextCursor !== cursor
        ) {
          return current;
        }
        return {
          requestKey,
          state: {
            items,
            kind: "ready",
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
        };
      });
    } catch (caught) {
      if (
        requestKeyRef.current !== requestKey ||
        !isCurrentEdgePaginationRequest(
          paginationRequestRef.current,
          requestKey,
          cursor,
          generation,
        )
      ) {
        return;
      }
      if (caught instanceof InventoryVersionConflictError) {
        acceptedItemsRef.current = null;
        setSnapshot({
          requestKey,
          state: { kind: "error", message: caught.message },
        });
        return;
      }
      setPagination({
        error: describePhaseTwoError(
          caught,
          `More group ${resourceName} could not be loaded.`,
        ),
        loading: true,
        requestKey,
      });
    } finally {
      if (
        requestKeyRef.current === requestKey &&
        isCurrentEdgePaginationRequest(
          paginationRequestRef.current,
          requestKey,
          cursor,
          generation,
        )
      ) {
        paginationRequestRef.current = null;
        setPagination((current) =>
          current.requestKey === requestKey
            ? { ...current, loading: false }
            : current,
        );
      }
    }
  }

  async function refreshItem(
    itemId: string,
    rejectedVersion: EdgeResourceVersion,
  ): Promise<T> {
    if (state.kind !== "ready" || loadedPageDepthRef.current < 1) {
      throw new Error(`The current ${resourceName} inventory is unavailable.`);
    }
    if (!versionOf) {
      throw new Error(
        `The ${resourceName} inventory cannot verify refreshed resource versions.`,
      );
    }
    const loadedPageDepth = loadedPageDepthRef.current;
    const controller = new AbortController();
    refreshControllersRef.current.add(controller);
    const visitedCursors = new Set<string>();
    let after: string | undefined;
    let refreshed:
      | {
          ambiguous: boolean;
          item: T;
          resourceVersion: EdgeResourceVersion;
        }
      | undefined;
    try {
      for (let pageIndex = 0; pageIndex < loadedPageDepth; pageIndex += 1) {
        // oxlint-disable-next-line no-await-in-loop -- Exact-edge refresh follows the bounded cursor chain sequentially.
        const page = await load(after, controller.signal);
        if (controller.signal.aborted || requestKeyRef.current !== requestKey) {
          throw new Error(`The ${resourceName} refresh was superseded.`);
        }
        validate?.(page.items);
        for (const candidate of page.items) {
          const candidateVersion = versionOf(candidate);
          assertInventoryResourceVersion(candidateVersion);
          if (
            identify(candidate) !== itemId ||
            candidateVersion.version < rejectedVersion.version ||
            candidateVersion.entityTag === rejectedVersion.entityTag
          ) {
            continue;
          }
          if (
            !refreshed ||
            candidateVersion.version > refreshed.resourceVersion.version
          ) {
            refreshed = {
              ambiguous: false,
              item: candidate,
              resourceVersion: candidateVersion,
            };
            continue;
          }
          if (
            candidateVersion.version === refreshed.resourceVersion.version &&
            candidateVersion.entityTag !== refreshed.resourceVersion.entityTag
          ) {
            refreshed.ambiguous = true;
          }
        }
        if (!page.nextCursor) {
          break;
        }
        if (visitedCursors.has(page.nextCursor)) {
          throw new Error(
            `The ${resourceName} refresh cursor did not advance.`,
          );
        }
        visitedCursors.add(page.nextCursor);
        after = page.nextCursor;
      }
      if (refreshed) {
        if (refreshed.ambiguous) {
          throw new InventoryVersionConflictError(
            `The authorization-edge refresh returned multiple entity tags at resource version ${refreshed.resourceVersion.version}. Reload the inventory before acting.`,
          );
        }
        const accepted = acceptedItemsRef.current;
        if (!accepted || accepted.requestKey !== requestKey) {
          throw new Error(`The ${resourceName} refresh was superseded.`);
        }
        const reconciled = reconcileExactRefreshItem(
          accepted.items,
          refreshed.item,
          rejectedVersion,
          identify,
          versionOf,
        );
        acceptedItemsRef.current = { items: reconciled.items, requestKey };
        setSnapshot((current) =>
          current.requestKey === requestKey && current.state.kind === "ready"
            ? {
                requestKey,
                state: { ...current.state, items: reconciled.items },
              }
            : current,
        );
        return reconciled.item;
      }
      throw new Error(
        `The current edge was not found within the ${loadedPageDepth} loaded ${loadedPageDepth === 1 ? "page" : "pages"}.`,
      );
    } finally {
      refreshControllersRef.current.delete(controller);
    }
  }

  return {
    loadMore,
    paginationError: paginationState.error ?? null,
    paginationLoading: paginationState.loading,
    refreshItem,
    reload: () => setRevision((value) => value + 1),
    state,
  };
}

function assertGroupEdges(
  edges: readonly {
    group: { id: string; tenantId: string };
    tenantId: string;
  }[],
  tenantId: string,
  groupId: string,
): void {
  if (
    edges.some(
      (edge) =>
        edge.tenantId !== tenantId ||
        edge.group.tenantId !== tenantId ||
        edge.group.id !== groupId,
    )
  ) {
    throw new Error(
      "The authorization-edge response escaped the active group.",
    );
  }
}

function assertEdgeExpiries(
  edges: readonly { provenance: { expiresAt?: string | undefined } }[],
): void {
  if (
    edges.some(
      (edge) =>
        edge.provenance.expiresAt !== undefined &&
        parseRfc3339Instant(edge.provenance.expiresAt) === undefined,
    )
  ) {
    throw new Error(
      "The authorization-edge response contained an invalid expiry deadline.",
    );
  }
}

class InventoryVersionConflictError extends Error {}

function mergeInventoryItems<T>(
  current: readonly T[],
  incoming: readonly T[],
  identify: (item: T) => string,
  versionOf?: (item: T) => EdgeResourceVersion,
): readonly T[] {
  if (!versionOf) {
    const items = new Map(current.map((item) => [identify(item), item]));
    for (const item of incoming) {
      items.set(identify(item), item);
    }
    return [...items.values()];
  }

  const items = new Map<string, T>();
  for (const item of [...current, ...incoming]) {
    const id = identify(item);
    const itemVersion = versionOf(item);
    assertInventoryResourceVersion(itemVersion);
    const accepted = items.get(id);
    if (!accepted) {
      items.set(id, item);
      continue;
    }
    const acceptedVersion = versionOf(accepted);
    assertInventoryResourceVersion(acceptedVersion);
    if (itemVersion.version > acceptedVersion.version) {
      items.set(id, item);
    }
  }
  return [...items.values()];
}

function reconcileExactRefreshItem<T>(
  current: readonly T[],
  candidate: T,
  rejectedVersion: EdgeResourceVersion,
  identify: (item: T) => string,
  versionOf: (item: T) => EdgeResourceVersion,
): { item: T; items: readonly T[] } {
  const candidateVersion = versionOf(candidate);
  assertInventoryResourceVersion(candidateVersion);
  assertInventoryResourceVersion(rejectedVersion);
  if (
    candidateVersion.version < rejectedVersion.version ||
    candidateVersion.entityTag === rejectedVersion.entityTag
  ) {
    throw new Error(
      "The authorization-edge refresh did not return a fresh full representation.",
    );
  }

  const candidateId = identify(candidate);
  const currentItem = current.find((item) => identify(item) === candidateId);
  if (!currentItem) {
    return { item: candidate, items: [...current, candidate] };
  }
  const currentVersion = versionOf(currentItem);
  assertInventoryResourceVersion(currentVersion);

  let accepted = candidate;
  if (currentVersion.version > candidateVersion.version) {
    accepted = currentItem;
  } else if (sameEdgeResourceVersion(currentVersion, candidateVersion)) {
    accepted = currentItem;
  } else if (sameEdgeResourceVersion(currentVersion, rejectedVersion)) {
    accepted = candidate;
  } else if (currentVersion.version === candidateVersion.version) {
    throw new InventoryVersionConflictError(
      `The authorization-edge refresh encountered a third entity tag at resource version ${candidateVersion.version}. Reload the inventory before acting.`,
    );
  }

  return {
    item: accepted,
    items: current.map((item) =>
      identify(item) === candidateId ? accepted : item,
    ),
  };
}

function sameEdgeResourceVersion(
  left: EdgeResourceVersion,
  right: EdgeResourceVersion,
): boolean {
  return left.version === right.version && left.entityTag === right.entityTag;
}

function assertInventoryResourceVersion(version: EdgeResourceVersion): void {
  const entityTagMatch = /^"v([1-9][0-9]*)-[A-Za-z0-9_-]+"$/.exec(
    version.entityTag,
  );
  if (
    !Number.isSafeInteger(version.version) ||
    version.version < 1 ||
    version.version > maximumEdgeResourceVersion ||
    !entityTagMatch ||
    entityTagMatch[1] !== String(version.version)
  ) {
    throw new InventoryVersionConflictError(
      "The authorization-edge inventory returned an invalid resource version. Reload the inventory before acting.",
    );
  }
}

function identifyEdge(item: { id: string }): string {
  return item.id;
}

function edgeResourceVersion(item: {
  etag: string;
  version: number;
}): EdgeResourceVersion {
  return { entityTag: item.etag, version: item.version };
}

function identifyTenantUser(item: TenantUserSummaryView): string {
  return item.user.id;
}

function identifyTenantRole(item: TenantRoleSummaryView): string {
  return item.id;
}

function isCurrentEdgePaginationRequest(
  request: EdgePaginationRequest | null,
  requestKey: string,
  cursor: string,
  generation: number,
): boolean {
  return (
    request?.requestKey === requestKey &&
    request.cursor === cursor &&
    request.generation === generation &&
    !request.controller.signal.aborted
  );
}

function hasTenantPermission(
  authority: TenantAuthorityView | undefined,
  permissionKey: TenantPermissionKeyView,
): boolean {
  return (
    authority?.permissions.some(
      (permission) =>
        permission.permissionKey === permissionKey &&
        permission.scope === "tenant",
    ) ?? false
  );
}

function readyCount<T>(state: EdgeInventoryState<T>): number | undefined {
  return state.kind === "ready" ? state.items.length : undefined;
}

function parseEdgeExpiry(value: string): { error?: string; value?: string } {
  if (!value) {
    return {};
  }
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) {
    return { error: "Choose a valid edge expiry." };
  }
  return { value: new Date(parsed).toISOString() };
}

function mutationMessage(error: unknown, fallback: string): string {
  if (error instanceof PhaseTwoApiError) {
    if (error.status === 409) {
      return "This command conflicts with current server state or an earlier idempotent request. Review the preserved input before retrying.";
    }
    if (error.status === 412) {
      return "This resource changed on the server. Your input is preserved; reload the current version before retrying.";
    }
    if (error.status === 428) {
      return "The server requires a current strong resource version. Reload before retrying.";
    }
  }
  return describePhaseTwoError(error, fallback);
}

function formatSourceKind(value: string): string {
  return value.replaceAll("_", " ");
}

function formatStatus(value: string): string {
  return value.replaceAll("_", " ");
}

function formatTimestamp(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.valueOf())
    ? "Unavailable"
    : new Intl.DateTimeFormat(undefined, {
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        month: "short",
        timeZoneName: "short",
        year: "numeric",
      }).format(date);
}

function toLocalDateTime(value: string): string {
  const date = new Date(value);
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.valueOf() - offset).toISOString().slice(0, 19);
}

function GroupDetailSkeleton(): React.JSX.Element {
  return (
    <div
      className="group-detail-skeleton"
      aria-label="Loading security-group detail"
    >
      <span />
      <span />
      <span />
    </div>
  );
}

function EdgeListSkeleton(): React.JSX.Element {
  return (
    <div
      className="edge-list-skeleton"
      aria-label="Loading authorization edges"
    >
      <span />
      <span />
    </div>
  );
}
