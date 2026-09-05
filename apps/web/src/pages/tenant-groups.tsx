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
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { ArrowDown, Eye, Network, Plus, RefreshCw } from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import { hasControlCharacters } from "../lib/text-validation";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type PhaseTwoApi,
  type TenantSecurityGroupCreateInput,
  type TenantSecurityGroupView,
  type VersionedView,
} from "../lib/phase-two-types";
import { TenantGroupDetailDialog } from "./tenant-group-detail";

type GroupListState =
  | { kind: "authority_error"; message: string }
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | { kind: "inactive" }
  | {
      items: readonly TenantSecurityGroupView[];
      kind: "ready";
      nextCursor?: string;
    }
  | { kind: "loading" };

export type TenantGroupDetailState =
  | { kind: "error"; message: string }
  | { kind: "forbidden" }
  | { kind: "loading" }
  | { group: VersionedView<TenantSecurityGroupView>; kind: "ready" };

interface PairSnapshot<T> {
  pairKey: string;
  state: T;
}

interface GroupSelection {
  generation: number;
  groupId: string;
  pairKey: string;
}

interface DetailRequest {
  controller: AbortController;
  generation: number;
  groupId: string;
  pairKey: string;
}

interface PaginationRequest {
  controller: AbortController;
  cursor: string;
  generation: number;
  pairKey: string;
}

interface PaginationState {
  error?: string;
  loading: boolean;
}

const groupFormSchema = z.object({
  description: z
    .string()
    .max(500, "Use 500 characters or fewer.")
    .refine(
      (value) => !hasControlCharacters(value),
      "Use a description without control characters.",
    ),
  key: z
    .string()
    .trim()
    .regex(
      /^[a-z][a-z0-9_]{2,63}$/,
      "Use 3–64 lowercase letters, numbers, or underscores, starting with a letter.",
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

type GroupFormValues = z.infer<typeof groupFormSchema>;

export function TenantGroupsPage(): React.JSX.Element {
  const { api, session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const requestPair = JSON.stringify([session.id, tenantId ?? null]);
  const requestPairRef = useRef(requestPair);
  requestPairRef.current = requestPair;
  const canRead = authority.hasPermission("group.read");
  const canManage = authority.hasPermission("group.manage");
  const authorityReady =
    Boolean(tenantId) && authority.status === "ready" && canRead;
  const authorityReadyRef = useRef(authorityReady);
  authorityReadyRef.current = authorityReady;
  const initialListState: GroupListState = deriveInitialListState(
    tenantId,
    authority.status,
    authority.message,
    canRead,
  );
  const [listSnapshot, setListSnapshot] = useState<
    PairSnapshot<GroupListState>
  >(() => ({ pairKey: requestPair, state: initialListState }));
  const listState =
    authorityReady && listSnapshot.pairKey === requestPair
      ? listSnapshot.state
      : initialListState;
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [notice, setNotice] = useState<string | null>(null);
  const [createGeneration, setCreateGeneration] = useState<number | null>(null);
  const createGenerationRef = useRef(0);
  const [paginationSnapshot, setPaginationSnapshot] = useState<
    PairSnapshot<PaginationState>
  >(() => ({ pairKey: requestPair, state: { loading: false } }));
  const paginationState =
    paginationSnapshot.pairKey === requestPair
      ? paginationSnapshot.state
      : { loading: false };
  const paginationGenerationRef = useRef(0);
  const paginationRequestRef = useRef<PaginationRequest | null>(null);
  const paginationCursorHistoryRef = useRef<Set<string>>(new Set());
  const [selection, setSelection] = useState<GroupSelection | null>(null);
  const selectionGenerationRef = useRef(0);
  const detailGenerationRef = useRef(0);
  const detailRequestRef = useRef<DetailRequest | null>(null);
  const [detailSnapshot, setDetailSnapshot] = useState<
    PairSnapshot<TenantGroupDetailState> & { groupId: string }
  >(() => ({ groupId: "", pairKey: requestPair, state: { kind: "loading" } }));
  const selected =
    authorityReady && selection?.pairKey === requestPair ? selection : null;
  const selectedRef = useRef<GroupSelection | null>(selected);
  selectedRef.current = selected;
  const selectedGroupId = selected?.groupId ?? null;
  const detailState =
    selectedGroupId &&
    detailSnapshot.pairKey === requestPair &&
    detailSnapshot.groupId === selectedGroupId
      ? detailSnapshot.state
      : { kind: "loading" as const };
  const createOpen =
    authorityReady &&
    createGeneration !== null &&
    createGeneration === createGenerationRef.current;

  useEffect(() => {
    if (authorityReady) {
      return;
    }
    createGenerationRef.current += 1;
    setCreateGeneration(null);
    selectionGenerationRef.current += 1;
    setSelection(null);
    detailGenerationRef.current += 1;
    detailRequestRef.current?.controller.abort();
    detailRequestRef.current = null;
    setDetailSnapshot({
      groupId: "",
      pairKey: requestPair,
      state: { kind: "loading" },
    });
    paginationGenerationRef.current += 1;
    paginationRequestRef.current?.controller.abort();
    paginationRequestRef.current = null;
    paginationCursorHistoryRef.current.clear();
    setPaginationSnapshot({ pairKey: requestPair, state: { loading: false } });
    setListSnapshot({ pairKey: requestPair, state: initialListState });
    setNotice(null);
  }, [
    authority.message,
    authority.status,
    authorityReady,
    canRead,
    requestPair,
    tenantId,
  ]);

  useEffect(() => {
    paginationGenerationRef.current += 1;
    paginationRequestRef.current?.controller.abort();
    paginationRequestRef.current = null;
    paginationCursorHistoryRef.current.clear();
    setPaginationSnapshot({ pairKey: requestPair, state: { loading: false } });

    const state = deriveInitialListState(
      tenantId,
      authority.status,
      authority.message,
      canRead,
    );
    if (!tenantId || authority.status !== "ready" || !canRead) {
      setListSnapshot({ pairKey: requestPair, state });
      return undefined;
    }

    const controller = new AbortController();
    setListSnapshot({ pairKey: requestPair, state: { kind: "loading" } });
    void api
      .listTenantSecurityGroups(tenantId, {
        includeArchived: true,
        signal: controller.signal,
      })
      .then((page) => {
        if (
          controller.signal.aborted ||
          requestPairRef.current !== requestPair ||
          !authorityReadyRef.current
        ) {
          return;
        }
        assertTenantGroups(page.items, tenantId);
        if (page.nextCursor) {
          paginationCursorHistoryRef.current.add(page.nextCursor);
        }
        setListSnapshot({
          pairKey: requestPair,
          state: {
            items: mergeTenantGroups([], page.items),
            kind: "ready",
            ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
          },
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          requestPairRef.current !== requestPair ||
          !authorityReadyRef.current
        ) {
          return;
        }
        setListSnapshot({
          pairKey: requestPair,
          state:
            caught instanceof PhaseTwoApiError && caught.status === 403
              ? { kind: "forbidden" }
              : {
                  kind: "error",
                  message: describePhaseTwoError(
                    caught,
                    "The tenant security-group inventory could not be loaded.",
                  ),
                },
        });
      });
    return () => controller.abort();
  }, [
    api,
    authority.message,
    authority.status,
    canRead,
    loadAttempt,
    requestPair,
    tenantId,
  ]);

  useEffect(() => {
    createGenerationRef.current += 1;
    setCreateGeneration(null);
    selectionGenerationRef.current += 1;
    setSelection(null);
    detailGenerationRef.current += 1;
    detailRequestRef.current?.controller.abort();
    detailRequestRef.current = null;
    setNotice(null);
    return () => {
      createGenerationRef.current += 1;
      selectionGenerationRef.current += 1;
      detailGenerationRef.current += 1;
      detailRequestRef.current?.controller.abort();
      detailRequestRef.current = null;
      paginationGenerationRef.current += 1;
      paginationRequestRef.current?.controller.abort();
      paginationRequestRef.current = null;
    };
  }, [requestPair]);

  function openCreate(): void {
    if (!authorityReadyRef.current) {
      return;
    }
    const generation = createGenerationRef.current + 1;
    createGenerationRef.current = generation;
    setCreateGeneration(generation);
  }

  function closeCreate(): void {
    createGenerationRef.current += 1;
    setCreateGeneration(null);
  }

  function openGroup(groupId: string): void {
    if (!authorityReadyRef.current) {
      return;
    }
    const generation = selectionGenerationRef.current + 1;
    selectionGenerationRef.current = generation;
    setSelection({ generation, groupId, pairKey: requestPair });
    void loadDetail(groupId, generation);
  }

  function closeGroup(): void {
    selectionGenerationRef.current += 1;
    detailGenerationRef.current += 1;
    detailRequestRef.current?.controller.abort();
    detailRequestRef.current = null;
    setSelection(null);
  }

  async function loadDetail(
    groupId: string,
    selectionGeneration: number,
  ): Promise<void> {
    if (!tenantId || !authorityReadyRef.current) {
      return;
    }
    detailRequestRef.current?.controller.abort();
    const controller = new AbortController();
    const generation = detailGenerationRef.current + 1;
    detailGenerationRef.current = generation;
    const expectedPair = requestPair;
    detailRequestRef.current = {
      controller,
      generation,
      groupId,
      pairKey: expectedPair,
    };
    setDetailSnapshot({
      groupId,
      pairKey: expectedPair,
      state: { kind: "loading" },
    });
    try {
      const group = await api.getTenantSecurityGroup(
        tenantId,
        groupId,
        controller.signal,
      );
      if (
        requestPairRef.current !== expectedPair ||
        !authorityReadyRef.current ||
        selectionGenerationRef.current !== selectionGeneration ||
        !isCurrentDetailRequest(
          detailRequestRef.current,
          expectedPair,
          groupId,
          generation,
        )
      ) {
        return;
      }
      assertTenantGroups([group.value], tenantId);
      setDetailSnapshot({
        groupId,
        pairKey: expectedPair,
        state: { group, kind: "ready" },
      });
    } catch (caught) {
      if (
        requestPairRef.current !== expectedPair ||
        !authorityReadyRef.current ||
        selectionGenerationRef.current !== selectionGeneration ||
        !isCurrentDetailRequest(
          detailRequestRef.current,
          expectedPair,
          groupId,
          generation,
        )
      ) {
        return;
      }
      setDetailSnapshot({
        groupId,
        pairKey: expectedPair,
        state:
          caught instanceof PhaseTwoApiError && caught.status === 403
            ? { kind: "forbidden" }
            : {
                kind: "error",
                message: describePhaseTwoError(
                  caught,
                  "The security-group detail could not be loaded.",
                ),
              },
      });
    } finally {
      if (
        isCurrentDetailRequest(
          detailRequestRef.current,
          expectedPair,
          groupId,
          generation,
        )
      ) {
        detailRequestRef.current = null;
      }
    }
  }

  async function loadMore(): Promise<void> {
    if (
      !tenantId ||
      !authorityReadyRef.current ||
      listState.kind !== "ready" ||
      !listState.nextCursor ||
      paginationState.loading
    ) {
      return;
    }
    const cursor = listState.nextCursor;
    const expectedPair = requestPair;
    paginationRequestRef.current?.controller.abort();
    const controller = new AbortController();
    const generation = paginationGenerationRef.current + 1;
    paginationGenerationRef.current = generation;
    paginationRequestRef.current = {
      controller,
      cursor,
      generation,
      pairKey: expectedPair,
    };
    setPaginationSnapshot({
      pairKey: expectedPair,
      state: { loading: true },
    });
    try {
      const page = await api.listTenantSecurityGroups(tenantId, {
        after: cursor,
        includeArchived: true,
        signal: controller.signal,
      });
      if (
        requestPairRef.current !== expectedPair ||
        !authorityReadyRef.current ||
        !isCurrentPaginationRequest(
          paginationRequestRef.current,
          expectedPair,
          cursor,
          generation,
        )
      ) {
        return;
      }
      assertTenantGroups(page.items, tenantId);
      if (
        page.nextCursor &&
        (page.nextCursor === cursor ||
          paginationCursorHistoryRef.current.has(page.nextCursor))
      ) {
        throw new Error("The security-group cursor did not advance.");
      }
      if (page.nextCursor) {
        paginationCursorHistoryRef.current.add(page.nextCursor);
      }
      setListSnapshot((current) => {
        if (
          current.pairKey !== expectedPair ||
          current.state.kind !== "ready" ||
          current.state.nextCursor !== cursor
        ) {
          return current;
        }
        const merged = tryMergeTenantGroups(current.state.items, page.items);
        return merged.ok
          ? {
              pairKey: expectedPair,
              state: {
                items: merged.items,
                kind: "ready",
                ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
              },
            }
          : {
              pairKey: expectedPair,
              state: {
                kind: "error",
                message:
                  "The security-group inventory returned conflicting representations at the same version. Reload the inventory before acting.",
              },
            };
      });
    } catch (caught) {
      if (
        requestPairRef.current !== expectedPair ||
        !authorityReadyRef.current ||
        !isCurrentPaginationRequest(
          paginationRequestRef.current,
          expectedPair,
          cursor,
          generation,
        )
      ) {
        return;
      }
      setPaginationSnapshot({
        pairKey: expectedPair,
        state: {
          error: describePhaseTwoError(
            caught,
            "More security groups could not be loaded.",
          ),
          loading: true,
        },
      });
    } finally {
      if (
        requestPairRef.current === expectedPair &&
        authorityReadyRef.current &&
        isCurrentPaginationRequest(
          paginationRequestRef.current,
          expectedPair,
          cursor,
          generation,
        )
      ) {
        paginationRequestRef.current = null;
        setPaginationSnapshot((current) =>
          current.pairKey === expectedPair
            ? {
                pairKey: expectedPair,
                state: { ...current.state, loading: false },
              }
            : current,
        );
      }
    }
  }

  function mergeGroupIntoInventory(group: TenantSecurityGroupView): void {
    if (!authorityReadyRef.current) {
      return;
    }
    setListSnapshot((current) => {
      if (current.pairKey !== requestPair || current.state.kind !== "ready") {
        return current;
      }
      const merged = tryMergeTenantGroups(current.state.items, [group]);
      return merged.ok
        ? {
            pairKey: requestPair,
            state: {
              ...current.state,
              items: merged.items,
            },
          }
        : {
            pairKey: requestPair,
            state: {
              kind: "error",
              message:
                "The security-group inventory returned conflicting representations at the same version. Reload the inventory before acting.",
            },
          };
    });
  }

  if (listState.kind === "forbidden") {
    return <ServerDenied resource="the tenant security-group inventory" />;
  }

  if (listState.kind === "inactive") {
    return (
      <div className="content content--narrow">
        <section className="page-heading">
          <div>
            <p className="section-label">Tenant authorization</p>
            <h1>Select a tenant to inspect security groups.</h1>
            <p>Group administration always requires an explicit tenant path.</p>
          </div>
        </section>
      </div>
    );
  }

  return (
    <div className="content tenant-admin-page tenant-group-page">
      <section className="page-heading" aria-labelledby="groups-page-title">
        <div>
          <p className="section-label">Access paths / Phase 2B.2a</p>
          <h1 id="groups-page-title">Security groups</h1>
          <p>
            Compose direct tenant membership edges with role edges while
            retaining the independent source and lifetime of every path. Groups
            cannot contain other groups.
          </p>
        </div>
        <Badge variant="outline">
          <Network aria-hidden="true" /> Direct-only topology
        </Badge>
      </section>

      {notice ? (
        <p className="group-action-notice" role="status">
          {notice}
        </p>
      ) : null}
      {paginationState.error ? (
        <FocusedError
          title="More groups could not be loaded"
          message={paginationState.error}
        />
      ) : null}
      {listState.kind === "authority_error" ? (
        <FocusedError
          title="Live authority unavailable"
          message={listState.message}
        />
      ) : null}
      {listState.kind === "loading" ? <GroupListSkeleton /> : null}
      {listState.kind === "error" ? (
        <div className="tenant-admin-error">
          <FocusedError message={listState.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setLoadAttempt((attempt) => attempt + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry group inventory
          </Button>
        </div>
      ) : null}
      {listState.kind === "ready" ? (
        <section
          className="authority-inventory"
          aria-labelledby="group-inventory-title"
        >
          <div className="section-heading group-inventory-heading">
            <div>
              <p className="section-label">Server inventory</p>
              <h2 id="group-inventory-title">Tenant-owned groups</h2>
            </div>
            {canManage ? (
              <Button type="button" onClick={openCreate}>
                <Plus aria-hidden="true" /> Create group
              </Button>
            ) : null}
          </div>
          {listState.items.length === 0 ? (
            <div className="tenant-empty group-empty-inline">
              <Network aria-hidden="true" />
              <h2>No security groups returned</h2>
              <p>
                {canManage
                  ? "Create a tenant-local group to begin composing access paths."
                  : "The server returned no groups for this tenant."}
              </p>
            </div>
          ) : (
            <Table className="authority-table group-table">
              <TableCaption className="sr-only">
                Security groups in the active tenant
              </TableCaption>
              <TableHeader>
                <TableRow>
                  <TableHead>Group</TableHead>
                  <TableHead>Topology</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listState.items.map((group) => (
                  <TableRow key={group.id}>
                    <TableCell>
                      <span className="role-name-cell">
                        <strong>{group.name}</strong>
                        <small>{group.key}</small>
                      </span>
                    </TableCell>
                    <TableCell>Direct members only</TableCell>
                    <TableCell>
                      <Badge variant={group.archived ? "outline" : "secondary"}>
                        {group.archived ? "Archived" : "Active"}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatTimestamp(group.updatedAt)}</TableCell>
                    <TableCell>
                      <Button
                        type="button"
                        size="sm"
                        variant="ghost"
                        aria-label={`Open ${group.name} (${group.key})`}
                        onClick={() => openGroup(group.id)}
                      >
                        <Eye aria-hidden="true" /> Open
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {listState.nextCursor ? (
            <Button
              type="button"
              variant="outline"
              disabled={paginationState.loading}
              onClick={() => void loadMore()}
            >
              <ArrowDown aria-hidden="true" />
              {paginationState.loading ? "Loading groups…" : "Load more groups"}
            </Button>
          ) : null}
        </section>
      ) : null}

      {tenantId && createOpen && canManage ? (
        <CreateGroupDialog
          api={api}
          csrfToken={session.csrfToken}
          onCreated={(group) => {
            if (
              requestPairRef.current !== requestPair ||
              !authorityReadyRef.current ||
              createGenerationRef.current !== createGeneration
            ) {
              return;
            }
            mergeGroupIntoInventory(group.value);
            setNotice(
              "Security group created, or the server confirmed the matching retry.",
            );
            closeCreate();
          }}
          onOpenChange={(open) => {
            if (!open) {
              closeCreate();
            }
          }}
          tenantId={tenantId}
        />
      ) : null}

      {tenantId && selected && selectedGroupId ? (
        <TenantGroupDetailDialog
          api={api}
          authority={authority.authority}
          canManage={canManage}
          csrfToken={session.csrfToken}
          detailState={detailState}
          groupId={selectedGroupId}
          key={`${requestPair}:${selectedGroupId}:${selected.generation}`}
          onArchived={() => {
            const current = selectedRef.current;
            if (
              requestPairRef.current !== requestPair ||
              !authorityReadyRef.current ||
              current?.pairKey !== selected.pairKey ||
              current.groupId !== selected.groupId ||
              current.generation !== selected.generation
            ) {
              return;
            }
            closeGroup();
            setNotice("Security group archived at the current server version.");
            setLoadAttempt((attempt) => attempt + 1);
            authority.reload();
          }}
          onChanged={(group) => {
            const current = selectedRef.current;
            if (
              requestPairRef.current !== requestPair ||
              !authorityReadyRef.current ||
              current?.pairKey !== selected.pairKey ||
              current.groupId !== selected.groupId ||
              current.generation !== selected.generation ||
              group.value.id !== selected.groupId
            ) {
              return;
            }
            mergeGroupIntoInventory(group.value);
            setDetailSnapshot({
              groupId: group.value.id,
              pairKey: requestPair,
              state: { group, kind: "ready" },
            });
          }}
          onOpenChange={(open) => {
            if (!open) {
              closeGroup();
            }
          }}
          onReload={() => {
            const current = selection;
            if (authorityReadyRef.current && current?.pairKey === requestPair) {
              void loadDetail(current.groupId, current.generation);
            }
          }}
          pairKey={requestPair}
          tenantId={tenantId}
        />
      ) : null}
    </div>
  );
}

function CreateGroupDialog({
  api,
  csrfToken,
  onCreated,
  onOpenChange,
  tenantId,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  onCreated: (group: VersionedView<TenantSecurityGroupView>) => void;
  onOpenChange: (open: boolean) => void;
  tenantId: string;
}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const id = useId();
  const [formError, setFormError] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);
  const { handleSubmit, register } = useForm<GroupFormValues>({
    defaultValues: { description: "", key: "", name: "" },
  });

  const submit = handleSubmit(async (rawValues) => {
    const parsed = groupFormSchema.safeParse(rawValues);
    if (!parsed.success) {
      setFormError(
        parsed.error.issues[0]?.message ?? "Review the group fields.",
      );
      return;
    }
    const input: TenantSecurityGroupCreateInput = {
      ...(parsed.data.description.trim()
        ? { description: parsed.data.description.trim() }
        : {}),
      key: parsed.data.key,
      name: parsed.data.name,
    };
    setFormError(null);
    setIsSaving(true);
    try {
      const created = await api.createTenantSecurityGroup(
        csrfToken,
        tenantId,
        idempotencyKeyForPayload(idempotencyBindingRef, {
          input,
          tenantId,
        }),
        input,
      );
      onCreated(created);
    } catch (caught) {
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
        return;
      }
      setFormError(
        mutationMessage(
          caught,
          "The group was not created. Your input is preserved.",
        ),
      );
    } finally {
      setIsSaving(false);
    }
  });

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="group-create-dialog">
        <DialogHeader>
          <DialogTitle>Create security group</DialogTitle>
          <DialogDescription>
            Creates one tenant-owned, non-nested group. Membership and role
            edges are added independently after creation.
          </DialogDescription>
        </DialogHeader>
        <form className="group-form" onSubmit={submit} noValidate>
          {formError ? (
            <FocusedError title="Group not created" message={formError} />
          ) : null}
          <FormField htmlFor={`${id}-group-key`} label="Group key">
            <Input
              id={`${id}-group-key`}
              autoComplete="off"
              maxLength={64}
              disabled={isSaving}
              {...register("key")}
            />
          </FormField>
          <FormField htmlFor={`${id}-group-name`} label="Group name">
            <Input
              id={`${id}-group-name`}
              autoComplete="off"
              maxLength={120}
              disabled={isSaving}
              {...register("name")}
            />
          </FormField>
          <FormField
            htmlFor={`${id}-group-description`}
            label="Description"
            optional
          >
            <Textarea
              id={`${id}-group-description`}
              maxLength={500}
              disabled={isSaving}
              {...register("description")}
            />
          </FormField>
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={isSaving}
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={isSaving}>
              {isSaving ? "Creating group…" : "Create group"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function deriveInitialListState(
  tenantId: string | undefined,
  status: string,
  message: string | undefined,
  canRead: boolean,
): GroupListState {
  if (!tenantId) {
    return { kind: "inactive" };
  }
  if (status === "error") {
    return {
      kind: "authority_error",
      message:
        message ??
        "Live tenant authority is unavailable. Group access stays closed.",
    };
  }
  if (status === "forbidden" || (status === "ready" && !canRead)) {
    return { kind: "forbidden" };
  }
  return { kind: "loading" };
}

function assertTenantGroups(
  groups: readonly TenantSecurityGroupView[],
  tenantId: string,
): void {
  if (groups.some((group) => group.tenantId !== tenantId)) {
    throw new Error("The security-group response escaped the active tenant.");
  }
}

export function mergeTenantGroups(
  current: readonly TenantSecurityGroupView[],
  incoming: readonly TenantSecurityGroupView[],
): readonly TenantSecurityGroupView[] {
  const merged = tryMergeTenantGroups(current, incoming);
  if (!merged.ok) {
    throw new Error(
      "The security-group inventory returned conflicting representations at the same version.",
    );
  }
  return merged.items;
}

function tryMergeTenantGroups(
  current: readonly TenantSecurityGroupView[],
  incoming: readonly TenantSecurityGroupView[],
): { items: readonly TenantSecurityGroupView[]; ok: true } | { ok: false } {
  const groups = new Map<string, TenantSecurityGroupView>();
  for (const group of [...current, ...incoming]) {
    if (!validInventoryVersion(group.version)) {
      return { ok: false };
    }
    const accepted = groups.get(group.id);
    if (!accepted || group.version > accepted.version) {
      groups.set(group.id, group);
      continue;
    }
    if (group.version < accepted.version) {
      continue;
    }
    if (!sameGroupRepresentation(accepted, group)) {
      return { ok: false };
    }
  }
  return { items: [...groups.values()], ok: true };
}

function validInventoryVersion(version: number): boolean {
  return (
    Number.isSafeInteger(version) && version > 0 && version <= 2_147_483_647
  );
}

function sameGroupRepresentation(
  left: TenantSecurityGroupView,
  right: TenantSecurityGroupView,
): boolean {
  return (
    left.id === right.id &&
    left.tenantId === right.tenantId &&
    left.key === right.key &&
    left.name === right.name &&
    left.description === right.description &&
    left.archived === right.archived &&
    left.archivedAt === right.archivedAt &&
    left.version === right.version &&
    left.createdAt === right.createdAt &&
    left.updatedAt === right.updatedAt
  );
}

function isCurrentDetailRequest(
  request: DetailRequest | null,
  pairKey: string,
  groupId: string,
  generation: number,
): boolean {
  return (
    request?.pairKey === pairKey &&
    request.groupId === groupId &&
    request.generation === generation &&
    !request.controller.signal.aborted
  );
}

function isCurrentPaginationRequest(
  request: PaginationRequest | null,
  pairKey: string,
  cursor: string,
  generation: number,
): boolean {
  return (
    request?.pairKey === pairKey &&
    request.cursor === cursor &&
    request.generation === generation &&
    !request.controller.signal.aborted
  );
}

function GroupListSkeleton(): React.JSX.Element {
  return (
    <div className="tenant-list-skeleton" aria-label="Loading security groups">
      <span />
      <span />
      <span />
    </div>
  );
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
