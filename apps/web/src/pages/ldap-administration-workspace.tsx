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
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  Activity,
  Archive,
  CheckCircle2,
  FlaskConical,
  KeyRound,
  Plus,
  RefreshCw,
  Save,
  ShieldAlert,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useLayoutEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import { TableColumnHeaders } from "../components/table-column-headers";
import { FormValidationAlert } from "./form-validation-alert";
import { reduceWorkspaceState } from "./workspace-state";

import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import {
  describePhaseTwoError,
  etagForVersion,
  PhaseTwoApiError,
  type PhaseTwoApi,
  type TenantLdapAuthProviderBindingView,
  type TenantLdapFilterTestResultView,
  type TenantLdapMappingDryRunResultView,
  type TenantLdapMappingView,
  type TenantLdapSyncRunView,
  type TenantLdapSyncStatusView,
  type TenantLdapUserSearchTestResultView,
  type VersionedView,
} from "../lib/phase-two-types";
import {
  bindingDraftFromView,
  createLdapBindingDraft,
  createLdapMappingDraft,
  mappingDraftFromView,
  toLdapBindingCreateInput,
  toLdapBindingUpdateInput,
  toLdapMappingCreateInput,
  toLdapMappingUpdateInput,
  validateLdapBindingDraft,
  validateLdapMappingDraft,
  validateLdapMutationReason,
  type LdapBindingDraft,
  type LdapMappingDraft,
} from "./ldap-administration-model";

const dateTimeFormatter = new Intl.DateTimeFormat(undefined, {
  dateStyle: "medium",
  timeStyle: "short",
});

type BindingState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | {
      binding: VersionedView<TenantLdapAuthProviderBindingView> | null;
      kind: "ready";
    };

interface LdapAdministrationWorkspaceProps {
  api: PhaseTwoApi;
  canMappingManage: boolean;
  canMappingRead: boolean;
  canProviderManage: boolean;
  canProviderTest: boolean;
  canSync: boolean;
  csrfToken: string;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  providerId: string;
  tenantId: string;
}

export function LdapAdministrationWorkspace(
  props: LdapAdministrationWorkspaceProps,
): React.JSX.Element {
  const model = useLdapAdministrationWorkspaceModel(props);
  return <LdapAdministrationWorkspaceView model={model.data} />;
}

function useLdapAdministrationWorkspaceModel({
  api,
  canMappingManage,
  canMappingRead,
  canProviderManage,
  canProviderTest,
  canSync,
  csrfToken,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  providerId,
  tenantId,
}: LdapAdministrationWorkspaceProps) {
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<LdapAdministrationWorkspaceState>,
    undefined,
    (): LdapAdministrationWorkspaceState => ({
      bindingState: {
        kind: "loading",
      },
      mappings: [],
      syncStatus: null,
      syncRuns: [],
      loadingRelated: false,
      relatedError: null,
      revision: 0,
    }),
  );
  const {
    bindingState,
    mappings,
    syncStatus,
    syncRuns,
    loadingRelated,
    relatedError,
    revision,
  } = workspaceState;
  const { setBindingState, setLoadingRelated, setRelatedError, setRevision } =
    useMemo(
      () => ({
        setBindingState: (
          value: React.SetStateAction<
            LdapAdministrationWorkspaceState["bindingState"]
          >,
        ) => updateWorkspaceState({ bindingState: value }),
        setLoadingRelated: (
          value: React.SetStateAction<
            LdapAdministrationWorkspaceState["loadingRelated"]
          >,
        ) => updateWorkspaceState({ loadingRelated: value }),
        setRelatedError: (
          value: React.SetStateAction<
            LdapAdministrationWorkspaceState["relatedError"]
          >,
        ) => updateWorkspaceState({ relatedError: value }),
        setRevision: (
          value: React.SetStateAction<
            LdapAdministrationWorkspaceState["revision"]
          >,
        ) => updateWorkspaceState({ revision: value }),
      }),
      [updateWorkspaceState],
    );

  const pairRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  }, [pairKey]);

  const handleError = useCallback(
    (caught: unknown, expectedPair: string): boolean => {
      if (
        pairRef.current !== expectedPair ||
        !(caught instanceof PhaseTwoApiError)
      ) {
        return false;
      }
      if (caught.status === 401) {
        onUnauthenticated();
        return true;
      }
      if (caught.status === 403) {
        onPermissionError();
      }
      return false;
    },
    [onPermissionError, onUnauthenticated],
  );

  useEffect(() => {
    const controller = new AbortController();
    const expectedPair = pairKey;
    updateWorkspaceState({
      bindingState: { kind: "loading" },
      mappings: [],
      syncStatus: null,
      syncRuns: [],
      relatedError: null,
    });
    void findProviderBinding(api, tenantId, providerId, controller.signal)
      .then((binding) => {
        if (controller.signal.aborted || pairRef.current !== expectedPair)
          return;
        setBindingState({ binding, kind: "ready" });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairRef.current !== expectedPair ||
          isAbortError(caught) ||
          handleError(caught, expectedPair)
        ) {
          return;
        }
        setBindingState({
          kind: "error",
          message: describePhaseTwoError(
            caught,
            "The tenant login binding could not be loaded.",
          ),
        });
      });
    return () => controller.abort();
  }, [
    setBindingState,
    api,
    handleError,
    pairKey,
    providerId,
    revision,
    tenantId,
  ]);

  const binding = bindingState.kind === "ready" ? bindingState.binding : null;
  useEffect(() => {
    if (!binding || !canMappingRead) return undefined;
    const controller = new AbortController();
    const expectedPair = pairKey;
    updateWorkspaceState({ loadingRelated: true, relatedError: null });
    void Promise.all([
      collectMappings(api, tenantId, binding.value.id, controller.signal),
      api.getTenantLdapSyncStatus(
        tenantId,
        binding.value.id,
        controller.signal,
      ),
      collectSyncRuns(api, tenantId, binding.value.id, controller.signal),
    ])
      .then(([nextMappings, status, runs]) => {
        if (controller.signal.aborted || pairRef.current !== expectedPair)
          return;
        updateWorkspaceState({
          mappings: nextMappings,
          syncStatus: status,
          syncRuns: runs,
        });
      })
      .catch((caught: unknown) => {
        if (
          controller.signal.aborted ||
          pairRef.current !== expectedPair ||
          isAbortError(caught) ||
          handleError(caught, expectedPair)
        ) {
          return;
        }
        setRelatedError(
          describePhaseTwoError(
            caught,
            "Mappings and synchronization provenance could not be loaded.",
          ),
        );
      })
      .finally(() => {
        if (pairRef.current === expectedPair) setLoadingRelated(false);
      });
    return () => controller.abort();
  }, [
    setRelatedError,
    setLoadingRelated,
    api,
    binding,
    canMappingRead,
    handleError,
    pairKey,
    tenantId,
  ]);

  function refresh(): void {
    setRevision((value) => value + 1);
  }

  return {
    kind: "ready" as const,
    data: {
      api,
      binding,
      bindingState,
      canMappingManage,
      canMappingRead,
      canProviderManage,
      canProviderTest,
      canSync,
      csrfToken,
      loadingRelated,
      mappings,
      onPermissionError,
      onUnauthenticated,
      pairKey,
      providerId,
      refresh,
      relatedError,
      syncRuns,
      syncStatus,
      tenantId,
    },
  };
}

function LdapAdministrationWorkspaceView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useLdapAdministrationWorkspaceModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const { binding, bindingState, mappings, providerId, refresh, syncStatus } =
    model;
  return (
    <section
      className="ldap-authority-workspace"
      aria-labelledby="ldap-authority-workspace-title"
    >
      <div className="ldap-provider-section-heading">
        <div>
          <p className="section-label">Authority provenance</p>
          <h3 id="ldap-authority-workspace-title">Login, mapping and sync</h3>
          <p>
            All matching rules contribute. Priority orders evaluation and never
            changes that all-match union.
          </p>
        </div>
        <Button type="button" size="sm" variant="outline" onClick={refresh}>
          <RefreshCw aria-hidden="true" /> Refresh authority
        </Button>
      </div>

      <ProvenanceRail
        binding={binding?.value ?? null}
        mappingCount={mappings.filter((mapping) => mapping.enabled).length}
        providerId={providerId}
        syncStatus={syncStatus?.value ?? null}
      />

      {bindingState.kind === "loading" ? (
        <p className="ldap-authority-muted" role="status">
          Loading tenant binding…
        </p>
      ) : null}
      {bindingState.kind === "error" ? (
        <FocusedError message={bindingState.message} />
      ) : null}
      {<LdapMissingBinding model={model} />}

      {<LdapBoundAdministration model={model} />}
    </section>
  );
}

function ProvenanceRail({
  binding,
  mappingCount,
  providerId,
  syncStatus,
}: {
  binding: TenantLdapAuthProviderBindingView | null;
  mappingCount: number;
  providerId: string;
  syncStatus: TenantLdapSyncStatusView | null;
}): React.JSX.Element {
  const nodes = [
    ["Provider", shortId(providerId)],
    ["Binding", binding ? binding.loginKey : "Not linked"],
    [
      "Access epoch",
      binding?.currentAccessEpochId
        ? shortId(binding.currentAccessEpochId)
        : "None",
    ],
    ["Mapping sources", `${mappingCount} live`],
    ["Sync", syncStatus?.scheduleState ?? "Unavailable"],
  ] as const;
  return (
    <ol className="ldap-provenance-rail" aria-label="LDAP authority provenance">
      {nodes.map(([label, value], index) => (
        <li key={label}>
          <span className="ldap-provenance-rail__index">{index + 1}</span>
          <span>
            <small>{label}</small>
            <strong>{value}</strong>
          </span>
        </li>
      ))}
    </ol>
  );
}

function BindingCard(props: {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  onChanged: () => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  tenantId: string;
  versioned: VersionedView<TenantLdapAuthProviderBindingView>;
}): React.JSX.Element {
  const model = useBindingCardModel(props);
  return <BindingCardView model={model.data} />;
}

function useBindingCardModel({
  api,
  canManage,
  csrfToken,
  onChanged,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  tenantId,
  versioned,
}: {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  onChanged: () => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  tenantId: string;
  versioned: VersionedView<TenantLdapAuthProviderBindingView>;
}) {
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<BindingCardState>,
    undefined,
    (): BindingCardState => ({
      editing: false,
      archiveReason: "",
      archiving: false,
      error: null,
    }),
  );
  const { editing, archiveReason, archiving, error } = workspaceState;
  const { setEditing, setArchiveReason, setArchiving, setError } = useMemo(
    () => ({
      setEditing: (value: React.SetStateAction<BindingCardState["editing"]>) =>
        updateWorkspaceState({ editing: value }),
      setArchiveReason: (
        value: React.SetStateAction<BindingCardState["archiveReason"]>,
      ) => updateWorkspaceState({ archiveReason: value }),
      setArchiving: (
        value: React.SetStateAction<BindingCardState["archiving"]>,
      ) => updateWorkspaceState({ archiving: value }),
      setError: (value: React.SetStateAction<BindingCardState["error"]>) =>
        updateWorkspaceState({ error: value }),
    }),
    [updateWorkspaceState],
  );

  const binding = versioned.value;

  async function archiveBinding(): Promise<void> {
    const validation = validateLdapMutationReason(archiveReason);
    if (validation || archiving) {
      setError(validation);
      return;
    }
    updateWorkspaceState({ archiving: true, error: null });
    try {
      await api.archiveTenantLdapAuthProviderBinding(
        csrfToken,
        tenantId,
        binding.id,
        versioned.etag,
        { reason: archiveReason },
      );
      onChanged();
    } catch (caught) {
      handleMutationSideEffects(caught, onUnauthenticated, onPermissionError);
      setError(mutationError(caught, "The binding was not archived."));
    } finally {
      setArchiving(false);
    }
  }

  return {
    kind: "ready" as const,
    data: {
      api,
      archiveBinding,
      archiveReason,
      archiving,
      binding,
      canManage,
      csrfToken,
      editing,
      error,
      onChanged,
      onPermissionError,
      onUnauthenticated,
      pairKey,
      setArchiveReason,
      setEditing,
      tenantId,
      versioned,
    },
  };
}

function BindingCardView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useBindingCardModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const { binding } = model;
  return (
    <Card className="ldap-authority-card">
      <CardHeader>
        <div className="ldap-authority-card__heading">
          <div>
            <CardTitle>Tenant login binding</CardTitle>
            <CardDescription>
              Authentication revision {binding.authRevision}; profile priority{" "}
              {binding.profilePriority}.
            </CardDescription>
          </div>
          <Badge variant={binding.enabled ? "default" : "secondary"}>
            {binding.archivedAt
              ? "Archived"
              : binding.enabled
                ? "Enabled"
                : "Disabled"}
          </Badge>
        </div>
      </CardHeader>
      <BindingCardCardContent model={model} />
    </Card>
  );
}

function BindingEditor({
  api,
  csrfToken,
  onChanged,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  providerId,
  tenantId,
  versioned,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  onChanged: () => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  providerId: string;
  tenantId: string;
  versioned?: VersionedView<TenantLdapAuthProviderBindingView>;
}): React.JSX.Element {
  const id = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<BindingEditorState>,
    undefined,
    (): BindingEditorState => ({
      draft: (() =>
        versioned
          ? bindingDraftFromView(versioned.value)
          : createLdapBindingDraft())(),
      errors: [],
      requestError: null,
      submitting: false,
    }),
  );
  const { draft, errors, requestError, submitting } = workspaceState;
  const { setDraft, setRequestError, setSubmitting } = useMemo(
    () => ({
      setDraft: (value: React.SetStateAction<BindingEditorState["draft"]>) =>
        updateWorkspaceState({ draft: value }),
      setRequestError: (
        value: React.SetStateAction<BindingEditorState["requestError"]>,
      ) => updateWorkspaceState({ requestError: value }),
      setSubmitting: (
        value: React.SetStateAction<BindingEditorState["submitting"]>,
      ) => updateWorkspaceState({ submitting: value }),
    }),
    [updateWorkspaceState],
  );

  const pairRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  }, [pairKey]);
  const idempotencyRef = useRef<{ fingerprint: string; key: string } | null>(
    null,
  );

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const validation = validateLdapBindingDraft(draft);
    updateWorkspaceState({ errors: validation, requestError: null });
    if (validation.length > 0 || submitting) return;
    const expectedPair = pairKey;
    setSubmitting(true);
    try {
      if (versioned) {
        await api.updateTenantLdapAuthProviderBinding(
          csrfToken,
          tenantId,
          versioned.value.id,
          versioned.etag,
          toLdapBindingUpdateInput(draft),
        );
      } else {
        const input = toLdapBindingCreateInput(providerId, draft);
        const idempotencyKey = idempotencyKeyForPayload(idempotencyRef, {
          input,
          tenantId,
        });
        await api.createTenantLdapAuthProviderBinding(
          csrfToken,
          tenantId,
          idempotencyKey,
          input,
        );
        idempotencyRef.current = null;
      }
      if (pairRef.current !== expectedPair) return;
      onChanged();
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      handleMutationSideEffects(caught, onUnauthenticated, onPermissionError);
      setRequestError(
        mutationError(
          caught,
          versioned
            ? "The binding was not updated."
            : "The binding was not created.",
        ),
      );
    } finally {
      // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
      if (pairRef.current === expectedPair) setSubmitting(false);
    }
  }

  return (
    <form
      className="ldap-authority-form"
      onSubmit={(event) => void submit(event)}
    >
      <div className="ldap-authority-form-grid">
        <FormField
          htmlFor={`${id}-login-key`}
          label="Login key"
          hint="Lowercase tenant-unique selector."
        >
          <Input
            id={`${id}-login-key`}
            value={draft.loginKey}
            maxLength={64}
            onChange={(event) =>
              setDraft({ ...draft, loginKey: event.currentTarget.value })
            }
          />
        </FormField>
        <FormField
          htmlFor={`${id}-profile-priority`}
          label="Profile priority"
          hint="Ordering only; it does not affect mapping authorization."
        >
          <Input
            id={`${id}-profile-priority`}
            inputMode="numeric"
            value={draft.profilePriority}
            onChange={(event) =>
              setDraft({ ...draft, profilePriority: event.currentTarget.value })
            }
          />
        </FormField>
      </div>
      <label className="ldap-authority-checkbox" htmlFor={`${id}-enabled`}>
        <Checkbox
          id={`${id}-enabled`}
          checked={draft.enabled}
          onCheckedChange={(checked) =>
            setDraft({ ...draft, enabled: checked === true })
          }
        />
        <span>
          Enable tenant login authority and open a new immutable access epoch
        </span>
      </label>
      <ValidationErrors errors={errors} />
      {requestError ? <FocusedError message={requestError} /> : null}
      <Button type="submit" size="sm" disabled={submitting}>
        {versioned ? <Save aria-hidden="true" /> : <Plus aria-hidden="true" />}
        {submitting ? "Saving…" : versioned ? "Save binding" : "Create binding"}
      </Button>
    </form>
  );
}

function MappingInventory({
  api,
  bindingId,
  canManage,
  csrfToken,
  loading,
  mappings,
  onChanged,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  bindingId: string;
  canManage: boolean;
  csrfToken: string;
  loading: boolean;
  mappings: readonly TenantLdapMappingView[];
  onChanged: () => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const [creating, setCreating] = useState(false);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selected = mappings.find((mapping) => mapping.id === selectedId);
  return (
    <Card className="ldap-authority-card">
      <CardHeader>
        <div className="ldap-authority-card__heading">
          <div>
            <CardTitle>All-match mapping rules</CardTitle>
            <CardDescription>
              Typed matchers contribute tenant group, role, and optional exact
              team-epoch targets.
            </CardDescription>
          </div>
          {canManage ? (
            <Button
              type="button"
              size="sm"
              onClick={() => setCreating((value) => !value)}
            >
              <Plus aria-hidden="true" />{" "}
              {creating ? "Close creator" : "Create mapping"}
            </Button>
          ) : null}
        </div>
      </CardHeader>
      <CardContent className="ldap-authority-stack">
        {creating ? (
          <MappingEditor
            api={api}
            bindingId={bindingId}
            csrfToken={csrfToken}
            onChanged={onChanged}
            onPermissionError={onPermissionError}
            onUnauthenticated={onUnauthenticated}
            pairKey={pairKey}
            tenantId={tenantId}
          />
        ) : null}
        {loading ? <p role="status">Loading mapping inventory…</p> : null}
        <div className="ldap-authority-table-wrap">
          <Table>
            <TableColumnHeaders
              columns={["Matcher", "Target", "Mode", "Status"]}
              actionLabel="Action"
              actionPresentation="visible"
            />
            <TableBody>
              {mappings.map((mapping) => (
                <TableRow key={mapping.id}>
                  <TableCell>
                    <strong>{matcherLabel(mapping)}</strong>
                    <small className="ldap-authority-table-detail">
                      {matcherValue(mapping)}
                    </small>
                  </TableCell>
                  <TableCell>
                    {mapping.target.roleIds.length} role
                    {mapping.target.roleIds.length === 1 ? "" : "s"}
                    <small className="ldap-authority-table-detail">
                      Group {shortId(mapping.target.tenantSecurityGroupId)}
                    </small>
                  </TableCell>
                  <TableCell>{mapping.reconciliationMode}</TableCell>
                  <TableCell>
                    <Badge variant={mapping.enabled ? "default" : "secondary"}>
                      {mapping.archivedAt
                        ? "Archived"
                        : mapping.enabled
                          ? "Enabled"
                          : "Disabled"}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      type="button"
                      size="sm"
                      variant="outline"
                      onClick={() => setSelectedId(mapping.id)}
                    >
                      Inspect
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {mappings.length === 0 && !loading ? (
          <p className="ldap-authority-muted">
            No mapping rules are configured.
          </p>
        ) : null}
        {selected ? (
          <MappingInspector
            api={api}
            canManage={canManage}
            csrfToken={csrfToken}
            mapping={selected}
            onChanged={onChanged}
            onClose={() => setSelectedId(null)}
            onPermissionError={onPermissionError}
            onUnauthenticated={onUnauthenticated}
            pairKey={pairKey}
            tenantId={tenantId}
          />
        ) : null}
      </CardContent>
    </Card>
  );
}

function MappingInspector({
  api,
  canManage,
  csrfToken,
  mapping,
  onChanged,
  onClose,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  mapping: TenantLdapMappingView;
  onChanged: () => void;
  onClose: () => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<MappingInspectorState>,
    undefined,
    (): MappingInspectorState => ({
      editing: false,
      reason: "",
      error: null,
      archiving: false,
    }),
  );
  const { editing, reason, error, archiving } = workspaceState;
  const { setEditing, setReason, setError, setArchiving } = useMemo(
    () => ({
      setEditing: (
        value: React.SetStateAction<MappingInspectorState["editing"]>,
      ) => updateWorkspaceState({ editing: value }),
      setReason: (
        value: React.SetStateAction<MappingInspectorState["reason"]>,
      ) => updateWorkspaceState({ reason: value }),
      setError: (value: React.SetStateAction<MappingInspectorState["error"]>) =>
        updateWorkspaceState({ error: value }),
      setArchiving: (
        value: React.SetStateAction<MappingInspectorState["archiving"]>,
      ) => updateWorkspaceState({ archiving: value }),
    }),
    [updateWorkspaceState],
  );

  async function archiveMapping(): Promise<void> {
    const validation = validateLdapMutationReason(reason);
    if (validation || archiving) {
      setError(validation);
      return;
    }
    updateWorkspaceState({ archiving: true, error: null });
    try {
      await api.archiveTenantLdapMapping(
        csrfToken,
        tenantId,
        mapping.id,
        etagForVersion(mapping.version),
        { reason },
      );
      onClose();
      onChanged();
    } catch (caught) {
      handleMutationSideEffects(caught, onUnauthenticated, onPermissionError);
      setError(mutationError(caught, "The mapping was not archived."));
    } finally {
      setArchiving(false);
    }
  }
  return (
    <div className="ldap-mapping-inspector">
      <div className="ldap-authority-card__heading">
        <div>
          <h4>Mapping {shortId(mapping.id)}</h4>
          <p>
            Priority {mapping.priority}; all matching rules still contribute.
          </p>
        </div>
        <Button type="button" size="sm" variant="ghost" onClick={onClose}>
          Close
        </Button>
      </div>
      <dl className="ldap-authority-facts">
        <div>
          <dt>Matcher</dt>
          <dd>
            {matcherLabel(mapping)} · {mapping.matcher.caseMode}
          </dd>
        </div>
        <div>
          <dt>Source epoch</dt>
          <dd>{mapping.currentSourceEpoch?.id ?? "None"}</dd>
        </div>
        <div>
          <dt>Security group</dt>
          <dd>{mapping.target.tenantSecurityGroupId}</dd>
        </div>
        <div>
          <dt>Exact team epoch</dt>
          <dd>
            {mapping.target.operatorTeamAssignment
              ? `${mapping.target.operatorTeamAssignment.operatorTeamId} / ${mapping.target.operatorTeamAssignment.assignmentEpochId}`
              : "None"}
          </dd>
        </div>
      </dl>
      {canManage && !mapping.archivedAt ? (
        <>
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setEditing((value) => !value)}
          >
            <Save aria-hidden="true" />{" "}
            {editing ? "Close editor" : "Edit mapping"}
          </Button>
          {editing ? (
            <MappingEditor
              api={api}
              bindingId={mapping.bindingId}
              csrfToken={csrfToken}
              mapping={mapping}
              onChanged={onChanged}
              onPermissionError={onPermissionError}
              onUnauthenticated={onUnauthenticated}
              pairKey={pairKey}
              tenantId={tenantId}
            />
          ) : null}
          <div className="ldap-authority-danger-zone">
            <FormField
              htmlFor={`archive-mapping-${mapping.id}`}
              label="Archive reason"
            >
              <Input
                id={`archive-mapping-${mapping.id}`}
                value={reason}
                maxLength={500}
                onChange={(event) => setReason(event.currentTarget.value)}
              />
            </FormField>
            <Button
              type="button"
              size="sm"
              variant="destructive"
              disabled={archiving}
              onClick={() => void archiveMapping()}
            >
              <Archive aria-hidden="true" />{" "}
              {archiving ? "Archiving…" : "Archive mapping"}
            </Button>
          </div>
        </>
      ) : null}
      {error ? <FocusedError message={error} /> : null}
    </div>
  );
}

function MappingEditor({
  api,
  bindingId,
  csrfToken,
  mapping,
  onChanged,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  bindingId: string;
  csrfToken: string;
  mapping?: TenantLdapMappingView;
  onChanged: () => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const id = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<MappingEditorState>,
    undefined,
    (): MappingEditorState => ({
      draft: (() =>
        mapping ? mappingDraftFromView(mapping) : createLdapMappingDraft())(),
      errors: [],
      requestError: null,
      submitting: false,
    }),
  );
  const { draft, errors, requestError, submitting } = workspaceState;
  const { setDraft, setRequestError, setSubmitting } = useMemo(
    () => ({
      setDraft: (value: React.SetStateAction<MappingEditorState["draft"]>) =>
        updateWorkspaceState({ draft: value }),
      setRequestError: (
        value: React.SetStateAction<MappingEditorState["requestError"]>,
      ) => updateWorkspaceState({ requestError: value }),
      setSubmitting: (
        value: React.SetStateAction<MappingEditorState["submitting"]>,
      ) => updateWorkspaceState({ submitting: value }),
    }),
    [updateWorkspaceState],
  );

  const pairRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  }, [pairKey]);
  const idempotencyRef = useRef<{ fingerprint: string; key: string } | null>(
    null,
  );

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const validation = validateLdapMappingDraft(draft);
    updateWorkspaceState({ errors: validation, requestError: null });
    if (validation.length > 0 || submitting) return;
    const expectedPair = pairKey;
    setSubmitting(true);
    try {
      if (mapping) {
        await api.updateTenantLdapMapping(
          csrfToken,
          tenantId,
          mapping.id,
          etagForVersion(mapping.version),
          toLdapMappingUpdateInput(draft),
        );
      } else {
        const input = toLdapMappingCreateInput(bindingId, draft);
        const idempotencyKey = idempotencyKeyForPayload(idempotencyRef, {
          input,
          tenantId,
        });
        await api.createTenantLdapMapping(
          csrfToken,
          tenantId,
          idempotencyKey,
          input,
        );
        idempotencyRef.current = null;
      }
      if (pairRef.current !== expectedPair) return;
      onChanged();
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      handleMutationSideEffects(caught, onUnauthenticated, onPermissionError);
      setRequestError(
        mutationError(
          caught,
          mapping
            ? "The mapping was not updated."
            : "The mapping was not created.",
        ),
      );
    } finally {
      // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
      if (pairRef.current === expectedPair) setSubmitting(false);
    }
  }

  return (
    <form
      className="ldap-authority-form ldap-mapping-form"
      onSubmit={(event) => void submit(event)}
    >
      <div className="ldap-authority-form-grid">
        <SelectField
          id={`${id}-matcher-type`}
          label="Typed matcher"
          value={draft.matcherType}
          options={[
            ["exact_dn", "Exact parsed DN"],
            ["exact_cn", "Exact CN"],
            ["regex", "Bounded RE2"],
          ]}
          onChange={(matcherType) => setDraft({ ...draft, matcherType })}
        />
        <SelectField
          id={`${id}-case-mode`}
          label="Case mode"
          value={draft.caseMode}
          options={[
            ["sensitive", "Sensitive"],
            ["insensitive", "Insensitive"],
          ]}
          onChange={(caseMode) => setDraft({ ...draft, caseMode })}
        />
        <FormField
          htmlFor={`${id}-priority`}
          label="Priority"
          hint="Display and evaluation order only."
        >
          <Input
            id={`${id}-priority`}
            inputMode="numeric"
            value={draft.priority}
            onChange={(event) =>
              setDraft({ ...draft, priority: event.currentTarget.value })
            }
          />
        </FormField>
        <SelectField
          id={`${id}-mode`}
          label="Reconciliation"
          value={draft.reconciliationMode}
          options={[
            ["additive", "Additive"],
            ["authoritative", "Authoritative"],
          ]}
          onChange={(reconciliationMode) =>
            setDraft({ ...draft, reconciliationMode })
          }
        />
      </div>
      <FormField
        htmlFor={`${id}-matcher`}
        label={
          draft.matcherType === "exact_dn"
            ? "Canonical group DN"
            : draft.matcherType === "exact_cn"
              ? "Group CN"
              : "RE2 pattern"
        }
        hint="The server parses/compiles this typed value before storing it."
      >
        <Input
          id={`${id}-matcher`}
          className="ldap-provider-code-input"
          value={draft.matcherValue}
          onChange={(event) =>
            setDraft({ ...draft, matcherValue: event.currentTarget.value })
          }
        />
      </FormField>
      <div className="ldap-authority-form-grid">
        <FormField htmlFor={`${id}-group-id`} label="Tenant security-group ID">
          <Input
            id={`${id}-group-id`}
            value={draft.tenantSecurityGroupId}
            onChange={(event) =>
              setDraft({
                ...draft,
                tenantSecurityGroupId: event.currentTarget.value,
              })
            }
          />
        </FormField>
        <FormField
          htmlFor={`${id}-roles`}
          label="Tenant role IDs"
          hint="1–32 IDs separated by spaces, commas, or lines."
        >
          <Textarea
            id={`${id}-roles`}
            value={draft.roleIds}
            onChange={(event) =>
              setDraft({ ...draft, roleIds: event.currentTarget.value })
            }
          />
        </FormField>
        <FormField htmlFor={`${id}-team-id`} label="Operator team ID" optional>
          <Input
            id={`${id}-team-id`}
            value={draft.operatorTeamId}
            onChange={(event) =>
              setDraft({ ...draft, operatorTeamId: event.currentTarget.value })
            }
          />
        </FormField>
        <FormField
          htmlFor={`${id}-epoch-id`}
          label="Exact live assignment epoch"
          optional
        >
          <Input
            id={`${id}-epoch-id`}
            value={draft.assignmentEpochId}
            onChange={(event) =>
              setDraft({
                ...draft,
                assignmentEpochId: event.currentTarget.value,
              })
            }
          />
        </FormField>
      </div>
      <FormField htmlFor={`${id}-notes`} label="Notes" optional>
        <Textarea
          id={`${id}-notes`}
          maxLength={2000}
          value={draft.notes}
          onChange={(event) =>
            setDraft({ ...draft, notes: event.currentTarget.value })
          }
        />
      </FormField>
      <FormField htmlFor={`${id}-reason`} label="Change reason">
        <Input
          id={`${id}-reason`}
          maxLength={500}
          value={draft.reason}
          onChange={(event) =>
            setDraft({ ...draft, reason: event.currentTarget.value })
          }
        />
      </FormField>
      {mapping ? (
        <label className="ldap-authority-checkbox" htmlFor={`${id}-enabled`}>
          <Checkbox
            id={`${id}-enabled`}
            checked={draft.enabled}
            onCheckedChange={(checked) =>
              setDraft({ ...draft, enabled: checked === true })
            }
          />
          <span>Enable mapping and open/rotate its immutable source epoch</span>
        </label>
      ) : (
        <p className="ldap-authority-muted">
          New mappings are created disabled; enable them through an
          ETag-protected edit.
        </p>
      )}
      <ValidationErrors errors={errors} />
      {requestError ? <FocusedError message={requestError} /> : null}
      <Button type="submit" size="sm" disabled={submitting}>
        <Save aria-hidden="true" />{" "}
        {submitting
          ? "Saving…"
          : mapping
            ? "Save mapping"
            : "Create disabled mapping"}
      </Button>
    </form>
  );
}

function DryRunPanel({
  api,
  bindingId,
  csrfToken,
  mappings,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  tenantId,
}: {
  api: PhaseTwoApi;
  bindingId: string;
  csrfToken: string;
  mappings: readonly TenantLdapMappingView[];
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  tenantId: string;
}): React.JSX.Element {
  const id = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<DryRunPanelState>,
    undefined,
    (): DryRunPanelState => ({
      username: "",
      included: [],
      result: null,
      error: null,
      running: false,
    }),
  );
  const { username, included, result, error, running } = workspaceState;
  const { setUsername, setIncluded, setError, setRunning } = useMemo(
    () => ({
      setUsername: (
        value: React.SetStateAction<DryRunPanelState["username"]>,
      ) => updateWorkspaceState({ username: value }),
      setIncluded: (
        value: React.SetStateAction<DryRunPanelState["included"]>,
      ) => updateWorkspaceState({ included: value }),
      setError: (value: React.SetStateAction<DryRunPanelState["error"]>) =>
        updateWorkspaceState({ error: value }),
      setRunning: (value: React.SetStateAction<DryRunPanelState["running"]>) =>
        updateWorkspaceState({ running: value }),
    }),
    [updateWorkspaceState],
  );

  const pairRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  }, [pairKey]);
  async function run(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (username.trim() === "" || running) return;
    const expectedPair = pairKey;
    updateWorkspaceState({ running: true, error: null, result: null });
    try {
      const next = await api.dryRunTenantLdapMappings(csrfToken, tenantId, {
        bindingId,
        includeDisabledMappingIds: [...included],
        username,
      });
      if (pairRef.current !== expectedPair) return;
      updateWorkspaceState({ username: "", result: next });
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      handleMutationSideEffects(caught, onUnauthenticated, onPermissionError);
      setError(
        mutationError(caught, "The redacted mapping dry-run did not complete."),
      );
    } finally {
      if (pairRef.current === expectedPair) setRunning(false);
    }
  }
  const disabledMappings = mappings.filter(
    (mapping) => !mapping.enabled && !mapping.archivedAt,
  );
  const includedIds = new Set(included);
  return (
    <Card className="ldap-authority-card ldap-dry-run-card">
      <CardHeader>
        <CardTitle>Redacted mapping dry-run</CardTitle>
        <CardDescription>
          Non-mutating evaluation. The response contains stable decisions, IDs
          and counts—never LDAP DNs or attribute values.
        </CardDescription>
      </CardHeader>
      <CardContent className="ldap-authority-stack">
        <form
          className="ldap-authority-form"
          onSubmit={(event) => void run(event)}
        >
          <FormField htmlFor={`${id}-username`} label="Candidate username">
            <Input
              id={`${id}-username`}
              autoComplete="off"
              value={username}
              onChange={(event) => setUsername(event.currentTarget.value)}
            />
          </FormField>
          {disabledMappings.length > 0 ? (
            <fieldset className="ldap-authority-disabled-mappings">
              <legend>Evaluate disabled mappings explicitly</legend>
              {disabledMappings.map((mapping) => (
                <label key={mapping.id} className="ldap-authority-checkbox">
                  <Checkbox
                    checked={includedIds.has(mapping.id)}
                    onCheckedChange={(checked) =>
                      setIncluded(
                        checked === true
                          ? [...included, mapping.id]
                          : included.filter(
                              (idValue) => idValue !== mapping.id,
                            ),
                      )
                    }
                  />
                  <span>
                    {matcherLabel(mapping)} · {shortId(mapping.id)}
                  </span>
                </label>
              ))}
            </fieldset>
          ) : null}
          <Button
            type="submit"
            size="sm"
            disabled={running || username.trim() === ""}
          >
            <FlaskConical aria-hidden="true" />{" "}
            {running ? "Evaluating…" : "Run redacted dry-run"}
          </Button>
        </form>
        {error ? <FocusedError message={error} /> : null}
        {result ? <DryRunResult result={result} /> : null}
      </CardContent>
    </Card>
  );
}

function DryRunResult({
  result,
}: {
  result: TenantLdapMappingDryRunResultView;
}): React.JSX.Element {
  const actionCount =
    result.plan.groupActions.length +
    result.plan.roleActions.length +
    result.plan.operatorTeamActions.length;
  return (
    <Alert className="ldap-redacted-result">
      {result.decision === "allow" ? (
        <CheckCircle2 aria-hidden="true" />
      ) : (
        <ShieldAlert aria-hidden="true" />
      )}
      <AlertTitle>
        {result.decision === "allow"
          ? "Access plan allowed"
          : "Access plan denied"}
      </AlertTitle>
      <AlertDescription>
        <dl className="ldap-authority-facts">
          <div>
            <dt>Outcome</dt>
            <dd>{result.outcome}</dd>
          </div>
          <div>
            <dt>Identity</dt>
            <dd>{result.identityDisposition}</dd>
          </div>
          <div>
            <dt>Observation</dt>
            <dd>
              {result.observationComplete
                ? "Complete"
                : "Incomplete — absence revokes suppressed"}
            </dd>
          </div>
          <div>
            <dt>Planned consequences</dt>
            <dd>{actionCount}</dd>
          </div>
          <div>
            <dt>Matched mapping IDs</dt>
            <dd>{result.matchedMappingIds.length}</dd>
          </div>
          <div>
            <dt>Denial categories</dt>
            <dd>
              {result.denialReasons.length > 0
                ? result.denialReasons.join(", ")
                : "None"}
            </dd>
          </div>
        </dl>
      </AlertDescription>
    </Alert>
  );
}

function DirectoryTests({
  api,
  csrfToken,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  providerId,
  tenantId,
}: {
  api: PhaseTwoApi;
  csrfToken: string;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  providerId: string;
  tenantId: string;
}): React.JSX.Element {
  const id = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<DirectoryTestsState>,
    undefined,
    (): DirectoryTestsState => ({
      username: "",
      filterTemplate: "",
      kind: "user",
      result: null,
      error: null,
      running: null,
    }),
  );
  const { username, filterTemplate, kind, result, error, running } =
    workspaceState;
  const { setUsername, setFilterTemplate, setKind, setError, setRunning } =
    useMemo(
      () => ({
        setUsername: (
          value: React.SetStateAction<DirectoryTestsState["username"]>,
        ) => updateWorkspaceState({ username: value }),
        setFilterTemplate: (
          value: React.SetStateAction<DirectoryTestsState["filterTemplate"]>,
        ) => updateWorkspaceState({ filterTemplate: value }),
        setKind: (value: React.SetStateAction<DirectoryTestsState["kind"]>) =>
          updateWorkspaceState({ kind: value }),
        setError: (value: React.SetStateAction<DirectoryTestsState["error"]>) =>
          updateWorkspaceState({ error: value }),
        setRunning: (
          value: React.SetStateAction<DirectoryTestsState["running"]>,
        ) => updateWorkspaceState({ running: value }),
      }),
      [updateWorkspaceState],
    );

  const pairRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  }, [pairKey]);
  async function run(test: "filter" | "search"): Promise<void> {
    if (running || username.trim() === "") return;
    const expectedPair = pairKey;
    updateWorkspaceState({ running: test, result: null, error: null });
    try {
      const next =
        test === "search"
          ? await api.searchTenantLdapAuthProviderUser(
              csrfToken,
              tenantId,
              providerId,
              { username },
            )
          : await api.testTenantLdapAuthProviderFilter(
              csrfToken,
              tenantId,
              providerId,
              {
                filterTemplate,
                gidNumber: null,
                kind,
                maxResults: 10,
                userDn: null,
                username,
              },
            );
      if (pairRef.current !== expectedPair) return;
      updateWorkspaceState({ username: "", filterTemplate: "", result: next });
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      handleMutationSideEffects(caught, onUnauthenticated, onPermissionError);
      setError(
        mutationError(caught, "The bounded directory test did not complete."),
      );
    } finally {
      if (pairRef.current === expectedPair) setRunning(null);
    }
  }
  return (
    <Card className="ldap-authority-card">
      <CardHeader>
        <CardTitle>Bounded directory tests</CardTitle>
        <CardDescription>
          Results expose presence, counts and allowlisted attribute names only.
        </CardDescription>
      </CardHeader>
      <CardContent className="ldap-authority-stack">
        <FormField
          htmlFor={`${id}-directory-username`}
          label="Candidate username"
        >
          <Input
            id={`${id}-directory-username`}
            autoComplete="off"
            value={username}
            onChange={(event) => setUsername(event.currentTarget.value)}
          />
        </FormField>
        <div className="ldap-authority-actions">
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={running !== null || username.trim() === ""}
            onClick={() => void run("search")}
          >
            <KeyRound aria-hidden="true" />{" "}
            {running === "search" ? "Searching…" : "Test configured search"}
          </Button>
        </div>
        <div className="ldap-authority-form-grid">
          <SelectField
            id={`${id}-filter-kind`}
            label="Filter kind"
            value={kind}
            options={[
              ["user", "User"],
              ["group", "Group"],
            ]}
            onChange={setKind}
          />
          <FormField
            htmlFor={`${id}-filter-template`}
            label="Typed filter template"
          >
            <Input
              id={`${id}-filter-template`}
              className="ldap-provider-code-input"
              value={filterTemplate}
              onChange={(event) => setFilterTemplate(event.currentTarget.value)}
            />
          </FormField>
        </div>
        <Button
          type="button"
          size="sm"
          variant="outline"
          disabled={
            running !== null ||
            username.trim() === "" ||
            filterTemplate.trim() === ""
          }
          onClick={() => void run("filter")}
        >
          <FlaskConical aria-hidden="true" />{" "}
          {running === "filter" ? "Testing…" : "Test filter"}
        </Button>
        {error ? <FocusedError message={error} /> : null}
        {result ? <DirectoryTestResult result={result} /> : null}
      </CardContent>
    </Card>
  );
}

function DirectoryTestResult({
  result,
}: {
  result: TenantLdapFilterTestResultView | TenantLdapUserSearchTestResultView;
}): React.JSX.Element {
  const attributeCount = result.entries.reduce(
    (count, entry) => count + entry.attributes.length,
    0,
  );
  return (
    <Alert className="ldap-redacted-result">
      <Activity aria-hidden="true" />
      <AlertTitle>Redacted test complete</AlertTitle>
      <AlertDescription>
        {result.matchedEntryCount} matched entr
        {result.matchedEntryCount === 1 ? "y" : "ies"}; {attributeCount}{" "}
        attribute-name projection{attributeCount === 1 ? "" : "s"};{" "}
        {result.truncated ? "truncated" : "not truncated"}. Values, DNs and
        immutable subjects remain redacted.
      </AlertDescription>
    </Alert>
  );
}

function SyncPanel({
  api,
  bindingId,
  canSync,
  csrfToken,
  onChanged,
  onPermissionError,
  onUnauthenticated,
  pairKey,
  runs,
  status,
  tenantId,
}: {
  api: PhaseTwoApi;
  bindingId: string;
  canSync: boolean;
  csrfToken: string;
  onChanged: () => void;
  onPermissionError: () => void;
  onUnauthenticated: () => void;
  pairKey: string;
  runs: readonly TenantLdapSyncRunView[];
  status: VersionedView<TenantLdapSyncStatusView> | null;
  tenantId: string;
}): React.JSX.Element {
  const id = useId();
  const [workspaceState, updateWorkspaceState] = useReducer(
    reduceWorkspaceState<SyncPanelState>,
    undefined,
    (): SyncPanelState => ({ reason: "", error: null, running: false }),
  );
  const { reason, error, running } = workspaceState;
  const { setReason, setError, setRunning } = useMemo(
    () => ({
      setReason: (value: React.SetStateAction<SyncPanelState["reason"]>) =>
        updateWorkspaceState({ reason: value }),
      setError: (value: React.SetStateAction<SyncPanelState["error"]>) =>
        updateWorkspaceState({ error: value }),
      setRunning: (value: React.SetStateAction<SyncPanelState["running"]>) =>
        updateWorkspaceState({ running: value }),
    }),
    [updateWorkspaceState],
  );

  const pairRef = useRef(pairKey);
  useLayoutEffect(() => {
    pairRef.current = pairKey;
  }, [pairKey]);
  const idempotencyRef = useRef<{ fingerprint: string; key: string } | null>(
    null,
  );
  async function startSync(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const validation = validateLdapMutationReason(reason);
    if (!status || validation || running) {
      setError(
        validation ?? "Sync status must be refreshed before starting a run.",
      );
      return;
    }
    const expectedPair = pairKey;
    const input = { reason };
    const idempotencyKey = idempotencyKeyForPayload(idempotencyRef, {
      bindingId,
      input,
      tenantId,
    });
    updateWorkspaceState({ running: true, error: null });
    try {
      await api.startTenantLdapManualSync(
        csrfToken,
        tenantId,
        bindingId,
        status.etag,
        idempotencyKey,
        input,
      );
      if (pairRef.current !== expectedPair) return;
      idempotencyRef.current = null;
      setReason("");
      onChanged();
    } catch (caught) {
      if (pairRef.current !== expectedPair) return;
      handleMutationSideEffects(caught, onUnauthenticated, onPermissionError);
      setError(mutationError(caught, "The manual sync was not started."));
    } finally {
      if (pairRef.current === expectedPair) setRunning(false);
    }
  }
  return (
    <Card className="ldap-authority-card">
      <CardHeader>
        <CardTitle>Synchronization provenance</CardTitle>
        <CardDescription>
          Incomplete or truncated enumeration never authorizes absence-based
          revocation.
        </CardDescription>
      </CardHeader>
      <CardContent className="ldap-authority-stack">
        {status ? (
          <dl className="ldap-authority-facts">
            <div>
              <dt>Schedule</dt>
              <dd>{status.value.scheduleState}</dd>
            </div>
            <div>
              <dt>Active run</dt>
              <dd>{status.value.activeRunId ?? "None"}</dd>
            </div>
            <div>
              <dt>Last run</dt>
              <dd>{status.value.lastRunState ?? "None"}</dd>
            </div>
            <div>
              <dt>Next scheduled</dt>
              <dd>
                {status.value.nextScheduledAt
                  ? formatTimestamp(status.value.nextScheduledAt)
                  : "None"}
              </dd>
            </div>
          </dl>
        ) : (
          <p className="ldap-authority-muted">Sync status unavailable.</p>
        )}
        {canSync ? (
          <form
            className="ldap-authority-form"
            onSubmit={(event) => void startSync(event)}
          >
            <FormField htmlFor={`${id}-sync-reason`} label="Manual sync reason">
              <Input
                id={`${id}-sync-reason`}
                maxLength={500}
                value={reason}
                onChange={(event) => setReason(event.currentTarget.value)}
              />
            </FormField>
            <Button type="submit" size="sm" disabled={running || !status}>
              <RefreshCw aria-hidden="true" />{" "}
              {running ? "Queueing…" : "Start manual sync"}
            </Button>
          </form>
        ) : (
          <PermissionNote>
            `identity_sync.run` is required to start a manual run.
          </PermissionNote>
        )}
        {error ? <FocusedError message={error} /> : null}
        <div className="ldap-authority-table-wrap">
          <Table>
            <TableColumnHeaders
              columns={[
                "Run",
                "State",
                "Enumeration",
                "Observed",
                "Absence revokes",
              ]}
            />
            <TableBody>
              {runs.map((run) => (
                <TableRow key={run.id}>
                  <TableCell>
                    <code>{shortId(run.id)}</code>
                  </TableCell>
                  <TableCell>{run.state}</TableCell>
                  <TableCell>
                    <SyncEnumerationBadge run={run} />
                  </TableCell>
                  <TableCell>{run.counters.observed}</TableCell>
                  <TableCell>
                    {run.enumeration.absenceBasedRevocationAllowed
                      ? "Allowed"
                      : "Suppressed"}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
        {runs.length === 0 ? (
          <p className="ldap-authority-muted">
            No sync runs have been recorded.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function SyncEnumerationBadge({
  run,
}: {
  run: TenantLdapSyncRunView;
}): React.JSX.Element {
  const unsafe =
    run.enumeration.state === "incomplete" ||
    run.enumeration.state === "truncated";
  return (
    <Badge
      variant={
        unsafe
          ? "destructive"
          : run.enumeration.complete
            ? "default"
            : "secondary"
      }
    >
      {run.enumeration.state}
    </Badge>
  );
}

function PermissionNote({
  children,
}: {
  children: React.ReactNode;
}): React.JSX.Element {
  return (
    <Alert>
      <ShieldAlert aria-hidden="true" />
      <AlertTitle>Control unavailable</AlertTitle>
      <AlertDescription>{children}</AlertDescription>
    </Alert>
  );
}

function ValidationErrors({
  errors,
}: {
  errors: readonly string[];
}): React.JSX.Element | null {
  if (errors.length === 0) return null;
  return <FormValidationAlert errors={errors} title="Review the form" />;
}

function SelectField<T extends string>({
  id,
  label,
  onChange,
  options,
  value,
}: {
  id: string;
  label: string;
  onChange: (value: T) => void;
  options: readonly (readonly [T, string])[];
  value: T;
}): React.JSX.Element {
  return (
    <FormField htmlFor={id} label={label}>
      <select
        className="ldap-authority-select"
        id={id}
        value={value}
        onChange={(event) => {
          const selected = options.find(
            ([optionValue]) => optionValue === event.currentTarget.value,
          )?.[0];
          if (selected !== undefined) onChange(selected);
        }}
      >
        {options.map(([optionValue, optionLabel]) => (
          <option key={optionValue} value={optionValue}>
            {optionLabel}
          </option>
        ))}
      </select>
    </FormField>
  );
}

async function findProviderBinding(
  api: PhaseTwoApi,
  tenantId: string,
  providerId: string,
  signal: AbortSignal,
): Promise<VersionedView<TenantLdapAuthProviderBindingView> | null> {
  let after: string | undefined;
  const seen = new Set<string>();
  for (let pageCount = 0; pageCount < 100; pageCount += 1) {
    // Cursor pages are dependent and cannot be requested in parallel.
    // eslint-disable-next-line no-await-in-loop
    const page = await api.listTenantLdapAuthProviderBindings(tenantId, {
      ...(after ? { after } : {}),
      includeArchived: true,
      signal,
    });
    const match = page.items.find((item) => item.providerId === providerId);
    if (match)
      return api.getTenantLdapAuthProviderBinding(tenantId, match.id, signal);
    if (!page.nextCursor) return null;
    if (page.nextCursor === after || seen.has(page.nextCursor))
      throw new Error("The LDAP binding cursor did not advance.");
    seen.add(page.nextCursor);
    after = page.nextCursor;
  }
  throw new Error(
    "The LDAP binding inventory exceeded the bounded page limit.",
  );
}

async function collectMappings(
  api: PhaseTwoApi,
  tenantId: string,
  bindingId: string,
  signal: AbortSignal,
): Promise<readonly TenantLdapMappingView[]> {
  const items: TenantLdapMappingView[] = [];
  let after: string | undefined;
  const seen = new Set<string>();
  for (let pageCount = 0; pageCount < 100; pageCount += 1) {
    // Cursor pages are dependent and cannot be requested in parallel.
    // eslint-disable-next-line no-await-in-loop
    const page = await api.listTenantLdapMappings(tenantId, {
      ...(after ? { after } : {}),
      bindingId,
      includeArchived: true,
      signal,
    });
    items.push(...page.items);
    if (!page.nextCursor)
      return items.toSorted(
        (left, right) =>
          left.priority - right.priority || left.id.localeCompare(right.id),
      );
    if (page.nextCursor === after || seen.has(page.nextCursor))
      throw new Error("The LDAP mapping cursor did not advance.");
    seen.add(page.nextCursor);
    after = page.nextCursor;
  }
  throw new Error(
    "The LDAP mapping inventory exceeded the bounded page limit.",
  );
}

async function collectSyncRuns(
  api: PhaseTwoApi,
  tenantId: string,
  bindingId: string,
  signal: AbortSignal,
): Promise<readonly TenantLdapSyncRunView[]> {
  const items: TenantLdapSyncRunView[] = [];
  let after: string | undefined;
  const seen = new Set<string>();
  for (let pageCount = 0; pageCount < 20; pageCount += 1) {
    // Cursor pages are dependent and cannot be requested in parallel.
    // eslint-disable-next-line no-await-in-loop
    const page = await api.listTenantLdapSyncRuns(tenantId, bindingId, {
      ...(after ? { after } : {}),
      signal,
    });
    items.push(...page.items);
    if (!page.nextCursor) return items;
    if (page.nextCursor === after || seen.has(page.nextCursor))
      throw new Error("The LDAP sync-run cursor did not advance.");
    seen.add(page.nextCursor);
    after = page.nextCursor;
  }
  throw new Error("The LDAP sync history exceeded the bounded page limit.");
}

function mutationError(caught: unknown, fallback: string): string {
  if (caught instanceof PhaseTwoApiError) {
    if (caught.status === 412)
      return "This projection is stale. Refresh authority before retrying the change.";
    if (caught.status === 428)
      return "The server requires a fresh strong ETag. Refresh authority before retrying.";
    if (caught.status === 409)
      return "The requested transition conflicts with current LDAP authority or idempotency state.";
    if (caught.status === 403)
      return "The server denied this action after rechecking tenant authority.";
  }
  return describePhaseTwoError(caught, fallback);
}

function handleMutationSideEffects(
  caught: unknown,
  onUnauthenticated: () => void,
  onPermissionError: () => void,
): void {
  if (!(caught instanceof PhaseTwoApiError)) return;
  if (caught.status === 401) onUnauthenticated();
  if (caught.status === 403) onPermissionError();
}

function matcherLabel(mapping: TenantLdapMappingView): string {
  if (mapping.matcher.type === "exact_dn") return "Exact parsed DN";
  if (mapping.matcher.type === "exact_cn") return "Exact CN";
  return "Bounded RE2";
}

function matcherValue(mapping: TenantLdapMappingView): string {
  if (mapping.matcher.type === "exact_dn") return mapping.matcher.dn;
  if (mapping.matcher.type === "exact_cn") return mapping.matcher.cn;
  return mapping.matcher.pattern;
}

function shortId(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function formatTimestamp(value: string): string {
  return dateTimeFormatter.format(new Date(value));
}

function isAbortError(caught: unknown): boolean {
  return caught instanceof DOMException && caught.name === "AbortError";
}

interface LdapAdministrationWorkspaceState {
  bindingState: BindingState;
  mappings: readonly TenantLdapMappingView[];
  syncStatus: VersionedView<TenantLdapSyncStatusView> | null;
  syncRuns: readonly TenantLdapSyncRunView[];
  loadingRelated: boolean;
  relatedError: string | null;
  revision: number;
}

interface BindingCardState {
  editing: boolean;
  archiveReason: string;
  archiving: boolean;
  error: string | null;
}

interface BindingEditorState {
  draft: LdapBindingDraft;
  errors: readonly string[];
  requestError: string | null;
  submitting: boolean;
}

interface MappingInspectorState {
  editing: boolean;
  reason: string;
  error: string | null;
  archiving: boolean;
}

interface MappingEditorState {
  draft: LdapMappingDraft;
  errors: readonly string[];
  requestError: string | null;
  submitting: boolean;
}

interface DryRunPanelState {
  username: string;
  included: readonly string[];
  result: TenantLdapMappingDryRunResultView | null;
  error: string | null;
  running: boolean;
}

interface DirectoryTestsState {
  username: string;
  filterTemplate: string;
  kind: "group" | "user";
  result:
    TenantLdapFilterTestResultView | TenantLdapUserSearchTestResultView | null;
  error: string | null;
  running: "filter" | "search" | null;
}

interface SyncPanelState {
  reason: string;
  error: string | null;
  running: boolean;
}

function LdapMissingBinding({
  model,
}: {
  model: React.ComponentProps<typeof LdapAdministrationWorkspaceView>["model"];
}): React.ReactNode {
  const {
    api,
    binding,
    bindingState,
    canProviderManage,
    csrfToken,
    onPermissionError,
    onUnauthenticated,
    pairKey,
    providerId,
    refresh,
    tenantId,
  } = model;
  return bindingState.kind === "ready" && !binding ? (
    <Card className="ldap-authority-card">
      <CardHeader>
        <CardTitle>No tenant login binding</CardTitle>
        <CardDescription>
          Create the tenant-owned login selector before authoring mapping
          consequences.
        </CardDescription>
      </CardHeader>
      <CardContent>
        {canProviderManage ? (
          <BindingEditor
            api={api}
            csrfToken={csrfToken}
            onChanged={refresh}
            onPermissionError={onPermissionError}
            onUnauthenticated={onUnauthenticated}
            pairKey={pairKey}
            providerId={providerId}
            tenantId={tenantId}
          />
        ) : (
          <PermissionNote>
            `identity_provider.manage` is required to create the binding.
          </PermissionNote>
        )}
      </CardContent>
    </Card>
  ) : null;
}

function LdapBoundAdministration({
  model,
}: {
  model: React.ComponentProps<typeof LdapAdministrationWorkspaceView>["model"];
}): React.ReactNode {
  const {
    api,
    binding,
    canMappingManage,
    canMappingRead,
    canProviderManage,
    canProviderTest,
    canSync,
    csrfToken,
    loadingRelated,
    mappings,
    onPermissionError,
    onUnauthenticated,
    pairKey,
    providerId,
    refresh,
    relatedError,
    syncRuns,
    syncStatus,
    tenantId,
  } = model;
  return binding ? (
    <>
      <BindingCard
        api={api}
        canManage={canProviderManage}
        csrfToken={csrfToken}
        onChanged={refresh}
        onPermissionError={onPermissionError}
        onUnauthenticated={onUnauthenticated}
        pairKey={pairKey}
        tenantId={tenantId}
        versioned={binding}
      />

      {canProviderTest ? (
        <DirectoryTests
          api={api}
          csrfToken={csrfToken}
          onPermissionError={onPermissionError}
          onUnauthenticated={onUnauthenticated}
          pairKey={pairKey}
          providerId={providerId}
          tenantId={tenantId}
        />
      ) : null}

      {!canMappingRead ? (
        <PermissionNote>
          `identity_mapping.read` is required to inspect mappings and sync
          provenance.
        </PermissionNote>
      ) : null}
      {canMappingRead ? (
        <>
          {relatedError ? <FocusedError message={relatedError} /> : null}
          <MappingInventory
            api={api}
            bindingId={binding.value.id}
            canManage={canMappingManage}
            csrfToken={csrfToken}
            loading={loadingRelated}
            mappings={mappings}
            onChanged={refresh}
            onPermissionError={onPermissionError}
            onUnauthenticated={onUnauthenticated}
            pairKey={pairKey}
            tenantId={tenantId}
          />
          <DryRunPanel
            api={api}
            bindingId={binding.value.id}
            csrfToken={csrfToken}
            mappings={mappings}
            onPermissionError={onPermissionError}
            onUnauthenticated={onUnauthenticated}
            pairKey={pairKey}
            tenantId={tenantId}
          />
          <SyncPanel
            api={api}
            bindingId={binding.value.id}
            canSync={canSync}
            csrfToken={csrfToken}
            onChanged={refresh}
            onPermissionError={onPermissionError}
            onUnauthenticated={onUnauthenticated}
            pairKey={pairKey}
            runs={syncRuns}
            status={syncStatus}
            tenantId={tenantId}
          />
        </>
      ) : null}
    </>
  ) : null;
}

function BindingCardCardContent({
  model,
}: {
  model: React.ComponentProps<typeof BindingCardView>["model"];
}): React.ReactNode {
  const {
    api,
    archiveBinding,
    archiveReason,
    archiving,
    binding,
    canManage,
    csrfToken,
    editing,
    error,
    onChanged,
    onPermissionError,
    onUnauthenticated,
    pairKey,
    setArchiveReason,
    setEditing,
    tenantId,
    versioned,
  } = model;
  return (
    <CardContent className="ldap-authority-stack">
      <dl className="ldap-authority-facts">
        <div>
          <dt>Login key</dt>
          <dd>
            <code>{binding.loginKey}</code>
          </dd>
        </div>
        <div>
          <dt>Version</dt>
          <dd>v{binding.version}</dd>
        </div>
        <div>
          <dt>Access epoch</dt>
          <dd>{binding.currentAccessEpochId ?? "None"}</dd>
        </div>
        <div>
          <dt>Archived at</dt>
          <dd>
            {binding.archivedAt ? formatTimestamp(binding.archivedAt) : "None"}
          </dd>
        </div>
      </dl>
      {canManage && !binding.archivedAt ? (
        <div className="ldap-authority-actions">
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={() => setEditing((value) => !value)}
          >
            <Save aria-hidden="true" />{" "}
            {editing ? "Close editor" : "Edit binding"}
          </Button>
        </div>
      ) : null}
      {editing ? (
        <BindingEditor
          api={api}
          csrfToken={csrfToken}
          onChanged={onChanged}
          onPermissionError={onPermissionError}
          onUnauthenticated={onUnauthenticated}
          pairKey={pairKey}
          providerId={binding.providerId}
          tenantId={tenantId}
          versioned={versioned}
        />
      ) : null}
      {canManage && !binding.archivedAt ? (
        <div className="ldap-authority-danger-zone">
          <FormField
            htmlFor={`archive-binding-${binding.id}`}
            label="Archive reason"
          >
            <Input
              id={`archive-binding-${binding.id}`}
              value={archiveReason}
              maxLength={500}
              onChange={(event) => setArchiveReason(event.currentTarget.value)}
            />
          </FormField>
          <Button
            type="button"
            size="sm"
            variant="destructive"
            disabled={archiving}
            onClick={() => void archiveBinding()}
          >
            <Archive aria-hidden="true" />{" "}
            {archiving ? "Archiving…" : "Archive binding"}
          </Button>
        </div>
      ) : null}
      {error ? <FocusedError message={error} /> : null}
    </CardContent>
  );
}
