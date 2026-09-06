import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { useInfiniteQuery, useQueryClient } from "@tanstack/react-query";
import {
  ArrowDown,
  Link2,
  RefreshCw,
  Trash2,
  UserPlus,
  UsersRound,
} from "lucide-react";
import {
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { FocusedError } from "../components/focused-error";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import { TenantInstant } from "../lib/tenant-date-time-context";
import {
  CaseContactApiError,
  caseContactApi,
  type ActiveCaseContact,
  type CaseContactApi,
  type CaseContactLink,
  type CaseContactRole,
  type CursorPage,
} from "./case-contact-api";

// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this component-owned stylesheet.
import "./case-contact-panel.css";

export interface ReloadedCaseBoundary {
  etag: string;
  version: number;
}

interface RemovalDraft {
  link: CaseContactLink;
  reason: string;
}

function useCaseContactPanelState({
  api = caseContactApi,
  authorityEpoch,
  canEdit,
  canRead,
  caseEtag,
  caseId,
  caseVersion,
  csrfToken,
  onReloadLatest,
  sessionId,
  tenantId,
}: {
  api?: CaseContactApi;
  authorityEpoch: string;
  canEdit: boolean;
  canRead: boolean;
  caseEtag: string;
  caseId: string;
  caseVersion: number;
  csrfToken: string;
  onReloadLatest: () => Promise<ReloadedCaseBoundary | null>;
  sessionId: string;
  tenantId: string;
}) {
  const id = useId();
  const queryClient = useQueryClient();
  const authorizationBoundary = JSON.stringify([
    authorityEpoch,
    canEdit,
    canRead,
    caseId,
    csrfToken,
    sessionId,
    tenantId,
  ]);
  const caseSnapshotBoundary = JSON.stringify([caseEtag, caseVersion]);
  const linkQueryKey = [
    "case-contact-links",
    authorizationBoundary,
    tenantId,
    caseId,
  ] as const;
  const inventoryQueryKey = [
    "case-contact-inventory",
    authorizationBoundary,
    tenantId,
    caseId,
  ] as const;
  const linkQuery = useInfiniteQuery({
    enabled: canRead,
    initialPageParam: undefined as string | undefined,
    queryKey: linkQueryKey,
    queryFn: ({ pageParam, signal }) =>
      api.listLinks({
        ...(pageParam === undefined ? {} : { after: pageParam }),
        caseId,
        limit: 50,
        signal,
        tenantId,
      }),
    getNextPageParam: safeNextCursor,
  });
  const inventoryQuery = useInfiniteQuery({
    enabled: canRead,
    initialPageParam: undefined as string | undefined,
    queryKey: inventoryQueryKey,
    queryFn: ({ pageParam, signal }) =>
      api.listActiveContacts({
        ...(pageParam === undefined ? {} : { after: pageParam }),
        caseId,
        limit: 50,
        signal,
        tenantId,
      }),
    getNextPageParam: safeNextCursor,
  });
  const linksProjection = flattenCanonicalPages(
    linkQuery.data?.pages,
    (link) => link.contactId,
  );
  const contactsProjection = flattenCanonicalPages(inventoryQuery.data?.pages);
  const links = linksProjection.items;
  const contacts = contactsProjection.items;
  const linkedContactIds = new Set(links.map((link) => link.contactId));
  const contactById = new Map(contacts.map((contact) => [contact.id, contact]));
  const availableContacts = contacts.filter(
    (contact) => !linkedContactIds.has(contact.id),
  );
  const [selectedContactId, setSelectedContactId] = useState("");
  const [role, setRole] = useState<CaseContactRole>("primary");
  const [removal, setRemoval] = useState<RemovalDraft | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [saving, setSaving] = useState<"archive" | "link" | null>(null);
  const [recoveryVersionFloor, setRecoveryVersionFloor] = useState<
    number | null
  >(null);
  const [reloadRequired, setReloadRequired] = useState(false);
  const mutationRequest = useRef<AbortController | null>(null);
  const authorizationToken = useRef({});
  const attempt = useRef<IdempotencyReference>({ current: null });
  const reloadLatest = useRef(onReloadLatest);
  const caseBoundaryIsCanonical = caseEtag === `"v${caseVersion}"`;
  useLayoutEffect(() => {
    reloadLatest.current = onReloadLatest;
  }, [onReloadLatest]);
  useLayoutEffect(() => {
    authorizationToken.current = {};
    mutationRequest.current?.abort();
    mutationRequest.current = null;
    attempt.current.current = null;
    setSelectedContactId("");
    setRole("primary");
    setRemoval(null);
    setProblem(null);
    setSaving(null);
    setRecoveryVersionFloor(null);
    setReloadRequired(false);
    return () => {
      authorizationToken.current = {};
      mutationRequest.current?.abort();
      queryClient.removeQueries({
        exact: true,
        queryKey: [
          "case-contact-links",
          authorizationBoundary,
          tenantId,
          caseId,
        ],
      });
      queryClient.removeQueries({
        exact: true,
        queryKey: [
          "case-contact-inventory",
          authorizationBoundary,
          tenantId,
          caseId,
        ],
      });
    };
  }, [authorizationBoundary, caseId, queryClient, tenantId]);
  useLayoutEffect(() => {
    authorizationToken.current = {};
    mutationRequest.current?.abort();
    mutationRequest.current = null;
    setSaving(null);
  }, [caseSnapshotBoundary]);
  useLayoutEffect(() => {
    if (
      recoveryVersionFloor !== null &&
      caseBoundaryIsCanonical &&
      caseVersion >= recoveryVersionFloor
    ) {
      attempt.current.current = null;
      setRecoveryVersionFloor(null);
      setReloadRequired(false);
    }
  }, [caseBoundaryIsCanonical, caseVersion, recoveryVersionFloor]);
  useLayoutEffect(() => {
    if (
      selectedContactId !== "" &&
      !availableContacts.some((contact) => contact.id === selectedContactId)
    ) {
      setSelectedContactId("");
      attempt.current.current = null;
    }
  }, [availableContacts, selectedContactId]);
  return {
    api,
    authorityEpoch,
    canEdit,
    canRead,
    caseEtag,
    caseId,
    caseVersion,
    csrfToken,
    onReloadLatest,
    sessionId,
    tenantId,
    id,
    queryClient,
    authorizationBoundary,
    caseSnapshotBoundary,
    linkQueryKey,
    inventoryQueryKey,
    linkQuery,
    inventoryQuery,
    linksProjection,
    contactsProjection,
    links,
    contacts,
    linkedContactIds,
    contactById,
    availableContacts,
    selectedContactId,
    setSelectedContactId,
    role,
    setRole,
    removal,
    setRemoval,
    problem,
    setProblem,
    saving,
    setSaving,
    recoveryVersionFloor,
    setRecoveryVersionFloor,
    reloadRequired,
    setReloadRequired,
    mutationRequest,
    authorizationToken,
    attempt,
    reloadLatest,
    caseBoundaryIsCanonical,
  };
}

export function CaseContactPanel(props: {
  api?: CaseContactApi;
  authorityEpoch: string;
  canEdit: boolean;
  canRead: boolean;
  caseEtag: string;
  caseId: string;
  caseVersion: number;
  csrfToken: string;
  onReloadLatest: () => Promise<ReloadedCaseBoundary | null>;
  sessionId: string;
  tenantId: string;
}): React.JSX.Element | null {
  const state = useCaseContactPanelState(props);
  const {
    api,
    canEdit,
    canRead,
    caseEtag,
    caseId,
    caseVersion,
    csrfToken,
    sessionId,
    tenantId,
    id,
    queryClient,
    linkQueryKey,
    linkQuery,
    inventoryQuery,
    linksProjection,
    contactsProjection,
    links,
    contactById,
    availableContacts,
    selectedContactId,
    setSelectedContactId,
    role,
    setRole,
    removal,
    setRemoval,
    problem,
    setProblem,
    saving,
    setSaving,
    recoveryVersionFloor,
    setRecoveryVersionFloor,
    reloadRequired,
    setReloadRequired,
    mutationRequest,
    authorizationToken,
    attempt,
    reloadLatest,
    caseBoundaryIsCanonical,
  } = state;
  if (!canRead) return null;
  const projectionsAreCanonical =
    linksProjection.canonical && contactsProjection.canonical;
  const mutationsAllowed =
    canEdit &&
    caseBoundaryIsCanonical &&
    projectionsAreCanonical &&
    !reloadRequired &&
    saving === null &&
    !linkQuery.isPending &&
    !inventoryQuery.isPending &&
    !linkQuery.isError &&
    !inventoryQuery.isError;
  const changeSelectedContact = (value: string): void => {
    setSelectedContactId(value);
    setProblem(null);
    attempt.current.current = null;
  };
  const changeRole = (value: string): void => {
    if (value !== "primary" && value !== "escalation" && value !== "watcher") {
      return;
    }
    setRole(value);
    setProblem(null);
    attempt.current.current = null;
  };
  const closeRemoval = (): void => {
    mutationRequest.current?.abort();
    mutationRequest.current = null;
    attempt.current.current = null;
    setRemoval(null);
    setProblem(null);
    setSaving(null);
  };
  const submitLink = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    const contact = availableContacts.find(
      (candidate) => candidate.id === selectedContactId,
    );
    if (!contact || !mutationsAllowed) return;
    void mutate({ kind: "link", contact, role });
  };
  const submitArchive = (event: FormEvent<HTMLFormElement>): void => {
    event.preventDefault();
    if (!removal || removal.reason.trim() === "" || !mutationsAllowed) return;
    void mutate({
      kind: "archive",
      link: removal.link,
      reason: removal.reason.trim(),
    });
  };
  const mutate = async (
    command:
      | {
          contact: ActiveCaseContact;
          kind: "link";
          role: CaseContactRole;
        }
      | { kind: "archive"; link: CaseContactLink; reason: string },
  ): Promise<void> => {
    if (!mutationsAllowed) return;
    const payload = {
      caseId,
      caseVersion,
      command:
        command.kind === "link"
          ? {
              contactId: command.contact.id,
              kind: command.kind,
              role: command.role,
            }
          : {
              kind: command.kind,
              linkId: command.link.id,
              linkVersion: command.link.version,
              reason: command.reason,
            },
      operation: "mutate-case-contact-link",
      sessionId,
      tenantId,
    };
    const idempotencyKey = idempotencyKeyForPayload(attempt.current, payload);
    const token = authorizationToken.current;
    const controller = new AbortController();
    mutationRequest.current?.abort();
    mutationRequest.current = controller;
    setProblem(null);
    setSaving(command.kind);
    try {
      if (command.kind === "link") {
        await api.link({
          caseEtag,
          caseId,
          contactId: command.contact.id,
          csrfToken,
          expectedCaseVersion: caseVersion,
          idempotencyKey,
          role: command.role,
          signal: controller.signal,
          tenantId,
        });
      } else {
        await api.archive({
          caseId,
          csrfToken,
          expectedCaseVersion: caseVersion,
          idempotencyKey,
          link: command.link,
          reason: command.reason,
          signal: controller.signal,
          tenantId,
        });
      }
      if (!ownsMutation(token, controller)) return;
      attempt.current.current = null;
      if (command.kind === "link") setSelectedContactId("");
      else setRemoval(null);
      const requiredVersion = caseVersion + 1;
      setRecoveryVersionFloor(requiredVersion);
      setReloadRequired(true);
      const synchronized = await synchronize(token, requiredVersion);
      if (!synchronized && authorizationToken.current === token) {
        setProblem(
          "The relationship was saved, but the latest Case snapshot could not be loaded. Reload before changing contacts again.",
        );
      }
    } catch (error) {
      if (!ownsMutation(token, controller) || isAbortError(error)) return;
      setProblem(
        contactProblem(
          error,
          "The Case contact relationship could not be updated.",
        ),
      );
      if (
        error instanceof CaseContactApiError &&
        (error.status === 412 || error.status === 428)
      ) {
        const requiredVersion = caseVersion + 1;
        setRecoveryVersionFloor(requiredVersion);
        setReloadRequired(true);
        await synchronize(token, requiredVersion);
      }
    } finally {
      if (ownsMutation(token, controller)) {
        mutationRequest.current = null;
        setSaving(null);
      }
    }
  };
  const synchronize = async (
    token = authorizationToken.current,
    minimumVersion = recoveryVersionFloor,
  ): Promise<boolean> => {
    if (authorizationToken.current !== token) return false;
    await invalidateExactContactCaches();
    if (authorizationToken.current !== token) return false;
    const boundary = await reloadLatest.current().catch(() => null);
    if (authorizationToken.current !== token) return false;
    return (
      boundary !== null &&
      boundary.etag === `"v${boundary.version}"` &&
      (minimumVersion === null || boundary.version >= minimumVersion)
    );
  };
  const invalidateExactContactCaches = async (): Promise<void> => {
    await Promise.all([
      queryClient.invalidateQueries({ exact: true, queryKey: linkQueryKey }),
      queryClient.invalidateQueries({
        exact: true,
        queryKey: ["ticket-activity", "case", tenantId, caseId],
      }),
      queryClient.invalidateQueries({
        exact: true,
        queryKey: ["ticket-audit", "case", tenantId, caseId],
      }),
    ]);
  };
  const ownsMutation = (token: object, controller: AbortController): boolean =>
    authorizationToken.current === token &&
    mutationRequest.current === controller &&
    !controller.signal.aborted;

  return (
    <CaseContactsContent
      attempt={attempt}
      availableContacts={availableContacts}
      canEdit={canEdit}
      caseBoundaryIsCanonical={caseBoundaryIsCanonical}
      changeRole={changeRole}
      changeSelectedContact={changeSelectedContact}
      closeRemoval={closeRemoval}
      contactById={contactById}
      id={id}
      inventoryQuery={inventoryQuery}
      linkQuery={linkQuery}
      links={links}
      mutationsAllowed={mutationsAllowed}
      problem={problem}
      projectionsAreCanonical={projectionsAreCanonical}
      reloadRequired={reloadRequired}
      removal={removal}
      role={role}
      saving={saving}
      selectedContactId={selectedContactId}
      setProblem={setProblem}
      setRemoval={setRemoval}
      submitArchive={submitArchive}
      submitLink={submitLink}
      synchronize={synchronize}
    />
  );
}

function safeNextCursor<T>(
  page: CursorPage<T>,
  pages: readonly CursorPage<T>[],
): string | undefined {
  return page.nextCursor !== undefined &&
    !pages
      .slice(0, -1)
      .some((candidate) => candidate.nextCursor === page.nextCursor)
    ? page.nextCursor
    : undefined;
}

function flattenCanonicalPages<T extends { id: string }>(
  pages: readonly CursorPage<T>[] | undefined,
  uniqueBy?: (item: T) => string,
): { canonical: boolean; items: readonly T[] } {
  if (!pages) return { canonical: true, items: [] };
  const items = pages.flatMap((page) => page.items);
  const secondaryKeys = new Set<string>();
  let previousId: string | undefined;
  for (const item of items) {
    const secondaryKey = uniqueBy?.(item);
    if (
      (previousId !== undefined && previousId >= item.id) ||
      (secondaryKey !== undefined && secondaryKeys.has(secondaryKey))
    ) {
      return { canonical: false, items: [] };
    }
    previousId = item.id;
    if (secondaryKey !== undefined) secondaryKeys.add(secondaryKey);
  }
  const cursors = pages
    .map((page) => page.nextCursor)
    .filter((cursor): cursor is string => cursor !== undefined);
  return {
    canonical: new Set(cursors).size === cursors.length,
    items,
  };
}

function originLabel(link: CaseContactLink): string {
  if (link.origin === "manual") return "Manual relationship";
  return link.escalationProvenance
    ? `Copied from Alert ${compactIdentifier(link.escalationProvenance.sourceAlertId)}`
    : "Copied during escalation";
}

function roleLabel(role: CaseContactRole): string {
  return role === "primary"
    ? "Primary"
    : role === "escalation"
      ? "Escalation"
      : "Watcher";
}

function compactIdentifier(value: string): string {
  return `…${value.slice(-8)}`;
}

function contactProblem(error: unknown, fallback: string): string {
  return error instanceof CaseContactApiError && error.message.trim() !== ""
    ? error.message
    : fallback;
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

interface CaseContactsContentProps {
  attempt: ReturnType<typeof useCaseContactPanelState>["attempt"];
  availableContacts: ReturnType<
    typeof useCaseContactPanelState
  >["availableContacts"];
  canEdit: ReturnType<typeof useCaseContactPanelState>["canEdit"];
  caseBoundaryIsCanonical: ReturnType<
    typeof useCaseContactPanelState
  >["caseBoundaryIsCanonical"];
  changeRole: (value: string) => void;
  changeSelectedContact: (value: string) => void;
  closeRemoval: () => void;
  contactById: ReturnType<typeof useCaseContactPanelState>["contactById"];
  id: ReturnType<typeof useCaseContactPanelState>["id"];
  inventoryQuery: ReturnType<typeof useCaseContactPanelState>["inventoryQuery"];
  linkQuery: ReturnType<typeof useCaseContactPanelState>["linkQuery"];
  links: ReturnType<typeof useCaseContactPanelState>["links"];
  mutationsAllowed: boolean;
  problem: ReturnType<typeof useCaseContactPanelState>["problem"];
  projectionsAreCanonical: boolean;
  reloadRequired: ReturnType<typeof useCaseContactPanelState>["reloadRequired"];
  removal: ReturnType<typeof useCaseContactPanelState>["removal"];
  role: ReturnType<typeof useCaseContactPanelState>["role"];
  saving: ReturnType<typeof useCaseContactPanelState>["saving"];
  selectedContactId: ReturnType<
    typeof useCaseContactPanelState
  >["selectedContactId"];
  setProblem: ReturnType<typeof useCaseContactPanelState>["setProblem"];
  setRemoval: ReturnType<typeof useCaseContactPanelState>["setRemoval"];
  submitArchive: (event: FormEvent<HTMLFormElement>) => void;
  submitLink: (event: FormEvent<HTMLFormElement>) => void;
  synchronize: (token?: {}, minimumVersion?: number | null) => Promise<boolean>;
}

function CaseContactsContent({
  attempt,
  availableContacts,
  canEdit,
  caseBoundaryIsCanonical,
  changeRole,
  changeSelectedContact,
  closeRemoval,
  contactById,
  id,
  inventoryQuery,
  linkQuery,
  links,
  mutationsAllowed,
  problem,
  projectionsAreCanonical,
  reloadRequired,
  removal,
  role,
  saving,
  selectedContactId,
  setProblem,
  setRemoval,
  submitArchive,
  submitLink,
  synchronize,
}: CaseContactsContentProps): React.JSX.Element {
  return (
    <div
      aria-labelledby="ticket-tab-contacts"
      className="case-contacts"
      id="ticket-panel-contacts"
      role="tabpanel"
    >
      <header className="case-contacts__heading">
        <span>
          <UsersRound aria-hidden="true" />
          <span>
            <h2>Customer contacts</h2>
            <small>
              PII is joined only from the separately authorized active-contact
              inventory.
            </small>
          </span>
        </span>
        <Badge variant="outline">{links.length} loaded links</Badge>
      </header>

      <CaseContactStatus
        caseBoundaryIsCanonical={caseBoundaryIsCanonical}
        inventoryQuery={inventoryQuery}
        linkQuery={linkQuery}
        links={links}
        problem={problem}
        projectionsAreCanonical={projectionsAreCanonical}
      />
      {projectionsAreCanonical && links.length > 0 ? (
        <CaseContactInventory
          attempt={attempt}
          canEdit={canEdit}
          contactById={contactById}
          links={links}
          mutationsAllowed={mutationsAllowed}
          setProblem={setProblem}
          setRemoval={setRemoval}
        />
      ) : null}

      {projectionsAreCanonical && linkQuery.hasNextPage ? (
        <Button
          disabled={linkQuery.isFetchingNextPage}
          onClick={() => void linkQuery.fetchNextPage()}
          size="sm"
          variant="outline"
        >
          <ArrowDown aria-hidden="true" />
          {linkQuery.isFetchingNextPage
            ? "Loading relationships…"
            : "Load more linked contacts"}
        </Button>
      ) : null}

      {projectionsAreCanonical && inventoryQuery.hasNextPage ? (
        <Button
          disabled={inventoryQuery.isFetchingNextPage}
          onClick={() => void inventoryQuery.fetchNextPage()}
          size="sm"
          type="button"
          variant="ghost"
        >
          <ArrowDown aria-hidden="true" />
          {inventoryQuery.isFetchingNextPage
            ? "Loading contacts…"
            : "Load more active contacts"}
        </Button>
      ) : null}

      {canEdit && projectionsAreCanonical ? (
        <CaseContactLinkForm
          availableContacts={availableContacts}
          changeRole={changeRole}
          changeSelectedContact={changeSelectedContact}
          id={id}
          mutationsAllowed={mutationsAllowed}
          role={role}
          saving={saving}
          selectedContactId={selectedContactId}
          submitLink={submitLink}
        />
      ) : null}

      {reloadRequired ? (
        <div className="case-contacts__reload">
          <p>
            Contact changes are locked until the current Case and relationship
            snapshots agree.
          </p>
          <Button
            disabled={saving !== null}
            onClick={() => void synchronize()}
            size="sm"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" /> Reload current Case
          </Button>
        </div>
      ) : null}

      <CaseContactRemovalDialog
        attempt={attempt}
        closeRemoval={closeRemoval}
        id={id}
        mutationsAllowed={mutationsAllowed}
        removal={removal}
        saving={saving}
        setProblem={setProblem}
        setRemoval={setRemoval}
        submitArchive={submitArchive}
      />
    </div>
  );
}

interface CaseContactRemovalDialogProps {
  attempt: ReturnType<typeof useCaseContactPanelState>["attempt"];
  closeRemoval: () => void;
  id: ReturnType<typeof useCaseContactPanelState>["id"];
  mutationsAllowed: boolean;
  removal: ReturnType<typeof useCaseContactPanelState>["removal"];
  saving: ReturnType<typeof useCaseContactPanelState>["saving"];
  setProblem: ReturnType<typeof useCaseContactPanelState>["setProblem"];
  setRemoval: ReturnType<typeof useCaseContactPanelState>["setRemoval"];
  submitArchive: (event: FormEvent<HTMLFormElement>) => void;
}

function CaseContactRemovalDialog({
  attempt,
  closeRemoval,
  id,
  mutationsAllowed,
  removal,
  saving,
  setProblem,
  setRemoval,
  submitArchive,
}: CaseContactRemovalDialogProps): React.JSX.Element {
  return (
    <Dialog
      open={removal !== null}
      onOpenChange={(open) => {
        if (!open && saving === null) closeRemoval();
      }}
    >
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Remove customer contact from this Case?</DialogTitle>
          <DialogDescription>
            The historical relationship remains archived and auditable. A reason
            is required.
          </DialogDescription>
        </DialogHeader>
        <form className="case-contacts__remove" onSubmit={submitArchive}>
          <Label htmlFor={`${id}-archive-reason`}>Removal reason</Label>
          <Textarea
            autoFocus
            disabled={saving !== null}
            id={`${id}-archive-reason`}
            maxLength={500}
            onChange={(event) => {
              setRemoval((current) =>
                current
                  ? { ...current, reason: event.currentTarget.value }
                  : null,
              );
              attempt.current.current = null;
              setProblem(null);
            }}
            required
            value={removal?.reason ?? ""}
          />
          <div>
            <Button
              disabled={saving !== null}
              onClick={closeRemoval}
              type="button"
              variant="ghost"
            >
              Cancel
            </Button>
            <Button
              disabled={
                !mutationsAllowed || (removal?.reason.trim() ?? "") === ""
              }
              type="submit"
              variant="destructive"
            >
              <Trash2 aria-hidden="true" />
              {saving === "archive" ? "Removing…" : "Confirm removal"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface CaseContactInventoryProps {
  attempt: ReturnType<typeof useCaseContactPanelState>["attempt"];
  canEdit: ReturnType<typeof useCaseContactPanelState>["canEdit"];
  contactById: ReturnType<typeof useCaseContactPanelState>["contactById"];
  links: ReturnType<typeof useCaseContactPanelState>["links"];
  mutationsAllowed: boolean;
  setProblem: ReturnType<typeof useCaseContactPanelState>["setProblem"];
  setRemoval: ReturnType<typeof useCaseContactPanelState>["setRemoval"];
}

function CaseContactInventory({
  attempt,
  canEdit,
  contactById,
  links,
  mutationsAllowed,
  setProblem,
  setRemoval,
}: CaseContactInventoryProps): React.JSX.Element {
  return (
    <ul className="case-contacts__list">
      {links.map((link) => {
        const contact = contactById.get(link.contactId);
        return (
          <li key={link.id}>
            <span className="case-contacts__icon">
              <Link2 aria-hidden="true" />
            </span>
            <span className="case-contacts__identity">
              <strong>
                {contact
                  ? `${contact.firstName} ${contact.lastName}`
                  : `Contact ${compactIdentifier(link.contactId)}`}
              </strong>
              {contact ? (
                <span>{contact.email}</span>
              ) : (
                <small>
                  Profile not loaded; no personal data is derived from the
                  relationship.
                </small>
              )}
              <small>
                Linked <TenantInstant value={link.createdAt} /> · v
                {link.version}
              </small>
            </span>
            <span className="case-contacts__classification">
              <Badge variant="secondary">{roleLabel(link.role)}</Badge>
              <small>{originLabel(link)}</small>
            </span>
            {canEdit ? (
              <Button
                aria-label={`Remove ${contact ? `${contact.firstName} ${contact.lastName}` : `contact ${compactIdentifier(link.contactId)}`} from Case`}
                disabled={!mutationsAllowed}
                onClick={() => {
                  attempt.current.current = null;
                  setProblem(null);
                  setRemoval({ link, reason: "" });
                }}
                size="sm"
                variant="outline"
              >
                <Trash2 aria-hidden="true" /> Remove
              </Button>
            ) : null}
          </li>
        );
      })}
    </ul>
  );
}

interface CaseContactStatusProps {
  caseBoundaryIsCanonical: ReturnType<
    typeof useCaseContactPanelState
  >["caseBoundaryIsCanonical"];
  inventoryQuery: ReturnType<typeof useCaseContactPanelState>["inventoryQuery"];
  linkQuery: ReturnType<typeof useCaseContactPanelState>["linkQuery"];
  links: ReturnType<typeof useCaseContactPanelState>["links"];
  problem: ReturnType<typeof useCaseContactPanelState>["problem"];
  projectionsAreCanonical: boolean;
}

function CaseContactStatus({
  caseBoundaryIsCanonical,
  inventoryQuery,
  linkQuery,
  links,
  problem,
  projectionsAreCanonical,
}: CaseContactStatusProps): React.JSX.Element {
  return (
    <>
      {problem ? (
        <p className="case-contacts__problem" role="alert">
          {problem}
        </p>
      ) : null}
      {!caseBoundaryIsCanonical || !projectionsAreCanonical ? (
        <FocusedError message="The Case contact projection was not safe to apply. Reload the current authorized snapshot." />
      ) : null}
      {linkQuery.isError || inventoryQuery.isError ? (
        <div className="case-contacts__error">
          <FocusedError
            message={contactProblem(
              linkQuery.error ?? inventoryQuery.error,
              "The Case contact inventory could not be loaded.",
            )}
          />
          <Button
            onClick={() => {
              void linkQuery.refetch();
              void inventoryQuery.refetch();
            }}
            size="sm"
            variant="outline"
          >
            <RefreshCw aria-hidden="true" /> Retry contacts
          </Button>
        </div>
      ) : null}
      {linkQuery.isPending || inventoryQuery.isPending ? (
        <div
          aria-label="Loading Case contacts"
          className="case-contacts__loading"
        >
          <span />
          <span />
          <span />
        </div>
      ) : null}

      {projectionsAreCanonical &&
      !linkQuery.isPending &&
      !linkQuery.isError &&
      links.length === 0 ? (
        <div className="case-contacts__empty">
          <Link2 aria-hidden="true" />
          <h3>No customer contacts linked</h3>
          <p>This Case has no active customer-contact relationship.</p>
        </div>
      ) : null}
    </>
  );
}

interface CaseContactLinkFormProps {
  availableContacts: CaseContactsContentProps["availableContacts"];
  changeRole: CaseContactsContentProps["changeRole"];
  changeSelectedContact: CaseContactsContentProps["changeSelectedContact"];
  id: CaseContactsContentProps["id"];
  mutationsAllowed: CaseContactsContentProps["mutationsAllowed"];
  role: CaseContactsContentProps["role"];
  saving: CaseContactsContentProps["saving"];
  selectedContactId: CaseContactsContentProps["selectedContactId"];
  submitLink: CaseContactsContentProps["submitLink"];
}

function CaseContactLinkForm({
  availableContacts,
  changeRole,
  changeSelectedContact,
  id,
  mutationsAllowed,
  role,
  saving,
  selectedContactId,
  submitLink,
}: CaseContactLinkFormProps): React.JSX.Element {
  return (
    <form className="case-contacts__add" onSubmit={submitLink}>
      <div>
        <Label htmlFor={`${id}-contact`}>Active customer contact</Label>
        <select
          disabled={!mutationsAllowed || availableContacts.length === 0}
          id={`${id}-contact`}
          onChange={(event) => changeSelectedContact(event.currentTarget.value)}
          required
          value={selectedContactId}
        >
          <option value="">Select a contact</option>
          {availableContacts.map((contact) => (
            <option key={contact.id} value={contact.id}>
              {contact.firstName} {contact.lastName} · {contact.email}
            </option>
          ))}
        </select>
      </div>
      <div>
        <Label htmlFor={`${id}-role`}>Relationship role</Label>
        <select
          disabled={!mutationsAllowed}
          id={`${id}-role`}
          onChange={(event) => changeRole(event.currentTarget.value)}
          value={role}
        >
          <option value="primary">Primary</option>
          <option value="escalation">Escalation</option>
          <option value="watcher">Watcher</option>
        </select>
      </div>
      <Button
        disabled={!mutationsAllowed || selectedContactId === ""}
        type="submit"
      >
        <UserPlus aria-hidden="true" />
        {saving === "link" ? "Linking…" : "Link contact"}
      </Button>
    </form>
  );
}
