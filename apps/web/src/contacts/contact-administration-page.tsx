import type {
  ContactRecipientRuleNode,
  CustomerContact,
  CustomerContactGroup,
  CustomerContactGroupVersionWrite,
  CustomerContactWrite,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  useInfiniteQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import {
  Archive,
  ContactRound,
  GitBranch,
  LoaderCircle,
  Plus,
  RefreshCw,
  Search,
  ShieldX,
  UsersRound,
} from "lucide-react";
import { useMemo, useRef, useState } from "react";
import { TableColumnHeaders } from "../components/table-column-headers";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import {
  idempotencyKeyForPayload,
  type IdempotencyReference,
} from "../lib/payload-idempotency";
import {
  ContactApiError,
  contactPortalApi,
  type ContactPortalApi,
} from "./contact-api";

export { contactAdministrationRouteDescriptor } from "./model";

// oxlint-disable-next-line import/no-unassigned-import -- Module-local visual language.
import "./contacts.css";

interface ContactAdministrationPageProps {
  api?: ContactPortalApi;
}

export function ContactAdministrationPage({
  api = contactPortalApi,
}: ContactAdministrationPageProps): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const canReadContacts = authority.hasPermission("contact.read", "tenant");
  const canManageContacts = authority.hasPermission("contact.manage", "tenant");
  const canReadGroups = authority.hasPermission("contact_group.read", "tenant");
  const canManageGroups = authority.hasPermission(
    "contact_group.manage",
    "tenant",
  );

  if (authority.status === "loading") {
    return <ContactBoundaryState loading />;
  }
  if (
    !tenantId ||
    authority.status !== "ready" ||
    (!canReadContacts && !canReadGroups)
  ) {
    return <ContactBoundaryState />;
  }

  return (
    <div className="content contact-admin">
      <ContactAdministrationWorkspace
        api={api}
        permissions={{
          contacts: { read: canReadContacts, manage: canManageContacts },
          groups: { read: canReadGroups, manage: canManageGroups },
        }}
        csrfToken={session.csrfToken}
        tenantId={tenantId}
      />
    </div>
  );
}

interface ContactAdministrationWorkspaceProps {
  api: ContactPortalApi;
  permissions: {
    contacts: { read: boolean; manage: boolean };
    groups: { read: boolean; manage: boolean };
  };
  csrfToken: string;
  tenantId: string;
}

export function ContactAdministrationWorkspace({
  api,
  permissions,
  csrfToken,
  tenantId,
}: ContactAdministrationWorkspaceProps): React.JSX.Element {
  const {
    contacts: { read: canReadContacts, manage: canManageContacts },
    groups: { read: canReadGroups, manage: canManageGroups },
  } = permissions;
  const [view, setView] = useState<"contacts" | "groups">(
    canReadContacts ? "contacts" : "groups",
  );

  return (
    <>
      <section className="contact-heading" aria-labelledby="contacts-title">
        <div className="contact-heading__signal" aria-hidden="true">
          <span />
          <ContactRound />
        </div>
        <div>
          <p className="section-label">Customer orbit / routing directory</p>
          <h1 id="contacts-title">Contacts and recipient groups</h1>
          <p>
            Maintain the people who can enter the customer portal and the
            versioned recipient rules used by incident notifications. Shared
            mailboxes are valid; identity links remain exact and tenant scoped.
          </p>
        </div>
        <div
          className="contact-view-switch"
          role="group"
          aria-label="Directory view"
        >
          {canReadContacts ? (
            <Button
              variant={view === "contacts" ? "default" : "outline"}
              onClick={() => setView("contacts")}
            >
              <ContactRound aria-hidden="true" /> Contacts
            </Button>
          ) : null}
          {canReadGroups ? (
            <Button
              variant={view === "groups" ? "default" : "outline"}
              onClick={() => setView("groups")}
            >
              <UsersRound aria-hidden="true" /> Recipient groups
            </Button>
          ) : null}
        </div>
      </section>

      {view === "contacts" && canReadContacts ? (
        <ContactDirectory
          api={api}
          canManage={canManageContacts}
          csrfToken={csrfToken}
          tenantId={tenantId}
        />
      ) : null}
      {view === "groups" && canReadGroups ? (
        <RecipientGroups
          api={api}
          canManage={canManageGroups}
          csrfToken={csrfToken}
          tenantId={tenantId}
        />
      ) : null}
    </>
  );
}

function ContactDirectory({
  api,
  canManage,
  csrfToken,
  tenantId,
}: {
  api: ContactPortalApi;
  canManage: boolean;
  csrfToken: string;
  tenantId: string;
}): React.JSX.Element {
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [activeOnly, setActiveOnly] = useState(true);
  const [editing, setEditing] = useState<CustomerContact | null>(null);
  const contacts = useInfiniteQuery({
    queryKey: ["customer-contacts", tenantId, search, activeOnly],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listContacts({
        ...(activeOnly ? { active: true } : {}),
        ...(pageParam ? { after: pageParam } : {}),
        ...(search.trim() ? { search: search.trim() } : {}),
        signal,
        tenantId,
      }),
    getNextPageParam: (lastPage) => lastPage.nextCursor,
  });
  const contactItems = contacts.data?.pages.flatMap((page) => page.items) ?? [];
  const archiveAttempt = useRef<IdempotencyReference>({ current: null });
  const archive = useMutation({
    mutationFn: (contact: CustomerContact) => {
      const reason = "Archived from contact directory";
      return api.archiveContact({
        contactId: contact.id,
        csrfToken,
        etag: `"v${contact.version}"`,
        idempotencyKey: idempotencyKeyForPayload(archiveAttempt.current, {
          contactId: contact.id,
          operation: "contact.archive",
          reason,
          tenantId,
          version: contact.version,
        }),
        reason,
        tenantId,
      });
    },
    onSuccess: async () => {
      archiveAttempt.current.current = null;
      await client.invalidateQueries({
        queryKey: ["customer-contacts", tenantId],
      });
    },
  });

  return (
    <section className="contact-panel" aria-labelledby="directory-title">
      <div className="contact-panel__toolbar">
        <div>
          <p className="section-label">Live tenant directory</p>
          <h2 id="directory-title">Customer contacts</h2>
        </div>
        <div className="contact-toolbar-actions">
          <Label className="contact-search">
            <Search aria-hidden="true" />
            <span className="sr-only">Search contacts</span>
            <Input
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              placeholder="Search name, mailbox, function…"
            />
          </Label>
          <Label className="contact-active-toggle">
            <input
              type="checkbox"
              checked={activeOnly}
              onChange={(event) => setActiveOnly(event.currentTarget.checked)}
            />
            Active only
          </Label>
          <Button
            variant="outline"
            onClick={() => void contacts.refetch()}
            disabled={contacts.isFetching}
          >
            <RefreshCw
              className={contacts.isFetching ? "is-spinning" : undefined}
              aria-hidden="true"
            />
            Refresh
          </Button>
          {canManage ? (
            <ContactEditor
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
              onSaved={() =>
                client.invalidateQueries({
                  queryKey: ["customer-contacts", tenantId],
                })
              }
            />
          ) : null}
        </div>
      </div>

      {contacts.isPending ? <LoadingRows label="Loading contacts" /> : null}
      {contacts.isError ? (
        <FocusedError
          title="Contact directory unavailable"
          message={describeContactError(contacts.error)}
        />
      ) : null}
      {!contacts.isPending && contactItems.length === 0 ? (
        <EmptyRoster
          title="No contacts in this orbit"
          detail="Adjust the filters or create the first customer contact."
        />
      ) : null}
      {contactItems.length > 0 ? (
        <div className="contact-table-frame">
          <Table>
            <TableColumnHeaders
              columns={[
                "Contact",
                "Routing",
                "Portal identity",
                "Availability",
              ]}
              actionLabel="Actions"
            />
            <TableBody>
              {contactItems.map((contact) => (
                <TableRow key={contact.id}>
                  <TableCell>
                    <strong>
                      {contact.firstName} {contact.lastName}
                    </strong>
                    <small>{contact.function}</small>
                  </TableCell>
                  <TableCell>
                    <span>{contact.email}</span>
                    <small>
                      {contact.contactClass} · priority{" "}
                      {contact.escalationPriority}
                    </small>
                  </TableCell>
                  <TableCell>
                    {contact.linkedAccount ? (
                      <Badge variant="outline">Linked exactly</Badge>
                    ) : (
                      <span className="contact-muted">Not linked</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <AvailabilityBands contact={contact} />
                  </TableCell>
                  <TableCell>
                    {canManage ? (
                      <div className="contact-row-actions">
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setEditing(contact)}
                        >
                          Edit
                        </Button>
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={
                            archive.isPending ||
                            contact.archivedAt !== undefined
                          }
                          onClick={() => archive.mutate(contact)}
                        >
                          <Archive aria-hidden="true" /> Archive
                        </Button>
                      </div>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ) : null}
      {contacts.hasNextPage ? (
        <Button
          variant="outline"
          disabled={contacts.isFetchingNextPage}
          onClick={() => void contacts.fetchNextPage()}
        >
          {contacts.isFetchingNextPage ? "Loading…" : "Load more contacts"}
        </Button>
      ) : null}
      {archive.isError ? (
        <FocusedError
          title="Archive failed"
          message={describeContactError(archive.error)}
        />
      ) : null}
      {editing ? (
        <ContactEditor
          api={api}
          contact={editing}
          csrfToken={csrfToken}
          open
          tenantId={tenantId}
          onOpenChange={(open) => {
            if (!open) setEditing(null);
          }}
          onSaved={async () => {
            setEditing(null);
            await client.invalidateQueries({
              queryKey: ["customer-contacts", tenantId],
            });
          }}
        />
      ) : null}
    </section>
  );
}

function ContactEditor({
  api,
  contact,
  csrfToken,
  onOpenChange,
  onSaved,
  open,
  tenantId,
}: {
  api: ContactPortalApi;
  contact?: CustomerContact;
  csrfToken: string;
  onOpenChange?: (open: boolean) => void;
  onSaved: () => void | Promise<void>;
  open?: boolean;
  tenantId: string;
}): React.JSX.Element {
  const [internalOpen, setInternalOpen] = useState(false);
  const [draft, setDraft] = useState(() => contactDraft(contact));
  const saveAttempt = useRef<IdempotencyReference>({ current: null });
  const mutation = useMutation({
    mutationFn: async () => {
      const body = contactBody(draft, contact);
      const idempotencyKey = idempotencyKeyForPayload(saveAttempt.current, {
        body,
        contactId: contact?.id,
        operation: contact ? "contact.replace" : "contact.create",
        tenantId,
        version: contact?.version,
      });
      return contact
        ? api.replaceContact({
            body,
            contactId: contact.id,
            csrfToken,
            etag: `"v${contact.version}"`,
            idempotencyKey,
            tenantId,
          })
        : api.createContact({
            body,
            csrfToken,
            idempotencyKey,
            tenantId,
          });
    },
    onSuccess: async () => {
      saveAttempt.current.current = null;
      await onSaved();
      setDraft(contactDraft());
      setInternalOpen(false);
      onOpenChange?.(false);
    },
  });
  const controlled = open !== undefined;
  const visible = controlled ? open : internalOpen;
  const changeOpen = (next: boolean): void => {
    if (!controlled) setInternalOpen(next);
    onOpenChange?.(next);
    if (next) setDraft(contactDraft(contact));
  };

  return (
    <Dialog open={visible} onOpenChange={changeOpen}>
      {!controlled ? (
        <DialogTrigger asChild>
          <Button>
            <Plus aria-hidden="true" /> New contact
          </Button>
        </DialogTrigger>
      ) : null}
      <DialogContent className="contact-dialog">
        <DialogHeader>
          <DialogTitle>
            {contact ? "Edit customer contact" : "Create customer contact"}
          </DialogTitle>
          <DialogDescription>
            Mailboxes may be shared. A portal identity requires both exact
            membership and user IDs.
          </DialogDescription>
        </DialogHeader>
        <form
          className="contact-form"
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <Field label="First name">
            <Input
              required
              value={draft.firstName}
              onChange={(event) =>
                setDraft({ ...draft, firstName: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Last name">
            <Input
              required
              value={draft.lastName}
              onChange={(event) =>
                setDraft({ ...draft, lastName: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Email">
            <Input
              required
              type="email"
              value={draft.email}
              onChange={(event) =>
                setDraft({ ...draft, email: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Phone">
            <Input
              value={draft.phone}
              onChange={(event) =>
                setDraft({ ...draft, phone: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Function">
            <Input
              required
              value={draft.function}
              onChange={(event) =>
                setDraft({ ...draft, function: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Language">
            <Input
              required
              value={draft.language}
              onChange={(event) =>
                setDraft({ ...draft, language: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="IANA timezone">
            <Input
              required
              value={draft.timezone}
              onChange={(event) =>
                setDraft({ ...draft, timezone: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Contact class">
            <Input
              required
              value={draft.contactClass}
              onChange={(event) =>
                setDraft({ ...draft, contactClass: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Escalation priority">
            <Input
              required
              type="number"
              min={0}
              max={100}
              value={draft.escalationPriority}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  escalationPriority: event.currentTarget.value,
                })
              }
            />
          </Field>
          <Field label="Notification categories">
            <Input
              value={draft.categories}
              onChange={(event) =>
                setDraft({ ...draft, categories: event.currentTarget.value })
              }
              placeholder="incident, sla"
            />
          </Field>
          <Field label="Tags">
            <Input
              value={draft.tags}
              onChange={(event) =>
                setDraft({ ...draft, tags: event.currentTarget.value })
              }
              placeholder="executive, region_eu"
            />
          </Field>
          <Field label="Membership ID">
            <Input
              value={draft.membershipId}
              onChange={(event) =>
                setDraft({ ...draft, membershipId: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="User ID">
            <Input
              value={draft.userId}
              onChange={(event) =>
                setDraft({ ...draft, userId: event.currentTarget.value })
              }
            />
          </Field>
          <Label className="contact-form__check">
            <input
              type="checkbox"
              checked={draft.emailAllowed}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  emailAllowed: event.currentTarget.checked,
                })
              }
            />{" "}
            Email notifications allowed
          </Label>
          <Label className="contact-form__check">
            <input
              type="checkbox"
              checked={draft.active}
              onChange={(event) =>
                setDraft({ ...draft, active: event.currentTarget.checked })
              }
            />{" "}
            Active contact
          </Label>
          {mutation.isError ? (
            <FocusedError
              title="Contact was not saved"
              message={describeContactError(mutation.error)}
            />
          ) : null}
          <div className="contact-form__actions">
            <Button
              type="button"
              variant="outline"
              onClick={() => changeOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending
                ? "Saving…"
                : contact
                  ? "Save version"
                  : "Create contact"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface ContactDraft {
  active: boolean;
  categories: string;
  contactClass: string;
  email: string;
  emailAllowed: boolean;
  escalationPriority: string;
  firstName: string;
  function: string;
  language: string;
  lastName: string;
  membershipId: string;
  phone: string;
  tags: string;
  timezone: string;
  userId: string;
}

function contactDraft(contact?: CustomerContact): ContactDraft {
  return {
    active: contact?.active ?? true,
    categories: contact?.notificationCategories.join(", ") ?? "incident",
    contactClass: contact?.contactClass ?? "customer",
    email: contact?.email ?? "",
    emailAllowed: contact?.emailAllowed ?? true,
    escalationPriority: String(contact?.escalationPriority ?? 50),
    firstName: contact?.firstName ?? "",
    function: contact?.function ?? "Incident liaison",
    language: contact?.language ?? "en",
    lastName: contact?.lastName ?? "",
    membershipId: contact?.linkedAccount?.membershipId ?? "",
    phone: contact?.phone ?? "",
    tags: contact?.tags.join(", ") ?? "",
    timezone: contact?.timezone ?? "Europe/Rome",
    userId: contact?.linkedAccount?.userId ?? "",
  };
}

function contactBody(
  draft: ContactDraft,
  contact?: CustomerContact,
): CustomerContactWrite {
  const linked = draft.membershipId.trim() || draft.userId.trim();
  if (linked && (!draft.membershipId.trim() || !draft.userId.trim())) {
    throw new ContactApiError(
      "Membership ID and user ID must be supplied together.",
    );
  }
  return {
    active: draft.active,
    contactClass: draft.contactClass.trim(),
    email: draft.email.trim().toLowerCase(),
    emailAllowed: draft.emailAllowed,
    escalationPriority: Number(draft.escalationPriority),
    firstName: draft.firstName.trim(),
    function: draft.function.trim(),
    language: draft.language.trim().toLowerCase(),
    lastName: draft.lastName.trim(),
    notificationCategories: stableKeys(draft.categories),
    notificationWindows: contact?.notificationWindows ?? [],
    ...(draft.phone.trim() ? { phone: draft.phone.trim() } : {}),
    tags: stableKeys(draft.tags),
    timezone: draft.timezone.trim(),
    ...(linked
      ? {
          linkedAccount: {
            membershipId: draft.membershipId.trim(),
            userId: draft.userId.trim(),
          },
        }
      : {}),
  };
}

function RecipientGroups({
  api,
  canManage,
  csrfToken,
  tenantId,
}: {
  api: ContactPortalApi;
  canManage: boolean;
  csrfToken: string;
  tenantId: string;
}): React.JSX.Element {
  const client = useQueryClient();
  const [search, setSearch] = useState("");
  const [editing, setEditing] = useState<CustomerContactGroup | null>(null);
  const groups = useInfiniteQuery({
    queryKey: ["customer-contact-groups", tenantId, search],
    initialPageParam: undefined as string | undefined,
    queryFn: ({ pageParam, signal }) =>
      api.listGroups({
        ...(pageParam ? { after: pageParam } : {}),
        ...(search.trim() ? { search: search.trim() } : {}),
        signal,
        tenantId,
      }),
    getNextPageParam: (lastPage) => lastPage.nextCursor,
  });
  const groupItems = groups.data?.pages.flatMap((page) => page.items) ?? [];

  return (
    <section className="contact-panel" aria-labelledby="groups-title">
      <div className="contact-panel__toolbar">
        <div>
          <p className="section-label">Versioned routing</p>
          <h2 id="groups-title">Recipient groups</h2>
        </div>
        <div className="contact-toolbar-actions">
          <Label className="contact-search">
            <Search aria-hidden="true" />
            <span className="sr-only">Search groups</span>
            <Input
              value={search}
              onChange={(event) => setSearch(event.currentTarget.value)}
              placeholder="Search groups…"
            />
          </Label>
          {canManage ? (
            <GroupEditor
              api={api}
              csrfToken={csrfToken}
              tenantId={tenantId}
              onSaved={() =>
                client.invalidateQueries({
                  queryKey: ["customer-contact-groups", tenantId],
                })
              }
            />
          ) : null}
        </div>
      </div>
      {groups.isPending ? (
        <LoadingRows label="Loading recipient groups" />
      ) : null}
      {groups.isError ? (
        <FocusedError
          title="Recipient groups unavailable"
          message={describeContactError(groups.error)}
        />
      ) : null}
      {!groups.isPending && groupItems.length === 0 ? (
        <EmptyRoster
          title="No recipient groups"
          detail="Create a manual cohort or a bounded dynamic rule."
        />
      ) : null}
      {groupItems.length > 0 ? (
        <div className="contact-group-grid">
          {groupItems.map((group) => (
            <Card key={group.id} className="contact-group-card">
              <CardHeader>
                <div className="contact-group-card__title">
                  <GitBranch aria-hidden="true" />
                  <div>
                    <CardTitle>{group.name}</CardTitle>
                    <CardDescription>
                      {group.key} · version {group.version}
                    </CardDescription>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <p>{group.description || "No routing note."}</p>
                <div className="contact-group-card__facts">
                  <Badge variant="outline">{group.mode}</Badge>
                  <span>
                    {group.mode === "manual"
                      ? `${group.memberIds.length} exact contacts`
                      : `${countRuleNodes(group.rule)} rule nodes`}
                  </span>
                </div>
                {canManage ? (
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setEditing(group)}
                  >
                    Create next version
                  </Button>
                ) : null}
              </CardContent>
            </Card>
          ))}
        </div>
      ) : null}
      {groups.hasNextPage ? (
        <Button
          variant="outline"
          disabled={groups.isFetchingNextPage}
          onClick={() => void groups.fetchNextPage()}
        >
          {groups.isFetchingNextPage
            ? "Loading…"
            : "Load more recipient groups"}
        </Button>
      ) : null}
      {editing ? (
        <GroupEditor
          api={api}
          csrfToken={csrfToken}
          group={editing}
          open
          tenantId={tenantId}
          onOpenChange={(open) => {
            if (!open) setEditing(null);
          }}
          onSaved={async () => {
            setEditing(null);
            await client.invalidateQueries({
              queryKey: ["customer-contact-groups", tenantId],
            });
          }}
        />
      ) : null}
    </section>
  );
}

function GroupEditor({
  api,
  csrfToken,
  group,
  onOpenChange,
  onSaved,
  open,
  tenantId,
}: {
  api: ContactPortalApi;
  csrfToken: string;
  group?: CustomerContactGroup;
  onOpenChange?: (open: boolean) => void;
  onSaved: () => void | Promise<void>;
  open?: boolean;
  tenantId: string;
}): React.JSX.Element {
  const [internalOpen, setInternalOpen] = useState(false);
  const [draft, setDraft] = useState(() => groupDraft(group));
  const saveAttempt = useRef<IdempotencyReference>({ current: null });
  const mutation = useMutation({
    mutationFn: async () => {
      const shape = groupShape(draft);
      const createBody = { ...shape, key: draft.key.trim() };
      const idempotencyKey = idempotencyKeyForPayload(saveAttempt.current, {
        body: group ? shape : createBody,
        groupId: group?.id,
        operation: group ? "contact_group.version" : "contact_group.create",
        tenantId,
        version: group?.version,
      });
      return group
        ? api.versionGroup({
            body: shape,
            csrfToken,
            etag: `"v${group.version}"`,
            groupId: group.id,
            idempotencyKey,
            tenantId,
          })
        : api.createGroup({
            body: createBody,
            csrfToken,
            idempotencyKey,
            tenantId,
          });
    },
    onSuccess: async () => {
      saveAttempt.current.current = null;
      await onSaved();
      setInternalOpen(false);
      onOpenChange?.(false);
    },
  });
  const controlled = open !== undefined;
  const visible = controlled ? open : internalOpen;
  const changeOpen = (next: boolean): void => {
    if (!controlled) setInternalOpen(next);
    onOpenChange?.(next);
    if (next) setDraft(groupDraft(group));
  };

  return (
    <Dialog open={visible} onOpenChange={changeOpen}>
      {!controlled ? (
        <DialogTrigger asChild>
          <Button>
            <Plus aria-hidden="true" /> New group
          </Button>
        </DialogTrigger>
      ) : null}
      <DialogContent className="contact-dialog">
        <DialogHeader>
          <DialogTitle>
            {group
              ? "Create recipient-group version"
              : "Create recipient group"}
          </DialogTitle>
          <DialogDescription>
            Rules are closed, bounded and versioned. This editor creates one
            validated predicate; API clients may compose the full AST.
          </DialogDescription>
        </DialogHeader>
        <form
          className="contact-form"
          onSubmit={(event) => {
            event.preventDefault();
            mutation.mutate();
          }}
        >
          <Field label="Stable key">
            <Input
              required
              disabled={group !== undefined}
              value={draft.key}
              onChange={(event) =>
                setDraft({ ...draft, key: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Name">
            <Input
              required
              value={draft.name}
              onChange={(event) =>
                setDraft({ ...draft, name: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Description">
            <Textarea
              value={draft.description}
              onChange={(event) =>
                setDraft({ ...draft, description: event.currentTarget.value })
              }
            />
          </Field>
          <Field label="Mode">
            <select
              value={draft.mode}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  mode: parseGroupMode(event.currentTarget.value),
                })
              }
            >
              <option value="manual">Manual</option>
              <option value="dynamic">Dynamic</option>
            </select>
          </Field>
          {draft.mode === "manual" ? (
            <Field label="Contact IDs">
              <Textarea
                value={draft.members}
                onChange={(event) =>
                  setDraft({ ...draft, members: event.currentTarget.value })
                }
                placeholder="One UUIDv7 per line"
              />
            </Field>
          ) : (
            <>
              <Field label="Rule field">
                <select
                  value={draft.ruleField}
                  onChange={(event) =>
                    setDraft({
                      ...draft,
                      ruleField: parseRuleField(event.currentTarget.value),
                    })
                  }
                >
                  <option value="contact_class">Contact class</option>
                  <option value="tag">Tag</option>
                  <option value="notification_category">
                    Notification category
                  </option>
                  <option value="language">Language</option>
                  <option value="timezone">Timezone</option>
                </select>
              </Field>
              <Field label="Rule value">
                <Input
                  required
                  value={draft.ruleValue}
                  onChange={(event) =>
                    setDraft({ ...draft, ruleValue: event.currentTarget.value })
                  }
                />
              </Field>
            </>
          )}
          {mutation.isError ? (
            <FocusedError
              title="Group was not saved"
              message={describeContactError(mutation.error)}
            />
          ) : null}
          <div className="contact-form__actions">
            <Button
              type="button"
              variant="outline"
              onClick={() => changeOpen(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={mutation.isPending}>
              {mutation.isPending
                ? "Saving…"
                : group
                  ? "Create version"
                  : "Create group"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}

interface GroupDraft {
  description: string;
  key: string;
  members: string;
  mode: "dynamic" | "manual";
  name: string;
  ruleField: NonNullable<ContactRecipientRuleNode["field"]>;
  ruleValue: string;
}

function groupDraft(group?: CustomerContactGroup): GroupDraft {
  return {
    description: group?.description ?? "",
    key: group?.key ?? "",
    members: group?.memberIds.join("\n") ?? "",
    mode: group?.mode ?? "manual",
    name: group?.name ?? "",
    ruleField: group?.rule?.field ?? "contact_class",
    ruleValue: group?.rule?.values?.[0] ?? "customer",
  };
}

function groupShape(draft: GroupDraft): CustomerContactGroupVersionWrite {
  if (draft.mode === "manual") {
    return {
      description: draft.description.trim(),
      memberIds: lines(draft.members),
      mode: "manual",
      name: draft.name.trim(),
    };
  }
  const containsField =
    draft.ruleField === "tag" || draft.ruleField === "notification_category";
  return {
    description: draft.description.trim(),
    memberIds: [],
    mode: "dynamic",
    name: draft.name.trim(),
    ruleSchemaVersion: 1,
    rule: {
      field: draft.ruleField,
      kind: "predicate",
      operator: containsField ? "contains" : "equals",
      values: [draft.ruleValue.trim()],
    },
  };
}

function parseGroupMode(value: string): GroupDraft["mode"] {
  if (value === "manual" || value === "dynamic") return value;
  throw new ContactApiError("The recipient group mode is not supported.");
}

function parseRuleField(value: string): GroupDraft["ruleField"] {
  if (
    value === "contact_class" ||
    value === "tag" ||
    value === "notification_category" ||
    value === "language" ||
    value === "timezone"
  ) {
    return value;
  }
  throw new ContactApiError(
    "The recipient rule field is not supported by this editor.",
  );
}

function AvailabilityBands({
  contact,
}: {
  contact: CustomerContact;
}): React.JSX.Element {
  const grouped = useMemo(
    () =>
      new Set(contact.notificationWindows.map((window) => window.isoWeekday)),
    [contact.notificationWindows],
  );
  return (
    <div
      className="availability-bands"
      aria-label={
        contact.notificationWindows.length === 0
          ? "Always available"
          : `${grouped.size} scheduled weekdays`
      }
    >
      {Array.from({ length: 7 }, (_, index) => (
        <span
          key={index}
          className={
            grouped.has(index + 1) || contact.notificationWindows.length === 0
              ? "is-live"
              : undefined
          }
        />
      ))}
      <small>
        {contact.notificationWindows.length === 0
          ? "Always"
          : `${grouped.size}/7 days`}
      </small>
    </div>
  );
}

function Field({
  children,
  label,
}: {
  children: React.ReactNode;
  label: string;
}): React.JSX.Element {
  return (
    <Label className="contact-form__field">
      <span>{label}</span>
      {children}
    </Label>
  );
}

function LoadingRows({ label }: { label: string }): React.JSX.Element {
  return (
    <div className="contact-loading" role="status">
      <LoaderCircle className="is-spinning" aria-hidden="true" /> {label}…
    </div>
  );
}

function EmptyRoster({
  detail,
  title,
}: {
  detail: string;
  title: string;
}): React.JSX.Element {
  return (
    <div className="contact-empty">
      <UsersRound aria-hidden="true" />
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

function ContactBoundaryState({
  loading = false,
}: {
  loading?: boolean;
}): React.JSX.Element {
  return (
    <div
      className="content content--narrow contact-boundary"
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
          ? "Checking contact authority…"
          : "Contact administration is unavailable."}
      </h1>
      <p>
        {loading
          ? "The directory remains closed until the current tenant authority is ready."
          : "An active tenant and contact.read or contact_group.read are required. Navigation is not authorization."}
      </p>
    </div>
  );
}

function stableKeys(value: string): string[] {
  return [
    ...new Set(
      value
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].toSorted();
}

function lines(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/\r?\n|,/u)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ].toSorted();
}

function countRuleNodes(rule: CustomerContactGroup["rule"]): number {
  if (!rule) return 0;
  return (
    1 +
    (rule.children ?? []).reduce(
      (total, child) => total + countRuleNodes(child),
      0,
    )
  );
}

function describeContactError(error: unknown): string {
  if (error instanceof ContactApiError) return error.message;
  return "The contact operation could not be completed.";
}
