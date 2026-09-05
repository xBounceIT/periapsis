import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
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
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@periapsis/ui/components/ui/table";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  Activity,
  BellOff,
  ExternalLink,
  Flag,
  RefreshCw,
  Settings2,
  ShieldCheck,
  TriangleAlert,
  Users,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { FormField } from "../components/form-field";
import {
  platformFailedNotificationsFlag,
  platformSettingsChangedEvent,
  type PlatformFailedNotificationPageView,
  type PlatformFeatureFlagView,
  type PlatformGlobalSettingsView,
  type PlatformHealthView,
  type PlatformOperationsApi,
  type PlatformOperationsAuthority,
  type PlatformQueueSnapshotView,
  type PlatformUserPageView,
  type PlatformUserView,
} from "./platform-operations-model";

type Loadable<T> =
  | { kind: "error"; message: string }
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; value: T };
type PlatformOperationsTab = "flags" | "overview" | "settings" | "users";
type Confirmation =
  | { kind: "flag"; flag: PlatformFeatureFlagView; nextEnabled: boolean }
  | { kind: "settings" };

interface SettingsDraft {
  defaultLocale: string;
  defaultTimezone: string;
  platformName: string;
  supportUrl: string;
}

export interface PlatformOperationsWorkspaceProps {
  api: PlatformOperationsApi;
  authority: PlatformOperationsAuthority;
  csrfToken: string;
  describeError?: (error: unknown, fallback: string) => string;
  sessionKey: string;
}

const idle = { kind: "idle" } as const;

export function PlatformOperationsWorkspace({
  api,
  authority,
  csrfToken,
  describeError = defaultDescribeError,
  sessionKey,
}: PlatformOperationsWorkspaceProps): React.JSX.Element {
  const availableTabs = useMemo(() => tabsForAuthority(authority), [authority]);
  const [activeTab, setActiveTab] = useState<PlatformOperationsTab>(
    availableTabs[0]?.key ?? "overview",
  );
  const [health, setHealth] = useState<Loadable<PlatformHealthView>>(idle);
  const [queues, setQueues] =
    useState<Loadable<PlatformQueueSnapshotView>>(idle);
  const [users, setUsers] = useState<Loadable<PlatformUserPageView>>(idle);
  const [settings, setSettings] =
    useState<Loadable<PlatformGlobalSettingsView>>(idle);
  const [flags, setFlags] =
    useState<Loadable<readonly PlatformFeatureFlagView[]>>(idle);
  const [failed, setFailed] =
    useState<Loadable<PlatformFailedNotificationPageView>>(idle);
  const [settingsDraft, setSettingsDraft] = useState<SettingsDraft | null>(
    null,
  );
  const [loadRevision, setLoadRevision] = useState(0);
  const [loadingMoreUsers, setLoadingMoreUsers] = useState(false);
  const [loadingMoreFailed, setLoadingMoreFailed] = useState(false);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [reason, setReason] = useState("");
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [mutating, setMutating] = useState(false);
  const reasonRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (!availableTabs.some((tab) => tab.key === activeTab)) {
      setActiveTab(availableTabs[0]?.key ?? "overview");
    }
  }, [activeTab, availableTabs]);

  useEffect(() => {
    const controller = new AbortController();
    if (authority.canReadOperations) {
      setHealth({ kind: "loading" });
      setQueues({ kind: "loading" });
      void api
        .getHealth({ signal: controller.signal })
        .then((value) => setHealth({ kind: "ready", value }))
        .catch((error: unknown) => {
          if (!controller.signal.aborted) {
            setHealth({
              kind: "error",
              message: describeError(
                error,
                "System health could not be loaded.",
              ),
            });
          }
        });
      void api
        .listQueues({ signal: controller.signal })
        .then((value) => setQueues({ kind: "ready", value }))
        .catch((error: unknown) => {
          if (!controller.signal.aborted) {
            setQueues({
              kind: "error",
              message: describeError(
                error,
                "Queue metrics could not be loaded.",
              ),
            });
          }
        });
    } else {
      setHealth(idle);
      setQueues(idle);
    }
    if (authority.canReadUsers) {
      setUsers({ kind: "loading" });
      void api
        .listUsers({ signal: controller.signal })
        .then((value) => setUsers({ kind: "ready", value }))
        .catch((error: unknown) => {
          if (!controller.signal.aborted) {
            setUsers({
              kind: "error",
              message: describeError(
                error,
                "Platform users could not be loaded.",
              ),
            });
          }
        });
    } else {
      setUsers(idle);
    }
    if (authority.canReadSettings) {
      setSettings({ kind: "loading" });
      void api
        .getSettings({ signal: controller.signal })
        .then((value) => {
          setSettings({ kind: "ready", value });
          setSettingsDraft(toSettingsDraft(value));
        })
        .catch((error: unknown) => {
          if (!controller.signal.aborted) {
            setSettings({
              kind: "error",
              message: describeError(
                error,
                "Global settings could not be loaded.",
              ),
            });
          }
        });
    } else {
      setSettings(idle);
      setSettingsDraft(null);
    }
    if (authority.canReadFeatureFlags) {
      setFlags({ kind: "loading" });
      void api
        .listFeatureFlags({ signal: controller.signal })
        .then((value) => setFlags({ kind: "ready", value }))
        .catch((error: unknown) => {
          if (!controller.signal.aborted) {
            setFlags({
              kind: "error",
              message: describeError(
                error,
                "Feature flags could not be loaded.",
              ),
            });
          }
        });
    } else {
      setFlags(idle);
    }
    return () => controller.abort();
  }, [api, authority, describeError, loadRevision, sessionKey]);

  const failedNotificationsEnabled =
    flags.kind === "ready" &&
    flags.value.find((flag) => flag.key === platformFailedNotificationsFlag)
      ?.enabled === true;

  useEffect(() => {
    if (!authority.canReadOperations || !failedNotificationsEnabled) {
      setFailed(idle);
      return undefined;
    }
    const controller = new AbortController();
    setFailed({ kind: "loading" });
    void api
      .listFailedNotifications({ signal: controller.signal })
      .then((value) => setFailed({ kind: "ready", value }))
      .catch((error: unknown) => {
        if (!controller.signal.aborted) {
          setFailed({
            kind: "error",
            message: describeError(
              error,
              "Failed notification summaries could not be loaded.",
            ),
          });
        }
      });
    return () => controller.abort();
  }, [
    api,
    authority.canReadOperations,
    describeError,
    failedNotificationsEnabled,
    loadRevision,
    sessionKey,
  ]);

  async function loadMoreUsers(): Promise<void> {
    if (users.kind !== "ready" || !users.value.nextCursor || loadingMoreUsers) {
      return;
    }
    const cursor = users.value.nextCursor;
    setLoadingMoreUsers(true);
    try {
      const page = await api.listUsers({ after: cursor });
      if (page.nextCursor === cursor) {
        throw new Error("The platform user cursor did not advance.");
      }
      setUsers((current) =>
        current.kind === "ready" && current.value.nextCursor === cursor
          ? {
              kind: "ready",
              value: {
                ...page,
                items: mergeUsers(current.value.items, page.items),
              },
            }
          : current,
      );
    } catch (error) {
      setUsers({
        kind: "error",
        message: describeError(
          error,
          "The next platform user page could not be loaded.",
        ),
      });
    } finally {
      setLoadingMoreUsers(false);
    }
  }

  async function loadMoreFailedNotifications(): Promise<void> {
    if (
      failed.kind !== "ready" ||
      !failed.value.nextCursor ||
      loadingMoreFailed
    ) {
      return;
    }
    const cursor = failed.value.nextCursor;
    setLoadingMoreFailed(true);
    try {
      const page = await api.listFailedNotifications({ after: cursor });
      if (page.nextCursor === cursor) {
        throw new Error("The failed notification cursor did not advance.");
      }
      setFailed((current) =>
        current.kind === "ready" && current.value.nextCursor === cursor
          ? {
              kind: "ready",
              value: {
                ...page,
                items: mergeFailedNotifications(
                  current.value.items,
                  page.items,
                ),
              },
            }
          : current,
      );
    } catch (error) {
      setFailed({
        kind: "error",
        message: describeError(
          error,
          "The next failed notification page could not be loaded.",
        ),
      });
    } finally {
      setLoadingMoreFailed(false);
    }
  }

  function openConfirmation(next: Confirmation): void {
    setConfirmation(next);
    setReason("");
    setMutationError(null);
  }

  function dismissConfirmation(): void {
    if (mutating) return;
    setConfirmation(null);
    setReason("");
    setMutationError(null);
  }

  async function confirmMutation(): Promise<void> {
    const safeReason = reason.trim();
    if (!confirmation || safeReason.length < 1 || safeReason.length > 500) {
      setMutationError("Enter a concise operational reason before continuing.");
      requestAnimationFrame(() => reasonRef.current?.focus());
      return;
    }
    setMutating(true);
    setMutationError(null);
    try {
      if (confirmation.kind === "settings") {
        if (settings.kind !== "ready" || !settingsDraft) return;
        const next = await api.updateSettings({
          body: {
            defaultLocale: settingsDraft.defaultLocale.trim(),
            defaultTimezone: settingsDraft.defaultTimezone.trim(),
            expectedVersion: settings.value.version,
            platformName: settingsDraft.platformName.trim(),
            supportUrl: settingsDraft.supportUrl.trim() || null,
          },
          csrfToken,
          reason: safeReason,
        });
        setSettings({ kind: "ready", value: next });
        setSettingsDraft(toSettingsDraft(next));
        window.dispatchEvent(new CustomEvent(platformSettingsChangedEvent));
      } else {
        const next = await api.updateFeatureFlag({
          body: {
            enabled: confirmation.nextEnabled,
            expectedVersion: confirmation.flag.version,
          },
          csrfToken,
          flagKey: confirmation.flag.key,
          reason: safeReason,
        });
        setFlags((current) =>
          current.kind === "ready"
            ? {
                kind: "ready",
                value: current.value.map((flag) =>
                  flag.key === next.key ? next : flag,
                ),
              }
            : current,
        );
      }
      setConfirmation(null);
      setReason("");
    } catch (error) {
      setMutationError(
        describeError(error, "The platform change was not applied."),
      );
      requestAnimationFrame(() => reasonRef.current?.focus());
    } finally {
      setMutating(false);
    }
  }

  if (availableTabs.length === 0) {
    return (
      <Alert>
        <ShieldCheck aria-hidden="true" />
        <AlertTitle>Platform operations authority required</AlertTitle>
        <AlertDescription>
          This workspace is hidden unless the current tenantless session has an
          explicit platform operations permission.
        </AlertDescription>
      </Alert>
    );
  }

  return (
    <section
      className="platform-operations"
      aria-labelledby="platform-operations-title"
    >
      <header className="platform-operations__header">
        <div>
          <p className="section-label">Platform boundary / live operations</p>
          <h2 id="platform-operations-title">Control plane</h2>
          <p>
            Redacted operational inventory, queue posture, safe defaults, and
            non-security feature controls from one tenantless authority
            boundary.
          </p>
        </div>
        <div className="platform-operations__header-actions">
          {health.kind === "ready" ? (
            <Badge
              variant={
                health.value.status === "healthy" ? "secondary" : "destructive"
              }
            >
              {health.value.status === "healthy" ? "Healthy" : "Degraded"}
            </Badge>
          ) : null}
          <Button
            type="button"
            variant="outline"
            onClick={() => setLoadRevision((current) => current + 1)}
          >
            <RefreshCw aria-hidden="true" /> Refresh
          </Button>
        </div>
      </header>

      <div
        className="platform-operations__tabs"
        role="tablist"
        aria-label="Platform control plane"
      >
        {availableTabs.map((tab) => (
          <button
            key={tab.key}
            aria-selected={activeTab === tab.key}
            className="platform-operations__tab"
            role="tab"
            type="button"
            onClick={() => setActiveTab(tab.key)}
          >
            <tab.Icon aria-hidden="true" /> {tab.label}
          </button>
        ))}
      </div>

      <div role="tabpanel">
        {activeTab === "overview" ? (
          <OverviewPanel
            failed={failed}
            failedNotificationsEnabled={failedNotificationsEnabled}
            flags={flags}
            health={health}
            loadingMoreFailed={loadingMoreFailed}
            onLoadMoreFailed={() => void loadMoreFailedNotifications()}
            queues={queues}
          />
        ) : null}
        {activeTab === "users" ? (
          <UsersPanel
            loadingMore={loadingMoreUsers}
            onLoadMore={() => void loadMoreUsers()}
            state={users}
          />
        ) : null}
        {activeTab === "settings" ? (
          <SettingsPanel
            canManage={authority.canManageSettings}
            draft={settingsDraft}
            onChange={setSettingsDraft}
            onSave={() => openConfirmation({ kind: "settings" })}
            state={settings}
          />
        ) : null}
        {activeTab === "flags" ? (
          <FlagsPanel
            canManage={authority.canManageFeatureFlags}
            onToggle={(flag) =>
              openConfirmation({
                kind: "flag",
                flag,
                nextEnabled: !flag.enabled,
              })
            }
            state={flags}
          />
        ) : null}
      </div>

      <Dialog
        open={confirmation !== null}
        onOpenChange={(open) => !open && dismissConfirmation()}
      >
        <DialogContent
          onOpenAutoFocus={(event) => {
            event.preventDefault();
            reasonRef.current?.focus();
          }}
        >
          <DialogHeader>
            <DialogTitle>
              {confirmation?.kind === "flag"
                ? confirmation.nextEnabled
                  ? "Enable failed notification view?"
                  : "Disable failed notification view?"
                : "Apply global platform settings?"}
            </DialogTitle>
            <DialogDescription>
              This versioned change requires fresh MFA and is recorded in the
              append-only platform audit stream. Concurrent changes are
              rejected.
            </DialogDescription>
          </DialogHeader>
          <FormField
            htmlFor="platform-operation-reason"
            label="Operational reason"
          >
            <Textarea
              id="platform-operation-reason"
              ref={reasonRef}
              disabled={mutating}
              maxLength={500}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
            />
          </FormField>
          {mutationError ? (
            <Alert variant="destructive">
              <TriangleAlert aria-hidden="true" />
              <AlertTitle>Change not applied</AlertTitle>
              <AlertDescription>{mutationError}</AlertDescription>
            </Alert>
          ) : null}
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              disabled={mutating}
              onClick={dismissConfirmation}
            >
              Cancel
            </Button>
            <Button
              type="button"
              disabled={mutating}
              onClick={() => void confirmMutation()}
            >
              {mutating ? "Applying…" : "Confirm versioned change"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </section>
  );
}

function OverviewPanel({
  failed,
  failedNotificationsEnabled,
  flags,
  health,
  loadingMoreFailed,
  onLoadMoreFailed,
  queues,
}: {
  failed: Loadable<PlatformFailedNotificationPageView>;
  failedNotificationsEnabled: boolean;
  flags: Loadable<readonly PlatformFeatureFlagView[]>;
  health: Loadable<PlatformHealthView>;
  loadingMoreFailed: boolean;
  onLoadMoreFailed: () => void;
  queues: Loadable<PlatformQueueSnapshotView>;
}): React.JSX.Element {
  return (
    <div className="platform-operations__stack">
      <LoadableError state={health} />
      <LoadableError state={queues} />
      {health.kind === "ready" ? (
        <div className="platform-health-rail" aria-label="System health checks">
          {health.value.checks.map((check) => (
            <div key={check.key} data-status={check.status}>
              <span>{healthLabel(check.key)}</span>
              <strong>{check.status}</strong>
              {check.failedCount !== undefined ? (
                <small>{check.failedCount} failed</small>
              ) : null}
              {check.pendingCount !== undefined ? (
                <small>{check.pendingCount} pending</small>
              ) : null}
            </div>
          ))}
          <p>Checked {formatInstant(health.value.checkedAt)}</p>
        </div>
      ) : null}
      {queues.kind === "ready" ? <QueueTable value={queues.value} /> : null}
      <LoadableError state={flags} />
      {flags.kind === "ready" && !failedNotificationsEnabled ? (
        <div className="platform-operations__empty">
          <BellOff aria-hidden="true" />
          <div>
            <strong>Failed notification view is disabled</strong>
            <p>
              The API is not queried while the allowlisted feature flag is off.
            </p>
          </div>
        </div>
      ) : null}
      {failedNotificationsEnabled ? (
        <FailedNotifications
          loadingMore={loadingMoreFailed}
          onLoadMore={onLoadMoreFailed}
          state={failed}
        />
      ) : null}
    </div>
  );
}

function QueueTable({
  value,
}: {
  value: PlatformQueueSnapshotView;
}): React.JSX.Element {
  return (
    <div className="platform-operations__table-frame">
      <div className="platform-operations__section-heading">
        <div>
          <p className="section-label">Bounded queue telemetry</p>
          <h3>Work sources</h3>
        </div>
        <span>{formatInstant(value.checkedAt)}</span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Source</TableHead>
            <TableHead>Pending</TableHead>
            <TableHead>In flight</TableHead>
            <TableHead>Failed</TableHead>
            <TableHead>Oldest eligible</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {value.sources.map((source) => (
            <TableRow key={source.key}>
              <TableCell className="font-medium">
                {queueLabel(source.key)}
              </TableCell>
              <TableCell>{source.pendingCount}</TableCell>
              <TableCell>{source.inFlightCount}</TableCell>
              <TableCell>{source.failedCount}</TableCell>
              <TableCell>{formatAge(source.oldestPendingSeconds)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function FailedNotifications({
  loadingMore,
  onLoadMore,
  state,
}: {
  loadingMore: boolean;
  onLoadMore: () => void;
  state: Loadable<PlatformFailedNotificationPageView>;
}): React.JSX.Element {
  if (state.kind === "loading" || state.kind === "idle") {
    return <p role="status">Loading redacted failed notification summaries…</p>;
  }
  if (state.kind === "error") return <LoadableError state={state} />;
  return (
    <div className="platform-operations__table-frame">
      <div className="platform-operations__section-heading">
        <div>
          <p className="section-label">Redacted dead letters</p>
          <h3>Failed notifications</h3>
        </div>
        <span>No recipients, bodies, or provider receipts</span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Delivery</TableHead>
            <TableHead>Tenant</TableHead>
            <TableHead>Channel</TableHead>
            <TableHead>Failure</TableHead>
            <TableHead>Attempts</TableHead>
            <TableHead>Failed</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {state.value.items.map((item) => (
            <TableRow key={item.id}>
              <TableCell className="font-mono text-xs">
                {shortID(item.id)}
              </TableCell>
              <TableCell className="font-mono text-xs">
                {shortID(item.tenantId)}
              </TableCell>
              <TableCell>{item.channel}</TableCell>
              <TableCell>
                {item.failureClass} · {item.failureCode}
              </TableCell>
              <TableCell>{item.attemptCount}</TableCell>
              <TableCell>{formatInstant(item.failureAt)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {state.value.items.length === 0 ? (
        <p className="platform-operations__empty-copy">
          No dead-lettered notifications.
        </p>
      ) : null}
      {state.value.nextCursor ? (
        <div className="platform-operations__table-actions">
          <Button
            type="button"
            variant="outline"
            disabled={loadingMore}
            onClick={onLoadMore}
          >
            {loadingMore ? "Loading…" : "Load more failures"}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function UsersPanel({
  loadingMore,
  onLoadMore,
  state,
}: {
  loadingMore: boolean;
  onLoadMore: () => void;
  state: Loadable<PlatformUserPageView>;
}): React.JSX.Element {
  if (state.kind === "loading" || state.kind === "idle")
    return <p role="status">Loading platform users…</p>;
  if (state.kind === "error") return <LoadableError state={state} />;
  return (
    <div className="platform-operations__table-frame">
      <div className="platform-operations__section-heading">
        <div>
          <p className="section-label">Global identity inventory</p>
          <h3>Users</h3>
        </div>
        <span>{state.value.items.length} loaded</span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>User</TableHead>
            <TableHead>State</TableHead>
            <TableHead>Platform roles</TableHead>
            <TableHead>Tenant memberships</TableHead>
            <TableHead>Live sessions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {state.value.items.map((user) => (
            <TableRow key={user.id}>
              <TableCell>
                <strong>{user.displayName}</strong>
                <small>{user.email ?? "No email"}</small>
              </TableCell>
              <TableCell>
                <Badge variant={user.active ? "secondary" : "outline"}>
                  {user.active ? "Active" : "Inactive"}
                </Badge>
              </TableCell>
              <TableCell>
                {user.platformRoles.length
                  ? user.platformRoles.join(", ")
                  : "None"}
              </TableCell>
              <TableCell>
                {user.activeTenantMembershipCount} active /{" "}
                {user.totalTenantMembershipCount} total
              </TableCell>
              <TableCell>{formatLiveSessions(user)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {state.value.nextCursor ? (
        <div className="platform-operations__table-actions">
          <Button
            type="button"
            variant="outline"
            disabled={loadingMore}
            onClick={onLoadMore}
          >
            {loadingMore ? "Loading…" : "Load more users"}
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function SettingsPanel({
  canManage,
  draft,
  onChange,
  onSave,
  state,
}: {
  canManage: boolean;
  draft: SettingsDraft | null;
  onChange: (value: SettingsDraft) => void;
  onSave: () => void;
  state: Loadable<PlatformGlobalSettingsView>;
}): React.JSX.Element {
  if (state.kind === "loading" || state.kind === "idle")
    return <p role="status">Loading global settings…</p>;
  if (state.kind === "error") return <LoadableError state={state} />;
  if (!draft)
    return <p role="alert">The settings projection is unavailable.</p>;
  return (
    <div className="platform-operations__settings">
      <div className="platform-operations__section-heading">
        <div>
          <p className="section-label">Typed global defaults</p>
          <h3>Platform settings</h3>
        </div>
        <Badge variant="outline">v{state.value.version}</Badge>
      </div>
      <div className="platform-operations__settings-grid">
        <FormField htmlFor="platform-name" label="Platform name">
          <Input
            id="platform-name"
            value={draft.platformName}
            disabled={!canManage}
            maxLength={120}
            onChange={(event) =>
              onChange({ ...draft, platformName: event.target.value })
            }
          />
        </FormField>
        <FormField htmlFor="platform-locale" label="Default locale">
          <Input
            id="platform-locale"
            value={draft.defaultLocale}
            disabled={!canManage}
            maxLength={8}
            onChange={(event) =>
              onChange({ ...draft, defaultLocale: event.target.value })
            }
          />
        </FormField>
        <FormField htmlFor="platform-timezone" label="Default timezone">
          <Input
            id="platform-timezone"
            value={draft.defaultTimezone}
            disabled={!canManage}
            maxLength={64}
            onChange={(event) =>
              onChange({ ...draft, defaultTimezone: event.target.value })
            }
          />
        </FormField>
        <FormField htmlFor="platform-support-url" label="Support URL (HTTPS)">
          <Input
            id="platform-support-url"
            type="url"
            value={draft.supportUrl}
            disabled={!canManage}
            maxLength={2048}
            onChange={(event) =>
              onChange({ ...draft, supportUrl: event.target.value })
            }
          />
        </FormField>
      </div>
      <div className="platform-operations__settings-footer">
        <span>Updated {formatInstant(state.value.updatedAt)}</span>
        {state.value.supportUrl ? (
          <a
            href={state.value.supportUrl}
            target="_blank"
            rel="noopener noreferrer"
          >
            Open support <ExternalLink aria-hidden="true" />
          </a>
        ) : null}
        {canManage ? (
          <Button type="button" onClick={onSave}>
            Review settings change
          </Button>
        ) : null}
      </div>
    </div>
  );
}

function FlagsPanel({
  canManage,
  onToggle,
  state,
}: {
  canManage: boolean;
  onToggle: (flag: PlatformFeatureFlagView) => void;
  state: Loadable<readonly PlatformFeatureFlagView[]>;
}): React.JSX.Element {
  if (state.kind === "loading" || state.kind === "idle")
    return <p role="status">Loading feature flags…</p>;
  if (state.kind === "error") return <LoadableError state={state} />;
  return (
    <div className="platform-operations__flag-list">
      <div className="platform-operations__section-heading">
        <div>
          <p className="section-label">Allowlisted controls</p>
          <h3>Feature flags</h3>
        </div>
        <span>The manager remains available when a feature is disabled.</span>
      </div>
      {state.value.map((flag) => (
        <div className="platform-operations__flag" key={flag.key}>
          <div>
            <strong>Failed notification view</strong>
            <code>{flag.key}</code>
          </div>
          <Badge variant={flag.enabled ? "secondary" : "outline"}>
            {flag.enabled ? "Enabled" : "Disabled"}
          </Badge>
          <span>
            v{flag.version} · {formatInstant(flag.updatedAt)}
          </span>
          {canManage ? (
            <Button
              type="button"
              variant={flag.enabled ? "destructive" : "default"}
              onClick={() => onToggle(flag)}
            >
              {flag.enabled ? "Disable view" : "Enable view"}
            </Button>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function LoadableError<T>({
  state,
}: {
  state: Loadable<T>;
}): React.JSX.Element | null {
  if (state.kind !== "error") return null;
  return (
    <Alert variant="destructive">
      <TriangleAlert aria-hidden="true" />
      <AlertTitle>Live projection unavailable</AlertTitle>
      <AlertDescription>{state.message}</AlertDescription>
    </Alert>
  );
}

function tabsForAuthority(authority: PlatformOperationsAuthority): readonly {
  Icon: typeof Activity;
  key: PlatformOperationsTab;
  label: string;
}[] {
  return [
    ...(authority.canReadOperations
      ? [{ Icon: Activity, key: "overview" as const, label: "Operations" }]
      : []),
    ...(authority.canReadUsers
      ? [{ Icon: Users, key: "users" as const, label: "Users" }]
      : []),
    ...(authority.canReadSettings
      ? [{ Icon: Settings2, key: "settings" as const, label: "Settings" }]
      : []),
    ...(authority.canReadFeatureFlags
      ? [{ Icon: Flag, key: "flags" as const, label: "Feature flags" }]
      : []),
  ];
}

function mergeUsers(
  current: readonly PlatformUserView[],
  next: readonly PlatformUserView[],
): readonly PlatformUserView[] {
  const merged = new Map(current.map((user) => [user.id, user]));
  for (const user of next) merged.set(user.id, user);
  return [...merged.values()];
}

function mergeFailedNotifications(
  current: readonly PlatformFailedNotificationPageView["items"][number][],
  next: readonly PlatformFailedNotificationPageView["items"][number][],
): readonly PlatformFailedNotificationPageView["items"][number][] {
  const merged = new Map(current.map((item) => [item.id, item]));
  for (const item of next) merged.set(item.id, item);
  return [...merged.values()];
}

function toSettingsDraft(settings: PlatformGlobalSettingsView): SettingsDraft {
  return {
    defaultLocale: settings.defaultLocale,
    defaultTimezone: settings.defaultTimezone,
    platformName: settings.platformName,
    supportUrl: settings.supportUrl ?? "",
  };
}

function formatLiveSessions(user: PlatformUserView): string {
  return user.liveSessionsByAuthenticationMethod.length
    ? user.liveSessionsByAuthenticationMethod
        .map((summary) => `${summary.method} ${summary.liveSessionCount}`)
        .join(", ")
    : "None";
}

function healthLabel(key: string): string {
  return (
    (
      {
        database: "Database",
        platform_audit_chain: "Audit chain",
        queue_backlog: "Backlog",
        queue_failures: "Dead letters",
      } as Record<string, string>
    )[key] ?? key
  );
}

function queueLabel(key: string): string {
  return key.replaceAll("_", " ");
}

function formatAge(seconds: number): string {
  if (seconds <= 0) return "—";
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h`;
}

function formatInstant(value: string): string {
  const instant = new Date(value);
  return Number.isNaN(instant.valueOf())
    ? "Unavailable"
    : instant.toLocaleString();
}

function shortID(value: string): string {
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

function defaultDescribeError(_error: unknown, fallback: string): string {
  return fallback;
}
