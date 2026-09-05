import type {
  PlatformSmtpConfigurationHealth,
  PlatformSmtpConfigurationTestRequest,
  SmtpConfiguration,
  SmtpConfigurationHealth,
  SmtpConfigurationTestRequest,
  SmtpConfigurationWriteWritable,
} from "@periapsis/contracts";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import { KeyRound, MailCheck } from "lucide-react";
import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { FormField } from "../components/form-field";
import {
  NotificationApiError,
  type NotificationAdminApi,
  type Versioned,
} from "./notification-api";
import {
  bindMutationAttempt,
  bindOpaqueMutationAttempt,
  emptySmtpWrite,
  forgetWriteOnlySmtp,
  resetMutationAttempt,
  resetOpaqueMutationAttempt,
  smtpWriteFromProjection,
  type MutationAttemptReference,
  type OpaqueMutationAttemptReference,
} from "./model";
import {
  EditorActions,
  NotificationEmpty,
  NotificationError,
  NotificationLoading,
} from "./notification-primitives";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts this module-owned stylesheet.
import "./notifications.css";

interface SmtpPanelProps {
  api: NotificationAdminApi;
  csrfToken: string;
  scope: "platform" | "tenant";
  tenantId?: string;
}

interface SmtpSnapshot {
  kind: "empty" | "error" | "loading" | "ready";
  error?: unknown;
  versioned?: Versioned<SmtpConfiguration>;
}

export function TenantSmtpPanel(props: Omit<SmtpPanelProps, "scope">) {
  return <SmtpPanel {...props} scope="tenant" />;
}

export function PlatformSmtpWorkspace({
  api,
  canManage,
  csrfToken,
}: {
  api: NotificationAdminApi;
  canManage: boolean;
  csrfToken: string;
}) {
  if (!canManage) {
    return (
      <section className="notification-workspace notification-workspace--denied">
        <NotificationEmpty
          title="Platform notification authority required"
          detail="This client-side visibility check is advisory. The platform API revalidates platform.notification.manage."
        />
      </section>
    );
  }
  return (
    <section
      className="notification-workspace notification-platform-smtp"
      aria-labelledby="platform-smtp-title"
    >
      <header className="notification-workspace__heading">
        <div>
          <p className="section-label">Platform boundary / Phase 6</p>
          <h1 id="platform-smtp-title">Global mail relay</h1>
          <p>
            Operate the sanitized platform fallback without exposing password or
            DKIM material.
          </p>
        </div>
        <Badge variant="outline">platform.notification.manage</Badge>
      </header>
      <SmtpPanel api={api} csrfToken={csrfToken} scope="platform" />
    </section>
  );
}

export function SmtpPanel({ api, csrfToken, scope, tenantId }: SmtpPanelProps) {
  const [snapshot, setSnapshot] = useState<SmtpSnapshot>({ kind: "loading" });
  const [draft, setDraft] =
    useState<SmtpConfigurationWriteWritable>(emptySmtpWrite);
  const [health, setHealth] = useState<
    SmtpConfigurationHealth | PlatformSmtpConfigurationHealth | null
  >(null);
  const [recipient, setRecipient] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<"save" | "test" | null>(null);
  const [actionError, setActionError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const saveAttempt = useRef<OpaqueMutationAttemptReference>({ current: null });
  const testAttempt = useRef<MutationAttemptReference>({ current: null });

  const load = useCallback(
    async (signal: AbortSignal) => {
      if (scope === "tenant") {
        if (!tenantId)
          throw new NotificationApiError("A tenant context is required.");
        return api.getTenantSmtp({ signal, tenantId });
      }
      return api.getPlatformSmtp({ signal });
    },
    [api, scope, tenantId],
  );

  useEffect(() => {
    const controller = new AbortController();
    setSnapshot({ kind: "loading" });
    void load(controller.signal).then(
      (versioned) => {
        if (controller.signal.aborted) return;
        setSnapshot({ kind: "ready", versioned });
        setDraft(smtpWriteFromProjection(versioned.value));
      },
      (error: unknown) => {
        if (controller.signal.aborted) return;
        setSnapshot(
          error instanceof NotificationApiError && error.status === 404
            ? { kind: "empty" }
            : { error, kind: "error" },
        );
        setDraft(emptySmtpWrite);
      },
    );
    return () => controller.abort();
  }, [load, revision]);

  function updateDraft(
    change: (
      current: SmtpConfigurationWriteWritable,
    ) => SmtpConfigurationWriteWritable,
  ): void {
    resetOpaqueMutationAttempt(saveAttempt.current);
    setDraft(change);
  }

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy("save");
    setActionError(null);
    setNotice(null);
    try {
      const idempotencyKey = bindOpaqueMutationAttempt(saveAttempt.current);
      const current = snapshot.versioned;
      const etag =
        scope === "tenant" && current?.value.inheritedFromGlobal
          ? undefined
          : current?.etag;
      const saved =
        scope === "tenant"
          ? await api.putTenantSmtp({
              body: draft,
              csrfToken,
              ...(etag ? { etag } : {}),
              idempotencyKey,
              tenantId: tenantId!,
            })
          : await api.putPlatformSmtp({
              body: draft,
              csrfToken,
              ...(etag ? { etag } : {}),
              idempotencyKey,
            });
      setSnapshot({ kind: "ready", versioned: saved });
      setDraft(forgetWriteOnlySmtp(smtpWriteFromProjection(saved.value)));
      resetOpaqueMutationAttempt(saveAttempt.current);
      setNotice(
        `SMTP version ${saved.value.version} is current. Write-only values were cleared.`,
      );
    } catch (error: unknown) {
      setActionError(error);
    } finally {
      setBusy(null);
    }
  }

  async function test(): Promise<void> {
    const current = snapshot.versioned;
    if (!current) return;
    setBusy("test");
    setActionError(null);
    try {
      const common = {
        configurationVersion: current.value.version,
        reason: reason.trim(),
      };
      let result: SmtpConfigurationHealth | PlatformSmtpConfigurationHealth;
      if (scope === "tenant") {
        const body: SmtpConfigurationTestRequest = {
          ...common,
          recipient: recipient.trim() || null,
        };
        const idempotencyKey = bindMutationAttempt(
          testAttempt.current,
          "tenant.smtp.test",
          tenantId ?? null,
          body,
        );
        result = await api.testTenantSmtp({
          body,
          csrfToken,
          idempotencyKey,
          tenantId: tenantId!,
        });
      } else {
        const body: PlatformSmtpConfigurationTestRequest = common;
        const idempotencyKey = bindMutationAttempt(
          testAttempt.current,
          "platform.smtp.test",
          null,
          body,
        );
        result = await api.testPlatformSmtp({
          body,
          csrfToken,
          idempotencyKey,
        });
      }
      setHealth(result);
      setRecipient("");
      resetMutationAttempt(testAttempt.current);
    } catch (error: unknown) {
      setActionError(error);
    } finally {
      setBusy(null);
    }
  }

  const projection = snapshot.versioned?.value;
  const isInherited =
    scope === "tenant" && projection?.inheritedFromGlobal === true;

  return (
    <div
      className="notification-smtp-layout"
      aria-busy={snapshot.kind === "loading"}
    >
      <section className="notification-provider-summary">
        <div className="notification-provider-summary__title">
          <div className="notification-provider-icon">
            <MailCheck aria-hidden="true" />
          </div>
          <div>
            <p className="section-label">Effective provider</p>
            <h2>{projection?.name ?? "No relay configured"}</h2>
          </div>
        </div>
        {snapshot.kind === "loading" ? (
          <NotificationLoading label="Loading SMTP configuration" />
        ) : null}
        {snapshot.kind === "error" ? (
          <NotificationError
            error={snapshot.error}
            fallback="SMTP configuration could not be loaded."
          />
        ) : null}
        {snapshot.kind === "empty" ? (
          <NotificationEmpty
            title="No SMTP configuration"
            detail={
              scope === "tenant"
                ? "No tenant override or platform fallback is available."
                : "Create the global relay used when tenants do not override it."
            }
          />
        ) : null}
        {projection ? (
          <dl className="notification-definition-list">
            <div>
              <dt>Boundary</dt>
              <dd>
                {isInherited ? (
                  <Badge variant="secondary">Platform fallback</Badge>
                ) : (
                  <Badge variant="outline">
                    {scope === "tenant" ? "Tenant override" : "Platform"}
                  </Badge>
                )}
              </dd>
            </div>
            <div>
              <dt>Endpoint</dt>
              <dd>
                {projection.host}:{projection.port} / {projection.security}
              </dd>
            </div>
            <div>
              <dt>Credentials</dt>
              <dd>
                {projection.passwordConfigured
                  ? "Password pinned"
                  : "No password"}
              </dd>
            </div>
            <div>
              <dt>DKIM</dt>
              <dd>
                {projection.dkim?.privateKeyConfigured
                  ? `${projection.dkim.selector} · key pinned`
                  : "Not configured"}
              </dd>
            </div>
            <div>
              <dt>Version</dt>
              <dd>v{projection.version}</dd>
            </div>
          </dl>
        ) : null}
        {projection ? (
          <section className="notification-toolbox">
            <h3>Provider health check</h3>
            <div className="notification-form-grid">
              {scope === "tenant" ? (
                <FormField
                  htmlFor={`${scope}-smtp-test-recipient`}
                  label="Optional test recipient"
                >
                  <Input
                    id={`${scope}-smtp-test-recipient`}
                    type="email"
                    autoComplete="off"
                    value={recipient}
                    onChange={(event) => {
                      setRecipient(event.target.value);
                      resetMutationAttempt(testAttempt.current);
                    }}
                  />
                </FormField>
              ) : null}
              <FormField
                htmlFor={`${scope}-smtp-test-reason`}
                label="Audited reason"
              >
                <Input
                  id={`${scope}-smtp-test-reason`}
                  maxLength={500}
                  value={reason}
                  onChange={(event) => {
                    setReason(event.target.value);
                    resetMutationAttempt(testAttempt.current);
                  }}
                />
              </FormField>
            </div>
            <Button
              type="button"
              variant="outline"
              disabled={busy !== null || !reason.trim()}
              onClick={() => void test()}
            >
              <MailCheck aria-hidden="true" /> Run health check
            </Button>
            {health ? (
              <div className="notification-health" role="status">
                <strong>
                  {health.healthy ? "Provider healthy" : "Provider degraded"}
                </strong>
                <ul>
                  {health.checks.map((check) => (
                    <li key={check.kind}>
                      <span>{check.kind}</span>
                      <Badge
                        variant={
                          check.outcome === "failed" ? "destructive" : "outline"
                        }
                      >
                        {check.outcome}
                      </Badge>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </section>
        ) : null}
      </section>

      <form
        className="notification-editor"
        onSubmit={(event) => void save(event)}
      >
        <header>
          <div>
            <p className="section-label">
              {isInherited
                ? "Create tenant override"
                : "Append provider version"}
            </p>
            <h2>SMTP settings</h2>
          </div>
          {snapshot.versioned && !isInherited ? (
            <Badge variant="outline">{snapshot.versioned.etag}</Badge>
          ) : null}
        </header>
        <p className="notification-secret-note">
          <KeyRound aria-hidden="true" /> Passwords and DKIM private keys are
          write-only. Blank values retain the encrypted pin.
        </p>
        {actionError ? (
          <NotificationError
            error={actionError}
            fallback="The SMTP operation could not be completed."
          />
        ) : null}
        {notice ? (
          <p className="notification-notice" role="status">
            {notice}
          </p>
        ) : null}
        <div className="notification-form-grid">
          <FormField htmlFor={`${scope}-smtp-name`} label="Name">
            <Input
              id={`${scope}-smtp-name`}
              required
              maxLength={160}
              value={draft.name}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  name: event.target.value,
                }))
              }
            />
          </FormField>
          <FormField htmlFor={`${scope}-smtp-host`} label="Host">
            <Input
              id={`${scope}-smtp-host`}
              required
              maxLength={253}
              value={draft.host}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  host: event.target.value,
                }))
              }
            />
          </FormField>
          <FormField htmlFor={`${scope}-smtp-port`} label="Port">
            <Input
              id={`${scope}-smtp-port`}
              required
              type="number"
              min={1}
              max={65535}
              value={draft.port}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  port: Number(event.target.value),
                }))
              }
            />
          </FormField>
          <label>
            Security
            <select
              value={draft.security}
              onChange={(event) => {
                const security = parseSmtpSecurity(event.target.value);
                if (security) {
                  updateDraft((current) => ({ ...current, security }));
                }
              }}
            >
              <option value="tls">TLS</option>
              <option value="starttls">STARTTLS</option>
              <option value="plain_local">
                Plain local (development only)
              </option>
            </select>
          </label>
          <FormField
            htmlFor={`${scope}-smtp-username`}
            label="Username"
            optional
          >
            <Input
              id={`${scope}-smtp-username`}
              autoComplete="off"
              value={draft.username ?? ""}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  username: event.target.value || null,
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor={`${scope}-smtp-password`}
            label="New password"
            optional
            hint="Never returned by the API"
          >
            <Input
              id={`${scope}-smtp-password`}
              type="password"
              autoComplete="new-password"
              value={draft.password ?? ""}
              onChange={(event) =>
                updateDraft((current) =>
                  withPassword(current, event.target.value),
                )
              }
            />
          </FormField>
          <FormField htmlFor={`${scope}-smtp-from-name`} label="From name">
            <Input
              id={`${scope}-smtp-from-name`}
              required
              value={draft.fromName}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  fromName: event.target.value,
                }))
              }
            />
          </FormField>
          <FormField htmlFor={`${scope}-smtp-from-email`} label="From email">
            <Input
              id={`${scope}-smtp-from-email`}
              required
              type="email"
              value={draft.fromEmail}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  fromEmail: event.target.value,
                }))
              }
            />
          </FormField>
          <FormField htmlFor={`${scope}-smtp-reply`} label="Reply-to" optional>
            <Input
              id={`${scope}-smtp-reply`}
              type="email"
              value={draft.replyToEmail ?? ""}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  replyToEmail: event.target.value || null,
                }))
              }
            />
          </FormField>
          <FormField htmlFor={`${scope}-smtp-timeout`} label="Timeout (ms)">
            <Input
              id={`${scope}-smtp-timeout`}
              required
              type="number"
              min={100}
              value={draft.timeoutMs}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  timeoutMs: Number(event.target.value),
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor={`${scope}-smtp-connections`}
            label="Maximum connections"
          >
            <Input
              id={`${scope}-smtp-connections`}
              required
              type="number"
              min={1}
              value={draft.maximumConnections}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  maximumConnections: Number(event.target.value),
                }))
              }
            />
          </FormField>
          <FormField htmlFor={`${scope}-smtp-rate`} label="Rate / second">
            <Input
              id={`${scope}-smtp-rate`}
              required
              type="number"
              min={1}
              value={draft.rateLimitPerSecond}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  rateLimitPerSecond: Number(event.target.value),
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor={`${scope}-smtp-max-messages`}
            label="Messages / connection"
          >
            <Input
              id={`${scope}-smtp-max-messages`}
              required
              type="number"
              min={1}
              value={draft.maximumMessagesPerConnection}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  maximumMessagesPerConnection: Number(event.target.value),
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor={`${scope}-smtp-dkim-domain`}
            label="DKIM domain"
            optional
          >
            <Input
              id={`${scope}-smtp-dkim-domain`}
              value={draft.dkim?.domainName ?? ""}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  dkim: {
                    domainName: event.target.value,
                    selector: current.dkim?.selector ?? "",
                  },
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor={`${scope}-smtp-dkim-selector`}
            label="DKIM selector"
            optional
          >
            <Input
              id={`${scope}-smtp-dkim-selector`}
              value={draft.dkim?.selector ?? ""}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  dkim: {
                    domainName: current.dkim?.domainName ?? "",
                    selector: event.target.value,
                    ...(current.dkim?.privateKey
                      ? { privateKey: current.dkim.privateKey }
                      : {}),
                  },
                }))
              }
            />
          </FormField>
          <FormField
            htmlFor={`${scope}-smtp-dkim-key`}
            label="New DKIM private key"
            optional
            hint="Write-only; blank retains the pin"
          >
            <Input
              id={`${scope}-smtp-dkim-key`}
              type="password"
              autoComplete="new-password"
              value={draft.dkim?.privateKey ?? ""}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  dkim: {
                    domainName: current.dkim?.domainName ?? "",
                    selector: current.dkim?.selector ?? "",
                    ...(event.target.value
                      ? { privateKey: event.target.value }
                      : {}),
                  },
                }))
              }
            />
          </FormField>
        </div>
        <div className="notification-check-row">
          <label className="notification-check">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(event) =>
                updateDraft((current) => ({
                  ...current,
                  enabled: event.target.checked,
                }))
              }
            />{" "}
            Provider enabled
          </label>
          <label className="notification-check">
            <input
              type="checkbox"
              checked={draft.clearPassword}
              onChange={(event) =>
                updateDraft((current) =>
                  forgetWriteOnlySmtp({
                    ...current,
                    clearPassword: event.target.checked,
                    ...(event.target.checked ? { username: null } : {}),
                  }),
                )
              }
            />{" "}
            Remove password pin
          </label>
          <label className="notification-check">
            <input
              type="checkbox"
              checked={draft.clearDkim}
              onChange={(event) =>
                updateDraft((current) =>
                  withDkimCleared(current, event.target.checked),
                )
              }
            />{" "}
            Remove DKIM pin
          </label>
        </div>
        <EditorActions
          busy={busy === "save"}
          submitLabel={
            isInherited || snapshot.kind === "empty"
              ? "Create override"
              : "Append version"
          }
        >
          <Button
            type="button"
            variant="ghost"
            onClick={() => setRevision((value) => value + 1)}
          >
            Discard changes
          </Button>
        </EditorActions>
      </form>
    </div>
  );
}

function withPassword(
  value: SmtpConfigurationWriteWritable,
  password: string,
): SmtpConfigurationWriteWritable {
  const { password: _previous, ...safe } = value;
  return password ? { ...safe, password } : safe;
}

function withDkimCleared(
  value: SmtpConfigurationWriteWritable,
  clearDkim: boolean,
): SmtpConfigurationWriteWritable {
  const { dkim, ...withoutDkim } = value;
  return {
    ...withoutDkim,
    clearDkim,
    ...(!clearDkim && dkim ? { dkim } : {}),
  };
}

function parseSmtpSecurity(
  value: string,
): SmtpConfigurationWriteWritable["security"] | undefined {
  return value === "tls" || value === "starttls" || value === "plain_local"
    ? value
    : undefined;
}
