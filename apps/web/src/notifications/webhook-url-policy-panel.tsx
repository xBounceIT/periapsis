import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Input } from "@periapsis/ui/components/ui/input";
import type { WebhookUrlPolicy } from "@periapsis/contracts";
import { Plus, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
} from "react";

import { FormField } from "../components/form-field";
import type { NotificationAdminApi, Versioned } from "./notification-api";
import {
  EditorActions,
  NotificationError,
  NotificationLoading,
} from "./notification-primitives";
import {
  bindMutationAttempt,
  resetMutationAttempt,
  type MutationAttemptReference,
} from "./model";
import {
  prepareWebhookUrlPolicyRules,
  previewWebhookUrlPolicy,
  webhookUrlPolicyDraft,
  type WebhookUrlPolicyRuleDraft,
} from "./webhook-url-policy-model";

interface WebhookUrlPolicyPanelProps {
  api: NotificationAdminApi;
  csrfToken: string;
  tenantId: string;
}

export function WebhookUrlPolicyPanel({
  api,
  csrfToken,
  tenantId,
}: WebhookUrlPolicyPanelProps): React.JSX.Element {
  const [current, setCurrent] = useState<Versioned<WebhookUrlPolicy> | null>(
    null,
  );
  const [rules, setRules] = useState<WebhookUrlPolicyRuleDraft[]>(() =>
    webhookUrlPolicyDraft(null),
  );
  const [loading, setLoading] = useState(true);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [auditReason, setAuditReason] = useState("");
  const [previewEndpoint, setPreviewEndpoint] = useState("");
  const publishAttempt = useRef<MutationAttemptReference>({ current: null });

  const load = useCallback(
    async (signal?: AbortSignal): Promise<void> => {
      setLoading(true);
      setReady(false);
      setError(null);
      try {
        const loaded = await api.getWebhookUrlPolicy({
          tenantId,
          ...(signal ? { signal } : {}),
        });
        if (signal?.aborted) return;
        setCurrent(loaded);
        setRules(webhookUrlPolicyDraft(loaded?.value ?? null));
        setNotice(null);
        setReady(true);
        resetMutationAttempt(publishAttempt.current);
      } catch (caught: unknown) {
        if (!signal?.aborted) setError(caught);
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [api, tenantId],
  );

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const preview = useMemo(
    () => previewWebhookUrlPolicy(rules, previewEndpoint),
    [previewEndpoint, rules],
  );

  function updateRule(
    index: number,
    update: (current: WebhookUrlPolicyRuleDraft) => WebhookUrlPolicyRuleDraft,
  ): void {
    setRules((existing) =>
      existing.map((rule, ruleIndex) =>
        ruleIndex === index ? update(rule) : rule,
      ),
    );
  }

  function addRule(): void {
    if (rules.length >= 256) return;
    setRules((existing) => [
      ...existing,
      { effect: "allow", match: "exact", hostname: "", port: "443" },
    ]);
  }

  async function publish(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!ready) return;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const body = {
        expectedVersion: current?.value.version ?? 0,
        rules: prepareWebhookUrlPolicyRules(rules),
      };
      const saved = await api.publishWebhookUrlPolicy({
        auditReason,
        body,
        csrfToken,
        etag: current?.etag ?? '"v0"',
        idempotencyKey: bindMutationAttempt(
          publishAttempt.current,
          "webhook-url-policy.publish",
          tenantId,
          { auditReason, body },
        ),
        tenantId,
      });
      if (saved.replayed) setReady(false);
      const visible = saved.replayed
        ? await api.getWebhookUrlPolicy({ tenantId })
        : { etag: saved.etag, value: saved.value };
      if (visible === null) {
        throw new TypeError(
          "The replayed webhook policy no longer has a current lineage.",
        );
      }
      setCurrent(visible);
      setRules(webhookUrlPolicyDraft(visible.value));
      setReady(true);
      setAuditReason("");
      setNotice(
        saved.replayed
          ? `Policy version ${saved.value.version} was already published; its exact result was replayed and current version ${visible.value.version} was reloaded.`
          : `Policy version ${saved.value.version} is current. Existing webhook configurations must be versioned against it.`,
      );
      resetMutationAttempt(publishAttempt.current);
    } catch (caught: unknown) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="notification-policy-layout">
      <section className="notification-provider-summary" aria-busy={loading}>
        <header className="notification-policy-heading">
          <div className="notification-provider-summary__title">
            <span className="notification-provider-icon">
              <ShieldCheck aria-hidden="true" />
            </span>
            <div>
              <p className="section-label">Outbound boundary</p>
              <h2>Webhook egress policy</h2>
            </div>
          </div>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={loading || busy}
            onClick={() => void load()}
          >
            <RefreshCw aria-hidden="true" /> Refresh
          </Button>
        </header>
        {loading ? (
          <NotificationLoading label="Loading webhook URL policy" />
        ) : null}
        {!loading ? (
          <dl className="notification-definition-list">
            <div>
              <dt>Current version</dt>
              <dd>{current ? `v${current.value.version}` : "Not published"}</dd>
            </div>
            <div>
              <dt>Protocol</dt>
              <dd>HTTPS only</dd>
            </div>
            <div>
              <dt>Default</dt>
              <dd>Deny</dd>
            </div>
            <div>
              <dt>Rules</dt>
              <dd>{current?.value.rules.length ?? 0}</dd>
            </div>
          </dl>
        ) : null}
        <p className="notification-secret-note">
          Publishing creates an immutable version and fences every older webhook
          configuration pin. Append a webhook configuration version under the
          new policy before delivery resumes.
        </p>
        <div className="notification-toolbox">
          <h3>Advisory endpoint preview</h3>
          <p>
            This browser preview never authorizes egress. The API and notifier
            re-evaluate the immutable policy and DNS-safe connector boundary.
          </p>
          <FormField htmlFor="webhook-policy-preview" label="HTTPS endpoint">
            <Input
              id="webhook-policy-preview"
              type="url"
              maxLength={2048}
              placeholder="https://hooks.example.com/periapsis"
              value={previewEndpoint}
              onChange={(event) => setPreviewEndpoint(event.target.value)}
            />
          </FormField>
          {previewEndpoint ? (
            <p className="notification-policy-preview" role="status">
              <Badge variant={preview.allowed ? "secondary" : "outline"}>
                {preview.allowed ? "Would allow" : "Would deny"}
              </Badge>
              <span>
                {preview.reason === "invalid"
                  ? "Endpoint or draft rule is not canonical."
                  : preview.reason === "default_deny"
                    ? "No rule matched; default deny applies."
                    : `${preview.reason === "denied_by_rule" ? "Deny" : "Allow"} rule ${(preview.ruleIndex ?? 0) + 1} matched.`}
              </span>
            </p>
          ) : null}
        </div>
      </section>

      <section
        className="notification-editor"
        aria-label="Webhook egress policy editor"
      >
        <form onSubmit={(event) => void publish(event)}>
          <header>
            <div>
              <p className="section-label">Immutable policy version</p>
              <h2>
                {current
                  ? `Publish version ${current.value.version + 1}`
                  : "Publish initial policy"}
              </h2>
            </div>
            <Badge variant="outline">{current?.etag ?? '"v0"'}</Badge>
          </header>
          {error ? (
            <NotificationError
              error={error}
              fallback="The webhook URL policy action could not be completed."
            />
          ) : null}
          {notice ? (
            <p className="notification-notice" role="status">
              {notice}
            </p>
          ) : null}

          <div className="notification-policy-rules">
            {rules.map((rule, index) => (
              <fieldset key={index} className="notification-policy-rule">
                <legend>Rule {index + 1}</legend>
                <label htmlFor={`webhook-policy-effect-${index}`}>
                  Effect
                  <select
                    id={`webhook-policy-effect-${index}`}
                    value={rule.effect}
                    onChange={(event) =>
                      updateRule(index, (currentRule) => ({
                        ...currentRule,
                        effect:
                          event.target.value === "deny" ? "deny" : "allow",
                      }))
                    }
                  >
                    <option value="allow">Allow</option>
                    <option value="deny">Deny</option>
                  </select>
                </label>
                <label htmlFor={`webhook-policy-match-${index}`}>
                  Match
                  <select
                    id={`webhook-policy-match-${index}`}
                    value={rule.match}
                    onChange={(event) =>
                      updateRule(index, (currentRule) => ({
                        ...currentRule,
                        match:
                          event.target.value === "subdomains"
                            ? "subdomains"
                            : "exact",
                      }))
                    }
                  >
                    <option value="exact">Exact host</option>
                    <option value="subdomains">Subdomains only</option>
                  </select>
                </label>
                <FormField
                  htmlFor={`webhook-policy-hostname-${index}`}
                  label="DNS hostname"
                  hint="No scheme, wildcard, path, IP literal, or trailing dot"
                >
                  <Input
                    id={`webhook-policy-hostname-${index}`}
                    required
                    maxLength={253}
                    value={rule.hostname}
                    onChange={(event) =>
                      updateRule(index, (currentRule) => ({
                        ...currentRule,
                        hostname: event.target.value,
                      }))
                    }
                  />
                </FormField>
                <FormField
                  htmlFor={`webhook-policy-port-${index}`}
                  label="Port"
                >
                  <Input
                    id={`webhook-policy-port-${index}`}
                    type="number"
                    required
                    min={1}
                    max={65_535}
                    value={rule.port}
                    onChange={(event) =>
                      updateRule(index, (currentRule) => ({
                        ...currentRule,
                        port: event.target.value,
                      }))
                    }
                  />
                </FormField>
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  disabled={busy}
                  aria-label={`Remove rule ${index + 1}`}
                  onClick={() =>
                    setRules((existing) =>
                      existing.filter((_, ruleIndex) => ruleIndex !== index),
                    )
                  }
                >
                  <Trash2 aria-hidden="true" /> Remove
                </Button>
              </fieldset>
            ))}
          </div>
          <Button
            type="button"
            size="sm"
            variant="outline"
            disabled={busy || rules.length >= 256}
            onClick={addRule}
          >
            <Plus aria-hidden="true" /> Add rule
          </Button>
          <FormField
            htmlFor="webhook-policy-reason"
            label="Audited reason"
            hint="Do not include URLs, hostnames, credentials, personal identifiers, or customer data"
          >
            <Input
              id="webhook-policy-reason"
              required
              maxLength={2048}
              value={auditReason}
              onChange={(event) => setAuditReason(event.target.value)}
            />
          </FormField>
          <EditorActions
            busy={busy || loading || !ready}
            submitLabel={
              current ? "Publish next version" : "Publish initial policy"
            }
          />
        </form>
      </section>
    </div>
  );
}
