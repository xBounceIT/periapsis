import { useQuery, useQueryClient } from "@tanstack/react-query";
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
import { Input } from "@periapsis/ui/components/ui/input";
import {
  CheckCircle2,
  Globe2,
  Palette,
  RefreshCw,
  Save,
  ShieldCheck,
} from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type FormEvent,
} from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { ServerDenied } from "../components/server-denied";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
} from "../lib/phase-two-types";
import {
  normalizeTenantSettingsDraft,
  tenantSettingsChangedEvent,
  tenantSettingsDraftDiffers,
  tenantSettingsDraftErrors,
  tenantSettingsDraftFrom,
  tenantSettingsManagePermission,
  tenantSettingsQueryKey,
  tenantSettingsReadPermission,
  tenantSettingsReasonIsValid,
  type TenantSettingsApi,
  type TenantSettingsDraft,
  type TenantSettingsFieldErrors,
  type VersionedTenantSettings,
} from "./model";
import { tenantSettingsApi } from "./tenant-settings-api";
// oxlint-disable-next-line import/no-unassigned-import -- Page-scoped tenant identity styles.
import "./tenant-settings.css";

interface TenantSettingsPageProps {
  api?: TenantSettingsApi;
}

const emptyDraft: TenantSettingsDraft = {
  accentColor: "#4ea5b5",
  brandMark: "",
  brandName: "",
  locale: "",
  primaryColor: "#172230",
  timezone: "",
};

interface TenantPreviewStyle extends CSSProperties {
  "--tenant-preview-accent": string;
  "--tenant-preview-primary": string;
}

export function TenantSettingsPage({
  api = tenantSettingsApi,
}: TenantSettingsPageProps = {}): React.JSX.Element {
  const { clearSession, session } = useSession();
  const authority = useTenantAuthority();
  const queryClient = useQueryClient();
  const tenantId = session.activeTenantId;
  const canRead = authority.hasPermission(
    tenantSettingsReadPermission,
    "tenant",
  );
  const canManage = authority.hasPermission(
    tenantSettingsManagePermission,
    "tenant",
  );
  const pairKey = session.id + ":" + (tenantId ?? "inactive");
  const pairKeyRef = useRef(pairKey);
  pairKeyRef.current = pairKey;
  const loadedPairRef = useRef<string | null>(null);
  const [draft, setDraft] = useState<TenantSettingsDraft>(emptyDraft);
  const [fieldErrors, setFieldErrors] = useState<TenantSettingsFieldErrors>({});
  const [reason, setReason] = useState("");
  const [reasonError, setReasonError] = useState<string | null>(null);
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [isSaving, setIsSaving] = useState(false);
  const queryKey = tenantSettingsQueryKey(session.id, tenantId ?? "inactive");
  const settingsQuery = useQuery({
    queryKey,
    queryFn: ({ signal }) => api.get(tenantId ?? "", signal),
    enabled: authority.status === "ready" && Boolean(tenantId) && canRead,
    retry: false,
    staleTime: 30_000,
  });

  useEffect(() => {
    if (!settingsQuery.data) return;
    const changedTenant = loadedPairRef.current !== pairKey;
    loadedPairRef.current = pairKey;
    setDraft(tenantSettingsDraftFrom(settingsQuery.data.value));
    setFieldErrors({});
    setReason("");
    setReasonError(null);
    if (changedTenant) setMutationError(null);
  }, [pairKey, settingsQuery.data]);

  const previewStyle = useMemo<TenantPreviewStyle>(
    () => ({
      "--tenant-preview-accent": colorOrFallback(draft.accentColor, "#4ea5b5"),
      "--tenant-preview-primary": colorOrFallback(
        draft.primaryColor,
        "#172230",
      ),
    }),
    [draft.accentColor, draft.primaryColor],
  );

  function change(field: keyof TenantSettingsDraft, value: string): void {
    setDraft((current) => ({ ...current, [field]: value }));
    setFieldErrors((current) => ({ ...current, [field]: undefined }));
    setMutationError(null);
    setNotice(null);
  }

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const current = settingsQuery.data;
    if (!tenantId || !current || !canManage || isSaving) return;
    const normalized = normalizeTenantSettingsDraft(draft);
    if (!tenantSettingsDraftDiffers(current.value, normalized)) {
      setMutationError(null);
      setNotice(
        "No tenant identity values changed; no audit event was created.",
      );
      return;
    }
    const errors = tenantSettingsDraftErrors(normalized);
    const nextReasonError = tenantSettingsReasonIsValid(reason)
      ? null
      : "Use 1–500 visible ASCII characters, without commas or surrounding spaces.";
    setDraft(normalized);
    setFieldErrors(errors);
    setReasonError(nextReasonError);
    setMutationError(null);
    setNotice(null);
    if (Object.keys(errors).length > 0 || nextReasonError) return;

    const expectedPair = pairKey;
    setIsSaving(true);
    try {
      const updated = await api.update(
        session.csrfToken,
        tenantId,
        current,
        reason,
        normalized,
      );
      if (pairKeyRef.current !== expectedPair) return;
      queryClient.setQueryData<VersionedTenantSettings>(queryKey, updated);
      setDraft(tenantSettingsDraftFrom(updated.value));
      setReason("");
      setNotice(
        "Tenant identity updated. The server committed the new version and its audit event together.",
      );
      announceTenantSettingsChanged(tenantId);
    } catch (caught) {
      if (pairKeyRef.current !== expectedPair) return;
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        const refreshed = await settingsQuery.refetch();
        if (pairKeyRef.current !== expectedPair) return;
        setNotice(null);
        setMutationError(
          refreshed.data
            ? "Someone changed these settings first. The latest version is loaded; review it before saving again."
            : "Someone changed these settings first, and the latest version could not be reloaded.",
        );
        if (refreshed.data) announceTenantSettingsChanged(tenantId);
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 401) {
        clearSession(session.id);
      } else if (caught instanceof PhaseTwoApiError && caught.status === 403) {
        authority.reload();
      }
      setMutationError(
        describePhaseTwoError(
          caught,
          "Tenant settings could not be updated. No local success is assumed.",
        ),
      );
    } finally {
      if (pairKeyRef.current === expectedPair) setIsSaving(false);
    }
  }

  if (!tenantId || authority.status === "inactive") {
    return (
      <div className="content tenant-settings-page">
        <Card>
          <CardHeader>
            <CardTitle>
              Select a tenant to open its identity envelope.
            </CardTitle>
            <CardDescription>
              Branding and regional settings always belong to one explicit
              active tenant.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    );
  }
  if (authority.status === "forbidden" || !canRead) {
    return <ServerDenied resource="tenant branding and regional settings" />;
  }
  if (authority.status === "error") {
    return (
      <TenantSettingsLoadError
        message={authority.message ?? "Tenant authority could not be resolved."}
        onRetry={authority.reload}
      />
    );
  }
  if (authority.status !== "ready" || settingsQuery.isLoading) {
    return <TenantSettingsSkeleton />;
  }
  if (
    settingsQuery.error instanceof PhaseTwoApiError &&
    settingsQuery.error.status === 403
  ) {
    return <ServerDenied resource="tenant branding and regional settings" />;
  }
  if (!settingsQuery.data) {
    return (
      <TenantSettingsLoadError
        message={describePhaseTwoError(
          settingsQuery.error,
          "Tenant settings could not be loaded.",
        )}
        onRetry={() => void settingsQuery.refetch()}
      />
    );
  }

  const settings = settingsQuery.data.value;
  const hasChanges = tenantSettingsDraftDiffers(settings, draft);
  return (
    <div className="content tenant-settings-page">
      <section
        className="page-heading tenant-settings-page__heading"
        aria-labelledby="tenant-settings-title"
      >
        <div>
          <p className="section-label">Tenant administration / identity</p>
          <h1 id="tenant-settings-title">Identity envelope</h1>
          <p>
            Set the safe text mark, operational colors, timezone, and locale
            shown for this tenant. Remote logos are deliberately unsupported;
            every save is version-bound and audited by the backend.
          </p>
        </div>
        <Badge variant={canManage ? "default" : "secondary"}>
          {canManage ? "Manage access" : "Read-only access"}
        </Badge>
      </section>

      {notice ? (
        <Alert className="tenant-settings-page__notice">
          <CheckCircle2 aria-hidden="true" />
          <AlertTitle>Identity synchronized</AlertTitle>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}
      {mutationError ? (
        <FocusedError
          title="Tenant identity was not changed"
          message={mutationError}
        />
      ) : null}

      <div className="tenant-settings-layout">
        <aside
          className="tenant-brand-preview"
          style={previewStyle}
          aria-label="Tenant identity preview"
        >
          <div className="tenant-brand-preview__orbit" aria-hidden="true">
            <span />
          </div>
          <p className="tenant-brand-preview__label">Live shell preview</p>
          <div className="tenant-brand-preview__identity">
            <span className="tenant-brand-preview__mark" aria-hidden="true">
              {draft.brandMark || "—"}
            </span>
            <div>
              <strong>{draft.brandName || "Unnamed tenant"}</strong>
              <small>Incident operations</small>
            </div>
          </div>
          <dl>
            <div>
              <dt>
                <Globe2 aria-hidden="true" /> Regional clock
              </dt>
              <dd>{draft.timezone || "Timezone pending"}</dd>
            </div>
            <div>
              <dt>Interface locale</dt>
              <dd>{draft.locale || "Locale pending"}</dd>
            </div>
            <div>
              <dt>Committed version</dt>
              <dd>v{settings.version}</dd>
            </div>
          </dl>
        </aside>

        <Card className="tenant-settings-card">
          <CardHeader>
            <div className="tenant-settings-card__title">
              <span aria-hidden="true">
                <Palette />
              </span>
              <div>
                <CardTitle>Safe tenant presentation</CardTitle>
                <CardDescription>
                  Text and color values only. Server authorization and RLS are
                  re-evaluated independently of this form.
                </CardDescription>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <form className="tenant-settings-form" onSubmit={save} noValidate>
              <fieldset disabled={isSaving}>
                <legend className="sr-only">Tenant identity values</legend>
                <div className="tenant-settings-form__grid">
                  <FormField
                    htmlFor="tenant-brand-name"
                    label="Brand name"
                    {...(fieldErrors.brandName
                      ? { error: fieldErrors.brandName }
                      : {})}
                    hint="Displayed as plain text in the authenticated shell."
                  >
                    <Input
                      id="tenant-brand-name"
                      value={draft.brandName}
                      maxLength={80}
                      readOnly={!canManage}
                      aria-invalid={Boolean(fieldErrors.brandName)}
                      aria-describedby={
                        fieldErrors.brandName
                          ? "tenant-brand-name-error"
                          : "tenant-brand-name-hint"
                      }
                      onChange={(event) =>
                        change("brandName", event.currentTarget.value)
                      }
                    />
                  </FormField>
                  <FormField
                    htmlFor="tenant-brand-mark"
                    label="Text mark"
                    {...(fieldErrors.brandMark
                      ? { error: fieldErrors.brandMark }
                      : {})}
                    hint="One to four uppercase letters or digits; no image URL."
                  >
                    <Input
                      id="tenant-brand-mark"
                      value={draft.brandMark}
                      maxLength={4}
                      readOnly={!canManage}
                      className="tenant-settings-form__mark-input"
                      aria-invalid={Boolean(fieldErrors.brandMark)}
                      aria-describedby={
                        fieldErrors.brandMark
                          ? "tenant-brand-mark-error"
                          : "tenant-brand-mark-hint"
                      }
                      onChange={(event) =>
                        change(
                          "brandMark",
                          event.currentTarget.value.toUpperCase(),
                        )
                      }
                    />
                  </FormField>
                  <ColorField
                    id="tenant-primary-color"
                    label="Primary color"
                    value={draft.primaryColor}
                    error={fieldErrors.primaryColor}
                    readOnly={!canManage}
                    onChange={(value) => change("primaryColor", value)}
                  />
                  <ColorField
                    id="tenant-accent-color"
                    label="Accent color"
                    value={draft.accentColor}
                    error={fieldErrors.accentColor}
                    readOnly={!canManage}
                    onChange={(value) => change("accentColor", value)}
                  />
                  <FormField
                    htmlFor="tenant-timezone"
                    label="Timezone"
                    {...(fieldErrors.timezone
                      ? { error: fieldErrors.timezone }
                      : {})}
                    hint="Canonical IANA name; the server performs the final lookup."
                  >
                    <Input
                      id="tenant-timezone"
                      list="tenant-timezone-suggestions"
                      value={draft.timezone}
                      maxLength={64}
                      readOnly={!canManage}
                      aria-invalid={Boolean(fieldErrors.timezone)}
                      aria-describedby={
                        fieldErrors.timezone
                          ? "tenant-timezone-error"
                          : "tenant-timezone-hint"
                      }
                      onChange={(event) =>
                        change("timezone", event.currentTarget.value)
                      }
                    />
                    <datalist id="tenant-timezone-suggestions">
                      <option value="UTC" />
                      <option value="Europe/Rome" />
                      <option value="Europe/London" />
                      <option value="America/New_York" />
                      <option value="Asia/Singapore" />
                    </datalist>
                  </FormField>
                  <FormField
                    htmlFor="tenant-locale"
                    label="Locale"
                    {...(fieldErrors.locale
                      ? { error: fieldErrors.locale }
                      : {})}
                    hint="A BCP 47 tag, for example en-US or it-IT."
                  >
                    <Input
                      id="tenant-locale"
                      value={draft.locale}
                      maxLength={35}
                      readOnly={!canManage}
                      aria-invalid={Boolean(fieldErrors.locale)}
                      aria-describedby={
                        fieldErrors.locale
                          ? "tenant-locale-error"
                          : "tenant-locale-hint"
                      }
                      onChange={(event) =>
                        change("locale", event.currentTarget.value)
                      }
                    />
                  </FormField>
                </div>

                {canManage ? (
                  <div className="tenant-settings-form__commit">
                    <FormField
                      htmlFor="tenant-settings-reason"
                      label="Audit reason"
                      {...(reasonError ? { error: reasonError } : {})}
                      hint="Non-secret operational reason; recorded in tenant audit and never reflected."
                    >
                      <Input
                        id="tenant-settings-reason"
                        value={reason}
                        maxLength={500}
                        autoComplete="off"
                        aria-invalid={Boolean(reasonError)}
                        aria-describedby={
                          reasonError
                            ? "tenant-settings-reason-error"
                            : "tenant-settings-reason-hint"
                        }
                        onChange={(event) => {
                          setReason(event.currentTarget.value);
                          setReasonError(null);
                          setMutationError(null);
                        }}
                      />
                    </FormField>
                    <div className="tenant-settings-form__actions">
                      <p>
                        <ShieldCheck aria-hidden="true" /> Strong precondition{" "}
                        {settingsQuery.data.etag}
                      </p>
                      <Button type="submit" disabled={isSaving || !hasChanges}>
                        <Save aria-hidden="true" />
                        {isSaving ? "Committing…" : "Save identity"}
                      </Button>
                    </div>
                  </div>
                ) : (
                  <p className="tenant-settings-form__readonly">
                    Manage permission is required to change these values. The
                    fields remain visible for operational context.
                  </p>
                )}
              </fieldset>
            </form>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

function announceTenantSettingsChanged(tenantId: string): void {
  window.dispatchEvent(
    new CustomEvent(tenantSettingsChangedEvent, { detail: { tenantId } }),
  );
}

function ColorField({
  error,
  id,
  label,
  onChange,
  readOnly,
  value,
}: {
  error: string | undefined;
  id: string;
  label: string;
  onChange: (value: string) => void;
  readOnly: boolean;
  value: string;
}): React.JSX.Element {
  const safeColor = colorOrFallback(value, "#172230");
  return (
    <FormField
      htmlFor={id + "-text"}
      label={label}
      {...(error ? { error } : {})}
      hint="Lowercase six-digit hexadecimal value."
    >
      <div className="tenant-settings-color-field">
        <input
          id={id + "-picker"}
          type="color"
          value={safeColor}
          disabled={readOnly}
          aria-label={label + " picker"}
          onChange={(event) =>
            onChange(event.currentTarget.value.toLowerCase())
          }
        />
        <Input
          id={id + "-text"}
          value={value}
          maxLength={7}
          readOnly={readOnly}
          spellCheck={false}
          aria-invalid={Boolean(error)}
          aria-describedby={error ? id + "-text-error" : id + "-text-hint"}
          onChange={(event) => onChange(event.currentTarget.value)}
        />
      </div>
    </FormField>
  );
}

function TenantSettingsSkeleton(): React.JSX.Element {
  return (
    <div className="content tenant-settings-page" aria-busy="true">
      <Card>
        <CardHeader>
          <CardTitle>Loading tenant identity…</CardTitle>
          <CardDescription>
            Resolving live authority and the current versioned settings.
          </CardDescription>
        </CardHeader>
      </Card>
    </div>
  );
}

function TenantSettingsLoadError({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}): React.JSX.Element {
  return (
    <div className="content tenant-settings-page tenant-settings-page__error">
      <FocusedError message={message} />
      <Button type="button" variant="outline" onClick={onRetry}>
        <RefreshCw aria-hidden="true" /> Reload tenant identity
      </Button>
    </div>
  );
}

function colorOrFallback(value: string, fallback: string): string {
  return /^#[0-9a-f]{6}$/u.test(value) ? value : fallback;
}
