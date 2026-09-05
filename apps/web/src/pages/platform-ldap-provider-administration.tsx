import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Badge } from "@periapsis/ui/components/ui/badge";
import { Button } from "@periapsis/ui/components/ui/button";
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Label } from "@periapsis/ui/components/ui/label";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  FlaskConical,
  KeyRound,
  Network,
  Save,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import {
  describePhaseTwoError,
  PhaseTwoApiError,
  type PhaseTwoApi,
  type PlatformLdapAuthProviderView,
  type PlatformLdapDiagnosticView,
  type VersionedView,
} from "../lib/phase-two-types";
import { generateUuidV7, isCanonicalUuidV7 } from "../lib/uuid-v7";
import {
  validateBindSecret,
  validateLdapProviderDraft,
  type LdapProviderDraft,
} from "./ldap-provider-model";
import { LdapProviderEditor } from "./tenant-ldap-providers";
import { validatePlatformAuthProviderAuditReason } from "./platform-auth-provider-model";

interface Notice {
  message: string;
  tone: "success" | "warning";
}

type PlatformEndpointDraft = PlatformLdapAuthProviderView["endpoints"][number];

interface PlatformLdapDraft extends Omit<LdapProviderDraft, "endpoints"> {
  endpoints: PlatformEndpointDraft[];
}

interface MappingDraft {
  caseSensitive: boolean;
  enabled: boolean;
  expectedVersion?: number;
  id: string;
  matcherType: "exact_cn" | "exact_dn" | "regex";
  matcherValue: string;
  notes: string;
  platformRoleId: string;
  priority: number;
  reconciliationMode: "additive" | "authoritative";
}

interface Props {
  api: PhaseTwoApi;
  canManageConfiguration: boolean;
  canManagePolicy: boolean;
  canTest: boolean;
  csrfToken: string;
  current: VersionedView<PlatformLdapAuthProviderView>;
  onChanged: () => void;
  onMutationBusyChange: (busy: boolean) => void;
  onNotice: (notice: Notice) => void;
  onPermissionError: () => void;
  onProviderProjectionStale: () => void;
  onUnauthenticated: () => void;
  providerMutationBusy: boolean;
  sessionId: string;
}

type BusyKind = "configuration" | "diagnostic" | "login" | "mapping" | "secret";
type TestKind =
  "bind" | "connection" | "filter" | "mapping_dry_run" | "search_user";

export function PlatformLdapProviderAdministration({
  api,
  canManageConfiguration,
  canManagePolicy,
  canTest,
  csrfToken,
  current,
  onChanged,
  onMutationBusyChange,
  onNotice,
  onPermissionError,
  onProviderProjectionStale,
  onUnauthenticated,
  providerMutationBusy,
  sessionId,
}: Props): React.JSX.Element {
  const [configurationDraft, setConfigurationDraft] = useState(() =>
    draftFromProvider(current.value),
  );
  const [configurationReason, setConfigurationReason] = useState("");
  const [bindSecret, setBindSecret] = useState("");
  const [secretReason, setSecretReason] = useState("");
  const [mappingDraft, setMappingDraft] =
    useState<MappingDraft>(newMappingDraft);
  const [mappingReason, setMappingReason] = useState("");
  const [testKind, setTestKind] = useState<TestKind>("connection");
  const [testUsername, setTestUsername] = useState("");
  const [testReason, setTestReason] = useState("");
  const [diagnostic, setDiagnostic] =
    useState<PlatformLdapDiagnosticView | null>(null);
  const [loginReason, setLoginReason] = useState("");
  const [loginConfirmation, setLoginConfirmation] = useState("");
  const [busy, setBusy] = useState<BusyKind | null>(null);
  const [error, setError] = useState<string | null>(null);
  const mountedRef = useRef(true);
  const sessionRef = useRef(sessionId);
  const testAbortRef = useRef<AbortController | null>(null);
  sessionRef.current = sessionId;

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      testAbortRef.current?.abort();
      onMutationBusyChange(false);
    };
  }, [onMutationBusyChange]);

  useEffect(() => {
    testAbortRef.current?.abort();
    testAbortRef.current = null;
    setConfigurationDraft(draftFromProvider(current.value));
    setConfigurationReason("");
    setBindSecret("");
    setSecretReason("");
    setMappingDraft(newMappingDraft());
    setMappingReason("");
    setTestKind("connection");
    setTestUsername("");
    setTestReason("");
    setDiagnostic(null);
    setLoginReason("");
    setLoginConfirmation("");
    setError(null);
  }, [current.value, sessionId]);

  const actionBlocked = providerMutationBusy || busy !== null;
  const requiresUsername = !["bind", "connection"].includes(testKind);
  const activeMappings = useMemo(
    () =>
      current.value.mappings.filter((mapping) => mapping.archivedAt === null),
    [current.value.mappings],
  );

  function begin(kind: BusyKind): boolean {
    if (actionBlocked) return false;
    setBusy(kind);
    setError(null);
    onMutationBusyChange(true);
    return true;
  }

  function finish(): void {
    if (!mountedRef.current) return;
    setBusy(null);
    onMutationBusyChange(false);
  }

  function handleFailure(caught: unknown, fallback: string): void {
    if (!mountedRef.current) return;
    if (caught instanceof PhaseTwoApiError && caught.status === 401) {
      onUnauthenticated();
      return;
    }
    if (caught instanceof PhaseTwoApiError && caught.status === 403) {
      onPermissionError();
    }
    if (
      caught instanceof PhaseTwoApiError &&
      (caught.status === 409 || caught.status === 412)
    ) {
      onProviderProjectionStale();
      onChanged();
    }
    setError(describePhaseTwoError(caught, fallback));
  }

  function acceptMutation(message: string): void {
    onNotice({ message, tone: "success" });
    onProviderProjectionStale();
    onChanged();
  }

  async function saveConfiguration(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManageConfiguration) return;
    const errors = [
      ...validateLdapProviderDraft(configurationDraft, "platform_global"),
    ];
    const reasonError =
      validatePlatformAuthProviderAuditReason(configurationReason);
    if (reasonError) errors.push(reasonError);
    if (errors.length > 0) {
      setError(errors.join(" "));
      return;
    }
    if (!begin("configuration")) return;
    try {
      await api.updatePlatformLdapAuthProvider(
        csrfToken,
        current.value.id,
        current,
        configurationReason,
        {
          configuration: {
            ...configurationDraft.configuration,
            jitMode: "existing_identity",
            noMatchPolicy: "deny",
          },
          description: configurationDraft.description,
          displayName: configurationDraft.displayName,
          endpoints: configurationDraft.endpoints.map((endpoint) => ({
            ...endpoint,
          })),
          expectedVersion: current.value.version,
          key: configurationDraft.key,
        },
      );
      acceptMutation(
        "The LDAP configuration was replaced at its exact provider version; existing sessions will be revalidated against the new revisions.",
      );
    } catch (caught) {
      handleFailure(caught, "The LDAP configuration was not updated.");
    } finally {
      finish();
    }
  }

  async function replaceSecret(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManageConfiguration) return;
    const secretError = validateBindSecret(bindSecret);
    const reasonError = validatePlatformAuthProviderAuditReason(secretReason);
    if (secretError || reasonError) {
      setError(secretError ?? reasonError);
      return;
    }
    if (!begin("secret")) return;
    const oneUseSecret = bindSecret;
    setBindSecret("");
    try {
      await api.replacePlatformLdapBindSecret(
        csrfToken,
        current.value.id,
        current,
        secretReason,
        { bindSecret: oneUseSecret, expectedVersion: current.value.version },
      );
      acceptMutation(
        "The LDAP bind secret was encrypted and rotated without readback. Existing LDAP sessions are now subject to revision revalidation.",
      );
    } catch (caught) {
      handleFailure(caught, "The write-only bind secret was not replaced.");
    } finally {
      finish();
    }
  }

  async function saveMapping(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManagePolicy) return;
    const reasonError = validatePlatformAuthProviderAuditReason(mappingReason);
    if (
      !isCanonicalUuidV7(mappingDraft.id) ||
      !isCanonicalUuidV7(mappingDraft.platformRoleId) ||
      mappingDraft.matcherValue.trim() === "" ||
      mappingDraft.matcherValue.length > 2048 ||
      mappingDraft.notes.length > 1000 ||
      !Number.isSafeInteger(mappingDraft.priority) ||
      mappingDraft.priority < 0 ||
      mappingDraft.priority > 1_000_000 ||
      reasonError
    ) {
      setError(
        reasonError ??
          "Mapping IDs, matcher, priority, role, and notes must satisfy the bounded LDAP policy.",
      );
      return;
    }
    if (!begin("mapping")) return;
    try {
      await api.putPlatformLdapMapping(
        csrfToken,
        current.value.id,
        mappingDraft.id,
        current,
        mappingReason,
        {
          caseSensitive: mappingDraft.caseSensitive,
          enabled: mappingDraft.enabled,
          ...(mappingDraft.expectedVersion === undefined
            ? {}
            : { expectedVersion: mappingDraft.expectedVersion }),
          matcherType: mappingDraft.matcherType,
          matcherValue: mappingDraft.matcherValue,
          notes: mappingDraft.notes,
          platformRoleId: mappingDraft.platformRoleId,
          priority: mappingDraft.priority,
          reconciliationMode: mappingDraft.reconciliationMode,
        },
      );
      acceptMutation(
        "The source-owned LDAP role mapping was saved. The server rejected any super-admin target and advanced the authorization plan revision.",
      );
    } catch (caught) {
      handleFailure(caught, "The LDAP role mapping was not saved.");
    } finally {
      finish();
    }
  }

  async function runDiagnostic(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canTest || (requiresUsername && testUsername.trim() === "")) {
      setError(
        requiresUsername
          ? "Enter the test username."
          : "LDAP test permission is required.",
      );
      return;
    }
    const reasonError = validatePlatformAuthProviderAuditReason(testReason);
    if (reasonError) {
      setError(reasonError);
      return;
    }
    if (!begin("diagnostic")) return;
    const expectedSessionId = sessionId;
    const controller = new AbortController();
    testAbortRef.current?.abort();
    testAbortRef.current = controller;
    try {
      const result = await api.testPlatformLdapProvider(
        csrfToken,
        current.value.id,
        testReason,
        {
          kind: testKind,
          ...(requiresUsername ? { username: testUsername } : {}),
        },
        controller.signal,
      );
      if (
        mountedRef.current &&
        sessionRef.current === expectedSessionId &&
        !controller.signal.aborted
      ) {
        setDiagnostic(result);
      }
    } catch (caught) {
      if (!(caught instanceof DOMException && caught.name === "AbortError")) {
        handleFailure(caught, "The redacted LDAP diagnostic did not complete.");
      }
    } finally {
      if (testAbortRef.current === controller) testAbortRef.current = null;
      finish();
    }
  }

  async function changeLoginState(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!canManagePolicy) return;
    const reasonError = validatePlatformAuthProviderAuditReason(loginReason);
    if (reasonError || loginConfirmation !== current.value.key) {
      setError(
        reasonError ??
          `Type ${current.value.key} to confirm the direct-login transition.`,
      );
      return;
    }
    if (!begin("login")) return;
    const enabled = !current.value.platformLoginEnabled;
    try {
      await api.setPlatformLdapLoginState(
        csrfToken,
        current.value.id,
        current,
        loginReason,
        { enabled, expectedVersion: current.value.version },
      );
      acceptMutation(
        `Direct platform LDAP login was ${enabled ? "enabled" : "disabled"}. Existing-identity linking still requires directory proof and mandatory local TOTP.`,
      );
    } catch (caught) {
      handleFailure(caught, "The direct LDAP login state was not changed.");
    } finally {
      finish();
    }
  }

  return (
    <section
      className="platform-idp-actions"
      aria-labelledby="platform-ldap-admin-title"
    >
      <div className="platform-idp-section-heading">
        <div>
          <p className="section-label">Platform-global directory authority</p>
          <h3 id="platform-ldap-admin-title">LDAP administration</h3>
        </div>
        <Badge variant="outline">
          <Network aria-hidden="true" /> Tenantless login
        </Badge>
      </div>

      <Alert>
        <ShieldCheck aria-hidden="true" />
        <AlertTitle>Existing identities only</AlertTitle>
        <AlertDescription>
          Successful LDAP proof never creates a user. First link and every login
          require an existing active user, a live non-super-admin role mapping,
          and that user&apos;s active local TOTP factor.
        </AlertDescription>
      </Alert>

      {error ? <FocusedError message={error} /> : null}

      <details>
        <summary>Replace LDAP configuration and endpoints</summary>
        <form
          className="platform-idp-form"
          onSubmit={(event) => void saveConfiguration(event)}
        >
          <LdapProviderEditor
            draft={configurationDraft}
            manageEnabled={false}
            mode="update"
            policy="platform_global"
            onChange={(draft) => setConfigurationDraft(withEndpointIds(draft))}
          />
          <ReasonField
            id="platform-ldap-configuration-reason"
            value={configurationReason}
            onChange={setConfigurationReason}
          />
          <Button
            type="submit"
            disabled={!canManageConfiguration || actionBlocked}
          >
            <Save aria-hidden="true" />{" "}
            {busy === "configuration" ? "Saving…" : "Save configuration"}
          </Button>
        </form>
      </details>

      <form
        className="platform-idp-form"
        onSubmit={(event) => void replaceSecret(event)}
      >
        <h4>Write-only bind secret</h4>
        <FormField
          htmlFor="platform-ldap-bind-secret"
          label="New bind secret"
          hint="Cleared from the form before the network request and never returned."
        >
          <Input
            id="platform-ldap-bind-secret"
            type="password"
            autoComplete="new-password"
            value={bindSecret}
            onChange={(event) => setBindSecret(event.currentTarget.value)}
          />
        </FormField>
        <ReasonField
          id="platform-ldap-secret-reason"
          value={secretReason}
          onChange={setSecretReason}
        />
        <Button
          type="submit"
          disabled={!canManageConfiguration || actionBlocked}
        >
          <KeyRound aria-hidden="true" />{" "}
          {busy === "secret" ? "Rotating…" : "Rotate bind secret"}
        </Button>
      </form>

      <div>
        <h4>Source-owned platform role mappings</h4>
        {activeMappings.length === 0 ? (
          <p>No live mappings are configured.</p>
        ) : (
          <div className="platform-idp-account-list">
            {activeMappings.map((mapping) => (
              <div key={mapping.id} className="platform-idp-account-row">
                <span>
                  <strong>{mapping.matcherType}</strong>
                  <code>{mapping.matcherValue}</code>
                </span>
                <span>
                  <small>Role</small>
                  <code>{mapping.platformRoleId}</code>
                </span>
                <Badge variant="outline">
                  {mapping.enabled ? "Enabled" : "Disabled"}
                </Badge>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={actionBlocked || !canManagePolicy}
                  onClick={() =>
                    setMappingDraft({
                      caseSensitive: mapping.caseSensitive,
                      enabled: mapping.enabled,
                      expectedVersion: mapping.version,
                      id: mapping.id,
                      matcherType: mapping.matcherType,
                      matcherValue: mapping.matcherValue,
                      notes: mapping.notes,
                      platformRoleId: mapping.platformRoleId,
                      priority: mapping.priority,
                      reconciliationMode: mapping.reconciliationMode,
                    })
                  }
                >
                  Edit
                </Button>
              </div>
            ))}
          </div>
        )}
        <form
          className="platform-idp-form"
          onSubmit={(event) => void saveMapping(event)}
        >
          <div className="platform-idp-form-grid">
            <FormField
              htmlFor="platform-ldap-mapping-id"
              label="Mapping UUIDv7"
            >
              <Input
                id="platform-ldap-mapping-id"
                readOnly
                value={mappingDraft.id}
              />
            </FormField>
            <FormField
              htmlFor="platform-ldap-role-id"
              label="Platform role UUIDv7"
              hint="The server denies platform_super_admin even when its ID is supplied."
            >
              <Input
                id="platform-ldap-role-id"
                value={mappingDraft.platformRoleId}
                onChange={(event) =>
                  setMappingDraft({
                    ...mappingDraft,
                    platformRoleId: event.currentTarget.value,
                  })
                }
              />
            </FormField>
            <SelectField
              id="platform-ldap-matcher-type"
              label="Matcher"
              value={mappingDraft.matcherType}
              onChange={(matcherType) =>
                setMappingDraft({ ...mappingDraft, matcherType })
              }
              options={[
                ["exact_dn", "Exact DN"],
                ["exact_cn", "Exact CN"],
                ["regex", "Regular expression"],
              ]}
            />
            <FormField
              htmlFor="platform-ldap-matcher-value"
              label="Matcher value"
            >
              <Input
                id="platform-ldap-matcher-value"
                value={mappingDraft.matcherValue}
                onChange={(event) =>
                  setMappingDraft({
                    ...mappingDraft,
                    matcherValue: event.currentTarget.value,
                  })
                }
              />
            </FormField>
            <FormField
              htmlFor="platform-ldap-mapping-priority"
              label="Priority"
            >
              <Input
                id="platform-ldap-mapping-priority"
                type="number"
                min={0}
                max={1_000_000}
                value={mappingDraft.priority}
                onChange={(event) =>
                  setMappingDraft({
                    ...mappingDraft,
                    priority: Number(event.currentTarget.value),
                  })
                }
              />
            </FormField>
            <SelectField
              id="platform-ldap-reconciliation"
              label="Reconciliation"
              value={mappingDraft.reconciliationMode}
              onChange={(reconciliationMode) =>
                setMappingDraft({ ...mappingDraft, reconciliationMode })
              }
              options={[
                ["authoritative", "Authoritative"],
                ["additive", "Additive"],
              ]}
            />
          </div>
          <label className="platform-idp-checkbox-row">
            <Checkbox
              checked={mappingDraft.caseSensitive}
              onCheckedChange={(value) =>
                setMappingDraft({
                  ...mappingDraft,
                  caseSensitive: value === true,
                })
              }
            />{" "}
            Case-sensitive match
          </label>
          <label className="platform-idp-checkbox-row">
            <Checkbox
              checked={mappingDraft.enabled}
              onCheckedChange={(value) =>
                setMappingDraft({ ...mappingDraft, enabled: value === true })
              }
            />{" "}
            Mapping enabled
          </label>
          <FormField
            htmlFor="platform-ldap-mapping-notes"
            label="Notes"
            optional
          >
            <Textarea
              id="platform-ldap-mapping-notes"
              maxLength={1000}
              value={mappingDraft.notes}
              onChange={(event) =>
                setMappingDraft({
                  ...mappingDraft,
                  notes: event.currentTarget.value,
                })
              }
            />
          </FormField>
          <ReasonField
            id="platform-ldap-mapping-reason"
            value={mappingReason}
            onChange={setMappingReason}
          />
          <div className="platform-idp-action-row">
            <Button type="submit" disabled={!canManagePolicy || actionBlocked}>
              <Save aria-hidden="true" />{" "}
              {busy === "mapping"
                ? "Saving…"
                : mappingDraft.expectedVersion
                  ? "Replace mapping"
                  : "Create mapping"}
            </Button>
            <Button
              type="button"
              variant="outline"
              disabled={actionBlocked}
              onClick={() => setMappingDraft(newMappingDraft())}
            >
              New mapping
            </Button>
          </div>
        </form>
      </div>

      <form
        className="platform-idp-form"
        onSubmit={(event) => void runDiagnostic(event)}
      >
        <h4>Redacted live diagnostic</h4>
        <div className="platform-idp-form-grid">
          <SelectField
            id="platform-ldap-test-kind"
            label="Test"
            value={testKind}
            onChange={(value) => {
              setTestKind(value);
              setDiagnostic(null);
            }}
            options={[
              ["connection", "Connection"],
              ["bind", "Bind"],
              ["search_user", "User search"],
              ["filter", "Filter"],
              ["mapping_dry_run", "Mapping dry run"],
            ]}
          />
          {requiresUsername ? (
            <FormField
              htmlFor="platform-ldap-test-username"
              label="Directory username"
            >
              <Input
                id="platform-ldap-test-username"
                maxLength={512}
                value={testUsername}
                onChange={(event) => setTestUsername(event.currentTarget.value)}
              />
            </FormField>
          ) : null}
        </div>
        <ReasonField
          id="platform-ldap-test-reason"
          value={testReason}
          onChange={setTestReason}
        />
        <Button type="submit" disabled={!canTest || actionBlocked}>
          <FlaskConical aria-hidden="true" />{" "}
          {busy === "diagnostic" ? "Testing…" : "Run live test"}
        </Button>
        {diagnostic ? (
          <Alert>
            <AlertTitle>
              {diagnostic.outcome === "success"
                ? "Test succeeded"
                : "Test failed"}
            </AlertTitle>
            <AlertDescription>
              {diagnostic.category} · {diagnostic.durationMs} ms
              {diagnostic.endpointPriority
                ? ` · endpoint ${diagnostic.endpointPriority}`
                : ""}
              {diagnostic.matchedEntryCount !== undefined &&
              diagnostic.matchedEntryCount !== null
                ? ` · ${diagnostic.matchedEntryCount} entries`
                : ""}
              {diagnostic.attributes.length > 0
                ? ` · attributes: ${diagnostic.attributes.join(", ")}`
                : ""}
            </AlertDescription>
          </Alert>
        ) : null}
      </form>

      <form
        className="platform-idp-form"
        onSubmit={(event) => void changeLoginState(event)}
      >
        <h4>
          {current.value.platformLoginEnabled ? "Disable" : "Enable"} tenantless
          LDAP login
        </h4>
        <p>
          {current.value.platformLoginEnabled
            ? "Disabling advances security authority and forces existing LDAP-backed sessions through revalidation."
            : "Activation is accepted only when an enabled endpoint, current bind secret, and at least one enabled non-super-admin mapping remain live."}
        </p>
        <ReasonField
          id="platform-ldap-login-reason"
          value={loginReason}
          onChange={setLoginReason}
        />
        <FormField
          htmlFor="platform-ldap-login-confirmation"
          label={`Type ${current.value.key} to confirm`}
        >
          <Input
            id="platform-ldap-login-confirmation"
            autoComplete="off"
            value={loginConfirmation}
            onChange={(event) =>
              setLoginConfirmation(event.currentTarget.value)
            }
          />
        </FormField>
        <Button
          type="submit"
          variant={
            current.value.platformLoginEnabled ? "destructive" : "default"
          }
          disabled={!canManagePolicy || actionBlocked}
        >
          {busy === "login"
            ? "Applying…"
            : current.value.platformLoginEnabled
              ? "Disable LDAP login"
              : "Enable LDAP login"}
        </Button>
      </form>
    </section>
  );
}

function draftFromProvider(
  provider: PlatformLdapAuthProviderView,
): PlatformLdapDraft {
  return {
    configuration: { ...provider.configuration },
    description: provider.description,
    displayName: provider.displayName,
    enabled: provider.enabled,
    endpoints: provider.endpoints.map((endpoint) => ({ ...endpoint })),
    key: provider.key,
  };
}

function withEndpointIds(draft: LdapProviderDraft): PlatformLdapDraft {
  return {
    ...draft,
    endpoints: draft.endpoints.map((endpoint) => ({
      ...endpoint,
      id:
        "id" in endpoint && isCanonicalUuidV7(endpoint.id)
          ? endpoint.id
          : generateUuidV7(),
    })),
  };
}

function newMappingDraft(): MappingDraft {
  return {
    caseSensitive: false,
    enabled: true,
    id: generateUuidV7(),
    matcherType: "exact_dn",
    matcherValue: "",
    notes: "",
    platformRoleId: "",
    priority: 100,
    reconciliationMode: "authoritative",
  };
}

function ReasonField({
  id,
  onChange,
  value,
}: {
  id: string;
  onChange: (value: string) => void;
  value: string;
}): React.JSX.Element {
  return (
    <FormField
      htmlFor={id}
      label="Audit reason"
      hint="Non-secret administrative reason; never include credentials, subjects, or directory data."
    >
      <Input
        id={id}
        maxLength={500}
        value={value}
        onChange={(event) => onChange(event.currentTarget.value)}
      />
    </FormField>
  );
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
    <div className="form-field">
      <Label htmlFor={id}>{label}</Label>
      <select
        className="native-select"
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
    </div>
  );
}
