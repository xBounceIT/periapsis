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
  KeyRound,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type PlatformAuthProviderView,
  type VersionedView,
} from "../lib/phase-two-types";
import { validatePlatformAuthProviderAuditReason } from "./platform-auth-provider-model";
import {
  parsePlatformSamlSpKeyMaterial,
  validatePlatformSamlMetadataMaterial,
  type PlatformSamlMetadataSource,
} from "./platform-auth-provider-saml-material-model";

type PlatformSamlProviderView = Extract<
  PlatformAuthProviderView,
  { kind: "saml" }
>;
type PlatformSamlMaterialMode = "clear" | "metadata" | "sp-key" | null;
type PlatformSamlMaterialMutation = Exclude<PlatformSamlMaterialMode, null>;

interface PlatformAuthProviderSamlMaterialsProps {
  api: PhaseTwoApi;
  canManage: boolean;
  csrfToken: string;
  current: VersionedView<PlatformSamlProviderView>;
  onChanged: () => void;
  onMutationBusyChange: (busy: boolean) => void;
  onNotice: (notice: { message: string; tone: "success" | "warning" }) => void;
  onPermissionError: () => void;
  onProviderProjectionStale: () => void;
  onUnauthenticated: () => void;
  providerMutationBusy: boolean;
  sessionId: string;
}

export function PlatformAuthProviderSamlMaterials({
  api,
  canManage,
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
}: PlatformAuthProviderSamlMaterialsProps): React.JSX.Element {
  const headingId = useId();
  const [mode, setMode] = useState<PlatformSamlMaterialMode>(null);
  const [metadataSource, setMetadataSource] =
    useState<PlatformSamlMetadataSource>("url");
  const [metadataUrl, setMetadataUrl] = useState("");
  const [metadataXml, setMetadataXml] = useState("");
  const [approveTrustReset, setApproveTrustReset] = useState(false);
  const [trustApprovalRequired, setTrustApprovalRequired] = useState(false);
  const [metadataReason, setMetadataReason] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [certificateBundlePem, setCertificateBundlePem] = useState("");
  const [spKeyReason, setSpKeyReason] = useState("");
  const [clearReason, setClearReason] = useState("");
  const [clearConfirmation, setClearConfirmation] = useState("");
  const [validationErrors, setValidationErrors] = useState<readonly string[]>(
    [],
  );
  const [mutationError, setMutationError] = useState<string | null>(null);
  const [submitting, setSubmitting] =
    useState<PlatformSamlMaterialMutation | null>(null);
  const mountedRef = useRef(false);
  const mutationTokenRef = useRef<symbol | null>(null);
  const contextRef = useRef({
    canManage,
    epoch: 0,
    providerId: current.value.id,
    providerVersion: current.value.version,
    sessionId,
  });
  const previousContext = contextRef.current;
  if (
    previousContext.canManage !== canManage ||
    previousContext.providerId !== current.value.id ||
    previousContext.providerVersion !== current.value.version ||
    previousContext.sessionId !== sessionId
  ) {
    contextRef.current = {
      canManage,
      epoch: previousContext.epoch + 1,
      providerId: current.value.id,
      providerVersion: current.value.version,
      sessionId,
    };
    mutationTokenRef.current = null;
  }

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      mutationTokenRef.current = null;
      onMutationBusyChange(false);
    };
  }, [onMutationBusyChange]);

  useEffect(() => {
    clearEditorState();
    setSubmitting(null);
    mutationTokenRef.current = null;
    onMutationBusyChange(false);
  }, [
    canManage,
    current.value.id,
    current.value.version,
    onMutationBusyChange,
    sessionId,
  ]);

  const provider = current.value;
  const blocked =
    providerMutationBusy || submitting !== null || provider.archivedAt !== null;

  function clearWriteOnlyInputs(): void {
    setMetadataUrl("");
    setMetadataXml("");
    setPrivateKeyPem("");
    setCertificateBundlePem("");
  }

  function clearEditorState(): void {
    clearWriteOnlyInputs();
    setMode(null);
    setMetadataSource("url");
    setApproveTrustReset(false);
    setTrustApprovalRequired(false);
    setMetadataReason("");
    setSpKeyReason("");
    setClearReason("");
    setClearConfirmation("");
    setValidationErrors([]);
    setMutationError(null);
  }

  function openEditor(nextMode: Exclude<PlatformSamlMaterialMode, null>): void {
    if (blocked || !canManage) return;
    clearEditorState();
    setMode(nextMode);
  }

  function beginMutation(
    mutation: PlatformSamlMaterialMutation,
  ): { epoch: number; token: symbol } | null {
    if (
      blocked ||
      !canManage ||
      mutationTokenRef.current !== null ||
      provider.archivedAt !== null
    ) {
      return null;
    }
    const token = Symbol(`platform-saml-${mutation}`);
    mutationTokenRef.current = token;
    setSubmitting(mutation);
    onMutationBusyChange(true);
    return { epoch: contextRef.current.epoch, token };
  }

  function mutationIsCurrent(epoch: number, token: symbol): boolean {
    const context = contextRef.current;
    return (
      mountedRef.current &&
      mutationTokenRef.current === token &&
      context.epoch === epoch &&
      context.canManage &&
      context.providerId === provider.id &&
      context.providerVersion === provider.version &&
      context.sessionId === sessionId
    );
  }

  function releaseMutation(token: symbol): void {
    if (!mountedRef.current || mutationTokenRef.current !== token) return;
    mutationTokenRef.current = null;
    setSubmitting(null);
    onMutationBusyChange(false);
  }

  function handleFailure(
    caught: unknown,
    fallback: string,
    epoch: number,
    token: symbol,
  ): void {
    if (!mutationIsCurrent(epoch, token)) return;
    if (caught instanceof PhaseTwoApiError && caught.status === 401) {
      onUnauthenticated();
      return;
    }
    if (caught instanceof PhaseTwoApiError && caught.status === 403) {
      onPermissionError();
    }
    if (
      caught instanceof PhaseTwoApiError &&
      caught.code === "saml_trust_approval_required"
    ) {
      setTrustApprovalRequired(true);
      setMutationError(
        "The replacement changes IdP trust without certificate continuity. Verify the new trust out of band, select explicit approval, and re-enter the metadata before retrying.",
      );
      return;
    }
    if (
      caught instanceof PhaseTwoApiError &&
      (caught.status === 409 || caught.status === 412)
    ) {
      setMode(null);
      onProviderProjectionStale();
    }
    setMutationError(fallback);
  }

  async function replaceMetadata(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const material = metadataSource === "url" ? metadataUrl : metadataXml;
    const errors = [
      validatePlatformSamlMetadataMaterial(metadataSource, material),
      validatePlatformAuthProviderAuditReason(metadataReason),
    ].filter((error): error is string => error !== null);
    if (trustApprovalRequired && !approveTrustReset) {
      errors.push(
        "Confirm explicit trust-reset approval only after completing the out-of-band review.",
      );
    }
    setValidationErrors(errors);
    setMutationError(null);
    if (errors.length > 0) return;
    const request = beginMutation("metadata");
    if (!request) return;
    const source = metadataSource;
    const reason = metadataReason;
    const approved = approveTrustReset;
    clearWriteOnlyInputs();
    setApproveTrustReset(false);
    try {
      const receipt = await api.replacePlatformSamlMetadata(
        csrfToken,
        provider.id,
        current,
        reason,
        source === "url"
          ? {
              approveTrustReset: approved,
              expectedVersion: provider.version,
              metadataUrl: material,
              source,
            }
          : {
              approveTrustReset: approved,
              expectedVersion: provider.version,
              metadataXml: material,
              source,
            },
      );
      if (!mutationIsCurrent(request.epoch, request.token)) return;
      clearEditorState();
      onProviderProjectionStale();
      onChanged();
      onNotice({
        message: `SAML IdP metadata was replaced write-only at trust revision ${receipt.materialRevision}. No raw metadata or certificate material was returned.`,
        tone: "success",
      });
    } catch (caught) {
      handleFailure(
        caught,
        "The write-only SAML metadata was not replaced. Re-enter it after reviewing the current provider version.",
        request.epoch,
        request.token,
      );
    } finally {
      releaseMutation(request.token);
    }
  }

  async function replaceSpKey(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const parsed = parsePlatformSamlSpKeyMaterial(
      privateKeyPem,
      certificateBundlePem,
    );
    const errors = [
      ...parsed.errors,
      validatePlatformAuthProviderAuditReason(spKeyReason),
    ].filter((error): error is string => error !== null);
    setValidationErrors(errors);
    setMutationError(null);
    if (errors.length > 0 || parsed.material === null) return;
    const request = beginMutation("sp-key");
    if (!request) return;
    const material = parsed.material;
    const reason = spKeyReason;
    clearWriteOnlyInputs();
    try {
      const receipt = await api.replacePlatformSamlSpKey(
        csrfToken,
        provider.id,
        current,
        reason,
        {
          certificates: material.certificates,
          expectedVersion: provider.version,
          privateKeyPkcs8: material.privateKeyPkcs8,
        },
      );
      if (!mutationIsCurrent(request.epoch, request.token)) return;
      clearEditorState();
      onProviderProjectionStale();
      onChanged();
      onNotice({
        message: `The SAML SP signing key was stored write-only at key revision ${receipt.materialRevision}. No private key or certificate was returned.`,
        tone: "success",
      });
    } catch (caught) {
      handleFailure(
        caught,
        "The write-only SAML SP key was not replaced. Re-enter the private key and certificate chain before retrying.",
        request.epoch,
        request.token,
      );
    } finally {
      releaseMutation(request.token);
    }
  }

  async function clearSpKey(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const errors = [
      validatePlatformAuthProviderAuditReason(clearReason),
    ].filter((error): error is string => error !== null);
    if (clearConfirmation !== provider.key) {
      errors.push(`Type ${provider.key} to confirm clearing the SP key.`);
    }
    setValidationErrors(errors);
    setMutationError(null);
    if (errors.length > 0 || !provider.configuration.spKeyPresent) return;
    const request = beginMutation("clear");
    if (!request) return;
    const reason = clearReason;
    try {
      const receipt = await api.clearPlatformSamlSpKey(
        csrfToken,
        provider.id,
        current,
        reason,
        { expectedVersion: provider.version },
      );
      if (!mutationIsCurrent(request.epoch, request.token)) return;
      clearEditorState();
      onProviderProjectionStale();
      onChanged();
      onNotice({
        message: `The SAML SP signing key was cleared at key revision ${receipt.materialRevision}. Provider execution remains governed by refreshed readiness.`,
        tone: "warning",
      });
    } catch (caught) {
      handleFailure(
        caught,
        "The SAML SP key was not cleared. Review the refreshed provider version before retrying.",
        request.epoch,
        request.token,
      );
    } finally {
      releaseMutation(request.token);
    }
  }

  return (
    <section
      className="platform-idp-saml-materials"
      aria-labelledby={headingId}
    >
      <div className="platform-idp-section-heading">
        <div>
          <p className="section-label">SAML protected material</p>
          <h3 id={headingId}>Trust and SP signing key</h3>
        </div>
        <Badge variant="outline">If-Match {current.etag}</Badge>
      </div>

      <div className="platform-idp-saml-material-status">
        <div>
          <span>IdP trust snapshot</span>
          <strong>Revision {provider.configuration.metadataRevision}</strong>
          <small>Raw metadata and signing certificates are never shown.</small>
        </div>
        <div>
          <span>SP signing key</span>
          <strong>
            {provider.configuration.spKeyPresent
              ? `Present · revision ${provider.configuration.spKeyRevision}`
              : `Absent · revision ${provider.configuration.spKeyRevision}`}
          </strong>
          <small>
            Only server-generated presence and revision are readable.
          </small>
        </div>
      </div>

      {!canManage ? (
        <Alert>
          <ShieldCheck aria-hidden="true" />
          <AlertTitle>Protected administration is read-only</AlertTitle>
          <AlertDescription>
            The current session did not return platform identity-provider manage
            authority. The backend independently enforces this boundary.
          </AlertDescription>
        </Alert>
      ) : provider.archivedAt !== null ? (
        <Alert>
          <ShieldAlert aria-hidden="true" />
          <AlertTitle>Archived provider</AlertTitle>
          <AlertDescription>
            Protected material cannot be changed after archival.
          </AlertDescription>
        </Alert>
      ) : (
        <>
          <div className="platform-idp-action-buttons">
            <Button
              type="button"
              variant="outline"
              aria-expanded={mode === "metadata"}
              aria-controls="platform-saml-metadata-form"
              disabled={blocked}
              onClick={() => openEditor("metadata")}
            >
              <RefreshCw aria-hidden="true" /> Replace IdP metadata
            </Button>
            <Button
              type="button"
              variant="outline"
              aria-expanded={mode === "sp-key"}
              aria-controls="platform-saml-sp-key-form"
              disabled={blocked}
              onClick={() => openEditor("sp-key")}
            >
              <KeyRound aria-hidden="true" />
              {provider.configuration.spKeyPresent
                ? "Rotate SP signing key"
                : "Set SP signing key"}
            </Button>
            {provider.configuration.spKeyPresent ? (
              <Button
                type="button"
                variant="destructive"
                aria-expanded={mode === "clear"}
                aria-controls="platform-saml-clear-key-form"
                disabled={blocked}
                onClick={() => openEditor("clear")}
              >
                <Trash2 aria-hidden="true" /> Clear SP signing key
              </Button>
            ) : null}
          </div>

          {mode === "metadata" ? (
            <form
              className="platform-idp-action-form platform-idp-secret-form"
              id="platform-saml-metadata-form"
              aria-label="Replace SAML IdP metadata"
              aria-busy={submitting === "metadata"}
              onSubmit={(event) => void replaceMetadata(event)}
            >
              <div>
                <h4>Replace write-only IdP trust metadata</h4>
                <p>
                  Fetch a deployment-approved HTTPS URL or submit one bounded
                  XML document. Neither source is retained in this form after an
                  attempt, and no raw trust material is read back.
                </p>
              </div>
              <FormField
                htmlFor="platform-saml-metadata-source"
                label="Metadata source"
              >
                <select
                  className="platform-idp-select"
                  disabled={blocked}
                  id="platform-saml-metadata-source"
                  value={metadataSource}
                  onChange={(event) => {
                    const nextSource = event.target.value;
                    if (nextSource !== "url" && nextSource !== "xml") return;
                    setMetadataSource(nextSource);
                    setMetadataUrl("");
                    setMetadataXml("");
                    setValidationErrors([]);
                    setMutationError(null);
                  }}
                >
                  <option value="url">HTTPS metadata URL</option>
                  <option value="xml">Upload metadata XML</option>
                </select>
              </FormField>
              {metadataSource === "url" ? (
                <FormField
                  htmlFor="platform-saml-metadata-url"
                  label="IdP metadata URL"
                  hint="HTTPS only. Retrieval uses the deployment-owned SSRF-resistant client."
                >
                  <Input
                    aria-describedby="platform-saml-metadata-url-hint"
                    autoCapitalize="none"
                    autoComplete="off"
                    disabled={blocked}
                    id="platform-saml-metadata-url"
                    spellCheck={false}
                    type="url"
                    value={metadataUrl}
                    onChange={(event) => setMetadataUrl(event.target.value)}
                  />
                </FormField>
              ) : (
                <FormField
                  htmlFor="platform-saml-metadata-xml"
                  label="IdP metadata XML"
                  hint="Write-only UTF-8 XML, limited to 512 KiB. It is cleared after every attempt."
                >
                  <Textarea
                    aria-describedby="platform-saml-metadata-xml-hint"
                    autoCapitalize="none"
                    autoComplete="off"
                    disabled={blocked}
                    id="platform-saml-metadata-xml"
                    rows={8}
                    spellCheck={false}
                    value={metadataXml}
                    onChange={(event) => setMetadataXml(event.target.value)}
                  />
                </FormField>
              )}
              <div className="platform-idp-boolean-field">
                <Checkbox
                  aria-describedby="platform-saml-approve-trust-reset-hint"
                  checked={approveTrustReset}
                  disabled={blocked}
                  id="platform-saml-approve-trust-reset"
                  onCheckedChange={(checked) =>
                    setApproveTrustReset(checked === true)
                  }
                />
                <div>
                  <Label htmlFor="platform-saml-approve-trust-reset">
                    Approve trust reset after out-of-band review
                  </Label>
                  <p id="platform-saml-approve-trust-reset-hint">
                    Leave off for normal certificate continuity. Select only
                    after independently verifying a deliberate trust rollover.
                  </p>
                </div>
              </div>
              {trustApprovalRequired ? (
                <Alert variant="destructive">
                  <ShieldAlert aria-hidden="true" />
                  <AlertTitle>Explicit trust approval required</AlertTitle>
                  <AlertDescription>
                    The server detected no trusted certificate continuity. The
                    prior XML or URL was cleared; verify the replacement out of
                    band, approve above, and re-enter it for a new attempt.
                  </AlertDescription>
                </Alert>
              ) : null}
              <AuditReasonField
                disabled={blocked}
                id="platform-saml-metadata-reason"
                value={metadataReason}
                onChange={setMetadataReason}
              />
              <FormFeedback
                errors={validationErrors}
                requestError={mutationError}
              />
              <div className="platform-idp-form-actions">
                <Button
                  type="button"
                  variant="ghost"
                  disabled={blocked}
                  onClick={clearEditorState}
                >
                  Cancel metadata replacement
                </Button>
                <Button type="submit" disabled={blocked}>
                  <RefreshCw aria-hidden="true" />
                  {submitting === "metadata"
                    ? "Submitting…"
                    : "Replace write-only metadata"}
                </Button>
              </div>
            </form>
          ) : null}

          {mode === "sp-key" ? (
            <form
              className="platform-idp-action-form platform-idp-secret-form"
              id="platform-saml-sp-key-form"
              aria-label="Replace SAML SP signing key"
              aria-busy={submitting === "sp-key"}
              onSubmit={(event) => void replaceSpKey(event)}
            >
              <div>
                <h4>Set write-only SP signing material</h4>
                <p>
                  Submit one unencrypted PKCS#8 private key and its ordered
                  X.509 certificate chain. PEM is converted to canonical DER
                  base64 in memory and cleared from the form after every
                  attempt.
                </p>
              </div>
              <FormField
                htmlFor="platform-saml-private-key"
                label="PKCS#8 private key PEM"
                hint="The block must use BEGIN PRIVATE KEY, not an encrypted, RSA, or EC-specific label."
              >
                <Textarea
                  aria-describedby="platform-saml-private-key-hint"
                  autoCapitalize="none"
                  autoComplete="new-password"
                  disabled={blocked}
                  id="platform-saml-private-key"
                  rows={7}
                  spellCheck={false}
                  value={privateKeyPem}
                  onChange={(event) => setPrivateKeyPem(event.target.value)}
                />
              </FormField>
              <FormField
                htmlFor="platform-saml-certificates"
                label="X.509 certificate chain PEM"
                hint="Enter one to eight distinct CERTIFICATE blocks, signer first."
              >
                <Textarea
                  aria-describedby="platform-saml-certificates-hint"
                  autoCapitalize="none"
                  autoComplete="off"
                  disabled={blocked}
                  id="platform-saml-certificates"
                  rows={8}
                  spellCheck={false}
                  value={certificateBundlePem}
                  onChange={(event) =>
                    setCertificateBundlePem(event.target.value)
                  }
                />
              </FormField>
              <AuditReasonField
                disabled={blocked}
                id="platform-saml-sp-key-reason"
                value={spKeyReason}
                onChange={setSpKeyReason}
              />
              <FormFeedback
                errors={validationErrors}
                requestError={mutationError}
              />
              <div className="platform-idp-form-actions">
                <Button
                  type="button"
                  variant="ghost"
                  disabled={blocked}
                  onClick={clearEditorState}
                >
                  Cancel SP key replacement
                </Button>
                <Button type="submit" disabled={blocked}>
                  <KeyRound aria-hidden="true" />
                  {submitting === "sp-key"
                    ? "Submitting…"
                    : "Store write-only SP key"}
                </Button>
              </div>
            </form>
          ) : null}

          {mode === "clear" && provider.configuration.spKeyPresent ? (
            <form
              className="platform-idp-action-form platform-idp-archive-form"
              id="platform-saml-clear-key-form"
              aria-label="Clear SAML SP signing key"
              aria-busy={submitting === "clear"}
              onSubmit={(event) => void clearSpKey(event)}
            >
              <div>
                <h4>Clear SP signing material</h4>
                <p>
                  This removes the current encrypted private key and certificate
                  chain. The key revision still advances so pinned work fails
                  closed. Type the provider key to confirm.
                </p>
              </div>
              <AuditReasonField
                disabled={blocked}
                id="platform-saml-clear-key-reason"
                value={clearReason}
                onChange={setClearReason}
              />
              <FormField
                htmlFor="platform-saml-clear-key-confirmation"
                label={`Type ${provider.key} to confirm`}
              >
                <Input
                  autoComplete="off"
                  disabled={blocked}
                  id="platform-saml-clear-key-confirmation"
                  value={clearConfirmation}
                  onChange={(event) => setClearConfirmation(event.target.value)}
                />
              </FormField>
              <FormFeedback
                errors={validationErrors}
                requestError={mutationError}
              />
              <div className="platform-idp-form-actions">
                <Button
                  type="button"
                  variant="ghost"
                  disabled={blocked}
                  onClick={clearEditorState}
                >
                  Cancel key clearing
                </Button>
                <Button type="submit" variant="destructive" disabled={blocked}>
                  <Trash2 aria-hidden="true" />
                  {submitting === "clear"
                    ? "Clearing…"
                    : "Clear SP signing key"}
                </Button>
              </div>
            </form>
          ) : null}
        </>
      )}
    </section>
  );
}

function AuditReasonField({
  disabled,
  id,
  onChange,
  value,
}: {
  disabled: boolean;
  id: string;
  onChange: (value: string) => void;
  value: string;
}): React.JSX.Element {
  return (
    <FormField
      htmlFor={id}
      label="Audit reason"
      hint="Visible ASCII, no commas, leading whitespace, or protected material."
    >
      <Input
        aria-describedby={`${id}-hint`}
        autoComplete="off"
        disabled={disabled}
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
      />
    </FormField>
  );
}

function FormFeedback({
  errors,
  requestError,
}: {
  errors: readonly string[];
  requestError: string | null;
}): React.JSX.Element | null {
  if (errors.length > 0) {
    return (
      <Alert variant="destructive">
        <ShieldAlert aria-hidden="true" />
        <AlertTitle>Review the protected-material command</AlertTitle>
        <AlertDescription>
          <ul>
            {errors.map((error) => (
              <li key={error}>{error}</li>
            ))}
          </ul>
        </AlertDescription>
      </Alert>
    );
  }
  return requestError ? <FocusedError message={requestError} /> : null;
}
