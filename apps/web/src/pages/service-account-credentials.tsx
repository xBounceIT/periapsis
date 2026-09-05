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
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  ArrowDown,
  Eye,
  KeyRound,
  Network,
  Plus,
  RotateCw,
} from "lucide-react";
import { useEffect, useId, useRef, useState } from "react";

import { useSession } from "../auth/session-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { SecretValue } from "../components/secret-value";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type ServiceAccountCredentialIssueInput,
  type ServiceAccountCredentialPageView,
  type ServiceAccountCredentialRotateInput,
  type ServiceAccountCredentialSecretView,
  type ServiceAccountCredentialView,
  type ServiceAccountView,
  type VersionedView,
} from "../lib/phase-two-types";
import { useBeforeUnloadWarning } from "../lib/use-before-unload-warning";
import {
  capitalize,
  credentialInput,
  credentialPermission,
  defaultCredentialExpiry,
  formatTimestamp,
  mutationMessage,
  toLocalDateTime,
  validateReason,
  type OneTimeSecretState,
  type PaginationState,
} from "./service-account-model";

export function CredentialPanel({
  account,
  canManageCredentials,
  credentialActionError,
  credentialDetail,
  credentialPagination,
  credentialRevokeReason,
  credentialRevoking,
  credentials,
  hidden,
  id,
  onCloseCredential,
  onIssue,
  onLoadMore,
  onOpenCredential,
  onRevoke,
  onRevokeReasonChange,
  onRotate,
  selectedCredentialId,
}: {
  account: ServiceAccountView;
  canManageCredentials: boolean;
  credentialActionError: string | null;
  credentialDetail:
    | { kind: "error"; message: string }
    | { kind: "loading" }
    | {
        credential: VersionedView<ServiceAccountCredentialView>;
        kind: "ready";
      }
    | null;
  credentialPagination: PaginationState;
  credentialRevokeReason: string;
  credentialRevoking: boolean;
  credentials: ServiceAccountCredentialPageView;
  hidden: boolean;
  id: string;
  onCloseCredential: () => void;
  onIssue: () => void;
  onLoadMore: () => void;
  onOpenCredential: (credential: ServiceAccountCredentialView) => void;
  onRevoke: () => void;
  onRevokeReasonChange: (reason: string) => void;
  onRotate: (credential: ServiceAccountCredentialView) => void;
  selectedCredentialId: string | null;
}): React.JSX.Element {
  return (
    <section
      id={`${id}-credentials-panel`}
      role="tabpanel"
      aria-labelledby={`${id}-credentials-tab`}
      hidden={hidden}
      tabIndex={0}
      className="service-account-tab-panel service-account-credential-panel"
    >
      <div className="service-account-panel-heading">
        <div>
          <p className="section-label">Redacted inventory</p>
          <h3>API credentials</h3>
        </div>
        {canManageCredentials && account.state === "active" ? (
          <Button type="button" onClick={onIssue}>
            <Plus aria-hidden="true" /> Issue credential
          </Button>
        ) : null}
      </div>
      <p className="capability-note">
        Inventory never contains a bearer token, locator, or digest. Empty
        network restrictions mean any trusted resolved client address.
      </p>
      {credentials.items.length === 0 ? (
        <div className="service-account-empty service-account-empty--inline">
          <KeyRound aria-hidden="true" />
          <h4>No credential metadata returned</h4>
          <p>
            {canManageCredentials && account.state === "active"
              ? "Issue a credential only after its exact alert.create@tenant authority is live."
              : "No redacted credential records are visible for this account."}
          </p>
        </div>
      ) : (
        <div className="service-account-credential-grid">
          {credentials.items.map((credential) => (
            <Card
              className="service-account-credential-card"
              key={credential.id}
            >
              <CardHeader>
                <span className="service-account-credential-mark">
                  <KeyRound aria-hidden="true" />
                </span>
                <div>
                  <CardTitle>{credential.label}</CardTitle>
                  <CardDescription>
                    Expires {formatTimestamp(credential.expiresAt)}
                  </CardDescription>
                </div>
                <Badge
                  variant={
                    credential.state === "active" ? "secondary" : "outline"
                  }
                >
                  {capitalize(credential.state)}
                </Badge>
              </CardHeader>
              <CardContent>
                <p>
                  <Network aria-hidden="true" />
                  {credential.allowedNetworks.length === 0
                    ? "Any trusted source address"
                    : `${credential.allowedNetworks.length} source network${credential.allowedNetworks.length === 1 ? "" : "s"}`}
                </p>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  aria-label={`View credential ${credential.label} (${credential.id})`}
                  onClick={() => onOpenCredential(credential)}
                >
                  <Eye aria-hidden="true" /> View redacted detail
                </Button>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
      {credentialPagination.error ? (
        <FocusedError
          title="More credentials could not be loaded"
          message={credentialPagination.error}
        />
      ) : null}
      {credentials.nextCursor ? (
        <Button
          type="button"
          variant="outline"
          disabled={credentialPagination.loading}
          onClick={onLoadMore}
        >
          <ArrowDown aria-hidden="true" />
          {credentialPagination.loading
            ? "Loading credentials…"
            : "Load more credentials"}
        </Button>
      ) : null}

      {selectedCredentialId ? (
        <Card className="service-account-credential-detail">
          <CardHeader>
            <div>
              <CardTitle>Redacted credential detail</CardTitle>
              <CardDescription>
                Loaded directly from the tenant-scoped detail operation.
              </CardDescription>
            </div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onCloseCredential}
            >
              Close detail
            </Button>
          </CardHeader>
          <CardContent>
            {credentialDetail?.kind === "loading" ? (
              <div
                className="service-account-inline-skeleton"
                aria-label="Loading redacted credential detail"
              >
                <span />
                <span />
              </div>
            ) : null}
            {credentialDetail?.kind === "error" ? (
              <FocusedError message={credentialDetail.message} />
            ) : null}
            {credentialDetail?.kind === "ready" ? (
              <>
                <dl className="service-account-facts service-account-credential-facts">
                  <div>
                    <dt>Label</dt>
                    <dd>{credentialDetail.credential.value.label}</dd>
                  </div>
                  <div>
                    <dt>Permission</dt>
                    <dd>
                      <code>alert.create@tenant</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Issued</dt>
                    <dd>
                      {formatTimestamp(
                        credentialDetail.credential.value.issuedAt,
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt>Last used</dt>
                    <dd>
                      {credentialDetail.credential.value.lastUsedAt
                        ? `${formatTimestamp(credentialDetail.credential.value.lastUsedAt)} · ${String(credentialDetail.credential.value.lastUsedIp)}`
                        : "Never"}
                    </dd>
                  </div>
                  <div>
                    <dt>ETag</dt>
                    <dd>
                      <code>{credentialDetail.credential.etag}</code>
                    </dd>
                  </div>
                  <div>
                    <dt>Networks</dt>
                    <dd>
                      {credentialDetail.credential.value.allowedNetworks
                        .length === 0
                        ? "Unrestricted"
                        : credentialDetail.credential.value.allowedNetworks.join(
                            ", ",
                          )}
                    </dd>
                  </div>
                </dl>
                {credentialActionError ? (
                  <FocusedError
                    title="Credential action not completed"
                    message={credentialActionError}
                  />
                ) : null}
                {canManageCredentials &&
                account.state === "active" &&
                credentialDetail.credential.value.state === "active" ? (
                  <div className="service-account-credential-actions">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() =>
                        onRotate(credentialDetail.credential.value)
                      }
                    >
                      <RotateCw aria-hidden="true" /> Rotate credential
                    </Button>
                    <form
                      className="service-account-inline-revoke"
                      onSubmit={(event) => {
                        event.preventDefault();
                        onRevoke();
                      }}
                    >
                      <FormField
                        htmlFor={`${id}-credential-revoke-reason`}
                        label="Revoke reason"
                      >
                        <Textarea
                          id={`${id}-credential-revoke-reason`}
                          maxLength={500}
                          disabled={credentialRevoking}
                          value={credentialRevokeReason}
                          onChange={(event) =>
                            onRevokeReasonChange(event.target.value)
                          }
                        />
                      </FormField>
                      <Button
                        type="submit"
                        variant="destructive"
                        disabled={credentialRevoking}
                      >
                        {credentialRevoking
                          ? "Revoking credential…"
                          : "Revoke credential"}
                      </Button>
                    </form>
                  </div>
                ) : null}
              </>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </section>
  );
}

type CredentialMutationDialogProps = {
  accountId: string;
  api: PhaseTwoApi;
  csrfToken: string;
  onMutationDenied: (
    caught: unknown,
    expectedPair: string,
    expectedSessionId: string,
  ) => boolean;
  onOpenChange: (open: boolean) => void;
  onReadDenied: (
    caught: unknown,
    expectedPair: string,
    expectedSessionId: string,
  ) => "forbidden" | "unauthenticated" | undefined;
  onReconciled?: (credential: ServiceAccountCredentialView) => void;
  onSecret: (secret: ServiceAccountCredentialSecretView) => void;
  pairKey: string;
  tenantId: string;
} & (
  | { credential?: never; mode: "issue" }
  | { credential: ServiceAccountCredentialView; mode: "rotate" }
);

function isAmbiguousCredentialMutationFailure(caught: unknown): boolean {
  return (
    !(caught instanceof PhaseTwoApiError) ||
    (caught.status === undefined &&
      caught.code === undefined &&
      caught.credentialId === undefined &&
      caught.location === undefined)
  );
}

export function CredentialMutationDialog(
  props: CredentialMutationDialogProps,
): React.JSX.Element {
  const {
    accountId,
    api,
    csrfToken,
    onMutationDenied,
    onOpenChange,
    onReadDenied,
    onReconciled,
    onSecret,
    pairKey,
    tenantId,
  } = props;
  const { session } = useSession();
  const id = useId();
  const [label, setLabel] = useState(
    props.mode === "rotate" ? props.credential.label : "",
  );
  const [expiresAt, setExpiresAt] = useState(
    props.mode === "rotate"
      ? toLocalDateTime(props.credential.expiresAt)
      : defaultCredentialExpiry(),
  );
  const [networks, setNetworks] = useState(
    props.mode === "rotate" ? props.credential.allowedNetworks.join("\n") : "",
  );
  const [revokeReason, setRevokeReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const mutationPendingRef = useRef(false);
  const mountedRef = useRef(true);
  const pairKeyRef = useRef(pairKey);
  pairKeyRef.current = pairKey;
  const sessionIdRef = useRef(session.id);
  sessionIdRef.current = session.id;
  const idempotencyBindingRef = useRef<{
    fingerprint: string;
    key: string;
  } | null>(null);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  useBeforeUnloadWarning(mutationPendingRef);

  function isCurrent(expectedPair: string, expectedSessionId: string): boolean {
    return (
      mountedRef.current &&
      pairKeyRef.current === expectedPair &&
      sessionIdRef.current === expectedSessionId
    );
  }

  function handleOpenChange(open: boolean): void {
    if (!open && mutationPendingRef.current) return;
    onOpenChange(open);
  }

  async function submit(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (mutationPendingRef.current) return;
    const parsed = credentialInput(label, expiresAt, networks);
    if (!parsed.ok) {
      setError(parsed.message);
      return;
    }
    if (props.mode === "rotate") {
      const reasonError = validateReason(revokeReason);
      if (reasonError) {
        setError(reasonError);
        return;
      }
    }
    const expectedPair = pairKey;
    const expectedSessionId = session.id;
    const input: ServiceAccountCredentialIssueInput = {
      allowedNetworks: parsed.allowedNetworks,
      expiresAt: parsed.expiresAt,
      label: parsed.label,
      permissions: [...credentialPermission],
    };
    let idempotencyPayload: unknown;
    let executeMutationWithKey: (
      idempotencyKey: string,
    ) => Promise<ServiceAccountCredentialSecretView>;
    if (props.mode === "issue") {
      idempotencyPayload = { accountId, input, operation: "issue", tenantId };
      executeMutationWithKey = (idempotencyKey) =>
        api.issueTenantServiceAccountCredential(
          csrfToken,
          tenantId,
          accountId,
          idempotencyKey,
          input,
        );
    } else {
      const credential = props.credential;
      const rotateInput = {
        ...input,
        revokeReason: revokeReason.trim(),
      } satisfies ServiceAccountCredentialRotateInput;
      idempotencyPayload = {
        accountId,
        credentialId: credential.id,
        input: rotateInput,
        operation: "rotate",
        tenantId,
      };
      executeMutationWithKey = (idempotencyKey) =>
        api.rotateTenantServiceAccountCredential(
          csrfToken,
          tenantId,
          accountId,
          credential.id,
          credential.etag,
          idempotencyKey,
          rotateInput,
        );
    }
    const idempotencyKey = idempotencyKeyForPayload(
      idempotencyBindingRef,
      idempotencyPayload,
    );
    const executeMutation = () => executeMutationWithKey(idempotencyKey);
    mutationPendingRef.current = true;
    setSaving(true);
    setError(null);
    try {
      let secret: ServiceAccountCredentialSecretView;
      try {
        secret = await executeMutation();
      } catch (firstFailure) {
        if (!isCurrent(expectedPair, expectedSessionId)) return;
        if (!isAmbiguousCredentialMutationFailure(firstFailure)) {
          throw firstFailure;
        }
        try {
          secret = await executeMutation();
        } catch (retryFailure) {
          if (
            isCurrent(expectedPair, expectedSessionId) &&
            isAmbiguousCredentialMutationFailure(retryFailure)
          ) {
            setError(
              "The credential outcome is still unknown after one automatic retry. Keep this dialog open and retry without changing the input; the same in-memory retry identity will be reused. If a later response identifies a completed credential, revoke it and issue another.",
            );
            return;
          }
          throw retryFailure;
        }
      }
      if (!isCurrent(expectedPair, expectedSessionId)) {
        return;
      }
      onSecret(secret);
      idempotencyBindingRef.current = null;
    } catch (caught) {
      if (!isCurrent(expectedPair, expectedSessionId)) {
        return;
      }
      if (onMutationDenied(caught, expectedPair, expectedSessionId)) return;
      if (
        caught instanceof PhaseTwoApiError &&
        caught.status === 409 &&
        caught.code === "one_time_secret_already_issued"
      ) {
        setError(
          "This exact request already completed. The bearer token cannot be shown again; revoke the reconciled credential and issue another if the first response was lost.",
        );
        if (caught.credentialId) {
          try {
            const reconciled = await api.getTenantServiceAccountCredential(
              tenantId,
              accountId,
              caught.credentialId,
            );
            if (isCurrent(expectedPair, expectedSessionId)) {
              onReconciled?.(reconciled.value);
            }
          } catch (reconciliationFailure) {
            if (isCurrent(expectedPair, expectedSessionId)) {
              onReadDenied(
                reconciliationFailure,
                expectedPair,
                expectedSessionId,
              );
            }
            // The safe replay metadata remains sufficient to explain the lost
            // one-time response. No second issuance key is generated here.
          }
        }
        return;
      }
      if (caught instanceof PhaseTwoApiError && caught.status === 412) {
        setError(
          "This credential changed on the server. Its current redacted detail and ETag are loading; the rotation input remains here.",
        );
        if (props.mode === "rotate") {
          try {
            const reconciled = await api.getTenantServiceAccountCredential(
              tenantId,
              accountId,
              props.credential.id,
            );
            if (isCurrent(expectedPair, expectedSessionId)) {
              onReconciled?.(reconciled.value);
              setError(
                "The current credential ETag is loaded. Review the preserved rotation input, then retry.",
              );
            }
          } catch (reconciliationFailure) {
            if (isCurrent(expectedPair, expectedSessionId)) {
              onReadDenied(
                reconciliationFailure,
                expectedPair,
                expectedSessionId,
              );
            }
            // Keep the caller-provided input and retry identity intact. A new
            // rotation is unsafe until redacted detail can be reconciled.
          }
        }
        return;
      }
      setError(
        mutationMessage(
          caught,
          props.mode === "issue"
            ? "The credential was not issued. Your input and retry identity are preserved."
            : "The credential was not rotated. Your input and retry identity are preserved.",
        ),
      );
    } finally {
      mutationPendingRef.current = false;
      if (isCurrent(expectedPair, expectedSessionId)) {
        setSaving(false);
      }
    }
  }

  return (
    <Dialog open onOpenChange={handleOpenChange}>
      <DialogContent
        className="service-account-credential-dialog"
        data-cache-policy="no-store"
        aria-busy={saving}
        onEscapeKeyDown={(event) => {
          if (mutationPendingRef.current) event.preventDefault();
        }}
        onInteractOutside={(event) => {
          if (mutationPendingRef.current) event.preventDefault();
        }}
      >
        <DialogHeader>
          <DialogTitle>
            {props.mode === "issue"
              ? "Issue API credential"
              : "Rotate API credential"}
          </DialogTitle>
          <DialogDescription>
            The resulting bearer token appears exactly once in memory. This
            dialog never writes it to cache, storage, URLs, telemetry, or toast
            text.
          </DialogDescription>
        </DialogHeader>
        <form className="service-account-form" onSubmit={submit} noValidate>
          {error ? (
            <FocusedError
              title="Credential action not completed"
              message={error}
            />
          ) : null}
          <FormField
            htmlFor={`${id}-credential-label`}
            label="Credential label"
          >
            <Input
              id={`${id}-credential-label`}
              autoComplete="off"
              maxLength={120}
              disabled={saving}
              value={label}
              onChange={(event) => setLabel(event.target.value)}
            />
          </FormField>
          <FormField htmlFor={`${id}-credential-expiry`} label="Expires at">
            <Input
              id={`${id}-credential-expiry`}
              type="datetime-local"
              disabled={saving}
              value={expiresAt}
              onChange={(event) => setExpiresAt(event.target.value)}
            />
          </FormField>
          <FormField
            htmlFor={`${id}-credential-permission`}
            label="Exact permission"
          >
            <Input
              id={`${id}-credential-permission`}
              value="alert.create@tenant"
              readOnly
              aria-readonly="true"
            />
          </FormField>
          <FormField
            htmlFor={`${id}-credential-networks`}
            label="Allowed CIDR networks"
            optional
          >
            <Textarea
              id={`${id}-credential-networks`}
              autoComplete="off"
              placeholder={"192.0.2.0/24\n2001:db8::/48"}
              disabled={saving}
              value={networks}
              onChange={(event) => setNetworks(event.target.value)}
            />
          </FormField>
          <p className="capability-note">
            Leave networks empty to allow any address resolved through the
            trusted proxy chain. At most 32 canonical CIDRs are accepted.
          </p>
          {props.mode === "rotate" ? (
            <FormField
              htmlFor={`${id}-rotation-reason`}
              label="Predecessor revoke reason"
            >
              <Textarea
                id={`${id}-rotation-reason`}
                maxLength={500}
                disabled={saving}
                value={revokeReason}
                onChange={(event) => setRevokeReason(event.target.value)}
              />
            </FormField>
          ) : null}
          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              disabled={saving}
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={saving}>
              {saving
                ? props.mode === "issue"
                  ? "Issuing credential…"
                  : "Rotating credential…"
                : props.mode === "issue"
                  ? "Issue credential"
                  : "Rotate credential"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export function OneTimeCredentialDialog({
  onDismiss,
  state,
}: {
  onDismiss: () => void;
  state: OneTimeSecretState;
}): React.JSX.Element {
  useBeforeUnloadWarning();

  return (
    <Dialog
      open
      onOpenChange={(open) => {
        if (!open) onDismiss();
      }}
    >
      <DialogContent
        className="service-account-secret-dialog"
        data-cache-policy="no-store"
      >
        <DialogHeader>
          <DialogTitle>Credential {state.operation} — copy it now</DialogTitle>
          <DialogDescription>
            Periapsis will never return this bearer token again. Store it in the
            collector secret manager before dismissing this view.
          </DialogDescription>
        </DialogHeader>
        <div className="service-account-secret-boundary">
          <SecretValue label="Bearer token" value={state.secret.bearerToken} />
          <dl>
            <div>
              <dt>Credential ID</dt>
              <dd>
                <code>{state.secret.credential.id}</code>
              </dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>{formatTimestamp(state.secret.credential.expiresAt)}</dd>
            </div>
          </dl>
        </div>
        <p className="service-account-secret-warning" role="note">
          Closing this dialog permanently removes the token from page state. The
          redacted credential record remains available.
        </p>
        <DialogFooter>
          <Button type="button" onClick={onDismiss}>
            I stored the token
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
