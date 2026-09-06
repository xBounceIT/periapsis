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
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { useSession } from "../auth/session-context";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { idempotencyKeyForPayload } from "../lib/payload-idempotency";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type ServiceAccountCredentialIssueInput,
  type ServiceAccountCredentialRotateInput,
  type ServiceAccountCredentialSecretView,
  type ServiceAccountCredentialView,
} from "../lib/phase-two-types";
import { useBeforeUnloadWarning } from "../lib/use-before-unload-warning";
import {
  credentialInput,
  credentialPermission,
  defaultCredentialExpiry,
  mutationMessage,
  toLocalDateTime,
  validateReason,
} from "./service-account-model";

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
  const model = useCredentialMutationDialogModel(props);
  return <CredentialMutationDialogView model={model.data} />;
}

function useCredentialMutationDialogModel(
  props: CredentialMutationDialogProps,
) {
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
  useLayoutEffect(() => {
    pairKeyRef.current = pairKey;
  }, [pairKey]);
  const sessionIdRef = useRef(session.id);
  useLayoutEffect(() => {
    sessionIdRef.current = session.id;
  }, [session]);
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
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setSaving(false);
      }
    }
  }

  return {
    kind: "ready" as const,
    data: {
      error,
      expiresAt,
      handleOpenChange,
      id,
      label,
      mutationPendingRef,
      networks,
      onOpenChange,
      props,
      revokeReason,
      saving,
      setExpiresAt,
      setLabel,
      setNetworks,
      setRevokeReason,
      submit,
    },
  };
}

function CredentialMutationDialogView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useCredentialMutationDialogModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  return <CredentialMutationDialogContent model={model} />;
}

function CredentialMutationDialogContent({
  model,
}: {
  model: React.ComponentProps<typeof CredentialMutationDialogView>["model"];
}): React.ReactNode {
  const { handleOpenChange, mutationPendingRef, props, saving } = model;
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
        <CredentialMutationDialogDialogForm model={model} />
      </DialogContent>
    </Dialog>
  );
}

function CredentialMutationDialogDialogForm({
  model,
}: {
  model: React.ComponentProps<typeof CredentialMutationDialogContent>["model"];
}): React.ReactNode {
  const {
    error,
    expiresAt,
    id,
    label,
    networks,
    onOpenChange,
    props,
    revokeReason,
    saving,
    setExpiresAt,
    setLabel,
    setNetworks,
    setRevokeReason,
    submit,
  } = model;
  return (
    <form className="service-account-form" onSubmit={submit} noValidate>
      {error ? (
        <FocusedError title="Credential action not completed" message={error} />
      ) : null}
      <FormField htmlFor={`${id}-credential-label`} label="Credential label">
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
        Leave networks empty to allow any address resolved through the trusted
        proxy chain. At most 32 canonical CIDRs are accepted.
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
  );
}
