import { Button } from "@periapsis/ui/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@periapsis/ui/components/ui/dialog";
import { SecretValue } from "../components/secret-value";
import { useBeforeUnloadWarning } from "../lib/use-before-unload-warning";
import {
  formatTimestamp,
  type OneTimeSecretState,
} from "./service-account-model";

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
