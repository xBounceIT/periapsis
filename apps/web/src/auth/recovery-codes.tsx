import {
  Alert,
  AlertDescription,
  AlertTitle,
} from "@periapsis/ui/components/ui/alert";
import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { Check, Copy, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { AccessLayout } from "../components/access-layout";
import type { BootstrapConfirmationView } from "../lib/phase-two-types";
import { useBeforeUnloadWarning } from "../lib/use-before-unload-warning";

interface RecoveryCodesProps {
  confirmation: BootstrapConfirmationView;
  onContinue: () => void;
}

export function RecoveryCodes({
  confirmation,
  onContinue,
}: RecoveryCodesProps): React.JSX.Element {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copyState, setCopyState] = useState<"copied" | "failed" | "idle">(
    "idle",
  );

  useBeforeUnloadWarning();

  async function copyCodes(): Promise<void> {
    try {
      await navigator.clipboard.writeText(
        confirmation.recoveryCodes.join("\n"),
      );
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <AccessLayout
      activeStep={2}
      eyebrow="One-time recovery material"
      title="Save the recovery codes now."
      description="The administrator and protected session now exist. These one-use recovery codes are returned only once and disappear from this interface when you continue."
    >
      <Card className="access-card recovery-card">
        <CardHeader>
          <CardTitle>Recovery codes</CardTitle>
          <CardDescription>
            Store them offline in an approved credential vault. Each code can
            complete one MFA challenge.
          </CardDescription>
        </CardHeader>
        <CardContent className="access-form">
          <Alert className="recovery-warning">
            <ShieldAlert aria-hidden="true" />
            <AlertTitle>This is the only display</AlertTitle>
            <AlertDescription>
              Leaving or reloading this page does not reveal the codes again.
              The session remains valid, but unsaved codes are lost.
            </AlertDescription>
          </Alert>

          <ol className="recovery-code-list" aria-label="Recovery codes">
            {confirmation.recoveryCodes.map((code, index) => (
              <li key={code}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <code>{code}</code>
              </li>
            ))}
          </ol>

          <Button
            type="button"
            variant="outline"
            onClick={() => void copyCodes()}
          >
            {copyState === "copied" ? (
              <Check aria-hidden="true" />
            ) : (
              <Copy aria-hidden="true" />
            )}
            {copyState === "copied" ? "Copied all codes" : "Copy all codes"}
          </Button>
          <p className="copy-feedback" aria-live="polite">
            {copyState === "failed"
              ? "Clipboard access failed. Select and copy each code manually."
              : copyState === "copied"
                ? "Recovery codes copied to the clipboard."
                : ""}
          </p>

          <label className="acknowledgement">
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(event) => setAcknowledged(event.currentTarget.checked)}
            />
            <span>
              I saved the recovery codes in an approved secure location.
            </span>
          </label>

          <Button
            type="button"
            size="lg"
            disabled={!acknowledged}
            onClick={onContinue}
          >
            Continue to the control plane
          </Button>
        </CardContent>
      </Card>
    </AccessLayout>
  );
}
