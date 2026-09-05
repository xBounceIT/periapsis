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
import { Input } from "@periapsis/ui/components/ui/input";
import { Clock3, KeyRound, ShieldCheck } from "lucide-react";
import { useId, useState } from "react";

import { AccessLayout } from "../components/access-layout";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { SecretValue } from "../components/secret-value";
import { readTextField } from "../lib/form-data";
import {
  describePhaseTwoError,
  type BootstrapConfirmationView,
  type BootstrapEnrollmentView,
  type PhaseTwoApi,
} from "../lib/phase-two-types";

interface BootstrapFlowProps {
  api: PhaseTwoApi;
  onConfirmed: (confirmation: BootstrapConfirmationView) => void;
}

export function BootstrapFlow({
  api,
  onConfirmed,
}: BootstrapFlowProps): React.JSX.Element {
  const [enrollment, setEnrollment] = useState<BootstrapEnrollmentView | null>(
    null,
  );
  const [reservedEmail, setReservedEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);
  const id = useId();

  async function reserveEnrollment(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = new FormData(form);
    const bootstrapToken = readTextField(fields, "bootstrapToken");
    const email = readTextField(fields, "email").trim().toLowerCase();

    setError(null);
    setIsPending(true);
    try {
      const result = await api.enrollBootstrap({
        bootstrapToken,
        email,
      });
      form.reset();
      setReservedEmail(email);
      setEnrollment(result);
    } catch (caught) {
      setError(
        describePhaseTwoError(
          caught,
          "The enrollment could not be reserved. Check the deployment token and try again.",
        ),
      );
    } finally {
      setIsPending(false);
    }
  }

  async function confirmEnrollment(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!enrollment) {
      return;
    }
    const form = event.currentTarget;
    const fields = new FormData(form);
    const password = readTextField(fields, "password");
    const passwordConfirmation = readTextField(fields, "passwordConfirmation");

    setError(null);
    setPasswordError(null);
    if (password !== passwordConfirmation) {
      setPasswordError("The password confirmation does not match.");
      requestAnimationFrame(() => {
        const confirmation = form.elements.namedItem("passwordConfirmation");
        if (confirmation instanceof HTMLElement) {
          confirmation.focus();
        }
      });
      return;
    }

    setIsPending(true);
    try {
      const result = await api.confirmBootstrap({
        bootstrapToken: readTextField(fields, "bootstrapToken"),
        code: readTextField(fields, "code").trim(),
        displayName: readTextField(fields, "displayName").trim(),
        email: readTextField(fields, "email").trim().toLowerCase(),
        enrollmentToken: enrollment.enrollmentToken,
        password,
      });
      form.reset();
      setEnrollment(null);
      setReservedEmail("");
      onConfirmed(result);
    } catch (caught) {
      setError(
        describePhaseTwoError(
          caught,
          "The TOTP proof or administrator details were not accepted. Review the fields and try again.",
        ),
      );
    } finally {
      setIsPending(false);
    }
  }

  if (!enrollment) {
    return (
      <AccessLayout
        activeStep={0}
        eyebrow="One-time platform bootstrap"
        title="Reserve the break-glass enrollment."
        description="Use the deployment bootstrap token to open a short enrollment window. No administrator or password is created at this step."
      >
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Begin enrollment</CardTitle>
            <CardDescription>
              The token comes from the platform operator who deployed this
              environment. It is sent as a protected request header and then
              cleared from the form.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="access-form" onSubmit={reserveEnrollment}>
              {error ? <FocusedError message={error} /> : null}
              <FormField
                htmlFor={`${id}-bootstrap-token`}
                label="Deployment bootstrap token"
                hint="This value is not saved in browser storage."
              >
                <Input
                  id={`${id}-bootstrap-token`}
                  name="bootstrapToken"
                  type="password"
                  autoComplete="off"
                  required
                  disabled={isPending}
                  aria-describedby={`${id}-bootstrap-token-hint`}
                />
              </FormField>
              <FormField
                htmlFor={`${id}-email`}
                label="Administrator email"
                hint="Reserve the enrollment for the address you will confirm next."
              >
                <Input
                  id={`${id}-email`}
                  name="email"
                  type="email"
                  autoComplete="username"
                  required
                  maxLength={320}
                  disabled={isPending}
                  aria-describedby={`${id}-email-hint`}
                />
              </FormField>
              <Button type="submit" size="lg" disabled={isPending}>
                <KeyRound aria-hidden="true" />
                {isPending
                  ? "Reserving enrollment…"
                  : "Generate TOTP enrollment"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </AccessLayout>
    );
  }

  return (
    <AccessLayout
      activeStep={1}
      eyebrow="One-time platform bootstrap"
      title="Prove the authenticator before creating access."
      description="Add this key to a local authenticator, then provide the current code and administrator details. The API creates the identity, permission grant, audit record, recovery codes, and session atomically."
    >
      <Card className="access-card access-card--wide">
        <CardHeader>
          <CardTitle>Confirm the break-glass administrator</CardTitle>
          <CardDescription className="enrollment-expiry">
            <Clock3 aria-hidden="true" /> Enrollment expires{" "}
            <time dateTime={enrollment.expiresAt}>
              {formatExpiry(enrollment.expiresAt)}
            </time>
          </CardDescription>
        </CardHeader>
        <CardContent className="enrollment-content">
          <Alert className="enrollment-note">
            <ShieldCheck aria-hidden="true" />
            <AlertTitle>Manual enrollment</AlertTitle>
            <AlertDescription>
              Add the key or URI to your authenticator. No QR dependency or
              external image service receives this secret.
            </AlertDescription>
          </Alert>
          <div className="secret-stack">
            <SecretValue label="Manual key" value={enrollment.totpSecret} />
            <SecretValue label="otpauth URI" value={enrollment.totpUri} />
          </div>

          <form className="access-form" onSubmit={confirmEnrollment}>
            {error ? <FocusedError message={error} /> : null}
            <div className="form-grid">
              <FormField
                htmlFor={`${id}-confirm-token`}
                label="Deployment bootstrap token"
                hint="Enter the deployment token again to confirm this reservation."
              >
                <Input
                  id={`${id}-confirm-token`}
                  name="bootstrapToken"
                  type="password"
                  autoComplete="off"
                  required
                  disabled={isPending}
                  aria-describedby={`${id}-confirm-token-hint`}
                />
              </FormField>
              <FormField
                htmlFor={`${id}-confirm-email`}
                label="Reserved email"
                hint="The reservation is bound to this normalized address. Keep this page open; a different address can be reserved only after this enrollment expires."
              >
                <Input
                  id={`${id}-confirm-email`}
                  name="email"
                  type="email"
                  autoComplete="username"
                  defaultValue={reservedEmail}
                  readOnly
                  aria-readonly="true"
                  required
                  maxLength={320}
                  disabled={isPending}
                  aria-describedby={`${id}-confirm-email-hint`}
                />
              </FormField>
              <FormField htmlFor={`${id}-display-name`} label="Display name">
                <Input
                  id={`${id}-display-name`}
                  name="displayName"
                  autoComplete="name"
                  required
                  maxLength={160}
                  disabled={isPending}
                />
              </FormField>
              <FormField
                htmlFor={`${id}-totp-code`}
                label="Authenticator code"
                hint="Enter the current six-digit code from the enrolled device."
              >
                <Input
                  id={`${id}-totp-code`}
                  name="code"
                  type="text"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  minLength={6}
                  maxLength={6}
                  required
                  disabled={isPending}
                  aria-describedby={`${id}-totp-code-hint`}
                />
              </FormField>
              <FormField htmlFor={`${id}-password`} label="Password">
                <Input
                  id={`${id}-password`}
                  name="password"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={15}
                  maxLength={128}
                  disabled={isPending}
                />
              </FormField>
              <FormField
                htmlFor={`${id}-password-confirmation`}
                label="Confirm password"
                {...(passwordError ? { error: passwordError } : {})}
              >
                <Input
                  id={`${id}-password-confirmation`}
                  name="passwordConfirmation"
                  type="password"
                  autoComplete="new-password"
                  required
                  minLength={15}
                  maxLength={128}
                  disabled={isPending}
                  aria-invalid={passwordError ? true : undefined}
                  aria-describedby={
                    passwordError
                      ? `${id}-password-confirmation-error`
                      : undefined
                  }
                />
              </FormField>
            </div>
            <Button type="submit" size="lg" disabled={isPending}>
              <ShieldCheck aria-hidden="true" />
              {isPending
                ? "Creating administrator…"
                : "Create break-glass administrator"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </AccessLayout>
  );
}

function formatExpiry(value: string): string {
  const expiry = new Date(value);
  if (Number.isNaN(expiry.valueOf())) {
    return "soon";
  }
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(expiry);
}
