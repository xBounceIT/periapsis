import { formatExpiry } from "./format-expiry";
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
  ArrowLeft,
  Fingerprint,
  KeyRound,
  LogIn,
  ShieldCheck,
} from "lucide-react";
import { useId, useRef, useState } from "react";

import { AccessLayout } from "../components/access-layout";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { readTextField } from "../lib/form-data";
import {
  describePhaseTwoError,
  type LoginChallengeView,
  type MfaMethod,
  type PhaseTwoApi,
  type SessionView,
} from "../lib/phase-two-types";
import { FederatedLoginForm } from "./federated-login-form";
import { LDAPLoginForm } from "./ldap-login-form";
import { mfaApi as defaultMfaApi, type MfaApi } from "./mfa/mfa-api";
import { PlatformOIDCLoginForm } from "./platform-oidc-login-form";
import { PlatformLDAPLoginForm } from "./platform-ldap-login-form";
import {
  getPasskeyResponse,
  type BrowserCredentials,
} from "./mfa/webauthn-browser";

interface ChallengeState {
  challenge: LoginChallengeView;
  email: string;
  method: MfaMethod;
}

interface LoginFlowProps {
  api: PhaseTwoApi;
  credentials?: BrowserCredentials;
  mfaApi?: Pick<MfaApi, "completePasskeyLogin" | "startPasskeyLogin">;
  onAuthenticated: (session: SessionView) => void;
}

function useLoginFlow({
  api,
  credentials,
  mfaApi = defaultMfaApi,
  onAuthenticated,
}: LoginFlowProps) {
  const [challengeState, setChallengeState] = useState<ChallengeState | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  // eslint-disable-next-line react-doctor/rendering-usetransition-loading -- Tracks network authentication and locks duplicate submissions synchronously; this is not a deferred UI transition.
  const [isPending, setIsPending] = useState(false);
  const pendingRef = useRef(false);
  const id = useId();

  function beginSubmission(): boolean {
    if (pendingRef.current) return false;
    pendingRef.current = true;
    setError(null);
    setIsPending(true);
    return true;
  }

  function finishSubmission(): void {
    pendingRef.current = false;
    setIsPending(false);
  }

  async function submitCredentials(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!beginSubmission()) return;
    const form = event.currentTarget;
    const fields = new FormData(form);
    const email = readTextField(fields, "email").trim().toLowerCase();

    try {
      const challenge = await api.login({
        email,
        password: readTextField(fields, "password"),
      });
      const method = challenge.methods.includes("totp")
        ? "totp"
        : challenge.methods[0];
      if (!method) {
        setError(
          "This sign-in challenge did not offer a supported verification method. Start again.",
        );
        return;
      }
      form.reset();
      setChallengeState({ challenge, email, method });
    } catch (caught) {
      setError(
        describePhaseTwoError(
          caught,
          "The email or password was not accepted. Check the credentials and try again.",
        ),
      );
    } finally {
      finishSubmission();
    }
  }

  async function submitMfa(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!challengeState) {
      return;
    }
    if (!beginSubmission()) return;
    const form = event.currentTarget;
    const fields = new FormData(form);

    try {
      const session = await api.completeMfa({
        challengeToken: challengeState.challenge.challengeToken,
        code: readTextField(fields, "code").trim(),
        method: challengeState.method,
      });
      form.reset();
      setChallengeState(null);
      onAuthenticated(session);
    } catch (caught) {
      setError(
        describePhaseTwoError(
          caught,
          challengeState.method === "totp"
            ? "The authenticator code was not accepted. Use the current code and try again."
            : "The recovery code was not accepted. Use an unused code and try again.",
        ),
      );
    } finally {
      finishSubmission();
    }
  }

  async function submitPasskey(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!beginSubmission()) return;
    const form = event.currentTarget;
    const tenantId = readTextField(new FormData(form), "tenantId").trim();

    try {
      const options = await mfaApi.startPasskeyLogin(tenantId);
      const response = await getPasskeyResponse(options, credentials);
      const session = await mfaApi.completePasskeyLogin(response);
      form.reset();
      onAuthenticated(session);
    } catch (caught) {
      setError(
        describePhaseTwoError(
          caught,
          "The passkey proof was not accepted. Confirm the tenant and try again.",
        ),
      );
    } finally {
      finishSubmission();
    }
  }

  function changeMethod(method: MfaMethod): void {
    setChallengeState((current) =>
      current ? { ...current, method } : current,
    );
    setError(null);
  }

  function restartLogin(): void {
    setChallengeState(null);
    setError(null);
  }

  return {
    challengeState,
    error,
    isPending,
    id,
    submitCredentials,
    submitMfa,
    submitPasskey,
    changeMethod,
    restartLogin,
  };
}

export function LoginFlow(props: LoginFlowProps): React.JSX.Element {
  const {
    challengeState,
    error,
    isPending,
    id,
    submitCredentials,
    submitMfa,
    submitPasskey,
    changeMethod,
    restartLogin,
  } = useLoginFlow(props);
  if (!challengeState) {
    return (
      <AccessLayout
        activeStep={0}
        eyebrow="Operator sign in"
        title="Identify the operator."
        description="Choose the tenant-bound organization flow configured by your administrator. Local credentials remain an emergency path and still require a separate MFA proof."
      >
        {error ? <FocusedError message={error} /> : null}
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Organization SSO</CardTitle>
            <CardDescription>
              Tenant and provider selection stay explicit. The browser starts a
              one-time OIDC or SAML ceremony without sending an existing
              session.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <FederatedLoginForm disabled={isPending} />
          </CardContent>
        </Card>
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Organization directory</CardTitle>
            <CardDescription>
              Verify a directory username and password against the selected
              tenant LDAP provider. Platform MFA remains a separate proof when
              required by live policy.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <LDAPLoginForm disabled={isPending} />
          </CardContent>
        </Card>
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Platform SSO</CardTitle>
            <CardDescription>
              Sign in through a global workforce provider that was explicitly
              enabled for pre-linked platform identities.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <PlatformOIDCLoginForm disabled={isPending} />
            <PlatformLDAPLoginForm disabled={isPending} />
          </CardContent>
        </Card>
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Emergency local sign-in</CardTitle>
            <CardDescription>
              The server returns the same failure response for unknown
              identities and incorrect credentials.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="access-form" onSubmit={submitCredentials}>
              <FormField htmlFor={`${id}-login-email`} label="Email">
                <Input
                  id={`${id}-login-email`}
                  name="email"
                  type="email"
                  autoComplete="username"
                  required
                  maxLength={320}
                  autoFocus
                  disabled={isPending}
                />
              </FormField>
              <FormField htmlFor={`${id}-login-password`} label="Password">
                <Input
                  id={`${id}-login-password`}
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  maxLength={128}
                  disabled={isPending}
                />
              </FormField>
              <Button type="submit" size="lg" disabled={isPending}>
                <LogIn aria-hidden="true" />
                {isPending ? "Checking credentials…" : "Continue to MFA"}
              </Button>
            </form>
          </CardContent>
        </Card>
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Use a passkey</CardTitle>
            <CardDescription>
              Tenant discovery stays explicit; the authenticator identifies the
              operator only inside that tenant boundary.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="access-form" onSubmit={submitPasskey}>
              <FormField
                htmlFor={`${id}-passkey-tenant`}
                label="Tenant ID"
                hint="Use the tenant UUID supplied by your administrator."
              >
                <Input
                  id={`${id}-passkey-tenant`}
                  name="tenantId"
                  type="text"
                  autoComplete="off"
                  inputMode="text"
                  pattern="[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
                  required
                  disabled={isPending}
                  aria-describedby={`${id}-passkey-tenant-hint`}
                />
              </FormField>
              <Button
                type="submit"
                size="lg"
                variant="outline"
                disabled={isPending}
              >
                <Fingerprint aria-hidden="true" />
                {isPending ? "Checking passkey…" : "Sign in with passkey"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </AccessLayout>
    );
  }

  return (
    <LocalLoginChallenge
      controller={{
        challengeState,
        error,
        isPending,
        id,
        submitCredentials,
        submitMfa,
        submitPasskey,
        changeMethod,
        restartLogin,
      }}
      challengeState={challengeState}
    />
  );
}

function LocalLoginChallenge({
  controller,
  challengeState,
}: {
  controller: ReturnType<typeof useLoginFlow>;
  challengeState: ChallengeState;
}): React.JSX.Element {
  const { error, isPending, id, submitMfa, changeMethod, restartLogin } =
    controller;
  const usesTotp = challengeState.method === "totp";
  return (
    <AccessLayout
      activeStep={1}
      eyebrow="Operator sign in"
      title="Complete the MFA proof."
      description={`The password was accepted for ${challengeState.email}. Finish the server-issued challenge before a session is created.`}
    >
      <Card className="access-card">
        <CardHeader>
          <CardTitle>Verify sign in</CardTitle>
          <CardDescription>
            Challenge expires {formatExpiry(challengeState.challenge.expiresAt)}
            .
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            key={challengeState.method}
            className="access-form"
            onSubmit={submitMfa}
          >
            {error ? <FocusedError message={error} /> : null}
            {challengeState.challenge.methods.length > 1 ? (
              <fieldset className="method-picker">
                <legend>Verification method</legend>
                <div>
                  {challengeState.challenge.methods.map((method) => (
                    <Button
                      key={method}
                      type="button"
                      variant={
                        challengeState.method === method
                          ? "secondary"
                          : "outline"
                      }
                      aria-pressed={challengeState.method === method}
                      onClick={() => changeMethod(method)}
                      disabled={isPending}
                    >
                      {method === "totp" ? (
                        <ShieldCheck aria-hidden="true" />
                      ) : (
                        <KeyRound aria-hidden="true" />
                      )}
                      {method === "totp" ? "Authenticator" : "Recovery code"}
                    </Button>
                  ))}
                </div>
              </fieldset>
            ) : null}
            <FormField
              htmlFor={`${id}-mfa-code`}
              label={usesTotp ? "Authenticator code" : "Recovery code"}
              hint={
                usesTotp
                  ? "Enter the current six-digit code."
                  : "Each recovery code can be used only once."
              }
            >
              <Input
                id={`${id}-mfa-code`}
                name="code"
                type="text"
                autoComplete="one-time-code"
                inputMode={usesTotp ? "numeric" : "text"}
                pattern={usesTotp ? "[0-9]{6}" : undefined}
                minLength={usesTotp ? 6 : 32}
                maxLength={usesTotp ? 6 : 64}
                required
                autoFocus
                disabled={isPending}
                aria-describedby={`${id}-mfa-code-hint`}
              />
            </FormField>
            <div className="form-actions">
              <Button type="submit" size="lg" disabled={isPending}>
                <ShieldCheck aria-hidden="true" />
                {isPending ? "Verifying…" : "Verify and sign in"}
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={restartLogin}
                disabled={isPending}
              >
                <ArrowLeft aria-hidden="true" /> Use a different account
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </AccessLayout>
  );
}
