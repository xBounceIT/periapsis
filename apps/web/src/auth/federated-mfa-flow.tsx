import type { MfaStepUpChallenge, TotpEnrollment } from "@periapsis/contracts";
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
import {
  ArrowLeft,
  Fingerprint,
  KeyRound,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
} from "lucide-react";
import { useId, useRef, useState } from "react";

import { AccessLayout } from "../components/access-layout";
import { FocusedError } from "../components/focused-error";
import { FormField } from "../components/form-field";
import { SecretValue } from "../components/secret-value";
import { readTextField } from "../lib/form-data";
import type { SessionView } from "../lib/phase-two-types";
import { useBeforeUnloadWarning } from "../lib/use-before-unload-warning";
import {
  federatedMfaApi as defaultApi,
  MfaApiError,
  type FederatedMfaApi,
} from "./mfa/mfa-api";
import {
  getPasskeyResponse,
  type BrowserCredentials,
} from "./mfa/webauthn-browser";

type LocalMethod = "recovery_code" | "totp";

type FlowState =
  | { kind: "choice" }
  | {
      challenge: MfaStepUpChallenge;
      factorId: string;
      kind: "challenge";
      method: LocalMethod;
    }
  | { enrollment: TotpEnrollment; kind: "enrollment" };

interface FederatedMfaFlowProps {
  api?: FederatedMfaApi;
  credentials?: BrowserCredentials;
  onAuthenticated: (session: SessionView) => void;
  onRestart: () => void;
}

export function FederatedMfaFlow({
  api = defaultApi,
  credentials,
  onAuthenticated,
  onRestart,
}: FederatedMfaFlowProps): React.JSX.Element {
  const [state, setState] = useState<FlowState>({ kind: "choice" });
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [isPending, setIsPending] = useState(false);
  const pendingRef = useRef(false);
  const id = useId();

  useBeforeUnloadWarning(state.kind === "enrollment");

  async function run(
    operation: () => Promise<void>,
    fallback: string,
    afterFailure?: () => void,
  ): Promise<void> {
    if (pendingRef.current) return;
    pendingRef.current = true;
    setError(null);
    setIsPending(true);
    try {
      await operation();
    } catch (caught) {
      afterFailure?.();
      setError(continuationError(caught, fallback));
    } finally {
      pendingRef.current = false;
      setIsPending(false);
    }
  }

  async function startLocalChallenge(): Promise<void> {
    await run(async () => {
      const challenge = await api.startLocalStepUp();
      const method: LocalMethod = challenge.methods.includes("totp")
        ? "totp"
        : "recovery_code";
      const factorId = challenge.totpFactorIds[0] ?? "";
      setNotice(null);
      setState({ challenge, factorId, kind: "challenge", method });
    }, "No local authenticator or recovery proof is available for this continuation.");
  }

  async function completeLocalChallenge(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (state.kind !== "challenge") return;
    const form = event.currentTarget;
    const code = readTextField(new FormData(form), "code").trim();
    await run(
      async () => {
        const session =
          state.method === "totp"
            ? await api.completeTotpStepUp(
                state.challenge.challengeId,
                state.factorId,
                code,
              )
            : await api.completeRecoveryStepUp(
                state.challenge.challengeId,
                code,
              );
        form.reset();
        onAuthenticated(session);
      },
      state.method === "totp"
        ? "The authenticator code was not accepted. Start a new one-use challenge and try again."
        : "The recovery code was not accepted. Start a new one-use challenge with an unused code.",
      () => setState({ kind: "choice" }),
    );
  }

  async function completeWithPasskey(): Promise<void> {
    await run(async () => {
      const options = await api.startPasskeyStepUp();
      let submitted = false;
      try {
        const response = await getPasskeyResponse(options, credentials);
        submitted = true;
        const session = await api.completePasskeyStepUp(response);
        onAuthenticated(session);
      } catch (caught) {
        if (!submitted) {
          await api.cancelCeremony();
        }
        throw caught;
      }
    }, "The passkey proof was cancelled or not accepted. Start a fresh proof to try again.");
  }

  async function startEnrollment(): Promise<void> {
    await run(async () => {
      const enrollment = await api.startTotpEnrollment();
      setNotice(null);
      setState({ enrollment, kind: "enrollment" });
    }, "This tenant does not allow authenticator enrollment from the current continuation.");
  }

  async function completeEnrollment(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (state.kind !== "enrollment") return;
    const form = event.currentTarget;
    const code = readTextField(new FormData(form), "code").trim();
    await run(
      async () => {
        await api.completeTotpEnrollment(state.enrollment.enrollmentId, code);
        form.reset();
        setState({ kind: "choice" });
        setNotice(
          "Authenticator enrolled. Now start a separate local proof with the new current code to create the session.",
        );
      },
      "The enrollment code was not accepted. The one-time secret was discarded; start enrollment again.",
      () => setState({ kind: "choice" }),
    );
  }

  function changeMethod(method: LocalMethod): void {
    if (state.kind !== "challenge") return;
    setState({
      ...state,
      factorId:
        method === "totp" ? (state.challenge.totpFactorIds[0] ?? "") : "",
      method,
    });
    setError(null);
  }

  async function discardCeremony(): Promise<void> {
    await run(async () => {
      await api.cancelCeremony();
      setNotice(null);
      setState({ kind: "choice" });
    }, "The one-use proof could not be discarded. Retry or restart organization sign in.");
  }

  async function restartSignIn(): Promise<void> {
    await run(async () => {
      await api.abandonContinuation();
      onRestart();
    }, "Federated browser state could not be cleared. Retry before starting another organization sign in.");
  }

  return (
    <AccessLayout
      activeStep={1}
      eyebrow="Organization sign in"
      title="Complete local MFA."
      description="Your identity provider proof was accepted, but tenant policy requires a separate local factor. No application session exists until one of these one-use proofs succeeds."
    >
      {error ? <FocusedError message={error} /> : null}
      {notice ? (
        <Alert>
          <ShieldCheck aria-hidden="true" />
          <AlertTitle>Authenticator ready</AlertTitle>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}

      {state.kind === "choice" ? (
        <>
          <Card className="access-card">
            <CardHeader>
              <CardTitle>Authenticator or recovery code</CardTitle>
              <CardDescription>
                Start one bounded challenge. The server reveals only methods
                allowed by the exact pending continuation.
              </CardDescription>
            </CardHeader>
            <CardContent className="access-form">
              <Button
                type="button"
                size="lg"
                disabled={isPending}
                onClick={() => void startLocalChallenge()}
              >
                <ShieldCheck aria-hidden="true" />
                {isPending ? "Starting proof…" : "Use local verification"}
              </Button>
            </CardContent>
          </Card>

          <Card className="access-card">
            <CardHeader>
              <CardTitle>Passkey</CardTitle>
              <CardDescription>
                Use an enrolled, user-verified authenticator bound to this
                Periapsis origin.
              </CardDescription>
            </CardHeader>
            <CardContent className="access-form">
              <Button
                type="button"
                size="lg"
                variant="outline"
                disabled={isPending}
                onClick={() => void completeWithPasskey()}
              >
                <Fingerprint aria-hidden="true" />
                {isPending ? "Checking passkey…" : "Verify with passkey"}
              </Button>
            </CardContent>
          </Card>

          <Card className="access-card">
            <CardHeader>
              <CardTitle>Enrollment grace</CardTitle>
              <CardDescription>
                If tenant policy allows a bounded first-login grace period,
                enroll an authenticator here. Enrollment alone does not create a
                session.
              </CardDescription>
            </CardHeader>
            <CardContent className="access-form">
              <Button
                type="button"
                variant="ghost"
                disabled={isPending}
                onClick={() => void startEnrollment()}
              >
                <Smartphone aria-hidden="true" /> Set up an authenticator
              </Button>
              <Button
                type="button"
                variant="ghost"
                disabled={isPending}
                onClick={() => void restartSignIn()}
              >
                <ArrowLeft aria-hidden="true" /> Restart organization sign in
              </Button>
            </CardContent>
          </Card>
        </>
      ) : null}

      {state.kind === "challenge" ? (
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Verify the local factor</CardTitle>
            <CardDescription>
              This one-use challenge expires{" "}
              {formatExpiry(state.challenge.expiresAt)}.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="access-form" onSubmit={completeLocalChallenge}>
              {state.challenge.methods.length > 1 ? (
                <fieldset className="method-picker">
                  <legend>Verification method</legend>
                  <div>
                    {state.challenge.methods.map((method) => (
                      <Button
                        key={method}
                        type="button"
                        variant={
                          state.method === method ? "secondary" : "outline"
                        }
                        aria-pressed={state.method === method}
                        disabled={isPending}
                        onClick={() => changeMethod(method)}
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

              {state.method === "totp" &&
              state.challenge.totpFactorIds.length > 1 ? (
                <FormField
                  htmlFor={`${id}-factor`}
                  label="Authenticator"
                  hint="Choose the factor that generated the current code."
                >
                  <select
                    id={`${id}-factor`}
                    value={state.factorId}
                    disabled={isPending}
                    onChange={(event) =>
                      setState({
                        ...state,
                        factorId: event.currentTarget.value,
                      })
                    }
                    aria-describedby={`${id}-factor-hint`}
                  >
                    {state.challenge.totpFactorIds.map((factorId, index) => (
                      <option key={factorId} value={factorId}>
                        Authenticator {index + 1}
                      </option>
                    ))}
                  </select>
                </FormField>
              ) : null}

              <FormField
                htmlFor={`${id}-proof-code`}
                label={
                  state.method === "totp"
                    ? "Authenticator code"
                    : "Recovery code"
                }
                hint={
                  state.method === "totp"
                    ? "Enter the current six-digit code."
                    : "Each recovery code can be used only once."
                }
              >
                <Input
                  id={`${id}-proof-code`}
                  name="code"
                  type="text"
                  autoComplete="one-time-code"
                  inputMode={state.method === "totp" ? "numeric" : "text"}
                  pattern={state.method === "totp" ? "[0-9]{6}" : undefined}
                  minLength={state.method === "totp" ? 6 : 16}
                  maxLength={state.method === "totp" ? 6 : 128}
                  required
                  autoFocus
                  disabled={isPending}
                  aria-describedby={`${id}-proof-code-hint`}
                />
              </FormField>
              <div className="form-actions">
                <Button type="submit" size="lg" disabled={isPending}>
                  <ShieldCheck aria-hidden="true" />
                  {isPending ? "Verifying…" : "Verify and create session"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={isPending}
                  onClick={() => void discardCeremony()}
                >
                  <ArrowLeft aria-hidden="true" /> Choose another method
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}

      {state.kind === "enrollment" ? (
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Enroll an authenticator</CardTitle>
            <CardDescription>
              Add the URI or manual secret to an approved authenticator, then
              verify the current code before this one-use enrollment expires.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="access-form" onSubmit={completeEnrollment}>
              <Alert>
                <ShieldAlert aria-hidden="true" />
                <AlertTitle>One-time enrollment material</AlertTitle>
                <AlertDescription>
                  It is displayed only in this live flow and is never accepted
                  back by the server except through the generated TOTP proof.
                </AlertDescription>
              </Alert>
              <SecretValue
                label="Provisioning URI"
                value={state.enrollment.provisioningUri}
              />
              <SecretValue
                label="Manual secret"
                value={state.enrollment.secret}
              />
              <FormField
                htmlFor={`${id}-enrollment-code`}
                label="Current six-digit code"
                hint={`Enrollment expires ${formatExpiry(state.enrollment.expiresAt)}.`}
              >
                <Input
                  id={`${id}-enrollment-code`}
                  name="code"
                  type="text"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  pattern="[0-9]{6}"
                  minLength={6}
                  maxLength={6}
                  required
                  autoFocus
                  disabled={isPending}
                  aria-describedby={`${id}-enrollment-code-hint`}
                />
              </FormField>
              <div className="form-actions">
                <Button type="submit" size="lg" disabled={isPending}>
                  <Smartphone aria-hidden="true" />
                  {isPending
                    ? "Verifying enrollment…"
                    : "Confirm authenticator"}
                </Button>
                <Button
                  type="button"
                  variant="ghost"
                  disabled={isPending}
                  onClick={() => void discardCeremony()}
                >
                  Discard one-time secret
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      ) : null}
    </AccessLayout>
  );
}

function continuationError(caught: unknown, fallback: string): string {
  if (caught instanceof MfaApiError) {
    if (caught.status === 401) {
      return "The federated continuation expired or was already used. Restart organization sign in.";
    }
    if (caught.status === 429) {
      return "Too many verification attempts. Wait before starting another proof.";
    }
    if (caught.message.trim() !== "") return caught.message;
  }
  return fallback;
}

function formatExpiry(value: string): string {
  const expiry = new Date(value);
  if (Number.isNaN(expiry.valueOf())) return "soon";
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    timeZoneName: "short",
  }).format(expiry);
}
