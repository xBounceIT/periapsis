const deviceDateFormatter = new Intl.DateTimeFormat(undefined, {
  day: "2-digit",
  month: "short",
  year: "numeric",
});
// oxlint-disable-next-line import/no-unassigned-import -- Component-scoped security workspace styles.
import "./mfa-workspace.css";

import type { MfaStepUpChallenge, TotpEnrollment } from "@periapsis/contracts";
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
  Check,
  Copy,
  Fingerprint,
  KeyRound,
  Laptop,
  Pencil,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Trash2,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
} from "react";
import { Link, useNavigate } from "react-router";

import { useSession } from "../session-context";
import { FocusedError } from "../../components/focused-error";
import { FormField } from "../../components/form-field";
import { readTextField } from "../../lib/form-data";
import { useBeforeUnloadWarning } from "../../lib/use-before-unload-warning";
import { mfaApi as defaultApi, MfaApiError, type MfaApi } from "./mfa-api";
import type { MfaDevicePageView, MfaDeviceView } from "./model";
import {
  createPasskeyResponse,
  getPasskeyResponse,
  type BrowserCredentials,
} from "./webauthn-browser";

type DeviceState =
  | { kind: "error"; message: string }
  | { kind: "loading" }
  | ({ kind: "ready"; queryKey: string } & MfaDevicePageView);

interface MfaSecurityWorkspaceProps {
  api?: MfaApi;
  credentials?: BrowserCredentials;
}

const deviceManagementAction = "mfa.device.manage";

function useMfaSecurityWorkspace({
  api = defaultApi,
  credentials,
}: MfaSecurityWorkspaceProps) {
  const {
    api: sessionApi,
    clearSession,
    session,
    updateSession,
  } = useSession();
  const navigate = useNavigate();
  const id = useId();
  const [devices, setDevices] = useState<DeviceState>({ kind: "loading" });
  const [includeRevoked, setIncludeRevoked] = useState(false);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [isLoadingMore, setIsLoadingMore] = useState(false);
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);
  const [recoveryCodes, setRecoveryCodes] = useState<readonly string[]>([]);
  const [stepUp, setStepUp] = useState<MfaStepUpChallenge | null>(null);
  const [stepUpMethod, setStepUpMethod] = useState<"recovery_code" | "totp">(
    "totp",
  );
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [copyState, setCopyState] = useState<"copied" | "failed" | "idle">(
    "idle",
  );
  const busyActionRef = useRef<string | null>(null);
  const inventoryQueryKey = `${session.activeTenantId ?? "none"}:${includeRevoked ? "all" : "active"}:${loadAttempt}`;

  useBeforeUnloadWarning(recoveryCodes.length > 0 || enrollment !== null);

  const activeTotp = useMemo(
    () =>
      devices.kind === "ready"
        ? devices.items.find(
            (device) => device.kind === "totp" && device.status === "active",
          )
        : undefined,
    [devices],
  );

  const handleAuthenticationError = useCallback(
    (caught: unknown): boolean => {
      if (caught instanceof MfaApiError && caught.status === 401) {
        void navigate("/");
        clearSession(session.id);
        return true;
      }
      return false;
    },
    [clearSession, navigate, session.id],
  );

  useEffect(() => {
    if (!session.activeTenantId) return undefined;
    const controller = new AbortController();
    setIsLoadingMore(false);
    setDevices({ kind: "loading" });
    void api
      .listDevices({ includeRevoked, signal: controller.signal })
      .then((page) => {
        if (!controller.signal.aborted) {
          setDevices({ kind: "ready", queryKey: inventoryQueryKey, ...page });
        }
      })
      .catch((caught: unknown) => {
        if (controller.signal.aborted) return;
        if (handleAuthenticationError(caught)) return;
        setDevices({
          kind: "error",
          message: errorMessage(caught, "MFA devices could not be loaded."),
        });
      });
    return () => controller.abort();
  }, [
    api,
    handleAuthenticationError,
    includeRevoked,
    inventoryQueryKey,
    session.activeTenantId,
  ]);

  async function refreshRotatedSession(): Promise<void> {
    const expected = session.id;
    const refreshed = await sessionApi.getSession();
    if (!refreshed) {
      clearSession(expected);
      void navigate("/");
      throw new MfaApiError(
        "The rotated session could not be revalidated.",
        401,
      );
    }
    updateSession(expected, refreshed);
  }

  async function loadMore(): Promise<void> {
    if (devices.kind !== "ready" || !devices.nextCursor || isLoadingMore)
      return;
    const cursor = devices.nextCursor;
    const queryKey = devices.queryKey;
    setIsLoadingMore(true);
    setError(null);
    try {
      const page = await api.listDevices({
        after: cursor,
        includeRevoked,
      });
      if (page.nextCursor === cursor)
        throw new MfaApiError("The device cursor did not advance.");
      setDevices((current) =>
        current.kind === "ready" &&
        current.queryKey === queryKey &&
        current.nextCursor === cursor
          ? {
              kind: "ready",
              items: appendUniqueDevices(current.items, page.items),
              queryKey,
              ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}),
            }
          : current,
      );
    } catch (caught) {
      if (!handleAuthenticationError(caught)) {
        setError(errorMessage(caught, "More MFA devices could not be loaded."));
      }
    } finally {
      setIsLoadingMore(false);
    }
  }

  async function startTotp(): Promise<void> {
    await run("start-totp", async () => {
      const result = await api.startTotpEnrollment(session.csrfToken);
      setEnrollment(result);
      setRecoveryCodes([]);
      setNotice(
        "Authenticator enrollment started. Save the secret before verifying it.",
      );
    });
  }

  async function finishTotp(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!enrollment) return;
    const form = event.currentTarget;
    const code = readTextField(new FormData(form), "code").trim();
    await run("finish-totp", async () => {
      await api.completeTotpEnrollment(
        session.csrfToken,
        enrollment.enrollmentId,
        code,
      );
      await refreshRotatedSession();
      form.reset();
      setEnrollment(null);
      setNotice("Authenticator enrolled and the browser session rotated.");
      setLoadAttempt((value) => value + 1);
    });
  }

  async function registerPasskey(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const displayName = readTextField(new FormData(form), "displayName");
    await run("register-passkey", async () => {
      const options = await api.startPasskeyRegistration(session.csrfToken);
      const response = await createPasskeyResponse(
        options,
        displayName,
        credentials,
      );
      await api.completePasskeyRegistration(session.csrfToken, response);
      await refreshRotatedSession();
      form.reset();
      setNotice("Passkey registered and the browser session rotated.");
      setLoadAttempt((value) => value + 1);
    });
  }

  async function startLocalVerification(): Promise<void> {
    await run("start-step-up", async () => {
      const challenge = await api.startLocalStepUp(
        session.csrfToken,
        deviceManagementAction,
      );
      setStepUp(challenge);
      setStepUpMethod(
        challenge.methods.includes("totp") ? "totp" : "recovery_code",
      );
      setNotice(null);
    });
  }

  async function finishLocalVerification(
    event: React.FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault();
    if (!stepUp) return;
    const form = event.currentTarget;
    const code = readTextField(new FormData(form), "code").trim();
    await run("finish-step-up", async () => {
      if (stepUpMethod === "totp") {
        if (!activeTotp)
          throw new MfaApiError("No active authenticator is available.");
        await api.completeTotpStepUp(
          session.csrfToken,
          stepUp.challengeId,
          activeTotp.id,
          code,
        );
      } else {
        await api.completeRecoveryStepUp(
          session.csrfToken,
          stepUp.challengeId,
          code,
        );
      }
      await refreshRotatedSession();
      form.reset();
      setStepUp(null);
      setNotice(
        "Fresh local MFA verified. Sensitive device actions are unlocked briefly.",
      );
    });
  }

  async function verifyWithPasskey(): Promise<void> {
    await run("passkey-step-up", async () => {
      const options = await api.startPasskeyStepUp(
        session.csrfToken,
        deviceManagementAction,
      );
      const response = await getPasskeyResponse(options, credentials);
      await api.completePasskeyStepUp(session.csrfToken, response);
      await refreshRotatedSession();
      setStepUp(null);
      setNotice(
        "Fresh passkey verification completed. Sensitive device actions are unlocked briefly.",
      );
    });
  }

  async function regenerateCodes(): Promise<void> {
    await run("recovery-codes", async () => {
      const codes = await api.regenerateRecoveryCodes(session.csrfToken);
      await refreshRotatedSession();
      setRecoveryCodes(codes);
      setCopyState("idle");
      setNotice(
        "Previous recovery codes were retired. Save this replacement set now.",
      );
    });
  }

  async function renamePasskey(
    event: React.FormEvent<HTMLFormElement>,
    device: MfaDeviceView,
  ): Promise<void> {
    event.preventDefault();
    const form = event.currentTarget;
    const displayName = readTextField(new FormData(form), "displayName");
    await run(`rename-${device.id}`, async () => {
      await api.renamePasskey(session.csrfToken, device, displayName);
      form.reset();
      setRenamingId(null);
      setNotice("Passkey renamed.");
      setLoadAttempt((value) => value + 1);
    });
  }

  async function revokeDevice(device: MfaDeviceView): Promise<void> {
    await run(`revoke-${device.id}`, async () => {
      const result = await api.revokeDevice(session.csrfToken, device);
      if (result.currentSessionRevoked) {
        clearSession(session.id);
        void navigate("/");
        return;
      }
      setConfirmingId(null);
      setNotice(
        `${device.kind === "passkey" ? "Passkey" : "Authenticator"} revoked.`,
      );
      setLoadAttempt((value) => value + 1);
    });
  }

  async function copyRecoveryCodes(): Promise<void> {
    try {
      await navigator.clipboard.writeText(recoveryCodes.join("\n"));
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  }

  async function run(
    key: string,
    operation: () => Promise<void>,
  ): Promise<void> {
    if (busyActionRef.current !== null) return;
    busyActionRef.current = key;
    setBusyAction(key);
    setError(null);
    setNotice(null);
    try {
      await operation();
    } catch (caught) {
      if (handleAuthenticationError(caught)) return;
      if (caught instanceof MfaApiError && caught.status === 412) {
        setLoadAttempt((value) => value + 1);
      }
      setError(
        errorMessage(caught, "The security operation did not complete."),
      );
    } finally {
      if (busyActionRef.current === key) {
        busyActionRef.current = null;
        setBusyAction(null);
      }
    }
  }

  return {
    session,
    id,
    devices,
    includeRevoked,
    setIncludeRevoked,
    setLoadAttempt,
    isLoadingMore,
    busyAction,
    error,
    notice,
    enrollment,
    setEnrollment,
    recoveryCodes,
    setRecoveryCodes,
    stepUp,
    setStepUp,
    stepUpMethod,
    setStepUpMethod,
    renamingId,
    setRenamingId,
    confirmingId,
    setConfirmingId,
    copyState,
    activeTotp,
    loadMore,
    startTotp,
    finishTotp,
    registerPasskey,
    startLocalVerification,
    finishLocalVerification,
    verifyWithPasskey,
    regenerateCodes,
    renamePasskey,
    revokeDevice,
    copyRecoveryCodes,
  };
}

export function MfaSecurityWorkspace(
  props: MfaSecurityWorkspaceProps,
): React.JSX.Element {
  const controller = useMfaSecurityWorkspace(props);
  const { session, error, notice } = controller;
  if (!session.activeTenantId) {
    return (
      <div className="content mfa-security">
        <FocusedError
          message="Select an active tenant before managing tenant-bound MFA devices."
          title="Tenant context required"
        />
      </div>
    );
  }

  return (
    <div className="content mfa-security">
      <section
        className="mfa-security__heading"
        aria-labelledby="mfa-security-title"
      >
        <div>
          <p className="section-label">Identity assurance</p>
          <h1 id="mfa-security-title">Security instruments</h1>
          <p>
            Enroll local factors, verify a recent step-up, and retire devices
            without exposing verifier material.
          </p>
        </div>
        <Badge variant="outline">
          <ShieldCheck aria-hidden="true" /> Owner-only
        </Badge>
      </section>

      <div className="mfa-security__status" aria-live="polite">
        {error ? (
          <FocusedError message={error} title="Security operation stopped" />
        ) : null}
        {notice ? (
          <Alert>
            <Check aria-hidden="true" />
            <AlertTitle>Security state updated</AlertTitle>
            <AlertDescription>{notice}</AlertDescription>
          </Alert>
        ) : null}
      </div>

      <section
        className="mfa-security__grid"
        aria-label="MFA enrollment and verification"
      >
        <FreshVerificationCard controller={controller} />
        <TotpEnrollmentCard controller={controller} />
        <PasskeyEnrollmentCard controller={controller} />
        <RecoveryCodeCard controller={controller} />
      </section>

      <DeviceInventory controller={controller} />

      <Card className="mfa-security__sessions">
        <CardHeader>
          <span className="mfa-security__icon" aria-hidden="true">
            <Laptop />
          </span>
          <div>
            <CardTitle>Browser sessions</CardTitle>
            <CardDescription>
              Review session metadata and revoke unexpected browsers separately.
            </CardDescription>
          </div>
        </CardHeader>
        <CardContent>
          <Button asChild variant="outline">
            <Link to="/sessions">Review sessions</Link>
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}

interface DeviceCardProps {
  busy: boolean;
  confirming: boolean;
  device: MfaDeviceView;
  nameId: string;
  onBeginRename: () => void;
  onBeginRevoke: () => void;
  onCancelRename: () => void;
  onCancelRevoke: () => void;
  onRename: (event: React.FormEvent<HTMLFormElement>) => void;
  onRevoke: () => void;
  renaming: boolean;
}

function DeviceCard(props: DeviceCardProps): React.JSX.Element {
  const { device } = props;
  const inactive = device.status !== "active";
  return (
    <Card className="mfa-security__device">
      <CardHeader>
        <span className="mfa-security__device-icon" aria-hidden="true">
          {device.kind === "passkey" ? <Fingerprint /> : <Smartphone />}
        </span>
        <div>
          <CardTitle>
            {device.kind === "passkey"
              ? device.displayName
              : "Authenticator app"}
          </CardTitle>
          <CardDescription>
            Added {formatTimestamp(device.createdAt)}
          </CardDescription>
        </div>
        <Badge variant={inactive ? "outline" : "secondary"}>
          {formatDeviceStatus(device.status)}
        </Badge>
      </CardHeader>
      <CardContent>
        <dl className="mfa-security__metadata">
          <div>
            <dt>Type</dt>
            <dd>{device.kind === "passkey" ? "Passkey" : "TOTP"}</dd>
          </div>
          <div>
            <dt>Last used</dt>
            <dd>
              {device.lastUsedAt
                ? formatTimestamp(device.lastUsedAt)
                : "Not recorded"}
            </dd>
          </div>
          {device.kind === "passkey" ? (
            <div>
              <dt>Authenticator</dt>
              <dd>
                {device.backedUp
                  ? "Synced passkey"
                  : device.discoverable
                    ? "Discoverable"
                    : "Device-bound"}
              </dd>
            </div>
          ) : null}
        </dl>
        <DeviceActions {...props} />
      </CardContent>
    </Card>
  );
}

function DeviceSkeleton(): React.JSX.Element {
  return (
    <div className="mfa-security__skeleton" aria-label="Loading MFA devices">
      <span />
      <span />
    </div>
  );
}

function appendUniqueDevices(
  current: readonly MfaDeviceView[],
  incoming: readonly MfaDeviceView[],
): readonly MfaDeviceView[] {
  const seen = new Set(current.map((device) => `${device.kind}:${device.id}`));
  return [
    ...current,
    ...incoming.filter((device) => {
      const key = `${device.kind}:${device.id}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    }),
  ];
}

function errorMessage(caught: unknown, fallback: string): string {
  return caught instanceof Error && caught.message ? caught.message : fallback;
}

function formatDeviceStatus(status: MfaDeviceView["status"]): string {
  const labels: Record<MfaDeviceView["status"], string> = {
    active: "Active",
    clone_suspected: "Clone suspected",
    revoked: "Revoked",
  };
  return labels[status];
}

function formatTimestamp(value: string): string {
  const instant = new Date(value);
  if (Number.isNaN(instant.valueOf())) return "Unavailable";
  return deviceDateFormatter.format(instant);
}

function FreshVerificationCard({
  controller,
}: {
  controller: ReturnType<typeof useMfaSecurityWorkspace>;
}): React.JSX.Element {
  const {
    stepUp,
    stepUpMethod,
    setStepUpMethod,
    id,
    busyAction,
    finishLocalVerification,
    setStepUp,
    startLocalVerification,
    activeTotp,
    devices,
    verifyWithPasskey,
  } = controller;
  return (
    <Card className="mfa-security__card mfa-security__card--assurance">
      <CardHeader>
        <span className="mfa-security__icon" aria-hidden="true">
          <ShieldCheck />
        </span>
        <div>
          <CardTitle>Fresh verification</CardTitle>
          <CardDescription>
            Required by recovery-code and device lifecycle mutations.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        {stepUp ? (
          <form
            className="mfa-security__form"
            onSubmit={finishLocalVerification}
          >
            {stepUp.methods.length > 1 ? (
              <fieldset className="mfa-security__method-picker">
                <legend>Verification method</legend>
                {stepUp.methods.map((method) => (
                  <Button
                    key={method}
                    type="button"
                    size="sm"
                    variant={stepUpMethod === method ? "secondary" : "outline"}
                    aria-pressed={stepUpMethod === method}
                    onClick={() => setStepUpMethod(method)}
                  >
                    {method === "totp" ? "Authenticator" : "Recovery code"}
                  </Button>
                ))}
              </fieldset>
            ) : null}
            <FormField
              htmlFor={`${id}-step-up-code`}
              label={
                stepUpMethod === "totp" ? "Authenticator code" : "Recovery code"
              }
            >
              <Input
                id={`${id}-step-up-code`}
                name="code"
                autoComplete="one-time-code"
                inputMode={stepUpMethod === "totp" ? "numeric" : "text"}
                minLength={stepUpMethod === "totp" ? 6 : 16}
                maxLength={stepUpMethod === "totp" ? 6 : 128}
                pattern={stepUpMethod === "totp" ? "[0-9]{6}" : undefined}
                required
                disabled={busyAction !== null}
              />
            </FormField>
            <div className="mfa-security__actions">
              <Button type="submit" disabled={busyAction !== null}>
                Verify locally
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setStepUp(null)}
                disabled={busyAction !== null}
              >
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <div className="mfa-security__actions">
            <Button
              type="button"
              variant="outline"
              onClick={() => void startLocalVerification()}
              disabled={
                busyAction !== null || (!activeTotp && devices.kind === "ready")
              }
            >
              <Smartphone aria-hidden="true" /> Verify code
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => void verifyWithPasskey()}
              disabled={busyAction !== null}
            >
              <Fingerprint aria-hidden="true" /> Use passkey
            </Button>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function TotpEnrollmentCard({
  controller,
}: {
  controller: ReturnType<typeof useMfaSecurityWorkspace>;
}): React.JSX.Element {
  const { enrollment, finishTotp, id, busyAction, setEnrollment, startTotp } =
    controller;
  return (
    <Card className="mfa-security__card">
      <CardHeader>
        <span className="mfa-security__icon" aria-hidden="true">
          <Smartphone />
        </span>
        <div>
          <CardTitle>Authenticator app</CardTitle>
          <CardDescription>Add one time-based code generator.</CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        {enrollment ? (
          <form className="mfa-security__form" onSubmit={finishTotp}>
            <Alert className="mfa-security__one-time">
              <ShieldAlert aria-hidden="true" />
              <AlertTitle>One-time enrollment secret</AlertTitle>
              <AlertDescription>
                Save this before continuing. It will not be shown again.
              </AlertDescription>
            </Alert>
            <code className="mfa-security__secret">{enrollment.secret}</code>
            <FormField
              htmlFor={`${id}-enrollment-code`}
              label="Current six-digit code"
            >
              <Input
                id={`${id}-enrollment-code`}
                name="code"
                autoComplete="one-time-code"
                inputMode="numeric"
                pattern="[0-9]{6}"
                minLength={6}
                maxLength={6}
                required
                disabled={busyAction !== null}
              />
            </FormField>
            <div className="mfa-security__actions">
              <Button type="submit" disabled={busyAction !== null}>
                Confirm authenticator
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => setEnrollment(null)}
                disabled={busyAction !== null}
              >
                Discard secret
              </Button>
            </div>
          </form>
        ) : (
          <Button
            type="button"
            onClick={() => void startTotp()}
            disabled={busyAction !== null}
          >
            <KeyRound aria-hidden="true" /> Add authenticator
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

function PasskeyEnrollmentCard({
  controller,
}: {
  controller: ReturnType<typeof useMfaSecurityWorkspace>;
}): React.JSX.Element {
  const { registerPasskey, id, busyAction } = controller;
  return (
    <Card className="mfa-security__card">
      <CardHeader>
        <span className="mfa-security__icon" aria-hidden="true">
          <Fingerprint />
        </span>
        <div>
          <CardTitle>Passkey</CardTitle>
          <CardDescription>
            Register a platform or roaming authenticator.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        <form className="mfa-security__form" onSubmit={registerPasskey}>
          <FormField htmlFor={`${id}-passkey-name`} label="Passkey name">
            <Input
              id={`${id}-passkey-name`}
              name="displayName"
              placeholder="Work laptop"
              minLength={1}
              maxLength={120}
              required
              disabled={busyAction !== null}
            />
          </FormField>
          <Button type="submit" disabled={busyAction !== null}>
            <Fingerprint aria-hidden="true" /> Register passkey
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}

function RecoveryCodeCard({
  controller,
}: {
  controller: ReturnType<typeof useMfaSecurityWorkspace>;
}): React.JSX.Element {
  const {
    recoveryCodes,
    copyRecoveryCodes,
    copyState,
    setRecoveryCodes,
    regenerateCodes,
    busyAction,
  } = controller;
  return (
    <Card className="mfa-security__card">
      <CardHeader>
        <span className="mfa-security__icon" aria-hidden="true">
          <KeyRound />
        </span>
        <div>
          <CardTitle>Recovery codes</CardTitle>
          <CardDescription>
            Replacing codes permanently retires the previous set.
          </CardDescription>
        </div>
      </CardHeader>
      <CardContent>
        {recoveryCodes.length > 0 ? (
          <div className="mfa-security__form">
            <Alert className="mfa-security__one-time">
              <ShieldAlert aria-hidden="true" />
              <AlertTitle>Save this replacement set now</AlertTitle>
              <AlertDescription>
                Leaving this page permanently hides these one-use values.
              </AlertDescription>
            </Alert>
            <ol
              className="mfa-security__codes"
              aria-label="Replacement recovery codes"
            >
              {recoveryCodes.map((code) => (
                <li key={code}>
                  <code>{code}</code>
                </li>
              ))}
            </ol>
            <Button
              type="button"
              variant="outline"
              onClick={() => void copyRecoveryCodes()}
            >
              {copyState === "copied" ? (
                <Check aria-hidden="true" />
              ) : (
                <Copy aria-hidden="true" />
              )}
              {copyState === "copied" ? "Copied" : "Copy codes"}
            </Button>
            <p aria-live="polite">
              {copyState === "failed"
                ? "Clipboard access failed. Copy each code manually."
                : ""}
            </p>
            <Button
              type="button"
              variant="ghost"
              onClick={() => setRecoveryCodes([])}
            >
              I saved the codes
            </Button>
          </div>
        ) : (
          <Button
            type="button"
            variant="outline"
            onClick={() => void regenerateCodes()}
            disabled={busyAction !== null}
          >
            <RefreshCw aria-hidden="true" /> Replace recovery codes
          </Button>
        )}
      </CardContent>
    </Card>
  );
}

function DeviceInventory({
  controller,
}: {
  controller: ReturnType<typeof useMfaSecurityWorkspace>;
}): React.JSX.Element {
  const {
    includeRevoked,
    setIncludeRevoked,
    devices,
    setLoadAttempt,
    busyAction,
    confirmingId,
    renamingId,
    id,
    setConfirmingId,
    setRenamingId,
    renamePasskey,
    revokeDevice,
    isLoadingMore,
    loadMore,
  } = controller;
  return (
    <section
      className="mfa-security__inventory"
      aria-labelledby="mfa-device-title"
    >
      <div className="mfa-security__section-heading">
        <div>
          <p className="section-label">Tenant-bound inventory</p>
          <h2 id="mfa-device-title">MFA devices</h2>
        </div>
        <label className="mfa-security__toggle">
          <input
            type="checkbox"
            checked={includeRevoked}
            onChange={(event) => setIncludeRevoked(event.currentTarget.checked)}
          />
          <span>Show revoked</span>
        </label>
      </div>

      {devices.kind === "loading" ? <DeviceSkeleton /> : null}
      {devices.kind === "error" ? (
        <div className="mfa-security__empty">
          <FocusedError message={devices.message} />
          <Button
            type="button"
            variant="outline"
            onClick={() => setLoadAttempt((value) => value + 1)}
          >
            <RefreshCw aria-hidden="true" /> Retry inventory
          </Button>
        </div>
      ) : null}
      {devices.kind === "ready" && devices.items.length === 0 ? (
        <div className="mfa-security__empty">
          <KeyRound aria-hidden="true" />
          <h3>No MFA devices returned</h3>
          <p>
            Enroll an authenticator or passkey to establish local assurance.
          </p>
        </div>
      ) : null}
      {devices.kind === "ready" && devices.items.length > 0 ? (
        <div className="mfa-security__devices">
          {devices.items.map((device) => (
            <DeviceCard
              key={`${device.kind}:${device.id}`}
              device={device}
              busy={busyAction !== null}
              confirming={confirmingId === device.id}
              renaming={renamingId === device.id}
              nameId={`${id}-${device.id}-name`}
              onBeginRename={() => {
                setConfirmingId(null);
                setRenamingId(device.id);
              }}
              onCancelRename={() => setRenamingId(null)}
              onRename={(event) => void renamePasskey(event, device)}
              onBeginRevoke={() => {
                setRenamingId(null);
                setConfirmingId(device.id);
              }}
              onCancelRevoke={() => setConfirmingId(null)}
              onRevoke={() => void revokeDevice(device)}
            />
          ))}
          {devices.nextCursor ? (
            <Button
              type="button"
              variant="outline"
              disabled={isLoadingMore}
              onClick={() => void loadMore()}
            >
              {isLoadingMore ? "Loading more devices…" : "Load more devices"}
            </Button>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function DeviceActions(props: DeviceCardProps): React.JSX.Element {
  const { device } = props;
  const inactive = device.status !== "active";
  return (
    <>
      {props.renaming ? (
        <form className="mfa-security__form" onSubmit={props.onRename}>
          <FormField htmlFor={props.nameId} label="New passkey name">
            <Input
              id={props.nameId}
              name="displayName"
              defaultValue={device.displayName}
              minLength={1}
              maxLength={120}
              required
              disabled={props.busy}
            />
          </FormField>
          <div className="mfa-security__actions">
            <Button type="submit" size="sm" disabled={props.busy}>
              Save name
            </Button>
            <Button
              type="button"
              size="sm"
              variant="ghost"
              onClick={props.onCancelRename}
              disabled={props.busy}
            >
              Cancel
            </Button>
          </div>
        </form>
      ) : props.confirming ? (
        <div className="mfa-security__confirmation" role="alert">
          <p>Revoke this device and every session family that depends on it?</p>
          <div className="mfa-security__actions">
            <Button
              type="button"
              variant="destructive"
              size="sm"
              onClick={props.onRevoke}
              disabled={props.busy}
            >
              <Trash2 aria-hidden="true" /> Confirm revoke
            </Button>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={props.onCancelRevoke}
              disabled={props.busy}
            >
              Keep device
            </Button>
          </div>
        </div>
      ) : inactive ? null : (
        <div className="mfa-security__actions">
          {device.kind === "passkey" ? (
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={props.onBeginRename}
            >
              <Pencil aria-hidden="true" /> Rename
            </Button>
          ) : null}
          <Button
            type="button"
            size="sm"
            variant="outline"
            onClick={props.onBeginRevoke}
          >
            <Trash2 aria-hidden="true" /> Revoke
          </Button>
        </div>
      )}
    </>
  );
}
