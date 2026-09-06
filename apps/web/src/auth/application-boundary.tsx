import { Button } from "@periapsis/ui/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@periapsis/ui/components/ui/card";
import { RefreshCw } from "lucide-react";
import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type Dispatch,
  type SetStateAction,
} from "react";
import { Outlet, useLocation, useNavigate } from "react-router";

import { AccessLayout } from "../components/access-layout";
import { FocusedError } from "../components/focused-error";
import {
  describePhaseTwoError,
  type BootstrapConfirmationView,
  type PhaseTwoApi,
  type SessionView,
} from "../lib/phase-two-types";
import {
  federatedMfaContinuationPath,
  subscribeToSessionTransitions,
} from "../lib/session-transition-transport";
import { BootstrapFlow } from "./bootstrap-flow";
import { FederatedMfaFlow } from "./federated-mfa-flow";
import { LoginFlow } from "./login-flow";
import type { FederatedMfaApi } from "./mfa/mfa-api";
import type { BrowserCredentials } from "./mfa/webauthn-browser";
import { RecoveryCodes } from "./recovery-codes";
import { SessionContext } from "./session-context";

type BoundaryState =
  | { kind: "authenticated"; session: SessionView }
  | { kind: "bootstrap" }
  | { kind: "checking" }
  | { kind: "error"; message: string }
  | { kind: "federated-mfa" }
  | { kind: "login" }
  | { confirmation: BootstrapConfirmationView; kind: "recovery" };

interface ApplicationBoundaryProps {
  api: PhaseTwoApi;
  credentials?: BrowserCredentials;
  federatedMfaApi?: FederatedMfaApi;
}

export function ApplicationBoundary({
  api,
  credentials,
  federatedMfaApi,
}: ApplicationBoundaryProps): React.JSX.Element {
  const location = useLocation();
  const navigate = useNavigate();
  const [state, setState] = useState<BoundaryState>({ kind: "checking" });
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [membershipRevision, setMembershipRevision] = useState(0);
  const transitionGenerationRef = useRef(0);
  const continuationRequested =
    `${location.pathname}${location.search}` === federatedMfaContinuationPath &&
    location.hash === "";

  useEffect(
    () =>
      subscribeToSessionTransitions((notice) => {
        const generation = transitionGenerationRef.current + 1;
        transitionGenerationRef.current = generation;
        if (notice.kind === "mfa_step_up_required") {
          setState({ kind: "federated-mfa" });
          void navigate(notice.location, { replace: true });
          return;
        }
        void api
          .getSession()
          .then((session) => {
            if (transitionGenerationRef.current !== generation) return;
            setState(
              session ? { kind: "authenticated", session } : { kind: "login" },
            );
          })
          .catch((caught: unknown) => {
            if (transitionGenerationRef.current !== generation) return;
            setState({
              kind: "error",
              message: describePhaseTwoError(
                caught,
                "The rotated session could not be revalidated. Retry the access check.",
              ),
            });
          });
      }),
    [api, navigate],
  );

  useEffect(() => {
    let cancelled = false;

    async function determineBoundary(): Promise<void> {
      setState({ kind: "checking" });
      try {
        if (continuationRequested) {
          setState({ kind: "federated-mfa" });
          return;
        }
        const bootstrap = await api.getBootstrapStatus();
        if (cancelled) {
          return;
        }
        if (bootstrap.available) {
          setState({ kind: "bootstrap" });
          return;
        }

        const session = await api.getSession();
        if (!cancelled) {
          setState(
            session ? { kind: "authenticated", session } : { kind: "login" },
          );
        }
      } catch (caught) {
        if (!cancelled) {
          setState({
            kind: "error",
            message: describePhaseTwoError(
              caught,
              "The API access boundary did not respond. Confirm the platform is reachable, then retry.",
            ),
          });
        }
      }
    }

    void determineBoundary();
    return () => {
      cancelled = true;
    };
  }, [api, continuationRequested, loadAttempt]);

  if (state.kind === "checking") {
    return (
      <AccessLayout
        activeStep={0}
        eyebrow="Access boundary"
        title="Checking platform access."
        description="Periapsis is asking the API whether this deployment requires bootstrap or already has a protected operator session."
      >
        <Card className="access-card access-check" aria-busy="true">
          <CardHeader>
            <CardTitle>Verifying server state</CardTitle>
            <CardDescription>
              No authorization decision is made from browser state.
            </CardDescription>
          </CardHeader>
          <CardContent className="access-check__lines" aria-hidden="true">
            <span />
            <span />
            <span />
          </CardContent>
        </Card>
      </AccessLayout>
    );
  }

  if (state.kind === "error") {
    return (
      <AccessLayout
        activeStep={0}
        eyebrow="Access boundary unavailable"
        title="The server state is unknown."
        description="Access stays closed until the bootstrap and session endpoints answer successfully."
      >
        <Card className="access-card">
          <CardHeader>
            <CardTitle>Retry the access check</CardTitle>
          </CardHeader>
          <CardContent className="access-form">
            <FocusedError message={state.message} />
            <Button
              type="button"
              size="lg"
              onClick={() => setLoadAttempt((attempt) => attempt + 1)}
            >
              <RefreshCw aria-hidden="true" /> Retry access check
            </Button>
          </CardContent>
        </Card>
      </AccessLayout>
    );
  }

  if (state.kind === "bootstrap") {
    return (
      <BootstrapFlow
        api={api}
        onConfirmed={(confirmation) =>
          setState({ kind: "recovery", confirmation })
        }
      />
    );
  }

  if (state.kind === "login") {
    return (
      <LoginFlow
        api={api}
        onAuthenticated={(session) =>
          setState({ kind: "authenticated", session })
        }
      />
    );
  }

  if (state.kind === "federated-mfa") {
    return (
      <FederatedMfaFlow
        {...(credentials ? { credentials } : {})}
        {...(federatedMfaApi ? { api: federatedMfaApi } : {})}
        onAuthenticated={(session) => {
          transitionGenerationRef.current += 1;
          setState({ kind: "authenticated", session });
          void navigate("/", { replace: true });
        }}
        onRestart={() => {
          transitionGenerationRef.current += 1;
          void navigate("/", { replace: true });
          setLoadAttempt((attempt) => attempt + 1);
        }}
      />
    );
  }

  if (state.kind === "recovery") {
    return (
      <RecoveryCodes
        confirmation={state.confirmation}
        onContinue={() =>
          setState({
            kind: "authenticated",
            session: state.confirmation.session,
          })
        }
      />
    );
  }

  return (
    <AuthenticatedSessionOutlet
      api={api}
      session={state.session}
      membershipRevision={membershipRevision}
      setState={setState}
      setMembershipRevision={setMembershipRevision}
    />
  );
}

function AuthenticatedSessionOutlet({
  api,
  session,
  membershipRevision,
  setState,
  setMembershipRevision,
}: {
  api: PhaseTwoApi;
  session: SessionView;
  membershipRevision: number;
  setState: Dispatch<SetStateAction<BoundaryState>>;
  setMembershipRevision: Dispatch<SetStateAction<number>>;
}): React.JSX.Element {
  const value = useMemo<React.ContextType<typeof SessionContext>>(
    () => ({
      api,
      clearSession: (expectedSessionId) =>
        setState((current) =>
          current.kind === "authenticated" &&
          current.session.id === expectedSessionId
            ? { kind: "login" }
            : current,
        ),
      membershipRevision,
      refreshMemberships: () =>
        setMembershipRevision((revision) => revision + 1),
      session,
      updateSession: (expectedSessionId, updatedSession) =>
        setState((current) =>
          current.kind === "authenticated" &&
          current.session.id === expectedSessionId
            ? { kind: "authenticated", session: updatedSession }
            : current,
        ),
    }),
    [api, session, membershipRevision, setState, setMembershipRevision],
  );
  return (
    <SessionContext.Provider value={value}>
      <Outlet />
    </SessionContext.Provider>
  );
}
