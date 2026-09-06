import type {
  MfaPolicyDocument,
  MfaPolicyLevel,
  MfaPolicyRequirement,
  MfaPolicySimulationResult,
  MfaPolicyTarget,
} from "@periapsis/contracts";
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
import { Checkbox } from "@periapsis/ui/components/ui/checkbox";
import { Input } from "@periapsis/ui/components/ui/input";
import { Textarea } from "@periapsis/ui/components/ui/textarea";
import {
  AlertTriangle,
  CheckCircle2,
  FlaskConical,
  History,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";
import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { useSession } from "../auth/session-context";
import { useTenantAuthority } from "../auth/tenant-authority-context";
import { FormField } from "../components/form-field";
import { hasPermission } from "../lib/phase-two-types";
import { MfaPolicyApiError, mfaPolicyApi } from "./mfa-policy-api";
import {
  bindMfaPolicyCommand,
  clearMfaPolicyCommand,
  isCanonicalUuidV7,
  isMfaPolicyAuditReason,
  isMfaPolicyInstant,
  mfaPolicyDraftFingerprint,
  mfaPolicyTargetApplies,
  normalizeMfaPolicyContext,
  platformMfaPolicyManagePermission,
  platformMfaPolicyReadPermission,
  tenantMfaPolicyManagePermission,
  tenantMfaPolicyReadPermission,
  type MfaPolicyApi,
  type MfaPolicyBoundary,
  type MfaPolicyCommandReference,
  type MfaPolicySimulationInput,
  type MfaPolicyTargetInput,
  type VersionedMfaPolicyDocument,
  type VersionedMfaPolicyMutation,
} from "./model";
// oxlint-disable-next-line import/no-unassigned-import -- Vite extracts the MFA policy workspace stylesheet.
import "./mfa-policy-admin.css";

interface MfaPolicyPageProps {
  api?: MfaPolicyApi;
}

export function PlatformMfaPolicyAdministrationPage({
  api = mfaPolicyApi,
}: MfaPolicyPageProps = {}): React.JSX.Element {
  const { session } = useSession();
  const canRead = hasPermission(session, platformMfaPolicyReadPermission);
  return (
    <div className="content">
      <MfaPolicyWorkspace
        api={api}
        boundary={{ kind: "platform" }}
        canManage={
          canRead && hasPermission(session, platformMfaPolicyManagePermission)
        }
        canRead={canRead}
        csrfToken={session.csrfToken}
      />
    </div>
  );
}

export function TenantMfaPolicyAdministrationPage({
  api = mfaPolicyApi,
}: MfaPolicyPageProps = {}): React.JSX.Element {
  const { session } = useSession();
  const authority = useTenantAuthority();
  const tenantId = session.activeTenantId;
  const ready = Boolean(tenantId) && authority.status === "ready";
  return (
    <div className="content">
      <MfaPolicyWorkspace
        api={api}
        boundary={
          tenantId
            ? { kind: "tenant", tenantId }
            : { kind: "tenant", tenantId: "" }
        }
        canManage={
          ready &&
          authority.hasPermission(tenantMfaPolicyManagePermission, "tenant")
        }
        canRead={
          ready &&
          authority.hasPermission(tenantMfaPolicyReadPermission, "tenant")
        }
        csrfToken={session.csrfToken}
        authorityPending={Boolean(tenantId) && authority.status === "loading"}
      />
    </div>
  );
}

interface MfaPolicyWorkspaceProps {
  api: MfaPolicyApi;
  authorityPending?: boolean;
  boundary: MfaPolicyBoundary;
  canManage: boolean;
  canRead: boolean;
  csrfToken: string;
}

type TargetScope = "action" | "role" | "security_group" | "tenant_baseline";
type SimulationState = {
  fingerprint: string;
  input: MfaPolicySimulationInput;
  result: MfaPolicySimulationResult;
};

export function MfaPolicyWorkspace(
  props: MfaPolicyWorkspaceProps,
): React.JSX.Element {
  const model = useMfaPolicyWorkspaceModel(props);
  if (model.kind === "content") return model.content;
  return <MfaPolicyWorkspaceView model={model.data} />;
}

function useMfaPolicyWorkspaceModel({
  api,
  authorityPending = false,
  boundary,
  canManage,
  canRead,
  csrfToken,
}: MfaPolicyWorkspaceProps) {
  const boundaryKey =
    boundary.kind === "platform" ? "platform" : `tenant:${boundary.tenantId}`;
  const boundaryTenantId =
    boundary.kind === "tenant" ? boundary.tenantId : undefined;
  const stableBoundary = useMemo<MfaPolicyBoundary>(
    () =>
      boundaryTenantId === undefined
        ? { kind: "platform" }
        : { kind: "tenant", tenantId: boundaryTenantId },
    [boundaryTenantId],
  );
  const [items, setItems] = useState<MfaPolicyDocument[]>([]);
  const [nextCursor, setNextCursor] = useState<{
    id: string;
    revision: number;
  } | null>(null);
  const [includeRetired, setIncludeRetired] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [selected, setSelected] = useState<VersionedMfaPolicyDocument | null>(
    null,
  );
  const [selectingKey, setSelectingKey] = useState<string | null>(null);
  const [scope, setScope] = useState<TargetScope>("tenant_baseline");
  const [targetValue, setTargetValue] = useState("");
  const [level, setLevel] = useState<MfaPolicyLevel>("mfa");
  const [localRequired, setLocalRequired] = useState(true);
  const [freshnessSeconds, setFreshnessSeconds] = useState("300");
  const [enrollmentDeadline, setEnrollmentDeadline] = useState("");
  const [roleIds, setRoleIds] = useState("");
  const [securityGroupIds, setSecurityGroupIds] = useState("");
  const [contextAction, setContextAction] = useState("mfa_policy.manage");
  const [reason, setReason] = useState("");
  const [simulation, setSimulation] = useState<SimulationState | null>(null);
  const generation = useRef(0);
  const selectionGeneration = useRef(0);
  const operationGeneration = useRef(0);
  const contextKeyRef = useRef(boundaryKey);
  useLayoutEffect(() => {
    contextKeyRef.current = boundaryKey;
  }, [boundaryKey]);
  const command = useRef<MfaPolicyCommandReference>({ current: null });

  function operationIsCurrent(
    requestGeneration: number,
    expectedContext: string,
  ): boolean {
    return (
      requestGeneration === operationGeneration.current &&
      contextKeyRef.current === expectedContext
    );
  }

  const load = useCallback(
    async (after?: { id: string; revision: number }): Promise<void> => {
      if (
        !canRead ||
        (stableBoundary.kind === "tenant" && !stableBoundary.tenantId)
      ) {
        setLoading(false);
        return;
      }
      const requestGeneration = ++generation.current;
      const expectedContext = boundaryKey;
      if (after) setLoadingMore(true);
      else setLoading(true);
      setError(null);
      try {
        const page = await api.list(stableBoundary, {
          ...(after ? { after } : {}),
          includeRetired,
        });
        if (
          requestGeneration !== generation.current ||
          contextKeyRef.current !== expectedContext
        ) {
          return;
        }
        setItems((current) =>
          after ? [...current, ...page.items] : page.items,
        );
        setNextCursor(page.nextCursor);
      } catch (caught: unknown) {
        if (
          requestGeneration === generation.current &&
          contextKeyRef.current === expectedContext
        ) {
          setError(
            mfaPolicyError(caught, "MFA policy history could not be loaded."),
          );
        }
      } finally {
        if (
          requestGeneration === generation.current &&
          contextKeyRef.current === expectedContext
        ) {
          // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
          setLoading(false);
          setLoadingMore(false);
        }
      }
    },
    [api, boundaryKey, canRead, includeRetired, stableBoundary],
  );

  useEffect(() => {
    generation.current += 1;
    selectionGeneration.current += 1;
    operationGeneration.current += 1;
    clearMfaPolicyCommand(command.current);
    setItems([]);
    setNextCursor(null);
    setSelected(null);
    setSimulation(null);
    setError(null);
    setNotice(null);
    setBusy(false);
    setLoading(true);
    void load();
    return () => {
      generation.current += 1;
      selectionGeneration.current += 1;
      operationGeneration.current += 1;
    };
  }, [boundaryKey, canRead, includeRetired, load]);

  function resetDraft(): void {
    if (busy) return;
    selectionGeneration.current += 1;
    setSelected(null);
    setScope("tenant_baseline");
    setTargetValue("");
    setLevel("mfa");
    setLocalRequired(true);
    setFreshnessSeconds("300");
    setEnrollmentDeadline("");
    setSimulation(null);
    setError(null);
    setNotice(null);
    clearMfaPolicyCommand(command.current);
  }

  async function selectDocument(document: MfaPolicyDocument): Promise<void> {
    if (busy) return;
    const requestGeneration = ++selectionGeneration.current;
    const expectedContext = boundaryKey;
    setSelectingKey(`${document.id}:${document.revision}`);
    setError(null);
    setNotice(null);
    try {
      const resource = await api.get(
        stableBoundary,
        document.id,
        document.revision,
      );
      if (
        requestGeneration !== selectionGeneration.current ||
        contextKeyRef.current !== expectedContext
      ) {
        return;
      }
      setSelected(resource);
      applyDocumentToDraft(resource.value);
      setSimulation(null);
      clearMfaPolicyCommand(command.current);
    } catch (caught: unknown) {
      if (
        requestGeneration === selectionGeneration.current &&
        contextKeyRef.current === expectedContext
      ) {
        setError(
          mfaPolicyError(
            caught,
            "The exact policy revision could not be loaded.",
          ),
        );
      }
    } finally {
      if (requestGeneration === selectionGeneration.current)
        setSelectingKey(null);
    }
  }

  function applyDocumentToDraft(document: MfaPolicyDocument): void {
    setLevel(document.requirement.level);
    setLocalRequired(document.requirement.localRequired);
    setFreshnessSeconds(String(document.requirement.freshnessSeconds));
    setEnrollmentDeadline(document.requirement.enrollmentDeadline ?? "");
    switch (document.target.scope) {
      case "tenant_baseline":
        setScope("tenant_baseline");
        setTargetValue("");
        break;
      case "role":
        setScope("role");
        setTargetValue(document.target.roleId ?? "");
        break;
      case "security_group":
        setScope("security_group");
        setTargetValue(document.target.securityGroupId ?? "");
        break;
      case "action":
        setScope("action");
        setTargetValue(document.target.action ?? "");
        break;
      case "platform_floor":
        break;
    }
  }

  function buildTarget(): MfaPolicyTargetInput {
    if (stableBoundary.kind === "platform") return { scope: "platform_floor" };
    if (scope === "tenant_baseline") return { scope };
    const exact = targetValue.trim();
    if (exact !== targetValue || exact === "") {
      throw new TypeError(
        "Enter an exact target value without surrounding whitespace.",
      );
    }
    if (scope === "action") return { action: exact, scope };
    if (!isCanonicalUuidV7(exact)) {
      throw new TypeError(
        "Role and security-group targets require a canonical UUIDv7.",
      );
    }
    return scope === "role"
      ? { roleId: exact, scope }
      : { scope, securityGroupId: exact };
  }

  function buildRequirement(): MfaPolicyRequirement {
    if (!/^(?:0|[1-9]\d*)$/u.test(freshnessSeconds)) {
      throw new TypeError("Freshness must be a whole number of seconds.");
    }
    const freshness = Number(freshnessSeconds);
    if (!Number.isSafeInteger(freshness) || freshness > 31_536_000) {
      throw new TypeError(
        "Freshness must be between 0 and 31,536,000 seconds.",
      );
    }
    let deadline: string | null = null;
    if (enrollmentDeadline !== "") {
      if (!isMfaPolicyInstant(enrollmentDeadline)) {
        throw new TypeError(
          "Deadline must be an RFC3339 UTC instant with millisecond precision.",
        );
      }
      if (Date.parse(enrollmentDeadline) <= Date.now()) {
        throw new TypeError("A publication deadline must be in the future.");
      }
      deadline = enrollmentDeadline;
    }
    return {
      enrollmentDeadline: deadline,
      freshnessSeconds: freshness,
      level,
      localRequired,
    };
  }

  function buildSimulation(
    operation: "publish" | "retire",
  ): MfaPolicySimulationInput {
    const target = buildTarget();
    const context =
      stableBoundary.kind === "tenant"
        ? normalizeMfaPolicyContext(
            splitIds(roleIds),
            splitIds(securityGroupIds),
            contextAction,
          )
        : undefined;
    if (context && !mfaPolicyTargetApplies(target, context)) {
      throw new TypeError(
        "The simulated target must be present in the exact context.",
      );
    }
    if (operation === "retire") {
      if (!selected || selected.value.status !== "live") {
        throw new TypeError(
          "Select an exact live revision before simulating retirement.",
        );
      }
      return {
        ...(context ? { context } : {}),
        expectedPolicyId: selected.value.id,
        expectedRevision: selected.value.revision,
        operation,
        target,
      };
    }
    return {
      ...(context ? { context } : {}),
      ...(selected ? { expectedPolicyId: selected.value.id } : {}),
      expectedRevision: selected?.value.revision ?? 0,
      operation,
      requirement: buildRequirement(),
      target,
    };
  }

  function currentSimulationFingerprint(
    operation: "publish" | "retire",
  ): string | null {
    try {
      return mfaPolicyDraftFingerprint(buildSimulation(operation));
    } catch {
      return null;
    }
  }

  async function simulate(operation: "publish" | "retire"): Promise<void> {
    const requestGeneration = ++operationGeneration.current;
    const expectedContext = boundaryKey;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const input = buildSimulation(operation);
      const result = await api.simulate(stableBoundary, csrfToken, input);
      if (!operationIsCurrent(requestGeneration, expectedContext)) {
        return;
      }
      setSimulation({
        fingerprint: mfaPolicyDraftFingerprint(input),
        input,
        result,
      });
    } catch (caught: unknown) {
      if (operationIsCurrent(requestGeneration, expectedContext)) {
        // react-doctor-disable-next-line no-unowned-async-error-clear -- operationIsCurrent verifies both operation generation and authorization context before clearing this simulation.
        setSimulation(null);
        setError(
          mfaPolicyError(
            caught,
            "The policy simulation could not be completed.",
          ),
        );
      }
    } finally {
      if (operationIsCurrent(requestGeneration, expectedContext)) {
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setBusy(false);
      }
    }
  }

  async function mutate(): Promise<void> {
    if (!simulation || !simulation.result.recovery.safe || !canManage) return;
    const operation = simulation.result.operation;
    if (currentSimulationFingerprint(operation) !== simulation.fingerprint)
      return;
    if (!isMfaPolicyAuditReason(reason)) {
      setError(
        "Audit reason must be 1–2048 visible ASCII characters and cannot contain commas.",
      );
      return;
    }
    const requestGeneration = ++operationGeneration.current;
    const expectedContext = boundaryKey;
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (operation === "retire") {
        if (!selected || simulation.input.operation !== "retire") return;
        const input = {
          expectedRevision: simulation.input.expectedRevision,
          target: simulation.input.target,
        };
        const commandId = bindMfaPolicyCommand(
          command.current,
          stableBoundary,
          "retire",
          reason,
          input,
        );
        const receipt = await api.retire(
          stableBoundary,
          csrfToken,
          commandId,
          reason,
          selected.value.id,
          selected.etag,
          input,
        );
        if (!operationIsCurrent(requestGeneration, expectedContext)) {
          return;
        }
        setNotice(
          receipt.value.replayed
            ? "The original retirement receipt was replayed; no second audit event was emitted."
            : "The exact policy revision was retired.",
        );
      } else if (simulation.input.requirement) {
        const common = {
          requirement: simulation.input.requirement,
          target: simulation.input.target,
        };
        let receipt: VersionedMfaPolicyMutation;
        if (selected) {
          const input = {
            ...common,
            expectedRevision: selected.value.revision,
          };
          const commandId = bindMfaPolicyCommand(
            command.current,
            stableBoundary,
            "publish",
            reason,
            input,
          );
          receipt = await api.replace(
            stableBoundary,
            csrfToken,
            commandId,
            reason,
            selected.value.id,
            selected.etag,
            input,
          );
        } else {
          const input = { ...common, expectedRevision: 0 as const };
          const commandId = bindMfaPolicyCommand(
            command.current,
            stableBoundary,
            "publish",
            reason,
            input,
          );
          receipt = await api.publish(
            stableBoundary,
            csrfToken,
            commandId,
            reason,
            input,
          );
        }
        if (!operationIsCurrent(requestGeneration, expectedContext)) {
          return;
        }
        setNotice(
          receipt.value.replayed
            ? "The original publication receipt was replayed; no second audit event was emitted."
            : selected
              ? "A new immutable policy revision was published."
              : "The policy was explicitly published at revision one.",
        );
      }
      clearMfaPolicyCommand(command.current);
      setSelected(null);
      setSimulation(null);
      setReason("");
      await load();
    } catch (caught: unknown) {
      if (operationIsCurrent(requestGeneration, expectedContext)) {
        if (caught instanceof MfaPolicyApiError) {
          if (caught.code === "mfa_policy_recovery_unsafe") {
            setSimulation(null);
          }
          if (
            caught.code === "conflict" ||
            caught.code === "not_found" ||
            caught.code === "precondition_failed"
          ) {
            setSelected(null);
            setSimulation(null);
            clearMfaPolicyCommand(command.current);
            await load();
            if (!operationIsCurrent(requestGeneration, expectedContext)) {
              return;
            }
          }
        }
        setError(
          mfaPolicyError(
            caught,
            "The policy mutation was not confirmed. Retrying keeps the same command ID.",
          ),
        );
      }
    } finally {
      if (operationIsCurrent(requestGeneration, expectedContext)) {
        // react-doctor-disable-next-line no-loading-flag-reset-outside-finally -- The owning request clears this flag in finally; the generation guard protects newer requests.
        setBusy(false);
      }
    }
  }

  if (authorityPending) {
    return {
      kind: "content" as const,
      content: <RouteState title="Checking live tenant authority…" />,
    };
  }
  if (
    !canRead ||
    (stableBoundary.kind === "tenant" && !stableBoundary.tenantId)
  ) {
    return {
      kind: "content" as const,
      content: (
        <RouteState
          destructive
          title="MFA policy administration is unavailable."
          message="An active boundary and explicit live identity_policy.read authority are required. Navigation is not an authorization boundary."
        />
      ),
    };
  }

  const operation = simulation?.result.operation;
  const simulationCurrent = operation
    ? currentSimulationFingerprint(operation)
    : null;
  const simulationFresh =
    simulation !== null && simulationCurrent === simulation.fingerprint;
  const mutationReady =
    simulationFresh &&
    simulation.result.recovery.safe &&
    canManage &&
    isMfaPolicyAuditReason(reason) &&
    !busy;

  return {
    kind: "ready" as const,
    data: {
      busy,
      canManage,
      contextAction,
      enrollmentDeadline,
      error,
      freshnessSeconds,
      includeRetired,
      items,
      level,
      load,
      loading,
      loadingMore,
      localRequired,
      mutate,
      mutationReady,
      nextCursor,
      notice,
      operation,
      reason,
      resetDraft,
      roleIds,
      scope,
      securityGroupIds,
      selectDocument,
      selected,
      selectingKey,
      setContextAction,
      setEnrollmentDeadline,
      setFreshnessSeconds,
      setIncludeRetired,
      setLevel,
      setLocalRequired,
      setReason,
      setRoleIds,
      setScope,
      setSecurityGroupIds,
      setTargetValue,
      simulate,
      simulation,
      simulationFresh,
      stableBoundary,
      targetValue,
    },
  };
}

function MfaPolicyWorkspaceView({
  model,
}: {
  model: Extract<
    ReturnType<typeof useMfaPolicyWorkspaceModel>,
    { kind: "ready" }
  >["data"];
}): React.JSX.Element {
  const {
    canManage,
    error,
    notice,
    simulation,
    simulationFresh,
    stableBoundary,
  } = model;
  return (
    <section
      className="mfa-policy-workspace"
      aria-labelledby="mfa-policy-title"
    >
      <header className="mfa-policy-heading">
        <div>
          <p className="section-label">Identity assurance control plane</p>
          <h1 id="mfa-policy-title">
            {stableBoundary.kind === "platform"
              ? "Platform MFA floor"
              : "Tenant MFA policies"}
          </h1>
          <p>
            Publish immutable revisions only after an exact-context simulation.
            Effective assurance folds monotonically: stronger level, local proof
            by OR, shortest non-zero freshness, and earliest enrollment
            deadline.
          </p>
        </div>
        <div className="mfa-policy-authority">
          <ShieldCheck aria-hidden="true" />
          <span>Live authority</span>
          <strong>{canManage ? "Read + manage" : "Read only"}</strong>
          <small>
            Mutations also require recent local assurance and DB recovery proof.
          </small>
        </div>
      </header>

      {error ? (
        <Alert variant="destructive" role="alert">
          <AlertTriangle aria-hidden="true" />
          <AlertTitle>Operation unavailable</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      ) : null}
      {notice ? (
        <Alert role="status">
          <CheckCircle2 aria-hidden="true" />
          <AlertTitle>Committed</AlertTitle>
          <AlertDescription>{notice}</AlertDescription>
        </Alert>
      ) : null}

      <div className="mfa-policy-grid">
        <MfaPublicationHistory model={model} />

        <div className="mfa-policy-editor">
          <MfaSimulationEditor model={model} />

          {simulation ? (
            <SimulationCard simulation={simulation} fresh={simulationFresh} />
          ) : null}

          <MfaPolicyWorkspaceAuditedPublicationGate model={model} />
        </div>
      </div>
    </section>
  );
}

function SimulationCard({
  fresh,
  simulation,
}: {
  fresh: boolean;
  simulation: SimulationState;
}): React.JSX.Element {
  const { effective, recovery } = simulation.result;
  return (
    <Card className="mfa-policy-simulation" aria-label="Simulation result">
      <CardHeader>
        <div className="mfa-policy-card-heading">
          <div>
            <CardTitle>Exact fold preview</CardTitle>
            <CardDescription>
              {fresh
                ? "Bound to the current draft and requested context."
                : "Stale: the draft changed after this simulation."}
            </CardDescription>
          </div>
          <Badge variant={recovery.safe && fresh ? "default" : "destructive"}>
            {recovery.safe ? "Recovery safe" : "Recovery unsafe"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        <dl className="mfa-policy-facts">
          <div>
            <dt>Eligible direct administrators</dt>
            <dd>{recovery.eligibleDirectAdministrators}</dd>
          </div>
          <div>
            <dt>Ready direct administrators</dt>
            <dd>{recovery.readyDirectAdministrators}</dd>
          </div>
          <div>
            <dt>Effective assurance</dt>
            <dd>
              {effective.requirement
                ? requirementLabel(effective.requirement)
                : "No platform floor"}
            </dd>
          </div>
        </dl>
        {recovery.reasonCodes.length > 0 ? (
          <Alert variant="destructive">
            <AlertTriangle aria-hidden="true" />
            <AlertTitle>Recovery safety failed</AlertTitle>
            <AlertDescription>
              {recovery.reasonCodes.map(recoveryReasonLabel).join(" · ")}
            </AlertDescription>
          </Alert>
        ) : null}
        <ol className="mfa-policy-sources">
          {effective.sources.map((source) => (
            <li
              key={`${source.source}:${source.policyId ?? "candidate"}:${targetLabel(source.target)}`}
            >
              <span>
                {source.source === "candidate"
                  ? "Candidate"
                  : `Revision ${source.revision}`}
              </span>
              <strong>{targetLabel(source.target)}</strong>
              <small>{requirementLabel(source.requirement)}</small>
            </li>
          ))}
        </ol>
      </CardContent>
    </Card>
  );
}

function RouteState({
  destructive = false,
  message = "The workspace remains closed until the server projection is ready.",
  title,
}: {
  destructive?: boolean;
  message?: string;
  title: string;
}): React.JSX.Element {
  return (
    <section
      aria-labelledby="mfa-policy-route-state-title"
      className="mfa-policy-route-state"
      role={destructive ? "alert" : "status"}
    >
      <p className="section-label">Live authorization</p>
      <h1 id="mfa-policy-route-state-title">{title}</h1>
      <p>{message}</p>
    </section>
  );
}

function splitIds(value: string): string[] {
  if (value.trim() === "") return [];
  return value
    .split(/[\n,]/u)
    .map((item) => item.trim())
    .filter(Boolean);
}

// oxlint-disable-next-line typescript/consistent-return -- The generated target scope union is exhaustively labeled.
function targetLabel(target: MfaPolicyTarget): string {
  switch (target.scope) {
    case "platform_floor":
      return "Platform floor";
    case "tenant_baseline":
      return "Tenant baseline";
    case "role":
      return `Role ${shortId(target.roleId ?? "")}`;
    case "security_group":
      return `Security group ${shortId(target.securityGroupId ?? "")}`;
    case "action":
      return `Action ${target.action ?? ""}`;
  }
}

function parseTargetScope(value: string): TargetScope {
  switch (value) {
    case "action":
    case "role":
    case "security_group":
    case "tenant_baseline":
      return value;
    default:
      throw new TypeError("MFA policy target scope is invalid.");
  }
}

function parsePolicyLevel(value: string): MfaPolicyLevel {
  switch (value) {
    case "primary":
    case "mfa":
    case "phishing_resistant":
      return value;
    default:
      throw new TypeError("MFA policy assurance level is invalid.");
  }
}

function requirementLabel(requirement: MfaPolicyRequirement): string {
  const local = requirement.localRequired ? ", local required" : "";
  const freshness =
    requirement.freshnessSeconds > 0
      ? `, ${requirement.freshnessSeconds}s freshness`
      : "";
  return `${requirement.level.replaceAll("_", " ")}${local}${freshness}`;
}

function recoveryReasonLabel(value: string): string {
  switch (value) {
    case "no_eligible_direct_administrator":
      return "No eligible direct administrator";
    case "no_ready_local_mfa":
      return "No administrator ready with local MFA";
    case "no_ready_local_phishing_resistant":
      return "No administrator ready with local phishing-resistant proof";
    case "no_ready_local_primary":
      return "No administrator ready with local primary proof";
    default:
      return "Unknown recovery failure";
  }
}

function shortId(value: string): string {
  return value.length > 13 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value;
}

function mfaPolicyError(caught: unknown, fallback: string): string {
  if (caught instanceof MfaPolicyApiError || caught instanceof TypeError) {
    return caught.message;
  }
  return fallback;
}

function MfaPublicationHistory({
  model,
}: {
  model: React.ComponentProps<typeof MfaPolicyWorkspaceView>["model"];
}): React.ReactNode {
  return (
    <Card className="mfa-policy-history">
      <MfaPublicationHistoryHeading model={model} />
      <MfaPublicationHistoryContent model={model} />
    </Card>
  );
}

function MfaSimulationEditor({
  model,
}: {
  model: React.ComponentProps<typeof MfaPolicyWorkspaceView>["model"];
}): React.ReactNode {
  const {
    busy,
    enrollmentDeadline,
    freshnessSeconds,
    level,
    localRequired,
    selected,
    setEnrollmentDeadline,
    setFreshnessSeconds,
    setLevel,
    setLocalRequired,
    simulate,
  } = model;
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          {selected
            ? "Replace or retire exact revision"
            : "Draft a publication"}
        </CardTitle>
        <CardDescription>
          {selected
            ? `Strong CAS is pinned to ${selected.etag}; changing the target is not allowed within a revision chain.`
            : "Creation uses expected revision zero. Nothing is created until Publish succeeds."}
        </CardDescription>
      </CardHeader>
      <CardContent className="mfa-policy-form">
        {<MfaSimulationTargetFields model={model} />}
        <FormField htmlFor="mfa-policy-level" label="Required assurance">
          <select
            id="mfa-policy-level"
            value={level}
            onChange={(event) => setLevel(parsePolicyLevel(event.target.value))}
          >
            <option value="primary">Primary</option>
            <option value="mfa">MFA</option>
            <option value="phishing_resistant">Phishing resistant</option>
          </select>
        </FormField>
        <label className="mfa-policy-check">
          <Checkbox
            checked={localRequired}
            onCheckedChange={(checked) => setLocalRequired(checked === true)}
          />
          Require a local authentication path
        </label>
        <FormField
          htmlFor="mfa-policy-freshness"
          label="Freshness (seconds)"
          hint="Zero adds no proof-age restriction; otherwise the shortest live value wins."
        >
          <Input
            id="mfa-policy-freshness"
            inputMode="numeric"
            value={freshnessSeconds}
            onChange={(event) => setFreshnessSeconds(event.target.value)}
          />
        </FormField>
        <FormField
          htmlFor="mfa-policy-deadline"
          label="Enrollment deadline (UTC)"
          optional
          hint="Exact RFC3339 UTC milliseconds, for example 2027-01-15T12:00:00.000Z."
        >
          <Input
            id="mfa-policy-deadline"
            value={enrollmentDeadline}
            onChange={(event) => setEnrollmentDeadline(event.target.value)}
            placeholder="2027-01-15T12:00:00.000Z"
          />
        </FormField>
        {<MfaSimulationContextForm model={model} />}
        <div className="mfa-policy-actions">
          <Button
            type="button"
            variant="outline"
            onClick={() => void simulate("publish")}
            disabled={busy || selected?.value.status === "retired"}
          >
            <FlaskConical aria-hidden="true" /> Simulate publication
          </Button>
          <Button
            type="button"
            variant="outline"
            onClick={() => void simulate("retire")}
            disabled={busy || !selected || selected.value.status !== "live"}
          >
            <FlaskConical aria-hidden="true" /> Simulate retirement
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function MfaPolicyWorkspaceAuditedPublicationGate({
  model,
}: {
  model: React.ComponentProps<typeof MfaPolicyWorkspaceView>["model"];
}): React.ReactNode {
  const {
    busy,
    canManage,
    mutate,
    mutationReady,
    operation,
    reason,
    selected,
    setReason,
    simulation,
    simulationFresh,
    stableBoundary,
  } = model;
  return (
    <Card>
      <CardHeader>
        <CardTitle>Audited publication gate</CardTitle>
        <CardDescription>
          Simulation is explanatory, not a capability. The database repeats
          recovery proof and CAS under lock.
        </CardDescription>
      </CardHeader>
      <CardContent className="mfa-policy-form">
        <FormField
          htmlFor="mfa-policy-reason"
          label="Audit reason"
          hint="Visible ASCII, 1–2048 characters, without commas. The first audit envelope wins on replay."
        >
          <Textarea
            id="mfa-policy-reason"
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </FormField>
        <Button
          type="button"
          onClick={() => void mutate()}
          disabled={!mutationReady}
        >
          {busy
            ? "Submitting…"
            : operation === "retire"
              ? "Retire exact revision"
              : selected
                ? "Publish replacement revision"
                : stableBoundary.kind === "platform"
                  ? "Publish platform floor"
                  : "Publish tenant policy"}
        </Button>
        {!canManage ? (
          <p className="mfa-policy-muted">
            Manage permission is required to publish or retire.
          </p>
        ) : null}
        {simulation && !simulationFresh ? (
          <p className="mfa-policy-muted">
            The draft changed after simulation. Simulate the exact draft again.
          </p>
        ) : null}
        {simulationFresh && simulation && !simulation.result.recovery.safe ? (
          <p className="mfa-policy-muted">
            Publication is blocked because the DB-authoritative recovery proof
            is unsafe.
          </p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function MfaPublicationHistoryHeading({
  model,
}: {
  model: React.ComponentProps<typeof MfaPublicationHistory>["model"];
}): React.ReactNode {
  const { busy, includeRetired, load, loading, setIncludeRetired } = model;
  return (
    <CardHeader>
      <div className="mfa-policy-card-heading">
        <div>
          <CardTitle>Publication history</CardTitle>
          <CardDescription>
            Stable ID/revision order; history is never rewritten.
          </CardDescription>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={() => void load()}
          disabled={loading}
        >
          <RefreshCw aria-hidden="true" /> Refresh
        </Button>
      </div>
      <label className="mfa-policy-check">
        <Checkbox
          checked={includeRetired}
          disabled={busy}
          onCheckedChange={(checked) => setIncludeRetired(checked === true)}
        />
        Include retired revisions
      </label>
    </CardHeader>
  );
}

function MfaPublicationHistoryContent({
  model,
}: {
  model: React.ComponentProps<typeof MfaPublicationHistory>["model"];
}): React.ReactNode {
  const {
    busy,
    items,
    load,
    loading,
    loadingMore,
    nextCursor,
    resetDraft,
    selectDocument,
    selected,
    selectingKey,
    stableBoundary,
  } = model;
  return (
    <CardContent className="mfa-policy-history__content">
      <Button
        type="button"
        variant="outline"
        onClick={resetDraft}
        disabled={busy}
      >
        New explicit publication
      </Button>
      {loading ? <p role="status">Loading policy history…</p> : null}
      {!loading && items.length === 0 ? (
        <div className="mfa-policy-empty">
          <History aria-hidden="true" />
          <strong>No publications yet</strong>
          <p>
            {stableBoundary.kind === "platform"
              ? "No platform floor is seeded implicitly. Publish one explicitly only when recovery safety is proven."
              : "This tenant has no policy publications in the selected history view."}
          </p>
        </div>
      ) : null}
      <div className="mfa-policy-history__items">
        {items.map((document) => {
          const key = `${document.id}:${document.revision}`;
          const active =
            selected?.value.id === document.id &&
            selected.value.revision === document.revision;
          return (
            <button
              type="button"
              className={active ? "is-selected" : undefined}
              key={key}
              onClick={() => void selectDocument(document)}
              disabled={busy || selectingKey !== null}
              aria-pressed={active}
            >
              <span>
                <strong>{targetLabel(document.target)}</strong>
                <small>
                  {shortId(document.id)} · revision {document.revision}
                </small>
              </span>
              <Badge
                variant={document.status === "live" ? "default" : "secondary"}
              >
                {selectingKey === key ? "Loading…" : document.status}
              </Badge>
            </button>
          );
        })}
      </div>
      {nextCursor ? (
        <Button
          type="button"
          variant="ghost"
          onClick={() => void load(nextCursor)}
          disabled={loadingMore}
        >
          {loadingMore ? "Loading…" : "Load more history"}
        </Button>
      ) : null}
    </CardContent>
  );
}

function MfaSimulationTargetFields({
  model,
}: {
  model: React.ComponentProps<typeof MfaSimulationEditor>["model"];
}): React.ReactNode {
  const {
    scope,
    selected,
    setScope,
    setTargetValue,
    stableBoundary,
    targetValue,
  } = model;
  return stableBoundary.kind === "platform" ? (
    <FormField htmlFor="mfa-policy-platform-target" label="Target">
      <Input id="mfa-policy-platform-target" value="platform_floor" readOnly />
    </FormField>
  ) : (
    <>
      <FormField htmlFor="mfa-policy-scope" label="Target scope">
        <select
          id="mfa-policy-scope"
          value={scope}
          onChange={(event) => {
            setScope(parseTargetScope(event.target.value));
            setTargetValue("");
          }}
          disabled={selected !== null}
        >
          <option value="tenant_baseline">Tenant baseline</option>
          <option value="security_group">Security group</option>
          <option value="role">Role</option>
          <option value="action">Action</option>
        </select>
      </FormField>
      {scope !== "tenant_baseline" ? (
        <FormField
          htmlFor="mfa-policy-target-value"
          label={
            scope === "action"
              ? "Exact action"
              : scope === "role"
                ? "Role UUIDv7"
                : "Security-group UUIDv7"
          }
          hint="The target must be present in the exact simulation context."
        >
          <Input
            id="mfa-policy-target-value"
            value={targetValue}
            onChange={(event) => setTargetValue(event.target.value)}
            readOnly={selected !== null}
          />
        </FormField>
      ) : null}
    </>
  );
}

function MfaSimulationContextForm({
  model,
}: {
  model: React.ComponentProps<typeof MfaSimulationEditor>["model"];
}): React.ReactNode {
  const {
    contextAction,
    roleIds,
    securityGroupIds,
    setContextAction,
    setRoleIds,
    setSecurityGroupIds,
    stableBoundary,
  } = model;
  return stableBoundary.kind === "tenant" ? (
    <fieldset className="mfa-policy-context">
      <legend>Exact simulation context</legend>
      <p>
        Role and group arrays are bounded, deduplicated UUIDv7 sets. Action
        never defaults implicitly.
      </p>
      <FormField
        htmlFor="mfa-policy-role-context"
        label="Role UUIDv7 values"
        optional
        hint="Separate values with commas or new lines."
      >
        <Textarea
          id="mfa-policy-role-context"
          value={roleIds}
          onChange={(event) => setRoleIds(event.target.value)}
        />
      </FormField>
      <FormField
        htmlFor="mfa-policy-group-context"
        label="Security-group UUIDv7 values"
        optional
        hint="Separate values with commas or new lines."
      >
        <Textarea
          id="mfa-policy-group-context"
          value={securityGroupIds}
          onChange={(event) => setSecurityGroupIds(event.target.value)}
        />
      </FormField>
      <FormField htmlFor="mfa-policy-context-action" label="Exact action">
        <Input
          id="mfa-policy-context-action"
          value={contextAction}
          onChange={(event) => setContextAction(event.target.value)}
        />
      </FormField>
    </fieldset>
  ) : null;
}
