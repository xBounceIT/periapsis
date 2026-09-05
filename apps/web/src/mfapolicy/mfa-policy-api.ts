import {
  getPlatformMfaPolicyRevision,
  getTenantMfaPolicyRevision,
  listPlatformMfaPolicies,
  listTenantMfaPolicies,
  publishPlatformMfaPolicy,
  publishTenantMfaPolicy,
  replacePlatformMfaPolicy,
  replaceTenantMfaPolicy,
  retirePlatformMfaPolicy,
  retireTenantMfaPolicy,
  simulatePlatformMfaPolicyChange,
  simulateTenantMfaPolicyChange,
  type MfaPolicyDocument,
  type MfaPolicyMutationResult,
  type MfaPolicyPage,
  type MfaPolicyRequirement,
  type MfaPolicyRecoveryReason,
  type MfaPolicySimulationContext,
  type MfaPolicySimulationResult,
  type MfaPolicySimulationSource,
  type MfaPolicyTarget,
  type PlatformMfaPolicyCreateRequest,
  type PlatformMfaPolicyReplaceRequest,
  type PlatformMfaPolicyRetireRequest,
  type PlatformMfaPolicySimulationRequest,
  type TenantMfaPolicyCreateRequest,
  type TenantMfaPolicyReplaceRequest,
  type TenantMfaPolicyRetireRequest,
  type TenantMfaPolicySimulationRequest,
} from "@periapsis/contracts";

import { sessionAwareFetch } from "../lib/session-transition-transport";
import {
  isCanonicalUuidV7,
  isMfaPolicyAuditReason,
  isMfaPolicyInstant,
  mfaPolicyTargetApplies,
  type MfaPolicyApi,
  type MfaPolicyBoundary,
  type MfaPolicyListInput,
  type MfaPolicyPublishInput,
  type MfaPolicyReplaceInput,
  type MfaPolicyRetireInput,
  type MfaPolicySimulationInput,
  type MfaPolicyTargetInput,
  type VersionedMfaPolicyDocument,
  type VersionedMfaPolicyMutation,
} from "./model";

interface GeneratedResult<T> {
  data: T | undefined;
  error?: unknown;
  response?: Response;
}

export class MfaPolicyApiError extends Error {
  readonly code: string;
  readonly status: number | undefined;

  constructor(
    message: string,
    code = "mfa_policy_unavailable",
    status?: number,
  ) {
    super(message);
    this.name = "MfaPolicyApiError";
    this.code = code;
    this.status = status;
  }
}

export const mfaPolicyApi: MfaPolicyApi = {
  async list(boundary, input = {}) {
    requireBoundary(boundary);
    requireListInput(input);
    const query = {
      limit: 100,
      ...(input.after
        ? {
            afterId: input.after.id,
            afterRevision: input.after.revision,
          }
        : {}),
      ...(input.includeRetired === undefined
        ? {}
        : { includeRetired: input.includeRetired }),
    };
    const result =
      boundary.kind === "platform"
        ? await listPlatformMfaPolicies({
            ...requestDefaults(),
            query,
            ...(input.signal ? { signal: input.signal } : {}),
          })
        : await listTenantMfaPolicies({
            ...requestDefaults(),
            path: { tenantId: boundary.tenantId },
            query,
            ...(input.signal ? { signal: input.signal } : {}),
          });
    requireSuccess(result.response, 200);
    return projectPage(unwrap(result), boundary, input);
  },

  async get(boundary, policyId, revision, signal) {
    requireBoundary(boundary);
    requirePolicyId(policyId);
    requireRevision(revision);
    const result =
      boundary.kind === "platform"
        ? await getPlatformMfaPolicyRevision({
            ...requestDefaults(),
            path: { policyId, revision },
            ...(signal ? { signal } : {}),
          })
        : await getTenantMfaPolicyRevision({
            ...requestDefaults(),
            path: { tenantId: boundary.tenantId, policyId, revision },
            ...(signal ? { signal } : {}),
          });
    requireSuccess(result.response, 200);
    const value = projectDocument(unwrap(result), boundary);
    if (value.id !== policyId || value.revision !== revision) {
      throw projectionMismatch();
    }
    return versionedDocument(value, result.response);
  },

  async simulate(boundary, csrfToken, input, signal) {
    requireBoundary(boundary);
    requireCsrf(csrfToken);
    const normalized = requireSimulationInput(boundary, input);
    const result =
      boundary.kind === "platform"
        ? await simulatePlatformMfaPolicyChange({
            ...requestDefaults(),
            body: platformSimulationRequest(normalized),
            headers: { "X-CSRF-Token": csrfToken },
            ...(signal ? { signal } : {}),
          })
        : await simulateTenantMfaPolicyChange({
            ...requestDefaults(),
            body: tenantSimulationRequest(normalized),
            headers: { "X-CSRF-Token": csrfToken },
            path: { tenantId: boundary.tenantId },
            ...(signal ? { signal } : {}),
          });
    requireSuccess(result.response, 200);
    return projectSimulation(unwrap(result), boundary, normalized);
  },

  async publish(boundary, csrfToken, commandId, reason, input, signal) {
    requireMutationHeaders(csrfToken, commandId, reason);
    requireBoundary(boundary);
    const normalized = requirePublishInput(boundary, input);
    const result =
      boundary.kind === "platform"
        ? await publishPlatformMfaPolicy({
            ...requestDefaults(),
            body: platformCreateRequest(normalized),
            headers: mutationHeaders(csrfToken, commandId, reason),
            ...(signal ? { signal } : {}),
          })
        : await publishTenantMfaPolicy({
            ...requestDefaults(),
            body: tenantCreateRequest(normalized),
            headers: mutationHeaders(csrfToken, commandId, reason),
            path: { tenantId: boundary.tenantId },
            ...(signal ? { signal } : {}),
          });
    requireSuccess(result.response, 201);
    const projected = projectMutation(unwrap(result), boundary);
    assertPublishTransition(projected, normalized, undefined);
    requireCreatedLocation(result.response, boundary, projected.policy);
    return versionedMutation(projected, result.response);
  },

  async replace(
    boundary,
    csrfToken,
    commandId,
    reason,
    policyId,
    etag,
    input,
    signal,
  ) {
    requireMutationHeaders(csrfToken, commandId, reason);
    requireBoundary(boundary);
    requirePolicyId(policyId);
    requireExpectedEtag(etag, input.expectedRevision, true);
    const normalized = requireReplaceInput(boundary, input);
    const headers = {
      ...mutationHeaders(csrfToken, commandId, reason),
      "If-Match": etag,
    };
    const result =
      boundary.kind === "platform"
        ? await replacePlatformMfaPolicy({
            ...requestDefaults(),
            body: platformReplaceRequest(normalized),
            headers,
            path: { policyId },
            ...(signal ? { signal } : {}),
          })
        : await replaceTenantMfaPolicy({
            ...requestDefaults(),
            body: tenantReplaceRequest(normalized),
            headers,
            path: { tenantId: boundary.tenantId, policyId },
            ...(signal ? { signal } : {}),
          });
    requireSuccess(result.response, 200);
    const projected = projectMutation(unwrap(result), boundary);
    assertPublishTransition(projected, normalized, policyId);
    return versionedMutation(projected, result.response);
  },

  async retire(
    boundary,
    csrfToken,
    commandId,
    reason,
    policyId,
    etag,
    input,
    signal,
  ) {
    requireMutationHeaders(csrfToken, commandId, reason);
    requireBoundary(boundary);
    requirePolicyId(policyId);
    requireExpectedEtag(etag, input.expectedRevision, false);
    const normalized = requireRetireInput(boundary, input);
    const headers = {
      ...mutationHeaders(csrfToken, commandId, reason),
      "If-Match": etag,
    };
    const result =
      boundary.kind === "platform"
        ? await retirePlatformMfaPolicy({
            ...requestDefaults(),
            body: platformRetireRequest(normalized),
            headers,
            path: { policyId },
            ...(signal ? { signal } : {}),
          })
        : await retireTenantMfaPolicy({
            ...requestDefaults(),
            body: tenantRetireRequest(normalized),
            headers,
            path: { tenantId: boundary.tenantId, policyId },
            ...(signal ? { signal } : {}),
          });
    requireSuccess(result.response, 200);
    const projected = projectMutation(unwrap(result), boundary);
    if (
      projected.policy.id !== policyId ||
      projected.policy.revision !== normalized.expectedRevision ||
      projected.policy.status !== "retired" ||
      !sameTarget(projected.policy.target, normalized.target, boundary)
    ) {
      throw projectionMismatch();
    }
    return versionedMutation(projected, result.response);
  },
};

function requestDefaults() {
  return {
    baseUrl: globalThis.location.origin,
    cache: "no-store" as const,
    credentials: "same-origin" as const,
    fetch: sessionAwareFetch,
  };
}

function mutationHeaders(csrfToken: string, commandId: string, reason: string) {
  return {
    "Idempotency-Key": commandId,
    "X-Audit-Reason": reason,
    "X-CSRF-Token": csrfToken,
  };
}

function unwrap<T>(result: GeneratedResult<T>): T {
  if (result.data !== undefined) return result.data;
  requireNoStore(result.response);
  const code = safeProblemCode(result.error);
  const status = result.response?.status;
  if (status === 409 && code === "mfa_policy_recovery_unsafe") {
    throw new MfaPolicyApiError(
      "Publishing this policy would leave no ready direct administrator.",
      code,
      status,
    );
  }
  const message =
    status === 400
      ? "The MFA policy request is invalid."
      : status === 401
        ? "The current session is no longer authenticated."
        : status === 403
          ? "The server denied this MFA policy operation."
          : status === 404
            ? "The requested MFA policy does not exist."
            : status === 409
              ? "The MFA policy command conflicts with current state or a prior command."
              : status === 412
                ? "The MFA policy revision is stale; reload and simulate again."
                : status === 428
                  ? "A current MFA policy revision is required."
                  : "The MFA policy service is unavailable.";
  throw new MfaPolicyApiError(
    message,
    code ?? "mfa_policy_unavailable",
    status,
  );
}

function requireSuccess(response: Response | undefined, status: number): void {
  requireNoStore(response);
  if (!response || (response.ok && response.status !== status)) {
    throw projectionMismatch();
  }
}

function requireNoStore(response: Response | undefined): void {
  const directives = response?.headers
    .get("Cache-Control")
    ?.split(",")
    .map((value) => value.trim().toLowerCase());
  if (!directives?.includes("no-store")) throw projectionMismatch();
}

function safeProblemCode(value: unknown): string | undefined {
  if (!isRecord(value)) return undefined;
  const code = value["code"];
  return typeof code === "string" && safeProblemCodes.has(code)
    ? code
    : undefined;
}

function projectPage(
  value: unknown,
  boundary: MfaPolicyBoundary,
  input: MfaPolicyListInput,
): MfaPolicyPage {
  if (!isRecord(value) || !exactKeys(value, pageKeys)) {
    throw projectionMismatch();
  }
  const rawItems = value["items"];
  if (!Array.isArray(rawItems) || rawItems.length > 100) {
    throw projectionMismatch();
  }
  const items = rawItems.map((item) => projectDocument(item, boundary));
  for (let index = 0; index < items.length; index += 1) {
    const previous = index === 0 ? input.after : items[index - 1];
    if (previous && compareCursor(previous, items[index]!) >= 0) {
      throw projectionMismatch();
    }
    if (!input.includeRetired && items[index]!.status !== "live") {
      throw projectionMismatch();
    }
  }
  const rawCursor = value["nextCursor"];
  let nextCursor: MfaPolicyPage["nextCursor"] = null;
  if (rawCursor !== null) {
    if (!isRecord(rawCursor) || !exactKeys(rawCursor, cursorKeys)) {
      throw projectionMismatch();
    }
    nextCursor = {
      id: canonicalUuid(rawCursor["id"]),
      revision: positiveRevision(rawCursor["revision"]),
    };
    const last = items.at(-1);
    if (!last || compareCursor(last, nextCursor) !== 0) {
      throw projectionMismatch();
    }
  }
  return { items, nextCursor };
}

function projectDocument(
  value: unknown,
  boundary: MfaPolicyBoundary,
): MfaPolicyDocument {
  if (!isRecord(value) || !exactKeys(value, documentKeys)) {
    throw projectionMismatch();
  }
  const target = projectTarget(value["target"], boundary, false);
  const requirement = projectRequirement(value["requirement"]);
  const createdAt = policyInstant(value["createdAt"]);
  const status = value["status"];
  const retiredAt =
    value["retiredAt"] === null ? null : policyInstant(value["retiredAt"]);
  if (
    (status !== "live" && status !== "retired") ||
    (status === "live" && retiredAt !== null) ||
    (status === "retired" &&
      (retiredAt === null || Date.parse(retiredAt) < Date.parse(createdAt))) ||
    (requirement.enrollmentDeadline !== null &&
      Date.parse(requirement.enrollmentDeadline) <= Date.parse(createdAt))
  ) {
    throw projectionMismatch();
  }
  return {
    createdAt,
    id: canonicalUuid(value["id"]),
    requirement,
    retiredAt,
    revision: positiveRevision(value["revision"]),
    status,
    target,
  };
}

function projectTarget(
  value: unknown,
  boundary: MfaPolicyBoundary,
  allowPlatformFloor: boolean,
): MfaPolicyTarget {
  if (!isRecord(value) || typeof value["scope"] !== "string") {
    throw projectionMismatch();
  }
  const scope = value["scope"];
  if (scope === "platform_floor") {
    if (
      !exactKeys(value, platformTargetKeys) ||
      (boundary.kind !== "platform" && !allowPlatformFloor)
    ) {
      throw projectionMismatch();
    }
    return { scope };
  }
  if (boundary.kind !== "tenant") throw projectionMismatch();
  const tenantId = canonicalUuid(value["tenantId"]);
  if (tenantId !== boundary.tenantId) throw projectionMismatch();
  if (scope === "tenant_baseline" && exactKeys(value, tenantTargetKeys)) {
    return { scope, tenantId };
  }
  if (scope === "role" && exactKeys(value, roleTargetKeys)) {
    return { roleId: canonicalUuid(value["roleId"]), scope, tenantId };
  }
  if (scope === "security_group" && exactKeys(value, groupTargetKeys)) {
    return {
      scope,
      securityGroupId: canonicalUuid(value["securityGroupId"]),
      tenantId,
    };
  }
  if (scope === "action" && exactKeys(value, actionTargetKeys)) {
    return { action: audience(value["action"]), scope, tenantId };
  }
  throw projectionMismatch();
}

function projectRequirement(value: unknown): MfaPolicyRequirement {
  if (!isRecord(value) || !exactKeys(value, requirementKeys)) {
    throw projectionMismatch();
  }
  const level = value["level"];
  const freshnessSeconds = value["freshnessSeconds"];
  const localRequired = value["localRequired"];
  const enrollmentDeadline =
    value["enrollmentDeadline"] === null
      ? null
      : policyInstant(value["enrollmentDeadline"]);
  if (
    (level !== "primary" &&
      level !== "mfa" &&
      level !== "phishing_resistant") ||
    typeof localRequired !== "boolean" ||
    !Number.isSafeInteger(freshnessSeconds) ||
    typeof freshnessSeconds !== "number" ||
    freshnessSeconds < 0 ||
    freshnessSeconds > maximumFreshnessSeconds
  ) {
    throw projectionMismatch();
  }
  return { enrollmentDeadline, freshnessSeconds, level, localRequired };
}

function projectSimulation(
  value: unknown,
  boundary: MfaPolicyBoundary,
  input: MfaPolicySimulationInput,
): MfaPolicySimulationResult {
  if (!isRecord(value) || !exactKeys(value, simulationKeys)) {
    throw projectionMismatch();
  }
  const operation = value["operation"];
  if (operation !== "publish" && operation !== "retire") {
    throw projectionMismatch();
  }
  const target = projectTarget(value["target"], boundary, false);
  if (
    operation !== input.operation ||
    !sameTarget(target, input.target, boundary)
  ) {
    throw projectionMismatch();
  }
  const context = projectResponseContext(value["context"], boundary, input);
  const current =
    value["current"] === null
      ? null
      : projectDocument(value["current"], boundary);
  if (
    (input.expectedRevision === 0 && current !== null) ||
    (input.expectedRevision > 0 &&
      (current === null ||
        current.id !== input.expectedPolicyId ||
        current.revision !== input.expectedRevision ||
        current.status !== "live" ||
        !sameTarget(current.target, input.target, boundary)))
  ) {
    throw projectionMismatch();
  }
  const candidate = projectCandidate(value["candidate"], boundary, input);
  const effective = projectEffective(
    value["effective"],
    boundary,
    context,
    candidate,
    operation,
  );
  const recovery = projectRecovery(value["recovery"]);
  return {
    candidate,
    context,
    current,
    effective,
    operation,
    recovery,
    target,
  };
}

function projectResponseContext(
  value: unknown,
  boundary: MfaPolicyBoundary,
  input: MfaPolicySimulationInput,
): MfaPolicySimulationContext | null {
  if (boundary.kind === "platform") {
    if (value !== null || input.context !== undefined)
      throw projectionMismatch();
    return null;
  }
  const context = projectContext(value);
  if (!sameContext(context, input.context)) throw projectionMismatch();
  return context;
}

function projectCandidate(
  value: unknown,
  boundary: MfaPolicyBoundary,
  input: MfaPolicySimulationInput,
): MfaPolicySimulationResult["candidate"] {
  if (input.operation === "retire") {
    if (value !== null) throw projectionMismatch();
    return null;
  }
  if (!isRecord(value) || !exactKeys(value, candidateKeys)) {
    throw projectionMismatch();
  }
  const target = projectTarget(value["target"], boundary, false);
  const requirement = projectRequirement(value["requirement"]);
  if (
    !sameTarget(target, input.target, boundary) ||
    !sameRequirement(requirement, input.requirement)
  ) {
    throw projectionMismatch();
  }
  return { requirement, target };
}

function projectEffective(
  value: unknown,
  boundary: MfaPolicyBoundary,
  context: MfaPolicySimulationContext | null,
  candidate: MfaPolicySimulationResult["candidate"],
  operation: "publish" | "retire",
): MfaPolicySimulationResult["effective"] {
  if (!isRecord(value) || !exactKeys(value, effectiveKeys)) {
    throw projectionMismatch();
  }
  const rawSources = value["sources"];
  if (!Array.isArray(rawSources) || rawSources.length > 1024) {
    throw projectionMismatch();
  }
  const sources = rawSources.map((source) =>
    projectSource(source, boundary, context),
  );
  let candidateCount = 0;
  let baselineCount = 0;
  const currentIds = new Set<string>();
  for (let index = 0; index < sources.length; index += 1) {
    const source = sources[index]!;
    if (
      index > 0 &&
      compareTarget(sources[index - 1]!.target, source.target) >= 0
    ) {
      throw projectionMismatch();
    }
    if (source.target.scope === "tenant_baseline") baselineCount += 1;
    if (source.source === "candidate") {
      candidateCount += 1;
      if (
        !candidate ||
        !sameStoredTarget(source.target, candidate.target) ||
        !sameRequirement(source.requirement, candidate.requirement)
      ) {
        throw projectionMismatch();
      }
    } else {
      if (!source.policyId || currentIds.has(source.policyId)) {
        throw projectionMismatch();
      }
      currentIds.add(source.policyId);
    }
  }
  if (
    candidateCount !== (candidate ? 1 : 0) ||
    (boundary.kind === "tenant" && baselineCount !== 1)
  ) {
    throw projectionMismatch();
  }
  const requirement =
    value["requirement"] === null
      ? null
      : projectRequirement(value["requirement"]);
  const folded = foldRequirements(sources);
  if (
    (requirement === null &&
      (folded !== null ||
        boundary.kind !== "platform" ||
        operation !== "retire")) ||
    (requirement !== null &&
      (folded === null || !sameRequirement(requirement, folded)))
  ) {
    throw projectionMismatch();
  }
  return { requirement, sources };
}

function projectSource(
  value: unknown,
  boundary: MfaPolicyBoundary,
  context: MfaPolicySimulationContext | null,
): MfaPolicySimulationSource {
  if (!isRecord(value) || typeof value["source"] !== "string") {
    throw projectionMismatch();
  }
  const source = value["source"];
  const current = source === "current";
  if (
    (current && !exactKeys(value, currentSourceKeys)) ||
    (!current &&
      (source !== "candidate" || !exactKeys(value, candidateSourceKeys)))
  ) {
    throw projectionMismatch();
  }
  const target = projectTarget(value["target"], boundary, true);
  if (!sourceApplies(target, boundary, context)) throw projectionMismatch();
  const requirement = projectRequirement(value["requirement"]);
  if (!current) return { requirement, source, target };
  return {
    policyId: canonicalUuid(value["policyId"]),
    requirement,
    revision: positiveRevision(value["revision"]),
    source,
    target,
  };
}

function projectRecovery(
  value: unknown,
): MfaPolicySimulationResult["recovery"] {
  if (!isRecord(value) || !exactKeys(value, recoveryKeys)) {
    throw projectionMismatch();
  }
  const safe = value["safe"];
  const eligible = nonnegativeSafeInteger(
    value["eligibleDirectAdministrators"],
  );
  const ready = nonnegativeSafeInteger(value["readyDirectAdministrators"]);
  const rawReasons: unknown = value["reasonCodes"];
  if (
    typeof safe !== "boolean" ||
    ready > eligible ||
    !Array.isArray(rawReasons) ||
    rawReasons.length > 3
  ) {
    throw projectionMismatch();
  }
  const reasonCodes = rawReasons.map(projectRecoveryReason);
  if (new Set(reasonCodes).size !== reasonCodes.length) {
    throw projectionMismatch();
  }
  if (
    (ready > 0 && (!safe || reasonCodes.length !== 0)) ||
    (ready === 0 && safe) ||
    (eligible === 0 &&
      (reasonCodes.length !== 1 ||
        reasonCodes[0] !== "no_eligible_direct_administrator")) ||
    (eligible > 0 &&
      ready === 0 &&
      (reasonCodes.length === 0 ||
        reasonCodes.includes("no_eligible_direct_administrator") ||
        reasonCodes.some(
          (reason, index) => index > 0 && reasonCodes[index - 1]! >= reason,
        )))
  ) {
    throw projectionMismatch();
  }
  return {
    eligibleDirectAdministrators: eligible,
    readyDirectAdministrators: ready,
    reasonCodes: [...reasonCodes],
    safe,
  };
}

function projectRecoveryReason(value: unknown): MfaPolicyRecoveryReason {
  if (typeof value !== "string" || !recoveryReasons.has(value)) {
    throw projectionMismatch();
  }
  switch (value) {
    case "no_eligible_direct_administrator":
    case "no_ready_local_mfa":
    case "no_ready_local_phishing_resistant":
    case "no_ready_local_primary":
      return value;
    default:
      throw projectionMismatch();
  }
}

function projectMutation(
  value: unknown,
  boundary: MfaPolicyBoundary,
): MfaPolicyMutationResult {
  if (
    !isRecord(value) ||
    !exactKeys(value, mutationKeys) ||
    typeof value["replayed"] !== "boolean"
  ) {
    throw projectionMismatch();
  }
  return {
    policy: projectDocument(value["policy"], boundary),
    replayed: value["replayed"],
  };
}

function versionedDocument(
  value: MfaPolicyDocument,
  response: Response | undefined,
): VersionedMfaPolicyDocument {
  const etag = requireResponseEtag(response, value.revision);
  return { etag, value };
}

function versionedMutation(
  value: MfaPolicyMutationResult,
  response: Response | undefined,
): VersionedMfaPolicyMutation {
  const etag = requireResponseEtag(response, value.policy.revision);
  return { etag, value };
}

function requireResponseEtag(
  response: Response | undefined,
  revision: number,
): string {
  const etag = response?.headers.get("ETag") ?? "";
  const match = strongEtagPattern.exec(etag);
  if (!match || Number(match[1]) !== revision) throw projectionMismatch();
  return etag;
}

function requireCreatedLocation(
  response: Response | undefined,
  boundary: MfaPolicyBoundary,
  document: MfaPolicyDocument,
): void {
  const prefix =
    boundary.kind === "platform"
      ? "/api/v1/platform"
      : `/api/v1/tenants/${boundary.tenantId}`;
  const expected = `${prefix}/mfa-policies/${document.id}/revisions/${document.revision}`;
  if (response?.headers.get("Location") !== expected)
    throw projectionMismatch();
}

function assertPublishTransition(
  value: MfaPolicyMutationResult,
  input: MfaPolicyPublishInput | MfaPolicyReplaceInput,
  policyId: string | undefined,
): void {
  const expectedRevision = input.expectedRevision + 1;
  if (
    value.policy.status !== "live" ||
    value.policy.revision !== expectedRevision ||
    (policyId !== undefined && value.policy.id !== policyId) ||
    !sameInputTarget(value.policy.target, input.target) ||
    !sameRequirement(value.policy.requirement, input.requirement)
  ) {
    throw projectionMismatch();
  }
}

function requireBoundary(boundary: MfaPolicyBoundary): void {
  if (boundary.kind === "platform") return;
  if (boundary.kind !== "tenant" || !isCanonicalUuidV7(boundary.tenantId)) {
    throw new TypeError("A canonical active tenant UUIDv7 is required.");
  }
}

function requireListInput(input: MfaPolicyListInput): void {
  if (input.after) {
    requirePolicyId(input.after.id);
    requireRevision(input.after.revision);
  }
  if (
    input.includeRetired !== undefined &&
    typeof input.includeRetired !== "boolean"
  ) {
    throw new TypeError("includeRetired must be boolean.");
  }
}

function requireSimulationInput(
  boundary: MfaPolicyBoundary,
  input: MfaPolicySimulationInput,
): MfaPolicySimulationInput {
  const target = requireInputTarget(input.target, boundary);
  const context =
    boundary.kind === "tenant" ? requireInputContext(input.context) : undefined;
  if (boundary.kind === "platform" && input.context !== undefined) {
    throw new TypeError("Platform simulation does not accept tenant context.");
  }
  if (context && !mfaPolicyTargetApplies(target, context)) {
    throw new TypeError(
      "The simulated target must be present in the exact context.",
    );
  }
  if (input.operation === "publish") {
    const requirement = requireInputRequirement(input.requirement, true);
    requirePublishCas(input.expectedPolicyId, input.expectedRevision);
    return {
      ...(context ? { context } : {}),
      ...(input.expectedPolicyId
        ? { expectedPolicyId: input.expectedPolicyId }
        : {}),
      expectedRevision: input.expectedRevision,
      operation: "publish",
      requirement,
      target,
    };
  }
  if (input.operation !== "retire" || input.requirement !== undefined) {
    throw new TypeError("Simulation operation is invalid.");
  }
  requirePolicyId(input.expectedPolicyId ?? "");
  requireRevision(input.expectedRevision);
  return {
    ...(context ? { context } : {}),
    expectedPolicyId: input.expectedPolicyId!,
    expectedRevision: input.expectedRevision,
    operation: "retire",
    target,
  };
}

function requirePublishInput(
  boundary: MfaPolicyBoundary,
  input: MfaPolicyPublishInput,
): MfaPolicyPublishInput {
  if (input.expectedRevision !== 0)
    throw new TypeError("Create revision must be zero.");
  return {
    expectedRevision: 0,
    requirement: requireInputRequirement(input.requirement, true),
    target: requireInputTarget(input.target, boundary),
  };
}

function requireReplaceInput(
  boundary: MfaPolicyBoundary,
  input: MfaPolicyReplaceInput,
): MfaPolicyReplaceInput {
  requireRevision(input.expectedRevision, true);
  return {
    expectedRevision: input.expectedRevision,
    requirement: requireInputRequirement(input.requirement, true),
    target: requireInputTarget(input.target, boundary),
  };
}

function requireRetireInput(
  boundary: MfaPolicyBoundary,
  input: MfaPolicyRetireInput,
): MfaPolicyRetireInput {
  requireRevision(input.expectedRevision);
  return {
    expectedRevision: input.expectedRevision,
    target: requireInputTarget(input.target, boundary),
  };
}

function platformSimulationRequest(
  input: MfaPolicySimulationInput,
): PlatformMfaPolicySimulationRequest {
  return {
    ...(input.expectedPolicyId
      ? { expectedPolicyId: input.expectedPolicyId }
      : {}),
    expectedRevision: input.expectedRevision,
    operation: input.operation,
    ...(input.requirement ? { requirement: input.requirement } : {}),
    target: platformTarget(input.target),
  };
}

function tenantSimulationRequest(
  input: MfaPolicySimulationInput,
): TenantMfaPolicySimulationRequest {
  if (!input.context) {
    throw new TypeError("Exact tenant simulation context is required.");
  }
  return {
    context: input.context,
    ...(input.expectedPolicyId
      ? { expectedPolicyId: input.expectedPolicyId }
      : {}),
    expectedRevision: input.expectedRevision,
    operation: input.operation,
    ...(input.requirement ? { requirement: input.requirement } : {}),
    target: tenantTarget(input.target),
  };
}

function platformCreateRequest(
  input: MfaPolicyPublishInput,
): PlatformMfaPolicyCreateRequest {
  return {
    expectedRevision: 0,
    requirement: input.requirement,
    target: platformTarget(input.target),
  };
}

function tenantCreateRequest(
  input: MfaPolicyPublishInput,
): TenantMfaPolicyCreateRequest {
  return {
    expectedRevision: 0,
    requirement: input.requirement,
    target: tenantTarget(input.target),
  };
}

function platformReplaceRequest(
  input: MfaPolicyReplaceInput,
): PlatformMfaPolicyReplaceRequest {
  return {
    expectedRevision: input.expectedRevision,
    requirement: input.requirement,
    target: platformTarget(input.target),
  };
}

function tenantReplaceRequest(
  input: MfaPolicyReplaceInput,
): TenantMfaPolicyReplaceRequest {
  return {
    expectedRevision: input.expectedRevision,
    requirement: input.requirement,
    target: tenantTarget(input.target),
  };
}

function platformRetireRequest(
  input: MfaPolicyRetireInput,
): PlatformMfaPolicyRetireRequest {
  return {
    expectedRevision: input.expectedRevision,
    target: platformTarget(input.target),
  };
}

function tenantRetireRequest(
  input: MfaPolicyRetireInput,
): TenantMfaPolicyRetireRequest {
  return {
    expectedRevision: input.expectedRevision,
    target: tenantTarget(input.target),
  };
}

function platformTarget(
  value: MfaPolicyTargetInput,
): PlatformMfaPolicyCreateRequest["target"] {
  if (value.scope !== "platform_floor") {
    throw new TypeError(
      "Platform policies can target only the explicit floor.",
    );
  }
  return { scope: "platform_floor" };
}

// oxlint-disable-next-line typescript/consistent-return -- The target union is exhaustively returned or rejected by its discriminator.
function tenantTarget(
  value: MfaPolicyTargetInput,
): TenantMfaPolicyCreateRequest["target"] {
  switch (value.scope) {
    case "tenant_baseline":
      return { scope: "tenant_baseline" };
    case "role":
      return { roleId: value.roleId, scope: "role" };
    case "security_group":
      return {
        scope: "security_group",
        securityGroupId: value.securityGroupId,
      };
    case "action":
      return { action: value.action, scope: "action" };
    case "platform_floor":
      throw new TypeError("Tenant policies cannot target the platform floor.");
  }
}

function requireInputTarget(
  value: MfaPolicyTargetInput,
  boundary: MfaPolicyBoundary,
): MfaPolicyTargetInput {
  if (!isRecord(value) || typeof value["scope"] !== "string") {
    throw new TypeError("MFA policy target is invalid.");
  }
  if (boundary.kind === "platform") {
    if (
      value["scope"] !== "platform_floor" ||
      !exactKeys(value, platformTargetKeys)
    ) {
      throw new TypeError(
        "Platform policies can target only the explicit floor.",
      );
    }
    return { scope: "platform_floor" };
  }
  switch (value["scope"]) {
    case "tenant_baseline":
      if (exactKeys(value, inputTenantTargetKeys))
        return { scope: "tenant_baseline" };
      break;
    case "role":
      if (exactKeys(value, inputRoleTargetKeys)) {
        return { roleId: canonicalInputUuid(value["roleId"]), scope: "role" };
      }
      break;
    case "security_group":
      if (exactKeys(value, inputGroupTargetKeys)) {
        return {
          scope: "security_group",
          securityGroupId: canonicalInputUuid(value["securityGroupId"]),
        };
      }
      break;
    case "action":
      if (exactKeys(value, inputActionTargetKeys)) {
        return { action: inputAudience(value["action"]), scope: "action" };
      }
      break;
  }
  throw new TypeError("Tenant MFA policy target is invalid.");
}

function requireInputRequirement(
  value: MfaPolicyRequirement | undefined,
  requireFuture: boolean,
): MfaPolicyRequirement {
  if (!value) throw new TypeError("An MFA policy requirement is required.");
  const projected = projectRequirement(value);
  if (
    requireFuture &&
    projected.enrollmentDeadline !== null &&
    Date.parse(projected.enrollmentDeadline) <= Date.now()
  ) {
    throw new TypeError("Enrollment deadline must be in the future.");
  }
  return projected;
}

function requireInputContext(
  value: MfaPolicySimulationContext | undefined,
): MfaPolicySimulationContext {
  if (!value)
    throw new TypeError("Exact tenant simulation context is required.");
  return projectContext(value);
}

function projectContext(value: unknown): MfaPolicySimulationContext {
  if (!isRecord(value) || !exactKeys(value, contextKeys))
    throw projectionMismatch();
  const action = audience(value["action"]);
  const roleIds = canonicalIdArray(value["roleIds"]);
  const securityGroupIds = canonicalIdArray(value["securityGroupIds"]);
  return { action, roleIds, securityGroupIds };
}

function requirePublishCas(
  policyId: string | undefined,
  revision: number,
): void {
  if (revision === 0) {
    if (policyId !== undefined)
      throw new TypeError("Create CAS cannot include a policy ID.");
    return;
  }
  requirePolicyId(policyId ?? "");
  requireRevision(revision, true);
}

function requireMutationHeaders(
  csrf: string,
  commandId: string,
  reason: string,
): void {
  requireCsrf(csrf);
  if (!isCanonicalUuidV7(commandId))
    throw new TypeError("Command ID must be UUIDv7.");
  if (!isMfaPolicyAuditReason(reason))
    throw new TypeError("Audit reason is invalid.");
}

function requireCsrf(value: string): void {
  if (value.length < 16 || value.length > 512)
    throw new TypeError("CSRF context is unavailable.");
}

function requirePolicyId(value: string): void {
  if (!isCanonicalUuidV7(value))
    throw new TypeError("Policy ID must be UUIDv7.");
}

function requireRevision(value: number, requireHeadroom = false): void {
  const maximum = requireHeadroom ? maximumRevision - 1 : maximumRevision;
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new TypeError("MFA policy revision is invalid.");
  }
}

function requireExpectedEtag(
  etag: string,
  revision: number,
  headroom: boolean,
): void {
  requireRevision(revision, headroom);
  if (etag !== `"v${revision}"` || !strongEtagPattern.test(etag)) {
    throw new TypeError(
      "MFA policy ETag does not match the expected revision.",
    );
  }
}

function canonicalUuid(value: unknown): string {
  if (typeof value !== "string" || !isCanonicalUuidV7(value))
    throw projectionMismatch();
  return value;
}

function canonicalInputUuid(value: unknown): string {
  if (typeof value !== "string" || !isCanonicalUuidV7(value)) {
    throw new TypeError("A canonical UUIDv7 target is required.");
  }
  return value;
}

function canonicalIdArray(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > 512) throw projectionMismatch();
  const result = value.map(canonicalUuid);
  if (
    new Set(result).size !== result.length ||
    result.some((item, index) => index > 0 && result[index - 1]! >= item)
  ) {
    throw projectionMismatch();
  }
  return result;
}

function policyInstant(value: unknown): string {
  if (typeof value !== "string" || !isMfaPolicyInstant(value)) {
    throw projectionMismatch();
  }
  return value;
}

function audience(value: unknown): string {
  if (typeof value !== "string" || !validAudience(value))
    throw projectionMismatch();
  return value;
}

function inputAudience(value: unknown): string {
  if (typeof value !== "string" || !validAudience(value)) {
    throw new TypeError("Action must be exact non-empty bounded text.");
  }
  return value;
}

function validAudience(value: string): boolean {
  return (
    value.length >= 1 &&
    value.length <= 256 &&
    value.trim() === value &&
    !/[\p{Cc}\p{Cf}]/u.test(value)
  );
}

function positiveRevision(value: unknown): number {
  if (typeof value !== "number") throw projectionMismatch();
  requireProjectionRevision(value);
  return value;
}

function requireProjectionRevision(value: number): void {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximumRevision) {
    throw projectionMismatch();
  }
}

function nonnegativeSafeInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw projectionMismatch();
  }
  return value;
}

function sourceApplies(
  target: MfaPolicyTarget,
  boundary: MfaPolicyBoundary,
  context: MfaPolicySimulationContext | null,
): boolean {
  if (target.scope === "platform_floor") return true;
  if (boundary.kind !== "tenant" || context === null) return false;
  if (target.scope === "tenant_baseline") return true;
  if (target.scope === "role")
    return context.roleIds.includes(target.roleId ?? "");
  if (target.scope === "security_group") {
    return context.securityGroupIds.includes(target.securityGroupId ?? "");
  }
  return target.scope === "action" && target.action === context.action;
}

function foldRequirements(
  sources: readonly MfaPolicySimulationSource[],
): MfaPolicyRequirement | null {
  if (sources.length === 0) return null;
  const levels = { primary: 1, mfa: 2, phishing_resistant: 3 } as const;
  let level: MfaPolicyRequirement["level"] = "primary";
  let localRequired = false;
  let freshnessSeconds = 0;
  let enrollmentDeadline: string | null = null;
  for (const source of sources) {
    const requirement = source.requirement;
    if (levels[requirement.level] > levels[level]) level = requirement.level;
    localRequired ||= requirement.localRequired;
    if (
      requirement.freshnessSeconds > 0 &&
      (freshnessSeconds === 0 ||
        requirement.freshnessSeconds < freshnessSeconds)
    ) {
      freshnessSeconds = requirement.freshnessSeconds;
    }
    if (
      requirement.enrollmentDeadline !== null &&
      (enrollmentDeadline === null ||
        Date.parse(requirement.enrollmentDeadline) <
          Date.parse(enrollmentDeadline))
    ) {
      enrollmentDeadline = requirement.enrollmentDeadline;
    }
  }
  return { enrollmentDeadline, freshnessSeconds, level, localRequired };
}

function compareCursor(
  left: { id: string; revision: number },
  right: { id: string; revision: number },
): number {
  if (left.id !== right.id) return left.id.localeCompare(right.id);
  if (left.revision < right.revision) return -1;
  if (left.revision > right.revision) return 1;
  return 0;
}

function compareTarget(left: MfaPolicyTarget, right: MfaPolicyTarget): number {
  const rank = {
    platform_floor: 0,
    tenant_baseline: 1,
    security_group: 2,
    role: 3,
    action: 4,
  } as const;
  const rankDifference = rank[left.scope] - rank[right.scope];
  if (rankDifference !== 0) return rankDifference;
  return targetStableValue(left).localeCompare(targetStableValue(right));
}

function targetStableValue(value: MfaPolicyTarget): string {
  return [
    value.tenantId ?? "",
    value.securityGroupId ?? "",
    value.roleId ?? "",
    value.action ?? "",
  ].join("\u0000");
}

function sameContext(
  left: MfaPolicySimulationContext,
  right: MfaPolicySimulationContext | undefined,
): boolean {
  return (
    right !== undefined &&
    left.action === right.action &&
    left.roleIds.length === right.roleIds.length &&
    left.securityGroupIds.length === right.securityGroupIds.length &&
    left.roleIds.every((id, index) => id === right.roleIds[index]) &&
    left.securityGroupIds.every(
      (id, index) => id === right.securityGroupIds[index],
    )
  );
}

function sameTarget(
  stored: MfaPolicyTarget,
  input: MfaPolicyTargetInput,
  boundary: MfaPolicyBoundary,
): boolean {
  return (
    sameInputTarget(stored, input) &&
    (boundary.kind === "platform"
      ? stored.tenantId === undefined
      : stored.scope === "platform_floor" ||
        stored.tenantId === boundary.tenantId)
  );
}

function sameInputTarget(
  stored: MfaPolicyTarget,
  input: MfaPolicyTargetInput,
): boolean {
  if (stored.scope !== input.scope) return false;
  if (input.scope === "role") return stored.roleId === input.roleId;
  if (input.scope === "security_group") {
    return stored.securityGroupId === input.securityGroupId;
  }
  if (input.scope === "action") return stored.action === input.action;
  return true;
}

function sameStoredTarget(
  left: MfaPolicyTarget,
  right: MfaPolicyTarget,
): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sameRequirement(
  left: MfaPolicyRequirement,
  right: MfaPolicyRequirement | undefined,
): boolean {
  return (
    right !== undefined &&
    left.level === right.level &&
    left.localRequired === right.localRequired &&
    left.freshnessSeconds === right.freshnessSeconds &&
    left.enrollmentDeadline === right.enrollmentDeadline
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(
  value: Record<string, unknown>,
  expected: ReadonlySet<string>,
): boolean {
  const keys = Object.keys(value);
  return (
    keys.length === expected.size && keys.every((key) => expected.has(key))
  );
}

function projectionMismatch(): MfaPolicyApiError {
  return new MfaPolicyApiError(
    "The MFA policy API returned an unsafe or inconsistent projection.",
    "projection_mismatch",
  );
}

const maximumRevision = Number.MAX_SAFE_INTEGER;
const maximumFreshnessSeconds = 31_536_000;
const strongEtagPattern = /^"v([1-9]\d{0,15})"$/u;
const safeProblemCodes = new Set([
  "conflict",
  "forbidden",
  "invalid_request",
  "mfa_policy_recovery_unsafe",
  "not_found",
  "precondition_failed",
  "precondition_required",
  "service_unavailable",
]);
const recoveryReasons = new Set([
  "no_eligible_direct_administrator",
  "no_ready_local_mfa",
  "no_ready_local_phishing_resistant",
  "no_ready_local_primary",
]);
const pageKeys = new Set(["items", "nextCursor"]);
const cursorKeys = new Set(["id", "revision"]);
const documentKeys = new Set([
  "createdAt",
  "id",
  "requirement",
  "retiredAt",
  "revision",
  "status",
  "target",
]);
const requirementKeys = new Set([
  "enrollmentDeadline",
  "freshnessSeconds",
  "level",
  "localRequired",
]);
const platformTargetKeys = new Set(["scope"]);
const tenantTargetKeys = new Set(["scope", "tenantId"]);
const roleTargetKeys = new Set(["roleId", "scope", "tenantId"]);
const groupTargetKeys = new Set(["scope", "securityGroupId", "tenantId"]);
const actionTargetKeys = new Set(["action", "scope", "tenantId"]);
const inputTenantTargetKeys = new Set(["scope"]);
const inputRoleTargetKeys = new Set(["roleId", "scope"]);
const inputGroupTargetKeys = new Set(["scope", "securityGroupId"]);
const inputActionTargetKeys = new Set(["action", "scope"]);
const simulationKeys = new Set([
  "candidate",
  "context",
  "current",
  "effective",
  "operation",
  "recovery",
  "target",
]);
const contextKeys = new Set(["action", "roleIds", "securityGroupIds"]);
const candidateKeys = new Set(["requirement", "target"]);
const effectiveKeys = new Set(["requirement", "sources"]);
const currentSourceKeys = new Set([
  "policyId",
  "requirement",
  "revision",
  "source",
  "target",
]);
const candidateSourceKeys = new Set(["requirement", "source", "target"]);
const recoveryKeys = new Set([
  "eligibleDirectAdministrators",
  "readyDirectAdministrators",
  "reasonCodes",
  "safe",
]);
const mutationKeys = new Set(["policy", "replayed"]);
