import { createHash } from "node:crypto";
import { isIP, type Socket } from "node:net";
import { domainToASCII } from "node:url";

import {
  DeliveryProviderError,
  NotificationValidationError,
} from "./errors.js";
import { requireInstant, requireInteger, requireUuidV7 } from "./validation.js";

const maximumPolicyVersion = 2_147_483_647;
const maximumRules = 256;
const maximumUrlBytes = 2_048;
const digestPattern = /^[0-9a-f]{64}$/u;
const safeUrlSuffixPattern =
  /^\/[A-Za-z0-9\-._~!$&'()*+,;=:@/]*(?:\?[A-Za-z0-9\-._~!$&'()*+,;=:@/?]*)?$/u;

export type WebhookUrlPolicyEffect = "allow" | "deny";
export type WebhookUrlPolicyMatch = "exact" | "subdomains";

export interface WebhookUrlPolicyRuleInput {
  readonly effect: WebhookUrlPolicyEffect;
  readonly match: WebhookUrlPolicyMatch;
  readonly hostname: string;
  readonly port?: number;
}

export interface WebhookUrlPolicyRule {
  readonly effect: WebhookUrlPolicyEffect;
  readonly match: WebhookUrlPolicyMatch;
  readonly hostname: string;
  readonly port: number;
  readonly digest: string;
}

export interface WebhookUrlPolicyVersionInput {
  readonly id: string;
  readonly versionId: string;
  readonly tenantId: string;
  readonly version: number;
  readonly rules: readonly WebhookUrlPolicyRuleInput[];
  readonly publishedByMembershipId: string;
  readonly publishedAt: Date;
}

export interface WebhookUrlPolicyVersion {
  readonly id: string;
  readonly versionId: string;
  readonly tenantId: string;
  readonly version: number;
  readonly scheme: "https";
  readonly defaultAction: "deny";
  readonly rules: readonly WebhookUrlPolicyRule[];
  readonly publishedByMembershipId: string;
  readonly publishedAt: string;
  readonly digest: string;
  readonly semanticDigest: string;
}

export interface WebhookUrlPolicyReplacementInput {
  readonly expectedVersion: number;
  readonly versionId: string;
  readonly rules: readonly WebhookUrlPolicyRuleInput[];
  readonly publishedByMembershipId: string;
  readonly publishedAt: Date;
}

export interface WebhookUrlPolicyPlan {
  readonly expectedVersion: number;
  readonly next: WebhookUrlPolicyVersion;
}

export interface CanonicalWebhookEndpoint {
  readonly url: string;
  readonly hostname: string;
  readonly port: number;
  readonly digest: string;
}

export type WebhookUrlPolicyDecisionReason =
  | "allowed_by_rule"
  | "denied_by_rule"
  | "default_deny"
  | "policy_pin_mismatch"
  | "policy_unavailable"
  | "target_mismatch";

export interface WebhookUrlPolicyDecisionEvidence {
  readonly allowed: boolean;
  readonly reason: WebhookUrlPolicyDecisionReason;
  readonly policyId: string;
  readonly policyVersion: number;
  readonly policyDigest: string;
  readonly endpointDigest: string;
  readonly matchedRuleDigest?: string;
}

export interface WebhookConfigurationPolicyPinInput {
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly tenantId: string;
  readonly endpointUrl: string;
}

export interface WebhookConfigurationPolicyPin {
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly tenantId: string;
  readonly endpointUrl: string;
  readonly endpointDigest: string;
  readonly policyId: string;
  readonly policyVersionId: string;
  readonly policyVersion: number;
  readonly policyDigest: string;
  readonly decision: WebhookUrlPolicyDecisionEvidence;
}

export interface WebhookDeliveryPolicyPinInput {
  readonly deliveryId: string;
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly tenantId: string;
  readonly endpointUrl: string;
}

export interface WebhookDeliveryPolicyPin {
  readonly deliveryId: string;
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly tenantId: string;
  readonly endpointUrl: string;
  readonly endpointDigest: string;
  readonly policyId: string;
  readonly policyVersionId: string;
  readonly policyVersion: number;
  readonly policyDigest: string;
}

export interface WebhookLocalDevelopmentPinInput {
  readonly deliveryId: string;
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly tenantId: string;
  readonly endpointUrl: string;
}

export interface WebhookLocalDevelopmentPin {
  readonly deliveryId: string;
  readonly configurationId: string;
  readonly configurationVersion: number;
  readonly tenantId: string;
  readonly endpointUrl: string;
  readonly endpointDigest: string;
  readonly localDevelopmentExemption: true;
}

export type WebhookDeliveryEgressPin =
  WebhookDeliveryPolicyPin | WebhookLocalDevelopmentPin;

export interface LiveWebhookUrlPolicySource {
  // Missing current state is returned as null and is a terminal pin mismatch.
  // Dependency failures reject and remain retry-safe.
  loadCurrent(input: {
    readonly tenantId: string;
    readonly policyId: string;
    readonly phase: "attempt" | "connect";
    readonly signal: AbortSignal;
  }): Promise<WebhookUrlPolicyVersion | null>;
  loadLocalDevelopmentAuthorization?(input: {
    readonly tenantId: string;
    readonly phase: "attempt" | "connect";
    readonly signal: AbortSignal;
  }): Promise<boolean>;
}

export interface WebhookPolicyTcpConnector {
  connect(input: {
    readonly host: string;
    readonly port: number;
    readonly timeoutMs: number;
    readonly requireLoopbackTarget?: boolean;
    readonly signal?: AbortSignal;
  }): Promise<Socket>;
}

export interface WebhookUrlPolicyAttemptPermit {
  readonly attemptEvidence:
    WebhookUrlPolicyDecisionEvidence | WebhookLocalDevelopmentEvidence;
}

export interface WebhookUrlPolicyConnection {
  readonly socket: Socket;
  readonly connectEvidence:
    WebhookUrlPolicyDecisionEvidence | WebhookLocalDevelopmentEvidence;
}

export interface WebhookLocalDevelopmentEvidence {
  readonly allowed: true;
  readonly reason: "local_development_exemption";
  readonly endpointDigest: string;
}

const authenticPolicies = new WeakSet<WebhookUrlPolicyVersion>();
const authenticEndpoints = new WeakSet<CanonicalWebhookEndpoint>();
const authenticConfigurationPins = new WeakSet<WebhookConfigurationPolicyPin>();
const authenticDeliveryPins = new WeakSet<WebhookDeliveryPolicyPin>();
const authenticLocalDevelopmentPins = new WeakSet<WebhookLocalDevelopmentPin>();
const permitStates = new WeakMap<
  WebhookUrlPolicyAttemptPermit,
  | Readonly<{
      kind: "policy";
      pin: WebhookDeliveryPolicyPin;
      endpoint: CanonicalWebhookEndpoint;
      gate: LiveWebhookUrlPolicyGate;
    }>
  | Readonly<{
      kind: "local";
      pin: WebhookLocalDevelopmentPin;
      endpoint: CanonicalLocalWebhookEndpoint;
      gate: LiveWebhookUrlPolicyGate;
    }>
>();

interface CanonicalLocalWebhookEndpoint {
  readonly url: string;
  readonly hostname: "localhost" | "127.0.0.1" | "::1";
  readonly port: number;
  readonly digest: string;
}

export class WebhookUrlPolicyEnforcementError extends DeliveryProviderError {
  readonly evidence: WebhookUrlPolicyDecisionEvidence;

  constructor(decisionEvidence: WebhookUrlPolicyDecisionEvidence) {
    super(
      decisionEvidence.reason === "policy_unavailable"
        ? "connectivity"
        : "security",
      decisionEvidence.reason === "policy_unavailable" ? "safe" : "terminal",
    );
    this.name = "WebhookUrlPolicyEnforcementError";
    this.evidence = decisionEvidence;
  }
}

export function createWebhookUrlPolicyVersion(
  input: WebhookUrlPolicyVersionInput,
): WebhookUrlPolicyVersion {
  requireUuidV7(input.id, "webhook URL policy id");
  requireUuidV7(input.versionId, "webhook URL policy version id");
  requireUuidV7(input.tenantId, "webhook URL policy tenant id");
  requireUuidV7(
    input.publishedByMembershipId,
    "webhook URL policy publisher membership id",
  );
  if (input.id === input.versionId) invalidPolicy();
  const version = requireInteger(
    input.version,
    "webhook URL policy version",
    1,
    maximumPolicyVersion,
  );
  const publishedAtValue = requireInstant(
    input.publishedAt,
    "webhook URL policy publishedAt",
  );
  if (
    publishedAtValue.getUTCFullYear() < 2000 ||
    publishedAtValue.getUTCFullYear() > 9999
  ) {
    invalidPolicy();
  }
  const publishedAt = publishedAtValue.toISOString();
  const rules = canonicalRules(input.rules);
  const semanticDigest = digest([
    "periapsis.webhook-url-policy-semantics.v1",
    "https",
    "deny",
    ...rules.map(canonicalRuleRecord),
  ]);
  const policyDigest = digest([
    "periapsis.webhook-url-policy-version.v1",
    input.tenantId,
    input.id,
    input.versionId,
    String(version),
    input.publishedByMembershipId,
    publishedAt,
    semanticDigest,
  ]);
  const policy = Object.freeze({
    id: input.id,
    versionId: input.versionId,
    tenantId: input.tenantId,
    version,
    scheme: "https" as const,
    defaultAction: "deny" as const,
    rules,
    publishedByMembershipId: input.publishedByMembershipId,
    publishedAt,
    digest: policyDigest,
    semanticDigest,
  });
  authenticPolicies.add(policy);
  return policy;
}

export function planWebhookUrlPolicyCreation(
  input: Omit<WebhookUrlPolicyVersionInput, "version">,
): WebhookUrlPolicyPlan {
  const next = createWebhookUrlPolicyVersion({ ...input, version: 1 });
  return Object.freeze({ expectedVersion: 0, next });
}

export function planWebhookUrlPolicyReplacement(
  current: WebhookUrlPolicyVersion,
  input: WebhookUrlPolicyReplacementInput,
): WebhookUrlPolicyPlan {
  if (!authenticPolicies.has(current)) invalidPolicy();
  const expectedVersion = requireInteger(
    input.expectedVersion,
    "webhook URL policy expected version",
    1,
    maximumPolicyVersion,
  );
  if (
    expectedVersion !== current.version ||
    current.version === maximumPolicyVersion
  ) {
    throw new NotificationValidationError(
      "webhook URL policy revision conflict",
    );
  }
  if (input.versionId === current.versionId) invalidPolicy();
  const next = createWebhookUrlPolicyVersion({
    id: current.id,
    versionId: input.versionId,
    tenantId: current.tenantId,
    version: current.version + 1,
    rules: input.rules,
    publishedByMembershipId: input.publishedByMembershipId,
    publishedAt: input.publishedAt,
  });
  if (Date.parse(next.publishedAt) < Date.parse(current.publishedAt)) {
    invalidPolicy();
  }
  if (next.semanticDigest === current.semanticDigest) {
    throw new NotificationValidationError(
      "webhook URL policy replacement has no change",
    );
  }
  return Object.freeze({ expectedVersion, next });
}

export function isAuthenticWebhookUrlPolicyVersion(
  value: WebhookUrlPolicyVersion,
): boolean {
  return authenticPolicies.has(value);
}

export function canonicalWebhookEndpoint(
  input: string,
): CanonicalWebhookEndpoint {
  if (
    typeof input !== "string" ||
    input.length === 0 ||
    Buffer.byteLength(input, "utf8") > maximumUrlBytes ||
    input !== input.normalize("NFC") ||
    input.trim() !== input ||
    hasForbiddenCodePoint(input) ||
    input.includes("\\") ||
    input.includes("%") ||
    input.includes("#")
  ) {
    invalidEndpoint();
  }

  const separator = input.indexOf("://");
  if (separator < 0 || input.slice(0, separator).toLowerCase() !== "https") {
    invalidEndpoint();
  }
  const authorityStart = separator + 3;
  const authorityEnd = firstDelimiter(input, authorityStart);
  const authority = input.slice(authorityStart, authorityEnd);
  if (
    authority.length === 0 ||
    authority.includes("@") ||
    authority.includes("%") ||
    authority.includes("[") ||
    authority.includes("]")
  ) {
    invalidEndpoint();
  }

  const { rawHostname, port } = splitAuthority(authority);
  const hostname = canonicalPolicyHostname(rawHostname);
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return invalidEndpoint();
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    parsed.hostname.toLowerCase() !== hostname ||
    canonicalUrlPort(parsed) !== port ||
    parsed.pathname.length > 1_024 ||
    parsed.search.length > 1_024
  ) {
    invalidEndpoint();
  }

  const suffix = `${parsed.pathname}${parsed.search}`;
  const rawSuffix = input.slice(authorityEnd);
  if (
    !safeUrlSuffixPattern.test(suffix) ||
    parsed.href.includes("%") ||
    hasDotPathSegment(rawSuffix)
  ) {
    invalidEndpoint();
  }
  const url = `https://${hostname}${port === 443 ? "" : `:${port}`}${suffix}`;
  const endpoint = Object.freeze({
    url,
    hostname,
    port,
    digest: digest(["periapsis.webhook-endpoint.v1", url]),
  });
  authenticEndpoints.add(endpoint);
  return endpoint;
}

export function evaluateWebhookUrlPolicy(
  policy: WebhookUrlPolicyVersion,
  endpointInput: string | CanonicalWebhookEndpoint,
): WebhookUrlPolicyDecisionEvidence {
  if (!authenticPolicies.has(policy)) invalidPolicy();
  const endpoint =
    typeof endpointInput === "string"
      ? canonicalWebhookEndpoint(endpointInput)
      : endpointInput;
  if (!authenticEndpoints.has(endpoint)) invalidEndpoint();

  const denied = policy.rules.find(
    (rule) => rule.effect === "deny" && ruleMatchesEndpoint(rule, endpoint),
  );
  if (denied !== undefined) {
    return evidence(policy, endpoint, false, "denied_by_rule", denied.digest);
  }
  const allowed = policy.rules.find(
    (rule) => rule.effect === "allow" && ruleMatchesEndpoint(rule, endpoint),
  );
  return allowed === undefined
    ? evidence(policy, endpoint, false, "default_deny")
    : evidence(policy, endpoint, true, "allowed_by_rule", allowed.digest);
}

export function createWebhookConfigurationPolicyPin(
  policy: WebhookUrlPolicyVersion,
  input: WebhookConfigurationPolicyPinInput,
): WebhookConfigurationPolicyPin {
  if (!authenticPolicies.has(policy)) invalidPolicy();
  requireUuidV7(input.configurationId, "webhook configuration id");
  requireUuidV7(input.tenantId, "webhook configuration tenant id");
  requireInteger(
    input.configurationVersion,
    "webhook configuration version",
    1,
    maximumPolicyVersion,
  );
  if (input.tenantId !== policy.tenantId) {
    throw new NotificationValidationError(
      "webhook URL policy tenant boundary violation",
    );
  }
  const endpoint = canonicalWebhookEndpoint(input.endpointUrl);
  const decision = evaluateWebhookUrlPolicy(policy, endpoint);
  if (!decision.allowed) {
    throw new WebhookUrlPolicyEnforcementError(decision);
  }
  const pin = Object.freeze({
    configurationId: input.configurationId,
    configurationVersion: input.configurationVersion,
    tenantId: input.tenantId,
    endpointUrl: endpoint.url,
    endpointDigest: endpoint.digest,
    policyId: policy.id,
    policyVersionId: policy.versionId,
    policyVersion: policy.version,
    policyDigest: policy.digest,
    decision,
  });
  authenticConfigurationPins.add(pin);
  return pin;
}

export function createWebhookDeliveryPolicyPin(
  configuration: WebhookConfigurationPolicyPin,
  input: WebhookDeliveryPolicyPinInput,
): WebhookDeliveryPolicyPin {
  if (!authenticConfigurationPins.has(configuration)) invalidPin();
  requireUuidV7(input.deliveryId, "webhook delivery id");
  requireUuidV7(input.configurationId, "webhook configuration id");
  requireUuidV7(input.tenantId, "webhook delivery tenant id");
  requireInteger(
    input.configurationVersion,
    "webhook configuration version",
    1,
    maximumPolicyVersion,
  );
  const endpoint = canonicalWebhookEndpoint(input.endpointUrl);
  if (
    input.configurationId !== configuration.configurationId ||
    input.configurationVersion !== configuration.configurationVersion ||
    input.tenantId !== configuration.tenantId ||
    endpoint.url !== configuration.endpointUrl ||
    endpoint.digest !== configuration.endpointDigest
  ) {
    invalidPin();
  }
  const pin = Object.freeze({
    deliveryId: input.deliveryId,
    configurationId: input.configurationId,
    configurationVersion: input.configurationVersion,
    tenantId: input.tenantId,
    endpointUrl: endpoint.url,
    endpointDigest: endpoint.digest,
    policyId: configuration.policyId,
    policyVersionId: configuration.policyVersionId,
    policyVersion: configuration.policyVersion,
    policyDigest: configuration.policyDigest,
  });
  authenticDeliveryPins.add(pin);
  return pin;
}

export function createWebhookLocalDevelopmentPin(
  input: WebhookLocalDevelopmentPinInput,
  options: { readonly allowPlainLocal: boolean },
): WebhookLocalDevelopmentPin {
  if (!options.allowPlainLocal) invalidPin();
  requireUuidV7(input.deliveryId, "webhook delivery id");
  requireUuidV7(input.configurationId, "webhook configuration id");
  requireUuidV7(input.tenantId, "webhook delivery tenant id");
  requireInteger(
    input.configurationVersion,
    "webhook configuration version",
    1,
    maximumPolicyVersion,
  );
  const endpoint = canonicalLocalWebhookEndpoint(input.endpointUrl);
  const pin = Object.freeze({
    deliveryId: input.deliveryId,
    configurationId: input.configurationId,
    configurationVersion: input.configurationVersion,
    tenantId: input.tenantId,
    endpointUrl: endpoint.url,
    endpointDigest: endpoint.digest,
    localDevelopmentExemption: true as const,
  });
  authenticLocalDevelopmentPins.add(pin);
  return pin;
}

export function isAuthenticWebhookDeliveryEgressPin(
  pin: WebhookDeliveryEgressPin,
): boolean {
  return isAuthenticPolicyPin(pin) || isAuthenticLocalDevelopmentPin(pin);
}

function isAuthenticLocalDevelopmentPin(
  pin: WebhookDeliveryEgressPin,
): pin is WebhookLocalDevelopmentPin {
  return (
    "localDevelopmentExemption" in pin &&
    pin.localDevelopmentExemption &&
    authenticLocalDevelopmentPins.has(pin)
  );
}

function isAuthenticPolicyPin(
  pin: WebhookDeliveryEgressPin,
): pin is WebhookDeliveryPolicyPin {
  return (
    !("localDevelopmentExemption" in pin) && authenticDeliveryPins.has(pin)
  );
}

export class LiveWebhookUrlPolicyGate {
  readonly #loadCurrent: LiveWebhookUrlPolicySource["loadCurrent"];
  readonly #loadLocalDevelopmentAuthorization:
    | NonNullable<
        LiveWebhookUrlPolicySource["loadLocalDevelopmentAuthorization"]
      >
    | undefined;
  readonly #connect: WebhookPolicyTcpConnector["connect"];
  readonly #allowPlainLocal: boolean;

  constructor(
    source: LiveWebhookUrlPolicySource,
    connector: WebhookPolicyTcpConnector,
    options: { readonly allowPlainLocal?: boolean } = {},
  ) {
    if (
      source === null ||
      source === undefined ||
      typeof source.loadCurrent !== "function" ||
      (options.allowPlainLocal === true &&
        typeof source.loadLocalDevelopmentAuthorization !== "function") ||
      connector === null ||
      connector === undefined ||
      typeof connector.connect !== "function"
    ) {
      throw new NotificationValidationError(
        "webhook URL policy gate dependencies are invalid",
      );
    }
    this.#loadCurrent = source.loadCurrent.bind(source);
    this.#loadLocalDevelopmentAuthorization =
      source.loadLocalDevelopmentAuthorization?.bind(source);
    this.#connect = connector.connect.bind(connector);
    this.#allowPlainLocal = options.allowPlainLocal === true;
  }

  async beginAttempt(
    pin: WebhookDeliveryEgressPin,
    signal: AbortSignal,
  ): Promise<WebhookUrlPolicyAttemptPermit> {
    requireAbortSignal(signal);
    signal.throwIfAborted();
    if (isAuthenticLocalDevelopmentPin(pin)) {
      if (!this.#allowPlainLocal) invalidPin();
      const endpoint = canonicalLocalWebhookEndpoint(pin.endpointUrl);
      if (endpoint.digest !== pin.endpointDigest) invalidPin();
      const attemptEvidence = await this.#revalidateLocal(
        pin,
        endpoint,
        "attempt",
        signal,
      );
      const permit = Object.freeze({ attemptEvidence });
      permitStates.set(
        permit,
        Object.freeze({ kind: "local", pin, endpoint, gate: this }),
      );
      return permit;
    }
    if (!isAuthenticPolicyPin(pin)) invalidPin();
    const endpoint = canonicalWebhookEndpoint(pin.endpointUrl);
    if (endpoint.digest !== pin.endpointDigest) invalidPin();
    const attemptEvidence = await this.#revalidate(
      pin,
      endpoint,
      "attempt",
      signal,
    );
    const permit = Object.freeze({ attemptEvidence });
    permitStates.set(
      permit,
      Object.freeze({ kind: "policy", pin, endpoint, gate: this }),
    );
    return permit;
  }

  async connect(
    permit: WebhookUrlPolicyAttemptPermit,
    target: {
      readonly host: string;
      readonly port: number;
      readonly timeoutMs: number;
      readonly signal?: AbortSignal;
    },
  ): Promise<WebhookUrlPolicyConnection> {
    const state = permitStates.get(permit);
    if (state === undefined || state.gate !== this) invalidPermit();
    // Consume before the first await so concurrent or repeated use cannot open
    // more than one socket under a single attempt decision.
    permitStates.delete(permit);

    const signal = target.signal ?? new AbortController().signal;
    requireAbortSignal(signal);
    signal.throwIfAborted();
    const timeoutMs = requireInteger(
      target.timeoutMs,
      "webhook connection timeout",
      100,
      120_000,
    );
    const local = state.kind === "local";
    let targetHost: string;
    try {
      targetHost = local
        ? canonicalLocalTargetHost(target.host)
        : canonicalPolicyHostname(target.host);
    } catch {
      if (local) invalidPin();
      throw new WebhookUrlPolicyEnforcementError(
        pinEvidence(state.pin, false, "target_mismatch"),
      );
    }
    if (
      targetHost !== state.endpoint.hostname ||
      target.port !== state.endpoint.port
    ) {
      if (local) invalidPin();
      throw new WebhookUrlPolicyEnforcementError(
        pinEvidence(state.pin, false, "target_mismatch"),
      );
    }

    const connectEvidence = local
      ? await this.#revalidateLocal(
          state.pin,
          state.endpoint,
          "connect",
          signal,
        )
      : await this.#revalidate(state.pin, state.endpoint, "connect", signal);
    signal.throwIfAborted();
    // There is intentionally no asynchronous step between the live policy
    // decision and invocation of the DNS/IP-pinning connector.
    let socket: Socket;
    try {
      socket = await this.#connect({
        host: state.endpoint.hostname,
        port: state.endpoint.port,
        timeoutMs,
        ...(local ? { requireLoopbackTarget: true } : {}),
        signal,
      });
    } catch (error) {
      signal.throwIfAborted();
      if (error instanceof DeliveryProviderError) throw error;
      throw new DeliveryProviderError("connectivity", "safe");
    }
    return Object.freeze({ socket, connectEvidence });
  }

  async #revalidateLocal(
    pin: WebhookLocalDevelopmentPin,
    endpoint: CanonicalLocalWebhookEndpoint,
    phase: "attempt" | "connect",
    signal: AbortSignal,
  ): Promise<WebhookLocalDevelopmentEvidence> {
    if (
      !this.#allowPlainLocal ||
      this.#loadLocalDevelopmentAuthorization === undefined ||
      !authenticLocalDevelopmentPins.has(pin) ||
      canonicalLocalWebhookEndpoint(pin.endpointUrl).digest !==
        endpoint.digest ||
      pin.endpointDigest !== endpoint.digest
    ) {
      invalidPin();
    }
    let authorized: unknown;
    try {
      authorized = await this.#loadLocalDevelopmentAuthorization({
        tenantId: pin.tenantId,
        phase,
        signal,
      });
    } catch {
      signal.throwIfAborted();
      throw new DeliveryProviderError("connectivity", "safe");
    }
    signal.throwIfAborted();
    if (authorized !== true) invalidPin();
    return localDevelopmentEvidence(endpoint);
  }

  async #revalidate(
    pin: WebhookDeliveryPolicyPin,
    endpoint: CanonicalWebhookEndpoint,
    phase: "attempt" | "connect",
    signal: AbortSignal,
  ): Promise<WebhookUrlPolicyDecisionEvidence> {
    let current: WebhookUrlPolicyVersion | null;
    try {
      current = await this.#loadCurrent(
        Object.freeze({
          tenantId: pin.tenantId,
          policyId: pin.policyId,
          phase,
          signal,
        }),
      );
    } catch {
      signal.throwIfAborted();
      throw new WebhookUrlPolicyEnforcementError(
        pinEvidence(pin, false, "policy_unavailable"),
      );
    }
    signal.throwIfAborted();
    if (
      current === null ||
      !authenticPolicies.has(current) ||
      current.tenantId !== pin.tenantId ||
      current.id !== pin.policyId ||
      current.versionId !== pin.policyVersionId ||
      current.version !== pin.policyVersion ||
      current.digest !== pin.policyDigest ||
      !digestPattern.test(current.digest)
    ) {
      throw new WebhookUrlPolicyEnforcementError(
        pinEvidence(pin, false, "policy_pin_mismatch"),
      );
    }
    const decision = evaluateWebhookUrlPolicy(current, endpoint);
    if (!decision.allowed) {
      throw new WebhookUrlPolicyEnforcementError(decision);
    }
    return decision;
  }
}

function canonicalLocalWebhookEndpoint(
  input: string,
): CanonicalLocalWebhookEndpoint {
  if (
    typeof input !== "string" ||
    input.length === 0 ||
    Buffer.byteLength(input, "utf8") > maximumUrlBytes ||
    input !== input.normalize("NFC") ||
    input.trim() !== input ||
    hasForbiddenCodePoint(input) ||
    input.includes("\\") ||
    input.includes("%") ||
    input.includes("#")
  ) {
    invalidEndpoint();
  }
  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return invalidEndpoint();
  }
  const hostname = canonicalLocalTargetHost(parsed.hostname);
  const port = parsed.port === "" ? 80 : Number(parsed.port);
  const suffix = `${parsed.pathname}${parsed.search}`;
  if (
    parsed.protocol !== "http:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.hash !== "" ||
    !Number.isInteger(port) ||
    port < 1 ||
    port > 65_535 ||
    parsed.pathname.length > 1_024 ||
    parsed.search.length > 1_024 ||
    !safeUrlSuffixPattern.test(suffix) ||
    hasDotPathSegment(`${parsed.pathname}${parsed.search}`)
  ) {
    invalidEndpoint();
  }
  const authority = hostname === "::1" ? "[::1]" : hostname;
  const url = `http://${authority}${port === 80 ? "" : `:${port}`}${suffix}`;
  return Object.freeze({
    url,
    hostname,
    port,
    digest: digest(["periapsis.webhook-endpoint.v1", url]),
  });
}

function canonicalLocalTargetHost(
  input: string,
): "localhost" | "127.0.0.1" | "::1" {
  const normalized = input.toLowerCase();
  const hostname =
    normalized.startsWith("[") && normalized.endsWith("]")
      ? normalized.slice(1, -1)
      : normalized;
  if (
    hostname !== "localhost" &&
    hostname !== "127.0.0.1" &&
    hostname !== "::1"
  ) {
    invalidEndpoint();
  }
  return hostname;
}

function localDevelopmentEvidence(
  endpoint: CanonicalLocalWebhookEndpoint,
): WebhookLocalDevelopmentEvidence {
  return Object.freeze({
    allowed: true,
    reason: "local_development_exemption",
    endpointDigest: endpoint.digest,
  });
}

function canonicalRules(
  inputs: readonly WebhookUrlPolicyRuleInput[],
): readonly WebhookUrlPolicyRule[] {
  if (!Array.isArray(inputs) || inputs.length > maximumRules) invalidPolicy();
  const rules: WebhookUrlPolicyRule[] = [];
  for (let index = 0; index < inputs.length; index += 1) {
    const input = inputs[index];
    if (
      input === undefined ||
      (input.effect !== "allow" && input.effect !== "deny") ||
      (input.match !== "exact" && input.match !== "subdomains")
    ) {
      invalidPolicy();
    }
    const hostname = canonicalPolicyHostname(input.hostname);
    const port = requireInteger(
      input.port ?? 443,
      "webhook URL policy port",
      1,
      65_535,
    );
    const canonical = [input.effect, input.match, hostname, String(port)];
    rules.push(
      Object.freeze({
        effect: input.effect,
        match: input.match,
        hostname,
        port,
        digest: digest(["periapsis.webhook-url-policy-rule.v1", ...canonical]),
      }),
    );
  }
  rules.sort(compareRules);
  for (let index = 1; index < rules.length; index += 1) {
    if (
      canonicalRuleRecord(rules[index]!) ===
      canonicalRuleRecord(rules[index - 1]!)
    ) {
      invalidPolicy();
    }
  }
  return Object.freeze(rules);
}

function canonicalPolicyHostname(input: string): string {
  if (
    typeof input !== "string" ||
    input.length === 0 ||
    Buffer.byteLength(input, "utf8") > 253 ||
    input !== input.normalize("NFC") ||
    input.trim() !== input ||
    hasForbiddenCodePoint(input) ||
    ["%", "@", "[", "]", "/", ":", "\\", "*"].some((character) =>
      input.includes(character),
    ) ||
    input.endsWith(".")
  ) {
    return invalidHostname();
  }
  let hostname: string;
  try {
    hostname = domainToASCII(input).toLowerCase();
  } catch {
    return invalidHostname();
  }
  if (
    hostname.length === 0 ||
    hostname.length > 253 ||
    hostname.endsWith(".") ||
    hostname.split(".").length < 2 ||
    hostname.endsWith(".localhost") ||
    isIP(hostname) !== 0 ||
    !hostname.split(".").every(validDomainLabel)
  ) {
    return invalidHostname();
  }
  let parsed: URL;
  try {
    parsed = new URL(`https://${input}/`);
  } catch {
    return invalidHostname();
  }
  if (
    parsed.hostname.toLowerCase() !== hostname ||
    isIP(parsed.hostname) !== 0
  ) {
    return invalidHostname();
  }
  return hostname;
}

function splitAuthority(authority: string): {
  rawHostname: string;
  port: number;
} {
  const firstColon = authority.indexOf(":");
  const lastColon = authority.lastIndexOf(":");
  if (firstColon !== lastColon) invalidEndpoint();
  if (lastColon < 0) return { rawHostname: authority, port: 443 };
  const rawHostname = authority.slice(0, lastColon);
  const rawPort = authority.slice(lastColon + 1);
  if (!/^[1-9][0-9]{0,4}$/u.test(rawPort)) invalidEndpoint();
  const port = Number(rawPort);
  if (port < 1 || port > 65_535 || rawPort !== String(port)) invalidEndpoint();
  return { rawHostname, port };
}

function canonicalUrlPort(endpoint: URL): number {
  if (endpoint.port === "") return 443;
  const port = Number(endpoint.port);
  return Number.isSafeInteger(port) ? port : 0;
}

function firstDelimiter(input: string, start: number): number {
  let result = input.length;
  for (const delimiter of ["/", "?", "#"]) {
    const index = input.indexOf(delimiter, start);
    if (index >= 0 && index < result) result = index;
  }
  return result;
}

function hasDotPathSegment(rawSuffix: string): boolean {
  const rawPath = rawSuffix.split("?", 1)[0] ?? "";
  return rawPath
    .split("/")
    .some((segment) => segment === "." || segment === "..");
}

function validDomainLabel(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= 63 &&
    /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(value)
  );
}

function ruleMatchesEndpoint(
  rule: WebhookUrlPolicyRule,
  endpoint: CanonicalWebhookEndpoint,
): boolean {
  if (rule.port !== endpoint.port) return false;
  return rule.match === "exact"
    ? endpoint.hostname === rule.hostname
    : endpoint.hostname !== rule.hostname &&
        endpoint.hostname.endsWith(`.${rule.hostname}`);
}

function compareRules(
  left: WebhookUrlPolicyRule,
  right: WebhookUrlPolicyRule,
): number {
  const leftRecord = canonicalRuleRecord(left);
  const rightRecord = canonicalRuleRecord(right);
  return leftRecord < rightRecord ? -1 : leftRecord > rightRecord ? 1 : 0;
}

function canonicalRuleRecord(rule: WebhookUrlPolicyRule): string {
  return `${rule.effect}\u0000${rule.match}\u0000${rule.hostname}\u0000${rule.port}`;
}

function evidence(
  policy: WebhookUrlPolicyVersion,
  endpoint: CanonicalWebhookEndpoint,
  allowed: boolean,
  reason: WebhookUrlPolicyDecisionReason,
  matchedRuleDigest?: string,
): WebhookUrlPolicyDecisionEvidence {
  return Object.freeze({
    allowed,
    reason,
    policyId: policy.id,
    policyVersion: policy.version,
    policyDigest: policy.digest,
    endpointDigest: endpoint.digest,
    ...(matchedRuleDigest === undefined ? {} : { matchedRuleDigest }),
  });
}

function pinEvidence(
  pin: WebhookDeliveryPolicyPin,
  allowed: boolean,
  reason: WebhookUrlPolicyDecisionReason,
): WebhookUrlPolicyDecisionEvidence {
  return Object.freeze({
    allowed,
    reason,
    policyId: pin.policyId,
    policyVersion: pin.policyVersion,
    policyDigest: pin.policyDigest,
    endpointDigest: pin.endpointDigest,
  });
}

function digest(parts: readonly string[]): string {
  const hash = createHash("sha256");
  for (const part of parts) {
    const bytes = Buffer.from(part, "utf8");
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(bytes.byteLength);
    hash.update(length);
    hash.update(bytes);
  }
  return hash.digest("hex");
}

function hasForbiddenCodePoint(value: string): boolean {
  return /[\p{Cc}\p{Cf}\p{Cs}]/u.test(value);
}

function requireAbortSignal(signal: AbortSignal): void {
  if (
    signal === null ||
    signal === undefined ||
    typeof signal.throwIfAborted !== "function"
  ) {
    throw new NotificationValidationError(
      "webhook URL policy signal is invalid",
    );
  }
}

function invalidPolicy(): never {
  throw new NotificationValidationError("webhook URL policy is invalid");
}

function invalidHostname(): never {
  throw new NotificationValidationError(
    "webhook URL policy hostname is invalid",
  );
}

function invalidEndpoint(): never {
  throw new NotificationValidationError("webhook endpoint URL is invalid");
}

function invalidPin(): never {
  throw new NotificationValidationError("webhook URL policy pin is invalid");
}

function invalidPermit(): never {
  throw new NotificationValidationError(
    "webhook URL policy attempt permit is invalid",
  );
}
