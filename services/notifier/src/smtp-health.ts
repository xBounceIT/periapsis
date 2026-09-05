import {
  DeliveryProviderError,
  NotificationConfigurationError,
  NotificationValidationError,
} from "./errors.js";
import {
  isAuthenticSmtpConfiguration,
  NodemailerSmtpProvider,
  type ProviderHealth,
  type SecretResolver,
  type SmtpConfiguration,
  type SmtpSocketConnector,
} from "./smtp.js";
import { requireInteger, requireUuidV7 } from "./validation.js";

export type SmtpHealthCheckKind = "dns" | "connect" | "tls" | "authentication";

export type SmtpHealthErrorClass =
  | "authentication"
  | "connectivity"
  | "tls"
  | "timeout"
  | "security"
  | "unknown";

export interface SmtpHealthCheck {
  readonly kind: SmtpHealthCheckKind;
  readonly outcome: "passed" | "failed" | "skipped";
  readonly errorClass?: SmtpHealthErrorClass;
}

export interface SmtpHealthProbeRequest {
  readonly probeId: string;
  readonly fenceToken: string;
  readonly tenantId?: string;
  readonly configurationScope: "tenant" | "platform";
  readonly configurationId: string;
  readonly configurationVersion: number;
}

export interface SmtpHealthProbeResult extends SmtpHealthProbeRequest {
  readonly healthy: boolean;
  readonly checkedAt: Date;
  readonly checks: readonly SmtpHealthCheck[];
}

export interface SmtpHealthConfigurationRepository {
  loadPinnedForProbe(
    tenantId: string | undefined,
    pin: Readonly<{
      scope: "tenant" | "platform";
      id: string;
      version: number;
    }>,
    signal: AbortSignal,
  ): Promise<SmtpConfiguration | null>;
}

export interface SmtpHealthProber {
  probe(input: unknown, signal: AbortSignal): Promise<SmtpHealthProbeResult>;
}

/**
 * Runs one bounded health check with an ephemeral provider. Health probes do
 * not share the delivery provider cache, so aborting or closing a probe cannot
 * affect an in-flight delivery and decrypted provider state is not retained.
 */
export class ExactPinnedSmtpHealthProbe implements SmtpHealthProber {
  readonly #repository: SmtpHealthConfigurationRepository;
  readonly #secrets: SecretResolver;
  readonly #connector: SmtpSocketConnector;

  constructor(dependencies: {
    repository: SmtpHealthConfigurationRepository;
    secrets: SecretResolver;
    connector: SmtpSocketConnector;
  }) {
    if (
      dependencies.repository === null ||
      typeof dependencies.repository !== "object" ||
      typeof dependencies.repository.loadPinnedForProbe !== "function" ||
      dependencies.secrets === null ||
      typeof dependencies.secrets !== "object" ||
      typeof dependencies.secrets.read !== "function" ||
      dependencies.connector === null ||
      typeof dependencies.connector !== "object" ||
      typeof dependencies.connector.connect !== "function"
    ) {
      throw new NotificationConfigurationError();
    }
    this.#repository = dependencies.repository;
    this.#secrets = dependencies.secrets;
    this.#connector = dependencies.connector;
  }

  async probe(
    input: unknown,
    signal: AbortSignal,
  ): Promise<SmtpHealthProbeResult> {
    const request = parseProbeRequest(input);
    signal.throwIfAborted();
    let provider: NodemailerSmtpProvider | undefined;
    try {
      const configuration = await this.#repository.loadPinnedForProbe(
        request.tenantId,
        {
          scope: request.configurationScope,
          id: request.configurationId,
          version: request.configurationVersion,
        },
        signal,
      );
      signal.throwIfAborted();
      if (!exactConfigurationMatches(request, configuration)) {
        return failedResult(request, "security", new Date());
      }
      provider = await NodemailerSmtpProvider.create(
        configuration,
        this.#secrets,
        this.#connector,
        signal,
      );
      const health = await provider.health(signal);
      return healthResult(request, configuration, health);
    } catch (error) {
      signal.throwIfAborted();
      return failedResult(request, safeErrorClass(error), new Date());
    } finally {
      provider?.close();
    }
  }
}

function parseProbeRequest(input: unknown): SmtpHealthProbeRequest {
  if (!isPlainRecord(input)) {
    throw new NotificationValidationError(
      "SMTP health request must be an object",
    );
  }
  const expected = new Set([
    "probeId",
    "fenceToken",
    "tenantId",
    "configurationScope",
    "configurationId",
    "configurationVersion",
  ]);
  if (Object.keys(input).some((key) => !expected.has(key))) {
    throw new NotificationValidationError(
      "SMTP health request contains unknown fields",
    );
  }
  const probeId = uuid(input.probeId, "SMTP health probeId");
  const fenceToken = uuid(input.fenceToken, "SMTP health fenceToken");
  const configurationId = uuid(
    input.configurationId,
    "SMTP health configurationId",
  );
  const configurationScope = input.configurationScope;
  if (configurationScope !== "tenant" && configurationScope !== "platform") {
    throw new NotificationValidationError(
      "SMTP health configuration scope is unsupported",
    );
  }
  const tenantId =
    input.tenantId === undefined
      ? undefined
      : uuid(input.tenantId, "SMTP health tenantId");
  if (configurationScope === "tenant" && tenantId === undefined) {
    throw new NotificationValidationError(
      "SMTP health tenant scope is inconsistent",
    );
  }
  if (typeof input.configurationVersion !== "number") {
    throw new NotificationValidationError(
      "SMTP health configurationVersion must be an integer",
    );
  }
  const configurationVersion = requireInteger(
    input.configurationVersion,
    "SMTP health configurationVersion",
    1,
    2_147_483_647,
  );
  return Object.freeze({
    probeId,
    fenceToken,
    ...(tenantId === undefined ? {} : { tenantId }),
    configurationScope,
    configurationId,
    configurationVersion,
  });
}

function exactConfigurationMatches(
  request: SmtpHealthProbeRequest,
  configuration: SmtpConfiguration | null,
): configuration is SmtpConfiguration {
  return (
    configuration !== null &&
    isAuthenticSmtpConfiguration(configuration) &&
    configuration.enabled &&
    configuration.id === request.configurationId &&
    configuration.version === request.configurationVersion &&
    (request.configurationScope === "tenant"
      ? configuration.tenantId === request.tenantId
      : configuration.tenantId === undefined)
  );
}

function healthResult(
  request: SmtpHealthProbeRequest,
  configuration: SmtpConfiguration,
  health: ProviderHealth,
): SmtpHealthProbeResult {
  if (!health.healthy) {
    return failedResult(
      request,
      health.errorClass ?? "unknown",
      health.checkedAt,
    );
  }
  const checks: SmtpHealthCheck[] = [
    { kind: "dns", outcome: "passed" },
    { kind: "connect", outcome: "passed" },
  ];
  if (configuration.security !== "plain_local") {
    checks.push({ kind: "tls", outcome: "passed" });
  }
  if (configuration.username !== undefined) {
    checks.push({ kind: "authentication", outcome: "passed" });
  }
  return Object.freeze({
    ...request,
    healthy: true,
    checkedAt: new Date(health.checkedAt.getTime()),
    checks: Object.freeze(checks.map((check) => Object.freeze(check))),
  });
}

function failedResult(
  request: SmtpHealthProbeRequest,
  errorClass: SmtpHealthErrorClass,
  checkedAt: Date,
): SmtpHealthProbeResult {
  const kind: SmtpHealthCheckKind =
    errorClass === "authentication"
      ? "authentication"
      : errorClass === "tls"
        ? "tls"
        : errorClass === "security"
          ? "dns"
          : "connect";
  return Object.freeze({
    ...request,
    healthy: false,
    checkedAt: new Date(checkedAt.getTime()),
    checks: Object.freeze([
      Object.freeze({ kind, outcome: "failed" as const, errorClass }),
    ]),
  });
}

function safeErrorClass(error: unknown): SmtpHealthErrorClass {
  if (error instanceof DeliveryProviderError) {
    switch (error.failureClass) {
      case "authentication":
      case "connectivity":
      case "security":
      case "timeout":
      case "tls":
      case "unknown":
        return error.failureClass;
      default:
        return "unknown";
    }
  }
  if (
    error instanceof NotificationConfigurationError ||
    error instanceof NotificationValidationError
  ) {
    return "security";
  }
  return "unknown";
}

function uuid(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new NotificationValidationError(`${field} must be a string`);
  }
  return requireUuidV7(value, field);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    (Object.getPrototypeOf(value) === Object.prototype ||
      Object.getPrototypeOf(value) === null)
  );
}
