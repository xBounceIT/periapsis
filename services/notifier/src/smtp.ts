import { createHash } from "node:crypto";
import { isIP, type Socket } from "node:net";
import { domainToASCII } from "node:url";

import nodemailer, { type Transporter } from "nodemailer";
import type SMTPPool from "nodemailer/lib/smtp-pool/index.js";

import {
  DeliveryProviderError,
  NotificationTenantBoundaryError,
  NotificationValidationError,
  type DeliveryFailureClass,
} from "./errors.js";
import {
  isAuthenticNotificationProtectedSecret,
  type NotificationProtectedSecret,
} from "./keyring.js";
import {
  canonicalEmail,
  requireInteger,
  requireKey,
  requireText,
  requireUuidV7,
} from "./validation.js";

export type SmtpSecurityMode = "tls" | "starttls" | "plain_local";

export interface SmtpConfigurationInput {
  id: string;
  tenantId?: string;
  name: string;
  host: string;
  port: number;
  security: SmtpSecurityMode;
  username?: string;
  passwordSecret?: NotificationProtectedSecret;
  fromName: string;
  fromEmail: string;
  replyToEmail?: string;
  timeoutMs: number;
  maximumConnections: number;
  maximumMessagesPerConnection: number;
  rateLimitPerSecond: number;
  dkim?: {
    domainName: string;
    selector: string;
    privateKeySecret: NotificationProtectedSecret;
  };
  enabled: boolean;
  version: number;
}

export interface SmtpConfiguration {
  readonly id: string;
  readonly tenantId?: string;
  readonly name: string;
  readonly host: string;
  readonly port: number;
  readonly security: SmtpSecurityMode;
  readonly username?: string;
  readonly passwordSecret?: NotificationProtectedSecret;
  readonly fromName: string;
  readonly fromEmail: string;
  readonly replyToEmail?: string;
  readonly timeoutMs: number;
  readonly maximumConnections: number;
  readonly maximumMessagesPerConnection: number;
  readonly rateLimitPerSecond: number;
  readonly dkim?: Readonly<{
    domainName: string;
    selector: string;
    privateKeySecret: NotificationProtectedSecret;
  }>;
  readonly enabled: boolean;
  readonly version: number;
}

export interface SecretResolver {
  read(
    secret: NotificationProtectedSecret,
    signal: AbortSignal,
  ): Promise<Uint8Array>;
}

export interface SmtpSocketConnector {
  connect(configuration: SmtpConfiguration): Promise<Socket>;
}

export interface EmailDeliveryInput {
  tenantId: string;
  recipient: string;
  subject: string;
  html: string;
  plainText: string;
  headers?: Readonly<Record<string, string>>;
}

export interface SanitizedProviderResponse {
  readonly provider: "smtp";
  readonly receiptDigest: string;
  readonly acceptedCount: number;
  readonly rejectedCount: number;
  readonly responseClass?: number;
}

export interface ProviderHealth {
  readonly healthy: boolean;
  readonly checkedAt: Date;
  readonly errorClass?:
    | "authentication"
    | "connectivity"
    | "tls"
    | "timeout"
    | "security"
    | "unknown";
}

const authenticSmtpConfigurations = new WeakSet<SmtpConfiguration>();

export function isAuthenticSmtpConfiguration(
  configuration: SmtpConfiguration,
): boolean {
  return (
    configuration !== null &&
    typeof configuration === "object" &&
    authenticSmtpConfigurations.has(configuration)
  );
}

export function createSmtpConfiguration(
  input: SmtpConfigurationInput,
  options: { allowPlainLocal?: boolean } = {},
): SmtpConfiguration {
  requireUuidV7(input.id, "smtp.id");
  if (input.tenantId !== undefined)
    requireUuidV7(input.tenantId, "smtp.tenantId");
  const name = requireText(input.name, "smtp.name", 160);
  const host = canonicalSmtpHost(input.host);
  requireInteger(input.port, "smtp.port", 1, 65_535);
  if (
    input.security !== "tls" &&
    input.security !== "starttls" &&
    input.security !== "plain_local"
  ) {
    throw new NotificationValidationError("SMTP security mode is unsupported");
  }
  if (input.security === "plain_local" && options.allowPlainLocal !== true) {
    throw new NotificationValidationError(
      "plaintext SMTP requires an explicit local-development opt-in",
    );
  }
  const hasUsername = input.username !== undefined;
  const hasPassword = input.passwordSecret !== undefined;
  if (hasUsername !== hasPassword) {
    throw new NotificationValidationError(
      "SMTP username and password secret must be configured together",
    );
  }
  const username =
    input.username === undefined
      ? undefined
      : requireText(input.username, "smtp.username", 320);
  const passwordSecret =
    input.passwordSecret === undefined
      ? undefined
      : requireScopedSecret(
          input.passwordSecret,
          input.tenantId,
          "smtp_password",
        );
  const fromName = requireText(input.fromName, "smtp.fromName", 160);
  const fromEmail = canonicalEmail(input.fromEmail, "smtp.fromEmail");
  const replyToEmail =
    input.replyToEmail === undefined
      ? undefined
      : canonicalEmail(input.replyToEmail, "smtp.replyToEmail");
  requireInteger(input.timeoutMs, "smtp.timeoutMs", 1_000, 120_000);
  requireInteger(input.maximumConnections, "smtp.maximumConnections", 1, 100);
  requireInteger(
    input.maximumMessagesPerConnection,
    "smtp.maximumMessagesPerConnection",
    1,
    10_000,
  );
  requireInteger(
    input.rateLimitPerSecond,
    "smtp.rateLimitPerSecond",
    1,
    10_000,
  );
  requireInteger(input.version, "smtp.version", 1, 2_147_483_647);
  const dkim =
    input.dkim === undefined
      ? undefined
      : canonicalDkim(input.dkim, input.tenantId);
  const configuration = Object.freeze({
    id: input.id,
    ...(input.tenantId === undefined ? {} : { tenantId: input.tenantId }),
    name,
    host,
    port: input.port,
    security: input.security,
    ...(username === undefined ? {} : { username }),
    ...(passwordSecret === undefined ? {} : { passwordSecret }),
    fromName,
    fromEmail,
    ...(replyToEmail === undefined ? {} : { replyToEmail }),
    timeoutMs: input.timeoutMs,
    maximumConnections: input.maximumConnections,
    maximumMessagesPerConnection: input.maximumMessagesPerConnection,
    rateLimitPerSecond: input.rateLimitPerSecond,
    ...(dkim === undefined ? {} : { dkim }),
    enabled: input.enabled,
    version: input.version,
  });
  authenticSmtpConfigurations.add(configuration);
  return configuration;
}

export function selectSmtpConfiguration(
  tenantId: string,
  globalConfiguration: SmtpConfiguration | undefined,
  tenantConfigurations: readonly SmtpConfiguration[],
): SmtpConfiguration | null {
  requireUuidV7(tenantId, "tenantId");
  if (
    (globalConfiguration !== undefined &&
      !authenticSmtpConfigurations.has(globalConfiguration)) ||
    tenantConfigurations.some(
      (configuration) => !authenticSmtpConfigurations.has(configuration),
    )
  ) {
    throw new NotificationValidationError(
      "SMTP configuration inventory contains a forged aggregate",
    );
  }
  if (globalConfiguration?.tenantId !== undefined) {
    throw new NotificationValidationError(
      "global SMTP configuration is tenant-scoped",
    );
  }
  let selected: SmtpConfiguration | undefined;
  const seenTenants = new Set<string>();
  for (const configuration of tenantConfigurations) {
    if (
      configuration.tenantId === undefined ||
      seenTenants.has(configuration.tenantId)
    ) {
      throw new NotificationValidationError(
        "tenant SMTP configuration inventory is ambiguous",
      );
    }
    seenTenants.add(configuration.tenantId);
    if (configuration.tenantId === tenantId) selected = configuration;
  }
  const resolved = selected ?? globalConfiguration;
  return resolved?.enabled === true ? resolved : null;
}

export class NodemailerSmtpProvider {
  readonly #configuration: SmtpConfiguration;
  readonly #transport: Transporter<SMTPPool.SentMessageInfo, SMTPPool.Options>;
  #closed = false;

  private constructor(
    configuration: SmtpConfiguration,
    transport: Transporter<SMTPPool.SentMessageInfo, SMTPPool.Options>,
  ) {
    this.#configuration = configuration;
    this.#transport = transport;
  }

  static async create(
    configuration: SmtpConfiguration,
    secrets: SecretResolver,
    connector: SmtpSocketConnector,
    signal: AbortSignal,
  ): Promise<NodemailerSmtpProvider> {
    if (
      !authenticSmtpConfigurations.has(configuration) ||
      !configuration.enabled ||
      connector === null ||
      typeof connector !== "object" ||
      typeof connector.connect !== "function"
    ) {
      throw new NotificationValidationError(
        "disabled SMTP configuration cannot create a provider",
      );
    }
    if (signal.aborted) throw signal.reason;
    let passwordBytes: Uint8Array | undefined;
    let dkimBytes: Uint8Array | undefined;
    try {
      passwordBytes =
        configuration.passwordSecret === undefined
          ? undefined
          : await secrets.read(configuration.passwordSecret, signal);
      dkimBytes =
        configuration.dkim === undefined
          ? undefined
          : await secrets.read(configuration.dkim.privateKeySecret, signal);
      if (signal.aborted) throw signal.reason;
      const decoder = new TextDecoder("utf-8", { fatal: true });
      const password =
        passwordBytes === undefined ? undefined : decoder.decode(passwordBytes);
      const privateKey =
        dkimBytes === undefined ? undefined : decoder.decode(dkimBytes);
      if (
        password !== undefined &&
        (password.length === 0 ||
          password.includes(String.fromCodePoint(0)) ||
          password.includes("\r") ||
          password.includes("\n"))
      ) {
        throw new NotificationValidationError(
          "SMTP password secret is invalid",
        );
      }
      if (privateKey !== undefined && !privateKey.includes("PRIVATE KEY")) {
        throw new NotificationValidationError(
          "DKIM private key secret is invalid",
        );
      }
      const options: SMTPPool.Options = {
        host: configuration.host,
        port: configuration.port,
        secure: configuration.security === "tls",
        requireTLS: configuration.security === "starttls",
        ignoreTLS: configuration.security === "plain_local",
        pool: true,
        maxConnections: configuration.maximumConnections,
        maxMessages: configuration.maximumMessagesPerConnection,
        rateDelta: 1_000,
        rateLimit: configuration.rateLimitPerSecond,
        connectionTimeout: configuration.timeoutMs,
        greetingTimeout: configuration.timeoutMs,
        socketTimeout: configuration.timeoutMs,
        disableFileAccess: true,
        disableUrlAccess: true,
        logger: false,
        debug: false,
        getSocket: (_options, callback) => {
          void connector.connect(configuration).then(
            (connection) => callback(null, { connection }),
            (error: unknown) =>
              callback(
                error instanceof Error
                  ? error
                  : new DeliveryProviderError("connectivity", "safe"),
                undefined,
              ),
          );
        },
        tls: {
          minVersion: "TLSv1.2",
          rejectUnauthorized: true,
          servername:
            isIP(configuration.host) === 0 ? configuration.host : undefined,
        },
        ...(configuration.username === undefined
          ? {}
          : { auth: { user: configuration.username, pass: password! } }),
        ...(configuration.dkim === undefined
          ? {}
          : {
              dkim: {
                domainName: configuration.dkim.domainName,
                keySelector: configuration.dkim.selector,
                privateKey: privateKey!,
              },
            }),
      };
      return new NodemailerSmtpProvider(
        configuration,
        nodemailer.createTransport(options),
      );
    } finally {
      passwordBytes?.fill(0);
      dkimBytes?.fill(0);
    }
  }

  async send(
    input: EmailDeliveryInput,
    signal: AbortSignal,
  ): Promise<SanitizedProviderResponse> {
    if (
      input.tenantId !== this.#configuration.tenantId &&
      this.#configuration.tenantId !== undefined
    ) {
      throw new NotificationTenantBoundaryError();
    }
    requireUuidV7(input.tenantId, "delivery.tenantId");
    const recipient = canonicalEmail(input.recipient, "delivery.recipient");
    const subject = requireText(input.subject, "delivery.subject", 998);
    const html = requireText(input.html, "delivery.html", 1024 * 1_024, {
      allowNewlines: true,
    });
    const plainText = requireText(
      input.plainText,
      "delivery.plainText",
      1024 * 1_024,
      {
        allowNewlines: true,
      },
    );
    const headers = canonicalHeaders(input.headers ?? {});
    if (signal.aborted) throw signal.reason;
    let info: SMTPPool.SentMessageInfo;
    try {
      info = await this.#runAbortable(
        () =>
          this.#transport.sendMail({
            from: {
              name: this.#configuration.fromName,
              address: this.#configuration.fromEmail,
            },
            ...(this.#configuration.replyToEmail === undefined
              ? {}
              : { replyTo: this.#configuration.replyToEmail }),
            to: recipient,
            subject,
            html,
            text: plainText,
            headers,
            disableFileAccess: true,
            disableUrlAccess: true,
          }),
        signal,
      );
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      throw classifySmtpDeliveryError(error);
    }
    if (signal.aborted) throw signal.reason;
    if (info.accepted.length !== 1 || info.rejected.length !== 0) {
      throw new DeliveryProviderError("unknown", "terminal");
    }
    const messageId = requireText(
      info.messageId,
      "SMTP receipt message id",
      998,
    );
    const responseCode = /^\s*([245])[0-9]{2}\b/u.exec(info.response)?.[1];
    return Object.freeze({
      provider: "smtp",
      receiptDigest: createHash("sha256").update(messageId).digest("hex"),
      acceptedCount: info.accepted.length,
      rejectedCount: info.rejected.length,
      ...(responseCode === undefined
        ? {}
        : { responseClass: Number(responseCode) }),
    });
  }

  async health(signal: AbortSignal): Promise<ProviderHealth> {
    const checkedAtEpoch = Date.now();
    try {
      if (signal.aborted) throw signal.reason;
      await this.#runAbortable(() => this.#transport.verify(), signal);
      if (signal.aborted) throw signal.reason;
      return Object.freeze({
        healthy: true,
        get checkedAt(): Date {
          return new Date(checkedAtEpoch);
        },
      });
    } catch (error) {
      if (signal.aborted) throw signal.reason;
      return Object.freeze({
        healthy: false,
        get checkedAt(): Date {
          return new Date(checkedAtEpoch);
        },
        errorClass: classifySmtpError(error),
      });
    }
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#transport.close();
  }

  async #runAbortable<T>(
    operation: () => Promise<T>,
    signal: AbortSignal,
  ): Promise<T> {
    if (this.#closed) {
      throw new DeliveryProviderError("connectivity", "safe");
    }
    if (signal.aborted) throw signal.reason;
    return new Promise<T>((resolve, reject) => {
      const onAbort = (): void => {
        this.close();
        reject(signal.reason);
      };
      signal.addEventListener("abort", onAbort, { once: true });
      void operation().then(
        (value) => {
          signal.removeEventListener("abort", onAbort);
          resolve(value);
        },
        (error: unknown) => {
          signal.removeEventListener("abort", onAbort);
          reject(error);
        },
      );
    });
  }
}

function canonicalDkim(
  input: NonNullable<SmtpConfigurationInput["dkim"]>,
  tenantId?: string,
): NonNullable<SmtpConfiguration["dkim"]> {
  const domainName = canonicalSmtpHost(input.domainName);
  const selector = requireKey(input.selector, "smtp.dkim.selector", 63);
  const privateKeySecret = requireScopedSecret(
    input.privateKeySecret,
    tenantId,
    "smtp_dkim_private_key",
  );
  return Object.freeze({ domainName, selector, privateKeySecret });
}

function requireScopedSecret(
  secret: NotificationProtectedSecret,
  tenantId: string | undefined,
  kind: NotificationProtectedSecret["kind"],
): NotificationProtectedSecret {
  if (
    !isAuthenticNotificationProtectedSecret(secret) ||
    secret.tenantId !== tenantId ||
    secret.kind !== kind
  ) {
    throw new NotificationValidationError(
      "protected SMTP secret has an invalid scope or kind",
    );
  }
  return secret;
}

export function canonicalSmtpHost(input: string): string {
  requireText(input, "smtp.host", 253);
  if (input === "localhost" || isIP(input) !== 0) return input.toLowerCase();
  const host = domainToASCII(input).toLowerCase();
  if (
    host.length === 0 ||
    host.length > 253 ||
    !host
      .split(".")
      .every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u.test(label))
  ) {
    throw new NotificationValidationError("smtp.host is invalid");
  }
  return host;
}

function canonicalHeaders(
  input: Readonly<Record<string, string>>,
): Readonly<Record<string, string>> {
  if (Object.keys(input).length > 32) {
    throw new NotificationValidationError("delivery has too many headers");
  }
  const result: Record<string, string> = {};
  const seen = new Set<string>();
  for (const [nameInput, valueInput] of Object.entries(input)) {
    const name = nameInput.toLowerCase();
    if (
      !["message-id", "x-correlation-id", "x-periapsis-delivery-id"].includes(
        name,
      ) ||
      seen.has(name)
    ) {
      throw new NotificationValidationError(
        "delivery header is not allowlisted",
      );
    }
    seen.add(name);
    const value = requireText(valueInput, `delivery header ${name}`, 998);
    if (
      (name === "message-id" &&
        !/^<[0-9a-f]{64}@notifications\.periapsis\.invalid>$/u.test(value)) ||
      (name === "x-periapsis-delivery-id" &&
        !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
          value,
        )) ||
      (name === "x-correlation-id" &&
        !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value))
    ) {
      throw new NotificationValidationError("delivery header value is invalid");
    }
    result[name] = value;
  }
  return Object.freeze(result);
}

function classifySmtpError(
  error: unknown,
): NonNullable<ProviderHealth["errorClass"]> {
  if (error instanceof DeliveryProviderError) {
    switch (error.failureClass) {
      case "authentication":
      case "connectivity":
      case "security":
      case "timeout":
      case "tls":
        return error.failureClass;
      default:
        return "unknown";
    }
  }
  const codeValue = errorProperty(error, "code");
  const code = typeof codeValue === "string" ? codeValue : "";
  if (["EAUTH", "EENVELOPE"].includes(code)) return "authentication";
  if (["ETIMEDOUT", "ESOCKETTIMEDOUT"].includes(code)) return "timeout";
  if (["ETLS", "ECERT", "ESOCKET"].includes(code)) return "tls";
  if (["ECONNECTION", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"].includes(code))
    return "connectivity";
  return "unknown";
}

function classifySmtpDeliveryError(error: unknown): DeliveryProviderError {
  if (error instanceof DeliveryProviderError) return error;
  const codeValue = errorProperty(error, "code");
  const responseCodeValue = errorProperty(error, "responseCode");
  const code = typeof codeValue === "string" ? codeValue : "";
  const responseCode =
    typeof responseCodeValue === "number" ? responseCodeValue : 0;
  let failureClass: DeliveryFailureClass = "unknown";
  let retrySafety: "safe" | "uncertain" | "terminal" = "uncertain";
  if (
    ["EAUTH", "EENVELOPE", "EMESSAGE"].includes(code) ||
    responseCode >= 500
  ) {
    failureClass = code === "EAUTH" ? "authentication" : "unknown";
    retrySafety = "terminal";
  } else if (
    responseCode === 421 ||
    responseCode === 450 ||
    responseCode === 451 ||
    responseCode === 452
  ) {
    failureClass = responseCode === 421 ? "connectivity" : "rate_limited";
    retrySafety = "safe";
  } else if (
    ["ECONNECTION", "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN"].includes(code)
  ) {
    failureClass = "connectivity";
    retrySafety = "safe";
  } else if (["ETLS", "ECERT"].includes(code)) {
    failureClass = "tls";
    retrySafety = "safe";
  } else if (["ETIMEDOUT", "ESOCKETTIMEDOUT", "ESOCKET"].includes(code)) {
    failureClass = "timeout";
    retrySafety = "uncertain";
  }
  return new DeliveryProviderError(failureClass, retrySafety);
}

function errorProperty(error: unknown, property: string): unknown {
  return typeof error === "object" && error !== null
    ? Reflect.get(error, property)
    : undefined;
}
