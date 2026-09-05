import {
  DeliveryProviderError,
  NotificationValidationError,
} from "./errors.js";
import type {
  EmailDeliveryProvider,
  EmailDeliveryProviderResolver,
} from "./delivery.js";
import {
  isAuthenticSmtpConfiguration,
  NodemailerSmtpProvider,
  type SecretResolver,
  type SmtpConfiguration,
  type SmtpSocketConnector,
} from "./smtp.js";
import { requireInteger, requireUuidV7 } from "./validation.js";

export interface SmtpConfigurationRepository {
  loadPinnedForTenant(
    tenantId: string,
    pin: Readonly<{
      scope: "tenant" | "platform";
      id: string;
      version: number;
    }>,
    signal: AbortSignal,
  ): Promise<SmtpConfiguration | null>;
}

interface CacheEntry {
  readonly provider: NodemailerSmtpProvider;
  lastUsed: number;
}

export class CachedSmtpProviderResolver implements EmailDeliveryProviderResolver {
  readonly #repository: SmtpConfigurationRepository;
  readonly #secrets: SecretResolver;
  readonly #connector: SmtpSocketConnector;
  readonly #maximumProviders: number;
  readonly #providers = new Map<string, CacheEntry>();
  readonly #pending = new Map<string, Promise<NodemailerSmtpProvider>>();
  #clock = 0;
  #closed = false;

  constructor(dependencies: {
    repository: SmtpConfigurationRepository;
    secrets: SecretResolver;
    connector: SmtpSocketConnector;
    maximumProviders?: number;
  }) {
    this.#repository = dependencies.repository;
    this.#secrets = dependencies.secrets;
    this.#connector = dependencies.connector;
    this.#maximumProviders = requireInteger(
      dependencies.maximumProviders ?? 64,
      "maximum SMTP providers",
      1,
      256,
    );
  }

  async resolve(
    tenantId: string,
    pin: Readonly<{
      scope: "tenant" | "platform";
      id: string;
      version: number;
    }>,
    signal: AbortSignal,
  ): Promise<EmailDeliveryProvider> {
    requireUuidV7(tenantId, "SMTP resolver tenantId");
    if (pin.scope !== "tenant" && pin.scope !== "platform") {
      throw new NotificationValidationError(
        "SMTP resolver configuration scope is unsupported",
      );
    }
    requireUuidV7(pin.id, "SMTP resolver configuration id");
    requireInteger(
      pin.version,
      "SMTP resolver configuration version",
      1,
      2_147_483_647,
    );
    if (this.#closed) {
      throw new DeliveryProviderError("connectivity", "safe");
    }
    if (signal.aborted) throw signal.reason;
    const configuration = await this.#repository.loadPinnedForTenant(
      tenantId,
      pin,
      signal,
    );
    if (this.#closed) {
      throw new DeliveryProviderError("connectivity", "safe");
    }
    if (signal.aborted) throw signal.reason;
    if (configuration === null || !configuration.enabled) {
      throw new DeliveryProviderError("authentication", "terminal");
    }
    if (
      !isAuthenticSmtpConfiguration(configuration) ||
      configuration.id !== pin.id ||
      configuration.version !== pin.version ||
      (pin.scope === "tenant"
        ? configuration.tenantId !== tenantId
        : configuration.tenantId !== undefined)
    ) {
      throw new DeliveryProviderError("security", "terminal");
    }
    const cacheKey = [
      tenantId,
      pin.scope,
      configuration.id,
      String(configuration.version),
    ].join(":");
    const cached = this.#providers.get(cacheKey);
    if (cached !== undefined) {
      cached.lastUsed = ++this.#clock;
      return cached.provider;
    }
    let pending = this.#pending.get(cacheKey);
    if (pending === undefined) {
      pending = this.#create(configuration, cacheKey);
      this.#pending.set(cacheKey, pending);
    }
    return awaitWithSignal(pending, signal);
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    for (const entry of this.#providers.values()) entry.provider.close();
    this.#providers.clear();
  }

  async #create(
    configuration: SmtpConfiguration,
    cacheKey: string,
  ): Promise<NodemailerSmtpProvider> {
    try {
      const provider = await NodemailerSmtpProvider.create(
        configuration,
        this.#secrets,
        this.#connector,
        AbortSignal.timeout(configuration.timeoutMs),
      );
      if (this.#closed) {
        provider.close();
        throw new DeliveryProviderError("connectivity", "safe");
      }
      this.#providers.set(cacheKey, {
        provider,
        lastUsed: ++this.#clock,
      });
      this.#evict();
      return provider;
    } finally {
      this.#pending.delete(cacheKey);
    }
  }

  #evict(): void {
    while (this.#providers.size > this.#maximumProviders) {
      let oldestKey: string | undefined;
      let oldestUse = Number.POSITIVE_INFINITY;
      for (const [key, entry] of this.#providers) {
        if (entry.lastUsed < oldestUse) {
          oldestKey = key;
          oldestUse = entry.lastUsed;
        }
      }
      if (oldestKey === undefined) {
        throw new NotificationValidationError("SMTP provider cache is corrupt");
      }
      this.#providers.get(oldestKey)?.provider.close();
      this.#providers.delete(oldestKey);
    }
  }
}

function awaitWithSignal<T>(
  operation: Promise<T>,
  signal: AbortSignal,
): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const onAbort = (): void => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    void operation.then(
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
