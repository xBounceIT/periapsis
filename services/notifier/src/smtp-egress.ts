import { lookup } from "node:dns/promises";
import { BlockList, createConnection, isIP, type Socket } from "node:net";

import {
  DeliveryProviderError,
  NotificationValidationError,
} from "./errors.js";
import {
  canonicalSmtpHost,
  isAuthenticSmtpConfiguration,
  type SmtpConfiguration,
  type SmtpSocketConnector,
} from "./smtp.js";
import { requireInteger } from "./validation.js";

export interface ResolvedNetworkAddress {
  readonly address: string;
  readonly family: 4 | 6;
}

export interface NetworkAddressResolver {
  resolve(
    hostname: string,
    signal: AbortSignal,
  ): Promise<readonly ResolvedNetworkAddress[]>;
}

export interface TcpSocketDialer {
  connect(input: {
    address: string;
    family: 4 | 6;
    port: number;
    signal: AbortSignal;
  }): Promise<Socket>;
}

export interface TcpEgressPolicyInput {
  allowedPorts?: readonly number[];
  allowedPrivateHosts?: readonly string[];
  maximumResolvedAddresses?: number;
}

export type SmtpResolvedAddress = ResolvedNetworkAddress;
export type SmtpDnsResolver = NetworkAddressResolver;
export type SmtpTcpDialer = TcpSocketDialer;
export type SmtpEgressPolicyInput = TcpEgressPolicyInput;

const neverAllowedAddresses = createBlockList([
  ["0.0.0.0", 8, "ipv4"],
  ["169.254.0.0", 16, "ipv4"],
  ["192.0.0.0", 24, "ipv4"],
  ["192.0.2.0", 24, "ipv4"],
  ["192.88.99.0", 24, "ipv4"],
  ["198.18.0.0", 15, "ipv4"],
  ["198.51.100.0", 24, "ipv4"],
  ["203.0.113.0", 24, "ipv4"],
  ["224.0.0.0", 4, "ipv4"],
  ["240.0.0.0", 4, "ipv4"],
  ["::", 128, "ipv6"],
  ["64:ff9b::", 96, "ipv6"],
  ["100::", 64, "ipv6"],
  ["2001:db8::", 32, "ipv6"],
  ["fe80::", 10, "ipv6"],
  ["ff00::", 8, "ipv6"],
] as const);

const privateAddresses = createBlockList([
  ["10.0.0.0", 8, "ipv4"],
  ["100.64.0.0", 10, "ipv4"],
  ["127.0.0.0", 8, "ipv4"],
  ["172.16.0.0", 12, "ipv4"],
  ["192.168.0.0", 16, "ipv4"],
  ["::1", 128, "ipv6"],
  ["fc00::", 7, "ipv6"],
] as const);

export class PolicyTcpSocketConnector {
  readonly #resolver: NetworkAddressResolver;
  readonly #dialer: TcpSocketDialer;
  readonly #allowedPorts: ReadonlySet<number>;
  readonly #allowedPrivateHosts: ReadonlySet<string>;
  readonly #maximumResolvedAddresses: number;

  constructor(
    dependencies: {
      resolver?: NetworkAddressResolver;
      dialer?: TcpSocketDialer;
      policy?: TcpEgressPolicyInput;
    } = {},
  ) {
    this.#resolver = dependencies.resolver ?? nodeDnsResolver;
    this.#dialer = dependencies.dialer ?? nodeTcpDialer;
    const ports = dependencies.policy?.allowedPorts ?? [465, 587];
    if (
      ports.length === 0 ||
      ports.length > 32 ||
      new Set(ports).size !== ports.length
    ) {
      throw new NotificationValidationError(
        "egress ports must be a non-empty unique allowlist",
      );
    }
    for (const port of ports) requireInteger(port, "egress port", 1, 65_535);
    this.#allowedPorts = new Set(ports);

    const privateHosts = (dependencies.policy?.allowedPrivateHosts ?? []).map(
      canonicalSmtpHost,
    );
    if (
      privateHosts.length > 64 ||
      new Set(privateHosts).size !== privateHosts.length
    ) {
      throw new NotificationValidationError(
        "private-host egress allowlist is invalid",
      );
    }
    this.#allowedPrivateHosts = new Set(privateHosts);
    this.#maximumResolvedAddresses = requireInteger(
      dependencies.policy?.maximumResolvedAddresses ?? 16,
      "maximum resolved addresses",
      1,
      64,
    );
  }

  async connect(target: {
    host: string;
    port: number;
    timeoutMs: number;
    requirePrivateTarget?: boolean;
    requireLoopbackTarget?: boolean;
    signal?: AbortSignal;
  }): Promise<Socket> {
    const host = canonicalSmtpHost(target.host);
    requireInteger(target.port, "egress target port", 1, 65_535);
    requireInteger(target.timeoutMs, "egress target timeout", 100, 120_000);
    if (
      target.requirePrivateTarget !== undefined &&
      typeof target.requirePrivateTarget !== "boolean"
    ) {
      throw new NotificationValidationError(
        "private-target egress policy must be boolean",
      );
    }
    if (
      target.requireLoopbackTarget !== undefined &&
      typeof target.requireLoopbackTarget !== "boolean"
    ) {
      throw new NotificationValidationError(
        "loopback-target egress policy must be boolean",
      );
    }
    target.signal?.throwIfAborted();
    if (!this.#allowedPorts.has(target.port)) {
      throw new DeliveryProviderError("security", "terminal");
    }

    const timeout = AbortSignal.timeout(target.timeoutMs);
    const deadline =
      target.signal === undefined
        ? timeout
        : AbortSignal.any([target.signal, timeout]);
    let addresses: readonly ResolvedNetworkAddress[];
    try {
      addresses = await this.#resolve(host, deadline);
    } catch (error) {
      target.signal?.throwIfAborted();
      if (error instanceof DeliveryProviderError) throw error;
      throw new DeliveryProviderError(
        timeout.aborted ? "timeout" : "connectivity",
        "safe",
      );
    }
    const permitsPrivate = this.#allowedPrivateHosts.has(host);
    for (const { address, family } of addresses) {
      const isPrivate = blocked(privateAddresses, address, family);
      const isExactLoopback =
        (family === 4 && address === "127.0.0.1") ||
        (family === 6 && address === "::1");
      if (
        (family === 6 && address.toLowerCase().startsWith("::ffff:")) ||
        blocked(neverAllowedAddresses, address, family) ||
        (isPrivate && !permitsPrivate) ||
        (target.requirePrivateTarget === true && !isPrivate) ||
        (target.requireLoopbackTarget === true && !isExactLoopback)
      ) {
        throw new DeliveryProviderError("security", "terminal");
      }
    }

    for (const address of addresses) {
      try {
        // All attempts share one deadline, preventing address fan-out from
        // multiplying the configured connection timeout.
        // eslint-disable-next-line no-await-in-loop
        return await this.#dialer.connect({
          ...address,
          port: target.port,
          signal: deadline,
        });
      } catch {
        target.signal?.throwIfAborted();
        if (deadline.aborted) break;
      }
    }
    target.signal?.throwIfAborted();
    throw new DeliveryProviderError(
      timeout.aborted ? "timeout" : "connectivity",
      "safe",
    );
  }

  async #resolve(
    host: string,
    signal: AbortSignal,
  ): Promise<readonly ResolvedNetworkAddress[]> {
    const literalFamily = isIP(host);
    const raw =
      literalFamily === 0
        ? await this.#resolver.resolve(host, signal)
        : [{ address: host, family: literalFamily }];
    if (signal.aborted) throw signal.reason;

    const unique = new Map<string, ResolvedNetworkAddress>();
    for (const item of raw) {
      if (
        (item.family !== 4 && item.family !== 6) ||
        isIP(item.address) !== item.family
      ) {
        throw new DeliveryProviderError("security", "terminal");
      }
      unique.set(`${item.family}:${item.address.toLowerCase()}`, {
        address: item.address.toLowerCase(),
        family: item.family,
      });
    }
    if (unique.size === 0 || unique.size > this.#maximumResolvedAddresses) {
      throw new DeliveryProviderError("security", "terminal");
    }
    return Object.freeze(
      [...unique.values()].toSorted((left, right) =>
        `${left.family}:${left.address}`.localeCompare(
          `${right.family}:${right.address}`,
        ),
      ),
    );
  }
}

export class PolicySmtpSocketConnector implements SmtpSocketConnector {
  readonly #connector: PolicyTcpSocketConnector;

  constructor(
    dependencies: {
      resolver?: SmtpDnsResolver;
      dialer?: SmtpTcpDialer;
      policy?: SmtpEgressPolicyInput;
    } = {},
  ) {
    this.#connector = new PolicyTcpSocketConnector(dependencies);
  }

  connect(configuration: SmtpConfiguration): Promise<Socket> {
    if (
      !isAuthenticSmtpConfiguration(configuration) ||
      !configuration.enabled
    ) {
      throw new NotificationValidationError(
        "SMTP egress received a forged or disabled configuration",
      );
    }
    return this.#connector.connect({
      ...configuration,
      requirePrivateTarget: configuration.security === "plain_local",
    });
  }
}

const nodeDnsResolver: NetworkAddressResolver = Object.freeze({
  async resolve(
    hostname: string,
    signal: AbortSignal,
  ): Promise<readonly ResolvedNetworkAddress[]> {
    const result = await abortable(
      lookup(hostname, { all: true, verbatim: true }),
      signal,
    );
    return result.map(({ address, family }) => {
      if (family !== 4 && family !== 6) {
        throw new DeliveryProviderError("security", "terminal");
      }
      return { address, family };
    });
  },
});

const nodeTcpDialer: TcpSocketDialer = Object.freeze({
  connect(input: {
    address: string;
    family: 4 | 6;
    port: number;
    signal: AbortSignal;
  }): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket = createConnection({
        host: input.address,
        family: input.family,
        port: input.port,
        signal: input.signal,
      });
      const cleanup = (): void => {
        socket.off("connect", onConnect);
        socket.off("error", onError);
      };
      const onConnect = (): void => {
        cleanup();
        socket.setNoDelay(true);
        socket.setKeepAlive(true);
        resolve(socket);
      };
      const onError = (error: Error): void => {
        cleanup();
        socket.destroy();
        reject(error);
      };
      socket.once("connect", onConnect);
      socket.once("error", onError);
    });
  },
});

function createBlockList(
  entries: readonly (readonly [string, number, "ipv4" | "ipv6"])[],
): BlockList {
  const result = new BlockList();
  for (const [network, prefix, family] of entries)
    result.addSubnet(network, prefix, family);
  return result;
}

function blocked(list: BlockList, address: string, family: 4 | 6): boolean {
  return list.check(address, family === 4 ? "ipv4" : "ipv6");
}

function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
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
