import { createDecipheriv, hkdfSync } from "node:crypto";

import { NotificationConfigurationError } from "./errors.js";
import {
  parseStrictJson,
  requireInteger,
  requireUuidV7,
} from "./validation.js";

const rootKeyBytes = 32;
const nonceBytes = 12;
const tagBytes = 16;
const maximumSecretBytes = 64 * 1_024;
const maximumKeyCount = 16;
const maximumKeyVersion = 32_767;
const hkdfSalt = "periapsis/notification/hkdf-sha256/v1";
const encryptionPurpose =
  "periapsis/notification/config-secret/aes-256-gcm/key/v1";
const aadSchema = "periapsis/notification/config-secret/aes-256-gcm/aad/v1";

export type NotificationSecretKind =
  "smtp_password" | "smtp_dkim_private_key" | "webhook_signing_key";

export interface NotificationSecretContext {
  readonly tenantId?: string;
  readonly secretId: string;
  readonly secretVersion: number;
  readonly kind: NotificationSecretKind;
}

export interface NotificationSecretEnvelope {
  readonly keyVersion: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

export interface NotificationProtectedSecretInput
  extends NotificationSecretContext, NotificationSecretEnvelope {}

export interface NotificationProtectedSecret {
  readonly tenantId?: string;
  readonly secretId: string;
  readonly secretVersion: number;
  readonly kind: NotificationSecretKind;
  readonly keyVersion: number;
  readonly nonce: Uint8Array;
  readonly ciphertext: Uint8Array;
}

interface KeyringDocument {
  readonly activeVersion: number;
  readonly keys: readonly Readonly<{ version: number; key: string }>[];
}

const authenticProtectedSecrets = new WeakSet<NotificationProtectedSecret>();
const protectedSecretMaterial = new WeakMap<
  NotificationProtectedSecret,
  Readonly<{ nonce: Uint8Array; ciphertext: Uint8Array }>
>();

export function createNotificationProtectedSecret(
  input: NotificationProtectedSecretInput,
): NotificationProtectedSecret {
  const context = canonicalSecretContext(input);
  const keyVersion = requireInteger(
    input.keyVersion,
    "notification secret key version",
    1,
    maximumKeyVersion,
  );
  if (
    !(input.nonce instanceof Uint8Array) ||
    input.nonce.byteLength !== nonceBytes ||
    !(input.ciphertext instanceof Uint8Array) ||
    input.ciphertext.byteLength <= tagBytes ||
    input.ciphertext.byteLength > maximumSecretBytes + tagBytes
  ) {
    throw invalidSecret();
  }
  const nonce = Uint8Array.from(input.nonce);
  const ciphertext = Uint8Array.from(input.ciphertext);
  const secret = Object.freeze({
    ...context,
    keyVersion,
    get nonce(): Uint8Array {
      return Uint8Array.from(nonce);
    },
    get ciphertext(): Uint8Array {
      return Uint8Array.from(ciphertext);
    },
    toJSON: () =>
      Object.freeze({
        protected: true,
        kind: context.kind,
        secretVersion: context.secretVersion,
        keyVersion,
      }),
  });
  authenticProtectedSecrets.add(secret);
  protectedSecretMaterial.set(secret, Object.freeze({ nonce, ciphertext }));
  return secret;
}

export function isAuthenticNotificationProtectedSecret(
  input: NotificationProtectedSecret,
): boolean {
  return authenticProtectedSecrets.has(input);
}

export class NotificationSecretKeyring {
  readonly #activeVersion: number;
  readonly #keys: Map<number, Buffer>;
  #closed = false;

  private constructor(activeVersion: number, keys: Map<number, Buffer>) {
    this.#activeVersion = activeVersion;
    this.#keys = keys;
  }

  static parse(document: Uint8Array): NotificationSecretKeyring {
    if (document.byteLength < 1 || document.byteLength > maximumSecretBytes) {
      throw invalidKeyring();
    }
    let decoded: unknown;
    try {
      decoded = parseStrictJson(
        new TextDecoder("utf-8", { fatal: true }).decode(document),
      );
    } catch {
      throw invalidKeyring();
    }
    const parsed = parseKeyringDocument(decoded);
    const keys = new Map<number, Buffer>();
    try {
      for (const entry of parsed.keys) {
        if (keys.has(entry.version)) throw invalidKeyring();
        const root = decodeRootKey(entry.key);
        try {
          const derived = Buffer.from(
            hkdfSync(
              "sha256",
              root,
              Buffer.from(hkdfSalt, "utf8"),
              Buffer.from(
                `${encryptionPurpose}/version/${entry.version}`,
                "utf8",
              ),
              rootKeyBytes,
            ),
          );
          keys.set(entry.version, derived);
        } finally {
          root.fill(0);
        }
      }
      if (!keys.has(parsed.activeVersion)) throw invalidKeyring();
      return new NotificationSecretKeyring(parsed.activeVersion, keys);
    } catch (error: unknown) {
      clearKeys(keys);
      if (error instanceof NotificationConfigurationError) throw error;
      throw invalidKeyring();
    }
  }

  get activeVersion(): number {
    return this.#activeVersion;
  }

  get versions(): readonly number[] {
    return Object.freeze(
      [...this.#keys.keys()].toSorted((left, right) => left - right),
    );
  }

  decrypt(
    contextInput: NotificationSecretContext,
    envelope: NotificationSecretEnvelope,
  ): Uint8Array {
    if (this.#closed) throw invalidSecret();
    const context = canonicalSecretContext(contextInput);
    const keyVersion = requireInteger(
      envelope.keyVersion,
      "notification secret key version",
      1,
      maximumKeyVersion,
    );
    if (
      !(envelope.nonce instanceof Uint8Array) ||
      envelope.nonce.byteLength !== nonceBytes
    ) {
      throw invalidSecret();
    }
    if (
      !(envelope.ciphertext instanceof Uint8Array) ||
      envelope.ciphertext.byteLength <= tagBytes ||
      envelope.ciphertext.byteLength > maximumSecretBytes + tagBytes
    ) {
      throw invalidSecret();
    }
    const retained = this.#keys.get(keyVersion);
    if (retained === undefined) throw invalidSecret();
    const key = Buffer.from(retained);
    const nonce = Buffer.from(envelope.nonce);
    const ciphertext = Buffer.from(envelope.ciphertext);
    const aad = secretAAD(context);
    try {
      const encrypted = ciphertext.subarray(
        0,
        ciphertext.byteLength - tagBytes,
      );
      const tag = ciphertext.subarray(ciphertext.byteLength - tagBytes);
      const decipher = createDecipheriv("aes-256-gcm", key, nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ]);
      if (
        plaintext.byteLength < 1 ||
        plaintext.byteLength > maximumSecretBytes
      ) {
        plaintext.fill(0);
        throw invalidSecret();
      }
      return new Uint8Array(plaintext);
    } catch {
      throw invalidSecret();
    } finally {
      key.fill(0);
      nonce.fill(0);
      ciphertext.fill(0);
      aad.fill(0);
    }
  }

  async read(
    secret: NotificationProtectedSecret,
    signal: AbortSignal,
  ): Promise<Uint8Array> {
    if (signal.aborted) throw signal.reason;
    const material = protectedSecretMaterial.get(secret);
    if (!authenticProtectedSecrets.has(secret) || material === undefined) {
      throw invalidSecret();
    }
    return this.decrypt(secret, {
      keyVersion: secret.keyVersion,
      nonce: material.nonce,
      ciphertext: material.ciphertext,
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    clearKeys(this.#keys);
  }

  toString(): string {
    return `NotificationSecretKeyring{activeVersion:${this.#activeVersion},retainedKeys:${this.#keys.size}}`;
  }
}

function parseKeyringDocument(input: unknown): KeyringDocument {
  if (!isRecord(input) || !hasExactKeys(input, ["activeVersion", "keys"])) {
    throw invalidKeyring();
  }
  const activeVersion = requireKeyVersion(input["activeVersion"]);
  const entries = input["keys"];
  if (
    !Array.isArray(entries) ||
    entries.length < 1 ||
    entries.length > maximumKeyCount
  ) {
    throw invalidKeyring();
  }
  const keys = entries.map(
    (entry): Readonly<{ version: number; key: string }> => {
      if (!isRecord(entry) || !hasExactKeys(entry, ["version", "key"])) {
        throw invalidKeyring();
      }
      const version = requireKeyVersion(entry["version"]);
      const key = entry["key"];
      if (typeof key !== "string") throw invalidKeyring();
      return Object.freeze({ version, key });
    },
  );
  return Object.freeze({ activeVersion, keys: Object.freeze(keys) });
}

function canonicalSecretContext(
  input: NotificationSecretContext,
): NotificationSecretContext {
  if (input === null || typeof input !== "object") throw invalidSecret();
  const secretId = requireUuidV7(input.secretId, "notification secret id");
  const secretVersion = requireInteger(
    input.secretVersion,
    "notification secret version",
    1,
    2_147_483_647,
  );
  if (!isSecretKind(input.kind)) throw invalidSecret();
  if (input.tenantId !== undefined) {
    return Object.freeze({
      tenantId: requireUuidV7(input.tenantId, "notification secret tenant id"),
      secretId,
      secretVersion,
      kind: input.kind,
    });
  }
  return Object.freeze({ secretId, secretVersion, kind: input.kind });
}

function secretAAD(context: NotificationSecretContext): Buffer {
  const version = Buffer.alloc(8);
  version.writeBigUInt64BE(BigInt(context.secretVersion));
  const tenant =
    context.tenantId === undefined
      ? Buffer.alloc(0)
      : uuidBytes(context.tenantId);
  const result = lengthPrefixed([
    Buffer.from(aadSchema, "utf8"),
    Buffer.from(context.tenantId === undefined ? "platform" : "tenant", "utf8"),
    tenant,
    uuidBytes(context.secretId),
    version,
    Buffer.from(context.kind, "utf8"),
  ]);
  version.fill(0);
  tenant.fill(0);
  return result;
}

function lengthPrefixed(parts: readonly Buffer[]): Buffer {
  const size = parts.reduce((total, part) => total + 4 + part.byteLength, 0);
  const result = Buffer.allocUnsafe(size);
  let offset = 0;
  for (const part of parts) {
    result.writeUInt32BE(part.byteLength, offset);
    offset += 4;
    part.copy(result, offset);
    offset += part.byteLength;
  }
  return result;
}

function uuidBytes(value: string): Buffer {
  return Buffer.from(value.replaceAll("-", ""), "hex");
}

function decodeRootKey(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{43}$/u.test(value)) throw invalidKeyring();
  const decoded = Buffer.from(value, "base64url");
  if (
    decoded.byteLength !== rootKeyBytes ||
    decoded.toString("base64url") !== value
  ) {
    decoded.fill(0);
    throw invalidKeyring();
  }
  return decoded;
}

function requireKeyVersion(value: unknown): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > maximumKeyVersion
  ) {
    throw invalidKeyring();
  }
  return value;
}

function isSecretKind(value: unknown): value is NotificationSecretKind {
  return (
    value === "smtp_password" ||
    value === "smtp_dkim_private_key" ||
    value === "webhook_signing_key"
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(
  value: Readonly<Record<string, unknown>>,
  expected: readonly string[],
): boolean {
  const keys = Object.keys(value).toSorted();
  const canonical = [...expected].toSorted();
  return (
    keys.length === canonical.length &&
    keys.every((key, index) => key === canonical[index])
  );
}

function clearKeys(keys: Map<number, Buffer>): void {
  for (const key of keys.values()) key.fill(0);
  keys.clear();
}

function invalidKeyring(): NotificationConfigurationError {
  return new NotificationConfigurationError("notification keyring is invalid");
}

function invalidSecret(): NotificationConfigurationError {
  return new NotificationConfigurationError(
    "protected notification secret is invalid",
  );
}
