import { describe, expect, it } from "vitest";

import { NotificationConfigurationError } from "./errors.js";
import {
  createNotificationProtectedSecret,
  NotificationSecretKeyring,
} from "./keyring.js";

describe("notification secret keyring", () => {
  it("decrypts the Go AES-GCM vector and binds every context dimension", async () => {
    const root = Uint8Array.from({ length: 32 }, (_, index) => index);
    const keyring = NotificationSecretKeyring.parse(
      new TextEncoder().encode(
        JSON.stringify({
          activeVersion: 7,
          keys: [{ version: 7, key: Buffer.from(root).toString("base64url") }],
        }),
      ),
    );
    root.fill(0);
    const context = {
      tenantId: "019c9878-1111-7222-8333-444455556666",
      secretId: "019c9878-7777-7888-8999-aaaabbbbcccc",
      secretVersion: 3,
      kind: "smtp_password" as const,
    };
    const envelope = {
      keyVersion: 7,
      nonce: Buffer.from("424242424242424242424242", "hex"),
      ciphertext: Buffer.from(
        "e2207ed000a94fd98bbdf8e678c2478a4689fb0ab9325a373220405d1f9a70d7a2fef0ce",
        "hex",
      ),
    };
    const plaintext = keyring.decrypt(context, envelope);
    expect(new TextDecoder().decode(plaintext)).toBe("cross-runtime-secret");
    plaintext.fill(0);
    const protectedSecret = createNotificationProtectedSecret({
      ...context,
      ...envelope,
    });
    expect(JSON.stringify(protectedSecret)).toBe(
      '{"protected":true,"kind":"smtp_password","secretVersion":3,"keyVersion":7}',
    );
    const exposedNonce = protectedSecret.nonce;
    const exposedCiphertext = protectedSecret.ciphertext;
    exposedNonce.fill(0);
    exposedCiphertext.fill(0);
    expect(protectedSecret.nonce).not.toEqual(exposedNonce);
    expect(protectedSecret.ciphertext).not.toEqual(exposedCiphertext);
    const resolved = await keyring.read(
      protectedSecret,
      new AbortController().signal,
    );
    expect(new TextDecoder().decode(resolved)).toBe("cross-runtime-secret");
    resolved.fill(0);
    expect(keyring.activeVersion).toBe(7);
    expect(keyring.versions).toEqual([7]);
    expect(keyring.toString()).not.toContain(Buffer.from(root).toString("hex"));

    const substitutions = [
      { ...context, tenantId: "019c9878-1111-7222-8333-444455556667" },
      { ...context, secretId: "019c9878-7777-7888-8999-aaaabbbbcccd" },
      { ...context, secretVersion: 4 },
      { ...context, kind: "webhook_signing_key" as const },
      { secretId: context.secretId, secretVersion: 3, kind: context.kind },
    ];
    for (const candidate of substitutions) {
      expect(() => keyring.decrypt(candidate, envelope)).toThrow(
        NotificationConfigurationError,
      );
    }

    const tampered = {
      ...envelope,
      ciphertext: Uint8Array.from(envelope.ciphertext),
    };
    tampered.ciphertext[0]! ^= 1;
    expect(() => keyring.decrypt(context, tampered)).toThrow(
      NotificationConfigurationError,
    );
    keyring.close();
    expect(() => keyring.decrypt(context, envelope)).toThrow(
      NotificationConfigurationError,
    );
  });

  it("rejects malformed, ambiguous, and non-canonical documents", () => {
    const key = Buffer.alloc(32, 0x7a).toString("base64url");
    for (const document of [
      {},
      { activeVersion: 1, keys: [] },
      { activeVersion: 2, keys: [{ version: 1, key }] },
      { activeVersion: 1, keys: [{ version: 1, key: "bad" }] },
      {
        activeVersion: 1,
        keys: [
          { version: 1, key },
          { version: 1, key },
        ],
      },
      { activeVersion: 1, keys: [{ version: 1, key }], extra: true },
      { activeVersion: 1, keys: [{ version: 1, key, extra: true }] },
    ]) {
      expect(() =>
        NotificationSecretKeyring.parse(
          new TextEncoder().encode(JSON.stringify(document)),
        ),
      ).toThrow(NotificationConfigurationError);
    }
    for (const document of [
      `{"activeVersion":1,"active\\u0056ersion":1,"keys":[{"version":1,"key":"${key}"}]}`,
      `{"activeVersion":1,"keys":[{"version":1,"version":1,"key":"${key}"}]}`,
    ]) {
      expect(() =>
        NotificationSecretKeyring.parse(new TextEncoder().encode(document)),
      ).toThrow(NotificationConfigurationError);
    }
  });
});
