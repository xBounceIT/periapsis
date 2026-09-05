import { describe, expect, it, vi } from "vitest";

import type {
  WebAuthnAuthenticationOptions,
  WebAuthnRegistrationOptions,
} from "@periapsis/contracts";

import {
  createPasskeyResponse,
  getPasskeyResponse,
  WebAuthnBrowserError,
  type BrowserCredentials,
} from "./webauthn-browser";

const ceremonyId = "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const challenge = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const userHandle = "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("browser WebAuthn boundary", () => {
  it("decodes canonical registration options and encodes a bounded response", async () => {
    const credential = new FakeRegistrationCredential();
    const create = vi.fn<BrowserCredentials["create"]>(async () => credential);

    const response = await createPasskeyResponse(
      registrationOptions(),
      "Work laptop",
      { create, get: async () => null },
    );

    expect(create).toHaveBeenCalledWith({
      publicKey: expect.objectContaining({
        challenge: expect.any(Uint8Array),
        excludeCredentials: [
          expect.objectContaining({ transports: ["internal"] }),
        ],
      }),
    });
    expect(response).toEqual({
      ceremonyId,
      credential: {
        clientExtensionResults: { credProps: { rk: true } },
        id: "AQI",
        response: {
          attestationObject: "BAU",
          clientDataJSON: "Aw",
          transports: ["internal", "smart_card"],
        },
        type: "public-key",
      },
      displayName: "Work laptop",
    });
  });

  it("drops a server smart-card transport hint that the browser DOM cannot express", async () => {
    const credential = new FakeAuthenticationCredential();
    const get = vi.fn<BrowserCredentials["get"]>(async () => credential);

    const response = await getPasskeyResponse(authenticationOptions(), {
      create: async () => null,
      get,
    });

    expect(get).toHaveBeenCalledWith({
      publicKey: expect.objectContaining({
        allowCredentials: [
          expect.objectContaining({ transports: ["internal"] }),
        ],
      }),
    });
    expect(response.credential).toEqual({
      id: "Bgc",
      response: {
        authenticatorData: "CQ",
        clientDataJSON: "CA",
        signature: "Cg",
        userHandle: "Cw",
      },
      type: "public-key",
    });
  });

  it("rejects non-canonical bytes before invoking the credential API", async () => {
    const create = vi.fn<BrowserCredentials["create"]>(async () => null);
    const options = registrationOptions();
    options.publicKey.challenge = "AQ==";

    await expect(
      createPasskeyResponse(options, "Work laptop", {
        create,
        get: async () => null,
      }),
    ).rejects.toBeInstanceOf(WebAuthnBrowserError);
    expect(create).not.toHaveBeenCalled();
  });

  it("rejects an all-zero challenge before invoking the credential API", async () => {
    const get = vi.fn<BrowserCredentials["get"]>(async () => null);
    const options = authenticationOptions();
    options.publicKey.challenge = "A".repeat(43);

    await expect(
      getPasskeyResponse(options, { create: async () => null, get }),
    ).rejects.toBeInstanceOf(WebAuthnBrowserError);
    expect(get).not.toHaveBeenCalled();
  });

  it("rejects a response that weakens the pinned user-verification policy", async () => {
    const get = vi.fn<BrowserCredentials["get"]>(async () => null);
    const options = authenticationOptions();
    options.publicKey.userVerification = "preferred";

    await expect(
      getPasskeyResponse(options, { create: async () => null, get }),
    ).rejects.toThrow("unsafe authentication options");
    expect(get).not.toHaveBeenCalled();
  });

  it("rejects null and structurally incomplete authenticator responses", async () => {
    await expect(
      getPasskeyResponse(authenticationOptions(), {
        create: async () => null,
        get: async () => null,
      }),
    ).rejects.toThrow("invalid assertion response");

    class IncompleteCredential implements Credential {
      readonly id = "incomplete";
      readonly type = "public-key";
    }
    await expect(
      createPasskeyResponse(registrationOptions(), "Work laptop", {
        create: async () => new IncompleteCredential(),
        get: async () => null,
      }),
    ).rejects.toThrow("invalid registration response");
  });
});

class FakeRegistrationCredential implements Credential {
  readonly id = "registration";
  readonly type = "public-key";
  readonly rawId = bytes(1, 2);
  readonly response = {
    attestationObject: bytes(4, 5),
    clientDataJSON: bytes(3),
    getTransports: () => ["smart-card", "internal", "internal"],
  };

  getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
    return { credProps: { rk: true } };
  }
}

class FakeAuthenticationCredential implements Credential {
  readonly id = "authentication";
  readonly type = "public-key";
  readonly rawId = bytes(6, 7);
  readonly response = {
    authenticatorData: bytes(9),
    clientDataJSON: bytes(8),
    signature: bytes(10),
    userHandle: bytes(11),
  };

  getClientExtensionResults(): AuthenticationExtensionsClientOutputs {
    return {};
  }
}

function registrationOptions(): WebAuthnRegistrationOptions {
  return {
    ceremonyId,
    expiresAt: "2026-08-26T12:00:00Z",
    publicKey: {
      attestation: "none",
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: "required",
        userVerification: "required",
      },
      challenge,
      excludeCredentials: [
        {
          id: "Ag",
          transports: ["smart_card", "internal"],
          type: "public-key",
        },
      ],
      pubKeyCredParams: [
        { alg: -7, type: "public-key" },
        { alg: -257, type: "public-key" },
      ],
      rp: { id: "console.example.invalid", name: "Periapsis" },
      timeout: 60_000,
      user: {
        displayName: "Ada Lovelace",
        id: userHandle,
        name: "ada@example.invalid",
      },
    },
  };
}

function authenticationOptions(): WebAuthnAuthenticationOptions {
  return {
    ceremonyId,
    expiresAt: "2026-08-26T12:00:00Z",
    publicKey: {
      allowCredentials: [
        {
          id: "Bgc",
          transports: ["smart_card", "internal"],
          type: "public-key",
        },
      ],
      challenge,
      rpId: "console.example.invalid",
      timeout: 60_000,
      userVerification: "required",
    },
  };
}

function bytes(...values: number[]): ArrayBuffer {
  return Uint8Array.from(values).buffer;
}
