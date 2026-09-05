import { describe, expect, it } from "vitest";

import {
  parsePlatformSamlSpKeyMaterial,
  validatePlatformSamlMetadataMaterial,
} from "./platform-auth-provider-saml-material-model";

describe("platform SAML protected-material form model", () => {
  it("accepts canonical HTTPS metadata coordinates and bounded XML", () => {
    expect(
      validatePlatformSamlMetadataMaterial(
        "url",
        "https://idp.example.test/metadata?environment=prod",
      ),
    ).toBeNull();
    expect(
      validatePlatformSamlMetadataMaterial(
        "xml",
        '<?xml version="1.0"?><EntityDescriptor />',
      ),
    ).toBeNull();
  });

  it("rejects unsafe URL authority and unbounded or malformed XML", () => {
    for (const value of [
      "http://idp.example.test/metadata",
      "https://user@idp.example.test/metadata",
      "https://IDP.example.test/metadata",
      "https://idp.example.test/metadata#certificate",
    ]) {
      expect(validatePlatformSamlMetadataMaterial("url", value)).not.toBeNull();
    }
    expect(validatePlatformSamlMetadataMaterial("xml", " \n ")).not.toBeNull();
    expect(
      validatePlatformSamlMetadataMaterial("xml", "<Entity\0Descriptor />"),
    ).not.toBeNull();
    expect(
      validatePlatformSamlMetadataMaterial(
        "xml",
        `<!--${"é".repeat(262_145)}-->`,
      ),
    ).not.toBeNull();
  });

  it("converts one PKCS#8 PEM and an ordered certificate chain to canonical base64", () => {
    const parsed = parsePlatformSamlSpKeyMaterial(
      pem("PRIVATE KEY", "AQIDBA==", "\r\n"),
      `${pem("CERTIFICATE", "BQYH", "\r\n")}\r\n${pem(
        "CERTIFICATE",
        "CAkK",
        "\r\n",
      )}`,
    );

    expect(parsed).toEqual({
      errors: [],
      material: {
        certificates: ["BQYH", "CAkK"],
        privateKeyPkcs8: "AQIDBA==",
      },
    });
  });

  it.each([
    {
      certificates: pem("CERTIFICATE", "BQYH"),
      key: pem("RSA PRIVATE KEY", "AQIDBA=="),
      label: "an algorithm-specific private-key label",
    },
    {
      certificates: pem("CERTIFICATE", "BQYH"),
      key: pem("PRIVATE KEY", "AQIDBA"),
      label: "unpadded base64",
    },
    {
      certificates: `${pem("CERTIFICATE", "BQYH")}\n${pem(
        "CERTIFICATE",
        "BQYH",
      )}`,
      key: pem("PRIVATE KEY", "AQIDBA=="),
      label: "a duplicate certificate",
    },
    {
      certificates: "unframed certificate bytes",
      key: pem("PRIVATE KEY", "AQIDBA=="),
      label: "unframed certificate material",
    },
  ])("rejects $label", ({ certificates, key }) => {
    const parsed = parsePlatformSamlSpKeyMaterial(key, certificates);

    expect(parsed.material).toBeNull();
    expect(parsed.errors.length).toBeGreaterThan(0);
  });

  it("rejects more than eight certificate blocks", () => {
    const certificates = Array.from({ length: 9 }, (_, index) =>
      pem("CERTIFICATE", btoa(String.fromCharCode(index))),
    ).join("\n");

    expect(
      parsePlatformSamlSpKeyMaterial(
        pem("PRIVATE KEY", "AQIDBA=="),
        certificates,
      ).material,
    ).toBeNull();
  });
});

function pem(label: string, body: string, newline = "\n"): string {
  return `-----BEGIN ${label}-----${newline}${body}${newline}-----END ${label}-----`;
}
