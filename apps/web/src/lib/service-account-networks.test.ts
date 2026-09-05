import { describe, expect, it } from "vitest";

import { canonicalizeServiceAccountCredentialNetworks } from "./service-account-networks";

describe("canonicalizeServiceAccountCredentialNetworks", () => {
  it("uses PostgreSQL cidr order across nested IPv4 and IPv6 prefixes", () => {
    expect(
      canonicalizeServiceAccountCredentialNetworks([
        "2001:db8:1::/48",
        "10.128.0.0/9",
        "2001:db8::/48",
        "10.0.0.0/9",
        "2001:db8::/32",
        "10.0.0.0/8",
        "2.0.0.0/8",
      ]),
    ).toEqual([
      "2.0.0.0/8",
      "10.0.0.0/8",
      "10.0.0.0/9",
      "10.128.0.0/9",
      "2001:db8::/32",
      "2001:db8::/48",
      "2001:db8:1::/48",
    ]);
  });

  it.each([
    ["host bits", ["192.0.2.1/24"]],
    ["IPv4 leading zero", ["192.000.2.0/24"]],
    ["IPv6 host bits", ["2001:db8::1/32"]],
    ["IPv6 uppercase", ["2001:DB8::/32"]],
    ["IPv6 expanded spelling", ["2001:0db8:0:0:0:0:0:0/32"]],
    ["IPv6 zone", ["fe80::%eth0/64"]],
    ["IPv4-mapped IPv6", ["::ffff:0:0/96"]],
    ["noncanonical mask", ["192.0.2.0/024"]],
    ["duplicate", ["192.0.2.0/24", "192.0.2.0/24"]],
  ])("rejects %s", (_case, networks) => {
    expect(
      canonicalizeServiceAccountCredentialNetworks(networks),
    ).toBeUndefined();
  });

  it("uses the first longest zero run for canonical IPv6 spelling", () => {
    expect(
      canonicalizeServiceAccountCredentialNetworks(["2001::1:0:0:1:1/128"]),
    ).toEqual(["2001::1:0:0:1:1/128"]);
    expect(
      canonicalizeServiceAccountCredentialNetworks(["2001:0:0:1::1:1/128"]),
    ).toBeUndefined();
  });
});
