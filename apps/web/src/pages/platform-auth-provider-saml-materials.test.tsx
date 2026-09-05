import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type PlatformAuthProviderView,
  type VersionedView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi } from "../test/phase-two-fixtures";
import { PlatformAuthProviderSamlMaterials } from "./platform-auth-provider-saml-materials";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const sessionId = "0198c97d-cf4f-7000-8000-000000000091";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("PlatformAuthProviderSamlMaterials", () => {
  it("shows only safe revision and presence state without manage authority", () => {
    renderMaterials({}, { canManage: false });

    expect(screen.getByText("Revision 1")).toBeVisible();
    expect(screen.getByText("Present · revision 2")).toBeVisible();
    expect(
      screen.getByText("Protected administration is read-only"),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Replace IdP metadata" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/EntityDescriptor/u)).not.toBeInTheDocument();
    expect(screen.queryByText(/PRIVATE KEY/u)).not.toBeInTheDocument();
  });

  it("replaces URL metadata at the exact provider version and refreshes the safe projection", async () => {
    const replace = vi.fn<PhaseTwoApi["replacePlatformSamlMetadata"]>(
      async () => ({ etag: '"v8"', materialRevision: 2 }),
    );
    const onChanged = vi.fn();
    const onNotice = vi.fn();
    const onProjectionStale = vi.fn();
    const onMutationBusyChange = vi.fn();
    renderMaterials(
      { replacePlatformSamlMetadata: replace },
      {
        onChanged,
        onMutationBusyChange,
        onNotice,
        onProviderProjectionStale: onProjectionStale,
      },
    );
    onMutationBusyChange.mockClear();

    fireEvent.click(
      screen.getByRole("button", { name: "Replace IdP metadata" }),
    );
    fireEvent.change(screen.getByLabelText("IdP metadata URL"), {
      target: { value: "https://idp.example.test/metadata" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Replace reviewed SAML metadata" },
    });
    fireEvent.click(
      within(
        screen.getByRole("form", { name: "Replace SAML IdP metadata" }),
      ).getByRole("button", { name: "Replace write-only metadata" }),
    );

    await waitFor(() =>
      expect(replace).toHaveBeenCalledWith(
        "csrf-memory-only",
        providerId,
        samlProviderView(),
        "Replace reviewed SAML metadata",
        {
          approveTrustReset: false,
          expectedVersion: 7,
          metadataUrl: "https://idp.example.test/metadata",
          source: "url",
        },
      ),
    );
    expect(onMutationBusyChange.mock.calls).toEqual([[true], [false]]);
    expect(onProjectionStale).toHaveBeenCalledOnce();
    expect(onChanged).toHaveBeenCalledOnce();
    expect(onNotice).toHaveBeenCalledWith({
      message:
        "SAML IdP metadata was replaced write-only at trust revision 2. No raw metadata or certificate material was returned.",
      tone: "success",
    });
  });

  it("clears reflected XML on a trust-continuity conflict and requires deliberate approval", async () => {
    const rawXml = '<EntityDescriptor ID="must-never-be-reflected" />';
    const replace = vi
      .fn<PhaseTwoApi["replacePlatformSamlMetadata"]>()
      .mockRejectedValue(
        new PhaseTwoApiError(rawXml, 409, {
          code: "saml_trust_approval_required",
        }),
      );
    renderMaterials({ replacePlatformSamlMetadata: replace });

    fireEvent.click(
      screen.getByRole("button", { name: "Replace IdP metadata" }),
    );
    fireEvent.change(screen.getByLabelText("Metadata source"), {
      target: { value: "xml" },
    });
    fireEvent.change(screen.getByLabelText("IdP metadata XML"), {
      target: { value: rawXml },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Review an IdP certificate rollover" },
    });
    fireEvent.submit(
      screen.getByRole("form", { name: "Replace SAML IdP metadata" }),
    );

    expect(
      await screen.findByText("Explicit trust approval required"),
    ).toBeVisible();
    expect(screen.getByLabelText("IdP metadata XML")).toHaveValue("");
    expect(screen.queryByText(rawXml)).not.toBeInTheDocument();
    expect(
      screen.getByLabelText("Approve trust reset after out-of-band review"),
    ).not.toBeChecked();

    fireEvent.submit(
      screen.getByRole("form", { name: "Replace SAML IdP metadata" }),
    );
    expect(
      await screen.findByText(
        "Confirm explicit trust-reset approval only after completing the out-of-band review.",
      ),
    ).toBeVisible();
    expect(replace).toHaveBeenCalledOnce();
  });

  it("converts PEM to canonical base64 and clears all write-only key fields before completion", async () => {
    const request = Promise.withResolvers<{
      etag: string;
      materialRevision: number;
    }>();
    const replace = vi.fn<PhaseTwoApi["replacePlatformSamlSpKey"]>(
      () => request.promise,
    );
    const onNotice = vi.fn();
    renderMaterials({ replacePlatformSamlSpKey: replace }, { onNotice });

    fireEvent.click(
      screen.getByRole("button", { name: "Rotate SP signing key" }),
    );
    fireEvent.change(screen.getByLabelText("PKCS#8 private key PEM"), {
      target: { value: pem("PRIVATE KEY", "AQIDBA==") },
    });
    fireEvent.change(screen.getByLabelText("X.509 certificate chain PEM"), {
      target: { value: pem("CERTIFICATE", "BQYH") },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Rotate approved SAML signing material" },
    });
    fireEvent.submit(
      screen.getByRole("form", { name: "Replace SAML SP signing key" }),
    );

    await waitFor(() => expect(replace).toHaveBeenCalledOnce());
    expect(replace).toHaveBeenCalledWith(
      "csrf-memory-only",
      providerId,
      samlProviderView(),
      "Rotate approved SAML signing material",
      {
        certificates: ["BQYH"],
        expectedVersion: 7,
        privateKeyPkcs8: "AQIDBA==",
      },
    );
    expect(screen.getByLabelText("PKCS#8 private key PEM")).toHaveValue("");
    expect(screen.getByLabelText("X.509 certificate chain PEM")).toHaveValue(
      "",
    );

    request.resolve({ etag: '"v8"', materialRevision: 3 });
    await waitFor(() => expect(onNotice).toHaveBeenCalledOnce());
    expect(onNotice.mock.calls[0]?.[0].message).not.toContain("AQIDBA==");
    expect(onNotice.mock.calls[0]?.[0].message).not.toContain("BQYH");
  });

  it("clears an existing key only after exact provider-key confirmation", async () => {
    const clear = vi.fn<PhaseTwoApi["clearPlatformSamlSpKey"]>(async () => ({
      etag: '"v8"',
      materialRevision: 3,
    }));
    renderMaterials({ clearPlatformSamlSpKey: clear });

    fireEvent.click(
      screen.getByRole("button", { name: "Clear SP signing key" }),
    );
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Retire compromised SAML signing material" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_saml to confirm"), {
      target: { value: "wrong" },
    });
    fireEvent.submit(
      screen.getByRole("form", { name: "Clear SAML SP signing key" }),
    );
    expect(clear).not.toHaveBeenCalled();
    expect(
      screen.getByText("Type workforce_saml to confirm clearing the SP key."),
    ).toBeVisible();

    fireEvent.change(screen.getByLabelText("Type workforce_saml to confirm"), {
      target: { value: "workforce_saml" },
    });
    fireEvent.submit(
      screen.getByRole("form", { name: "Clear SAML SP signing key" }),
    );

    await waitFor(() =>
      expect(clear).toHaveBeenCalledWith(
        "csrf-memory-only",
        providerId,
        samlProviderView(),
        "Retire compromised SAML signing material",
        { expectedVersion: 7 },
      ),
    );
  });

  it("drops an in-flight material completion when the session changes", async () => {
    const request = Promise.withResolvers<{
      etag: string;
      materialRevision: number;
    }>();
    const replace = vi.fn<PhaseTwoApi["replacePlatformSamlMetadata"]>(
      () => request.promise,
    );
    const api = createPhaseTwoApi({
      replacePlatformSamlMetadata: replace,
    });
    const onChanged = vi.fn();
    const onNotice = vi.fn();
    const onProjectionStale = vi.fn();
    const onMutationBusyChange = vi.fn();
    const common = {
      api,
      canManage: true,
      csrfToken: "csrf-memory-only",
      current: samlProviderView(),
      onChanged,
      onMutationBusyChange,
      onNotice,
      onPermissionError: vi.fn(),
      onProviderProjectionStale: onProjectionStale,
      onUnauthenticated: vi.fn(),
      providerMutationBusy: false,
    };
    const view = render(
      <PlatformAuthProviderSamlMaterials
        {...common}
        sessionId="0198c97d-cf4f-7000-8000-000000000091"
      />,
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Replace IdP metadata" }),
    );
    fireEvent.change(screen.getByLabelText("IdP metadata URL"), {
      target: { value: "https://idp.example.test/metadata" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Replace reviewed SAML metadata" },
    });
    fireEvent.submit(
      screen.getByRole("form", { name: "Replace SAML IdP metadata" }),
    );
    await waitFor(() => expect(replace).toHaveBeenCalledOnce());

    view.rerender(
      <PlatformAuthProviderSamlMaterials
        {...common}
        sessionId="0198c97d-cf4f-7000-8000-000000000092"
      />,
    );
    expect(
      screen.queryByRole("form", { name: "Replace SAML IdP metadata" }),
    ).not.toBeInTheDocument();
    await act(async () => {
      request.resolve({ etag: '"v8"', materialRevision: 2 });
      await Promise.resolve();
    });

    expect(onChanged).not.toHaveBeenCalled();
    expect(onNotice).not.toHaveBeenCalled();
    expect(onProjectionStale).not.toHaveBeenCalled();
    expect(onMutationBusyChange).toHaveBeenLastCalledWith(false);
  });
});

function renderMaterials(
  overrides: Partial<PhaseTwoApi>,
  props: Partial<
    React.ComponentProps<typeof PlatformAuthProviderSamlMaterials>
  > = {},
): ReturnType<typeof render> {
  return render(
    <PlatformAuthProviderSamlMaterials
      api={createPhaseTwoApi(overrides)}
      canManage
      csrfToken="csrf-memory-only"
      current={samlProviderView()}
      onChanged={vi.fn()}
      onMutationBusyChange={vi.fn()}
      onNotice={vi.fn()}
      onPermissionError={vi.fn()}
      onProviderProjectionStale={vi.fn()}
      onUnauthenticated={vi.fn()}
      providerMutationBusy={false}
      sessionId={sessionId}
      {...props}
    />,
  );
}

function samlProviderView(): VersionedView<
  Extract<PlatformAuthProviderView, { kind: "saml" }>
> {
  return {
    etag: '"v7"',
    value: {
      accountMode: "disabled",
      activationAvailable: false,
      archivedAt: null,
      assurancePolicyRevision: 1,
      configuration: {
        acsUrl: "https://soc.example.test/api/v1/auth/platform/saml/acs",
        clockSkewNanoseconds: 120_000_000_000,
        encryptionPolicy: "disabled",
        expectedEntityId: "https://idp.example.test/entity",
        maxAuthenticationAgeNanoseconds: 28_800_000_000_000,
        metadataRevision: 1,
        redirectSignatureAlgorithm:
          "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        requestedAuthnContexts: [],
        signaturePolicy: "both",
        spEntityId:
          "https://soc.example.test/api/v1/auth/platform/saml/workforce_saml/metadata",
        spKeyPresent: true,
        spKeyRevision: 2,
        subjectSource: "persistent_nameid",
      },
      configurationRevision: 1,
      configured: true,
      createdAt: "2026-08-30T10:00:00Z",
      description: "Corporate workforce federation",
      displayName: "Workforce SAML",
      enabled: false,
      id: providerId,
      key: "workforce_saml",
      kind: "saml",
      planRevision: 1,
      platformLoginActivationAvailable: false,
      platformLoginEnabled: false,
      secretPresent: true,
      securityRevision: 1,
      updatedAt: "2026-08-30T10:05:00Z",
      version: 7,
    },
  };
}

function pem(label: string, body: string): string {
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}
