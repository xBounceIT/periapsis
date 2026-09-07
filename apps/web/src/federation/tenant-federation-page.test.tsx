import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import type {
  TenantFederationAuthProvider,
  TenantFederationAssurancePolicy,
  TenantFederationMappingPolicy,
  TenantFederationAuthProviderSummary,
  TenantFederationAuthProviderUpdateRequest,
} from "@periapsis/contracts";

import { SessionContext } from "../auth/session-context";
import { TenantAuthorityProvider } from "../auth/tenant-authority-context";
import type {
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import type { TenantFederationApi } from "./tenant-federation-api";
import { TenantFederationPage } from "./tenant-federation-page";

const tenantId = "0198c97d-cf4f-7000-8000-000000000010";
const foreignTenantId = "0198c97d-cf4f-7000-8000-000000000011";
const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const foreignProviderId = "0198c97d-cf4f-7000-8000-000000000098";
const freshProviderId = "0198c97d-cf4f-7000-8000-00000000009a";
const staleProviderId = "0198c97d-cf4f-7000-8000-00000000009b";
const bindingId = "0198c97d-cf4f-7000-8000-000000000089";
const foreignBindingId = "0198c97d-cf4f-7000-8000-000000000099";
const freshBindingId = "0198c97d-cf4f-7000-8000-00000000009c";
const staleBindingId = "0198c97d-cf4f-7000-8000-00000000009d";
const mappingRuleId = "0198c97d-cf4f-7000-8000-000000000090";
const assuranceRuleId = "0198c97d-cf4f-7000-8000-000000000091";
const securityGroupId = "0198c97d-cf4f-7000-8000-000000000092";
const roleId = "0198c97d-cf4f-7000-8000-000000000093";
const operatorTeamId = "0198c97d-cf4f-7000-8000-000000000094";
const assignmentEpochId = "0198c97d-cf4f-7000-8000-000000000095";

afterEach(cleanup);

describe("TenantFederationPage", () => {
  it("uses live tenant authority for controls and renders only safe projection metadata", async () => {
    const api = federationApiFixture();
    renderPage(api, ["identity_provider.read"]);

    expect(await screen.findByText("Workforce SSO")).toBeVisible();
    expect(screen.getByText("workforce_oidc")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create provider" }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Inspect and manage" }));
    expect(await screen.findByText("Present · revision 2")).toBeVisible();
    expect(
      screen.getByText(/api\/v1\/auth\/federated\/oidc\/callback/u),
    ).toBeVisible();
    expect(
      screen.queryByRole("form", { name: "Rotate OIDC client secret" }),
    ).not.toBeInTheDocument();
  });

  it("marks an enabled provider with expired trust as explicitly unavailable", async () => {
    const base = oidcProvider();
    const provider: TenantFederationAuthProvider = {
      ...base,
      binding: { ...base.binding, enabled: true },
      configured: false,
      enabled: true,
    };
    const api = federationApiFixture({
      get: async () => ({ etag: '"v4"', value: provider }),
      list: async () => ({ items: [summary(provider)] }),
    });
    renderPage(api, ["identity_provider.read"]);

    expect(await screen.findByText("Enabled · unavailable")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Inspect and manage" }));
    await screen.findByLabelText("Workforce SSO federation controls");
    expect(screen.getAllByText("Enabled · unavailable")).toHaveLength(2);
  });

  it("removes loaded provider detail synchronously when the active tenant changes", async () => {
    const tenantAProvider = scopedOidcProvider(
      tenantId,
      providerId,
      bindingId,
      "Tenant A private configuration",
    );
    const tenantBProvider = scopedOidcProvider(
      foreignTenantId,
      foreignProviderId,
      foreignBindingId,
      "Tenant B federation",
    );
    const api = federationApiFixture({
      get: async (requestedTenantId) => ({
        etag: '"v4"',
        value:
          requestedTenantId === tenantId ? tenantAProvider : tenantBProvider,
      }),
      list: async (requestedTenantId) => ({
        items: [
          summary(
            requestedTenantId === tenantId ? tenantAProvider : tenantBProvider,
          ),
        ],
      }),
    });
    const page = renderSwitchablePage(api, [
      "identity_provider.read",
      "identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    expect(
      await screen.findByLabelText(
        "Tenant A private configuration federation controls",
      ),
    ).toBeVisible();
    fireEvent.click(
      screen.getByLabelText("Confirm permanent archival of this provider"),
    );
    expect(
      screen.getByLabelText("Confirm permanent archival of this provider"),
    ).toBeChecked();

    page.switchTenant(foreignTenantId);

    expect(
      screen.queryByLabelText(
        "Tenant A private configuration federation controls",
      ),
    ).not.toBeInTheDocument();
    expect(await screen.findByText("Tenant B federation")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Inspect and manage" }));
    expect(
      await screen.findByLabelText("Tenant B federation federation controls"),
    ).toBeVisible();
    expect(
      screen.getByLabelText("Confirm permanent archival of this provider"),
    ).not.toBeChecked();
  });

  it("ignores a provider detail response that completes after a tenant change", async () => {
    const tenantAProvider = scopedOidcProvider(
      tenantId,
      providerId,
      bindingId,
      "Tenant A delayed configuration",
    );
    const tenantBProvider = scopedOidcProvider(
      foreignTenantId,
      foreignProviderId,
      foreignBindingId,
      "Tenant B current federation",
    );
    let resolveTenantADetail:
      | ((value: { etag: string; value: TenantFederationAuthProvider }) => void)
      | undefined;
    const tenantADetail = new Promise<{
      etag: string;
      value: TenantFederationAuthProvider;
    }>((resolve) => {
      resolveTenantADetail = resolve;
    });
    const get = vi.fn<TenantFederationApi["get"]>(async (requestedTenantId) =>
      requestedTenantId === tenantId
        ? tenantADetail
        : { etag: '"v4"', value: tenantBProvider },
    );
    const api = federationApiFixture({
      get,
      list: async (requestedTenantId) => ({
        items: [
          summary(
            requestedTenantId === tenantId ? tenantAProvider : tenantBProvider,
          ),
        ],
      }),
    });
    const page = renderSwitchablePage(api, ["identity_provider.read"]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    expect(await screen.findByText("Loading provider detail…")).toBeVisible();
    page.switchTenant(foreignTenantId);
    expect(
      await screen.findByText("Tenant B current federation"),
    ).toBeVisible();

    await act(async () => {
      resolveTenantADetail?.({ etag: '"v4"', value: tenantAProvider });
      await tenantADetail;
    });

    expect(
      screen.queryByLabelText(
        "Tenant A delayed configuration federation controls",
      ),
    ).not.toBeInTheDocument();
    expect(get.mock.calls[0]?.[2]).toBeInstanceOf(AbortSignal);
    expect(get.mock.calls[0]?.[2]?.aborted).toBe(true);
  });

  it("does not let stale pagination overwrite a newer mutation refresh", async () => {
    const initialProvider = scopedOidcProvider(
      tenantId,
      providerId,
      bindingId,
      "Provider awaiting archive",
    );
    const freshProvider = scopedOidcProvider(
      tenantId,
      freshProviderId,
      freshBindingId,
      "Fresh inventory provider",
    );
    const staleProvider = scopedOidcProvider(
      tenantId,
      staleProviderId,
      staleBindingId,
      "Stale paginated provider",
    );
    let resolveStalePage:
      | ((value: {
          items: readonly TenantFederationAuthProviderSummary[];
        }) => void)
      | undefined;
    const stalePage = new Promise<{
      items: readonly TenantFederationAuthProviderSummary[];
    }>((resolve) => {
      resolveStalePage = resolve;
    });
    let rootLoads = 0;
    const list = vi.fn<TenantFederationApi["list"]>(
      async (_requestedTenantId, options) => {
        if (options?.after) return stalePage;
        rootLoads += 1;
        return rootLoads === 1
          ? { items: [summary(initialProvider)], nextCursor: "page-2" }
          : { items: [summary(freshProvider)] };
      },
    );
    const archive = vi.fn<TenantFederationApi["archive"]>(async () => '"v5"');
    renderPage(
      federationApiFixture({
        archive,
        get: async () => ({ etag: '"v4"', value: initialProvider }),
        list,
      }),
      ["identity_provider.read", "identity_provider.manage"],
    );

    expect(await screen.findByText("Provider awaiting archive")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Load more providers" }),
    );
    expect(
      await screen.findByRole("button", { name: "Loading more…" }),
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Inspect and manage" }));
    fireEvent.change(await screen.findByLabelText("Audit reason"), {
      target: { value: "archive and refresh inventory" },
    });
    fireEvent.click(
      screen.getByLabelText("Confirm permanent archival of this provider"),
    );
    fireEvent.click(screen.getByRole("button", { name: "Archive" }));

    expect(await screen.findByText("Fresh inventory provider")).toBeVisible();
    const paginationSignal = list.mock.calls.find(
      ([, options]) => options?.after === "page-2",
    )?.[1]?.signal;
    expect(paginationSignal?.aborted).toBe(true);
    await act(async () => {
      resolveStalePage?.({ items: [summary(staleProvider)] });
      await stalePage;
    });
    expect(
      screen.queryByText("Stale paginated provider"),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Fresh inventory provider")).toBeVisible();
  });

  it("keeps secret entry write-only and clears the controlled field after rotation", async () => {
    const replaceOidcClientSecret = vi.fn<
      TenantFederationApi["replaceOidcClientSecret"]
    >(async () => ({ etag: '"v5"', secretRevision: 3 }));
    const get = vi
      .fn<TenantFederationApi["get"]>()
      .mockResolvedValueOnce({ etag: '"v4"', value: oidcProvider() })
      .mockResolvedValueOnce({
        etag: '"v5"',
        value: oidcProvider({ clientSecretRevision: 3, version: 5 }),
      });
    const api = federationApiFixture({ get, replaceOidcClientSecret });
    renderPage(api, ["identity_provider.read", "identity_provider.manage"]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    const secret = await screen.findByLabelText("New client secret");
    fireEvent.change(secret, { target: { value: "one-time-browser-secret" } });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "scheduled rotation" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Rotate client secret" }),
    );

    await waitFor(() => expect(replaceOidcClientSecret).toHaveBeenCalledOnce());
    expect(replaceOidcClientSecret).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      "one-time-browser-secret",
      "scheduled rotation",
    );
    await waitFor(() => expect(secret).toHaveValue(""));
    expect(
      screen.queryByText("one-time-browser-secret"),
    ).not.toBeInTheDocument();
  });

  it("exposes explicit secret retirement without reading credential material", async () => {
    const clearOidcClientSecret = vi.fn<
      TenantFederationApi["clearOidcClientSecret"]
    >(async () => ({ etag: '"v5"', secretRevision: 3 }));
    const api = federationApiFixture({ clearOidcClientSecret });
    renderPage(api, ["identity_provider.read", "identity_provider.manage"]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    fireEvent.change(await screen.findByLabelText("Audit reason"), {
      target: { value: "retire compromised credential" },
    });
    const clearButton = screen.getByRole("button", {
      name: "Clear client secret",
    });
    expect(clearButton).toBeDisabled();
    fireEvent.click(clearButton);
    expect(clearOidcClientSecret).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByLabelText(
        "Confirm permanent retirement of this OIDC client secret",
      ),
    );
    fireEvent.click(clearButton);

    await waitFor(() => expect(clearOidcClientSecret).toHaveBeenCalledOnce());
    expect(clearOidcClientSecret).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      "retire compromised credential",
    );
  });

  it("requires an affirmative interlock before permanently archiving a provider", async () => {
    const archive = vi.fn<TenantFederationApi["archive"]>(async () => '"v5"');
    renderPage(federationApiFixture({ archive }), [
      "identity_provider.read",
      "identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    fireEvent.change(await screen.findByLabelText("Audit reason"), {
      target: { value: "retire obsolete tenant provider" },
    });
    const archiveButton = screen.getByRole("button", { name: "Archive" });
    expect(archiveButton).toBeDisabled();
    fireEvent.click(archiveButton);
    expect(archive).not.toHaveBeenCalled();

    fireEvent.click(
      screen.getByLabelText("Confirm permanent archival of this provider"),
    );
    fireEvent.click(archiveButton);

    await waitFor(() => expect(archive).toHaveBeenCalledOnce());
    expect(archive).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      "retire obsolete tenant provider",
    );
  });

  it("keeps offline_access coupled to refresh rotation in the create editor", async () => {
    renderPage(federationApiFixture(), [
      "identity_provider.read",
      "identity_provider.manage",
    ]);
    fireEvent.click(
      await screen.findByRole("button", { name: "Create provider" }),
    );
    const scopes = screen.getByLabelText("OIDC extra scopes");
    const refresh = screen.getByLabelText(
      "Allow bounded refresh-token rotation",
    );

    expect(scopes).toHaveValue("email, profile");
    fireEvent.click(refresh);
    expect(scopes).toHaveValue("email, profile, offline_access");
    fireEvent.click(refresh);
    expect(scopes).toHaveValue("email, profile");
  });

  it("edits OIDC policy while keeping the post-logout redirect deployment-managed", async () => {
    const update = vi.fn<TenantFederationApi["update"]>(
      async (_csrf, _tenant, _provider, _etag, input) => ({
        etag: '"v5"',
        value: oidcProvider({ version: 5, update: input }),
      }),
    );
    renderPage(federationApiFixture({ update }), [
      "identity_provider.read",
      "identity_provider.manage",
    ]);
    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    fireEvent.change(await screen.findByLabelText("JIT user lifecycle"), {
      target: { value: "create" },
    });
    fireEvent.change(screen.getByLabelText("No mapping match"), {
      target: { value: "provider_access_only" },
    });
    fireEvent.change(screen.getByLabelText("HTTPS issuer"), {
      target: { value: "https://login.example.com/realms/workforce" },
    });
    fireEvent.change(screen.getByLabelText("Client ID"), {
      target: { value: "periapsis-browser" },
    });
    const postLogoutRedirect = screen.getByLabelText(
      "Post-logout redirect URI",
    );
    expect(postLogoutRedirect).toHaveAttribute("readonly");
    expect(postLogoutRedirect).toHaveValue(
      `${globalThis.location.origin}/signed-out`,
    );
    fireEvent.change(screen.getByLabelText("OIDC extra scopes"), {
      target: { value: "profile, email, roles" },
    });
    fireEvent.click(
      screen.getByLabelText("Allow bounded refresh-token rotation"),
    );
    expect(screen.getByLabelText("OIDC extra scopes")).toHaveValue(
      "profile, email, roles",
    );
    fireEvent.click(
      screen.getByLabelText("Fetch profile claims from validated UserInfo"),
    );
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "enable OIDC JIT and exact mapping" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save provider" }));

    await waitFor(() => expect(update).toHaveBeenCalledOnce());
    expect(update).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      {
        kind: "oidc",
        displayName: "Workforce SSO",
        description: "Tenant workforce",
        enabled: false,
        jitMode: "create",
        noMatchPolicy: "provider_access_only",
        reason: "enable OIDC JIT and exact mapping",
        configuration: {
          issuer: "https://login.example.com/realms/workforce",
          clientId: "periapsis-browser",
          postLogoutRedirectUri: `${globalThis.location.origin}/signed-out`,
          extraScopes: ["profile", "email", "roles"],
          allowRefreshToken: false,
          useUserInfo: true,
        },
      },
    );
  });

  it("edits SAML protocol policy and immutable subject fields without material input", async () => {
    const provider = samlProvider();
    const update = vi.fn<TenantFederationApi["update"]>(async () => ({
      etag: '"v5"',
      value: samlProvider({ version: 5 }),
    }));
    renderPage(
      federationApiFixture({
        get: async () => ({ etag: '"v4"', value: provider }),
        list: async () => ({ items: [summary(provider)] }),
        update,
      }),
      ["identity_provider.read", "identity_provider.manage"],
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    fireEvent.change(await screen.findByLabelText("Stable SAML subject"), {
      target: { value: "immutable_attribute" },
    });
    fireEvent.change(screen.getByLabelText("Subject attribute Name"), {
      target: { value: "urn:example:immutable-id" },
    });
    fireEvent.change(screen.getByLabelText("Subject attribute NameFormat"), {
      target: {
        value: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
      },
    });
    fireEvent.change(screen.getByLabelText("Required SAML signature"), {
      target: { value: "signed_response" },
    });
    const clockSkew = screen.getByLabelText("Clock skew seconds");
    const maximumAuthenticationAge = screen.getByLabelText(
      "Maximum authentication age seconds",
    );
    expect(clockSkew).toHaveAttribute("max", "300");
    expect(maximumAuthenticationAge).toHaveAttribute("max", "86400");
    fireEvent.change(clockSkew, {
      target: { value: "45" },
    });
    fireEvent.change(maximumAuthenticationAge, {
      target: { value: "1800" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "pin immutable SAML subject" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save provider" }));

    await waitFor(() => expect(update).toHaveBeenCalledOnce());
    expect(update.mock.calls[0]?.[4]).toMatchObject({
      kind: "saml",
      jitMode: "disabled",
      noMatchPolicy: "deny",
      reason: "pin immutable SAML subject",
      configuration: {
        expectedEntityId: "https://id.example.com/saml/metadata",
        signaturePolicy: "signed_response",
        encryptionPolicy: "disabled",
        subjectSource: "immutable_attribute",
        subjectAttributeName: "urn:example:immutable-id",
        subjectAttributeNameFormat:
          "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
        clockSkewSeconds: 45,
        maxAuthenticationAgeSeconds: 1800,
      },
    });
    expect(
      screen.queryByRole("textbox", { name: /private key/iu }),
    ).not.toBeInTheDocument();
  });

  it("creates SAML policy without exposing metadata, certificate, or key inputs", async () => {
    const create = vi.fn<TenantFederationApi["create"]>(async () => ({
      etag: '"v4"',
      location: `/api/v1/tenants/${tenantId}/federated-auth-providers/${providerId}`,
      value: oidcProvider(),
    }));
    renderPage(federationApiFixture({ create }), [
      "identity_provider.read",
      "identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create provider" }),
    );
    fireEvent.change(screen.getByLabelText("Protocol"), {
      target: { value: "saml" },
    });
    expect(screen.getByLabelText("Clock skew seconds")).toHaveAttribute(
      "max",
      "300",
    );
    expect(
      screen.getByLabelText("Maximum authentication age seconds"),
    ).toHaveAttribute("max", "86400");
    expect(screen.getByText("Trust remains write-only")).toBeVisible();
    expect(screen.queryByLabelText(/metadata/iu)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/private key/iu)).not.toBeInTheDocument();
  });

  it("keeps Unicode code-point boundaries reachable in the mounted create form", async () => {
    const create = vi.fn<TenantFederationApi["create"]>(async () => ({
      etag: '"v4"',
      location: `/api/v1/tenants/${tenantId}/federated-auth-providers/${providerId}`,
      value: oidcProvider(),
    }));
    renderPage(federationApiFixture({ create }), [
      "identity_provider.read",
      "identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create provider" }),
    );
    const displayName = "\u{1f680}".repeat(120);
    const description = "\u{1f680}".repeat(1000);
    const reason = "\u{1f680}".repeat(500);
    const displayNameInput = screen.getByLabelText("Display name");
    const descriptionInput = screen.getByLabelText("Description");
    const reasonInput = screen.getByLabelText("Audit reason");
    expect(displayNameInput).toHaveAttribute("maxlength", "240");
    expect(descriptionInput).toHaveAttribute("maxlength", "2000");
    expect(reasonInput).toHaveAttribute("maxlength", "1000");
    fireEvent.change(displayNameInput, { target: { value: displayName } });
    fireEvent.change(descriptionInput, { target: { value: description } });
    fireEvent.change(reasonInput, { target: { value: reason } });
    fireEvent.change(screen.getByLabelText("Provider key"), {
      target: { value: "unicode_boundary" },
    });
    fireEvent.change(screen.getByLabelText("Login key"), {
      target: { value: "unicode-boundary" },
    });
    fireEvent.change(screen.getByLabelText("HTTPS issuer"), {
      target: { value: "https://id.example.com" },
    });
    fireEvent.change(screen.getByLabelText("Client ID"), {
      target: { value: "periapsis-unicode-boundary" },
    });

    fireEvent.submit(
      screen.getByRole("form", { name: "Create federated identity provider" }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]?.[3]).toMatchObject({
      displayName,
      description,
      reason,
    });
  });

  it("reuses the create idempotency key after an ambiguous transport failure", async () => {
    const create = vi
      .fn<TenantFederationApi["create"]>()
      .mockRejectedValueOnce(new TypeError("response was lost after commit"))
      .mockResolvedValueOnce({
        etag: '"v4"',
        location: `/api/v1/tenants/${tenantId}/federated-auth-providers/${providerId}`,
        value: oidcProvider(),
      });
    renderPage(federationApiFixture({ create }), [
      "identity_provider.read",
      "identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create provider" }),
    );
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Retry-safe workforce" },
    });
    fireEvent.change(screen.getByLabelText("Provider key"), {
      target: { value: "retry_safe_oidc" },
    });
    fireEvent.change(screen.getByLabelText("Login key"), {
      target: { value: "retry-safe" },
    });
    fireEvent.change(screen.getByLabelText("HTTPS issuer"), {
      target: { value: "https://id.example.com" },
    });
    fireEvent.change(screen.getByLabelText("Client ID"), {
      target: { value: "periapsis-retry" },
    });
    const postLogoutRedirect = screen.getByLabelText(
      "Post-logout redirect URI",
    );
    expect(postLogoutRedirect).toHaveAttribute("readonly");
    expect(postLogoutRedirect).toHaveValue(
      `${globalThis.location.origin}/signed-out`,
    );
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "create retry-safe provider" },
    });

    fireEvent.click(
      screen.getByRole("button", { name: "Create disabled provider" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    const firstIdempotencyKey = create.mock.calls[0]?.[2];
    expect(create.mock.calls[0]?.[3]).toMatchObject({
      kind: "oidc",
      configuration: {
        postLogoutRedirectUri: `${globalThis.location.origin}/signed-out`,
      },
    });
    expect(firstIdempotencyKey).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create disabled provider" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(create.mock.calls[1]?.[2]).toBe(firstIdempotencyKey);
  });

  it("replaces tenant SAML metadata write-only with an explicit trust-reset ceremony", async () => {
    const provider = samlProvider();
    const replaceSamlMetadata = vi.fn<
      TenantFederationApi["replaceSamlMetadata"]
    >(async () => ({ etag: '"v5"', materialRevision: 3 }));
    const get = vi
      .fn<TenantFederationApi["get"]>()
      .mockResolvedValueOnce({ etag: '"v4"', value: provider })
      .mockResolvedValueOnce({
        etag: '"v5"',
        value: samlProvider({ metadataRevision: 3, version: 5 }),
      });
    renderPage(
      federationApiFixture({
        get,
        list: async () => ({ items: [summary(provider)] }),
        replaceSamlMetadata,
      }),
      ["identity_provider.read", "identity_provider.manage"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    expect(await screen.findByText("Revision 2")).toBeVisible();
    expect(
      screen.getAllByText(
        "https://soc.example.com/api/v1/auth/federated/saml/acme/workforce/metadata",
      ),
    ).toHaveLength(2);
    expect(
      screen.queryByRole("textbox", { name: /private key/iu }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: /certificate/iu }),
    ).not.toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Metadata source"), {
      target: { value: "xml" },
    });
    fireEvent.change(screen.getByLabelText("Write-only IdP metadata XML"), {
      target: { value: "<EntityDescriptor/>" },
    });
    fireEvent.click(
      screen.getByLabelText(/Approve a verified signing-trust reset/iu),
    );
    fireEvent.change(screen.getByLabelText("SAML material audit reason"), {
      target: { value: "verified out of band" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Replace IdP metadata" }),
    );

    await waitFor(() => expect(replaceSamlMetadata).toHaveBeenCalledOnce());
    expect(replaceSamlMetadata).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      {
        source: "xml",
        metadataXml: "<EntityDescriptor/>",
        approveTrustReset: true,
        reason: "verified out of band",
      },
    );
    await waitFor(() =>
      expect(
        screen.queryByDisplayValue("<EntityDescriptor/>"),
      ).not.toBeInTheDocument(),
    );
  });

  it("generates and clears tenant SAML credentials without accepting key material", async () => {
    const provider = samlProvider();
    const replaceSamlSpCredential = vi.fn<
      TenantFederationApi["replaceSamlSpCredential"]
    >(async () => ({ etag: '"v5"', materialRevision: 3 }));
    const clearSamlSpCredential = vi.fn<
      TenantFederationApi["clearSamlSpCredential"]
    >(async () => ({ etag: '"v5"', materialRevision: 3 }));
    renderPage(
      federationApiFixture({
        clearSamlSpCredential,
        get: async () => ({ etag: '"v4"', value: provider }),
        list: async () => ({ items: [summary(provider)] }),
        replaceSamlSpCredential,
      }),
      ["identity_provider.read", "identity_provider.manage"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    fireEvent.change(
      await screen.findByLabelText("SAML material audit reason"),
      { target: { value: "scheduled server rotation" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Generate SP credential" }),
    );
    await waitFor(() => expect(replaceSamlSpCredential).toHaveBeenCalledOnce());
    expect(replaceSamlSpCredential).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      "scheduled server rotation",
    );
    expect(
      screen.queryByRole("textbox", { name: /private key/iu }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("textbox", { name: /certificate/iu }),
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("SAML material audit reason"), {
      target: { value: "retire compromised credential" },
    });
    const clearButton = screen.getByRole("button", {
      name: "Clear SP credential",
    });
    expect(clearButton).toBeDisabled();
    fireEvent.click(clearButton);
    expect(clearSamlSpCredential).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByLabelText(
        "Confirm permanent retirement of this SAML SP credential",
      ),
    );
    fireEvent.click(clearButton);
    await waitFor(() => expect(clearSamlSpCredential).toHaveBeenCalledOnce());
    expect(clearSamlSpCredential).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      "retire compromised credential",
    );
  });

  it("blocks SP credential rotation while either SAML execution boundary is live", async () => {
    const provider = samlProvider({ enabled: true });
    renderPage(
      federationApiFixture({
        get: async () => ({ etag: '"v4"', value: provider }),
        list: async () => ({ items: [summary(provider)] }),
      }),
      ["identity_provider.read", "identity_provider.manage"],
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    fireEvent.change(
      await screen.findByLabelText("SAML material audit reason"),
      { target: { value: "unsafe live rotation" } },
    );
    expect(
      screen.getByRole("button", { name: "Generate SP credential" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Clear SP credential" }),
    ).toBeDisabled();
  });

  it("hydrates OIDC mapping and assurance before editing and supports atomic zero-rule revocation", async () => {
    const getMappingPolicy = vi.fn<TenantFederationApi["getMappingPolicy"]>(
      async () => ({
        etag: '"v4"',
        mappingRevision: 2,
        value: oidcMappingPolicy(),
      }),
    );
    const getAssurancePolicy = vi.fn<TenantFederationApi["getAssurancePolicy"]>(
      async () => ({
        assurancePolicyRevision: 2,
        etag: '"v4"',
        value: oidcAssurancePolicy(),
      }),
    );
    const replaceMappingPolicy = vi.fn<
      TenantFederationApi["replaceMappingPolicy"]
    >(async () => ({ etag: '"v5"', revision: 3 }));
    const api = federationApiFixture({
      getAssurancePolicy,
      getMappingPolicy,
      replaceMappingPolicy,
    });
    renderPage(api, [
      "identity_provider.read",
      "identity_mapping.read",
      "identity_mapping.manage",
      "identity_policy.read",
      "identity_policy.manage",
      "role.grant",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    const mappingEditor = await screen.findByLabelText<HTMLTextAreaElement>(
      "Mapping policy JSON",
    );
    await waitFor(() => expect(mappingEditor).toBeEnabled());
    expect(getMappingPolicy).toHaveBeenCalledWith(
      tenantId,
      providerId,
      { kind: "oidc", useUserInfo: false },
      expect.any(AbortSignal),
    );
    expect(
      screen.getByText(/UserInfo extraction must be absent/u),
    ).toBeVisible();
    const assuranceEditor = await screen.findByLabelText<HTMLTextAreaElement>(
      "Assurance trust policy JSON",
    );
    await waitFor(() => expect(assuranceEditor).toBeEnabled());
    expect(getAssurancePolicy).toHaveBeenCalledWith(
      tenantId,
      providerId,
      expect.any(AbortSignal),
    );
    expect(JSON.parse(mappingEditor.value)).toEqual({
      kind: "oidc",
      oidcClaimRules: oidcMappingPolicy().oidcClaimRules,
      rules: oidcMappingPolicy().rules,
    });
    expect(JSON.parse(assuranceEditor.value)).toEqual({
      kind: "oidc",
      rules: oidcAssurancePolicy().rules,
    });

    const revoked = {
      kind: "oidc",
      oidcClaimRules: oidcMappingPolicy().oidcClaimRules,
      rules: [],
    };
    fireEvent.change(mappingEditor, {
      target: { value: JSON.stringify(revoked) },
    });
    fireEvent.change(screen.getByLabelText("Mapping policy audit reason"), {
      target: { value: "revoke every federated role assignment" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Replace mapping policy" }),
    );
    await waitFor(() => expect(replaceMappingPolicy).toHaveBeenCalledOnce());
    expect(replaceMappingPolicy).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      tenantId,
      providerId,
      '"v4"',
      {
        ...revoked,
        reason: "revoke every federated role assignment",
      },
      { kind: "oidc", useUserInfo: false },
    );
    await waitFor(() =>
      expect(getMappingPolicy.mock.calls.length).toBeGreaterThan(1),
    );
  });

  it("hydrates SAML Name/NameFormat, exact group-role-team targets, and assurance rules", async () => {
    const provider = samlProvider();
    const getMappingPolicy = vi.fn<TenantFederationApi["getMappingPolicy"]>(
      async () => ({
        etag: '"v4"',
        mappingRevision: 7,
        value: samlMappingPolicy(),
      }),
    );
    const getAssurancePolicy = vi.fn<TenantFederationApi["getAssurancePolicy"]>(
      async () => ({
        assurancePolicyRevision: 5,
        etag: '"v4"',
        value: samlAssurancePolicy(),
      }),
    );
    renderPage(
      federationApiFixture({
        get: async () => ({ etag: '"v4"', value: provider }),
        getAssurancePolicy,
        getMappingPolicy,
        list: async () => ({ items: [summary(provider)] }),
      }),
      [
        "identity_provider.read",
        "identity_mapping.read",
        "identity_policy.read",
      ],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    const mappingEditor = await screen.findByLabelText<HTMLTextAreaElement>(
      "Mapping policy JSON",
    );
    const assuranceEditor = await screen.findByLabelText<HTMLTextAreaElement>(
      "Assurance trust policy JSON",
    );
    await waitFor(() => {
      expect(mappingEditor).toBeEnabled();
      expect(assuranceEditor).toBeEnabled();
    });
    const mapping = JSON.parse(mappingEditor.value);
    expect(mapping.kind).toBe("saml");
    expect(mapping.samlAttributeRules).toEqual(
      samlMappingPolicy().samlAttributeRules,
    );
    expect(mapping.rules[0]).toMatchObject({
      tenantSecurityGroupId: securityGroupId,
      roleIds: [roleId],
      operatorTeamId,
      operatorTeamAssignmentEpochId: assignmentEpochId,
    });
    expect(JSON.parse(assuranceEditor.value)).toEqual({
      kind: "saml",
      rules: samlAssurancePolicy().rules,
    });
    expect(mappingEditor).toHaveAttribute("readonly");
    expect(assuranceEditor).toHaveAttribute("readonly");
  });

  it("does not expose mapping mutation without role.grant even when identity_mapping.manage is present", async () => {
    renderPage(
      federationApiFixture({
        getMappingPolicy: async () => ({
          etag: '"v4"',
          mappingRevision: 2,
          value: oidcMappingPolicy(),
        }),
      }),
      [
        "identity_provider.read",
        "identity_mapping.read",
        "identity_mapping.manage",
      ],
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Inspect and manage" }),
    );
    expect(await screen.findByLabelText("Mapping policy JSON")).toHaveAttribute(
      "readonly",
    );
    expect(
      screen.queryByRole("button", { name: "Replace mapping policy" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(
        /requires both identity_mapping\.manage and role\.grant/u,
      ),
    ).toBeVisible();
  });
});

function renderPage(
  federationApi: TenantFederationApi,
  permissions: readonly TenantPermissionKeyView[],
): void {
  const api = createPhaseTwoApi({
    getTenantAuthority: async () => authorityFixture(permissions),
  });
  render(
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: {
          ...sessionFixture,
          absoluteExpiresAt: "2099-08-24T12:00:00Z",
          activeTenantId: tenantId,
          idleExpiresAt: "2099-08-23T12:00:00Z",
        },
        updateSession: vi.fn(),
      }}
    >
      <TenantAuthorityProvider>
        <TenantFederationPage api={federationApi} />
      </TenantAuthorityProvider>
    </SessionContext.Provider>,
  );
}

function renderSwitchablePage(
  federationApi: TenantFederationApi,
  permissions: readonly TenantPermissionKeyView[],
): { switchTenant: (nextTenantId: string) => void } {
  const api = createPhaseTwoApi({
    getTenantAuthority: async (requestedTenantId) =>
      authorityFixture(permissions, requestedTenantId),
  });
  const clearSession = vi.fn();
  const refreshMemberships = vi.fn();
  const updateSession = vi.fn();
  const view = (activeTenantId: string) => (
    <SessionContext.Provider
      value={{
        api,
        clearSession,
        membershipRevision: 0,
        refreshMemberships,
        session: {
          ...sessionFixture,
          absoluteExpiresAt: "2099-08-24T12:00:00Z",
          activeTenantId,
          idleExpiresAt: "2099-08-23T12:00:00Z",
        },
        updateSession,
      }}
    >
      <TenantAuthorityProvider>
        <TenantFederationPage api={federationApi} />
      </TenantAuthorityProvider>
    </SessionContext.Provider>
  );
  const rendered = render(view(tenantId));
  return {
    switchTenant(nextTenantId) {
      rendered.rerender(view(nextTenantId));
    },
  };
}

function federationApiFixture(
  overrides: Partial<TenantFederationApi> = {},
): TenantFederationApi {
  const provider = oidcProvider();
  return {
    archive: async () => '"v5"',
    clearOidcClientSecret: async () => ({ etag: '"v5"', secretRevision: 3 }),
    create: async () => ({
      etag: '"v4"',
      location: `/api/v1/tenants/${tenantId}/federated-auth-providers/${providerId}`,
      value: provider,
    }),
    get: async () => ({ etag: '"v4"', value: provider }),
    getAssurancePolicy: async () => {
      throw new Error("unexpected assurance-policy lookup");
    },
    getMappingPolicy: async () => {
      throw new Error("unexpected mapping-policy lookup");
    },
    list: async () => ({ items: [summary(provider)] }),
    refreshOidcTrustDocuments: async () => {
      throw new Error("unexpected OIDC trust refresh");
    },
    replaceOidcClientSecret: async () => ({ etag: '"v5"', secretRevision: 3 }),
    replaceAssurancePolicy: async () => {
      throw new Error("unexpected assurance-policy replacement");
    },
    replaceMappingPolicy: async () => {
      throw new Error("unexpected mapping-policy replacement");
    },
    replaceSamlMetadata: async () => ({
      etag: '"v5"',
      materialRevision: 3,
    }),
    replaceSamlSpCredential: async () => ({
      etag: '"v5"',
      materialRevision: 3,
    }),
    clearSamlSpCredential: async () => ({
      etag: '"v5"',
      materialRevision: 3,
    }),
    update: async () => ({ etag: '"v5"', value: { ...provider, version: 5 } }),
    ...overrides,
  };
}

function samlProvider(
  overrides: {
    enabled?: boolean;
    metadataRevision?: number;
    spKeyPresent?: boolean;
    spKeyRevision?: number;
    version?: number;
  } = {},
): TenantFederationAuthProvider {
  const enabled = overrides.enabled ?? false;
  return {
    archivedAt: null,
    assurancePolicyRevision: 1,
    binding: {
      enabled,
      id: bindingId,
      loginKey: "workforce",
      updatedAt: "2026-08-30T19:00:00Z",
      version: 4,
    },
    configuration: {
      acsUrl: "https://soc.example.com/api/v1/auth/federated/saml/acs",
      clockSkewSeconds: 120,
      encryptionPolicy: "disabled",
      expectedEntityId: "https://id.example.com/saml/metadata",
      maxAuthenticationAgeSeconds: 28800,
      metadataRevision: overrides.metadataRevision ?? 2,
      redirectSignatureAlgorithm:
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      requestedAuthnContexts: [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      signaturePolicy: "both",
      singleLogoutConfigured: false,
      spEntityId:
        "https://soc.example.com/api/v1/auth/federated/saml/acme/workforce/metadata",
      spKeyPresent: overrides.spKeyPresent ?? true,
      spKeyRevision: overrides.spKeyRevision ?? 2,
      subjectAttributeName: null,
      subjectAttributeNameFormat: null,
      subjectSource: "persistent_nameid",
    },
    configurationRevision: 2,
    configured: true,
    createdAt: "2026-08-30T18:00:00Z",
    description: "Tenant workforce SAML",
    displayName: "Workforce SAML",
    enabled,
    id: providerId,
    jitMode: "disabled",
    key: "workforce_saml",
    kind: "saml",
    noMatchPolicy: "deny",
    planRevision: 1,
    securityRevision: 2,
    tenantId,
    updatedAt: "2026-08-30T19:00:00Z",
    version: overrides.version ?? 4,
  };
}

function authorityFixture(
  permissions: readonly TenantPermissionKeyView[],
  scopeTenantId: string = tenantId,
): TenantAuthorityView {
  return {
    delegationCeiling: [],
    evaluatedAt: "2026-08-30T19:00:00Z",
    legacyMembershipRole: "tenant_admin",
    membershipId: "0198c97d-cf4f-7000-8000-000000000020",
    membershipStatus: "active",
    operatorTeamRelationships: [],
    permissions: permissions.map((permissionKey) => ({
      permissionKey,
      scope: "tenant",
    })),
    roleGrants: [],
    tenantId: scopeTenantId,
    userId: sessionFixture.user.id,
  };
}

function scopedOidcProvider(
  scopeTenantId: string,
  scopeProviderId: string,
  scopeBindingId: string,
  displayName: string,
): TenantFederationAuthProvider {
  const provider = oidcProvider();
  return {
    ...provider,
    binding: {
      ...provider.binding,
      id: scopeBindingId,
      loginKey: `login_${scopeProviderId.slice(-4)}`,
    },
    description: `${displayName} tenant-only description`,
    displayName,
    id: scopeProviderId,
    key: `provider_${scopeProviderId.slice(-4)}`,
    tenantId: scopeTenantId,
  };
}

function oidcProvider(
  overrides: {
    clientSecretRevision?: number;
    update?: TenantFederationAuthProviderUpdateRequest;
    version?: number;
  } = {},
): TenantFederationAuthProvider {
  const update = overrides.update;
  return {
    archivedAt: null,
    assurancePolicyRevision: 1,
    binding: {
      enabled: false,
      id: bindingId,
      loginKey: "workforce",
      updatedAt: "2026-08-30T19:00:00Z",
      version: 4,
    },
    configuration: {
      allowRefreshToken: true,
      clientId: "periapsis-tenant",
      clientSecretPresent: true,
      clientSecretRevision: overrides.clientSecretRevision ?? 2,
      discoveryRevision: 2,
      extraScopes: ["email", "profile", "offline_access"],
      issuer: "https://id.example.com",
      jwksRevision: 2,
      postLogoutRedirectUri: "https://soc.example.com/signed-out",
      redirectUri:
        "https://soc.example.com/api/v1/auth/federated/oidc/callback",
      useUserInfo: false,
    },
    configurationRevision: 2,
    configured: true,
    createdAt: "2026-08-30T18:00:00Z",
    description: update?.description ?? "Tenant workforce",
    displayName: update?.displayName ?? "Workforce SSO",
    enabled: update?.enabled ?? false,
    id: providerId,
    jitMode: update?.jitMode ?? "disabled",
    key: "workforce_oidc",
    kind: "oidc",
    noMatchPolicy: update?.noMatchPolicy ?? "deny",
    planRevision: 1,
    securityRevision: 2,
    tenantId,
    updatedAt: "2026-08-30T19:00:00Z",
    version: overrides.version ?? 4,
  };
}

function summary(
  provider: TenantFederationAuthProvider,
): TenantFederationAuthProviderSummary {
  return {
    archivedAt: provider.archivedAt,
    binding: provider.binding,
    configured: provider.configured,
    createdAt: provider.createdAt,
    description: provider.description,
    displayName: provider.displayName,
    enabled: provider.enabled,
    id: provider.id,
    key: provider.key,
    kind: provider.kind,
    tenantId: provider.tenantId,
    updatedAt: provider.updatedAt,
    version: provider.version,
  };
}

function oidcMappingPolicy(): Extract<
  TenantFederationMappingPolicy,
  { kind: "oidc" }
> {
  return {
    tenantId,
    providerId,
    kind: "oidc",
    providerVersion: 4,
    mappingRevision: 2,
    oidcClaimRules: [
      {
        source: "id_token",
        kind: "profile",
        claimName: "preferred_username",
        profileField: "username",
        required: true,
      },
      {
        source: "id_token",
        kind: "groups",
        claimName: "roles",
        profileField: null,
        required: false,
      },
      {
        source: "id_token",
        kind: "amr",
        claimName: "amr",
        profileField: null,
        required: false,
      },
    ],
    rules: [mappingRule("roles")],
  };
}

function samlMappingPolicy(): Extract<
  TenantFederationMappingPolicy,
  { kind: "saml" }
> {
  return {
    tenantId,
    providerId,
    kind: "saml",
    providerVersion: 4,
    mappingRevision: 7,
    samlAttributeRules: [
      {
        kind: "profile",
        attributeName: "uid",
        attributeNameFormat:
          "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        profileField: "username",
        required: true,
      },
      {
        kind: "groups",
        attributeName: "groups",
        attributeNameFormat:
          "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
        profileField: null,
        required: false,
      },
    ],
    rules: [mappingRule(null)],
  };
}

function mappingRule(claimName: string | null) {
  return {
    ruleId: mappingRuleId,
    priority: 10,
    matcherKind: "group_equals" as const,
    claimName,
    matcherValue: "soc-analysts",
    reconciliationMode: "authoritative" as const,
    tenantSecurityGroupId: securityGroupId,
    roleIds: [roleId],
    operatorTeamId,
    operatorTeamAssignmentEpochId: assignmentEpochId,
    enabled: true,
  };
}

function oidcAssurancePolicy(): TenantFederationAssurancePolicy {
  return {
    tenantId,
    providerId,
    kind: "oidc",
    providerVersion: 4,
    assurancePolicyRevision: 2,
    rules: [
      {
        ruleId: assuranceRuleId,
        enabled: true,
        level: "mfa",
        exactValue: null,
        requiredValues: ["otp", "pwd"],
        maximumAuthenticationAgeSeconds: 900,
      },
    ],
  };
}

function samlAssurancePolicy(): TenantFederationAssurancePolicy {
  return {
    tenantId,
    providerId,
    kind: "saml",
    providerVersion: 4,
    assurancePolicyRevision: 5,
    rules: [
      {
        ruleId: assuranceRuleId,
        enabled: true,
        level: "mfa",
        exactValue: "urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken",
        maximumAuthenticationAgeSeconds: 900,
      },
    ],
  };
}
