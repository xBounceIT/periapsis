import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type PlatformAuthProviderAccountView,
  type PlatformAuthProviderSummaryView,
  type PlatformAuthProviderView,
  type SessionView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { PlatformAuthProvidersPage } from "./platform-auth-providers";
import { createLdapProviderDraft } from "./ldap-provider-model";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const accountId = "0198c97d-cf4f-7000-8000-000000000089";
const publicOrigin = "https://soc.example.com";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("platform-global LDAP administration", () => {
  it("creates LDAP disabled with existing-identity policy", async () => {
    const createPlatformAuthProvider = vi.fn<
      PhaseTwoApi["createPlatformAuthProvider"]
    >(async (_csrf, _key, _reason, input) => {
      if (input.kind !== "ldap") throw new Error("Expected LDAP create input");
      return {
        etag: '"v1"',
        location: `/api/v1/platform/auth-providers/${providerId}`,
        value: ldapProviderFixture({
          configuration: input.configuration,
          displayName: input.displayName,
          key: input.key,
          version: 1,
        }),
      };
    });
    renderPage({ createPlatformAuthProvider }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create staged provider" }),
    );
    fireEvent.click(screen.getByRole("button", { name: /LDAP/ }));
    fireEvent.change(screen.getByLabelText("Key"), {
      target: { value: "workforce_ldap" },
    });
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Workforce LDAP" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Stage global LDAP authority" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create disabled provider" }),
    );

    await waitFor(() => expect(createPlatformAuthProvider).toHaveBeenCalled());
    const input = createPlatformAuthProvider.mock.calls[0]?.[3];
    expect(input).toMatchObject({
      kind: "ldap",
      configuration: {
        jitMode: "existing_identity",
        noMatchPolicy: "deny",
      },
    });
  });

  it("shows only LDAP-native administration and runs redacted diagnostics", async () => {
    const provider = ldapProviderFixture();
    const testPlatformLdapProvider = vi.fn<
      PhaseTwoApi["testPlatformLdapProvider"]
    >(async () => ({
      attributes: [],
      category: "ok",
      durationMs: 12,
      endpointPriority: 1,
      kind: "connection",
      outcome: "success",
      testId: "0198c97d-cf4f-7000-8000-000000000091",
    }));
    renderPage(
      {
        getPlatformAuthProvider: async () => ({
          etag: '"v7"',
          value: provider,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(provider)],
        }),
        testPlatformLdapProvider,
      },
      [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
        "platform.identity_provider.test",
        "platform.identity_policy.manage",
        "platform.identity_binding.read",
        "platform.identity_account.read",
      ],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Inspect Workforce LDAP/i }),
    );
    expect(await screen.findByText("LDAP administration")).toBeVisible();
    expect(screen.getByText("Existing identities only")).toBeVisible();
    expect(screen.queryByText("Tenant bindings")).not.toBeInTheDocument();
    expect(
      screen.queryByText("Linked platform accounts"),
    ).not.toBeInTheDocument();

    fireEvent.change(screen.getAllByLabelText("Audit reason").at(-2)!, {
      target: { value: "Validate directory connection" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Run live test" }));
    expect(await screen.findByText("Test succeeded")).toBeVisible();
    expect(testPlatformLdapProvider).toHaveBeenCalledWith(
      sessionFixture.csrfToken,
      providerId,
      "Validate directory connection",
      { kind: "connection" },
      expect.any(AbortSignal),
    );
  });
});

describe("PlatformAuthProvidersPage", () => {
  it("exposes binding-only authority without listing provider metadata", async () => {
    const listPlatformAuthProviders = vi.fn<
      PhaseTwoApi["listPlatformAuthProviders"]
    >(async () => ({ items: [] }));
    const listPlatformAuthProviderTenantBindings = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderTenantBindings"]
    >(async () => ({ items: [] }));
    renderPage(
      {
        listPlatformAuthProviderTenantBindings,
        listPlatformAuthProviders,
      },
      ["platform.identity_binding.read", "platform.identity_binding.manage"],
    );

    expect(
      screen.getByRole("heading", { name: "Tenant bindings by provider ID" }),
    ).toBeVisible();
    expect(screen.getByText("Binding-only authority")).toBeVisible();
    expect(listPlatformAuthProviders).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Platform provider ID"), {
      target: { value: "not-a-provider-id" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Open tenant bindings" }),
    );
    expect(
      screen.getByText("Platform provider ID must be a canonical UUIDv7."),
    ).toBeVisible();
    expect(listPlatformAuthProviderTenantBindings).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Platform provider ID"), {
      target: { value: providerId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Open tenant bindings" }),
    );

    expect(
      await screen.findByText("No tenant bindings recorded."),
    ).toBeVisible();
    expect(listPlatformAuthProviderTenantBindings).toHaveBeenCalledWith(
      providerId,
      expect.objectContaining({ includeArchived: true }),
    );
    expect(
      screen.getByRole("button", { name: "Create tenant binding" }),
    ).toBeVisible();
  });

  it("exposes account-only authority without listing provider metadata", async () => {
    const account = platformAccountFixture();
    const listPlatformAuthProviders = vi.fn<
      PhaseTwoApi["listPlatformAuthProviders"]
    >(async () => ({ items: [] }));
    const listPlatformAuthProviderAccounts = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderAccounts"]
    >(async () => ({ items: [account] }));
    const listPlatformAuthProviderTenantBindings = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderTenantBindings"]
    >(async () => ({ items: [] }));
    const prelinkPlatformAuthProviderAccount = vi.fn<
      PhaseTwoApi["prelinkPlatformAuthProviderAccount"]
    >(async () => ({
      etag: '"v3-u1"',
      location: `/api/v1/platform/auth-providers/${providerId}/accounts/${account.id}`,
      value: account,
    }));
    renderPage(
      {
        listPlatformAuthProviderAccounts,
        listPlatformAuthProviderTenantBindings,
        listPlatformAuthProviders,
        prelinkPlatformAuthProviderAccount,
      },
      ["platform.identity_account.read", "platform.identity_account.manage"],
    );

    expect(
      screen.getByRole("heading", {
        name: "Linked platform accounts by provider ID",
      }),
    ).toBeVisible();
    expect(screen.getByText("Account-only authority")).toBeVisible();
    expect(listPlatformAuthProviders).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Platform provider ID"), {
      target: { value: providerId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Open account register" }),
    );

    expect(await screen.findByText("Ada Account")).toBeVisible();
    expect(listPlatformAuthProviderAccounts).toHaveBeenCalledWith(
      providerId,
      expect.objectContaining({ includeRetired: true }),
    );
    expect(listPlatformAuthProviderTenantBindings).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Prelink account" }));
    fireEvent.change(screen.getByLabelText("Exact OIDC issuer"), {
      target: { value: "https://identity.example.com/tenant" },
    });
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: account.user.id },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "account-only-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Prelink from scoped account authority" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: account.user.id },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "account-only-subject" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm permanent link" }),
    );

    await waitFor(() =>
      expect(prelinkPlatformAuthProviderAccount).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        expect.any(String),
        "Prelink from scoped account authority",
        {
          issuer: "https://identity.example.com/tenant",
          subject: "account-only-subject",
          userId: account.user.id,
        },
      ),
    );
    expect(
      await screen.findByText(/Ada Account is linked to this provider/i),
    ).toBeVisible();
    fireEvent.change(screen.getByLabelText("Platform provider ID"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000099" },
    });
    expect(
      screen.queryByText(/Ada Account is linked to this provider/i),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Ada Account")).not.toBeInTheDocument();
    expect(listPlatformAuthProviders).not.toHaveBeenCalled();
  });

  it("hides a mutation notice synchronously when the session changes", async () => {
    const previous = {
      ...platformAccountFixture(),
      user: {
        ...platformAccountFixture().user,
        displayName: "Previous Session Person",
      },
    };
    const api = createPhaseTwoApi({
      listPlatformAuthProviderAccounts: async () => ({ items: [] }),
      prelinkPlatformAuthProviderAccount: async () => ({
        etag: '"v3-u1"',
        location: `/api/v1/platform/auth-providers/${providerId}/accounts/${previous.id}`,
        value: previous,
      }),
    });
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    const permissions: SessionView["permissions"] = [
      "platform.identity_account.read",
      "platform.identity_account.manage",
    ];
    const view = render(
      pageForSession(api, { ...sessionFixture, permissions }, vi.fn()),
    );

    fireEvent.change(screen.getByLabelText("Platform provider ID"), {
      target: { value: providerId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Open account register" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Prelink account" }),
    );
    fireEvent.change(screen.getByLabelText("Exact OIDC issuer"), {
      target: { value: "https://identity.example.com/tenant" },
    });
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: previous.user.id },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "previous-session-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Create a session-bound notice" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: previous.user.id },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "previous-session-subject" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm permanent link" }),
    );
    expect(
      await screen.findByText(/Previous Session Person is linked/i),
    ).toBeVisible();

    view.rerender(
      pageForSession(
        api,
        {
          ...sessionFixture,
          csrfToken: "new-session-csrf",
          id: "0198c97d-cf4f-7000-8000-000000000097",
          permissions,
        },
        vi.fn(),
      ),
    );

    expect(
      screen.queryByText(/Previous Session Person is linked/i),
    ).not.toBeInTheDocument();
  });

  it("mounts binding and account records together for independent scoped authority", async () => {
    const listPlatformAuthProviders = vi.fn<
      PhaseTwoApi["listPlatformAuthProviders"]
    >(async () => ({ items: [] }));
    const listPlatformAuthProviderAccounts = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderAccounts"]
    >(async () => ({ items: [platformAccountFixture()] }));
    const listPlatformAuthProviderTenantBindings = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderTenantBindings"]
    >(async () => ({ items: [] }));
    renderPage(
      {
        listPlatformAuthProviderAccounts,
        listPlatformAuthProviderTenantBindings,
        listPlatformAuthProviders,
      },
      ["platform.identity_binding.read", "platform.identity_account.read"],
    );

    expect(
      screen.getByRole("heading", { name: "Provider-scoped identity records" }),
    ).toBeVisible();
    expect(listPlatformAuthProviders).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Platform provider ID"), {
      target: { value: providerId },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Open identity records" }),
    );

    expect(
      await screen.findByText("No tenant bindings recorded."),
    ).toBeVisible();
    expect(await screen.findByText("Ada Account")).toBeVisible();
    expect(listPlatformAuthProviderTenantBindings).toHaveBeenCalledTimes(1);
    expect(listPlatformAuthProviderAccounts).toHaveBeenCalledTimes(1);
  });

  it("unmounts provider-scoped records as soon as the provider ID draft changes", async () => {
    const listPlatformAuthProviderAccounts = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderAccounts"]
    >(async () => ({ items: [platformAccountFixture()] }));
    renderPage({ listPlatformAuthProviderAccounts }, [
      "platform.identity_account.read",
      "platform.identity_account.manage",
    ]);
    const input = screen.getByLabelText("Platform provider ID");
    fireEvent.change(input, { target: { value: providerId } });
    fireEvent.click(
      screen.getByRole("button", { name: "Open account register" }),
    );
    expect(await screen.findByText("Ada Account")).toBeVisible();

    fireEvent.change(input, {
      target: { value: "0198c97d-cf4f-7000-8000-000000000099" },
    });

    expect(screen.queryByText("Ada Account")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Prelink account" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    ).not.toBeInTheDocument();
    expect(listPlatformAuthProviderAccounts).toHaveBeenCalledOnce();
  });

  it("mounts explicit disabled-only tenant bindings inside provider detail", async () => {
    const listPlatformAuthProviderTenantBindings = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderTenantBindings"]
    >(async () => ({ items: [] }));
    renderPage({ listPlatformAuthProviderTenantBindings }, [
      "platform.identity_provider.read",
      "platform.identity_binding.read",
      "platform.identity_binding.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: /Inspect Workforce OIDC/i }),
    );
    expect(
      await screen.findByRole("heading", { name: "Tenant bindings" }),
    ).toBeVisible();
    expect(
      await screen.findByText("No tenant bindings recorded."),
    ).toBeVisible();
    expect(
      screen.getByText("Explicit tenant admission boundary"),
    ).toBeVisible();
    expect(listPlatformAuthProviderTenantBindings).toHaveBeenCalledWith(
      providerId,
      expect.objectContaining({ includeArchived: true }),
    );
  });

  it("mounts the provider-global account register only with account authority", async () => {
    const account = platformAccountFixture();
    const listPlatformAuthProviderAccounts = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderAccounts"]
    >(async () => ({ items: [account] }));
    renderPage({ listPlatformAuthProviderAccounts }, [
      "platform.identity_provider.read",
      "platform.identity_account.read",
      "platform.identity_account.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: /Inspect Workforce OIDC/i }),
    );
    expect(
      await screen.findByRole("heading", { name: "Linked platform accounts" }),
    ).toBeVisible();
    expect(await screen.findByText("Ada Account")).toBeVisible();
    expect(listPlatformAuthProviderAccounts).toHaveBeenCalledWith(
      providerId,
      expect.objectContaining({ includeRetired: true }),
    );
    expect(
      screen.getByRole("button", { name: "Prelink account" }),
    ).toBeVisible();
  });

  it("keeps provider detail locked while a tenant-binding mutation is in flight", async () => {
    const pending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>
        >
      >();
    const createPlatformAuthProviderTenantBinding = vi.fn<
      PhaseTwoApi["createPlatformAuthProviderTenantBinding"]
    >(() => pending.promise);
    const updatePlatformAuthProvider =
      vi.fn<PhaseTwoApi["updatePlatformAuthProvider"]>();
    renderPage(
      {
        createPlatformAuthProviderTenantBinding,
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
        updatePlatformAuthProvider,
      },
      [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
        "platform.identity_binding.read",
        "platform.identity_binding.manage",
      ],
    );

    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Edit metadata" }));
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Keep provider mutation serialized" },
    });
    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    fireEvent.change(screen.getByLabelText("Tenant ID"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000090" },
    });
    fireEvent.change(screen.getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(screen.getByLabelText("Binding audit reason"), {
      target: { value: "Reserve Acme federation coordinates" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create staged binding" }),
    );

    await waitFor(() =>
      expect(createPlatformAuthProviderTenantBinding).toHaveBeenCalledOnce(),
    );
    expect(
      screen.queryByRole("button", { name: "Close" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Edit metadata" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Set client secret" }),
    ).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Archive provider" }),
    ).toBeDisabled();
    const replaceMetadata = screen.getByRole("button", {
      name: "Replace metadata",
    });
    expect(replaceMetadata).toBeDisabled();
    fireEvent.submit(replaceMetadata.closest("form")!);
    expect(updatePlatformAuthProvider).not.toHaveBeenCalled();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.getByText("Discovery coordinates")).toBeVisible();

    await act(async () => pending.reject(new Error("connection lost")));
    expect(await screen.findByRole("button", { name: "Close" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Edit metadata" })).toBeEnabled();
  });

  it("makes tenant-binding commands non-writable during a provider mutation", async () => {
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformAuthProvider"]>>
      >();
    const updatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["updatePlatformAuthProvider"]
    >(() => pending.promise);
    renderPage(
      {
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
        updatePlatformAuthProvider,
      },
      [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
        "platform.identity_binding.read",
        "platform.identity_binding.manage",
      ],
    );

    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Edit metadata" }));
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Confirm the provider mutation interlock" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replace metadata" }));

    await waitFor(() =>
      expect(updatePlatformAuthProvider).toHaveBeenCalledOnce(),
    );
    expect(
      screen.queryByRole("button", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
    expect(screen.getByText("Provider mutation in progress")).toBeVisible();

    await act(async () =>
      pending.resolve({
        etag: '"v8"',
        value: oidcProviderFixture({ version: 8 }),
      }),
    );
    expect(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    ).toBeEnabled();
  });

  it("keeps binding mutation ownership when only provider-manage authority changes", async () => {
    const pending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>
        >
      >();
    const provider = oidcProviderFixture();
    const createPlatformAuthProviderTenantBinding = vi.fn<
      PhaseTwoApi["createPlatformAuthProviderTenantBinding"]
    >(() => pending.promise);
    const api = createPhaseTwoApi({
      createPlatformAuthProviderTenantBinding,
      getPlatformAuthProvider: async () => ({ etag: '"v7"', value: provider }),
      listPlatformAuthProviders: async () => ({
        items: [providerSummary(provider)],
      }),
      listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
    });
    const permissions: SessionView["permissions"] = [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
      "platform.identity_binding.read",
      "platform.identity_binding.manage",
    ];
    const clearSession = vi.fn();
    const view = render(
      pageForSession(api, { ...sessionFixture, permissions }, clearSession),
    );

    await openDetail();
    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    fireEvent.change(screen.getByLabelText("Tenant ID"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000090" },
    });
    fireEvent.change(screen.getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(screen.getByLabelText("Binding audit reason"), {
      target: { value: "Preserve the binding mutation owner" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create staged binding" }),
    );
    await waitFor(() =>
      expect(createPlatformAuthProviderTenantBinding).toHaveBeenCalledOnce(),
    );

    view.rerender(
      pageForSession(
        api,
        {
          ...sessionFixture,
          permissions: permissions.filter(
            (permission) => permission !== "platform.identity_provider.manage",
          ),
        },
        clearSession,
      ),
    );
    await waitFor(() =>
      expect(
        screen.queryByRole("button", { name: "Edit metadata" }),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: "Close" }),
    ).not.toBeInTheDocument();

    await act(async () => pending.reject(new Error("connection lost")));
    expect(await screen.findByRole("button", { name: "Close" })).toBeVisible();
  });

  it("renders a read-only staged inventory and sanitized detail", async () => {
    renderPage({}, ["platform.identity_provider.read"]);

    expect(await screen.findByText("Workforce OIDC")).toBeVisible();
    expect(screen.getAllByText("Blocked")).toHaveLength(2);
    expect(
      screen.queryByRole("button", { name: "Create staged provider" }),
    ).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: /Inspect Workforce OIDC/i }),
    );
    expect(await screen.findByText("Discovery coordinates")).toBeVisible();
    expect(screen.getByText("https://identity.example.com")).toBeVisible();
    expect(
      screen.getByText("Deployment-managed registration values"),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Edit metadata" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(/browser-only-secret/i)).not.toBeInTheDocument();
  });

  it("does not restore stale provider inventory after read permission returns", async () => {
    const provider = oidcProviderFixture();
    const listPlatformAuthProviders = vi
      .fn<PhaseTwoApi["listPlatformAuthProviders"]>()
      .mockResolvedValueOnce({ items: [providerSummary(provider)] })
      .mockResolvedValueOnce({ items: [] });
    const api = createPhaseTwoApi({ listPlatformAuthProviders });
    const authorized: SessionView = {
      ...sessionFixture,
      permissions: ["platform.identity_provider.read"],
    };
    const view = render(pageForSession(api, authorized, vi.fn()));

    await screen.findByText("Workforce OIDC");
    view.rerender(
      pageForSession(api, { ...authorized, permissions: [] }, vi.fn()),
    );
    expect(
      screen.getByText(/global identity providers are not available/i),
    ).toBeVisible();
    view.rerender(pageForSession(api, authorized, vi.fn()));

    expect(screen.queryByText("Workforce OIDC")).not.toBeInTheDocument();
    expect(
      await screen.findByText("No global providers recorded"),
    ).toBeVisible();
    expect(listPlatformAuthProviders).toHaveBeenCalledTimes(2);
  });

  it("drops a stale provider detail when the refresh is forbidden", async () => {
    const provider = oidcProviderFixture();
    const getPlatformAuthProvider = vi
      .fn<PhaseTwoApi["getPlatformAuthProvider"]>()
      .mockResolvedValueOnce({ etag: '"v7"', value: provider })
      .mockRejectedValueOnce(
        new PhaseTwoApiError("Provider read authority was revoked.", 403),
      );
    const updatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["updatePlatformAuthProvider"]
    >(async () => {
      throw new PhaseTwoApiError("The provider version is stale.", 412);
    });
    renderPage({ getPlatformAuthProvider, updatePlatformAuthProvider }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);

    await openDetail();
    expect(screen.getByText("https://identity.example.com")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Edit metadata" }));
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Refresh after a stale metadata command" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replace metadata" }));

    expect(
      await screen.findByText("Provider read authority was revoked."),
    ).toBeVisible();
    expect(getPlatformAuthProvider).toHaveBeenCalledTimes(2);
    expect(
      screen.queryByText("https://identity.example.com"),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Provider facts")).not.toBeInTheDocument();
  });

  it("refreshes tenant-binding projections after any stale provider mutation", async () => {
    const provider = oidcProviderFixture();
    const getPlatformAuthProvider = vi.fn<
      PhaseTwoApi["getPlatformAuthProvider"]
    >(async () => ({ etag: '"v7"', value: provider }));
    const listPlatformAuthProviderTenantBindings = vi.fn<
      PhaseTwoApi["listPlatformAuthProviderTenantBindings"]
    >(async () => ({ items: [] }));
    const updatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["updatePlatformAuthProvider"]
    >(async () => {
      throw new PhaseTwoApiError("The provider version is stale.", 412);
    });
    renderPage(
      {
        getPlatformAuthProvider,
        listPlatformAuthProviderTenantBindings,
        updatePlatformAuthProvider,
      },
      [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
        "platform.identity_binding.read",
      ],
    );

    await openDetail();
    await waitFor(() =>
      expect(listPlatformAuthProviderTenantBindings).toHaveBeenCalledTimes(1),
    );
    fireEvent.click(screen.getByRole("button", { name: "Edit metadata" }));
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Refresh every dependent readiness projection" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replace metadata" }));

    await waitFor(() =>
      expect(getPlatformAuthProvider).toHaveBeenCalledTimes(2),
    );
    await waitFor(() =>
      expect(listPlatformAuthProviderTenantBindings).toHaveBeenCalledTimes(2),
    );
    expect(updatePlatformAuthProvider).toHaveBeenCalledOnce();
  });

  it("keeps offline_access coupled to refresh handling in the OIDC editor", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    renderPage({}, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create staged provider" }),
    );
    const scopes = screen.getByLabelText("Additional scopes");
    fireEvent.change(scopes, { target: { value: "profile email" } });
    const refresh = screen.getByLabelText("Allow refresh-token handling later");
    fireEvent.click(refresh);
    expect(scopes).toHaveValue("profile email offline_access");
    expect(
      screen.getByText(/bounded encrypted refresh lifecycle/i),
    ).toBeVisible();

    fireEvent.click(refresh);
    expect(scopes).toHaveValue("profile email");
  });

  it("creates only a disabled SAML definition with encryption fixed off", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const saml = samlProviderFixture();
    const createPlatformAuthProvider = vi.fn<
      PhaseTwoApi["createPlatformAuthProvider"]
    >(async () => ({
      etag: '"v1"',
      location: `/api/v1/platform/auth-providers/${saml.id}`,
      value: saml,
    }));
    renderPage(
      {
        createPlatformAuthProvider,
        getPlatformAuthProvider: async () => ({ etag: '"v1"', value: saml }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create staged provider" }),
    );
    expect(
      screen.getByRole("form", { name: "Create staged identity provider" }),
    ).toBeVisible();
    const oidcChoice = screen.getByRole("button", { name: /OIDC/i });
    const samlChoice = screen.getByRole("button", { name: /SAML 2.0/i });
    expect(oidcChoice).toHaveAttribute("aria-pressed", "true");
    expect(samlChoice).toHaveAttribute("aria-pressed", "false");
    expect(screen.getByLabelText("Platform redirect URI")).toHaveValue(
      `${publicOrigin}/api/v1/auth/platform/oidc/callback`,
    );
    expect(screen.getByLabelText("Platform redirect URI")).toHaveAttribute(
      "readonly",
    );
    expect(screen.getByLabelText("Tenant redirect URI")).toHaveValue(
      `${publicOrigin}/api/v1/auth/federated/oidc/callback`,
    );
    expect(screen.getByLabelText("Tenant redirect URI")).toHaveAttribute(
      "readonly",
    );
    expect(screen.getByLabelText("Post-logout redirect URI")).toHaveValue(
      `${publicOrigin}/signed-out`,
    );
    expect(screen.getByLabelText("Post-logout redirect URI")).toHaveAttribute(
      "readonly",
    );
    fireEvent.click(samlChoice);
    expect(oidcChoice).toHaveAttribute("aria-pressed", "false");
    expect(samlChoice).toHaveAttribute("aria-pressed", "true");
    fireEvent.change(screen.getByLabelText("Stable key"), {
      target: { value: "workforce_saml" },
    });
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Workforce SAML" },
    });
    fireEvent.change(screen.getByLabelText("Expected IdP entity ID"), {
      target: { value: "https://idp.example.com/entity" },
    });
    expect(screen.getByLabelText("SP entity ID")).toHaveValue(
      `${publicOrigin}/api/v1/auth/platform/saml/workforce_saml/metadata`,
    );
    expect(screen.getByLabelText("SP entity ID")).toHaveAttribute("readonly");
    expect(screen.getByLabelText("ACS URL")).toHaveValue(
      `${publicOrigin}/api/v1/auth/platform/saml/acs`,
    );
    expect(screen.getByLabelText("ACS URL")).toHaveAttribute("readonly");
    expect(
      screen.getByText("Deployment-managed registration values"),
    ).toBeVisible();
    fireEvent.change(screen.getByLabelText("Requested AuthnContexts"), {
      target: {
        value:
          "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      },
    });
    fireEvent.change(await screen.findByLabelText("Audit reason"), {
      target: { value: "Stage workforce SAML coordinates" },
    });
    expect(screen.getByText("Assertion encryption: disabled")).toBeVisible();
    expect(
      screen.queryByLabelText("Encryption policy"),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Create disabled provider" }),
    );

    await waitFor(() => expect(createPlatformAuthProvider).toHaveBeenCalled());
    const [csrfToken, idempotencyKey, auditReason, input] =
      createPlatformAuthProvider.mock.calls[0]!;
    expect(csrfToken).toBe(sessionFixture.csrfToken);
    expect(idempotencyKey).toMatch(/^[0-9a-f-]{36}$/);
    expect(auditReason).toBe("Stage workforce SAML coordinates");
    expect(input.kind).toBe("saml");
    if (input.kind !== "saml") throw new Error("Expected SAML input.");
    expect(input.configuration.encryptionPolicy).toBe("disabled");
    expect(input.configuration.spEntityId).toBe(
      `${publicOrigin}/api/v1/auth/platform/saml/workforce_saml/metadata`,
    );
    expect(input.configuration.acsUrl).toBe(
      `${publicOrigin}/api/v1/auth/platform/saml/acs`,
    );
    expect(input).not.toHaveProperty("enabled");
    expect(input).not.toHaveProperty("platformLoginEnabled");
    expect(input.configuration).not.toHaveProperty("spKey");
  });

  it("fails closed without a browser public origin instead of exposing editable endpoints", async () => {
    vi.stubGlobal("location", undefined);
    const createPlatformAuthProvider =
      vi.fn<PhaseTwoApi["createPlatformAuthProvider"]>();
    renderPage({ createPlatformAuthProvider }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create staged provider" }),
    );
    expect(screen.getByLabelText("Platform redirect URI")).toHaveAttribute(
      "readonly",
    );
    expect(screen.getByLabelText("Platform redirect URI")).toHaveValue("");
    expect(screen.getByLabelText("Tenant redirect URI")).toHaveAttribute(
      "readonly",
    );
    expect(screen.getByLabelText("Tenant redirect URI")).toHaveValue("");
    fireEvent.change(screen.getByLabelText("Stable key"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Workforce OIDC" },
    });
    fireEvent.change(screen.getByLabelText("Issuer"), {
      target: { value: "https://identity.example.com" },
    });
    fireEvent.change(screen.getByLabelText("Client ID"), {
      target: { value: "periapsis-platform" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Stage workforce OIDC coordinates" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create disabled provider" }),
    );

    expect(await screen.findByText(/endpoints are unavailable/i)).toBeVisible();
    expect(createPlatformAuthProvider).not.toHaveBeenCalled();
  });

  it("warns when a safe create retry returns a provider that is already active", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const staged = oidcProviderFixture();
    const active = oidcProviderFixture({
      accountMode: "create",
      configuration: {
        ...staged.configuration,
        clientSecretPresent: true,
      },
      enabled: true,
      platformLoginActivationAvailable: true,
      secretPresent: true,
      updatedAt: "2026-08-27T10:10:00Z",
      version: 8,
    });
    renderPage(
      {
        createPlatformAuthProvider: async () => ({
          etag: '"v8"',
          location: `/api/v1/platform/auth-providers/${providerId}`,
          value: active,
        }),
        getPlatformAuthProvider: async () => ({
          etag: '"v8"',
          value: active,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(active)],
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );

    await submitOidcCreate("workforce_oidc", "Workforce OIDC");

    expect(
      await screen.findByText(
        /already active.*safe retry.*direct platform login/i,
      ),
    ).toBeVisible();
    expect(screen.queryByText(/was staged disabled/i)).not.toBeInTheDocument();
    expect(
      await screen.findByRole("button", {
        name: "Activate direct platform login",
      }),
    ).toBeVisible();
  });

  it("warns when a safe create retry returns a provider already ready to activate", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const staged = oidcProviderFixture();
    const ready = oidcProviderFixture({
      activationAvailable: true,
      configuration: {
        ...staged.configuration,
        clientSecretPresent: true,
      },
      secretPresent: true,
      updatedAt: "2026-08-27T10:10:00Z",
      version: 7,
    });
    renderPage(
      {
        createPlatformAuthProvider: async () => ({
          etag: '"v7"',
          location: `/api/v1/platform/auth-providers/${providerId}`,
          value: ready,
        }),
        getPlatformAuthProvider: async () => ({
          etag: '"v7"',
          value: ready,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(ready)],
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );

    await submitOidcCreate("workforce_oidc", "Workforce OIDC");

    expect(
      await screen.findByText(
        /already ready.*safe retry.*without activating either login boundary/i,
      ),
    ).toBeVisible();
    expect(screen.queryByText(/was staged disabled/i)).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /direct platform login/i }),
    ).not.toBeInTheDocument();
  });

  it("warns when a safe create retry returns a later disabled provider", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const current = oidcProviderFixture({
      updatedAt: "2026-08-27T10:10:00Z",
      version: 9,
    });
    renderPage(
      {
        createPlatformAuthProvider: async () => ({
          etag: '"v9"',
          location: `/api/v1/platform/auth-providers/${providerId}`,
          value: current,
        }),
        getPlatformAuthProvider: async () => ({
          etag: '"v9"',
          value: current,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(current)],
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );

    await submitOidcCreate("workforce_oidc", "Workforce OIDC");

    expect(
      await screen.findByText(
        /already exists.*currently disabled.*safe retry/i,
      ),
    ).toBeVisible();
    expect(screen.queryByText(/was staged disabled/i)).not.toBeInTheDocument();
  });

  it("closes create and reloads inventory after a provider create conflict", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const listPlatformAuthProviders = vi
      .fn<PhaseTwoApi["listPlatformAuthProviders"]>()
      .mockResolvedValue({ items: [] });
    const createPlatformAuthProvider = vi
      .fn<PhaseTwoApi["createPlatformAuthProvider"]>()
      .mockRejectedValue(
        new PhaseTwoApiError(
          "The create request conflicts with current state.",
          409,
        ),
      );
    renderPage({ createPlatformAuthProvider, listPlatformAuthProviders }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);

    await submitOidcCreate("workforce_oidc", "Workforce OIDC");

    expect(
      await screen.findByText(/create request conflicted.*reloaded/i),
    ).toBeVisible();
    expect(
      screen.queryByText("Create staged identity provider"),
    ).not.toBeInTheDocument();
    await waitFor(() =>
      expect(listPlatformAuthProviders).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformAuthProvider).toHaveBeenCalledOnce();
  });

  it("locks the create draft and reuses its idempotency key after an uncertain failure", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformAuthProvider"]>>
      >();
    const createPlatformAuthProvider = vi
      .fn<PhaseTwoApi["createPlatformAuthProvider"]>()
      .mockImplementationOnce(() => pending.promise)
      .mockRejectedValueOnce(new Error("connection lost after request commit"));
    renderPage({ createPlatformAuthProvider }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);

    await submitOidcCreate("locked_workforce_oidc", "Locked workforce OIDC");
    await waitFor(() =>
      expect(createPlatformAuthProvider).toHaveBeenCalledTimes(1),
    );

    const oidcChoice = screen.getByRole("button", { name: /OIDC/i });
    const samlChoice = screen.getByRole("button", { name: /SAML 2.0/i });
    const stableKey = screen.getByLabelText("Stable key");
    expect(oidcChoice).toBeDisabled();
    expect(samlChoice).toBeDisabled();
    expect(stableKey).toBeDisabled();
    expect(screen.getByLabelText("Audit reason")).toBeDisabled();

    fireEvent.click(samlChoice);
    fireEvent.change(stableKey, { target: { value: "changed_during_submit" } });
    expect(oidcChoice).toHaveAttribute("aria-pressed", "true");
    expect(
      screen.queryByLabelText("Expected IdP entity ID"),
    ).not.toBeInTheDocument();

    await act(async () =>
      pending.reject(new Error("connection lost after request commit")),
    );
    const retry = screen.getByRole("button", {
      name: "Create disabled provider",
    });
    await waitFor(() => expect(retry).toBeEnabled());
    expect(stableKey).toHaveValue("locked_workforce_oidc");
    fireEvent.click(retry);
    await waitFor(() =>
      expect(createPlatformAuthProvider).toHaveBeenCalledTimes(2),
    );

    const firstRequest = createPlatformAuthProvider.mock.calls[0]!;
    const retriedRequest = createPlatformAuthProvider.mock.calls[1]!;
    expect(retriedRequest[0]).toBe(firstRequest[0]);
    expect(retriedRequest[1]).toBe(firstRequest[1]);
    expect(retriedRequest[2]).toBe(firstRequest[2]);
    expect(retriedRequest[3]).toEqual(firstRequest[3]);
  });

  it.each([
    ["stable key", "Stable key", "rotated_workforce_oidc", "change"],
    ["display name", "Display name", "Rotated workforce OIDC", "change"],
    ["description", "Description", "Rotated provider description", "change"],
    ["issuer", "Issuer", "https://rotated.example.com", "change"],
    ["client ID", "Client ID", "rotated-client", "change"],
    ["additional scopes", "Additional scopes", "email", "change"],
    ["audit reason", "Audit reason", "Stage rotated workforce OIDC", "change"],
    ["refresh-token policy", "Allow refresh-token handling later", "", "click"],
    ["UserInfo policy", "Use the UserInfo endpoint", "", "click"],
  ] as const)(
    "rotates the create idempotency key when the %s changes after an uncertain failure",
    async (_label, fieldLabel, nextValue, eventKind) => {
      vi.stubGlobal("location", { origin: publicOrigin });
      const createPlatformAuthProvider = vi
        .fn<PhaseTwoApi["createPlatformAuthProvider"]>()
        .mockRejectedValue(new Error("connection lost after request commit"));
      renderPage({ createPlatformAuthProvider }, [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
      ]);

      await submitOidcCreate("workforce_oidc", "Workforce OIDC");
      await waitFor(() =>
        expect(createPlatformAuthProvider).toHaveBeenCalledTimes(1),
      );
      const submit = screen.getByRole("button", {
        name: "Create disabled provider",
      });
      await waitFor(() => expect(submit).toBeEnabled());

      const field = screen.getByLabelText(fieldLabel);
      if (eventKind === "click") {
        fireEvent.click(field);
      } else {
        fireEvent.change(field, { target: { value: nextValue } });
      }
      fireEvent.click(submit);

      await waitFor(() =>
        expect(createPlatformAuthProvider).toHaveBeenCalledTimes(2),
      );
      expect(createPlatformAuthProvider.mock.calls[1]?.[1]).not.toBe(
        createPlatformAuthProvider.mock.calls[0]?.[1],
      );
    },
  );

  it("ignores an old create completion after a same-session permission flap and newer submit", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const first =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformAuthProvider"]>>
      >();
    const second =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformAuthProvider"]>>
      >();
    const firstProvider = oidcProviderFixture({
      id: "0198c97d-cf4f-7000-8000-000000000077",
      key: "first_workforce_oidc",
      version: 1,
    });
    const secondProvider = oidcProviderFixture({
      id: "0198c97d-cf4f-7000-8000-000000000066",
      key: "second_workforce_oidc",
      version: 1,
    });
    const createPlatformAuthProvider = vi
      .fn<PhaseTwoApi["createPlatformAuthProvider"]>()
      .mockImplementationOnce(() => first.promise)
      .mockImplementationOnce(() => second.promise);
    const getPlatformAuthProvider = vi.fn<
      PhaseTwoApi["getPlatformAuthProvider"]
    >(async () => ({ etag: '"v1"', value: secondProvider }));
    const api = createPhaseTwoApi({
      createPlatformAuthProvider,
      getPlatformAuthProvider,
      listPlatformAuthProviders: async () => ({
        items: [providerSummary(oidcProviderFixture())],
      }),
    });
    const authorized: SessionView = {
      ...sessionFixture,
      permissions: [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
      ],
    };
    const view = render(pageForSession(api, authorized, vi.fn()));

    await submitOidcCreate("first_workforce_oidc", "First workforce OIDC");
    await waitFor(() =>
      expect(createPlatformAuthProvider).toHaveBeenCalledTimes(1),
    );

    view.rerender(
      pageForSession(
        api,
        {
          ...authorized,
          permissions: ["platform.identity_provider.read"],
        },
        vi.fn(),
      ),
    );
    await waitFor(() =>
      expect(
        screen.queryByText("Create staged identity provider"),
      ).not.toBeInTheDocument(),
    );

    view.rerender(pageForSession(api, authorized, vi.fn()));
    await submitOidcCreate("second_workforce_oidc", "Second workforce OIDC");
    await waitFor(() =>
      expect(createPlatformAuthProvider).toHaveBeenCalledTimes(2),
    );
    expect(screen.getByRole("button", { name: "Creating…" })).toBeDisabled();

    await act(async () =>
      first.resolve({
        etag: '"v1"',
        location: `/api/v1/platform/auth-providers/${firstProvider.id}`,
        value: firstProvider,
      }),
    );
    expect(screen.getByText("Create staged identity provider")).toBeVisible();
    expect(screen.getByRole("button", { name: "Creating…" })).toBeDisabled();
    expect(getPlatformAuthProvider).not.toHaveBeenCalled();

    await act(async () =>
      second.resolve({
        etag: '"v1"',
        location: `/api/v1/platform/auth-providers/${secondProvider.id}`,
        value: secondProvider,
      }),
    );
    await waitFor(() =>
      expect(getPlatformAuthProvider).toHaveBeenCalledWith(
        secondProvider.id,
        expect.any(AbortSignal),
      ),
    );
  });

  it("ignores a create completion after read authority unmounts the page controls", async () => {
    vi.stubGlobal("location", { origin: publicOrigin });
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformAuthProvider"]>>
      >();
    const createdProvider = oidcProviderFixture({
      id: "0198c97d-cf4f-7000-8000-000000000055",
      key: "unmounted_workforce_oidc",
      version: 1,
    });
    const createPlatformAuthProvider = vi.fn<
      PhaseTwoApi["createPlatformAuthProvider"]
    >(() => pending.promise);
    const getPlatformAuthProvider = vi.fn<
      PhaseTwoApi["getPlatformAuthProvider"]
    >(async () => ({ etag: '"v1"', value: createdProvider }));
    const api = createPhaseTwoApi({
      createPlatformAuthProvider,
      getPlatformAuthProvider,
      listPlatformAuthProviders: async () => ({
        items: [providerSummary(oidcProviderFixture())],
      }),
    });
    const authorized: SessionView = {
      ...sessionFixture,
      permissions: [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
      ],
    };
    const clearSession = vi.fn();
    const view = render(pageForSession(api, authorized, clearSession));

    await submitOidcCreate(
      "unmounted_workforce_oidc",
      "Unmounted workforce OIDC",
    );
    await waitFor(() =>
      expect(createPlatformAuthProvider).toHaveBeenCalledTimes(1),
    );

    view.rerender(
      pageForSession(api, { ...authorized, permissions: [] }, clearSession),
    );
    expect(
      await screen.findByText(/global identity providers are not available/i),
    ).toBeVisible();
    await act(async () =>
      pending.resolve({
        etag: '"v1"',
        location: `/api/v1/platform/auth-providers/${createdProvider.id}`,
        value: createdProvider,
      }),
    );

    view.rerender(pageForSession(api, authorized, clearSession));
    await screen.findByText("Workforce OIDC");
    expect(getPlatformAuthProvider).not.toHaveBeenCalled();
    expect(
      screen.queryByText(/was created disabled at version/i),
    ).not.toBeInTheDocument();
  });

  it("activates OIDC tenant execution with explicit account mode while direct platform login remains separate", async () => {
    const base = oidcProviderFixture();
    const current = oidcProviderFixture({
      activationAvailable: true,
      configuration: {
        ...base.configuration,
        clientSecretPresent: true,
      },
      secretPresent: true,
    });
    const activated = oidcProviderFixture({
      accountMode: "create",
      configuration: current.configuration,
      enabled: true,
      platformLoginActivationAvailable: true,
      secretPresent: true,
      version: 8,
    });
    const deactivated = oidcProviderFixture({
      activationAvailable: true,
      configuration: current.configuration,
      secretPresent: true,
      version: 9,
    });
    const activatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["activatePlatformAuthProvider"]
    >(async () => ({ etag: '"v8"', value: activated }));
    const deactivatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["deactivatePlatformAuthProvider"]
    >(async () => ({ etag: '"v9"', value: deactivated }));
    renderPage(
      {
        activatePlatformAuthProvider,
        deactivatePlatformAuthProvider,
        getPlatformAuthProvider: async () => ({
          etag: '"v7"',
          value: current,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(current)],
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );
    await openDetail();

    expect(
      screen.queryByRole("button", { name: /platform login/i }),
    ).not.toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Activate tenant execution" }),
    );
    expect(
      screen.getByRole("form", { name: "Activate provider tenant execution" }),
    ).toBeVisible();
    fireEvent.change(screen.getByLabelText("External identity account mode"), {
      target: { value: "create" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Enable Acme tenant federation" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_oidc to confirm"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Activate tenant execution" })
        .at(-1)!,
    );

    await waitFor(() =>
      expect(activatePlatformAuthProvider).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        { etag: '"v7"', value: current },
        "Enable Acme tenant federation",
        { accountMode: "create", expectedVersion: 7 },
      ),
    );
    expect(
      await screen.findByRole("button", {
        name: "Deactivate tenant execution",
      }),
    ).toBeVisible();
    expect(screen.getByText("Tenant execution active")).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "Activate direct platform login",
      }),
    ).toBeVisible();
    expect(screen.queryByText("Archive provider")).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Deactivate tenant execution" }),
    );
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Close Acme tenant federation" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_oidc to confirm"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Deactivate tenant execution" })
        .at(-1)!,
    );
    await waitFor(() =>
      expect(deactivatePlatformAuthProvider).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        { etag: '"v8"', value: activated },
        "Close Acme tenant federation",
        { expectedVersion: 8 },
      ),
    );
    expect(
      await screen.findByRole("button", { name: "Activate tenant execution" }),
    ).toBeVisible();
  });

  it("activates and deactivates direct OIDC login as a distinct pre-linked-only boundary", async () => {
    const base = oidcProviderFixture();
    const current = oidcProviderFixture({
      accountMode: "existing_identity",
      configuration: {
        ...base.configuration,
        clientSecretPresent: true,
        useUserInfo: false,
      },
      enabled: true,
      platformLoginActivationAvailable: true,
      secretPresent: true,
      version: 8,
    });
    const activated = oidcProviderFixture({
      ...current,
      platformLoginActivationAvailable: false,
      platformLoginEnabled: true,
      version: 9,
    });
    const deactivated = oidcProviderFixture({
      ...activated,
      platformLoginActivationAvailable: true,
      platformLoginEnabled: false,
      version: 10,
    });
    const activatePlatformOidcDirectLogin = vi.fn<
      PhaseTwoApi["activatePlatformOidcDirectLogin"]
    >(async () => ({ etag: '"v9"', value: activated }));
    const deactivatePlatformOidcDirectLogin = vi.fn<
      PhaseTwoApi["deactivatePlatformOidcDirectLogin"]
    >(async () => ({ etag: '"v10"', value: deactivated }));
    renderPage(
      {
        activatePlatformOidcDirectLogin,
        deactivatePlatformOidcDirectLogin,
        getPlatformAuthProvider: async () => ({
          etag: '"v8"',
          value: current,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(current)],
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );
    await openDetail();

    expect(screen.getByText("Ready to activate")).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: "Activate direct platform login",
      }),
    ).toBeEnabled();
    fireEvent.click(
      screen.getByRole("button", {
        name: "Activate direct platform login",
      }),
    );
    expect(
      screen.getByRole("form", { name: "Activate direct platform login" }),
    ).toBeVisible();
    expect(
      screen.getByText(/admits pre-linked identities only/i),
    ).toBeVisible();
    expect(screen.getByText(/account mode: existing identity/i)).toBeVisible();
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Enable pre-linked workforce login" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_oidc to confirm"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Activate direct platform login" })
        .at(-1)!,
    );

    await waitFor(() =>
      expect(activatePlatformOidcDirectLogin).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        { etag: '"v8"', value: current },
        "Enable pre-linked workforce login",
        { expectedVersion: 8 },
      ),
    );
    expect(
      await screen.findByRole("button", {
        name: "Deactivate direct platform login",
      }),
    ).toBeEnabled();
    expect(
      screen.getByRole("button", { name: "Deactivate tenant execution" }),
    ).toBeDisabled();
    expect(screen.getByText(/active · pre-linked identities/i)).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", {
        name: "Deactivate direct platform login",
      }),
    );
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Disable direct workforce login" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_oidc to confirm"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Deactivate direct platform login" })
        .at(-1)!,
    );

    await waitFor(() =>
      expect(deactivatePlatformOidcDirectLogin).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        { etag: '"v9"', value: activated },
        "Disable direct workforce login",
        { expectedVersion: 9 },
      ),
    );
    expect(
      await screen.findByRole("button", {
        name: "Activate direct platform login",
      }),
    ).toBeVisible();
  });

  it("shows authoritative direct-login unavailability and disables activation", async () => {
    const base = oidcProviderFixture();
    const unavailable = oidcProviderFixture({
      accountMode: "existing_identity",
      configuration: {
        ...base.configuration,
        clientSecretPresent: true,
      },
      enabled: true,
      platformLoginActivationAvailable: false,
      secretPresent: true,
      version: 8,
    });
    const activatePlatformOidcDirectLogin =
      vi.fn<PhaseTwoApi["activatePlatformOidcDirectLogin"]>();
    renderPage(
      {
        activatePlatformOidcDirectLogin,
        getPlatformAuthProvider: async () => ({
          etag: '"v8"',
          value: unavailable,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(unavailable)],
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );
    await openDetail();

    const unavailableAction = screen.getByRole("button", {
      name: "Direct platform login unavailable",
    });
    expect(unavailableAction).toBeDisabled();
    expect(screen.getByText("Blocked · UserInfo is tenant-only")).toBeVisible();
    fireEvent.click(unavailableAction);
    expect(
      screen.queryByRole("form", { name: "Activate direct platform login" }),
    ).not.toBeInTheDocument();
    expect(activatePlatformOidcDirectLogin).not.toHaveBeenCalled();
  });

  it("uses authoritative SAML readiness for tenant and direct platform activation", async () => {
    const base = samlProviderFixture();
    const saml = samlProviderFixture({
      activationAvailable: true,
      configuration: {
        ...base.configuration,
        spKeyPresent: true,
        spKeyRevision: 2,
      },
      secretPresent: true,
    });
    const tenantActive = samlProviderFixture({
      ...saml,
      accountMode: "existing_identity",
      activationAvailable: false,
      enabled: true,
      platformLoginActivationAvailable: true,
      version: 2,
    });
    const directActive = samlProviderFixture({
      ...tenantActive,
      platformLoginActivationAvailable: false,
      platformLoginEnabled: true,
      version: 3,
    });
    const activatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["activatePlatformAuthProvider"]
    >(async () => ({ etag: '"v2"', value: tenantActive }));
    const activatePlatformOidcDirectLogin = vi.fn<
      PhaseTwoApi["activatePlatformOidcDirectLogin"]
    >(async () => ({ etag: '"v3"', value: directActive }));
    renderPage(
      {
        activatePlatformAuthProvider,
        activatePlatformOidcDirectLogin,
        getPlatformAuthProvider: async () => ({ etag: '"v1"', value: saml }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(saml)],
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /Inspect Workforce SAML/i }),
    );
    await screen.findByText("Trust coordinates");

    fireEvent.click(
      screen.getByRole("button", { name: "Activate tenant execution" }),
    );
    expect(
      screen.getByText("Activate SAML 2.0 tenant execution"),
    ).toBeVisible();
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Enable SAML tenant execution" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_saml to confirm"), {
      target: { value: "workforce_saml" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Activate tenant execution" })
        .at(-1)!,
    );

    await waitFor(() =>
      expect(activatePlatformAuthProvider).toHaveBeenCalled(),
    );
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Activate direct platform login",
      }),
    );
    expect(
      screen.getByText("Activate direct SAML 2.0 platform login"),
    ).toBeVisible();
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Enable direct SAML platform login" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_saml to confirm"), {
      target: { value: "workforce_saml" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Activate direct platform login" })
        .at(-1)!,
    );

    await waitFor(() =>
      expect(activatePlatformOidcDirectLogin).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        { etag: '"v2"', value: tenantActive },
        "Enable direct SAML platform login",
        { expectedVersion: 2 },
      ),
    );
  });

  it("drops lifecycle confirmation and refreshes the exact provider after a stale ETag", async () => {
    const base = oidcProviderFixture();
    const current = oidcProviderFixture({
      activationAvailable: true,
      configuration: {
        ...base.configuration,
        clientSecretPresent: true,
      },
      secretPresent: true,
    });
    const refreshed = oidcProviderFixture({
      configuration: current.configuration,
      secretPresent: true,
      updatedAt: "2026-08-27T10:06:00Z",
      version: 8,
    });
    const getPlatformAuthProvider = vi
      .fn<PhaseTwoApi["getPlatformAuthProvider"]>()
      .mockResolvedValueOnce({ etag: '"v7"', value: current })
      .mockResolvedValue({ etag: '"v8"', value: refreshed });
    const activatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["activatePlatformAuthProvider"]
    >(async () => {
      throw new PhaseTwoApiError("The provider version is stale.", 412);
    });
    renderPage({ activatePlatformAuthProvider, getPlatformAuthProvider }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);
    await openDetail();
    fireEvent.click(
      screen.getByRole("button", { name: "Activate tenant execution" }),
    );
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Attempt activation from current readiness" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_oidc to confirm"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Activate tenant execution" })
        .at(-1)!,
    );

    await waitFor(() =>
      expect(getPlatformAuthProvider).toHaveBeenCalledTimes(2),
    );
    expect(activatePlatformAuthProvider).toHaveBeenCalledOnce();
    expect(
      screen.queryByLabelText("Type workforce_oidc to confirm"),
    ).not.toBeInTheDocument();
    expect(screen.getAllByText("Staged · disabled").length).toBeGreaterThan(0);
  });

  it("ignores an OIDC lifecycle completion after provider manage permission is lost", async () => {
    const base = oidcProviderFixture();
    const current = oidcProviderFixture({
      activationAvailable: true,
      configuration: {
        ...base.configuration,
        clientSecretPresent: true,
      },
      secretPresent: true,
    });
    const activated = oidcProviderFixture({
      accountMode: "create",
      configuration: current.configuration,
      enabled: true,
      secretPresent: true,
      version: 8,
    });
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["activatePlatformAuthProvider"]>>
      >();
    const activatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["activatePlatformAuthProvider"]
    >(() => pending.promise);
    const api = createPhaseTwoApi({
      activatePlatformAuthProvider,
      getPlatformAuthProvider: async () => ({
        etag: '"v7"',
        value: current,
      }),
      listPlatformAuthProviders: async () => ({
        items: [providerSummary(current)],
      }),
    });
    const authorized: SessionView = {
      ...sessionFixture,
      permissions: [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
      ],
    };
    const view = render(pageForSession(api, authorized, vi.fn()));
    await openDetail();
    fireEvent.click(
      screen.getByRole("button", { name: "Activate tenant execution" }),
    );
    fireEvent.change(screen.getByLabelText("External identity account mode"), {
      target: { value: "create" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Activate before authority changes" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_oidc to confirm"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.click(
      screen
        .getAllByRole("button", { name: "Activate tenant execution" })
        .at(-1)!,
    );
    await waitFor(() =>
      expect(activatePlatformAuthProvider).toHaveBeenCalledOnce(),
    );

    view.rerender(
      pageForSession(
        api,
        {
          ...authorized,
          permissions: ["platform.identity_provider.read"],
        },
        vi.fn(),
      ),
    );
    await act(async () => pending.resolve({ etag: '"v8"', value: activated }));

    expect(
      screen.queryByText(/tenant execution is active in Create mode/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Deactivate tenant execution" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Type workforce_oidc to confirm"),
    ).not.toBeInTheDocument();
  });

  it("replaces OIDC secret write-only with the current ETag and body version", async () => {
    const current = oidcProviderFixture();
    const refreshed = oidcProviderFixture({
      configuration: {
        ...current.configuration,
        clientSecretPresent: true,
        clientSecretRevision: 2,
      },
      secretPresent: true,
      version: 8,
    });
    const getPlatformAuthProvider = vi
      .fn<PhaseTwoApi["getPlatformAuthProvider"]>()
      .mockResolvedValueOnce({ etag: '"v7"', value: current })
      .mockResolvedValue({ etag: '"v8"', value: refreshed });
    const replacePlatformOidcAuthProviderClientSecret = vi.fn<
      PhaseTwoApi["replacePlatformOidcAuthProviderClientSecret"]
    >(async () => '"v8"');
    renderPage(
      {
        getPlatformAuthProvider,
        replacePlatformOidcAuthProviderClientSecret,
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Set client secret" }));
    expect(
      screen.getByRole("form", { name: "Replace OIDC client secret" }),
    ).toBeVisible();
    const secret = "browser-only-secret-value";
    fireEvent.change(screen.getByLabelText("Client secret"), {
      target: { value: secret },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Rotate upstream OIDC credential" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Store write-only secret" }),
    );

    await waitFor(() =>
      expect(replacePlatformOidcAuthProviderClientSecret).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        '"v7"',
        "Rotate upstream OIDC credential",
        { clientSecret: secret, expectedVersion: 7 },
      ),
    );
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
    expect(
      await screen.findByText(/client secret was replaced write-only/i),
    ).toBeVisible();
  });

  it("updates metadata then archives with explicit audit reasons", async () => {
    const updated = oidcProviderFixture({
      displayName: "Workforce login coordinates",
      version: 8,
    });
    const updatePlatformAuthProvider = vi.fn<
      PhaseTwoApi["updatePlatformAuthProvider"]
    >(async () => ({ etag: '"v8"', value: updated }));
    const archivePlatformAuthProvider = vi.fn<
      PhaseTwoApi["archivePlatformAuthProvider"]
    >(async () => '"v9"');
    renderPage({ archivePlatformAuthProvider, updatePlatformAuthProvider }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);
    await openDetail();

    fireEvent.click(screen.getByRole("button", { name: "Edit metadata" }));
    expect(
      screen.getByRole("form", { name: "Edit provider metadata" }),
    ).toBeVisible();
    expect(screen.getByLabelText("Stable key")).toHaveAttribute("readonly");
    expect(screen.getByText(/immutable public locator/i)).toBeVisible();
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Workforce login coordinates" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Clarify the staged provider label" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replace metadata" }));

    await waitFor(() =>
      expect(updatePlatformAuthProvider).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        expect.objectContaining({
          etag: '"v7"',
          value: expect.objectContaining({ id: providerId, version: 7 }),
        }),
        "Clarify the staged provider label",
        {
          description: "Corporate workforce federation",
          displayName: "Workforce login coordinates",
          expectedVersion: 7,
          key: "workforce_oidc",
        },
      ),
    );
    expect(
      await screen.findByText(/metadata was replaced at version 8/i),
    ).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Archive provider" }));
    expect(
      screen.getByRole("form", { name: "Archive provider" }),
    ).toBeVisible();
    fireEvent.change(await screen.findByLabelText("Audit reason"), {
      target: { value: "Retire the unused staged definition" },
    });
    fireEvent.change(screen.getByLabelText("Type workforce_oidc to confirm"), {
      target: { value: "workforce_oidc" },
    });
    fireEvent.click(
      screen.getAllByRole("button", { name: "Archive provider" }).at(-1)!,
    );

    await waitFor(() =>
      expect(archivePlatformAuthProvider).toHaveBeenCalledWith(
        sessionFixture.csrfToken,
        providerId,
        '"v8"',
        "Retire the unused staged definition",
        { expectedVersion: 8 },
      ),
    );
  });

  it("keeps active tenant execution explicit after a provider metadata update", async () => {
    const staged = oidcProviderFixture();
    const active = oidcProviderFixture({
      accountMode: "existing_identity",
      configuration: {
        ...staged.configuration,
        clientSecretPresent: true,
      },
      enabled: true,
      secretPresent: true,
    });
    const updated = oidcProviderFixture({
      ...active,
      displayName: "Active workforce coordinates",
      updatedAt: "2026-08-27T10:06:00Z",
      version: 8,
    });
    renderPage(
      {
        getPlatformAuthProvider: async () => ({
          etag: '"v7"',
          value: active,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(active)],
        }),
        updatePlatformAuthProvider: async () => ({
          etag: '"v8"',
          value: updated,
        }),
      },
      ["platform.identity_provider.read", "platform.identity_provider.manage"],
    );

    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Edit metadata" }));
    fireEvent.change(screen.getByLabelText("Display name"), {
      target: { value: "Active workforce coordinates" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Clarify the active provider label" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Replace metadata" }));

    expect(
      await screen.findByText(
        /metadata was replaced.*tenant execution remains active.*direct platform login remains disabled/i,
      ),
    ).toBeVisible();
    expect(
      screen.queryByText(/provider and login remain disabled/i),
    ).not.toBeInTheDocument();
  });

  it.each([409, 412])(
    "discards stale archive confirmation and refreshes provider and bindings after %i",
    async (status) => {
      const current = oidcProviderFixture();
      const refreshed = oidcProviderFixture({
        updatedAt: "2026-08-27T10:06:00Z",
        version: 8,
      });
      const getPlatformAuthProvider = vi
        .fn<PhaseTwoApi["getPlatformAuthProvider"]>()
        .mockResolvedValueOnce({ etag: '"v7"', value: current })
        .mockResolvedValue({ etag: '"v8"', value: refreshed });
      const listPlatformAuthProviderTenantBindings = vi.fn<
        PhaseTwoApi["listPlatformAuthProviderTenantBindings"]
      >(async () => ({ items: [] }));
      const archivePlatformAuthProvider = vi.fn<
        PhaseTwoApi["archivePlatformAuthProvider"]
      >(async () => {
        throw new PhaseTwoApiError(
          "The provider conflicts with current server state.",
          status,
        );
      });
      renderPage(
        {
          archivePlatformAuthProvider,
          getPlatformAuthProvider,
          listPlatformAuthProviderTenantBindings,
        },
        [
          "platform.identity_provider.read",
          "platform.identity_provider.manage",
          "platform.identity_binding.read",
          "platform.identity_binding.manage",
        ],
      );
      await openDetail();
      await screen.findByText("No tenant bindings recorded.");

      fireEvent.click(screen.getByRole("button", { name: "Archive provider" }));
      fireEvent.change(await screen.findByLabelText("Audit reason"), {
        target: { value: "Retire the stale provider projection" },
      });
      fireEvent.change(
        screen.getByLabelText("Type workforce_oidc to confirm"),
        { target: { value: "workforce_oidc" } },
      );
      fireEvent.click(
        screen.getAllByRole("button", { name: "Archive provider" }).at(-1)!,
      );

      await waitFor(() =>
        expect(archivePlatformAuthProvider).toHaveBeenCalledOnce(),
      );
      await waitFor(() =>
        expect(getPlatformAuthProvider).toHaveBeenCalledTimes(2),
      );
      await waitFor(() =>
        expect(listPlatformAuthProviderTenantBindings).toHaveBeenCalledTimes(2),
      );
      expect(listPlatformAuthProviderTenantBindings).toHaveBeenNthCalledWith(
        2,
        providerId,
        expect.objectContaining({ includeArchived: true }),
      );
      expect(
        screen.queryByLabelText("Type workforce_oidc to confirm"),
      ).not.toBeInTheDocument();

      fireEvent.click(
        await screen.findByRole("button", { name: "Archive provider" }),
      );
      expect(await screen.findByLabelText("Audit reason")).toHaveValue("");
      expect(
        screen.getByLabelText("Type workforce_oidc to confirm"),
      ).toHaveValue("");
      fireEvent.click(
        screen.getAllByRole("button", { name: "Archive provider" }).at(-1)!,
      );
      expect(archivePlatformAuthProvider).toHaveBeenCalledOnce();
    },
  );

  it("serializes write-only secret submission and keeps the dialog locked until completion", async () => {
    const pending = deferred<string>();
    const replacePlatformOidcAuthProviderClientSecret = vi.fn<
      PhaseTwoApi["replacePlatformOidcAuthProviderClientSecret"]
    >(() => pending.promise);
    renderPage({ replacePlatformOidcAuthProviderClientSecret }, [
      "platform.identity_provider.read",
      "platform.identity_provider.manage",
    ]);
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Set client secret" }));
    fireEvent.change(screen.getByLabelText("Client secret"), {
      target: { value: "single-flight-secret" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Rotate the upstream client credential" },
    });
    const form = screen.getByLabelText("Client secret").closest("form");
    if (!form) throw new Error("Expected the secret form.");

    act(() => {
      fireEvent.submit(form);
      fireEvent.submit(form);
    });

    expect(replacePlatformOidcAuthProviderClientSecret).toHaveBeenCalledTimes(
      1,
    );
    expect(form).toHaveAttribute("aria-busy", "true");
    expect(screen.getByLabelText("Client secret")).toBeDisabled();
    expect(screen.getByLabelText("Audit reason")).toBeDisabled();
    expect(
      screen.queryByRole("button", { name: "Close" }),
    ).not.toBeInTheDocument();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.getByText("Discovery coordinates")).toBeVisible();

    await act(async () => pending.resolve('"v8"'));
    expect(
      await screen.findByText(/client secret was replaced write-only/i),
    ).toBeVisible();
  });

  it("discards an in-flight provider mutation after the session context changes", async () => {
    const pending = deferred<string>();
    const provider = oidcProviderFixture();
    const api = createPhaseTwoApi({
      getPlatformAuthProvider: async () => ({ etag: '"v7"', value: provider }),
      listPlatformAuthProviders: async () => ({
        items: [providerSummary(provider)],
      }),
      replacePlatformOidcAuthProviderClientSecret: () => pending.promise,
    });
    const clearSession = vi.fn();
    const authorizedSession: SessionView = {
      ...sessionFixture,
      permissions: [
        "platform.identity_provider.read",
        "platform.identity_provider.manage",
      ],
    };
    const view = render(pageForSession(api, authorizedSession, clearSession));
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Set client secret" }));
    fireEvent.change(screen.getByLabelText("Client secret"), {
      target: { value: "old-session-secret" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Rotate before the session changes" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Store write-only secret" }),
    );

    view.rerender(
      pageForSession(
        api,
        {
          ...authorizedSession,
          id: "0198c97d-cf4f-7000-8000-000000000199",
        },
        clearSession,
      ),
    );
    await act(async () => pending.resolve('"v8"'));

    expect(
      screen.queryByText(/client secret was replaced write-only/i),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Discovery coordinates")).not.toBeInTheDocument();
  });

  it.each([
    ["metadata", "manage"],
    ["secret", "manage"],
    ["archive", "manage"],
    ["metadata", "read"],
    ["secret", "read"],
    ["archive", "read"],
  ] as const)(
    "discards an in-flight %s mutation after %s authority is lost",
    async (operation, lostAuthority) => {
      const current = oidcProviderFixture();
      const updated = oidcProviderFixture({
        displayName: "Stale completion name",
        version: 8,
      });
      const metadataPending =
        deferred<
          Awaited<ReturnType<PhaseTwoApi["updatePlatformAuthProvider"]>>
        >();
      const secretPending = deferred<string>();
      const archivePending = deferred<string>();
      const updatePlatformAuthProvider = vi.fn<
        PhaseTwoApi["updatePlatformAuthProvider"]
      >(() => metadataPending.promise);
      const replacePlatformOidcAuthProviderClientSecret = vi.fn<
        PhaseTwoApi["replacePlatformOidcAuthProviderClientSecret"]
      >(() => secretPending.promise);
      const archivePlatformAuthProvider = vi.fn<
        PhaseTwoApi["archivePlatformAuthProvider"]
      >(() => archivePending.promise);
      const api = createPhaseTwoApi({
        archivePlatformAuthProvider,
        getPlatformAuthProvider: async () => ({
          etag: '"v7"',
          value: current,
        }),
        listPlatformAuthProviders: async () => ({
          items: [providerSummary(current)],
        }),
        replacePlatformOidcAuthProviderClientSecret,
        updatePlatformAuthProvider,
      });
      const authorized: SessionView = {
        ...sessionFixture,
        permissions: [
          "platform.identity_provider.read",
          "platform.identity_provider.manage",
        ],
      };
      const clearSession = vi.fn();
      const view = render(pageForSession(api, authorized, clearSession));
      await openDetail();

      if (operation === "metadata") {
        fireEvent.click(screen.getByRole("button", { name: "Edit metadata" }));
        fireEvent.change(screen.getByLabelText("Display name"), {
          target: { value: "Stale completion name" },
        });
        fireEvent.change(screen.getByLabelText("Audit reason"), {
          target: { value: "Attempt metadata before authority loss" },
        });
        fireEvent.click(
          screen.getByRole("button", { name: "Replace metadata" }),
        );
        await waitFor(() =>
          expect(updatePlatformAuthProvider).toHaveBeenCalledTimes(1),
        );
      } else if (operation === "secret") {
        fireEvent.click(
          screen.getByRole("button", { name: "Set client secret" }),
        );
        fireEvent.change(screen.getByLabelText("Client secret"), {
          target: { value: "stale-authority-secret" },
        });
        fireEvent.change(screen.getByLabelText("Audit reason"), {
          target: { value: "Attempt secret before authority loss" },
        });
        fireEvent.click(
          screen.getByRole("button", { name: "Store write-only secret" }),
        );
        await waitFor(() =>
          expect(
            replacePlatformOidcAuthProviderClientSecret,
          ).toHaveBeenCalledTimes(1),
        );
      } else {
        fireEvent.click(
          screen.getByRole("button", { name: "Archive provider" }),
        );
        fireEvent.change(await screen.findByLabelText("Audit reason"), {
          target: { value: "Attempt archive before authority loss" },
        });
        fireEvent.change(
          screen.getByLabelText("Type workforce_oidc to confirm"),
          { target: { value: "workforce_oidc" } },
        );
        fireEvent.click(
          screen.getAllByRole("button", { name: "Archive provider" }).at(-1)!,
        );
        await waitFor(() =>
          expect(archivePlatformAuthProvider).toHaveBeenCalledTimes(1),
        );
      }

      const lostPermissions: SessionView["permissions"] =
        lostAuthority === "read" ? [] : ["platform.identity_provider.read"];
      view.rerender(
        pageForSession(
          api,
          { ...authorized, permissions: lostPermissions },
          clearSession,
        ),
      );
      if (lostAuthority === "read") {
        expect(
          await screen.findByText(
            /global identity providers are not available/i,
          ),
        ).toBeVisible();
      } else {
        await waitFor(() =>
          expect(
            screen.queryByRole("button", { name: "Edit metadata" }),
          ).not.toBeInTheDocument(),
        );
      }

      await act(async () => {
        if (operation === "metadata") {
          metadataPending.resolve({ etag: '"v8"', value: updated });
        } else if (operation === "secret") {
          secretPending.resolve('"v8"');
        } else {
          archivePending.resolve('"v8"');
        }
      });

      view.rerender(pageForSession(api, authorized, clearSession));
      if (lostAuthority === "read") {
        expect(
          screen.queryByText("Discovery coordinates"),
        ).not.toBeInTheDocument();
        fireEvent.click(
          await screen.findByRole("button", {
            name: /Inspect Workforce OIDC/i,
          }),
        );
      }
      expect(await screen.findByText("Discovery coordinates")).toBeVisible();
      expect(
        screen.queryByText(/metadata was replaced at version/i),
      ).not.toBeInTheDocument();
      expect(
        screen.queryByText(/client secret was replaced write-only/i),
      ).not.toBeInTheDocument();
      expect(screen.queryByText(/was archived/i)).not.toBeInTheDocument();
    },
  );

  it("allows only one pagination request for a cursor at a time", async () => {
    const cursor = "0198c97d-cf4f-7000-8000-000000000099";
    const pending =
      deferred<Awaited<ReturnType<PhaseTwoApi["listPlatformAuthProviders"]>>>();
    const provider = oidcProviderFixture();
    const listPlatformAuthProviders = vi
      .fn<PhaseTwoApi["listPlatformAuthProviders"]>()
      .mockResolvedValueOnce({
        items: [providerSummary(provider)],
        nextCursor: cursor,
      })
      .mockImplementationOnce(() => pending.promise);
    renderPage({ listPlatformAuthProviders }, [
      "platform.identity_provider.read",
    ]);
    await screen.findByText("Workforce OIDC");
    const loadMore = screen.getByRole("button", {
      name: "Load more providers",
    });

    act(() => {
      fireEvent.click(loadMore);
      fireEvent.click(loadMore);
    });

    expect(listPlatformAuthProviders).toHaveBeenCalledTimes(2);
    await act(async () => pending.resolve({ items: [] }));
    expect(
      screen.queryByText(/cursor did not advance/i),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(
        "More platform identity providers could not be loaded.",
      ),
    ).not.toBeInTheDocument();
  });

  it("aborts a pending provider page when the session context changes", async () => {
    const first = oidcProviderFixture();
    const stale = oidcProviderFixture({
      displayName: "Stale session provider",
      id: "0198c97d-cf4f-7000-8000-000000000099",
      key: "stale_session_provider",
    });
    const pending =
      deferred<Awaited<ReturnType<PhaseTwoApi["listPlatformAuthProviders"]>>>();
    let paginationSignal: AbortSignal | undefined;
    const listPlatformAuthProviders = vi.fn<
      PhaseTwoApi["listPlatformAuthProviders"]
    >((options) => {
      if (options?.after) {
        paginationSignal = options.signal;
        return pending.promise;
      }
      return Promise.resolve({
        items: [providerSummary(first)],
        nextCursor: first.id,
      });
    });
    const api = createPhaseTwoApi({ listPlatformAuthProviders });
    const authorized: SessionView = {
      ...sessionFixture,
      permissions: ["platform.identity_provider.read"],
    };
    const clearSession = vi.fn();
    const view = render(pageForSession(api, authorized, clearSession));

    await screen.findByText(first.displayName);
    fireEvent.click(
      screen.getByRole("button", { name: "Load more providers" }),
    );
    await waitFor(() =>
      expect(listPlatformAuthProviders).toHaveBeenCalledTimes(2),
    );
    expect(paginationSignal?.aborted).toBe(false);

    view.rerender(
      pageForSession(
        api,
        {
          ...authorized,
          id: "0198c97d-cf4f-7000-8000-000000000199",
        },
        clearSession,
      ),
    );
    expect(paginationSignal?.aborted).toBe(true);
    await waitFor(() =>
      expect(listPlatformAuthProviders).toHaveBeenCalledTimes(3),
    );
    await act(async () => pending.resolve({ items: [providerSummary(stale)] }));

    expect(screen.queryByText(stale.displayName)).not.toBeInTheDocument();
    expect(screen.getByText(first.displayName)).toBeVisible();
  });

  it("rejects unseen backwards provider cursors and items before a clean retry", async () => {
    const first = oidcProviderFixture();
    const backwards = oidcProviderFixture({
      displayName: "Backwards provider",
      id: "0198c97d-cf4f-7000-8000-000000000077",
      key: "backwards_provider",
    });
    const forward = oidcProviderFixture({
      displayName: "Forward provider",
      id: "0198c97d-cf4f-7000-8000-000000000099",
      key: "forward_provider",
    });
    const listPlatformAuthProviders = vi
      .fn<PhaseTwoApi["listPlatformAuthProviders"]>()
      .mockResolvedValueOnce({
        items: [providerSummary(first)],
        nextCursor: first.id,
      })
      .mockResolvedValueOnce({
        items: [providerSummary(forward)],
        nextCursor: backwards.id,
      })
      .mockResolvedValueOnce({ items: [providerSummary(backwards)] })
      .mockResolvedValueOnce({ items: [providerSummary(forward)] });
    renderPage({ listPlatformAuthProviders }, [
      "platform.identity_provider.read",
    ]);

    await screen.findByText(first.displayName);
    fireEvent.click(
      screen.getByRole("button", { name: "Load more providers" }),
    );
    expect(
      await screen.findByText(
        "More platform identity providers could not be loaded.",
      ),
    ).toBeVisible();
    expect(screen.queryByText(forward.displayName)).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Load more providers" }),
    );
    await waitFor(() =>
      expect(listPlatformAuthProviders).toHaveBeenCalledTimes(3),
    );
    expect(screen.queryByText(backwards.displayName)).not.toBeInTheDocument();
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Load more providers" }),
      ).toBeEnabled(),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Load more providers" }),
    );
    expect(await screen.findByText(forward.displayName)).toBeVisible();
    expect(listPlatformAuthProviders).toHaveBeenCalledTimes(4);
  });

  it("rejects a repeated stable provider key across pages and permits a clean retry", async () => {
    const first = oidcProviderFixture();
    const repeatedKey = oidcProviderFixture({
      id: "0198c97d-cf4f-7000-8000-000000000089",
      key: first.key,
      displayName: "Conflicting workforce provider",
    });
    const clean = oidcProviderFixture({
      id: repeatedKey.id,
      key: "workforce_oidc_secondary",
      displayName: "Secondary workforce provider",
    });
    const listPlatformAuthProviders = vi
      .fn<PhaseTwoApi["listPlatformAuthProviders"]>()
      .mockResolvedValueOnce({
        items: [providerSummary(first)],
        nextCursor: first.id,
      })
      .mockResolvedValueOnce({ items: [providerSummary(repeatedKey)] })
      .mockResolvedValueOnce({ items: [providerSummary(clean)] });
    renderPage({ listPlatformAuthProviders }, [
      "platform.identity_provider.read",
    ]);

    await screen.findByText(first.displayName);
    fireEvent.click(
      screen.getByRole("button", { name: "Load more providers" }),
    );
    expect(
      await screen.findByText(
        "More platform identity providers could not be loaded.",
      ),
    ).toBeVisible();
    expect(screen.queryByText(repeatedKey.displayName)).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Load more providers" }),
    );
    expect(await screen.findByText(clean.displayName)).toBeVisible();
    expect(listPlatformAuthProviders).toHaveBeenCalledTimes(3);
  });
});

async function openDetail(): Promise<void> {
  fireEvent.click(
    await screen.findByRole("button", { name: /Inspect Workforce OIDC/i }),
  );
  await screen.findByText("Discovery coordinates");
}

async function submitOidcCreate(
  key: string,
  displayName: string,
): Promise<void> {
  fireEvent.click(
    await screen.findByRole("button", { name: "Create staged provider" }),
  );
  fireEvent.change(screen.getByLabelText("Stable key"), {
    target: { value: key },
  });
  fireEvent.change(screen.getByLabelText("Display name"), {
    target: { value: displayName },
  });
  fireEvent.change(screen.getByLabelText("Issuer"), {
    target: { value: "https://identity.example.com" },
  });
  fireEvent.change(screen.getByLabelText("Client ID"), {
    target: { value: "periapsis-platform" },
  });
  fireEvent.change(screen.getByLabelText("Audit reason"), {
    target: { value: `Stage ${displayName}` },
  });
  fireEvent.click(
    screen.getByRole("button", { name: "Create disabled provider" }),
  );
}

function renderPage(
  overrides: Partial<PhaseTwoApi>,
  permissions: SessionView["permissions"],
): void {
  const provider = oidcProviderFixture();
  const api = createPhaseTwoApi({
    getPlatformAuthProvider: async () => ({ etag: '"v7"', value: provider }),
    listPlatformAuthProviders: async () => ({
      items: [providerSummary(provider)],
    }),
    ...overrides,
  });
  render(pageForSession(api, { ...sessionFixture, permissions }, vi.fn()));
}

function pageForSession(
  api: PhaseTwoApi,
  session: SessionView,
  clearSession: (expectedSessionId?: string) => void,
): React.JSX.Element {
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession,
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session,
        updateSession: vi.fn(),
      }}
    >
      <PlatformAuthProvidersPage />
    </SessionContext.Provider>
  );
}

function providerSummary(
  provider: PlatformAuthProviderView,
): PlatformAuthProviderSummaryView {
  return {
    activationAvailable: provider.activationAvailable,
    archivedAt: provider.archivedAt,
    configured: provider.configured,
    createdAt: provider.createdAt,
    description: provider.description,
    displayName: provider.displayName,
    enabled: provider.enabled,
    id: provider.id,
    key: provider.key,
    kind: provider.kind,
    platformLoginActivationAvailable: provider.platformLoginActivationAvailable,
    platformLoginEnabled: provider.platformLoginEnabled,
    secretPresent: provider.secretPresent,
    updatedAt: provider.updatedAt,
    version: provider.version,
  };
}

function oidcProviderFixture(
  overrides: Partial<Extract<PlatformAuthProviderView, { kind: "oidc" }>> = {},
): Extract<PlatformAuthProviderView, { kind: "oidc" }> {
  return {
    accountMode: "disabled",
    activationAvailable: false,
    archivedAt: null,
    assurancePolicyRevision: 1,
    configuration: {
      allowRefreshToken: false,
      clientId: "periapsis-platform",
      clientSecretPresent: false,
      clientSecretRevision: 1,
      discoveryRevision: 1,
      extraScopes: ["profile", "email"],
      issuer: "https://identity.example.com",
      jwksRevision: 1,
      postLogoutRedirectUri: "https://soc.example.com/signed-out",
      redirectUri: "https://soc.example.com/api/v1/auth/platform/oidc/callback",
      tenantRedirectUri:
        "https://soc.example.com/api/v1/auth/federated/oidc/callback",
      useUserInfo: true,
    },
    configurationRevision: 1,
    configured: true,
    createdAt: "2026-08-27T10:00:00Z",
    description: "Corporate workforce federation",
    displayName: "Workforce OIDC",
    enabled: false,
    id: providerId,
    key: "workforce_oidc",
    kind: "oidc",
    planRevision: 1,
    platformLoginActivationAvailable: false,
    platformLoginEnabled: false,
    secretPresent: false,
    securityRevision: 1,
    updatedAt: "2026-08-27T10:05:00Z",
    version: 7,
    ...overrides,
  };
}

function platformAccountFixture(): PlatformAuthProviderAccountView {
  return {
    admittedConfigurationRevision: 1,
    admittedSecurityRevision: 1,
    createdAt: "2026-08-28T11:00:00Z",
    id: "0198c97d-cf4f-7000-8000-000000000089",
    lastObservationState: "known",
    lastObservedAt: "2026-08-28T11:05:00Z",
    providerId,
    retiredAt: null,
    state: "active",
    updatedAt: "2026-08-28T11:05:00Z",
    user: {
      active: true,
      displayName: "Ada Account",
      email: "ada.account@example.invalid",
      id: "0198c97d-cf4f-7000-8000-000000000090",
      version: 1,
    },
    version: 3,
  };
}

function ldapProviderFixture(
  overrides: Partial<Extract<PlatformAuthProviderView, { kind: "ldap" }>> = {},
): Extract<PlatformAuthProviderView, { kind: "ldap" }> {
  const ldap = createLdapProviderDraft("active_directory");
  return {
    accountMode: "disabled",
    activationAvailable: false,
    archivedAt: null,
    assurancePolicyRevision: 1,
    configuration: {
      ...ldap.configuration,
      jitMode: "existing_identity",
      noMatchPolicy: "deny",
    },
    configurationRevision: 1,
    configured: true,
    createdAt: "2026-08-27T10:00:00Z",
    description: "Corporate directory login",
    displayName: "Workforce LDAP",
    enabled: false,
    endpoints: ldap.endpoints.map((endpoint) => ({
      ...endpoint,
      id: "0198c97d-cf4f-7000-8000-000000000090",
    })),
    id: providerId,
    key: "workforce_ldap",
    kind: "ldap",
    mappings: [],
    planRevision: 1,
    platformLoginActivationAvailable: false,
    platformLoginEnabled: false,
    secretPresent: false,
    securityRevision: 1,
    updatedAt: "2026-08-27T10:05:00Z",
    version: 7,
    ...overrides,
  };
}

function samlProviderFixture(
  overrides: Partial<Extract<PlatformAuthProviderView, { kind: "saml" }>> = {},
): Extract<PlatformAuthProviderView, { kind: "saml" }> {
  return {
    accountMode: "disabled",
    activationAvailable: false,
    archivedAt: null,
    assurancePolicyRevision: 1,
    configuration: {
      acsUrl: "https://soc.example.com/api/v1/auth/platform/saml/acs",
      clockSkewNanoseconds: 120_000_000_000,
      encryptionPolicy: "disabled",
      expectedEntityId: "https://idp.example.com/entity",
      maxAuthenticationAgeNanoseconds: 28_800_000_000_000,
      metadataRevision: 1,
      redirectSignatureAlgorithm:
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      requestedAuthnContexts: [
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
      ],
      signaturePolicy: "signed_assertion",
      spEntityId:
        "https://soc.example.com/api/v1/auth/platform/saml/workforce_saml/metadata",
      spKeyPresent: false,
      spKeyRevision: 1,
      subjectSource: "persistent_nameid",
    },
    configurationRevision: 1,
    configured: true,
    createdAt: "2026-08-27T10:00:00Z",
    description: "Corporate workforce SAML federation",
    displayName: "Workforce SAML",
    enabled: false,
    id: providerId,
    key: "workforce_saml",
    kind: "saml",
    planRevision: 1,
    platformLoginActivationAvailable: false,
    platformLoginEnabled: false,
    secretPresent: false,
    securityRevision: 1,
    updatedAt: "2026-08-27T10:05:00Z",
    version: 1,
    ...overrides,
  };
}

function deferred<T>(): {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T) => void;
} {
  let reject!: (reason?: unknown) => void;
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    reject = rejectPromise;
    resolve = resolvePromise;
  });
  return { promise, reject, resolve };
}
