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
  type PlatformAuthProviderTenantBindingView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi } from "../test/phase-two-fixtures";
import { PlatformAuthProviderTenantBindings } from "./platform-auth-provider-tenant-bindings";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const bindingId = "0198c97d-cf4f-7000-8000-000000000089";
const tenantId = "0198c97d-cf4f-7000-8000-000000000090";

afterEach(cleanup);

describe("PlatformAuthProviderTenantBindings", () => {
  it("shows loading, then an accessible empty state", async () => {
    const pending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>
        >
      >();
    renderBindings({
      listPlatformAuthProviderTenantBindings: vi
        .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
        .mockReturnValue(pending.promise),
    });

    expect(screen.getByRole("status")).toHaveTextContent(
      "Loading tenant bindings",
    );
    pending.resolve({ items: [] });
    expect(
      await screen.findByText("No tenant bindings recorded."),
    ).toBeVisible();
    expect(
      screen.getByRole("region", { name: "Tenant bindings" }),
    ).toBeVisible();
  });

  it("does not offer binding creation while provider execution is active", async () => {
    renderBindings(
      { listPlatformAuthProviderTenantBindings: async () => ({ items: [] }) },
      { providerEnabled: true },
    );

    expect(
      await screen.findByText("No tenant bindings recorded."),
    ).toBeVisible();
    expect(screen.getByText("Provider execution active")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
  });

  it("treats a ready binding as proof that provider execution is active", async () => {
    const ready = bindingFixture({ activationAvailable: true });
    renderBindings({
      listPlatformAuthProviderTenantBindings: async () => ({ items: [ready] }),
    });

    expect(await screen.findByText("Ready to activate")).toBeVisible();
    expect(screen.getByText("Provider execution active")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
  });

  it("keeps binding lifecycle controls absent for a known SAML provider", async () => {
    const poisonedReady = bindingFixture({ activationAvailable: true });
    renderBindings(
      {
        getPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v7-t11"',
          value: poisonedReady,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({
          items: [poisonedReady],
        }),
      },
      { providerKind: "saml" },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    await screen.findByText(/If-Match "v7-t11"/);
    expect(
      screen.queryByRole("button", { name: "Activate tenant admission" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Deactivate tenant admission" }),
    ).not.toBeInTheDocument();
  });

  it("keeps binding lifecycle controls absent for a known disabled provider", async () => {
    const poisonedReady = bindingFixture({ activationAvailable: true });
    renderBindings(
      {
        getPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v7-t11"',
          value: poisonedReady,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({
          items: [poisonedReady],
        }),
      },
      { providerEnabled: false, providerKind: "oidc" },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    await screen.findByText(/If-Match "v7-t11"/);
    expect(
      screen.queryByRole("button", { name: "Activate tenant admission" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Deactivate tenant admission" }),
    ).not.toBeInTheDocument();
  });

  it("omits tenant-membership JIT when the known provider cannot create identities", async () => {
    const ready = bindingFixture({ activationAvailable: true });
    renderBindings(
      {
        getPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v7-t11"',
          value: ready,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({
          items: [ready],
        }),
      },
      {
        providerAccountMode: "existing_identity",
        providerKind: "oidc",
      },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Activate tenant admission" }),
    );
    const form = screen.getByRole("form", { name: "Activate tenant binding" });
    expect(
      within(form).getByRole("option", { name: "Disabled" }),
    ).toBeVisible();
    expect(
      within(form).queryByRole("option", {
        name: "Create tenant membership/access",
      }),
    ).not.toBeInTheDocument();
  });

  it("renders a retryable list error and recovers", async () => {
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockRejectedValueOnce(new Error("temporary outage"))
      .mockResolvedValueOnce({ items: [] });
    renderBindings({ listPlatformAuthProviderTenantBindings: list });

    expect(
      await screen.findByText("Tenant bindings could not be loaded."),
    ).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Retry tenant bindings" }),
    );
    expect(
      await screen.findByText("No tenant bindings recorded."),
    ).toBeVisible();
    expect(list).toHaveBeenCalledTimes(2);
  });

  it("merges an advancing tenant-binding page without losing the first page", async () => {
    const first = bindingFixture();
    const second = bindingFixture({
      activationAvailable: true,
      id: "0198c97d-cf4f-7000-8000-000000000091",
      loginKey: "workforce_beta",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
        status: "active",
        version: 12,
      },
      version: 8,
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [first], nextCursor: first.id })
      .mockResolvedValueOnce({ items: [second] });
    renderBindings({ listPlatformAuthProviderTenantBindings: list });

    expect(await screen.findByText("Acme SOC")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));

    expect(await screen.findByText("Beta SOC")).toBeVisible();
    expect(screen.getByText("Acme SOC")).toBeVisible();
    expect(screen.getByText("Provider execution active")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
    expect(list).toHaveBeenNthCalledWith(
      2,
      providerId,
      expect.objectContaining({
        after: first.id,
        includeArchived: true,
      }),
    );
    expect(
      screen.queryByRole("button", { name: "Load more bindings" }),
    ).not.toBeInTheDocument();
  });

  it.each(["cursor", "binding", "tenant"] as const)(
    "rejects a repeated %s across pages and permits a clean retry",
    async (repeated) => {
      const first = bindingFixture();
      const second = bindingFixture({
        id: "0198c97d-cf4f-7000-8000-000000000091",
        loginKey: "workforce_beta",
        tenant: {
          id: "0198c97d-cf4f-7000-8000-000000000092",
          name: "Beta SOC",
          slug: "beta",
          status: "active",
          version: 12,
        },
        version: 8,
      });
      const repeatedTenant = {
        ...second,
        tenant: { ...first.tenant },
      };
      const repeatedBinding = {
        ...first,
        tenant: { ...second.tenant },
      };
      const malformedPage =
        repeated === "cursor"
          ? { items: [second], nextCursor: first.id }
          : repeated === "binding"
            ? { items: [repeatedBinding] }
            : { items: [repeatedTenant] };
      const list = vi
        .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
        .mockResolvedValueOnce({ items: [first], nextCursor: first.id })
        .mockResolvedValueOnce(malformedPage)
        .mockResolvedValueOnce({ items: [second] });
      renderBindings({ listPlatformAuthProviderTenantBindings: list });

      await screen.findByText("Acme SOC");
      fireEvent.click(
        screen.getByRole("button", { name: "Load more bindings" }),
      );
      expect(
        await screen.findByText("More tenant bindings could not be loaded."),
      ).toBeVisible();
      expect(screen.queryByText("Beta SOC")).not.toBeInTheDocument();

      fireEvent.click(
        screen.getByRole("button", { name: "Load more bindings" }),
      );
      expect(await screen.findByText("Beta SOC")).toBeVisible();
      expect(list).toHaveBeenCalledTimes(3);
    },
  );

  it("rejects a continuation item that does not advance beyond the requested cursor", async () => {
    const first = bindingFixture();
    const older = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000087",
      loginKey: "workforce_older",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000096",
        name: "Older SOC",
        slug: "older",
        status: "active",
        version: 12,
      },
    });
    const next = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      loginKey: "workforce_beta",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
        status: "active",
        version: 12,
      },
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [first], nextCursor: first.id })
      .mockResolvedValueOnce({ items: [older] })
      .mockResolvedValueOnce({ items: [next] });
    renderBindings({ listPlatformAuthProviderTenantBindings: list });

    await screen.findByText("Acme SOC");
    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));
    expect(
      await screen.findByText("More tenant bindings could not be loaded."),
    ).toBeVisible();
    expect(screen.queryByText("Older SOC")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));
    expect(await screen.findByText("Beta SOC")).toBeVisible();
    expect(list).toHaveBeenCalledTimes(3);
  });

  it("rejects a historical cursor cycle without discarding accepted pages", async () => {
    const first = bindingFixture();
    const second = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      loginKey: "workforce_beta",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
        status: "active",
        version: 12,
      },
    });
    const third = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000093",
      loginKey: "workforce_gamma",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000094",
        name: "Gamma SOC",
        slug: "gamma",
        status: "active",
        version: 13,
      },
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [first], nextCursor: first.id })
      .mockResolvedValueOnce({ items: [second], nextCursor: second.id })
      .mockResolvedValueOnce({ items: [third], nextCursor: first.id })
      .mockResolvedValueOnce({ items: [third] });
    renderBindings({ listPlatformAuthProviderTenantBindings: list });

    await screen.findByText("Acme SOC");
    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));
    expect(await screen.findByText("Beta SOC")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));

    expect(
      await screen.findByText("More tenant bindings could not be loaded."),
    ).toBeVisible();
    expect(screen.getByText("Acme SOC")).toBeVisible();
    expect(screen.getByText("Beta SOC")).toBeVisible();
    expect(screen.queryByText("Gamma SOC")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));
    expect(await screen.findByText("Gamma SOC")).toBeVisible();
    expect(list).toHaveBeenCalledTimes(4);
  });

  it("ignores a late pagination response after the provider changes", async () => {
    const first = bindingFixture();
    const staleSecond = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      loginKey: "workforce_beta",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
        status: "active",
        version: 12,
      },
    });
    const nextProviderId = "0198c97d-cf4f-7000-8000-000000000093";
    const current = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000094",
      loginKey: "workforce_gamma",
      providerId: nextProviderId,
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000095",
        name: "Gamma SOC",
        slug: "gamma",
        status: "active",
        version: 13,
      },
    });
    const stalePage =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>
        >
      >();
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>(
      (requestedProviderId, options) => {
        if (requestedProviderId === providerId && options?.after) {
          return stalePage.promise;
        }
        return Promise.resolve(
          requestedProviderId === providerId
            ? { items: [first], nextCursor: first.id }
            : { items: [current], nextCursor: first.id },
        );
      },
    );
    const view = renderBindings({
      listPlatformAuthProviderTenantBindings: list,
    });

    await screen.findByText("Acme SOC");
    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    view.rerenderProps({ providerId: nextProviderId });
    expect(await screen.findByText("Gamma SOC")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Load more bindings" }),
    ).toBeVisible();

    await act(async () => stalePage.resolve({ items: [staleSecond] }));
    expect(screen.getByText("Gamma SOC")).toBeVisible();
    expect(screen.queryByText("Beta SOC")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Load more bindings" }),
    ).toBeVisible();
  });

  it("aborts stale pagination when a mutation reloads the binding list", async () => {
    const first = bindingFixture();
    const staleSecond = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      loginKey: "workforce_beta",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
        status: "active",
        version: 12,
      },
    });
    const stalePage =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>
        >
      >();
    let paginationSignal: AbortSignal | undefined;
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>(
      (_requestedProviderId, options) => {
        if (options?.after) {
          paginationSignal = options.signal;
          return stalePage.promise;
        }
        return Promise.resolve({ items: [first], nextCursor: first.id });
      },
    );
    const create = vi
      .fn<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>()
      .mockResolvedValue({
        etag: '"v1-t11"',
        location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
        value: bindingFixture({ version: 1 }),
      });
    renderBindings({
      createPlatformAuthProviderTenantBinding: create,
      listPlatformAuthProviderTenantBindings: list,
    });

    await screen.findByText("Acme SOC");
    fireEvent.click(screen.getByRole("button", { name: "Load more bindings" }));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    fireEvent.click(
      screen.getByRole("button", { name: "Create tenant binding" }),
    );
    const form = screen.getByRole("form", { name: "Create tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Profile priority"), {
      target: { value: "50" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Reload after reserving tenant admission" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    await waitFor(() => expect(list).toHaveBeenCalledTimes(3));
    expect(paginationSignal?.aborted).toBe(true);
    await act(async () => stalePage.resolve({ items: [staleSecond] }));
    expect(screen.queryByText("Beta SOC")).not.toBeInTheDocument();
  });

  it("clears an expired session without retaining an unauthenticated error", async () => {
    const onUnauthenticated = vi.fn();
    renderBindings(
      {
        listPlatformAuthProviderTenantBindings: vi
          .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
          .mockRejectedValue(new PhaseTwoApiError("Session expired", 401)),
      },
      { onUnauthenticated },
    );

    await waitFor(() => expect(onUnauthenticated).toHaveBeenCalledOnce());
    expect(screen.queryByText("Session expired")).not.toBeInTheDocument();
  });

  it("reports a server-side forbidden result despite advisory UI permission", async () => {
    const onPermissionError = vi.fn();
    renderBindings(
      {
        listPlatformAuthProviderTenantBindings: vi
          .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
          .mockRejectedValue(new PhaseTwoApiError("Access denied", 403)),
      },
      { onPermissionError },
    );

    expect(await screen.findByText("Access denied")).toBeVisible();
    expect(onPermissionError).toHaveBeenCalledOnce();
    expect(
      screen.getByRole("button", { name: "Retry tenant bindings" }),
    ).toBeVisible();
  });

  it("does not restore stale binding data or create input after read permission returns", async () => {
    const binding = bindingFixture();
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [binding] })
      .mockResolvedValueOnce({ items: [] });
    const view = renderBindings({
      listPlatformAuthProviderTenantBindings: list,
    });

    await screen.findByText("Acme SOC");
    fireEvent.click(
      screen.getByRole("button", { name: "Create tenant binding" }),
    );
    fireEvent.change(screen.getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });

    view.rerenderProps({ canRead: false });
    expect(
      screen.getByText("Binding read permission not returned"),
    ).toBeVisible();
    view.rerenderProps({ canRead: true });

    expect(screen.queryByText("Acme SOC")).not.toBeInTheDocument();
    await screen.findByText("No tenant bindings recorded.");
    fireEvent.click(
      screen.getByRole("button", { name: "Create tenant binding" }),
    );
    expect(screen.getByLabelText("Tenant ID")).toHaveValue("");
    expect(list).toHaveBeenCalledTimes(2);
  });

  it("does not query or expose bindings without explicit read permission", () => {
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>();
    renderBindings(
      { listPlatformAuthProviderTenantBindings: list },
      { canManage: true, canRead: false },
    );

    expect(
      screen.getByText("Binding read permission not returned"),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
  });

  it("keeps read-only binding detail inspectable and all mutations hidden", async () => {
    const binding = bindingFixture();
    renderBindings(
      {
        getPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v7-t11"',
          value: binding,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({
          items: [binding],
        }),
      },
      { canManage: false },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Inspect .* binding/i }),
    );
    expect(await screen.findByText("Staged · not ready")).toBeVisible();
    expect(screen.getByText("Read-only authority")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Edit key and priority" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Archive binding" }),
    ).not.toBeInTheDocument();
  });

  it("creates only staged binding metadata with no activation control", async () => {
    const created = bindingFixture({ version: 1 });
    const onMutationBusyChange = vi.fn();
    const create = vi.fn<
      PhaseTwoApi["createPlatformAuthProviderTenantBinding"]
    >(async () => ({
      etag: '"v1-t11"',
      location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
      value: created,
    }));
    renderBindings(
      {
        createPlatformAuthProviderTenantBinding: create,
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
      },
      { onMutationBusyChange },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    const form = screen.getByRole("form", { name: "Create tenant binding" });
    expect(within(form).queryByRole("checkbox")).not.toBeInTheDocument();
    expect(within(form).queryByText(/enable sso/i)).not.toBeInTheDocument();
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Profile priority"), {
      target: { value: "50" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Reserve Acme federation coordinates" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledOnce());
    expect(create.mock.calls[0]?.[4]).toEqual({
      loginKey: "workforce_acme",
      profilePriority: 50,
      tenantId,
    });
    expect(create.mock.calls[0]?.[4]).not.toHaveProperty("enabled");
    expect(await screen.findByText("Staged · not ready")).toBeVisible();
    expect(onMutationBusyChange).toHaveBeenCalledWith(true);
    expect(onMutationBusyChange).toHaveBeenLastCalledWith(false);
  });

  it("reuses the payload-bound idempotency key for an unchanged create retry", async () => {
    const created = bindingFixture({ version: 1 });
    const create = vi
      .fn<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>()
      .mockRejectedValueOnce(new Error("connection lost"))
      .mockResolvedValueOnce({
        etag: '"v1-t11"',
        location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
        value: created,
      });
    renderBindings({
      createPlatformAuthProviderTenantBinding: create,
      listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    const form = screen.getByRole("form", { name: "Create tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Profile priority"), {
      target: { value: "50" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Reserve Acme federation coordinates" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );
    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect(
        within(form).getByRole("button", { name: "Create staged binding" }),
      ).toBeEnabled(),
    );
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(create.mock.calls[0]?.[2]).toBe(create.mock.calls[1]?.[2]);
    expect(await screen.findByText("Staged · not ready")).toBeVisible();
  });

  it.each([
    ["target tenant", "Tenant ID", "0198c97d-cf4f-7000-8000-000000000091"],
    ["login metadata", "Tenant login key", "workforce_beta"],
    ["profile priority", "Profile priority", "51"],
    [
      "audit reason",
      "Binding audit reason",
      "Reserve updated federation coordinates",
    ],
  ])(
    "rotates the idempotency key when the %s changes after an uncertain create",
    async (_label, fieldLabel, changedValue) => {
      const create = vi
        .fn<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>()
        .mockRejectedValue(new Error("connection lost"));
      renderBindings({
        createPlatformAuthProviderTenantBinding: create,
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
      });

      fireEvent.click(
        await screen.findByRole("button", { name: "Create tenant binding" }),
      );
      const form = screen.getByRole("form", { name: "Create tenant binding" });
      fireEvent.change(within(form).getByLabelText("Tenant ID"), {
        target: { value: tenantId },
      });
      fireEvent.change(within(form).getByLabelText("Tenant login key"), {
        target: { value: "workforce_acme" },
      });
      fireEvent.change(within(form).getByLabelText("Profile priority"), {
        target: { value: "50" },
      });
      fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
        target: { value: "Reserve Acme federation coordinates" },
      });
      fireEvent.click(
        within(form).getByRole("button", { name: "Create staged binding" }),
      );
      await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
      await waitFor(() =>
        expect(
          within(form).getByRole("button", { name: "Create staged binding" }),
        ).toBeEnabled(),
      );

      fireEvent.change(within(form).getByLabelText(fieldLabel), {
        target: { value: changedValue },
      });
      fireEvent.click(
        within(form).getByRole("button", { name: "Create staged binding" }),
      );

      await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
      expect(create.mock.calls[1]?.[2]).not.toBe(create.mock.calls[0]?.[2]);
    },
  );

  it("retires a conflicted create attempt and reloads the authorized binding list", async () => {
    const existing = bindingFixture({ version: 1 });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [] })
      .mockResolvedValue({ items: [existing] });
    const create = vi
      .fn<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>()
      .mockRejectedValueOnce(
        new PhaseTwoApiError("The request conflicts with current state.", 409),
      )
      .mockRejectedValueOnce(new Error("connection lost"));
    const onNotice = vi.fn();
    renderBindings(
      {
        createPlatformAuthProviderTenantBinding: create,
        listPlatformAuthProviderTenantBindings: list,
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    let form = screen.getByRole("form", { name: "Create tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Profile priority"), {
      target: { value: "50" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Retry an uncertain binding command" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(create).toHaveBeenCalledOnce();
    expect(
      screen.queryByRole("form", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
    expect(await screen.findByText("Acme SOC")).toBeVisible();
    expect(onNotice).toHaveBeenCalledWith({
      message: expect.stringMatching(/bounded to 24 hours.*being reloaded/i),
      tone: "warning",
    });

    fireEvent.click(
      screen.getByRole("button", { name: "Create tenant binding" }),
    );
    form = screen.getByRole("form", { name: "Create tenant binding" });
    expect(within(form).getByLabelText("Tenant ID")).toHaveValue("");
    expect(within(form).getByLabelText("Tenant login key")).toHaveValue("");
    expect(within(form).getByLabelText("Profile priority")).toHaveValue(100);
    expect(within(form).getByLabelText("Binding audit reason")).toHaveValue("");

    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Profile priority"), {
      target: { value: "50" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Retry an uncertain binding command" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    await waitFor(() => expect(create).toHaveBeenCalledTimes(2));
    expect(create.mock.calls[1]?.[2]).not.toBe(create.mock.calls[0]?.[2]);
  });

  it("warns when a safe create retry returns the current archived projection", async () => {
    const onNotice = vi.fn();
    const archived = bindingFixture({
      archivedAt: "2026-08-28T11:00:00Z",
      updatedAt: "2026-08-28T11:00:00Z",
      version: 5,
    });
    renderBindings(
      {
        createPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v5-t11"',
          location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
          value: archived,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    const form = screen.getByRole("form", { name: "Create tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Retry an uncertain binding command" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    expect(await screen.findByText("Archived")).toBeVisible();
    expect(onNotice).toHaveBeenCalledWith({
      message: expect.stringMatching(/already archived.*safe retry/i),
      tone: "warning",
    });
    expect(onNotice).not.toHaveBeenCalledWith(
      expect.objectContaining({ tone: "success" }),
    );
  });

  it("warns when a safe create retry returns the current active projection", async () => {
    const onNotice = vi.fn();
    const onProviderProjectionStale = vi.fn();
    const active = bindingFixture({
      authRevision: 2,
      currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000093",
      enabled: true,
      mappingRevision: 2,
      updatedAt: "2026-08-28T11:00:00Z",
      version: 8,
    });
    renderBindings(
      {
        createPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v8-t11"',
          location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
          value: active,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
      },
      { onNotice, onProviderProjectionStale },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    const form = screen.getByRole("form", { name: "Create tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Retry an uncertain binding command" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    expect(await screen.findByText("Tenant admission active")).toBeVisible();
    expect(onProviderProjectionStale).toHaveBeenCalledOnce();
    expect(screen.getByText("Provider execution active")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Edit key and priority" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Archive binding" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Deactivate tenant admission" }),
    ).toBeVisible();
    expect(onNotice).toHaveBeenCalledWith({
      message: expect.stringMatching(
        /already active.*safe retry.*access epoch/i,
      ),
      tone: "warning",
    });
    expect(onNotice).not.toHaveBeenCalledWith(
      expect.objectContaining({ tone: "success" }),
    );
  });

  it("warns when a safe create retry returns a binding already ready to activate", async () => {
    const onNotice = vi.fn();
    const onProviderProjectionStale = vi.fn();
    const ready = bindingFixture({
      activationAvailable: true,
      updatedAt: "2026-08-28T11:00:00Z",
      version: 7,
    });
    renderBindings(
      {
        createPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v7-t11"',
          location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
          value: ready,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
      },
      { onNotice, onProviderProjectionStale },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    const form = screen.getByRole("form", { name: "Create tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Retry an uncertain binding command" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    expect(await screen.findByText("Ready to activate")).toBeVisible();
    expect(onProviderProjectionStale).toHaveBeenCalledOnce();
    expect(screen.getByText("Provider execution active")).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
    expect(onNotice).toHaveBeenCalledWith({
      message: expect.stringMatching(
        /already ready.*safe retry.*did not create/i,
      ),
      tone: "warning",
    });
    expect(onNotice).not.toHaveBeenCalledWith(
      expect.objectContaining({ tone: "success" }),
    );
  });

  it("warns when a safe create retry returns a later disabled binding", async () => {
    const onNotice = vi.fn();
    const current = bindingFixture({
      updatedAt: "2026-08-28T11:00:00Z",
      version: 6,
    });
    renderBindings(
      {
        createPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v6-t11"',
          location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
          value: current,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    const form = screen.getByRole("form", { name: "Create tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant ID"), {
      target: { value: tenantId },
    });
    fireEvent.change(within(form).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme" },
    });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Retry an uncertain binding command" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Create staged binding" }),
    );

    await waitFor(() =>
      expect(onNotice).toHaveBeenCalledWith({
        message: expect.stringMatching(
          /already exists.*currently disabled.*safe retry/i,
        ),
        tone: "warning",
      }),
    );
    expect(onNotice).not.toHaveBeenCalledWith(
      expect.objectContaining({ tone: "success" }),
    );
  });

  it("loads an ETag before editing, then archives the refreshed binding", async () => {
    const initial = bindingFixture();
    const updated = bindingFixture({
      loginKey: "workforce_acme_next",
      profilePriority: 75,
      version: 8,
    });
    const get = vi.fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>(
      async () => ({ etag: '"v7-t11"', value: initial }),
    );
    const update = vi.fn<
      PhaseTwoApi["updatePlatformAuthProviderTenantBinding"]
    >(async () => ({ etag: '"v8-t11"', value: updated }));
    const archive = vi.fn<
      PhaseTwoApi["archivePlatformAuthProviderTenantBinding"]
    >(async () => '"v9-t11"');
    renderBindings({
      archivePlatformAuthProviderTenantBinding: archive,
      getPlatformAuthProviderTenantBinding: get,
      listPlatformAuthProviderTenantBindings: async () => ({
        items: [initial],
      }),
      updatePlatformAuthProviderTenantBinding: update,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    await waitFor(() => expect(get).toHaveBeenCalledOnce());
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit key and priority" }),
    );
    const editForm = screen.getByRole("form", { name: "Edit tenant binding" });
    fireEvent.change(within(editForm).getByLabelText("Tenant login key"), {
      target: { value: "workforce_acme_next" },
    });
    fireEvent.change(within(editForm).getByLabelText("Profile priority"), {
      target: { value: "75" },
    });
    fireEvent.change(within(editForm).getByLabelText("Binding audit reason"), {
      target: { value: "Adjust profile precedence" },
    });
    fireEvent.click(
      within(editForm).getByRole("button", { name: "Save binding metadata" }),
    );
    await waitFor(() => expect(update).toHaveBeenCalledOnce());
    expect(update).toHaveBeenCalledWith(
      "csrf-memory-only",
      providerId,
      bindingId,
      { etag: '"v7-t11"', value: initial },
      "Adjust profile precedence",
      {
        expectedTenantVersion: 11,
        expectedVersion: 7,
        loginKey: "workforce_acme_next",
        profilePriority: 75,
      },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Archive binding" }),
    );
    const archiveForm = screen.getByRole("form", {
      name: "Archive tenant binding",
    });
    fireEvent.change(
      within(archiveForm).getByLabelText("Binding audit reason"),
      { target: { value: "Retire unused tenant admission" } },
    );
    fireEvent.change(
      within(archiveForm).getByLabelText("Type workforce_acme_next to confirm"),
      { target: { value: "workforce_acme_next" } },
    );
    fireEvent.click(
      within(archiveForm).getByRole("button", { name: "Archive binding" }),
    );
    await waitFor(() => expect(archive).toHaveBeenCalledOnce());
    expect(archive).toHaveBeenCalledWith(
      "csrf-memory-only",
      providerId,
      bindingId,
      '"v8-t11"',
      "Retire unused tenant admission",
      { expectedTenantVersion: 11, expectedVersion: 8 },
    );
  });

  it("reloads the exact current detail after a 412 without retrying the mutation", async () => {
    const initial = bindingFixture();
    const current = bindingFixture({
      loginKey: "workforce_current",
      version: 9,
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [initial] })
      .mockResolvedValue({ items: [current] });
    const get = vi
      .fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>()
      .mockResolvedValueOnce({ etag: '"v7-t11"', value: initial })
      .mockResolvedValueOnce({ etag: '"v9-t11"', value: current });
    const update = vi
      .fn<PhaseTwoApi["updatePlatformAuthProviderTenantBinding"]>()
      .mockRejectedValue(new PhaseTwoApiError("Binding changed", 412));
    const onNotice = vi.fn();
    renderBindings(
      {
        getPlatformAuthProviderTenantBinding: get,
        listPlatformAuthProviderTenantBindings: list,
        updatePlatformAuthProviderTenantBinding: update,
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit key and priority" }),
    );
    const editForm = screen.getByRole("form", { name: "Edit tenant binding" });
    fireEvent.change(within(editForm).getByLabelText("Binding audit reason"), {
      target: { value: "Update from the current server version" },
    });
    fireEvent.click(
      within(editForm).getByRole("button", { name: "Save binding metadata" }),
    );

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(get).toHaveBeenNthCalledWith(
      1,
      providerId,
      bindingId,
      expect.any(AbortSignal),
    );
    expect(get).toHaveBeenNthCalledWith(
      2,
      providerId,
      bindingId,
      expect.any(AbortSignal),
    );
    expect(update).toHaveBeenCalledOnce();
    expect(onNotice).toHaveBeenCalledWith(
      expect.objectContaining({ tone: "warning" }),
    );
    expect(await screen.findByText(/If-Match "v9-t11"/)).toBeVisible();
    expect(await screen.findByText("workforce_current")).toBeVisible();
    expect(
      screen.queryByRole("form", { name: "Edit tenant binding" }),
    ).not.toBeInTheDocument();
  });

  it("reloads the exact current detail after an archive 412", async () => {
    const initial = bindingFixture();
    const current = bindingFixture({
      loginKey: "workforce_current",
      version: 9,
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [initial] })
      .mockResolvedValue({ items: [current] });
    const get = vi
      .fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>()
      .mockResolvedValueOnce({ etag: '"v7-t11"', value: initial })
      .mockResolvedValueOnce({ etag: '"v9-t11"', value: current });
    const archive = vi
      .fn<PhaseTwoApi["archivePlatformAuthProviderTenantBinding"]>()
      .mockRejectedValue(new PhaseTwoApiError("Binding changed", 412));
    const onNotice = vi.fn();
    renderBindings(
      {
        archivePlatformAuthProviderTenantBinding: archive,
        getPlatformAuthProviderTenantBinding: get,
        listPlatformAuthProviderTenantBindings: list,
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Archive binding" }),
    );
    const archiveForm = screen.getByRole("form", {
      name: "Archive tenant binding",
    });
    fireEvent.change(
      within(archiveForm).getByLabelText("Binding audit reason"),
      { target: { value: "Archive from the current server version" } },
    );
    fireEvent.change(
      within(archiveForm).getByLabelText("Type workforce_acme to confirm"),
      { target: { value: "workforce_acme" } },
    );
    fireEvent.click(
      within(archiveForm).getByRole("button", { name: "Archive binding" }),
    );

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(get).toHaveBeenNthCalledWith(
      1,
      providerId,
      bindingId,
      expect.any(AbortSignal),
    );
    expect(get).toHaveBeenNthCalledWith(
      2,
      providerId,
      bindingId,
      expect.any(AbortSignal),
    );
    expect(archive).toHaveBeenCalledOnce();
    expect(onNotice).toHaveBeenCalledWith(
      expect.objectContaining({ tone: "warning" }),
    );
    expect(await screen.findByText(/If-Match "v9-t11"/)).toBeVisible();
    expect(await screen.findByText("workforce_current")).toBeVisible();
    expect(
      screen.queryByRole("form", { name: "Archive tenant binding" }),
    ).not.toBeInTheDocument();
  });

  it("activates tenant admission with explicit JIT/no-match choices, reason, and confirmation", async () => {
    const ready = bindingFixture({ activationAvailable: true });
    const active = bindingFixture({
      authRevision: 2,
      currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
      enabled: true,
      jitMode: "create",
      mappingRevision: 2,
      noMatchPolicy: "provider_access_only",
      version: 8,
    });
    const deactivated = bindingFixture({
      activationAvailable: true,
      authRevision: 3,
      mappingRevision: 2,
      version: 9,
    });
    const activate = vi.fn<
      PhaseTwoApi["activatePlatformAuthProviderTenantBinding"]
    >(async () => ({ etag: '"v8-t11"', value: active }));
    const deactivate = vi.fn<
      PhaseTwoApi["deactivatePlatformAuthProviderTenantBinding"]
    >(async () => ({ etag: '"v9-t11"', value: deactivated }));
    renderBindings({
      activatePlatformAuthProviderTenantBinding: activate,
      deactivatePlatformAuthProviderTenantBinding: deactivate,
      getPlatformAuthProviderTenantBinding: async () => ({
        etag: '"v7-t11"',
        value: ready,
      }),
      listPlatformAuthProviderTenantBindings: async () => ({
        items: [ready],
      }),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Activate tenant admission" }),
    );
    const form = screen.getByRole("form", { name: "Activate tenant binding" });
    fireEvent.change(within(form).getByLabelText("Tenant membership JIT"), {
      target: { value: "create" },
    });
    fireEvent.change(
      within(form).getByLabelText("When no tenant authority matches"),
      { target: { value: "provider_access_only" } },
    );
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Open Acme tenant admission" },
    });
    fireEvent.change(
      within(form).getByLabelText("Type workforce_acme to confirm"),
      { target: { value: "workforce_acme" } },
    );
    fireEvent.click(
      within(form).getByRole("button", { name: "Activate tenant admission" }),
    );

    await waitFor(() =>
      expect(activate).toHaveBeenCalledWith(
        "csrf-memory-only",
        providerId,
        bindingId,
        { etag: '"v7-t11"', value: ready },
        "Open Acme tenant admission",
        {
          expectedTenantVersion: 11,
          expectedVersion: 7,
          jitMode: "create",
          noMatchPolicy: "provider_access_only",
        },
      ),
    );
    expect(await screen.findByText("Tenant admission active")).toBeVisible();
    expect(
      screen.getByText("0198c97d-cf4f-7000-8000-000000000091"),
    ).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Deactivate tenant admission" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Archive binding" }),
    ).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Deactivate tenant admission" }),
    );
    const deactivationForm = screen.getByRole("form", {
      name: "Deactivate tenant binding",
    });
    fireEvent.change(
      within(deactivationForm).getByLabelText("Binding audit reason"),
      { target: { value: "Close Acme tenant admission" } },
    );
    fireEvent.change(
      within(deactivationForm).getByLabelText("Type workforce_acme to confirm"),
      { target: { value: "workforce_acme" } },
    );
    fireEvent.click(
      within(deactivationForm).getByRole("button", {
        name: "Deactivate tenant admission",
      }),
    );
    await waitFor(() =>
      expect(deactivate).toHaveBeenCalledWith(
        "csrf-memory-only",
        providerId,
        bindingId,
        { etag: '"v8-t11"', value: active },
        "Close Acme tenant admission",
        { expectedTenantVersion: 11, expectedVersion: 8 },
      ),
    );
    expect(
      await screen.findByRole("button", { name: "Activate tenant admission" }),
    ).toBeVisible();
    expect(screen.getByText("Disabled")).toBeVisible();
    expect(screen.getByText("Deny")).toBeVisible();
    fireEvent.click(
      screen.getByRole("button", { name: "Activate tenant admission" }),
    );
    const reactivationForm = screen.getByRole("form", {
      name: "Activate tenant binding",
    });
    expect(
      within(reactivationForm).getByLabelText("Tenant membership JIT"),
    ).toHaveValue("disabled");
    expect(
      within(reactivationForm).getByLabelText(
        "When no tenant authority matches",
      ),
    ).toHaveValue("deny");
  });

  it("refreshes binding detail and drops lifecycle confirmation after a stale composite ETag", async () => {
    const ready = bindingFixture({ activationAvailable: true });
    const refreshed = bindingFixture({
      updatedAt: "2026-08-28T10:06:00Z",
      version: 8,
    });
    const get = vi
      .fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>()
      .mockResolvedValueOnce({ etag: '"v7-t11"', value: ready })
      .mockResolvedValue({ etag: '"v8-t11"', value: refreshed });
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>(
      async () => ({ items: [ready] }),
    );
    const activate = vi.fn<
      PhaseTwoApi["activatePlatformAuthProviderTenantBinding"]
    >(async () => {
      throw new PhaseTwoApiError("The binding version is stale.", 412);
    });
    renderBindings({
      activatePlatformAuthProviderTenantBinding: activate,
      getPlatformAuthProviderTenantBinding: get,
      listPlatformAuthProviderTenantBindings: list,
    });
    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Activate tenant admission" }),
    );
    const form = screen.getByRole("form", { name: "Activate tenant binding" });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Open current Acme admission" },
    });
    fireEvent.change(
      within(form).getByLabelText("Type workforce_acme to confirm"),
      { target: { value: "workforce_acme" } },
    );
    fireEvent.click(
      within(form).getByRole("button", { name: "Activate tenant admission" }),
    );

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(activate).toHaveBeenCalledOnce();
    expect(
      screen.queryByRole("form", { name: "Activate tenant binding" }),
    ).not.toBeInTheDocument();
    expect(await screen.findByText(/If-Match "v8-t11"/)).toBeVisible();
  });

  it("refreshes the selected exact detail when provider lifecycle readiness changes", async () => {
    const staged = bindingFixture();
    const ready = bindingFixture({ activationAvailable: true });
    const get = vi
      .fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>()
      .mockResolvedValueOnce({ etag: '"v7-t11"', value: staged })
      .mockResolvedValueOnce({ etag: '"v7-t11"', value: ready });
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>(
      async () => ({ items: [ready] }),
    );
    const view = renderBindings(
      {
        getPlatformAuthProviderTenantBinding: get,
        listPlatformAuthProviderTenantBindings: list,
      },
      { refreshRevision: 0 },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    await screen.findByText("Staged · not ready");
    expect(
      screen.queryByRole("button", { name: "Activate tenant admission" }),
    ).not.toBeInTheDocument();

    view.rerenderProps({ refreshRevision: 1 });

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    expect(
      await screen.findByRole("button", { name: "Activate tenant admission" }),
    ).toBeVisible();
    expect(get).toHaveBeenLastCalledWith(
      providerId,
      bindingId,
      expect.any(AbortSignal),
    );
  });

  it("ignores a lifecycle completion after binding manage permission is lost", async () => {
    const ready = bindingFixture({ activationAvailable: true });
    const active = bindingFixture({
      currentAccessEpochId: "0198c97d-cf4f-7000-8000-000000000091",
      enabled: true,
      version: 8,
    });
    const pending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["activatePlatformAuthProviderTenantBinding"]>
        >
      >();
    const onNotice = vi.fn();
    const view = renderBindings(
      {
        activatePlatformAuthProviderTenantBinding: () => pending.promise,
        getPlatformAuthProviderTenantBinding: async () => ({
          etag: '"v7-t11"',
          value: ready,
        }),
        listPlatformAuthProviderTenantBindings: async () => ({
          items: [ready],
        }),
      },
      { onNotice },
    );
    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Activate tenant admission" }),
    );
    const form = screen.getByRole("form", { name: "Activate tenant binding" });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Open admission before permission changes" },
    });
    fireEvent.change(
      within(form).getByLabelText("Type workforce_acme to confirm"),
      { target: { value: "workforce_acme" } },
    );
    fireEvent.click(
      within(form).getByRole("button", { name: "Activate tenant admission" }),
    );
    view.rerenderProps({ canManage: false });
    await act(async () => pending.resolve({ etag: '"v8-t11"', value: active }));

    expect(onNotice).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("form", { name: "Activate tenant binding" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText("Tenant admission active"),
    ).not.toBeInTheDocument();
  });

  it("reloads exact binding state after an update conflict without retrying", async () => {
    const initial = bindingFixture();
    const get = vi.fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>(
      async () => ({ etag: '"v7-t11"', value: initial }),
    );
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>(
      async () => ({ items: [initial] }),
    );
    const update = vi
      .fn<PhaseTwoApi["updatePlatformAuthProviderTenantBinding"]>()
      .mockRejectedValue(
        new PhaseTwoApiError("The request conflicts with current state.", 409),
      );
    const onNotice = vi.fn();
    renderBindings(
      {
        getPlatformAuthProviderTenantBinding: get,
        listPlatformAuthProviderTenantBindings: list,
        updatePlatformAuthProviderTenantBinding: update,
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit key and priority" }),
    );
    const form = screen.getByRole("form", { name: "Edit tenant binding" });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Resolve metadata conflict" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Save binding metadata" }),
    );

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(update).toHaveBeenCalledOnce();
    expect(onNotice).toHaveBeenCalledWith({
      message: expect.stringMatching(/update conflicted.*being reloaded/i),
      tone: "warning",
    });
    expect(
      screen.queryByRole("form", { name: "Edit tenant binding" }),
    ).not.toBeInTheDocument();
  });

  it("reloads terminal binding state after an archive conflict without retrying", async () => {
    const initial = bindingFixture();
    const archived = bindingFixture({
      archivedAt: "2026-08-28T11:00:00Z",
      updatedAt: "2026-08-28T11:00:00Z",
      version: 8,
    });
    const get = vi
      .fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>()
      .mockResolvedValueOnce({ etag: '"v7-t11"', value: initial })
      .mockResolvedValue({ etag: '"v8-t11"', value: archived });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderTenantBindings"]>()
      .mockResolvedValueOnce({ items: [initial] })
      .mockResolvedValue({ items: [archived] });
    const archive = vi
      .fn<PhaseTwoApi["archivePlatformAuthProviderTenantBinding"]>()
      .mockRejectedValue(
        new PhaseTwoApiError("The request conflicts with current state.", 409),
      );
    const onNotice = vi.fn();
    renderBindings(
      {
        archivePlatformAuthProviderTenantBinding: archive,
        getPlatformAuthProviderTenantBinding: get,
        listPlatformAuthProviderTenantBindings: list,
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Archive binding" }),
    );
    const form = screen.getByRole("form", { name: "Archive tenant binding" });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Resolve archival conflict" },
    });
    fireEvent.change(
      within(form).getByLabelText("Type workforce_acme to confirm"),
      { target: { value: "workforce_acme" } },
    );
    fireEvent.click(
      within(form).getByRole("button", { name: "Archive binding" }),
    );

    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(archive).toHaveBeenCalledOnce();
    expect(onNotice).toHaveBeenCalledWith({
      message: expect.stringMatching(/archival conflicted.*being reloaded/i),
      tone: "warning",
    });
    expect(await screen.findAllByText("Archived")).toHaveLength(2);
    expect(
      screen.queryByRole("form", { name: "Archive tenant binding" }),
    ).not.toBeInTheDocument();
  });

  it("ignores a late detail response after another binding is selected", async () => {
    const first = bindingFixture();
    const second = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      loginKey: "workforce_beta",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
        status: "active",
        version: 12,
      },
      version: 8,
    });
    const firstPending = deferred<{
      etag: string;
      value: PlatformAuthProviderTenantBindingView;
    }>();
    const secondPending = deferred<{
      etag: string;
      value: PlatformAuthProviderTenantBindingView;
    }>();
    renderBindings({
      getPlatformAuthProviderTenantBinding: (_providerId, selectedId) =>
        selectedId === first.id ? firstPending.promise : secondPending.promise,
      listPlatformAuthProviderTenantBindings: async () => ({
        items: [first, second],
      }),
    });

    const manageButtons = await screen.findAllByRole("button", {
      name: /Manage .* binding/i,
    });
    fireEvent.click(manageButtons[0]!);
    fireEvent.click(manageButtons[1]!);
    await act(async () => {
      secondPending.resolve({ etag: '"v8-t12"', value: second });
    });
    expect(await screen.findByText(/If-Match "v8-t12"/)).toBeVisible();
    await act(async () => {
      firstPending.resolve({ etag: '"v7-t11"', value: first });
    });
    expect(screen.getByText(/If-Match "v8-t12"/)).toBeVisible();
  });

  it("does not carry destructive confirmation into another tenant binding", async () => {
    const first = bindingFixture();
    const second = bindingFixture({
      id: "0198c97d-cf4f-7000-8000-000000000091",
      tenant: {
        id: "0198c97d-cf4f-7000-8000-000000000092",
        name: "Beta SOC",
        slug: "beta",
        status: "active",
        version: 12,
      },
      version: 8,
    });
    renderBindings({
      getPlatformAuthProviderTenantBinding: async (
        _requestedProviderId,
        selectedId,
      ) =>
        selectedId === first.id
          ? { etag: '"v7-t11"', value: first }
          : { etag: '"v8-t12"', value: second },
      listPlatformAuthProviderTenantBindings: async () => ({
        items: [first, second],
      }),
    });

    const manageButtons = await screen.findAllByRole("button", {
      name: /Manage .* binding/i,
    });
    fireEvent.click(manageButtons[0]!);
    fireEvent.click(
      await screen.findByRole("button", { name: "Archive binding" }),
    );
    let form = screen.getByRole("form", { name: "Archive tenant binding" });
    fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
      target: { value: "Archive the first tenant admission" },
    });
    fireEvent.change(
      within(form).getByLabelText("Type workforce_acme to confirm"),
      { target: { value: "workforce_acme" } },
    );

    fireEvent.click(manageButtons[1]!);
    expect(await screen.findByText(/If-Match "v8-t12"/)).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Archive binding" }));
    form = screen.getByRole("form", { name: "Archive tenant binding" });
    expect(within(form).getByLabelText("Binding audit reason")).toHaveValue("");
    expect(
      within(form).getByLabelText("Type workforce_acme to confirm"),
    ).toHaveValue("");
  });

  it("keeps create and detail workflows exclusive across a late detail response", async () => {
    const staleDetail =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>>
      >();
    let detailSignal: AbortSignal | undefined;
    const get = vi.fn<PhaseTwoApi["getPlatformAuthProviderTenantBinding"]>(
      (_requestedProviderId, _requestedBindingId, signal) => {
        detailSignal = signal;
        return staleDetail.promise;
      },
    );
    renderBindings({
      getPlatformAuthProviderTenantBinding: get,
      listPlatformAuthProviderTenantBindings: async () => ({
        items: [bindingFixture()],
      }),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    await waitFor(() => expect(get).toHaveBeenCalledOnce());
    fireEvent.click(
      screen.getByRole("button", { name: "Create tenant binding" }),
    );

    expect(detailSignal?.aborted).toBe(true);
    expect(
      screen.getByRole("form", { name: "Create tenant binding" }),
    ).toBeVisible();
    await act(async () =>
      staleDetail.resolve({ etag: '"v7-t11"', value: bindingFixture() }),
    );
    expect(screen.queryByText(/If-Match "v7-t11"/)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Manage .* binding/i }));
    expect(
      screen.queryByRole("form", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
    expect(await screen.findByText(/If-Match "v7-t11"/)).toBeVisible();
  });

  it("closes every open mutation form when manage authority or provider state changes", async () => {
    const binding = bindingFixture();
    const view = renderBindings({
      getPlatformAuthProviderTenantBinding: async () => ({
        etag: '"v7-t11"',
        value: binding,
      }),
      listPlatformAuthProviderTenantBindings: async () => ({
        items: [binding],
      }),
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Create tenant binding" }),
    );
    expect(
      screen.getByRole("form", { name: "Create tenant binding" }),
    ).toBeVisible();
    view.rerenderProps({ canManage: false });
    await waitFor(() =>
      expect(
        screen.queryByRole("form", { name: "Create tenant binding" }),
      ).not.toBeInTheDocument(),
    );

    view.rerenderProps({ canManage: true });
    fireEvent.click(
      await screen.findByRole("button", { name: /Manage .* binding/i }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Edit key and priority" }),
    );
    expect(
      screen.getByRole("form", { name: "Edit tenant binding" }),
    ).toBeVisible();
    view.rerenderProps({ providerArchived: true });
    await waitFor(() =>
      expect(
        screen.queryByRole("form", { name: "Edit tenant binding" }),
      ).not.toBeInTheDocument(),
    );

    view.rerenderProps({ providerArchived: false });
    fireEvent.click(
      await screen.findByRole("button", { name: "Archive binding" }),
    );
    expect(
      screen.getByRole("form", { name: "Archive tenant binding" }),
    ).toBeVisible();
    view.rerenderProps({ canManage: false });
    await waitFor(() =>
      expect(
        screen.queryByRole("form", { name: "Archive tenant binding" }),
      ).not.toBeInTheDocument(),
    );
  });

  it("invalidates pending mutations when authority, provider writability, or session context is lost", async () => {
    const firstPending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>
        >
      >();
    const secondPending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>
        >
      >();
    const thirdPending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>
        >
      >();
    const fourthPending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>
        >
      >();
    const fifthPending =
      deferred<
        Awaited<
          ReturnType<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>
        >
      >();
    const created = {
      etag: '"v1-t11"',
      location: `/api/v1/platform/auth-providers/${providerId}/tenant-bindings/${bindingId}`,
      value: bindingFixture({ version: 1 }),
    };
    const create = vi
      .fn<PhaseTwoApi["createPlatformAuthProviderTenantBinding"]>()
      .mockReturnValueOnce(firstPending.promise)
      .mockReturnValueOnce(secondPending.promise)
      .mockReturnValueOnce(thirdPending.promise)
      .mockReturnValueOnce(fourthPending.promise)
      .mockReturnValueOnce(fifthPending.promise);
    const onMutationBusyChange = vi.fn();
    const onNotice = vi.fn();
    const view = renderBindings(
      {
        createPlatformAuthProviderTenantBinding: create,
        listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
      },
      { onMutationBusyChange, onNotice },
    );

    async function startCreate(): Promise<void> {
      fireEvent.click(
        await screen.findByRole("button", { name: "Create tenant binding" }),
      );
      const form = screen.getByRole("form", { name: "Create tenant binding" });
      fireEvent.change(within(form).getByLabelText("Tenant ID"), {
        target: { value: tenantId },
      });
      fireEvent.change(within(form).getByLabelText("Tenant login key"), {
        target: { value: "workforce_acme" },
      });
      fireEvent.change(within(form).getByLabelText("Profile priority"), {
        target: { value: "50" },
      });
      fireEvent.change(within(form).getByLabelText("Binding audit reason"), {
        target: { value: "Reserve Acme federation coordinates" },
      });
      fireEvent.click(
        within(form).getByRole("button", { name: "Create staged binding" }),
      );
      await waitFor(() =>
        expect(onMutationBusyChange).toHaveBeenLastCalledWith(true),
      );
      expect(form).toHaveAttribute("aria-busy", "true");
      expect(within(form).getByLabelText("Tenant ID")).toBeDisabled();
      expect(
        within(form).getByLabelText("Binding audit reason"),
      ).toBeDisabled();
    }

    await startCreate();
    view.rerenderProps({ canManage: false });
    await waitFor(() =>
      expect(onMutationBusyChange).toHaveBeenLastCalledWith(false),
    );
    expect(
      screen.queryByRole("form", { name: "Create tenant binding" }),
    ).not.toBeInTheDocument();
    await act(async () => firstPending.resolve(created));
    expect(onNotice).not.toHaveBeenCalled();
    expect(screen.queryByText("Staged · not ready")).not.toBeInTheDocument();

    view.rerenderProps({ canManage: true });
    await startCreate();
    view.rerenderProps({ providerArchived: true });
    await waitFor(() =>
      expect(onMutationBusyChange).toHaveBeenLastCalledWith(false),
    );
    await act(async () => secondPending.resolve(created));
    expect(onNotice).not.toHaveBeenCalled();
    expect(screen.queryByText("Staged · not ready")).not.toBeInTheDocument();

    view.rerenderProps({ providerArchived: false });
    await startCreate();
    view.rerenderProps({
      sessionId: "0198c97d-cf4f-7000-8000-000000000002",
    });
    await waitFor(() =>
      expect(onMutationBusyChange).toHaveBeenLastCalledWith(false),
    );
    await act(async () => thirdPending.resolve(created));
    expect(onNotice).not.toHaveBeenCalled();
    expect(screen.queryByText("Staged · not ready")).not.toBeInTheDocument();

    await startCreate();
    view.rerenderProps({ canRead: false });
    await waitFor(() =>
      expect(onMutationBusyChange).toHaveBeenLastCalledWith(false),
    );
    expect(
      screen.getByText("Binding read permission not returned"),
    ).toBeVisible();
    await act(async () => fourthPending.resolve(created));
    expect(onNotice).not.toHaveBeenCalled();
    expect(screen.queryByText("Acme SOC")).not.toBeInTheDocument();
    expect(screen.queryByText("Staged · not ready")).not.toBeInTheDocument();

    view.rerenderProps({ canRead: true, providerEnabled: false });
    await startCreate();
    view.rerenderProps({ providerEnabled: true });
    await waitFor(() =>
      expect(onMutationBusyChange).toHaveBeenLastCalledWith(false),
    );
    expect(screen.getByText("Provider execution active")).toBeVisible();
    await act(async () => fifthPending.resolve(created));
    expect(onNotice).not.toHaveBeenCalled();
    expect(screen.queryByText("Acme SOC")).not.toBeInTheDocument();
    expect(
      onMutationBusyChange.mock.calls.map(([busy]) => busy).slice(-10),
    ).toEqual([
      true,
      false,
      true,
      false,
      true,
      false,
      true,
      false,
      true,
      false,
    ]);
  });
});

interface BindingRenderHandle {
  rerenderProps: (
    props: Partial<
      React.ComponentProps<typeof PlatformAuthProviderTenantBindings>
    >,
  ) => void;
}

function renderBindings(
  overrides: Partial<PhaseTwoApi> = {},
  props: Partial<
    React.ComponentProps<typeof PlatformAuthProviderTenantBindings>
  > = {},
): BindingRenderHandle {
  const api = createPhaseTwoApi({
    listPlatformAuthProviderTenantBindings: async () => ({ items: [] }),
    ...overrides,
  });
  let currentProps: React.ComponentProps<
    typeof PlatformAuthProviderTenantBindings
  > = {
    api,
    canManage: true,
    canRead: true,
    csrfToken: "csrf-memory-only",
    onMutationBusyChange: vi.fn(),
    onNotice: vi.fn(),
    onPermissionError: vi.fn(),
    onUnauthenticated: vi.fn(),
    providerArchived: false,
    providerMutationBusy: false,
    providerId,
    sessionId: "0198c97d-cf4f-7000-8000-000000000001",
    ...props,
  };
  const view = render(<PlatformAuthProviderTenantBindings {...currentProps} />);
  return {
    rerenderProps(nextProps) {
      currentProps = { ...currentProps, ...nextProps };
      view.rerender(<PlatformAuthProviderTenantBindings {...currentProps} />);
    },
  };
}

function bindingFixture(
  overrides: Partial<PlatformAuthProviderTenantBindingView> = {},
): PlatformAuthProviderTenantBindingView {
  return {
    activationAvailable: false,
    archivedAt: null,
    authRevision: 1,
    createdAt: "2026-08-28T10:00:00Z",
    currentAccessEpochId: null,
    enabled: false,
    id: bindingId,
    jitMode: "disabled",
    loginKey: "workforce_acme",
    mappingRevision: 1,
    noMatchPolicy: "deny",
    origin: "platform",
    profilePriority: 50,
    providerId,
    tenant: {
      id: tenantId,
      name: "Acme SOC",
      slug: "acme",
      status: "active",
      version: 11,
    },
    updatedAt: "2026-08-28T10:05:00Z",
    version: 7,
    ...overrides,
  };
}

function deferred<T>(): {
  promise: Promise<T>;
  reject: (reason?: unknown) => void;
  resolve: (value: T) => void;
} {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((nextResolve, nextReject) => {
    resolve = nextResolve;
    reject = nextReject;
  });
  return { promise, reject, resolve };
}
