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
  type PlatformAuthProviderAccountView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi } from "../test/phase-two-fixtures";
import { PlatformAuthProviderAccounts } from "./platform-auth-provider-accounts";

const providerId = "0198c97d-cf4f-7000-8000-000000000088";
const accountId = "0198c97d-cf4f-7000-8000-000000000089";
const userId = "0198c97d-cf4f-7000-8000-000000000090";
const sessionId = "0198c97d-cf4f-7000-8000-000000000091";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("PlatformAuthProviderAccounts", () => {
  it("does not query the account register without explicit read authority", () => {
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>();
    renderAccounts(
      { listPlatformAuthProviderAccounts: list },
      { canManage: false, canRead: false },
    );

    expect(
      screen.getByText("Account register permission not returned"),
    ).toBeVisible();
    expect(list).not.toHaveBeenCalled();
    expect(
      screen.queryByRole("button", { name: "Prelink account" }),
    ).not.toBeInTheDocument();
  });

  it("renders only the bounded account and platform-user projection", async () => {
    const account = accountFixture();
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>(
      async () => ({ items: [account] }),
    );
    renderAccounts({ listPlatformAuthProviderAccounts: list });

    expect(await screen.findByText("Ada Account")).toBeVisible();
    expect(screen.getByText("ada.account@example.invalid")).toBeVisible();
    expect(screen.getByText(accountId)).toBeVisible();
    expect(screen.getByText("cfg 4 · sec 7")).toBeVisible();
    expect(screen.getByText("1 loaded")).toBeVisible();
    const observedAt = document.querySelector(
      'time[datetime="2026-08-29T11:05:00Z"]',
    );
    expect(observedAt).toBeVisible();
    expect(observedAt?.textContent).not.toBe("");
    expect(screen.queryByText("exact-secret-subject")).not.toBeInTheDocument();
    expect(list).toHaveBeenCalledWith(
      providerId,
      expect.objectContaining({ includeRetired: true }),
    );
  });

  it("renders a legacy observation marker without inventing a timestamp", async () => {
    const legacy = accountFixture({
      lastObservationState: "legacy_unknown",
      lastObservedAt: null,
      retiredAt: "2026-08-30T08:00:00Z",
      state: "retired",
      updatedAt: "2026-08-30T08:00:00Z",
      version: 1,
    });
    renderAccounts({
      listPlatformAuthProviderAccounts: async () => ({ items: [legacy] }),
    });

    const marker = await screen.findByText("Legacy observation unavailable");
    expect(marker).toBeVisible();
    expect(marker.closest("td")?.querySelector("time")).toBeNull();
  });

  it("prelinks the exact write-only OIDC tuple without adding authority", async () => {
    const created = accountFixture();
    const prelink = vi.fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>(
      async () => ({
        etag: '"v3-u1"',
        location: `/api/v1/platform/auth-providers/${providerId}/accounts/${accountId}`,
        value: created,
      }),
    );
    const onNotice = vi.fn();
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    renderAccounts(
      {
        listPlatformAuthProviderAccounts: async () => ({ items: [] }),
        prelinkPlatformAuthProviderAccount: prelink,
      },
      { onNotice },
    );

    const prelinkTrigger = await screen.findByRole("button", {
      name: "Prelink account",
    });
    fireEvent.click(prelinkTrigger);
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    expect(screen.getByLabelText("Existing platform user ID")).toHaveAttribute(
      "aria-describedby",
      expect.stringMatching(/-user-hint$/),
    );
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "exact-secret-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Prelink the approved platform identity" },
    });
    fireEvent.click(
      within(
        screen.getByRole("form", { name: "Prelink exact OIDC identity" }),
      ).getByRole("button", { name: "Review permanent link" }),
    );
    expect(prelink).not.toHaveBeenCalled();
    expect(screen.getByText("Permanent subject reservation")).toBeVisible();
    expect(
      screen.getByRole("heading", {
        name: "Confirm permanent authentication mapping",
      }),
    ).toHaveFocus();
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "exact-secret-subject" },
    });
    fireEvent.click(
      within(
        screen.getByRole("form", { name: "Prelink exact OIDC identity" }),
      ).getByRole("button", { name: "Confirm permanent link" }),
    );

    await waitFor(() =>
      expect(prelink).toHaveBeenCalledWith(
        "csrf-memory-only",
        providerId,
        "0198c97d-cf4f-7000-8000-000000000099",
        "Prelink the approved platform identity",
        {
          issuer: "https://identity.example.com",
          subject: "exact-secret-subject",
          userId,
        },
      ),
    );
    expect(onNotice).toHaveBeenCalledWith({
      message:
        "Ada Account is linked to this provider without changing platform authority.",
      tone: "success",
    });
    expect(
      screen.queryByLabelText("Exact OIDC subject"),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("exact-secret-subject")).not.toBeInTheDocument();
    await waitFor(() => expect(prelinkTrigger).toHaveFocus());
  });

  it("never renders a reflected write-only subject from a failed prelink response", async () => {
    const reflectedSubject = "must-never-be-reflected";
    const prelink = vi
      .fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>()
      .mockRejectedValue(new PhaseTwoApiError(reflectedSubject, 400));
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    renderAccounts({
      listPlatformAuthProviderAccounts: async () => ({ items: [] }),
      prelinkPlatformAuthProviderAccount: prelink,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Prelink account" }),
    );
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: reflectedSubject },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Verify prelink failure redaction" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: reflectedSubject },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm permanent link" }),
    );

    expect(
      await screen.findByText(/provider account could not be prelinked/i),
    ).toBeVisible();
    expect(screen.queryByText(reflectedSubject)).not.toBeInTheDocument();
  });

  it("clears a write-only subject whenever the prelink disclosure closes", async () => {
    renderAccounts({
      listPlatformAuthProviderAccounts: async () => ({ items: [] }),
    });

    const trigger = await screen.findByRole("button", {
      name: "Prelink account",
    });
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "must-not-survive-disclosure" },
    });
    fireEvent.click(trigger);
    expect(trigger).toHaveAttribute("aria-expanded", "false");
    fireEvent.click(trigger);

    expect(screen.getByLabelText("Exact OIDC subject")).toHaveValue("");
    expect(
      screen.queryByDisplayValue("must-not-survive-disclosure"),
    ).not.toBeInTheDocument();
  });

  it("returns focus to the prelink disclosure when Cancel clears the form", async () => {
    renderAccounts({
      listPlatformAuthProviderAccounts: async () => ({ items: [] }),
    });

    const trigger = await screen.findByRole("button", {
      name: "Prelink account",
    });
    fireEvent.click(trigger);
    fireEvent.click(
      within(
        screen.getByRole("form", { name: "Prelink exact OIDC identity" }),
      ).getByRole("button", { name: "Cancel" }),
    );

    await waitFor(() => expect(trigger).toHaveFocus());
    expect(
      screen.queryByRole("form", { name: "Prelink exact OIDC identity" }),
    ).not.toBeInTheDocument();
  });

  it("aborts a pending retirement read when a competing prelink action opens", async () => {
    const active = accountFixture();
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["getPlatformAuthProviderAccount"]>>
      >();
    let retirementSignal: AbortSignal | undefined;
    const get = vi.fn<PhaseTwoApi["getPlatformAuthProviderAccount"]>(
      (_providerId, _accountId, signal) => {
        retirementSignal = signal;
        return pending.promise;
      },
    );
    renderAccounts({
      getPlatformAuthProviderAccount: get,
      listPlatformAuthProviderAccounts: async () => ({ items: [active] }),
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    );
    await screen.findByText("Loading current account version");
    fireEvent.click(screen.getByRole("button", { name: "Prelink account" }));
    expect(retirementSignal?.aborted).toBe(true);

    await act(async () => pending.resolve({ etag: '"v3-u1"', value: active }));
    expect(
      screen.queryByRole("heading", { name: "Retire account link" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("form", { name: "Prelink exact OIDC identity" }),
    ).toBeVisible();
  });

  it("does not acquire the mutation lock when secure retry-key generation fails", async () => {
    const prelink = vi.fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>();
    const onMutationBusyChange = vi.fn();
    vi.spyOn(globalThis.crypto, "randomUUID").mockImplementation(() => {
      throw new Error("crypto unavailable");
    });
    renderAccounts(
      {
        listPlatformAuthProviderAccounts: async () => ({ items: [] }),
        prelinkPlatformAuthProviderAccount: prelink,
      },
      { onMutationBusyChange },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Prelink account" }),
    );
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "exact-secret-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Prelink with a secure retry key" },
    });
    const form = screen.getByRole("form", {
      name: "Prelink exact OIDC identity",
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "exact-secret-subject" },
    });
    fireEvent.click(
      within(form).getByRole("button", { name: "Confirm permanent link" }),
    );

    expect(
      await screen.findByText(
        "A secure idempotency key could not be generated. Reload this page before retrying.",
      ),
    ).toBeVisible();
    expect(prelink).not.toHaveBeenCalled();
    expect(onMutationBusyChange).not.toHaveBeenCalledWith(true);
    expect(
      within(form).getByRole("button", { name: "Confirm permanent link" }),
    ).toBeEnabled();
  });

  it("reuses the same idempotency key after an ambiguous retry with an unchanged payload", async () => {
    const created = accountFixture();
    const prelink = vi
      .fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>()
      .mockRejectedValueOnce(new TypeError("connection reset"))
      .mockResolvedValueOnce({
        etag: '"v3-u1"',
        location: `/api/v1/platform/auth-providers/${providerId}/accounts/${accountId}`,
        value: created,
      });
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    renderAccounts({
      listPlatformAuthProviderAccounts: async () => ({ items: [] }),
      prelinkPlatformAuthProviderAccount: prelink,
    });

    fireEvent.click(
      await screen.findByRole("button", { name: "Prelink account" }),
    );
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "retry-stable-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Retry the exact prelink operation" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "retry-stable-subject" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm permanent link" }),
    );
    expect(await screen.findByText(/could not be prelinked/i)).toBeVisible();

    fireEvent.click(screen.getByRole("button", { name: "Back to edit" }));
    await waitFor(() =>
      expect(screen.getByLabelText("Existing platform user ID")).toHaveFocus(),
    );
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "temporary-edited-subject" },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "retry-stable-subject" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "retry-stable-subject" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm permanent link" }),
    );

    await waitFor(() => expect(prelink).toHaveBeenCalledTimes(2));
    expect(prelink.mock.calls[0]?.[2]).toBe(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    expect(prelink.mock.calls[1]?.[2]).toBe(prelink.mock.calls[0]?.[2]);
  });

  it("loads a current strong ETag before retiring the exact account", async () => {
    const active = accountFixture();
    const current = { etag: '"v3-u1"', value: active } as const;
    const retired = accountFixture({
      retiredAt: "2026-08-30T08:00:00Z",
      state: "retired",
      updatedAt: "2026-08-30T08:00:00Z",
      version: 4,
    });
    const get = vi.fn<PhaseTwoApi["getPlatformAuthProviderAccount"]>(
      async () => current,
    );
    const retire = vi.fn<PhaseTwoApi["retirePlatformAuthProviderAccount"]>(
      async () => ({ etag: '"v4-u1"', value: retired }),
    );
    const onNotice = vi.fn();
    renderAccounts(
      {
        getPlatformAuthProviderAccount: get,
        listPlatformAuthProviderAccounts: async () => ({ items: [active] }),
        retirePlatformAuthProviderAccount: retire,
      },
      { onNotice },
    );

    const retireButton = await screen.findByRole("button", {
      name: `Retire account link ${accountId} for Ada Account`,
    });
    fireEvent.click(retireButton);
    const retirementHeading = await screen.findByRole("heading", {
      name: "Retire account link",
    });
    expect(retirementHeading).toBeVisible();
    expect(retirementHeading).toHaveFocus();
    expect(retireButton).toHaveAttribute("aria-expanded", "true");
    expect(screen.getByLabelText("Confirm account ID")).toHaveAttribute(
      "aria-describedby",
      expect.stringMatching(/-retire-confirmation-hint$/),
    );
    expect(get).toHaveBeenCalledWith(
      providerId,
      accountId,
      expect.any(AbortSignal),
    );
    fireEvent.change(screen.getByLabelText("Confirm account ID"), {
      target: { value: accountId },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Retire the superseded identity link" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Retire account" }));

    await waitFor(() =>
      expect(retire).toHaveBeenCalledWith(
        "csrf-memory-only",
        providerId,
        accountId,
        current,
        "Retire the superseded identity link",
      ),
    );
    expect(onNotice).toHaveBeenCalledWith({
      message:
        "Ada Account was retired. Linked admission grants, continuations, and session families were revoked by the server.",
      tone: "success",
    });
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Linked platform accounts" }),
      ).toHaveFocus(),
    );
  });

  it("moves focus to the ledger when the current account is already retired", async () => {
    const active = accountFixture();
    const retired = accountFixture({
      retiredAt: "2026-08-30T08:00:00Z",
      state: "retired",
      updatedAt: "2026-08-30T08:00:00Z",
      version: 4,
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>()
      .mockResolvedValueOnce({ items: [active] })
      .mockResolvedValueOnce({ items: [retired] });
    const onNotice = vi.fn();
    renderAccounts(
      {
        getPlatformAuthProviderAccount: async () => ({
          etag: '"v4-u1"',
          value: retired,
        }),
        listPlatformAuthProviderAccounts: list,
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    );

    await waitFor(() =>
      expect(onNotice).toHaveBeenCalledWith({
        message:
          "Ada Account is already retired. The register has been refreshed.",
        tone: "warning",
      }),
    );
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { name: "Linked platform accounts" }),
      ).toHaveFocus(),
    );
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(
      screen.queryByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    ).not.toBeInTheDocument();
  });

  it("returns focus to the invoking Retire button when retirement is cancelled", async () => {
    const active = accountFixture();
    renderAccounts({
      getPlatformAuthProviderAccount: async () => ({
        etag: '"v3-u1"',
        value: active,
      }),
      listPlatformAuthProviderAccounts: async () => ({ items: [active] }),
    });

    const trigger = await screen.findByRole("button", {
      name: `Retire account link ${accountId} for Ada Account`,
    });
    fireEvent.click(trigger);
    await screen.findByRole("heading", { name: "Retire account link" });
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    await waitFor(() => expect(trigger).toHaveFocus());
    expect(trigger).toHaveAttribute("aria-expanded", "false");
  });

  it("toggles an expanded retirement disclosure without reloading the account", async () => {
    const active = accountFixture();
    const get = vi.fn<PhaseTwoApi["getPlatformAuthProviderAccount"]>(
      async () => ({ etag: '"v3-u1"', value: active }),
    );
    renderAccounts({
      getPlatformAuthProviderAccount: get,
      listPlatformAuthProviderAccounts: async () => ({ items: [active] }),
    });

    const trigger = await screen.findByRole("button", {
      name: `Retire account link ${accountId} for Ada Account`,
    });
    fireEvent.click(trigger);
    await screen.findByRole("heading", { name: "Retire account link" });
    expect(trigger).toHaveAttribute("aria-expanded", "true");
    fireEvent.click(trigger);

    expect(trigger).toHaveAttribute("aria-expanded", "false");
    expect(
      screen.queryByRole("heading", { name: "Retire account link" }),
    ).not.toBeInTheDocument();
    expect(get).toHaveBeenCalledOnce();
  });

  it("drops a stale retirement form instead of reusing its obsolete ETag", async () => {
    const active = accountFixture();
    const get = vi.fn<PhaseTwoApi["getPlatformAuthProviderAccount"]>(
      async () => ({ etag: '"v3-u1"', value: active }),
    );
    const retire = vi
      .fn<PhaseTwoApi["retirePlatformAuthProviderAccount"]>()
      .mockRejectedValue(new PhaseTwoApiError("Account changed", 412));
    renderAccounts({
      getPlatformAuthProviderAccount: get,
      listPlatformAuthProviderAccounts: async () => ({ items: [active] }),
      retirePlatformAuthProviderAccount: retire,
    });

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    );
    await screen.findByText("Retire account link");
    fireEvent.change(screen.getByLabelText("Confirm account ID"), {
      target: { value: accountId },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Retire from the current account version" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Retire account" }));

    expect(
      await screen.findByText(
        "The account changed or was already retired. Refresh the register before retrying.",
      ),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Retire account" }),
    ).not.toBeInTheDocument();
    expect(retire).toHaveBeenCalledOnce();

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    );
    await waitFor(() => expect(get).toHaveBeenCalledTimes(2));
  });

  it("aborts and ignores a stale register response after the provider changes", async () => {
    const stale =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["listPlatformAuthProviderAccounts"]>>
      >();
    const nextProviderId = "0198c97d-cf4f-7000-8000-000000000092";
    let staleSignal: AbortSignal | undefined;
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>(
      (requestedProviderId, options) => {
        if (requestedProviderId === providerId) {
          staleSignal = options?.signal;
          return stale.promise;
        }
        return Promise.resolve({
          items: [
            accountFixture({
              id: "0198c97d-cf4f-7000-8000-000000000093",
              providerId: nextProviderId,
              user: {
                active: true,
                displayName: "Current Account",
                email: null,
                id: "0198c97d-cf4f-7000-8000-000000000094",
                version: 1,
              },
            }),
          ],
        });
      },
    );
    const view = renderAccounts({ listPlatformAuthProviderAccounts: list });
    await waitFor(() => expect(list).toHaveBeenCalledOnce());

    view.rerenderProps({ providerId: nextProviderId, providerVersion: 8 });
    expect(await screen.findByText("Current Account")).toBeVisible();
    expect(staleSignal?.aborted).toBe(true);

    await act(async () => stale.resolve({ items: [accountFixture()] }));
    expect(screen.getByText("Current Account")).toBeVisible();
    expect(screen.queryByText("Ada Account")).not.toBeInTheDocument();
  });

  it("keeps readable rows visible across manage-only and issuer-mode changes", async () => {
    const active = accountFixture();
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>(
      async () => ({ items: [active] }),
    );
    const view = renderAccounts({ listPlatformAuthProviderAccounts: list });
    expect(await screen.findByText("Ada Account")).toBeVisible();

    view.rerenderProps({ canManage: false });
    expect(screen.getByText("Ada Account")).toBeVisible();
    expect(
      screen.queryByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    ).not.toBeInTheDocument();

    view.rerenderProps({
      allowWriteOnlyIssuer: true,
      canManage: true,
    });
    expect(screen.getByText("Ada Account")).toBeVisible();
    expect(
      screen.queryByLabelText("Loading linked platform accounts"),
    ).not.toBeInTheDocument();
    expect(list).toHaveBeenCalledOnce();
  });

  it("hides retired rows synchronously when the retired filter closes", async () => {
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["listPlatformAuthProviderAccounts"]>>
      >();
    const retired = accountFixture({
      retiredAt: "2026-08-30T08:00:00Z",
      state: "retired",
      updatedAt: "2026-08-30T08:00:00Z",
      user: {
        active: true,
        displayName: "Retired Ada",
        email: "retired.ada@example.invalid",
        id: userId,
        version: 1,
      },
      version: 4,
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>()
      .mockResolvedValueOnce({ items: [retired] })
      .mockImplementationOnce(() => pending.promise);
    renderAccounts({ listPlatformAuthProviderAccounts: list });

    expect(await screen.findByText("Retired Ada")).toBeVisible();
    fireEvent.click(
      screen.getByRole("checkbox", { name: "Include retired tombstones" }),
    );

    expect(screen.queryByText("Retired Ada")).not.toBeInTheDocument();
    expect(
      screen.getByLabelText("Loading linked platform accounts"),
    ).toBeVisible();
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    await act(async () => pending.resolve({ items: [] }));
    expect(
      await screen.findByText("No account links in this view"),
    ).toBeVisible();
  });

  it("gives duplicate display names distinct destructive action names", async () => {
    const secondAccountId = "0198c97d-cf4f-7000-8000-000000000092";
    renderAccounts({
      listPlatformAuthProviderAccounts: async () => ({
        items: [
          accountFixture(),
          accountFixture({
            id: secondAccountId,
            user: {
              active: true,
              displayName: "Ada Account",
              email: null,
              id: "0198c97d-cf4f-7000-8000-000000000093",
              version: 1,
            },
          }),
        ],
      }),
    });

    expect(
      await screen.findByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    ).toBeVisible();
    expect(
      screen.getByRole("button", {
        name: `Retire account link ${secondAccountId} for Ada Account`,
      }),
    ).toBeVisible();
  });

  it("hides old rows and confirmed write-only state synchronously on a scope change", async () => {
    const nextProviderId = "0198c97d-cf4f-7000-8000-000000000092";
    const next = accountFixture({
      id: "0198c97d-cf4f-7000-8000-000000000093",
      providerId: nextProviderId,
      user: {
        active: true,
        displayName: "Current Account",
        email: null,
        id: "0198c97d-cf4f-7000-8000-000000000094",
        version: 1,
      },
    });
    const prelink = vi.fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>();
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>(
      async (requestedProviderId) => ({
        items: requestedProviderId === providerId ? [accountFixture()] : [next],
      }),
    );
    const view = renderAccounts({
      listPlatformAuthProviderAccounts: list,
      prelinkPlatformAuthProviderAccount: prelink,
    });
    expect(await screen.findByText("Ada Account")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Prelink account" }));
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "old-provider-secret" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Review before provider scope changes" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    expect(
      screen.getByRole("heading", {
        name: "Confirm permanent authentication mapping",
      }),
    ).toBeVisible();

    view.rerenderProps({ providerId: nextProviderId, providerVersion: 8 });
    expect(screen.queryByText("Ada Account")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("form", { name: "Prelink exact OIDC identity" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByDisplayValue("old-provider-secret"),
    ).not.toBeInTheDocument();
    expect(prelink).not.toHaveBeenCalled();
    expect(await screen.findByText("Current Account")).toBeVisible();
  });

  it("clears account PII and write-only input when pagination loses authority", async () => {
    const account = accountFixture();
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>()
      .mockResolvedValueOnce({ items: [account], nextCursor: account.id })
      .mockRejectedValueOnce(new PhaseTwoApiError("Forbidden", 403));
    const onPermissionError = vi.fn();
    renderAccounts(
      { listPlatformAuthProviderAccounts: list },
      { onPermissionError },
    );

    expect(await screen.findByText("Ada Account")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Prelink account" }));
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "must-be-cleared" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Load more accounts" }));

    await waitFor(() => expect(onPermissionError).toHaveBeenCalledOnce());
    expect(screen.queryByText("Ada Account")).not.toBeInTheDocument();
    expect(screen.queryByText(accountId)).not.toBeInTheDocument();
    expect(
      screen.queryByLabelText("Exact OIDC subject"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByDisplayValue("must-be-cleared"),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(/Account-register access was denied/i),
    ).toBeVisible();
    expect(
      screen.queryByLabelText("Loading linked platform accounts"),
    ).not.toBeInTheDocument();
  });

  it("ignores a late prelink completion after the session changes", async () => {
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>>
      >();
    const prelink = vi.fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>(
      () => pending.promise,
    );
    const onMutationBusyChange = vi.fn();
    const onNotice = vi.fn();
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    const view = renderAccounts(
      {
        listPlatformAuthProviderAccounts: async () => ({ items: [] }),
        prelinkPlatformAuthProviderAccount: prelink,
      },
      { onMutationBusyChange, onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Prelink account" }),
    );
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "session-bound-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Prelink before session rotation" },
    });
    fireEvent.click(
      within(
        screen.getByRole("form", { name: "Prelink exact OIDC identity" }),
      ).getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "session-bound-subject" },
    });
    fireEvent.click(
      within(
        screen.getByRole("form", { name: "Prelink exact OIDC identity" }),
      ).getByRole("button", { name: "Confirm permanent link" }),
    );
    await waitFor(() => expect(prelink).toHaveBeenCalledOnce());
    expect(onMutationBusyChange).toHaveBeenCalledWith(true);

    view.rerenderProps({
      sessionId: "0198c97d-cf4f-7000-8000-000000000095",
    });
    await act(async () =>
      pending.resolve({
        etag: '"v3-u1"',
        location: `/api/v1/platform/auth-providers/${providerId}/accounts/${accountId}`,
        value: accountFixture(),
      }),
    );

    expect(onNotice).not.toHaveBeenCalled();
    expect(onMutationBusyChange).toHaveBeenLastCalledWith(false);
    expect(screen.queryByText("Ada Account")).not.toBeInTheDocument();
  });

  it("handles a late current-session 401 before stale-scope filtering", async () => {
    const active = accountFixture();
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["getPlatformAuthProviderAccount"]>>
      >();
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>(
      async () => ({ items: [active] }),
    );
    const onUnauthenticated = vi.fn();
    const view = renderAccounts(
      {
        getPlatformAuthProviderAccount: () => pending.promise,
        listPlatformAuthProviderAccounts: list,
      },
      { onUnauthenticated },
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    );
    await screen.findByText("Loading current account version");
    view.rerenderProps({ providerVersion: 8 });
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Ada Account")).toBeVisible();

    await act(async () =>
      pending.reject(new PhaseTwoApiError("Session expired", 401)),
    );

    expect(onUnauthenticated).toHaveBeenCalledOnce();
    expect(screen.queryByText("Ada Account")).not.toBeInTheDocument();
    expect(
      screen.getByLabelText("Loading linked platform accounts"),
    ).toBeVisible();
  });

  it("does not let a late 401 from an old session clear the new session", async () => {
    const active = accountFixture();
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["getPlatformAuthProviderAccount"]>>
      >();
    const list = vi.fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>(
      async () => ({ items: [active] }),
    );
    const onUnauthenticated = vi.fn();
    const view = renderAccounts(
      {
        getPlatformAuthProviderAccount: () => pending.promise,
        listPlatformAuthProviderAccounts: list,
      },
      { onUnauthenticated },
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Retire account link ${accountId} for Ada Account`,
      }),
    );
    await screen.findByText("Loading current account version");
    view.rerenderProps({
      sessionId: "0198c97d-cf4f-7000-8000-000000000095",
    });
    await waitFor(() => expect(list).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Ada Account")).toBeVisible();

    await act(async () =>
      pending.reject(new PhaseTwoApiError("Old session expired", 401)),
    );

    expect(onUnauthenticated).not.toHaveBeenCalled();
    expect(screen.getByText("Ada Account")).toBeVisible();
  });

  it("ignores a prelink completion from the prior mutation scope", async () => {
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>>
      >();
    const prelink = vi.fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>(
      () => pending.promise,
    );
    const onNotice = vi.fn();
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    const view = renderAccounts(
      {
        listPlatformAuthProviderAccounts: async () => ({ items: [] }),
        prelinkPlatformAuthProviderAccount: prelink,
      },
      { onNotice },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Prelink account" }),
    );
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "old-issuer-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Prelink before issuer scope changes" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "old-issuer-subject" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm permanent link" }),
    );
    await waitFor(() => expect(prelink).toHaveBeenCalledOnce());

    view.rerenderProps({
      prelinkIssuer: "https://next-identity.example.com",
    });
    await act(async () => {
      pending.resolve({
        etag: '"v3-u1"',
        location: `/api/v1/platform/auth-providers/${providerId}/accounts/${accountId}`,
        value: accountFixture(),
      });
      await Promise.resolve();
    });

    expect(onNotice).not.toHaveBeenCalled();
    expect(
      screen.queryByText(/Ada Account is linked to this provider/i),
    ).not.toBeInTheDocument();
  });

  it("ignores a late forbidden prelink after a new provider revision is loaded", async () => {
    const pending =
      deferred<
        Awaited<ReturnType<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>>
      >();
    const current = accountFixture({
      id: "0198c97d-cf4f-7000-8000-000000000093",
      user: {
        active: true,
        displayName: "Current Revision Account",
        email: null,
        id: "0198c97d-cf4f-7000-8000-000000000094",
        version: 1,
      },
    });
    const list = vi
      .fn<PhaseTwoApi["listPlatformAuthProviderAccounts"]>()
      .mockResolvedValueOnce({ items: [] })
      .mockResolvedValueOnce({ items: [current] });
    const prelink = vi.fn<PhaseTwoApi["prelinkPlatformAuthProviderAccount"]>(
      () => pending.promise,
    );
    const onPermissionError = vi.fn();
    vi.spyOn(globalThis.crypto, "randomUUID").mockReturnValue(
      "0198c97d-cf4f-7000-8000-000000000099",
    );
    const view = renderAccounts(
      {
        listPlatformAuthProviderAccounts: list,
        prelinkPlatformAuthProviderAccount: prelink,
      },
      { onPermissionError },
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Prelink account" }),
    );
    fireEvent.change(screen.getByLabelText("Existing platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Exact OIDC subject"), {
      target: { value: "stale-revision-subject" },
    });
    fireEvent.change(screen.getByLabelText("Audit reason"), {
      target: { value: "Prelink before provider revision changes" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Review permanent link" }),
    );
    fireEvent.change(screen.getByLabelText("Confirm platform user ID"), {
      target: { value: userId },
    });
    fireEvent.change(screen.getByLabelText("Re-enter exact OIDC subject"), {
      target: { value: "stale-revision-subject" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Confirm permanent link" }),
    );
    await waitFor(() => expect(prelink).toHaveBeenCalledOnce());

    view.rerenderProps({ providerVersion: 8 });
    expect(await screen.findByText("Current Revision Account")).toBeVisible();
    await act(async () =>
      pending.reject(new PhaseTwoApiError("old scope forbidden", 403)),
    );

    expect(screen.getByText("Current Revision Account")).toBeVisible();
    expect(onPermissionError).not.toHaveBeenCalled();
    expect(
      screen.queryByText(/Account-register access was denied/i),
    ).not.toBeInTheDocument();
  });
});

interface AccountRenderHandle {
  rerenderProps: (
    props: Partial<React.ComponentProps<typeof PlatformAuthProviderAccounts>>,
  ) => void;
}

function renderAccounts(
  overrides: Partial<PhaseTwoApi> = {},
  props: Partial<
    React.ComponentProps<typeof PlatformAuthProviderAccounts>
  > = {},
): AccountRenderHandle {
  const api = createPhaseTwoApi({
    listPlatformAuthProviderAccounts: async () => ({ items: [] }),
    ...overrides,
  });
  let currentProps: React.ComponentProps<typeof PlatformAuthProviderAccounts> =
    {
      api,
      canManage: true,
      canRead: true,
      csrfToken: "csrf-memory-only",
      onMutationBusyChange: vi.fn(),
      onNotice: vi.fn(),
      onPermissionError: vi.fn(),
      onUnauthenticated: vi.fn(),
      prelinkIssuer: "https://identity.example.com",
      providerId,
      providerMutationBusy: false,
      providerVersion: 7,
      sessionId,
      ...props,
    };
  const view = render(<PlatformAuthProviderAccounts {...currentProps} />);
  return {
    rerenderProps(nextProps) {
      currentProps = { ...currentProps, ...nextProps };
      view.rerender(<PlatformAuthProviderAccounts {...currentProps} />);
    },
  };
}

function accountFixture(
  overrides: Partial<PlatformAuthProviderAccountView> = {},
): PlatformAuthProviderAccountView {
  return {
    admittedConfigurationRevision: 4,
    admittedSecurityRevision: 7,
    createdAt: "2026-08-29T11:00:00Z",
    id: accountId,
    lastObservationState: "known",
    lastObservedAt: "2026-08-29T11:05:00Z",
    providerId,
    retiredAt: null,
    state: "active",
    updatedAt: "2026-08-29T11:05:00Z",
    user: {
      active: true,
      displayName: "Ada Account",
      email: "ada.account@example.invalid",
      id: userId,
      version: 1,
    },
    version: 3,
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
