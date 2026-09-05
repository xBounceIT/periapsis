import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { StrictMode, useState } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { PlatformOperatorTeamCoordinatorProvider } from "../auth/platform-operator-team-coordinator";
import { SessionContext } from "../auth/session-context";
import {
  PhaseTwoApiError,
  type PhaseTwoApi,
  type OperatorTeamView,
} from "../lib/phase-two-types";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { PlatformOperatorTeamsPage } from "./platform-operator-teams";

const teamId = "0198c97d-cf4f-7000-8000-000000000401";

afterEach(cleanup);

describe("PlatformOperatorTeamsPage", () => {
  it("uses only explicit platform capabilities for inventory and management visibility", async () => {
    const listPlatformOperatorTeams = vi.fn();
    renderPage(createPhaseTwoApi({ listPlatformOperatorTeams }), []);

    expect(
      screen.getByRole("heading", {
        name: "Operator teams are not available.",
      }),
    ).toBeVisible();
    expect(listPlatformOperatorTeams).not.toHaveBeenCalled();

    cleanup();
    renderPage(
      createPhaseTwoApi({
        listPlatformOperatorTeams: async () => ({ items: [teamFixture()] }),
      }),
      ["platform.operator_team.read"],
    );
    expect(
      await screen.findByRole("heading", { name: "Operator-team identities" }),
    ).toBeVisible();
    expect(
      screen.queryByRole("button", { name: "Create operator team" }),
    ).not.toBeInTheDocument();
  });

  it("closes and resets the create dialog when manage authority is removed", async () => {
    const api = createPhaseTwoApi({
      listPlatformOperatorTeams: async () => ({ items: [] }),
    });
    render(<MutablePlatformPermissionsHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create operator team" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
      target: { value: "draft_team" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
      target: { value: "Draft team" },
    });

    fireEvent.click(screen.getByText("Remove platform team manage"));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: "Create operator team" }),
    ).not.toBeInTheDocument();

    fireEvent.click(
      screen.getByRole("button", { name: "Restore platform team manage" }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Create operator team" }),
    );
    expect(screen.getByRole("textbox", { name: "Immutable key" })).toHaveValue(
      "",
    );
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue("");
  });

  it("invalidates detail mutation drafts across manage authority loss and restoration", async () => {
    const team = teamFixture();
    const api = createPhaseTwoApi({
      getPlatformOperatorTeam: async () => ({ etag: '"v2"', value: team }),
      listPlatformOperatorTeams: async () => ({ items: [team] }),
    });
    render(<MutablePlatformPermissionsHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open ${team.name} (${team.key})`,
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Pre-revocation draft" } },
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Archive reason" }), {
      target: { value: "Pre-revocation archive draft" },
    });

    fireEvent.click(screen.getByText("Remove platform team manage"));
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
        team.name,
      ),
    );
    expect(screen.getByRole("textbox", { name: "Team name" })).toBeDisabled();
    expect(
      screen.queryByRole("textbox", { name: "Archive reason" }),
    ).not.toBeInTheDocument();

    fireEvent.click(screen.getByText("Restore platform team manage"));
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: "Team name" })).toBeEnabled(),
    );
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      team.name,
    );
    expect(screen.getByRole("textbox", { name: "Archive reason" })).toHaveValue(
      "",
    );
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Archive operator team" }),
    ).toBeDisabled();
  });

  it("discards an old mutation error after manage authority is removed and restored", async () => {
    const team = teamFixture();
    const pendingUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const updatePlatformOperatorTeam = vi.fn(async () => pendingUpdate.promise);
    const api = createPhaseTwoApi({
      getPlatformOperatorTeam: async () => ({ etag: '"v2"', value: team }),
      listPlatformOperatorTeams: async () => ({ items: [team] }),
      updatePlatformOperatorTeam,
    });
    render(<MutablePlatformPermissionsHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open ${team.name} (${team.key})`,
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Pre-revocation pending draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByText("Remove platform team manage"));
    fireEvent.click(screen.getByText("Restore platform team manage"));
    await waitFor(() =>
      expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
        team.name,
      ),
    );

    await act(async () => {
      pendingUpdate.reject(new PhaseTwoApiError("old mutation failed", 412));
      await expect(pendingUpdate.promise).rejects.toThrow(
        "old mutation failed",
      );
    });
    expect(screen.queryByText("old mutation failed")).not.toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      team.name,
    );
  });

  it("starts a fresh create generation after manage authority is removed and restored", async () => {
    const oldCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const freshCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    let createCount = 0;
    const createPlatformOperatorTeam = vi.fn(
      async (
        ..._arguments: Parameters<PhaseTwoApi["createPlatformOperatorTeam"]>
      ) => {
        createCount += 1;
        return createCount === 1 ? oldCreate.promise : freshCreate.promise;
      },
    );
    const api = createPhaseTwoApi({
      createPlatformOperatorTeam,
      listPlatformOperatorTeams: async () => ({ items: [] }),
    });
    render(<MutablePlatformPermissionsHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", { name: "Create operator team" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
      target: { value: "pending_team" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
      target: { value: "Pending team" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByText("Remove platform team manage"));
    fireEvent.click(screen.getByText("Restore platform team manage"));
    fireEvent.click(
      await screen.findByRole("button", { name: "Create operator team" }),
    );
    expect(
      screen.getByRole("textbox", { name: "Immutable key" }),
    ).toBeEnabled();
    expect(screen.getByRole("textbox", { name: "Team name" })).toBeEnabled();
    fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
      target: { value: "pending_team" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
      target: { value: "Pending team" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformOperatorTeam.mock.calls[1]?.[1]).not.toBe(
      createPlatformOperatorTeam.mock.calls[0]?.[1],
    );

    await act(async () => {
      oldCreate.reject(new PhaseTwoApiError("old create failed", 412));
      await expect(oldCreate.promise).rejects.toThrow("old create failed");
    });
    expect(screen.queryByText("old create failed")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Creating team…" }),
    ).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Immutable key" })).toHaveValue(
      "pending_team",
    );

    await act(async () => {
      freshCreate.resolve({
        etag: '"v2"',
        value: teamFixture({ key: "pending_team", name: "Pending team" }),
      });
      await freshCreate.promise;
    });
    expect(await screen.findByText("Operator team created")).toBeVisible();
  });

  it("starts a fresh metadata save after manage authority is removed and restored", async () => {
    const team = teamFixture();
    let currentTeam = team;
    const oldUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const freshUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    let updateCount = 0;
    const updatePlatformOperatorTeam = vi.fn(
      async (
        ..._arguments: Parameters<PhaseTwoApi["updatePlatformOperatorTeam"]>
      ) => {
        updateCount += 1;
        return updateCount === 1 ? oldUpdate.promise : freshUpdate.promise;
      },
    );
    const api = createPhaseTwoApi({
      getPlatformOperatorTeam: async () => ({
        etag: `"v${currentTeam.version}"`,
        value: currentTeam,
      }),
      listPlatformOperatorTeams: async () => ({ items: [team] }),
      updatePlatformOperatorTeam,
    });
    render(<MutablePlatformPermissionsHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open ${team.name} (${team.key})`,
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Old pending name" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByText("Remove platform team manage"));
    fireEvent.click(screen.getByText("Restore platform team manage"));
    const name = await screen.findByRole("textbox", { name: "Team name" });
    expect(name).toBeEnabled();
    expect(name).toHaveValue(team.name);
    fireEvent.change(name, { target: { value: "Fresh pending name" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      oldUpdate.resolve({
        etag: '"v3"',
        value: teamFixture({ name: "Old committed name", version: 3 }),
      });
      await oldUpdate.promise;
    });
    expect(
      screen.getByRole("button", { name: "Saving changes…" }),
    ).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Fresh pending name",
    );

    await act(async () => {
      currentTeam = teamFixture({ name: "Fresh pending name", version: 3 });
      freshUpdate.resolve({
        etag: '"v3"',
        value: currentTeam,
      });
      await freshUpdate.promise;
    });
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Fresh pending name",
    );
  });

  it("starts a fresh archive after manage authority is removed and restored", async () => {
    const team = teamFixture();
    const oldArchive = createDeferred<void>();
    const freshArchive = createDeferred<void>();
    let archiveCount = 0;
    const archivePlatformOperatorTeam = vi.fn(
      async (
        ..._arguments: Parameters<PhaseTwoApi["archivePlatformOperatorTeam"]>
      ) => {
        archiveCount += 1;
        return archiveCount === 1 ? oldArchive.promise : freshArchive.promise;
      },
    );
    const api = createPhaseTwoApi({
      archivePlatformOperatorTeam,
      getPlatformOperatorTeam: async () => ({ etag: '"v2"', value: team }),
      listPlatformOperatorTeams: async () => ({ items: [team] }),
    });
    render(<MutablePlatformPermissionsHarness api={api} />);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open ${team.name} (${team.key})`,
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Archive reason" }),
      { target: { value: "Old pending archive" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Archive operator team" }),
    );
    await waitFor(() =>
      expect(archivePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByText("Remove platform team manage"));
    fireEvent.click(screen.getByText("Restore platform team manage"));
    const reason = await screen.findByRole("textbox", {
      name: "Archive reason",
    });
    expect(reason).toBeEnabled();
    expect(reason).toHaveValue("");
    fireEvent.change(reason, { target: { value: "Fresh pending archive" } });
    fireEvent.click(
      screen.getByRole("button", { name: "Archive operator team" }),
    );
    await waitFor(() =>
      expect(archivePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      oldArchive.resolve(undefined);
      await oldArchive.promise;
    });
    expect(screen.getByRole("dialog")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Archiving team…" }),
    ).toBeDisabled();

    await act(async () => {
      freshArchive.resolve(undefined);
      await freshArchive.promise;
    });
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
  });

  it("serializes a pending metadata save against archive synchronously", async () => {
    const team = teamFixture();
    const pendingUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const updatePlatformOperatorTeam = vi.fn(
      async (
        ..._arguments: Parameters<PhaseTwoApi["updatePlatformOperatorTeam"]>
      ) => pendingUpdate.promise,
    );
    const archivePlatformOperatorTeam = vi.fn(async () => undefined);
    const api = createPhaseTwoApi({
      archivePlatformOperatorTeam,
      getPlatformOperatorTeam: async () => ({ etag: '"v2"', value: team }),
      listPlatformOperatorTeams: async () => ({ items: [team] }),
      updatePlatformOperatorTeam,
    });
    renderPage(api, [
      "platform.operator_team.manage",
      "platform.operator_team.read",
    ]);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open ${team.name} (${team.key})`,
      }),
    );
    const name = await screen.findByRole("textbox", { name: "Team name" });
    const archiveReason = screen.getByRole("textbox", {
      name: "Archive reason",
    });
    fireEvent.change(name, { target: { value: "Serialized save" } });
    fireEvent.change(archiveReason, {
      target: { value: "Must wait for save" },
    });
    const form = name.closest("form");
    const archiveButton = screen.getByRole("button", {
      name: "Archive operator team",
    });
    expect(form).not.toBeNull();

    act(() => {
      form?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      archiveButton.dispatchEvent(
        new MouseEvent("click", { bubbles: true, cancelable: true }),
      );
    });

    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    expect(archivePlatformOperatorTeam).not.toHaveBeenCalled();
    expect(name).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Description" })).toBeDisabled();
    expect(archiveReason).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Saving changes…" }),
    ).toBeDisabled();
    expect(archiveButton).toBeDisabled();

    await act(async () => {
      pendingUpdate.resolve({
        etag: '"v3"',
        value: teamFixture({ name: "Serialized save", version: 3 }),
      });
      await pendingUpdate.promise;
    });
    await waitFor(() => expect(name).toBeEnabled());
    expect(archiveReason).toBeEnabled();
    expect(archiveButton).toBeEnabled();
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });

  it("admits only one rapid metadata form submission", async () => {
    const team = teamFixture();
    const pendingUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const updatePlatformOperatorTeam = vi.fn(
      async (
        ..._arguments: Parameters<PhaseTwoApi["updatePlatformOperatorTeam"]>
      ) => pendingUpdate.promise,
    );
    const api = createPhaseTwoApi({
      getPlatformOperatorTeam: async () => ({ etag: '"v2"', value: team }),
      listPlatformOperatorTeams: async () => ({ items: [team] }),
      updatePlatformOperatorTeam,
    });
    renderPage(api, [
      "platform.operator_team.manage",
      "platform.operator_team.read",
    ]);

    fireEvent.click(
      await screen.findByRole("button", {
        name: `Open ${team.name} (${team.key})`,
      }),
    );
    const name = await screen.findByRole("textbox", { name: "Team name" });
    fireEvent.change(name, { target: { value: "Single admitted save" } });
    const form = name.closest("form");
    expect(form).not.toBeNull();

    act(() => {
      form?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
      form?.dispatchEvent(
        new Event("submit", { bubbles: true, cancelable: true }),
      );
    });
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );

    await act(async () => {
      pendingUpdate.resolve({
        etag: '"v3"',
        value: teamFixture({ name: "Single admitted save", version: 3 }),
      });
      await pendingUpdate.promise;
    });
    await waitFor(() => expect(name).toBeEnabled());
    expect(screen.getByRole("button", { name: "Save changes" })).toBeDisabled();
  });

  it.each(["close", "x", "escape", "overlay"] as const)(
    "dismisses a pending detail save through %s without surfacing its late failure",
    async (dismissal) => {
      const team = teamFixture();
      const pendingUpdate =
        createDeferred<
          Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
        >();
      const updatePlatformOperatorTeam = vi.fn(
        async () => pendingUpdate.promise,
      );
      renderPage(
        createPhaseTwoApi({
          getPlatformOperatorTeam: async () => ({
            etag: '"v2"',
            value: team,
          }),
          listPlatformOperatorTeams: async () => ({ items: [team] }),
          updatePlatformOperatorTeam,
        }),
        ["platform.operator_team.manage", "platform.operator_team.read"],
      );

      fireEvent.click(
        await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
      );
      const name = await screen.findByRole("textbox", { name: "Team name" });
      fireEvent.change(name, { target: { value: "Pending detail" } });
      fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
      await waitFor(() =>
        expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
      );

      dismissDialog(dismissal);
      await waitFor(() =>
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
      );
      await act(async () => {
        pendingUpdate.reject(new Error("late detail failure"));
        await expect(pendingUpdate.promise).rejects.toThrow(
          "late detail failure",
        );
      });
      expect(screen.queryByText("late detail failure")).not.toBeInTheDocument();
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    },
  );

  it("reconciles a detached save into a reopened copy of the same team", async () => {
    const initial = teamFixture();
    const committed = teamFixture({
      name: "Detached save committed",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const oldUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const reopenedUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const updatePlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldUpdate.promise)
      .mockImplementationOnce(async () => reopenedUpdate.promise);
    const getPlatformOperatorTeam = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValue({ etag: '"v3"', value: committed });
    const listPlatformOperatorTeams = vi
      .fn()
      .mockResolvedValueOnce({ items: [initial] })
      .mockResolvedValue({ items: [committed] });
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam,
        listPlatformOperatorTeams,
        updatePlatformOperatorTeam,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Detached save draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    dismissDialog("close");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    const reopenedName = await screen.findByRole("textbox", {
      name: "Team name",
    });
    fireEvent.change(reopenedName, {
      target: { value: "Reopened unsaved draft" },
    });
    expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(2);

    await act(async () => {
      oldUpdate.resolve({ etag: '"v3"', value: committed });
      await oldUpdate.promise;
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Reopened unsaved draft",
    );

    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(updatePlatformOperatorTeam).toHaveBeenNthCalledWith(
      2,
      sessionFixture.csrfToken,
      teamId,
      '"v3"',
      { name: "Reopened unsaved draft" },
    );
  });

  it("defers same-team reconciliation until the successor mutation settles", async () => {
    const initial = teamFixture();
    const committed = teamFixture({
      name: "Detached predecessor committed",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const oldUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const successorUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const updatePlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldUpdate.promise)
      .mockImplementationOnce(async () => successorUpdate.promise);
    const getPlatformOperatorTeam = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValue({ etag: '"v3"', value: committed });
    const listPlatformOperatorTeams = vi
      .fn()
      .mockResolvedValueOnce({ items: [initial] })
      .mockResolvedValue({ items: [committed] });
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam,
        listPlatformOperatorTeams,
        updatePlatformOperatorTeam,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Detached predecessor draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    dismissDialog("x");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Successor pending draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      oldUpdate.resolve({ etag: '"v3"', value: committed });
      await oldUpdate.promise;
    });
    expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(1);
    expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("button", { name: "Saving changes…" }),
    ).toBeDisabled();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Successor pending draft",
    );

    await act(async () => {
      successorUpdate.reject(new PhaseTwoApiError("successor stale", 412));
      await expect(successorUpdate.promise).rejects.toThrow("successor stale");
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Successor pending draft",
    );
  });

  it("reloads inventory when create commits during an older initial list request", async () => {
    const created = teamFixture({
      key: "created_during_load",
      name: "Created during load",
      version: 1,
    });
    const initialList = createDeferred<{ items: OperatorTeamView[] }>();
    const listPlatformOperatorTeams = vi
      .fn()
      .mockImplementationOnce(async () => initialList.promise)
      .mockResolvedValue({ items: [created] });
    const createPlatformOperatorTeam = vi.fn(async () => ({
      etag: '"v1"',
      value: created,
    }));
    renderPage(
      createPhaseTwoApi({
        createPlatformOperatorTeam,
        listPlatformOperatorTeams,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    await submitCreate(created.key, created.name);
    expect(await screen.findByText("Operator team created")).toBeVisible();
    expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(1);

    await act(async () => {
      initialList.resolve({ items: [] });
      await initialList.promise;
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    expect(await screen.findByText(created.name)).toBeVisible();
  });

  it("reports an archived fulfilled create replay as historical and releases its payload key", async () => {
    const archived = teamFixture({
      key: "archived_replay",
      name: "Archived replay team",
      state: "archived",
      version: 3,
    });
    let committed = false;
    const createPlatformOperatorTeam = vi
      .fn()
      .mockRejectedValueOnce(
        new PhaseTwoApiError("ambiguous archived create", 503),
      )
      .mockImplementationOnce(async () => {
        committed = true;
        return { etag: '"v3"', value: archived };
      })
      .mockRejectedValueOnce(
        new PhaseTwoApiError("fresh archived create cleanup", 503),
      );
    renderPage(
      createPhaseTwoApi({
        createPlatformOperatorTeam,
        listPlatformOperatorTeams: async () => ({
          items: committed ? [archived] : [],
        }),
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    await submitCreate(archived.key, archived.name);
    expect(await screen.findByText("ambiguous archived create")).toBeVisible();
    const retainedKey = createPlatformOperatorTeam.mock.calls[0]?.[1];

    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformOperatorTeam.mock.calls[1]?.[1]).toBe(retainedKey);
    expect(await screen.findByText("Operator team is archived")).toBeVisible();
    expect(
      screen.getByText(
        `${archived.name} is historical and is not available for tenant assignment.`,
      ),
    ).toBeVisible();
    expect(screen.queryByText("Operator team created")).not.toBeInTheDocument();

    await submitCreate(archived.key, archived.name);
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(createPlatformOperatorTeam.mock.calls[2]?.[1]).not.toBe(retainedKey);
    expect(
      await screen.findByText("fresh archived create cleanup"),
    ).toBeVisible();
  });

  it("reconciles a fulfilled detached create and releases its payload key", async () => {
    const created = teamFixture({
      key: "route_created",
      name: "Route-created team",
      version: 1,
    });
    const oldCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    let committed = false;
    const createPlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldCreate.promise)
      .mockResolvedValue({ etag: '"v1"', value: created });
    const listPlatformOperatorTeams = vi.fn(async () => ({
      items: committed ? [created] : [],
    }));
    render(
      <PersistentPlatformRouteHarness
        api={createPhaseTwoApi({
          createPlatformOperatorTeam,
          listPlatformOperatorTeams,
        })}
      />,
    );

    await submitCreate(created.key, created.name);
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    const originalKey = createPlatformOperatorTeam.mock.calls[0]?.[1];

    fireEvent.click(screen.getByText("Leave platform teams route"));
    expect(
      await screen.findByText("Alternate application route"),
    ).toBeVisible();
    fireEvent.click(screen.getByText("Return to platform teams"));
    expect(
      await screen.findByRole("heading", { name: "Operator-team identities" }),
    ).toBeVisible();
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    expect(screen.queryByText(created.name)).not.toBeInTheDocument();

    await act(async () => {
      committed = true;
      oldCreate.resolve({ etag: '"v1"', value: created });
      await oldCreate.promise;
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(3),
    );
    expect(await screen.findByText(created.name)).toBeVisible();

    await submitCreate(created.key, created.name);
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformOperatorTeam.mock.calls[1]?.[1]).not.toBe(originalKey);
  });

  it("retains an ambiguous detached create across a route remount", async () => {
    const ambiguousCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const retryCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const createPlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => ambiguousCreate.promise)
      .mockImplementationOnce(async () => retryCreate.promise);
    render(
      <PersistentPlatformRouteHarness
        api={createPhaseTwoApi({
          createPlatformOperatorTeam,
          listPlatformOperatorTeams: async () => ({ items: [] }),
        })}
      />,
    );

    await submitCreate("ambiguous_route", "Ambiguous route team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    const originalKey = createPlatformOperatorTeam.mock.calls[0]?.[1];
    fireEvent.click(screen.getByText("Leave platform teams route"));
    await act(async () => {
      ambiguousCreate.reject(new Error("ambiguous detached create"));
      await expect(ambiguousCreate.promise).rejects.toThrow(
        "ambiguous detached create",
      );
    });
    fireEvent.click(await screen.findByText("Return to platform teams"));
    await submitCreate("ambiguous_route", "Ambiguous route team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformOperatorTeam.mock.calls[1]?.[1]).toBe(originalKey);

    await act(async () => {
      retryCreate.reject(new Error("retry cleanup"));
      await expect(retryCreate.promise).rejects.toThrow("retry cleanup");
    });
  });

  it("keeps route-remount create binding ownership with an overlapping retry", async () => {
    const created = teamFixture({
      key: "route_retry",
      name: "Route retry team",
      version: 1,
    });
    const oldCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const successorCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const thirdCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    let committed = false;
    const createPlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldCreate.promise)
      .mockImplementationOnce(async () => successorCreate.promise)
      .mockImplementationOnce(async () => thirdCreate.promise);
    const listPlatformOperatorTeams = vi.fn(async () => ({
      items: committed ? [created] : [],
    }));
    render(
      <PersistentPlatformRouteHarness
        api={createPhaseTwoApi({
          createPlatformOperatorTeam,
          listPlatformOperatorTeams,
        })}
      />,
    );

    await submitCreate(created.key, created.name);
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    const originalKey = createPlatformOperatorTeam.mock.calls[0]?.[1];
    fireEvent.click(screen.getByText("Leave platform teams route"));
    fireEvent.click(await screen.findByText("Return to platform teams"));
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );

    await submitCreate(created.key, created.name);
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformOperatorTeam.mock.calls[1]?.[1]).toBe(originalKey);

    await act(async () => {
      committed = true;
      oldCreate.resolve({ etag: '"v1"', value: created });
      await oldCreate.promise;
    });
    expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("dialog")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Creating team…" }),
    ).toBeDisabled();

    await act(async () => {
      successorCreate.reject(new Error("ambiguous route retry"));
      await expect(successorCreate.promise).rejects.toThrow(
        "ambiguous route retry",
      );
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(3),
    );
    expect(await screen.findByText(created.name)).toBeVisible();
    expect(screen.getByRole("dialog")).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(createPlatformOperatorTeam.mock.calls[2]?.[1]).toBe(originalKey);
  });

  it("reloads inventory and current detail after a detached route save commits", async () => {
    const initial = teamFixture();
    const committed = teamFixture({
      name: "Route-detached save committed",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const oldUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    let didCommit = false;
    const listPlatformOperatorTeams = vi.fn(async () => ({
      items: [didCommit ? committed : initial],
    }));
    const getPlatformOperatorTeam = vi.fn(async () =>
      didCommit
        ? { etag: '"v3"', value: committed }
        : { etag: '"v2"', value: initial },
    );
    render(
      <PersistentPlatformRouteHarness
        api={createPhaseTwoApi({
          getPlatformOperatorTeam,
          listPlatformOperatorTeams,
          updatePlatformOperatorTeam: async () => oldUpdate.promise,
        })}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Route-detached draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    fireEvent.click(screen.getByText("Leave platform teams route"));
    expect(
      await screen.findByText("Alternate application route"),
    ).toBeVisible();
    fireEvent.click(screen.getByText("Return to platform teams"));
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    await screen.findByRole("textbox", { name: "Team name" });
    expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(2);

    await act(async () => {
      didCommit = true;
      oldUpdate.resolve({ etag: '"v3"', value: committed });
      await oldUpdate.promise;
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(3),
    );
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      committed.name,
    );
    expect(
      screen.getByText(committed.name, { selector: "strong" }),
    ).toBeVisible();
  });

  it("defers route-remount reconciliation behind a fresh same-team save", async () => {
    const initial = teamFixture();
    const committed = teamFixture({
      name: "Route predecessor committed",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const oldUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const successorUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    let didCommit = false;
    const updatePlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldUpdate.promise)
      .mockImplementationOnce(async () => successorUpdate.promise);
    const listPlatformOperatorTeams = vi.fn(async () => ({
      items: [didCommit ? committed : initial],
    }));
    const getPlatformOperatorTeam = vi.fn(async () =>
      didCommit
        ? { etag: '"v3"', value: committed }
        : { etag: '"v2"', value: initial },
    );
    render(
      <PersistentPlatformRouteHarness
        api={createPhaseTwoApi({
          getPlatformOperatorTeam,
          listPlatformOperatorTeams,
          updatePlatformOperatorTeam,
        })}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Route predecessor draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByText("Leave platform teams route"));
    fireEvent.click(await screen.findByText("Return to platform teams"));
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Route successor pending" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(2);

    await act(async () => {
      didCommit = true;
      oldUpdate.resolve({ etag: '"v3"', value: committed });
      await oldUpdate.promise;
    });
    expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2);
    expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(2);
    expect(
      screen.getByRole("button", { name: "Saving changes…" }),
    ).toBeDisabled();

    await act(async () => {
      successorUpdate.reject(
        new PhaseTwoApiError("route successor stale", 412),
      );
      await expect(successorUpdate.promise).rejects.toThrow(
        "route successor stale",
      );
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(3),
    );
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Route successor pending",
    );
  });

  it("retains detached-save reconciliation across a failed detail refresh", async () => {
    const initial = teamFixture();
    const committed = teamFixture({
      name: "Committed after failed refresh",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const pendingUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const getPlatformOperatorTeam = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockRejectedValueOnce(
        new PhaseTwoApiError("reconciliation detail failed", 500),
      )
      .mockResolvedValue({ etag: '"v3"', value: committed });
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam,
        listPlatformOperatorTeams: vi
          .fn()
          .mockResolvedValueOnce({ items: [initial] })
          .mockResolvedValue({ items: [committed] }),
        updatePlatformOperatorTeam: async () => pendingUpdate.promise,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Detached draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    dismissDialog("close");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    await screen.findByRole("textbox", { name: "Team name" });

    await act(async () => {
      pendingUpdate.resolve({ etag: '"v3"', value: committed });
      await pendingUpdate.promise;
    });
    expect(
      await screen.findByText("reconciliation detail failed"),
    ).toBeVisible();
    expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(3);

    fireEvent.click(screen.getByRole("button", { name: "Retry team detail" }));
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(4),
    );
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();
  });

  it("reschedules a newer inventory generation once after an older refresh fails", async () => {
    const alpha = teamFixture({ name: "Alpha SOC" });
    const bravo = teamFixture({
      id: "0198c97d-cf4f-7000-8000-000000000402",
      key: "bravo_soc",
      name: "Bravo SOC",
    });
    const committedAlpha = { ...alpha, name: "Committed Alpha", version: 3 };
    const committedBravo = { ...bravo, name: "Committed Bravo", version: 3 };
    const alphaUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const bravoUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const failedRefresh = createDeferred<{ items: OperatorTeamView[] }>();
    let alphaCommitted = false;
    let bravoCommitted = false;
    let listCount = 0;
    const listPlatformOperatorTeams = vi.fn(async () => {
      listCount += 1;
      if (listCount === 2) return failedRefresh.promise;
      return {
        items: [
          alphaCommitted ? committedAlpha : alpha,
          bravoCommitted ? committedBravo : bravo,
        ],
      };
    });
    const updatePlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => alphaUpdate.promise)
      .mockImplementationOnce(async () => bravoUpdate.promise);
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam: async (requestedTeamId) => ({
          etag:
            requestedTeamId === alpha.id
              ? alphaCommitted
                ? '"v3"'
                : '"v2"'
              : bravoCommitted
                ? '"v3"'
                : '"v2"',
          value:
            requestedTeamId === alpha.id
              ? alphaCommitted
                ? committedAlpha
                : alpha
              : bravoCommitted
                ? committedBravo
                : bravo,
        }),
        listPlatformOperatorTeams,
        updatePlatformOperatorTeam,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open Alpha SOC (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: committedAlpha.name } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    dismissDialog("close");

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Bravo SOC (bravo_soc)",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: committedBravo.name } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      alphaCommitted = true;
      alphaUpdate.resolve({ etag: '"v3"', value: committedAlpha });
      await alphaUpdate.promise;
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      bravoCommitted = true;
      bravoUpdate.resolve({ etag: '"v3"', value: committedBravo });
      await bravoUpdate.promise;
      failedRefresh.reject(new Error("older inventory refresh failed"));
      await expect(failedRefresh.promise).rejects.toThrow(
        "older inventory refresh failed",
      );
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(3),
    );
    expect(await screen.findByText(committedAlpha.name)).toBeVisible();
    expect(screen.getByText(committedBravo.name)).toBeVisible();
    await act(async () => Promise.resolve());
    expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(3);
  });

  it("retains detached-save reconciliation when its detail refresh is aborted", async () => {
    const initial = teamFixture();
    const committed = teamFixture({
      name: "Committed after aborted refresh",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const pendingUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const pendingRefresh =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["getPlatformOperatorTeam"]>>
      >();
    let refreshSignal: AbortSignal | undefined;
    let getCount = 0;
    const getPlatformOperatorTeam = vi.fn(
      async (
        _teamId: string,
        signal?: AbortSignal,
      ): ReturnType<PhaseTwoApi["getPlatformOperatorTeam"]> => {
        getCount += 1;
        if (getCount <= 2) return { etag: '"v2"', value: initial };
        if (getCount === 3) {
          refreshSignal = signal;
          return pendingRefresh.promise;
        }
        return { etag: '"v3"', value: committed };
      },
    );
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam,
        listPlatformOperatorTeams: vi
          .fn()
          .mockResolvedValueOnce({ items: [initial] })
          .mockResolvedValue({ items: [committed] }),
        updatePlatformOperatorTeam: async () => pendingUpdate.promise,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Detached draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    dismissDialog("close");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    await screen.findByRole("textbox", { name: "Team name" });

    await act(async () => {
      pendingUpdate.resolve({ etag: '"v3"', value: committed });
      await pendingUpdate.promise;
    });
    await waitFor(() => expect(refreshSignal).toBeDefined());
    dismissDialog("close");
    await waitFor(() => expect(refreshSignal?.aborted).toBe(true));
    fireEvent.click(screen.getByRole("button", { name: /Open .* \(soc_l1\)/ }));
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(4),
    );
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();

    await act(async () => {
      pendingRefresh.resolve({ etag: '"v2"', value: initial });
      await pendingRefresh.promise;
    });
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();
  });

  it("releases reconciliation ownership across an A to B selection change", async () => {
    const alpha = teamFixture({ name: "Alpha SOC" });
    const committedAlpha = teamFixture({
      name: "Committed Alpha SOC",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const bravo = teamFixture({
      id: "0198c97d-cf4f-7000-8000-000000000402",
      key: "bravo_soc",
      name: "Bravo SOC",
    });
    const oldUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const successorUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    let alphaCommitted = false;
    const updatePlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldUpdate.promise)
      .mockImplementationOnce(async () => successorUpdate.promise);
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam: async (requestedTeamId) => ({
          etag:
            alphaCommitted && requestedTeamId === alpha.id ? '"v3"' : '"v2"',
          value:
            requestedTeamId === alpha.id
              ? alphaCommitted
                ? committedAlpha
                : alpha
              : bravo,
        }),
        listPlatformOperatorTeams: async () => ({
          items: [alphaCommitted ? committedAlpha : alpha, bravo],
        }),
        updatePlatformOperatorTeam,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha SOC (soc_l1)",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Detached Alpha draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    dismissDialog("close");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open Alpha SOC (soc_l1)" }),
    );
    await screen.findByRole("textbox", { name: "Team name" });

    await act(async () => {
      alphaCommitted = true;
      oldUpdate.resolve({ etag: '"v3"', value: committedAlpha });
      await oldUpdate.promise;
      dismissDialog("close");
    });
    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Bravo SOC (bravo_soc)",
      }),
    );
    expect(
      await screen.findByRole("heading", { name: "Operator team · Bravo SOC" }),
    ).toBeVisible();
    dismissDialog("close");

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Committed Alpha SOC (soc_l1)",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      { target: { value: "Successor Alpha draft" } },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(
      screen.getByRole("button", { name: "Saving changes…" }),
    ).toBeDisabled();
  });

  it("does not let an old detail success update a newer pending team operation", async () => {
    const alpha = teamFixture({ name: "Alpha SOC" });
    const bravo = teamFixture({
      id: "0198c97d-cf4f-7000-8000-000000000402",
      key: "bravo_soc",
      name: "Bravo SOC",
    });
    let currentBravo = bravo;
    const oldUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const freshUpdate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["updatePlatformOperatorTeam"]>>
      >();
    const updatePlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldUpdate.promise)
      .mockImplementationOnce(async () => freshUpdate.promise);
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam: async (requestedTeamId) => ({
          etag:
            requestedTeamId === alpha.id
              ? '"v2"'
              : `"v${currentBravo.version}"`,
          value: requestedTeamId === alpha.id ? alpha : currentBravo,
        }),
        listPlatformOperatorTeams: async () => ({ items: [alpha, bravo] }),
        updatePlatformOperatorTeam,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha SOC (soc_l1)",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Team name" }),
      {
        target: { value: "Old Alpha draft" },
      },
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    dismissDialog("escape");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Open Bravo SOC (bravo_soc)" }),
    );
    const freshName = await screen.findByRole("textbox", { name: "Team name" });
    fireEvent.change(freshName, { target: { value: "Fresh Bravo draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      oldUpdate.resolve({
        etag: '"v3"',
        value: { ...alpha, name: "Old Alpha draft", version: 3 },
      });
      await oldUpdate.promise;
    });
    expect(
      screen.getByRole("heading", { name: "Operator team · Bravo SOC" }),
    ).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Fresh Bravo draft",
    );
    expect(
      screen.getByRole("button", { name: "Saving changes…" }),
    ).toBeDisabled();

    await act(async () => {
      currentBravo = { ...bravo, name: "Fresh Bravo draft", version: 3 };
      freshUpdate.resolve({
        etag: '"v3"',
        value: currentBravo,
      });
      await freshUpdate.promise;
    });
    expect(
      screen.getByRole("heading", {
        name: "Operator team · Fresh Bravo draft",
      }),
    ).toBeVisible();
  });

  it("does not let a late archive close a newly opened team detail", async () => {
    const alpha = teamFixture({ name: "Alpha SOC" });
    const bravo = teamFixture({
      id: "0198c97d-cf4f-7000-8000-000000000402",
      key: "bravo_soc",
      name: "Bravo SOC",
    });
    const pendingArchive = createDeferred<void>();
    const archivePlatformOperatorTeam = vi.fn(
      async () => pendingArchive.promise,
    );
    renderPage(
      createPhaseTwoApi({
        archivePlatformOperatorTeam,
        getPlatformOperatorTeam: async (requestedTeamId) => ({
          etag: '"v2"',
          value: requestedTeamId === alpha.id ? alpha : bravo,
        }),
        listPlatformOperatorTeams: async () => ({ items: [alpha, bravo] }),
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Open Alpha SOC (soc_l1)",
      }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Archive reason" }),
      { target: { value: "Retire Alpha after handoff" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Archive operator team" }),
    );
    await waitFor(() =>
      expect(archivePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    dismissDialog("overlay");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Open Bravo SOC (bravo_soc)" }),
    );
    expect(
      await screen.findByRole("heading", {
        name: "Operator team · Bravo SOC",
      }),
    ).toBeVisible();
    await act(async () => {
      pendingArchive.resolve(undefined);
      await pendingArchive.promise;
    });
    expect(
      screen.getByRole("heading", { name: "Operator team · Bravo SOC" }),
    ).toBeVisible();
  });

  it("reconciles a detached archive into the reopened team's lifecycle", async () => {
    const initial = teamFixture();
    const archived = teamFixture({
      state: "archived",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    });
    const pendingArchive = createDeferred<void>();
    const archivePlatformOperatorTeam = vi.fn(
      async () => pendingArchive.promise,
    );
    const getPlatformOperatorTeam = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValue({ etag: '"v3"', value: archived });
    const listPlatformOperatorTeams = vi
      .fn()
      .mockResolvedValueOnce({ items: [initial] })
      .mockResolvedValue({ items: [archived] });
    renderPage(
      createPhaseTwoApi({
        archivePlatformOperatorTeam,
        getPlatformOperatorTeam,
        listPlatformOperatorTeams,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    fireEvent.change(
      await screen.findByRole("textbox", { name: "Archive reason" }),
      { target: { value: "Retire the queue" } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Archive operator team" }),
    );
    await waitFor(() =>
      expect(archivePlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    dismissDialog("overlay");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    expect(
      await screen.findByRole("heading", { name: "Operator team · SOC L1" }),
    ).toBeVisible();

    await act(async () => {
      pendingArchive.resolve(undefined);
      await pendingArchive.promise;
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(screen.getByRole("dialog")).toBeVisible();
    expect(screen.getByText('"v3"', { selector: "code" })).toBeVisible();
    expect(
      screen.queryByRole("textbox", { name: "Archive reason" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Archive operator team" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText(archived.name, { selector: "strong" }).closest("tr"),
    ).toHaveTextContent("archived");
  });

  it("unlocks creation for a new session while an old create is pending", async () => {
    const pendingCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const createPlatformOperatorTeam = vi.fn(async () => pendingCreate.promise);
    const listPlatformOperatorTeams = vi.fn(async () => ({ items: [] }));
    render(
      <MutablePlatformPermissionsHarness
        api={createPhaseTwoApi({
          createPlatformOperatorTeam,
          listPlatformOperatorTeams,
        })}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create operator team" }),
    );
    expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(1);
    fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
      target: { value: "pending_team" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
      target: { value: "Pending team" },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );

    fireEvent.click(screen.getByText("Rotate platform team session"));
    fireEvent.click(
      await screen.findByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    expect(
      screen.getByRole("textbox", { name: "Immutable key" }),
    ).toBeEnabled();
    expect(screen.getByRole("textbox", { name: "Team name" })).toBeEnabled();

    await act(async () => {
      pendingCreate.resolve({ etag: '"v2"', value: teamFixture() });
      await pendingCreate.promise;
    });
    expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2);
    expect(screen.getByRole("dialog")).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Immutable key" })).toHaveValue(
      "",
    );
    expect(screen.queryByText("Operator team created")).not.toBeInTheDocument();
  });

  it("makes a pending create completion a no-op after the page unmounts", async () => {
    const pendingCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const createPlatformOperatorTeam = vi.fn(async () => pendingCreate.promise);
    const clearSession = vi.fn();
    const page = render(
      <SessionContext.Provider
        value={{
          api: createPhaseTwoApi({
            createPlatformOperatorTeam,
            listPlatformOperatorTeams: async () => ({ items: [] }),
          }),
          clearSession,
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          session: {
            ...sessionFixture,
            permissions: [
              "platform.operator_team.manage",
              "platform.operator_team.read",
            ],
          },
          updateSession: vi.fn(),
        }}
      >
        <PlatformOperatorTeamCoordinatorProvider>
          <PlatformOperatorTeamsPage />
        </PlatformOperatorTeamCoordinatorProvider>
      </SessionContext.Provider>,
    );

    await submitCreate("pending_team", "Pending team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    page.unmount();

    await act(async () => {
      pendingCreate.reject(new PhaseTwoApiError("expired route", 401));
      await expect(pendingCreate.promise).rejects.toThrow("expired route");
    });
    expect(clearSession).not.toHaveBeenCalled();
  });

  it("aborts an old inventory page before a same-session read reload", async () => {
    const delayedPage = createDeferred<{
      items: OperatorTeamView[];
    }>();
    const refreshed = teamFixture({ name: "Refreshed SOC" });
    const stale = teamFixture({
      id: "0198c97d-cf4f-7000-8000-000000000499",
      key: "stale_soc",
      name: "Stale SOC page",
    });
    let initialLoads = 0;
    let pendingSignal: AbortSignal | undefined;
    const listPlatformOperatorTeams = vi.fn(
      async (
        options?: Parameters<PhaseTwoApi["listPlatformOperatorTeams"]>[0],
      ) => {
        if (options?.after) {
          pendingSignal = options.signal;
          return delayedPage.promise;
        }
        initialLoads += 1;
        return {
          items: [initialLoads === 1 ? teamFixture() : refreshed],
          nextCursor: "platform-cursor-a",
        };
      },
    );
    render(
      <MutablePlatformPermissionsHarness
        api={createPhaseTwoApi({ listPlatformOperatorTeams })}
      />,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more operator teams" }),
    );
    await waitFor(() => expect(pendingSignal).toBeDefined());
    fireEvent.click(
      screen.getByRole("button", { name: "Remove platform team read" }),
    );
    await waitFor(() => expect(pendingSignal?.aborted).toBe(true));
    fireEvent.click(
      screen.getByRole("button", { name: "Restore platform team read" }),
    );
    expect(await screen.findByText(refreshed.name)).toBeVisible();

    await act(async () => {
      delayedPage.resolve({ items: [stale] });
      await delayedPage.promise;
    });
    expect(screen.queryByText(stale.name)).not.toBeInTheDocument();
  });

  it("clears a stale pagination error when a create triggers a full inventory reload", async () => {
    const initial = teamFixture();
    const created = teamFixture({
      id: "0198c97d-cf4f-7000-8000-000000000498",
      key: "page_recovery",
      name: "Pagination recovery team",
      version: 1,
    });
    let inventoryLoads = 0;
    const listPlatformOperatorTeams = vi.fn(
      async (
        options?: Parameters<PhaseTwoApi["listPlatformOperatorTeams"]>[0],
      ) => {
        if (options?.after) {
          throw new PhaseTwoApiError("stale operator-team page error", 503);
        }
        inventoryLoads += 1;
        return inventoryLoads === 1
          ? { items: [initial], nextCursor: "platform-page-error" }
          : { items: [initial, created] };
      },
    );
    const createPlatformOperatorTeam = vi.fn(async () => ({
      etag: '"v1"',
      value: created,
    }));
    renderPage(
      createPhaseTwoApi({
        createPlatformOperatorTeam,
        listPlatformOperatorTeams,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Load more operator teams" }),
    );
    expect(
      await screen.findByText("stale operator-team page error"),
    ).toBeVisible();

    await submitCreate(created.key, created.name);
    expect(await screen.findByText("Operator team created")).toBeVisible();
    await waitFor(() =>
      expect(
        listPlatformOperatorTeams.mock.calls.length,
      ).toBeGreaterThanOrEqual(3),
    );
    expect(
      screen.queryByText("stale operator-team page error"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Load more operator teams" }),
    ).not.toBeInTheDocument();
  });

  it("keeps an idempotency key per ambiguous create payload", async () => {
    const createPlatformOperatorTeam = vi
      .fn()
      .mockRejectedValue(new Error("transport interrupted"));
    renderPage(
      createPhaseTwoApi({
        createPlatformOperatorTeam,
        listPlatformOperatorTeams: async () => ({ items: [] }),
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Create operator team" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
      target: { value: "soc_l2" },
    });
    const name = screen.getByRole("textbox", { name: "Team name" });
    fireEvent.change(name, { target: { value: "SOC L2" } });
    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await screen.findByText(/same payload can be retried safely/i);
    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );

    const firstKey = createPlatformOperatorTeam.mock.calls[0]?.[1];
    const retryKey = createPlatformOperatorTeam.mock.calls[1]?.[1];
    expect(retryKey).toBe(firstKey);

    fireEvent.change(name, { target: { value: "SOC L2 escalation" } });
    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(3),
    );
    expect(createPlatformOperatorTeam.mock.calls[2]?.[1]).not.toBe(firstKey);

    fireEvent.change(name, { target: { value: "SOC L2" } });
    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(4),
    );
    expect(createPlatformOperatorTeam.mock.calls[3]?.[1]).toBe(firstKey);
  });

  it.each(["cancel", "x", "escape", "overlay"] as const)(
    "dismisses a pending create through %s without surfacing its late failure",
    async (dismissal) => {
      const pendingCreate =
        createDeferred<
          Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
        >();
      const createPlatformOperatorTeam = vi.fn(
        async () => pendingCreate.promise,
      );
      renderPage(
        createPhaseTwoApi({
          createPlatformOperatorTeam,
          listPlatformOperatorTeams: async () => ({ items: [] }),
        }),
        ["platform.operator_team.manage", "platform.operator_team.read"],
      );

      await submitCreate("pending_team", "Pending team");
      await waitFor(() =>
        expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
      );
      dismissDialog(dismissal);
      await waitFor(() =>
        expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
      );

      await act(async () => {
        pendingCreate.reject(new Error("late create failure"));
        await expect(pendingCreate.promise).rejects.toThrow(
          "late create failure",
        );
      });
      expect(screen.queryByText("late create failure")).not.toBeInTheDocument();
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    },
  );

  it("keeps an ambiguous create retry bound while a late failure settles", async () => {
    const oldCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const retryCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const createPlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldCreate.promise)
      .mockImplementationOnce(async () => retryCreate.promise);
    renderPage(
      createPhaseTwoApi({
        createPlatformOperatorTeam,
        listPlatformOperatorTeams: async () => ({ items: [] }),
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    await submitCreate("pending_team", "Pending team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    dismissDialog("cancel");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    await submitCreate("pending_team", "Pending team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformOperatorTeam.mock.calls[1]?.[1]).toBe(
      createPlatformOperatorTeam.mock.calls[0]?.[1],
    );

    await act(async () => {
      oldCreate.reject(new Error("old transport interrupted"));
      await expect(oldCreate.promise).rejects.toThrow(
        "old transport interrupted",
      );
    });
    expect(screen.getByRole("dialog")).toBeVisible();
    expect(
      screen.getByRole("button", { name: "Creating team…" }),
    ).toBeDisabled();
    expect(
      screen.queryByText("old transport interrupted"),
    ).not.toBeInTheDocument();

    await act(async () => {
      retryCreate.resolve({
        etag: '"v2"',
        value: teamFixture({ key: "pending_team", name: "Pending team" }),
      });
      await retryCreate.promise;
    });
    expect(await screen.findByText("Operator team created")).toBeVisible();
  });

  it("does not let an old create success close or populate a newer operation", async () => {
    const oldCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const freshCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const createPlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldCreate.promise)
      .mockImplementationOnce(async () => freshCreate.promise);
    renderPage(
      createPhaseTwoApi({
        createPlatformOperatorTeam,
        listPlatformOperatorTeams: async () => ({ items: [] }),
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    await submitCreate("old_team", "Old team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    dismissDialog("x");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    await submitCreate("fresh_team", "Fresh team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );

    await act(async () => {
      oldCreate.resolve({
        etag: '"v2"',
        value: teamFixture({ key: "old_team", name: "Old team" }),
      });
      await oldCreate.promise;
    });
    expect(screen.getByRole("dialog")).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Immutable key" })).toHaveValue(
      "fresh_team",
    );
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Fresh team",
    );
    expect(
      screen.getByRole("button", { name: "Creating team…" }),
    ).toBeDisabled();
    expect(screen.queryByText("Operator team created")).not.toBeInTheDocument();

    await act(async () => {
      freshCreate.resolve({
        etag: '"v2"',
        value: teamFixture({ key: "fresh_team", name: "Fresh team" }),
      });
      await freshCreate.promise;
    });
    expect(await screen.findByText("Operator team created")).toBeVisible();
  });

  it("releases a fulfilled detached create while preserving its reopened draft", async () => {
    const created = teamFixture({
      key: "pending_team",
      name: "Pending team",
    });
    const oldCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const retryCreate =
      createDeferred<
        Awaited<ReturnType<PhaseTwoApi["createPlatformOperatorTeam"]>>
      >();
    const createPlatformOperatorTeam = vi
      .fn()
      .mockImplementationOnce(async () => oldCreate.promise)
      .mockImplementationOnce(async () => retryCreate.promise);
    const listPlatformOperatorTeams = vi
      .fn()
      .mockResolvedValueOnce({ items: [] })
      .mockResolvedValue({ items: [created] });
    renderPage(
      createPhaseTwoApi({
        createPlatformOperatorTeam,
        listPlatformOperatorTeams,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    await submitCreate("pending_team", "Pending team");
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(1),
    );
    const firstKey = createPlatformOperatorTeam.mock.calls[0]?.[1];
    dismissDialog("cancel");
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
      target: { value: "pending_team" },
    });
    fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
      target: { value: "Pending team" },
    });

    await act(async () => {
      oldCreate.resolve({ etag: '"v2"', value: created });
      await oldCreate.promise;
    });
    await waitFor(() =>
      expect(listPlatformOperatorTeams).toHaveBeenCalledTimes(2),
    );
    expect(screen.getByRole("dialog")).toBeVisible();
    expect(screen.getByRole("textbox", { name: "Immutable key" })).toHaveValue(
      "pending_team",
    );
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      "Pending team",
    );
    expect(screen.getByRole("textbox", { name: "Team name" })).toBeEnabled();
    expect(screen.queryByText("Operator team created")).not.toBeInTheDocument();
    expect(
      screen.getByText(created.name, { selector: "strong" }),
    ).toBeVisible();

    fireEvent.click(
      screen.getByRole("button", { name: "Create operator team" }),
    );
    await waitFor(() =>
      expect(createPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(createPlatformOperatorTeam.mock.calls[1]?.[1]).not.toBe(firstKey);

    await act(async () => {
      retryCreate.resolve({ etag: '"v2"', value: created });
      await retryCreate.promise;
    });
    expect(await screen.findByText("Operator team created")).toBeVisible();
  });

  it.each(["\u0000", "\u0085"])(
    "rejects %s in platform descriptions and archive reasons before any API call",
    async (controlCharacter) => {
      const team = teamFixture();
      const createPlatformOperatorTeam = vi.fn();
      const updatePlatformOperatorTeam = vi.fn();
      const archivePlatformOperatorTeam = vi.fn();
      renderPage(
        createPhaseTwoApi({
          archivePlatformOperatorTeam,
          createPlatformOperatorTeam,
          getPlatformOperatorTeam: async () => ({
            etag: '"v2"',
            value: team,
          }),
          listPlatformOperatorTeams: async () => ({ items: [team] }),
          updatePlatformOperatorTeam,
        }),
        ["platform.operator_team.manage", "platform.operator_team.read"],
      );

      fireEvent.click(
        await screen.findByRole("button", { name: "Create operator team" }),
      );
      fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
        target: { value: "invalid_team" },
      });
      fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
        target: { value: "Invalid team" },
      });
      fireEvent.change(screen.getByRole("textbox", { name: "Description" }), {
        target: { value: `Invalid${controlCharacter}description` },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Create operator team" }),
      );
      expect(
        await screen.findByText(
          "Use a description without control characters.",
        ),
      ).toBeVisible();
      expect(createPlatformOperatorTeam).not.toHaveBeenCalled();

      dismissDialog("cancel");
      fireEvent.click(
        await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
      );
      const description = await screen.findByRole("textbox", {
        name: "Description",
      });
      fireEvent.change(description, {
        target: { value: `Invalid${controlCharacter}description` },
      });
      fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
      expect(
        await screen.findByText(
          "Use a description without control characters.",
        ),
      ).toBeVisible();
      expect(updatePlatformOperatorTeam).not.toHaveBeenCalled();

      fireEvent.change(
        screen.getByRole("textbox", { name: "Archive reason" }),
        { target: { value: `Invalid${controlCharacter}reason` } },
      );
      fireEvent.click(
        screen.getByRole("button", { name: "Archive operator team" }),
      );
      expect(
        await screen.findByText("Use a reason without control characters."),
      ).toBeVisible();
      expect(archivePlatformOperatorTeam).not.toHaveBeenCalled();
    },
  );

  it("preserves a metadata draft across 412 refresh and retries with the current ETag", async () => {
    const initial = teamFixture();
    const current = {
      ...initial,
      description: "Concurrent queue description",
      updatedAt: "2026-08-24T09:00:00Z",
      version: 3,
    };
    const saved = {
      ...current,
      name: "SOC L1 operator draft",
      updatedAt: "2026-08-24T09:15:00Z",
      version: 4,
    };
    const getPlatformOperatorTeam = vi
      .fn()
      .mockResolvedValueOnce({ etag: '"v2"', value: initial })
      .mockResolvedValueOnce({ etag: '"v3"', value: current });
    const updatePlatformOperatorTeam = vi
      .fn()
      .mockRejectedValueOnce(new PhaseTwoApiError("stale metadata", 412))
      .mockResolvedValueOnce({ etag: '"v4"', value: saved });
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam,
        listPlatformOperatorTeams: async () => ({ items: [initial] }),
        updatePlatformOperatorTeam,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    const name = await screen.findByRole("textbox", { name: "Team name" });
    fireEvent.change(name, { target: { value: saved.name } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(await screen.findByText(/stale metadata/i)).toBeVisible();
    expect(updatePlatformOperatorTeam).toHaveBeenNthCalledWith(
      1,
      sessionFixture.csrfToken,
      teamId,
      '"v2"',
      { name: saved.name },
    );

    fireEvent.click(
      screen.getByRole("button", { name: "Load current version" }),
    );
    await waitFor(() =>
      expect(getPlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(screen.getByRole("textbox", { name: "Team name" })).toHaveValue(
      saved.name,
    );
    expect(screen.getByRole("textbox", { name: "Description" })).toHaveValue(
      current.description,
    );
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));
    await waitFor(() =>
      expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(2),
    );
    expect(updatePlatformOperatorTeam).toHaveBeenNthCalledWith(
      2,
      sessionFixture.csrfToken,
      teamId,
      '"v3"',
      { name: saved.name },
    );
  });

  it("settles a detail mutation after the StrictMode effect remount", async () => {
    const initial = teamFixture();
    const saved = {
      ...initial,
      name: "Strict-mode SOC",
      updatedAt: "2026-08-24T09:15:00Z",
      version: 3,
    };
    const updatePlatformOperatorTeam = vi.fn(async () => ({
      etag: '"v3"',
      value: saved,
    }));
    renderPage(
      createPhaseTwoApi({
        getPlatformOperatorTeam: async () => ({
          etag: '"v2"',
          value: initial,
        }),
        listPlatformOperatorTeams: async () => ({ items: [initial] }),
        updatePlatformOperatorTeam,
      }),
      ["platform.operator_team.manage", "platform.operator_team.read"],
      true,
    );

    fireEvent.click(
      await screen.findByRole("button", { name: "Open SOC L1 (soc_l1)" }),
    );
    const name = await screen.findByRole("textbox", { name: "Team name" });
    fireEvent.change(name, { target: { value: saved.name } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    expect(
      await screen.findByRole("heading", {
        name: `Operator team · ${saved.name}`,
      }),
    ).toBeVisible();
    expect(updatePlatformOperatorTeam).toHaveBeenCalledTimes(1);
  });
});

function renderPage(
  api: ReturnType<typeof createPhaseTwoApi>,
  permissions: readonly string[],
  strict = false,
): ReturnType<typeof render> {
  const page = (
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: { ...sessionFixture, permissions },
        updateSession: vi.fn(),
      }}
    >
      <PlatformOperatorTeamCoordinatorProvider>
        <PlatformOperatorTeamsPage />
      </PlatformOperatorTeamCoordinatorProvider>
    </SessionContext.Provider>
  );
  return render(strict ? <StrictMode>{page}</StrictMode> : page);
}

function MutablePlatformPermissionsHarness({
  api,
}: {
  api: ReturnType<typeof createPhaseTwoApi>;
}): React.JSX.Element {
  const [canManage, setCanManage] = useState(true);
  const [canRead, setCanRead] = useState(true);
  const [sessionId, setSessionId] = useState(sessionFixture.id);
  const permissions = [
    ...(canRead ? ["platform.operator_team.read"] : []),
    ...(canManage ? ["platform.operator_team.manage"] : []),
  ];
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: { ...sessionFixture, id: sessionId, permissions },
        updateSession: vi.fn(),
      }}
    >
      <PlatformOperatorTeamCoordinatorProvider>
        <PlatformOperatorTeamsPage />
        <button type="button" onClick={() => setCanManage(false)}>
          Remove platform team manage
        </button>
        <button type="button" onClick={() => setCanManage(true)}>
          Restore platform team manage
        </button>
        <button type="button" onClick={() => setCanRead(false)}>
          Remove platform team read
        </button>
        <button type="button" onClick={() => setCanRead(true)}>
          Restore platform team read
        </button>
        <button
          type="button"
          onClick={() => setSessionId("0198c97d-cf4f-7000-8000-000000000098")}
        >
          Rotate platform team session
        </button>
      </PlatformOperatorTeamCoordinatorProvider>
    </SessionContext.Provider>
  );
}

function PersistentPlatformRouteHarness({
  api,
}: {
  api: ReturnType<typeof createPhaseTwoApi>;
}): React.JSX.Element {
  const [platformRoute, setPlatformRoute] = useState(true);
  return (
    <SessionContext.Provider
      value={{
        api,
        clearSession: vi.fn(),
        membershipRevision: 0,
        refreshMemberships: vi.fn(),
        session: {
          ...sessionFixture,
          permissions: [
            "platform.operator_team.manage",
            "platform.operator_team.read",
          ],
        },
        updateSession: vi.fn(),
      }}
    >
      <PlatformOperatorTeamCoordinatorProvider>
        {platformRoute ? (
          <PlatformOperatorTeamsPage />
        ) : (
          <p>Alternate application route</p>
        )}
        <button
          type="button"
          onClick={() => setPlatformRoute((current) => !current)}
        >
          {platformRoute
            ? "Leave platform teams route"
            : "Return to platform teams"}
        </button>
      </PlatformOperatorTeamCoordinatorProvider>
    </SessionContext.Provider>
  );
}

function teamFixture(
  overrides: Partial<OperatorTeamView> = {},
): OperatorTeamView {
  return {
    activeAssignmentCount: 0,
    createdAt: "2026-08-24T08:00:00Z",
    description: "Primary triage queue",
    id: teamId,
    key: "soc_l1",
    name: "SOC L1",
    state: "active",
    updatedAt: "2026-08-24T08:00:00Z",
    version: 2,
    ...overrides,
  };
}

async function submitCreate(key: string, name: string): Promise<void> {
  fireEvent.click(
    await screen.findByRole("button", { name: "Create operator team" }),
  );
  fireEvent.change(screen.getByRole("textbox", { name: "Immutable key" }), {
    target: { value: key },
  });
  fireEvent.change(screen.getByRole("textbox", { name: "Team name" }), {
    target: { value: name },
  });
  fireEvent.click(screen.getByRole("button", { name: "Create operator team" }));
}

function dismissDialog(
  method: "cancel" | "close" | "escape" | "overlay" | "x",
): void {
  if (method === "cancel") {
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    return;
  }
  if (method === "escape") {
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    return;
  }
  if (method === "overlay") {
    const overlay = document.querySelector<HTMLElement>(
      '[data-slot="dialog-overlay"]',
    );
    expect(overlay).not.toBeNull();
    if (overlay) {
      fireEvent.pointerDown(overlay, {
        button: 0,
        ctrlKey: false,
        pointerType: "mouse",
      });
      fireEvent.click(overlay);
    }
    return;
  }
  const closeButtons = screen.getAllByRole("button", { name: "Close" });
  const button = method === "x" ? closeButtons[0] : closeButtons.at(-1);
  expect(button).toBeDefined();
  if (button) fireEvent.click(button);
}

interface Deferred<T> {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
}

function createDeferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, reject, resolve };
}
