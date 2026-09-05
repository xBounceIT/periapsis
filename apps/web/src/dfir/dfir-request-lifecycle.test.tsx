import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  alertDfirApi,
  projectAlertWorkspace,
  type AlertDfirApi,
} from "./alert-dfir-api";
import { AlertDfirPanel } from "./alert-dfir-panel";
import { alertDfirWorkspaceFixture } from "./alert-dfir-test-fixtures";
import {
  caseDfirApi,
  projectWorkspace,
  type CaseDfirApi,
} from "./case-dfir-api";
import { CaseDfirPanel } from "./case-dfir-panel";
import { dfirWorkspaceFixture } from "./case-dfir-test-fixtures";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const firstRootId = "0198c97d-cf4f-7000-8000-000000000002";
const nextRootId = "0198c97d-cf4f-7000-8000-000000000003";
const resourceId = "0198c97d-cf4f-7000-8000-000000000004";
const empty = {
  tenantId,
  assets: [],
  attachments: [],
  evidence: [],
  indicators: [],
  relationships: [],
  sharedResources: [],
  tasks: [],
  timeline: [],
};

afterEach(cleanup);

describe.each(["case", "alert"] as const)("%s request ownership", (kind) => {
  it.each(
    (["mutation", "download"] as const).flatMap((action) =>
      (["resolve", "abort", "reject"] as const).flatMap((settlement) =>
        (
          [
            "navigation",
            "read-revocation",
            "manage-revocation",
            "unrelated-revocation",
          ] as const
        )
          .filter((trigger) =>
            action === "mutation"
              ? trigger !== "unrelated-revocation"
              : trigger !== "manage-revocation",
          )
          .map((trigger) => ({ action, settlement, trigger })),
      ),
    ),
  )(
    "ignores a superseded $action request after $trigger that later $settlement settles",
    async ({ action, settlement, trigger }) => {
      const oldRequest = Promise.withResolvers<void>();
      const currentRequest = Promise.withResolvers<void>();
      const changeLink = vi
        .fn<(input: { signal?: AbortSignal }) => Promise<void>>()
        .mockImplementationOnce(() =>
          action === "mutation" ? oldRequest.promise : currentRequest.promise,
        )
        .mockImplementationOnce(() => currentRequest.promise);
      const attachment = {
        ...dfirWorkspaceFixture().attachments[0]!,
        subject: { kind, id: firstRootId },
      };
      const prepareDownload = vi.fn(
        async (_input: { signal?: AbortSignal }) => {
          await oldRequest.promise;
          return {
            attachment,
            downloadUrl: "https://storage.invalid/private?signature=opaque",
            expiresAt: "2099-08-30T10:00:00Z",
          };
        },
      );
      const getCaseWorkspace: CaseDfirApi["getWorkspace"] = async ({
        caseId,
      }) =>
        projectWorkspace(
          dfirWorkspaceFixture({
            ...empty,
            caseId,
            attachments: caseId === firstRootId ? [attachment] : [],
          }),
          tenantId,
          caseId,
        );
      const getAlertWorkspace: AlertDfirApi["getWorkspace"] = async ({
        alertId,
      }) =>
        projectAlertWorkspace(
          alertDfirWorkspaceFixture({
            ...empty,
            alertId,
            attachments: alertId === firstRootId ? [attachment] : [],
          }),
          tenantId,
          alertId,
        );
      const caseApi = {
        ...caseDfirApi,
        changeLink,
        prepareDownload,
        getWorkspace: getCaseWorkspace,
      };
      const alertApi = {
        ...alertDfirApi,
        changeLink,
        prepareDownload,
        getWorkspace: getAlertWorkspace,
      };
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false } },
      });
      const panel = (id: string, deniedPermission?: string) => (
        <QueryClientProvider client={queryClient}>
          {kind === "case" ? (
            <CaseDfirPanel
              api={caseApi}
              caseId={id}
              tenantId={tenantId}
              csrfToken="csrf-test"
              hasPermission={(permission) => permission !== deniedPermission}
            />
          ) : (
            <AlertDfirPanel
              api={alertApi}
              alertId={id}
              tenantId={tenantId}
              csrfToken="csrf-test"
              hasPermission={(permission) => permission !== deniedPermission}
            />
          )}
        </QueryClientProvider>
      );
      const { rerender } = render(panel(firstRootId));
      const submit = async () => {
        await waitFor(() =>
          expect(
            screen.getByRole("button", { name: "Link resource" }),
          ).toBeEnabled(),
        );
        fireEvent.change(screen.getByLabelText("Existing resource ID"), {
          target: { value: resourceId },
        });
        const form = screen
          .getByRole("button", { name: "Link resource" })
          .closest("form");
        if (!form) throw new Error("Missing shared resource form");
        fireEvent.submit(form);
      };
      if (action === "mutation") {
        await submit();
        expect(changeLink).toHaveBeenCalledTimes(1);
      } else {
        fireEvent.click(await screen.findByRole("tab", { name: /Files/u }));
        fireEvent.click(screen.getByRole("button", { name: /memory\.raw/u }));
        fireEvent.click(
          screen.getByRole("button", { name: "Prepare secure download" }),
        );
        expect(prepareDownload).toHaveBeenCalledTimes(1);
      }
      const oldSignal =
        action === "mutation"
          ? changeLink.mock.calls[0]![0].signal
          : prepareDownload.mock.calls[0]![0].signal;
      if (trigger === "unrelated-revocation") {
        rerender(panel(firstRootId, "dfir.attachment.manage"));
        expect(oldSignal?.aborted).toBe(false);
      } else if (trigger !== "navigation") {
        rerender(
          panel(
            firstRootId,
            trigger === "read-revocation"
              ? "dfir.attachment.read"
              : "dfir.ioc.manage",
          ),
        );
        expect(oldSignal?.aborted).toBe(true);
        if (trigger === "read-revocation") {
          expect(
            queryClient.getQueryData([`${kind}-dfir`, tenantId, firstRootId]),
          ).toBeUndefined();
        }
      }
      rerender(panel(nextRootId));
      await submit();
      expect(oldSignal?.aborted).toBe(true);
      expect(changeLink).toHaveBeenCalledTimes(action === "mutation" ? 2 : 1);
      expect(
        screen.getByRole("button", { name: "Link resource" }),
      ).toBeDisabled();
      await act(async () => {
        if (settlement === "resolve") oldRequest.resolve();
        else
          oldRequest.reject(
            settlement === "abort"
              ? new DOMException("aborted", "AbortError")
              : new Error("previous request failed"),
          );
      });
      expect(
        screen.getByRole("button", { name: "Link resource" }),
      ).toBeDisabled();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(
        screen.queryByRole("link", { name: "Download authorized file" }),
      ).not.toBeInTheDocument();
      await act(async () => {
        currentRequest.resolve();
      });
      await waitFor(() =>
        expect(
          screen.getByRole("button", { name: "Link resource" }),
        ).toBeEnabled(),
      );
    },
  );
});
