import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { alertDfirApi, projectAlertWorkspace } from "./alert-dfir-api";
import { AlertDfirPanel } from "./alert-dfir-panel";
import { alertDfirWorkspaceFixture } from "./alert-dfir-test-fixtures";
import { caseDfirApi, projectWorkspace } from "./case-dfir-api";
import { CaseDfirPanel } from "./case-dfir-panel";
import { dfirWorkspaceFixture } from "./case-dfir-test-fixtures";
import type { SharedLinkIntent } from "./shared-resource-links";

const tenantId = "0198c97d-cf4f-7000-8000-000000000001";
const rootId = "0198c97d-cf4f-7000-8000-000000000002";
const nextId = "0198c97d-cf4f-7000-8000-000000000003";
const resourceId = "0198c97d-cf4f-7000-8000-000000000004";
const allowPermission = () => true;

afterEach(cleanup);

describe.each(["case", "alert"] as const)(
  "%s shared resource navigation",
  (rootKind) => {
    it.each(["ticket", "tenant"] as const)(
      "resets the draft and caller identity when navigating to a cached %s",
      async (changedCoordinate) => {
        const nextTenantId = changedCoordinate === "tenant" ? nextId : tenantId;
        const nextRootId = changedCoordinate === "ticket" ? nextId : rootId;
        const queryClient = new QueryClient({
          defaultOptions: { queries: { retry: false, staleTime: Infinity } },
        });
        const getWorkspace = vi.fn(async () => {
          throw new Error("The destination workspace must already be cached");
        });
        const changeLink = vi.fn(
          async (
            _input: SharedLinkIntent & {
              tenantId: string;
              idempotencyKey: string;
              caseId?: string;
              alertId?: string;
            },
          ) => {
            throw new Error(
              "Keep the failed intent available for an exact retry",
            );
          },
        );
        const caseApi = { ...caseDfirApi, getWorkspace, changeLink };
        const alertApi = { ...alertDfirApi, getWorkspace, changeLink };

        for (const [cachedTenantId, cachedRootId] of [
          [tenantId, rootId],
          [nextTenantId, nextRootId],
        ] as const) {
          const emptyWorkspace = {
            tenantId: cachedTenantId,
            assets: [],
            attachments: [],
            evidence: [],
            indicators: [],
            relationships: [],
            sharedResources: [],
            tasks: [],
            timeline: [],
          };
          queryClient.setQueryData(
            [`${rootKind}-dfir`, cachedTenantId, cachedRootId],
            rootKind === "case"
              ? projectWorkspace(
                  dfirWorkspaceFixture({
                    ...emptyWorkspace,
                    caseId: cachedRootId,
                  }),
                  cachedTenantId,
                  cachedRootId,
                )
              : projectAlertWorkspace(
                  alertDfirWorkspaceFixture({
                    ...emptyWorkspace,
                    alertId: cachedRootId,
                  }),
                  cachedTenantId,
                  cachedRootId,
                ),
          );
        }

        const panel = (currentTenantId: string, currentRootId: string) => (
          <QueryClientProvider client={queryClient}>
            {rootKind === "case" ? (
              <CaseDfirPanel
                api={caseApi}
                caseId={currentRootId}
                csrfToken="csrf-test"
                hasPermission={allowPermission}
                tenantId={currentTenantId}
              />
            ) : (
              <AlertDfirPanel
                api={alertApi}
                alertId={currentRootId}
                csrfToken="csrf-test"
                hasPermission={allowPermission}
                tenantId={currentTenantId}
              />
            )}
          </QueryClientProvider>
        );
        const { rerender } = render(panel(tenantId, rootId));
        const submit = () => {
          fireEvent.change(screen.getByLabelText("Existing resource ID"), {
            target: { value: resourceId },
          });
          fireEvent.change(screen.getByLabelText("Current resource version"), {
            target: { value: "3" },
          });
          const form = screen
            .getByRole("button", { name: "Link resource" })
            .closest("form");
          if (!form) throw new Error("Missing shared resource form");
          fireEvent.submit(form);
        };
        submit();
        await waitFor(() => {
          expect(changeLink).toHaveBeenCalledTimes(1);
          expect(
            screen.getByRole("button", { name: "Link resource" }),
          ).toBeEnabled();
        });
        const firstIntent = changeLink.mock.calls[0]![0];
        submit();
        await waitFor(() => {
          expect(changeLink).toHaveBeenCalledTimes(2);
          expect(
            screen.getByRole("button", { name: "Link resource" }),
          ).toBeEnabled();
        });
        expect(changeLink.mock.calls[1]![0].eventId).toBe(firstIntent.eventId);

        rerender(panel(nextTenantId, nextRootId));
        expect(screen.getByLabelText("Existing resource ID")).toHaveValue("");
        expect(screen.getByLabelText("Current resource version")).toHaveValue(
          1,
        );
        submit();
        await waitFor(() => expect(changeLink).toHaveBeenCalledTimes(3));
        const nextIntent = changeLink.mock.calls[2]![0];
        expect(nextIntent).toMatchObject({
          tenantId: nextTenantId,
          [rootKind === "case" ? "caseId" : "alertId"]: nextRootId,
          resourceId,
          expectedVersion: 3,
        });
        expect(nextIntent.eventId).not.toBe(firstIntent.eventId);
        expect(nextIntent.idempotencyKey).toBe(nextIntent.eventId);
        expect(getWorkspace).not.toHaveBeenCalled();
      },
    );
  },
);
