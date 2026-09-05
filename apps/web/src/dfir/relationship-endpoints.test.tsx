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
import { alertDfirExtendedWorkspaceFixture } from "./alert-dfir-test-fixtures";
import { caseDfirApi, projectWorkspace } from "./case-dfir-api";
import { CaseDfirPanel } from "./case-dfir-panel";
import { dfirWorkspaceFixture } from "./case-dfir-test-fixtures";

afterEach(cleanup);

describe.each(["case", "alert"] as const)(
  "%s relationship endpoints",
  (kind) => {
    it("projects an IOC-to-asset relationship owned by the requested workspace", () => {
      const workspace =
        kind === "case"
          ? dfirWorkspaceFixture()
          : alertDfirExtendedWorkspaceFixture();
      const relation = workspace.relationships[0]!;
      relation.source = { kind: "ioc", id: workspace.indicators[0]!.id };
      relation.target = { kind: "asset", id: workspace.assets[0]!.id };
      const projected =
        "caseId" in workspace
          ? projectWorkspace(workspace, workspace.tenantId, workspace.caseId)
          : projectAlertWorkspace(
              workspace,
              workspace.tenantId,
              workspace.alertId,
            );
      expect(projected.workspace.relationships[0]).toMatchObject({
        source: relation.source,
        target: relation.target,
      });
    });

    it("submits independently selected IOC and asset endpoints with the path root", async () => {
      const workspace =
        kind === "case"
          ? dfirWorkspaceFixture()
          : alertDfirExtendedWorkspaceFixture();
      const caseWorkspace = dfirWorkspaceFixture();
      const caseSnapshot = projectWorkspace(
        caseWorkspace,
        caseWorkspace.tenantId,
        caseWorkspace.caseId,
      );
      const alertWorkspace = alertDfirExtendedWorkspaceFixture();
      const alertSnapshot = projectAlertWorkspace(
        alertWorkspace,
        alertWorkspace.tenantId,
        alertWorkspace.alertId,
      );
      const create = vi.fn(async () => undefined);
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false } },
      });
      render(
        <QueryClientProvider client={queryClient}>
          {"caseId" in workspace ? (
            <CaseDfirPanel
              api={{
                ...caseDfirApi,
                create,
                getWorkspace: async () => caseSnapshot,
              }}
              caseId={workspace.caseId}
              tenantId={workspace.tenantId}
              csrfToken="csrf-test"
              hasPermission={() => true}
            />
          ) : (
            <AlertDfirPanel
              api={{
                ...alertDfirApi,
                create,
                getWorkspace: async () => alertSnapshot,
              }}
              alertId={workspace.alertId}
              tenantId={workspace.tenantId}
              csrfToken="csrf-test"
              hasPermission={() => true}
            />
          )}
        </QueryClientProvider>,
      );
      fireEvent.click(await screen.findByRole("tab", { name: /Links/u }));
      fireEvent.click(screen.getByRole("button", { name: "Add links" }));
      fireEvent.change(screen.getByLabelText("Source type"), {
        target: { value: "ioc" },
      });
      fireEvent.change(screen.getByLabelText("Source ID"), {
        target: { value: workspace.indicators[0]!.id },
      });
      fireEvent.change(screen.getByLabelText("Target type"), {
        target: { value: "asset" },
      });
      fireEvent.change(screen.getByLabelText("Target ID"), {
        target: { value: workspace.assets[0]!.id },
      });
      fireEvent.change(screen.getByLabelText("Relationship"), {
        target: { value: "observed_on" },
      });
      fireEvent.click(
        screen.getByRole("button", { name: "Add to investigation" }),
      );
      await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
      expect(create).toHaveBeenCalledWith(
        expect.objectContaining({
          tenantId: workspace.tenantId,
          ...("caseId" in workspace
            ? { caseId: workspace.caseId }
            : { alertId: workspace.alertId }),
          operation: {
            panel: "relationships",
            body: expect.objectContaining({
              source: { kind: "ioc", id: workspace.indicators[0]!.id },
              target: { kind: "asset", id: workspace.assets[0]!.id },
              relationshipType: "observed_on",
            }),
          },
        }),
      );
    });
  },
);
