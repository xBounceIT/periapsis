import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { formatTenantInstant } from "../lib/tenant-date-time";
import type * as TenantDateTime from "../lib/tenant-date-time-context";
import { TenantDateTimeProvider } from "../lib/tenant-date-time-context";
import { projectAlertWorkspace } from "./alert-dfir-api";
import { AlertDfirPanel } from "./alert-dfir-panel";
import {
  alertDfirAlertId,
  alertDfirExtendedWorkspaceFixture,
  alertDfirTenantId,
} from "./alert-dfir-test-fixtures";
import { projectWorkspace } from "./case-dfir-api";
import { CaseDfirPanel } from "./case-dfir-panel";
import {
  dfirCaseId,
  dfirTenantId,
  dfirWorkspaceFixture,
} from "./case-dfir-test-fixtures";
import { CaseDfirWorkspace } from "./case-dfir-workspace";
import { evidenceCustodyFixture } from "./evidence-custody-test-fixtures";

const instantRenders = vi.hoisted(() => ({ count: 0 }));

vi.mock("../lib/tenant-date-time-context", async (importOriginal) => {
  const actual = await importOriginal<typeof TenantDateTime>();
  return {
    ...actual,
    TenantInstant(props: ComponentProps<typeof actual.TenantInstant>) {
      instantRenders.count++;
      // Count entry into the timestamp subtree without replacing its real
      // parsing, Intl formatting, context subscription or rendered DOM.
      return <actual.TenantInstant {...props} />;
    },
  };
});

beforeEach(() => {
  instantRenders.count = 0;
});
afterEach(cleanup);

function caseSource(version = 999) {
  const source = dfirWorkspaceFixture();
  const evidence = source.evidence[0]!;
  evidence.version = version;
  evidence.custody = evidenceCustodyFixture(evidence.custody[0]!, version);
  return source;
}

async function unexpectedOperation(): Promise<never> {
  throw new Error("Unexpected unrelated DFIR operation");
}

const unrelatedOperations = {
  assignTask: unexpectedOperation,
  changeLink: unexpectedOperation,
  create: unexpectedOperation,
  prepareDownload: unexpectedOperation,
  prepareUpload: unexpectedOperation,
  replace: unexpectedOperation,
  replaceTaskChecklist: unexpectedOperation,
  replaceTaskComments: unexpectedOperation,
  replaceTaskDetails: unexpectedOperation,
  rescheduleTask: unexpectedOperation,
  retractRelationship: unexpectedOperation,
  transitionTask: unexpectedOperation,
  upload: unexpectedOperation,
};

describe("read-only custody history rendering", () => {
  it.each(["Case", "Alert"] as const)(
    "%s keeps all 999 real timestamps stable through dialog and mutation state",
    async (subject) => {
      const pending = Promise.withResolvers<void>();
      const appendCustody = vi.fn(async () => pending.promise);
      const queryClient = new QueryClient({
        defaultOptions: { queries: { retry: false } },
      });
      const source = caseSource();
      const alertSource = alertDfirExtendedWorkspaceFixture();
      const alertEvidence = alertSource.evidence[0]!;
      alertEvidence.version = 999;
      alertEvidence.custody = evidenceCustodyFixture(
        alertEvidence.custody[0]!,
        999,
      );
      const title =
        subject === "Case" ? source.evidence[0]!.title : alertEvidence.title;
      render(
        <QueryClientProvider client={queryClient}>
          {subject === "Case" ? (
            <CaseDfirPanel
              api={{
                ...unrelatedOperations,
                appendCustody,
                getWorkspace: async () =>
                  projectWorkspace(source, dfirTenantId, dfirCaseId),
              }}
              caseId={dfirCaseId}
              csrfToken="csrf-test"
              hasPermission={() => true}
              tenantId={dfirTenantId}
            />
          ) : (
            <AlertDfirPanel
              alertId={alertDfirAlertId}
              api={{
                ...unrelatedOperations,
                appendCustody,
                getWorkspace: async () =>
                  projectAlertWorkspace(
                    alertSource,
                    alertDfirTenantId,
                    alertDfirAlertId,
                  ),
              }}
              csrfToken="csrf-test"
              hasPermission={() => true}
              tenantId={alertDfirTenantId}
            />
          )}
        </QueryClientProvider>,
      );
      fireEvent.click(await screen.findByRole("tab", { name: /Evidence/u }));
      const history = screen.getByLabelText(`Custody history for ${title}`);
      expect(history.children).toHaveLength(999);
      expect(history.querySelectorAll("time")).toHaveLength(999);
      const counts = {
        mounted: instantRenders.count,
        opened: 0,
        busy: 0,
        closed: 0,
      };
      fireEvent.click(
        screen.getByRole("button", { name: "Open custody record" }),
      );
      const dialog = screen.getByRole("dialog");
      counts.opened = instantRenders.count;
      fireEvent.change(within(dialog).getByLabelText("Reason"), {
        target: { value: "Final custody event" },
      });
      const append = within(dialog).getByRole("button", {
        name: "Append custody event",
      });
      fireEvent.click(append);
      await waitFor(() => expect(appendCustody).toHaveBeenCalledTimes(1));
      expect(append).toBeDisabled();
      expect(appendCustody).toHaveBeenCalledWith(
        expect.objectContaining({
          body: expect.objectContaining({
            expectedVersion: 999,
            reason: "Final custody event",
          }),
        }),
      );
      counts.busy = instantRenders.count;
      await act(async () => pending.resolve());
      await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
      counts.closed = instantRenders.count;
      expect(screen.getByLabelText(`Custody history for ${title}`)).toBe(
        history,
      );
      expect(history.children).toHaveLength(999);
      expect(history.querySelectorAll("time")).toHaveLength(999);
      expect(counts).toEqual({
        mounted: 999,
        opened: 999,
        busy: 999,
        closed: 999,
      });
    },
  );

  it("keeps fresh authority callbacks live without rerendering unchanged history", () => {
    const data = projectWorkspace(caseSource(), dfirTenantId, dfirCaseId).data;
    const firstOpen = vi.fn();
    const latestOpen = vi.fn();
    const latestCreate = vi.fn();
    const view = render(
      <CaseDfirWorkspace
        data={data}
        initialPanel="evidence"
        hasPermission={() => true}
        onCreate={vi.fn()}
        onOpen={firstOpen}
      />,
    );
    const history = screen.getByLabelText(
      `Custody history for ${data.evidence[0]!.title}`,
    );
    view.rerender(
      <CaseDfirWorkspace
        data={data}
        busy
        initialPanel="evidence"
        hasPermission={() => false}
        onCreate={latestCreate}
        onOpen={latestOpen}
      />,
    );
    expect(screen.queryByRole("button", { name: "Add evidence" })).toBeNull();
    fireEvent.click(
      screen.getByRole("button", { name: "Open custody record" }),
    );
    expect(firstOpen).not.toHaveBeenCalled();
    expect(latestOpen).toHaveBeenCalledExactlyOnceWith(
      "evidence",
      data.evidence[0]!.id,
    );
    view.rerender(
      <CaseDfirWorkspace
        data={data}
        initialPanel="evidence"
        hasPermission={() => true}
        onCreate={latestCreate}
        onOpen={latestOpen}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Add evidence" }));
    expect(latestCreate).toHaveBeenCalledExactlyOnceWith("evidence");
    expect(history.children).toHaveLength(999);
    expect(instantRenders.count).toBe(999);
  });

  it("updates the title, changed events and complete 1000-event successor", () => {
    const source = caseSource();
    const initial = projectWorkspace(source, dfirTenantId, dfirCaseId).data;
    const props = {
      initialPanel: "evidence",
      hasPermission: () => true,
      onCreate: vi.fn(),
      onOpen: vi.fn(),
    } as const;
    const view = render(<CaseDfirWorkspace {...props} data={initial} />);
    const title = "Renamed authorized evidence";
    view.rerender(
      <CaseDfirWorkspace
        {...props}
        data={{ ...initial, evidence: [{ ...initial.evidence[0]!, title }] }}
      />,
    );
    expect(
      screen.queryByLabelText(
        `Custody history for ${initial.evidence[0]!.title}`,
      ),
    ).toBeNull();
    expect(
      screen.getByLabelText(`Custody history for ${title}`).children,
    ).toHaveLength(999);
    const successor = caseSource(1_000);
    successor.evidence[0]!.title = title;
    const updated = projectWorkspace(successor, dfirTenantId, dfirCaseId).data;
    const replaced = {
      ...updated,
      evidence: [
        {
          ...updated.evidence[0]!,
          custody: updated.evidence[0]!.custody.map((event, index) =>
            index === 998
              ? {
                  ...event,
                  action: "transferred",
                  actorLabel: "Authorized custodian",
                  occurredAt: "2026-09-06T09:30:00Z",
                }
              : event,
          ),
        },
      ],
    };
    view.rerender(<CaseDfirWorkspace {...props} data={replaced} />);
    const history = screen.getByLabelText(`Custody history for ${title}`);
    expect(history.children).toHaveLength(1_000);
    expect(history.querySelectorAll("time")).toHaveLength(1_000);
    expect(
      Array.from(history.children, (row) => row.firstElementChild?.textContent),
    ).toEqual(Array.from({ length: 1_000 }, (_, index) => String(index + 1)));
    expect(history.children[998]).toHaveTextContent("transferred");
    expect(history.children[998]).toHaveTextContent("Authorized custodian");
    expect(history.children[998]!.querySelector("time")).toHaveAttribute(
      "datetime",
      "2026-09-06T09:30:00Z",
    );
  });

  it("updates real locale and timezone timestamps through the unchanged memoized history", () => {
    const data = projectWorkspace(caseSource(), dfirTenantId, dfirCaseId).data;
    const props = {
      data,
      initialPanel: "evidence",
      hasPermission: () => true,
      onCreate: vi.fn(),
      onOpen: vi.fn(),
    } as const;
    const view = render(
      <TenantDateTimeProvider locale="en-GB" timeZone="UTC">
        <CaseDfirWorkspace {...props} />
      </TenantDateTimeProvider>,
    );
    const history = screen.getByLabelText(
      `Custody history for ${data.evidence[0]!.title}`,
    );
    const before = history.querySelector("time")!.textContent;
    view.rerender(
      <TenantDateTimeProvider locale="it-IT" timeZone="Europe/Rome">
        <CaseDfirWorkspace {...props} />
      </TenantDateTimeProvider>,
    );
    expect(history.children).toHaveLength(999);
    expect(history.querySelectorAll("time")).toHaveLength(999);
    for (const time of history.querySelectorAll("time")) {
      expect(time).toHaveAttribute("title", "Displayed in Europe/Rome");
    }
    expect(history.querySelector("time")).not.toHaveTextContent(before);
    expect(history.querySelector("time")).toHaveTextContent(
      formatTenantInstant(data.evidence[0]!.custody[0]!.occurredAt, {
        locale: "it-IT",
        timeZone: "Europe/Rome",
      }),
    );
  });
});
