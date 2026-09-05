import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CaseDfirWorkspace } from "./case-dfir-workspace";
import {
  compactDigest,
  safeDfirProblem,
  type DfirCaseData,
  type DfirPermission,
} from "./model";

const digest = "a".repeat(64);
const data: DfirCaseData = {
  iocs: [
    {
      id: "ioc-1",
      relatedRoots: [],
      type: "domain",
      value: "example.test",
      confidence: 85,
      tlp: "amber",
      malicious: "suspicious",
      tags: ["phishing"],
    },
  ],
  assets: [],
  evidence: [
    {
      id: "evidence-1",
      title: "Memory image",
      evidenceType: "memory_image",
      classification: "restricted",
      scanState: "available",
      sizeBytes: 2_048,
      sha256: digest,
      legalHold: true,
      custody: [
        {
          id: "custody-1",
          sequence: 1,
          action: "collected",
          occurredAt: "2026-08-25T10:00:00Z",
          actorLabel: "SOC analyst",
        },
        {
          id: "custody-2",
          sequence: 2,
          action: "sealed",
          occurredAt: "2026-08-25T10:05:00Z",
          actorLabel: "Evidence custodian",
        },
      ],
    },
  ],
  timeline: [],
  tasks: [],
  attachments: [],
  relationships: [],
};

afterEach(cleanup);

describe("CaseDfirWorkspace", () => {
  it("shows only projected related tickets with the matching route", () => {
    const caseId = "0198c97d-cf4f-7000-8000-000000000071";
    const alertId = "0198c97d-cf4f-7000-8000-000000000072";
    render(
      <CaseDfirWorkspace
        data={{
          ...data,
          iocs: data.iocs.map((ioc) => ({
            ...ioc,
            relatedRoots: [
              { kind: "case", id: caseId },
              { kind: "alert", id: alertId },
            ],
          })),
        }}
        hasPermission={() => true}
        onCreate={vi.fn()}
        onOpen={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByText("Linked tickets (2)"));
    expect(
      screen.getByRole("link", { name: `Case ${caseId}` }),
    ).toHaveAttribute("href", `/cases/${caseId}`);
    expect(
      screen.getByRole("link", { name: `Alert ${alertId}` }),
    ).toHaveAttribute("href", `/alerts/${alertId}`);
    expect(screen.getAllByRole("link")).toHaveLength(2);
  });

  it("treats permission visibility as advisory and sends scoped create intent", () => {
    const onCreate = vi.fn();
    const allowed = new Set<DfirPermission>(["dfir.ioc.manage"]);
    render(
      <CaseDfirWorkspace
        data={data}
        hasPermission={(permission) => allowed.has(permission)}
        onCreate={onCreate}
        onOpen={vi.fn()}
      />,
    );
    fireEvent.click(screen.getByRole("button", { name: "Add ioc" }));
    expect(onCreate).toHaveBeenCalledWith("iocs");
    fireEvent.click(screen.getByRole("tab", { name: /Assets/u }));
    expect(
      screen.queryByRole("button", { name: /Add assets/u }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByText("No systems or identities are linked to this Case yet."),
    ).toBeInTheDocument();
  });

  it("supports keyboard tab movement and renders custody as an ordered provenance rail", () => {
    const onOpen = vi.fn();
    render(
      <CaseDfirWorkspace
        data={data}
        hasPermission={() => false}
        initialPanel="assets"
        onCreate={vi.fn()}
        onOpen={onOpen}
      />,
    );
    const assets = screen.getByRole("tab", { name: /Assets/u });
    assets.focus();
    fireEvent.keyDown(assets, { key: "ArrowRight" });
    expect(screen.getByRole("tab", { name: /Evidence/u })).toHaveAttribute(
      "aria-selected",
      "true",
    );
    expect(
      screen.getByLabelText("Custody history for Memory image"),
    ).toHaveTextContent("collected");
    expect(
      screen.getByLabelText("Custody history for Memory image"),
    ).toHaveTextContent("sealed");
    expect(screen.getByText(compactDigest(digest))).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Open custody record" }),
    );
    expect(onOpen).toHaveBeenCalledWith("evidence", "evidence-1");
  });

  it("never renders untrusted backend problem detail", () => {
    render(
      <CaseDfirWorkspace
        data={data}
        problem={{ status: 409 }}
        hasPermission={() => false}
        onCreate={vi.fn()}
        onOpen={vi.fn()}
      />,
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      safeDfirProblem({ status: 409 }),
    );
    expect(screen.getByRole("alert")).not.toHaveTextContent("LDAP");
    expect(safeDfirProblem({ status: 500 })).not.toContain("detail");
  });
});
