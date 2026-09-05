import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  DfirResourceForm,
  formInstant,
  instantInputValue,
  taskSpecFromDraft,
} from "./resource-form";

afterEach(cleanup);

describe("DfirResourceForm", () => {
  it("keeps Case task creation intent-only", () => {
    const spec = taskSpecFromDraft(
      {
        panel: "tasks",
        title: "Contain the endpoint",
        description: "",
        priority: "high",
        operatorTeamId: "",
        assigneeId: "",
        dueAt: "",
        checklist: "Isolate host",
        slaInstanceId: "",
      },
      ["018f0000-0000-7000-8000-000000000001"],
    );

    expect(spec).not.toHaveProperty("status");
    expect(spec.checklist).toEqual([
      {
        id: "018f0000-0000-7000-8000-000000000001",
        title: "Isolate host",
        completed: false,
      },
    ]);
  });

  it("round-trips microsecond instants through the local form value", () => {
    const instant = "2026-08-30T09:15:12.123456Z";

    expect(formInstant(instantInputValue(instant))).toBe(instant);
  });

  it("normalizes a valid IOC draft before handing it to the caller", async () => {
    const onSubmit = vi.fn();
    render(
      <DfirResourceForm
        panel="iocs"
        subjectKind="case"
        onCancel={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    fireEvent.change(screen.getByLabelText("Observable value"), {
      target: { value: "example.test" },
    });
    fireEvent.change(screen.getByLabelText("Source"), {
      target: { value: "Threat intelligence" },
    });
    fireEvent.change(screen.getByLabelText("Confidence"), {
      target: { value: "87" },
    });
    fireEvent.change(screen.getByLabelText("Description"), {
      target: { value: "  Command channel  " },
    });
    fireEvent.change(screen.getByLabelText("First seen"), {
      target: { value: "2026-08-30T09:00" },
    });
    fireEvent.change(screen.getByLabelText("Last seen"), {
      target: { value: "2026-08-30T10:00" },
    });
    fireEvent.change(screen.getByLabelText("Tags, comma separated"), {
      target: { value: "c2, phishing" },
    });
    fireEvent.change(screen.getByLabelText("Enrichment (JSON object)"), {
      target: { value: '{"provider":"sandbox","score":98}' },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({
          panel: "iocs",
          type: "domain",
          value: "example.test",
          source: "Threat intelligence",
          confidence: 87,
          description: "Command channel",
          enrichment: { provider: "sandbox", score: 98 },
          firstSeen: "2026-08-30T09:00",
          lastSeen: "2026-08-30T10:00",
          tags: "c2, phishing",
        }),
      ),
    );
  });

  it("rejects an upload beyond the tenant limit before invoking its caller", async () => {
    const onSubmit = vi.fn();
    render(
      <DfirResourceForm
        panel="attachments"
        subjectKind="case"
        maximumUploadBytes={4}
        onCancel={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    const file = new File(["five!"], "evidence.bin", {
      type: "application/octet-stream",
    });
    fireEvent.change(screen.getByLabelText("File"), {
      target: { files: [file] },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Prepare secure upload" }),
    );

    expect(
      await screen.findByText(
        "The selected file exceeds this tenant's upload limit.",
      ),
    ).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("rejects a relationship from a resource to itself", async () => {
    const onSubmit = vi.fn();
    const resourceID = "0198c97d-cf4f-7000-8000-000000000010";
    render(
      <DfirResourceForm
        panel="relationships"
        subjectKind="case"
        onCancel={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    fireEvent.change(screen.getByLabelText("Source ID"), {
      target: { value: resourceID },
    });
    fireEvent.change(screen.getByLabelText("Target type"), {
      target: { value: "case" },
    });
    fireEvent.change(screen.getByLabelText("Target ID"), {
      target: { value: resourceID },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );

    expect(
      await screen.findByText("A resource cannot relate to itself."),
    ).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("renders and normalizes an external relationship target", async () => {
    const onSubmit = vi.fn();
    render(
      <DfirResourceForm
        panel="relationships"
        subjectKind="case"
        onCancel={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    fireEvent.change(screen.getByLabelText("Source ID"), {
      target: { value: "0198c97d-cf4f-7000-8000-000000000010" },
    });
    fireEvent.change(screen.getByLabelText("Target type"), {
      target: { value: "external" },
    });
    expect(screen.queryByLabelText("Target ID")).toBeNull();
    fireEvent.change(screen.getByLabelText("Target external type"), {
      target: { value: "misp_event" },
    });
    fireEvent.change(screen.getByLabelText("Target external ID"), {
      target: { value: "  event--784  " },
    });
    fireEvent.change(
      screen.getByLabelText("Relationship metadata (JSON object)"),
      { target: { value: '{"confidence":"high"}' } },
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith({
        metadata: { confidence: "high" },
        panel: "relationships",
        relationshipType: "related_to",
        sourceId: "0198c97d-cf4f-7000-8000-000000000010",
        sourceKind: "case",
        targetExternalId: "event--784",
        targetExternalType: "misp_event",
        targetKind: "external",
      }),
    );
  });

  it("offers evidence links for an Alert timeline", () => {
    render(
      <DfirResourceForm
        panel="timeline"
        subjectKind="alert"
        onCancel={vi.fn()}
        onSubmit={vi.fn()}
      />,
    );

    expect(screen.getByLabelText("Linked IOC UUIDv7 values")).toBeVisible();
    expect(screen.getByLabelText("Linked asset UUIDv7 values")).toBeVisible();
    expect(
      screen.getByLabelText("Linked evidence UUIDv7 values"),
    ).toBeVisible();
  });

  it("rejects a document whose encoded payload exceeds the contract limit", async () => {
    const onSubmit = vi.fn();
    render(
      <DfirResourceForm
        panel="iocs"
        subjectKind="case"
        onCancel={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    fireEvent.change(screen.getByLabelText("Observable value"), {
      target: { value: "oversized.example" },
    });
    fireEvent.change(screen.getByLabelText("Source"), {
      target: { value: "Threat intelligence" },
    });
    fireEvent.change(screen.getByLabelText("Enrichment (JSON object)"), {
      target: { value: JSON.stringify({ value: "€".repeat(22_000) }) },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );

    expect(
      await screen.findByText(
        "Use a JSON object within the 64 KiB document limit.",
      ),
    ).toBeVisible();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("rejects evidence retention that ends before collection", async () => {
    const onSubmit = vi.fn();
    render(
      <DfirResourceForm
        panel="evidence"
        subjectKind="case"
        onCancel={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    fireEvent.change(screen.getByLabelText("Evidence title"), {
      target: { value: "Memory image" },
    });
    fireEvent.change(screen.getByLabelText("Evidence type"), {
      target: { value: "memory_image" },
    });
    fireEvent.change(screen.getByLabelText("Collection source"), {
      target: { value: "EDR" },
    });
    fireEvent.change(screen.getByLabelText("Collected at"), {
      target: { value: "2026-08-30T10:00" },
    });
    fireEvent.change(screen.getByLabelText("Retain until"), {
      target: { value: "2026-08-29T10:00" },
    });
    fireEvent.change(screen.getByLabelText("File"), {
      target: { files: [new File(["bytes"], "memory.raw")] },
    });
    fireEvent.click(
      screen.getByRole("button", { name: "Begin evidence collection" }),
    );

    expect(
      await screen.findByText(
        "Retention cannot end before evidence collection.",
      ),
    ).toBeVisible();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("uses the canonical urgent task priority instead of ticket-only critical", async () => {
    const onSubmit = vi.fn();
    render(
      <DfirResourceForm
        panel="tasks"
        subjectKind="case"
        onCancel={vi.fn()}
        onSubmit={onSubmit}
      />,
    );

    fireEvent.change(screen.getByLabelText("Task title"), {
      target: { value: "Contain the affected endpoint" },
    });
    const priority = screen.getByLabelText("Priority");
    if (!(priority instanceof HTMLSelectElement))
      throw new Error("Priority control must be a select");
    fireEvent.change(priority, {
      target: { value: "urgent" },
    });
    expect(Array.from(priority.options, (option) => option.value)).toEqual([
      "low",
      "medium",
      "high",
      "urgent",
    ]);
    fireEvent.click(
      screen.getByRole("button", { name: "Add to investigation" }),
    );

    await waitFor(() =>
      expect(onSubmit).toHaveBeenCalledWith(
        expect.objectContaining({ panel: "tasks", priority: "urgent" }),
      ),
    );
  });
});
