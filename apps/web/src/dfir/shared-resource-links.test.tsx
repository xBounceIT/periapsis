import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SharedResourceLinks } from "./shared-resource-links";

const resourceId = "0198c97d-cf4f-7000-8000-000000000198";
afterEach(cleanup);

describe("shared resource link controls", () => {
  it("keeps caller identity stable on retry and changes it when the intent changes", () => {
    const onSubmit = vi.fn();
    render(
      <SharedResourceLinks
        assets={[]}
        indicators={[]}
        busy={false}
        canManageAssets={false}
        canManageIndicators
        onSubmit={onSubmit}
      />,
    );
    fireEvent.change(screen.getByLabelText("Existing resource ID"), {
      target: { value: resourceId },
    });
    fireEvent.change(screen.getByLabelText("Current resource version"), {
      target: { value: "3000000000" },
    });
    const form = screen
      .getByRole("button", { name: "Link resource" })
      .closest("form");
    if (!form) throw new Error("Missing shared resource form");
    fireEvent.submit(form);
    fireEvent.submit(form);
    expect(onSubmit).toHaveBeenCalledTimes(2);
    expect(onSubmit.mock.calls[0]?.[0]).toEqual(onSubmit.mock.calls[1]?.[0]);
    expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({
      resourceId,
      resourceKind: "ioc",
      expectedVersion: 3_000_000_000,
      linked: true,
    });
    fireEvent.change(screen.getByLabelText("Current resource version"), {
      target: { value: "3000000001" },
    });
    fireEvent.submit(form);
    expect(onSubmit.mock.calls[2]?.[0].eventId).not.toBe(
      onSubmit.mock.calls[0]?.[0].eventId,
    );
  });

  it("takes unlink CAS from the current inventory and requires confirmation", () => {
    const onSubmit = vi.fn();
    render(
      <SharedResourceLinks
        assets={[{ id: resourceId, version: 8 }]}
        indicators={[]}
        busy={false}
        canManageAssets
        canManageIndicators={false}
        onSubmit={onSubmit}
      />,
    );
    fireEvent.change(screen.getByLabelText("Link action"), {
      target: { value: "unlink" },
    });
    fireEvent.change(screen.getByLabelText("Linked resource"), {
      target: { value: resourceId },
    });
    expect(
      screen.getByLabelText("Remove this resource from this ticket"),
    ).toBeRequired();
    fireEvent.click(
      screen.getByLabelText("Remove this resource from this ticket"),
    );
    const form = screen
      .getByRole("button", { name: "Confirm unlink" })
      .closest("form");
    if (!form) throw new Error("Missing shared resource form");
    fireEvent.submit(form);
    expect(onSubmit.mock.calls[0]?.[0]).toMatchObject({
      resourceId,
      resourceKind: "asset",
      expectedVersion: 8,
      linked: false,
    });
  });

  it("hides every mutation when neither manage capability is present", () => {
    render(
      <SharedResourceLinks
        assets={[]}
        indicators={[]}
        busy={false}
        canManageAssets={false}
        canManageIndicators={false}
        onSubmit={vi.fn()}
      />,
    );
    expect(screen.queryByText("Shared resource links")).not.toBeInTheDocument();
  });
});
