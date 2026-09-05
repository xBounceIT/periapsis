import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SafeMarkdown } from "./safe-markdown";

describe("SafeMarkdown", () => {
  it.each([
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "[unsafe](javascript:alert(1))",
    "[data](data:text/html,<script>alert(1)</script>)",
  ])("renders hostile input as inert text: %s", (markdown) => {
    const { container } = render(<SafeMarkdown markdown={markdown} />);

    expect(container.querySelector("img, script, iframe, object")).toBeNull();
    expect(container.querySelector("a")).toBeNull();
    expect(container.textContent).toContain(
      markdown.startsWith("[")
        ? markdown.slice(1, markdown.indexOf("]"))
        : markdown,
    );
  });

  it("allows only absolute HTTP links with safe link attributes", () => {
    render(
      <SafeMarkdown markdown="Read [runbook](https://example.invalid/runbook)." />,
    );

    const link = screen.getByRole("link", { name: "runbook" });
    expect(link).toHaveAttribute("href", "https://example.invalid/runbook");
    expect(link).toHaveAttribute("rel", "nofollow noopener noreferrer");
    expect(link).toHaveAttribute("target", "_blank");
  });
});
