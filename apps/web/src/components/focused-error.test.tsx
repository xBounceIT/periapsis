import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { FocusedError } from "./focused-error";

afterEach(cleanup);

describe("FocusedError", () => {
  it("preserves existing focus when autofocus is suppressed", () => {
    const view = render(<button type="button">Stable focus target</button>);
    const stableTarget = screen.getByRole("button", {
      name: "Stable focus target",
    });
    stableTarget.focus();

    view.rerender(
      <>
        <button type="button">Stable focus target</button>
        <FocusedError autoFocus={false} message="Reload failed." />
      </>,
    );
    expect(stableTarget).toHaveFocus();

    view.rerender(
      <>
        <button type="button">Stable focus target</button>
        <FocusedError autoFocus={false} message="Reload still failed." />
      </>,
    );
    expect(stableTarget).toHaveFocus();
  });

  it("focuses the alert by default", () => {
    render(<FocusedError message="Mutation failed." />);

    expect(screen.getByRole("alert")).toHaveFocus();
  });
});
