import { cleanup, render, screen } from "@testing-library/react";
import { createMemoryRouter, RouterProvider } from "react-router";
import { afterEach, expect, it } from "vitest";
import { RouteErrorBoundary } from "./route-error-boundary";

afterEach(cleanup);

it("shows a recoverable page error without exposing loader diagnostics", async () => {
  const router = createMemoryRouter([
    {
      path: "/",
      loader: () => {
        throw new Error("Internal loader diagnostics");
      },
      ErrorBoundary: RouteErrorBoundary,
    },
  ]);
  render(<RouterProvider router={router} />);
  expect(
    await screen.findByRole("heading", {
      name: "This page could not be loaded",
    }),
  ).toBeVisible();
  expect(screen.getByRole("button", { name: "Reload page" })).toBeVisible();
  expect(screen.queryByText("Internal loader diagnostics")).toBeNull();
  router.dispose();
});
