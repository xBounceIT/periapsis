import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ContactAdministrationWorkspace } from "./contact-administration-page";
import {
  contactTenantId,
  createContactPortalApi,
  customerContactFixture,
} from "./contact-test-fixtures";

afterEach(cleanup);

describe("ContactAdministrationWorkspace", () => {
  it("loads opaque cursor pages without dropping the current filters", async () => {
    const secondContact = {
      ...customerContactFixture,
      email: "secondary@example.invalid",
      firstName: "Secondary",
      id: "01991c20-7d5f-7000-8000-000000000008",
    };
    const listContacts = vi.fn(
      async (input: { after?: string; active?: boolean }) =>
        input.after === "contact-cursor-1"
          ? { items: [secondContact] }
          : { items: [customerContactFixture], nextCursor: "contact-cursor-1" },
    );

    renderWorkspace(createContactPortalApi({ listContacts }));

    expect(await screen.findByText("Ari Customer")).toBeVisible();
    fireEvent.click(screen.getByRole("button", { name: "Load more contacts" }));
    expect(await screen.findByText("Secondary Customer")).toBeVisible();
    expect(listContacts).toHaveBeenLastCalledWith(
      expect.objectContaining({ active: true, after: "contact-cursor-1" }),
    );
  });

  it("keeps all mutation controls absent for a read-only operator", async () => {
    renderWorkspace(createContactPortalApi(), false);

    expect(await screen.findByText("Ari Customer")).toBeVisible();
    expect(screen.queryByRole("button", { name: "New contact" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Edit" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Archive" })).toBeNull();
  });

  it("reuses the archive retry key after an ambiguous failure", async () => {
    const archiveContact = vi
      .fn(async (_input: { idempotencyKey: string }) => ({
        etag: '"v2"',
        value: {
          ...customerContactFixture,
          active: false,
          archivedAt: "2026-08-25T10:00:00Z",
          updatedAt: "2026-08-25T10:00:00Z",
          version: 2,
        },
      }))
      .mockRejectedValueOnce(new TypeError("network response was lost"));
    renderWorkspace(createContactPortalApi({ archiveContact }));

    fireEvent.click(await screen.findByRole("button", { name: "Archive" }));
    await waitFor(() => expect(archiveContact).toHaveBeenCalledTimes(1));
    fireEvent.click(screen.getByRole("button", { name: "Archive" }));
    await waitFor(() => expect(archiveContact).toHaveBeenCalledTimes(2));

    expect(archiveContact.mock.calls[0]?.[0].idempotencyKey).toBe(
      archiveContact.mock.calls[1]?.[0].idempotencyKey,
    );
  });
});

function renderWorkspace(
  api: ReturnType<typeof createContactPortalApi>,
  canManageContacts = true,
): void {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <ContactAdministrationWorkspace
        api={api}
        canManageContacts={canManageContacts}
        canManageGroups={false}
        canReadContacts
        canReadGroups={false}
        csrfToken="csrf-memory-only"
        tenantId={contactTenantId}
      />
    </QueryClientProvider>,
  );
}
