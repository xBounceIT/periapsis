import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { SessionContext } from "../auth/session-context";
import {
  TenantAuthorityProvider,
  useTenantAuthority,
} from "../auth/tenant-authority-context";
import type {
  TenantAuthorityView,
  TenantPermissionKeyView,
} from "../lib/phase-two-types";
import type { TicketComment, TicketingApi } from "../lib/ticketing-api";
import { createPhaseTwoApi, sessionFixture } from "../test/phase-two-fixtures";
import { TicketCommentPanel } from "./ticket-comment-panel";
import { TicketingApiProvider } from "./ticketing-context";
import {
  alertId,
  caseId,
  createTicketingApi,
  membershipId,
  tenantId,
} from "./ticketing-test-fixtures";

afterEach(cleanup);

const permissions: TenantPermissionKeyView[] = [
  "alert.read",
  "alert.comment.read",
  "alert.comment.public",
  "alert.comment.private",
];
const candidates = Array.from({ length: 51 }, (_, index) => ({
  audience: "operator" as const,
  displayName: `Candidate ${String(index).padStart(2, "0")}`,
  membershipId: `0198c97d-cf4f-7000-8001-${index.toString(16).padStart(12, "0")}`,
}));
const comment: Extract<TicketComment, { projection: "operator" }> = {
  projection: "operator",
  id: "0198c97d-cf4f-7000-8000-000000000096",
  tenantId,
  resourceKind: "alert",
  resourceId: alertId,
  visibility: "public",
  bodyMarkdown: "Original author text",
  author: { audience: "operator", displayName: "SOC analyst", membershipId },
  attachments: [],
  canEdit: true,
  editableUntil: "2099-08-30T09:15:00Z",
  mentions: [],
  origin: "api",
  revision: 1,
  createdAt: "2026-08-30T09:00:00Z",
  updatedAt: "2026-08-30T09:00:00Z",
};

describe("mounted comment mention selection", () => {
  it.each(["create", "edit"] as const)(
    "%s preserves the 50-member boundary, re-enables deselected capacity and sends the exact replacement set",
    async (mode) => {
      const { createComment, editComment, listCommentMentionCandidates } =
        renderPanel();
      const form = await composer(mode);
      fireEvent.change(within(form).getByLabelText("Comment"), {
        target: { value: "Current draft" },
      });
      const picker = within(form).getByRole("group", {
        name: "Mention ticket operators",
      });
      const checkboxes = within(picker).getAllByRole("checkbox");
      expect(checkboxes).toHaveLength(51);
      for (const checkbox of checkboxes.slice(0, 50)) fireEvent.click(checkbox);

      expect(
        within(picker).getAllByRole("checkbox", { checked: true }),
      ).toHaveLength(50);
      expect(checkboxes[50]).toBeDisabled();
      expect(within(picker).getByRole("status")).toHaveTextContent(
        "The maximum of 50 operator mentions is selected.",
      );
      fireEvent.click(checkboxes[50]!);
      expect(checkboxes[50]).not.toBeChecked();

      fireEvent.click(checkboxes[0]!);
      expect(checkboxes[0]).not.toBeChecked();
      expect(checkboxes[50]).toBeEnabled();
      expect(within(picker).queryByRole("status")).toBeNull();
      fireEvent.change(within(form).getByLabelText("Comment"), {
        target: { value: "Latest draft" },
      });
      fireEvent.change(within(form).getByLabelText("Attachment IDs"), {
        target: { value: caseId },
      });
      fireEvent.click(checkboxes[50]!);
      expect(checkboxes[0]).toBeDisabled();
      expect(checkboxes[50]).toBeChecked();
      if (mode === "edit")
        fireEvent.change(within(form).getByLabelText("Reason for edit"), {
          target: { value: "Correct the operator set" },
        });
      fireEvent.click(
        within(form).getByRole("button", {
          name: mode === "create" ? "Post comment" : "Save revision",
        }),
      );

      const mutation = mode === "create" ? createComment : editComment;
      await waitFor(() => expect(mutation).toHaveBeenCalledTimes(1));
      expect(mutation.mock.calls[0]?.[0].body).toEqual({
        attachmentIds: [caseId],
        bodyMarkdown: "Latest draft",
        mentionedMembershipIds: candidates
          .slice(1)
          .map((candidate) => candidate.membershipId)
          .toSorted(),
        ...(mode === "create"
          ? { visibility: "public" }
          : { reason: "Correct the operator set" }),
      });
      expect(listCommentMentionCandidates).toHaveBeenCalledTimes(1);
    },
  );

  it("uses the fresh create draft after a successful post without restoring old mentions or fields", async () => {
    const { createComment } = renderPanel();
    let form = await composer("create");
    fireEvent.change(within(form).getByLabelText("Comment"), {
      target: { value: "First draft" },
    });
    fireEvent.click(
      within(form).getByRole("checkbox", { name: "Candidate 00" }),
    );
    fireEvent.click(within(form).getByRole("button", { name: "Post comment" }));
    await waitFor(() =>
      expect(within(form).getByLabelText("Comment")).toHaveValue(""),
    );
    form = await composer("create");
    expect(
      within(form).getByRole("checkbox", { name: "Candidate 00" }),
    ).not.toBeChecked();
    fireEvent.change(within(form).getByLabelText("Comment"), {
      target: { value: "Fresh private draft" },
    });
    fireEvent.change(within(form).getByLabelText("Attachment IDs"), {
      target: { value: caseId },
    });
    fireEvent.click(
      within(form).getByRole("checkbox", { name: "Private operator note" }),
    );
    fireEvent.click(
      within(form).getByRole("checkbox", { name: "Candidate 01" }),
    );
    fireEvent.click(within(form).getByRole("button", { name: "Post comment" }));
    await waitFor(() => expect(createComment).toHaveBeenCalledTimes(2));
    expect(createComment.mock.calls[1]?.[0].body).toEqual({
      attachmentIds: [caseId],
      bodyMarkdown: "Fresh private draft",
      mentionedMembershipIds: [candidates[1]!.membershipId],
      visibility: "private",
    });
  });

  it("uses a freshly reopened edit draft and invalidates only the edited preview on selection", async () => {
    const { editComment, previewComment } = renderPanel();
    const createForm = await composer("create");
    fireEvent.change(within(createForm).getByLabelText("Comment"), {
      target: { value: "Independent create preview" },
    });
    fireEvent.click(within(createForm).getByRole("tab", { name: "Preview" }));
    const createPreview = await within(createForm).findByRole("region", {
      name: "Accepted comment preview",
    });
    let form = await composer("edit");
    fireEvent.click(
      within(form).getByRole("checkbox", { name: "Candidate 00" }),
    );
    fireEvent.click(within(form).getByRole("button", { name: "Preview edit" }));
    expect(
      await within(form).findByRole("region", {
        name: "Accepted comment preview",
      }),
    ).toBeVisible();
    fireEvent.click(
      within(form).getByRole("checkbox", { name: "Candidate 01" }),
    );
    expect(
      within(form).queryByRole("region", { name: "Accepted comment preview" }),
    ).toBeNull();
    expect(createPreview).toBeInTheDocument();
    fireEvent.click(
      within(screen.getByRole("dialog")).getByRole("button", { name: "Close" }),
    );
    form = await composer("edit");
    expect(
      within(form).getByRole("checkbox", { name: "Candidate 00" }),
    ).not.toBeChecked();
    expect(
      within(form).getByRole("checkbox", { name: "Candidate 01" }),
    ).not.toBeChecked();
    fireEvent.change(within(form).getByLabelText("Comment"), {
      target: { value: "Fresh edit" },
    });
    fireEvent.change(within(form).getByLabelText("Reason for edit"), {
      target: { value: "Fresh correction" },
    });
    fireEvent.click(
      within(form).getByRole("checkbox", { name: "Candidate 02" }),
    );
    fireEvent.click(
      within(form).getByRole("button", { name: "Save revision" }),
    );
    await waitFor(() => expect(editComment).toHaveBeenCalledTimes(1));
    expect(editComment.mock.calls[0]?.[0].body).toEqual({
      bodyMarkdown: "Fresh edit",
      reason: "Fresh correction",
      mentionedMembershipIds: [candidates[2]!.membershipId],
    });
    expect(previewComment).toHaveBeenCalledTimes(2);
  });

  it.each(["create", "edit"] as const)(
    "%s clears selection and preview across live authority revocation and restoration",
    async (mode) => {
      let livePermissions = permissions;
      const { previewComment } = renderPanel(() => livePermissions);
      let form = await composer(mode);
      fireEvent.change(within(form).getByLabelText("Comment"), {
        target: { value: "Before revocation" },
      });
      fireEvent.click(
        within(form).getByRole("checkbox", { name: "Candidate 00" }),
      );
      fireEvent.click(
        within(form).getByRole(mode === "create" ? "tab" : "button", {
          name: mode === "create" ? "Preview" : "Preview edit",
        }),
      );
      expect(
        await within(form).findByRole("region", {
          name: "Accepted comment preview",
        }),
      ).toBeVisible();
      livePermissions = ["alert.read", "alert.comment.read"];
      fireEvent.click(
        screen.getByRole("button", { name: "Reload authority", hidden: true }),
      );
      await waitFor(() =>
        expect(
          screen.queryByRole("button", { name: "Post comment" }),
        ).toBeNull(),
      );
      expect(screen.queryByRole("dialog")).toBeNull();
      expect(
        screen.queryByRole("region", { name: "Accepted comment preview" }),
      ).toBeNull();
      livePermissions = permissions;
      fireEvent.click(screen.getByRole("button", { name: "Reload authority" }));
      form = await composer(mode);
      expect(
        within(form).getByRole("checkbox", { name: "Candidate 00" }),
      ).not.toBeChecked();
      expect(within(form).getByLabelText("Comment")).toHaveValue(
        mode === "create" ? "" : comment.bodyMarkdown,
      );
      if (mode === "create")
        fireEvent.change(within(form).getByLabelText("Comment"), {
          target: { value: "Restored draft" },
        });
      fireEvent.click(
        within(form).getByRole("checkbox", { name: "Candidate 01" }),
      );
      fireEvent.click(
        within(form).getByRole(mode === "create" ? "tab" : "button", {
          name: mode === "create" ? "Preview" : "Preview edit",
        }),
      );
      await waitFor(() => expect(previewComment).toHaveBeenCalledTimes(2));
      expect(
        previewComment.mock.calls[1]?.[0].body.mentionedMembershipIds,
      ).toEqual([candidates[1]!.membershipId]);
    },
  );
});

async function composer(mode: "create" | "edit"): Promise<HTMLElement> {
  await screen.findByRole("button", { name: "Post comment" });
  if (mode === "edit")
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }));
  const scope = mode === "edit" ? within(screen.getByRole("dialog")) : screen;
  const picker = await scope.findByRole("group", {
    name: "Mention ticket operators",
  });
  return picker.closest("form")!;
}

function AuthorityReloadControl(): React.JSX.Element {
  const authority = useTenantAuthority();
  return (
    <button type="button" onClick={authority.reload}>
      Reload authority
    </button>
  );
}

function renderPanel(
  getPermissions: () => readonly TenantPermissionKeyView[] = () => permissions,
) {
  const createComment = vi.fn<TicketingApi["createComment"]>(
    async () => comment,
  );
  const editComment = vi.fn<TicketingApi["editComment"]>(async () => ({
    etag: '"comment-r2"',
    replayed: false,
    value: { ...comment, revision: 2 },
  }));
  const previewComment = vi.fn<TicketingApi["previewComment"]>(
    async ({ body }) => ({
      attachments: [],
      bodyMarkdown: body.bodyMarkdown,
      visibility: body.visibility,
      mentions: candidates.filter((candidate) =>
        body.mentionedMembershipIds?.includes(candidate.membershipId),
      ),
    }),
  );
  const listCommentMentionCandidates = vi.fn<
    TicketingApi["listCommentMentionCandidates"]
  >(async () => candidates);
  const api = createTicketingApi({
    createComment,
    editComment,
    previewComment,
    listCommentMentionCandidates,
    listComments: async () => ({ items: [comment] }),
    listCommentRevisions: async () => ({ items: [] }),
  });
  const phaseApi = createPhaseTwoApi({
    getTenantAuthority: async (): Promise<TenantAuthorityView> => ({
      delegationCeiling: [],
      evaluatedAt: "2026-08-25T08:00:00Z",
      legacyMembershipRole: "analyst",
      membershipId,
      membershipStatus: "active",
      operatorTeamRelationships: [],
      permissions: getPermissions().map((permissionKey) => ({
        permissionKey,
        scope: "tenant",
      })),
      roleGrants: [],
      tenantId,
      userId: sessionFixture.user.id,
    }),
  });
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={queryClient}>
      <SessionContext.Provider
        value={{
          api: phaseApi,
          clearSession: vi.fn(),
          membershipRevision: 0,
          refreshMemberships: vi.fn(),
          updateSession: vi.fn(),
          session: {
            ...sessionFixture,
            activeTenantId: tenantId,
            absoluteExpiresAt: "2099-08-25T12:00:00Z",
            idleExpiresAt: "2099-08-25T11:00:00Z",
          },
        }}
      >
        <TenantAuthorityProvider>
          <TicketingApiProvider api={api}>
            <AuthorityReloadControl />
            <TicketCommentPanel
              kind="alert"
              projection="operator"
              resourceId={alertId}
              tenantId={tenantId}
            />
          </TicketingApiProvider>
        </TenantAuthorityProvider>
      </SessionContext.Provider>
    </QueryClientProvider>,
  );
  return {
    createComment,
    editComment,
    previewComment,
    listCommentMentionCandidates,
  };
}
