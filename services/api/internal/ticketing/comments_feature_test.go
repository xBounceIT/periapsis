package ticketing

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestEditCommentFreshCASWindowAndPrivateCapability(t *testing.T) {
	fixture := newServiceFixture(t)
	commentID := mustUUIDv7(t)
	createdAt := fixture.record.CreatedAt
	body := "Corrected **analysis**"
	bodyHTML, err := RenderCommentMarkdown(body)
	if err != nil {
		t.Fatal(err)
	}
	state := operatorCommentEditState(fixture, kernel.CommentPrivate, 2, createdAt)
	result := operatorCommentFromState(fixture, commentID, state, 3, body, bodyHTML, true)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record, commentPreflight: CommentEditPreflight{State: state},
		commentEdit: CommentWriteResult{Comment: result},
	}
	service := mustService(t, repository)

	comment, projection, replayed, err := service.EditComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, commentID, CommentEditInput{
			BodyMarkdown: body, Reason: "Corrected indicator context", ExpectedRevision: 2,
			IdempotencyKey: "comment-edit-private-0001",
		},
	)
	if err != nil || projection != ProjectionOperator || replayed || comment.Revision != 3 ||
		repository.commentEditCalls.Load() != 1 {
		t.Fatalf("EditComment() = (%+v, %v, %t, %v), writes=%d", comment, projection, replayed, err, repository.commentEditCalls.Load())
	}
	if !containsCapability(repository.accessCalls, CapabilityAlertCommentPublic) ||
		!containsCapability(repository.accessCalls, CapabilityAlertCommentPrivate) ||
		!containsCapability(repository.accessCalls, CapabilityAlertRead) {
		t.Fatalf("edit capabilities = %q", repository.accessCalls)
	}
}

func TestPortalCommentEditRequiresExactFrozenMembershipAndContact(t *testing.T) {
	fixture := newServiceFixture(t)
	commentID := mustUUIDv7(t)
	contactID := fixture.actor.UserID
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt)
	state.Origin = CommentOriginCustomerPortal
	state.AuthorAudience = CommentAudienceCustomer
	state.AuthorContactID = &contactID
	result := operatorCommentFromState(
		fixture, commentID, state, 2, "Customer correction", "<p>Customer correction</p>", true,
	)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalCustomer, record: fixture.record,
		permissions:      []kernel.Permission{kernel.PermissionPortalCommentPublic},
		commentPreflight: CommentEditPreflight{State: state},
		commentEdit:      CommentWriteResult{Comment: result},
	}
	service := mustService(t, repository)
	comment, projection, replayed, err := service.EditPortalComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, commentID, CommentEditInput{
			BodyMarkdown: "Customer correction", Reason: "author_correction", ExpectedRevision: 1,
			IdempotencyKey: "portal-comment-edit-0001",
		},
	)
	if err != nil || projection != ProjectionCustomer || replayed || !comment.CanEdit ||
		repository.commentEditCalls.Load() != 1 {
		t.Fatalf("EditPortalComment() = (%+v, %v, %t, %v), writes=%d",
			comment, projection, replayed, err, repository.commentEditCalls.Load())
	}

	wrongContact := mustUUIDv7(t)
	state.AuthorContactID = &wrongContact
	hidden := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalCustomer, record: fixture.record,
		permissions:      []kernel.Permission{kernel.PermissionPortalCommentPublic},
		commentPreflight: CommentEditPreflight{State: state},
	}
	_, _, _, err = mustService(t, hidden).EditPortalComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, commentID, CommentEditInput{
			BodyMarkdown: "Customer correction", Reason: "author_correction", ExpectedRevision: 1,
			IdempotencyKey: "portal-comment-edit-hidden-0001",
		},
	)
	if !errors.Is(err, ErrNotFound) || hidden.commentEditCalls.Load() != 0 {
		t.Fatalf("EditPortalComment(contact mismatch) error=%v writes=%d", err, hidden.commentEditCalls.Load())
	}
}

func TestEditCommentFreshStaleOrExpiredStopsBeforeWriter(t *testing.T) {
	fixture := newServiceFixture(t)
	commentID := mustUUIDv7(t)
	clock := time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC)
	tests := []struct {
		name     string
		state    CommentEditState
		expected int
		want     error
	}{
		{
			name: "stale CAS", state: operatorCommentEditState(fixture, kernel.CommentPublic, 3, fixture.record.CreatedAt),
			expected: 2, want: ErrPreconditionFailed,
		},
		{
			name: "window exact boundary",
			state: operatorCommentEditState(fixture, kernel.CommentPublic, 2,
				clock.Add(-commentEditWindowSeconds*time.Second)),
			expected: 2, want: ErrForbidden,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{
				fixture: fixture, record: fixture.record, commentPreflight: CommentEditPreflight{State: test.state},
			}
			service := mustService(t, repository)
			_, _, _, err := service.EditComment(
				context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
				fixture.ticketUUID, commentID, CommentEditInput{
					BodyMarkdown: "Corrected analysis", Reason: "Corrected context", ExpectedRevision: test.expected,
					IdempotencyKey: "comment-edit-fresh-0001",
				},
			)
			if !errors.Is(err, test.want) || repository.commentEditCalls.Load() != 0 {
				t.Fatalf("EditComment() error=%v writes=%d, want %v and zero", err, repository.commentEditCalls.Load(), test.want)
			}
		})
	}
}

func TestEditCommentExactReplayReturnsHistoricalSafeRenderingAfterAdvanceAndExpiry(t *testing.T) {
	fixture := newServiceFixture(t)
	commentID := mustUUIDv7(t)
	clock := time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC)
	createdAt := clock.Add(-time.Hour)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 7, createdAt)
	replayRevision := 2
	historicalHTML := "<p><strong>Historical safe rendering</strong></p>"
	result := operatorCommentFromState(
		fixture, commentID, state, replayRevision, "Historical safe rendering", historicalHTML, false,
	)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		commentPreflight: CommentEditPreflight{
			State: state, Replayed: true, ReplayRevision: &replayRevision,
		},
		commentEdit: CommentWriteResult{Comment: result, Replayed: true},
	}
	service := mustService(t, repository)

	comment, _, replayed, err := service.EditComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, commentID, CommentEditInput{
			BodyMarkdown: "Historical safe rendering", Reason: "Corrected context", ExpectedRevision: 1,
			IdempotencyKey: "comment-edit-replay-0001",
		},
	)
	if err != nil || !replayed || comment.Revision != replayRevision || comment.BodyHTML != historicalHTML || comment.CanEdit ||
		repository.commentEditCalls.Load() != 1 {
		t.Fatalf("EditComment(replay) = (%+v, %t, %v), writes=%d", comment, replayed, err, repository.commentEditCalls.Load())
	}
}

func TestEditCommentRejectsReplayRevisionAheadOfCurrentState(t *testing.T) {
	fixture := newServiceFixture(t)
	replayRevision := 2
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		commentPreflight: CommentEditPreflight{
			State:    operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt),
			Replayed: true, ReplayRevision: &replayRevision,
		},
	}
	_, _, _, err := mustService(t, repository).EditComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, mustUUIDv7(t), CommentEditInput{
			BodyMarkdown: "Corrected", Reason: "Corrected context", ExpectedRevision: 1,
			IdempotencyKey: "comment-edit-impossible-replay-0001",
		},
	)
	if !errors.Is(err, ErrUnavailable) || repository.commentEditCalls.Load() != 0 {
		t.Fatalf("EditComment(impossible replay) error=%v writes=%d", err, repository.commentEditCalls.Load())
	}
}

func TestEditCommentRejectsFreshWriterResultAfterReplayPreflight(t *testing.T) {
	fixture := newServiceFixture(t)
	commentID := mustUUIDv7(t)
	createdAt := fixture.record.CreatedAt.Add(-time.Hour)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 7, createdAt)
	replayRevision := 2
	result := operatorCommentFromState(
		fixture, commentID, state, replayRevision, "Corrected", "<p>Corrected</p>", false,
	)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		commentPreflight: CommentEditPreflight{
			State: state, Replayed: true, ReplayRevision: &replayRevision,
		},
		commentEdit: CommentWriteResult{Comment: result, Replayed: false},
	}
	_, _, _, err := mustService(t, repository).EditComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, commentID, CommentEditInput{
			BodyMarkdown: "Corrected", Reason: "Corrected context", ExpectedRevision: 1,
			IdempotencyKey: "comment-edit-replay-became-fresh-0001",
		},
	)
	if !errors.Is(err, ErrUnavailable) || repository.commentEditCalls.Load() != 1 {
		t.Fatalf("EditComment(replay became fresh) error=%v writes=%d", err, repository.commentEditCalls.Load())
	}
}

func TestEditCommentKeyConflictStopsBeforeWriter(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture, record: fixture.record, commentPreflightErr: ErrConflict}
	service := mustService(t, repository)
	_, _, _, err := service.EditComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, mustUUIDv7(t), CommentEditInput{
			BodyMarkdown: "Corrected", Reason: "Corrected context", ExpectedRevision: 1,
			IdempotencyKey: "comment-edit-conflict-0001",
		},
	)
	if !errors.Is(err, ErrConflict) || repository.commentEditCalls.Load() != 0 {
		t.Fatalf("EditComment(conflict) error=%v writes=%d", err, repository.commentEditCalls.Load())
	}
}

func TestPrivateCommentEditDoesNotDistinguishMissingFromHidden(t *testing.T) {
	fixture := newServiceFixture(t)
	commentID := mustUUIDv7(t)
	input := CommentEditInput{
		BodyMarkdown: "Corrected", Reason: "Corrected context", ExpectedRevision: 1,
		IdempotencyKey: "comment-edit-hidden-0001",
	}
	missing := &fakeRepository{fixture: fixture, record: fixture.record, commentPreflightErr: ErrNotFound}
	_, _, _, missingErr := mustService(t, missing).EditComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, commentID, input,
	)
	hidden := &fakeRepository{
		fixture: fixture, record: fixture.record,
		commentPreflight: CommentEditPreflight{State: operatorCommentEditState(
			fixture, kernel.CommentPrivate, 1, fixture.record.CreatedAt,
		)},
		accessErrors: map[Capability]error{CapabilityAlertCommentPrivate: ErrForbidden},
	}
	_, _, _, hiddenErr := mustService(t, hidden).EditComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, commentID, input,
	)
	if !errors.Is(missingErr, ErrNotFound) || !errors.Is(hiddenErr, ErrNotFound) ||
		missing.commentEditCalls.Load() != 0 || hidden.commentEditCalls.Load() != 0 {
		t.Fatalf("missing/hidden errors=%v/%v writes=%d/%d", missingErr, hiddenErr,
			missing.commentEditCalls.Load(), hidden.commentEditCalls.Load())
	}
}

func TestCommentEditCommitDoesNotDistinguishHiddenFromMissing(t *testing.T) {
	fixture := newServiceFixture(t)
	commentID := mustUUIDv7(t)
	input := CommentEditInput{
		BodyMarkdown: "Corrected", Reason: "Corrected context", ExpectedRevision: 1,
		IdempotencyKey: "comment-edit-commit-hidden-0001",
	}
	for _, repositoryErr := range []error{ErrForbidden, ErrNotFound} {
		repository := &fakeRepository{
			fixture: fixture, record: fixture.record,
			commentPreflight: CommentEditPreflight{State: operatorCommentEditState(
				fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt,
			)},
			commentEditErr: repositoryErr,
		}
		_, _, _, err := mustService(t, repository).EditComment(
			context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
			fixture.ticketUUID, commentID, input,
		)
		if !errors.Is(err, ErrNotFound) || repository.commentEditCalls.Load() != 1 {
			t.Fatalf("EditComment(commit %v) error=%v writes=%d", repositoryErr, err, repository.commentEditCalls.Load())
		}
	}
}

func TestValidCommentRejectsPrivateAttachmentOnPublicCommentAndBoundaryCanEdit(t *testing.T) {
	fixture := newServiceFixture(t)
	createdAt := fixture.record.CreatedAt
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, createdAt)
	comment := operatorCommentFromState(fixture, mustUUIDv7(t), state, 1, "Analysis", "<p>Analysis</p>", true)
	comment.Attachments = []CommentAttachment{{
		ID: mustUUIDv7(t), OriginalFilename: "evidence<1>.txt", Visibility: kernel.CommentPrivate,
	}}
	membership, _ := entityID(fixture.membershipUUID)
	access := LiveAccess{MembershipID: membership}
	if validComment(comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, ProjectionOperator, access, createdAt) {
		t.Fatal("public comment with private attachment accepted")
	}
	comment.Attachments = nil
	if validComment(comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, ProjectionOperator, access, comment.EditableUntil) {
		t.Fatal("canEdit accepted at exact editableUntil boundary")
	}
	comment.Origin = CommentOriginSystem
	if validComment(comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, ProjectionOperator, access, createdAt) {
		t.Fatal("system-origin comment advertised as editable")
	}
	comment.CanEdit = false
	comment.UpdatedAt = comment.EditableUntil
	if validComment(comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, ProjectionOperator, access, createdAt) {
		t.Fatal("revision persisted at exact editableUntil boundary was accepted")
	}
	comment.Origin = CommentOriginAPI
	comment.UpdatedAt = comment.CreatedAt.Add(time.Microsecond)
	if validComment(comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, ProjectionOperator, access, createdAt) {
		t.Fatal("revision one with a non-creation updatedAt was accepted")
	}
	comment.Revision = 2
	comment.UpdatedAt = comment.CreatedAt
	if validComment(comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert, ProjectionOperator, access, createdAt) {
		t.Fatal("child revision without a later updatedAt was accepted")
	}
}

func TestValidCommentRequiresCurrentWritePermissionBeforeAdvertisingCanEdit(t *testing.T) {
	fixture := newServiceFixture(t)
	createdAt := fixture.record.CreatedAt
	commentID := mustUUIDv7(t)
	tests := []struct {
		name        string
		principal   kernel.PrincipalKind
		visibility  kernel.CommentVisibility
		projection  Projection
		permissions []kernel.Permission
		portal      bool
	}{
		{
			name: "operator public without public permission", principal: kernel.PrincipalOperator,
			visibility: kernel.CommentPublic, projection: ProjectionOperator,
			permissions: []kernel.Permission{kernel.PermissionAlertUpdate},
		},
		{
			name: "operator private without public permission", principal: kernel.PrincipalOperator,
			visibility: kernel.CommentPrivate, projection: ProjectionOperator,
			permissions: []kernel.Permission{kernel.PermissionAlertCommentPrivate},
		},
		{
			name: "customer without portal permission", principal: kernel.PrincipalCustomer,
			visibility: kernel.CommentPublic, projection: ProjectionCustomer,
			permissions: []kernel.Permission{kernel.PermissionAlertCommentPublic}, portal: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{
				fixture: fixture, principal: test.principal, permissions: test.permissions,
			}
			access, err := repository.ResolveAccess(
				context.Background(), fixture.actor, fixture.tenantUUID, CapabilityAlertCommentPublic,
			)
			if err != nil {
				t.Fatal(err)
			}
			state := operatorCommentEditState(fixture, test.visibility, 1, createdAt)
			comment := operatorCommentFromState(
				fixture, commentID, state, 2, "Corrected", "<p>Corrected</p>", true,
			)
			if test.portal {
				contactID := uuidFromEntity(*access.CustomerContactID)
				comment.Origin = CommentOriginCustomerPortal
				comment.Author.Audience = CommentAudienceCustomer
				comment.Author.ContactID = &contactID
			}
			if validComment(
				comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
				test.projection, access, createdAt,
			) {
				t.Fatal("canEdit=true accepted without the current write permission set")
			}
		})
	}
}

func TestCommentListDowngradesCanEditWhenCurrentWriteScopeIsDenied(t *testing.T) {
	fixture := newServiceFixture(t)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt)
	comment := operatorCommentFromState(
		fixture, mustUUIDv7(t), state, 1, "Readable", "<p>Readable</p>", true,
	)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		comments:     StoredCommentPage{Items: []Comment{comment}},
		accessErrors: map[Capability]error{CapabilityAlertCommentPublic: ErrForbidden},
	}
	page, err := mustService(t, repository).Comments(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, CursorPageInput{Limit: 10},
	)
	if err != nil || len(page.Items) != 1 || page.Items[0].CanEdit ||
		!containsCapability(repository.accessCalls, CapabilityAlertCommentPublic) {
		t.Fatalf("Comments(write scope denied) = (%+v, %v), capabilities=%q", page, err, repository.accessCalls)
	}
}

func TestCommentFilenameAndUnicodeScalarBounds(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{"evidence<1>.txt", strings.Repeat("é", 127), "case #1.e01"} {
		if !validCommentAttachmentFilename(valid) {
			t.Fatalf("valid filename rejected: %q", valid)
		}
	}
	for _, invalid := range []string{".", "..", "folder/file", `folder\file`, "line\nfeed", "invoice\u202efdp.exe", strings.Repeat("é", 128)} {
		if validCommentAttachmentFilename(invalid) {
			t.Fatalf("invalid filename accepted: %q", invalid)
		}
	}
	body := strings.Repeat("😀", maximumCommentCharacters)
	if _, err := RenderCommentMarkdown(body); err != nil {
		t.Fatalf("20,000 Unicode scalars rejected: %v", err)
	}
	if _, err := RenderCommentMarkdown(body + "😀"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("20,001 Unicode scalars error=%v, want invalid", err)
	}
	if !validCommentDisplayName(strings.Repeat("😀", 200)) || validCommentDisplayName(strings.Repeat("😀", 201)) {
		t.Fatal("display-name Unicode scalar bound drifted")
	}
	if validCommentMentionSearch("analyst\u202e") || validCommentEditReason("Corrected\u2066reason") {
		t.Fatal("bidi formatting control accepted by comment query/reason validation")
	}
}

func TestCommentPreviewAndMentionCandidatesFailClosedOnRepositoryDrift(t *testing.T) {
	fixture := newServiceFixture(t)
	attachmentID := mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		commentPreview: StoredCommentPreview{Attachments: []CommentAttachment{{
			ID: attachmentID, OriginalFilename: "private.e01", Visibility: kernel.CommentPrivate,
		}}},
	}
	service := mustService(t, repository)
	_, err := service.PreviewComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentPreviewInput{
			Visibility: kernel.CommentPublic, BodyMarkdown: "Public preview", AttachmentIDs: []uuid.UUID{attachmentID},
		},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("PreviewComment(private attachment) error=%v, want unavailable", err)
	}

	first := mustUUIDv7(t)
	second := mustUUIDv7(t)
	repository.commentCandidates = []CommentMentionCandidate{
		{MembershipID: first, DisplayName: "Zulu"},
		{MembershipID: second, DisplayName: "Alpha"},
	}
	_, err = service.CommentMentionCandidates(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentMentionCandidateInput{Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CommentMentionCandidates(non-canonical) error=%v, want unavailable", err)
	}
}

func TestCustomerRevisionHistoryRejectsOperatorOnlyFields(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalCustomer, record: fixture.record,
		commentRevisions: StoredCommentRevisionPage{Items: []CommentRevision{{
			Revision: 1, BodyMarkdown: "Public", BodyHTML: "<p>Public</p>",
			Reason: "original_comment", EditedAt: fixture.record.CreatedAt,
			Attachments: []CommentAttachment{}, Mentions: []CommentMention{},
		}}},
	}
	service := mustService(t, repository)
	_, err := service.CommentRevisionsPortal(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, mustUUIDv7(t), CommentRevisionPageInput{Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CommentRevisionsPortal(operator reason) error=%v, want unavailable", err)
	}
}

func TestCommentRevisionHistoryRequiresMonotonicEditedAt(t *testing.T) {
	t.Parallel()
	editedAt := time.Date(2026, time.September, 1, 12, 0, 0, 0, time.UTC)
	page := StoredCommentRevisionPage{Items: []CommentRevision{
		{
			Revision: 2, BodyMarkdown: "Corrected", BodyHTML: "<p>Corrected</p>",
			Reason: "author_correction", EditedAt: editedAt,
			Attachments: []CommentAttachment{}, Mentions: []CommentMention{},
		},
		{
			Revision: 1, BodyMarkdown: "Original", BodyHTML: "<p>Original</p>",
			Reason: "original_comment", EditedAt: editedAt,
			Attachments: []CommentAttachment{}, Mentions: []CommentMention{},
		},
	}}
	if validCommentRevisionPageResult(page, false) {
		t.Fatal("revision history accepted equal editedAt timestamps")
	}
	page.Items[0].EditedAt = editedAt.Add(time.Microsecond)
	page.Items[0].Revision = 3
	if validCommentRevisionPageResult(page, false) {
		t.Fatal("revision history accepted a gap in append-only revisions")
	}
	page.Items[0].Revision = 2
	if !validCommentRevisionPageResult(page, false) {
		t.Fatal("revision history rejected strictly monotonic editedAt timestamps")
	}
}

func TestCommentPaginationRejectsNonExclusiveRepositoryResults(t *testing.T) {
	t.Parallel()
	fixture := newServiceFixture(t)
	after := mustUUIDv7(t)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt)
	comment := operatorCommentFromState(
		fixture, after, state, 1, "Existing", "<p>Existing</p>", false,
	)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		comments: StoredCommentPage{Items: []Comment{comment}},
	}
	_, err := mustService(t, repository).Comments(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, CursorPageInput{After: &after, Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Comments(non-exclusive cursor) error=%v, want unavailable", err)
	}

	afterRevision := 2
	repository.commentRevisions = StoredCommentRevisionPage{Items: []CommentRevision{{
		Revision: 2, BodyMarkdown: "Corrected", BodyHTML: "<p>Corrected</p>",
		Reason: "author_correction", EditedAt: fixture.record.CreatedAt.Add(time.Microsecond),
		Attachments: []CommentAttachment{}, Mentions: []CommentMention{},
	}}}
	_, err = mustService(t, repository).CommentRevisions(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, mustUUIDv7(t), CommentRevisionPageInput{AfterRevision: &afterRevision, Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("CommentRevisions(non-exclusive cursor) error=%v, want unavailable", err)
	}
}

func TestPrivateCommentPreviewRequiresPublicAndPrivatePolicy(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		permissions: []kernel.Permission{kernel.PermissionAlertCommentPrivate},
	}
	service := mustService(t, repository)
	_, err := service.PreviewComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentPreviewInput{Visibility: kernel.CommentPrivate, BodyMarkdown: "Internal preview"},
	)
	if !errors.Is(err, ErrForbidden) || repository.commentPreviewCalls.Load() != 0 {
		t.Fatalf("PreviewComment(private-only) error=%v repository calls=%d", err, repository.commentPreviewCalls.Load())
	}
}

func TestPortalCommentPolicyAcceptsOnlyPortalCommentPermission(t *testing.T) {
	fixture := newServiceFixture(t)
	createdAt := fixture.record.CreatedAt
	contactID := fixture.actor.UserID
	comment := Comment{
		ID: mustUUIDv7(t), TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID,
		ResourceKind: kernel.AggregateAlert, Visibility: kernel.CommentPublic,
		BodyMarkdown: "Customer update", BodyHTML: "<p>Customer update</p>",
		Author: CommentAuthor{
			MembershipID: fixture.membershipUUID, ContactID: &contactID,
			DisplayName: "Customer", Audience: CommentAudienceCustomer,
		},
		Origin: CommentOriginCustomerPortal, Revision: 1, CreatedAt: createdAt, UpdatedAt: createdAt,
		EditableUntil: createdAt.Add(commentEditWindowSeconds * time.Second), CanEdit: true,
		Attachments: []CommentAttachment{}, Mentions: []CommentMention{},
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalCustomer, record: fixture.record,
		permissions:    []kernel.Permission{kernel.PermissionPortalCommentPublic},
		commentPreview: StoredCommentPreview{Attachments: []CommentAttachment{}, Mentions: []CommentMention{}},
		commentCreate:  CommentWriteResult{Comment: comment},
	}
	service := mustService(t, repository)
	preview, err := service.PreviewPortalComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentPreviewInput{Visibility: kernel.CommentPublic, BodyMarkdown: "Customer update"},
	)
	if err != nil || preview.Projection != ProjectionCustomer {
		t.Fatalf("PreviewPortalComment() = (%+v, %v)", preview, err)
	}
	created, projection, _, err := service.AddPortalComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentInput{
			Visibility: kernel.CommentPublic, BodyMarkdown: "Customer update", IdempotencyKey: "portal-comment-create-0001",
		},
	)
	if err != nil || projection != ProjectionCustomer || created.Origin != CommentOriginCustomerPortal {
		t.Fatalf("AddPortalComment() = (%+v, %v, %v)", created, projection, err)
	}
}

func TestPortalCommentRequiresLiveCustomerContactBeforeRepositoryAccess(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &missingPortalContactRepository{fakeRepository: &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalCustomer, record: fixture.record,
		permissions: []kernel.Permission{kernel.PermissionPortalCommentPublic},
	}}
	_, err := mustService(t, repository).PreviewPortalComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentPreviewInput{Visibility: kernel.CommentPublic, BodyMarkdown: "Customer update"},
	)
	if !errors.Is(err, ErrForbidden) || repository.commentPreviewCalls.Load() != 0 {
		t.Fatalf("PreviewPortalComment(missing contact) error=%v repository calls=%d",
			err, repository.commentPreviewCalls.Load())
	}
}

func TestCommentReadRejectsIncoherentFrozenOriginAudienceWhenNotEditable(t *testing.T) {
	fixture := newServiceFixture(t)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt)
	comment := operatorCommentFromState(
		fixture, mustUUIDv7(t), state, 1, "Historical", "<p>Historical</p>", false,
	)
	contactID := mustUUIDv7(t)
	comment.Origin = CommentOriginCustomerPortal
	comment.Author.Audience = CommentAudienceOperator
	comment.Author.ContactID = &contactID
	membership, _ := entityID(fixture.membershipUUID)
	if validComment(
		comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
		ProjectionOperator, LiveAccess{MembershipID: membership}, fixture.record.CreatedAt,
	) {
		t.Fatal("incoherent frozen origin/audience accepted when canEdit=false")
	}
}

func TestAddCommentReplayPreservesSafeHistoricalRendering(t *testing.T) {
	fixture := newServiceFixture(t)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt)
	historicalHTML := "<p><strong>Historical create</strong></p>"
	comment := operatorCommentFromState(
		fixture, mustUUIDv7(t), state, 1, "Historical create", historicalHTML, false,
	)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		commentCreate: CommentWriteResult{Comment: comment, Replayed: true},
	}
	created, _, replayed, err := mustService(t, repository).AddComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentInput{
			Visibility: kernel.CommentPublic, BodyMarkdown: "Historical create",
			IdempotencyKey: "comment-create-historical-replay-0001",
		},
	)
	if err != nil || !replayed || created.BodyHTML != historicalHTML {
		t.Fatalf("AddComment(historical replay) = (%+v, %t, %v)", created, replayed, err)
	}
}

func TestEscalationCopyPreservesFrozenAudienceButIsNeverEditable(t *testing.T) {
	fixture := newServiceFixture(t)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt)
	comment := operatorCommentFromState(
		fixture, mustUUIDv7(t), state, 1, "Copied customer evidence", "<p>Copied customer evidence</p>", false,
	)
	contactID := mustUUIDv7(t)
	comment.Origin = CommentOriginEscalationCopy
	comment.Author.Audience = CommentAudienceCustomer
	comment.Author.ContactID = &contactID
	membership, _ := entityID(fixture.membershipUUID)
	access := LiveAccess{MembershipID: membership}
	if !validComment(
		comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
		ProjectionOperator, access, fixture.record.CreatedAt,
	) {
		t.Fatal("customer-authored escalation copy was rejected")
	}
	comment.Visibility = kernel.CommentPrivate
	if validComment(
		comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
		ProjectionOperator, access, fixture.record.CreatedAt,
	) {
		t.Fatal("private escalation copy was accepted")
	}
	comment.Visibility = kernel.CommentPublic
	comment.CanEdit = true
	if validComment(
		comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
		ProjectionOperator, access, fixture.record.CreatedAt,
	) {
		t.Fatal("editable escalation copy was accepted")
	}
	comment.CanEdit = false
	comment.Author.Audience = CommentAuthorAudience("external")
	if validComment(
		comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
		ProjectionOperator, access, fixture.record.CreatedAt,
	) {
		t.Fatal("escalation copy with unknown frozen audience was accepted")
	}
	comment.Origin = CommentOriginCustomerPortal
	comment.Author.Audience = CommentAudienceCustomer
	comment.Visibility = kernel.CommentPrivate
	if validComment(
		comment, fixture.tenantUUID, fixture.ticketUUID, kernel.AggregateAlert,
		ProjectionOperator, access, fixture.record.CreatedAt,
	) {
		t.Fatal("private customer-portal comment was accepted")
	}
}

func TestAddCommentReassertsFrozenAuthorOnReplay(t *testing.T) {
	fixture := newServiceFixture(t)
	state := operatorCommentEditState(fixture, kernel.CommentPublic, 1, fixture.record.CreatedAt)
	comment := operatorCommentFromState(
		fixture, mustUUIDv7(t), state, 1, "Created", "<p>Created</p>", false,
	)
	comment.Author.MembershipID = mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture, record: fixture.record,
		commentCreate: CommentWriteResult{Comment: comment, Replayed: true},
	}
	service := mustService(t, repository)
	_, _, _, err := service.AddComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		CommentInput{
			Visibility: kernel.CommentPublic, BodyMarkdown: "Created", IdempotencyKey: "comment-create-replay-0001",
		},
	)
	if !errors.Is(err, ErrUnavailable) || repository.commentCreateCalls.Load() != 1 {
		t.Fatalf("AddComment(mismatched replay author) error=%v calls=%d", err, repository.commentCreateCalls.Load())
	}
}

func operatorCommentEditState(
	fixture serviceFixture,
	visibility kernel.CommentVisibility,
	revision int,
	createdAt time.Time,
) CommentEditState {
	return CommentEditState{
		Visibility: visibility, AuthorMembershipID: fixture.membershipUUID,
		Origin: CommentOriginAPI, AuthorAudience: CommentAudienceOperator, Revision: revision,
		CreatedAt: createdAt, EditableUntil: createdAt.Add(commentEditWindowSeconds * time.Second),
	}
}

func operatorCommentFromState(
	fixture serviceFixture,
	commentID uuid.UUID,
	state CommentEditState,
	revision int,
	bodyMarkdown, bodyHTML string,
	canEdit bool,
) Comment {
	updatedAt := state.CreatedAt
	if revision > 1 {
		updatedAt = state.CreatedAt.Add(time.Minute)
	}
	return Comment{
		ID: commentID, TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID,
		ResourceKind: kernel.AggregateAlert, Visibility: state.Visibility,
		BodyMarkdown: bodyMarkdown, BodyHTML: bodyHTML,
		Author: CommentAuthor{
			MembershipID: state.AuthorMembershipID, ContactID: state.AuthorContactID,
			DisplayName: "DFIR Operator", Audience: state.AuthorAudience,
		},
		Origin: state.Origin, Revision: revision, CreatedAt: state.CreatedAt,
		UpdatedAt: updatedAt, EditableUntil: state.EditableUntil, CanEdit: canEdit,
		Attachments: []CommentAttachment{}, Mentions: []CommentMention{},
	}
}

func containsCapability(values []Capability, wanted Capability) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type missingPortalContactRepository struct {
	*fakeRepository
}

func (repository *missingPortalContactRepository) ResolveAccess(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	capability Capability,
) (LiveAccess, error) {
	access, err := repository.fakeRepository.ResolveAccess(ctx, actor, tenantID, capability)
	access.CustomerContactID = nil
	return access, err
}
