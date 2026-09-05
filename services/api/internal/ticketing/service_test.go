package ticketing

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func TestListFailsClosedWhenRepositoryLeaksCustomerHiddenRows(t *testing.T) {
	fixture := newServiceFixture(t)
	hidden := fixture.record
	hidden.Snapshot = mustSnapshot(t, fixture.workflow, fixture.tenant, fixture.ticket, false, kernel.Assignment{}, 1)
	repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalCustomer, list: RecordPage{Items: []Record{hidden}}}
	service := mustService(t, repository)

	page, err := service.List(context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, ListInput{Limit: 10})
	if !errors.Is(err, ErrUnavailable) || len(page.Items) != 0 {
		t.Fatalf("List() = (%v, %v), want fail-closed unavailable", page, err)
	}
	if repository.listCalls.Load() != 1 {
		t.Fatalf("repository list calls = %d, want 1", repository.listCalls.Load())
	}
}

func TestCustomerCommentProjectionAndCreationFailClosed(t *testing.T) {
	fixture := newServiceFixture(t)
	now := fixture.record.CreatedAt
	private := Comment{
		ID: mustUUIDv7(t), TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID,
		ResourceKind: kernel.AggregateAlert, Visibility: kernel.CommentPrivate,
		BodyMarkdown: "Internal analysis", BodyHTML: "<p>Internal analysis</p>",
		Author: CommentAuthor{
			MembershipID: fixture.membershipUUID, DisplayName: "Operator", Audience: CommentAudienceOperator,
		},
		Origin: CommentOriginAPI, Revision: 1, CreatedAt: now, UpdatedAt: now,
		EditableUntil: now.Add(commentEditWindowSeconds * time.Second),
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalCustomer, record: fixture.record,
		comments: StoredCommentPage{Items: []Comment{private}},
	}
	service := mustService(t, repository)

	page, err := service.CommentsPortal(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, CursorPageInput{Limit: 10},
	)
	if !errors.Is(err, ErrUnavailable) || len(page.Items) != 0 {
		t.Fatalf("Comments(private leak) = (%+v, %v), want fail-closed unavailable", page, err)
	}

	_, _, _, err = service.AddComment(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, CommentInput{
			Visibility: kernel.CommentPrivate, BodyMarkdown: "Customer private note",
			IdempotencyKey: "customer-comment-0001",
		},
	)
	if !errors.Is(err, ErrForbidden) || repository.commentCreateCalls.Load() != 0 {
		t.Fatalf("AddComment(private customer) error = %v, writes=%d, want forbidden before write", err, repository.commentCreateCalls.Load())
	}

	public := private
	public.ID = mustUUIDv7(t)
	public.Visibility = kernel.CommentPublic
	public.BodyMarkdown = "Customer-safe update"
	public.BodyHTML = "<p>Customer-safe update</p>"
	repository.comments = StoredCommentPage{Items: []Comment{public}}
	page, err = service.CommentsPortal(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, CursorPageInput{Limit: 10},
	)
	if err != nil || page.Projection != ProjectionCustomer || len(page.Items) != 1 || page.Items[0].Visibility != kernel.CommentPublic {
		t.Fatalf("Comments(public) = (%+v, %v)", page, err)
	}
}

func TestCustomerActivityProjectionRequiresRedactedActorAndNoDetails(t *testing.T) {
	fixture := newServiceFixture(t)
	view := View{Record: fixture.record, Projection: ProjectionCustomer}
	activity := Activity{
		ID: mustUUIDv7(t), TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID,
		ResourceKind: kernel.AggregateAlert, Kind: "comment.public", Summary: "Public update",
		ActorKind: ActivityActorRedacted, DisplayName: "Support team", Origin: "operator",
		OccurredAt: fixture.record.CreatedAt,
	}
	if !validActivity(activity, view, fixture.tenantUUID, kernel.AggregateAlert) {
		t.Fatalf("valid redacted customer activity was rejected: %+v", activity)
	}
	activity.ActorKind, activity.ActorID = ActivityActorHuman, fixture.membershipUUID
	if validActivity(activity, view, fixture.tenantUUID, kernel.AggregateAlert) {
		t.Fatal("customer activity retained an internal actor identifier")
	}
	activity.ActorKind, activity.ActorID = ActivityActorRedacted, uuid.Nil
	activity.Details = map[string]any{"private": "operator-only"}
	if validActivity(activity, view, fixture.tenantUUID, kernel.AggregateAlert) {
		t.Fatal("customer activity retained an operator detail bag")
	}
}

func TestActivityFeedUsesCompoundKindCapabilityAndRejectsLeakedRows(t *testing.T) {
	fixture := newServiceFixture(t)
	activity := Activity{
		ID: mustUUIDv7(t), TenantID: fixture.tenantUUID, ResourceID: fixture.ticketUUID,
		ResourceKind: kernel.AggregateAlert, Kind: "assigned", Summary: "Alert assigned",
		ActorKind: ActivityActorHuman, ActorID: fixture.membershipUUID,
		DisplayName: "Operator", Origin: "operator", Details: map[string]any{},
		OccurredAt: fixture.record.CreatedAt,
	}
	repository := &fakeRepository{
		fixture: fixture,
		activityFeed: StoredActivityPage{
			Items: []Activity{activity}, NextCursor: &activity.ID,
		},
	}
	service := mustService(t, repository)

	page, err := service.ActivityFeed(
		context.Background(), fixture.actor, fixture.tenantUUID,
		kernel.AggregateAlert, CursorPageInput{Limit: 25},
	)
	if err != nil || page.Projection != ProjectionOperator || len(page.Items) != 1 ||
		page.NextCursor == nil || *page.NextCursor != activity.ID {
		t.Fatalf("ActivityFeed() = (%+v, %v)", page, err)
	}
	if repository.activityFeedCalls.Load() != 1 ||
		repository.activityFeedKind != kernel.AggregateAlert ||
		repository.activityFeedPage.Limit != 25 {
		t.Fatalf("feed repository call = count %d, kind %v, page %+v",
			repository.activityFeedCalls.Load(), repository.activityFeedKind, repository.activityFeedPage)
	}
	if len(repository.accessCalls) != 1 || repository.accessCalls[0] != CapabilityAlertActivityFeed {
		t.Fatalf("resolved capabilities = %v", repository.accessCalls)
	}

	leaked := activity
	leaked.ResourceKind = kernel.AggregateCase
	repository.activityFeed = StoredActivityPage{Items: []Activity{leaked}}
	page, err = service.ActivityFeed(
		context.Background(), fixture.actor, fixture.tenantUUID,
		kernel.AggregateAlert, CursorPageInput{Limit: 25},
	)
	if !errors.Is(err, ErrUnavailable) || len(page.Items) != 0 {
		t.Fatalf("ActivityFeed(leak) = (%+v, %v), want unavailable", page, err)
	}
}

func TestActivityFeedRejectsCustomerProjectionBeforeRepositoryRead(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalCustomer}
	service := mustService(t, repository)

	_, err := service.ActivityFeed(
		context.Background(), fixture.actor, fixture.tenantUUID,
		kernel.AggregateCase, CursorPageInput{Limit: 25},
	)
	if !errors.Is(err, ErrForbidden) || repository.activityFeedCalls.Load() != 0 {
		t.Fatalf("ActivityFeed(customer) error=%v calls=%d", err, repository.activityFeedCalls.Load())
	}
}

func TestActivityFeedRejectsIncoherentPagination(t *testing.T) {
	fixture := newServiceFixture(t)
	newer := Activity{
		ID: uuid.MustParse("0198c97d-cf4f-7000-8000-000000000089"), TenantID: fixture.tenantUUID,
		ResourceID: fixture.ticketUUID, ResourceKind: kernel.AggregateAlert, Kind: "assigned",
		Summary: "Alert assigned", ActorKind: ActivityActorHuman, ActorID: fixture.membershipUUID,
		DisplayName: "Operator", Origin: "operator", Details: map[string]any{}, OccurredAt: fixture.record.CreatedAt,
	}
	older := newer
	older.ID = uuid.MustParse("0198c97d-cf4f-7000-8000-000000000088")
	wrongCursor := uuid.MustParse("0198c97d-cf4f-7000-8000-000000000087")
	tests := []struct {
		name string
		page StoredActivityPage
	}{
		{name: "ascending items", page: StoredActivityPage{Items: []Activity{older, newer}}},
		{name: "cursor without items", page: StoredActivityPage{NextCursor: &wrongCursor}},
		{name: "cursor differs from last item", page: StoredActivityPage{Items: []Activity{newer, older}, NextCursor: &wrongCursor}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{fixture: fixture, activityFeed: test.page}
			service := mustService(t, repository)
			page, err := service.ActivityFeed(
				context.Background(), fixture.actor, fixture.tenantUUID,
				kernel.AggregateAlert, CursorPageInput{Limit: 25},
			)
			if !errors.Is(err, ErrUnavailable) || len(page.Items) != 0 {
				t.Fatalf("ActivityFeed() = (%+v, %v), want unavailable", page, err)
			}
		})
	}
}

func TestAddCommentEnforcesCanonicalContractBoundsBeforeRepositoryAccess(t *testing.T) {
	fixture := newServiceFixture(t)
	uuids := func(count int) []uuid.UUID {
		values := make([]uuid.UUID, count)
		for index := range values {
			values[index] = mustUUIDv7(t)
		}
		return values
	}
	tests := []struct {
		name        string
		body        string
		attachments []uuid.UUID
		mentions    []uuid.UUID
	}{
		{name: "body over 20000 characters", body: strings.Repeat("a", maximumCommentCharacters+1)},
		{name: "more than 20 attachments", body: "bounded", attachments: uuids(maximumCommentAttachments + 1)},
		{name: "more than 50 mentions", body: "bounded", mentions: uuids(maximumCommentMentions + 1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record}
			service := mustService(t, repository)
			_, _, _, err := service.AddComment(
				context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
				fixture.ticketUUID, CommentInput{
					Visibility: kernel.CommentPublic, BodyMarkdown: test.body,
					AttachmentIDs: test.attachments, MentionedIDs: test.mentions,
					IdempotencyKey: "bounded-comment-0001",
				},
			)
			if !errors.Is(err, ErrInvalidInput) || repository.getCalls.Load() != 0 ||
				repository.commentCreateCalls.Load() != 0 {
				t.Fatalf("AddComment() error=%v gets=%d writes=%d", err, repository.getCalls.Load(), repository.commentCreateCalls.Load())
			}
		})
	}
}

func TestMutationRejectsMissingAuditBeforeRepositoryAccess(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record}
	service := mustService(t, repository)
	actor := fixture.actor
	actor.Audit = AuditContext{}

	_, err := service.Mutate(
		context.Background(), actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		kernel.ActionClaim, MutationInput{ExpectedVersion: 1},
	)
	if !errors.Is(err, ErrForbidden) || repository.getCalls.Load() != 0 || repository.applyCalls.Load() != 0 {
		t.Fatalf("Mutate(missing audit) error=%v gets=%d writes=%d", err, repository.getCalls.Load(), repository.applyCalls.Load())
	}
}

func TestTransitionWorkflowConditionUsesCurrentAndProposedTicketFacts(t *testing.T) {
	fixture := newServiceFixture(t)
	workflow := conditionalAlertWorkflow(t)
	fixture.workflow = workflow
	fixture.record.Workflow = workflow
	fixture.record.Snapshot = mustSnapshot(
		t, workflow, fixture.tenant, fixture.ticket, true, kernel.Assignment{}, 1,
	)
	fixture.record.Severity = "low"
	fixture.record.CustomFields = map[string]any{"risk_score": float64(2)}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
	}
	service := mustService(t, repository)
	input := MutationInput{
		ExpectedVersion: 1,
		TransitionKey:   "close_alert",
		TargetStateKey:  "closed",
		CustomFields:    map[string]any{"risk_score": float64(9)},
		IdempotencyKey:  "conditional-transition-0001",
	}

	if _, err := service.Mutate(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, kernel.ActionTransition, input,
	); !errors.Is(err, ErrForbidden) || repository.applyCalls.Load() != 0 {
		t.Fatalf("false workflow condition error=%v writes=%d", err, repository.applyCalls.Load())
	}

	repository.record.Severity = "high"
	result, err := service.Mutate(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, kernel.ActionTransition, input,
	)
	if err != nil || result.View.Record.Snapshot.State().String() != "closed" || repository.applyCalls.Load() != 1 {
		t.Fatalf("matching workflow condition result=%+v error=%v writes=%d", result, err, repository.applyCalls.Load())
	}
}

func TestOperatorTeamScopeRejectsRepositoryRosterLeakage(t *testing.T) {
	fixture := newServiceFixture(t)
	rogueTeam, _ := entityID(mustUUIDv7(t))
	record := fixture.record
	record.Snapshot = mustSnapshot(t, fixture.workflow, fixture.tenant, fixture.ticket, true, mustAssignment(t, rogueTeam, nil, nil), 1)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, scopes: []Scope{ScopeOperatorTeam},
		claimableTeams: []kernel.EntityID{fixture.team}, operatorTeams: []kernel.EntityID{rogueTeam}, record: record,
	}
	service := mustService(t, repository)

	_, err := service.Get(context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID)
	if !errors.Is(err, ErrUnavailable) || repository.getCalls.Load() != 0 {
		t.Fatalf("Get(roster leak) error=%v gets=%d, want fail closed before resource lookup", err, repository.getCalls.Load())
	}
}

func TestCustomFieldValueGrammarIsClosed(t *testing.T) {
	tests := []struct {
		name   string
		values map[string]any
		valid  bool
	}{
		{name: "scalars and flat array", values: map[string]any{"score": json.Number("42"), "labels": []any{"one", true, 3}}, valid: true},
		{name: "explicit null", values: map[string]any{"optional": nil}, valid: true},
		{name: "nested object", values: map[string]any{"nested": map[string]any{"secret": "value"}}},
		{name: "nested array", values: map[string]any{"nested": []any{[]any{"value"}}}},
		{name: "null array item", values: map[string]any{"items": []any{nil}}},
		{name: "non finite", values: map[string]any{"score": math.NaN()}},
		{name: "invalid key", values: map[string]any{"Invalid Key": "value"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateCustomFields(test.values)
			if (err == nil) != test.valid {
				t.Fatalf("ValidateCustomFields() error = %v, valid=%t", err, test.valid)
			}
		})
	}
}

func TestEscalationFingerprintBindsNewCaseContentCanonically(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator}
	access, err := repository.ResolveAccess(context.Background(), fixture.actor, fixture.tenantUUID, CapabilityAlertEscalate)
	if err != nil {
		t.Fatal(err)
	}
	caseWorkflow := caseWorkflow(t)
	caseID, _ := entityID(mustUUIDv7(t))
	linkID, _ := entityID(mustUUIDv7(t))
	source, err := kernel.NewEscalationSource(
		fixture.workflow, linkID, fixture.record.Snapshot, 1, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := kernel.NewCaseCreationTarget(caseWorkflow, fixture.tenant, caseID, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := kernel.NewIdempotencyKey("escalation-content-0001")
	reason, _ := kernel.NewEscalationReason("Investigate correlated alert")
	command, err := kernel.NewEscalationCommand(
		fixture.tenant, key, time.Date(2026, 8, 25, 10, 0, 2, 0, time.UTC),
		kernel.RelationEscalation, reason, target, []kernel.EscalationSource{source},
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := kernel.NewEscalationReplayIdentity(command, access.Authority)
	if err != nil {
		t.Fatal(err)
	}
	base := EscalationInput{Target: EscalationTargetInput{NewCase: &CreateCaseInput{
		Title: "Investigation", Severity: "high", Priority: "urgent", Category: "security",
		Tags: []string{"endpoint", "malware"}, CustomFields: map[string]any{"alpha": 1, "beta": "two"},
	}}}
	first, err := escalationFingerprint(identity, base, "escalate")
	if err != nil {
		t.Fatal(err)
	}
	reordered := base
	content := *base.Target.NewCase
	content.CustomFields = map[string]any{"beta": "two", "alpha": 1}
	reordered.Target.NewCase = &content
	second, err := escalationFingerprint(identity, reordered, "escalate")
	if err != nil || first != second {
		t.Fatalf("canonical map order changed fingerprint: equal=%t err=%v", first == second, err)
	}
	drifted := reordered
	driftedContent := *reordered.Target.NewCase
	driftedContent.Title = "Different investigation"
	drifted.Target.NewCase = &driftedContent
	third, err := escalationFingerprint(identity, drifted, "escalate")
	if err != nil || first == third {
		t.Fatalf("new Case payload drift was not bound: equal=%t err=%v", first == third, err)
	}
	linkFingerprint, err := escalationFingerprint(identity, base, EscalationOperationLink)
	if err != nil || first == linkFingerprint {
		t.Fatalf("explicit link shared escalation replay identity: equal=%t err=%v", first == linkFingerprint, err)
	}
}

func TestEscalationUseCasePlansMixedPinnedAlertWorkflows(t *testing.T) {
	fixture := newServiceFixture(t)
	secondWorkflowID, _ := entityID(mustUUIDv7(t))
	secondWorkflow, err := kernel.NewWorkflowDefinition(
		secondWorkflowID, kernel.AggregateAlert, 2,
		fixture.workflow.States(), fixture.workflow.Transitions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	secondAlertID := mustUUIDv7(t)
	secondAlertEntity, _ := entityID(secondAlertID)
	secondRecord := fixture.record
	secondRecord.Workflow = secondWorkflow
	secondRecord.Snapshot, err = kernel.NewTicketSnapshot(
		secondWorkflow, fixture.tenant, secondAlertEntity, secondWorkflow.InitialState(), 1, true, kernel.Assignment{},
	)
	if err != nil {
		t.Fatal(err)
	}
	secondRecord.Number = "ALT-000002"

	caseWorkflow := caseWorkflow(t)
	caseID := mustUUIDv7(t)
	caseEntity, _ := entityID(caseID)
	caseSnapshot, err := kernel.NewTicketSnapshot(
		caseWorkflow, fixture.tenant, caseEntity, caseWorkflow.InitialState(), 1, true, kernel.Assignment{},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.record.CreatedAt
	caseRecord := Record{
		Workflow: caseWorkflow, Snapshot: caseSnapshot, Number: "CASE-000001",
		Title: "Existing investigation", Description: "Investigation", Summary: "",
		Severity: "high", Priority: "urgent", Category: "security", Tags: []string{},
		CustomFields: map[string]any{}, CustomerCustomFields: map[string]any{},
		Creator: Creator{
			Kind: kernel.PrincipalOperator, ID: mustUUIDv7(t), UserID: &fixture.actor.UserID, DisplayName: "Operator",
		},
		DetectionTime: now, OpenedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator,
		records: map[uuid.UUID]Record{
			fixture.ticketUUID: fixture.record, secondAlertID: secondRecord, caseID: caseRecord,
		},
	}
	service := mustService(t, repository)
	input := EscalationInput{
		PathAlertID: fixture.ticketUUID, ExpectedVersion: 1, Relation: "escalation",
		Reason: "Correlated alerts", IdempotencyKey: "mixed-service-escalation-0001",
		Sources: []EscalationSourceInput{
			{AlertID: secondAlertID, ExpectedVersion: 1, Selection: CopySelection{ItemIDs: map[kernel.CopyField][]uuid.UUID{}}},
			{AlertID: fixture.ticketUUID, ExpectedVersion: 1, Selection: CopySelection{ItemIDs: map[kernel.CopyField][]uuid.UUID{}}},
		},
		Target: EscalationTargetInput{ExistingCaseID: &caseID, ExistingCaseVersion: 1},
	}

	_, err = service.Escalate(context.Background(), fixture.actor, fixture.tenantUUID, input)
	if !errors.Is(err, ErrUnavailable) || repository.escalationCommitCalls.Load() != 1 {
		t.Fatalf("Escalate(mixed workflows) error=%v commits=%d, want repository commit attempt", err, repository.escalationCommitCalls.Load())
	}
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	if repository.escalationReplayQuery.Operation != EscalationOperationEscalate ||
		repository.escalationWrite.Operation != EscalationOperationEscalate {
		t.Fatalf("Escalate persistence operations = (%q,%q), want escalation namespace",
			repository.escalationReplayQuery.Operation, repository.escalationWrite.Operation)
	}
}

func TestEscalationSelectionCapabilitiesAreExactAndDeterministic(t *testing.T) {
	t.Parallel()

	sources := []EscalationSourceInput{
		{Selection: CopySelection{ItemIDs: map[kernel.CopyField][]uuid.UUID{
			kernel.CopyAttachments: {mustUUIDv7(t)},
			kernel.CopyContacts:    {mustUUIDv7(t)},
			kernel.CopyIOCs:        {mustUUIDv7(t)},
		}}},
		{Selection: CopySelection{ItemIDs: map[kernel.CopyField][]uuid.UUID{
			kernel.CopyAssets: {mustUUIDv7(t)},
			kernel.CopyIOCs:   {},
		}}},
	}
	want := []Capability{
		CapabilityDFIRIOCRead,
		CapabilityDFIRAssetRead,
		CapabilityDFIRAttachmentRead,
	}
	got := escalationSelectionCapabilities(sources)
	if len(got) != len(want) {
		t.Fatalf("selection capabilities = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("selection capabilities = %v, want %v", got, want)
		}
	}
}

func TestEscalationRequiresDFIRReadBeforeLoadingSourceRows(t *testing.T) {
	t.Parallel()

	fixture := newServiceFixture(t)
	iocID := mustUUIDv7(t)
	caseID := mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture,
		accessErrors: map[Capability]error{
			CapabilityDFIRIOCRead: ErrForbidden,
		},
	}
	service := mustService(t, repository)
	_, err := service.Escalate(
		context.Background(),
		fixture.actor,
		fixture.tenantUUID,
		EscalationInput{
			PathAlertID: fixture.ticketUUID, ExpectedVersion: 1,
			Relation: "escalation", Reason: "Selected IOC", IdempotencyKey: "dfir-read-gate-0001",
			Sources: []EscalationSourceInput{{
				AlertID: fixture.ticketUUID, ExpectedVersion: 1,
				Selection: CopySelection{
					Fields:  []kernel.CopyField{kernel.CopyIOCs},
					ItemIDs: map[kernel.CopyField][]uuid.UUID{kernel.CopyIOCs: {iocID}},
				},
			}},
			Target: EscalationTargetInput{ExistingCaseID: &caseID, ExistingCaseVersion: 1},
		},
	)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Escalate() error = %v, want forbidden", err)
	}
	if repository.getCalls.Load() != 0 || repository.escalationCommitCalls.Load() != 0 {
		t.Fatalf(
			"Escalate() loaded or committed before DFIR authorization: get=%d commit=%d",
			repository.getCalls.Load(),
			repository.escalationCommitCalls.Load(),
		)
	}
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	if len(repository.accessCalls) != 2 ||
		repository.accessCalls[0] != CapabilityAlertEscalate ||
		repository.accessCalls[1] != CapabilityDFIRIOCRead {
		t.Fatalf("access calls = %v", repository.accessCalls)
	}
}

func TestLinkRejectsCreateCaseBeforeRepositoryAccess(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture}
	service := mustService(t, repository)
	_, err := service.Link(context.Background(), fixture.actor, fixture.tenantUUID, EscalationInput{
		PathAlertID: fixture.ticketUUID, ExpectedVersion: 1,
		Relation: "escalation", Reason: "Existing Case only",
		IdempotencyKey: "explicit-link-create-case-0001",
		Sources: []EscalationSourceInput{{
			AlertID: fixture.ticketUUID, ExpectedVersion: 1,
			Selection: CopySelection{ItemIDs: map[kernel.CopyField][]uuid.UUID{}},
		}},
		Target: EscalationTargetInput{NewCase: &CreateCaseInput{
			Title: "Must not be created", Severity: "high", Priority: "urgent",
		}},
	})
	if !errors.Is(err, ErrInvalidInput) || repository.getCalls.Load() != 0 ||
		repository.escalationCommitCalls.Load() != 0 {
		t.Fatalf("Link(create Case) error=%v gets=%d commits=%d", err, repository.getCalls.Load(), repository.escalationCommitCalls.Load())
	}
}

func TestLinkUsesIndependentReplayAndCommitNamespace(t *testing.T) {
	fixture := newServiceFixture(t)
	caseID := mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture,
		records: map[uuid.UUID]Record{
			fixture.ticketUUID: fixture.record,
			caseID:             unlinkCaseRecord(t, fixture, caseID, 3),
		},
	}
	service := mustService(t, repository)
	_, err := service.Link(context.Background(), fixture.actor, fixture.tenantUUID, EscalationInput{
		PathAlertID: fixture.ticketUUID, ExpectedVersion: 1,
		Relation: "correlation", Reason: "Explicit existing Case link",
		IdempotencyKey: "explicit-link-operation-0001",
		Sources: []EscalationSourceInput{{
			AlertID: fixture.ticketUUID, ExpectedVersion: 1,
			Selection: CopySelection{ItemIDs: map[kernel.CopyField][]uuid.UUID{}},
		}},
		Target: EscalationTargetInput{ExistingCaseID: &caseID, ExistingCaseVersion: 3},
	})
	if !errors.Is(err, ErrUnavailable) || repository.escalationCommitCalls.Load() != 1 {
		t.Fatalf("Link(existing Case) error=%v commits=%d, want repository commit attempt", err, repository.escalationCommitCalls.Load())
	}
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	if repository.escalationReplayQuery.Operation != EscalationOperationLink ||
		repository.escalationWrite.Operation != EscalationOperationLink {
		t.Fatalf("Link persistence operations = (%q,%q), want independent link namespace",
			repository.escalationReplayQuery.Operation, repository.escalationWrite.Operation)
	}
}

func TestUnlinkPlansBothAggregatesAndCommitsOneRetraction(t *testing.T) {
	fixture := newServiceFixture(t)
	caseID := mustUUIDv7(t)
	caseRecord := unlinkCaseRecord(t, fixture, caseID, 3)
	linkID := mustUUIDv7(t)
	retractedAt := time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC)
	repository := &fakeRepository{
		fixture: fixture,
		records: map[uuid.UUID]Record{
			fixture.ticketUUID: fixture.record,
			caseID:             caseRecord,
		},
		linkLifecycle: LinkLifecycle{LinkID: linkID},
		unlinkReceipt: UnlinkReceipt{
			TenantID: fixture.tenantUUID, AlertID: fixture.ticketUUID,
			CaseID: caseID, LinkID: linkID,
			PreviousAlertVersion: 1, AlertVersion: 2,
			PreviousCaseVersion: 3, CaseVersion: 4,
			RetractedAt: retractedAt,
		},
	}
	service := mustService(t, repository)
	receipt, err := service.Unlink(context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, UnlinkInput{
		CaseID: caseID, ExpectedVersion: 1, ExpectedCaseVersion: 3,
		Reason: "Relationship superseded", IdempotencyKey: "unlink-both-aggregates-0001",
	})
	if err != nil || receipt.LinkID != linkID || repository.unlinkCommitCalls.Load() != 1 {
		t.Fatalf("Unlink() receipt=%+v error=%v commits=%d", receipt, err, repository.unlinkCommitCalls.Load())
	}
	write := repository.unlinkWrite
	if write.AlertPlan.Action() != kernel.ActionEscalate || write.CasePlan.Action() != kernel.ActionLink ||
		write.AlertPlan.ExpectedVersion() != 1 || write.CasePlan.ExpectedVersion() != 3 ||
		!slices.Equal(write.Effects, []string{"activity", "audit", "sla"}) {
		t.Fatalf("Unlink() write plan drifted: %+v", write)
	}
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	if !slices.Equal(repository.accessCalls, []Capability{CapabilityAlertEscalate, CapabilityCaseUpdate}) {
		t.Fatalf("Unlink() access calls=%v", repository.accessCalls)
	}
}

func TestUnlinkExactReplayDoesNotReloadOrRewrite(t *testing.T) {
	fixture := newServiceFixture(t)
	caseID, linkID := mustUUIDv7(t), mustUUIDv7(t)
	replay := UnlinkReceipt{
		TenantID: fixture.tenantUUID, AlertID: fixture.ticketUUID,
		CaseID: caseID, LinkID: linkID,
		PreviousAlertVersion: 4, AlertVersion: 5,
		PreviousCaseVersion: 8, CaseVersion: 9,
		RetractedAt: time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC),
	}
	repository := &fakeRepository{
		fixture: fixture, unlinkReplay: replay, unlinkReplayFound: true,
	}
	service := mustService(t, repository)
	receipt, err := service.Unlink(context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, UnlinkInput{
		CaseID: caseID, ExpectedVersion: 4, ExpectedCaseVersion: 8,
		Reason: "Relationship superseded", IdempotencyKey: "unlink-exact-replay-0001",
	})
	if err != nil || !receipt.Replayed || repository.getCalls.Load() != 0 ||
		repository.unlinkCommitCalls.Load() != 0 {
		t.Fatalf("Unlink(replay) receipt=%+v error=%v gets=%d commits=%d", receipt, err, repository.getCalls.Load(), repository.unlinkCommitCalls.Load())
	}
}

func TestUnlinkFailsClosedForStaleOrRetractedPair(t *testing.T) {
	fixture := newServiceFixture(t)
	caseID, linkID := mustUUIDv7(t), mustUUIDv7(t)
	for _, test := range []struct {
		name      string
		caseVer   uint64
		retracted bool
		want      error
	}{
		{name: "stale Case", caseVer: 4, want: ErrPreconditionFailed},
		{name: "terminal retraction", caseVer: 3, retracted: true, want: ErrConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{
				fixture: fixture,
				records: map[uuid.UUID]Record{
					fixture.ticketUUID: fixture.record,
					caseID:             unlinkCaseRecord(t, fixture, caseID, test.caseVer),
				},
				linkLifecycle: LinkLifecycle{LinkID: linkID, Retracted: test.retracted},
			}
			service := mustService(t, repository)
			_, err := service.Unlink(context.Background(), fixture.actor, fixture.tenantUUID, fixture.ticketUUID, UnlinkInput{
				CaseID: caseID, ExpectedVersion: 1, ExpectedCaseVersion: 3,
				Reason: "Relationship superseded", IdempotencyKey: "unlink-fail-closed-0001",
			})
			if !errors.Is(err, test.want) || repository.unlinkCommitCalls.Load() != 0 {
				t.Fatalf("Unlink() error=%v commits=%d, want %v", err, repository.unlinkCommitCalls.Load(), test.want)
			}
		})
	}
}

func TestUnlinkFingerprintBindsBothVersionsPairAndReason(t *testing.T) {
	fixture := newServiceFixture(t)
	base := UnlinkInput{
		CaseID: mustUUIDv7(t), ExpectedVersion: 2, ExpectedCaseVersion: 5,
		Reason: "Original reason", IdempotencyKey: "unlink-fingerprint-0001",
	}
	first, err := unlinkFingerprint(fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID, base)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*UnlinkInput){
		"case":          func(value *UnlinkInput) { value.CaseID = mustUUIDv7(t) },
		"alert version": func(value *UnlinkInput) { value.ExpectedVersion++ },
		"case version":  func(value *UnlinkInput) { value.ExpectedCaseVersion++ },
		"reason":        func(value *UnlinkInput) { value.Reason = "Different reason" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			next, nextErr := unlinkFingerprint(fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID, changed)
			if nextErr != nil || next == first {
				t.Fatalf("fingerprint did not bind %s: equal=%t error=%v", name, next == first, nextErr)
			}
		})
	}
}

func TestReadRejectsServicePrincipalAndRepositoryScopeLeakage(t *testing.T) {
	fixture := newServiceFixture(t)
	tests := []struct {
		name      string
		principal kernel.PrincipalKind
		scopes    []Scope
		creator   uuid.UUID
		want      error
		getCalls  int32
	}{
		{name: "service principal", principal: kernel.PrincipalServiceAccount, scopes: []Scope{ScopeTenant}, creator: fixture.actor.UserID, want: ErrForbidden},
		{name: "own scope leakage", principal: kernel.PrincipalOperator, scopes: []Scope{ScopeOwn}, creator: mustUUIDv7(t), want: ErrUnavailable, getCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := fixture.record
			record.Creator.UserID = &test.creator
			repository := &fakeRepository{fixture: fixture, principal: test.principal, scopes: test.scopes, record: record}
			service := mustService(t, repository)
			_, err := service.Get(context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID)
			if !errors.Is(err, test.want) {
				t.Fatalf("Get() error = %v, want %v", err, test.want)
			}
			if got := repository.getCalls.Load(); got != test.getCalls {
				t.Fatalf("repository get calls = %d, want %d", got, test.getCalls)
			}
		})
	}
}

func TestClaimWithoutTeamIsDeterministicOrRejected(t *testing.T) {
	fixture := newServiceFixture(t)
	secondTeamUUID := mustUUIDv7(t)
	secondTeam, _ := entityID(secondTeamUUID)
	tests := []struct {
		name       string
		assignment kernel.Assignment
		teams      []kernel.EntityID
		wantErr    error
		wantTeam   kernel.EntityID
	}{
		{name: "one eligible team", teams: []kernel.EntityID{fixture.team}, wantTeam: fixture.team},
		{name: "ambiguous unassigned", teams: []kernel.EntityID{fixture.team, secondTeam}, wantErr: ErrInvalidInput},
		{name: "existing team wins", assignment: mustAssignment(t, fixture.team, nil, nil), teams: []kernel.EntityID{fixture.team, secondTeam}, wantTeam: fixture.team},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record := fixture.record
			record.Snapshot = mustSnapshot(t, fixture.workflow, fixture.tenant, fixture.ticket, true, test.assignment, 1)
			repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: record, claimableTeams: test.teams}
			service := mustService(t, repository)
			result, err := service.Mutate(
				context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
				fixture.ticketUUID, kernel.ActionClaim, MutationInput{ExpectedVersion: 1},
			)
			if test.wantErr != nil {
				if !errors.Is(err, test.wantErr) || repository.applyCalls.Load() != 0 {
					t.Fatalf("Mutate() = (%v, %v), apply=%d, want %v before write", result, err, repository.applyCalls.Load(), test.wantErr)
				}
				return
			}
			if err != nil || result.ClaimWinner == nil {
				t.Fatalf("Mutate() = (%v, %v), want persisted claim", result, err)
			}
			team, present := result.View.Record.Snapshot.Assignment().Team()
			if !present || team != test.wantTeam {
				t.Fatalf("claim team = (%v,%t), want %v", team, present, test.wantTeam)
			}
		})
	}
}

func TestTransitionKeyAndTargetMismatchNeverReachRepository(t *testing.T) {
	fixture := newServiceFixture(t)
	repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record}
	service := mustService(t, repository)

	_, err := service.Mutate(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
		kernel.ActionTransition,
		MutationInput{
			ExpectedVersion: 1, TransitionKey: "close_alert", TargetStateKey: "new",
			IdempotencyKey: "transition-key-0001", CustomFields: map[string]any{},
		},
	)
	if !errors.Is(err, ErrConflict) || repository.applyCalls.Load() != 0 {
		t.Fatalf("Mutate() error = %v, writes = %d, want fail-closed conflict", err, repository.applyCalls.Load())
	}
}

func TestExplicitCloseAndReopenIntentIsEnforcedBeforeCommit(t *testing.T) {
	tests := []struct {
		name       string
		state      string
		version    uint64
		transition string
		target     string
		intent     kernel.TransitionIntent
		wantState  string
	}{
		{name: "close", state: "new", version: 1, transition: "close_alert", target: "closed", intent: kernel.TransitionIntentClose, wantState: "closed"},
		{name: "reopen", state: "closed", version: 2, transition: "reopen_alert", target: "new", intent: kernel.TransitionIntentReopen, wantState: "new"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			state, _ := kernel.NewKey(test.state)
			snapshot, err := kernel.NewTicketSnapshot(
				fixture.workflow, fixture.tenant, fixture.ticket, state, test.version, true, kernel.Assignment{},
			)
			if err != nil {
				t.Fatal(err)
			}
			record := fixture.record
			record.Snapshot = snapshot
			repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: record}
			service := mustService(t, repository)

			result, err := service.Mutate(
				context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
				kernel.ActionTransition, MutationInput{
					ExpectedVersion: test.version, TransitionIntent: test.intent, TransitionKey: test.transition,
					TargetStateKey: test.target, IdempotencyKey: "explicit-transition-0001", CustomFields: map[string]any{},
				},
			)
			if err != nil || result.View.Record.Snapshot.State().String() != test.wantState ||
				repository.applyCalls.Load() != 1 || len(repository.accessCalls) != 1 ||
				repository.accessCalls[0] != CapabilityAlertUpdate {
				t.Fatalf("Mutate(%s)=(%+v,%v), writes=%d access=%v", test.name, result, err, repository.applyCalls.Load(), repository.accessCalls)
			}
		})
	}
}

func TestExplicitTransitionIntentMismatchNeverReachesRepository(t *testing.T) {
	tests := []struct {
		name       string
		state      string
		version    uint64
		transition string
		target     string
		intent     kernel.TransitionIntent
		wantErr    error
	}{
		{name: "close cannot reopen", state: "closed", version: 2, transition: "reopen_alert", target: "new", intent: kernel.TransitionIntentClose, wantErr: ErrConflict},
		{name: "reopen cannot close", state: "new", version: 1, transition: "close_alert", target: "closed", intent: kernel.TransitionIntentReopen, wantErr: ErrConflict},
		{name: "unknown intent", state: "new", version: 1, transition: "close_alert", target: "closed", intent: kernel.TransitionIntent("unknown"), wantErr: ErrInvalidInput},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			state, _ := kernel.NewKey(test.state)
			snapshot, err := kernel.NewTicketSnapshot(
				fixture.workflow, fixture.tenant, fixture.ticket, state, test.version, true, kernel.Assignment{},
			)
			if err != nil {
				t.Fatal(err)
			}
			record := fixture.record
			record.Snapshot = snapshot
			repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator, record: record}
			service := mustService(t, repository)

			_, err = service.Mutate(
				context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, fixture.ticketUUID,
				kernel.ActionTransition, MutationInput{
					ExpectedVersion: test.version, TransitionIntent: test.intent, TransitionKey: test.transition,
					TargetStateKey: test.target, IdempotencyKey: "explicit-transition-0002", CustomFields: map[string]any{},
				},
			)
			if !errors.Is(err, test.wantErr) || repository.applyCalls.Load() != 0 {
				t.Fatalf("Mutate(%s) error=%v writes=%d, want %v before write", test.name, err, repository.applyCalls.Load(), test.wantErr)
			}
		})
	}
}

func TestExplicitTransitionIntentCannotBypassLivePermissions(t *testing.T) {
	fixture := newServiceFixture(t)
	tests := []struct {
		name       string
		kind       kernel.AggregateKind
		intent     kernel.TransitionIntent
		capability Capability
	}{
		{name: "Alert close", kind: kernel.AggregateAlert, intent: kernel.TransitionIntentClose, capability: CapabilityAlertUpdate},
		{name: "Alert reopen", kind: kernel.AggregateAlert, intent: kernel.TransitionIntentReopen, capability: CapabilityAlertUpdate},
		{name: "Case close", kind: kernel.AggregateCase, intent: kernel.TransitionIntentClose, capability: CapabilityCaseTransition},
		{name: "Case reopen", kind: kernel.AggregateCase, intent: kernel.TransitionIntentReopen, capability: CapabilityCaseTransition},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &fakeRepository{
				fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
				accessErrors: map[Capability]error{test.capability: ErrForbidden},
			}
			service := mustService(t, repository)
			_, err := service.Mutate(
				context.Background(), fixture.actor, fixture.tenantUUID, test.kind, fixture.ticketUUID,
				kernel.ActionTransition, MutationInput{
					ExpectedVersion: 1, TransitionIntent: test.intent, TransitionKey: "close_alert",
					TargetStateKey: "closed", IdempotencyKey: "permission-transition-0001", CustomFields: map[string]any{},
				},
			)
			if !errors.Is(err, ErrForbidden) || repository.getCalls.Load() != 0 || repository.applyCalls.Load() != 0 ||
				len(repository.accessCalls) != 1 || repository.accessCalls[0] != test.capability {
				t.Fatalf("Mutate(%s) error=%v gets=%d writes=%d access=%v", test.name, err, repository.getCalls.Load(), repository.applyCalls.Load(), repository.accessCalls)
			}
		})
	}
}

func TestTransitionFingerprintDistinguishesExplicitRouteIntentWithoutChangingGenericReplay(t *testing.T) {
	tenantID := uuid.MustParse("00000000-0000-0000-0000-000000000001")
	actorID := uuid.MustParse("00000000-0000-0000-0000-000000000002")
	ticketID := uuid.MustParse("00000000-0000-0000-0000-000000000003")
	input := MutationInput{
		ExpectedVersion: 7, TransitionKey: "close_alert", TargetStateKey: "closed", Comment: "reason",
		CustomFields: map[string]any{"classification": "malware"},
	}
	generic, err := mutationFingerprint(tenantID, actorID, ticketID, kernel.AggregateAlert, kernel.ActionTransition, input)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := hex.DecodeString("0334928cd07200da9a483c955bb75d1b4a7e2b75805858cb18cf1cf0d0acf79f")
	if err != nil || !slices.Equal(generic[:], legacy) {
		t.Fatalf("generic fingerprint = %x, want historical %x", generic, legacy)
	}
	input.TransitionIntent = kernel.TransitionIntentClose
	closeFingerprint, err := mutationFingerprint(tenantID, actorID, ticketID, kernel.AggregateAlert, kernel.ActionTransition, input)
	if err != nil {
		t.Fatal(err)
	}
	input.TransitionIntent = kernel.TransitionIntentReopen
	reopenFingerprint, err := mutationFingerprint(tenantID, actorID, ticketID, kernel.AggregateAlert, kernel.ActionTransition, input)
	if err != nil {
		t.Fatal(err)
	}
	if generic == closeFingerprint || generic == reopenFingerprint || closeFingerprint == reopenFingerprint {
		t.Fatalf("route fingerprints collided: generic=%x close=%x reopen=%x", generic, closeFingerprint, reopenFingerprint)
	}
}

func TestTransitionExactReplayReturnsCurrentProjectionBeforeStalePlanning(t *testing.T) {
	fixture := newServiceFixture(t)
	closed, _ := kernel.NewKey("closed")
	current, err := kernel.NewTicketSnapshot(
		fixture.workflow, fixture.tenant, fixture.ticket, closed, 3, true, kernel.Assignment{},
	)
	if err != nil {
		t.Fatal(err)
	}
	record := fixture.record
	record.Snapshot = current
	record.UpdatedAt = record.UpdatedAt.Add(2 * time.Minute)
	input := MutationInput{
		ExpectedVersion: 1, TransitionKey: "close_alert", TargetStateKey: "closed",
		IdempotencyKey: "transition-key-0001", CustomFields: map[string]any{},
	}
	fingerprint, err := mutationFingerprint(
		fixture.tenantUUID, fixture.actor.UserID, fixture.ticketUUID,
		kernel.AggregateAlert, kernel.ActionTransition, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: record,
		replay: WriteResult{Record: record}, replayFound: true, replayFingerprint: &fingerprint,
	}
	service := mustService(t, repository)

	result, err := service.Mutate(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, kernel.ActionTransition, input,
	)
	if err != nil || !result.Replayed || result.View.Record.Snapshot.Version() != 3 || repository.applyCalls.Load() != 0 {
		t.Fatalf("Mutate(replay) = (%+v, %v), writes=%d", result, err, repository.applyCalls.Load())
	}

	input.TargetStateKey = "new"
	_, err = service.Mutate(
		context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert,
		fixture.ticketUUID, kernel.ActionTransition, input,
	)
	if !errors.Is(err, ErrConflict) || repository.applyCalls.Load() != 0 {
		t.Fatalf("Mutate(key reuse) error = %v, writes=%d, want conflict", err, repository.applyCalls.Load())
	}
}

func TestConcurrentClaimHasOnePersistedWinner(t *testing.T) {
	fixture := newServiceFixture(t)
	secondActor := fixture.actor
	secondActor.UserID = mustUUIDv7(t)
	repository := &fakeRepository{
		fixture: fixture, principal: kernel.PrincipalOperator, record: fixture.record,
		claimableTeams: []kernel.EntityID{fixture.team}, synchronizeGets: true,
	}
	service := mustService(t, repository)

	actors := []Actor{fixture.actor, secondActor}
	errorsByActor := make([]error, len(actors))
	results := make([]MutationResult, len(actors))
	var group sync.WaitGroup
	for index := range actors {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index], errorsByActor[index] = service.Mutate(
				context.Background(), actors[index], fixture.tenantUUID, kernel.AggregateAlert,
				fixture.ticketUUID, kernel.ActionClaim, MutationInput{ExpectedVersion: 1},
			)
		}(index)
	}
	group.Wait()

	winners := 0
	losers := 0
	for index, err := range errorsByActor {
		switch {
		case err == nil:
			winners++
			if results[index].ClaimWinner == nil || results[index].ClaimWinner.ClaimedBy != actors[index].UserID {
				t.Fatalf("actor %d returned a false claim winner: %+v", index, results[index].ClaimWinner)
			}
		case errors.Is(err, ErrConflict):
			losers++
		default:
			t.Fatalf("actor %d error = %v", index, err)
		}
	}
	if winners != 1 || losers != 1 || repository.applyCalls.Load() != 2 {
		t.Fatalf("winners=%d losers=%d writes=%d, want 1/1/2", winners, losers, repository.applyCalls.Load())
	}
}

func FuzzHostileTicketInputsDoNotReachListRepository(f *testing.F) {
	for _, seed := range []string{"", "%%%", "YWJj", "with=padding", "a,b", "\x00"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, cursor string) {
		fixture := newServiceFixture(t)
		repository := &fakeRepository{fixture: fixture, principal: kernel.PrincipalOperator}
		service := mustService(t, repository)
		_, err := service.List(context.Background(), fixture.actor, fixture.tenantUUID, kernel.AggregateAlert, ListInput{After: cursor, Limit: 1})
		if !validOpaqueCursor(cursor) && !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("cursor %q error = %v, want invalid input", cursor, err)
		}
	})
}

type serviceFixture struct {
	tenantUUID     uuid.UUID
	ticketUUID     uuid.UUID
	teamUUID       uuid.UUID
	actor          Actor
	membershipUUID uuid.UUID
	tenant         kernel.EntityID
	ticket         kernel.EntityID
	team           kernel.EntityID
	workflow       kernel.WorkflowDefinition
	record         Record
}

func newServiceFixture(t testing.TB) serviceFixture {
	t.Helper()
	tenantUUID := mustUUIDv7(t)
	ticketUUID := mustUUIDv7(t)
	teamUUID := mustUUIDv7(t)
	actorUUID := mustUUIDv7(t)
	membershipUUID := mustUUIDv7(t)
	tenant, _ := entityID(tenantUUID)
	ticket, _ := entityID(ticketUUID)
	team, _ := entityID(teamUUID)
	workflow := alertWorkflow(t)
	now := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	record := Record{
		Workflow: workflow, Snapshot: mustSnapshot(t, workflow, tenant, ticket, true, kernel.Assignment{}, 1),
		Number: "ALT-000001", Title: "Validated alert", Description: "Description", Severity: "high",
		Priority: "urgent", Category: "security", Source: "sensor", SourceType: "edr",
		Tags: []string{"endpoint", "malware"}, CustomFields: map[string]any{}, CustomerCustomFields: map[string]any{},
		Creator: Creator{
			Kind: kernel.PrincipalOperator, ID: membershipUUID, UserID: &actorUUID, DisplayName: "Operator",
		},
		DetectedAt: now.Add(-time.Minute), ReceivedAt: now, CreatedAt: now, UpdatedAt: now,
	}
	actor := Actor{
		UserID: actorUUID, SessionID: mustUUIDv7(t), ActiveTenantID: tenantUUID,
		AuthenticationMethod: "totp",
		Audit: AuditContext{
			RequestID: mustUUIDv7(t), CorrelationID: mustUUIDv7(t),
			RemoteAddress: netip.MustParseAddr("198.51.100.42"), UserAgent: "ticketing-test",
		},
	}
	return serviceFixture{
		tenantUUID: tenantUUID, ticketUUID: ticketUUID, teamUUID: teamUUID,
		actor: actor, membershipUUID: membershipUUID, tenant: tenant, ticket: ticket,
		team: team, workflow: workflow, record: record,
	}
}

func alertWorkflow(t testing.TB) kernel.WorkflowDefinition {
	t.Helper()
	effects, err := kernel.NewEffectPlan(kernel.EffectActivity, kernel.EffectAudit, kernel.EffectSLA, kernel.EffectNotification)
	if err != nil {
		t.Fatal(err)
	}
	actions := make([]kernel.StateAction, 0, 6)
	for _, action := range []kernel.Action{
		kernel.ActionCreate, kernel.ActionAssign, kernel.ActionClaim, kernel.ActionRelease,
		kernel.ActionTransfer, kernel.ActionEscalate,
	} {
		value, actionErr := kernel.NewStateAction(action, effects)
		if actionErr != nil {
			t.Fatal(actionErr)
		}
		actions = append(actions, value)
	}
	newKey, _ := kernel.NewKey("new")
	closedKey, _ := kernel.NewKey("closed")
	newState, _ := kernel.NewStateDefinition(newKey, true, false, kernel.VisibilityCustomer, actions)
	closedState, _ := kernel.NewStateDefinition(closedKey, false, true, kernel.VisibilityCustomer, nil)
	transitionKey, _ := kernel.NewKey("close_alert")
	transition, err := kernel.NewTransitionDefinition(transitionKey, newKey, closedKey, false, false, nil, nil, nil, effects)
	if err != nil {
		t.Fatal(err)
	}
	reopenKey, _ := kernel.NewKey("reopen_alert")
	reopen, err := kernel.NewTransitionDefinition(reopenKey, closedKey, newKey, false, true, nil, nil, nil, effects)
	if err != nil {
		t.Fatal(err)
	}
	workflowID, _ := entityID(mustUUIDv7(t))
	workflow, err := kernel.NewWorkflowDefinition(
		workflowID, kernel.AggregateAlert, 1, []kernel.StateDefinition{newState, closedState},
		[]kernel.TransitionDefinition{transition, reopen},
	)
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func conditionalAlertWorkflow(t testing.TB) kernel.WorkflowDefinition {
	t.Helper()
	effects, err := kernel.NewEffectPlan(
		kernel.EffectActivity, kernel.EffectAudit, kernel.EffectSLA, kernel.EffectNotification,
	)
	if err != nil {
		t.Fatal(err)
	}
	newKey, _ := kernel.NewKey("new")
	closedKey, _ := kernel.NewKey("closed")
	create, _ := kernel.NewStateAction(kernel.ActionCreate, effects)
	newState, _ := kernel.NewStateDefinition(
		newKey, true, false, kernel.VisibilityCustomer, []kernel.StateAction{create},
	)
	closedState, _ := kernel.NewStateDefinition(closedKey, false, true, kernel.VisibilityCustomer, nil)

	predicateNode := func(field string, operator kernel.ConditionOperator, values ...kernel.ConditionValue) kernel.ConditionNode {
		parsedField, fieldErr := kernel.NewConditionField(field)
		predicate, predicateErr := kernel.NewConditionPredicate(parsedField, operator, values...)
		node, nodeErr := kernel.NewPredicateConditionNode(predicate)
		if fieldErr != nil || predicateErr != nil || nodeErr != nil {
			t.Fatalf("condition predicate %s: %v / %v / %v", field, fieldErr, predicateErr, nodeErr)
		}
		return node
	}
	high, _ := kernel.NewTextConditionValue("high")
	minimumRisk, _ := kernel.NewNumberConditionValue(7)
	root, err := kernel.NewAllConditionNode(
		predicateNode("severity", kernel.ConditionEqual, high),
		predicateNode("custom.risk_score", kernel.ConditionGreaterThanOrEqual, minimumRisk),
		predicateNode("tag.endpoint", kernel.ConditionEqual, kernel.NewBooleanConditionValue(true)),
	)
	if err != nil {
		t.Fatal(err)
	}
	condition, err := kernel.NewCondition(root)
	if err != nil {
		t.Fatal(err)
	}
	transitionKey, _ := kernel.NewKey("close_alert")
	transition, err := kernel.NewConditionalTransitionDefinition(
		transitionKey, newKey, closedKey, false, false, nil, nil, nil, condition, effects,
	)
	if err != nil {
		t.Fatal(err)
	}
	workflowID, _ := entityID(mustUUIDv7(t))
	workflow, err := kernel.NewWorkflowDefinition(
		workflowID, kernel.AggregateAlert, 1,
		[]kernel.StateDefinition{newState, closedState}, []kernel.TransitionDefinition{transition},
	)
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func caseWorkflow(t testing.TB) kernel.WorkflowDefinition {
	t.Helper()
	effects, err := kernel.NewEffectPlan(kernel.EffectActivity, kernel.EffectAudit, kernel.EffectSLA, kernel.EffectNotification)
	if err != nil {
		t.Fatal(err)
	}
	openKey, _ := kernel.NewKey("open")
	closedKey, _ := kernel.NewKey("closed")
	actions := make([]kernel.StateAction, 0, 2)
	for _, action := range []kernel.Action{kernel.ActionCreate, kernel.ActionLink} {
		value, actionErr := kernel.NewStateAction(action, effects)
		if actionErr != nil {
			t.Fatal(actionErr)
		}
		actions = append(actions, value)
	}
	openState, _ := kernel.NewStateDefinition(openKey, true, false, kernel.VisibilityCustomer, actions)
	closedState, _ := kernel.NewStateDefinition(closedKey, false, true, kernel.VisibilityInternal, nil)
	closeKey, _ := kernel.NewKey("close_case")
	closeTransition, err := kernel.NewTransitionDefinition(
		closeKey, openKey, closedKey, false, false, nil, nil, nil, effects,
	)
	if err != nil {
		t.Fatal(err)
	}
	workflowID, _ := entityID(mustUUIDv7(t))
	workflow, err := kernel.NewWorkflowDefinition(
		workflowID, kernel.AggregateCase, 1,
		[]kernel.StateDefinition{openState, closedState}, []kernel.TransitionDefinition{closeTransition},
	)
	if err != nil {
		t.Fatal(err)
	}
	return workflow
}

func unlinkCaseRecord(t testing.TB, fixture serviceFixture, id uuid.UUID, version uint64) Record {
	t.Helper()
	workflow := caseWorkflow(t)
	caseEntity, _ := entityID(id)
	state, _ := kernel.NewKey("open")
	snapshot, err := kernel.NewTicketSnapshot(
		workflow, fixture.tenant, caseEntity, state, version, true, kernel.Assignment{},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := fixture.record.CreatedAt
	return Record{
		Workflow: workflow, Snapshot: snapshot, Number: "CASE-000001",
		Title: "Linked investigation", Summary: "Linked investigation",
		Description: "Investigation", Severity: "high", Priority: "urgent",
		Category: "security", Tags: []string{}, CustomFields: map[string]any{},
		CustomerCustomFields: map[string]any{},
		Creator: Creator{
			Kind: kernel.PrincipalOperator, ID: fixture.membershipUUID,
			UserID: &fixture.actor.UserID, DisplayName: "Operator",
		},
		DetectionTime: now, OpenedAt: now, CreatedAt: now, UpdatedAt: now,
	}
}

func mustSnapshot(t testing.TB, workflow kernel.WorkflowDefinition, tenant, ticket kernel.EntityID, visible bool, assignment kernel.Assignment, version uint64) kernel.TicketSnapshot {
	t.Helper()
	state, _ := kernel.NewKey("new")
	snapshot, err := kernel.NewTicketSnapshot(workflow, tenant, ticket, state, version, visible, assignment)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func mustAssignment(t testing.TB, team kernel.EntityID, assignee, claimant *kernel.EntityID) kernel.Assignment {
	t.Helper()
	value, err := kernel.NewAssignment(&team, assignee, claimant)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustUUIDv7(t testing.TB) uuid.UUID {
	t.Helper()
	value, err := uuid.NewV7()
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func mustService(t testing.TB, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository, func() time.Time {
		return time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC)
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fakeRepository struct {
	fixture                      serviceFixture
	principal                    kernel.PrincipalKind
	scopes                       []Scope
	claimableTeams               []kernel.EntityID
	operatorTeams                []kernel.EntityID
	permissions                  []kernel.Permission
	customerContactID            *kernel.EntityID
	record                       Record
	records                      map[uuid.UUID]Record
	list                         RecordPage
	comments                     StoredCommentPage
	commentPreview               StoredCommentPreview
	commentCandidates            []CommentMentionCandidate
	commentRevisions             StoredCommentRevisionPage
	activityFeed                 StoredActivityPage
	activityFeedErr              error
	activityFeedKind             kernel.AggregateKind
	activityFeedPage             CursorPageInput
	commentPreflight             CommentEditPreflight
	commentPreflightErr          error
	commentCreate                CommentWriteResult
	commentCreateErr             error
	commentEdit                  CommentWriteResult
	commentEditErr               error
	export                       CustomerPortalExport
	synchronizeGets              bool
	getGate                      chan struct{}
	mutex                        sync.Mutex
	getCount                     int
	getCalls                     atomic.Int32
	listCalls                    atomic.Int32
	applyCalls                   atomic.Int32
	metadataCalls                atomic.Int32
	watcherListCalls             atomic.Int32
	watcherMutationCalls         atomic.Int32
	commentCreateCalls           atomic.Int32
	commentPreviewCalls          atomic.Int32
	commentPreflightCalls        atomic.Int32
	commentEditCalls             atomic.Int32
	exportCalls                  atomic.Int32
	activityFeedCalls            atomic.Int32
	escalationCommitCalls        atomic.Int32
	escalationWrite              EscalationWrite
	escalationReplayQuery        EscalationReplayQuery
	linkLifecycle                LinkLifecycle
	linkLifecycleErr             error
	unlinkCommitCalls            atomic.Int32
	unlinkReceipt                UnlinkReceipt
	unlinkErr                    error
	unlinkWrite                  UnlinkWrite
	unlinkReplay                 UnlinkReceipt
	unlinkReplayFound            bool
	unlinkReplayErr              error
	alertRelationPage            StoredAlertRelationPage
	alertRelationRecord          AlertRelationRecord
	alertRelationReceipt         AlertRelationMutationReceipt
	alertRelationReplay          AlertRelationMutationReceipt
	alertRelationFound           bool
	alertRelationErr             error
	alertRelationCreates         atomic.Int32
	alertRelationRetracts        atomic.Int32
	alertRelationCreateWrite     AlertRelationCreateWrite
	alertRelationRetractionWrite AlertRelationRetractionWrite
	deleteCalls                  atomic.Int32
	deleteReceipt                DeleteAlertReceipt
	deleteErr                    error
	deleteWrite                  DeleteAlertWrite
	deleteReplay                 DeleteAlertReceipt
	deleteReplayFound            bool
	deleteReplayErr              error
	replay                       WriteResult
	replayFound                  bool
	replayFingerprint            *[32]byte
	replaceMetadata              func(context.Context, MetadataWrite) (MetadataMutationResult, error)
	listWatchers                 func(context.Context, WatcherListQuery) (TicketWatcherProjection, error)
	mutateWatcher                func(context.Context, WatcherMutationWrite) (WatcherMutationResult, error)
	accessErrors                 map[Capability]error
	accessCalls                  []Capability
}

func (repository *fakeRepository) ResolveAccess(_ context.Context, actor Actor, _ uuid.UUID, capability Capability) (LiveAccess, error) {
	repository.mutex.Lock()
	repository.accessCalls = append(repository.accessCalls, capability)
	accessErr := repository.accessErrors[capability]
	repository.mutex.Unlock()
	if accessErr != nil {
		return LiveAccess{}, accessErr
	}
	principal := repository.principal
	if principal == 0 {
		principal = kernel.PrincipalOperator
	}
	scopes := repository.scopes
	if scopes == nil {
		scopes = []Scope{ScopeTenant}
	}
	actorID, _ := entityID(actor.UserID)
	permissions := repository.permissions
	if permissions == nil {
		permissions = []kernel.Permission{
			kernel.PermissionAlertCreate, kernel.PermissionAlertRead, kernel.PermissionAlertUpdate, kernel.PermissionAlertAssign,
			kernel.PermissionAlertClaim, kernel.PermissionAlertEscalate, kernel.PermissionAlertCommentPublic,
			kernel.PermissionAlertCommentPrivate, kernel.PermissionCaseCreate, kernel.PermissionCaseUpdate,
			kernel.PermissionCaseClaim, kernel.PermissionCaseTransfer, kernel.PermissionCaseTransition,
			kernel.PermissionCaseCommentPublic, kernel.PermissionCaseCommentPrivate,
		}
	}
	claimable := repository.claimableTeams
	if claimable == nil {
		claimable = []kernel.EntityID{repository.fixture.team}
	}
	manageable := []kernel.EntityID{repository.fixture.team}
	roster := make([]kernel.RosterPair, 0, len(claimable))
	for _, team := range claimable {
		pair, pairErr := kernel.NewRosterPair(team, actorID)
		if pairErr != nil {
			return LiveAccess{}, pairErr
		}
		roster = append(roster, pair)
	}
	authority, err := kernel.NewAuthorizationSnapshot(
		repository.fixture.tenant, actorID, principal, true, nil, permissions,
		claimable, manageable, roster,
	)
	if err != nil {
		return LiveAccess{}, err
	}
	operatorTeams := repository.operatorTeams
	if operatorTeams == nil {
		operatorTeams = claimable
	}
	contactID := repository.customerContactID
	if principal == kernel.PrincipalCustomer && contactID == nil {
		value := actorID
		contactID = &value
	}
	membershipID, _ := entityID(repository.fixture.membershipUUID)
	return LiveAccess{
		Authority: authority, Scopes: scopes, OperatorTeams: operatorTeams,
		MembershipID: membershipID, CustomerContactID: contactID,
	}, nil
}

func (repository *fakeRepository) Workflow(context.Context, uuid.UUID, uuid.UUID, kernel.AggregateKind, *uuid.UUID) (kernel.WorkflowDefinition, error) {
	return repository.fixture.workflow, nil
}

func (repository *fakeRepository) ReserveID(context.Context, uuid.UUID) (kernel.EntityID, error) {
	value, err := uuid.NewV7()
	if err != nil {
		return kernel.EntityID{}, err
	}
	return entityID(value)
}

func (repository *fakeRepository) List(context.Context, uuid.UUID, kernel.AggregateKind, ListInput, LiveAccess) (RecordPage, error) {
	repository.listCalls.Add(1)
	return repository.list, nil
}

func (repository *fakeRepository) Get(_ context.Context, _ uuid.UUID, _ uuid.UUID, _ kernel.AggregateKind, id uuid.UUID) (Record, error) {
	repository.getCalls.Add(1)
	if repository.records != nil {
		record, exists := repository.records[id]
		if !exists {
			return Record{}, ErrNotFound
		}
		return record, nil
	}
	repository.mutex.Lock()
	if repository.record.Snapshot.Version() == 0 {
		repository.record = repository.fixture.record
	}
	record := repository.record
	if repository.synchronizeGets {
		if repository.getGate == nil {
			repository.getGate = make(chan struct{})
		}
		repository.getCount++
		gate := repository.getGate
		if repository.getCount == 2 {
			close(gate)
		}
		repository.mutex.Unlock()
		<-gate
		return record, nil
	}
	repository.mutex.Unlock()
	return record, nil
}

func (repository *fakeRepository) GetForAccess(ctx context.Context, tenantID uuid.UUID, kind kernel.AggregateKind, id uuid.UUID, _ LiveAccess) (Record, error) {
	return repository.Get(ctx, uuid.Nil, tenantID, kind, id)
}

func (repository *fakeRepository) CreateCase(context.Context, CreateCaseWrite) (WriteResult, error) {
	return WriteResult{}, ErrUnavailable
}

func (repository *fakeRepository) ApplyMutation(_ context.Context, write MutationWrite) (WriteResult, error) {
	repository.applyCalls.Add(1)
	repository.mutex.Lock()
	defer repository.mutex.Unlock()
	if repository.record.Snapshot.Version() != write.Plan.ExpectedVersion() {
		return WriteResult{}, ErrConflict
	}
	next, err := kernel.ApplyMutationPlan(repository.record.Workflow, repository.record.Snapshot, write.Plan)
	if err != nil {
		return WriteResult{}, err
	}
	repository.record.Snapshot = next
	if write.Plan.Action() == kernel.ActionClaim {
		claimedAt := time.Date(2026, 8, 25, 10, 0, 1, 0, time.UTC)
		repository.record.ClaimedAt = &claimedAt
	}
	repository.record.UpdatedAt = repository.record.UpdatedAt.Add(time.Second)
	return WriteResult{Record: repository.record}, nil
}

func (repository *fakeRepository) LookupMutationReplay(_ context.Context, query MutationReplayQuery) (WriteResult, bool, error) {
	if repository.replayFingerprint != nil && query.Fingerprint != *repository.replayFingerprint {
		return WriteResult{}, false, ErrConflict
	}
	return repository.replay, repository.replayFound, nil
}

func (repository *fakeRepository) ReplaceMetadata(ctx context.Context, write MetadataWrite) (MetadataMutationResult, error) {
	repository.metadataCalls.Add(1)
	if repository.replaceMetadata == nil {
		return MetadataMutationResult{}, ErrUnavailable
	}
	return repository.replaceMetadata(ctx, write)
}

func (repository *fakeRepository) ListWatchers(ctx context.Context, query WatcherListQuery) (TicketWatcherProjection, error) {
	repository.watcherListCalls.Add(1)
	if repository.listWatchers == nil {
		return TicketWatcherProjection{}, ErrUnavailable
	}
	return repository.listWatchers(ctx, query)
}

func (repository *fakeRepository) MutateWatcher(ctx context.Context, write WatcherMutationWrite) (WatcherMutationResult, error) {
	repository.watcherMutationCalls.Add(1)
	if repository.mutateWatcher == nil {
		return WatcherMutationResult{}, ErrUnavailable
	}
	return repository.mutateWatcher(ctx, write)
}

func (repository *fakeRepository) DeleteAlert(_ context.Context, write DeleteAlertWrite) (DeleteAlertReceipt, error) {
	repository.deleteCalls.Add(1)
	repository.mutex.Lock()
	repository.deleteWrite = write
	repository.mutex.Unlock()
	return repository.deleteReceipt, repository.deleteErr
}

func (repository *fakeRepository) LookupAlertDeleteReplay(context.Context, DeleteAlertReplayQuery) (DeleteAlertReceipt, bool, error) {
	return repository.deleteReplay, repository.deleteReplayFound, repository.deleteReplayErr
}

func (repository *fakeRepository) ListComments(context.Context, Record, CursorPageInput, LiveAccess) (StoredCommentPage, error) {
	return repository.comments, nil
}

func (repository *fakeRepository) PreviewComment(context.Context, CommentPreviewQuery) (StoredCommentPreview, error) {
	repository.commentPreviewCalls.Add(1)
	return repository.commentPreview, nil
}

func (repository *fakeRepository) ListCommentMentionCandidates(context.Context, CommentMentionCandidateQuery) ([]CommentMentionCandidate, error) {
	return slices.Clone(repository.commentCandidates), nil
}

func (repository *fakeRepository) ExportPortal(context.Context, uuid.UUID, kernel.AggregateKind, uuid.UUID, LiveAccess, int) (CustomerPortalExport, error) {
	repository.exportCalls.Add(1)
	return repository.export, nil
}

func (repository *fakeRepository) CreateComment(context.Context, CommentWrite) (CommentWriteResult, error) {
	repository.commentCreateCalls.Add(1)
	return repository.commentCreate, repository.commentCreateErr
}

func (repository *fakeRepository) PreflightCommentEdit(context.Context, CommentEditWrite) (CommentEditPreflight, error) {
	repository.commentPreflightCalls.Add(1)
	return repository.commentPreflight, repository.commentPreflightErr
}

func (repository *fakeRepository) EditComment(context.Context, CommentEditWrite) (CommentWriteResult, error) {
	repository.commentEditCalls.Add(1)
	return repository.commentEdit, repository.commentEditErr
}

func (repository *fakeRepository) ListCommentRevisions(context.Context, CommentRevisionQuery) (StoredCommentRevisionPage, error) {
	return repository.commentRevisions, nil
}

func (repository *fakeRepository) ListActivities(context.Context, Record, CursorPageInput, LiveAccess) (StoredActivityPage, error) {
	return StoredActivityPage{}, ErrUnavailable
}

func (repository *fakeRepository) ListActivityFeed(_ context.Context, _ uuid.UUID, kind kernel.AggregateKind, page CursorPageInput, _ LiveAccess) (StoredActivityPage, error) {
	repository.activityFeedCalls.Add(1)
	repository.activityFeedKind = kind
	repository.activityFeedPage = page
	return repository.activityFeed, repository.activityFeedErr
}

func (repository *fakeRepository) ListLinks(context.Context, Record, CursorPageInput, LiveAccess, LiveAccess) (StoredLinkPage, error) {
	return StoredLinkPage{}, ErrUnavailable
}

func (repository *fakeRepository) ResolveLinkLifecycle(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID) (LinkLifecycle, error) {
	return repository.linkLifecycle, repository.linkLifecycleErr
}

func (repository *fakeRepository) ResolveEscalationSelection(context.Context, uuid.UUID, Record, CopySelection) (SelectionEvidence, error) {
	return SelectionEvidence{}, nil
}

func (repository *fakeRepository) CommitEscalation(_ context.Context, write EscalationWrite) (EscalationWriteResult, error) {
	repository.escalationCommitCalls.Add(1)
	repository.mutex.Lock()
	repository.escalationWrite = write
	repository.mutex.Unlock()
	return EscalationWriteResult{}, ErrUnavailable
}

func (repository *fakeRepository) LookupEscalationReplay(_ context.Context, query EscalationReplayQuery) (EscalationWriteResult, bool, error) {
	repository.mutex.Lock()
	repository.escalationReplayQuery = query
	repository.mutex.Unlock()
	return EscalationWriteResult{}, false, nil
}

func (repository *fakeRepository) CommitUnlink(_ context.Context, write UnlinkWrite) (UnlinkReceipt, error) {
	repository.unlinkCommitCalls.Add(1)
	repository.mutex.Lock()
	repository.unlinkWrite = write
	repository.mutex.Unlock()
	return repository.unlinkReceipt, repository.unlinkErr
}

func (repository *fakeRepository) LookupUnlinkReplay(context.Context, UnlinkReplayQuery) (UnlinkReceipt, bool, error) {
	return repository.unlinkReplay, repository.unlinkReplayFound, repository.unlinkReplayErr
}

func (repository *fakeRepository) ListAlertRelations(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, CursorPageInput, LiveAccess) (StoredAlertRelationPage, error) {
	return repository.alertRelationPage, repository.alertRelationErr
}

func (repository *fakeRepository) GetAlertRelation(context.Context, uuid.UUID, uuid.UUID, uuid.UUID, uuid.UUID, LiveAccess) (AlertRelationRecord, error) {
	return repository.alertRelationRecord, repository.alertRelationErr
}

func (repository *fakeRepository) CommitAlertRelationCreate(_ context.Context, write AlertRelationCreateWrite) (AlertRelationMutationReceipt, error) {
	repository.alertRelationCreates.Add(1)
	repository.alertRelationCreateWrite = write
	return repository.alertRelationReceipt, repository.alertRelationErr
}

func (repository *fakeRepository) LookupAlertRelationCreateReplay(context.Context, AlertRelationReplayQuery) (AlertRelationMutationReceipt, bool, error) {
	return repository.alertRelationReplay, repository.alertRelationFound, repository.alertRelationErr
}

func (repository *fakeRepository) CommitAlertRelationRetraction(_ context.Context, write AlertRelationRetractionWrite) (AlertRelationMutationReceipt, error) {
	repository.alertRelationRetracts.Add(1)
	repository.alertRelationRetractionWrite = write
	return repository.alertRelationReceipt, repository.alertRelationErr
}

func (repository *fakeRepository) LookupAlertRelationRetractionReplay(context.Context, AlertRelationReplayQuery) (AlertRelationMutationReceipt, bool, error) {
	return repository.alertRelationReplay, repository.alertRelationFound, repository.alertRelationErr
}
