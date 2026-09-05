package notificationinbox

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	testNow          = time.Date(2026, 9, 2, 18, 0, 0, 0, time.UTC)
	testTenantID     = testUUID("018f0000-0001-7000-8000-000000000001")
	testOtherTenant  = testUUID("018f0000-0001-7000-8000-000000000002")
	testUserID       = testUUID("018f0000-0002-7000-8000-000000000001")
	testOtherUser    = testUUID("018f0000-0002-7000-8000-000000000002")
	testSessionID    = testUUID("018f0000-0003-7000-8000-000000000001")
	testOtherSession = testUUID("018f0000-0003-7000-8000-000000000002")
	testRequestID    = testUUID("018f0000-0004-7000-8000-000000000001")
	testCorrelation  = testUUID("018f0000-0004-7000-8000-000000000002")
	testItemIDs      = []uuid.UUID{
		testUUID("018f0000-0005-7000-8000-000000000001"),
		testUUID("018f0000-0006-7000-8000-000000000001"),
		testUUID("018f0000-0007-7000-8000-000000000001"),
		testUUID("018f0000-0008-7000-8000-000000000001"),
		testUUID("018f0000-0009-7000-8000-000000000001"),
		testUUID("018f0000-000a-7000-8000-000000000001"),
	}
	testResourceID = testUUID("018f0000-000b-7000-8000-000000000001")
)

func TestNewServiceRejectsNilDependencies(t *testing.T) {
	var typedNil *fakeRepository
	for name, test := range map[string]struct {
		repository Repository
		clock      Clock
	}{
		"nil repository":       {clock: testClock},
		"typed nil repository": {repository: typedNil, clock: testClock},
		"nil clock":            {repository: newFakeRepository(PrincipalOperator)},
	} {
		t.Run(name, func(t *testing.T) {
			service, err := NewService(test.repository, test.clock)
			if !errors.Is(err, ErrUnavailable) || service != nil {
				t.Fatalf("NewService() = (%v, %v), want (nil, ErrUnavailable)", service, err)
			}
		})
	}
}

func TestItemIsExactAllowlistProjection(t *testing.T) {
	type field struct {
		name string
		tag  string
	}
	want := []field{
		{"ID", "id"}, {"TenantID", "tenantId"}, {"UserID", "userId"}, {"Audience", "audience"},
		{"EventType", "eventType"}, {"ResourceKind", "resourceKind"}, {"ResourceID", "resourceId"},
		{"ResourceVersion", "resourceVersion"}, {"Title", "title"}, {"Summary", "summary"},
		{"OccurredAt", "occurredAt"}, {"ReadAt", "readAt"}, {"Revision", "revision"},
	}
	typeOfItem := reflect.TypeOf(Item{})
	if typeOfItem.NumField() != len(want) {
		t.Fatalf("Item has %d fields, want exact allowlist of %d", typeOfItem.NumField(), len(want))
	}
	for index, expected := range want {
		actual := typeOfItem.Field(index)
		if actual.Name != expected.name || actual.Tag.Get("json") != expected.tag {
			t.Errorf("Item field %d = %s/%q, want %s/%q", index, actual.Name, actual.Tag.Get("json"), expected.name, expected.tag)
		}
	}
	for _, forbidden := range []string{"context", "template", "recipient", "secret", "email", "delivery"} {
		for index := range typeOfItem.NumField() {
			fieldName := strings.ToLower(typeOfItem.Field(index).Name)
			if strings.Contains(fieldName, forbidden) {
				t.Fatalf("Item unexpectedly exposes forbidden field %q", typeOfItem.Field(index).Name)
			}
		}
	}
}

func TestItemSupportsEveryTenantNotificationObjectKind(t *testing.T) {
	tests := map[ResourceKind]EventType{
		ResourceAlert: EventAlertCreated, ResourceCase: EventCaseCreated,
		ResourceTask: EventTaskAssigned, ResourceEvidence: EventEvidenceAdded,
		ResourceContact: EventContactChanged,
	}
	for kind, eventType := range tests {
		t.Run(string(kind), func(t *testing.T) {
			item := validTestItem(testItemIDs[0], AudienceOperator, 1, nil)
			item.ResourceKind = kind
			item.EventType = eventType
			if !validItem(item, testTenantID, testUserID, AudienceOperator, testNow) {
				t.Fatalf("validItem() rejected notification object kind %q", kind)
			}
		})
	}
}

func TestItemRejectsEventAndResourceMismatch(t *testing.T) {
	item := validTestItem(testItemIDs[0], AudienceOperator, 1, nil)
	item.EventType = EventTaskAssigned
	if validItem(item, testTenantID, testUserID, AudienceOperator, testNow) {
		t.Fatal("validItem() accepted a task event bound to an Alert")
	}
}

func TestItemAcceptsNotificationOutboxFutureClockSkew(t *testing.T) {
	item := validTestItem(testItemIDs[0], AudienceOperator, 1, nil)
	item.OccurredAt = testNow.Add(maximumClockSkew)
	if !validItem(item, testTenantID, testUserID, AudienceOperator, testNow) {
		t.Fatal("validItem() rejected the notification outbox future-clock-skew boundary")
	}
	item.OccurredAt = testNow.Add(maximumClockSkew + time.Microsecond)
	if validItem(item, testTenantID, testUserID, AudienceOperator, testNow) {
		t.Fatal("validItem() accepted an instant beyond the notification outbox clock-skew boundary")
	}
}

func TestSensitiveStringersAreRedacted(t *testing.T) {
	readAt := testNow
	item := validTestItem(testItemIDs[4], AudienceOperator, 7, &readAt)
	actor := validTestActor()
	secret := "never-log-this-key"
	values := []any{
		actor, actor.Audit, validTestAccess(PrincipalOperator), item,
		ListInput{After: &item.ID, Limit: 10, UnreadOnly: true},
		Page{TenantID: testTenantID, UserID: testUserID, Items: []Item{item}, NextCursor: &item.ID, InboxRevision: 9},
		UnreadState{TenantID: testTenantID, UserID: testUserID, Count: 2, InboxRevision: 9},
		SetReadStateInput{ItemID: item.ID, Read: true, ExpectedRevision: 7, IdempotencyKey: secret},
		MarkAllReadInput{ExpectedRevision: 9, IdempotencyKey: secret},
		CommandBinding{Operation: operationSetReadState},
		ReadStateResult{Item: item, InboxRevision: 9, Changed: true},
		MarkAllReadResult{TenantID: testTenantID, UserID: testUserID, Affected: 2, InboxRevision: 9},
	}
	for _, value := range values {
		rendered := fmt.Sprintf("%v %#v", value, value)
		for _, sensitive := range []string{secret, item.Title, item.Summary, actor.Audit.UserAgent, testUserID.String()} {
			if strings.Contains(rendered, sensitive) {
				t.Errorf("%T stringer leaked %q: %s", value, sensitive, rendered)
			}
		}
	}
}

func TestAccessEvidenceIsExactFreshAndSupportsBothPrincipals(t *testing.T) {
	for _, principal := range []Principal{PrincipalOperator, PrincipalCustomer} {
		repository := newFakeRepository(principal)
		service := mustService(t, repository)
		state, err := service.CountUnread(context.Background(), validTestActor(), testTenantID)
		if err != nil {
			t.Fatalf("CountUnread(%s): %v", principal, err)
		}
		if state.TenantID != testTenantID || state.UserID != testUserID {
			t.Fatalf("CountUnread(%s) returned wrong coordinate: %#v", principal, state)
		}
	}
	for name, evaluatedAt := range map[string]time.Time{
		"maximum past age":    testNow.Add(-MaximumAccessAge),
		"maximum future skew": testNow.Add(maximumClockSkew),
	} {
		t.Run(name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			repository.access.EvaluatedAt = evaluatedAt
			service := mustService(t, repository)
			if _, err := service.CountUnread(context.Background(), validTestActor(), testTenantID); err != nil {
				t.Fatalf("CountUnread() rejected boundary evidence: %v", err)
			}
		})
	}

	tests := map[string]func(*AccessEvidence){
		"wrong tenant":    func(value *AccessEvidence) { value.TenantID = testOtherTenant },
		"wrong user":      func(value *AccessEvidence) { value.UserID = testOtherUser },
		"wrong session":   func(value *AccessEvidence) { value.SessionID = testOtherSession },
		"unauthenticated": func(value *AccessEvidence) { value.Authenticated = false },
		"inactive":        func(value *AccessEvidence) { value.Active = false },
		"invalid principal": func(value *AccessEvidence) {
			value.Principal = Principal(99)
		},
		"stale": func(value *AccessEvidence) { value.EvaluatedAt = testNow.Add(-MaximumAccessAge - time.Microsecond) },
		"beyond future skew": func(value *AccessEvidence) {
			value.EvaluatedAt = testNow.Add(maximumClockSkew + time.Microsecond)
		},
		"not UTC": func(value *AccessEvidence) {
			value.EvaluatedAt = value.EvaluatedAt.In(time.FixedZone("offset", 3_600))
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			mutate(&repository.access)
			service := mustService(t, repository)
			_, err := service.CountUnread(context.Background(), validTestActor(), testTenantID)
			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("CountUnread() error = %v, want ErrForbidden", err)
			}
			if repository.countCalls != 0 {
				t.Fatalf("CountUnread repository called %d times after invalid evidence", repository.countCalls)
			}
		})
	}
}

func TestAccessEvidenceIsMeasuredAfterRepositoryEvaluation(t *testing.T) {
	repository := newFakeRepository(PrincipalOperator)
	repository.access.EvaluatedAt = testNow.Add(maximumClockSkew + 2*time.Second)
	clockCalls := 0
	clock := func() time.Time {
		clockCalls++
		if clockCalls == 1 {
			return testNow
		}
		return testNow.Add(2 * time.Second)
	}
	service, err := NewService(repository, clock)
	if err != nil {
		t.Fatalf("NewService(): %v", err)
	}
	if _, err := service.CountUnread(context.Background(), validTestActor(), testTenantID); err != nil {
		t.Fatalf("CountUnread rejected evidence produced during ResolveAccess: %v", err)
	}
}

func TestRequestEnvelopeFailsClosed(t *testing.T) {
	invalidUser := validTestActor()
	invalidUser.UserID = uuid.New()
	invalidAudit := validTestActor()
	invalidAudit.Audit.CorrelationID = uuid.New()
	oversizedUserAgent := validTestActor()
	oversizedUserAgent.Audit.UserAgent = strings.Repeat("a", 513)

	tests := map[string]struct {
		ctx      context.Context
		actor    Actor
		tenantID uuid.UUID
		want     error
	}{
		"wrong active tenant":  {context.Background(), validTestActor(), testOtherTenant, ErrForbidden},
		"invalid user":         {context.Background(), invalidUser, testTenantID, ErrForbidden},
		"invalid audit":        {context.Background(), invalidAudit, testTenantID, ErrInvalidInput},
		"oversized user agent": {context.Background(), oversizedUserAgent, testTenantID, ErrInvalidInput},
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	tests["canceled context"] = struct {
		ctx      context.Context
		actor    Actor
		tenantID uuid.UUID
		want     error
	}{canceled, validTestActor(), testTenantID, ErrUnavailable}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			service := mustService(t, repository)
			_, err := service.CountUnread(test.ctx, test.actor, test.tenantID)
			if !errors.Is(err, test.want) {
				t.Fatalf("CountUnread() error = %v, want %v", err, test.want)
			}
			if repository.resolveCalls != 0 || repository.countCalls != 0 {
				t.Fatalf("repository called for invalid envelope: resolve=%d count=%d", repository.resolveCalls, repository.countCalls)
			}
		})
	}
}

func TestListUsesScopedLookaheadAndPaginatesWithoutDuplicates(t *testing.T) {
	repository := newFakeRepository(PrincipalCustomer)
	repository.listFn = func(params ListParams) (ListSnapshot, error) {
		if params.TenantID != testTenantID || params.UserID != testUserID ||
			params.Access.Principal != PrincipalCustomer || params.FetchLimit != 3 {
			t.Fatalf("List params not exact scoped lookahead: %#v", params)
		}
		var items []Item
		switch {
		case params.After == nil:
			items = []Item{
				validTestItem(testItemIDs[5], AudienceCustomer, 1, nil),
				validTestItem(testItemIDs[4], AudienceCustomer, 1, nil),
				validTestItem(testItemIDs[3], AudienceCustomer, 1, nil),
			}
		case *params.After == testItemIDs[4]:
			items = []Item{
				validTestItem(testItemIDs[3], AudienceCustomer, 1, nil),
				validTestItem(testItemIDs[2], AudienceCustomer, 1, nil),
			}
		default:
			t.Fatalf("unexpected cursor: %v", params.After)
		}
		return ListSnapshot{TenantID: testTenantID, UserID: testUserID, Items: items, InboxRevision: 8}, nil
	}
	service := mustService(t, repository)
	first, err := service.List(context.Background(), validTestActor(), testTenantID, ListInput{Limit: 2, UnreadOnly: true})
	if err != nil {
		t.Fatalf("first List(): %v", err)
	}
	if len(first.Items) != 2 || first.NextCursor == nil || *first.NextCursor != testItemIDs[4] {
		t.Fatalf("first page = %#v, want two items and cursor %s", first, testItemIDs[4])
	}
	second, err := service.List(context.Background(), validTestActor(), testTenantID, ListInput{
		After: first.NextCursor, Limit: 2, UnreadOnly: true,
	})
	if err != nil {
		t.Fatalf("second List(): %v", err)
	}
	if len(second.Items) != 2 || second.NextCursor != nil {
		t.Fatalf("second page = %#v, want terminal two-item page", second)
	}
	got := []uuid.UUID{first.Items[0].ID, first.Items[1].ID, second.Items[0].ID, second.Items[1].ID}
	want := []uuid.UUID{testItemIDs[5], testItemIDs[4], testItemIDs[3], testItemIDs[2]}
	if !slices.Equal(got, want) {
		t.Fatalf("pagination IDs = %v, want newest-first unique %v", got, want)
	}
	seen := map[uuid.UUID]struct{}{}
	for _, id := range got {
		if _, duplicate := seen[id]; duplicate {
			t.Fatalf("duplicate item across pages: %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestListReturnsDefensiveCopies(t *testing.T) {
	readAt := testNow.Add(-time.Minute)
	items := []Item{validTestItem(testItemIDs[5], AudienceOperator, 1, &readAt)}
	repository := newFakeRepository(PrincipalOperator)
	repository.listFn = func(ListParams) (ListSnapshot, error) {
		return ListSnapshot{TenantID: testTenantID, UserID: testUserID, Items: items, InboxRevision: 1}, nil
	}
	service := mustService(t, repository)
	page, err := service.List(context.Background(), validTestActor(), testTenantID, ListInput{Limit: 1})
	if err != nil {
		t.Fatalf("List(): %v", err)
	}
	items[0].Title = "mutated title"
	*items[0].ReadAt = testNow
	if page.Items[0].Title == items[0].Title || page.Items[0].ReadAt.Equal(*items[0].ReadAt) {
		t.Fatal("List returned repository-owned item or timestamp memory")
	}
}

func TestListRejectsInvalidInputBeforeRepositoryList(t *testing.T) {
	invalidCursor := uuid.New()
	for name, input := range map[string]ListInput{
		"negative limit": {Limit: -1},
		"over max":       {Limit: MaximumPageLimit + 1},
		"non v7 cursor":  {After: &invalidCursor},
	} {
		t.Run(name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			service := mustService(t, repository)
			_, err := service.List(context.Background(), validTestActor(), testTenantID, input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("List() error = %v, want ErrInvalidInput", err)
			}
			if repository.resolveCalls != 0 || repository.listCalls != 0 {
				t.Fatalf("repository called for invalid input: resolve=%d list=%d", repository.resolveCalls, repository.listCalls)
			}
		})
	}
}

func TestListRejectsRepositoryDivergence(t *testing.T) {
	base := func() ListSnapshot {
		return ListSnapshot{
			TenantID: testTenantID, UserID: testUserID, InboxRevision: 5,
			Items: []Item{
				validTestItem(testItemIDs[4], AudienceOperator, 1, nil),
				validTestItem(testItemIDs[3], AudienceOperator, 1, nil),
			},
		}
	}
	tests := map[string]func(*ListSnapshot){
		"wrong tenant snapshot": func(value *ListSnapshot) { value.TenantID = testOtherTenant },
		"wrong user snapshot":   func(value *ListSnapshot) { value.UserID = testOtherUser },
		"wrong item tenant":     func(value *ListSnapshot) { value.Items[0].TenantID = testOtherTenant },
		"wrong item user":       func(value *ListSnapshot) { value.Items[0].UserID = testOtherUser },
		"wrong audience":        func(value *ListSnapshot) { value.Items[0].Audience = AudienceCustomer },
		"invalid event type":    func(value *ListSnapshot) { value.Items[0].EventType = EventType("ticket.assigned") },
		"invalid resource kind": func(value *ListSnapshot) { value.Items[0].ResourceKind = ResourceKind("secret") },
		"invalid title":         func(value *ListSnapshot) { value.Items[0].Title = " title" },
		"read item in unread list": func(value *ListSnapshot) {
			readAt := testNow
			value.Items[0].ReadAt = &readAt
		},
		"ascending": func(value *ListSnapshot) {
			value.Items[0], value.Items[1] = value.Items[1], value.Items[0]
		},
		"duplicate":           func(value *ListSnapshot) { value.Items[1].ID = value.Items[0].ID },
		"zero inbox revision": func(value *ListSnapshot) { value.InboxRevision = 0 },
		"row at cursor":       func(value *ListSnapshot) { value.Items[0].ID = testItemIDs[5] },
		"too many rows": func(value *ListSnapshot) {
			value.Items = append(value.Items,
				validTestItem(testItemIDs[2], AudienceOperator, 1, nil),
				validTestItem(testItemIDs[1], AudienceOperator, 1, nil),
			)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			snapshot := base()
			mutate(&snapshot)
			repository := newFakeRepository(PrincipalOperator)
			repository.listFn = func(ListParams) (ListSnapshot, error) { return snapshot, nil }
			service := mustService(t, repository)
			cursor := testItemIDs[5]
			_, err := service.List(context.Background(), validTestActor(), testTenantID, ListInput{
				After: &cursor, Limit: 2, UnreadOnly: true,
			})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("List() error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestListRejectsOperatorOnlyEventsForCustomer(t *testing.T) {
	operatorOnly := []EventType{
		EventAlertWatcherAdded,
		EventAlertWatcherRemoved,
		EventCaseWatcherAdded,
		EventCaseWatcherRemoved,
		EventCommentPrivateAdded,
	}
	for _, eventType := range operatorOnly {
		t.Run(string(eventType), func(t *testing.T) {
			item := validTestItem(testItemIDs[4], AudienceCustomer, 1, nil)
			item.EventType = eventType
			if eventType == EventCaseWatcherAdded || eventType == EventCaseWatcherRemoved {
				item.ResourceKind = ResourceCase
			}
			repository := newFakeRepository(PrincipalCustomer)
			repository.listFn = func(ListParams) (ListSnapshot, error) {
				return ListSnapshot{
					TenantID: testTenantID, UserID: testUserID, InboxRevision: 1,
					Items: []Item{item},
				}, nil
			}
			service := mustService(t, repository)
			_, err := service.List(context.Background(), validTestActor(), testTenantID, ListInput{Limit: 1})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("List() error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestListCannotRelaxCursorByMutatingRepositoryParams(t *testing.T) {
	originalCursor := testItemIDs[3]
	repository := newFakeRepository(PrincipalOperator)
	repository.listFn = func(params ListParams) (ListSnapshot, error) {
		*params.After = testItemIDs[5]
		return ListSnapshot{
			TenantID: testTenantID, UserID: testUserID, InboxRevision: 5,
			Items: []Item{validTestItem(testItemIDs[4], AudienceOperator, 1, nil)},
		}, nil
	}
	service := mustService(t, repository)
	_, err := service.List(context.Background(), validTestActor(), testTenantID, ListInput{
		After: &originalCursor, Limit: 2,
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("List() error = %v, want ErrUnavailable for row above original cursor", err)
	}
	if originalCursor != testItemIDs[3] {
		t.Fatal("repository mutated caller-owned cursor")
	}
}

func TestCountUnreadIsBoundedAndCoordinateChecked(t *testing.T) {
	valid := UnreadState{TenantID: testTenantID, UserID: testUserID, Count: MaximumUnreadCount, InboxRevision: 7}
	tests := map[string]UnreadState{
		"wrong tenant":  {TenantID: testOtherTenant, UserID: testUserID, Count: 1, InboxRevision: 1},
		"wrong user":    {TenantID: testTenantID, UserID: testOtherUser, Count: 1, InboxRevision: 1},
		"over bound":    {TenantID: testTenantID, UserID: testUserID, Count: MaximumUnreadCount + 1, InboxRevision: 1},
		"zero revision": {TenantID: testTenantID, UserID: testUserID, Count: 1},
	}
	repository := newFakeRepository(PrincipalOperator)
	repository.unread = valid
	service := mustService(t, repository)
	if got, err := service.CountUnread(context.Background(), validTestActor(), testTenantID); err != nil || got != valid {
		t.Fatalf("CountUnread() = (%#v, %v), want valid maximum", got, err)
	}
	for name, state := range tests {
		t.Run(name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			repository.unread = state
			service := mustService(t, repository)
			_, err := service.CountUnread(context.Background(), validTestActor(), testTenantID)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("CountUnread() error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestSetReadStateChangedNoopUnreadAndReplaySemantics(t *testing.T) {
	tests := []struct {
		name     string
		read     bool
		changed  bool
		replayed bool
	}{
		{"mark read", true, true, false},
		{"mark unread", false, true, false},
		{"already read no-op", true, false, false},
		{"changed replay", true, true, true},
		{"no-op replay", false, false, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			repository.setReadFn = func(params SetReadStateParams) (ReadStateResult, error) {
				if params.TenantID != testTenantID || params.UserID != testUserID || params.ItemID != testItemIDs[4] ||
					params.ExpectedRevision != 5 || params.Command.Operation != operationSetReadState || params.Audit != validTestActor().Audit {
					t.Fatalf("SetReadState params mismatch: %#v", params)
				}
				var readAt *time.Time
				if test.read {
					value := testNow
					readAt = &value
				}
				revision := uint64(5)
				if test.changed {
					revision++
				}
				result := ReadStateResult{
					Item:          validTestItem(testItemIDs[4], AudienceOperator, revision, readAt),
					InboxRevision: 12, Changed: test.changed, Replayed: test.replayed,
				}
				if err := params.ValidateResult(result); err != nil {
					t.Fatalf("ValidateResult(valid result): %v", err)
				}
				return result, nil
			}
			service := mustService(t, repository)
			input := SetReadStateInput{
				ItemID: testItemIDs[4], Read: test.read, ExpectedRevision: 5,
				IdempotencyKey: "read-state-key-0001",
			}
			result, err := service.SetReadState(context.Background(), validTestActor(), testTenantID, input)
			if err != nil {
				t.Fatalf("SetReadState(): %v", err)
			}
			if result.Changed != test.changed || result.Replayed != test.replayed || (result.Item.ReadAt != nil) != test.read {
				t.Fatalf("SetReadState() = %#v", result)
			}
		})
	}
}

func TestCommandBindingIsScopedStableAndDoesNotRetainRawKey(t *testing.T) {
	base := SetReadStateInput{ItemID: testItemIDs[4], Read: true, ExpectedRevision: 5, IdempotencyKey: "raw-secret-key-0001"}
	first, err := bindSetReadStateCommand(testTenantID, testUserID, base.ItemID, base)
	if err != nil {
		t.Fatalf("bindSetReadStateCommand(): %v", err)
	}
	second, _ := bindSetReadStateCommand(testTenantID, testUserID, base.ItemID, base)
	changed := base
	changed.Read = false
	third, _ := bindSetReadStateCommand(testTenantID, testUserID, base.ItemID, changed)
	otherUser, _ := bindSetReadStateCommand(testTenantID, testOtherUser, base.ItemID, base)
	if first != second {
		t.Fatal("identical command did not produce a stable binding")
	}
	if first.KeyDigest != third.KeyDigest || first.RequestDigest == third.RequestDigest {
		t.Fatal("same key must preserve key digest and bind distinct request content")
	}
	if first.RequestDigest == otherUser.RequestDigest {
		t.Fatal("request digest is not bound to the personal user coordinate")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", first, first), base.IdempotencyKey) {
		t.Fatal("CommandBinding stringer retained the raw idempotency key")
	}
}

func TestSetReadStateRejectsInvalidInputBeforeRepository(t *testing.T) {
	valid := SetReadStateInput{ItemID: testItemIDs[4], Read: true, ExpectedRevision: 5, IdempotencyKey: "read-state-key-0001"}
	tests := map[string]SetReadStateInput{
		"invalid item":  func() SetReadStateInput { value := valid; value.ItemID = uuid.New(); return value }(),
		"zero revision": func() SetReadStateInput { value := valid; value.ExpectedRevision = 0; return value }(),
		"max revision":  func() SetReadStateInput { value := valid; value.ExpectedRevision = MaximumRevision; return value }(),
		"short key":     func() SetReadStateInput { value := valid; value.IdempotencyKey = "short"; return value }(),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			service := mustService(t, repository)
			_, err := service.SetReadState(context.Background(), validTestActor(), testTenantID, input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("SetReadState() error = %v, want ErrInvalidInput", err)
			}
			if repository.resolveCalls != 0 || repository.setReadCalls != 0 {
				t.Fatalf("repository called for invalid input: resolve=%d write=%d", repository.resolveCalls, repository.setReadCalls)
			}
		})
	}
}

func TestSetReadStateRejectsRepositoryDivergenceAndMissingValidation(t *testing.T) {
	readAt := testNow
	valid := ReadStateResult{
		Item:          validTestItem(testItemIDs[4], AudienceOperator, 6, &readAt),
		InboxRevision: 12, Changed: true,
	}
	tests := map[string]func(*ReadStateResult){
		"wrong item":       func(value *ReadStateResult) { value.Item.ID = testItemIDs[3] },
		"wrong tenant":     func(value *ReadStateResult) { value.Item.TenantID = testOtherTenant },
		"wrong user":       func(value *ReadStateResult) { value.Item.UserID = testOtherUser },
		"wrong audience":   func(value *ReadStateResult) { value.Item.Audience = AudienceCustomer },
		"wrong read state": func(value *ReadStateResult) { value.Item.ReadAt = nil },
		"wrong revision":   func(value *ReadStateResult) { value.Item.Revision = 5 },
		"zero inbox rev":   func(value *ReadStateResult) { value.InboxRevision = 0 },
		"changed mismatch": func(value *ReadStateResult) {
			value.Changed = false
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := valid
			result.Item = cloneItem(valid.Item)
			mutate(&result)
			repository := newFakeRepository(PrincipalOperator)
			repository.setReadFn = func(params SetReadStateParams) (ReadStateResult, error) {
				if err := params.ValidateResult(result); err != nil {
					return ReadStateResult{}, err
				}
				return result, nil
			}
			service := mustService(t, repository)
			_, err := service.SetReadState(context.Background(), validTestActor(), testTenantID, SetReadStateInput{
				ItemID: testItemIDs[4], Read: true, ExpectedRevision: 5, IdempotencyKey: "read-state-key-0001",
			})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("SetReadState() error = %v, want ErrUnavailable", err)
			}
		})
	}

	repository := newFakeRepository(PrincipalOperator)
	repository.setReadFn = func(SetReadStateParams) (ReadStateResult, error) { return valid, nil }
	service := mustService(t, repository)
	_, err := service.SetReadState(context.Background(), validTestActor(), testTenantID, SetReadStateInput{
		ItemID: testItemIDs[4], Read: true, ExpectedRevision: 5, IdempotencyKey: "read-state-key-0001",
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("SetReadState without adapter validation error = %v, want ErrUnavailable", err)
	}
}

func TestMarkAllReadChangedNoopAndReplaySemantics(t *testing.T) {
	tests := []struct {
		name     string
		affected uint64
		replayed bool
	}{
		{"changed", 3, false},
		{"no-op", 0, false},
		{"changed replay", 3, true},
		{"no-op replay", 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalCustomer)
			repository.markAllFn = func(params MarkAllReadParams) (MarkAllReadResult, error) {
				changed := test.affected > 0
				revision := uint64(8)
				if changed {
					revision++
				}
				result := MarkAllReadResult{
					TenantID: testTenantID, UserID: testUserID, Affected: test.affected,
					InboxRevision: revision, Changed: changed, Replayed: test.replayed,
				}
				if params.Access.Principal != PrincipalCustomer || params.Command.Operation != operationMarkAllRead {
					t.Fatalf("MarkAllRead params mismatch: %#v", params)
				}
				if err := params.ValidateResult(result); err != nil {
					t.Fatalf("ValidateResult(valid result): %v", err)
				}
				return result, nil
			}
			service := mustService(t, repository)
			result, err := service.MarkAllRead(context.Background(), validTestActor(), testTenantID, MarkAllReadInput{
				ExpectedRevision: 8, IdempotencyKey: "mark-all-read-key-01",
			})
			if err != nil {
				t.Fatalf("MarkAllRead(): %v", err)
			}
			if result.Affected != test.affected || result.Changed != (test.affected > 0) || result.Replayed != test.replayed {
				t.Fatalf("MarkAllRead() = %#v", result)
			}
		})
	}
}

func TestMarkAllReadRejectsInvalidInputBeforeRepository(t *testing.T) {
	for name, input := range map[string]MarkAllReadInput{
		"max revision": {ExpectedRevision: MaximumRevision, IdempotencyKey: "mark-all-read-key-01"},
		"short key":    {ExpectedRevision: 1, IdempotencyKey: "short"},
	} {
		t.Run(name, func(t *testing.T) {
			repository := newFakeRepository(PrincipalOperator)
			service := mustService(t, repository)
			_, err := service.MarkAllRead(context.Background(), validTestActor(), testTenantID, input)
			if !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("MarkAllRead() error = %v, want ErrInvalidInput", err)
			}
			if repository.resolveCalls != 0 || repository.markAllCalls != 0 {
				t.Fatalf("repository called for invalid input: resolve=%d write=%d", repository.resolveCalls, repository.markAllCalls)
			}
		})
	}
}

func TestMarkAllReadRejectsRepositoryDivergenceAndMissingValidation(t *testing.T) {
	valid := MarkAllReadResult{
		TenantID: testTenantID, UserID: testUserID, Affected: 3,
		InboxRevision: 9, Changed: true,
	}
	tests := map[string]func(*MarkAllReadResult){
		"wrong tenant":     func(value *MarkAllReadResult) { value.TenantID = testOtherTenant },
		"wrong user":       func(value *MarkAllReadResult) { value.UserID = testOtherUser },
		"over bound":       func(value *MarkAllReadResult) { value.Affected = MaximumUnreadCount + 1 },
		"changed mismatch": func(value *MarkAllReadResult) { value.Changed = false },
		"wrong revision":   func(value *MarkAllReadResult) { value.InboxRevision = 8 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			result := valid
			mutate(&result)
			repository := newFakeRepository(PrincipalOperator)
			repository.markAllFn = func(params MarkAllReadParams) (MarkAllReadResult, error) {
				if err := params.ValidateResult(result); err != nil {
					return MarkAllReadResult{}, err
				}
				return result, nil
			}
			service := mustService(t, repository)
			_, err := service.MarkAllRead(context.Background(), validTestActor(), testTenantID, MarkAllReadInput{
				ExpectedRevision: 8, IdempotencyKey: "mark-all-read-key-01",
			})
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("MarkAllRead() error = %v, want ErrUnavailable", err)
			}
		})
	}

	repository := newFakeRepository(PrincipalOperator)
	repository.markAllFn = func(MarkAllReadParams) (MarkAllReadResult, error) { return valid, nil }
	service := mustService(t, repository)
	_, err := service.MarkAllRead(context.Background(), validTestActor(), testTenantID, MarkAllReadInput{
		ExpectedRevision: 8, IdempotencyKey: "mark-all-read-key-01",
	})
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("MarkAllRead without adapter validation error = %v, want ErrUnavailable", err)
	}
}

func TestMutationValidatorMustBeCalledExactlyOnce(t *testing.T) {
	readAt := testNow
	readResult := ReadStateResult{
		Item:          validTestItem(testItemIDs[4], AudienceOperator, 6, &readAt),
		InboxRevision: 12, Changed: true,
	}
	t.Run("set read state", func(t *testing.T) {
		repository := newFakeRepository(PrincipalOperator)
		repository.setReadFn = func(params SetReadStateParams) (ReadStateResult, error) {
			_ = params.ValidateResult(readResult)
			_ = params.ValidateResult(readResult)
			return readResult, nil
		}
		service := mustService(t, repository)
		_, err := service.SetReadState(context.Background(), validTestActor(), testTenantID, SetReadStateInput{
			ItemID: testItemIDs[4], Read: true, ExpectedRevision: 5, IdempotencyKey: "read-state-key-0001",
		})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("SetReadState() error = %v, want ErrUnavailable", err)
		}
	})

	t.Run("mark all read", func(t *testing.T) {
		result := MarkAllReadResult{
			TenantID: testTenantID, UserID: testUserID, Affected: 3,
			InboxRevision: 9, Changed: true,
		}
		repository := newFakeRepository(PrincipalOperator)
		repository.markAllFn = func(params MarkAllReadParams) (MarkAllReadResult, error) {
			_ = params.ValidateResult(result)
			_ = params.ValidateResult(result)
			return result, nil
		}
		service := mustService(t, repository)
		_, err := service.MarkAllRead(context.Background(), validTestActor(), testTenantID, MarkAllReadInput{
			ExpectedRevision: 8, IdempotencyKey: "mark-all-read-key-01",
		})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("MarkAllRead() error = %v, want ErrUnavailable", err)
		}
	})
}

func TestRepositoryErrorMapping(t *testing.T) {
	unknown := errors.New("driver details")
	for name, test := range map[string]struct {
		got  error
		want error
	}{
		"invalid":      {repositoryError(fmt.Errorf("wrapped: %w", ErrRepositoryInvalidInput)), ErrInvalidInput},
		"forbidden":    {repositoryError(ErrRepositoryForbidden), ErrForbidden},
		"not found":    {repositoryError(ErrRepositoryNotFound), ErrNotFound},
		"conflict":     {repositoryError(ErrRepositoryConflict), ErrConflict},
		"precondition": {repositoryError(ErrRepositoryPrecondition), ErrPreconditionFailed},
		"context":      {repositoryError(context.Canceled), ErrUnavailable},
		"unknown":      {repositoryError(unknown), ErrUnavailable},
	} {
		t.Run(name, func(t *testing.T) {
			if !errors.Is(test.got, test.want) {
				t.Fatalf("repositoryError() = %v, want %v", test.got, test.want)
			}
			if errors.Is(test.got, unknown) {
				t.Fatal("repositoryError leaked underlying driver error")
			}
		})
	}
}

type fakeRepository struct {
	access AccessEvidence
	unread UnreadState

	resolveErr error
	listFn     func(ListParams) (ListSnapshot, error)
	setReadFn  func(SetReadStateParams) (ReadStateResult, error)
	markAllFn  func(MarkAllReadParams) (MarkAllReadResult, error)

	resolveCalls int
	listCalls    int
	countCalls   int
	setReadCalls int
	markAllCalls int
}

func newFakeRepository(principal Principal) *fakeRepository {
	return &fakeRepository{
		access: validTestAccess(principal),
		unread: UnreadState{TenantID: testTenantID, UserID: testUserID},
	}
}

func (repository *fakeRepository) ResolveAccess(context.Context, Actor, uuid.UUID) (AccessEvidence, error) {
	repository.resolveCalls++
	return repository.access, repository.resolveErr
}

func (repository *fakeRepository) List(_ context.Context, params ListParams) (ListSnapshot, error) {
	repository.listCalls++
	if repository.listFn == nil {
		return ListSnapshot{}, ErrRepositoryInvalidInput
	}
	return repository.listFn(params)
}

func (repository *fakeRepository) CountUnread(context.Context, CountUnreadParams) (UnreadState, error) {
	repository.countCalls++
	return repository.unread, nil
}

func (repository *fakeRepository) SetReadState(_ context.Context, params SetReadStateParams) (ReadStateResult, error) {
	repository.setReadCalls++
	if repository.setReadFn == nil {
		return ReadStateResult{}, ErrRepositoryInvalidInput
	}
	return repository.setReadFn(params)
}

func (repository *fakeRepository) MarkAllRead(_ context.Context, params MarkAllReadParams) (MarkAllReadResult, error) {
	repository.markAllCalls++
	if repository.markAllFn == nil {
		return MarkAllReadResult{}, ErrRepositoryInvalidInput
	}
	return repository.markAllFn(params)
}

func mustService(t *testing.T, repository Repository) *Service {
	t.Helper()
	service, err := NewService(repository, testClock)
	if err != nil {
		t.Fatalf("NewService(): %v", err)
	}
	return service
}

func testClock() time.Time { return testNow }

func validTestActor() Actor {
	return Actor{
		UserID: testUserID, SessionID: testSessionID, ActiveTenantID: testTenantID,
		Audit: AuditMetadata{
			RequestID: testRequestID, CorrelationID: testCorrelation,
			RemoteAddress: netip.MustParseAddr("192.0.2.10"), UserAgent: "notification-inbox-test/1",
		},
	}
}

func validTestAccess(principal Principal) AccessEvidence {
	return AccessEvidence{
		TenantID: testTenantID, UserID: testUserID, SessionID: testSessionID,
		Principal: principal, Authenticated: true, Active: true, EvaluatedAt: testNow,
	}
}

func validTestItem(id uuid.UUID, audience Audience, revision uint64, readAt *time.Time) Item {
	return Item{
		ID: id, TenantID: testTenantID, UserID: testUserID, Audience: audience,
		EventType: EventAlertAssigned, ResourceKind: ResourceAlert, ResourceID: testResourceID,
		ResourceVersion: 4, Title: "Ticket assigned", Summary: "A concise safe summary",
		OccurredAt: testNow.Add(-2 * time.Minute), ReadAt: readAt, Revision: revision,
	}
}

func testUUID(value string) uuid.UUID { return uuid.MustParse(value) }
