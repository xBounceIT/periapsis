package contacts

import (
	"slices"
	"testing"
	"time"
)

func TestTicketResolutionRequiresExactContactLinkSetAndDeduplicatesSharedMailbox(t *testing.T) {
	t.Parallel()
	tenant := testID(1)
	first := testContact(10, tenant, "shared@example.com")
	second := testContact(30, tenant, "shared@example.com")
	third := testContact(50, tenant, "third@example.com")
	input := ResolutionInput{
		TenantID: tenant, Selector: AllCustomerContactsTarget(), Category: testKey("comment.public_added"),
		OccurredAt: testInstant(9), Surface: SurfaceTicketEvent,
		TicketContactIDs: []EntityID{third.ID(), second.ID(), first.ID()}, Contacts: []Contact{third, first, second},
	}
	plan, err := ResolveTargets(input)
	if err != nil {
		t.Fatal(err)
	}
	recipients := plan.Recipients()
	if len(recipients) != 2 || recipients[0].Email().String() != "shared@example.com" ||
		!slices.Equal(recipients[0].ContactIDs(), []EntityID{first.ID(), second.ID()}) ||
		recipients[1].Email().String() != "third@example.com" {
		t.Fatalf("recipients = %#v", recipients)
	}
	if plan.Digest() == ([32]byte{}) {
		t.Fatal("empty resolution digest")
	}
	input.Contacts = []Contact{first, second}
	if _, err := ResolveTargets(input); err != ErrResolutionDrift {
		t.Fatalf("missing resolver result error = %v", err)
	}
	input.Contacts = []Contact{first, second, third}
	input.TicketContactIDs = nil
	if _, err := ResolveTargets(input); err != ErrResolutionDenied {
		t.Fatalf("missing link boundary error = %v", err)
	}
}

func TestResolutionFailsClosedOnTenantDuplicateAndGroupVersionDrift(t *testing.T) {
	t.Parallel()
	tenant, otherTenant := testID(2), testID(3)
	contact := testContact(20, tenant, "person@example.com")
	other := testContact(40, otherTenant, "other@example.com")
	groupID := testID(60)
	predicate, _ := NewPredicate(FieldContactClass, OperatorEquals, "gold")
	version, _ := NewGroupVersion(groupID, tenant, 3, "Gold", "", GroupDynamic, predicate, nil, testInstant(8))
	selector, _ := NewContactGroupTarget(groupID, 3)
	base := ResolutionInput{
		TenantID: tenant, Selector: selector, Category: testKey("comment.public_added"), OccurredAt: testInstant(9),
		Surface: SurfaceTenantEvent, Contacts: []Contact{contact}, GroupVersions: []GroupVersion{version},
	}
	if _, err := ResolveTargets(base); err != nil {
		t.Fatalf("valid resolution error = %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*ResolutionInput)
	}{
		{"mixed tenant", func(input *ResolutionInput) { input.Contacts = append(input.Contacts, other) }},
		{"duplicate contact", func(input *ResolutionInput) { input.Contacts = append(input.Contacts, contact) }},
		{"missing group", func(input *ResolutionInput) { input.GroupVersions = nil }},
		{"duplicate group", func(input *ResolutionInput) { input.GroupVersions = append(input.GroupVersions, version) }},
		{"wrong group version", func(input *ResolutionInput) {
			wrong, _ := NewGroupVersion(groupID, tenant, 4, "Gold", "", GroupDynamic, predicate, nil, testInstant(8))
			input.GroupVersions = []GroupVersion{wrong}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.Contacts = slices.Clone(base.Contacts)
			input.GroupVersions = slices.Clone(base.GroupVersions)
			test.mutate(&input)
			if _, err := ResolveTargets(input); err != ErrResolutionDrift {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestManualDynamicAndTagTargets(t *testing.T) {
	t.Parallel()
	tenant := testID(4)
	first := testContact(10, tenant, "first@example.com")
	second := testContact(30, tenant, "second@example.com")
	secondFields := second.Fields()
	secondFields.Class = testKey("silver")
	secondFields.Tags = []Key{testKey("general")}
	second, _ = ReplaceContact(second, secondFields, 1, testInstant(9))
	groupID := testID(70)
	manual, _ := NewGroupVersion(groupID, tenant, 1, "Manual", "", GroupManual, RuleNode{}, []EntityID{second.ID()}, testInstant(8))
	dynamicRule, _ := NewPredicate(FieldContactClass, OperatorEquals, "gold")
	dynamic, _ := NewGroupVersion(groupID, tenant, 2, "Dynamic", "", GroupDynamic, dynamicRule, nil, testInstant(8))

	manualTarget, _ := NewContactGroupTarget(groupID, 1)
	dynamicTarget, _ := NewContactGroupTarget(groupID, 2)
	tagTarget, _ := NewContactTagTarget(testKey("executive"))
	for _, test := range []struct {
		name     string
		target   TargetSelector
		versions []GroupVersion
		email    string
	}{
		{"manual", manualTarget, []GroupVersion{manual}, "second@example.com"},
		{"dynamic", dynamicTarget, []GroupVersion{dynamic}, "first@example.com"},
		{"tag", tagTarget, nil, "first@example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, err := ResolveTargets(ResolutionInput{
				TenantID: tenant, Selector: test.target, Category: testKey("comment.public_added"),
				OccurredAt: testInstant(10), Surface: SurfaceTenantEvent,
				Contacts: []Contact{second, first}, GroupVersions: test.versions,
			})
			if err != nil {
				t.Fatal(err)
			}
			if recipients := plan.Recipients(); len(recipients) != 1 || recipients[0].Email().String() != test.email {
				t.Fatalf("recipients = %#v", recipients)
			}
		})
	}
}

func TestNotificationWindowsUseIANAWallTimeAcrossDST(t *testing.T) {
	t.Parallel()
	tenant := testID(5)
	contact := testContact(10, tenant, "dst@example.com")
	window, _ := NewNotificationWindow(Sunday, 120, 180)
	fields := contact.Fields()
	fields.NotificationWindows = []NotificationWindow{window}
	contact, _ = ReplaceContact(contact, fields, 1, testInstant(9))
	resolve := func(at time.Time) int {
		plan, err := ResolveTargets(ResolutionInput{
			TenantID: tenant, Selector: AllCustomerContactsTarget(), Category: testKey("comment.public_added"),
			OccurredAt: at, Surface: SurfaceTenantEvent, Contacts: []Contact{contact},
		})
		if err != nil {
			t.Fatal(err)
		}
		return len(plan.Recipients())
	}
	// Europe/Rome repeats 02:30 during the autumn transition; both real
	// instants are inside the same local window.
	firstOccurrence := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC)
	secondOccurrence := time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC)
	if resolve(firstOccurrence) != 1 || resolve(secondOccurrence) != 1 {
		t.Fatal("repeated DST wall time did not honor the configured window")
	}
	// The spring transition skips 02:30 entirely; adjacent real instants map
	// outside the configured wall-time window.
	beforeSkip := time.Date(2026, 3, 29, 0, 30, 0, 0, time.UTC)
	afterSkip := time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC)
	if resolve(beforeSkip) != 0 || resolve(afterSkip) != 0 {
		t.Fatal("non-existent DST wall time was treated as deliverable")
	}
}

func TestResolutionDigestIsIndependentOfResolverOrder(t *testing.T) {
	t.Parallel()
	tenant := testID(6)
	first := testContact(10, tenant, "b@example.com")
	second := testContact(30, tenant, "a@example.com")
	base := ResolutionInput{
		TenantID: tenant, Selector: AllCustomerContactsTarget(), Category: testKey("sla.warning"),
		OccurredAt: testInstant(9), Surface: SurfaceTenantEvent, Contacts: []Contact{first, second},
	}
	firstPlan, err := ResolveTargets(base)
	if err != nil {
		t.Fatal(err)
	}
	base.Contacts = []Contact{second, first}
	secondPlan, err := ResolveTargets(base)
	if err != nil {
		t.Fatal(err)
	}
	if firstPlan.Digest() != secondPlan.Digest() {
		t.Fatal("resolver order changed the snapshot digest")
	}
}
