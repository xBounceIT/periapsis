package contacts

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestContactConstructionAndCustomerProjection(t *testing.T) {
	t.Parallel()
	tenant := testID(1)
	fields := testFields("Shared@Example.COM")
	linked, err := NewLinkedAccount(testID(30), testID(60))
	if err != nil {
		t.Fatal(err)
	}
	fields.LinkedAccount = &linked
	firstWindow, _ := NewNotificationWindow(Monday, 540, 720)
	secondWindow, _ := NewNotificationWindow(Friday, 780, 1_020)
	fields.NotificationWindows = []NotificationWindow{secondWindow, firstWindow}

	contact, err := NewContact(testID(10), tenant, fields, testInstant(8))
	if err != nil {
		t.Fatalf("NewContact() error = %v", err)
	}
	if got := contact.Fields().Email.String(); got != "shared@example.com" {
		t.Fatalf("canonical email = %q", got)
	}
	if got := contact.Fields().NotificationWindows; !slices.Equal(got, []NotificationWindow{firstWindow, secondWindow}) {
		t.Fatalf("windows not canonical: %#v", got)
	}
	copy := contact.Fields()
	copy.Tags[0] = testKey("mutated")
	copy.NotificationWindows[0] = secondWindow
	copy.LinkedAccount = nil
	if contact.Fields().Tags[0].String() != "executive" || contact.Fields().NotificationWindows[0] != firstWindow ||
		contact.Fields().LinkedAccount == nil {
		t.Fatal("contact leaked mutable constructor state")
	}
	projection, err := ProjectCustomerSafe(contact)
	if err != nil {
		t.Fatal(err)
	}
	if projection.ID != contact.ID() || projection.Version != 1 || projection.Email.String() != "shared@example.com" {
		t.Fatalf("unexpected projection: %#v", projection)
	}
	formatted := contact.String()
	for _, private := range []string{"shared@example.com", fields.Phone, fields.FirstName, fields.LastName} {
		if strings.Contains(formatted, private) {
			t.Fatalf("String() leaked %q: %s", private, formatted)
		}
	}
}

func TestSharedMailboxIsAllowed(t *testing.T) {
	t.Parallel()
	tenant := testID(2)
	first := testContact(20, tenant, "shared@example.com")
	second := testContact(40, tenant, "shared@example.com")
	if first.Fields().Email != second.Fields().Email || first.ID() == second.ID() {
		t.Fatal("shared mailbox construction failed")
	}
}

func TestContactReplacePreferencesAndArchive(t *testing.T) {
	t.Parallel()
	contact := testContact(21, testID(3), "person@example.com")
	window, _ := NewNotificationWindow(Tuesday, 480, 1_020)
	next, err := UpdateNotificationPreferences(contact, []Key{testKey("sla.warning")}, []NotificationWindow{window}, false, 1, testInstant(9))
	if err != nil {
		t.Fatal(err)
	}
	if next.Version() != 2 || next.Fields().EmailAllowed || !slices.Equal(next.Fields().NotificationCategories, []Key{testKey("sla.warning")}) {
		t.Fatalf("unexpected preference version: %#v", next.Fields())
	}
	if _, err := UpdateNotificationPreferences(next, nil, nil, true, 1, testInstant(10)); err != ErrVersionConflict {
		t.Fatalf("stale update error = %v", err)
	}
	archived, err := ArchiveContact(next, 2, testInstant(10))
	if err != nil {
		t.Fatal(err)
	}
	if archived.Active() || archived.ArchivedAt() == nil || archived.Version() != 3 {
		t.Fatalf("invalid archive: %s", archived)
	}
	if _, err := ProjectCustomerSafe(archived); err != ErrResolutionDenied {
		t.Fatalf("archived projection error = %v", err)
	}
	if _, err := ReplaceContact(archived, archived.Fields(), 3, testInstant(11)); err != ErrInvalidContact {
		t.Fatalf("archived replace error = %v", err)
	}
}

func TestContactRejectsInvalidFields(t *testing.T) {
	t.Parallel()
	validID := testID(4)
	validTenant := testID(5)
	validAt := testInstant(8)
	overlapA, _ := NewNotificationWindow(Monday, 60, 120)
	overlapB, _ := NewNotificationWindow(Monday, 119, 180)

	tests := []struct {
		name   string
		mutate func(*EntityID, *EntityID, *ContactFields, *time.Time)
	}{
		{"zero id", func(id, _ *EntityID, _ *ContactFields, _ *time.Time) { *id = EntityID{} }},
		{"zero tenant", func(_, tenant *EntityID, _ *ContactFields, _ *time.Time) { *tenant = EntityID{} }},
		{"empty first name", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) { fields.FirstName = "" }},
		{"directional last name", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) { fields.LastName = "Ro\u202essi" }},
		{"invalid email", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) {
			fields.Email = Email{canonical: "x@localhost"}
		}},
		{"html phone", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) { fields.Phone = "<redacted>" }},
		{"invalid language", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) { fields.Language = "UND" }},
		{"filesystem timezone", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) { fields.Timezone = "../../etc/passwd" }},
		{"invalid class", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) { fields.Class = Key{} }},
		{"duplicate categories", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) {
			fields.NotificationCategories = []Key{testKey("sla.warning"), testKey("sla.warning")}
		}},
		{"overlapping windows", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) {
			fields.NotificationWindows = []NotificationWindow{overlapA, overlapB}
		}},
		{"invalid linked pair", func(_, _ *EntityID, fields *ContactFields, _ *time.Time) {
			fields.LinkedAccount = &LinkedAccount{membershipID: testID(20)}
		}},
		{"non utc instant", func(_, _ *EntityID, _ *ContactFields, at *time.Time) { *at = at.In(time.FixedZone("bad", 60)) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			id, tenant, fields, at := validID, validTenant, testFields("person@example.com"), validAt
			test.mutate(&id, &tenant, &fields, &at)
			if _, err := NewContact(id, tenant, fields, at); err != ErrInvalidContact {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestNotificationWindowBounds(t *testing.T) {
	t.Parallel()
	for _, input := range []struct {
		day        ISOWeekday
		start, end int
	}{
		{0, 0, 1}, {8, 0, 1}, {Monday, -1, 1}, {Monday, 0, 0},
		{Monday, 1_440, 1_441}, {Monday, 60, 60}, {Monday, 120, 60},
	} {
		if _, err := NewNotificationWindow(input.day, input.start, input.end); err != ErrInvalidContact {
			t.Fatalf("NewNotificationWindow(%d,%d,%d) error = %v", input.day, input.start, input.end, err)
		}
	}
}
