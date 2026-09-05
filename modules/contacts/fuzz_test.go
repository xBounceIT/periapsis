package contacts

import (
	"strings"
	"testing"
	"time"
)

func FuzzNewEmail(f *testing.F) {
	for _, seed := range []string{
		"person@example.com", "Shared@Example.COM", "x@localhost", "a..b@example.com",
		"\x00@example.com", "name@exa\u202emple.com", "name@example..com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		email, err := NewEmail(value)
		if err == nil && (!validEmail(email) || email.String() != strings.ToLower(value)) {
			t.Fatalf("accepted non-canonical email %q", value)
		}
	})
}

func FuzzRuleConstruction(f *testing.F) {
	for _, seed := range []struct {
		field, operator uint8
		value           string
	}{
		{uint8(FieldTag), uint8(OperatorContains), "security"},
		{uint8(FieldEscalationPriority), uint8(OperatorGreaterThanOrEqual), "50"},
		{255, 255, "<script>"},
	} {
		f.Add(seed.field, seed.operator, seed.value)
	}
	f.Fuzz(func(t *testing.T, field, operator uint8, value string) {
		rule, err := NewPredicate(PredicateField(field), PredicateOperator(operator), value)
		if err == nil && !validRule(rule) {
			t.Fatal("constructor returned an invalid rule")
		}
	})
}

func FuzzResolveTargetsNeverCrossesTenant(f *testing.F) {
	f.Add(byte(1), byte(2), true)
	f.Add(byte(10), byte(10), false)
	f.Fuzz(func(t *testing.T, tenantSeed, contactTenantSeed byte, ticket bool) {
		tenant := testID(tenantSeed)
		contactTenant := testID(contactTenantSeed)
		contact := testContact(80, contactTenant, "fuzz@example.com")
		surface := SurfaceTenantEvent
		var links []EntityID
		if ticket {
			surface = SurfaceTicketEvent
			links = []EntityID{contact.ID()}
		}
		plan, err := ResolveTargets(ResolutionInput{
			TenantID: tenant, Selector: AllCustomerContactsTarget(), Category: testKey("sla.warning"),
			OccurredAt: time.Date(2026, 8, 25, 9, 0, 0, 0, time.UTC), Surface: surface,
			TicketContactIDs: links, Contacts: []Contact{contact},
		})
		if tenant != contactTenant {
			if err != ErrResolutionDrift {
				t.Fatalf("mixed tenant error = %v", err)
			}
			return
		}
		if err != nil || len(plan.Recipients()) != 1 {
			t.Fatalf("same tenant resolution = %#v, %v", plan, err)
		}
	})
}
