package ticketing

import (
	"strings"
	"testing"
)

func TestPlanAlertRelationIsExplicitAndNonMerging(t *testing.T) {
	tenant, source, target, actor := fixtureID(1), fixtureID(301), fixtureID(302), fixtureID(303)
	authority := authorityFixture(t, actor)
	reason, err := NewAlertRelationReason("Same endpoint and detection window")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanAlertRelation(
		tenant, actor, source, target, AlertRelationCorrelation, reason, 4, 9, authority,
	)
	if err != nil || plan.Source() != source || plan.Target() != target ||
		plan.SourceVersion() != 5 || plan.TargetVersion() != 10 ||
		plan.String() == "" {
		t.Fatalf("PlanAlertRelation() plan=%+v error=%v", plan, err)
	}
}

func TestPlanAlertRelationRejectsSelfUnknownAndNonOperator(t *testing.T) {
	tenant, source, target, actor := fixtureID(1), fixtureID(304), fixtureID(305), fixtureID(306)
	reason, _ := NewAlertRelationReason("Explicit evidence")
	operator := authorityFixture(t, actor)
	customer := authorityFrom(t, operator, PrincipalCustomer, true, nil, []Permission{PermissionAlertUpdate}, nil, nil, nil)
	updateOnly := authorityFrom(t, operator, PrincipalOperator, true, nil, []Permission{PermissionAlertUpdate}, nil, nil, nil)

	tests := []struct {
		name      string
		target    EntityID
		kind      AlertRelationKind
		authority AuthorizationSnapshot
	}{
		{name: "self", target: source, kind: AlertRelationDuplicateOf, authority: operator},
		{name: "unknown kind", target: target, kind: 99, authority: operator},
		{name: "customer", target: target, kind: AlertRelationCorrelation, authority: customer},
		{name: "update without read", target: target, kind: AlertRelationCorrelation, authority: updateOnly},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := PlanAlertRelation(tenant, actor, source, test.target, test.kind, reason, 1, 1, test.authority); err == nil {
				t.Fatal("PlanAlertRelation() accepted invalid relation")
			}
		})
	}
}

func TestAlertRelationReasonHasOnePlainTextRepresentation(t *testing.T) {
	for _, value := range []string{
		"Evidence contains <script> as literal text",
		"Una correlazione verificata",
	} {
		reason, err := NewAlertRelationReason(value)
		if err != nil || reason.Value() != value || reason.String() == value {
			t.Fatalf("NewAlertRelationReason(%q) = (%v, %v)", value, reason, err)
		}
	}

	for name, value := range map[string]string{
		"empty":           "",
		"leading space":   " reason",
		"trailing space":  "reason ",
		"tab":             "reason\ttext",
		"newline":         "reason\ntext",
		"bidi":            "reason\u202etext",
		"oversized bytes": string(make([]byte, maxAlertRelationReasonBytes+1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewAlertRelationReason(value); err == nil {
				t.Fatalf("NewAlertRelationReason(%q) accepted invalid text", value)
			}
		})
	}
	if _, err := NewAlertRelationReason(strings.Repeat("é", 1_001)); err == nil {
		t.Fatal("NewAlertRelationReason accepted more than 2,000 UTF-8 bytes")
	}
}

func TestParseAlertRelationKindIsClosed(t *testing.T) {
	for value, want := range map[string]AlertRelationKind{
		"duplicate_of": AlertRelationDuplicateOf,
		"correlation":  AlertRelationCorrelation,
	} {
		got, err := ParseAlertRelationKind(value)
		if err != nil || got != want || got.String() != value {
			t.Fatalf("ParseAlertRelationKind(%q)=%v,%v", value, got, err)
		}
	}
	if _, err := ParseAlertRelationKind("duplicate"); err == nil {
		t.Fatal("ParseAlertRelationKind() accepted unknown value")
	}
}
