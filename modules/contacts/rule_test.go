package contacts

import (
	"slices"
	"strings"
	"testing"
)

func TestRuleIsCanonicalAndMatchesOnlyAllowlistedMetadata(t *testing.T) {
	t.Parallel()
	tag, _ := NewPredicate(FieldTag, OperatorContains, "executive")
	priority, _ := NewPredicate(FieldEscalationPriority, OperatorGreaterThanOrEqual, "20")
	rule, err := NewAllRule(priority, tag)
	if err != nil {
		t.Fatal(err)
	}
	if rule.Children()[0].Field().String() != "escalation_priority" || rule.Children()[1].Field().String() != "tag" {
		t.Fatalf("children are not deterministically ordered: %#v", rule.Children())
	}
	contact := testContact(10, testID(1), "person@example.com")
	if !rule.matches(contact) {
		t.Fatal("valid contact did not match")
	}
	fields := contact.Fields()
	fields.EscalationPriority = 19
	next, err := ReplaceContact(contact, fields, 1, testInstant(9))
	if err != nil {
		t.Fatal(err)
	}
	if rule.matches(next) {
		t.Fatal("out-of-range contact matched")
	}
	children := rule.Children()
	children[0].values[0] = "0"
	if !rule.matches(contact) {
		t.Fatal("rule leaked mutable children")
	}
}

func TestRuleRejectsHostileShapes(t *testing.T) {
	t.Parallel()
	valid, _ := NewPredicate(FieldActive, OperatorEquals, "true")
	tests := []RuleNode{
		{},
		{kind: RuleAll},
		{kind: RuleAll, children: []RuleNode{valid, valid}},
		{kind: RuleNot, children: []RuleNode{valid, valid}},
		{kind: RulePredicate, field: FieldActive, operator: OperatorContains, values: []string{"true"}},
		{kind: RulePredicate, field: FieldTag, operator: OperatorContains, values: []string{"Bad Tag"}},
		{kind: RulePredicate, field: FieldLinkedAccount, operator: OperatorExists, values: []string{"unexpected"}},
		{kind: RulePredicate, field: FieldEscalationPriority, operator: OperatorEquals, values: []string{"01"}},
		{kind: RuleNodeKind(255)},
	}
	deep := valid
	for range maximumRuleDepth {
		deep = RuleNode{kind: RuleNot, children: []RuleNode{deep}}
	}
	tests = append(tests, deep)
	for index, input := range tests {
		if _, err := canonicalRule(input); err != ErrInvalidRule {
			t.Fatalf("case %d error = %v", index, err)
		}
	}
}

func TestPredicateValueOrderingAndDuplication(t *testing.T) {
	t.Parallel()
	rule, err := NewPredicate(FieldContactClass, OperatorOneOf, "silver", "gold")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rule.Values(), []string{"gold", "silver"}) {
		t.Fatalf("values = %#v", rule.Values())
	}
	if _, err := NewPredicate(FieldContactClass, OperatorOneOf, "gold", "gold"); err != ErrInvalidRule {
		t.Fatalf("duplicate values error = %v", err)
	}
	if strings.Contains(strings.Join(rule.Values(), ","), "@") {
		t.Fatal("rule unexpectedly accepts destination data")
	}
}

func TestManualAndDynamicGroupsAreVersionPinned(t *testing.T) {
	t.Parallel()
	tenant, groupID := testID(1), testID(2)
	manual, err := NewGroupVersion(groupID, tenant, 1, "Primary contacts", "", GroupManual, RuleNode{},
		[]EntityID{testID(20), testID(10)}, testInstant(8))
	if err != nil {
		t.Fatal(err)
	}
	group, err := NewRecipientGroup(groupID, tenant, testKey("primary"), manual, testInstant(8))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(group.Current().Members(), []EntityID{testID(10), testID(20)}) {
		t.Fatalf("manual members not sorted: %#v", group.Current().Members())
	}
	predicate, _ := NewPredicate(FieldContactClass, OperatorEquals, "gold")
	next, err := VersionRecipientGroup(group, "Gold contacts", "Dynamic", GroupDynamic, predicate, nil, 1, testInstant(9))
	if err != nil {
		t.Fatal(err)
	}
	if next.Current().Version() != 2 || next.Current().Mode() != GroupDynamic {
		t.Fatalf("unexpected version: %s", next)
	}
	if _, err := VersionRecipientGroup(next, "x", "", GroupManual, RuleNode{}, nil, 1, testInstant(10)); err != ErrVersionConflict {
		t.Fatalf("stale version error = %v", err)
	}
	if _, err := NewGroupVersion(groupID, tenant, 3, "Bad", "", GroupDynamic, predicate,
		[]EntityID{testID(10)}, testInstant(10)); err != ErrInvalidGroup {
		t.Fatalf("mixed group error = %v", err)
	}
}
