package contacts

import (
	"slices"
	"strconv"
	"strings"
)

type RuleNodeKind uint8

const (
	RuleAll RuleNodeKind = iota + 1
	RuleAny
	RuleNot
	RulePredicate
)

func (kind RuleNodeKind) String() string {
	switch kind {
	case RuleAll:
		return "all"
	case RuleAny:
		return "any"
	case RuleNot:
		return "not"
	case RulePredicate:
		return "predicate"
	default:
		return "unknown"
	}
}

type PredicateField uint8

const (
	FieldActive PredicateField = iota + 1
	FieldEmailAllowed
	FieldContactClass
	FieldTag
	FieldNotificationCategory
	FieldLanguage
	FieldTimezone
	FieldEscalationPriority
	FieldLinkedAccount
)

func (field PredicateField) String() string {
	switch field {
	case FieldActive:
		return "active"
	case FieldEmailAllowed:
		return "email_allowed"
	case FieldContactClass:
		return "contact_class"
	case FieldTag:
		return "tag"
	case FieldNotificationCategory:
		return "notification_category"
	case FieldLanguage:
		return "language"
	case FieldTimezone:
		return "timezone"
	case FieldEscalationPriority:
		return "escalation_priority"
	case FieldLinkedAccount:
		return "linked_account"
	default:
		return "unknown"
	}
}

type PredicateOperator uint8

const (
	OperatorEquals PredicateOperator = iota + 1
	OperatorNotEquals
	OperatorOneOf
	OperatorNoneOf
	OperatorContains
	OperatorNotContains
	OperatorGreaterThanOrEqual
	OperatorLessThanOrEqual
	OperatorExists
	OperatorNotExists
)

func (operator PredicateOperator) String() string {
	switch operator {
	case OperatorEquals:
		return "equals"
	case OperatorNotEquals:
		return "not_equals"
	case OperatorOneOf:
		return "one_of"
	case OperatorNoneOf:
		return "none_of"
	case OperatorContains:
		return "contains"
	case OperatorNotContains:
		return "not_contains"
	case OperatorGreaterThanOrEqual:
		return "greater_than_or_equal"
	case OperatorLessThanOrEqual:
		return "less_than_or_equal"
	case OperatorExists:
		return "exists"
	case OperatorNotExists:
		return "not_exists"
	default:
		return "unknown"
	}
}

// RuleNode is an immutable, bounded declarative rule. Values can only target
// allowlisted contact metadata; names, addresses, and phone numbers are not
// rule fields.
type RuleNode struct {
	kind     RuleNodeKind
	children []RuleNode
	field    PredicateField
	operator PredicateOperator
	values   []string
}

func NewAllRule(children ...RuleNode) (RuleNode, error) {
	return newCompositeRule(RuleAll, children)
}

func NewAnyRule(children ...RuleNode) (RuleNode, error) {
	return newCompositeRule(RuleAny, children)
}

func NewNotRule(child RuleNode) (RuleNode, error) {
	return canonicalRule(RuleNode{kind: RuleNot, children: []RuleNode{child}})
}

func NewPredicate(field PredicateField, operator PredicateOperator, values ...string) (RuleNode, error) {
	return canonicalRule(RuleNode{kind: RulePredicate, field: field, operator: operator, values: slices.Clone(values)})
}

func newCompositeRule(kind RuleNodeKind, children []RuleNode) (RuleNode, error) {
	return canonicalRule(RuleNode{kind: kind, children: slices.Clone(children)})
}

func canonicalRule(input RuleNode) (RuleNode, error) {
	nodes := 0
	result, signature, ok := canonicalRuleAt(input, 1, &nodes)
	if !ok || signature == "" || nodes > maximumRuleNodes {
		return RuleNode{}, ErrInvalidRule
	}
	return result, nil
}

func canonicalRuleAt(input RuleNode, depth int, nodes *int) (RuleNode, string, bool) {
	*nodes++
	if depth > maximumRuleDepth || *nodes > maximumRuleNodes {
		return RuleNode{}, "", false
	}
	switch input.kind {
	case RuleAll, RuleAny:
		if len(input.children) < 1 || len(input.children) > maximumPredicateValues ||
			input.field != 0 || input.operator != 0 || len(input.values) != 0 {
			return RuleNode{}, "", false
		}
		type signedChild struct {
			node      RuleNode
			signature string
		}
		children := make([]signedChild, len(input.children))
		for index, child := range input.children {
			canonical, signature, ok := canonicalRuleAt(child, depth+1, nodes)
			if !ok {
				return RuleNode{}, "", false
			}
			children[index] = signedChild{node: canonical, signature: signature}
		}
		slices.SortFunc(children, func(left, right signedChild) int { return strings.Compare(left.signature, right.signature) })
		result := RuleNode{kind: input.kind, children: make([]RuleNode, len(children))}
		parts := make([]string, len(children))
		for index, child := range children {
			if index > 0 && child.signature == children[index-1].signature {
				return RuleNode{}, "", false
			}
			result.children[index] = child.node
			parts[index] = child.signature
		}
		return result, input.kind.String() + "(" + strings.Join(parts, ",") + ")", true
	case RuleNot:
		if len(input.children) != 1 || input.field != 0 || input.operator != 0 || len(input.values) != 0 {
			return RuleNode{}, "", false
		}
		child, signature, ok := canonicalRuleAt(input.children[0], depth+1, nodes)
		return RuleNode{kind: RuleNot, children: []RuleNode{child}}, "not(" + signature + ")", ok
	case RulePredicate:
		if len(input.children) != 0 {
			return RuleNode{}, "", false
		}
		values, ok := canonicalPredicate(input.field, input.operator, input.values)
		if !ok {
			return RuleNode{}, "", false
		}
		result := RuleNode{kind: RulePredicate, field: input.field, operator: input.operator, values: values}
		return result, "predicate(" + input.field.String() + "," + input.operator.String() + "," + strings.Join(values, "|") + ")", true
	default:
		return RuleNode{}, "", false
	}
}

func canonicalPredicate(field PredicateField, operator PredicateOperator, input []string) ([]string, bool) {
	if len(input) > maximumPredicateValues {
		return nil, false
	}
	values := slices.Clone(input)
	switch field {
	case FieldActive, FieldEmailAllowed:
		if operator != OperatorEquals && operator != OperatorNotEquals || len(values) != 1 ||
			values[0] != "true" && values[0] != "false" {
			return nil, false
		}
	case FieldContactClass:
		if !setOperator(operator) || !canonicalStableValues(values, 1, maximumPredicateValues) {
			return nil, false
		}
	case FieldTag, FieldNotificationCategory:
		if operator != OperatorContains && operator != OperatorNotContains ||
			!canonicalStableValues(values, 1, 1) {
			return nil, false
		}
	case FieldLanguage:
		if !setOperator(operator) || len(values) < 1 {
			return nil, false
		}
		for _, value := range values {
			if !validLanguage(value) {
				return nil, false
			}
		}
		if !sortUniqueStrings(values) {
			return nil, false
		}
	case FieldTimezone:
		if !setOperator(operator) || len(values) < 1 || len(values) > maximumPredicateValues {
			return nil, false
		}
		for _, value := range values {
			if !validTimezone(value) {
				return nil, false
			}
		}
		if !sortUniqueStrings(values) {
			return nil, false
		}
	case FieldEscalationPriority:
		if operator != OperatorEquals && operator != OperatorNotEquals &&
			operator != OperatorGreaterThanOrEqual && operator != OperatorLessThanOrEqual || len(values) != 1 {
			return nil, false
		}
		if _, ok := parseBoundedInteger(values[0], 0, 100); !ok {
			return nil, false
		}
	case FieldLinkedAccount:
		if operator != OperatorExists && operator != OperatorNotExists || len(values) != 0 {
			return nil, false
		}
	default:
		return nil, false
	}
	return values, true
}

func setOperator(operator PredicateOperator) bool {
	return operator == OperatorEquals || operator == OperatorNotEquals ||
		operator == OperatorOneOf || operator == OperatorNoneOf
}

func canonicalStableValues(values []string, minimum, maximum int) bool {
	if len(values) < minimum || len(values) > maximum {
		return false
	}
	for _, value := range values {
		if !validKey(value) {
			return false
		}
	}
	return sortUniqueStrings(values)
}

func sortUniqueStrings(values []string) bool {
	slices.Sort(values)
	for index := 1; index < len(values); index++ {
		if values[index-1] == values[index] {
			return false
		}
	}
	return true
}

func (node RuleNode) Kind() RuleNodeKind          { return node.kind }
func (node RuleNode) Field() PredicateField       { return node.field }
func (node RuleNode) Operator() PredicateOperator { return node.operator }
func (node RuleNode) Children() []RuleNode        { return slices.Clone(node.children) }
func (node RuleNode) Values() []string            { return slices.Clone(node.values) }

func validRule(node RuleNode) bool {
	canonical, err := canonicalRule(node)
	return err == nil && sameRule(canonical, node)
}

func sameRule(left, right RuleNode) bool {
	if left.kind != right.kind || left.field != right.field || left.operator != right.operator ||
		!slices.Equal(left.values, right.values) || len(left.children) != len(right.children) {
		return false
	}
	for index := range left.children {
		if !sameRule(left.children[index], right.children[index]) {
			return false
		}
	}
	return true
}

func (node RuleNode) matches(contact Contact) bool {
	switch node.kind {
	case RuleAll:
		for _, child := range node.children {
			if !child.matches(contact) {
				return false
			}
		}
		return true
	case RuleAny:
		for _, child := range node.children {
			if child.matches(contact) {
				return true
			}
		}
		return false
	case RuleNot:
		return !node.children[0].matches(contact)
	case RulePredicate:
		return node.matchesPredicate(contact)
	default:
		return false
	}
}

func (node RuleNode) matchesPredicate(contact Contact) bool {
	fields := contact.fields
	switch node.field {
	case FieldActive:
		return compareBoolean(contact.Active(), node.operator, node.values[0] == "true")
	case FieldEmailAllowed:
		return compareBoolean(fields.EmailAllowed, node.operator, node.values[0] == "true")
	case FieldContactClass:
		return compareSetValue(fields.Class.value, node.operator, node.values)
	case FieldTag:
		return compareContainedKey(fields.Tags, node.operator, node.values[0])
	case FieldNotificationCategory:
		return compareContainedKey(fields.NotificationCategories, node.operator, node.values[0])
	case FieldLanguage:
		return compareSetValue(fields.Language, node.operator, node.values)
	case FieldTimezone:
		return compareSetValue(fields.Timezone, node.operator, node.values)
	case FieldEscalationPriority:
		value, _ := strconv.Atoi(node.values[0])
		switch node.operator {
		case OperatorEquals:
			return int(fields.EscalationPriority) == value
		case OperatorNotEquals:
			return int(fields.EscalationPriority) != value
		case OperatorGreaterThanOrEqual:
			return int(fields.EscalationPriority) >= value
		case OperatorLessThanOrEqual:
			return int(fields.EscalationPriority) <= value
		}
	case FieldLinkedAccount:
		return node.operator == OperatorExists && fields.LinkedAccount != nil ||
			node.operator == OperatorNotExists && fields.LinkedAccount == nil
	}
	return false
}

func compareBoolean(actual bool, operator PredicateOperator, expected bool) bool {
	return operator == OperatorEquals && actual == expected || operator == OperatorNotEquals && actual != expected
}

func compareSetValue(actual string, operator PredicateOperator, expected []string) bool {
	contains := slices.Contains(expected, actual)
	switch operator {
	case OperatorEquals, OperatorOneOf:
		return contains
	case OperatorNotEquals, OperatorNoneOf:
		return !contains
	default:
		return false
	}
}

func compareContainedKey(actual []Key, operator PredicateOperator, expected string) bool {
	contains := slices.ContainsFunc(actual, func(value Key) bool { return value.value == expected })
	return operator == OperatorContains && contains || operator == OperatorNotContains && !contains
}
