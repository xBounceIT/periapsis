package ticketing

import (
	"math"
	"slices"
	"strings"
	"time"
)

const (
	maxConditionDepth     = 8
	maxConditionNodes     = 128
	maxConditionChildren  = 32
	maxConditionValues    = 32
	maxConditionFacts     = 256
	maxConditionTextBytes = 2 * 1024
	customConditionPrefix = "custom."
	tagConditionPrefix    = "tag."
)

// ConditionValueKind is the closed scalar vocabulary accepted by workflow
// conditions. Collections, executable strings, regular expressions, SQL, and
// arbitrary objects are deliberately absent.
type ConditionValueKind uint8

const (
	ConditionValueText ConditionValueKind = iota + 1
	ConditionValueNumber
	ConditionValueBoolean
	ConditionValueInstant
)

func (kind ConditionValueKind) String() string {
	switch kind {
	case ConditionValueText:
		return "text"
	case ConditionValueNumber:
		return "number"
	case ConditionValueBoolean:
		return "boolean"
	case ConditionValueInstant:
		return "instant"
	default:
		return "unknown"
	}
}

type ConditionValue struct {
	kind    ConditionValueKind
	text    string
	number  float64
	boolean bool
	instant time.Time
}

func NewTextConditionValue(value string) (ConditionValue, error) {
	if !validText(value, maxConditionTextBytes, false) {
		return ConditionValue{}, ErrInvalidWorkflow
	}
	return ConditionValue{kind: ConditionValueText, text: value}, nil
}

func NewNumberConditionValue(value float64) (ConditionValue, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return ConditionValue{}, ErrInvalidWorkflow
	}
	return ConditionValue{kind: ConditionValueNumber, number: value}, nil
}

func NewBooleanConditionValue(value bool) ConditionValue {
	return ConditionValue{kind: ConditionValueBoolean, boolean: value}
}

func NewInstantConditionValue(value time.Time) (ConditionValue, error) {
	canonical := value.Round(0).UTC().Truncate(time.Microsecond)
	if !validInstant(canonical) {
		return ConditionValue{}, ErrInvalidWorkflow
	}
	return ConditionValue{kind: ConditionValueInstant, instant: canonical}, nil
}

func (value ConditionValue) Kind() ConditionValueKind { return value.kind }

func (value ConditionValue) Text() (string, bool) {
	return value.text, value.kind == ConditionValueText
}

func (value ConditionValue) Number() (float64, bool) {
	return value.number, value.kind == ConditionValueNumber
}

func (value ConditionValue) Boolean() (bool, bool) {
	return value.boolean, value.kind == ConditionValueBoolean
}

func (value ConditionValue) Instant() (time.Time, bool) {
	return value.instant, value.kind == ConditionValueInstant
}

func validConditionValue(value ConditionValue) bool {
	switch value.kind {
	case ConditionValueText:
		return validText(value.text, maxConditionTextBytes, false) && value.number == 0 &&
			!value.boolean && value.instant.IsZero()
	case ConditionValueNumber:
		return value.text == "" && !math.IsNaN(value.number) && !math.IsInf(value.number, 0) &&
			!value.boolean && value.instant.IsZero()
	case ConditionValueBoolean:
		return value.text == "" && value.number == 0 && value.instant.IsZero()
	case ConditionValueInstant:
		return value.text == "" && value.number == 0 && !value.boolean && validInstant(value.instant)
	default:
		return false
	}
}

func compareConditionValues(left, right ConditionValue) int {
	if left.kind != right.kind {
		return int(left.kind) - int(right.kind)
	}
	switch left.kind {
	case ConditionValueText:
		return strings.Compare(left.text, right.text)
	case ConditionValueNumber:
		if left.number < right.number {
			return -1
		}
		if left.number > right.number {
			return 1
		}
		return 0
	case ConditionValueBoolean:
		if left.boolean == right.boolean {
			return 0
		}
		if !left.boolean {
			return -1
		}
		return 1
	case ConditionValueInstant:
		return left.instant.Compare(right.instant)
	default:
		return 0
	}
}

var builtInConditionFields = map[string]ConditionValueKind{
	"aggregate_kind":   ConditionValueText,
	"state":            ConditionValueText,
	"severity":         ConditionValueText,
	"priority":         ConditionValueText,
	"category":         ConditionValueText,
	"classification":   ConditionValueText,
	"source":           ConditionValueText,
	"source_type":      ConditionValueText,
	"customer_visible": ConditionValueBoolean,
	"assigned":         ConditionValueBoolean,
	"assignee_present": ConditionValueBoolean,
	"claimed":          ConditionValueBoolean,
	"comment_present":  ConditionValueBoolean,
	"detected_at":      ConditionValueInstant,
	"received_at":      ConditionValueInstant,
	"opened_at":        ConditionValueInstant,
	"created_at":       ConditionValueInstant,
	"updated_at":       ConditionValueInstant,
}

// ConditionField is either a closed core fact or a validated custom/tag key.
// It contains data only and can never name a function, path, or expression.
type ConditionField struct {
	key string
}

func NewConditionField(value string) (ConditionField, error) {
	if _, exists := builtInConditionFields[value]; exists {
		return ConditionField{key: value}, nil
	}
	for _, prefix := range []string{customConditionPrefix, tagConditionPrefix} {
		if strings.HasPrefix(value, prefix) {
			key, err := NewKey(strings.TrimPrefix(value, prefix))
			if err == nil {
				return ConditionField{key: prefix + key.String()}, nil
			}
		}
	}
	return ConditionField{}, ErrInvalidWorkflow
}

func (field ConditionField) String() string { return field.key }

func (field ConditionField) expectedKind() (ConditionValueKind, bool) {
	if kind, exists := builtInConditionFields[field.key]; exists {
		return kind, true
	}
	if strings.HasPrefix(field.key, tagConditionPrefix) {
		return ConditionValueBoolean, true
	}
	return 0, false
}

func validConditionField(field ConditionField) bool {
	rebuilt, err := NewConditionField(field.key)
	return err == nil && rebuilt == field
}

type ConditionOperator uint8

const (
	ConditionEqual ConditionOperator = iota + 1
	ConditionNotEqual
	ConditionIn
	ConditionNotIn
	ConditionLessThan
	ConditionLessThanOrEqual
	ConditionGreaterThan
	ConditionGreaterThanOrEqual
	ConditionExists
	ConditionNotExists
)

func (operator ConditionOperator) String() string {
	switch operator {
	case ConditionEqual:
		return "equal"
	case ConditionNotEqual:
		return "not_equal"
	case ConditionIn:
		return "in"
	case ConditionNotIn:
		return "not_in"
	case ConditionLessThan:
		return "less_than"
	case ConditionLessThanOrEqual:
		return "less_than_or_equal"
	case ConditionGreaterThan:
		return "greater_than"
	case ConditionGreaterThanOrEqual:
		return "greater_than_or_equal"
	case ConditionExists:
		return "exists"
	case ConditionNotExists:
		return "not_exists"
	default:
		return "unknown"
	}
}

type ConditionPredicate struct {
	field    ConditionField
	operator ConditionOperator
	values   []ConditionValue
}

func NewConditionPredicate(
	field ConditionField,
	operator ConditionOperator,
	values ...ConditionValue,
) (ConditionPredicate, error) {
	canonical := slices.Clone(values)
	if !validConditionField(field) || !validConditionOperator(operator, canonical) {
		return ConditionPredicate{}, ErrInvalidWorkflow
	}
	var valueKind ConditionValueKind
	for index, value := range canonical {
		if !validConditionValue(value) || index > 0 && value.kind != valueKind {
			return ConditionPredicate{}, ErrInvalidWorkflow
		}
		valueKind = value.kind
	}
	if expected, constrained := field.expectedKind(); constrained && len(canonical) > 0 && expected != valueKind {
		return ConditionPredicate{}, ErrInvalidWorkflow
	}
	if isOrderingCondition(operator) && valueKind != ConditionValueNumber && valueKind != ConditionValueInstant {
		return ConditionPredicate{}, ErrInvalidWorkflow
	}
	if operator == ConditionIn || operator == ConditionNotIn {
		slices.SortFunc(canonical, compareConditionValues)
		for index := 1; index < len(canonical); index++ {
			if compareConditionValues(canonical[index-1], canonical[index]) == 0 {
				return ConditionPredicate{}, ErrInvalidWorkflow
			}
		}
	}
	return ConditionPredicate{field: field, operator: operator, values: canonical}, nil
}

func (predicate ConditionPredicate) Field() ConditionField       { return predicate.field }
func (predicate ConditionPredicate) Operator() ConditionOperator { return predicate.operator }
func (predicate ConditionPredicate) Values() []ConditionValue    { return slices.Clone(predicate.values) }

func validConditionOperator(operator ConditionOperator, values []ConditionValue) bool {
	switch operator {
	case ConditionExists, ConditionNotExists:
		return len(values) == 0
	case ConditionEqual, ConditionNotEqual, ConditionLessThan, ConditionLessThanOrEqual,
		ConditionGreaterThan, ConditionGreaterThanOrEqual:
		return len(values) == 1
	case ConditionIn, ConditionNotIn:
		return len(values) >= 1 && len(values) <= maxConditionValues
	default:
		return false
	}
}

func isOrderingCondition(operator ConditionOperator) bool {
	return operator >= ConditionLessThan && operator <= ConditionGreaterThanOrEqual
}

func validConditionPredicate(predicate ConditionPredicate) bool {
	rebuilt, err := NewConditionPredicate(predicate.field, predicate.operator, predicate.values...)
	return err == nil && rebuilt.field == predicate.field && rebuilt.operator == predicate.operator &&
		slices.EqualFunc(rebuilt.values, predicate.values, func(left, right ConditionValue) bool {
			return compareConditionValues(left, right) == 0
		})
}

type ConditionNodeKind uint8

const (
	ConditionPredicateNode ConditionNodeKind = iota + 1
	ConditionAllNode
	ConditionAnyNode
	ConditionNotNode
)

func (kind ConditionNodeKind) String() string {
	switch kind {
	case ConditionPredicateNode:
		return "predicate"
	case ConditionAllNode:
		return "all"
	case ConditionAnyNode:
		return "any"
	case ConditionNotNode:
		return "not"
	default:
		return "unknown"
	}
}

type ConditionNode struct {
	kind      ConditionNodeKind
	predicate ConditionPredicate
	children  []ConditionNode
}

func NewPredicateConditionNode(predicate ConditionPredicate) (ConditionNode, error) {
	if !validConditionPredicate(predicate) {
		return ConditionNode{}, ErrInvalidWorkflow
	}
	return ConditionNode{kind: ConditionPredicateNode, predicate: predicate}, nil
}

func NewAllConditionNode(children ...ConditionNode) (ConditionNode, error) {
	return newCompoundConditionNode(ConditionAllNode, children)
}

func NewAnyConditionNode(children ...ConditionNode) (ConditionNode, error) {
	return newCompoundConditionNode(ConditionAnyNode, children)
}

func NewNotConditionNode(child ConditionNode) (ConditionNode, error) {
	if !validConditionNodeLocal(child) {
		return ConditionNode{}, ErrInvalidWorkflow
	}
	return ConditionNode{kind: ConditionNotNode, children: []ConditionNode{cloneConditionNode(child)}}, nil
}

func newCompoundConditionNode(kind ConditionNodeKind, children []ConditionNode) (ConditionNode, error) {
	if len(children) < 2 || len(children) > maxConditionChildren {
		return ConditionNode{}, ErrInvalidWorkflow
	}
	owned := cloneConditionNodes(children)
	for _, child := range owned {
		if !validConditionNodeLocal(child) {
			return ConditionNode{}, ErrInvalidWorkflow
		}
	}
	return ConditionNode{kind: kind, children: owned}, nil
}

func (node ConditionNode) Kind() ConditionNodeKind { return node.kind }

func (node ConditionNode) Predicate() (ConditionPredicate, bool) {
	if node.kind != ConditionPredicateNode {
		return ConditionPredicate{}, false
	}
	return ConditionPredicate{
		field: node.predicate.field, operator: node.predicate.operator, values: slices.Clone(node.predicate.values),
	}, true
}

func (node ConditionNode) Children() []ConditionNode { return cloneConditionNodes(node.children) }

func validConditionNodeLocal(node ConditionNode) bool {
	switch node.kind {
	case ConditionPredicateNode:
		return len(node.children) == 0 && validConditionPredicate(node.predicate)
	case ConditionAllNode, ConditionAnyNode:
		return zeroConditionPredicate(node.predicate) && len(node.children) >= 2 && len(node.children) <= maxConditionChildren
	case ConditionNotNode:
		return zeroConditionPredicate(node.predicate) && len(node.children) == 1
	default:
		return false
	}
}

// Condition owns a bounded immutable AST. Its zero value means no configured
// condition and evaluates true, preserving existing workflow versions.
type Condition struct {
	root ConditionNode
}

func NewCondition(root ConditionNode) (Condition, error) {
	nodes := 0
	if !validConditionTree(root, 1, &nodes) {
		return Condition{}, ErrInvalidWorkflow
	}
	return Condition{root: cloneConditionNode(root)}, nil
}

func (condition Condition) Configured() bool { return condition.root.kind != 0 }

func (condition Condition) Root() (ConditionNode, bool) {
	if !condition.Configured() {
		return ConditionNode{}, false
	}
	return cloneConditionNode(condition.root), true
}

func validCondition(condition Condition) bool {
	if !condition.Configured() {
		return zeroConditionNode(condition.root)
	}
	nodes := 0
	return validConditionTree(condition.root, 1, &nodes)
}

func validConditionTree(node ConditionNode, depth int, nodes *int) bool {
	(*nodes)++
	if depth > maxConditionDepth || *nodes > maxConditionNodes || !validConditionNodeLocal(node) {
		return false
	}
	for _, child := range node.children {
		if !validConditionTree(child, depth+1, nodes) {
			return false
		}
	}
	return true
}

func zeroConditionPredicate(predicate ConditionPredicate) bool {
	return predicate.field == (ConditionField{}) && predicate.operator == 0 && len(predicate.values) == 0
}

func zeroConditionNode(node ConditionNode) bool {
	return node.kind == 0 && zeroConditionPredicate(node.predicate) && len(node.children) == 0
}

func cloneConditionNode(node ConditionNode) ConditionNode {
	result := node
	result.predicate.values = slices.Clone(node.predicate.values)
	result.children = cloneConditionNodes(node.children)
	return result
}

func cloneCondition(condition Condition) Condition {
	if !condition.Configured() {
		return Condition{}
	}
	return Condition{root: cloneConditionNode(condition.root)}
}

func cloneConditionNodes(nodes []ConditionNode) []ConditionNode {
	result := make([]ConditionNode, len(nodes))
	for index, node := range nodes {
		result[index] = cloneConditionNode(node)
	}
	return result
}

type ConditionFact struct {
	field    ConditionField
	value    ConditionValue
	hasValue bool
}

func NewConditionFact(field ConditionField, value ConditionValue) (ConditionFact, error) {
	if !validConditionField(field) || !validConditionValue(value) {
		return ConditionFact{}, ErrInvalidCommand
	}
	if expected, constrained := field.expectedKind(); constrained && expected != value.kind {
		return ConditionFact{}, ErrInvalidCommand
	}
	return ConditionFact{field: field, value: value, hasValue: true}, nil
}

// NewPresenceConditionFact records that a field exists but cannot participate
// in scalar comparison (for example an array, object, or explicit null).
func NewPresenceConditionFact(field ConditionField) (ConditionFact, error) {
	if !validConditionField(field) {
		return ConditionFact{}, ErrInvalidCommand
	}
	return ConditionFact{field: field}, nil
}

func (fact ConditionFact) Field() ConditionField { return fact.field }

func (fact ConditionFact) Value() (ConditionValue, bool) {
	return fact.value, fact.hasValue
}

func validConditionFact(fact ConditionFact) bool {
	if !validConditionField(fact.field) {
		return false
	}
	if !fact.hasValue {
		return fact.value == (ConditionValue{})
	}
	_, err := NewConditionFact(fact.field, fact.value)
	return err == nil
}

type ConditionFacts struct {
	items []ConditionFact
}

func NewConditionFacts(facts ...ConditionFact) (ConditionFacts, error) {
	if len(facts) > maxConditionFacts {
		return ConditionFacts{}, ErrInvalidCommand
	}
	owned := slices.Clone(facts)
	for _, fact := range owned {
		if !validConditionFact(fact) {
			return ConditionFacts{}, ErrInvalidCommand
		}
	}
	slices.SortFunc(owned, func(left, right ConditionFact) int {
		return strings.Compare(left.field.key, right.field.key)
	})
	for index := 1; index < len(owned); index++ {
		if owned[index-1].field == owned[index].field {
			return ConditionFacts{}, ErrInvalidCommand
		}
	}
	return ConditionFacts{items: owned}, nil
}

func (facts ConditionFacts) Items() []ConditionFact { return slices.Clone(facts.items) }

func validConditionFacts(facts ConditionFacts) bool {
	rebuilt, err := NewConditionFacts(facts.items...)
	return err == nil && slices.EqualFunc(rebuilt.items, facts.items, func(left, right ConditionFact) bool {
		return left.field == right.field && left.hasValue == right.hasValue &&
			(!left.hasValue || compareConditionValues(left.value, right.value) == 0)
	})
}

func (facts ConditionFacts) fact(field ConditionField) (ConditionFact, bool) {
	index, found := slices.BinarySearchFunc(facts.items, field, func(candidate ConditionFact, target ConditionField) int {
		return strings.Compare(candidate.field.key, target.key)
	})
	if !found {
		return ConditionFact{}, false
	}
	return facts.items[index], true
}

func (condition Condition) Evaluate(facts ConditionFacts) bool {
	if !validCondition(condition) || !validConditionFacts(facts) {
		return false
	}
	if !condition.Configured() {
		return true
	}
	matched, determinate := evaluateConditionNode(condition.root, facts)
	return determinate && matched
}

func evaluateConditionNode(node ConditionNode, facts ConditionFacts) (bool, bool) {
	switch node.kind {
	case ConditionPredicateNode:
		return evaluateConditionPredicate(node.predicate, facts)
	case ConditionAllNode:
		determinate := true
		for _, child := range node.children {
			matched, known := evaluateConditionNode(child, facts)
			if known && !matched {
				return false, true
			}
			if !known {
				determinate = false
			}
		}
		return determinate, determinate
	case ConditionAnyNode:
		determinate := true
		for _, child := range node.children {
			matched, known := evaluateConditionNode(child, facts)
			if known && matched {
				return true, true
			}
			if !known {
				determinate = false
			}
		}
		return false, determinate
	case ConditionNotNode:
		matched, known := evaluateConditionNode(node.children[0], facts)
		if !known {
			return false, false
		}
		return !matched, true
	default:
		return false, false
	}
}

func evaluateConditionPredicate(predicate ConditionPredicate, facts ConditionFacts) (bool, bool) {
	fact, exists := facts.fact(predicate.field)
	if predicate.operator == ConditionExists {
		return exists, true
	}
	if predicate.operator == ConditionNotExists {
		return !exists, true
	}
	// Negative comparisons also fail closed when a fact is missing or has a
	// different type; absence must be requested explicitly with not_exists.
	if !exists || !fact.hasValue || len(predicate.values) == 0 || fact.value.kind != predicate.values[0].kind {
		return false, false
	}
	actual := fact.value
	comparison := compareConditionValues(actual, predicate.values[0])
	switch predicate.operator {
	case ConditionEqual:
		return comparison == 0, true
	case ConditionNotEqual:
		return comparison != 0, true
	case ConditionIn, ConditionNotIn:
		_, found := slices.BinarySearchFunc(predicate.values, actual, compareConditionValues)
		if predicate.operator == ConditionIn {
			return found, true
		}
		return !found, true
	case ConditionLessThan:
		return comparison < 0, true
	case ConditionLessThanOrEqual:
		return comparison <= 0, true
	case ConditionGreaterThan:
		return comparison > 0, true
	case ConditionGreaterThanOrEqual:
		return comparison >= 0, true
	default:
		return false, false
	}
}
