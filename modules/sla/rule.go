package sla

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	maximumRuleDepth  = 16
	maximumRuleNodes  = 256
	maximumFactValues = 128
)

type FactKind string

const (
	FactCustomerTier         FactKind = "customer_tier"
	FactObjectType           FactKind = "object_type"
	FactSeverity             FactKind = "severity"
	FactPriority             FactKind = "priority"
	FactCategory             FactKind = "category"
	FactSource               FactKind = "source"
	FactOperatorTeam         FactKind = "operator_team"
	FactTag                  FactKind = "tag"
	FactCustomField          FactKind = "custom_field"
	FactLocalHour            FactKind = "local_hour"
	FactLocalWeekday         FactKind = "local_weekday"
	FactCustomerContactClass FactKind = "customer_contact_class"
)

func validFactKind(value FactKind) bool {
	switch value {
	case FactCustomerTier, FactObjectType, FactSeverity, FactPriority, FactCategory,
		FactSource, FactOperatorTeam, FactTag, FactCustomField, FactLocalHour,
		FactLocalWeekday, FactCustomerContactClass:
		return true
	default:
		return false
	}
}

type FactPath struct {
	Kind FactKind
	Key  Key
}

func validFactPath(path FactPath) bool {
	if !validFactKind(path.Kind) {
		return false
	}
	return path.Kind == FactCustomField == validKey(path.Key.value)
}

type FactInput struct {
	Path   FactPath
	Values []string
}

type FactSnapshotInput struct {
	TenantID    EntityID
	ObjectType  ObjectType
	EvaluatedAt time.Time
	Timezone    string
	Facts       []FactInput
}

type FactSnapshot struct {
	tenantID    EntityID
	objectType  ObjectType
	evaluatedAt time.Time
	timezone    string
	values      map[FactPath][]string
}

func NewFactSnapshot(input FactSnapshotInput) (FactSnapshot, error) {
	location, err := loadIANALocation(input.Timezone)
	if err != nil || !validEntityID(input.TenantID) || !validObjectType(input.ObjectType) ||
		!validInstant(input.EvaluatedAt) || len(input.Facts) > maximumRuleNodes {
		return FactSnapshot{}, ErrInvalidPolicy
	}
	values := make(map[FactPath][]string, len(input.Facts)+3)
	for _, fact := range input.Facts {
		if !validFactPath(fact.Path) || fact.Path.Kind == FactObjectType ||
			fact.Path.Kind == FactLocalHour || fact.Path.Kind == FactLocalWeekday {
			return FactSnapshot{}, ErrInvalidPolicy
		}
		if _, duplicate := values[fact.Path]; duplicate {
			return FactSnapshot{}, ErrInvalidPolicy
		}
		canonical, ok := canonicalFactValues(fact.Path.Kind, fact.Values)
		if !ok {
			return FactSnapshot{}, ErrInvalidPolicy
		}
		values[fact.Path] = canonical
	}
	local := input.EvaluatedAt.In(location)
	values[FactPath{Kind: FactObjectType}] = []string{string(input.ObjectType)}
	values[FactPath{Kind: FactLocalHour}] = []string{strconv.Itoa(local.Hour())}
	values[FactPath{Kind: FactLocalWeekday}] = []string{strings.ToLower(local.Weekday().String())}
	return FactSnapshot{
		tenantID: input.TenantID, objectType: input.ObjectType, evaluatedAt: input.EvaluatedAt,
		timezone: input.Timezone, values: values,
	}, nil
}

func (snapshot FactSnapshot) TenantID() EntityID     { return snapshot.tenantID }
func (snapshot FactSnapshot) ObjectType() ObjectType { return snapshot.objectType }
func (snapshot FactSnapshot) EvaluatedAt() time.Time { return snapshot.evaluatedAt }
func (snapshot FactSnapshot) Timezone() string       { return snapshot.timezone }
func (snapshot FactSnapshot) Values(path FactPath) []string {
	return slices.Clone(snapshot.values[path])
}
func (snapshot FactSnapshot) String() string {
	return fmt.Sprintf(
		"sla.FactSnapshot{object:%s,evaluatedAt:%s,timezone:%s,facts:%d,values:[REDACTED]}",
		snapshot.objectType, snapshot.evaluatedAt.Format(time.RFC3339), snapshot.timezone, len(snapshot.values),
	)
}
func (snapshot FactSnapshot) GoString() string { return snapshot.String() }

type RuleKind string

const (
	RuleAll       RuleKind = "all"
	RuleAny       RuleKind = "any"
	RuleNot       RuleKind = "not"
	RulePredicate RuleKind = "predicate"
)

type PredicateOperator string

const (
	PredicateEquals    PredicateOperator = "equals"
	PredicateNotEquals PredicateOperator = "not_equals"
	PredicateOneOf     PredicateOperator = "one_of"
	PredicateNoneOf    PredicateOperator = "none_of"
	PredicateExists    PredicateOperator = "exists"
	PredicateNotExists PredicateOperator = "not_exists"
)

type PredicateInput struct {
	Path     FactPath
	Operator PredicateOperator
	Values   []string
}

type RuleInput struct {
	Kind      RuleKind
	Children  []*RuleInput
	Predicate PredicateInput
}

type predicate struct {
	path     FactPath
	operator PredicateOperator
	values   []string
}

type Rule struct {
	kind      RuleKind
	children  []Rule
	predicate predicate
}

func NewRule(input *RuleInput) (Rule, error) {
	if input == nil {
		return Rule{}, ErrInvalidPolicy
	}
	nodes := 0
	stack := make(map[*RuleInput]bool)
	rule, ok := canonicalRule(input, 0, &nodes, stack)
	if !ok {
		return Rule{}, ErrInvalidPolicy
	}
	return rule, nil
}

func (rule Rule) Matches(snapshot FactSnapshot) bool {
	if !snapshot.valid() {
		return false
	}
	switch rule.kind {
	case RuleAll:
		for _, child := range rule.children {
			if !child.Matches(snapshot) {
				return false
			}
		}
		return true
	case RuleAny:
		for _, child := range rule.children {
			if child.Matches(snapshot) {
				return true
			}
		}
		return false
	case RuleNot:
		return len(rule.children) == 1 && !rule.children[0].Matches(snapshot)
	case RulePredicate:
		return rule.predicate.matches(snapshot.values[rule.predicate.path])
	default:
		return false
	}
}

func (rule Rule) String() string {
	return fmt.Sprintf("sla.Rule{kind:%s,nodes:%d,predicates:[REDACTED]}", rule.kind, rule.nodeCount())
}
func (rule Rule) GoString() string { return rule.String() }

func canonicalRule(input *RuleInput, depth int, nodes *int, stack map[*RuleInput]bool) (Rule, bool) {
	if input == nil || depth > maximumRuleDepth || *nodes >= maximumRuleNodes || stack[input] {
		return Rule{}, false
	}
	*nodes++
	stack[input] = true
	defer delete(stack, input)
	switch input.Kind {
	case RuleAll, RuleAny:
		if input.Kind == RuleAny && len(input.Children) == 0 || len(input.Children) > maximumRuleNodes ||
			!emptyPredicateInput(input.Predicate) {
			return Rule{}, false
		}
		children := make([]Rule, len(input.Children))
		for index, child := range input.Children {
			canonical, ok := canonicalRule(child, depth+1, nodes, stack)
			if !ok {
				return Rule{}, false
			}
			children[index] = canonical
		}
		return Rule{kind: input.Kind, children: children}, true
	case RuleNot:
		if len(input.Children) != 1 || !emptyPredicateInput(input.Predicate) {
			return Rule{}, false
		}
		child, ok := canonicalRule(input.Children[0], depth+1, nodes, stack)
		return Rule{kind: RuleNot, children: []Rule{child}}, ok
	case RulePredicate:
		if len(input.Children) != 0 || !validFactPath(input.Predicate.Path) {
			return Rule{}, false
		}
		values, ok := canonicalPredicateValues(input.Predicate.Path.Kind, input.Predicate.Operator, input.Predicate.Values)
		if !ok {
			return Rule{}, false
		}
		return Rule{kind: RulePredicate, predicate: predicate{
			path: input.Predicate.Path, operator: input.Predicate.Operator, values: values,
		}}, true
	default:
		return Rule{}, false
	}
}

func emptyPredicateInput(input PredicateInput) bool {
	return input.Path == (FactPath{}) && input.Operator == "" && len(input.Values) == 0
}

func canonicalPredicateValues(kind FactKind, operator PredicateOperator, inputs []string) ([]string, bool) {
	wantsNone := operator == PredicateExists || operator == PredicateNotExists
	wantsOne := operator == PredicateEquals || operator == PredicateNotEquals
	wantsMany := operator == PredicateOneOf || operator == PredicateNoneOf
	if !wantsNone && !wantsOne && !wantsMany || wantsNone && len(inputs) != 0 ||
		wantsOne && len(inputs) != 1 || wantsMany && (len(inputs) == 0 || len(inputs) > maximumFactValues) {
		return nil, false
	}
	if wantsNone {
		return nil, true
	}
	return canonicalFactLiterals(kind, inputs)
}

func canonicalFactValues(kind FactKind, inputs []string) ([]string, bool) {
	if len(inputs) == 0 || len(inputs) > maximumFactValues {
		return nil, false
	}
	if kind != FactTag && kind != FactOperatorTeam && kind != FactCustomField && len(inputs) != 1 {
		return nil, false
	}
	result := slices.Clone(inputs)
	for _, value := range result {
		if !validFactLiteral(kind, value) {
			return nil, false
		}
	}
	slices.Sort(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func canonicalFactLiterals(kind FactKind, inputs []string) ([]string, bool) {
	if len(inputs) == 0 || len(inputs) > maximumFactValues {
		return nil, false
	}
	result := slices.Clone(inputs)
	for _, value := range result {
		if !validFactLiteral(kind, value) {
			return nil, false
		}
	}
	slices.Sort(result)
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, false
		}
	}
	return result, true
}

func validFactLiteral(kind FactKind, value string) bool {
	if !validText(value, 2_048, false, false) {
		return false
	}
	switch kind {
	case FactCustomerTier, FactSeverity, FactPriority, FactCategory, FactSource, FactTag, FactCustomerContactClass:
		return validKey(value)
	case FactOperatorTeam:
		_, err := ParseEntityID(value)
		return err == nil
	case FactObjectType:
		return validObjectType(ObjectType(value))
	case FactLocalHour:
		hour, err := strconv.Atoi(value)
		return err == nil && hour >= 0 && hour <= 23 && strconv.Itoa(hour) == value
	case FactLocalWeekday:
		return value == "sunday" || value == "monday" || value == "tuesday" || value == "wednesday" ||
			value == "thursday" || value == "friday" || value == "saturday"
	case FactCustomField:
		return true
	default:
		return false
	}
}

func (predicate predicate) matches(facts []string) bool {
	switch predicate.operator {
	case PredicateExists:
		return len(facts) != 0
	case PredicateNotExists:
		return len(facts) == 0
	case PredicateEquals:
		return slices.Contains(facts, predicate.values[0])
	case PredicateNotEquals:
		return !slices.Contains(facts, predicate.values[0])
	case PredicateOneOf:
		return intersectsSorted(facts, predicate.values)
	case PredicateNoneOf:
		return !intersectsSorted(facts, predicate.values)
	default:
		return false
	}
}

func intersectsSorted(left, right []string) bool {
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) && rightIndex < len(right) {
		switch strings.Compare(left[leftIndex], right[rightIndex]) {
		case -1:
			leftIndex++
		case 1:
			rightIndex++
		default:
			return true
		}
	}
	return false
}

func (rule Rule) nodeCount() int {
	count := 1
	for _, child := range rule.children {
		count += child.nodeCount()
	}
	return count
}

func (snapshot FactSnapshot) valid() bool {
	return validEntityID(snapshot.tenantID) && validObjectType(snapshot.objectType) &&
		validInstant(snapshot.evaluatedAt) && snapshot.timezone != "" && snapshot.values != nil
}
