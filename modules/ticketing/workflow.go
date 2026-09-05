package ticketing

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// StateAction declares whether a non-transition command is admitted in one
// workflow state and which transactional side effects it must schedule.
type StateAction struct {
	action  Action
	effects EffectPlan
}

func NewStateAction(action Action, effects EffectPlan) (StateAction, error) {
	if !validAction(action) || action == ActionTransition || !validEffectPlan(effects) {
		return StateAction{}, ErrInvalidWorkflow
	}
	return StateAction{action: action, effects: effects}, nil
}

func (action StateAction) Action() Action      { return action.action }
func (action StateAction) Effects() EffectPlan { return action.effects }

// StateDefinition is immutable after construction. Customer visibility is a
// workflow gate and is combined with the aggregate's own visibility flag.
type StateDefinition struct {
	key        Key
	initial    bool
	terminal   bool
	visibility Visibility
	actions    []StateAction
}

func NewStateDefinition(
	key Key,
	initial bool,
	terminal bool,
	visibility Visibility,
	actions []StateAction,
) (StateDefinition, error) {
	if !validKey(key.value) || !validVisibility(visibility) || len(actions) > int(ActionLink) {
		return StateDefinition{}, ErrInvalidWorkflow
	}
	canonical := slices.Clone(actions)
	for _, action := range canonical {
		if !validAction(action.action) || action.action == ActionTransition || !validEffectPlan(action.effects) {
			return StateDefinition{}, ErrInvalidWorkflow
		}
	}
	slices.SortFunc(canonical, func(left, right StateAction) int {
		return int(left.action) - int(right.action)
	})
	for index := 1; index < len(canonical); index++ {
		if canonical[index-1].action == canonical[index].action {
			return StateDefinition{}, ErrInvalidWorkflow
		}
	}
	return StateDefinition{
		key:        key,
		initial:    initial,
		terminal:   terminal,
		visibility: visibility,
		actions:    canonical,
	}, nil
}

func (state StateDefinition) Key() Key               { return state.key }
func (state StateDefinition) Initial() bool          { return state.initial }
func (state StateDefinition) Terminal() bool         { return state.terminal }
func (state StateDefinition) Visibility() Visibility { return state.visibility }
func (state StateDefinition) Actions() []StateAction { return slices.Clone(state.actions) }
func (state StateDefinition) String() string         { return state.key.value }

func (state StateDefinition) effectFor(action Action) (EffectPlan, bool) {
	index, found := slices.BinarySearchFunc(state.actions, action, func(candidate StateAction, target Action) int {
		return int(candidate.action) - int(target)
	})
	if !found {
		return EffectPlan{}, false
	}
	return state.actions[index].effects, true
}

func validStateDefinition(state StateDefinition) bool {
	if !validKey(state.key.value) || !validVisibility(state.visibility) || len(state.actions) > int(ActionLink) {
		return false
	}
	for index, action := range state.actions {
		if !validAction(action.action) || action.action == ActionTransition || !validEffectPlan(action.effects) ||
			index > 0 && state.actions[index-1].action >= action.action {
			return false
		}
	}
	return true
}

// TransitionDefinition is an exact allowlisted edge. Required roles are
// any-of; required permissions and custom fields are all-of. Reopen is valid
// only for an edge leaving a terminal state.
type TransitionDefinition struct {
	key                  Key
	from                 Key
	to                   Key
	requiredComment      bool
	reopen               bool
	requiredRoles        []Key
	requiredPermissions  []Permission
	requiredCustomFields []Key
	condition            Condition
	effects              EffectPlan
}

func NewTransitionDefinition(
	key Key,
	from Key,
	to Key,
	requiredComment bool,
	reopen bool,
	requiredRoles []Key,
	requiredPermissions []Permission,
	requiredCustomFields []Key,
	effects EffectPlan,
) (TransitionDefinition, error) {
	return NewConditionalTransitionDefinition(
		key, from, to, requiredComment, reopen, requiredRoles, requiredPermissions,
		requiredCustomFields, Condition{}, effects,
	)
}

func NewConditionalTransitionDefinition(
	key Key,
	from Key,
	to Key,
	requiredComment bool,
	reopen bool,
	requiredRoles []Key,
	requiredPermissions []Permission,
	requiredCustomFields []Key,
	condition Condition,
	effects EffectPlan,
) (TransitionDefinition, error) {
	roles, rolesOK := canonicalKeys(requiredRoles, maxRequirements)
	permissions, permissionsOK := canonicalPermissions(requiredPermissions, maxRequirements)
	fields, fieldsOK := canonicalKeys(requiredCustomFields, maxRequirements)
	if !validKey(key.value) || !validKey(from.value) || !validKey(to.value) || from == to || !rolesOK || !permissionsOK ||
		!fieldsOK || !validCondition(condition) || !validEffectPlan(effects) {
		return TransitionDefinition{}, ErrInvalidWorkflow
	}
	return TransitionDefinition{
		key:                  key,
		from:                 from,
		to:                   to,
		requiredComment:      requiredComment,
		reopen:               reopen,
		requiredRoles:        roles,
		requiredPermissions:  permissions,
		requiredCustomFields: fields,
		condition:            cloneCondition(condition),
		effects:              effects,
	}, nil
}

func (transition TransitionDefinition) Key() Key              { return transition.key }
func (transition TransitionDefinition) From() Key             { return transition.from }
func (transition TransitionDefinition) To() Key               { return transition.to }
func (transition TransitionDefinition) RequiredComment() bool { return transition.requiredComment }
func (transition TransitionDefinition) Reopen() bool          { return transition.reopen }
func (transition TransitionDefinition) RequiredRoles() []Key {
	return slices.Clone(transition.requiredRoles)
}
func (transition TransitionDefinition) RequiredPermissions() []Permission {
	return slices.Clone(transition.requiredPermissions)
}
func (transition TransitionDefinition) RequiredCustomFields() []Key {
	return slices.Clone(transition.requiredCustomFields)
}
func (transition TransitionDefinition) Condition() Condition {
	return cloneCondition(transition.condition)
}
func (transition TransitionDefinition) Effects() EffectPlan { return transition.effects }

func (transition TransitionDefinition) String() string {
	return transition.key.value + ":" + transition.from.value + "->" + transition.to.value
}

func validTransitionDefinition(transition TransitionDefinition) bool {
	roles, rolesOK := canonicalKeys(transition.requiredRoles, maxRequirements)
	permissions, permissionsOK := canonicalPermissions(transition.requiredPermissions, maxRequirements)
	fields, fieldsOK := canonicalKeys(transition.requiredCustomFields, maxRequirements)
	return validKey(transition.key.value) && validKey(transition.from.value) && validKey(transition.to.value) && transition.from != transition.to &&
		rolesOK && slices.Equal(roles, transition.requiredRoles) &&
		permissionsOK && slices.Equal(permissions, transition.requiredPermissions) &&
		fieldsOK && slices.Equal(fields, transition.requiredCustomFields) && validCondition(transition.condition) &&
		validEffectPlan(transition.effects)
}

// WorkflowDefinition is a version-pinned, aggregate-specific state machine.
// Alert and Case definitions are never interchangeable, even if their state
// keys happen to match.
type WorkflowDefinition struct {
	id          EntityID
	kind        AggregateKind
	version     uint64
	initial     Key
	states      []StateDefinition
	transitions []TransitionDefinition
}

func NewWorkflowDefinition(
	id EntityID,
	kind AggregateKind,
	version uint64,
	states []StateDefinition,
	transitions []TransitionDefinition,
) (WorkflowDefinition, error) {
	if !validEntityID(id) || !validAggregateKind(kind) || version == 0 || version > maxVersion ||
		len(states) < 2 || len(states) > maxWorkflowStates || len(transitions) == 0 ||
		len(transitions) > maxWorkflowTransitions {
		return WorkflowDefinition{}, ErrInvalidWorkflow
	}
	canonicalStates := cloneStates(states)
	slices.SortFunc(canonicalStates, func(left, right StateDefinition) int {
		return strings.Compare(left.key.value, right.key.value)
	})
	stateByKey := make(map[Key]StateDefinition, len(canonicalStates))
	initialCount := 0
	terminalCount := 0
	var initial Key
	for _, state := range canonicalStates {
		if !validStateDefinition(state) {
			return WorkflowDefinition{}, ErrInvalidWorkflow
		}
		if _, duplicate := stateByKey[state.key]; duplicate {
			return WorkflowDefinition{}, ErrInvalidWorkflow
		}
		stateByKey[state.key] = state
		if state.initial {
			initialCount++
			initial = state.key
		}
		if state.terminal {
			terminalCount++
		}
		for _, action := range state.actions {
			if kind == AggregateAlert && action.action == ActionLink ||
				kind == AggregateCase && action.action == ActionEscalate {
				return WorkflowDefinition{}, ErrInvalidWorkflow
			}
		}
		_, allowsCreate := state.effectFor(ActionCreate)
		if allowsCreate != state.initial {
			return WorkflowDefinition{}, ErrInvalidWorkflow
		}
	}
	if initialCount != 1 || terminalCount == 0 || stateByKey[initial].terminal {
		return WorkflowDefinition{}, ErrInvalidWorkflow
	}

	canonicalTransitions := cloneTransitions(transitions)
	slices.SortFunc(canonicalTransitions, compareTransitions)
	outgoing := make(map[Key][]TransitionDefinition, len(canonicalStates))
	transitionKeys := make(map[Key]struct{}, len(canonicalTransitions))
	edges := make(map[[2]Key]struct{}, len(canonicalTransitions))
	for _, transition := range canonicalTransitions {
		if !validTransitionDefinition(transition) {
			return WorkflowDefinition{}, ErrInvalidWorkflow
		}
		fromState, fromExists := stateByKey[transition.from]
		toState, toExists := stateByKey[transition.to]
		_, duplicateKey := transitionKeys[transition.key]
		_, duplicateEdge := edges[[2]Key{transition.from, transition.to}]
		if !fromExists || !toExists || duplicateKey || duplicateEdge {
			return WorkflowDefinition{}, ErrInvalidWorkflow
		}
		transitionKeys[transition.key] = struct{}{}
		edges[[2]Key{transition.from, transition.to}] = struct{}{}
		for _, permission := range transition.requiredPermissions {
			if !permissionBelongsToKind(permission, kind) {
				return WorkflowDefinition{}, ErrInvalidWorkflow
			}
		}
		if transition.reopen != fromState.terminal || transition.reopen && toState.terminal ||
			!transition.reopen && toState.initial {
			return WorkflowDefinition{}, ErrInvalidWorkflow
		}
		outgoing[transition.from] = append(outgoing[transition.from], transition)
	}
	for _, state := range canonicalStates {
		if !state.terminal && len(outgoing[state.key]) == 0 {
			return WorkflowDefinition{}, ErrInvalidWorkflow
		}
	}
	if !allStatesReachable(initial, canonicalStates, outgoing) {
		return WorkflowDefinition{}, ErrInvalidWorkflow
	}

	return WorkflowDefinition{
		id:          id,
		kind:        kind,
		version:     version,
		initial:     initial,
		states:      canonicalStates,
		transitions: canonicalTransitions,
	}, nil
}

func (workflow WorkflowDefinition) ID() EntityID              { return workflow.id }
func (workflow WorkflowDefinition) Kind() AggregateKind       { return workflow.kind }
func (workflow WorkflowDefinition) Version() uint64           { return workflow.version }
func (workflow WorkflowDefinition) InitialState() Key         { return workflow.initial }
func (workflow WorkflowDefinition) States() []StateDefinition { return cloneStates(workflow.states) }
func (workflow WorkflowDefinition) Transitions() []TransitionDefinition {
	return cloneTransitions(workflow.transitions)
}

func (workflow WorkflowDefinition) String() string {
	return fmt.Sprintf("WorkflowDefinition{kind:%s,version:%d,states:%d,transitions:%d}",
		workflow.kind, workflow.version, len(workflow.states), len(workflow.transitions))
}

func (workflow WorkflowDefinition) state(key Key) (StateDefinition, bool) {
	index, found := slices.BinarySearchFunc(workflow.states, key, func(candidate StateDefinition, target Key) int {
		return strings.Compare(candidate.key.value, target.value)
	})
	if !found {
		return StateDefinition{}, false
	}
	return workflow.states[index], true
}

func (workflow WorkflowDefinition) transition(key Key) (TransitionDefinition, bool) {
	target := TransitionDefinition{key: key}
	index, found := slices.BinarySearchFunc(workflow.transitions, target, compareTransitions)
	if !found {
		return TransitionDefinition{}, false
	}
	return workflow.transitions[index], true
}

func validWorkflowDefinition(workflow WorkflowDefinition) bool {
	if !validEntityID(workflow.id) || !validAggregateKind(workflow.kind) || workflow.version == 0 ||
		workflow.version > maxVersion || !validKey(workflow.initial.value) ||
		len(workflow.states) < 2 || len(workflow.states) > maxWorkflowStates ||
		len(workflow.transitions) == 0 || len(workflow.transitions) > maxWorkflowTransitions {
		return false
	}
	rebuilt, err := NewWorkflowDefinition(
		workflow.id,
		workflow.kind,
		workflow.version,
		workflow.states,
		workflow.transitions,
	)
	return err == nil && rebuilt.initial == workflow.initial &&
		reflect.DeepEqual(rebuilt.states, workflow.states) && reflect.DeepEqual(rebuilt.transitions, workflow.transitions)
}

func compareTransitions(left, right TransitionDefinition) int {
	return strings.Compare(left.key.value, right.key.value)
}

func cloneStates(states []StateDefinition) []StateDefinition {
	result := slices.Clone(states)
	for index := range result {
		result[index].actions = slices.Clone(result[index].actions)
	}
	return result
}

func cloneTransitions(transitions []TransitionDefinition) []TransitionDefinition {
	result := slices.Clone(transitions)
	for index := range result {
		result[index].requiredRoles = slices.Clone(result[index].requiredRoles)
		result[index].requiredPermissions = slices.Clone(result[index].requiredPermissions)
		result[index].requiredCustomFields = slices.Clone(result[index].requiredCustomFields)
		result[index].condition = cloneCondition(result[index].condition)
	}
	return result
}

func allStatesReachable(
	initial Key,
	states []StateDefinition,
	outgoing map[Key][]TransitionDefinition,
) bool {
	seen := map[Key]struct{}{initial: {}}
	queue := []Key{initial}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, transition := range outgoing[current] {
			if _, exists := seen[transition.to]; exists {
				continue
			}
			seen[transition.to] = struct{}{}
			queue = append(queue, transition.to)
		}
	}
	return len(seen) == len(states)
}
