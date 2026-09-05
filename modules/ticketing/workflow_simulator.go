package ticketing

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var ErrInvalidWorkflowSimulation = errors.New("invalid workflow simulation")

// WorkflowSimulationScenario is hypothetical data used only to explain a
// published definition. It never creates an AuthorizationSnapshot and its
// output must never be reused as an authorization decision.
type WorkflowSimulationScenario struct {
	state                Key
	commentPresent       bool
	roles                []Key
	permissions          []Permission
	providedCustomFields []Key
	facts                ConditionFacts
}

func NewWorkflowSimulationScenario(
	state Key,
	commentPresent bool,
	roles []Key,
	permissions []Permission,
	providedCustomFields []Key,
	facts ConditionFacts,
) (WorkflowSimulationScenario, error) {
	canonicalRoles, rolesOK := canonicalKeys(roles, maxRequirements)
	canonicalPermissions, permissionsOK := canonicalPermissions(permissions, maxRequirements)
	canonicalFields, fieldsOK := canonicalKeys(providedCustomFields, maxRequirements)
	if !validKey(state.value) || !rolesOK || !permissionsOK || !fieldsOK || !validConditionFacts(facts) {
		return WorkflowSimulationScenario{}, ErrInvalidWorkflowSimulation
	}
	return WorkflowSimulationScenario{
		state: state, commentPresent: commentPresent, roles: canonicalRoles,
		permissions: canonicalPermissions, providedCustomFields: canonicalFields,
		facts: ConditionFacts{items: slices.Clone(facts.items)},
	}, nil
}

func (scenario WorkflowSimulationScenario) State() Key           { return scenario.state }
func (scenario WorkflowSimulationScenario) CommentPresent() bool { return scenario.commentPresent }
func (scenario WorkflowSimulationScenario) Roles() []Key         { return slices.Clone(scenario.roles) }
func (scenario WorkflowSimulationScenario) Permissions() []Permission {
	return slices.Clone(scenario.permissions)
}
func (scenario WorkflowSimulationScenario) ProvidedCustomFields() []Key {
	return slices.Clone(scenario.providedCustomFields)
}
func (scenario WorkflowSimulationScenario) Facts() ConditionFacts {
	return ConditionFacts{items: slices.Clone(scenario.facts.items)}
}

func (scenario WorkflowSimulationScenario) String() string {
	return fmt.Sprintf(
		"WorkflowSimulationScenario{state:%s,comment:%t,roles:%d,permissions:%d,custom_fields:%d,facts:[REDACTED]}",
		scenario.state, scenario.commentPresent, len(scenario.roles), len(scenario.permissions),
		len(scenario.providedCustomFields),
	)
}

// TransitionSimulation explains every gate on one outgoing transition. Roles
// are any-of; permissions and custom fields are all-of. A missing or mistyped
// condition fact is reported as a failed condition.
type TransitionSimulation struct {
	key                   Key
	from                  Key
	to                    Key
	reopen                bool
	eligible              bool
	commentSatisfied      bool
	roleSatisfied         bool
	permissionsSatisfied  bool
	customFieldsSatisfied bool
	conditionSatisfied    bool
	missingRoles          []Key
	missingPermissions    []Permission
	missingCustomFields   []Key
	effects               EffectPlan
}

func (result TransitionSimulation) Key() Key                    { return result.key }
func (result TransitionSimulation) From() Key                   { return result.from }
func (result TransitionSimulation) To() Key                     { return result.to }
func (result TransitionSimulation) Reopen() bool                { return result.reopen }
func (result TransitionSimulation) Eligible() bool              { return result.eligible }
func (result TransitionSimulation) CommentSatisfied() bool      { return result.commentSatisfied }
func (result TransitionSimulation) RoleSatisfied() bool         { return result.roleSatisfied }
func (result TransitionSimulation) PermissionsSatisfied() bool  { return result.permissionsSatisfied }
func (result TransitionSimulation) CustomFieldsSatisfied() bool { return result.customFieldsSatisfied }
func (result TransitionSimulation) ConditionSatisfied() bool    { return result.conditionSatisfied }
func (result TransitionSimulation) MissingRoles() []Key         { return slices.Clone(result.missingRoles) }
func (result TransitionSimulation) MissingPermissions() []Permission {
	return slices.Clone(result.missingPermissions)
}
func (result TransitionSimulation) MissingCustomFields() []Key {
	return slices.Clone(result.missingCustomFields)
}
func (result TransitionSimulation) Effects() EffectPlan { return result.effects }

func (result TransitionSimulation) String() string {
	return fmt.Sprintf(
		"TransitionSimulation{transition:%s,eligible:%t,missing_roles:%d,missing_permissions:%d,missing_fields:%d,condition:%t}",
		result.key, result.eligible, len(result.missingRoles), len(result.missingPermissions),
		len(result.missingCustomFields), result.conditionSatisfied,
	)
}

func SimulateWorkflow(
	workflow WorkflowDefinition,
	scenario WorkflowSimulationScenario,
) ([]TransitionSimulation, error) {
	if !validWorkflowDefinition(workflow) || !validWorkflowSimulationScenario(scenario) {
		return nil, ErrInvalidWorkflowSimulation
	}
	if _, exists := workflow.state(scenario.state); !exists {
		return nil, ErrInvalidWorkflowSimulation
	}
	for _, permission := range scenario.permissions {
		if !permissionBelongsToKind(permission, workflow.kind) {
			return nil, ErrInvalidWorkflowSimulation
		}
	}
	facts, err := simulationFacts(workflow, scenario)
	if err != nil {
		return nil, err
	}
	results := make([]TransitionSimulation, 0)
	for _, transition := range workflow.transitions {
		if transition.from != scenario.state {
			continue
		}
		missingRoles := missingAnyOfKeys(transition.requiredRoles, scenario.roles)
		missingPermissions := missingPermissions(transition.requiredPermissions, scenario.permissions)
		missingFields := missingAllOfKeys(transition.requiredCustomFields, scenario.providedCustomFields)
		commentSatisfied := !transition.requiredComment || scenario.commentPresent
		roleSatisfied := len(missingRoles) == 0
		permissionsSatisfied := len(missingPermissions) == 0
		fieldsSatisfied := len(missingFields) == 0
		conditionSatisfied := transition.condition.Evaluate(facts)
		results = append(results, TransitionSimulation{
			key: transition.key, from: transition.from, to: transition.to, reopen: transition.reopen,
			eligible:         commentSatisfied && roleSatisfied && permissionsSatisfied && fieldsSatisfied && conditionSatisfied,
			commentSatisfied: commentSatisfied, roleSatisfied: roleSatisfied,
			permissionsSatisfied: permissionsSatisfied, customFieldsSatisfied: fieldsSatisfied,
			conditionSatisfied: conditionSatisfied, missingRoles: missingRoles,
			missingPermissions: missingPermissions, missingCustomFields: missingFields,
			effects: transition.effects,
		})
	}
	return results, nil
}

func validWorkflowSimulationScenario(scenario WorkflowSimulationScenario) bool {
	rebuilt, err := NewWorkflowSimulationScenario(
		scenario.state, scenario.commentPresent, scenario.roles, scenario.permissions,
		scenario.providedCustomFields, scenario.facts,
	)
	return err == nil && rebuilt.state == scenario.state && rebuilt.commentPresent == scenario.commentPresent &&
		slices.Equal(rebuilt.roles, scenario.roles) && slices.Equal(rebuilt.permissions, scenario.permissions) &&
		slices.Equal(rebuilt.providedCustomFields, scenario.providedCustomFields) &&
		validConditionFacts(rebuilt.facts)
}

func simulationFacts(
	workflow WorkflowDefinition,
	scenario WorkflowSimulationScenario,
) (ConditionFacts, error) {
	items := slices.Clone(scenario.facts.items)
	derived := []struct {
		name  string
		value string
	}{
		{name: "aggregate_kind", value: workflow.kind.String()},
		{name: "state", value: scenario.state.value},
	}
	for _, item := range derived {
		field, fieldErr := NewConditionField(item.name)
		value, valueErr := NewTextConditionValue(item.value)
		if fieldErr != nil || valueErr != nil {
			return ConditionFacts{}, ErrInvalidWorkflowSimulation
		}
		if existing, found := scenario.facts.fact(field); found {
			actual, hasValue := existing.Value()
			text, isText := actual.Text()
			if !hasValue || !isText || text != item.value {
				return ConditionFacts{}, ErrInvalidWorkflowSimulation
			}
			continue
		}
		fact, factErr := NewConditionFact(field, value)
		if factErr != nil {
			return ConditionFacts{}, ErrInvalidWorkflowSimulation
		}
		items = append(items, fact)
	}
	result, err := NewConditionFacts(items...)
	if err != nil {
		return ConditionFacts{}, ErrInvalidWorkflowSimulation
	}
	return result, nil
}

func missingAnyOfKeys(required, actual []Key) []Key {
	if len(required) == 0 {
		return nil
	}
	for _, item := range required {
		if _, found := slices.BinarySearchFunc(actual, item, compareSimulationKey); found {
			return nil
		}
	}
	return slices.Clone(required)
}

func missingAllOfKeys(required, actual []Key) []Key {
	missing := make([]Key, 0, len(required))
	for _, item := range required {
		if _, found := slices.BinarySearchFunc(actual, item, compareSimulationKey); !found {
			missing = append(missing, item)
		}
	}
	return missing
}

func compareSimulationKey(candidate, target Key) int {
	return strings.Compare(candidate.value, target.value)
}

func missingPermissions(required, actual []Permission) []Permission {
	missing := make([]Permission, 0, len(required))
	for _, item := range required {
		if _, found := slices.BinarySearch(actual, item); !found {
			missing = append(missing, item)
		}
	}
	return missing
}
