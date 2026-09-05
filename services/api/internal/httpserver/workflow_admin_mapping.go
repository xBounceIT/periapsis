package httpserver

import (
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	"github.com/periapsis-im/periapsis/services/api/internal/contract"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

func mapManagedWorkflow(record applicationticketing.WorkflowAdminRecord) (contract.ManagedWorkflow, error) {
	definition, err := mapWorkflowDefinition(record.Workflow.Current())
	if err != nil {
		return contract.ManagedWorkflow{}, err
	}
	kind := contract.WorkflowKind(record.Workflow.Kind().String())
	status := contract.WorkflowAdminStatus(record.Workflow.Status().String())
	if !kind.Valid() || !status.Valid() || record.Workflow.Revision() == 0 ||
		record.Workflow.Revision() > uint64(maximumResourceVersion) || record.Workflow.CurrentVersion() == 0 ||
		record.Workflow.CurrentVersion() > uint64(maximumResourceVersion) {
		return contract.ManagedWorkflow{}, applicationticketing.ErrUnavailable
	}
	id := uuid.UUID(record.Workflow.ID().Bytes())
	tenantID := uuid.UUID(record.Workflow.Tenant().Bytes())
	if id == uuid.Nil || tenantID == uuid.Nil || definition.Id != id || definition.Kind != kind ||
		uint64(definition.Version) != record.Workflow.CurrentVersion() {
		return contract.ManagedWorkflow{}, applicationticketing.ErrUnavailable
	}
	result := contract.ManagedWorkflow{
		Id: id, TenantId: tenantID, Kind: kind, Key: record.Workflow.Key().String(),
		DisplayName: record.Workflow.DisplayName(), Description: record.Workflow.Description(),
		IsDefault: record.Workflow.IsDefault(), Status: status,
		Revision: int64(record.Workflow.Revision()), CurrentVersion: int64(record.Workflow.CurrentVersion()),
		Current: definition, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
	if record.ArchivedAt != nil {
		archivedAt := *record.ArchivedAt
		result.ArchivedAt = &archivedAt
	}
	return result, nil
}

func mapWorkflowDefinition(definition kernel.WorkflowDefinition) (contract.WorkflowDefinition, error) {
	kind := contract.WorkflowKind(definition.Kind().String())
	if !kind.Valid() || definition.Version() == 0 || definition.Version() > uint64(maximumResourceVersion) {
		return contract.WorkflowDefinition{}, applicationticketing.ErrUnavailable
	}
	states := definition.States()
	mappedStates := make([]contract.WorkflowStateDefinition, len(states))
	for index, state := range states {
		actions := state.Actions()
		mappedActions := make([]contract.WorkflowStateAction, len(actions))
		for actionIndex, action := range actions {
			mappedAction := contract.WorkflowAction(action.Action().String())
			if !mappedAction.Valid() {
				return contract.WorkflowDefinition{}, applicationticketing.ErrUnavailable
			}
			mappedActions[actionIndex] = contract.WorkflowStateAction{
				Action: mappedAction, Effects: mapWorkflowEffects(action.Effects()),
			}
		}
		visibility := contract.WorkflowVisibility(state.Visibility().String())
		if !visibility.Valid() {
			return contract.WorkflowDefinition{}, applicationticketing.ErrUnavailable
		}
		mappedStates[index] = contract.WorkflowStateDefinition{
			Key: state.Key().String(), Initial: state.Initial(), Terminal: state.Terminal(),
			Visibility: visibility, Actions: mappedActions,
		}
	}
	transitions := definition.Transitions()
	mappedTransitions := make([]contract.WorkflowTransitionDefinition, len(transitions))
	for index, transition := range transitions {
		permissions := transition.RequiredPermissions()
		mappedPermissions := make([]contract.WorkflowPermission, len(permissions))
		for permissionIndex, permission := range permissions {
			mapped := contract.WorkflowPermission(permission.String())
			if !mapped.Valid() {
				return contract.WorkflowDefinition{}, applicationticketing.ErrUnavailable
			}
			mappedPermissions[permissionIndex] = mapped
		}
		mapped := contract.WorkflowTransitionDefinition{
			Key: transition.Key().String(), From: transition.From().String(), To: transition.To().String(),
			RequiredComment: transition.RequiredComment(), Reopen: transition.Reopen(),
			RequiredRoles:        workflowKeyStrings(transition.RequiredRoles()),
			RequiredPermissions:  mappedPermissions,
			RequiredCustomFields: workflowKeyStrings(transition.RequiredCustomFields()),
			Effects:              mapWorkflowEffects(transition.Effects()),
		}
		if transition.Condition().Configured() {
			condition, err := mapWorkflowCondition(transition.Condition())
			if err != nil {
				return contract.WorkflowDefinition{}, err
			}
			mapped.Condition = &condition
		}
		mappedTransitions[index] = mapped
	}
	return contract.WorkflowDefinition{
		Id: uuid.UUID(definition.ID().Bytes()), Kind: kind, Version: int64(definition.Version()),
		InitialState: definition.InitialState().String(), States: mappedStates, Transitions: mappedTransitions,
	}, nil
}

func mapWorkflowVersion(record applicationticketing.WorkflowVersionRecord) (contract.WorkflowVersionRecord, error) {
	definition, err := mapWorkflowDefinition(record.Definition)
	if err != nil {
		return contract.WorkflowVersionRecord{}, err
	}
	result := contract.WorkflowVersionRecord{
		TenantId: record.TenantID, WorkflowId: uuid.UUID(record.Definition.ID().Bytes()),
		Definition: definition, PublisherDisplayName: record.PublisherDisplayName,
		PublishedAt: record.PublishedAt,
	}
	if record.PublishedByMembershipID != nil {
		membershipID := *record.PublishedByMembershipID
		result.PublishedByMembershipId = &membershipID
	}
	return result, nil
}

func mapWorkflowSimulation(result applicationticketing.WorkflowSimulationResult) (contract.WorkflowSimulationResult, error) {
	kind := contract.WorkflowKind(result.Kind.String())
	if !kind.Valid() || result.Version == 0 || result.Version > uint64(maximumResourceVersion) || result.WorkflowID == uuid.Nil {
		return contract.WorkflowSimulationResult{}, applicationticketing.ErrUnavailable
	}
	transitions := make([]contract.WorkflowTransitionSimulation, len(result.Results))
	for index, item := range result.Results {
		permissions := item.MissingPermissions()
		mappedPermissions := make([]contract.WorkflowPermission, len(permissions))
		for permissionIndex, permission := range permissions {
			mapped := contract.WorkflowPermission(permission.String())
			if !mapped.Valid() {
				return contract.WorkflowSimulationResult{}, applicationticketing.ErrUnavailable
			}
			mappedPermissions[permissionIndex] = mapped
		}
		transitions[index] = contract.WorkflowTransitionSimulation{
			Key: item.Key().String(), From: item.From().String(), To: item.To().String(),
			Reopen: item.Reopen(), Eligible: item.Eligible(),
			Gates: contract.WorkflowTransitionGates{
				CommentSatisfied: item.CommentSatisfied(), RoleSatisfied: item.RoleSatisfied(),
				PermissionsSatisfied:  item.PermissionsSatisfied(),
				CustomFieldsSatisfied: item.CustomFieldsSatisfied(), ConditionSatisfied: item.ConditionSatisfied(),
			},
			MissingRoles:        workflowKeyStrings(item.MissingRoles()),
			MissingPermissions:  mappedPermissions,
			MissingCustomFields: workflowKeyStrings(item.MissingCustomFields()),
			Effects:             mapWorkflowEffects(item.Effects()),
		}
	}
	return contract.WorkflowSimulationResult{
		WorkflowId: result.WorkflowID, Kind: kind, Version: int64(result.Version),
		Explanatory: true, Transitions: transitions,
	}, nil
}

func mapWorkflowCondition(condition kernel.Condition) (contract.WorkflowCondition, error) {
	root, configured := condition.Root()
	if !configured {
		return contract.WorkflowCondition{}, errors.New("workflow condition is absent")
	}
	payload, err := mapWorkflowConditionNode(root)
	if err != nil {
		return contract.WorkflowCondition{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return contract.WorkflowCondition{}, applicationticketing.ErrUnavailable
	}
	var mapped contract.WorkflowCondition
	if err := mapped.UnmarshalJSON(encoded); err != nil {
		return contract.WorkflowCondition{}, applicationticketing.ErrUnavailable
	}
	return mapped, nil
}

func mapWorkflowConditionNode(node kernel.ConditionNode) (map[string]any, error) {
	if predicate, ok := node.Predicate(); ok {
		values := predicate.Values()
		mappedValues := make([]map[string]any, len(values))
		for index, value := range values {
			mapped, err := mapWorkflowConditionValue(value)
			if err != nil {
				return nil, err
			}
			mappedValues[index] = mapped
		}
		return map[string]any{
			"kind": "predicate", "field": predicate.Field().String(),
			"operator": predicate.Operator().String(), "values": mappedValues,
		}, nil
	}
	children := node.Children()
	mappedChildren := make([]map[string]any, len(children))
	for index, child := range children {
		mapped, err := mapWorkflowConditionNode(child)
		if err != nil {
			return nil, err
		}
		mappedChildren[index] = mapped
	}
	kind := node.Kind().String()
	if kind != "all" && kind != "any" && kind != "not" {
		return nil, applicationticketing.ErrUnavailable
	}
	return map[string]any{"kind": kind, "children": mappedChildren}, nil
}

func mapWorkflowConditionValue(value kernel.ConditionValue) (map[string]any, error) {
	switch value.Kind().String() {
	case "text":
		item, ok := value.Text()
		if !ok {
			return nil, applicationticketing.ErrUnavailable
		}
		return map[string]any{"type": "text", "value": item}, nil
	case "number":
		item, ok := value.Number()
		if !ok {
			return nil, applicationticketing.ErrUnavailable
		}
		return map[string]any{"type": "number", "value": item}, nil
	case "boolean":
		item, ok := value.Boolean()
		if !ok {
			return nil, applicationticketing.ErrUnavailable
		}
		return map[string]any{"type": "boolean", "value": item}, nil
	case "instant":
		item, ok := value.Instant()
		if !ok {
			return nil, applicationticketing.ErrUnavailable
		}
		return map[string]any{"type": "instant", "value": item}, nil
	default:
		return nil, applicationticketing.ErrUnavailable
	}
}

func mapWorkflowEffects(plan kernel.EffectPlan) contract.WorkflowEffectPlan {
	effects := plan.Effects()
	result := make([]contract.WorkflowEffect, len(effects))
	for index, effect := range effects {
		result[index] = contract.WorkflowEffect(effect.String())
	}
	return result
}

func workflowKeyStrings(values []kernel.Key) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}
