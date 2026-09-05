package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"
	"unicode/utf8"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	applicationticketing "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

const (
	maximumWorkflowJSONDepth      = 24
	maximumWorkflowJSONValues     = 65_536
	maximumWorkflowConditionDepth = 8
	maximumWorkflowConditionNodes = 128
)

type workflowCreateBody struct {
	Kind        string             `json:"kind"`
	Key         string             `json:"key"`
	DisplayName string             `json:"displayName"`
	Description string             `json:"description"`
	Design      workflowDesignBody `json:"design"`
}

type workflowPublishBody struct {
	ExpectedRevision int64              `json:"expectedRevision"`
	Design           workflowDesignBody `json:"design"`
}

type workflowMetadataBody struct {
	ExpectedRevision int64  `json:"expectedRevision"`
	DisplayName      string `json:"displayName"`
	Description      string `json:"description"`
}

type workflowLifecycleBody struct {
	ExpectedRevision int64 `json:"expectedRevision"`
}

type workflowDesignBody struct {
	States      []workflowStateBody      `json:"states"`
	Transitions []workflowTransitionBody `json:"transitions"`
}

type workflowStateBody struct {
	Key        string                    `json:"key"`
	Initial    bool                      `json:"initial"`
	Terminal   bool                      `json:"terminal"`
	Visibility string                    `json:"visibility"`
	Actions    []workflowStateActionBody `json:"actions"`
}

type workflowStateActionBody struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
}

type workflowTransitionBody struct {
	Key                  string         `json:"key"`
	From                 string         `json:"from"`
	To                   string         `json:"to"`
	RequiredComment      bool           `json:"requiredComment"`
	Reopen               bool           `json:"reopen"`
	RequiredRoles        []string       `json:"requiredRoles"`
	RequiredPermissions  []string       `json:"requiredPermissions"`
	RequiredCustomFields []string       `json:"requiredCustomFields"`
	Condition            map[string]any `json:"condition,omitempty"`
	Effects              []string       `json:"effects"`
}

type workflowSimulationBody struct {
	Version              int64                        `json:"version"`
	State                string                       `json:"state"`
	CommentPresent       bool                         `json:"commentPresent"`
	Roles                []string                     `json:"roles"`
	Permissions          []string                     `json:"permissions"`
	ProvidedCustomFields []string                     `json:"providedCustomFields"`
	Facts                []workflowSimulationFactBody `json:"facts"`
}

type workflowSimulationFactBody struct {
	Field string         `json:"field"`
	Value map[string]any `json:"value,omitempty"`
}

// decodeWorkflowBody enforces an exact, duplicate-free, bounded JSON document
// before any kernel constructor runs. Conditions remain data-only maps only
// long enough for the depth/node-bounded parser below to close their union.
func decodeWorkflowBody(r *http.Request, destination any) error {
	mediaType, err := requestMediaType(r)
	if err != nil || mediaType != "application/json" {
		return errors.New("unsupported workflow request content type")
	}
	defer r.Body.Close()
	body, err := io.ReadAll(io.LimitReader(r.Body, maximumPhase4BodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maximumPhase4BodyBytes || !utf8.Valid(body) {
		clear(body)
		return errors.New("workflow request body is invalid")
	}
	defer clear(body)

	scanner := json.NewDecoder(bytes.NewReader(body))
	scanner.UseNumber()
	count := 0
	if err := scanWorkflowJSONValue(scanner, 0, &count); err != nil {
		return err
	}
	if _, err := scanner.Token(); !errors.Is(err, io.EOF) {
		return errors.New("workflow request body must contain one JSON value")
	}

	var raw any
	if err := json.Unmarshal(body, &raw); err != nil {
		return errors.New("workflow request body does not match the exact contract shape")
	}
	if err := validatePhase4JSONShape(raw, reflect.TypeOf(destination)); err != nil {
		return fmt.Errorf("workflow request body does not match the exact contract shape: %w", err)
	}
	strict := json.NewDecoder(bytes.NewReader(body))
	strict.DisallowUnknownFields()
	if err := strict.Decode(destination); err != nil {
		return errors.New("workflow request body does not match the contract")
	}
	if err := strict.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("workflow request body must contain one JSON value")
	}
	return nil
}

func scanWorkflowJSONValue(decoder *json.Decoder, depth int, count *int) error {
	if depth > maximumWorkflowJSONDepth || *count >= maximumWorkflowJSONValues {
		return errors.New("workflow request body exceeds structural bounds")
	}
	*count++
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok || invalidPhase4JSONKey(key) {
				return errors.New("workflow request body contains an invalid object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("workflow request body contains a duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanWorkflowJSONValue(decoder, depth+1, count); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim('}') {
			return errors.New("workflow request body contains an unterminated object")
		}
	case '[':
		for decoder.More() {
			if err := scanWorkflowJSONValue(decoder, depth+1, count); err != nil {
				return err
			}
		}
		closing, closeErr := decoder.Token()
		if closeErr != nil || closing != json.Delim(']') {
			return errors.New("workflow request body contains an unterminated array")
		}
	default:
		return errors.New("workflow request body contains an invalid delimiter")
	}
	return nil
}

func workflowDesignInput(body workflowDesignBody) (applicationticketing.WorkflowDesignInput, error) {
	states := make([]kernel.StateDefinition, len(body.States))
	for index, item := range body.States {
		key, err := kernel.NewKey(item.Key)
		if err != nil {
			return applicationticketing.WorkflowDesignInput{}, applicationticketing.ErrInvalidInput
		}
		visibility, err := workflowVisibility(item.Visibility)
		if err != nil {
			return applicationticketing.WorkflowDesignInput{}, err
		}
		actions := make([]kernel.StateAction, len(item.Actions))
		for actionIndex, actionBody := range item.Actions {
			action, actionErr := workflowAction(actionBody.Action)
			effects, effectsErr := workflowEffectPlan(actionBody.Effects)
			if actionErr != nil || effectsErr != nil {
				return applicationticketing.WorkflowDesignInput{}, applicationticketing.ErrInvalidInput
			}
			actions[actionIndex], err = kernel.NewStateAction(action, effects)
			if err != nil {
				return applicationticketing.WorkflowDesignInput{}, applicationticketing.ErrInvalidInput
			}
		}
		states[index], err = kernel.NewStateDefinition(key, item.Initial, item.Terminal, visibility, actions)
		if err != nil {
			return applicationticketing.WorkflowDesignInput{}, applicationticketing.ErrInvalidInput
		}
	}

	transitions := make([]kernel.TransitionDefinition, len(body.Transitions))
	for index, item := range body.Transitions {
		key, keyErr := kernel.NewKey(item.Key)
		from, fromErr := kernel.NewKey(item.From)
		to, toErr := kernel.NewKey(item.To)
		roles, rolesErr := workflowKeys(item.RequiredRoles)
		fields, fieldsErr := workflowKeys(item.RequiredCustomFields)
		permissions, permissionsErr := workflowPermissions(item.RequiredPermissions)
		effects, effectsErr := workflowEffectPlan(item.Effects)
		condition, conditionErr := workflowCondition(item.Condition)
		if keyErr != nil || fromErr != nil || toErr != nil || rolesErr != nil || fieldsErr != nil ||
			permissionsErr != nil || effectsErr != nil || conditionErr != nil {
			return applicationticketing.WorkflowDesignInput{}, applicationticketing.ErrInvalidInput
		}
		var err error
		transitions[index], err = kernel.NewConditionalTransitionDefinition(
			key, from, to, item.RequiredComment, item.Reopen, roles, permissions, fields, condition, effects,
		)
		if err != nil {
			return applicationticketing.WorkflowDesignInput{}, applicationticketing.ErrInvalidInput
		}
	}
	return applicationticketing.WorkflowDesignInput{States: states, Transitions: transitions}, nil
}

func workflowSimulationInput(body workflowSimulationBody) (applicationticketing.WorkflowSimulationInput, error) {
	if body.Version < 0 {
		return applicationticketing.WorkflowSimulationInput{}, applicationticketing.ErrInvalidInput
	}
	state, err := kernel.NewKey(body.State)
	if err != nil {
		return applicationticketing.WorkflowSimulationInput{}, applicationticketing.ErrInvalidInput
	}
	roles, err := workflowKeys(body.Roles)
	if err != nil {
		return applicationticketing.WorkflowSimulationInput{}, err
	}
	permissions, err := workflowPermissions(body.Permissions)
	if err != nil {
		return applicationticketing.WorkflowSimulationInput{}, err
	}
	fields, err := workflowKeys(body.ProvidedCustomFields)
	if err != nil {
		return applicationticketing.WorkflowSimulationInput{}, err
	}
	facts := make([]kernel.ConditionFact, len(body.Facts))
	for index, item := range body.Facts {
		field, fieldErr := kernel.NewConditionField(item.Field)
		if fieldErr != nil {
			return applicationticketing.WorkflowSimulationInput{}, applicationticketing.ErrInvalidInput
		}
		if item.Value == nil {
			facts[index], err = kernel.NewPresenceConditionFact(field)
		} else {
			value, valueErr := workflowConditionValue(item.Value)
			if valueErr != nil {
				return applicationticketing.WorkflowSimulationInput{}, applicationticketing.ErrInvalidInput
			}
			facts[index], err = kernel.NewConditionFact(field, value)
		}
		if err != nil {
			return applicationticketing.WorkflowSimulationInput{}, applicationticketing.ErrInvalidInput
		}
	}
	conditionFacts, err := kernel.NewConditionFacts(facts...)
	if err != nil {
		return applicationticketing.WorkflowSimulationInput{}, applicationticketing.ErrInvalidInput
	}
	return applicationticketing.WorkflowSimulationInput{
		Version: uint64(body.Version), State: state, CommentPresent: body.CommentPresent,
		Roles: roles, Permissions: permissions, ProvidedCustomFields: fields, Facts: conditionFacts,
	}, nil
}

func workflowCondition(raw map[string]any) (kernel.Condition, error) {
	if raw == nil {
		return kernel.Condition{}, nil
	}
	nodes := 0
	root, err := workflowConditionNode(raw, 1, &nodes)
	if err != nil {
		return kernel.Condition{}, applicationticketing.ErrInvalidInput
	}
	condition, err := kernel.NewCondition(root)
	if err != nil {
		return kernel.Condition{}, applicationticketing.ErrInvalidInput
	}
	return condition, nil
}

func workflowConditionNode(raw map[string]any, depth int, nodes *int) (kernel.ConditionNode, error) {
	if depth > maximumWorkflowConditionDepth || *nodes >= maximumWorkflowConditionNodes {
		return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
	}
	*nodes++
	kind, ok := raw["kind"].(string)
	if !ok {
		return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
	}
	if kind == "predicate" {
		if !workflowObjectHasExactKeys(raw, "kind", "field", "operator", "values") {
			return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
		}
		fieldValue, fieldOK := raw["field"].(string)
		operatorValue, operatorOK := raw["operator"].(string)
		valueItems, valuesOK := raw["values"].([]any)
		if !fieldOK || !operatorOK || !valuesOK {
			return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
		}
		field, fieldErr := kernel.NewConditionField(fieldValue)
		operator, operatorErr := workflowConditionOperator(operatorValue)
		values := make([]kernel.ConditionValue, len(valueItems))
		for index, item := range valueItems {
			object, objectOK := item.(map[string]any)
			if !objectOK {
				return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
			}
			value, valueErr := workflowConditionValue(object)
			if valueErr != nil {
				return kernel.ConditionNode{}, valueErr
			}
			values[index] = value
		}
		if fieldErr != nil || operatorErr != nil {
			return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
		}
		predicate, err := kernel.NewConditionPredicate(field, operator, values...)
		if err != nil {
			return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
		}
		return kernel.NewPredicateConditionNode(predicate)
	}
	if !workflowObjectHasExactKeys(raw, "kind", "children") {
		return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
	}
	childItems, ok := raw["children"].([]any)
	if !ok {
		return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
	}
	children := make([]kernel.ConditionNode, len(childItems))
	for index, item := range childItems {
		object, objectOK := item.(map[string]any)
		if !objectOK {
			return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
		}
		var err error
		children[index], err = workflowConditionNode(object, depth+1, nodes)
		if err != nil {
			return kernel.ConditionNode{}, err
		}
	}
	switch kind {
	case "all":
		return kernel.NewAllConditionNode(children...)
	case "any":
		return kernel.NewAnyConditionNode(children...)
	case "not":
		if len(children) != 1 {
			return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
		}
		return kernel.NewNotConditionNode(children[0])
	default:
		return kernel.ConditionNode{}, applicationticketing.ErrInvalidInput
	}
}

func workflowConditionValue(raw map[string]any) (kernel.ConditionValue, error) {
	if !workflowObjectHasExactKeys(raw, "type", "value") {
		return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
	}
	kind, ok := raw["type"].(string)
	if !ok {
		return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
	}
	switch kind {
	case "text":
		value, ok := raw["value"].(string)
		if !ok {
			return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
		}
		return kernel.NewTextConditionValue(value)
	case "number":
		value, ok := raw["value"].(float64)
		if !ok {
			return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
		}
		return kernel.NewNumberConditionValue(value)
	case "boolean":
		value, ok := raw["value"].(bool)
		if !ok {
			return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
		}
		return kernel.NewBooleanConditionValue(value), nil
	case "instant":
		value, ok := raw["value"].(string)
		if !ok {
			return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
		}
		instant, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
		}
		return kernel.NewInstantConditionValue(instant)
	default:
		return kernel.ConditionValue{}, applicationticketing.ErrInvalidInput
	}
}

func workflowVisibility(value string) (kernel.Visibility, error) {
	switch value {
	case "internal":
		return kernel.VisibilityInternal, nil
	case "customer":
		return kernel.VisibilityCustomer, nil
	default:
		return 0, applicationticketing.ErrInvalidInput
	}
}

func workflowAction(value string) (kernel.Action, error) {
	switch value {
	case "create":
		return kernel.ActionCreate, nil
	case "assign":
		return kernel.ActionAssign, nil
	case "claim":
		return kernel.ActionClaim, nil
	case "release":
		return kernel.ActionRelease, nil
	case "transfer":
		return kernel.ActionTransfer, nil
	case "escalate":
		return kernel.ActionEscalate, nil
	case "link":
		return kernel.ActionLink, nil
	default:
		return 0, applicationticketing.ErrInvalidInput
	}
}

func workflowEffectPlan(values []string) (kernel.EffectPlan, error) {
	effects := make([]kernel.Effect, len(values))
	for index, value := range values {
		switch value {
		case "activity":
			effects[index] = kernel.EffectActivity
		case "audit":
			effects[index] = kernel.EffectAudit
		case "sla":
			effects[index] = kernel.EffectSLA
		case "notification":
			effects[index] = kernel.EffectNotification
		default:
			return kernel.EffectPlan{}, applicationticketing.ErrInvalidInput
		}
	}
	plan, err := kernel.NewEffectPlan(effects...)
	if err != nil {
		return kernel.EffectPlan{}, applicationticketing.ErrInvalidInput
	}
	return plan, nil
}

func workflowPermissions(values []string) ([]kernel.Permission, error) {
	result := make([]kernel.Permission, len(values))
	for index, value := range values {
		permission, err := kernel.ParsePermission(value)
		if err != nil {
			return nil, applicationticketing.ErrInvalidInput
		}
		result[index] = permission
	}
	return result, nil
}

func workflowKeys(values []string) ([]kernel.Key, error) {
	result := make([]kernel.Key, len(values))
	for index, value := range values {
		key, err := kernel.NewKey(value)
		if err != nil {
			return nil, applicationticketing.ErrInvalidInput
		}
		result[index] = key
	}
	return result, nil
}

func workflowConditionOperator(value string) (kernel.ConditionOperator, error) {
	switch value {
	case "equal":
		return kernel.ConditionEqual, nil
	case "not_equal":
		return kernel.ConditionNotEqual, nil
	case "in":
		return kernel.ConditionIn, nil
	case "not_in":
		return kernel.ConditionNotIn, nil
	case "less_than":
		return kernel.ConditionLessThan, nil
	case "less_than_or_equal":
		return kernel.ConditionLessThanOrEqual, nil
	case "greater_than":
		return kernel.ConditionGreaterThan, nil
	case "greater_than_or_equal":
		return kernel.ConditionGreaterThanOrEqual, nil
	case "exists":
		return kernel.ConditionExists, nil
	case "not_exists":
		return kernel.ConditionNotExists, nil
	default:
		return 0, applicationticketing.ErrInvalidInput
	}
}

func workflowObjectHasExactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := value[key]; !exists {
			return false
		}
	}
	return true
}
