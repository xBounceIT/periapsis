package ticketing

import (
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

const (
	workflowAdminCommandDomain       = "periapsis.ticketing.workflow-admin.command.v1"
	workflowAdminIdempotencyDomain   = "periapsis.ticketing.workflow-admin.idempotency.v1\x00"
	maximumWorkflowAdminCommandBytes = 480 * 1024
)

type workflowAdminFingerprintEnvelope struct {
	Domain           string                   `json:"domain"`
	Action           string                   `json:"action"`
	TenantID         string                   `json:"tenantId"`
	WorkflowID       string                   `json:"workflowId,omitempty"`
	ExpectedRevision uint64                   `json:"expectedRevision"`
	CatalogKey       string                   `json:"catalogKey,omitempty"`
	DisplayName      string                   `json:"displayName,omitempty"`
	Description      string                   `json:"description,omitempty"`
	Design           *workflowDesignCanonical `json:"design,omitempty"`
}

type workflowDesignCanonical struct {
	Kind        string                        `json:"kind"`
	States      []workflowStateCanonical      `json:"states"`
	Transitions []workflowTransitionCanonical `json:"transitions"`
}

type workflowStateCanonical struct {
	Key        string                    `json:"key"`
	Initial    bool                      `json:"initial"`
	Terminal   bool                      `json:"terminal"`
	Visibility string                    `json:"visibility"`
	Actions    []workflowActionCanonical `json:"actions"`
}

type workflowActionCanonical struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
}

type workflowTransitionCanonical struct {
	Key                  string                      `json:"key"`
	From                 string                      `json:"from"`
	To                   string                      `json:"to"`
	RequiredComment      bool                        `json:"requiredComment"`
	Reopen               bool                        `json:"reopen"`
	RequiredRoles        []string                    `json:"requiredRoles"`
	RequiredPermissions  []string                    `json:"requiredPermissions"`
	RequiredCustomFields []string                    `json:"requiredCustomFields"`
	Condition            *workflowConditionCanonical `json:"condition,omitempty"`
	Effects              []string                    `json:"effects"`
}

type workflowConditionCanonical struct {
	Kind     string                       `json:"kind"`
	Field    string                       `json:"field,omitempty"`
	Operator string                       `json:"operator,omitempty"`
	Values   []workflowValueCanonical     `json:"values,omitempty"`
	Children []workflowConditionCanonical `json:"children,omitempty"`
}

type workflowValueCanonical struct {
	Kind    string  `json:"kind"`
	Text    string  `json:"text"`
	Number  float64 `json:"number"`
	Boolean bool    `json:"boolean"`
	Instant string  `json:"instant"`
}

func bindWorkflowAdminCommand(
	idempotencyKey string,
	action kernel.WorkflowAdministrationAction,
	tenantID uuid.UUID,
	workflowID *uuid.UUID,
	expectedRevision uint64,
	catalogKey string,
	displayName string,
	description string,
	definition *kernel.WorkflowDefinition,
) (WorkflowAdminCommandBinding, error) {
	if !validIdempotencyKey(idempotencyKey) || !validWorkflowUUID(tenantID) ||
		!validWorkflowAdminCommandShape(
			action, workflowID, expectedRevision, catalogKey, displayName, description, definition,
		) {
		return WorkflowAdminCommandBinding{}, ErrInvalidInput
	}
	envelope := workflowAdminFingerprintEnvelope{
		Domain: workflowAdminCommandDomain,
		Action: action.String(), TenantID: tenantID.String(), ExpectedRevision: expectedRevision,
		CatalogKey: catalogKey, DisplayName: displayName, Description: description,
	}
	if workflowID != nil {
		envelope.WorkflowID = workflowID.String()
	}
	if definition != nil {
		design, err := canonicalWorkflowDesign(*definition)
		if err != nil {
			return WorkflowAdminCommandBinding{}, err
		}
		envelope.Design = &design
	}
	payload, err := json.Marshal(envelope)
	if err != nil || len(payload) > maximumWorkflowAdminCommandBytes {
		return WorkflowAdminCommandBinding{}, ErrInvalidInput
	}
	return WorkflowAdminCommandBinding{
		Action:      action,
		KeyHash:     sha256.Sum256([]byte(workflowAdminIdempotencyDomain + idempotencyKey)),
		Fingerprint: sha256.Sum256(payload),
	}, nil
}

func validWorkflowAdminCommandShape(
	action kernel.WorkflowAdministrationAction,
	workflowID *uuid.UUID,
	expectedRevision uint64,
	catalogKey string,
	displayName string,
	description string,
	definition *kernel.WorkflowDefinition,
) bool {
	switch action {
	case kernel.WorkflowAdministrationCreate:
		return workflowID == nil && expectedRevision == 0 && definition != nil &&
			definition.Version() == 1 && catalogKey != "" && displayName != ""
	case kernel.WorkflowAdministrationPublish:
		return workflowID != nil && validWorkflowUUID(*workflowID) &&
			expectedRevision > 0 && expectedRevision <= maxResourceVersion && definition != nil &&
			definition.Version() <= maxResourceVersion &&
			uuidFromEntity(definition.ID()) == *workflowID && catalogKey == "" &&
			displayName == "" && description == ""
	case kernel.WorkflowAdministrationUpdateMetadata:
		return workflowID != nil && validWorkflowUUID(*workflowID) &&
			expectedRevision > 0 && expectedRevision <= maxResourceVersion && definition == nil &&
			catalogKey == "" && displayName != ""
	case kernel.WorkflowAdministrationSetDefault, kernel.WorkflowAdministrationArchive,
		kernel.WorkflowAdministrationRestore:
		return workflowID != nil && validWorkflowUUID(*workflowID) &&
			expectedRevision > 0 && expectedRevision <= maxResourceVersion && definition == nil &&
			catalogKey == "" && displayName == "" && description == ""
	default:
		return false
	}
}

func canonicalWorkflowDesign(definition kernel.WorkflowDefinition) (workflowDesignCanonical, error) {
	if definition.Version() == 0 || definition.Kind() != kernel.AggregateAlert && definition.Kind() != kernel.AggregateCase {
		return workflowDesignCanonical{}, ErrInvalidInput
	}
	result := workflowDesignCanonical{Kind: definition.Kind().String()}
	for _, state := range definition.States() {
		item := workflowStateCanonical{
			Key: state.Key().String(), Initial: state.Initial(), Terminal: state.Terminal(),
			Visibility: state.Visibility().String(), Actions: []workflowActionCanonical{},
		}
		for _, action := range state.Actions() {
			item.Actions = append(item.Actions, workflowActionCanonical{
				Action: action.Action().String(), Effects: effectStrings(action.Effects()),
			})
		}
		result.States = append(result.States, item)
	}
	for _, transition := range definition.Transitions() {
		condition, err := canonicalWorkflowCondition(transition.Condition())
		if err != nil {
			return workflowDesignCanonical{}, err
		}
		item := workflowTransitionCanonical{
			Key: transition.Key().String(), From: transition.From().String(), To: transition.To().String(),
			RequiredComment: transition.RequiredComment(), Reopen: transition.Reopen(),
			RequiredRoles:        keyStringsForFingerprint(transition.RequiredRoles()),
			RequiredPermissions:  permissionStringsForFingerprint(transition.RequiredPermissions()),
			RequiredCustomFields: keyStringsForFingerprint(transition.RequiredCustomFields()),
			Condition:            condition, Effects: effectStrings(transition.Effects()),
		}
		result.Transitions = append(result.Transitions, item)
	}
	return result, nil
}

func canonicalWorkflowCondition(condition kernel.Condition) (*workflowConditionCanonical, error) {
	root, configured := condition.Root()
	if !configured {
		return nil, nil
	}
	result, err := canonicalWorkflowConditionNode(root)
	if err != nil {
		return nil, err
	}
	return &result, nil
}

func canonicalWorkflowConditionNode(node kernel.ConditionNode) (workflowConditionCanonical, error) {
	result := workflowConditionCanonical{Kind: node.Kind().String()}
	if predicate, exists := node.Predicate(); exists {
		result.Field = predicate.Field().String()
		result.Operator = predicate.Operator().String()
		for _, value := range predicate.Values() {
			canonical, err := canonicalWorkflowValue(value)
			if err != nil {
				return workflowConditionCanonical{}, err
			}
			result.Values = append(result.Values, canonical)
		}
		return result, nil
	}
	for _, child := range node.Children() {
		canonical, err := canonicalWorkflowConditionNode(child)
		if err != nil {
			return workflowConditionCanonical{}, err
		}
		result.Children = append(result.Children, canonical)
	}
	return result, nil
}

func canonicalWorkflowValue(value kernel.ConditionValue) (workflowValueCanonical, error) {
	result := workflowValueCanonical{Kind: value.Kind().String()}
	switch value.Kind() {
	case kernel.ConditionValueText:
		result.Text, _ = value.Text()
	case kernel.ConditionValueNumber:
		result.Number, _ = value.Number()
	case kernel.ConditionValueBoolean:
		result.Boolean, _ = value.Boolean()
	case kernel.ConditionValueInstant:
		instant, exists := value.Instant()
		if !exists {
			return workflowValueCanonical{}, ErrInvalidInput
		}
		result.Instant = instant.Format(time.RFC3339Nano)
	default:
		return workflowValueCanonical{}, ErrInvalidInput
	}
	return result, nil
}

func keyStringsForFingerprint(values []kernel.Key) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func permissionStringsForFingerprint(values []kernel.Permission) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func effectStrings(plan kernel.EffectPlan) []string {
	effects := plan.Effects()
	result := make([]string, len(effects))
	for index, effect := range effects {
		result[index] = effect.String()
	}
	return result
}
