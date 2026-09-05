package postgres

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
	application "github.com/periapsis-im/periapsis/services/api/internal/ticketing"
)

type ticketWorkflowStateJSON struct {
	Key        string                     `json:"key"`
	Initial    bool                       `json:"initial"`
	Terminal   bool                       `json:"terminal"`
	Visibility string                     `json:"visibility"`
	Actions    []ticketWorkflowActionJSON `json:"actions"`
}

type ticketWorkflowActionJSON struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
}

type ticketWorkflowTransitionJSON struct {
	Key                  string                       `json:"key"`
	From                 string                       `json:"from"`
	To                   string                       `json:"to"`
	RequiredComment      bool                         `json:"requiredComment"`
	Reopen               bool                         `json:"reopen"`
	RequiredRoles        []string                     `json:"requiredRoles"`
	RequiredPermissions  []string                     `json:"requiredPermissions"`
	RequiredCustomFields []string                     `json:"requiredCustomFields"`
	Condition            *ticketWorkflowConditionJSON `json:"condition,omitempty"`
	Effects              []string                     `json:"effects"`
}

type ticketWorkflowConditionJSON struct {
	Kind     string                             `json:"kind"`
	Field    string                             `json:"field,omitempty"`
	Operator string                             `json:"operator,omitempty"`
	Values   []ticketWorkflowConditionValueJSON `json:"values,omitempty"`
	Children []ticketWorkflowConditionJSON      `json:"children,omitempty"`
}

type ticketWorkflowConditionValueJSON struct {
	Type  string          `json:"type"`
	Value json.RawMessage `json:"value"`
}

type ticketWorkflowCommandSnapshotJSON struct {
	SchemaVersion  int                            `json:"schemaVersion"`
	Action         string                         `json:"action"`
	WorkflowID     uuid.UUID                      `json:"workflowId"`
	AggregateKind  string                         `json:"aggregateKind"`
	Key            string                         `json:"key"`
	DisplayName    string                         `json:"displayName"`
	Description    string                         `json:"description"`
	IsDefault      bool                           `json:"isDefault"`
	Status         string                         `json:"status"`
	Revision       int64                          `json:"revision"`
	CurrentVersion int32                          `json:"currentVersion"`
	States         []ticketWorkflowStateJSON      `json:"states"`
	Transitions    []ticketWorkflowTransitionJSON `json:"transitions"`
	CreatedAt      time.Time                      `json:"createdAt"`
	UpdatedAt      time.Time                      `json:"updatedAt"`
	ArchivedAt     *time.Time                     `json:"archivedAt"`
}

func mapTicketWorkflow(
	id uuid.UUID,
	kind kernel.AggregateKind,
	version int32,
	statesJSON []byte,
	transitionsJSON []byte,
) (kernel.WorkflowDefinition, error) {
	workflowID, err := ticketEntityID(id)
	if err != nil || version < 1 {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow identity")
	}
	var storedStates []ticketWorkflowStateJSON
	var storedTransitions []ticketWorkflowTransitionJSON
	if err := json.Unmarshal(statesJSON, &storedStates); err != nil {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow states")
	}
	if err := json.Unmarshal(transitionsJSON, &storedTransitions); err != nil {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow transitions")
	}
	states := make([]kernel.StateDefinition, 0, len(storedStates))
	for _, stored := range storedStates {
		key, keyErr := kernel.NewKey(stored.Key)
		visibility, visibilityErr := ticketVisibility(stored.Visibility)
		actions := make([]kernel.StateAction, 0, len(stored.Actions))
		if keyErr != nil || visibilityErr != nil {
			return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow state")
		}
		for _, storedAction := range stored.Actions {
			action, actionErr := ticketAction(storedAction.Action)
			effects, effectsErr := ticketEffects(storedAction.Effects)
			if actionErr != nil || effectsErr != nil {
				return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow action")
			}
			value, constructorErr := kernel.NewStateAction(action, effects)
			if constructorErr != nil {
				return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow action definition")
			}
			actions = append(actions, value)
		}
		state, constructorErr := kernel.NewStateDefinition(
			key, stored.Initial, stored.Terminal, visibility, actions,
		)
		if constructorErr != nil {
			return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow state definition")
		}
		states = append(states, state)
	}
	transitions := make([]kernel.TransitionDefinition, 0, len(storedTransitions))
	for _, stored := range storedTransitions {
		key, keyErr := kernel.NewKey(stored.Key)
		from, fromErr := kernel.NewKey(stored.From)
		to, toErr := kernel.NewKey(stored.To)
		roles, rolesErr := ticketKeys(stored.RequiredRoles)
		permissions, permissionsErr := ticketPermissions(stored.RequiredPermissions)
		fields, fieldsErr := ticketKeys(stored.RequiredCustomFields)
		condition, conditionErr := ticketCondition(stored.Condition)
		effects, effectsErr := ticketEffects(stored.Effects)
		if keyErr != nil || fromErr != nil || toErr != nil || rolesErr != nil ||
			permissionsErr != nil || fieldsErr != nil || conditionErr != nil || effectsErr != nil {
			return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow transition")
		}
		transition, constructorErr := kernel.NewConditionalTransitionDefinition(
			key, from, to, stored.RequiredComment, stored.Reopen,
			roles, permissions, fields, condition, effects,
		)
		if constructorErr != nil {
			return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow transition definition")
		}
		transitions = append(transitions, transition)
	}
	workflow, err := kernel.NewWorkflowDefinition(
		workflowID, kind, uint64(version), states, transitions,
	)
	if err != nil {
		return kernel.WorkflowDefinition{}, invalidTicketProjection("invalid workflow definition")
	}
	return workflow, nil
}

func marshalTicketWorkflow(workflow kernel.WorkflowDefinition) ([]byte, []byte, error) {
	workflowID, identifierErr := uuid.Parse(workflow.ID().String())
	if identifierErr != nil || workflow.Version() == 0 || workflow.Version() > uint64(math.MaxInt32) ||
		workflow.Kind() != kernel.AggregateAlert && workflow.Kind() != kernel.AggregateCase {
		return nil, nil, invalidTicketProjection("invalid workflow definition")
	}
	states := make([]ticketWorkflowStateJSON, 0, len(workflow.States()))
	for _, state := range workflow.States() {
		stored := ticketWorkflowStateJSON{
			Key: state.Key().String(), Initial: state.Initial(), Terminal: state.Terminal(),
			Visibility: state.Visibility().String(), Actions: []ticketWorkflowActionJSON{},
		}
		for _, action := range state.Actions() {
			stored.Actions = append(stored.Actions, ticketWorkflowActionJSON{
				Action: action.Action().String(), Effects: ticketEffectStrings(action.Effects()),
			})
		}
		states = append(states, stored)
	}
	transitions := make([]ticketWorkflowTransitionJSON, 0, len(workflow.Transitions()))
	for _, transition := range workflow.Transitions() {
		condition, err := marshalTicketWorkflowCondition(transition.Condition())
		if err != nil {
			return nil, nil, err
		}
		transitions = append(transitions, ticketWorkflowTransitionJSON{
			Key: transition.Key().String(), From: transition.From().String(), To: transition.To().String(),
			RequiredComment: transition.RequiredComment(), Reopen: transition.Reopen(),
			RequiredRoles:        ticketKeyStrings(transition.RequiredRoles()),
			RequiredPermissions:  ticketPermissionStrings(transition.RequiredPermissions()),
			RequiredCustomFields: ticketKeyStrings(transition.RequiredCustomFields()),
			Condition:            condition, Effects: ticketEffectStrings(transition.Effects()),
		})
	}
	statesJSON, err := json.Marshal(states)
	if err != nil {
		return nil, nil, invalidTicketProjection("encode workflow states")
	}
	transitionsJSON, err := json.Marshal(transitions)
	if err != nil {
		return nil, nil, invalidTicketProjection("encode workflow transitions")
	}
	if _, err := mapTicketWorkflow(
		workflowID, workflow.Kind(), int32(workflow.Version()), statesJSON, transitionsJSON,
	); err != nil {
		return nil, nil, err
	}
	return statesJSON, transitionsJSON, nil
}

func mapWorkflowAdminCommandSnapshot(
	encoded []byte,
	tenantID uuid.UUID,
	action string,
	workflowID uuid.UUID,
	resultRevision int64,
) (application.WorkflowAdminRecord, error) {
	if len(encoded) == 0 || len(encoded) > 512*1024 || !authorizationUUIDv7(tenantID) ||
		!authorizationUUIDv7(workflowID) || resultRevision < 1 || resultRevision > math.MaxInt32 {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay envelope")
	}
	var stored ticketWorkflowCommandSnapshotJSON
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&stored); err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay snapshot")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("workflow replay snapshot has trailing data")
	}
	if stored.SchemaVersion != 1 || stored.Action != action || stored.WorkflowID != workflowID ||
		stored.Revision != resultRevision || stored.CurrentVersion < 1 ||
		stored.CreatedAt.IsZero() || stored.UpdatedAt.IsZero() || stored.UpdatedAt.Before(stored.CreatedAt) {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("workflow replay snapshot identity mismatch")
	}
	kind, err := workflowAdminKind(stored.AggregateKind)
	if err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay kind")
	}
	states, err := json.Marshal(stored.States)
	if err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay states")
	}
	transitions, err := json.Marshal(stored.Transitions)
	if err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay transitions")
	}
	definition, err := mapTicketWorkflow(workflowID, kind, stored.CurrentVersion, states, transitions)
	if err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay definition")
	}
	tenant, err := ticketEntityID(tenantID)
	if err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay tenant")
	}
	key, err := kernel.NewKey(stored.Key)
	if err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay key")
	}
	status := kernel.WorkflowActive
	var archivedAt *time.Time
	switch stored.Status {
	case "active":
		if stored.ArchivedAt != nil {
			return application.WorkflowAdminRecord{}, invalidTicketProjection("active workflow replay is archived")
		}
	case "archived":
		if stored.ArchivedAt == nil || stored.ArchivedAt.Before(stored.CreatedAt) ||
			stored.ArchivedAt.After(stored.UpdatedAt) {
			return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay archive time")
		}
		status = kernel.WorkflowArchived
		value := ticketTime(*stored.ArchivedAt)
		archivedAt = &value
	default:
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay status")
	}
	workflow, err := kernel.NewManagedWorkflow(
		tenant, key, stored.DisplayName, stored.Description, stored.IsDefault, status,
		uint64(stored.Revision), definition,
	)
	if err != nil {
		return application.WorkflowAdminRecord{}, invalidTicketProjection("invalid workflow replay aggregate")
	}
	return application.WorkflowAdminRecord{
		Workflow: workflow, CreatedAt: ticketTime(stored.CreatedAt), UpdatedAt: ticketTime(stored.UpdatedAt),
		ArchivedAt: archivedAt,
	}, nil
}

func marshalTicketWorkflowCondition(condition kernel.Condition) (*ticketWorkflowConditionJSON, error) {
	root, configured := condition.Root()
	if !configured {
		return nil, nil
	}
	value, err := marshalTicketWorkflowConditionNode(root, 1)
	if err != nil {
		return nil, err
	}
	return &value, nil
}

func marshalTicketWorkflowConditionNode(
	node kernel.ConditionNode,
	depth int,
) (ticketWorkflowConditionJSON, error) {
	if depth > 8 {
		return ticketWorkflowConditionJSON{}, invalidTicketProjection("workflow condition exceeds depth")
	}
	stored := ticketWorkflowConditionJSON{Kind: node.Kind().String()}
	if predicate, exists := node.Predicate(); exists {
		stored.Field = predicate.Field().String()
		stored.Operator = predicate.Operator().String()
		stored.Values = make([]ticketWorkflowConditionValueJSON, 0, len(predicate.Values()))
		for _, value := range predicate.Values() {
			encoded, err := marshalTicketWorkflowConditionValue(value)
			if err != nil {
				return ticketWorkflowConditionJSON{}, err
			}
			stored.Values = append(stored.Values, encoded)
		}
		return stored, nil
	}
	children := node.Children()
	stored.Children = make([]ticketWorkflowConditionJSON, 0, len(children))
	for _, child := range children {
		encoded, err := marshalTicketWorkflowConditionNode(child, depth+1)
		if err != nil {
			return ticketWorkflowConditionJSON{}, err
		}
		stored.Children = append(stored.Children, encoded)
	}
	return stored, nil
}

func marshalTicketWorkflowConditionValue(
	value kernel.ConditionValue,
) (ticketWorkflowConditionValueJSON, error) {
	var scalar any
	switch value.Kind() {
	case kernel.ConditionValueText:
		scalar, _ = value.Text()
	case kernel.ConditionValueNumber:
		scalar, _ = value.Number()
	case kernel.ConditionValueBoolean:
		scalar, _ = value.Boolean()
	case kernel.ConditionValueInstant:
		instant, ok := value.Instant()
		if !ok {
			return ticketWorkflowConditionValueJSON{}, invalidTicketProjection("invalid workflow instant")
		}
		scalar = instant.Format(time.RFC3339Nano)
	default:
		return ticketWorkflowConditionValueJSON{}, invalidTicketProjection("invalid workflow condition value")
	}
	encoded, err := json.Marshal(scalar)
	if err != nil {
		return ticketWorkflowConditionValueJSON{}, invalidTicketProjection("encode workflow condition value")
	}
	return ticketWorkflowConditionValueJSON{Type: value.Kind().String(), Value: encoded}, nil
}

func ticketEffectStrings(plan kernel.EffectPlan) []string {
	effects := plan.Effects()
	result := make([]string, len(effects))
	for index, effect := range effects {
		result[index] = effect.String()
	}
	return result
}

func ticketKeyStrings(values []kernel.Key) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func ticketPermissionStrings(values []kernel.Permission) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = value.String()
	}
	return result
}

func ticketCondition(stored *ticketWorkflowConditionJSON) (kernel.Condition, error) {
	if stored == nil {
		return kernel.Condition{}, nil
	}
	root, err := ticketConditionNode(*stored, 1)
	if err != nil {
		return kernel.Condition{}, err
	}
	return kernel.NewCondition(root)
}

func ticketConditionNode(stored ticketWorkflowConditionJSON, depth int) (kernel.ConditionNode, error) {
	if depth > 8 {
		return kernel.ConditionNode{}, kernel.ErrInvalidWorkflow
	}
	switch stored.Kind {
	case "predicate":
		if len(stored.Children) != 0 {
			return kernel.ConditionNode{}, kernel.ErrInvalidWorkflow
		}
		field, fieldErr := kernel.NewConditionField(stored.Field)
		operator, operatorErr := ticketConditionOperator(stored.Operator)
		values := make([]kernel.ConditionValue, 0, len(stored.Values))
		for _, storedValue := range stored.Values {
			value, err := ticketConditionValue(storedValue)
			if err != nil {
				return kernel.ConditionNode{}, err
			}
			values = append(values, value)
		}
		if fieldErr != nil || operatorErr != nil {
			return kernel.ConditionNode{}, kernel.ErrInvalidWorkflow
		}
		predicate, err := kernel.NewConditionPredicate(field, operator, values...)
		if err != nil {
			return kernel.ConditionNode{}, err
		}
		return kernel.NewPredicateConditionNode(predicate)
	case "all", "any":
		if stored.Field != "" || stored.Operator != "" || len(stored.Values) != 0 {
			return kernel.ConditionNode{}, kernel.ErrInvalidWorkflow
		}
		children, err := ticketConditionChildren(stored.Children, depth)
		if err != nil {
			return kernel.ConditionNode{}, err
		}
		if stored.Kind == "all" {
			return kernel.NewAllConditionNode(children...)
		}
		return kernel.NewAnyConditionNode(children...)
	case "not":
		if stored.Field != "" || stored.Operator != "" || len(stored.Values) != 0 || len(stored.Children) != 1 {
			return kernel.ConditionNode{}, kernel.ErrInvalidWorkflow
		}
		child, err := ticketConditionNode(stored.Children[0], depth+1)
		if err != nil {
			return kernel.ConditionNode{}, err
		}
		return kernel.NewNotConditionNode(child)
	default:
		return kernel.ConditionNode{}, kernel.ErrInvalidWorkflow
	}
}

func ticketConditionChildren(stored []ticketWorkflowConditionJSON, parentDepth int) ([]kernel.ConditionNode, error) {
	children := make([]kernel.ConditionNode, 0, len(stored))
	for _, child := range stored {
		node, err := ticketConditionNode(child, parentDepth+1)
		if err != nil {
			return nil, err
		}
		children = append(children, node)
	}
	return children, nil
}

func ticketConditionOperator(value string) (kernel.ConditionOperator, error) {
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
		return 0, kernel.ErrInvalidWorkflow
	}
}

func ticketConditionValue(stored ticketWorkflowConditionValueJSON) (kernel.ConditionValue, error) {
	switch stored.Type {
	case "text":
		var value *string
		if err := json.Unmarshal(stored.Value, &value); err != nil || value == nil {
			return kernel.ConditionValue{}, kernel.ErrInvalidWorkflow
		}
		return kernel.NewTextConditionValue(*value)
	case "number":
		var value *float64
		if err := json.Unmarshal(stored.Value, &value); err != nil || value == nil {
			return kernel.ConditionValue{}, kernel.ErrInvalidWorkflow
		}
		return kernel.NewNumberConditionValue(*value)
	case "boolean":
		var value *bool
		if err := json.Unmarshal(stored.Value, &value); err != nil || value == nil {
			return kernel.ConditionValue{}, kernel.ErrInvalidWorkflow
		}
		return kernel.NewBooleanConditionValue(*value), nil
	case "instant":
		var value *string
		if err := json.Unmarshal(stored.Value, &value); err != nil || value == nil {
			return kernel.ConditionValue{}, kernel.ErrInvalidWorkflow
		}
		instant, err := time.Parse(time.RFC3339Nano, *value)
		if err != nil {
			return kernel.ConditionValue{}, kernel.ErrInvalidWorkflow
		}
		return kernel.NewInstantConditionValue(instant)
	default:
		return kernel.ConditionValue{}, kernel.ErrInvalidWorkflow
	}
}

func ticketKeys(values []string) ([]kernel.Key, error) {
	result := make([]kernel.Key, 0, len(values))
	for _, value := range values {
		key, err := kernel.NewKey(value)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	return result, nil
}

func ticketPermissions(values []string) ([]kernel.Permission, error) {
	result := make([]kernel.Permission, 0, len(values))
	for _, value := range values {
		permission, err := kernel.ParsePermission(value)
		if err != nil {
			return nil, err
		}
		result = append(result, permission)
	}
	return result, nil
}

func ticketEffects(values []string) (kernel.EffectPlan, error) {
	effects := make([]kernel.Effect, 0, len(values))
	for _, value := range values {
		switch value {
		case "activity":
			effects = append(effects, kernel.EffectActivity)
		case "audit":
			effects = append(effects, kernel.EffectAudit)
		case "sla":
			effects = append(effects, kernel.EffectSLA)
		case "notification":
			effects = append(effects, kernel.EffectNotification)
		default:
			return kernel.EffectPlan{}, kernel.ErrInvalidWorkflow
		}
	}
	return kernel.NewEffectPlan(effects...)
}

func ticketAction(value string) (kernel.Action, error) {
	switch value {
	case "create":
		return kernel.ActionCreate, nil
	case "transition":
		return kernel.ActionTransition, nil
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
		return 0, kernel.ErrInvalidWorkflow
	}
}

func ticketVisibility(value string) (kernel.Visibility, error) {
	switch value {
	case "internal":
		return kernel.VisibilityInternal, nil
	case "customer":
		return kernel.VisibilityCustomer, nil
	default:
		return 0, kernel.ErrInvalidWorkflow
	}
}

type ticketRecordScanner interface {
	Scan(...any) error
}

func scanTicketRecord(
	row ticketRecordScanner,
	tenantUUID uuid.UUID,
	kind kernel.AggregateKind,
) (application.Record, error) {
	var (
		id, workflowID, creatorID                                                uuid.UUID
		number, state, title, description, summary, severity, priority, category string
		classification, source, sourceType, creatorKind, creatorDisplay          string
		externalID, deduplicationKey                                             pgtype.Text
		workflowVersion, version                                                 int32
		customerVisible                                                          bool
		tags                                                                     []string
		customJSON, customerCustomJSON, rawJSON, statesJSON, transitionsJSON     []byte
		detectedAt, receivedAt, detectionTime, openedAt                          pgtype.Timestamptz
		createdAt, updatedAt                                                     time.Time
		acknowledgedAt, closedAt, assignedAt, firstResponseAt                    pgtype.Timestamptz
		resolvedAt, claimedAt                                                    pgtype.Timestamptz
		assignedTeamID, assigneeUserID, claimedByUserID                          pgtype.UUID
		creatorUserID                                                            pgtype.UUID
	)
	if err := row.Scan(
		&id, &number, &workflowID, &workflowVersion, &state, &customerVisible,
		&title, &description, &summary, &severity, &priority, &category,
		&classification, &source, &sourceType, &externalID, &deduplicationKey,
		&tags, &customJSON, &customerCustomJSON, &rawJSON,
		&creatorKind, &creatorID, &creatorDisplay, &creatorUserID,
		&detectedAt, &receivedAt, &detectionTime, &openedAt,
		&createdAt, &updatedAt, &acknowledgedAt, &closedAt, &assignedAt,
		&firstResponseAt, &resolvedAt, &claimedAt,
		&assignedTeamID, &assigneeUserID, &claimedByUserID, &version,
		&statesJSON, &transitionsJSON,
	); err != nil {
		return application.Record{}, err
	}
	workflow, err := mapTicketWorkflow(
		workflowID, kind, workflowVersion, statesJSON, transitionsJSON,
	)
	if err != nil {
		return application.Record{}, err
	}
	assignment, err := mapTicketAssignment(assignedTeamID, assigneeUserID, claimedByUserID)
	if err != nil {
		return application.Record{}, err
	}
	tenantID, err := ticketEntityID(tenantUUID)
	if err != nil {
		return application.Record{}, err
	}
	ticketID, err := ticketEntityID(id)
	if err != nil {
		return application.Record{}, err
	}
	stateKey, err := kernel.NewKey(state)
	if err != nil {
		return application.Record{}, invalidTicketProjection("invalid ticket state")
	}
	snapshot, err := kernel.NewTicketSnapshot(
		workflow, tenantID, ticketID, stateKey, uint64(version), customerVisible, assignment,
	)
	if err != nil {
		return application.Record{}, invalidTicketProjection("invalid ticket snapshot")
	}
	customFields, err := decodeTicketMap(customJSON)
	if err != nil {
		return application.Record{}, err
	}
	customerCustomFields, err := decodeTicketMap(customerCustomJSON)
	if err != nil {
		return application.Record{}, err
	}
	rawPayload, err := decodeTicketMap(rawJSON)
	if err != nil {
		return application.Record{}, err
	}
	creatorPrincipal, err := ticketPrincipal(creatorKind)
	if err != nil {
		return application.Record{}, err
	}
	classificationPointer := optionalNonEmptyString(classification)
	var creatorUserIDPointer *uuid.UUID
	if creatorUserID.Valid {
		value := uuid.UUID(creatorUserID.Bytes)
		creatorUserIDPointer = &value
	}
	result := application.Record{
		Workflow: workflow, Snapshot: snapshot, Number: number, Title: title,
		Description: description, Summary: summary, Severity: severity, Priority: priority,
		Category: category, Classification: classificationPointer, Source: source,
		SourceType: sourceType, ExternalID: databaseOptionalString(externalID),
		DeduplicationKey: databaseOptionalString(deduplicationKey), Tags: tags,
		CustomFields: customFields, CustomerCustomFields: customerCustomFields,
		RawPayload: rawPayload,
		Creator: application.Creator{
			Kind: creatorPrincipal, ID: creatorID, UserID: creatorUserIDPointer, DisplayName: creatorDisplay,
		},
		CreatedAt: ticketTime(createdAt), UpdatedAt: ticketTime(updatedAt),
		AcknowledgedAt: ticketOptionalTime(acknowledgedAt), ClosedAt: ticketOptionalTime(closedAt),
		AssignedAt: ticketOptionalTime(assignedAt), FirstResponseAt: ticketOptionalTime(firstResponseAt),
		ResolvedAt: ticketOptionalTime(resolvedAt), ClaimedAt: ticketOptionalTime(claimedAt),
	}
	if detectedAt.Valid {
		result.DetectedAt = ticketTime(detectedAt.Time)
	}
	if receivedAt.Valid {
		result.ReceivedAt = ticketTime(receivedAt.Time)
	}
	if detectionTime.Valid {
		result.DetectionTime = ticketTime(detectionTime.Time)
	}
	if openedAt.Valid {
		result.OpenedAt = ticketTime(openedAt.Time)
	}
	return result, nil
}

func mapTicketAssignment(team, assignee, claimant pgtype.UUID) (kernel.Assignment, error) {
	teamID, err := optionalTicketEntityID(team)
	if err != nil {
		return kernel.Assignment{}, err
	}
	assigneeID, err := optionalTicketEntityID(assignee)
	if err != nil {
		return kernel.Assignment{}, err
	}
	claimantID, err := optionalTicketEntityID(claimant)
	if err != nil {
		return kernel.Assignment{}, err
	}
	assignment, err := kernel.NewAssignment(teamID, assigneeID, claimantID)
	if err != nil {
		return kernel.Assignment{}, invalidTicketProjection("invalid assignment")
	}
	return assignment, nil
}

func optionalTicketEntityID(value pgtype.UUID) (*kernel.EntityID, error) {
	if !value.Valid {
		return nil, nil
	}
	id, err := ticketEntityID(value.Bytes)
	if err != nil {
		return nil, err
	}
	return &id, nil
}

func ticketEntityID(value uuid.UUID) (kernel.EntityID, error) {
	id, err := kernel.NewEntityID([16]byte(value))
	if err != nil {
		return kernel.EntityID{}, invalidTicketProjection("invalid UUIDv7")
	}
	return id, nil
}

func ticketPrincipal(value string) (kernel.PrincipalKind, error) {
	switch value {
	case "operator":
		return kernel.PrincipalOperator, nil
	case "customer":
		return kernel.PrincipalCustomer, nil
	case "service_account":
		return kernel.PrincipalServiceAccount, nil
	default:
		return 0, invalidTicketProjection("invalid ticket creator principal")
	}
}

func decodeTicketMap(value []byte) (map[string]any, error) {
	if len(value) == 0 {
		return map[string]any{}, nil
	}
	result := make(map[string]any)
	if err := json.Unmarshal(value, &result); err != nil {
		return nil, invalidTicketProjection("invalid ticket JSON projection")
	}
	return result, nil
}

func databaseOptionalString(value pgtype.Text) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

func optionalNonEmptyString(value string) *string {
	if value == "" {
		return nil
	}
	result := value
	return &result
}

func ticketTime(value time.Time) time.Time { return value.UTC().Truncate(time.Microsecond) }

func ticketDatabaseTime(value time.Time) pgtype.Timestamptz {
	if value.IsZero() {
		return pgtype.Timestamptz{}
	}
	return pgtype.Timestamptz{Time: ticketTime(value), Valid: true}
}

func ticketOptionalTime(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := ticketTime(value.Time)
	return &result
}

func invalidTicketProjection(message string) error {
	return fmt.Errorf("%w: %s", application.ErrUnavailable, message)
}

func mapTicketDatabaseError(err error) error {
	if err == nil || errors.Is(err, application.ErrInvalidInput) ||
		errors.Is(err, application.ErrForbidden) || errors.Is(err, application.ErrNotFound) ||
		errors.Is(err, application.ErrConflict) || errors.Is(err, application.ErrPreconditionFailed) ||
		errors.Is(err, application.ErrUnavailable) {
		return err
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return application.ErrNotFound
	}
	switch postgresCode(err) {
	case "22023", "22P02", "22007":
		return application.ErrInvalidInput
	case "42501":
		return application.ErrForbidden
	case "P0002":
		return application.ErrNotFound
	case "23503", "23505", "23514", "55000":
		return application.ErrConflict
	case "40001", "40P01":
		return application.ErrConflict
	default:
		return fmt.Errorf("%w: database operation failed", application.ErrUnavailable)
	}
}
