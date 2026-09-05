package ticketing

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	kernel "github.com/periapsis-im/periapsis/modules/ticketing"
)

func (service *Service) CreateCase(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	input CreateCaseInput,
) (MutationResult, error) {
	if !validMutationActor(actor, tenantID) {
		return MutationResult{}, ErrForbidden
	}
	if err := validateCreateCaseInput(input); err != nil {
		return MutationResult{}, err
	}
	access, err := service.access(ctx, actor, tenantID, CapabilityCaseCreate)
	if err != nil {
		return MutationResult{}, err
	}
	if access.Authority.Principal() != kernel.PrincipalOperator {
		return MutationResult{}, ErrForbidden
	}
	workflow, err := service.repository.Workflow(ctx, actor.UserID, tenantID, kernel.AggregateCase, input.WorkflowID)
	if err != nil {
		return MutationResult{}, repositoryError(err)
	}
	caseID, err := service.repository.ReserveID(ctx, tenantID)
	if err != nil {
		return MutationResult{}, repositoryError(err)
	}
	tenant, _ := entityID(tenantID)
	command, err := kernel.NewCreateCommand(tenant, caseID, workflow.ID(), workflow.Version(), 0, input.CustomerVisible)
	if err != nil {
		return MutationResult{}, ErrUnavailable
	}
	decision := kernel.PlanCreate(workflow, command, access.Authority)
	createPlan, err := mutationPlan(decision)
	if err != nil {
		return MutationResult{}, err
	}
	plans := []kernel.MutationPlan{createPlan}
	expectedSnapshot, err := kernel.SnapshotFromCreatePlan(workflow, createPlan)
	if err != nil {
		return MutationResult{}, ErrUnavailable
	}
	if input.AssignedTeamID != nil {
		team, teamErr := entityID(*input.AssignedTeamID)
		if teamErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		var assignee *kernel.EntityID
		if input.AssigneeUserID != nil {
			value, assigneeErr := entityID(*input.AssigneeUserID)
			if assigneeErr != nil {
				return MutationResult{}, ErrInvalidInput
			}
			assignee = &value
		}
		assignCommand, commandErr := kernel.NewAssignCommand(tenant, caseID, expectedSnapshot.Version(), team, assignee)
		if commandErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		assignPlan, planErr := mutationPlan(kernel.PlanAssign(workflow, expectedSnapshot, assignCommand, access.Authority))
		if planErr != nil {
			return MutationResult{}, planErr
		}
		plans = append(plans, assignPlan)
		expectedSnapshot, err = kernel.ApplyMutationPlan(workflow, expectedSnapshot, assignPlan)
		if err != nil {
			return MutationResult{}, ErrUnavailable
		}
	}
	result, err := service.repository.CreateCase(ctx, CreateCaseWrite{
		Actor: actor, Content: input, Plans: plans,
		IdempotencyHash: sha256.Sum256([]byte(input.IdempotencyKey)), Audit: actor.Audit,
	})
	if err != nil {
		return MutationResult{}, repositoryError(err)
	}
	if validateRecord(result.Record, tenantID, kernel.AggregateCase) != nil ||
		uuidFromEntity(result.Record.Snapshot.ID()) != uuidFromEntity(caseID) && !result.Replayed ||
		!result.Replayed && !sameSnapshot(expectedSnapshot, result.Record.Snapshot) {
		return MutationResult{}, ErrUnavailable
	}
	return MutationResult{
		View:    View{Record: result.Record, Projection: ProjectionOperator},
		Effects: effectsForPlans(plans), Replayed: result.Replayed,
	}, nil
}

func (service *Service) Mutate(
	ctx context.Context,
	actor Actor,
	tenantID uuid.UUID,
	kind kernel.AggregateKind,
	id uuid.UUID,
	action kernel.Action,
	input MutationInput,
) (MutationResult, error) {
	if !validMutationActor(actor, tenantID) {
		return MutationResult{}, ErrForbidden
	}
	capability := mutationCapability(kind, action)
	if !validCapability(capability) || input.ExpectedVersion == 0 || input.ExpectedVersion > maxResourceVersion ||
		!validMutationTransitionIntent(action, input.TransitionIntent) ||
		(action == kernel.ActionTransition && !validIdempotencyKey(input.IdempotencyKey)) ||
		(action == kernel.ActionRelease || action == kernel.ActionTransfer) && !validText(input.Reason, 2_000, true) ||
		!validText(input.Reason, 2_000, false) {
		return MutationResult{}, ErrInvalidInput
	}
	access, err := service.access(ctx, actor, tenantID, capability)
	if err != nil {
		return MutationResult{}, err
	}
	view, err := service.getAuthorized(ctx, tenantID, kind, id, access)
	if err != nil {
		return MutationResult{}, err
	}
	if view.Projection != ProjectionOperator {
		return MutationResult{}, ErrForbidden
	}
	var idempotencyHash [sha256.Size]byte
	var fingerprint [sha256.Size]byte
	if input.IdempotencyKey != "" {
		idempotencyHash = sha256.Sum256([]byte(input.IdempotencyKey))
	}
	if action == kernel.ActionTransition {
		if err := validateTransitionInput(access.Authority.Principal(), input); err != nil {
			return MutationResult{}, err
		}
		var fingerprintErr error
		fingerprint, fingerprintErr = mutationFingerprint(tenantID, actor.UserID, id, kind, action, input)
		if fingerprintErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		replay, found, replayErr := service.repository.LookupMutationReplay(ctx, MutationReplayQuery{
			TenantID: tenantID, ActorID: actor.UserID, TicketID: id, Kind: kind, Action: action,
			KeyHash: idempotencyHash, Fingerprint: fingerprint,
		})
		if replayErr != nil {
			return MutationResult{}, repositoryError(replayErr)
		}
		if found {
			if validateRecord(replay.Record, tenantID, kind) != nil || uuidFromEntity(replay.Record.Snapshot.ID()) != id {
				return MutationResult{}, ErrUnavailable
			}
			return MutationResult{
				View: View{Record: replay.Record, Projection: ProjectionOperator}, Replayed: true,
			}, nil
		}
	}
	tenant := view.Record.Snapshot.Tenant()
	ticket := view.Record.Snapshot.ID()
	var decision kernel.Decision
	switch action {
	case kernel.ActionAssign:
		team, assignee, conversionErr := assignmentTarget(input.TeamID, input.AssigneeID)
		if conversionErr != nil {
			return MutationResult{}, conversionErr
		}
		command, commandErr := kernel.NewAssignCommand(tenant, ticket, input.ExpectedVersion, team, assignee)
		if commandErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		decision = kernel.PlanAssign(view.Record.Workflow, view.Record.Snapshot, command, access.Authority)
	case kernel.ActionClaim:
		team, teamErr := claimTeam(view.Record, access, input.TeamID)
		if teamErr != nil {
			return MutationResult{}, teamErr
		}
		command, commandErr := kernel.NewClaimCommand(tenant, ticket, input.ExpectedVersion, team)
		if commandErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		decision = kernel.PlanClaim(view.Record.Workflow, view.Record.Snapshot, command, access.Authority)
	case kernel.ActionRelease:
		command, commandErr := kernel.NewReleaseCommand(tenant, ticket, input.ExpectedVersion)
		if commandErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		decision = kernel.PlanRelease(view.Record.Workflow, view.Record.Snapshot, command, access.Authority)
	case kernel.ActionTransfer:
		team, assignee, conversionErr := assignmentTarget(input.TeamID, input.AssigneeID)
		if conversionErr != nil {
			return MutationResult{}, conversionErr
		}
		command, commandErr := kernel.NewTransferCommand(tenant, ticket, input.ExpectedVersion, team, assignee)
		if commandErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		decision = kernel.PlanTransfer(view.Record.Workflow, view.Record.Snapshot, command, access.Authority)
	case kernel.ActionTransition:
		transition, transitionErr := contractKey(input.TransitionKey)
		target, targetErr := contractKey(input.TargetStateKey)
		fieldNames := make([]string, 0, len(input.CustomFields))
		for name := range input.CustomFields {
			fieldNames = append(fieldNames, name)
		}
		fields, fieldsErr := customKeys(fieldNames)
		if transitionErr != nil || targetErr != nil || fieldsErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		if !validCustomFields(input.CustomFields) {
			return MutationResult{}, ErrInvalidInput
		}
		var comment *kernel.CommentDraft
		if input.Comment != "" {
			value, commentErr := kernel.NewCommentDraft(access.Authority.Principal(), kernel.CommentPrivate, input.Comment)
			if commentErr != nil {
				return MutationResult{}, ErrInvalidInput
			}
			comment = &value
		}
		command, commandErr := kernel.NewTransitionCommand(
			tenant, ticket, input.ExpectedVersion, transition, target, comment, fields,
		)
		if commandErr != nil {
			return MutationResult{}, ErrInvalidInput
		}
		facts, factsErr := transitionConditionFacts(view.Record, input)
		if factsErr != nil {
			return MutationResult{}, factsErr
		}
		decision = kernel.PlanTransitionWithIntentAndFacts(
			view.Record.Workflow, view.Record.Snapshot, command, access.Authority, input.TransitionIntent, facts,
		)
	default:
		return MutationResult{}, ErrInvalidInput
	}
	plan, err := mutationPlan(decision)
	if err != nil {
		return MutationResult{}, err
	}
	expected, err := kernel.ApplyMutationPlan(view.Record.Workflow, view.Record.Snapshot, plan)
	if err != nil {
		return MutationResult{}, ErrUnavailable
	}
	result, err := service.repository.ApplyMutation(ctx, MutationWrite{
		Actor: actor, Current: view.Record, Plan: plan, TransitionKey: input.TransitionKey, Reason: input.Reason, CustomFields: input.CustomFields,
		IdempotencyHash: idempotencyHash, Fingerprint: fingerprint, Audit: actor.Audit,
	})
	if err != nil {
		return MutationResult{}, repositoryError(err)
	}
	if validateRecord(result.Record, tenantID, kind) != nil || !result.Replayed && !sameSnapshot(expected, result.Record.Snapshot) {
		return MutationResult{}, ErrUnavailable
	}
	mutationResult := MutationResult{
		View:    View{Record: result.Record, Projection: ProjectionOperator},
		Effects: effectsForPlans([]kernel.MutationPlan{plan}), Replayed: result.Replayed,
	}
	if action == kernel.ActionClaim {
		claimant, claimed := result.Record.Snapshot.Assignment().Claimant()
		if !claimed || claimant != access.Authority.Actor() || result.Record.ClaimedAt == nil || result.Record.ClaimedAt.IsZero() {
			return MutationResult{}, ErrUnavailable
		}
		mutationResult.ClaimWinner = &ClaimWinner{
			ClaimedBy: uuidFromEntity(claimant), ClaimedAt: *result.Record.ClaimedAt,
			Version: result.Record.Snapshot.Version(),
		}
	}
	return mutationResult, nil
}

func validateTransitionInput(principal kernel.PrincipalKind, input MutationInput) error {
	if _, err := contractKey(input.TransitionKey); err != nil {
		return ErrInvalidInput
	}
	if _, err := contractKey(input.TargetStateKey); err != nil {
		return ErrInvalidInput
	}
	fieldNames := make([]string, 0, len(input.CustomFields))
	for name := range input.CustomFields {
		fieldNames = append(fieldNames, name)
	}
	if _, err := customKeys(fieldNames); err != nil || !validCustomFields(input.CustomFields) {
		return ErrInvalidInput
	}
	if input.Comment != "" {
		if _, err := kernel.NewCommentDraft(principal, kernel.CommentPrivate, input.Comment); err != nil {
			return ErrInvalidInput
		}
	}
	return nil
}

func mutationFingerprint(tenantID, actorID, ticketID uuid.UUID, kind kernel.AggregateKind, action kernel.Action, input MutationInput) ([sha256.Size]byte, error) {
	canonical := struct {
		TenantID       string         `json:"tenant_id"`
		ActorID        string         `json:"actor_id"`
		TicketID       string         `json:"ticket_id"`
		Kind           string         `json:"kind"`
		Action         string         `json:"action"`
		Intent         string         `json:"intent,omitempty"`
		Expected       uint64         `json:"expected_version"`
		TransitionKey  string         `json:"transition_key"`
		TargetStateKey string         `json:"target_state_key"`
		Comment        string         `json:"comment"`
		CustomFields   map[string]any `json:"custom_fields"`
	}{
		TenantID: tenantID.String(), ActorID: actorID.String(), TicketID: ticketID.String(),
		Kind: kind.String(), Action: action.String(), Intent: input.TransitionIntent.String(), Expected: input.ExpectedVersion,
		TransitionKey: input.TransitionKey, TargetStateKey: input.TargetStateKey,
		Comment: input.Comment, CustomFields: input.CustomFields,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil || len(encoded) > 512*1024 {
		return [sha256.Size]byte{}, ErrInvalidInput
	}
	return sha256.Sum256(encoded), nil
}

func validMutationTransitionIntent(action kernel.Action, intent kernel.TransitionIntent) bool {
	if action != kernel.ActionTransition {
		return intent == kernel.TransitionIntentAny
	}
	return intent == kernel.TransitionIntentAny || intent == kernel.TransitionIntentClose ||
		intent == kernel.TransitionIntentReopen
}

func validateCreateCaseInput(input CreateCaseInput) error {
	if !validIdempotencyKey(input.IdempotencyKey) || !validText(input.Title, 240, true) ||
		!validText(input.Description, 20_000, false) || !validText(input.Summary, 2_000, false) ||
		!validText(input.Category, 120, false) || !validOptionalText(input.Classification, 120) ||
		!validEnum(input.Severity, "informational", "low", "medium", "high", "critical") ||
		!validEnum(input.Priority, "low", "medium", "high", "urgent", "critical") ||
		!validTags(input.Tags) || !validCustomFields(input.CustomFields) ||
		input.DetectionTime != (time.Time{}) && !validStoredInstant(input.DetectionTime) ||
		input.AssigneeUserID != nil && input.AssignedTeamID == nil {
		return ErrInvalidInput
	}
	for key := range input.CustomFields {
		if _, err := customKey(key); err != nil {
			return ErrInvalidInput
		}
	}
	for _, value := range []*uuid.UUID{input.WorkflowID, input.AssignedTeamID, input.AssigneeUserID} {
		if value != nil {
			if _, err := entityID(*value); err != nil {
				return ErrInvalidInput
			}
		}
	}
	return nil
}

// ValidateCreateCaseInput applies the same bounded syntax checks used by the use case.
func ValidateCreateCaseInput(input CreateCaseInput) error { return validateCreateCaseInput(input) }

func mutationCapability(kind kernel.AggregateKind, action kernel.Action) Capability {
	if kind == kernel.AggregateAlert {
		switch action {
		case kernel.ActionAssign, kernel.ActionTransfer:
			return CapabilityAlertAssign
		case kernel.ActionClaim, kernel.ActionRelease:
			return CapabilityAlertClaim
		case kernel.ActionTransition:
			return CapabilityAlertUpdate
		}
	}
	if kind == kernel.AggregateCase {
		switch action {
		case kernel.ActionAssign, kernel.ActionTransfer:
			return CapabilityCaseTransfer
		case kernel.ActionClaim, kernel.ActionRelease:
			return CapabilityCaseClaim
		case kernel.ActionTransition:
			return CapabilityCaseTransition
		}
	}
	return ""
}

func assignmentTarget(teamID, assigneeID *uuid.UUID) (kernel.EntityID, *kernel.EntityID, error) {
	if teamID == nil {
		return kernel.EntityID{}, nil, ErrInvalidInput
	}
	team, err := entityID(*teamID)
	if err != nil {
		return kernel.EntityID{}, nil, ErrInvalidInput
	}
	if assigneeID == nil {
		return team, nil, nil
	}
	assignee, err := entityID(*assigneeID)
	if err != nil {
		return kernel.EntityID{}, nil, ErrInvalidInput
	}
	return team, &assignee, nil
}

func claimTeam(record Record, access LiveAccess, requested *uuid.UUID) (kernel.EntityID, error) {
	if requested != nil {
		team, err := entityID(*requested)
		if err != nil {
			return kernel.EntityID{}, ErrInvalidInput
		}
		return team, nil
	}
	if team, assigned := record.Snapshot.Assignment().Team(); assigned {
		return team, nil
	}
	teams := access.Authority.ClaimableTeams()
	if len(teams) != 1 {
		return kernel.EntityID{}, ErrInvalidInput
	}
	return teams[0], nil
}

func contractKey(value string) (kernel.Key, error) {
	if value == "" || len(value) > 64 || value[0] < 'a' || value[0] > 'z' {
		return kernel.Key{}, ErrInvalidInput
	}
	for _, character := range value[1:] {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			character == '_' || character == '-' {
			continue
		}
		return kernel.Key{}, ErrInvalidInput
	}
	key, err := kernel.NewKey(value)
	if err != nil {
		return kernel.Key{}, ErrInvalidInput
	}
	return key, nil
}

func contractKeys(values []string) ([]kernel.Key, error) {
	if len(values) > 64 {
		return nil, ErrInvalidInput
	}
	result := make([]kernel.Key, 0, len(values))
	for _, value := range values {
		key, err := contractKey(value)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	slices.SortFunc(result, func(left, right kernel.Key) int { return strings.Compare(left.String(), right.String()) })
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func customKey(value string) (kernel.Key, error) {
	key, err := kernel.NewKey(value)
	if err != nil {
		return kernel.Key{}, ErrInvalidInput
	}
	return key, nil
}

func customKeys(values []string) ([]kernel.Key, error) {
	if len(values) > 100 {
		return nil, ErrInvalidInput
	}
	result := make([]kernel.Key, 0, len(values))
	for _, value := range values {
		key, err := customKey(value)
		if err != nil {
			return nil, err
		}
		result = append(result, key)
	}
	slices.SortFunc(result, func(left, right kernel.Key) int { return strings.Compare(left.String(), right.String()) })
	for index := 1; index < len(result); index++ {
		if result[index-1] == result[index] {
			return nil, ErrInvalidInput
		}
	}
	return result, nil
}

func mutationPlan(decision kernel.Decision) (kernel.MutationPlan, error) {
	if plan, allowed := decision.Plan(); allowed {
		return plan, nil
	}
	switch decision.Reason() {
	case kernel.ReasonInvalidSnapshot:
		return kernel.MutationPlan{}, ErrUnavailable
	case kernel.ReasonTenantAccess, kernel.ReasonTargetMismatch, kernel.ReasonPrincipalKind,
		kernel.ReasonPermission, kernel.ReasonRole, kernel.ReasonCondition, kernel.ReasonTeamEligibility,
		kernel.ReasonAssigneeEligibility, kernel.ReasonNotClaimant, kernel.ReasonAssignedToOther:
		return kernel.MutationPlan{}, ErrForbidden
	case kernel.ReasonRequiredComment, kernel.ReasonRequiredCustomField:
		return kernel.MutationPlan{}, ErrInvalidInput
	case kernel.ReasonVersionConflict:
		return kernel.MutationPlan{}, ErrPreconditionFailed
	case kernel.ReasonVersionExhausted:
		return kernel.MutationPlan{}, ErrConflict
	default:
		return kernel.MutationPlan{}, ErrConflict
	}
}

func sameSnapshot(left, right kernel.TicketSnapshot) bool {
	return left.Kind() == right.Kind() && left.Tenant() == right.Tenant() && left.ID() == right.ID() &&
		left.WorkflowID() == right.WorkflowID() && left.WorkflowVersion() == right.WorkflowVersion() &&
		left.State() == right.State() && left.Version() == right.Version() &&
		left.CustomerVisible() == right.CustomerVisible() && left.Assignment() == right.Assignment()
}

func effectsForPlans(plans []kernel.MutationPlan) []string {
	seen := make(map[string]struct{}, 4)
	for _, plan := range plans {
		for _, effect := range plan.Effects().Effects() {
			seen[effect.String()] = struct{}{}
		}
	}
	result := make([]string, 0, len(seen))
	for _, value := range []string{"activity", "audit", "sla", "notification"} {
		if _, exists := seen[value]; exists {
			result = append(result, value)
		}
	}
	return result
}

// Linked/unlinked are explicit relationship lifecycle actions, but the
// notification event catalog has no corresponding event types. Excluding the
// effect here keeps the committed effect receipt honest instead of silently
// claiming a notification that cannot be emitted.
func effectsForLinkLifecyclePlans(plans []kernel.MutationPlan) []string {
	return slices.DeleteFunc(effectsForPlans(plans), func(effect string) bool {
		return effect == "notification"
	})
}
