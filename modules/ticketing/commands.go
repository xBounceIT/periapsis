package ticketing

import (
	"fmt"
	"slices"
)

type DecisionOutcome uint8

const (
	OutcomeAllowed DecisionOutcome = iota + 1
	OutcomeDenied
	OutcomeConflict
)

func (outcome DecisionOutcome) String() string {
	switch outcome {
	case OutcomeAllowed:
		return "allowed"
	case OutcomeDenied:
		return "denied"
	case OutcomeConflict:
		return "conflict"
	default:
		return "unknown"
	}
}

type DecisionReason uint8

const (
	ReasonNone DecisionReason = iota
	ReasonInvalidSnapshot
	ReasonTenantAccess
	ReasonTargetMismatch
	ReasonPrincipalKind
	ReasonPermission
	ReasonRole
	ReasonWorkflowState
	ReasonRequiredComment
	ReasonRequiredCustomField
	ReasonCondition
	ReasonTeamEligibility
	ReasonAssigneeEligibility
	ReasonAlreadyAssigned
	ReasonAlreadyClaimed
	ReasonNotClaimed
	ReasonNotClaimant
	ReasonAssignedToOther
	ReasonNoChange
	ReasonVersionConflict
	ReasonVersionExhausted
)

func (reason DecisionReason) String() string {
	switch reason {
	case ReasonNone:
		return "none"
	case ReasonInvalidSnapshot:
		return "invalid_snapshot"
	case ReasonTenantAccess:
		return "tenant_access"
	case ReasonTargetMismatch:
		return "target_mismatch"
	case ReasonPrincipalKind:
		return "principal_kind"
	case ReasonPermission:
		return "permission"
	case ReasonRole:
		return "role"
	case ReasonWorkflowState:
		return "workflow_state"
	case ReasonRequiredComment:
		return "required_comment"
	case ReasonRequiredCustomField:
		return "required_custom_field"
	case ReasonCondition:
		return "condition"
	case ReasonTeamEligibility:
		return "team_eligibility"
	case ReasonAssigneeEligibility:
		return "assignee_eligibility"
	case ReasonAlreadyAssigned:
		return "already_assigned"
	case ReasonAlreadyClaimed:
		return "already_claimed"
	case ReasonNotClaimed:
		return "not_claimed"
	case ReasonNotClaimant:
		return "not_claimant"
	case ReasonAssignedToOther:
		return "assigned_to_other"
	case ReasonNoChange:
		return "no_change"
	case ReasonVersionConflict:
		return "version_conflict"
	case ReasonVersionExhausted:
		return "version_exhausted"
	default:
		return "unknown"
	}
}

// Decision is fail-closed. A mutation plan exists only for OutcomeAllowed.
type Decision struct {
	outcome DecisionOutcome
	reason  DecisionReason
	plan    MutationPlan
}

func (decision Decision) Outcome() DecisionOutcome { return decision.outcome }
func (decision Decision) Reason() DecisionReason   { return decision.reason }
func (decision Decision) Allowed() bool            { return decision.outcome == OutcomeAllowed }
func (decision Decision) Plan() (MutationPlan, bool) {
	return decision.plan, decision.outcome == OutcomeAllowed
}

func (decision Decision) String() string {
	return fmt.Sprintf("Decision{outcome:%s,reason:%s}", decision.outcome, decision.reason)
}

func deny(reason DecisionReason) Decision {
	return Decision{outcome: OutcomeDenied, reason: reason}
}

func conflict(reason DecisionReason) Decision {
	return Decision{outcome: OutcomeConflict, reason: reason}
}

func allow(plan MutationPlan) Decision {
	return Decision{outcome: OutcomeAllowed, reason: ReasonNone, plan: plan}
}

type commandTarget struct {
	tenant          EntityID
	ticket          EntityID
	expectedVersion uint64
}

func newCommandTarget(tenant, ticket EntityID, expectedVersion uint64, create bool) (commandTarget, error) {
	if !validEntityID(tenant) || !validEntityID(ticket) || create && expectedVersion != 0 ||
		!create && (expectedVersion == 0 || expectedVersion > maxVersion) {
		return commandTarget{}, ErrInvalidCommand
	}
	return commandTarget{tenant: tenant, ticket: ticket, expectedVersion: expectedVersion}, nil
}

type CreateCommand struct {
	target          commandTarget
	workflowID      EntityID
	workflowVersion uint64
	customerVisible bool
}

func NewCreateCommand(
	tenant EntityID,
	ticket EntityID,
	workflowID EntityID,
	workflowVersion uint64,
	expectedVersion uint64,
	customerVisible bool,
) (CreateCommand, error) {
	target, err := newCommandTarget(tenant, ticket, expectedVersion, true)
	if err != nil || !validEntityID(workflowID) || workflowVersion == 0 || workflowVersion > maxVersion {
		return CreateCommand{}, ErrInvalidCommand
	}
	return CreateCommand{
		target:          target,
		workflowID:      workflowID,
		workflowVersion: workflowVersion,
		customerVisible: customerVisible,
	}, nil
}

type TransitionCommand struct {
	target               commandTarget
	transition           Key
	to                   Key
	comment              *CommentDraft
	providedCustomFields []Key
}

func (command TransitionCommand) String() string {
	return fmt.Sprintf("TransitionCommand{expected:%d,transition:%s,to:%s,comment:%t,custom_fields:%d}",
		command.target.expectedVersion, command.transition, command.to, command.comment != nil, len(command.providedCustomFields))
}

func (command TransitionCommand) GoString() string { return command.String() }

func NewTransitionCommand(
	tenant EntityID,
	ticket EntityID,
	expectedVersion uint64,
	transition Key,
	to Key,
	comment *CommentDraft,
	providedCustomFields []Key,
) (TransitionCommand, error) {
	target, err := newCommandTarget(tenant, ticket, expectedVersion, false)
	fields, fieldsOK := canonicalKeys(providedCustomFields, maxCustomFieldValues)
	if err != nil || !validKey(transition.value) || !validKey(to.value) || !fieldsOK || comment != nil && !validCommentDraft(*comment) {
		return TransitionCommand{}, ErrInvalidCommand
	}
	var ownedComment *CommentDraft
	if comment != nil {
		copy := *comment
		ownedComment = &copy
	}
	return TransitionCommand{target: target, transition: transition, to: to, comment: ownedComment, providedCustomFields: fields}, nil
}

type AssignCommand struct {
	target      commandTarget
	team        EntityID
	hasAssignee bool
	assignee    EntityID
}

func NewAssignCommand(
	tenant EntityID,
	ticket EntityID,
	expectedVersion uint64,
	team EntityID,
	assignee *EntityID,
) (AssignCommand, error) {
	target, err := newCommandTarget(tenant, ticket, expectedVersion, false)
	if err != nil || !validEntityID(team) || assignee != nil && !validEntityID(*assignee) {
		return AssignCommand{}, ErrInvalidCommand
	}
	command := AssignCommand{target: target, team: team}
	if assignee != nil {
		command.hasAssignee = true
		command.assignee = *assignee
	}
	return command, nil
}

type ClaimCommand struct {
	target commandTarget
	team   EntityID
}

func NewClaimCommand(
	tenant EntityID,
	ticket EntityID,
	expectedVersion uint64,
	team EntityID,
) (ClaimCommand, error) {
	target, err := newCommandTarget(tenant, ticket, expectedVersion, false)
	if err != nil || !validEntityID(team) {
		return ClaimCommand{}, ErrInvalidCommand
	}
	return ClaimCommand{target: target, team: team}, nil
}

type ReleaseCommand struct {
	target commandTarget
}

func NewReleaseCommand(tenant, ticket EntityID, expectedVersion uint64) (ReleaseCommand, error) {
	target, err := newCommandTarget(tenant, ticket, expectedVersion, false)
	if err != nil {
		return ReleaseCommand{}, err
	}
	return ReleaseCommand{target: target}, nil
}

type TransferCommand struct {
	target      commandTarget
	team        EntityID
	hasAssignee bool
	assignee    EntityID
}

func NewTransferCommand(
	tenant EntityID,
	ticket EntityID,
	expectedVersion uint64,
	team EntityID,
	assignee *EntityID,
) (TransferCommand, error) {
	target, err := newCommandTarget(tenant, ticket, expectedVersion, false)
	if err != nil || !validEntityID(team) || assignee != nil && !validEntityID(*assignee) {
		return TransferCommand{}, ErrInvalidCommand
	}
	command := TransferCommand{target: target, team: team}
	if assignee != nil {
		command.hasAssignee = true
		command.assignee = *assignee
	}
	return command, nil
}

func PlanCreate(
	workflow WorkflowDefinition,
	command CreateCommand,
	authority AuthorizationSnapshot,
) Decision {
	if !validWorkflowDefinition(workflow) || !validAuthorizationSnapshot(authority) {
		return deny(ReasonInvalidSnapshot)
	}
	if !authority.tenantAccess || authority.tenant != command.target.tenant {
		return deny(ReasonTenantAccess)
	}
	if workflow.id != command.workflowID || workflow.version != command.workflowVersion {
		return deny(ReasonTargetMismatch)
	}
	permission, _ := permissionFor(workflow.kind, ActionCreate)
	if !authority.hasPermission(permission) {
		return deny(ReasonPermission)
	}
	if workflow.kind == AggregateCase && authority.principal != PrincipalOperator {
		return deny(ReasonPrincipalKind)
	}
	initial, exists := workflow.state(workflow.initial)
	if !exists {
		return deny(ReasonInvalidSnapshot)
	}
	effects, allowed := initial.effectFor(ActionCreate)
	if !allowed {
		return deny(ReasonWorkflowState)
	}
	return allow(MutationPlan{
		action:          ActionCreate,
		kind:            workflow.kind,
		tenant:          command.target.tenant,
		ticket:          command.target.ticket,
		workflowID:      workflow.id,
		workflowVersion: workflow.version,
		actor:           authority.actor,
		expectedVersion: 0,
		nextVersion:     1,
		toState:         workflow.initial,
		customerVisible: command.customerVisible,
		effects:         effects,
	})
}

func PlanTransition(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	command TransitionCommand,
	authority AuthorizationSnapshot,
) Decision {
	return PlanTransitionWithFacts(workflow, ticket, command, authority, ConditionFacts{})
}

func PlanTransitionWithFacts(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	command TransitionCommand,
	authority AuthorizationSnapshot,
	facts ConditionFacts,
) Decision {
	return PlanTransitionWithIntentAndFacts(
		workflow, ticket, command, authority, TransitionIntentAny, facts,
	)
}

// PlanTransitionWithIntentAndFacts binds an explicit close or reopen command
// to the validated workflow edge before a mutation plan can be produced.
func PlanTransitionWithIntentAndFacts(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	command TransitionCommand,
	authority AuthorizationSnapshot,
	intent TransitionIntent,
	facts ConditionFacts,
) Decision {
	state, decision := validateExistingCommand(workflow, ticket, command.target, authority, ActionTransition)
	if decision.outcome != 0 {
		return decision
	}
	transition, exists := workflow.transition(command.transition)
	if !exists || transition.from != state.key || transition.to != command.to {
		return deny(ReasonWorkflowState)
	}
	target, targetExists := workflow.state(transition.to)
	if !targetExists || !transitionMatchesIntent(state, target, transition, intent) {
		return deny(ReasonWorkflowState)
	}
	if !authority.hasAllPermissions(transition.requiredPermissions) {
		return deny(ReasonPermission)
	}
	if !authority.hasAnyRole(transition.requiredRoles) {
		return deny(ReasonRole)
	}
	if transition.requiredComment && command.comment == nil {
		return deny(ReasonRequiredComment)
	}
	if command.comment != nil && !CanCreateComment(ticket.kind, ticket.tenant, *command.comment, authority) {
		return deny(ReasonPermission)
	}
	if !containsAllKeys(command.providedCustomFields, transition.requiredCustomFields) {
		return deny(ReasonRequiredCustomField)
	}
	if !validConditionFacts(facts) || !transition.condition.Evaluate(facts) {
		return deny(ReasonCondition)
	}
	decision = allowedExistingPlan(
		workflow,
		ticket,
		authority.actor,
		ActionTransition,
		command.to,
		ticket.assignment,
		transition.effects,
	)
	if command.comment != nil {
		comment := *command.comment
		decision.plan.comment = &comment
	}
	return decision
}

func transitionMatchesIntent(
	current StateDefinition,
	target StateDefinition,
	transition TransitionDefinition,
	intent TransitionIntent,
) bool {
	switch intent {
	case TransitionIntentAny:
		return true
	case TransitionIntentClose:
		return !current.terminal && target.terminal && !transition.reopen
	case TransitionIntentReopen:
		return current.terminal && !target.terminal && transition.reopen
	default:
		return false
	}
}

func PlanAssign(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	command AssignCommand,
	authority AuthorizationSnapshot,
) Decision {
	state, decision := validateExistingCommand(workflow, ticket, command.target, authority, ActionAssign)
	if decision.outcome != 0 {
		return decision
	}
	if ticket.assignment.hasClaimant {
		return deny(ReasonAlreadyClaimed)
	}
	// Assignment is the unassigned-queue operation. Once a team owns the
	// ticket, changing that ownership must cross the separately allowlisted
	// transfer action and its source-team authority checks.
	if ticket.assignment.hasTeam {
		return deny(ReasonAlreadyAssigned)
	}
	if !authority.mayManageTeam(command.team) {
		return deny(ReasonTeamEligibility)
	}
	if command.hasAssignee && !authority.mayAssign(command.team, command.assignee) {
		return deny(ReasonAssigneeEligibility)
	}
	assignment, _ := assignmentFor(command.team, command.hasAssignee, command.assignee, false, EntityID{})
	if assignment == ticket.assignment {
		return deny(ReasonNoChange)
	}
	effects, _ := state.effectFor(ActionAssign)
	return allowedExistingPlan(workflow, ticket, authority.actor, ActionAssign, ticket.state, assignment, effects)
}

func PlanClaim(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	command ClaimCommand,
	authority AuthorizationSnapshot,
) Decision {
	state, decision := validateExistingCommand(workflow, ticket, command.target, authority, ActionClaim)
	if decision.outcome != 0 {
		return decision
	}
	if ticket.assignment.hasClaimant {
		return deny(ReasonAlreadyClaimed)
	}
	if ticket.assignment.hasTeam && ticket.assignment.team != command.team {
		return deny(ReasonTeamEligibility)
	}
	if ticket.assignment.hasAssignee && ticket.assignment.assignee != authority.actor {
		return deny(ReasonAssignedToOther)
	}
	if !authority.mayClaimTeam(command.team) {
		return deny(ReasonTeamEligibility)
	}
	assignment, _ := assignmentFor(command.team, true, authority.actor, true, authority.actor)
	effects, _ := state.effectFor(ActionClaim)
	return allowedExistingPlan(workflow, ticket, authority.actor, ActionClaim, ticket.state, assignment, effects)
}

func PlanRelease(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	command ReleaseCommand,
	authority AuthorizationSnapshot,
) Decision {
	state, decision := validateExistingCommand(workflow, ticket, command.target, authority, ActionRelease)
	if decision.outcome != 0 {
		return decision
	}
	if !ticket.assignment.hasClaimant {
		return deny(ReasonNotClaimed)
	}
	if ticket.assignment.claimant != authority.actor {
		managePermission, _ := permissionFor(workflow.kind, ActionTransfer)
		if !authority.hasPermission(managePermission) || !authority.mayManageTeam(ticket.assignment.team) {
			return deny(ReasonNotClaimant)
		}
	}
	assignment, _ := assignmentFor(ticket.assignment.team, false, EntityID{}, false, EntityID{})
	effects, _ := state.effectFor(ActionRelease)
	return allowedExistingPlan(workflow, ticket, authority.actor, ActionRelease, ticket.state, assignment, effects)
}

func PlanTransfer(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	command TransferCommand,
	authority AuthorizationSnapshot,
) Decision {
	state, decision := validateExistingCommand(workflow, ticket, command.target, authority, ActionTransfer)
	if decision.outcome != 0 {
		return decision
	}
	if !ticket.assignment.hasTeam {
		return deny(ReasonWorkflowState)
	}
	// A transfer removes the current team's ownership as well as granting the
	// target team's ownership. Requiring both sides prevents a manager of an
	// unrelated target queue from pulling work out of another team's queue.
	if !authority.mayManageTeam(ticket.assignment.team) ||
		!authority.mayManageTeam(command.team) {
		return deny(ReasonTeamEligibility)
	}
	if command.hasAssignee && !authority.mayAssign(command.team, command.assignee) {
		return deny(ReasonAssigneeEligibility)
	}
	assignment, _ := assignmentFor(command.team, command.hasAssignee, command.assignee, false, EntityID{})
	if assignment == ticket.assignment {
		return deny(ReasonNoChange)
	}
	effects, _ := state.effectFor(ActionTransfer)
	return allowedExistingPlan(workflow, ticket, authority.actor, ActionTransfer, ticket.state, assignment, effects)
}

func validateExistingCommand(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	target commandTarget,
	authority AuthorizationSnapshot,
	action Action,
) (StateDefinition, Decision) {
	if !validWorkflowDefinition(workflow) || !validTicketSnapshot(workflow, ticket) ||
		!validAuthorizationSnapshot(authority) {
		return StateDefinition{}, deny(ReasonInvalidSnapshot)
	}
	if !authority.tenantAccess || authority.tenant != ticket.tenant {
		return StateDefinition{}, deny(ReasonTenantAccess)
	}
	if target.tenant != ticket.tenant || target.ticket != ticket.id {
		return StateDefinition{}, deny(ReasonTargetMismatch)
	}
	if authority.principal != PrincipalOperator {
		return StateDefinition{}, deny(ReasonPrincipalKind)
	}
	permission, exists := permissionFor(ticket.kind, action)
	if !exists || !authority.hasPermission(permission) {
		return StateDefinition{}, deny(ReasonPermission)
	}
	if target.expectedVersion != ticket.version {
		return StateDefinition{}, conflict(ReasonVersionConflict)
	}
	if ticket.version == maxVersion {
		return StateDefinition{}, conflict(ReasonVersionExhausted)
	}
	state, exists := workflow.state(ticket.state)
	if !exists {
		return StateDefinition{}, deny(ReasonInvalidSnapshot)
	}
	if action != ActionTransition {
		if _, admitted := state.effectFor(action); !admitted {
			return StateDefinition{}, deny(ReasonWorkflowState)
		}
	}
	return state, Decision{}
}

func allowedExistingPlan(
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	actor EntityID,
	action Action,
	toState Key,
	assignment Assignment,
	effects EffectPlan,
) Decision {
	return allow(MutationPlan{
		action:          action,
		kind:            ticket.kind,
		tenant:          ticket.tenant,
		ticket:          ticket.id,
		workflowID:      workflow.id,
		workflowVersion: workflow.version,
		actor:           actor,
		expectedVersion: ticket.version,
		nextVersion:     ticket.version + 1,
		fromState:       ticket.state,
		toState:         toState,
		customerVisible: ticket.customerVisible,
		assignment:      assignment,
		effects:         effects,
	})
}

func assignmentFor(
	team EntityID,
	hasAssignee bool,
	assignee EntityID,
	hasClaimant bool,
	claimant EntityID,
) (Assignment, error) {
	var assigneePointer *EntityID
	if hasAssignee {
		assigneePointer = &assignee
	}
	var claimantPointer *EntityID
	if hasClaimant {
		claimantPointer = &claimant
	}
	return NewAssignment(&team, assigneePointer, claimantPointer)
}

func containsAllKeys(provided, required []Key) bool {
	for _, key := range required {
		if _, found := slices.BinarySearchFunc(provided, key, func(candidate, target Key) int {
			return compareKey(candidate, target)
		}); !found {
			return false
		}
	}
	return true
}

func compareKey(left, right Key) int {
	if left.value < right.value {
		return -1
	}
	if left.value > right.value {
		return 1
	}
	return 0
}

// SerializedClaimAttempt carries the ordering assigned by the persistence
// serialization boundary. The kernel never pretends request arrival or UI state
// chooses a winner; order plus a UUIDv7 tie-breaker make the model reproducible.
type SerializedClaimAttempt struct {
	order     uint64
	attemptID EntityID
	command   ClaimCommand
	authority AuthorizationSnapshot
}

func NewSerializedClaimAttempt(
	order uint64,
	attemptID EntityID,
	command ClaimCommand,
	authority AuthorizationSnapshot,
) (SerializedClaimAttempt, error) {
	if order == 0 || !validEntityID(attemptID) || !validAuthorizationSnapshot(authority) {
		return SerializedClaimAttempt{}, ErrInvalidCommand
	}
	return SerializedClaimAttempt{order: order, attemptID: attemptID, command: command, authority: authority}, nil
}

type ClaimAttemptDecision struct {
	attemptID EntityID
	decision  Decision
}

func (decision ClaimAttemptDecision) AttemptID() EntityID { return decision.attemptID }
func (decision ClaimAttemptDecision) Decision() Decision  { return decision.decision }

// ResolveSerializedClaimAttempts is an executable concurrency oracle for
// compare-and-update tests. At most one eligible attempt can advance the
// snapshot; every later attempt carrying the old version conflicts.
func ResolveSerializedClaimAttempts(
	workflow WorkflowDefinition,
	current TicketSnapshot,
	attempts []SerializedClaimAttempt,
) ([]ClaimAttemptDecision, TicketSnapshot, error) {
	if !validTicketSnapshot(workflow, current) || len(attempts) == 0 || len(attempts) > maxAuthorityItems {
		return nil, TicketSnapshot{}, ErrInvalidCommand
	}
	ordered := slices.Clone(attempts)
	for _, attempt := range ordered {
		if attempt.order == 0 || !validEntityID(attempt.attemptID) ||
			!validAuthorizationSnapshot(attempt.authority) {
			return nil, TicketSnapshot{}, ErrInvalidCommand
		}
	}
	slices.SortFunc(ordered, func(left, right SerializedClaimAttempt) int {
		if left.order < right.order {
			return -1
		}
		if left.order > right.order {
			return 1
		}
		return compareEntityID(left.attemptID, right.attemptID)
	})
	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].attemptID == ordered[index].attemptID {
			return nil, TicketSnapshot{}, ErrInvalidCommand
		}
	}
	result := make([]ClaimAttemptDecision, 0, len(ordered))
	snapshot := current
	for _, attempt := range ordered {
		decision := PlanClaim(workflow, snapshot, attempt.command, attempt.authority)
		result = append(result, ClaimAttemptDecision{attemptID: attempt.attemptID, decision: decision})
		plan, allowed := decision.Plan()
		if !allowed {
			continue
		}
		var err error
		snapshot, err = ApplyMutationPlan(workflow, snapshot, plan)
		if err != nil {
			return nil, TicketSnapshot{}, err
		}
	}
	return result, snapshot, nil
}
