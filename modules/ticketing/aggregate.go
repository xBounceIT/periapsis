package ticketing

import "fmt"

// Assignment keeps team ownership, an optional assignee, and an optional
// claimant distinct. A claimant is always the current assignee of a team-owned
// ticket; malformed partial combinations cannot be constructed.
type Assignment struct {
	hasTeam     bool
	team        EntityID
	hasAssignee bool
	assignee    EntityID
	hasClaimant bool
	claimant    EntityID
}

func NewAssignment(team, assignee, claimant *EntityID) (Assignment, error) {
	if team == nil {
		if assignee != nil || claimant != nil {
			return Assignment{}, ErrInvalidTicket
		}
		return Assignment{}, nil
	}
	if !validEntityID(*team) || assignee != nil && !validEntityID(*assignee) ||
		claimant != nil && !validEntityID(*claimant) ||
		claimant != nil && (assignee == nil || *assignee != *claimant) {
		return Assignment{}, ErrInvalidTicket
	}
	result := Assignment{hasTeam: true, team: *team}
	if assignee != nil {
		result.hasAssignee = true
		result.assignee = *assignee
	}
	if claimant != nil {
		result.hasClaimant = true
		result.claimant = *claimant
	}
	return result, nil
}

func (assignment Assignment) Team() (EntityID, bool) {
	return assignment.team, assignment.hasTeam
}

func (assignment Assignment) Assignee() (EntityID, bool) {
	return assignment.assignee, assignment.hasAssignee
}

func (assignment Assignment) Claimant() (EntityID, bool) {
	return assignment.claimant, assignment.hasClaimant
}

func (assignment Assignment) Claimed() bool { return assignment.hasClaimant }

func (assignment Assignment) String() string {
	return fmt.Sprintf("Assignment{team:%t,assignee:%t,claimant:%t}",
		assignment.hasTeam, assignment.hasAssignee, assignment.hasClaimant)
}

func validAssignment(assignment Assignment) bool {
	if !assignment.hasTeam {
		return !assignment.hasAssignee && !assignment.hasClaimant &&
			assignment.team == (EntityID{}) && assignment.assignee == (EntityID{}) && assignment.claimant == (EntityID{})
	}
	if !validEntityID(assignment.team) || assignment.hasAssignee != validEntityID(assignment.assignee) ||
		assignment.hasClaimant != validEntityID(assignment.claimant) {
		return false
	}
	return !assignment.hasClaimant || assignment.hasAssignee && assignment.assignee == assignment.claimant
}

// TicketSnapshot is the minimum immutable aggregate projection required by
// the command kernel. Business content is deliberately absent.
type TicketSnapshot struct {
	kind            AggregateKind
	tenant          EntityID
	id              EntityID
	workflowID      EntityID
	workflowVersion uint64
	state           Key
	version         uint64
	customerVisible bool
	assignment      Assignment
}

func NewTicketSnapshot(
	workflow WorkflowDefinition,
	tenant EntityID,
	id EntityID,
	state Key,
	version uint64,
	customerVisible bool,
	assignment Assignment,
) (TicketSnapshot, error) {
	if !validWorkflowDefinition(workflow) || !validEntityID(tenant) || !validEntityID(id) ||
		version == 0 || version > maxVersion || !validAssignment(assignment) {
		return TicketSnapshot{}, ErrInvalidTicket
	}
	if _, exists := workflow.state(state); !exists {
		return TicketSnapshot{}, ErrInvalidTicket
	}
	return TicketSnapshot{
		kind:            workflow.kind,
		tenant:          tenant,
		id:              id,
		workflowID:      workflow.id,
		workflowVersion: workflow.version,
		state:           state,
		version:         version,
		customerVisible: customerVisible,
		assignment:      assignment,
	}, nil
}

func (ticket TicketSnapshot) Kind() AggregateKind     { return ticket.kind }
func (ticket TicketSnapshot) Tenant() EntityID        { return ticket.tenant }
func (ticket TicketSnapshot) ID() EntityID            { return ticket.id }
func (ticket TicketSnapshot) WorkflowID() EntityID    { return ticket.workflowID }
func (ticket TicketSnapshot) WorkflowVersion() uint64 { return ticket.workflowVersion }
func (ticket TicketSnapshot) State() Key              { return ticket.state }
func (ticket TicketSnapshot) Version() uint64         { return ticket.version }
func (ticket TicketSnapshot) CustomerVisible() bool   { return ticket.customerVisible }
func (ticket TicketSnapshot) Assignment() Assignment  { return ticket.assignment }

func (ticket TicketSnapshot) String() string {
	return fmt.Sprintf("TicketSnapshot{kind:%s,state:%s,version:%d,customer_visible:%t,%s}",
		ticket.kind, ticket.state, ticket.version, ticket.customerVisible, ticket.assignment)
}

func validTicketSnapshot(workflow WorkflowDefinition, ticket TicketSnapshot) bool {
	if !validWorkflowDefinition(workflow) || !validAggregateKind(ticket.kind) ||
		ticket.kind != workflow.kind || ticket.workflowID != workflow.id ||
		ticket.workflowVersion != workflow.version || !validEntityID(ticket.tenant) ||
		!validEntityID(ticket.id) || ticket.version == 0 || ticket.version > maxVersion ||
		!validAssignment(ticket.assignment) {
		return false
	}
	_, exists := workflow.state(ticket.state)
	return exists
}

// MutationPlan contains only deterministic state and mandatory side-effect
// intent. Persistence must apply it with compare-and-update on ExpectedVersion
// and atomically write every listed effect.
type MutationPlan struct {
	action          Action
	kind            AggregateKind
	tenant          EntityID
	ticket          EntityID
	workflowID      EntityID
	workflowVersion uint64
	actor           EntityID
	expectedVersion uint64
	nextVersion     uint64
	fromState       Key
	toState         Key
	customerVisible bool
	assignment      Assignment
	effects         EffectPlan
	comment         *CommentDraft
}

func (plan MutationPlan) Action() Action          { return plan.action }
func (plan MutationPlan) Kind() AggregateKind     { return plan.kind }
func (plan MutationPlan) Tenant() EntityID        { return plan.tenant }
func (plan MutationPlan) Ticket() EntityID        { return plan.ticket }
func (plan MutationPlan) WorkflowID() EntityID    { return plan.workflowID }
func (plan MutationPlan) WorkflowVersion() uint64 { return plan.workflowVersion }
func (plan MutationPlan) Actor() EntityID         { return plan.actor }
func (plan MutationPlan) ExpectedVersion() uint64 { return plan.expectedVersion }
func (plan MutationPlan) NextVersion() uint64     { return plan.nextVersion }
func (plan MutationPlan) FromState() Key          { return plan.fromState }
func (plan MutationPlan) ToState() Key            { return plan.toState }
func (plan MutationPlan) CustomerVisible() bool   { return plan.customerVisible }
func (plan MutationPlan) Assignment() Assignment  { return plan.assignment }
func (plan MutationPlan) Effects() EffectPlan     { return plan.effects }
func (plan MutationPlan) Comment() (CommentDraft, bool) {
	if plan.comment == nil {
		return CommentDraft{}, false
	}
	return *plan.comment, true
}

func (plan MutationPlan) String() string {
	return fmt.Sprintf("MutationPlan{action:%s,kind:%s,expected:%d,next:%d,from:%s,to:%s,effects:%v,comment:%t}",
		plan.action, plan.kind, plan.expectedVersion, plan.nextVersion, plan.fromState, plan.toState,
		plan.effects.Effects(), plan.comment != nil)
}

func (plan MutationPlan) GoString() string { return plan.String() }

func SnapshotFromCreatePlan(workflow WorkflowDefinition, plan MutationPlan) (TicketSnapshot, error) {
	if !validWorkflowDefinition(workflow) || plan.action != ActionCreate || plan.expectedVersion != 0 ||
		plan.nextVersion != 1 || plan.workflowID != workflow.id || plan.workflowVersion != workflow.version ||
		plan.kind != workflow.kind || plan.fromState != (Key{}) || plan.toState != workflow.initial ||
		!validEntityID(plan.tenant) || !validEntityID(plan.ticket) || !validEntityID(plan.actor) ||
		!validAssignment(plan.assignment) || !validEffectPlan(plan.effects) || plan.comment != nil {
		return TicketSnapshot{}, ErrPlanDoesNotApply
	}
	return NewTicketSnapshot(
		workflow,
		plan.tenant,
		plan.ticket,
		plan.toState,
		plan.nextVersion,
		plan.customerVisible,
		plan.assignment,
	)
}

func ApplyMutationPlan(
	workflow WorkflowDefinition,
	current TicketSnapshot,
	plan MutationPlan,
) (TicketSnapshot, error) {
	if !validTicketSnapshot(workflow, current) || plan.action == ActionCreate ||
		!validAction(plan.action) || plan.kind != current.kind || plan.tenant != current.tenant ||
		plan.ticket != current.id || plan.workflowID != current.workflowID ||
		plan.workflowVersion != current.workflowVersion || plan.expectedVersion != current.version ||
		plan.nextVersion != current.version+1 || plan.fromState != current.state ||
		!validEntityID(plan.actor) || !validAssignment(plan.assignment) || !validEffectPlan(plan.effects) ||
		plan.action != ActionTransition && plan.comment != nil ||
		plan.comment != nil && !validCommentDraft(*plan.comment) {
		return TicketSnapshot{}, ErrPlanDoesNotApply
	}
	if _, exists := workflow.state(plan.toState); !exists {
		return TicketSnapshot{}, ErrPlanDoesNotApply
	}
	return NewTicketSnapshot(
		workflow,
		current.tenant,
		current.id,
		plan.toState,
		plan.nextVersion,
		plan.customerVisible,
		plan.assignment,
	)
}
