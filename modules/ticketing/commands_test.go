package ticketing

import (
	"reflect"
	"testing"
)

func TestCreateAndTransitionPlansAreVersionAndWorkflowPinned(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	authority := authorityFixture(t, fixtureID(101))
	create, err := NewCreateCommand(
		fixtureID(1), fixtureID(301), workflow.ID(), workflow.Version(), 0, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := PlanCreate(workflow, create, authority)
	plan, allowed := decision.Plan()
	if !allowed {
		t.Fatalf("create denied: %s", decision)
	}
	if plan.ExpectedVersion() != 0 || plan.NextVersion() != 1 || plan.ToState().String() != "new" ||
		!reflect.DeepEqual(plan.Effects().Effects(), []Effect{EffectActivity, EffectAudit}) {
		t.Fatalf("unexpected create plan: %s", plan)
	}
	ticket, err := SnapshotFromCreatePlan(workflow, plan)
	if err != nil {
		t.Fatal(err)
	}

	comment, err := NewCommentDraft(PrincipalOperator, CommentPrivate, "Validated triage reason")
	if err != nil {
		t.Fatal(err)
	}
	transition, err := NewTransitionCommand(
		ticket.Tenant(),
		ticket.ID(),
		ticket.Version(),
		mustKey(t, "new_to_triage"),
		mustKey(t, "triage"),
		&comment,
		[]Key{mustKey(t, "classification")},
	)
	if err != nil {
		t.Fatal(err)
	}
	decision = PlanTransition(workflow, ticket, transition, authority)
	plan, allowed = decision.Plan()
	if !allowed {
		t.Fatalf("transition denied: %s", decision)
	}
	if plan.FromState().String() != "new" || plan.ToState().String() != "triage" ||
		plan.ExpectedVersion() != 1 || plan.NextVersion() != 2 {
		t.Fatalf("unexpected transition plan: %s", plan)
	}
	plannedComment, present := plan.Comment()
	if !present || plannedComment.Body() != comment.Body() || plannedComment.Visibility() != CommentPrivate {
		t.Fatal("validated transition comment was not retained in the mutation plan")
	}
	next, err := ApplyMutationPlan(workflow, ticket, plan)
	if err != nil {
		t.Fatal(err)
	}
	if next.State().String() != "triage" || next.Version() != 2 || !next.CustomerVisible() {
		t.Fatalf("unexpected transitioned ticket: %s", next)
	}
	if CanProjectTicket(workflow, next, ProjectionCustomerAPI) {
		t.Fatal("internal workflow state leaked despite aggregate visibility flag")
	}
}

func TestTransitionDeniesMissingRequirementsAndStaleVersions(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	ticket := mustTicket(t, workflow, fixtureID(301), "new", 4, true, Assignment{})
	base := authorityFixture(t, fixtureID(101))
	comment, err := NewCommentDraft(PrincipalOperator, CommentPrivate, "Required reason")
	if err != nil {
		t.Fatal(err)
	}
	classification := mustKey(t, "classification")
	validCommand, err := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 4, mustKey(t, "new_to_triage"), mustKey(t, "triage"), &comment, []Key{classification},
	)
	if err != nil {
		t.Fatal(err)
	}

	withoutRole := authorityFrom(
		t, base, PrincipalOperator, true, nil, base.Permissions(), base.ClaimableTeams(),
		base.ManageableTeams(), base.AssignableRoster(),
	)
	withoutUpdate := make([]Permission, 0, len(base.Permissions()))
	for _, permission := range base.Permissions() {
		if permission != PermissionAlertUpdate {
			withoutUpdate = append(withoutUpdate, permission)
		}
	}
	permissionDenied := authorityFrom(
		t, base, PrincipalOperator, true, base.Roles(), withoutUpdate, base.ClaimableTeams(),
		base.ManageableTeams(), base.AssignableRoster(),
	)
	noAccess := authorityFrom(
		t, base, PrincipalOperator, false, base.Roles(), base.Permissions(), base.ClaimableTeams(),
		base.ManageableTeams(), base.AssignableRoster(),
	)

	noComment, _ := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 4, mustKey(t, "new_to_triage"), mustKey(t, "triage"), nil, []Key{classification},
	)
	noField, _ := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 4, mustKey(t, "new_to_triage"), mustKey(t, "triage"), &comment, nil,
	)
	stale, _ := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 3, mustKey(t, "new_to_triage"), mustKey(t, "triage"), &comment, []Key{classification},
	)
	unknownEdge, _ := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 4, mustKey(t, "triage_to_closed"), mustKey(t, "closed"), &comment, []Key{classification},
	)
	mismatchedTarget, _ := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 4, mustKey(t, "new_to_triage"), mustKey(t, "closed"), &comment, []Key{classification},
	)
	unknownKey, _ := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 4, mustKey(t, "unknown_transition"), mustKey(t, "triage"), &comment, []Key{classification},
	)

	tests := []struct {
		name      string
		command   TransitionCommand
		authority AuthorizationSnapshot
		outcome   DecisionOutcome
		reason    DecisionReason
	}{
		{"tenant denied first", validCommand, noAccess, OutcomeDenied, ReasonTenantAccess},
		{"missing core permission", validCommand, permissionDenied, OutcomeDenied, ReasonPermission},
		{"missing role", validCommand, withoutRole, OutcomeDenied, ReasonRole},
		{"missing comment", noComment, base, OutcomeDenied, ReasonRequiredComment},
		{"missing custom field", noField, base, OutcomeDenied, ReasonRequiredCustomField},
		{"stale version", stale, base, OutcomeConflict, ReasonVersionConflict},
		{"key belongs to another source", unknownEdge, base, OutcomeDenied, ReasonWorkflowState},
		{"key target mismatch", mismatchedTarget, base, OutcomeDenied, ReasonWorkflowState},
		{"key absent", unknownKey, base, OutcomeDenied, ReasonWorkflowState},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := PlanTransition(workflow, ticket, test.command, test.authority)
			if decision.Outcome() != test.outcome || decision.Reason() != test.reason {
				t.Fatalf("decision = %s, want %s/%s", decision, test.outcome, test.reason)
			}
			if _, exists := decision.Plan(); exists {
				t.Fatal("denied decision exposed a mutation plan")
			}
		})
	}
}

func TestExplicitTransitionIntentsAreBoundToValidatedWorkflowSemantics(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	authority := authorityFixture(t, fixtureID(101))
	comment, err := NewCommentDraft(PrincipalOperator, CommentPrivate, "Intent verified")
	if err != nil {
		t.Fatal(err)
	}

	command := func(ticket TicketSnapshot, transition, target string) TransitionCommand {
		t.Helper()
		result, commandErr := NewTransitionCommand(
			ticket.Tenant(), ticket.ID(), ticket.Version(), mustKey(t, transition), mustKey(t, target), &comment,
			[]Key{mustKey(t, "classification")},
		)
		if commandErr != nil {
			t.Fatal(commandErr)
		}
		return result
	}
	assertIntent := func(ticket TicketSnapshot, transition, target string, intent TransitionIntent, allowed bool) {
		t.Helper()
		decision := PlanTransitionWithIntentAndFacts(
			workflow, ticket, command(ticket, transition, target), authority, intent, ConditionFacts{},
		)
		if decision.Allowed() != allowed {
			t.Fatalf("%s intent for %s -> %s = %s, allowed=%t", intent, ticket.State(), target, decision, allowed)
		}
		if !allowed && decision.Reason() != ReasonWorkflowState {
			t.Fatalf("denied intent reason = %s, want %s", decision.Reason(), ReasonWorkflowState)
		}
	}

	newTicket := mustTicket(t, workflow, fixtureID(301), "new", 1, true, Assignment{})
	assertIntent(newTicket, "new_to_triage", "triage", TransitionIntentAny, true)
	assertIntent(newTicket, "new_to_triage", "triage", TransitionIntentClose, false)
	assertIntent(newTicket, "new_to_triage", "triage", TransitionIntentReopen, false)

	triageTicket := mustTicket(t, workflow, fixtureID(302), "triage", 2, true, Assignment{})
	assertIntent(triageTicket, "triage_to_closed", "closed", TransitionIntentClose, true)
	assertIntent(triageTicket, "triage_to_closed", "closed", TransitionIntentReopen, false)

	closedTicket := mustTicket(t, workflow, fixtureID(303), "closed", 3, true, Assignment{})
	assertIntent(closedTicket, "reopen_triage", "triage", TransitionIntentReopen, true)
	assertIntent(closedTicket, "reopen_triage", "triage", TransitionIntentClose, false)
	assertIntent(closedTicket, "reopen_triage", "triage", TransitionIntent("unknown"), false)
}

func TestAssignmentClaimReleaseAndTransferLifecycle(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	actor := fixtureID(101)
	authority := authorityFixture(t, actor)
	ticket := mustTicket(t, workflow, fixtureID(301), "new", 1, true, Assignment{})

	assign, err := NewAssignCommand(ticket.Tenant(), ticket.ID(), 1, fixtureID(201), &actor)
	if err != nil {
		t.Fatal(err)
	}
	ticket = applyAllowed(t, workflow, ticket, PlanAssign(workflow, ticket, assign, authority), ActionAssign)
	team, teamSet := ticket.Assignment().Team()
	assignee, assigneeSet := ticket.Assignment().Assignee()
	if !teamSet || team != fixtureID(201) || !assigneeSet || assignee != actor || ticket.Assignment().Claimed() {
		t.Fatalf("unexpected assignment: %s", ticket.Assignment())
	}

	claim, err := NewClaimCommand(ticket.Tenant(), ticket.ID(), 2, fixtureID(201))
	if err != nil {
		t.Fatal(err)
	}
	ticket = applyAllowed(t, workflow, ticket, PlanClaim(workflow, ticket, claim, authority), ActionClaim)
	claimant, claimed := ticket.Assignment().Claimant()
	if !claimed || claimant != actor {
		t.Fatalf("unexpected claim: %s", ticket.Assignment())
	}

	release, err := NewReleaseCommand(ticket.Tenant(), ticket.ID(), 3)
	if err != nil {
		t.Fatal(err)
	}
	ticket = applyAllowed(t, workflow, ticket, PlanRelease(workflow, ticket, release, authority), ActionRelease)
	if _, assigned := ticket.Assignment().Assignee(); assigned || ticket.Assignment().Claimed() {
		t.Fatalf("release retained personal ownership: %s", ticket.Assignment())
	}

	other := fixtureID(102)
	transfer, err := NewTransferCommand(ticket.Tenant(), ticket.ID(), 4, fixtureID(202), &other)
	if err != nil {
		t.Fatal(err)
	}
	ticket = applyAllowed(t, workflow, ticket, PlanTransfer(workflow, ticket, transfer, authority), ActionTransfer)
	team, _ = ticket.Assignment().Team()
	assignee, _ = ticket.Assignment().Assignee()
	if team != fixtureID(202) || assignee != other || ticket.Version() != 5 || ticket.Assignment().Claimed() {
		t.Fatalf("unexpected transfer: %s", ticket)
	}
}

func TestClaimFailsClosedForTeamAndCurrentOwnership(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	actor := fixtureID(101)
	base := authorityFixture(t, actor)
	team := fixtureID(201)
	other := fixtureID(102)
	assignedOther, err := NewAssignment(&team, &other, nil)
	if err != nil {
		t.Fatal(err)
	}
	claimedOther, err := NewAssignment(&team, &other, &other)
	if err != nil {
		t.Fatal(err)
	}
	command, _ := NewClaimCommand(fixtureID(1), fixtureID(301), 1, team)

	noTeams := authorityFrom(
		t, base, PrincipalOperator, true, base.Roles(), base.Permissions(), nil,
		base.ManageableTeams(), base.AssignableRoster(),
	)
	tests := []struct {
		name      string
		ticket    TicketSnapshot
		authority AuthorizationSnapshot
		reason    DecisionReason
	}{
		{"team not authorized", mustTicket(t, workflow, fixtureID(301), "new", 1, true, Assignment{}), noTeams, ReasonTeamEligibility},
		{"assigned to another", mustTicket(t, workflow, fixtureID(301), "new", 1, true, assignedOther), base, ReasonAssignedToOther},
		{"already claimed", mustTicket(t, workflow, fixtureID(301), "new", 1, true, claimedOther), base, ReasonAlreadyClaimed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := PlanClaim(workflow, test.ticket, command, test.authority)
			if decision.Outcome() != OutcomeDenied || decision.Reason() != test.reason {
				t.Fatalf("decision = %s, want denied/%s", decision, test.reason)
			}
		})
	}
}

func TestAssignmentCannotBypassTransferAuthority(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	actor := fixtureID(101)
	base := authorityFixture(t, actor)
	sourceTeam := fixtureID(201)
	targetTeam := fixtureID(202)
	assigned, err := NewAssignment(&sourceTeam, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ticket := mustTicket(t, workflow, fixtureID(301), "new", 4, true, assigned)

	assign, err := NewAssignCommand(ticket.Tenant(), ticket.ID(), ticket.Version(), targetTeam, nil)
	if err != nil {
		t.Fatal(err)
	}
	if decision := PlanAssign(workflow, ticket, assign, base); decision.Outcome() != OutcomeDenied ||
		decision.Reason() != ReasonAlreadyAssigned {
		t.Fatalf("assignment over existing ownership = %s", decision)
	}

	targetOnly := authorityFrom(
		t,
		base,
		PrincipalOperator,
		true,
		base.Roles(),
		base.Permissions(),
		base.ClaimableTeams(),
		[]EntityID{targetTeam},
		base.AssignableRoster(),
	)
	transfer, err := NewTransferCommand(
		ticket.Tenant(), ticket.ID(), ticket.Version(), targetTeam, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if decision := PlanTransfer(workflow, ticket, transfer, targetOnly); decision.Outcome() != OutcomeDenied ||
		decision.Reason() != ReasonTeamEligibility {
		t.Fatalf("target-only transfer authority = %s", decision)
	}

	if decision := PlanTransfer(workflow, ticket, transfer, base); !decision.Allowed() {
		t.Fatalf("two-sided transfer denied = %s", decision)
	}
}

func TestSerializedClaimAttemptsChooseOneDeterministicWinner(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	ticket := mustTicket(t, workflow, fixtureID(301), "new", 8, true, Assignment{})
	firstActor := fixtureID(101)
	secondActor := fixtureID(102)
	firstAuthority := authorityFixture(t, firstActor)
	secondBase := authorityFixture(t, secondActor)
	secondAuthority := authorityFrom(
		t,
		secondBase,
		PrincipalOperator,
		true,
		secondBase.Roles(),
		secondBase.Permissions(),
		[]EntityID{fixtureID(201)},
		secondBase.ManageableTeams(),
		secondBase.AssignableRoster(),
	)
	firstCommand, _ := NewClaimCommand(ticket.Tenant(), ticket.ID(), 8, fixtureID(201))
	secondCommand, _ := NewClaimCommand(ticket.Tenant(), ticket.ID(), 8, fixtureID(201))
	firstAttempt, err := NewSerializedClaimAttempt(20, fixtureID(402), firstCommand, firstAuthority)
	if err != nil {
		t.Fatal(err)
	}
	secondAttempt, err := NewSerializedClaimAttempt(10, fixtureID(401), secondCommand, secondAuthority)
	if err != nil {
		t.Fatal(err)
	}

	decisions, result, err := ResolveSerializedClaimAttempts(
		workflow, ticket, []SerializedClaimAttempt{firstAttempt, secondAttempt},
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(decisions) != 2 || decisions[0].AttemptID() != fixtureID(401) ||
		decisions[0].Decision().Outcome() != OutcomeAllowed ||
		decisions[1].Decision().Outcome() != OutcomeConflict ||
		decisions[1].Decision().Reason() != ReasonVersionConflict {
		t.Fatalf("unexpected race decisions: %#v", decisions)
	}
	winner, claimed := result.Assignment().Claimant()
	if !claimed || winner != secondActor || result.Version() != 9 {
		t.Fatalf("unexpected winner snapshot: %s", result)
	}

	reversed, reversedResult, err := ResolveSerializedClaimAttempts(
		workflow, ticket, []SerializedClaimAttempt{secondAttempt, firstAttempt},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decisions, reversed) || result != reversedResult {
		t.Fatal("claim result depended on input slice order")
	}
}

func TestVersionExhaustionConflictsWithoutPlan(t *testing.T) {
	workflow := alertWorkflowFixture(t)
	ticket := mustTicket(t, workflow, fixtureID(301), "new", maxVersion, true, Assignment{})
	command, err := NewClaimCommand(ticket.Tenant(), ticket.ID(), maxVersion, fixtureID(201))
	if err != nil {
		t.Fatal(err)
	}
	decision := PlanClaim(workflow, ticket, command, authorityFixture(t, fixtureID(101)))
	if decision.Outcome() != OutcomeConflict || decision.Reason() != ReasonVersionExhausted {
		t.Fatalf("decision = %s", decision)
	}
}

func TestCaseWorkflowUsesIndependentPermissionsAndLifecycle(t *testing.T) {
	workflow := caseWorkflowFixture(t)
	actor := fixtureID(101)
	authority := authorityFixture(t, actor)
	create, err := NewCreateCommand(
		fixtureID(1), fixtureID(401), workflow.ID(), workflow.Version(), 0, true,
	)
	if err != nil {
		t.Fatal(err)
	}
	createPlan, allowed := PlanCreate(workflow, create, authority).Plan()
	if !allowed {
		t.Fatal("operator case creation denied")
	}
	ticket, err := SnapshotFromCreatePlan(workflow, createPlan)
	if err != nil {
		t.Fatal(err)
	}

	serviceAuthority := authorityFrom(
		t,
		authority,
		PrincipalServiceAccount,
		true,
		nil,
		[]Permission{PermissionCaseCreate},
		nil,
		nil,
		nil,
	)
	if decision := PlanCreate(workflow, create, serviceAuthority); decision.Reason() != ReasonPrincipalKind {
		t.Fatalf("service account case create = %s", decision)
	}

	team := fixtureID(201)
	assign, _ := NewAssignCommand(ticket.Tenant(), ticket.ID(), 1, team, &actor)
	ticket = applyAllowed(t, workflow, ticket, PlanAssign(workflow, ticket, assign, authority), ActionAssign)
	claim, _ := NewClaimCommand(ticket.Tenant(), ticket.ID(), 2, team)
	ticket = applyAllowed(t, workflow, ticket, PlanClaim(workflow, ticket, claim, authority), ActionClaim)
	release, _ := NewReleaseCommand(ticket.Tenant(), ticket.ID(), 3)
	ticket = applyAllowed(t, workflow, ticket, PlanRelease(workflow, ticket, release, authority), ActionRelease)

	comment, _ := NewCommentDraft(PrincipalOperator, CommentPrivate, "Resolution validated")
	transition, _ := NewTransitionCommand(
		ticket.Tenant(), ticket.ID(), 4, mustKey(t, "close_case"), mustKey(t, "closed"), &comment, nil,
	)
	decision := PlanTransition(workflow, ticket, transition, authority)
	ticket = applyAllowed(t, workflow, ticket, decision, ActionTransition)
	if ticket.Kind() != AggregateCase || ticket.State().String() != "closed" || ticket.Version() != 5 {
		t.Fatalf("unexpected case lifecycle result: %s", ticket)
	}

	alertOnlyAuthority := authorityFrom(
		t,
		authority,
		PrincipalOperator,
		true,
		authority.Roles(),
		[]Permission{PermissionAlertCreate, PermissionAlertClaim, PermissionAlertAssign},
		authority.ClaimableTeams(),
		authority.ManageableTeams(),
		authority.AssignableRoster(),
	)
	caseTicket := mustTicket(t, workflow, fixtureID(402), "open", 1, true, Assignment{})
	caseClaim, _ := NewClaimCommand(caseTicket.Tenant(), caseTicket.ID(), 1, team)
	if decision := PlanClaim(workflow, caseTicket, caseClaim, alertOnlyAuthority); decision.Reason() != ReasonPermission {
		t.Fatalf("alert permission crossed into case workflow: %s", decision)
	}
}

func applyAllowed(
	t testing.TB,
	workflow WorkflowDefinition,
	ticket TicketSnapshot,
	decision Decision,
	action Action,
) TicketSnapshot {
	t.Helper()
	plan, allowed := decision.Plan()
	if !allowed {
		t.Fatalf("%s denied: %s", action, decision)
	}
	if plan.Action() != action {
		t.Fatalf("plan action = %s, want %s", plan.Action(), action)
	}
	next, err := ApplyMutationPlan(workflow, ticket, plan)
	if err != nil {
		t.Fatalf("ApplyMutationPlan(%s): %v", action, err)
	}
	return next
}
