package ticketing

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEscalationPlansIndependentAggregatesAndCanonicalLinks(t *testing.T) {
	alertWorkflow := alertWorkflowFixture(t)
	caseWorkflow := caseWorkflowFixture(t)
	authority := authorityFixture(t, fixtureID(101))
	firstAlert := mustTicket(t, alertWorkflow, fixtureID(301), "new", 4, true, Assignment{})
	secondAlert := mustTicket(t, alertWorkflow, fixtureID(302), "new", 7, true, Assignment{})
	firstSource := richEscalationSource(t, alertWorkflow, firstAlert, fixtureID(501))
	secondSource, err := NewEscalationSource(
		alertWorkflow,
		fixtureID(502),
		secondAlert,
		7,
		[]CopyField{CopyTags, CopyTitle},
		nil,
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewCaseCreationTarget(caseWorkflow, fixtureID(1), fixtureID(401), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewIdempotencyKey("escalate-request-0001")
	if err != nil {
		t.Fatal(err)
	}
	reason, err := NewEscalationReason("Correlated indicators require investigation")
	if err != nil {
		t.Fatal(err)
	}
	linkedAt := time.Date(2026, time.August, 25, 9, 30, 0, 123_456_000, time.UTC)
	command, err := NewEscalationCommand(
		fixtureID(1),
		key,
		linkedAt,
		RelationEscalation,
		reason,
		target,
		[]EscalationSource{secondSource, firstSource},
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := PlanEscalation(sourceWorkflowBindings(t, alertWorkflow, command.sources), caseWorkflow, command, authority)
	plan, allowed := decision.Plan()
	if !allowed {
		t.Fatalf("escalation denied: %s/%s", decision.Outcome(), decision.Reason())
	}
	if len(plan.AlertMutations()) != 2 || len(plan.Links()) != 2 || plan.CaseMutation().Action() != ActionCreate {
		t.Fatalf("unexpected escalation plan: %s", plan)
	}
	caseSnapshot, err := SnapshotFromCreatePlan(caseWorkflow, plan.CaseMutation())
	if err != nil {
		t.Fatal(err)
	}
	if caseSnapshot.Kind() != AggregateCase || caseSnapshot.ID() != fixtureID(401) || caseSnapshot.Version() != 1 {
		t.Fatalf("unexpected case snapshot: %s", caseSnapshot)
	}

	links := plan.Links()
	if links[0].Alert() != fixtureID(301) || links[1].Alert() != fixtureID(302) {
		t.Fatalf("links are not sorted by alert: %#v", links)
	}
	if links[0].SourceAlertVersion() != 4 || links[1].SourceAlertVersion() != 7 ||
		links[0].Case() != caseSnapshot.ID() || links[1].Case() != caseSnapshot.ID() ||
		links[0].LinkedAt() != linkedAt || links[0].LinkedBy() != authority.Actor() {
		t.Fatalf("link provenance incomplete: %#v", links)
	}
	if got := links[0].CopyFields(); !reflect.DeepEqual(got, []CopyField{
		CopyTitle, CopyCustomFields, CopyIOCs, CopyPublicComments,
	}) {
		t.Fatalf("copy fields not canonical: %v", got)
	}
	for _, comment := range links[0].PublicComments() {
		if comment.Visibility() != CommentPublic {
			t.Fatal("non-public comment entered escalation plan")
		}
	}

	sourceByID := map[EntityID]TicketSnapshot{
		firstAlert.ID():  firstAlert,
		secondAlert.ID(): secondAlert,
	}
	for _, mutation := range plan.AlertMutations() {
		original := sourceByID[mutation.Ticket()]
		next, err := ApplyMutationPlan(alertWorkflow, original, mutation)
		if err != nil {
			t.Fatal(err)
		}
		if next.Kind() != AggregateAlert || next.ID() != original.ID() || next.State() != original.State() ||
			next.Version() != original.Version()+1 {
			t.Fatalf("alert aggregate was merged or converted: before=%s after=%s", original, next)
		}
	}
	if firstAlert.Version() != 4 || secondAlert.Version() != 7 {
		t.Fatal("source snapshots were mutated")
	}

	reordered, err := NewEscalationCommand(
		fixtureID(1), key, linkedAt, RelationEscalation, reason, target,
		[]EscalationSource{firstSource, secondSource},
	)
	if err != nil {
		t.Fatal(err)
	}
	replay, replayAllowed := PlanEscalation(sourceWorkflowBindings(t, alertWorkflow, reordered.sources), caseWorkflow, reordered, authority).Plan()
	if !replayAllowed || CompareEscalationReplay(plan, replay) != ReplayExact || plan.Fingerprint() != replay.Fingerprint() {
		t.Fatal("canonical exact replay did not resolve to the prior operation")
	}

	originalSources := []EscalationSource{firstSource, secondSource}
	postCommitSources := make([]EscalationSource, 0, len(originalSources))
	for index, originalSource := range originalSources {
		var mutation MutationPlan
		for _, candidate := range plan.AlertMutations() {
			if candidate.Ticket() == originalSource.Alert().ID() {
				mutation = candidate
			}
		}
		advancedAlert, applyErr := ApplyMutationPlan(alertWorkflow, originalSource.Alert(), mutation)
		if applyErr != nil {
			t.Fatal(applyErr)
		}
		postCommitSource, sourceErr := NewEscalationSource(
			alertWorkflow,
			fixtureID(uint16(598+index)),
			advancedAlert,
			originalSource.ExpectedVersion(),
			originalSource.CopyFields(),
			originalSource.CustomFields(),
			originalSource.Items(),
			originalSource.PublicComments(),
		)
		if sourceErr != nil {
			t.Fatal(sourceErr)
		}
		postCommitSources = append(postCommitSources, postCommitSource)
	}
	postCommitTarget, err := NewCaseCreationTarget(caseWorkflow, fixtureID(1), fixtureID(499), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	postCommitRetry, err := NewEscalationCommand(
		fixtureID(1),
		key,
		linkedAt.Add(time.Minute),
		RelationEscalation,
		reason,
		postCommitTarget,
		postCommitSources,
	)
	if err != nil {
		t.Fatal(err)
	}
	retryIdentity, err := NewEscalationReplayIdentity(postCommitRetry, authority)
	if err != nil {
		t.Fatal(err)
	}
	if CompareEscalationReplayIdentity(plan.ReplayIdentity(), retryIdentity) != ReplayExact {
		t.Fatal("post-commit exact retry depended on server-generated IDs, timestamp, or advanced versions")
	}
}

func TestEscalationValidatesEveryMixedSourceWorkflowBinding(t *testing.T) {
	firstWorkflow := alertWorkflowFixture(t)
	secondWorkflow, err := NewWorkflowDefinition(
		fixtureID(12), AggregateAlert, 4, firstWorkflow.States(), firstWorkflow.Transitions(),
	)
	if err != nil {
		t.Fatal(err)
	}
	caseWorkflow := caseWorkflowFixture(t)
	firstAlert := mustTicket(t, firstWorkflow, fixtureID(301), "new", 4, true, Assignment{})
	secondAlert := mustTicket(t, secondWorkflow, fixtureID(302), "new", 7, true, Assignment{})
	firstSource, err := NewEscalationSource(firstWorkflow, fixtureID(501), firstAlert, 4, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondSource, err := NewEscalationSource(secondWorkflow, fixtureID(502), secondAlert, 7, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	target, err := NewCaseCreationTarget(caseWorkflow, fixtureID(1), fixtureID(401), 0, true)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewIdempotencyKey("mixed-workflow-escalation")
	reason, _ := NewEscalationReason("Mixed pinned workflows")
	command, err := NewEscalationCommand(
		fixtureID(1), key, time.Date(2026, 8, 25, 10, 30, 0, 0, time.UTC),
		RelationEscalation, reason, target, []EscalationSource{secondSource, firstSource},
	)
	if err != nil {
		t.Fatal(err)
	}
	firstBinding, _ := NewEscalationSourceWorkflow(firstAlert.ID(), firstWorkflow)
	secondBinding, _ := NewEscalationSourceWorkflow(secondAlert.ID(), secondWorkflow)
	plan, allowed := PlanEscalation(
		[]EscalationSourceWorkflow{secondBinding, firstBinding}, caseWorkflow, command,
		authorityFixture(t, fixtureID(101)),
	).Plan()
	if !allowed || len(plan.AlertMutations()) != 2 {
		t.Fatalf("mixed-workflow plan = (%s, %t)", plan, allowed)
	}
	workflowByAlert := map[EntityID]WorkflowDefinition{
		firstAlert.ID(): firstWorkflow, secondAlert.ID(): secondWorkflow,
	}
	snapshotByAlert := map[EntityID]TicketSnapshot{
		firstAlert.ID(): firstAlert, secondAlert.ID(): secondAlert,
	}
	for _, mutation := range plan.AlertMutations() {
		if _, applyErr := ApplyMutationPlan(
			workflowByAlert[mutation.Ticket()], snapshotByAlert[mutation.Ticket()], mutation,
		); applyErr != nil {
			t.Fatalf("apply mixed source %s: %v", mutation.Ticket(), applyErr)
		}
	}

	driftedBinding, _ := NewEscalationSourceWorkflow(secondAlert.ID(), firstWorkflow)
	extraBinding, _ := NewEscalationSourceWorkflow(fixtureID(303), firstWorkflow)
	tests := []struct {
		name     string
		bindings []EscalationSourceWorkflow
		reason   DecisionReason
	}{
		{name: "missing", bindings: []EscalationSourceWorkflow{firstBinding}, reason: ReasonTargetMismatch},
		{name: "extra", bindings: []EscalationSourceWorkflow{firstBinding, secondBinding, extraBinding}, reason: ReasonTargetMismatch},
		{name: "duplicate", bindings: []EscalationSourceWorkflow{firstBinding, firstBinding}, reason: ReasonInvalidSnapshot},
		{name: "workflow drift", bindings: []EscalationSourceWorkflow{firstBinding, driftedBinding}, reason: ReasonTargetMismatch},
		{name: "malformed", bindings: []EscalationSourceWorkflow{firstBinding, {}}, reason: ReasonInvalidSnapshot},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decision := PlanEscalation(test.bindings, caseWorkflow, command, authorityFixture(t, fixtureID(101)))
			if decision.Outcome() != OutcomeDenied || decision.Reason() != test.reason {
				t.Fatalf("decision = %s/%s, want denied/%s", decision.Outcome(), decision.Reason(), test.reason)
			}
		})
	}
}

func TestEscalationPayloadDriftConflictsAndSensitiveDataIsRedacted(t *testing.T) {
	alertWorkflow := alertWorkflowFixture(t)
	caseWorkflow := caseWorkflowFixture(t)
	authority := authorityFixture(t, fixtureID(101))
	alert := mustTicket(t, alertWorkflow, fixtureID(301), "new", 4, true, Assignment{})
	source := richEscalationSource(t, alertWorkflow, alert, fixtureID(501))
	target, _ := NewCaseCreationTarget(caseWorkflow, fixtureID(1), fixtureID(401), 0, true)
	key, _ := NewIdempotencyKey("same-idempotency-key")
	linkedAt := time.Date(2026, time.August, 25, 10, 0, 0, 0, time.UTC)
	firstReason, _ := NewEscalationReason("First confidential reason")
	secondReason, _ := NewEscalationReason("Different confidential reason")
	firstCommand, _ := NewEscalationCommand(
		fixtureID(1), key, linkedAt, RelationEscalation, firstReason, target, []EscalationSource{source},
	)
	secondCommand, _ := NewEscalationCommand(
		fixtureID(1), key, linkedAt, RelationEscalation, secondReason, target, []EscalationSource{source},
	)
	firstPlan, firstAllowed := PlanEscalation(sourceWorkflowBindings(t, alertWorkflow, firstCommand.sources), caseWorkflow, firstCommand, authority).Plan()
	secondPlan, secondAllowed := PlanEscalation(sourceWorkflowBindings(t, alertWorkflow, secondCommand.sources), caseWorkflow, secondCommand, authority).Plan()
	if !firstAllowed || !secondAllowed || CompareEscalationReplay(firstPlan, secondPlan) != ReplayConflict {
		t.Fatal("same idempotency key with payload drift did not conflict")
	}
	permissionsAfterRevocation := make([]Permission, 0, len(authority.Permissions()))
	for _, permission := range authority.Permissions() {
		if permission != PermissionAlertEscalate {
			permissionsAfterRevocation = append(permissionsAfterRevocation, permission)
		}
	}
	revokedAuthority := authorityFrom(
		t,
		authority,
		PrincipalOperator,
		true,
		authority.Roles(),
		permissionsAfterRevocation,
		authority.ClaimableTeams(),
		authority.ManageableTeams(),
		authority.AssignableRoster(),
	)
	if _, err := NewEscalationReplayIdentity(firstCommand, revokedAuthority); err == nil {
		t.Fatal("idempotent replay survived current authority revocation")
	}
	for _, rendered := range []string{
		fmt.Sprint(firstCommand),
		fmt.Sprintf("%#v", firstCommand),
		fmt.Sprint(firstPlan),
		fmt.Sprintf("%#v", firstPlan),
		fmt.Sprint(firstPlan.Links()[0]),
		fmt.Sprintf("%#v", firstPlan.Links()[0]),
	} {
		if strings.Contains(rendered, firstReason.Value()) || strings.Contains(rendered, "same-idempotency-key") ||
			!strings.Contains(rendered, "REDACTED") {
			t.Fatalf("escalation formatting leaked sensitive material: %q", rendered)
		}
	}
}

func TestEscalationToExistingCaseUsesIndependentLinkMutation(t *testing.T) {
	alertWorkflow := alertWorkflowFixture(t)
	caseWorkflow := caseWorkflowFixture(t)
	authority := authorityFixture(t, fixtureID(101))
	alert := mustTicket(t, alertWorkflow, fixtureID(301), "new", 4, true, Assignment{})
	source, err := NewEscalationSource(
		alertWorkflow, fixtureID(501), alert, 4, nil, nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	caseTicket := mustTicket(t, caseWorkflow, fixtureID(401), "open", 9, true, Assignment{})
	target, err := NewExistingCaseTarget(caseWorkflow, caseTicket, 9)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := NewIdempotencyKey("link-existing-case")
	reason, _ := NewEscalationReason("Attach to active investigation")
	command, err := NewEscalationCommand(
		fixtureID(1), key, time.Date(2026, 8, 25, 11, 0, 0, 0, time.UTC),
		RelationCorrelation, reason, target, []EscalationSource{source},
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, allowed := PlanEscalation(sourceWorkflowBindings(t, alertWorkflow, command.sources), caseWorkflow, command, authority).Plan()
	if !allowed {
		t.Fatal("existing-case link denied")
	}
	if plan.CaseMutation().Action() != ActionLink || plan.CaseMutation().ExpectedVersion() != 9 ||
		plan.CaseMutation().NextVersion() != 10 {
		t.Fatalf("unexpected existing case mutation: %s", plan.CaseMutation())
	}
	if len(plan.Links()[0].CopyFields()) != 0 {
		t.Fatal("link-only escalation invented copied fields")
	}
	next, err := ApplyMutationPlan(caseWorkflow, caseTicket, plan.CaseMutation())
	if err != nil {
		t.Fatal(err)
	}
	if next.ID() != caseTicket.ID() || next.Kind() != AggregateCase || next.State() != caseTicket.State() {
		t.Fatal("link mutation changed aggregate identity or state")
	}
}

func TestEscalationRejectsPrivateCommentsAmbiguityAndStaleSnapshots(t *testing.T) {
	alertWorkflow := alertWorkflowFixture(t)
	caseWorkflow := caseWorkflowFixture(t)
	alert := mustTicket(t, alertWorkflow, fixtureID(301), "new", 4, true, Assignment{})
	privateReference, err := NewCommentReference(fixtureID(601), CommentPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewEscalationSource(
		alertWorkflow,
		fixtureID(501),
		alert,
		4,
		[]CopyField{CopyPublicComments},
		nil,
		nil,
		[]CommentReference{privateReference},
	); err == nil {
		t.Fatal("private comment accepted for escalation copy")
	}
	if _, err := NewEscalationSource(
		alertWorkflow,
		fixtureID(501),
		alert,
		4,
		[]CopyField{CopyCustomFields},
		nil,
		nil,
		nil,
	); err == nil {
		t.Fatal("implicit all-custom-fields selection accepted")
	}

	staleSource, err := NewEscalationSource(
		alertWorkflow, fixtureID(501), alert, 3, []CopyField{CopyTitle}, nil, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	target, _ := NewCaseCreationTarget(caseWorkflow, fixtureID(1), fixtureID(401), 0, true)
	key, _ := NewIdempotencyKey("stale-source")
	reason, _ := NewEscalationReason("Stale source")
	command, err := NewEscalationCommand(
		fixtureID(1), key, time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		RelationEscalation, reason, target, []EscalationSource{staleSource},
	)
	if err != nil {
		t.Fatal(err)
	}
	decision := PlanEscalation(sourceWorkflowBindings(t, alertWorkflow, command.sources), caseWorkflow, command, authorityFixture(t, fixtureID(101)))
	if decision.Outcome() != OutcomeConflict || decision.Reason() != ReasonVersionConflict {
		t.Fatalf("stale source decision = %s/%s", decision.Outcome(), decision.Reason())
	}

	sources := make([]EscalationSource, maxEscalationAlerts+1)
	for index := range sources {
		sources[index] = staleSource
	}
	if _, err := NewEscalationCommand(
		fixtureID(1), key, time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC),
		RelationEscalation, reason, target, sources,
	); err == nil {
		t.Fatal("unbounded escalation source set accepted")
	}
}

func richEscalationSource(
	t testing.TB,
	workflow WorkflowDefinition,
	alert TicketSnapshot,
	linkID EntityID,
) EscalationSource {
	t.Helper()
	item, err := NewCopyItemReference(CopyIOCs, fixtureID(701))
	if err != nil {
		t.Fatal(err)
	}
	comment, err := NewCommentReference(fixtureID(601), CommentPublic)
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewEscalationSource(
		workflow,
		linkID,
		alert,
		alert.Version(),
		[]CopyField{CopyPublicComments, CopyIOCs, CopyTitle, CopyCustomFields},
		[]Key{mustKey(t, "malware_family")},
		[]CopyItemReference{item},
		[]CommentReference{comment},
	)
	if err != nil {
		t.Fatalf("NewEscalationSource: %v", err)
	}
	return source
}

func sourceWorkflowBindings(
	t testing.TB,
	workflow WorkflowDefinition,
	sources []EscalationSource,
) []EscalationSourceWorkflow {
	t.Helper()
	bindings := make([]EscalationSourceWorkflow, 0, len(sources))
	for _, source := range sources {
		binding, err := NewEscalationSourceWorkflow(source.Alert().ID(), workflow)
		if err != nil {
			t.Fatalf("NewEscalationSourceWorkflow: %v", err)
		}
		bindings = append(bindings, binding)
	}
	return bindings
}
